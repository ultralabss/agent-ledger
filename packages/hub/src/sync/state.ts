/** Durable sync state (F3b B3a, docs/f3b-b3-plan.md §1.1): `.hub/sync/state.json` (halt, backoff,
 *  accepted mirror, D2 confirmations, ratchet) and `.hub/sync/inflight.json` (APPLY crash marker).
 *
 *  Threat model:
 *   - Actor: a crash / power loss, a buggy later batch, a local process with the same uid (out of
 *     model: `.hub/` is the local trust boundary), and attacker-influenced strings (remote error
 *     text, device labels) that reach `detail` fields.
 *   - Protected: the halt / quarantine decision must survive restarts; a half-written file must never
 *     be read as state; the unsigned-commit ratchet (`seenSigning`) must never shrink; the inflight
 *     marker must never name a path outside the ledger tree.
 *   - Failure modes: torn write, symlink / foreign-owned file, hostile or truncated JSON, unbounded
 *     lists, `detail` carrying a secret or URL.
 *   - Stance: fail closed. A corrupt or invalid file THROWS `StateError('CORRUPT')` (the caller halts
 *     `config`); it is never replaced by an empty state behind the caller's back. Single writer = the
 *     hub process (in-process serialisation here); B4 CLI goes through loopback routes to `SyncLoop`.
 *     Writes: private tmp (exclusive, 0600) -> fsync -> rename -> directory fsync.
 *   - No secrets: `detail` is a short sanitised line; callers never pass URLs, stderr or blob text.
 */

import { randomBytes } from 'node:crypto';
import { link, lstat, mkdir, open, readdir, rename, rm } from 'node:fs/promises';
import nodePath from 'node:path';
import { ensurePrivateDir, openPrivate, renameRetry, TrustError } from '@agent-ledger/shared';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { validateRemoteUrl } from './gitx.ts';
import { assertTreePath } from './treebuild.ts';

export const SYNC_DIR = '.hub/sync';
export const INFLIGHT_FILE = 'inflight.json';
export const STATE_FILE = 'state.json';
/** `<ledger>/.hub/sync.yml`: where the remote lives (written by `sync init`, B4). */
export const SYNC_CONFIG_FILE = '.hub/sync.yml';
/** `<ledger>/.hub/sync/enrol.json`: enrolment in progress (`sync init|join`). While it exists the hub refuses to start. */
export const ENROL_FILE = 'enrol.json';
export const MAX_ENROL_BYTES = 4 * 1024;
/** A marker older than this is taken over whatever its pid says (pid reuse must not wedge enrolment). */
export const ENROL_STALE_MS = 24 * 60 * 60_000;

export const MAX_STATE_BYTES = 512 * 1024;
export const MAX_INFLIGHT_BYTES = 12 * 1024 * 1024;
export const MAX_SYNC_CONFIG_BYTES = 4 * 1024;
export const MAX_INFLIGHT_PATHS = 20_000;
export const MAX_CONFIRMATIONS = 64;
export const MAX_OVERRIDES = 16;
export const MAX_SEEN_SIGNING = 64;
export const MAX_NOTED = 200;

export type HaltClass = 'no-contact' | 'sticky' | 'probe' | 'd2' | 'local' | 'terminal';
export type HaltReason =
  | 'auth'
  | 'hostkey'
  | 'history-rewrite'
  | 'config'
  | 'format'
  | 'inflight'
  | 'detached'
  | 'quarantine:revocation-root'
  | 'quarantine:revocation-self'
  | `quarantine:${string}`;

export interface HaltState {
  reason: HaltReason;
  cls: HaltClass;
  since: string;
  tip: string | null;
  rule: string | null;
  /** One short sanitised line; never a URL, stderr or content. */
  detail: string;
  d2: { commit: string; deviceIds: string[]; kind: 'root' | 'self' } | null;
}

export interface Confirmation {
  kind: 'root' | 'self';
  device_id: string;
  commit: string;
  fp: string;
  at: string;
}

export interface SyncState {
  v: 1;
  halt: HaltState | null;
  /** `failures` = consecutive failed cycles; `nextAt` = ISO time before which no retry. */
  backoff: { failures: number; nextAt: string | null; lastError: string | null };
  /** Mirror of `refs/ledger-sync/accepted` (the ref is the truth; a mismatch halts `config`). */
  accepted: string | null;
  confirmations: Confirmation[];
  overrides: { tip: string; at: string; secretAck?: boolean }[];
  /** Device ids ever seen signing (OQ-4 ratchet). GROWS ONLY: `update` refuses to drop one. */
  seenSigning: string[];
  strikes: { tip: string; n: number } | null;
  noted: { key: string; at: string }[];
  pushBlocked: { rule: string; tip: string; since: string } | null;
  /** UNVERIFIED shape (the plan elides it): last finished cycle, for status output only. */
  lastCycle: { at: string; outcome: string; ms: number } | null;
}

export interface InflightNotes {
  inbox: {
    to_session: string;
    repo: string | null;
    item_id: string | null;
    body: string;
    origin: 'hub';
  }[];
  releaseLeases: { item: string; session: string }[];
  /** UNVERIFIED shape (the plan elides it): hub-proposed items, flat string records. */
  proposed: Record<string, string>[];
}

export interface Inflight {
  v: 1;
  id: string;
  createdAt: string;
  mode: 'ff' | 'merge';
  /** accepted before this cycle / local main before / merge or FF result / fetched remote tip. */
  A: string;
  L: string;
  M: string;
  F: string;
  treeL: string;
  treeM: string;
  /** Repo-relative paths the APPLY touches (`assertTreePath`-clean). */
  changed: string[];
  notes: InflightNotes;
  stage: 'prepared' | 'ref-moved' | 'notes-done';
}

export type StateErrorCode = 'CORRUPT' | 'INVALID' | 'UNSAFE' | 'INVARIANT' | 'IO' | 'BUSY';

export class StateError extends Error {
  readonly code: StateErrorCode;
  constructor(code: StateErrorCode, message: string) {
    super(message);
    this.name = 'StateError';
    this.code = code;
  }
}

/* ---------------- schemas ---------------- */

const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const DEVICE_ID_RE = /^d_[a-z2-7]{10}$/;
const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
const TOKEN_RE = /^[a-z0-9][a-z0-9:_.-]{0,59}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const SLUG_RE = /^[a-z0-9-]{1,100}$/;
// eslint-disable-next-line no-control-regex
const NO_CONTROL_RE = /^[^\u0000-\u001f\u007f]*$/;
// eslint-disable-next-line no-control-regex
const BODY_RE = /^[^\u0000-\u0008\u000b-\u001f\u007f]*$/;
const QUARANTINE_RE = /^quarantine:[a-z0-9][a-z0-9:_.-]{0,59}$/;

const sha = z.string().regex(SHA_RE);
const deviceId = z.string().regex(DEVICE_ID_RE);
const iso = z.string().max(40).regex(ISO_RE).refine((s) => Number.isFinite(Date.parse(s)));
const token = z.string().regex(TOKEN_RE);
const line = (max: number): z.ZodString => z.string().max(max).regex(NO_CONTROL_RE);

const FIXED_REASONS: Record<string, HaltClass> = {
  auth: 'no-contact',
  hostkey: 'no-contact',
  'history-rewrite': 'sticky',
  config: 'local',
  format: 'sticky',
  inflight: 'local',
  detached: 'terminal',
  'quarantine:revocation-root': 'd2',
  'quarantine:revocation-self': 'd2',
};

const haltSchema = z
  .strictObject({
    reason: z.string().refine((r) => r in FIXED_REASONS || QUARANTINE_RE.test(r)),
    cls: z.enum(['no-contact', 'sticky', 'probe', 'd2', 'local', 'terminal']),
    since: iso,
    tip: sha.nullable(),
    rule: token.nullable(),
    detail: line(200),
    d2: z
      .strictObject({
        commit: sha,
        deviceIds: z.array(deviceId).min(1).max(MAX_SEEN_SIGNING),
        kind: z.enum(['root', 'self']),
      })
      .nullable(),
  })
  .superRefine((h, ctx) => {
    // The class decides how much network contact is allowed (invariant 14): it must follow from the reason.
    const want = FIXED_REASONS[h.reason] ?? 'probe';
    if (h.cls !== want) ctx.addIssue({ code: 'custom', message: 'halt class does not match reason' });
    const d2Reason = h.reason === 'quarantine:revocation-root' ? 'root' : h.reason === 'quarantine:revocation-self' ? 'self' : null;
    if (d2Reason === null ? h.d2 !== null : h.d2 === null || h.d2.kind !== d2Reason) {
      ctx.addIssue({ code: 'custom', message: 'halt d2 does not match reason' });
    }
  });

const confirmationSchema = z.strictObject({
  kind: z.enum(['root', 'self']),
  device_id: deviceId,
  commit: sha,
  fp: z.string().regex(FP_RE),
  at: iso,
});

const stateSchema = z.strictObject({
  v: z.literal(1),
  halt: haltSchema.nullable(),
  backoff: z.strictObject({
    failures: z.number().int().min(0).max(1_000_000),
    nextAt: iso.nullable(),
    lastError: token.nullable(),
  }),
  accepted: sha.nullable(),
  confirmations: z.array(confirmationSchema).max(MAX_CONFIRMATIONS),
  overrides: z
    .array(z.strictObject({ tip: sha, at: iso, secretAck: z.boolean().optional() }))
    .max(MAX_OVERRIDES),
  seenSigning: z.array(deviceId).max(MAX_SEEN_SIGNING),
  strikes: z.strictObject({ tip: sha, n: z.number().int().min(1).max(1000) }).nullable(),
  noted: z.array(z.strictObject({ key: line(120), at: iso })).max(MAX_NOTED),
  pushBlocked: z.strictObject({ rule: token, tip: sha, since: iso }).nullable(),
  lastCycle: z
    .strictObject({ at: iso, outcome: token, ms: z.number().int().min(0).max(24 * 3600 * 1000) })
    .nullable(),
});

const inflightSchema = z
  .strictObject({
    v: z.literal(1),
    id: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/),
    createdAt: iso,
    mode: z.enum(['ff', 'merge']),
    A: sha,
    L: sha,
    M: sha,
    F: sha,
    treeL: sha,
    treeM: sha,
    changed: z
      .array(
        z.string().refine((p) => {
          try {
            assertTreePath(p);
            return true;
          } catch {
            return false;
          }
        }),
      )
      .max(MAX_INFLIGHT_PATHS),
    notes: z.strictObject({
      inbox: z
        .array(
          z.strictObject({
            to_session: line(80),
            repo: z.string().regex(SLUG_RE).nullable(),
            item_id: line(40).nullable(),
            body: z.string().max(2000).regex(BODY_RE),
            origin: z.literal('hub'),
          }),
        )
        .max(20),
      releaseLeases: z.array(z.strictObject({ item: line(40), session: line(80) })).max(200),
      proposed: z.array(z.record(z.string().regex(TOKEN_RE), z.string().max(400).regex(BODY_RE)).refine((r) => Object.keys(r).length <= 8)).max(20),
    }),
    stage: z.enum(['prepared', 'ref-moved', 'notes-done']),
  })
  .superRefine((m, ctx) => {
    // FF: the result IS the fetched tip; merge: a new commit with parents [L,F]. L never equals M.
    if (m.L === m.M) ctx.addIssue({ code: 'custom', message: 'marker: L equals M' });
    if (m.mode === 'ff' ? m.M !== m.F : m.M === m.F) ctx.addIssue({ code: 'custom', message: 'marker: M does not fit mode' });
  });

/* ---------------- helpers ---------------- */

export function emptyState(): SyncState {
  return {
    v: 1,
    halt: null,
    backoff: { failures: 0, nextAt: null, lastError: null },
    accepted: null,
    confirmations: [],
    overrides: [],
    seenSigning: [],
    strikes: null,
    noted: [],
    pushBlocked: null,
    lastCycle: null,
  };
}

/** Confirmation key: bound to the COMMIT and the DEVICE (D2: a confirmation for one revocation never
 *  confirms another commit or another id). Both parts are validated: a malformed part throws. */
export function confirmationKey(commit: string, deviceIdArg: string): string {
  if (typeof commit !== 'string' || !SHA_RE.test(commit) || typeof deviceIdArg !== 'string' || !DEVICE_ID_RE.test(deviceIdArg)) {
    throw new StateError('INVALID', 'confirmation key needs a commit sha and a device id');
  }
  return `${commit}:${deviceIdArg}`;
}

const BACKOFF_BASE_MS = 30_000;
const BACKOFF_CAP_MS = 15 * 60_000;

/** Delay before the next cycle after `failures` consecutive failures INCLUDING the one that just
 *  happened (1 -> 30 s, 2 -> 60 s, ... capped at 15 min), +-20 % jitter. `rnd` returns [0,1). */
export function nextBackoff(failures: number, rnd: () => number = Math.random): number {
  const n = typeof failures === 'number' && !Number.isNaN(failures) ? Math.min(Math.max(Math.trunc(failures) - 1, 0), 30) : 0;
  const base = Math.min(BACKOFF_BASE_MS * 2 ** n, BACKOFF_CAP_MS);
  let r = rnd();
  if (typeof r !== 'number' || !Number.isFinite(r)) r = 0.5;
  r = Math.min(Math.max(r, 0), 1);
  return Math.round(base * (0.8 + r * 0.4));
}

function fail(what: string, err: z.ZodError | unknown): never {
  void err; // never echo parsed content into the message
  throw new StateError('CORRUPT', `${what} is not valid`);
}

export function parseSyncState(text: string): SyncState {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return fail('state.json', null);
  }
  const res = stateSchema.safeParse(raw);
  if (!res.success) return fail('state.json', res.error);
  return res.data as SyncState;
}

export function parseInflight(text: string): Inflight {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return fail('inflight.json', null);
  }
  const res = inflightSchema.safeParse(raw);
  if (!res.success) return fail('inflight.json', res.error);
  return res.data as Inflight;
}

/** Cap the lists (keep the newest). `seenSigning` is only trimmed by growth beyond its cap (oldest first), see `update`. */
function normalise(s: SyncState): SyncState {
  const tail = <T>(a: T[], max: number): T[] => (a.length > max ? a.slice(a.length - max) : a);
  return {
    ...s,
    confirmations: tail(s.confirmations, MAX_CONFIRMATIONS),
    overrides: tail(s.overrides, MAX_OVERRIDES),
    noted: tail(s.noted, MAX_NOTED),
    seenSigning: tail(s.seenSigning, MAX_SEEN_SIGNING),
  };
}

/* ---------------- file IO ---------------- */

const isErrno = (err: unknown, code: string): boolean => (err as NodeJS.ErrnoException | null)?.code === code;

/** `null` = absent. Refuses symlinks / non-regular files / foreign owners; capped (oversize = CORRUPT). */
async function readCapped(path: string, max: number): Promise<string | null> {
  let st;
  try {
    st = await lstat(path, { bigint: true });
  } catch (err) {
    if (isErrno(err, 'ENOENT')) return null;
    throw new StateError('IO', `cannot stat ${nodePath.basename(path)}`);
  }
  if (st.isSymbolicLink() || !st.isFile()) throw new StateError('UNSAFE', `${nodePath.basename(path)} is not a regular file`);
  if (st.size > BigInt(max)) throw new StateError('CORRUPT', `${nodePath.basename(path)} is too large`);
  let h;
  try {
    h = await openPrivate(path, 'read');
  } catch (err) {
    if (isErrno(err, 'ENOENT')) return null;
    if (err instanceof TrustError) throw new StateError('UNSAFE', `${nodePath.basename(path)} failed the ownership check`);
    throw new StateError('IO', `cannot open ${nodePath.basename(path)}`);
  }
  try {
    const text = await h.readText();
    if (Buffer.byteLength(text, 'utf8') > max) throw new StateError('CORRUPT', `${nodePath.basename(path)} is too large`);
    return text;
  } finally {
    await h.close().catch(() => undefined);
  }
}

async function fsyncDir(dir: string): Promise<void> {
  let fh;
  try {
    fh = await open(dir, 'r');
  } catch (err) {
    if (process.platform === 'win32') return; // directories cannot be opened there; NOT verified
    throw err;
  }
  try {
    await fh.sync();
  } catch (err) {
    if (!isErrno(err, 'EINVAL') && !isErrno(err, 'ENOTSUP') && process.platform !== 'win32') throw err;
  } finally {
    await fh.close().catch(() => undefined);
  }
}

/** tmp (exclusive, 0600, no-follow) -> fsync -> rename -> directory fsync. */
async function writeDurable(path: string, text: string): Promise<void> {
  const tmp = `${path}.${String(process.pid)}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    const h = await openPrivate(tmp, 'excl', 0o600);
    try {
      await h.writeFile(text);
      await h.sync();
    } finally {
      await h.close();
    }
    await renameRetry(tmp, path);
  } catch (err) {
    await rm(tmp, { force: true }).catch(() => undefined);
    if (err instanceof StateError) throw err;
    if (err instanceof TrustError) throw new StateError('UNSAFE', 'sync directory failed the ownership check');
    throw new StateError('IO', `cannot write ${nodePath.basename(path)}`);
  }
  try {
    await fsyncDir(nodePath.dirname(path));
  } catch {
    throw new StateError('IO', 'cannot sync the sync directory');
  }
}

const TMP_LEFTOVER_RE = /^(?:state|inflight|enrol)\.json\.\d+\.[0-9a-f]{12}\.tmp$/;
const TMP_STALE_MS = 10 * 60_000;

async function sweepTmp(dir: string): Promise<void> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return;
  }
  for (const name of names) {
    if (!TMP_LEFTOVER_RE.test(name)) continue;
    const p = nodePath.join(dir, name);
    const st = await lstat(p).catch(() => null);
    if (st === null || st.isSymbolicLink() || !st.isFile()) continue;
    if (Math.abs(Date.now() - st.mtimeMs) <= TMP_STALE_MS) continue; // clocks jump: distance
    await rm(p, { force: true }).catch(() => undefined);
  }
}

export class StateStore {
  readonly inflightPath: string;
  readonly statePath: string;
  private readonly dir: string;
  private chain: Promise<unknown> = Promise.resolve();

  private constructor(dir: string) {
    this.dir = dir;
    this.statePath = nodePath.join(dir, STATE_FILE);
    this.inflightPath = nodePath.join(dir, INFLIGHT_FILE);
  }

  /** `ledgerDir` = the ledger root; the store lives in `<root>/.hub/sync` (private dir, created). */
  static async open(ledgerDir: string): Promise<StateStore> {
    const hub = nodePath.join(ledgerDir, '.hub');
    const dir = nodePath.join(ledgerDir, SYNC_DIR);
    try {
      if (process.platform === 'win32') await ensurePrivateDir(hub);
      else await mkdir(hub, { recursive: true, mode: 0o700 });
      await ensurePrivateDir(dir);
    } catch (err) {
      if (err instanceof TrustError) throw new StateError('UNSAFE', 'sync directory is not private to this user');
      throw new StateError('IO', 'cannot create the sync directory');
    }
    await sweepTmp(dir);
    return new StateStore(dir);
  }

  /** Absent file = empty state. Corrupt / unsafe / oversize THROWS (the caller halts `config`). */
  async read(): Promise<SyncState> {
    const text = await readCapped(this.statePath, MAX_STATE_BYTES);
    return text === null ? emptyState() : parseSyncState(text);
  }

  /** Read-modify-write, serialised in this process. `fn` may mutate its argument or return a new
   *  state. The result is validated before it is written, `seenSigning` may only grow, and the
   *  newest entries of the cap-only lists are kept. Returns what was written. */
  update(fn: (s: SyncState) => SyncState | void): Promise<SyncState> {
    const run = async (): Promise<SyncState> => {
      const before = await this.read();
      const draft = structuredClone(before);
      const out = fn(draft);
      const proposed = (out ?? draft) as SyncState;
      const grewPastCap = Array.isArray(proposed.seenSigning) && proposed.seenSigning.length > MAX_SEEN_SIGNING;
      const next = normalise(proposed);
      const text = JSON.stringify(next);
      let checked: SyncState;
      try {
        checked = parseSyncState(text);
      } catch {
        throw new StateError('INVALID', 'refusing to write an invalid sync state');
      }
      const now = new Set(checked.seenSigning);
      // The ratchet only grows. The single exception is the cap itself: more than 64 ids (the lifetime device
      // cap is 25) evicts the OLDEST entries instead of throwing, so a registry abuse can neither make `update`
      // fail forever nor silently shrink the list below the cap. Any other shrink is refused.
      if (!grewPastCap && before.seenSigning.some((id) => !now.has(id))) {
        throw new StateError('INVARIANT', 'seenSigning only grows');
      }
      const body = `${JSON.stringify(checked)}\n`;
      if (Buffer.byteLength(body, 'utf8') > MAX_STATE_BYTES) throw new StateError('INVALID', 'sync state too large');
      await writeDurable(this.statePath, body);
      return checked;
    };
    const p = this.chain.then(run, run);
    this.chain = p.catch(() => undefined); // a failed update never breaks the chain
    return p;
  }

  /** `null` = no marker. Corrupt / unsafe THROWS: the marker is evidence of a half-done APPLY. */
  async readInflight(): Promise<Inflight | null> {
    const text = await readCapped(this.inflightPath, MAX_INFLIGHT_BYTES);
    return text === null ? null : parseInflight(text);
  }

  async writeInflight(m: Inflight): Promise<void> {
    let body: string;
    try {
      body = `${JSON.stringify(parseInflight(JSON.stringify(m)))}\n`;
    } catch {
      throw new StateError('INVALID', 'refusing to write an invalid inflight marker');
    }
    if (Buffer.byteLength(body, 'utf8') > MAX_INFLIGHT_BYTES) throw new StateError('INVALID', 'inflight marker too large');
    await this.serialised(() => writeDurable(this.inflightPath, body));
  }

  /** Idempotent. The directory is fsynced so a crash after this never resurrects the marker. */
  async clearInflight(): Promise<void> {
    await this.serialised(async () => {
      try {
        await rm(this.inflightPath, { force: true });
      } catch {
        throw new StateError('IO', 'cannot remove the inflight marker');
      }
      await fsyncDir(this.dir).catch(() => {
        throw new StateError('IO', 'cannot sync the sync directory');
      });
    });
  }

  private serialised<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.chain.then(fn, fn);
    this.chain = p.catch(() => undefined);
    return p;
  }
}

/* ---------------- sync.yml ---------------- */

const syncConfigSchema = z.strictObject({
  v: z.literal(1),
  // eslint-disable-next-line no-control-regex
  remote: z.string().min(1).max(1024).regex(/^[^\u0000- \u007f]+$/).refine((r) => !r.startsWith('-')),
});

/** `<ledger>/.hub/sync.yml`: strict, <= 4 KB, no YAML aliases. `null` = absent (not enrolled).
 *  Anything present but unusable THROWS `StateError('CORRUPT')`. The URL itself is validated again by
 *  `validateRemoteUrl` at every use; this only keeps obviously hostile text out of the process. */
export async function readSyncConfig(ledgerDir: string): Promise<{ v: 1; remote: string } | null> {
  const text = await readCapped(nodePath.join(ledgerDir, SYNC_CONFIG_FILE), MAX_SYNC_CONFIG_BYTES);
  if (text === null) return null;
  let raw: unknown;
  try {
    raw = parseYaml(text, { maxAliasCount: 0 });
  } catch {
    return fail('sync.yml', null);
  }
  const res = syncConfigSchema.safeParse(raw);
  if (!res.success) return fail('sync.yml', res.error);
  return res.data as { v: 1; remote: string };
}

async function ensureLedgerHub(ledgerDir: string, sync: boolean): Promise<void> {
  const hub = nodePath.join(ledgerDir, '.hub');
  try {
    if (process.platform === 'win32') await ensurePrivateDir(hub);
    else await mkdir(hub, { recursive: true, mode: 0o700 });
    if (sync) await ensurePrivateDir(nodePath.join(ledgerDir, SYNC_DIR));
  } catch (err) {
    if (err instanceof TrustError) throw new StateError('UNSAFE', 'sync directory is not private to this user');
    throw new StateError('IO', 'cannot create the sync directory');
  }
}

/** Parse the config text we are about to write exactly as `readSyncConfig` would, and require the URL back. */
function syncConfigText(remote: string): string {
  const text = `v: 1\nremote: ${JSON.stringify(remote)}\n`;
  let raw: unknown;
  try {
    raw = parseYaml(text, { maxAliasCount: 0 });
  } catch {
    return fail('sync.yml', null);
  }
  const res = syncConfigSchema.safeParse(raw);
  if (!res.success || res.data.remote !== remote || Buffer.byteLength(text, 'utf8') > MAX_SYNC_CONFIG_BYTES) {
    return fail('sync.yml', res.success ? null : res.error);
  }
  return text;
}

/** Write `<ledger>/.hub/sync.yml` (`sync init|join`): the remote is re-validated with `validateRemoteUrl`
 *  (ssh / scp only, no credentials, no leading dash; `testLocalRemotes` is a TEST seam, never from env),
 *  the file text is parsed back with the reader's schema, then tmp (0600, exclusive) -> fsync -> rename ->
 *  dir fsync. A symlink at the destination is replaced, never followed (rename). Throws `StateError`
 *  (`INVALID` for a refused URL: the message never contains it). */
export async function writeSyncConfig(
  ledgerDir: string,
  remote: string,
  opts: { testLocalRemotes?: readonly string[] } = {},
): Promise<void> {
  try {
    validateRemoteUrl(remote, opts.testLocalRemotes ?? []);
  } catch {
    throw new StateError('INVALID', 'refusing to write sync.yml: the remote URL is not acceptable');
  }
  const text = syncConfigText(remote);
  await ensureLedgerHub(ledgerDir, false);
  await writeDurable(nodePath.join(ledgerDir, SYNC_CONFIG_FILE), text);
}

/* ---------------- enrol marker (`.hub/sync/enrol.json`) ---------------- */

/** Stage tokens are owned by `enrol.ts` (B4b); the grammar only keeps them out of paths, URLs and prose. */
const enrolSchema = z.strictObject({
  v: z.literal(1),
  kind: z.enum(['init', 'join']),
  stage: z.string().regex(/^[a-z][a-z0-9-]{0,29}$/),
  pid: z.number().int().min(1).max(2 ** 31 - 1),
  startedAt: iso,
  remote: syncConfigSchema.shape.remote,
  F0: sha.optional(),
});
export type EnrolMarker = z.infer<typeof enrolSchema>;

function parseEnrol(text: string): EnrolMarker {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return fail('enrol marker', null);
  }
  const res = enrolSchema.safeParse(raw);
  if (!res.success) return fail('enrol marker', res.error);
  return res.data;
}

function enrolPath(ledgerDir: string): string {
  return nodePath.join(ledgerDir, SYNC_DIR, ENROL_FILE);
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return !isErrno(err, 'ESRCH'); // EPERM = exists, owned by someone else
  }
}

export interface EnrolOptions {
  /** Test seams. */
  now?: () => number;
  pidAlive?: (pid: number) => boolean;
}

/** `null` = no marker. Present but invalid / oversize / unsafe THROWS (fail closed: the hub stays down). */
export async function readEnrolMarker(ledgerDir: string): Promise<EnrolMarker | null> {
  const text = await readCapped(enrolPath(ledgerDir), MAX_ENROL_BYTES);
  return text === null ? null : parseEnrol(text);
}

/** Dead owner, or older than `ENROL_STALE_MS` (distance, not sign: clocks jump). */
function takeoverAllowed(m: EnrolMarker, o: EnrolOptions): boolean {
  const now = (o.now ?? Date.now)();
  if (Math.abs(now - Date.parse(m.startedAt)) > ENROL_STALE_MS) return true;
  return !(o.pidAlive ?? pidAlive)(m.pid);
}

/** `link(tmp, path)` = atomic create-if-absent with complete content (never a torn marker). */
async function createExclusive(path: string, text: string): Promise<void> {
  const tmp = `${path}.${String(process.pid)}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    const h = await openPrivate(tmp, 'excl', 0o600);
    try {
      await h.writeFile(text);
      await h.sync();
    } finally {
      await h.close();
    }
    try {
      await link(tmp, path);
    } catch (err) {
      if (isErrno(err, 'EEXIST')) throw new StateError('BUSY', 'an enrolment marker already exists');
      throw new StateError('IO', 'cannot create the enrolment marker');
    }
  } catch (err) {
    if (err instanceof StateError) throw err;
    if (err instanceof TrustError) throw new StateError('UNSAFE', 'sync directory failed the ownership check');
    throw new StateError('IO', 'cannot write the enrolment marker');
  } finally {
    await rm(tmp, { force: true }).catch(() => undefined);
  }
  try {
    await fsyncDir(nodePath.dirname(path));
  } catch {
    throw new StateError('IO', 'cannot sync the sync directory');
  }
}

/** Move a stale marker out of the way. `rename` is atomic, so of two simultaneous takers one gets
 *  ENOENT. What was moved must be the exact marker we judged stale; otherwise (someone created a
 *  fresh one in between) put it back and report BUSY. */
async function removeStale(path: string, judged: EnrolMarker): Promise<void> {
  const aside = `${path}.stale.${String(process.pid)}.${randomBytes(6).toString('hex')}`;
  try {
    await rename(path, aside);
  } catch (err) {
    if (isErrno(err, 'ENOENT')) return;
    throw new StateError('IO', 'cannot take over the enrolment marker');
  }
  try {
    const moved = parseEnrol((await readCapped(aside, MAX_ENROL_BYTES)) ?? '');
    if (moved.pid !== judged.pid || moved.startedAt !== judged.startedAt || moved.kind !== judged.kind) {
      await link(aside, path).catch(() => undefined);
      throw new StateError('BUSY', 'an enrolment marker is held by another process');
    }
  } catch (err) {
    if (err instanceof StateError && err.code === 'BUSY') throw err;
    // the moved file was unreadable now: it is not what we judged, put it back untouched
    await link(aside, path).catch(() => undefined);
    throw new StateError('BUSY', 'an enrolment marker is held by another process');
  } finally {
    await rm(aside, { force: true }).catch(() => undefined);
  }
}

/** Create or advance the marker. No marker: created atomically and exclusively. Same pid and kind
 *  (stage advance): replaced atomically. Marker of a dead pid, or older than 24 h: taken over. Anything
 *  else (live foreign owner, other kind of the same live pid) THROWS `StateError('BUSY')`; a corrupt
 *  marker throws `CORRUPT` (clear it with `clearEnrolMarker(dir, { force: true })`). The input is
 *  validated first (strict, 4 KB): nothing invalid ever reaches the disk. */
export async function writeEnrolMarker(ledgerDir: string, marker: EnrolMarker, opts: EnrolOptions = {}): Promise<void> {
  const res = enrolSchema.safeParse(marker);
  if (!res.success) throw new StateError('INVALID', 'refusing to write an invalid enrolment marker');
  const text = JSON.stringify(res.data);
  if (Buffer.byteLength(text, 'utf8') > MAX_ENROL_BYTES) throw new StateError('INVALID', 'refusing to write an oversize enrolment marker');
  await ensureLedgerHub(ledgerDir, true);
  const path = enrolPath(ledgerDir);
  const existing = await readEnrolMarker(ledgerDir);
  if (existing === null) return createExclusive(path, text);
  if (existing.pid === res.data.pid && existing.kind === res.data.kind) return writeDurable(path, text);
  if (!takeoverAllowed(existing, opts)) throw new StateError('BUSY', 'an enrolment is already in progress');
  await removeStale(path, existing);
  return createExclusive(path, text);
}

/** Remove the marker. No marker = no-op. Allowed for the owner (same pid) and for a takeover-eligible
 *  marker; a live foreign marker THROWS `BUSY`. `force: true` (the human `--abort`) removes whatever is
 *  there, a corrupt marker included: it only ever unlinks the marker path itself. */
export async function clearEnrolMarker(ledgerDir: string, opts: EnrolOptions & { force?: boolean } = {}): Promise<void> {
  const path = enrolPath(ledgerDir);
  if ((await lstat(path).catch(() => null)) === null) return;
  if (opts.force !== true) {
    const existing = await readEnrolMarker(ledgerDir);
    if (existing === null) return;
    if (existing.pid !== process.pid && !takeoverAllowed(existing, opts)) {
      throw new StateError('BUSY', 'an enrolment is in progress in another process');
    }
  }
  try {
    await rm(path, { force: true });
    await fsyncDir(nodePath.dirname(path));
  } catch {
    throw new StateError('IO', 'cannot remove the enrolment marker');
  }
}
