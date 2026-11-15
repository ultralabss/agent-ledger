/**
 * Offline write spool.
 *
 * The hub is a local process that gets restarted, crashed into and developed on.
 * Without a spool, every `ledger add` during a hub restart is a lost write and
 * the agent has to be told to retry — which it never is. A write that cannot
 * reach the hub goes to the spool directory (default
 * `$XDG_STATE_HOME/agent-ledger/spool`, else `~/.local/state/agent-ledger/spool`;
 * override with `LEDGER_SPOOL_DIR`) and the next successful command
 * (or `ledger wait`, or the hub itself on startup) replays it.
 *
 * Design constraints, in the order they mattered:
 *
 *  - **Only "hub is not running" spools.** ECONNREFUSED, a connect timeout, a
 *    502/503 from something that is not the hub. A 4xx is the hub *answering* —
 *    queueing that would turn a validation error into an infinite retry.
 *  - **Never the token.** The spool holds method, path and body. The token is
 *    read from the ledger at replay time, so a spool file that leaks is a leak of
 *    the user's own item text and nothing more.
 *  - **Secret scan before the write, not at replay.** Same scanner as the hub
 *    (`@agent-ledger/shared`). A rejected record is never written at all — otherwise
 *    the secret would sit in plaintext on disk until replay finally 422'd.
 *  - **Append-only JSONL, one file per session.** Append is atomic enough for
 *    single lines under `O_APPEND`, and per-session files mean two sessions
 *    queueing at once never interleave a half-written record.
 *  - **Idempotency key per record.** Replay is at-least-once (the process can die
 *    between "hub accepted" and "record removed"), so the hub dedupes on the key
 *    and returns the first response.
 *  - **0700 dir / 0600 files, with the same path-chain check as `install.sh`.**
 *    The spool contains ledger content and is replayed as authenticated writes;
 *    a world-writable parent would let another local user inject items.
 */

import {
  open as openFile,
  readFile,
  readdir,
  stat,
} from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { dirname, join } from 'node:path';
import { renameRetry, rmRetry } from './fsretry.ts';
import { spoolDir } from './paths.ts';
import {
  assertPrivateDir,
  ensurePrivateDir,
  isRootOwnedTrustedParent,
  openPrivate,
  TrustError,
  type TrustHandle,
} from './platformTrust.ts';
import { scanSecrets } from './secrets.ts';

/**
 * Spool failures carry the CLI exit code they should produce (4 validation,
 * 5 secret scanner). It lives here rather than in the CLI because the hub's own
 * startup sweep uses the same module and must not depend on the CLI package.
 */
export class SpoolError extends Error {
  readonly exitCode: number;

  constructor(exitCode: number, message: string) {
    super(message);
    this.name = 'SpoolError';
    this.exitCode = exitCode;
  }
}

/** Minimal client shape `replaySpool` needs. The CLI's `HubClient` satisfies it;
 *  so does the hub's in-process adapter. */
export interface KeyedRequester {
  requestKeyed(
    method: string,
    path: string,
    payload: unknown,
    key: string,
  ): Promise<{ status: number }>;
}

/** What `enqueue` needs to know about the caller. */
export interface SpoolContext {
  session: string | null;
}

export { spoolDir };

export interface SpoolRecord {
  /** 128-bit random, hex. Doubles as the `Idempotency-Key` header. */
  key: string;
  /** ms epoch. */
  ts: number;
  session: string | null;
  method: string;
  path: string;
  body: unknown;
  /** The command line that produced it, for the `QUEUED`/`failed` message. */
  cmd: string;
  /**
   * `HMAC-SHA256(token, canonical(method,path,body,key,ts,session))`.
   * The token itself is never written — only this proof that whoever wrote
   * the record held it. Verified at replay against the CURRENT token, so a
   * spool file edited by another local process, or replayed after the hub
   * token rotated, fails closed instead of being replayed as an
   * authenticated write.
   */
  hmac: string;
}

export interface SpoolStats {
  queued: number;
  failed: number;
}

export interface ReplayResult {
  sent: number;
  failed: number;
  /** True when the hub was unreachable and nothing was replayed. */
  offline: boolean;
}

/** Enough to notice a runaway loop before it fills the disk. */
const MAX_SPOOL_RECORDS = 5000;
/** A single record: generous for a `--why`, far below any line-length worry. */
const MAX_RECORD_BYTES = 64 * 1024;
/** A queued write this old is more likely a forgotten spool from a
 *  stale checkout than a legitimate delayed retry — refused rather than
 *  replayed blind. */
const MAX_RECORD_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * The exact set of writes the CLI ever queues. Replay executes an
 * arbitrary stored method+path; without this, a corrupted or tampered spool
 * record could replay as `POST /v1/intrude` or `POST /v1/override` with full
 * hub authority. Deliberately a positive list, not a denylist: a new endpoint
 * is unspoolable by default until someone adds it here on purpose.
 */
const ITEM_ACTION_RE =
  /^\/v1\/items\/[^/]+\/(comments|steps|done|drop|dup|block|reopen|release|claim)$/;
const ITEM_PATCH_RE = /^\/v1\/items\/[^/]+$/;
const INTAKE_TRIAGE_RE = /^\/v1\/intake\/[^/]+\/triage$/;

export function isSpoolableRequest(method: string, path: string, body: unknown): boolean {
  const pathname = path.split('?')[0] ?? path;
  if (method === 'POST' && pathname === '/v1/items') return true;
  if (method === 'POST' && ITEM_ACTION_RE.test(pathname)) return true;
  if (method === 'PATCH' && ITEM_PATCH_RE.test(pathname)) return true;
  if (method === 'POST' && pathname === '/v1/decisions') return true;
  if (method === 'POST' && pathname === '/v1/journal') return true;
  if (method === 'POST' && INTAKE_TRIAGE_RE.test(pathname)) return true;
  if (method === 'POST' && pathname === '/v1/intake') {
    const action = (body as { action?: unknown } | null | undefined)?.action;
    return action === undefined || action === null || action === 'triage';
  }
  return false;
}

/** Stable JSON so `body` key order never changes the signature. */
function canonicalize(
  method: string,
  path: string,
  body: unknown,
  key: string,
  ts: number,
  session: string | null,
): string {
  return JSON.stringify({ method, path, body: body ?? null, key, ts, session }, sortedReplacer);
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = (value as Record<string, unknown>)[k];
    }
    return out;
  }
  return value;
}

export function computeSpoolHmac(
  token: string,
  fields: { method: string; path: string; body: unknown; key: string; ts: number; session: string | null },
): string {
  return createHmac('sha256', token)
    .update(canonicalize(fields.method, fields.path, fields.body, fields.key, fields.ts, fields.session))
    .digest('hex');
}

function hmacMatches(expected: string, actual: string): boolean {
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(actual, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Map a platformTrust refusal to the CLI exit code spool failures carry (4). Anything
 * that is not a TrustError (ENOSPC, EACCES, ...) is rethrown untouched.
 */
function toSpoolError(err: unknown): unknown {
  if (err instanceof TrustError) return new SpoolError(4, `spool: ${err.message}`);
  return err;
}

/**
 * Create the spool directory chain, or verify it when it exists. The trust decision
 * (every component from `$HOME` down is a real directory owned by us and not writable
 * by group or other; a symlinked or group-writable component is refused rather than
 * fixed; win32: owner + protected DACL) lives in platformTrust, shared with the token
 * and the ledger. A refusal surfaces as `SpoolError(4)`.
 */
export async function ensureSpoolDir(dir: string): Promise<string> {
  try {
    await ensurePrivateDir(dir);
  } catch (err) {
    throw toSpoolError(err);
  }
  return dir;
}

/** A root-owned parent we may sit under (`/tmp`: root, sticky). Kept as a re-export:
 *  the rule itself moved into the platformTrust POSIX backend, unchanged. */
export const isTrustedRootParent = isRootOwnedTrustedParent;

function sessionFile(dir: string, session: string | null): string {
  // The session id is an agent-supplied uuid; the pid fallback keeps two concurrent
  // hookless CLI calls in separate files. Both are constrained to a safe charset
  // because this becomes a filename.
  const raw = session ?? `pid-${process.pid}`;
  const safe = raw.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
  return join(dir, `${safe}.jsonl`);
}

/** Any method that changes state. GETs are never spooled — they are re-read. */
export function isWriteMethod(method: string): boolean {
  return method !== 'GET' && method !== 'HEAD';
}

/**
 * 128-bit random, hex — the same shape `enqueue` used to generate
 * internally. Callers now generate this BEFORE the first send of a write, so
 * the direct attempt and a later spool/replay of it carry the identical key —
 * the hub's Idempotency-Key guard then dedupes a slow-but-successful write
 * instead of writing it twice.
 */
export function generateIdempotencyKey(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Queue one write.
 *
 * Throws `SpoolError(5)` when the body carries a secret: the record is not written,
 * which is the whole point of scanning here rather than at replay.
 */
export async function enqueue(
  cfg: SpoolContext,
  input: { method: string; path: string; body: unknown; cmd: string },
  env: NodeJS.ProcessEnv = process.env,
  /** The hub token, used only to sign the record — never stored. */
  token?: string | null,
  /**
   * The key already sent on the direct attempt that failed, so the
   * replay reuses it instead of minting a fresh one. Optional only for
   * backward compat with call sites that have not generated one yet — falls
   * back to a fresh key as before.
   */
  key?: string,
): Promise<SpoolRecord> {
  const dir = await ensureSpoolDir(spoolDir(env));
  assertNoSecretsInBody(input.body);

  // Refuse to queue anything outside the fixed set of writes the
  // CLI actually spools — see `isSpoolableRequest`.
  if (!isSpoolableRequest(input.method, input.path, input.body)) {
    throw new SpoolError(
      4,
      `spool: ${input.method} ${input.path} cannot be queued — wait for the hub or retry once it is up`,
    );
  }
  if (!token) {
    throw new SpoolError(4, 'spool: missing token to sign the record — is the hub running?');
  }

  const effectiveKey = key ?? generateIdempotencyKey();
  const ts = Date.now();
  const record: SpoolRecord = {
    key: effectiveKey,
    ts,
    session: cfg.session,
    method: input.method,
    path: input.path,
    body: input.body,
    cmd: input.cmd,
    hmac: computeSpoolHmac(token, {
      method: input.method,
      path: input.path,
      body: input.body,
      key: effectiveKey,
      ts,
      session: cfg.session,
    }),
  };
  const line = `${JSON.stringify(record)}\n`;
  if (Buffer.byteLength(line, 'utf8') > MAX_RECORD_BYTES) {
    throw new SpoolError(4, 'spool: request is too large to queue (> 64 KB)');
  }
  const stats = await spoolStats(env);
  if (stats.queued >= MAX_SPOOL_RECORDS) {
    throw new SpoolError(
      4,
      `spool: ${stats.queued} records queued (cap ${MAX_SPOOL_RECORDS}) — run \`ledger wait\` or check the hub`,
    );
  }
  const file = sessionFile(dir, cfg.session);
  await safeAppend(file, line);
  return record;
}

/**
 * Append through platformTrust.openPrivate: the file is opened without following links
 * and identity / ownership are verified on the open descriptor (not the path, which is a
 * second, racy syscall). `appendFile` would follow a symlink at `file` and write
 * wherever another local user pointed it.
 */
async function safeAppend(file: string, data: string): Promise<void> {
  let handle: TrustHandle;
  try {
    handle = await openPrivate(file, 'append', 0o600);
  } catch (err) {
    throw toSpoolError(err);
  }
  try {
    await handle.writeFile(data);
  } finally {
    await handle.close();
  }
}

/**
 * Atomic private rewrite: the data goes to a random-named, exclusively created 0600
 * sibling (never a predictable `${file}.tmp` an attacker could pre-plant as a symlink or
 * hard link), is synced, then renamed over `file`. The containing directory is verified
 * private first. A failure removes the temp file.
 */
async function writePrivateAtomic(file: string, text: string): Promise<void> {
  try {
    await assertPrivateDir(dirname(file));
  } catch (err) {
    throw toSpoolError(err);
  }
  const tmp = `${file}.${randomBytes(8).toString('hex')}.tmp`;
  let handle: TrustHandle;
  try {
    handle = await openPrivate(tmp, 'excl', 0o600);
  } catch (err) {
    throw toSpoolError(err);
  }
  try {
    await handle.writeFile(text);
    await handle.sync();
  } catch (err) {
    await handle.close().catch(() => undefined);
    await rmRetry(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
  await handle.close();
  try {
    await renameRetry(tmp, file);
  } catch (err) {
    await rmRetry(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
}

/**
 * Scan every string in the body, recursively — same rule as the hub's
 * `assertNoSecretsDeep`. Values are never echoed back, only rule names.
 */
function assertNoSecretsInBody(body: unknown): void {
  const strings: string[] = [];
  collectStrings(body, strings);
  const rules: string[] = [];
  for (const value of strings) {
    for (const finding of scanSecrets(value)) {
      if (!rules.includes(finding.rule)) rules.push(finding.rule);
    }
  }
  if (rules.length > 0) {
    throw new SpoolError(
      5,
      `secret scanner: text not stored, not even queued (rules: ${rules.join(', ')})`,
    );
  }
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) collectStrings(v, out);
  }
}

/* ---------------- reading the spool ---------------- */

async function listSpoolFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir).catch(() => [] as string[]);
  return entries
    .filter((e) => e.endsWith('.jsonl'))
    .sort()
    .map((e) => join(dir, e));
}

/** A spool file a local attacker (or a runaway loop) grew past this is
 *  never read into memory at all — it goes straight to `failed/`. */
const MAX_SPOOL_FILE_BYTES = 8 * 1024 * 1024;
/** A single line over this is dropped rather than parsed: `MAX_RECORD_BYTES`
 *  already caps what `enqueue` itself ever writes, so a line this long can
 *  only be hostile or corrupt. */
const MAX_SPOOL_LINE_BYTES = 128 * 1024;

/**
 * Stream a spool file line by line rather than `readFile`-ing it whole: the
 * file is untrusted (another local process, or a crash, can grow it), so
 * neither the full byte buffer nor a single oversized line should ever sit in
 * memory. Returns `'oversized'` without reading a byte of content when the
 * file itself is past {@link MAX_SPOOL_FILE_BYTES}.
 */
async function forEachSpoolLine(
  file: string,
  onLine: (line: string) => void,
): Promise<'ok' | 'oversized'> {
  const st = await stat(file).catch(() => null);
  if (st === null) return 'ok';
  if (st.size > MAX_SPOOL_FILE_BYTES) return 'oversized';
  const rl = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (line.trim() === '') continue;
    if (Buffer.byteLength(line, 'utf8') > MAX_SPOOL_LINE_BYTES) continue;
    onLine(line);
  }
  return 'ok';
}

async function quarantineOversizedFile(dir: string, file: string): Promise<void> {
  const failedDir = join(dir, 'failed');
  // Fail-closed: if `failed/` cannot be verified private the file stays where it is.
  try {
    await ensurePrivateDir(failedDir);
  } catch {
    return;
  }
  const base = file.split(/[/\\]/).pop() ?? 'spool.jsonl';
  await renameRetry(file, join(failedDir, `oversized-${Date.now()}-${base}`)).catch(() => undefined);
}

/** Records in replay order: by timestamp, so cross-session order is causal. */
export async function readSpool(env: NodeJS.ProcessEnv = process.env): Promise<
  { file: string; record: SpoolRecord }[]
> {
  const dir = spoolDir(env);
  const out: { file: string; record: SpoolRecord }[] = [];
  for (const file of await listSpoolFiles(dir)) {
    const status = await forEachSpoolLine(file, (line) => {
      let record: unknown;
      try {
        record = JSON.parse(line);
      } catch {
        // A torn last line (process killed mid-append) is skipped, not fatal.
        return;
      }
      if (isSpoolRecord(record)) out.push({ file, record });
    });
    if (status === 'oversized') await quarantineOversizedFile(dir, file);
  }
  out.sort((a, b) => a.record.ts - b.record.ts || a.record.key.localeCompare(b.record.key));
  return out;
}

function isSpoolRecord(v: unknown): v is SpoolRecord {
  if (v === null || typeof v !== 'object') return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r['key'] === 'string' &&
    typeof r['ts'] === 'number' &&
    typeof r['method'] === 'string' &&
    typeof r['path'] === 'string' &&
    r['path'].startsWith('/v1/')
  );
}

export async function spoolStats(env: NodeJS.ProcessEnv = process.env): Promise<SpoolStats> {
  const queued = (await readSpool(env)).length;
  const failedDir = join(spoolDir(env), 'failed');
  const failed = (await readdir(failedDir).catch(() => [] as string[])).filter((f) =>
    f.endsWith('.jsonl'),
  ).length;
  return { queued, failed };
}

/**
 * A healthz-polled stats read must not pay for a full `readFile` +
 * `JSON.parse` of every spool record on every 1 s tick — that is exactly the
 * "read the contents" cost this finding is about. This counts non-empty
 * lines by streaming bytes (no buffering, no `JSON.parse`, so a record's
 * payload is never materialised) and skips a file past
 * {@link MAX_SPOOL_FILE_BYTES} outright — its count is folded into the next
 * real `readSpool`/replay pass, which quarantines it.
 */
export async function lightSpoolStats(env: NodeJS.ProcessEnv = process.env): Promise<SpoolStats> {
  const dir = spoolDir(env);
  let queued = 0;
  for (const file of await listSpoolFiles(dir)) {
    const st = await stat(file).catch(() => null);
    if (st === null || st.size === 0 || st.size > MAX_SPOOL_FILE_BYTES) continue;
    await forEachSpoolLine(file, () => {
      queued += 1;
    });
  }
  const failedDir = join(dir, 'failed');
  const failed = (await readdir(failedDir).catch(() => [] as string[])).filter((f) =>
    f.endsWith('.jsonl'),
  ).length;
  return { queued, failed };
}

/* ---------------- replay ---------------- */

/**
 * Replay everything, in order, under an exclusive lock.
 *
 * The lock is a `wx` lockfile with a staleness window rather than a flock: it has
 * to work identically from a CLI process and from the hub's own startup sweep,
 * and both may be killed at any moment. A lock older than
 * {@link LOCK_STALE_MS} is assumed dead and taken — the worst case is a double
 * replay, which the idempotency key already makes safe.
 */
const LOCK_STALE_MS = 60_000;

export async function replaySpool(
  client: KeyedRequester,
  env: NodeJS.ProcessEnv = process.env,
  /** Reads the CURRENT token (ledger, or the hub's own for the
   *  in-process sweep) — never the token the record was signed with, which is
   *  exactly what makes a rotated token fail closed. */
  getToken?: () => Promise<string | null>,
): Promise<ReplayResult> {
  const dir = spoolDir(env);
  const pending = await readSpool(env);
  if (pending.length === 0) return { sent: 0, failed: 0, offline: false };

  const lock = join(dir, '.replay.lock');
  if (!(await takeLock(lock))) return { sent: 0, failed: 0, offline: false };

  const currentToken = getToken ? await getToken().catch(() => null) : null;

  let sent = 0;
  let failed = 0;
  const done = new Set<string>();
  const failedRecords: { record: SpoolRecord; reason: string }[] = [];
  try {
    for (const { record } of pending) {
      const integrity = checkRecordIntegrity(record, currentToken);
      if (integrity !== null) {
        failedRecords.push({ record, reason: integrity });
        done.add(record.key);
        failed += 1;
        continue;
      }
      let res: { status: number };
      try {
        res = await client.requestKeyed(record.method, record.path, record.body, record.key);
      } catch (err) {
        if (isHubDown(err)) {
          // Still down. Everything from here on stays queued, in order.
          return { sent, failed, offline: true };
        }
        const status = statusOf(err);
        // 409 DUPLICATE is the dedupe answering — that is a successful replay of
        // an item somebody already created, not a failure.
        if (status !== null && status >= 400 && status < 500 && !isBenignConflict(err)) {
          failedRecords.push({ record, reason: (err as Error).message.slice(0, 500) });
          done.add(record.key);
          failed += 1;
          continue;
        }
        if (isBenignConflict(err)) {
          done.add(record.key);
          sent += 1;
          continue;
        }
        // 5xx from a hub that IS up: leave it queued and stop, so a transient
        // internal error does not shred the whole spool.
        return { sent, failed, offline: false };
      }
      void res;
      done.add(record.key);
      sent += 1;
    }
    return { sent, failed, offline: false };
  } finally {
    if (failedRecords.length > 0) await moveToFailed(dir, failedRecords);
    // Rewrite the spool files with only what is still pending. Done last so a
    // crash mid-replay leaves records queued (at-least-once) rather than lost.
    if (done.size > 0) await pruneSpool(dir, done);
    await rmRetry(lock, { force: true }).catch(() => undefined);
  }
}

/**
 * The replay-side gate. Runs on EVERY record, for both the CLI's own
 * drain and the hub's in-process startup sweep (both call `replaySpool`), so
 * there is exactly one place this can be bypassed rather than two.
 * Returns a `failed/` reason, or `null` to proceed.
 */
function checkRecordIntegrity(record: SpoolRecord, token: string | null): string | null {
  if (Date.now() - record.ts > MAX_RECORD_AGE_MS) {
    return 'spool: record older than 7 days, discarded without replay';
  }
  if (!isSpoolableRequest(record.method, record.path, record.body)) {
    return `spool: ${record.method} ${record.path} is not on the replay allowlist`;
  }
  if (token === null) {
    return 'spool: no current token to verify the HMAC — skipping replay';
  }
  if (typeof record.hmac !== 'string' || record.hmac === '') {
    return 'spool: record without HMAC (predates this version) — skipping replay';
  }
  const expected = computeSpoolHmac(token, {
    method: record.method,
    path: record.path,
    body: record.body,
    key: record.key,
    ts: record.ts,
    session: record.session,
  });
  if (!hmacMatches(expected, record.hmac)) {
    return 'spool: HMAC mismatch (edited record or rotated token)';
  }
  return null;
}

/**
 * HTTP status of a failed replay.
 *
 * Read from the error object, never parsed out of the message: the hub's 422
 * message is the validation text ("priority: invalid input") and contains no
 * number at all, so a regex silently classified every 4xx as "unknown" and left
 * the record queued forever.
 */
function statusOf(err: unknown): number | null {
  const s = (err as { status?: unknown })?.status;
  return typeof s === 'number' ? s : null;
}

/** A replayed create that the hub now considers a duplicate has already had its
 *  effect (or a human decided against it) — either way, stop retrying it. */
function isBenignConflict(err: unknown): boolean {
  const e = err as { exitCode?: number; message?: string };
  return e?.exitCode === 2 || /DUPLICATE|ALREADY_DONE/i.test(e?.message ?? '');
}

/** Exit code 3 / `hubDown` means the transport found nobody answering. Duck-typed
 *  so it works for both the CLI's `CliError` and the hub's in-process adapter. */
function isHubDown(err: unknown): boolean {
  const e = err as { exitCode?: number; hubDown?: boolean };
  return e?.hubDown === true || e?.exitCode === 3;
}

/** Injectable seams so the lock logic is testable without a real filesystem. */
export interface TakeLockDeps {
  open?: (lock: string) => Promise<{ writeFile: (d: string) => Promise<void>; close: () => Promise<void> }>;
  stat?: (lock: string) => Promise<{ mtimeMs: number } | null>;
  readFile?: (lock: string) => Promise<string | null>;
  rm?: (lock: string) => Promise<void>;
  /** `process.kill(pid, 0)` shape: returns normally if the pid exists, throws an errno otherwise. */
  kill?: (pid: number) => void;
  now?: () => number;
}

const LOCK_MAX_ATTEMPTS = 3;

/** Dead only on ESRCH. EPERM (exists, not ours) and any unknown error count as alive: never steal on doubt. */
function pidIsDead(pid: number, kill: (pid: number) => void): boolean {
  try {
    kill(pid);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ESRCH';
  }
}

/**
 * Take the replay lock. At most {@link LOCK_MAX_ATTEMPTS} attempts, no recursion. An existing lock
 * is stolen only when it is stale (mtime older than {@link LOCK_STALE_MS}) AND its owner pid is
 * provably dead; a lock with a live pid is never stolen, however old. If removing the stale lock
 * fails (EPERM/EBUSY on Windows) we give up (`false`) rather than loop.
 */
export async function takeLock(lock: string, deps: TakeLockDeps = {}): Promise<boolean> {
  const open =
    deps.open ??
    (async (l: string) => {
      const h = await openFile(l, 'wx', 0o600);
      return { writeFile: (d: string) => h.writeFile(d, 'utf8'), close: () => h.close() };
    });
  const statLock = deps.stat ?? ((l: string) => stat(l).catch(() => null));
  const readLock = deps.readFile ?? ((l: string) => readFile(l, 'utf8').catch(() => null));
  const removeLock = deps.rm ?? ((l: string) => rmRetry(l, { force: true }));
  const kill = deps.kill ?? ((pid: number) => void process.kill(pid, 0));
  const now = deps.now ?? Date.now;

  for (let attempt = 0; attempt < LOCK_MAX_ATTEMPTS; attempt += 1) {
    try {
      const handle = await open(lock);
      try {
        await handle.writeFile(String(process.pid));
      } finally {
        await handle.close();
      }
      return true;
    } catch {
      const st = await statLock(lock);
      // Lock vanished between open and stat: just try again. Fresh lock: someone else holds it.
      if (st === null) continue;
      if (Math.abs(now() - st.mtimeMs) <= LOCK_STALE_MS) return false;
      const text = await readLock(lock);
      const pid = text === null ? Number.NaN : Number.parseInt(text.trim(), 10);
      // A stale lock without a readable pid (crash between create and write) has no live owner.
      if (Number.isInteger(pid) && pid > 0 && !pidIsDead(pid, kill)) return false;
      try {
        await removeLock(lock);
      } catch {
        return false;
      }
    }
  }
  return false;
}

async function pruneSpool(dir: string, done: Set<string>): Promise<void> {
  for (const file of await listSpoolFiles(dir)) {
    const text = await readFile(file, 'utf8').catch(() => null);
    if (text === null) continue;
    const keep: string[] = [];
    for (const line of text.split(/\r?\n/)) {
      if (line.trim() === '') continue;
      try {
        const rec = JSON.parse(line) as SpoolRecord;
        if (!done.has(rec.key)) keep.push(line);
      } catch {
        /* torn line: drop it, it can never be replayed */
      }
    }
    if (keep.length === 0) {
      await rmRetry(file, { force: true }).catch(() => undefined);
      continue;
    }
    // tmp + rename: a reader never sees a half-rewritten spool file.
    await writePrivateAtomic(file, `${keep.join('\n')}\n`);
  }
}

async function moveToFailed(
  dir: string,
  records: { record: SpoolRecord; reason: string }[],
): Promise<void> {
  const failedDir = join(dir, 'failed');
  try {
    await ensurePrivateDir(failedDir);
  } catch (err) {
    throw toSpoolError(err);
  }
  const file = join(failedDir, `${new Date().toISOString().slice(0, 10)}.jsonl`);
  const lines = records
    .map((r) => JSON.stringify({ ...r.record, failed_at: Date.now(), reason: r.reason }))
    .join('\n');
  await safeAppend(file, `${lines}\n`);
}

/* ---------------- Recovery after a token rotation ---------------- */

export interface FailedSpoolRecord extends SpoolRecord {
  failed_at: number;
  reason: string;
}

export interface FailedSpoolFile {
  /** Bare filename under `<spoolDir>/failed/` — the exact string `spool retry`
   *  expects as its argument. */
  file: string;
  records: FailedSpoolRecord[];
}

function isFailedSpoolRecord(v: unknown): v is FailedSpoolRecord {
  if (!isSpoolRecord(v)) return false;
  const r = v as unknown as Record<string, unknown>;
  return typeof r['failed_at'] === 'number' && typeof r['reason'] === 'string';
}

/** Every `failed/*.jsonl` file with its records — the data behind `ledger spool
 *  failed`. Oldest file first, matching `moveToFailed`'s one-file-per-day layout. */
export async function readFailedSpool(
  env: NodeJS.ProcessEnv = process.env,
): Promise<FailedSpoolFile[]> {
  const failedDir = join(spoolDir(env), 'failed');
  const names = (await readdir(failedDir).catch(() => [] as string[]))
    .filter((f) => f.endsWith('.jsonl'))
    .sort();
  const out: FailedSpoolFile[] = [];
  for (const name of names) {
    const records: FailedSpoolRecord[] = [];
    await forEachSpoolLine(join(failedDir, name), (line) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        return;
      }
      if (isFailedSpoolRecord(parsed)) records.push(parsed);
    });
    out.push({ file: name, records });
  }
  return out;
}

/** `spool retry`'s file argument is user input from a CLI flag — reject
 *  anything that is not exactly one of the names `readFailedSpool` itself
 *  would report, so it cannot walk outside `<spoolDir>/failed/`. */
function validateFailedFileName(name: string): string {
  if (name === '' || name.includes('/') || name.includes('\\') || name.includes('..') || !name.endsWith('.jsonl')) {
    throw new SpoolError(4, `spool: invalid file name "${name}" — use the exact name shown by \`ledger spool failed\``);
  }
  return name;
}

async function rewriteFailedFile(file: string, keep: FailedSpoolRecord[]): Promise<void> {
  if (keep.length === 0) {
    await rmRetry(file, { force: true }).catch(() => undefined);
    return;
  }
  await writePrivateAtomic(file, `${keep.map((r) => JSON.stringify(r)).join('\n')}\n`);
}

export interface RetryResult extends ReplayResult {
  /** Records moved from `failed/` back into the pending queue and handed to
   *  `replaySpool`. */
  requeued: number;
  /** Records left untouched in `failed/` because they no longer pass
   *  `isSpoolableRequest` — never silently resent. */
  skipped: number;
}

const ZERO_RETRY: RetryResult = { requeued: 0, skipped: 0, sent: 0, failed: 0, offline: false };

/**
 * Recovery after a token rotation. `ledger spool failed` shows what is
 * stuck; this re-signs the eligible records from ONE named `failed/*.jsonl`
 * file with the CURRENT token and hands them to the normal `replaySpool` path
 * (so hub-down / 4xx / 5xx during the retry itself are handled exactly like
 * any other replay, not by a second, parallel error-handling path here).
 *
 * Without `confirm: true` this is a hard no-op — it does not even read the
 * file — matching the "nothing without `--confirm`" rule at the CLI layer.
 */
export async function retryFailedSpool(
  client: KeyedRequester,
  fileName: string,
  confirm: boolean,
  env: NodeJS.ProcessEnv = process.env,
  getToken?: () => Promise<string | null>,
): Promise<RetryResult> {
  if (!confirm) return ZERO_RETRY;
  const dir = spoolDir(env);
  const safeName = validateFailedFileName(fileName);
  const file = join(dir, 'failed', safeName);

  const records: FailedSpoolRecord[] = [];
  await forEachSpoolLine(file, (line) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return;
    }
    if (isFailedSpoolRecord(parsed)) records.push(parsed);
  });
  if (records.length === 0) return ZERO_RETRY;

  const currentToken = getToken ? await getToken().catch(() => null) : null;
  if (currentToken === null) return { ...ZERO_RETRY, skipped: records.length };

  const eligible: SpoolRecord[] = [];
  const kept: FailedSpoolRecord[] = [];
  let skipped = 0;
  for (const r of records) {
    if (!isSpoolableRequest(r.method, r.path, r.body)) {
      kept.push(r);
      skipped += 1;
      continue;
    }
    const hmac = computeSpoolHmac(currentToken, {
      method: r.method,
      path: r.path,
      body: r.body,
      key: r.key,
      ts: r.ts,
      session: r.session,
    });
    eligible.push({ key: r.key, ts: r.ts, session: r.session, method: r.method, path: r.path, body: r.body, cmd: r.cmd, hmac });
  }
  // Retried records leave `failed/` regardless of outcome — they now live in
  // the pending queue (`replaySpool` below re-fails them back to `failed/` on
  // their own if the resend does not work out).
  await rewriteFailedFile(file, kept);
  if (eligible.length === 0) return { ...ZERO_RETRY, skipped };

  const requeueFile = join(dir, `retry-${Date.now()}-${randomBytes(4).toString('hex')}.jsonl`);
  await safeAppend(requeueFile, `${eligible.map((r) => JSON.stringify(r)).join('\n')}\n`);

  const result = await replaySpool(client, env, getToken);
  return { requeued: eligible.length, skipped, ...result };
}

/* ---------------- messages ---------------- */

/** The line the user sees instead of a result. */
export function queuedMessage(record: SpoolRecord): string {
  // The CLI appends `?format=line`, so compare the pathname, not the raw value.
  const isCreate =
    record.method === 'POST' && (record.path.split('?')[0] ?? '') === '/v1/items';
  const note = isCreate ? ' — it gets its ID only once sent, it has NO ID yet' : '';
  return (
    `QUEUED ${record.key.slice(0, 8)} ${record.cmd}${note} — hub is not running, it will be sent automatically.\n` +
    'To get a notice once the hub is back, run in the background: ledger wait'
  );
}

export const HUB_DOWN_HOOK_TEXT =
  'AGENT-LEDGER DOWN: ledger writes are queued and sent automatically. ' +
  'To get a notice once the hub is back, run in the background: ledger wait';
