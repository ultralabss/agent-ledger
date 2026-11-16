/** `devices.yml` (synced) and the local `.hub/allowed_signers` — schema, validation
 *  and the pure rule that decides whether a changed `devices.yml` may be accepted
 *  (docs/multi-device-spec.md §2.1, §6, §8 T1/T9/T16). No IO here.
 *
 *  Trust model: TOFU chain rooted at the first device. A change is accepted only
 *  when its commit is signed by a key that is ALREADY trusted locally AND still
 *  registered, non-revoked, in the base `devices.yml`. Nothing a peer writes
 *  inside the new file can make its own key trusted.
 */

import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { z } from 'zod';
import { isSingleLine, sanitizeField } from './sanitize.ts';
import { slotSchema } from './schema.ts';
import { DEVICE_ID_RE, GIT_NAMESPACE, SIGN_NAMESPACE, parseEd25519Pub } from './sshkey.ts';

export const DEVICES_MAX_ENTRIES = 64;
export const DEVICES_MAX_BYTES = 64 * 1024;
export const REVOKE_REASON_MAX = 200;

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const isoSchema = z.string().regex(ISO_RE, 'ISO-8601 UTC timestamp').refine((s) => !Number.isNaN(Date.parse(s)), 'invalid date');
const deviceIdSchema = z.string().regex(DEVICE_ID_RE, 'device id: d_ + 10 base32 chars');
export const labelSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'label: lowercase letters, digits, -');
// DK-4: byte-exact canonical form. `parseEd25519Pub` tolerates a trailing newline / spaces, which
// would let two different strings name one key (duplicate check, identity compare, file diffs).
const pubkeySchema = z.string().refine((s) => parseEd25519Pub(s)?.line === s, 'pubkey: canonical `ssh-ed25519 <base64>` only');

/** `.hub/device.yml` (local, never synced). `key_fp` is set by `device init`. */
export const deviceFileSchema = z.object({
  device_id: deviceIdSchema,
  label: labelSchema,
  // `slot:` left empty in hand-written YAML parses to null — same as primary.
  slot: slotSchema.nullable().transform((v) => v ?? ''),
  key_fp: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/).optional(),
});
export type DeviceFile = z.infer<typeof deviceFileSchema>;

export const revokedSchema = z.strictObject({
  at: isoSchema,
  by: deviceIdSchema,
  reason: z.string().min(1).max(REVOKE_REASON_MAX).refine(isSingleLine, 'reason must be a single line'),
});

export const deviceEntrySchema = z.strictObject({
  id: deviceIdSchema,
  label: labelSchema,
  slot: slotSchema,
  pubkey: pubkeySchema,
  added: isoSchema,
  added_by: deviceIdSchema,
  revoked: revokedSchema.nullable(),
  role: z.literal('owner'),
  /** Optional liveness hint, written by trusted devices (F3). Not part of identity. */
  last_seen: isoSchema.optional(),
});
export type DeviceEntry = z.infer<typeof deviceEntrySchema>;

export const devicesFileSchema = z.strictObject({
  devices: z.array(deviceEntrySchema).max(DEVICES_MAX_ENTRIES),
});
export type DevicesFile = z.infer<typeof devicesFileSchema>;

export class DevicesError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'DevicesError';
    this.code = code;
  }
}

/** ANSI escape sequences (CSI / OSC), then everything `sanitizeField` drops, then bidi
 *  controls, zero-width and invisible format characters. Text that came from a file a peer
 *  can write (or from a tool's stderr) must pass through this before it reaches a terminal,
 *  a doctor line or a log (DK-2). Never throws, always one line. */
const ANSI_CSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g;
const INVISIBLE = /[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g;
export function safeOutput(text: string, max = 300): string {
  return sanitizeField(text.replace(ANSI_OSC, '').replace(ANSI_CSI, ''), max * 2).replace(INVISIBLE, '').slice(0, max);
}

/** Fixed, value-free description of the first schema issue: `field.path (kind)`. The field
 *  path comes from our own schema (identifiers and array indices), never from the input. */
function describeIssue(issue: z.core.$ZodIssue | undefined): string {
  if (issue === undefined) return 'invalid';
  const path = issue.path
    .map((seg) => (typeof seg === 'number' ? `[${Math.min(Math.max(seg, 0), 9999)}]` : /^[a-z_]{1,16}$/.test(String(seg)) ? `.${String(seg)}` : '.?'))
    .join('')
    .replace(/^\./, '');
  const kind =
    issue.code === 'invalid_type' ? 'type'
    : issue.code === 'invalid_format' ? 'format'
    : issue.code === 'too_big' || issue.code === 'too_small' ? 'range'
    : issue.code === 'unrecognized_keys' ? 'unknown-field'
    : issue.code === 'invalid_value' ? 'value'
    : 'invalid';
  return `${path === '' ? '(root)' : path} (${kind})`;
}

/** Cross-entry invariants the per-field schema cannot express. Returns a problem or `null`.
 *  Messages carry only schema-validated tokens (ids, slot letters), never free text. */
export function devicesInvariantProblem(file: DevicesFile): string | null {
  const ids = new Set<string>();
  const slots = new Set<string>();
  const keys = new Set<string>();
  const byId = new Map(file.devices.map((d) => [d.id, d]));
  for (const d of file.devices) {
    // DK-1/DK-7: an id is a function of the key (no id squatting, root included). The F1
    // random id is migrated by `rekeyLegacyDeviceId` BEFORE the root is registered.
    if (parseEd25519Pub(d.pubkey)?.deviceId !== d.id) return `${d.id}: id is not derived from its pubkey`;
    if (ids.has(d.id)) return `duplicate id ${d.id}`;
    if (slots.has(d.slot)) return `duplicate slot "${d.slot}"`;
    const canon = parseEd25519Pub(d.pubkey)?.line ?? d.pubkey;
    if (keys.has(canon)) return `duplicate pubkey (${d.id})`;
    ids.add(d.id);
    slots.add(d.slot);
    keys.add(canon);
    if (d.slot === '') {
      // Slot "" is the primary ledger: exactly the self-registered root.
      if (d.added_by !== d.id) return `slot "" is reserved for the self-registered primary (${d.id})`;
    } else if (d.added_by === d.id) {
      return `${d.id} registered itself with a slot — only the primary root may`;
    } else if (!byId.has(d.added_by)) {
      return `${d.id}: added_by ${d.added_by} is not in the file`;
    }
    if (d.revoked !== null && !byId.has(d.revoked.by)) return `${d.id}: revoked.by ${d.revoked.by} is not in the file`;
  }
  return null;
}

/** Parse + validate. Throws `DevicesError` (code `DEVICES_INVALID` / `DEVICES_TOO_LARGE`). */
export function parseDevicesYaml(text: string): DevicesFile {
  if (Buffer.byteLength(text, 'utf8') > DEVICES_MAX_BYTES) {
    throw new DevicesError('DEVICES_TOO_LARGE', `devices.yml exceeds ${DEVICES_MAX_BYTES} bytes`);
  }
  let raw: unknown;
  try {
    raw = parseYaml(text, { maxAliasCount: 0 });
  } catch {
    throw new DevicesError('DEVICES_INVALID', 'devices.yml is not valid YAML');
  }
  const res = devicesFileSchema.safeParse(raw ?? { devices: [] });
  if (!res.success) {
    throw new DevicesError('DEVICES_INVALID', `devices.yml: invalid field ${describeIssue(res.error.issues[0])}`);
  }
  const problem = devicesInvariantProblem(res.data);
  if (problem !== null) throw new DevicesError('DEVICES_INVALID', `devices.yml: ${problem}`);
  return res.data;
}

export function renderDevicesYaml(file: DevicesFile): string {
  const parsed = devicesFileSchema.safeParse(file);
  if (!parsed.success) {
    throw new DevicesError('DEVICES_INVALID', `devices.yml: invalid field ${describeIssue(parsed.error.issues[0])}`);
  }
  const checked = parsed.data;
  const problem = devicesInvariantProblem(checked);
  if (problem !== null) throw new DevicesError('DEVICES_INVALID', `devices.yml: ${problem}`);
  const text = stringifyYaml(checked, { lineWidth: 0 });
  if (Buffer.byteLength(text, 'utf8') > DEVICES_MAX_BYTES) {
    throw new DevicesError('DEVICES_TOO_LARGE', `devices.yml would exceed ${DEVICES_MAX_BYTES} bytes`);
  }
  return text;
}

/* ---------------- allowed_signers (local, `.hub/allowed_signers`) ---------------- */

export interface Signer {
  id: string;
  /** Canonical `ssh-ed25519 <base64>`. */
  pubkey: string;
}

/** The `git` namespace is there for F3 (commit signatures); payload signatures use `agent-ledger-v1`. */
const SIGNER_NAMESPACES = `${SIGN_NAMESPACE},${GIT_NAMESPACE}`;
const SIGNER_LINE_RE = new RegExp(`^(d_[a-z2-7]{10}) namespaces="${SIGNER_NAMESPACES}" (ssh-ed25519 [A-Za-z0-9+/]{68})$`);

export function renderAllowedSigners(signers: readonly Signer[]): string {
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const s of [...signers].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))) {
    const pub = parseEd25519Pub(s.pubkey);
    if (!DEVICE_ID_RE.test(s.id) || pub === null) throw new DevicesError('SIGNERS_INVALID', 'invalid signer entry');
    if (seen.has(s.id)) throw new DevicesError('SIGNERS_INVALID', `duplicate signer ${s.id}`);
    seen.add(s.id);
    lines.push(`${s.id} namespaces="${SIGNER_NAMESPACES}" ${pub.line}`);
  }
  return lines.length === 0 ? '' : `${lines.join('\n')}\n`;
}

/** Strict: a line that is not exactly what `renderAllowedSigners` writes is an error,
 *  never silently dropped or passed through (an options field such as `cert-authority`
 *  or a wider `namespaces` would widen trust). */
export function parseAllowedSigners(text: string): Signer[] {
  if (text.length > DEVICES_MAX_BYTES) throw new DevicesError('SIGNERS_INVALID', 'allowed_signers is too large');
  const out: Signer[] = [];
  const seen = new Set<string>();
  for (const line of text.split('\n')) {
    if (line === '') continue;
    const m = SIGNER_LINE_RE.exec(line);
    const pub = m?.[2] === undefined ? null : parseEd25519Pub(m[2]);
    if (m === null || m[1] === undefined || pub === null) {
      throw new DevicesError('SIGNERS_INVALID', 'allowed_signers has an unexpected line');
    }
    if (seen.has(m[1])) throw new DevicesError('SIGNERS_INVALID', `duplicate signer ${m[1]}`);
    seen.add(m[1]);
    out.push({ id: m[1], pubkey: pub.line });
  }
  return out;
}

/* ---------------- acceptDevicesChange (T16, D2) ---------------- */

export type AcceptReason =
  | 'invalid-base'
  | 'invalid-incoming'
  | 'signer-invalid'
  | 'signer-untrusted'
  | 'signer-unregistered'
  | 'signer-revoked'
  | 'no-root'
  | 'bad-root'
  | 'entry-removed'
  | 'entry-modified'
  | 'unrevoke'
  | 'revoke-invalid'
  | 'new-entry-revoked'
  | 'added-by-mismatch'
  /** `last_seen` changed on an entry that is not the signer's own (F-11). */
  | 'last-seen-foreign'
  /** `added` / `revoked.at` of a new entry / new revocation is not within ±15 min of the commit time. */
  | 'time-unbound';

/** What an accepted change revokes. `root` = the primary (slot "") is among the newly revoked.
 *  Revoking the root or THIS device is never applied automatically (D2): the caller (F3b gate)
 *  quarantines and waits for a human, so the classification is part of every accepted result. */
export interface RevokeClass {
  root: boolean;
  /** Ids newly revoked by this change (sorted). */
  ids: string[];
}

export type AcceptResult =
  | { ok: true; kind: 'root' | 'update' | 'noop'; revokes: RevokeClass }
  | { ok: false; reason: AcceptReason; detail: string };

/** `added` / `revoked.at` must lie within this distance of the introducing commit's time. */
export const DEVICES_TIME_BOUND_MS = 15 * 60 * 1000;

export interface AcceptOpts {
  /** Only `ledger device init --root` on the machine that creates the ledger. A
   *  peer's `devices.yml` is NEVER accepted as a root. */
  allowRoot?: boolean;
  /** Committer time (epoch ms) of the commit that carries `incoming`. REQUIRED for every
   *  change on top of a `base` (fail closed: missing / non-finite → `time-unbound`). Clocks
   *  jump, so the distance is `Math.abs`. Trust never compares against the local clock. */
  commitTimeMs?: number;
}

const reject = (reason: AcceptReason, detail: string): AcceptResult => ({ ok: false, reason, detail });
const NO_REVOKES: RevokeClass = { root: false, ids: [] };

/** Identity fields of an entry: they never change after registration. */
function sameIdentity(a: DeviceEntry, b: DeviceEntry): string | null {
  for (const k of ['id', 'label', 'slot', 'pubkey', 'added', 'added_by', 'role'] as const) {
    if (a[k] !== b[k]) return k;
  }
  return null;
}

function timeBound(iso: string, commitTimeMs: number): boolean {
  const t = Date.parse(iso);
  return Number.isFinite(t) && Math.abs(t - commitTimeMs) <= DEVICES_TIME_BOUND_MS;
}

/**
 * May `incoming` replace `base`, given the commit that carries it was signed by
 * `signerPubkey`? `trusted` = canonical `ssh-ed25519 …` lines of the keys this
 * device has approved (`.hub/allowed_signers`).
 *
 *  - signer must be trusted locally, registered in `base`, not revoked there;
 *  - entries are never removed; identity fields never change (a cudzí pubkey
 *    cannot be swapped); `revoked` goes null → object only, by the signer, never back;
 *  - a new entry is added by the signer (`added_by`), is not pre-revoked, has a
 *    fresh slot (uniqueness in the file also retires revoked slots forever) and an id
 *    derived from its own pubkey (id ↔ key binding, enforced by the file invariants);
 *  - `added` of a new entry and `revoked.at` of a new revocation are bound to the commit
 *    time (±15 min) — they are evidence, never compared to a clock (D2, S21);
 *  - `last_seen` may change only on the signer's own entry (F-11);
 *  - `base === null` is accepted only as an explicit local root (`allowRoot`).
 * On success `revokes` classifies what the change revokes so the caller can hold
 * root / self revocations for human confirmation (D2).
 * Pure; the caller supplies already-parsed data (it is re-validated here).
 */
export function acceptDevicesChange(
  base: DevicesFile | null,
  incoming: DevicesFile,
  signerPubkey: string,
  trusted: ReadonlySet<string>,
  opts: AcceptOpts = {},
): AcceptResult {
  const inc = devicesFileSchema.safeParse(incoming);
  const incProblem = inc.success ? devicesInvariantProblem(inc.data) : 'schema';
  if (!inc.success || incProblem !== null) return reject('invalid-incoming', incProblem ?? 'invalid');
  const next = inc.data;
  const signer = parseEd25519Pub(signerPubkey);
  if (signer === null) return reject('signer-invalid', 'signer key is not a canonical ssh-ed25519 line');
  const commitTimeMs = opts.commitTimeMs;
  const haveTime = typeof commitTimeMs === 'number' && Number.isFinite(commitTimeMs);

  if (base === null) {
    if (opts.allowRoot !== true) return reject('no-root', 'no local devices.yml: a peer file is never a trust root');
    const only = next.devices[0];
    if (
      next.devices.length !== 1 ||
      only === undefined ||
      only.slot !== '' ||
      only.added_by !== only.id ||
      only.revoked !== null ||
      only.last_seen !== undefined ||
      only.pubkey !== signer.line
    ) {
      return reject('bad-root', 'root must be one self-signed, self-added, unrevoked primary entry');
    }
    // A local root has no introducing commit; when the caller does have one it is bound too.
    if (haveTime && !timeBound(only.added, commitTimeMs)) return reject('time-unbound', `${only.id}: added is not within 15 min of the commit time`);
    return { ok: true, kind: 'root', revokes: NO_REVOKES };
  }

  const b = devicesFileSchema.safeParse(base);
  if (!b.success || devicesInvariantProblem(b.data) !== null) return reject('invalid-base', 'local devices.yml is invalid');
  const old = b.data;

  if (![...trusted].some((t) => parseEd25519Pub(t)?.line === signer.line)) {
    return reject('signer-untrusted', 'commit signer key is not approved on this device');
  }
  const signerEntry = old.devices.find((d) => parseEd25519Pub(d.pubkey)?.line === signer.line);
  if (signerEntry === undefined) return reject('signer-unregistered', 'signer key is not in the current devices.yml');
  if (signerEntry.revoked !== null) return reject('signer-revoked', `signer ${signerEntry.id} is revoked`);

  const incById = new Map(next.devices.map((d) => [d.id, d]));
  const baseById = new Map(old.devices.map((d) => [d.id, d]));
  const revokedIds: string[] = [];
  let revokesRoot = false;

  for (const was of old.devices) {
    const now = incById.get(was.id);
    if (now === undefined) return reject('entry-removed', `${was.id} was removed (entries are never deleted)`);
    const changed = sameIdentity(was, now);
    if (changed !== null) return reject('entry-modified', `${was.id}: ${changed} changed`);
    if (was.revoked !== null) {
      if (now.revoked === null) return reject('unrevoke', `${was.id}: revocation is permanent`);
      if (JSON.stringify(now.revoked) !== JSON.stringify(was.revoked)) {
        return reject('entry-modified', `${was.id}: revocation record changed`);
      }
    } else if (now.revoked !== null) {
      if (now.revoked.by !== signerEntry.id) return reject('revoke-invalid', `${was.id}: revoked.by must be the signer ${signerEntry.id}`);
      if (!haveTime || !timeBound(now.revoked.at, commitTimeMs)) {
        return reject('time-unbound', `${was.id}: revoked.at is not within 15 min of the commit time`);
      }
      revokedIds.push(was.id);
      if (was.slot === '') revokesRoot = true;
    }
    if (now.last_seen !== was.last_seen && was.id !== signerEntry.id) {
      return reject('last-seen-foreign', `${was.id}: last_seen may only be changed by the device itself`);
    }
  }

  for (const d of next.devices) {
    if (baseById.has(d.id)) continue;
    if (d.revoked !== null) return reject('new-entry-revoked', `${d.id}: cannot be added already revoked`);
    if (d.added_by !== signerEntry.id) return reject('added-by-mismatch', `${d.id}: added_by must be the signer ${signerEntry.id}`);
    if (d.last_seen !== undefined) return reject('last-seen-foreign', `${d.id}: a new entry cannot carry last_seen`);
    if (!haveTime || !timeBound(d.added, commitTimeMs)) return reject('time-unbound', `${d.id}: added is not within 15 min of the commit time`);
    // id ↔ key derivation, slot uniqueness / non-empty slot: enforced by devicesInvariantProblem above
  }

  return {
    ok: true,
    kind: JSON.stringify(old) === JSON.stringify(next) ? 'noop' : 'update',
    revokes: { root: revokesRoot, ids: revokedIds.sort() },
  };
}
