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
import { isSingleLine } from './sanitize.ts';
import { slotSchema } from './schema.ts';
import { DEVICE_ID_RE, SIGN_NAMESPACE, parseEd25519Pub } from './sshkey.ts';

export const DEVICES_MAX_ENTRIES = 64;
export const DEVICES_MAX_BYTES = 64 * 1024;
export const REVOKE_REASON_MAX = 200;

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const isoSchema = z.string().regex(ISO_RE, 'ISO-8601 UTC timestamp').refine((s) => !Number.isNaN(Date.parse(s)), 'invalid date');
const deviceIdSchema = z.string().regex(DEVICE_ID_RE, 'device id: d_ + 10 base32 chars');
export const labelSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'label: lowercase letters, digits, -');
const pubkeySchema = z.string().refine((s) => parseEd25519Pub(s) !== null, 'pubkey: canonical `ssh-ed25519 <base64>` only');

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

/** Cross-entry invariants the per-field schema cannot express. Returns a problem or `null`. */
export function devicesInvariantProblem(file: DevicesFile): string | null {
  const ids = new Set<string>();
  const slots = new Set<string>();
  const keys = new Set<string>();
  const byId = new Map(file.devices.map((d) => [d.id, d]));
  for (const d of file.devices) {
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
    throw new DevicesError('DEVICES_INVALID', `devices.yml: ${res.error.issues[0]?.message ?? 'invalid'}`);
  }
  const problem = devicesInvariantProblem(res.data);
  if (problem !== null) throw new DevicesError('DEVICES_INVALID', `devices.yml: ${problem}`);
  return res.data;
}

export function renderDevicesYaml(file: DevicesFile): string {
  const checked = devicesFileSchema.parse(file);
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
const SIGNER_NAMESPACES = `${SIGN_NAMESPACE},git`;
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

/* ---------------- acceptDevicesChange (T16) ---------------- */

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
  | 'id-not-derived';

export type AcceptResult =
  | { ok: true; kind: 'root' | 'update' | 'noop' }
  | { ok: false; reason: AcceptReason; detail: string };

export interface AcceptOpts {
  /** Only `ledger device init --root` on the machine that creates the ledger. A
   *  peer's `devices.yml` is NEVER accepted as a root. */
  allowRoot?: boolean;
}

const reject = (reason: AcceptReason, detail: string): AcceptResult => ({ ok: false, reason, detail });

/** Identity fields of an entry: they never change after registration. */
function sameIdentity(a: DeviceEntry, b: DeviceEntry): string | null {
  for (const k of ['id', 'label', 'slot', 'pubkey', 'added', 'added_by', 'role'] as const) {
    if (a[k] !== b[k]) return k;
  }
  return null;
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
 *    derived from its own pubkey (id ↔ key binding, no id squatting);
 *  - `base === null` is accepted only as an explicit local root (`allowRoot`).
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
  if (!inc.success || devicesInvariantProblem(inc.data) !== null) {
    return reject('invalid-incoming', inc.success ? (devicesInvariantProblem(inc.data) ?? 'invalid') : 'schema');
  }
  const next = inc.data;
  const signer = parseEd25519Pub(signerPubkey);
  if (signer === null) return reject('signer-invalid', 'signer key is not a canonical ssh-ed25519 line');

  if (base === null) {
    if (opts.allowRoot !== true) return reject('no-root', 'no local devices.yml: a peer file is never a trust root');
    const only = next.devices[0];
    if (
      next.devices.length !== 1 ||
      only === undefined ||
      only.slot !== '' ||
      only.added_by !== only.id ||
      only.revoked !== null ||
      only.pubkey !== signer.line
    ) {
      return reject('bad-root', 'root must be one self-signed, self-added, unrevoked primary entry');
    }
    return { ok: true, kind: 'root' };
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
    } else if (now.revoked !== null && now.revoked.by !== signerEntry.id) {
      return reject('revoke-invalid', `${was.id}: revoked.by must be the signer ${signerEntry.id}`);
    }
  }

  for (const d of next.devices) {
    if (baseById.has(d.id)) continue;
    if (d.revoked !== null) return reject('new-entry-revoked', `${d.id}: cannot be added already revoked`);
    if (d.added_by !== signerEntry.id) return reject('added-by-mismatch', `${d.id}: added_by must be the signer ${signerEntry.id}`);
    if (parseEd25519Pub(d.pubkey)?.deviceId !== d.id) return reject('id-not-derived', `${d.id}: id is not derived from its pubkey`);
    // slot uniqueness / non-empty slot is enforced by devicesInvariantProblem above
  }

  return { ok: true, kind: JSON.stringify(old) === JSON.stringify(next) ? 'noop' : 'update' };
}
