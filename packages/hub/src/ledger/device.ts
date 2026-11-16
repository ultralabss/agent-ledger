/** Ledger format 2 building blocks: format marker, local device identity, per-device
 *  counter files, `.hub/local.yml`. Pure file IO + validation, no ledger state.
 *
 *  Safety stance (docs/multi-device-spec.md §2, §8): every parse here is
 *  FAIL-CLOSED where a wrong guess could mint a duplicate id (device file,
 *  counters, format marker) and fail-soft only for display data (local paths).
 */

import { randomBytes } from 'node:crypto';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { z } from 'zod';
import { reposLocalFileSchema, slotSchema, slugSchema } from '@agent-ledger/shared';
import { LedgerError } from '../errors.ts';
import { DEVICE_ID_RE } from './paths.ts';
import { readText, writeAtomic } from './fsops.ts';

/** Highest ledger format this hub understands. 1 = pre-sync (repos.yml with
 *  `path`/`next`), 2 = split repos.yml + counters + device identity. */
export const LEDGER_FORMAT = 2;

export class LedgerFormatError extends LedgerError {
  constructor(message: string) {
    super(500, 'LEDGER_FORMAT', message);
    this.name = 'LedgerFormatError';
  }
}

/** Marker file → format number; an absent file is format 1 (legacy ledger).
 *  A newer or unreadable marker REFUSES to start: writing into a ledger whose
 *  layout we do not understand could corrupt it. */
export async function readLedgerFormat(file: string): Promise<number> {
  const text = await readText(file);
  if (text === null) return 1;
  const t = text.trim();
  if (!/^[0-9]{1,6}$/.test(t) || Number(t) < 1) {
    throw new LedgerFormatError('ledger.format is unreadable — refusing to start (restore the file or upgrade the hub)');
  }
  const n = Number(t);
  if (n > LEDGER_FORMAT) {
    throw new LedgerFormatError(
      `ledger format ${n} is newer than this hub supports (${LEDGER_FORMAT}) — upgrade the hub`,
    );
  }
  return n;
}

export async function writeLedgerFormat(file: string, n = LEDGER_FORMAT): Promise<void> {
  await writeAtomic(file, `${n}\n`, 0o600);
}

/* ---------------- device identity ---------------- */

export interface DeviceIdentity {
  device_id: string;
  label: string;
  /** Item-id slot letter; `""` = primary. */
  slot: string;
}

const labelSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'label: lowercase letters, digits, -');
export const deviceFileSchema = z.object({
  device_id: z.string().regex(DEVICE_ID_RE, 'device_id: d_ + 10 base32 chars'),
  label: labelSchema,
  // `slot:` left empty in hand-written YAML parses to null — same as primary.
  slot: slotSchema.nullable().transform((v) => v ?? ''),
});

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

/** CSPRNG. 256 % 32 === 0, so the byte→char map is unbiased.
 *  (Phase F2 replaces the source with sha256(pubkey); the shape is the same.) */
export function newDeviceId(): string {
  const bytes = randomBytes(10);
  let out = 'd_';
  for (const b of bytes) out += B32[b % 32];
  return out;
}

function defaultLabel(): string {
  // Platform only: a hostname can carry a personal name and this label is
  // meant to be synced later (devices.yml).
  return process.platform === 'darwin' ? 'mac' : process.platform === 'win32' ? 'win' : 'linux';
}

function parseDevice(text: string): DeviceIdentity | null {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch {
    return null;
  }
  const res = deviceFileSchema.safeParse(raw);
  return res.success ? res.data : null;
}

/** Read `.hub/device.yml`, creating it on first boot (slot `""`, random id).
 *  An existing but invalid file is NEVER regenerated: a new device id and a
 *  default slot next to an existing counters/ directory is exactly how two
 *  writers end up minting the same id. */
export async function loadOrCreateDevice(file: string): Promise<DeviceIdentity> {
  const text = await readText(file);
  if (text !== null) {
    const dev = parseDevice(text);
    if (dev === null) {
      throw new LedgerError(
        500,
        'DEVICE_INVALID',
        '.hub/device.yml is invalid — refusing to mint ids (fix or restore it; it is not regenerated automatically)',
      );
    }
    return dev;
  }
  const fresh: DeviceIdentity = { device_id: newDeviceId(), label: defaultLabel(), slot: '' };
  await writeAtomic(file, stringifyYaml(fresh, { lineWidth: 0 }), 0o600);
  // Whoever won a (theoretical) race, everyone must agree with what is on disk.
  const back = parseDevice((await readText(file)) ?? '');
  if (back === null) throw new LedgerError(500, 'DEVICE_INVALID', '.hub/device.yml could not be written');
  return back;
}

/* ---------------- counters/<device_id>.yml ---------------- */

/** `{slug: n}` — n = LAST allocated number (0 / absent = none yet). */
const counterFileSchema = z.record(slugSchema, z.number().int().min(0).max(Number.MAX_SAFE_INTEGER - 1));

export function parseCounterFile(text: string): Map<string, number> {
  const res = counterFileSchema.safeParse(parseYaml(text) ?? {});
  if (!res.success) throw new Error('invalid counter file');
  return new Map(Object.entries(res.data));
}

/** `null` = file absent. Throws on invalid content (caller decides). */
export async function readCounterFile(file: string): Promise<Map<string, number> | null> {
  const text = await readText(file);
  return text === null ? null : parseCounterFile(text);
}

export async function writeCounterFile(file: string, counters: Map<string, number>): Promise<void> {
  const sorted = Object.fromEntries([...counters.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  await writeAtomic(file, stringifyYaml(sorted, { lineWidth: 0 }), 0o600);
}

/** Per-key max across every `counters/d_*.yml` (name allowlist, anything else
 *  is ignored). A file that does not parse is skipped and reported, not trusted. */
export async function readAllCounters(
  dir: string,
  onBad?: (name: string) => void,
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return out;
  }
  for (const name of names.sort()) {
    if (!name.endsWith('.yml') || !DEVICE_ID_RE.test(name.slice(0, -4))) continue;
    let map: Map<string, number> | null;
    try {
      map = await readCounterFile(join(dir, name));
    } catch {
      onBad?.(name);
      continue;
    }
    for (const [slug, n] of map ?? []) {
      if (n > (out.get(slug) ?? 0)) out.set(slug, n);
    }
  }
  return out;
}

/* ---------------- .hub/local.yml ---------------- */

export interface RepoLocal {
  path?: string | null;
  graphify?: string | null;
  docs?: string[];
}

/** `null` = invalid file (caller keeps its last good view and does not
 *  overwrite the file); absent = empty map. */
export async function readLocalFile(file: string): Promise<Map<string, RepoLocal> | null> {
  const text = await readText(file);
  if (text === null) return new Map();
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch {
    return null;
  }
  const res = reposLocalFileSchema.safeParse(raw ?? {});
  return res.success ? new Map(Object.entries(res.data)) : null;
}

export async function writeLocalFile(file: string, local: Map<string, RepoLocal>): Promise<void> {
  const sorted = Object.fromEntries([...local.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  await writeAtomic(file, stringifyYaml(sorted, { lineWidth: 0 }), 0o600);
}

/** Absolute in any common spelling (POSIX, `~`, drive, UNC). Such a string must
 *  never be written to a synced file. */
export function isAbsoluteLike(s: string): boolean {
  return /^(?:[\\/]|~|[A-Za-z]:)/.test(s);
}
