/** `devices.yml` merger (F3b B2, finding F-7). Pure text in, text out.
 *
 *  Revocation is monotonic (union of revoked entries, earliest record wins,
 *  deterministic total order); `last_seen` is the per-entry max of valid
 *  timestamps; additions are a union. A slot / pubkey / id clash between two
 *  concurrent additions is NOT resolved here — the result is a `devices-conflict`
 *  signal and the caller quarantines (a trust file never picks a winner).
 *
 *  Output goes through the shared renderer (LF only, schema key order) and entries
 *  are sorted by slot, so the bytes do not depend on which side was "ours". When
 *  one side is a no-op the other side is returned verbatim; the same function is
 *  the verifier's expectation for merge commits (gate.ts), so both agree.
 */

import {
  DevicesError,
  parseDevicesYaml,
  renderDevicesYaml,
  safeOutput,
  type DeviceEntry,
  type DevicesFile,
} from '@agent-ledger/shared';
import { cmpStr, cmpTime, parseIsoTime } from './common.ts';
import type { SyncNote } from './types.ts';

export type DevicesMergeResult =
  | { ok: true; merged: string; notes: SyncNote[] }
  | { ok: false; rule: 'devices-parse' | 'devices-conflict'; detail: string };

const IDENTITY_KEYS = ['id', 'label', 'slot', 'pubkey', 'added', 'added_by', 'role'] as const;

function fail(rule: 'devices-parse' | 'devices-conflict', detail: string): Extract<DevicesMergeResult, { ok: false }> {
  return { ok: false, rule, detail: safeOutput(detail, 160) };
}

function parseOrNull(text: string): DevicesFile | null {
  try {
    return parseDevicesYaml(text);
  } catch {
    return null;
  }
}

/** Earliest revocation record: instant, then the raw record (total). */
function earliestRevoked(list: readonly NonNullable<DeviceEntry['revoked']>[]): NonNullable<DeviceEntry['revoked']> {
  const key = (r: NonNullable<DeviceEntry['revoked']>): string => JSON.stringify([r.at, r.by, r.reason]);
  return [...list].sort((a, b) => cmpTime(a.at, b.at) || cmpStr(key(a), key(b)))[0] as NonNullable<DeviceEntry['revoked']>;
}

export function mergeDevices(base: string | null, ours: string, theirs: string): DevicesMergeResult {
  try {
    const o = parseOrNull(ours);
    const t = parseOrNull(theirs);
    const b = base === null ? { devices: [] } : parseOrNull(base);
    if (o === null || t === null || b === null) return fail('devices-parse', 'devices.yml is not valid');
    // No-op sides: verbatim (already validated above).
    if (ours === theirs) return { ok: true, merged: ours, notes: [] };
    if (base !== null && ours === base) return { ok: true, merged: theirs, notes: [] };
    if (base !== null && theirs === base) return { ok: true, merged: ours, notes: [] };

    const versions = new Map<string, DeviceEntry[]>();
    for (const f of [b, o, t]) {
      for (const d of f.devices) versions.set(d.id, [...(versions.get(d.id) ?? []), d]);
    }
    const merged: DeviceEntry[] = [];
    for (const [id, list] of [...versions.entries()].sort(([x], [y]) => cmpStr(x, y))) {
      const first = list[0] as DeviceEntry;
      for (const v of list) {
        for (const k of IDENTITY_KEYS) {
          if (v[k] !== first[k]) return fail('devices-conflict', `${id}: ${k} differs between sides`);
        }
      }
      const revs = list.flatMap((v) => (v.revoked === null ? [] : [v.revoked]));
      const seen = list
        .map((v) => v.last_seen)
        .filter((x): x is string => x !== undefined && Number.isFinite(parseIsoTime(x)))
        .sort(cmpTime);
      const entry: DeviceEntry = {
        id: first.id,
        label: first.label,
        slot: first.slot,
        pubkey: first.pubkey,
        added: first.added,
        added_by: first.added_by,
        revoked: revs.length === 0 ? null : earliestRevoked(revs),
        role: first.role,
      };
      const last = seen[seen.length - 1];
      if (last !== undefined) entry.last_seen = last;
      merged.push(entry);
    }
    merged.sort((x, y) => cmpStr(x.slot, y.slot) || cmpStr(x.id, y.id));
    try {
      // The renderer re-validates the cross-entry invariants (slot / pubkey / id
      // uniqueness, added_by, revoked.by): a clash surfaces here.
      return { ok: true, merged: renderDevicesYaml({ devices: merged }), notes: [] };
    } catch (e) {
      if (e instanceof DevicesError) return fail('devices-conflict', e.message);
      throw e;
    }
  } catch {
    return fail('devices-parse', 'devices.yml merge failed');
  }
}

/** Absent file = no registry on that side. Both absent -> absent; one absent -> the
 *  other side verbatim (after validation). Shared by the tree dispatcher and the
 *  merge-commit verifier so they cannot disagree. */
export function mergeDevicesNullable(
  base: string | null,
  ours: string | null,
  theirs: string | null,
): { ok: true; merged: string | null; notes: SyncNote[] } | Extract<DevicesMergeResult, { ok: false }> {
  if (ours === null && theirs === null) return { ok: true, merged: null, notes: [] };
  if (ours === null || theirs === null) {
    const only = (ours ?? theirs) as string;
    return parseOrNull(only) === null ? fail('devices-parse', 'devices.yml is not valid') : { ok: true, merged: only, notes: [] };
  }
  return mergeDevices(base, ours, theirs);
}
