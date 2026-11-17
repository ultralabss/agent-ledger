/** Small deterministic helpers shared by the typed mergers. */

import { createHash } from 'node:crypto';
import { RESERVED_SYNC_WORKER, SNOWFLAKE_EPOCH_MS } from '@agent-ledger/shared';
import type { MergeCtx } from './types.ts';

export function cmpStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Canonical JSON (sorted keys) — structural equality for frontmatter values. */
export function canon(v: unknown): string {
  if (v === undefined) return 'undefined';
  return JSON.stringify(sortKeys(v));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(o)
        .sort(cmpStr)
        .map((k) => [k, sortKeys(o[k])]),
    );
  }
  return v;
}

export function same(a: unknown, b: unknown): boolean {
  return canon(a) === canon(b);
}

const ISO_STRICT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:\d{2})$/;

/** Strict ISO-8601 instant (`Z` or `±hh:mm`, `T` separator, real calendar date).
 *  Anything else — including strings `Date.parse` would guess at — is `-Infinity`
 *  (F3A-4): an unparsable timestamp can never win a "newest" comparison. */
export function parseIsoTime(s: unknown): number {
  if (typeof s !== 'string' || s.length > 40) return Number.NEGATIVE_INFINITY;
  const m = ISO_STRICT.exec(s);
  if (m === null) return Number.NEGATIVE_INFINITY;
  const [y, mo, d, h, mi, se] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i]));
  if ((h as number) > 23 || (mi as number) > 59 || (se as number) > 59) return Number.NEGATIVE_INFINITY;
  const ms = m[7] === undefined ? 0 : Number(m[7].padEnd(3, '0'));
  const utc = Date.UTC(y as number, (mo as number) - 1, d as number, h as number, mi as number, se as number, ms);
  const chk = new Date(utc);
  if (chk.getUTCFullYear() !== y || chk.getUTCMonth() !== (mo as number) - 1 || chk.getUTCDate() !== d) {
    return Number.NEGATIVE_INFINITY;
  }
  let off = 0;
  if (m[8] !== 'Z') {
    const oh = Number((m[8] as string).slice(1, 3));
    const om = Number((m[8] as string).slice(4, 6));
    if (oh > 23 || om > 59) return Number.NEGATIVE_INFINITY;
    off = (oh * 60 + om) * 60_000 * ((m[8] as string).startsWith('-') ? -1 : 1);
  }
  return utc - off;
}

/** TOTAL order: by instant (unparsable = -Infinity), then by the raw string, so two
 *  spellings of one instant — or two garbage values — still order deterministically. */
export function cmpTime(a: string, b: string): number {
  const x = parseIsoTime(a);
  const y = parseIsoTime(b);
  if (x !== y) return x < y ? -1 : 1;
  return cmpStr(a, b);
}

export function maxTime(a: string, b: string): string {
  return cmpTime(a, b) >= 0 ? a : b;
}

export function minTime(a: string, b: string): string {
  return cmpTime(a, b) <= 0 ? a : b;
}

/** `2026-09-28T14:02:00+02:00` → `2026-09-28 14:02` (log/comment/journal stamp). */
export function stampOf(iso: string): string {
  const m = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/.exec(iso);
  return m ? `${m[1]} ${m[2]}` : '1970-01-01 00:00';
}

/** Conflict winner: newer `updated`; tie → lower device_id. Symmetric under
 *  swapping the sides together with their devices. */
export function oursWins(ctx: MergeCtx, oursUpdated: string, theirsUpdated: string): boolean {
  const c = cmpTime(oursUpdated, theirsUpdated);
  if (c !== 0) return c > 0;
  return cmpStr(ctx.ourDevice, ctx.theirDevice) <= 0;
}

export interface Merged<T> {
  value: T;
  conflict: boolean;
  loser: T | undefined;
}

/** Field-level 3-way. `base === undefined` = no base value. */
export function merge3<T>(base: T | undefined, ours: T, theirs: T, preferOurs: boolean): Merged<T> {
  if (same(ours, theirs)) return { value: ours, conflict: false, loser: undefined };
  if (base !== undefined && same(ours, base)) return { value: theirs, conflict: false, loser: undefined };
  if (base !== undefined && same(theirs, base)) return { value: ours, conflict: false, loser: undefined };
  return preferOurs
    ? { value: ours, conflict: true, loser: theirs }
    : { value: theirs, conflict: true, loser: ours };
}

/** 3-way set merge: kept = in base and both sides, plus whatever either side
 *  added. Order is preserved only when one side did not touch the list;
 *  otherwise canonical (sorted) so the result is side-independent. */
export function mergeSet(base: readonly string[], ours: readonly string[], theirs: readonly string[]): string[] {
  if (same(ours, theirs)) return [...ours];
  if (same(ours, base)) return [...theirs];
  if (same(theirs, base)) return [...ours];
  const b = new Set(base);
  const o = new Set(ours);
  const t = new Set(theirs);
  const out = new Set<string>();
  for (const x of o) if (!b.has(x) || t.has(x)) out.add(x);
  for (const x of t) if (!b.has(x) || o.has(x)) out.add(x);
  return [...out].sort(cmpStr);
}

/** Union (never deletes), sorted canonically unless one side is a no-op. */
export function unionList(
  base: readonly string[],
  ours: readonly string[],
  theirs: readonly string[],
): string[] {
  if (same(ours, theirs)) return [...ours];
  if (same(ours, base)) return [...theirs];
  if (same(theirs, base)) return [...ours];
  return [...new Set([...ours, ...theirs])].sort(cmpStr);
}

/** Numeric-aware id order: decimal ids by value (before anything else). */
export function cmpIds(a: string, b: string): number {
  const na = /^\d{1,30}$/.test(a);
  const nb = /^\d{1,30}$/.test(b);
  if (na && nb) {
    const x = BigInt(a);
    const y = BigInt(b);
    if (x !== y) return x < y ? -1 : 1;
    return cmpStr(a, b); // `1` vs `01`: same value, still a total order
  }
  if (na) return -1;
  if (nb) return 1;
  return cmpStr(a, b);
}

/** Worker field reserved for engine-minted comments: slot workers are 1..25. */
export const SYNC_WORKER = BigInt(RESERVED_SYNC_WORKER);

/** Deterministic Snowflake-shaped id for a `sync` comment: time = the merged
 *  `updated`, worker 1023, sequence = hash of `seed`. No clock, no counter —
 *  both hubs mint the identical id for the identical conflict. */
export function syncCommentId(updated: string, seed: string): string {
  const ms = parseIsoTime(updated);
  const rel = Number.isFinite(ms) ? Math.max(0, ms - SNOWFLAKE_EPOCH_MS) : 0;
  const ts = BigInt(rel) & ((1n << 41n) - 1n);
  const h = createHash('sha256').update(seed).digest();
  const seq = BigInt(((h[0] as number) << 8) | (h[1] as number)) & 0xfffn;
  return String((ts << 22n) | (SYNC_WORKER << 12n) | seq);
}

/** Short single-line excerpt for notes and Log lines. */
export function excerpt(v: unknown, max = 160): string {
  const raw = typeof v === 'string' ? v : (JSON.stringify(v) ?? 'undefined');
  const one = raw.replace(/\s+/g, ' ').trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}
