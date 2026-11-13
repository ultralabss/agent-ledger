/**
 * Staleness of an open item — pure, no I/O. Everything it needs comes in as an
 * argument (the item, two timestamps the runtime DB knows, the clock, env).
 *
 * "Activity" is anything that shows somebody touched the item:
 *  - `fm.updated` (every ledger write bumps it),
 *  - the newest `## Log` line and the newest comment — so
 *    `ledger note <ID> "tidy: kept — <reason>"` (a comment) or a log line
 *    resets the age with no special case,
 *  - `item_files.last_at` (a commit naming the item landed),
 *  - the newest claim / lease on the item (taken or released).
 *
 * Thresholds, in days (an item is stale when `ageDays >= threshold`, so an item
 * idle for exactly the threshold already is):
 *  - P0/P1 and `proposed` → N, P2/P3 → 3×N, N = `LEDGER_STALE_DAYS`, default 7
 *    (so 7 / 21 / 7). One number, 1–3650; anything else falls back to the default.
 *  - only `open`, `doing`, `proposed`, `blocked` are ever stale; `done` and
 *    `dropped` never.
 *  - `blocked` is stale only when it has open blockers and every one of them is
 *    stale itself — while a blocker is moving, the item is waiting, not
 *    forgotten. A blocked item with no open blocker uses its own age.
 *
 * Clocks jump (sleep/wake, NTP, a hand-edited file): a timestamp more than a
 * day in the future is ignored, the rest is clamped to `now`, and an age is
 * never negative.
 */

import { parseStamp, type Item, type ItemStatus, type StaleInfo } from '@agent-ledger/shared';

export const DAY_MS = 86_400_000;
export const DEFAULT_STALE_DAYS = 7;
/** P2/P3 wait this many times longer than P0/P1. */
export const COLD_FACTOR = 3;
/** A timestamp further than this ahead of `now` is not believed. */
const FUTURE_SLACK_MS = DAY_MS;

export type StaleEnv = Readonly<Record<string, string | undefined>>;

export interface StaleThresholds {
  /** P0 / P1. */
  hot: number;
  /** P2 / P3. */
  cold: number;
  proposed: number;
}

const STALE_STATUSES: ReadonlySet<ItemStatus> = new Set<ItemStatus>([
  'open',
  'doing',
  'proposed',
  'blocked',
]);

export function isStaleCandidate(status: ItemStatus): boolean {
  return STALE_STATUSES.has(status);
}

export function staleThresholds(env: StaleEnv = process.env): StaleThresholds {
  const raw = env.LEDGER_STALE_DAYS?.trim() ?? '';
  let base = DEFAULT_STALE_DAYS;
  if (/^\d{1,4}$/.test(raw)) {
    const n = Number(raw);
    if (n >= 1 && n <= 3650) base = n;
  }
  return { hot: base, cold: base * COLD_FACTOR, proposed: base };
}

export function thresholdFor(item: Item, thresholds: StaleThresholds): number {
  if (item.fm.status === 'proposed') return thresholds.proposed;
  return item.fm.priority === 'P0' || item.fm.priority === 'P1' ? thresholds.hot : thresholds.cold;
}

/** What the runtime DB knows about an item (both optional, ms since epoch). */
export interface ActivitySources {
  itemFilesLastAt?: number | null | undefined;
  lastLeaseAt?: number | null | undefined;
}

/** ISO with an offset (`fm.created`, `fm.updated`) or a local `YYYY-MM-DD HH:MM`
 *  stamp (log lines, comments). */
export function parseItemTime(value: string): number | null {
  const s = value.trim();
  if (/(?:Z|[+-]\d{2}:\d{2})$/i.test(s)) {
    const t = Date.parse(s);
    return Number.isNaN(t) ? null : t;
  }
  return parseStamp(s)?.getTime() ?? null;
}

/** Newest sign of life, ms since epoch. Falls back to `now` (never stale)
 *  when no timestamp parses — an unreadable date is not evidence of age. */
export function lastActivity(
  item: Item,
  sources: ActivitySources = {},
  now: number = Date.now(),
): number {
  const candidates: (number | null | undefined)[] = [
    parseItemTime(item.fm.updated),
    parseItemTime(item.fm.created),
    sources.itemFilesLastAt,
    sources.lastLeaseAt,
  ];
  for (const l of item.log) candidates.push(parseItemTime(l.at));
  for (const c of item.comments) candidates.push(parseItemTime(c.at));
  let best: number | null = null;
  for (const t of candidates) {
    if (typeof t !== 'number' || !Number.isFinite(t)) continue;
    if (t > now + FUTURE_SLACK_MS) continue;
    if (best === null || t > best) best = t;
  }
  return best === null ? now : Math.min(best, now);
}

export interface StalenessOptions {
  activity?: ActivitySources | undefined;
  /** `blocked` only: for every OPEN blocker, whether it is stale. Closed or
   *  unknown blockers must not be listed. */
  openBlockersStale?: readonly boolean[] | undefined;
}

export function ageDaysOf(lastMs: number, now: number): number {
  return Math.max(0, Math.floor((now - lastMs) / DAY_MS));
}

export function staleness(
  item: Item,
  now: number = Date.now(),
  env: StaleEnv = process.env,
  opts: StalenessOptions = {},
): StaleInfo {
  const thresholdDays = thresholdFor(item, staleThresholds(env));
  const ageDays = ageDaysOf(lastActivity(item, opts.activity, now), now);
  if (!isStaleCandidate(item.fm.status)) return { ageDays, thresholdDays, stale: false };
  let stale = ageDays >= thresholdDays;
  if (stale && item.fm.status === 'blocked') {
    const blockers = opts.openBlockersStale ?? [];
    if (blockers.length > 0 && !blockers.every(Boolean)) stale = false;
  }
  return { ageDays, thresholdDays, stale };
}

/**
 * Staleness for many items that may block each other: resolves the `blocked`
 * rule through `lookup` (any repo), memoised, with a cycle guard (a blocker
 * cycle is nobody making progress, so it counts as stale).
 */
export function stalenessResolver(
  lookup: (id: string) => Item | undefined,
  activityOf: (item: Item) => ActivitySources,
  now: number = Date.now(),
  env: StaleEnv = process.env,
): (item: Item) => StaleInfo {
  const memo = new Map<string, StaleInfo>();
  const inProgress = new Set<string>();

  const resolve = (item: Item): StaleInfo => {
    const id = item.fm.id;
    const hit = memo.get(id);
    if (hit) return hit;
    if (inProgress.has(id)) return { ageDays: 0, thresholdDays: 0, stale: true };
    inProgress.add(id);
    let openBlockersStale: boolean[] | undefined;
    if (item.fm.status === 'blocked') {
      openBlockersStale = [];
      for (const bid of item.fm.blocked_by) {
        const blocker = lookup(bid);
        if (!blocker || !isStaleCandidate(blocker.fm.status)) continue;
        openBlockersStale.push(resolve(blocker).stale);
      }
    }
    inProgress.delete(id);
    const info = staleness(item, now, env, { activity: activityOf(item), openBlockersStale });
    memo.set(id, info);
    return info;
  };
  return resolve;
}
