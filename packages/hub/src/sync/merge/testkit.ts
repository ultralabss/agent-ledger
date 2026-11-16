/** Test support: seeded PRNG + item fixtures. No dependencies. */

import { parseItem, serializeItem, type Item, type ItemFrontmatter } from '@agent-ledger/shared';
import type { MergeCtx } from './types.ts';

export interface Rng {
  next(): number;
  int(n: number): number;
  pick<T>(xs: readonly T[]): T;
  chance(p: number): boolean;
}

/** mulberry32 — fixed seed, fully deterministic. */
export function rng(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (n) => Math.floor(next() * n),
    pick: (xs) => xs[Math.floor(next() * xs.length)] as never,
    chance: (p) => next() < p,
  };
}

export const DEV_A = 'd_aaaaaaaaaa';
export const DEV_B = 'd_bbbbbbbbbb';
export const DEV_C = 'd_cccccccccc';

export const ctxOf = (our: string, their: string, remoteIsTheirs = true): MergeCtx => ({
  ourDevice: our,
  theirDevice: their,
  remoteIsTheirs,
});

export const T0 = '2026-11-10T09:00:00+01:00';

export function baseItem(): Item {
  const fm: ItemFrontmatter = {
    id: 'ACME-1',
    title: 'Base title',
    status: 'open',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    repo: 'acme',
    area: null,
    paths: [],
    blocks: [],
    blocked_by: [],
    requested_by: null,
    intake: null,
    aliases: [],
    claimed_by: null,
    source: { session: null, agent: null, commit: null },
    done: null,
    created: T0,
    updated: T0,
  };
  return {
    fm,
    why: 'l0\nl1\nl2\nl3\nl4',
    steps: [
      { n: 1, done: false, text: 'first' },
      { n: 2, done: false, text: 'second' },
    ],
    rec: 'r0\nr1\nr2',
    comments: [{ at: '2026-11-10 09:00', author: 'x', id: '1000', text: 'hello' }],
    log: [{ at: '2026-11-10 09:00', session: 's0', text: 'created' }],
  };
}

export function baseText(): string {
  return serializeItem(baseItem());
}

/** parse → mutate → serialize (unknown sections and keys survive). */
export function edit(text: string, fn: (item: Item) => void): string {
  const { item, doc } = parseItem(text);
  fn(item);
  return serializeItem(item, doc);
}

export const MARKERS = /^(<{7}|={7}|>{7})/m;
