/** Item fixtures for the staleness and tidy tests (not a test file itself). */

import {
  isoLocal,
  stamp,
  type Item,
  type ItemFrontmatter,
  type ItemPriority,
  type ItemStatus,
} from '@agent-ledger/shared';
import { DAY_MS } from './stale.ts';

export const NOW = Date.parse('2026-11-13T12:00:00Z');

export interface MkOpts {
  id?: string;
  repo?: string;
  status?: ItemStatus;
  priority?: ItemPriority;
  owner?: string;
  title?: string;
  why?: string;
  intake?: string | null;
  session?: string | null;
  /** Days between the last write and NOW. */
  ageDays?: number;
  /** Days between creation and NOW (default: `ageDays`). */
  createdDays?: number;
  blocked_by?: string[];
  claimed?: boolean;
  log?: { daysAgo: number; text: string }[];
  comments?: { daysAgo: number; text: string }[];
}

/** An item whose every timestamp is exactly `ageDays` before NOW. */
export function mk(o: MkOpts = {}): Item {
  const age = o.ageDays ?? 0;
  const at = (d: number): Date => new Date(NOW - d * DAY_MS);
  const fm: ItemFrontmatter = {
    id: o.id ?? 'ACME-1',
    title: o.title ?? 'rework the cart totals',
    status: o.status ?? 'open',
    kind: 'BACKLOG',
    priority: o.priority ?? 'P1',
    owner: o.owner ?? 'agent',
    repo: o.repo ?? 'acme',
    area: null,
    paths: [],
    blocks: [],
    blocked_by: o.blocked_by ?? [],
    requested_by: null,
    intake: o.intake === undefined ? null : o.intake,
    aliases: [],
    claimed_by: o.claimed ? { session: 'sess-claim', since: isoLocal(at(age)) } : null,
    source: { session: o.session === undefined ? 'sess-creator' : o.session, agent: null, commit: null },
    done: null,
    created: isoLocal(at(o.createdDays ?? age)),
    updated: isoLocal(at(age)),
  };
  return {
    fm,
    why: o.why ?? '',
    steps: [],
    rec: '',
    comments: (o.comments ?? []).map((c, i) => ({
      at: stamp(at(c.daysAgo)),
      author: 'orchestrator',
      id: `c${i}`,
      text: c.text,
    })),
    log: (o.log ?? []).map((l) => ({ at: stamp(at(l.daysAgo)), session: 'abcd', text: l.text })),
  };
}
