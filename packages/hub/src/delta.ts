/**
 * "What changed in the ledger since your last message".
 *
 * The failure this fixes: session A is told about ACME-120, session B fixes and
 * closes it, and A keeps working on it for another twenty minutes because
 * nothing told it. The brief only runs at session start, so a long session goes
 * blind exactly when parallel work is happening.
 *
 * So on every `user-prompt-submit` (and on `session-start` with
 * `source: resume`) the hub prints a short block of what other sessions did.
 * Deliberately small — five lines, then a pointer to `ledger history`. A change
 * feed that fills half a screen gets ignored like any other wall of text.
 *
 * **Why a sequence cursor.** The first implementation filtered the journal (and
 * then item `updated`) by timestamp, and both are second- or minute-resolution.
 * A millisecond cursor taken at 10:31:11.450 sorts after a change stamped
 * 10:31:11.000, so every change made in the same second as the cursor vanished —
 * precisely the parallel-session case. `changes.seq` is a SQLite rowid: monotonic
 * by construction, so nothing can be missed and nothing can repeat.
 *
 * Scoping rules, each there to keep the block honest:
 *  - only repos the session has a stake in (home, touched, or claimed),
 *  - never the session's own changes (it knows what it did),
 *  - nothing new → print nothing at all, not "no changes".
 */

import { shortSession } from '@agent-ledger/shared';
import type { ChangeRow, RuntimeStore } from './db/store.ts';
import type { Ledger } from './ledger/ledger.ts';
import { sessionLabel, type Sessions } from './sessions.ts';

/** Lines shown before the `… +N` pointer. */
export const MAX_DELTA_LINES = 5;
/** Read cap: enough to know there are "more", without loading a whole week. */
const SCAN_LIMIT = 200;

export interface DeltaDeps {
  ledger: Ledger;
  store: RuntimeStore;
  sessions: Sessions;
}

export interface DeltaBlock {
  text: string;
  /** New cursor value — persist it only once the text has really been emitted. */
  cursor: number;
}

/**
 * Build the block, or `null` when the session is unknown or has no repos.
 *
 * Does NOT advance the cursor: the caller persists it after the text has been
 * handed to the agent, so a hook that dies mid-write does not eat a change.
 */
export function buildDelta(deps: DeltaDeps, session: string): DeltaBlock | null {
  const row = deps.store.getSession(session);
  if (row === null) return null;
  const repos = deps.store.sessionRepos(session);
  if (repos.length === 0) return null;

  if (row.delta_cursor === null) {
    // First prompt of this session: there is no "since last message" yet, and
    // replaying the backlog as "changes" would be noise. Start the clock.
    return { text: '', cursor: deps.store.latestChangeSeq() };
  }

  const cursor = row.delta_cursor;
  const rows = deps.store.listChanges(repos, cursor, SCAN_LIMIT);
  if (rows.length === 0) return { text: '', cursor };

  // Own changes are dropped AFTER the read, not in SQL: the cursor still has to
  // advance past them, otherwise a session that works alone re-scans its own
  // history on every prompt.
  const others = rows.filter((r) => r.actor !== session);
  const newest = rows[rows.length - 1]?.seq ?? cursor;
  if (others.length === 0) return { text: '', cursor: newest };

  // Newest first: if only five fit, they should be the five that matter.
  const ordered = [...others].reverse();
  const lines = ordered.slice(0, MAX_DELTA_LINES).map((r) => deltaLine(deps, r));
  const extra = ordered.length - lines.length;
  const repoLabel = uniqueRepos(ordered, repos);

  const out = [`Ledger changes (${repoLabel}) since your last message:`, ...lines];
  if (extra > 0) {
    out.push(`… +${extra} (ledger history --since ${sinceHint(ordered[ordered.length - 1]?.at)})`);
  }
  return { text: out.join('\n'), cursor: newest };
}

/** Only the repos that actually changed — naming quiet repos is noise. */
function uniqueRepos(rows: readonly ChangeRow[], fallback: readonly string[]): string {
  const set = [...new Set(rows.map((r) => r.repo))];
  return (set.length > 0 ? set : fallback).join(', ');
}

/** `ACME-120 done · session "Write queue" (session title, unverified) (61e0) · abc1234` */
function deltaLine(deps: DeltaDeps, row: ChangeRow): string {
  return [
    `${row.item_id} ${label(row.kind)}`,
    actorLabel(deps, row.actor),
    row.commit_sha?.slice(0, 7) ?? '',
  ]
    .filter((p) => p !== '')
    .join(' · ');
}

function label(kind: string): string {
  switch (kind) {
    case 'created':
      return 'created';
    case 'done':
      return 'done';
    case 'dropped':
      return 'dropped';
    case 'claimed':
      return 'claimed';
    case 'reopened':
      return 'reopened';
    case 'released':
      return 'released';
    default:
      return 'changed';
  }
}

/** Sidebar name when the hub still has the session row, else the 4-char handle. */
function actorLabel(deps: DeltaDeps, actor: string | null): string {
  if (actor === null || actor === '') return '';
  const view = deps.sessions.get(actor);
  return view === null ? `session ${shortSession(actor)}` : sessionLabel(view);
}

/** `--since` value that covers the window we just reported. */
function sinceHint(oldestAt: number | undefined): string {
  const from = oldestAt ?? Date.now();
  const hours = Math.ceil((Date.now() - from) / 3_600_000);
  return hours <= 24 ? `${Math.max(1, hours)}h` : `${Math.ceil(hours / 24)}d`;
}
