/**
 * File memory on the FIRST edit of a file in a session.
 *
 * The failure it prevents: an agent rewrites a file that another live session
 * is holding, or that a commit last week changed for a reason recorded in an
 * item, and nobody finds out until the merge. The hub already knows all three
 * facts; this is the one place that says them out loud.
 *
 * Token discipline:
 *  - one shot per (session, file) — the mark makes a 40-edit loop cost nothing;
 *  - at most `MAX_SHOWN` files per session produce output, after that silence;
 *  - at most `MAX_CHECKED` files per session are even *examined*, so a session
 *    that touches 300 files does not pay 300 `git log` calls;
 *  - "only if" is the rule, not a filter: with no claim, no recent commit and
 *    no item mentioning the path, the function returns `''`.
 */

import { frameUntrusted, isOpen, untrustedSnippet } from '@agent-ledger/shared';
import type { RuntimeStore } from './db/store.ts';
import type { Ledger } from './ledger/ledger.ts';
import { readPathCommits } from './gitreader.ts';
import { agoShort } from './relevance.ts';
import { shortSession } from '@agent-ledger/shared';
import type { Sessions } from './sessions.ts';

export interface FileMemoryDeps {
  ledger: Ledger;
  store: RuntimeStore;
  sessions: Sessions;
}

export interface FileMemoryInput {
  session: string;
  repo: string;
  checkout: string;
  rel_path: string;
  now?: number;
}

/** Files per session that may produce a line. */
export const MAX_SHOWN = 5;
/** Files per session that get looked at. The gap between this and `MAX_SHOWN`
 *  is the "many edits, few surprises" case — common and cheap. */
const MAX_CHECKED = 40;
/** Lines, per the spec. Claim, commit, item — in that order of usefulness. */
const MAX_LINES = 3;
const RECENT_COMMIT_DAYS = 7;
const LINE_MAX = 120;

/**
 * 1–3 lines, or `''`. Never throws: it is on the PostToolUse path and the
 * inbox travels in the same envelope.
 */
export async function fileMemory(deps: FileMemoryDeps, input: FileMemoryInput): Promise<string> {
  const now = input.now ?? Date.now();
  const key = `${input.session}:${input.repo}:${input.rel_path}`;
  // Not the first edit of this file in this session → nothing, no IO.
  if (!deps.store.markOnce('filemem-seen', key, now)) return '';
  if (deps.store.countMarks('filemem-seen', `${input.session}:`) > MAX_CHECKED) return '';
  if (deps.store.countMarks('filemem-shown', `${input.session}:`) >= MAX_SHOWN) return '';

  const lines: string[] = [];
  try {
    const claim = claimLine(deps, input, now);
    if (claim !== null) lines.push(claim);
    const commit = await commitLine(deps, input, now);
    if (commit !== null) lines.push(commit);
    const item = itemLine(deps, input);
    if (item !== null) lines.push(item);
  } catch {
    return '';
  }
  if (lines.length === 0) return '';
  // Only a file that actually said something counts against the budget.
  deps.store.markOnce('filemem-shown', key, now);
  // The lines embed claim patterns, commit subjects and item/decision
  // titles — none written by the hub. One frame for the whole block.
  return frameUntrusted(lines.slice(0, MAX_LINES).join('\n'));
}

/** Another LIVE session holds this path — by claim glob or by having edited it. */
function claimLine(deps: FileMemoryDeps, input: FileMemoryInput, now: number): string | null {
  const claims = deps.sessions
    .claimsOfPath(input.checkout, input.rel_path)
    .filter((c) => c.session !== input.session);
  if (claims.length > 0) {
    const c = claims[0] as { session: string; pattern: string; item_id: string | null };
    return clamp(
      `${input.rel_path}: claim session ${shortSession(c.session)}${
        c.item_id ? ` (${c.item_id})` : ''
      } via "${untrustedSnippet(c.pattern, 60)}" — check you are not overwriting it`,
    );
  }
  const others = deps.store
    .ownersOfPath(input.checkout, input.rel_path)
    .filter((o) => o.session_id !== input.session);
  for (const o of others) {
    const view = deps.sessions.get(o.session_id);
    if (view === null || view.liveness === 'ended') continue;
    return clamp(
      `${input.rel_path}: uncommitted changes by session ${shortSession(o.session_id)} (${
        o.via
      }, ${agoShort(o.last_at, now)}) — not yours`,
    );
  }
  return null;
}

/** A commit in the last week that carried a `Closes:`/`Refs:` trailer. Those
 *  are the commits with a recorded *reason*; an untrailered one is noise. */
async function commitLine(
  deps: FileMemoryDeps,
  input: FileMemoryInput,
  now: number,
): Promise<string | null> {
  const commits = await readPathCommits(input.checkout, input.rel_path, RECENT_COMMIT_DAYS, 10);
  const own = new Set(
    deps.store
      .listLeases({ session: input.session, active: true })
      .map((l) => l.item_id)
      .filter((id): id is string => id !== null),
  );
  for (const c of commits) {
    const ids = [...c.closes, ...c.refs].filter((id) => !own.has(id));
    if (ids.length === 0) continue;
    const t = Date.parse(c.at);
    return clamp(
      `${input.rel_path}: ${c.short} ${untrustedSnippet(c.subject, 80)} (${ids.slice(0, 2).join(', ')}${
        Number.isFinite(t) ? `, ${agoShort(t, now)}` : ''
      })`,
    );
  }
  return null;
}

/** An open item or a decision that names this path. Scanned in memory over the
 *  repo's items (tens, not thousands) — no FTS, because a path tokenises into
 *  words that match half the ledger. */
function itemLine(deps: FileMemoryDeps, input: FileMemoryInput): string | null {
  const needle = input.rel_path;
  const base = needle.slice(needle.lastIndexOf('/') + 1);
  // A bare `index.ts` would match every item in the fleet — such a file only
  // counts when the item names its full path.
  const generic = /^(index|types|utils|main|mod|bin)\.[a-z]+$/.test(base);
  for (const item of deps.ledger.listItems({ repo: input.repo })) {
    if (!isOpen(item.fm.status)) continue;
    const hay = [item.fm.paths.join(' '), item.fm.title, item.why, item.rec].join('\n');
    if (!hay.includes(needle) && !(!generic && hay.includes(base))) continue;
    return clamp(`${needle}: mentioned by ${item.fm.id} ${item.fm.status} ${untrustedSnippet(item.fm.title, 60)}`);
  }
  for (const d of deps.ledger.listDecisions(input.repo)) {
    if (!d.body.includes(needle) && !d.title.includes(needle)) continue;
    return clamp(`${needle}: mentioned by decision D${d.n} ${untrustedSnippet(d.title, 60)}`);
  }
  return null;
}

function clamp(s: string, max = LINE_MAX): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}
