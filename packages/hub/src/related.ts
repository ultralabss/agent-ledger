/**
 * "Related:" reminder: what the fleet already did about the
 * topic of the user's message.
 *
 * Problem it solves: a session starts work on something the fleet already did
 * last week, because nothing connected the user's words to the ledger. The
 * brief lists what is *open*; this lists what is *related*, including closed
 * work and decisions, which is where the expensive repetition lives. It
 * also adds *where* (a few paths per item), so the next session does not spend an
 * Explore run finding what the hub already knew.
 *
 * Pull, not dump — token discipline is the hard constraint on this feature:
 *  - the first eligible message of a session is checked against the
 *    base threshold; every LATER message is checked too, but against a
 *    clearly higher bar (`relevance.ts`), and only if the session still has
 *    budget;
 *  - a ledger ref is shown at most once per session, whatever the message;
 *  - a session as a whole gets at most `SESSION_MAX_HITS` hits and
 *    `SESSION_MAX_CHARS` characters; once either is spent this function returns
 *    before it touches the search index;
 *  - one hit is one line of ≤ `ENTRY_MAX` characters; a message carries at most
 *    `MAX_HITS_FIRST` / `MAX_HITS_LATER` of them;
 *  - nothing at all unless a hit clears both halves of the threshold — a short
 *    generic request inserts zero characters;
 *  - the prompt is used to build an FTS query and then dropped. It is never
 *    written to the DB, the journal or the log, which is also why the hook
 *    route deliberately does not secret-scan it. The only thing remembered is
 *    which refs were shown and how many characters they cost.
 */

import { frameUntrusted, isOpen, untrustedSnippet, type Decision } from '@agent-ledger/shared';
import type { RuntimeStore } from './db/store.ts';
import type { Ledger } from './ledger/ledger.ts';
import { itemPaths } from './related-paths.ts';
import {
  agoShort,
  contentTokens,
  LATER_MIN_PROMPT_TOKENS,
  mentionedIds,
  MIN_PROMPT_TOKENS,
  relevance,
  type RelevanceTier,
} from './relevance.ts';

export interface RelatedDeps {
  ledger: Ledger;
  store: RuntimeStore;
}

export interface RelatedInput {
  session: string;
  /** Repo of the session. `ops` is always searched alongside it. */
  repo: string | null;
  /** The session's own checkout (possibly a worktree) — an extra place to look
   *  a path up in, next to the repo's registered checkout. */
  checkout?: string | null | undefined;
  prompt: string | undefined;
  now?: number;
}

/** Hits per message: the first eligible message of a session, then every later
 *  one (which also has to clear a higher bar, `relevance.ts`). */
const MAX_HITS_FIRST = 3;
const MAX_HITS_LATER = 2;
/** SPEC §9: the whole session, however many messages it sends. */
export const SESSION_MAX_HITS = 5;
export const SESSION_MAX_CHARS = 1_500;
/** `markOnce` kind: key `<session>:<ref>:<characters it cost>`. One row is
 *  both the "already shown" dedupe and one unit of the session budget. */
const SHOWN = 'related-shown';
/** Characters of the prompt that may shape the query. A pasted stack trace
 *  past this adds no topic, only tokens to intersect. */
const PROMPT_SLICE = 4_000;
/** Candidates pulled from FTS before thresholding. */
const SEARCH_LIMIT = 24;
/** One hit on one line: `ID · state · title · path1, path2`. */
const ENTRY_MAX = 240;
const TITLE_MAX = 60;
/** What `Related: ` + the untrusted frame add around the first hit of a message,
 *  and the newline between hits — counted so the character budget is honest. */
const FRAME_COST = `Related: ${frameUntrusted('')}`.length;

/**
 * The reminder, or `''`.
 *
 * Fail-soft by contract: this runs on the prompt hook, and an exception here
 * would cost the session its delta and inbox too. Every caller gets a string.
 */
export function relatedLines(deps: RelatedDeps, input: RelatedInput): string {
  const prompt = input.prompt;
  if (typeof prompt !== 'string' || prompt.trim() === '') return '';
  const now = input.now ?? Date.now();

  // The session budget is checked before anything else, so a session
  // that has had its share pays for a message with one indexed read.
  const spent = shownBudget(deps.store, input.session);
  if (spent.hits >= SESSION_MAX_HITS || spent.chars >= SESSION_MAX_CHARS) return '';

  // Decide first whether this message even clears the topic threshold,
  // THEN spend the first-message mark. A short first message ("ok",
  // "continue") used to burn the session's only shot at the base threshold for
  // nothing — now it still gets a real chance on its next message.
  const head = prompt.slice(0, PROMPT_SLICE);
  const tokens = contentTokens(head);
  if (tokens.length < MIN_PROMPT_TOKENS) return '';

  // The mark decides which bar this message faces. It used to be spent as a
  // once-per-session gate; now it is kept as "was this the first eligible
  // message" and lets every later one through at the higher bar.
  const tier: RelevanceTier = deps.store.markOnce('related', input.session, now) ? 'first' : 'later';
  if (tier === 'later' && tokens.length < LATER_MIN_PROMPT_TOKENS) return '';
  const already = mentionedIds(head);
  for (const lease of ownLeaseItems(deps.store, input.session)) already.add(lease);

  const repos = new Set<string>(['ops']);
  if (input.repo !== null) repos.add(input.repo);

  const seen = new Set<string>();
  const scored: Candidate[] = [];

  for (const repo of repos) {
    let hits;
    try {
      hits = deps.store.searchScored(tokens.join(' '), SEARCH_LIMIT, {
        repo,
        // `context` and `intake` docs are whole files: they match nearly any
        // prompt and would make the threshold meaningless.
        kinds: ['item', 'decision'],
      });
    } catch {
      continue;
    }
    for (const hit of hits) {
      if (seen.has(hit.ref)) continue;
      // Once per session — a ref the agent was already told about.
      if (spent.refs.has(hit.ref)) continue;
      // `ops` is searched for every session, but most `ops` items are
      // fleet-wide business that says nothing about THIS repo — surfacing
      // them anyway reminds a session of unrelated work. Only let an `ops`
      // hit through when it actually names or was requested by this repo.
      if (repo === 'ops' && input.repo !== null && !opsHitRelevant(deps, input.repo, hit)) continue;
      const { overlap, passes } = relevance(
        tokens,
        { text: `${hit.title} ${hit.excerpt}`, score: hit.score },
        tier,
      );
      if (!passes) continue;
      // The agent already named it — repeating it back is pure cost.
      if (already.has(hit.ref)) continue;
      seen.add(hit.ref);
      scored.push({ ref: hit.ref, kind: hit.kind, repo, overlap, rank: hit.score ?? 0 });
    }
  }

  if (scored.length === 0) return '';
  // Overlap first (topic match), BM25 as the tie-break.
  scored.sort((a, b) => b.overlap - a.overlap || a.rank - b.rank);

  // Render only as many as can still be shown: the path lookup (one lstat per
  // path) is the expensive part and is not spent on hits that get cut anyway.
  const perMessage = tier === 'first' ? MAX_HITS_FIRST : MAX_HITS_LATER;
  const room = Math.min(perMessage, SESSION_MAX_HITS - spent.hits);
  const lines: { ref: string; text: string }[] = [];
  let chars = FRAME_COST;
  for (const c of scored) {
    if (lines.length >= room) break;
    // `getItem` for an item another session deleted, a decision gone from the
    // file: skip and let the next candidate take the slot.
    const text =
      c.kind === 'decision'
        ? decisionEntry(deps, c.ref, c.repo)
        : itemEntry(deps, c, input, now);
    if (text === null) continue;
    const cost = text.length + (lines.length === 0 ? 0 : 1);
    if (spent.chars + chars + cost > SESSION_MAX_CHARS) continue;
    lines.push({ ref: c.ref, text });
    chars += cost;
  }

  // Spend the budget only for what is actually printed. A ref that lost the
  // race to a concurrent hook on the same session is dropped, not doubled.
  const shown: string[] = [];
  for (const [i, line] of lines.entries()) {
    const cost = line.text.length + (i === 0 ? FRAME_COST : 1);
    if (!deps.store.markOnce(SHOWN, `${input.session}:${line.ref}:${cost}`, now)) continue;
    shown.push(line.text);
  }
  if (shown.length === 0) return '';
  // Entries embed decision/item titles, which are free text written by
  // whoever filed them — framed once for the whole block, not per entry.
  return `Related: ${frameUntrusted(shown.join('\n'))}`;
}

interface Candidate {
  ref: string;
  kind: string;
  repo: string;
  overlap: number;
  rank: number;
}

/** What this session has already been told, and what it cost. */
function shownBudget(
  store: RuntimeStore,
  session: string,
): { hits: number; chars: number; refs: Set<string> } {
  const refs = new Set<string>();
  let chars = 0;
  const prefix = `${session}:`;
  try {
    for (const key of store.markKeys(SHOWN, prefix)) {
      const rest = key.slice(prefix.length);
      const cut = rest.lastIndexOf(':');
      if (cut < 0) continue;
      refs.add(rest.slice(0, cut));
      chars += Number(rest.slice(cut + 1)) || 0;
    }
  } catch {
    /* no budget data = no feed; the caller sees a full budget */
    return { hits: SESSION_MAX_HITS, chars: SESSION_MAX_CHARS, refs };
  }
  return { hits: refs.size, chars, refs };
}

/** Items the session itself holds right now — it knows about those. */
function ownLeaseItems(store: RuntimeStore, session: string): string[] {
  try {
    return store
      .listLeases({ session, active: true })
      .map((l) => l.item_id)
      .filter((id): id is string => id !== null);
  } catch {
    return [];
  }
}

/** An `ops` hit counts as relevant to `repo` only when it names it
 *  (title/decision) or was explicitly requested by an item that belongs to
 *  it — never just because it matched the prompt's words. */
function opsHitRelevant(
  deps: RelatedDeps,
  repo: string,
  hit: { kind: string; ref: string; title: string },
): boolean {
  const needle = repo.toLowerCase();
  if (hit.title.toLowerCase().includes(needle)) return true;
  if (hit.kind !== 'item') return false;
  try {
    const requestedBy = deps.ledger.getItem(hit.ref).item.fm.requested_by;
    if (requestedBy === null) return false;
    return deps.ledger.getItem(requestedBy).item.fm.repo === repo;
  } catch {
    return false;
  }
}

/** `ACME-32 · done 2 d ago · Related on the first message · packages/hub/src/related.ts, …` */
function itemEntry(deps: RelatedDeps, c: Candidate, input: RelatedInput, now: number): string | null {
  let item;
  try {
    item = deps.ledger.getItem(c.ref).item;
  } catch {
    return null;
  }
  const fm = item.fm;
  // The session that did this work needs no reminder of it.
  try {
    if (deps.store.itemWorkers(c.repo, fm.id, 5).includes(input.session)) return null;
  } catch {
    /* unknown = not its own */
  }
  const state: string[] = [fm.status];
  if (isOpen(fm.status)) {
    if (fm.kind !== 'BACKLOG') state.push(fm.kind);
  } else {
    const t = Date.parse(fm.done?.at ?? fm.updated);
    if (Number.isFinite(t)) state.push(agoShort(t, now));
  }
  const head = [fm.id, state.join(' '), untrustedSnippet(fm.title, TITLE_MAX)].join(' · ');
  const roots = new Set<string>();
  const registered = safeRepoPath(deps.ledger, c.repo);
  if (registered !== null) roots.add(registered);
  if (input.checkout && c.repo === input.repo) roots.add(input.checkout);
  const paths = itemPaths(deps.store, { repo: c.repo, itemId: fm.id, roots: [...roots] });
  // Add paths one by one while the line still fits — the path list is the
  // elastic part, the id/state/title is what makes the hit a hit.
  let line = head;
  const kept: string[] = [];
  for (const path of paths) {
    const next = `${head} · ${[...kept, path].join(', ')}`;
    if (next.length > ENTRY_MAX) break;
    kept.push(path);
    line = next;
  }
  return clamp(line);
}

function safeRepoPath(ledger: Ledger, repo: string): string | null {
  try {
    return ledger.repoPath(repo);
  } catch {
    return null;
  }
}

/** `D12 · rozhodnutie · Snowflake ID vo fleete` */
function decisionEntry(deps: RelatedDeps, ref: string, repo: string): string | null {
  const n = Number(ref.replace(/^D/i, ''));
  if (!Number.isFinite(n)) return null;
  const d: Decision | undefined = deps.ledger.listDecisions(repo).find((x) => x.n === n);
  if (d === undefined) return null;
  return clamp(`D${d.n} · rozhodnutie · ${untrustedSnippet(d.title, TITLE_MAX)}`);
}

function clamp(s: string, max = ENTRY_MAX): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}
