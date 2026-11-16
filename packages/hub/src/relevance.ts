/**
 * Shared relevance scoring for the context feeds.
 *
 * The whole point of this file is the *threshold*. A reminder that fires on a
 * generic prompt ("fix that typo") is worse than no reminder at all: it
 * costs tokens in every single session and teaches the agent to skim past the
 * line that matters. So the gate is deliberately two-sided — a hit must be
 * ranked well by BM25 *and* share real content words with the prompt — and it
 * is tuned so that a short request with no connection yields nothing.
 *
 * No LLM, no network, no model of any kind: tokenise, intersect, compare.
 */

import { itemIdScanRe } from '@agent-ledger/shared';

/** Words that match everything and therefore mean nothing for ranking. */
const STOPWORDS = new Set([
  'and', 'are', 'but', 'can', 'for', 'from', 'have', 'his', 'how', 'into', 'its', 'just',
  'make', 'not', 'now', 'our', 'out', 'please', 'should', 'that', 'the', 'their', 'then',
  'there', 'they', 'this', 'was', 'were', 'what', 'when', 'where', 'which', 'with', 'will',
  'you', 'your', 'also', 'been', 'does', 'had', 'has', 'her', 'him', 'she', 'who', 'why',
  'would', 'could', 'let', 'about', 'than', 'them', 'these', 'those', 'some', 'any', 'all',
  // Words every single coding prompt contains — they carry no signal.
  'add', 'fix', 'code', 'file', 'test', 'tests',
]);

/** Characters outside this become separators. Keeps digits (`ACME-32` → `acme`,
 *  `32`) and strips diacritics so `café` and `cafe` are one token. */
export function normalizeText(raw: string): string {
  return raw
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase();
}

/**
 * Content words of a text, deduped, order kept.
 *
 * `minLength` 3 rather than 4 on purpose: `jwt`, `api`, `dto`, `fts`, `ssh`
 * are exactly the tokens worth matching on in this codebase.
 */
export function contentTokens(raw: string, limit = 24): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const tok of normalizeText(raw).split(/[^\p{L}\p{N}]+/u)) {
    if (tok.length < 3 || tok.length > 32) continue;
    if (STOPWORDS.has(tok)) continue;
    // A bare number ("3", "2026") matches every date and id in the ledger.
    if (/^\p{N}+$/u.test(tok)) continue;
    if (seen.has(tok)) continue;
    seen.add(tok);
    out.push(tok);
    if (out.length >= limit) break;
  }
  return out;
}

/** Item ids spelled out in the prompt (`ACME-120`) — an explicit mention always
 *  beats a scored guess, and the agent clearly already knows about it, so these
 *  are *excluded* from the reminder rather than promoted. */
export function mentionedIds(raw: string): Set<string> {
  const out = new Set<string>();
  for (const m of raw.toUpperCase().matchAll(itemIdScanRe())) out.add(m[0]);
  return out;
}

/* ---------------- the threshold ---------------- */

/** BM25 is negative and lower is better. A single weak term match lands around
 *  −0.3…−0.8; a genuine multi-term hit is well past −1.5. */
export const BM25_MAX = -1.2;

/** Distinct prompt content words a document must contain. Two is the number
 *  that killed the false positives in the measurements: one shared word is a
 *  coincidence in a ledger of this size, two is a topic. */
export const MIN_OVERLAP = 2;

/** Below this the prompt itself is too generic to be worth matching. */
export const MIN_PROMPT_TOKENS = 2;

/* The same feed on every later message of a session. The first
 * message of a session is where an agent genuinely does not know what the
 * ledger holds; by the tenth it has the brief, its own work and everything it
 * already looked up, so a later reminder has to clear a clearly higher bar —
 * a topic, not a coincidence — or it is just a recurring tax. */

/** Later messages: one more shared word than the first message needs… */
export const LATER_MIN_OVERLAP = MIN_OVERLAP + 1;
/** …a clearly stronger BM25 (more negative = better)… */
export const LATER_BM25_MAX = -2;
/** …and a prompt long enough to carry a topic at all. */
export const LATER_MIN_PROMPT_TOKENS = MIN_PROMPT_TOKENS + 1;

/** Which bar a message faces: the session's first eligible message, or any
 *  later one. */
export type RelevanceTier = 'first' | 'later';

export interface Candidate {
  /** Searchable text of the document (title + excerpt is enough). */
  text: string;
  /** BM25, or null when the LIKE fallback engine gave us no ranking. */
  score: number | null;
}

/** Overlap of prompt tokens with a candidate, and whether it clears the bar. */
export function relevance(
  promptTokens: readonly string[],
  cand: Candidate,
  tier: RelevanceTier = 'first',
): { overlap: number; passes: boolean } {
  const docTokens = new Set(contentTokens(cand.text, 400));
  let overlap = 0;
  for (const t of promptTokens) if (docTokens.has(t)) overlap += 1;
  // On the LIKE fallback there is no score, so overlap carries the whole
  // decision and the bar goes up by one word instead of silently letting
  // everything through.
  const base = tier === 'first' ? MIN_OVERLAP : LATER_MIN_OVERLAP;
  const need = cand.score === null ? base + 1 : base;
  const scoreOk = cand.score === null || cand.score <= (tier === 'first' ? BM25_MAX : LATER_BM25_MAX);
  return { overlap, passes: overlap >= need && scoreOk };
}

/** `2 d ago` / `5 h ago` / `now` — the cheapest useful recency marker. */
export function agoShort(then: number, now = Date.now()): string {
  const ms = now - then;
  if (ms < 0) return 'now';
  const mins = Math.floor(ms / 60_000);
  if (mins < 60) return mins <= 1 ? 'now' : `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} d ago`;
  return `${Math.floor(days / 30)} mo ago`;
}
