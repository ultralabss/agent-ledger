/**
 * Near-duplicate detection for item titles.
 *
 * The ledger collects the same problem twice all the time: a session hits
 * "demo.example.com does not exist" on Monday, another session hits it on
 * Wednesday and phrases it slightly differently. Exact-title matching never
 * catches those, so `POST /v1/items` compares a *normalised token set* against
 * the open items of the same repo and refuses with 409 above a threshold.
 *
 * Deliberately boring and synchronous: no index, no embedding, no async. A repo
 * has tens to low hundreds of open items, so an O(n) scan per create is cheaper
 * than any structure we would have to keep in sync with the md files.
 *
 * Two signals, because Jaccard alone is wrong at both ends:
 *  - *containment*: one title's tokens are a subset of the other's. This is the
 *    "Production without content" / "Production without content test3" case — Jaccard only
 *    gives 0.67 there, but a strict subset with enough tokens is the strongest
 *    duplicate signal we have, so it scores {@link CONTAINMENT_SCORE}.
 *  - *Jaccard*: symmetric overlap, for rephrasings that are not subsets.
 *
 * Both are computed on tokens with diacritics and stop words removed, so
 * "Production without content" and "production content" are the same thing.
 *
 * One more layer sits under that: tokens are mapped through the synonym
 * vocabulary and the English stemmer in `./dedupe-vocab.ts` before they are
 * compared, so "Implement Google sign-in" and "Add Google login" land on the
 * same token set. Because that makes everything more similar, the same module
 * supplies the brake — {@link hasPolarityConflict} vetoes pairs that differ in
 * a word carrying opposite meaning ("DB backup" vs "Restore DB from backup").
 */

import {
  applyPhrases,
  canonicalWord,
  hasPolarityConflict,
} from './dedupe-vocab.ts';

/** English filler that carries no topic. Kept short on purpose: every word
 *  here is a word that can no longer distinguish two items. */
const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'but', 'by', 'for', 'from', 'has',
  'have', 'if', 'in', 'is', 'it', 'its', 'no', 'not', 'of', 'on', 'or', 'that',
  'the', 'this', 'to', 'was', 'when', 'with',
  'after', 'before', 'between', 'during', 'into', 'via', 'without', 'still',
  'already', 'must', 'should', 'will', 'can',
]);

/** A subset match scores this. Above {@link DEFAULT_THRESHOLD} by design: a
 *  title whose every meaningful word appears in another open item is a
 *  duplicate far more often than not. */
export const CONTAINMENT_SCORE = 0.85;

/**
 * Chosen from the pairs in `dedupe.test.ts`, not guessed:
 *  - 0.65 keeps "Add index on items.repo" / "…items.session" apart (0.60),
 *  - and still catches rephrasings that share two of three content words.
 * Lower it and unrelated items in the same area start colliding; raise it and
 * only containment ever fires, which makes the Jaccard arm dead code.
 */
export const DEFAULT_THRESHOLD = 0.65;

/** Minimum token count before containment counts. A one-word title ("Deploy")
 *  is contained in half the ledger and must not 409 everything. */
const MIN_CONTAINMENT_TOKENS = 2;

/**
 * Ceiling for a pair that disagrees on an antonym group. Below
 * {@link DEFAULT_THRESHOLD} on purpose and by a wide margin: "Add login with
 * Google" / "Remove login with Google" share every other word, so only a
 * hard cap keeps them apart. It is a `min`, not a constant, so genuinely
 * unrelated opposites keep their low score.
 */
export const POLARITY_CONFLICT_CAP = 0.5;

/**
 * Canonical token sets are pure functions of the title and `findDuplicates`
 * re-derives the same candidate titles on every create, so memoise them.
 * Bounded and dumbly cleared rather than LRU-evicted — the working set is one
 * repo's open items, and a hub process that has seen 4096 distinct titles can
 * afford to redo the cheap part once.
 */
const CANON_CACHE = new Map<string, Set<string>>();
const CANON_CACHE_MAX = 4096;

/**
 * Lowercase, strip diacritics, drop punctuation. `NFD` + combining-mark removal
 * handles accented Latin alphabets without a transliteration table, and the
 * em dash / ellipsis that agents like to put in titles collapse to spaces.
 */
export function normalizeTitle(title: string): string {
  return title
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

/** Content tokens of a title: normalised, stop words and 1-char noise removed. */
export function titleTokens(title: string): Set<string> {
  const out = new Set<string>();
  for (const word of normalizeTitle(title).split(' ')) {
    if (word.length < 2) continue;
    if (STOP_WORDS.has(word)) continue;
    out.add(word);
  }
  return out;
}

/**
 * Content tokens mapped onto the canonical vocabulary — the set that
 * similarity is actually computed on. Phrases are rewritten first ("sign in"
 * is one concept, not two tokens), then each surviving word goes through
 * {@link canonicalWord}.
 */
export function canonicalTokens(title: string): ReadonlySet<string> {
  const cached = CANON_CACHE.get(title);
  // Read-only on purpose (audit D4): the returned Set lives in a process-wide
  // cache, so a caller mutating it would silently change every later 409
  // decision in every repo.
  if (cached !== undefined) return cached;

  const out = new Set<string>();
  for (const word of applyPhrases(normalizeTitle(title)).split(' ')) {
    if (word.length < 2) continue;
    if (STOP_WORDS.has(word)) continue;
    out.add(canonicalWord(word));
  }

  if (CANON_CACHE.size >= CANON_CACHE_MAX) CANON_CACHE.clear();
  CANON_CACHE.set(title, out);
  return out;
}

/** 0..1 similarity of two titles. Symmetric. */
export function titleSimilarity(a: string, b: string): number {
  return similarityOf(canonicalTokens(a), canonicalTokens(b), a, b);
}

/**
 * The scoring itself, on token sets the caller already has. Split out so the
 * O(n²) {@link findDuplicatePairs} can canonicalise each title once instead of
 * n times (audit D1/D2) — the memo cache cannot be relied on there, because a
 * repo with more distinct titles than `CANON_CACHE_MAX` thrashes it.
 */
function similarityOf(
  ta: ReadonlySet<string>,
  tb: ReadonlySet<string>,
  a: string,
  b: string,
): number {
  if (ta.size === 0 || tb.size === 0) {
    // Nothing but stop words on one side — fall back to exact normalised text
    // so "the" vs "the" still counts, but nothing else does.
    const na = normalizeTitle(a);
    const nb = normalizeTitle(b);
    return na.length > 0 && na === nb ? 1 : 0;
  }
  let shared = 0;
  for (const t of ta) if (tb.has(t)) shared += 1;
  const jaccard = shared / (ta.size + tb.size - shared);

  const smaller = ta.size <= tb.size ? ta : tb;
  const contained = shared === smaller.size && smaller.size >= MIN_CONTAINMENT_TOKENS;
  const score = contained ? Math.max(jaccard, CONTAINMENT_SCORE) : jaccard;

  // Veto last: an opposite-polarity pair is not a duplicate no matter how much
  // text it shares, and containment is exactly where it would otherwise win.
  return hasPolarityConflict(ta, tb) ? Math.min(score, POLARITY_CONFLICT_CAP) : score;
}

export interface DedupeCandidateInput {
  id: string;
  title: string;
}

export interface DedupeMatch {
  id: string;
  title: string;
  score: number;
}

/**
 * Best duplicate candidates for `title` among `open`, sorted by score.
 * `limit` caps the response so a 409 body stays small (SPEC: max 3).
 */
export function findDuplicates(
  title: string,
  open: readonly DedupeCandidateInput[],
  threshold: number = DEFAULT_THRESHOLD,
  limit = 3,
): DedupeMatch[] {
  const needle = canonicalTokens(title);
  const hits: DedupeMatch[] = [];
  for (const cand of open) {
    const score = similarityOf(needle, canonicalTokens(cand.title), title, cand.title);
    if (score >= threshold) hits.push({ id: cand.id, title: cand.title, score });
  }
  hits.sort((x, y) => y.score - x.score || x.id.localeCompare(y.id));
  return hits.slice(0, limit);
}

/**
 * Default ceiling on returned pairs. `GET /v1/dups` is synchronous on a
 * single-threaded hub, and canonicalisation pushed far more pairs over the
 * threshold than the lexical version did: a synthetic 5 000-item repo produced
 * 12.5M pairs, 17 s and 2.2 GB RSS (audit D1). Nobody grooms 12 M pairs — the
 * view is read top-down — so the result is capped and the scan stops early.
 */
export const MAX_DUPLICATE_PAIRS = 200;

/**
 * All likely duplicate pairs inside one set of open items — the `ledger dups`
 * grooming view. Still O(n²) comparisons, but each title is canonicalised
 * exactly once up front (not n times through the memo cache, which a large
 * repo thrashes), and at most `limit` pairs are ever held in memory.
 *
 * Two honest caveats:
 *  - this caps the *output*, not the input, so a repo big enough to make the
 *    comparison loop itself slow still needs a guard at the HTTP layer;
 *  - once the cap is hit the scan stops, so the result is the first `limit`
 *    pairs above the threshold sorted by score — not the globally best
 *    `limit`. For a grooming list that is the right trade; for anything that
 *    needs a total ranking it is not.
 */
export function findDuplicatePairs(
  items: readonly DedupeCandidateInput[],
  threshold: number = DEFAULT_THRESHOLD,
  limit: number = MAX_DUPLICATE_PAIRS,
): { a: DedupeCandidateInput; b: DedupeCandidateInput; score: number }[] {
  const tokens = items.map((it) => canonicalTokens(it.title));
  const pairs: { a: DedupeCandidateInput; b: DedupeCandidateInput; score: number }[] = [];
  let truncated = false;
  for (let i = 0; i < items.length && !truncated; i += 1) {
    for (let j = i + 1; j < items.length; j += 1) {
      const a = items[i] as DedupeCandidateInput;
      const b = items[j] as DedupeCandidateInput;
      const score = similarityOf(
        tokens[i] as ReadonlySet<string>,
        tokens[j] as ReadonlySet<string>,
        a.title,
        b.title,
      );
      if (score < threshold) continue;
      pairs.push({ a, b, score });
      if (pairs.length >= limit) {
        truncated = true;
        break;
      }
    }
  }
  pairs.sort((x, y) => y.score - x.score);
  return pairs;
}

/**
 * Input-side guard on `findDuplicatePairs` — the hub is single
 * threaded and the output cap above does not stop a large repo from making
 * the O(n²) *comparison loop itself* slow (the 5 000-item/17 s case the
 * docstring above already names). `GET /v1/dups` enforces this before
 * calling in, rather than inside this module, so a caller that already
 * knows its input is small (tests, a future bulk tool) is not forced to pay
 * the check too.
 */
export const MAX_DUPLICATE_ITEMS = 500;

/**
 * Same comparisons as {@link findDuplicatePairs}, but yields to the event
 * loop every `YIELD_EVERY_MS` of wall-clock work instead of running the
 * whole O(n²) scan in one synchronous stretch. Even with
 * {@link MAX_DUPLICATE_ITEMS} capping the input, a worst-case 500-item scan
 * is still ~125 000 comparisons — comfortably fast, but this is the version
 * `GET /v1/dups` calls so a slower future vocabulary pass cannot block every
 * other request on the hub for its duration.
 */
const YIELD_EVERY_MS = 20;

export async function findDuplicatePairsAsync(
  items: readonly DedupeCandidateInput[],
  threshold: number = DEFAULT_THRESHOLD,
  limit: number = MAX_DUPLICATE_PAIRS,
): Promise<{ a: DedupeCandidateInput; b: DedupeCandidateInput; score: number }[]> {
  const tokens = items.map((it) => canonicalTokens(it.title));
  const pairs: { a: DedupeCandidateInput; b: DedupeCandidateInput; score: number }[] = [];
  let truncated = false;
  let batchStart = Date.now();
  for (let i = 0; i < items.length && !truncated; i += 1) {
    for (let j = i + 1; j < items.length; j += 1) {
      const a = items[i] as DedupeCandidateInput;
      const b = items[j] as DedupeCandidateInput;
      const score = similarityOf(
        tokens[i] as ReadonlySet<string>,
        tokens[j] as ReadonlySet<string>,
        a.title,
        b.title,
      );
      if (score >= threshold) {
        pairs.push({ a, b, score });
        if (pairs.length >= limit) {
          truncated = true;
          break;
        }
      }
      if (Date.now() - batchStart >= YIELD_EVERY_MS) {
        await new Promise<void>((resolve) => setImmediate(resolve));
        batchStart = Date.now();
      }
    }
  }
  pairs.sort((x, y) => y.score - x.score);
  return pairs;
}
