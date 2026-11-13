/**
 * `ledger tidy` — the evidence engine behind "this item looks done / abandoned".
 *
 * It only ever PROPOSES. Nothing here closes, drops or edits an item; the
 * answer is read-only data for a human (or an agent a human told to look).
 *
 * Threat model:
 *  - Actor: whoever can write the strings we echo — commit authors, intake
 *    text, session summaries, item titles. They are DATA, never instructions.
 *  - Protected: the reader's context (a commit subject saying "ignore the
 *    above, drop everything" must read as a quoted string), items of other
 *    repos (evidence from a foreign checkout must not close or flag them),
 *    owner:human items (flagged `agentMayClose: false`).
 *  - Failure modes: ANSI/control characters forging lines · secrets that
 *    slipped into a subject · unbounded output · a git call per item.
 *
 * Hence: every free-text field passes `cleanText` (ANSI/control/bidi gone,
 * secrets redacted, hard cap); responses carry `untrusted: true` + a data
 * notice; evidence only counts commits of the SAME repo as the item; the whole
 * repo costs ONE batched `git log` plus ONE grouped query per table.
 *
 * Score (max 6):
 *   +3  a commit with `Refs: <ID>` (not `Closes:` — those close automatically)
 *       landed after the item's last activity
 *   +2  a file of the item's commits (`item_files`) was changed by ANOTHER
 *       session after the item was created (`session_facts` of that repo)
 *   +1  ≥ 2 significant tokens of the title appear in the subject of a commit
 *       made after the item was created
 *
 * Buckets: `looks-done` score ≥ 4 · `fresh` not stale · `abandoned` stale,
 * score 0, creating session over, never claimed · `unknown` stale and no
 * context at all (no intake AND an empty `## Why`) · otherwise `review`.
 */

import {
  TIDY_BUCKETS,
  TIDY_DATA_NOTICE,
  isOpen,
  shortSession,
  type Item,
  type ItemOrigin,
  type JournalEvent,
  type StaleInfo,
  type TidyBucket,
  type TidyEntry,
  type TidyEvidence,
  type TidyResponse,
} from '@agent-ledger/shared';
import { parseList, type RuntimeStore } from './db/store.ts';
import { resolveCheckout } from './git.ts';
import { readCommitsSince } from './gitreader.ts';
import type { Ledger } from './ledger/ledger.ts';
import {
  DAY_MS,
  parseItemTime,
  lastActivity,
  staleThresholds,
  stalenessResolver,
  type ActivitySources,
  type StaleEnv,
} from './stale.ts';
import { cleanText } from './why.ts';

export const TIDY_DEFAULT_LIMIT = 20;
const SUMMARY_MAX = 300;
const INTAKE_MAX = 300;
const SUBJECT_MAX = 120;
const TOP_FILES = 5;
/** Never look further back than this for commits. */
const MAX_LOOKBACK_MS = 365 * DAY_MS;
const COMMIT_LIMIT = 1_000;
const FACT_ROWS = 200;

/** A commit of ONE repo, reduced to what the engine reads. `repo` is the slug
 *  of the checkout it was read from — evidence for an item of another repo is
 *  ignored. */
export interface TidyCommit {
  repo: string;
  sha: string;
  subject: string;
  atMs: number;
  /** `Refs: ID` trailers, upper-case. */
  refs: readonly string[];
}

export interface ItemFileRow {
  path: string;
  n: number;
  last_at: number;
}

export interface SessionFileFact {
  session: string;
  last_at: number;
  files: readonly string[];
}

/* ---------------- activity (runtime DB), one grouped query per repo ---------------- */

export interface ActivityIndex {
  sources(item: Item): ActivitySources;
  files(item: Item): ItemFileRow[];
  /** A claim/lease on the item exists or ever existed. */
  everLeased(item: Item): boolean;
}

export function activityIndex(store: RuntimeStore | undefined): ActivityIndex {
  const filesByRepo = new Map<string, Map<string, ItemFileRow[]>>();
  const leasesByRepo = new Map<string, Map<string, { last_at: number; n: number }>>();

  const filesOf = (repo: string): Map<string, ItemFileRow[]> => {
    let m = filesByRepo.get(repo);
    if (m) return m;
    m = new Map();
    if (store) {
      try {
        for (const r of store.itemFilesByRepo(repo)) {
          const list = m.get(r.item_id) ?? [];
          list.push({ path: r.path, n: r.n, last_at: r.last_at });
          m.set(r.item_id, list);
        }
      } catch {
        // A cache table: no rows means no evidence, never a failed brief.
      }
    }
    filesByRepo.set(repo, m);
    return m;
  };
  const leasesOf = (repo: string): Map<string, { last_at: number; n: number }> => {
    let m = leasesByRepo.get(repo);
    if (m) return m;
    m = new Map();
    if (store) {
      try {
        for (const r of store.leaseActivityByRepo(repo)) m.set(r.item_id, { last_at: r.last_at, n: r.n });
      } catch {
        // see above
      }
    }
    leasesByRepo.set(repo, m);
    return m;
  };

  return {
    sources(item) {
      const rows = filesOf(item.fm.repo).get(item.fm.id);
      const lease = leasesOf(item.fm.repo).get(item.fm.id);
      return {
        itemFilesLastAt: rows && rows.length > 0 ? Math.max(...rows.map((r) => r.last_at)) : null,
        lastLeaseAt: lease ? lease.last_at : null,
      };
    },
    files: (item) => filesOf(item.fm.repo).get(item.fm.id) ?? [],
    everLeased: (item) => (leasesOf(item.fm.repo).get(item.fm.id)?.n ?? 0) > 0,
  };
}

/* ---------------- commits: ONE git log per repo, briefly cached ---------------- */

const COMMIT_TTL_MS = 60_000;
const COMMIT_CACHE_MAX = 16;
const commitCache = new Map<string, { at: number; sinceMs: number; commits: TidyCommit[] }>();

export function clearTidyCommitCache(): void {
  commitCache.clear();
}

/** Oldest `created` among the repo's open items, clamped to one year back. */
export function oldestOpenCreated(ledger: Ledger, repo: string, now: number = Date.now()): number {
  let oldest = now;
  for (const it of ledger.listItems({ repo })) {
    if (!isOpen(it.fm.status)) continue;
    const t = parseItemTime(it.fm.created);
    if (t !== null && t < oldest) oldest = t;
  }
  return Math.max(oldest, now - MAX_LOOKBACK_MS);
}

/**
 * Commits of the repo's own checkout since `sinceMs` (one `git log`, 60 s cache
 * per checkout). `null` = no readable checkout / git failed — callers say
 * "no commit evidence", they do not guess.
 */
export async function loadTidyCommits(
  ledger: Ledger,
  repo: string,
  sinceMs: number,
  now: number = Date.now(),
  timeoutMs = 8_000,
): Promise<TidyCommit[] | null> {
  const path = ledger.repoPath(repo);
  if (path === null) return null;
  let checkout: string | null;
  try {
    checkout = (await resolveCheckout(path))?.checkout ?? null;
  } catch {
    return null;
  }
  if (checkout === null) return null;

  const cached = commitCache.get(checkout);
  if (cached && now - cached.at < COMMIT_TTL_MS && cached.sinceMs <= sinceMs) return cached.commits;

  let raw;
  try {
    raw = await readCommitsSince(checkout, sinceMs, COMMIT_LIMIT, timeoutMs);
  } catch {
    return null;
  }
  const commits: TidyCommit[] = raw.map((c) => ({
    repo,
    sha: c.sha,
    subject: cleanText(c.subject, SUBJECT_MAX),
    atMs: Date.parse(c.at),
    refs: c.refs,
  }));
  if (commitCache.size >= COMMIT_CACHE_MAX) {
    const first = commitCache.keys().next().value;
    if (first !== undefined) commitCache.delete(first);
  }
  commitCache.set(checkout, { at: now, sinceMs, commits });
  return commits;
}

/**
 * Commits for the brief: skipped (null) when no open item is old enough to be
 * stale — the common case, and then SessionStart pays no extra git call — and
 * on a short timeout otherwise. Never throws.
 */
export async function loadCommitsForBrief(
  ledger: Ledger,
  repo: string,
  env: StaleEnv = process.env,
  now: number = Date.now(),
): Promise<TidyCommit[] | null> {
  try {
    const oldest = oldestOpenCreated(ledger, repo, now);
    const t = staleThresholds(env);
    if (now - oldest < Math.min(t.hot, t.cold, t.proposed) * DAY_MS) return null;
    return await loadTidyCommits(ledger, repo, oldest, now, 3_000);
  } catch {
    return null;
  }
}

/* ---------------- scoring ---------------- */

const STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'from', 'into', 'that', 'this', 'when', 'then', 'than', 'not',
  'are', 'was', 'were', 'add', 'fix', 'update', 'use', 'using', 'make', 'new', 'via', 'support',
  'implement', 'item', 'task', 'todo', 'check', 'issue', 'need', 'needs', 'should', 'must',
  'can', 'all', 'any', 'more', 'also', 'only', 'still', 'some', 'get', 'set', 'each', 'per',
  'too', 'its', 'our', 'out', 'has', 'have', 'had', 'but', 'bug', 'feat', 'chore', 'docs',
  'test', 'tests', 'remove', 'move', 'change', 'improve', 'refactor', 'wip',
]);

/** Lower-case significant words of a title or subject (diacritics folded). */
export function significantTokens(text: string): Set<string> {
  const out = new Set<string>();
  const folded = text.toLowerCase().normalize('NFKD').replace(/\p{M}+/gu, '');
  for (const t of folded.split(/[^\p{L}\p{N}]+/u)) {
    if (t.length < 3 || /^\d+$/.test(t) || STOPWORDS.has(t)) continue;
    out.add(t);
  }
  return out;
}

const subjectTokens = new WeakMap<TidyCommit, Set<string>>();
function tokensOfCommit(c: TidyCommit): Set<string> {
  let t = subjectTokens.get(c);
  if (!t) {
    t = significantTokens(c.subject);
    subjectTokens.set(c, t);
  }
  return t;
}

export interface ClassifyInput {
  item: Item;
  info: StaleInfo;
  /** `lastActivity()` of the item, ms. */
  lastMs: number;
  /** Any repos — commits of another repo than the item's are ignored. */
  commits: readonly TidyCommit[];
  files: readonly ItemFileRow[];
  /** `session_facts` of the item's repo. */
  facts: readonly SessionFileFact[];
  /** Lazy: only asked when the item is stale with no evidence. */
  creatorEnded: boolean | (() => boolean);
  everClaimed: boolean | (() => boolean);
}

const truthy = (v: boolean | (() => boolean)): boolean => (typeof v === 'function' ? v() : v);

export interface Classification {
  bucket: TidyBucket;
  score: number;
  evidence: TidyEvidence[];
}

const clean = (s: string, max: number): string => cleanText(s, max);

export function classify(input: ClassifyInput): Classification {
  const { item, info, lastMs } = input;
  const evidence: TidyEvidence[] = [];
  let score = 0;
  const createdMs = parseItemTime(item.fm.created) ?? 0;
  const own = input.commits
    .filter((c) => c.repo === item.fm.repo && Number.isFinite(c.atMs))
    .sort((a, b) => b.atMs - a.atMs);

  // +3: `Refs: <ID>` after the last activity (`Closes:` is handled elsewhere).
  const refs = own.filter((c) => c.atMs > lastMs && c.refs.includes(item.fm.id));
  const newestRef = refs[0];
  if (newestRef) {
    score += 3;
    evidence.push({
      kind: 'refs-commit',
      sha: newestRef.sha,
      subject: clean(newestRef.subject, SUBJECT_MAX),
      detail: `${refs.length} commit${refs.length === 1 ? '' : 's'} with "Refs: ${item.fm.id}" after the last ledger activity`,
    });
  }

  // +2: files of the item's commits changed by ANOTHER session after creation.
  if (input.files.length > 0) {
    const paths = new Set(input.files.map((f) => f.path));
    const sessions: { session: string; hits: string[] }[] = [];
    for (const fact of input.facts) {
      if (fact.session === item.fm.source.session) continue;
      if (fact.last_at <= createdMs) continue;
      const hits = fact.files.filter((f) => paths.has(f));
      if (hits.length > 0) sessions.push({ session: fact.session, hits });
    }
    const first = sessions[0];
    if (first) {
      score += 2;
      evidence.push({
        kind: 'other-session-files',
        detail: clean(
          `session ${shortSession(first.session)} changed ${first.hits.slice(0, 3).join(', ')}${
            first.hits.length > 3 ? ` +${first.hits.length - 3}` : ''
          }${sessions.length > 1 ? ` (${sessions.length} sessions)` : ''}`,
          240,
        ),
      });
    }
  }

  // +1: the title's words show up in a later commit subject.
  const titleTokens = significantTokens(item.fm.title);
  if (titleTokens.size >= 2) {
    for (const c of own) {
      if (c.atMs <= createdMs) continue;
      const shared = [...tokensOfCommit(c)].filter((t) => titleTokens.has(t));
      if (shared.length < 2) continue;
      score += 1;
      evidence.push({
        kind: 'title-match',
        sha: c.sha,
        subject: clean(c.subject, SUBJECT_MAX),
        detail: clean(`shares ${shared.slice(0, 4).join(', ')} with the item title`, 160),
      });
      break;
    }
  }

  let bucket: TidyBucket;
  if (score >= 4) bucket = 'looks-done';
  else if (!info.stale) bucket = 'fresh';
  else if (score === 0 && truthy(input.creatorEnded) && !truthy(input.everClaimed)) bucket = 'abandoned';
  else if (item.fm.intake === null && item.why.trim() === '') bucket = 'unknown';
  else bucket = 'review';
  return { bucket, score, evidence };
}

const BUCKET_RANK: Record<TidyBucket, number> = {
  'looks-done': 0,
  abandoned: 1,
  unknown: 2,
  review: 3,
  fresh: 4,
};

/* ---------------- one repo ---------------- */

export interface TidyRow extends Classification {
  item: Item;
  info: StaleInfo;
  lastMs: number;
}

export interface TidyDeps {
  ledger: Ledger;
  store?: RuntimeStore | undefined;
  /** Commits of the repo's checkout; `null`/absent = no git evidence. */
  commits?: readonly TidyCommit[] | null | undefined;
  /** Is the creating session over? Default: no runtime row, or `ended_at` set. */
  sessionEnded?: ((sessionId: string) => boolean) | undefined;
  now?: number | undefined;
  env?: StaleEnv | undefined;
  activity?: ActivityIndex | undefined;
}

export function lookupItem(ledger: Ledger): (id: string) => Item | undefined {
  return (id) => {
    try {
      return ledger.getItem(id).item;
    } catch {
      return undefined;
    }
  };
}

export interface RepoAnalysis {
  rows: TidyRow[];
  open: number;
  stale: number;
  counts: Record<TidyBucket, number>;
  thresholds: { hot: number; cold: number; proposed: number };
  /** The index the analysis read, so a caller can reuse its cached queries. */
  activity: ActivityIndex;
}

export function analyzeRepo(deps: TidyDeps, repo: string): RepoAnalysis {
  const now = deps.now ?? Date.now();
  const env = deps.env ?? process.env;
  const act = deps.activity ?? activityIndex(deps.store);
  const resolve = stalenessResolver(lookupItem(deps.ledger), (i) => act.sources(i), now, env);
  const commits = deps.commits ?? [];
  const facts: SessionFileFact[] = [];
  if (deps.store) {
    try {
      for (const f of deps.store.sessionFactsRecent(repo, FACT_ROWS)) {
        facts.push({ session: f.session, last_at: f.last_at, files: parseList(f.files) });
      }
    } catch {
      // runtime cache only
    }
  }
  const ended =
    deps.sessionEnded ??
    ((id: string): boolean => {
      const row = deps.store?.getSession(id) ?? null;
      return row === null || row.ended_at !== null;
    });

  const counts = Object.fromEntries(TIDY_BUCKETS.map((b) => [b, 0])) as Record<TidyBucket, number>;
  const rows: TidyRow[] = [];
  let open = 0;
  let stale = 0;
  for (const item of deps.ledger.listItems({ repo })) {
    if (!isOpen(item.fm.status)) continue;
    open += 1;
    const info = resolve(item);
    if (info.stale) stale += 1;
    const lastMs = lastActivity(item, act.sources(item), now);
    const src = item.fm.source.session;
    const c = classify({
      item,
      info,
      lastMs,
      commits,
      files: act.files(item),
      facts,
      // No creating session on record = nothing is running it.
      creatorEnded: () => (src === null ? true : ended(src)),
      everClaimed: () => item.fm.claimed_by !== null || act.everLeased(item),
    });
    counts[c.bucket] += 1;
    rows.push({ item, info, lastMs, ...c });
  }
  rows.sort(
    (a, b) =>
      BUCKET_RANK[a.bucket] - BUCKET_RANK[b.bucket] ||
      b.score - a.score ||
      b.info.ageDays - a.info.ageDays ||
      a.item.fm.id.localeCompare(b.item.fm.id),
  );
  return { rows, open, stale, counts, thresholds: staleThresholds(env), activity: act };
}

/* ---------------- origin ---------------- */

export interface OriginDeps {
  ledger: Ledger;
  store?: RuntimeStore | undefined;
  commits?: readonly TidyCommit[] | null | undefined;
  activity?: ActivityIndex | undefined;
  /** Journal events of the item's repo (read once per request). */
  journal?: readonly JournalEvent[] | undefined;
}

export function originOf(deps: OriginDeps, item: Item): ItemOrigin {
  const act = deps.activity ?? activityIndex(deps.store);
  const createdMs = parseItemTime(item.fm.created) ?? 0;
  const src = item.fm.source.session;

  let sessionSummary: string | null = null;
  if (src !== null) {
    const tag = shortSession(src);
    const journal = deps.journal ?? deps.ledger.listJournal(item.fm.repo);
    let best: JournalEvent | null = null;
    for (const ev of journal) {
      if (ev.type !== 'session.summary' || ev.session !== tag) continue;
      if (best === null || ev.at > best.at) best = ev;
    }
    if (best) sessionSummary = cleanText(best.fields.join(' · '), SUMMARY_MAX) || null;
  }

  let intake: string | null = null;
  if (item.fm.intake !== null) {
    try {
      intake = cleanText(deps.ledger.getIntake(item.fm.intake).text, INTAKE_MAX) || null;
    } catch {
      intake = null;
    }
  }

  let first: TidyCommit | null = null;
  for (const c of deps.commits ?? []) {
    if (c.repo !== item.fm.repo || !Number.isFinite(c.atMs) || c.atMs <= createdMs) continue;
    if (first === null || c.atMs < first.atMs) first = c;
  }

  const topFiles = [...act.files(item)]
    .sort((a, b) => b.last_at - a.last_at || b.n - a.n || a.path.localeCompare(b.path))
    .slice(0, TOP_FILES)
    .map((f) => cleanText(f.path, 160))
    .filter((p) => p !== '');

  return {
    id: item.fm.id,
    created: cleanText(item.fm.created, 40),
    session: src === null ? null : cleanText(src, 64) || null,
    sessionSummary,
    intake,
    firstCommitAfterCreated: first
      ? { sha: first.sha, subject: cleanText(first.subject, SUBJECT_MAX) }
      : null,
    topFiles,
    untrusted: true,
    data_notice: TIDY_DATA_NOTICE,
  };
}

/* ---------------- the answer ---------------- */

function recommend(row: TidyRow): string {
  const id = row.item.fm.id;
  const keep = `or keep it: ledger note ${id} "tidy: kept — <reason>" (resets the age)`;
  const hit = row.evidence.find((e) => e.sha !== undefined);
  switch (row.bucket) {
    case 'looks-done':
      return `Likely done${hit ? ` (commit ${hit.sha?.slice(0, 7)})` : ''} — verify the work, then close ${id}; ${keep}.`;
    case 'abandoned':
      return `No sign of work and the session that created it is over — drop ${id} with a reason; ${keep}.`;
    case 'unknown':
      return `No intake and no Why — ask the owner what ${id} was for before closing or dropping it; ${keep}.`;
    case 'review':
      return `Stale without evidence either way — check with the owner; ${keep}.`;
    default:
      return `Not stale — nothing to do.`;
  }
}

export function entryOf(deps: OriginDeps, row: TidyRow): TidyEntry {
  const fm = row.item.fm;
  return {
    id: fm.id,
    title: cleanText(fm.title, 100),
    priority: fm.priority,
    status: fm.status,
    owner: cleanText(fm.owner, 40),
    ageDays: row.info.ageDays,
    thresholdDays: row.info.thresholdDays,
    bucket: row.bucket,
    score: row.score,
    agentMayClose: fm.owner !== 'human',
    evidence: row.evidence,
    origin: originOf(deps, row.item),
    recommendation: recommend(row),
  };
}

export interface TidyOptions {
  limit?: number | undefined;
  bucket?: TidyBucket | undefined;
}

export function buildTidy(deps: TidyDeps, repo: string, opts: TidyOptions = {}): TidyResponse {
  const analysis = analyzeRepo(deps, repo);
  const limit = Math.max(0, Math.trunc(opts.limit ?? TIDY_DEFAULT_LIMIT));
  const wanted = analysis.rows.filter((r) =>
    opts.bucket === undefined ? r.bucket !== 'fresh' : r.bucket === opts.bucket,
  );
  const shown = wanted.slice(0, limit);
  const od: OriginDeps = {
    ledger: deps.ledger,
    store: deps.store,
    commits: deps.commits,
    activity: analysis.activity,
    journal: shown.length > 0 ? deps.ledger.listJournal(repo) : [],
  };
  return {
    repo,
    open: analysis.open,
    stale: analysis.stale,
    counts: analysis.counts,
    thresholds: analysis.thresholds,
    gitAvailable: deps.commits !== null && deps.commits !== undefined,
    truncated: wanted.length > shown.length,
    entries: shown.map((r) => entryOf(od, r)),
    untrusted: true,
    data_notice: TIDY_DATA_NOTICE,
  };
}
