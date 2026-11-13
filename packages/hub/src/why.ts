/**
 * `ledger why <path|dir|glob>` — "who touched this and why", from facts the hub
 * already holds. Metadata only: this module never opens a file of the repo.
 *
 * Threat model:
 *  - Actor: an agent (or anything with the hub token) asking about a path; and
 *    whoever wrote the text it gets back — item titles, claim intents, session
 *    summaries and decisions are DATA that may carry a prompt injection.
 *  - Protected: files outside the repo / behind symlinks (existence and names),
 *    gitignored paths (often `.env`, keys), secrets that slipped into a title,
 *    the reader's context (an answer that reads like instructions).
 *  - Failure modes: `..` / absolute path / symlink out of the checkout · a glob
 *    that fans out over the whole repo · an ignored path whose history is
 *    listed anyway · an ANSI/newline-laden title forging a line · an unbounded
 *    answer.
 *
 * Hence: the path is resolved with `realpath` and must stay inside the repo's
 * checkout; globs are `*`/`**`/`?` only; every candidate path is checked with
 * `git check-ignore` and an ignored or unverifiable one yields nothing (fail
 * closed); all free text goes through `cleanText` (ANSI/control/bidi stripped,
 * secrets redacted, hard cap) and the answer carries `WHY_DATA_NOTICE`; every
 * list has a cap and git is only ever spawned with an argv array.
 *
 * Sources, strongest first: live claims (`leases`, with intent), `item_files`
 * (files of commits whose trailer named an item), `touched` (uncommitted), the
 * summaries in `session_facts`, decisions/journal that name the path, and the
 * git history of the path with `Refs:`/`Closes:` trailers.
 */

import { isAbsolute, join, relative, sep } from 'node:path';
import type { ItemStatus, WhyView } from '@agent-ledger/shared';
import {
  isOpen,
  redactSecrets,
  sanitizeField,
  shortSession,
  WHY_DATA_NOTICE,
} from '@agent-ledger/shared';
import type { RuntimeStore } from './db/store.ts';
import { parseList } from './db/store.ts';
import { invalid } from './errors.ts';
import { resolveCheckout } from './git.ts';
import { checkIgnored, readPathHistory } from './gitreader.ts';
import { matchGlob } from './guard/globs.ts';
import type { Ledger } from './ledger/ledger.ts';
import { realpathOrParent } from './sessions.ts';
import type { Sessions } from './sessions.ts';

/** Raw `path` parameter, absolute or relative. */
export const WHY_INPUT_MAX = 400;
/** A normalized repo-relative path/glob. */
const REL_MAX = 240;
/** Distinct paths an answer is built from; the rest is `truncated`. */
export const WHY_MAX_PATHS = 25;
export const WHY_MAX_ITEMS = 10;
export const WHY_MAX_CLAIMS = 5;
export const WHY_MAX_MENTIONS = 5;
export const WHY_MAX_SESSIONS = 5;
export const WHY_MAX_UNCOMMITTED = 5;
/** Commits read from git per request. */
export const WHY_GIT_COMMITS = 50;
/** Rows read per ledger table before matching. */
const DB_ROWS = 500;
const FACT_ROWS = 100;
const TITLE_MAX = 100;
const INTENT_MAX = 100;
const WHY_TEXT_MAX = 100;
const MENTION_MAX = 100;
/** Sources are bounded text; cut before scanning so a huge field costs nothing. */
const RAW_TEXT_MAX = 2_000;

/* ---------------- text ---------------- */

// ESC [ … final byte  ·  ESC ] … BEL|ST  ·  any other ESC + one char.
const ANSI_CSI = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g;
const ANSI_OTHER = /\u001b[@-Z\\-_]/g;
// Zero-width and bidi controls can reorder or hide text on a terminal.
const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;

/**
 * One line of data from the ledger or git, safe to print: ANSI sequences,
 * control characters, newlines and bidi tricks gone, secrets redacted (before
 * the cut, so a secret cannot survive as a truncated prefix), length capped.
 */
export function cleanText(value: unknown, max: number): string {
  if (typeof value !== 'string' || value === '') return '';
  const bounded = value.length > RAW_TEXT_MAX ? value.slice(0, RAW_TEXT_MAX) : value;
  const plain = bounded
    .replace(ANSI_OSC, '')
    .replace(ANSI_CSI, '')
    .replace(ANSI_OTHER, '')
    .replace(INVISIBLE, '');
  return sanitizeField(redactSecrets(plain).text, max);
}

/* ---------------- path spec ---------------- */

export interface WhySpec {
  kind: 'path' | 'glob';
  /** Repo-relative path (kind `path`) or glob (kind `glob`), `/`-separated. */
  rel: string;
  /** Literal directory part before the first wildcard (`''` = repo root);
   *  for kind `path` it is `rel` itself. */
  prefix: string;
}

// Letters, digits and the punctuation file names use; `*`/`?` are the only
// wildcards. No `[ ] { } ! \` — a glob here is never a regex or a brace set.
const GLOB_CHARS = /^[\p{L}\p{N}._@+\-/*? ]+$/u;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * Validate and normalize the raw `path` against the repo checkout. Throws a 422
 * `LedgerError` without echoing the input (it may be hostile or contain a
 * real path outside the repo).
 */
export async function parseWhySpec(raw: unknown, checkout: string): Promise<WhySpec> {
  if (typeof raw !== 'string' || raw.length === 0) throw invalid('path is required');
  if (raw.length > WHY_INPUT_MAX) throw invalid('path is too long');
  if (CONTROL.test(raw) || raw.includes('\\')) {
    throw invalid('path must not contain control characters or backslashes');
  }
  const wild = /[*?]/.test(raw);
  if (wild) {
    if (!GLOB_CHARS.test(raw) || /\*{3,}/.test(raw)) {
      throw invalid('glob supports only * ** ? and plain path characters');
    }
    if ((raw.match(/[*?]/g) ?? []).length > 12) throw invalid('glob has too many wildcards');
  }
  const segs = raw.split('/').filter((s) => s !== '' && s !== '.');
  if (segs.includes('..')) throw invalid('path must not contain ".."');
  const firstWild = wild ? segs.findIndex((s) => /[*?]/.test(s)) : -1;
  const literal = firstWild < 0 ? segs : segs.slice(0, firstWild);
  const wildTail = firstWild < 0 ? [] : segs.slice(firstWild);

  // Relative input is anchored at the checkout (the CLI sends absolute paths).
  const base = raw.startsWith('/') ? `/${literal.join('/')}` : join(checkout, ...literal);
  const real = await realpathOrParent(base);
  if (real === null) throw invalid('path cannot be resolved');
  const back = relative(checkout, real);
  // `realpath` followed every existing symlink, so this is also the symlink
  // check: a link out of the repo resolves to something outside it.
  if (back.startsWith('..') || isAbsolute(back)) throw invalid('path is outside the repo');
  const prefix = back === '' ? '' : back.split(sep).join('/');
  if (prefix.split('/').includes('.git')) throw invalid('path is inside .git');

  if (!wild) {
    if (prefix === '') throw invalid('name a file, a directory or a glob inside the repo, not its root');
    if (prefix.length > REL_MAX || CONTROL.test(prefix)) throw invalid('path is too long');
    return { kind: 'path', rel: prefix, prefix };
  }
  if (/[[\]{}\\]/.test(prefix)) throw invalid('glob prefix contains unsupported characters');
  const rel = [...(prefix === '' ? [] : [prefix]), ...wildTail].join('/');
  if (rel.length > REL_MAX) throw invalid('glob is too long');
  return { kind: 'glob', rel, prefix };
}

function matcherOf(spec: WhySpec): (path: string) => boolean {
  if (spec.kind === 'glob') return (p) => matchGlob(spec.rel, p);
  // A file or a directory: itself or anything below it. Not `matchGlob`: a real
  // name like `app/[id]/page.tsx` must not be read as a character class.
  return (p) => p === spec.rel || p.startsWith(`${spec.rel}/`);
}

/** Text that names the path, for decisions/journal. Needs some substance, else
 *  every note mentioning "a.ts" would hit. */
function needleOf(spec: WhySpec): string | null {
  const n = spec.kind === 'path' ? spec.rel : spec.prefix;
  return n.length >= 3 ? n : null;
}

/** `needle` occurs in `text` as a whole path (not inside a longer word). */
export function mentionsPath(text: string, needle: string): boolean {
  let from = 0;
  for (;;) {
    const at = text.indexOf(needle, from);
    if (at < 0) return false;
    const before = at === 0 ? '' : (text[at - 1] as string);
    const after = text[at + needle.length] ?? '';
    const okBefore = before === '' || !/[\p{L}\p{N}._\-/]/u.test(before);
    const okAfter = after === '' || !/[\p{L}\p{N}_\-]/u.test(after);
    if (okBefore && okAfter) return true;
    from = at + 1;
  }
}

/** Does a claim pattern concern the asked path? Claims are intent, so this errs
 *  towards "yes" for a directory/glob question. */
function claimCovers(spec: WhySpec, pattern: string): boolean {
  const p = pattern.replace(/^\.\//, '').replace(/^\/+/, '').replace(/\/+$/, '');
  if (p === '') return false;
  const wildAt = p.search(/[*?[]/);
  const lit = wildAt < 0 ? p : p.slice(0, wildAt).replace(/\/[^/]*$/, '');
  if (spec.kind === 'path') {
    if (matchGlob(pattern, spec.rel)) return true;
    // A narrower claim inside the asked directory.
    return lit !== '' && lit.startsWith(`${spec.rel}/`);
  }
  const a = spec.prefix;
  if (a === '' || lit === '') return true;
  return a === lit || a.startsWith(`${lit}/`) || lit.startsWith(`${a}/`);
}

/* ---------------- the answer ---------------- */

export interface WhyDeps {
  ledger: Ledger;
  store: RuntimeStore;
  sessions: Sessions;
  now?: () => number;
}

interface PathHit {
  path: string;
  at: number;
}

const iso = (ms: number): string => new Date(ms).toISOString();

function emptyView(repo: string, spec: WhySpec): WhyView {
  return {
    notice: WHY_DATA_NOTICE,
    repo,
    path: cleanText(spec.rel, REL_MAX),
    kind: spec.kind,
    ignored: false,
    note: null,
    items: [],
    claims: [],
    mentions: [],
    sessions: [],
    last_changed: null,
    uncommitted: [],
    matched_paths: 0,
    truncated: false,
  };
}

export async function whyOfPath(deps: WhyDeps, slug: string, rawPath: unknown): Promise<WhyView> {
  const { ledger, store, sessions } = deps;
  const repoPath = ledger.repoPath(slug);
  const layout = repoPath === null ? null : await resolveCheckout(repoPath);
  if (layout === null) throw invalid(`${slug} has no git checkout — nothing to look a path up in`);
  const checkout = layout.checkout;
  const spec = await parseWhySpec(rawPath, checkout);
  const view = emptyView(slug, spec);

  // Ignore state is decided first and cached: it gates BOTH the ledger rows and
  // the git history, and a failure to decide counts as ignored.
  const ignoreCache = new Map<string, boolean>();
  const isHidden = async (rel: string): Promise<boolean> => {
    const hit = ignoreCache.get(rel);
    if (hit !== undefined) return hit;
    const state = await checkIgnored(checkout, rel);
    const hidden = state !== 'not-ignored';
    ignoreCache.set(rel, hidden);
    return hidden;
  };
  if (spec.prefix !== '' && (await isHidden(spec.prefix))) {
    view.ignored = true;
    view.note = 'ignored by git (or not verifiable) — nothing is recorded or shown for it';
    return view;
  }

  const matches = matcherOf(spec);
  const nowMs = (deps.now ?? Date.now)();

  /* ---- ledger rows ---- */
  const itemRows = store
    .itemFilesUnder(slug, spec.prefix, DB_ROWS)
    .filter((r) => matches(r.path));
  const touchedRows = sessions
    .touchedFor({ repo: slug })
    .filter((t) => matches(t.rel_path));
  const factRows: { session: string; at: number; why: string | null; paths: string[] }[] = [];
  for (const f of store.sessionFactsRecent(slug, FACT_ROWS)) {
    const paths = parseList(f.files).filter(matches);
    if (paths.length > 0) factRows.push({ session: f.session, at: f.last_at, why: f.why, paths });
  }

  // Candidate paths, newest first, capped — and each one checked for ignore.
  const seen = new Map<string, number>();
  const bump = (path: string, at: number): void => {
    if (path.length > REL_MAX || CONTROL.test(path)) return;
    seen.set(path, Math.max(seen.get(path) ?? 0, at));
  };
  for (const r of itemRows) bump(r.path, r.last_at);
  for (const t of touchedRows) bump(t.rel_path, Date.parse(t.last_at) || 0);
  for (const f of factRows) for (const p of f.paths) bump(p, f.at);
  const ordered = [...seen.entries()].sort((a, b) => b[1] - a[1]).map(([p]) => p);
  view.truncated = ordered.length > WHY_MAX_PATHS;
  const examined = ordered.slice(0, WHY_MAX_PATHS);
  const allowed = new Set<string>();
  for (let i = 0; i < examined.length; i += 5) {
    const batch = examined.slice(i, i + 5);
    const verdicts = await Promise.all(batch.map((p) => isHidden(p)));
    batch.forEach((p, k) => {
      if (verdicts[k] === false) allowed.add(p);
    });
  }
  view.matched_paths = allowed.size;

  /* ---- git history (tracked paths only: git never lists an ignored file) ---- */
  let commits: Awaited<ReturnType<typeof readPathHistory>> = [];
  try {
    commits = await readPathHistory(checkout, spec.rel, spec.kind === 'glob' ? 'glob' : 'literal', WHY_GIT_COMMITS);
  } catch {
    commits = [];
  }
  const gitCount = new Map<string, number>();
  for (const c of commits) {
    for (const id of new Set([...c.closes, ...c.refs])) gitCount.set(id, (gitCount.get(id) ?? 0) + 1);
  }
  const newestCommit = commits.length > 0 ? Date.parse(commits[0]?.at ?? '') : Number.NaN;

  /* ---- live claims over the path ---- */
  const claims: { session: string; pattern: string; item_id: string | null; intent: string | null }[] = [];
  for (const lease of store.listLeases({ repo: slug, active: true })) {
    if (lease.kind !== 'claim') continue;
    const row = store.getSession(lease.session_id);
    if (row === null || sessions.liveness(row, nowMs) === 'ended') continue;
    const lv = sessions.leaseView(lease);
    const pattern = lv.paths.find((p) => claimCovers(spec, p));
    if (pattern === undefined) continue;
    claims.push({
      session: shortSession(lease.session_id),
      pattern: cleanText(pattern, 80),
      item_id: lease.item_id,
      intent: lease.intent === null ? null : cleanText(lease.intent, INTENT_MAX) || null,
    });
  }

  /* ---- items ---- */
  interface ItemAcc {
    lastAt: number;
    n: number;
  }
  const acc = new Map<string, ItemAcc>();
  const touchItem = (id: string, at: number, n: number): void => {
    const cur = acc.get(id) ?? { lastAt: 0, n: 0 };
    cur.lastAt = Math.max(cur.lastAt, at);
    cur.n = Math.max(cur.n, n);
    acc.set(id, cur);
  };
  for (const r of itemRows) if (allowed.has(r.path)) touchItem(r.item_id, r.last_at, r.n);
  for (const id of gitCount.keys()) touchItem(id, Number.isFinite(newestCommit) ? newestCommit : 0, 0);
  for (const c of claims) if (c.item_id !== null) touchItem(c.item_id, nowMs, 0);

  const ranked: { open: boolean; lastAt: number; entry: WhyView['items'][number] }[] = [];
  for (const [id, a] of acc) {
    let fm: { id: string; title: string; status: ItemStatus };
    try {
      const stored = ledger.getItem(id).item.fm;
      fm = { id: stored.id, title: stored.title, status: stored.status };
    } catch {
      continue; // a trailer naming an id this ledger does not know
    }
    const own = claims.find((c) => c.item_id === id);
    ranked.push({
      open: isOpen(fm.status),
      lastAt: a.lastAt,
      entry: {
        id: cleanText(fm.id, 24),
        status: cleanText(fm.status, 16),
        title: cleanText(fm.title, TITLE_MAX),
        commits: gitCount.get(id) ?? (a.n > 0 ? a.n : null),
        claim: own === undefined ? null : { session: own.session, pattern: own.pattern, intent: own.intent },
      },
    });
  }
  // Open work first (that is what a reader must not collide with), then newest.
  ranked.sort((x, y) => Number(y.open) - Number(x.open) || y.lastAt - x.lastAt);
  view.items = ranked.slice(0, WHY_MAX_ITEMS).map((r) => r.entry);
  if (ranked.length > WHY_MAX_ITEMS) view.truncated = true;

  const shownClaimItems = new Set(view.items.filter((i) => i.claim !== null).map((i) => i.id));
  const looseClaims = claims.filter((c) => c.item_id === null || !shownClaimItems.has(c.item_id));
  view.claims = looseClaims.slice(0, WHY_MAX_CLAIMS);
  if (looseClaims.length > WHY_MAX_CLAIMS) view.truncated = true;

  /* ---- decisions / journal that name the path ---- */
  const needle = needleOf(spec);
  if (needle !== null) {
    for (const d of ledger.listDecisions(slug)) {
      if (view.mentions.length >= WHY_MAX_MENTIONS) break;
      if (!mentionsPath(`${d.title}\n${d.body}`, needle)) continue;
      view.mentions.push({ kind: 'decision', ref: `D${d.n}`, text: cleanText(d.title, MENTION_MAX) });
    }
    for (const ev of ledger.listJournal(slug)) {
      if (view.mentions.length >= WHY_MAX_MENTIONS) break;
      if (!mentionsPath(ev.fields.join(' '), needle)) continue;
      view.mentions.push({
        kind: 'journal',
        ref: cleanText(`${ev.at} ${ev.type}`, 40),
        text: cleanText(ev.fields.join(' '), MENTION_MAX),
      });
    }
  }

  /* ---- sessions ---- */
  view.sessions = factRows
    .filter((f) => f.paths.some((p) => allowed.has(p)))
    .slice(0, WHY_MAX_SESSIONS)
    .map((f) => ({
      session: shortSession(f.session),
      last_at: iso(f.at),
      why: f.why === null ? null : cleanText(f.why, WHY_TEXT_MAX) || null,
    }));

  /* ---- uncommitted ---- */
  view.uncommitted = touchedRows
    .filter((t) => allowed.has(t.rel_path))
    .slice(0, WHY_MAX_UNCOMMITTED)
    .map((t) => ({
      session: shortSession(t.session),
      via: cleanText(t.via, 12),
      path: cleanText(t.rel_path, 120),
      orphan: t.orphan,
    }));

  /* ---- last change: git first, ledger facts as the fallback ---- */
  if (Number.isFinite(newestCommit)) {
    view.last_changed = { at: iso(newestCommit), source: 'git' };
  } else {
    const ledgerAt = Math.max(
      0,
      ...itemRows.filter((r) => allowed.has(r.path)).map((r) => r.last_at),
      ...factRows.filter((f) => f.paths.some((p) => allowed.has(p))).map((f) => f.at),
    );
    if (ledgerAt > 0) view.last_changed = { at: iso(ledgerAt), source: 'ledger' };
  }
  return view;
}
