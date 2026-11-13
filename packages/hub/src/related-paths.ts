/**
 * "Where in the code does this item live", from facts the hub already
 * holds. No LLM, no git at read time, no new IO on the prompt hook except one
 * `lstat` per path that is about to be shown.
 *
 * Two sources, strongest first:
 *  1. `item_files` — the files of every commit whose trailer named the item
 *     (`Refs:` / `Closes:`), written by the repo watcher when the commit lands;
 *  2. `session_facts.files` of the sessions that claimed or closed the item —
 *     what they touched, which is wider than the item (a session often does
 *     more than one thing), hence weight 1 against a commit's 3 and a cut-off
 *     for sessions that touched too much to say anything.
 *
 * The files are folded into at most `MAX_PATHS` entries by directory
 * (`dir/*` for two or more files in one directory, `dir/**` when sibling
 * directories had to be lifted) so a hit costs ~100 characters, not a file
 * list. Before a path is shown it is looked up in the repo's checkout; one that
 * is gone is kept but flagged `(maybe moved)` — a moved file is still the
 * best pointer to where the work happened.
 */

import { lstatSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import type { RuntimeStore } from './db/store.ts';
import { parseList } from './db/store.ts';

/** Entries per hit (SPEC §9). */
export const MAX_PATHS = 4;
/** A commit touching more files than this is a rename/format sweep: its file
 *  list says nothing about the item, so it is not recorded at all. */
export const MAX_COMMIT_FILES = 25;
/** A session that touched more files than this did too many things for its
 *  file list to be pinned on one item. */
const SESSION_FILES_MAX = 40;
/** One entry is cut to this many characters (tail kept — the file name is the
 *  informative end). */
const PATH_MAX = 56;
const MOVED = ' (maybe moved)';

/** Weight of a path seen in a commit that named the item / in a session that
 *  worked on it. */
const W_COMMIT = 3;
const W_SESSION = 1;

const NOISE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);
const NOISE_FILES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'yarn.lock',
  'bun.lockb',
  'cargo.lock',
  'changelog.md',
]);

/** Everything outside this becomes `?` in what the agent reads. Same family as
 *  `untrustedSnippet`, minus the characters a path never needs. */
const DISPLAY_CHARSET = /[^\p{L}\p{N}._@+\-/]/gu;

/** A repo-relative path we are willing to store and print, else `null`. */
export function cleanRelPath(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw === '' || raw.length > 240) return null;
  if (/[\u0000-\u001f\u007f]/.test(raw)) return null;
  const p = raw.replace(/^(\.\/)+/, '');
  if (p === '' || p.startsWith('/') || p.includes('\\') || /^[A-Za-z]:/.test(p)) return null;
  const segs = p.split('/');
  if (segs.some((s) => s === '' || s === '.' || s === '..')) return null;
  return p;
}

export function isNoisePath(path: string): boolean {
  const segs = path.split('/');
  if (segs.slice(0, -1).some((s) => NOISE_DIRS.has(s))) return true;
  return NOISE_FILES.has((segs[segs.length - 1] ?? '').toLowerCase());
}

/**
 * The repo watcher calls this for every commit with `Refs:`/`Closes:` ids.
 * Never throws — the commit is already applied; this is a convenience.
 */
export function recordCommitFiles(
  store: RuntimeStore,
  repo: string,
  ids: readonly string[],
  files: readonly string[],
  now = Date.now(),
): void {
  if (ids.length === 0 || files.length === 0 || files.length > MAX_COMMIT_FILES) return;
  const useful: string[] = [];
  for (const f of files) {
    const p = cleanRelPath(f);
    if (p !== null && !isNoisePath(p)) useful.push(p);
  }
  if (useful.length === 0) return;
  try {
    for (const id of new Set(ids)) store.addItemFiles(repo, id, useful, now);
  } catch {
    /* cache only */
  }
}

/* ---------------- folding files into globs ---------------- */

interface Entry {
  /** Directory without a trailing slash; `''` for the repo root. */
  dir: string;
  /** Set for a single file; `null` for a directory entry. */
  file: string | null;
  /** `dir/**` (lifted from deeper directories) instead of `dir/*`. */
  tree: boolean;
  w: number;
  order: number;
}

function depthOf(e: Entry): number {
  return e.dir === '' ? 0 : e.dir.split('/').length;
}

function dirOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

/** Heaviest first, insertion order breaking ties. */
function rank(a: Entry, b: Entry): number {
  return b.w - a.w || a.order - b.order;
}

/**
 * Fold weighted files into at most `max` specs: a file path, `dir/*` or
 * `dir/**`. Exported for tests.
 */
export function mergePaths(weights: ReadonlyMap<string, number>, max = MAX_PATHS): string[] {
  const byDir = new Map<string, string[]>();
  for (const path of weights.keys()) {
    const dir = dirOf(path);
    const list = byDir.get(dir);
    if (list) list.push(path);
    else byDir.set(dir, [path]);
  }

  let order = 0;
  let entries: Entry[] = [];
  for (const [dir, files] of byDir) {
    if (dir !== '' && files.length >= 2) {
      const w = files.reduce((sum, f) => sum + (weights.get(f) ?? 0), 0);
      entries.push({ dir, file: null, tree: false, w, order: order++ });
      continue;
    }
    for (const f of files) {
      entries.push({ dir, file: f, tree: false, w: weights.get(f) ?? 0, order: order++ });
    }
  }

  // Still too many: lift the deepest directories one level, so siblings meet
  // in their parent. Stops at the first level — never a bare `*`.
  while (entries.length > max) {
    const deepest = Math.max(...entries.map(depthOf));
    if (deepest <= 1) break;
    entries = coalesce(
      entries.map((e) =>
        depthOf(e) === deepest
          ? { dir: dirOf(e.dir), file: null, tree: true, w: e.w, order: e.order }
          : e,
      ),
    );
  }

  return entries
    .sort(rank)
    .slice(0, max)
    .map((e) => (e.file !== null ? e.file : `${e.dir}/${e.tree ? '**' : '*'}`));
}

/** One entry per directory/tree; a lifted tree swallows what lies under it. */
function coalesce(entries: Entry[]): Entry[] {
  const trees = entries
    .filter((e) => e.file === null && e.tree)
    .sort((a, b) => a.dir.length - b.dir.length);
  const out = new Map<string, Entry>();
  for (const e of entries) {
    // Shortest tree that contains this entry (a tree contains itself).
    const host = trees.find((t) => e.dir === t.dir || e.dir.startsWith(`${t.dir}/`));
    const key = host ? `T:${host.dir}` : e.file !== null ? `F:${e.file}` : `D:${e.dir}`;
    let acc = out.get(key);
    if (acc === undefined) {
      acc = host ? { ...host, w: 0 } : { ...e, w: 0 };
      out.set(key, acc);
    }
    acc.w += e.w;
    acc.order = Math.min(acc.order, e.order);
  }
  return [...out.values()];
}

/* ---------------- the hit's path segment ---------------- */

export interface PathsInput {
  repo: string;
  itemId: string;
  /** Checkouts to look the path up in; empty = nothing can be verified. */
  roots: readonly string[];
}

/**
 * Up to `MAX_PATHS` display strings for one item, `[]` when the hub knows no
 * files for it. Never throws.
 */
export function itemPaths(store: RuntimeStore, input: PathsInput): string[] {
  const weights = new Map<string, number>();
  const bump = (raw: unknown, w: number): void => {
    const p = cleanRelPath(raw);
    if (p === null || isNoisePath(p)) return;
    weights.set(p, (weights.get(p) ?? 0) + w);
  };
  try {
    for (const row of store.itemFiles(input.repo, input.itemId)) bump(row.path, W_COMMIT);
    for (const session of store.itemWorkers(input.repo, input.itemId)) {
      const facts = store.getSessionFacts(session, input.repo);
      if (facts === null || facts.file_count > SESSION_FILES_MAX) continue;
      for (const f of parseList(facts.files)) bump(f, W_SESSION);
    }
    return mergePaths(weights).map((spec) => display(spec, input.roots));
  } catch {
    return [];
  }
}

function display(spec: string, roots: readonly string[]): string {
  const dirSpec = spec.endsWith('/**') ? spec.slice(0, -3) : spec.endsWith('/*') ? spec.slice(0, -2) : null;
  const glob = dirSpec === null ? '' : spec.slice(dirSpec.length);
  const rel = dirSpec ?? spec;
  const shown = cut(rel.replace(DISPLAY_CHARSET, '?'), PATH_MAX - glob.length) + glob;
  // Nothing to look in (`ops`, a repo with no checkout): say nothing rather
  // than call every path moved.
  if (roots.length === 0) return shown;
  return existsIn(roots, rel) ? shown : `${shown}${MOVED}`;
}

function cut(s: string, max: number): string {
  return s.length > max ? `…${s.slice(s.length - max + 1)}` : s;
}

/** `lstat`, not `stat`: a symlink is "there", and we never follow one out of
 *  the checkout. `rel` already passed `cleanRelPath`; the `relative` test is
 *  the belt to that pair of braces. */
function existsIn(roots: readonly string[], rel: string): boolean {
  for (const root of roots) {
    try {
      const abs = join(root, rel);
      const back = relative(root, abs);
      if (back === '' || back.startsWith('..') || isAbsolute(back)) continue;
      lstatSync(abs);
      return true;
    } catch {
      /* not here — try the next checkout */
    }
  }
  return false;
}
