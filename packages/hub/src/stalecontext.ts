/**
 * "CONTEXT.md is probably stale".
 *
 * `CONTEXT.md` is the one document every session in a repo reads, and it is the
 * one nobody remembers to update. The hub can tell: it already sees every
 * commit, so it records the ones that changed the *shape* of the repo — a new
 * or deleted top-level directory, the workspace/script manifests, the container
 * and CI definitions — and compares them against the mtime of `CONTEXT.md`.
 *
 * Token cost: ONE line in the brief, only above the threshold. No new feed, no
 * per-hook output.
 */

import { stat } from 'node:fs/promises';
import type { RuntimeStore } from './db/store.ts';
import type { LedgerPaths } from './ledger/paths.ts';

/** Commits of this kind before the line appears. */
export const STALE_COMMIT_THRESHOLD = 5;

/** A single structural commit is enough when it added or removed a top-level
 *  directory — that is the change that makes "where things are" wrong outright. */
const TOPLEVEL_IS_ENOUGH = true;

export interface StructuralReason {
  /** `dir:packages` | `manifest:package.json` | `ci` | `docker` */
  kind: 'dir' | 'manifest' | 'ci' | 'docker';
  detail: string;
}

/**
 * Does this commit change the structure of the repo?
 *
 * Deliberately file-name based: the alternative (diffing `package.json` to see
 * whether `scripts` actually changed) means reading blobs for every commit in
 * every watched repo, and a `package.json` commit that did not touch scripts is
 * still usually worth a glance at CONTEXT.md.
 */
export function structuralReason(
  files: readonly string[],
  newDirs: readonly string[] = [],
): StructuralReason | null {
  // A brand-new top-level directory is the strongest signal there is — it is
  // literally the "where things are" section of CONTEXT.md going out of date.
  if (newDirs.length > 0) return { kind: 'dir', detail: newDirs[0] as string };
  for (const raw of files) {
    const f = raw.replace(/^\.\//, '');
    const base = f.slice(f.lastIndexOf('/') + 1);
    if (f === 'pnpm-workspace.yaml' || f === 'pnpm-workspace.yml') {
      return { kind: 'manifest', detail: 'pnpm-workspace.yaml' };
    }
    // Root manifest only: a `packages/*/package.json` bump is routine.
    if (f === 'package.json') return { kind: 'manifest', detail: 'package.json' };
    if (
      /^docker-compose.*\.ya?ml$/.test(base) ||
      base === 'Dockerfile' ||
      base.startsWith('Dockerfile.')
    ) {
      return { kind: 'docker', detail: base };
    }
    if (f.startsWith('.github/workflows/') || f === '.gitlab-ci.yml' || f === '.circleci/config.yml') {
      return { kind: 'ci', detail: 'CI' };
    }
  }
  return null;
}

/**
 * Top-level directories a commit's files live in.
 *
 * The caller turns this into "new dirs" by asking the `topdir` marks, which are
 * seeded from the working tree the first time a repo is watched — otherwise
 * every directory would look new on the first sync and the very first brief
 * would cry stale. A *deleted* top-level dir is deliberately NOT detected: it
 * would need a tree listing per commit, and the manifest/CI signals catch the
 * restructures that matter in practice.
 */
export function topLevelDirs(files: readonly string[]): string[] {
  const out = new Set<string>();
  for (const raw of files) {
    const f = raw.replace(/^\.\//, '');
    if (!f.includes('/')) continue;
    const top = f.slice(0, f.indexOf('/'));
    if (top === '' || top.startsWith('.')) continue;
    out.add(top);
  }
  return [...out];
}

export interface StaleDeps {
  store: RuntimeStore;
  paths: LedgerPaths;
}

/**
 * The brief line, or null.
 *
 * `null` on every unknown: no CONTEXT.md (the brief already says "CONTEXT.md
 * missing"), no structural commits, below the threshold.
 */
export async function staleContextLine(deps: StaleDeps, repo: string): Promise<string | null> {
  let since: number;
  try {
    since = (await stat(deps.paths.contextFile(repo))).mtimeMs;
  } catch {
    return null;
  }
  const commits = deps.store.structCommitsSince(repo, since);
  if (commits.length === 0) return null;
  const newDir = commits.find((c) => c.reason.startsWith('dir:'));
  const enough = commits.length >= STALE_COMMIT_THRESHOLD || (TOPLEVEL_IS_ENOUGH && newDir !== undefined);
  if (!enough) return null;
  const what = newDir
    ? `new directory ${newDir.reason.slice(4)}`
    : `${commits.length} structural commits`;
  return `CONTEXT.md may be stale (${what} since ${day(since)}) — update it`;
}

function day(ms: number): string {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(
    d.getDate(),
  ).padStart(2, '0')}`;
}
