/**
 * Sandboxed, TOCTOU-hardened reads of attacker-influenced file paths.
 *
 * This module is the extraction of what used to live inside
 * `guard/recap.ts`. The Stop-hook recap check had the hardened reader
 * (`readTailVerified` — `O_NOFOLLOW`, `fstat` dev/ino identity, parent-chain
 * snapshot), while `transcript.ts` read the *same* attacker-influenced
 * `transcript_path` through the plain `readTail`/`readHead` pair: realpath →
 * root check → `stat` by name → `open` by name. Three separate name
 * resolutions, i.e. the exact `realpath`→`open` TOCTOU the recap path had
 * already closed, reachable through a different caller. One hardened reader,
 * two callers, no second-best copy.
 *
 * The whole rationale for each step is kept here, next to the code that does
 * it, because every future caller of a hook-supplied path needs to read it:
 *
 *  1. `O_NOFOLLOW` on the open. `real` is already a realpath, so its final
 *     component MUST NOT be a symlink; if it is one now, it was swapped after
 *     our check and the open fails (ELOOP) instead of following it.
 *  2. `fstat` the fd and compare `dev`+`ino` with an `lstat` of the same path.
 *     macOS has no `/proc/self/fd` realpath, so identity — not path — is what
 *     we can actually verify. A mismatch means the name now points somewhere
 *     else; we refuse.
 *  3. Size and content both come from that one fd. The old `readTail` would
 *     `stat` by name for the size and then open by name again — two more
 *     windows.
 *  4. H3-1: (1)/(2) only prove the FINAL path component still names the inode
 *     we opened. A directory between `root` and `real` could be swapped for a
 *     symlink after the root check and before `open()` — the kernel follows it
 *     mid-resolution, `real` (same string) lands on a different file, yet a
 *     same-name dev/ino compare taken fresh on both sides of that swap would
 *     still agree with itself. Every directory component from `root` down to
 *     `real` is therefore `lstat`'d BEFORE the open and again AFTER, and none
 *     of them may be a symlink or have changed identity in between.
 *
 * Residual window: the two component-chain snapshots (before/after `open`)
 * bracket the open rather than being atomic with it — a swap that lands and
 * reverts entirely within that narrow gap is not caught. Node has no
 * `openat`/`O_BENEATH` equivalent to close this fully; `O_NOFOLLOW` + the
 * repeated snapshot is what the platform allows.
 */

import { constants as FS } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { sep } from 'node:path';

/** Why a verified read produced no text. `aliased` is deliberately distinct
 *  from `unreadable`: it means the path changed identity between the root
 *  check and the read, which is a TOCTOU signal worth logging on its own. */
export type VerifiedSkip = 'unreadable' | 'aliased';

export type VerifiedRead =
  | { text: string; skipped: null }
  | { text: null; skipped: VerifiedSkip };

/** Which end of the file to read when it is larger than the window. */
export type ReadWindow = 'head' | 'tail';

export async function safeRealpath(p: string): Promise<string | null> {
  try {
    return await realpath(p);
  } catch {
    return null;
  }
}

export function insideAny(abs: string, roots: readonly string[]): boolean {
  return matchedRoot(abs, roots) !== null;
}

/** Which of `roots` contains `abs`, or `null`. Roots are realpath'd too: on
 *  macOS `~/.claude` under a symlinked home would otherwise never match. */
export function matchedRoot(abs: string, roots: readonly string[]): string | null {
  for (const root of roots) {
    if (typeof root !== 'string' || root === '') continue;
    if (abs === root || abs.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) return root;
  }
  return null;
}

export interface ComponentSnapshot {
  path: string;
  dev: number;
  ino: number;
  isSymlink: boolean;
}

/** `root` and every path segment down to (excluding) `real` itself — `real`'s
 *  own identity is separately proven via the open fd's `fstat`. Exported for
 *  the H3-1 unit tests; internal to normal use. */
export function parentChain(root: string, real: string): string[] {
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
  if (real !== root && !real.startsWith(prefix)) return [root];
  const rest = real === root ? '' : real.slice(prefix.length);
  const parts = rest.split(sep).filter((p) => p !== '');
  parts.pop(); // drop the file's own basename — that identity is fstat'd separately
  const chain: string[] = [root];
  let cur = root;
  for (const part of parts) {
    cur = cur.endsWith(sep) ? `${cur}${part}` : `${cur}${sep}${part}`;
    chain.push(cur);
  }
  return chain;
}

export async function snapshotChain(chain: readonly string[]): Promise<ComponentSnapshot[] | null> {
  const out: ComponentSnapshot[] = [];
  for (const p of chain) {
    const st = await lstat(p).catch(() => null);
    if (st === null) return null;
    out.push({ path: p, dev: st.dev, ino: st.ino, isSymlink: st.isSymbolicLink() });
  }
  return out;
}

export function chainStable(before: ComponentSnapshot[], after: ComponentSnapshot[]): boolean {
  if (before.length !== after.length) return false;
  return before.every((b, i) => {
    const a = after[i];
    return a !== undefined && a.path === b.path && a.dev === b.dev && a.ino === b.ino && a.isSymlink === b.isSymlink;
  });
}

/**
 * Read at most `max` bytes from one end of `real`, proving throughout that the
 * file is the inode the caller validated against `root`.
 *
 * `real` must already be a realpath that `matchedRoot(real, roots)` accepted,
 * and `root` must be the root it matched — the parent chain is walked from
 * there, so passing an unrelated root would check the wrong components.
 */
export async function readWindowVerified(
  root: string,
  real: string,
  max: number,
  window: ReadWindow,
): Promise<VerifiedRead> {
  let handle: FileHandle | null = null;
  try {
    const chain = parentChain(root, real);
    const before = await snapshotChain(chain);
    if (before === null) return { text: null, skipped: 'unreadable' };
    if (before.some((s) => s.isSymlink)) return { text: null, skipped: 'aliased' };

    handle = await open(real, FS.O_RDONLY | FS.O_NOFOLLOW);
    const st = await handle.stat();
    if (!st.isFile()) return { text: null, skipped: 'unreadable' };
    // Identity check: the name we validated must still resolve to this inode.
    const named = await lstat(real).catch(() => null);
    if (named === null) return { text: null, skipped: 'unreadable' };
    if (named.dev !== st.dev || named.ino !== st.ino) return { text: null, skipped: 'aliased' };
    // A transcript is a plain file written by Claude Code; more than one link
    // to it means something else is deliberately aliasing it.
    if (st.nlink !== 1) return { text: null, skipped: 'aliased' };

    const after = await snapshotChain(chain);
    if (after === null) return { text: null, skipped: 'unreadable' };
    if (!chainStable(before, after)) return { text: null, skipped: 'aliased' };

    const length = Math.min(st.size, max);
    if (length === 0) return { text: '', skipped: null };
    const buf = Buffer.alloc(length);
    const position = window === 'tail' ? st.size - length : 0;
    const { bytesRead } = await handle.read(buf, 0, length, position);
    return { text: buf.subarray(0, bytesRead).toString('utf8'), skipped: null };
  } catch {
    return { text: null, skipped: 'unreadable' };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Last `max` bytes, verified. Never reads the whole file. */
export function readTailVerified(root: string, real: string, max: number): Promise<VerifiedRead> {
  return readWindowVerified(root, real, max, 'tail');
}

/** First `max` bytes, verified. */
export function readHeadVerified(root: string, real: string, max: number): Promise<VerifiedRead> {
  return readWindowVerified(root, real, max, 'head');
}

/** Test/inspection seam: resolve the configured roots once at startup. */
export async function resolveRoots(roots: readonly string[]): Promise<string[]> {
  const out: string[] = [];
  for (const root of roots) {
    const real = await safeRealpath(root);
    out.push(real ?? root);
  }
  return out;
}
