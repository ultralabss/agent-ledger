/** Path normalisation for output of `git` and for `fs.watch` names.
 *
 *  Git (incl. Git for Windows) prints `C:/Users/me/repo` with forward slashes,
 *  while Node paths on win32 are `C:\Users\me\repo`; and Windows volumes are
 *  case-insensitive. POSIX behaviour is deliberately identical to before:
 *  every function is the identity / plain `===` unless `platform === 'win32'`. */

import { win32 } from 'node:path';

/** `fs.watch` yields `a\b` on Windows; ignore rules are written with `/`. */
export function toPosix(p: string, platform: NodeJS.Platform = process.platform): string {
  return platform === 'win32' ? p.replace(/\\/g, '/') : p;
}

/** Normalise an absolute path git printed (`C:/x/y`, `C:\x\y\`) for storage and
 *  comparison. win32: `path.win32.normalize`, trailing separator dropped (except
 *  for a drive root). Elsewhere: unchanged. */
export function normalizeGitPath(p: string, platform: NodeJS.Platform = process.platform): string {
  if (platform !== 'win32') return p;
  let n = win32.normalize(p);
  while (n.length > 3 && /[\\/]$/.test(n)) n = n.slice(0, -1);
  return n;
}

/** Same filesystem path? win32: normalised + case-folded; elsewhere `===`. */
export function samePathGit(
  a: string,
  b: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (platform !== 'win32') return a === b;
  return normalizeGitPath(a, platform).toLowerCase() === normalizeGitPath(b, platform).toLowerCase();
}
