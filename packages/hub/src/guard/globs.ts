/**
 * Glob matching and path exclusions for the F2 guards (SPEC §10.3, §10.11).
 *
 * No dependency: `claim --paths "apps/server/src/auth/**,*.ts"` needs `*`, `**`,
 * `?` and a character class, nothing more. Everything is anchored and compiled
 * against a `/`-separated path relative to the checkout, so a pattern can never
 * reach outside it — and a pattern is never used as a filesystem path.
 */

import { realpath as fsRealpath } from 'node:fs';
import nodePath, { sep } from 'node:path';
import { probeCaseInsensitive, slugSchema } from '@agent-ledger/shared';

/** Longest pattern we parse. A longer one is treated as "matches nothing". */
const MAX_PATTERN = 300;

/** Parsed pattern: path segments plus the "this also names a directory" flag. */
interface Parsed {
  segs: string[];
  /** True when the pattern matches everything beneath it as well. */
  prefixOk: boolean;
}

const cache = new Map<string, Parsed | null>();

/** S8 (T11): matching options. `caseInsensitive` = the checkout's volume ignores case. */
export interface MatchOpts {
  caseInsensitive?: boolean;
}

/**
 * Pattern and path are both NFC-normalised (a decomposed `é` must not slip past a claim written
 * with `é`; on a case-sensitive volume this only ever widens a claim, never narrows it) and,
 * on a case-insensitive volume, case-folded the same way. Over-matching is the safe direction.
 */
function foldText(text: string, opts: MatchOpts): string {
  if (typeof text !== 'string') return text;
  const nfc = text.normalize('NFC');
  return opts.caseInsensitive === true ? nfc.toLowerCase() : nfc;
}

/** `a\b` → `a/b`. `touched.rel_path` is stored `/`-separated; so are patterns. */
export function toPosix(rel: string): string {
  return rel.split(sep).join('/');
}

/**
 * Parse one glob into segments. `null` = never matches (too long, or nothing
 * but separators). Semantics, deliberately narrow:
 *  - `**` crosses `/`, `*` and `?` do not,
 *  - a trailing `/` or a bare directory name matches everything beneath it
 *    (`src` matches `src/a/b.ts`) — that is what agents mean by `--paths src`,
 *  - a leading `/` or `./` is stripped: the pattern is always checkout-relative.
 */
function parse(pattern: string): Parsed | null {
  const cached = cache.get(pattern);
  if (cached !== undefined) return cached;
  const built = build(pattern);
  // Bounded: the cache is keyed by attacker-influenced strings (claim paths).
  if (cache.size > 512) cache.clear();
  cache.set(pattern, built);
  return built;
}

function build(pattern: string): Parsed | null {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > MAX_PATTERN) {
    return null;
  }
  let p = toPosix(pattern).trim();
  p = p.replace(/^\.\//, '').replace(/^\/+/, '');
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.replace(/\/+$/, '');
  if (p === '' || p === '.') return null;
  const segs = p.split('/').filter((s) => s !== '' && s !== '.');
  if (segs.length === 0) return null;
  // A pattern without a wildcard names either the file itself or a directory
  // prefix — both are what the author meant.
  return { segs, prefixOk: dirOnly || !/[*?[]/.test(p) };
}

/**
 * Does `relPath` (checkout-relative, `/`-separated) match `pattern`?
 *
 * Audit S2 (ReDoS): this used to compile the glob to a RegExp. Two audited
 * measurements killed that approach — `a*a*a*…b` (24 chars, 11 stars) against
 * 40 `a`s took 7.8 s, and `a**a**…b` took 79 s. Patterns come from
 * `ledger claim --paths`, and `matchAny` runs on EVERY PreToolUse, so one claim
 * could wedge the single-threaded hub — guards and all of `/v1/*` with it. JS
 * has no regex timeout, so the fix is not a better regex: it is not using one.
 *
 * What replaces it is the standard two-level wildcard match with a single
 * backtrack pointer per level — O(segments × path) and O(pattern × segment),
 * no nesting, no exponential case. A pattern is also never rejected for being
 * "too complex": that would silently turn a claim into "protects nothing",
 * which is a fail-OPEN, and the guard must not have one.
 */
export function matchGlob(pattern: string, relPath: string, opts: MatchOpts = {}): boolean {
  const parsed = parse(foldText(pattern, opts));
  if (parsed === null) return false;
  const path = toPosix(foldText(relPath, opts))
    .replace(/^\.\//, '')
    .replace(/^\/+/, '')
    .split('/')
    .filter((s) => s !== '');
  if (path.length === 0) return false;
  return matchSegments(parsed.segs, path, parsed.prefixOk);
}

/** `**` consumes zero or more whole segments; everything else is one segment. */
function matchSegments(pat: readonly string[], path: readonly string[], prefixOk: boolean): boolean {
  let pi = 0;
  let si = 0;
  let starPi = -1;
  let starSi = -1;
  while (si < path.length) {
    if (pi < pat.length) {
      const seg = pat[pi] as string;
      if (seg === '**') {
        // Trailing `**` eats the rest, including nothing (`src/**` ↔ `src`).
        if (pi === pat.length - 1) return true;
        starPi = pi;
        starSi = si;
        pi += 1;
        continue;
      }
      if (matchSegment(seg, path[si] as string)) {
        pi += 1;
        si += 1;
        continue;
      }
    }
    // Either the pattern ran out while the path continues, or the segment at
    // `pi` did not match: try the last `**` again against one more segment
    // before giving up (audit H4 — without this, `a/**/b` failed to match
    // `a/b/c/b` because the greedy zero-segment `**` reached the literal `b`
    // too early and returned before backtracking).
    if (starPi >= 0) {
      starSi += 1;
      si = starSi;
      pi = starPi + 1;
      continue;
    }
    // No `**` left to retry: pattern truly ran out (directory-style pattern
    // covers what is below it) or it was a literal mismatch.
    return pi >= pat.length ? prefixOk : false;
  }
  while (pi < pat.length && pat[pi] === '**') pi += 1;
  return pi === pat.length;
}

/** One segment: `*` (not crossing `/`), `?`, `[abc]` / `[!abc]`, else literal. */
function matchSegment(pat: string, str: string): boolean {
  let p = 0;
  let s = 0;
  let starP = -1;
  let starS = -1;
  while (s < str.length) {
    if (p < pat.length) {
      const ch = pat[p] as string;
      if (ch === '*') {
        starP = p;
        starS = s;
        p += 1;
        continue;
      }
      if (ch === '?') {
        p += 1;
        s += 1;
        continue;
      }
      if (ch === '[') {
        const cls = matchClass(pat, p, str[s] as string);
        if (cls !== null) {
          if (cls.ok) {
            p = cls.next;
            s += 1;
            continue;
          }
          // A well-formed class that does not match: fall through to backtrack.
          if (starP < 0) return false;
          starS += 1;
          s = starS;
          p = starP + 1;
          continue;
        }
        // Unterminated `[` is a literal bracket.
        if (ch === str[s]) {
          p += 1;
          s += 1;
          continue;
        }
      } else if (ch === str[s]) {
        p += 1;
        s += 1;
        continue;
      }
    }
    if (starP >= 0) {
      starS += 1;
      s = starS;
      p = starP + 1;
      continue;
    }
    return false;
  }
  while (p < pat.length && pat[p] === '*') p += 1;
  return p === pat.length;
}

/** `[abc]` / `[!abc]` at `at`. `null` = unterminated (treat `[` literally). */
function matchClass(pat: string, at: number, ch: string): { ok: boolean; next: number } | null {
  const close = pat.indexOf(']', at + 1);
  if (close <= at + 1) return null;
  let body = pat.slice(at + 1, close);
  let negate = false;
  if (body.startsWith('!') || body.startsWith('^')) {
    negate = true;
    body = body.slice(1);
  }
  let hit = false;
  for (let i = 0; i < body.length; i += 1) {
    // `a-z` range; a trailing `-` is a literal.
    if (body[i + 1] === '-' && i + 2 < body.length) {
      const lo = body[i] as string;
      const hi = body[i + 2] as string;
      if (ch >= lo && ch <= hi) hit = true;
      i += 2;
      continue;
    }
    if (body[i] === ch) hit = true;
  }
  return { ok: negate ? !hit : hit, next: close + 1 };
}

/** First matching pattern, or null. Used for the deny reason text. */
export function matchAny(patterns: readonly string[], relPath: string, opts: MatchOpts = {}): string | null {
  for (const pattern of patterns) {
    if (matchGlob(pattern, relPath, opts)) return pattern;
  }
  return null;
}

/* ---------------- exclusions (SPEC §10.11) ---------------- */

/** Temp roots. macOS resolves `/tmp` → `/private/tmp` and `TMPDIR` lives under
 *  `/var/folders`, whose realpath is `/private/var/folders`. */
const TEMP_ROOTS = [
  '/tmp',
  '/private/tmp',
  '/var/tmp',
  '/private/var/tmp',
  '/var/folders',
  '/private/var/folders',
  '/dev/shm',
];

/** Directory names that mean "throwaway workspace, do not attribute". */
const SCRATCH_SEGMENTS = new Set(['scratchpad', 'scratchpads', '.scratch', 'claude-scratch']);

export interface ExcludeOptions {
  /** Ledger root — its own files are changed through `ledger`, never attributed. */
  ledgerRoot: string;
  /** False in tests, whose git repos legitimately live under `tmpdir()`. */
  excludeTemp: boolean;
}

function isUnder(abs: string, root: string): boolean {
  return abs === root || abs.startsWith(root.endsWith('/') ? root : `${root}/`);
}

/**
 * True when a path must not create a repo registration or a `touched` row.
 * Deliberately separate from the guard's rule 1: the ledger is *denied* for
 * edits, whereas `/tmp` is simply uninteresting — a scratch file there is
 * allowed, it just never becomes someone's uncommitted work.
 */
export function isExcludedPath(abs: string, opts: ExcludeOptions): boolean {
  if (typeof abs !== 'string' || abs === '') return true;
  const p = toPosix(abs);
  if (isUnder(p, toPosix(opts.ledgerRoot))) return true;
  if (opts.excludeTemp) {
    for (const root of TEMP_ROOTS) {
      if (isUnder(p, root)) return true;
    }
  }
  for (const segment of p.split('/')) {
    if (SCRATCH_SEGMENTS.has(segment)) return true;
  }
  return false;
}

/**
 * SPEC §10.3 rule 1 carve-out: exactly `<ledger>/<repo>/CONTEXT.md` is
 * editable — one segment under the ledger root. Not `<ledger>/CONTEXT.md`
 * (no repo segment) and not `<ledger>/.hub/CONTEXT.md` or anything deeper
 * (S4: a bare `endsWith('/CONTEXT.md')` let those through too).
 */
export function isLedgerContextFile(abs: string, ledgerRoot: string): boolean {
  const a = toPosix(abs);
  const root = toPosix(ledgerRoot).replace(/\/+$/, '');
  if (!isUnder(a, root) || a === root) return false;
  const rel = a.slice(root.length + 1);
  const parts = rel.split('/');
  // A repo slug is `[a-z0-9-]+` (SPEC, `slugSchema`) — `.hub` and anything
  // else reserved directly under the ledger root can never match it, so this
  // doubles as the "is it actually a registered-repo-shaped segment" check
  // without needing the repo list here.
  return parts.length === 2 && parts[1] === 'CONTEXT.md' && slugSchema.safeParse(parts[0]).success;
}

/* ---------------- canonical checkout-relative path (S8, T11) ---------------- */

export type CanonicalRel = { ok: true; rel: string } | { ok: false; reason: string };

export interface CanonicalDeps {
  platform?: NodeJS.Platform;
  /** Test seam; production is `fs.realpath.native`. */
  realpath?: (p: string) => Promise<string>;
}

const MAX_CANON_PATH = 4096;
const WIN_DEVICE_RE = /^(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\..*)?$/i;
/** `PROGRA~1`, `FOO~1.TXT`: a name that may alias a long name that does not exist yet. */
const WIN_SHORT_NAME_RE = /^[^.]{1,6}~\d+(?:\.[^.]{0,3})?$/;

function nativeRealpath(p: string): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    fsRealpath.native(p, (err, out) => (err === null ? resolvePromise(out) : reject(err)));
  });
}

/**
 * Windows-only refusals on the segments of an (absolute, realpath'd or about-to-exist) name:
 * alternate data streams, trailing dot/space (silently stripped by Win32, so `a.ts.` IS `a.ts`),
 * device names (`CON`, `NUL.txt`), the `\\?\` / `\\.\` namespaces.
 */
function winSegmentProblem(seg: string): string | null {
  if (seg.includes(':')) return 'alternate data stream or drive in a path segment';
  if (/[. ]$/.test(seg)) return 'trailing dot or space (Win32 strips it, so the name is not what it looks like)';
  if (WIN_DEVICE_RE.test(seg)) return 'reserved device name';
  if (/[<>"|?*\u0000-\u001f]/.test(seg)) return 'invalid character in a Windows name';
  return null;
}

/**
 * The ONE spelling the guard compares against claims and holds: checkout-relative, `/`-separated,
 * NFC, symlinks/junctions/8.3 aliases resolved by the OS (`realpath.native` of the file, or of its
 * nearest existing ancestor plus the not-yet-existing tail for a new file).
 *
 * Refuses (never guesses) when: the path has a NUL or is absurdly long; the unresolved tail contains
 * `.`/`..`; the result is outside the checkout; on win32 the raw or resolved name uses `\\?\`, an
 * ADS `:`, a trailing dot/space, a device name, or a not-yet-existing 8.3 short name.
 * Case folding is NOT applied here: `rel` is also an exact-match key for `touched` rows, which carry
 * the on-disk spelling; claim matching folds at match time (`MatchOpts.caseInsensitive`).
 */
export async function canonicalRel(checkout: string, p: string, deps: CanonicalDeps = {}): Promise<CanonicalRel> {
  const platform = deps.platform ?? process.platform;
  const win = platform === 'win32';
  const api = win ? nodePath.win32 : nodePath.posix;
  const realpath = deps.realpath ?? nativeRealpath;
  const bad = (reason: string): CanonicalRel => ({ ok: false, reason });
  if (typeof p !== 'string' || p === '' || typeof checkout !== 'string' || checkout === '') return bad('empty path');
  if (p.includes('\0') || checkout.includes('\0')) return bad('NUL in path');
  if (p.length > MAX_CANON_PATH) return bad('path too long');
  if (win && /^[\\/]{2}[?.][\\/]/.test(p)) return bad('Win32 device/extended-length namespace (\\\\?\\ or \\\\.\\)');

  // Not normalised on purpose: `a/link/../b` must be resolved by the OS (link first), not folded
  // lexically. `..` in the part that does not exist yet is refused below.
  const abs = api.isAbsolute(p) ? p : `${checkout.replace(/[\\/]+$/, '')}${api.sep}${p}`;
  if (win && /^[A-Za-z]:(?![\\/])/.test(abs)) return bad('drive-relative path');

  let realCheckout: string;
  try {
    realCheckout = await realpath(checkout);
  } catch {
    return bad('checkout cannot be resolved');
  }

  const tail: string[] = [];
  let current = abs;
  let real: string | null = null;
  for (let i = 0; i < 64 && real === null; i += 1) {
    try {
      real = await realpath(current);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT' && code !== 'ENOTDIR') return bad('path cannot be resolved');
      const parent = api.dirname(current);
      if (parent === current) return bad('path cannot be resolved');
      tail.unshift(api.basename(current));
      current = parent;
    }
  }
  if (real === null) return bad('path too deep');
  if (tail.some((s) => s === '.' || s === '..' || s === '')) return bad('`.`/`..` in a path that does not exist yet');
  if (win) {
    for (const seg of tail) {
      if (WIN_SHORT_NAME_RE.test(seg)) return bad('8.3 short name for a file that does not exist yet');
    }
  }
  const full = tail.length === 0 ? real : api.join(real, ...tail);

  const relRaw = api.relative(realCheckout, full);
  if (relRaw === '') return { ok: true, rel: '' };
  if (relRaw === '..' || relRaw.startsWith(`..${api.sep}`) || api.isAbsolute(relRaw)) {
    return bad('outside the checkout');
  }
  const segs = relRaw.split(api.sep);
  if (win) {
    for (const seg of segs) {
      const problem = winSegmentProblem(seg);
      if (problem !== null) return bad(problem);
    }
  }
  return { ok: true, rel: segs.join('/').normalize('NFC') };
}

const CI_TTL_MS = 10 * 60 * 1000;
const ciCache = new Map<string, { v: boolean; at: number }>();

/**
 * Is the volume under `checkout` case-insensitive? Stat-only (`probeCaseInsensitive` creates
 * nothing in the user's repo); cached per checkout for 10 min, with `Math.abs` so a clock that
 * jumped backwards just re-probes. Any doubt answers `true`: folding case only widens a claim.
 */
export async function checkoutCaseInsensitive(
  checkout: string,
  opts: { now?: () => number; probe?: (dir: string) => Promise<boolean> } = {},
): Promise<boolean> {
  const now = (opts.now ?? Date.now)();
  const hit = ciCache.get(checkout);
  if (hit !== undefined && Math.abs(now - hit.at) < CI_TTL_MS) return hit.v;
  let v: boolean;
  try {
    v = await (opts.probe ?? ((d) => probeCaseInsensitive(d)))(checkout);
  } catch {
    v = true;
  }
  if (ciCache.size > 256) ciCache.clear();
  ciCache.set(checkout, { v, at: now });
  return v;
}

/** Test seam. */
export function resetCaseCache(): void {
  ciCache.clear();
}
