/**
 * Read-only git reader for code repos — SPEC §6.3.
 *
 * Hard rules, enforced here and nowhere else:
 *  - only `status`, `worktree list`, `for-each-ref`, `log`, `diff --name-only`,
 *    `rev-list --count`, `rev-parse`, `check-ignore -q`, `config --get remote.origin.url`
 *    (repo identity, credentials stripped). Nothing that mutates, ever.
 *  - every invocation goes through `git()` in `git.ts`, which supplies the
 *    absolute binary, `--no-optional-locks` and `-c core.fsmonitor=false`.
 *  - a git failure is never fatal: the caller gets `null`/empty and the UI
 *    shows "git unavailable" instead of the hub dying.
 */

import type {
  DirtyFileView,
  GitBranchView,
  GitWorktreeView,
  ReleaseView,
  TouchedVia,
} from '@agent-ledger/shared';
import { itemIdScanRe, originHintSchema, rootShaSchema, sanitizeField } from '@agent-ledger/shared';
import { git } from './git.ts';
import { normalizeGitPath } from './gitpath.ts';

export interface CheckoutStatus {
  head: string | null;
  branch: string | null;
  detached: boolean;
  ahead: number | null;
  behind: number | null;
  /** Porcelain code (2 chars) per path, relative to the checkout. */
  dirty: { rel_path: string; code: string; staged: boolean; untracked: boolean }[];
}

export interface CommitInfo {
  sha: string;
  short: string;
  subject: string;
  body: string;
  at: string;
  files: string[];
  /** `Closes: ACME-1` trailers, uppercased. */
  closes: string[];
  /** `Refs: ACME-1` trailers, uppercased. */
  refs: string[];
}


/**
 * `git status --porcelain=v2 -b`. Chosen over v1 because the `# branch.ab`
 * header gives ahead/behind in the same call (no extra `rev-list`), and because
 * v2 quotes nothing: the path is the rest of the line, so a filename with a
 * space parses without guessing.
 */
export async function readStatus(checkout: string): Promise<CheckoutStatus | null> {
  // `-uall`: without it git collapses an untracked tree into the directory
  // (`src/`), which can never be matched against a `touched` rel_path — the
  // file would show as "nobody's" in `who` right after a session created it.
  const res = await git(
    checkout,
    ['status', '--porcelain=v2', '-b', '-z', '--untracked-files=all'],
    15_000,
  );
  if (res.code !== 0) return null;
  const out: CheckoutStatus = {
    head: null,
    branch: null,
    detached: false,
    ahead: null,
    behind: null,
    dirty: [],
  };
  // `-z` separates records with NUL. Rename/copy records (`2 `) carry a second
  // NUL-separated field (the original path) which must be consumed, not parsed
  // as its own record.
  const records = res.stdout.split('\0');
  for (let i = 0; i < records.length; i += 1) {
    const rec = records[i] ?? '';
    if (rec === '') continue;
    if (rec.startsWith('# ')) {
      readBranchHeader(rec.slice(2), out);
      continue;
    }
    const kind = rec[0];
    if (kind === '1') {
      const f = rec.split(' ');
      push(out, f[1] ?? '..', f.slice(8).join(' '));
      continue;
    }
    if (kind === '2') {
      const f = rec.split(' ');
      push(out, f[1] ?? '..', f.slice(9).join(' '));
      i += 1; // skip the original path of the rename
      continue;
    }
    if (kind === 'u') {
      const f = rec.split(' ');
      push(out, f[1] ?? 'UU', f.slice(10).join(' '));
      continue;
    }
    if (kind === '?') {
      push(out, '??', rec.slice(2));
      continue;
    }
    // `!` (ignored) is never requested and `# ` is handled above.
  }
  out.dirty.sort((a, b) => (a.rel_path < b.rel_path ? -1 : a.rel_path > b.rel_path ? 1 : 0));
  return out;
}

function readBranchHeader(line: string, out: CheckoutStatus): void {
  if (line.startsWith('branch.oid ')) {
    const oid = line.slice('branch.oid '.length).trim();
    out.head = oid === '(initial)' ? null : oid;
    return;
  }
  if (line.startsWith('branch.head ')) {
    const name = line.slice('branch.head '.length).trim();
    if (name === '(detached)') {
      out.detached = true;
      out.branch = null;
    } else {
      out.branch = name;
    }
    return;
  }
  if (line.startsWith('branch.ab ')) {
    const m = /^branch\.ab \+(\d+) -(\d+)$/.exec(line.trim());
    if (m) {
      out.ahead = Number(m[1]);
      out.behind = Number(m[2]);
    }
  }
}

function push(out: CheckoutStatus, code: string, rel: string): void {
  const rel_path = rel.trim();
  if (rel_path === '') return;
  out.dirty.push({
    rel_path,
    code,
    staged: code[0] !== '.' && code[0] !== '?' && code[0] !== undefined,
    untracked: code === '??',
  });
}

/** `git worktree list --porcelain`. The first record is the main working tree. */
export async function readWorktrees(checkout: string): Promise<GitWorktreeView[]> {
  const res = await git(checkout, ['worktree', 'list', '--porcelain'], 15_000);
  if (res.code !== 0) return [];
  const out: GitWorktreeView[] = [];
  let current: GitWorktreeView | null = null;
  const flush = (): void => {
    if (current) out.push(current);
    current = null;
  };
  for (const raw of res.stdout.split('\n')) {
    const line = raw.trimEnd();
    if (line === '') {
      flush();
      continue;
    }
    if (line.startsWith('worktree ')) {
      flush();
      current = {
        path: normalizeGitPath(line.slice('worktree '.length)),
        head: null,
        branch: null,
        detached: false,
        bare: false,
        main: out.length === 0,
        live: false,
      };
      continue;
    }
    if (!current) continue;
    if (line.startsWith('HEAD ')) current.head = line.slice('HEAD '.length);
    else if (line.startsWith('branch ')) {
      current.branch = line.slice('branch '.length).replace(/^refs\/heads\//, '');
    } else if (line === 'detached') current.detached = true;
    else if (line === 'bare') current.bare = true;
  }
  flush();
  return out;
}

/**
 * Local branches with ahead/behind against `main` (or `master`).
 * `for-each-ref` gives the list and the upstream in one call; the counts need
 * one `rev-list --count --left-right` per branch, so the list is capped.
 */
export async function readBranches(checkout: string, limit = 50): Promise<GitBranchView[]> {
  const res = await git(checkout, [
    'for-each-ref',
    '--sort=-committerdate',
    `--count=${limit}`,
    '--format=%(refname:short)%09%(objectname)%09%(upstream:short)',
    'refs/heads',
  ]);
  if (res.code !== 0) return [];
  const rows = res.stdout
    .split('\n')
    .map((l) => l.split('\t'))
    .filter((f) => (f[0] ?? '') !== '');

  const names = new Set(rows.map((f) => f[0] as string));
  const base = names.has('main') ? 'main' : names.has('master') ? 'master' : null;

  const out: GitBranchView[] = [];
  for (const f of rows) {
    const name = f[0] as string;
    const view: GitBranchView = {
      name,
      head: f[1] ?? '',
      ahead: 0,
      behind: 0,
      base,
      upstream: (f[2] ?? '') === '' ? null : (f[2] as string),
      stale: name.startsWith('task/'),
    };
    if (base && name !== base) {
      const counts = await git(checkout, [
        'rev-list',
        '--left-right',
        '--count',
        `${base}...${name}`,
      ]);
      if (counts.code === 0) {
        const m = /^(\d+)\s+(\d+)$/.exec(counts.stdout.trim());
        if (m) {
          view.behind = Number(m[1]);
          view.ahead = Number(m[2]);
        }
      }
    }
    out.push(view);
  }
  return out;
}

/** Newest `v*` tag by version (see `compareTags`), with its date and sha. */
export async function readLastRelease(checkout: string): Promise<ReleaseView | null> {
  return (await readTags(checkout, 200))[0] ?? null;
}

/** `v1.2.3` → `[1, 2, 3]`, or null for a tag that is not semver. */
export function semver(tag: string): [number, number, number] | null {
  const m = /^v(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(tag.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/**
 * Newest release first.
 *
 * Sorted by semantic version, NOT by `creatordate`: two tags created in the
 * same second (a scripted release, or a test) tie on the date and git then
 * falls back to refname, which put `v0.1.0` before `v0.2.0` and made "the
 * previous release" — and therefore the commit range a release covers —
 * non-deterministic. Version order is what "previous release" means here
 * anyway. Non-semver `v*` tags keep date order and sort after the semver ones.
 */
export function compareTags(a: ReleaseView, b: ReleaseView): number {
  const sa = semver(a.tag);
  const sb = semver(b.tag);
  if (sa && sb) {
    for (let i = 0; i < 3; i += 1) {
      const diff = (sb[i] as number) - (sa[i] as number);
      if (diff !== 0) return diff;
    }
    return a.tag < b.tag ? 1 : a.tag > b.tag ? -1 : 0;
  }
  if (sa) return -1;
  if (sb) return 1;
  const da = a.at ?? '';
  const db = b.at ?? '';
  return da < db ? 1 : da > db ? -1 : 0;
}

/** All `v*` tags, newest first. */
export async function readTags(checkout: string, limit = 200): Promise<ReleaseView[]> {
  const res = await git(checkout, [
    'for-each-ref',
    '--sort=-creatordate',
    `--count=${limit}`,
    '--format=%(refname:short)%09%(creatordate:iso-strict)%09%(objectname)',
    'refs/tags/v*',
  ]);
  if (res.code !== 0) return [];
  return res.stdout
    .split('\n')
    .map((l) => l.split('\t'))
    .filter((f) => (f[0] ?? '') !== '')
    .map((f) => ({ tag: f[0] as string, at: (f[1] ?? '') || null, sha: (f[2] ?? '') || null }))
    .sort(compareTags);
}

export async function revParse(checkout: string, rev: string): Promise<string | null> {
  const res = await git(checkout, ['rev-parse', '--verify', '--quiet', rev]);
  if (res.code !== 0) return null;
  const sha = res.stdout.trim();
  return /^[0-9a-f]{40}$/.test(sha) ? sha : null;
}

/**
 * Portable repo identity (ledger format 2): the OLDEST root commit of the
 * default branch (committer time, ties → lowest sha, so every machine picks the
 * same one). `origin/HEAD` when present, else `HEAD`. `null` for an empty repo
 * or any git failure — identity is best effort, never fatal.
 */
export async function readRootSha(checkout: string): Promise<string | null> {
  const base = (await revParse(checkout, 'refs/remotes/origin/HEAD')) !== null ? 'refs/remotes/origin/HEAD' : 'HEAD';
  const res = await git(checkout, ['log', '--max-parents=0', '--format=%H %ct', base, '--'], 10_000).catch(
    () => null,
  );
  if (res === null || res.code !== 0) return null;
  let best: { sha: string; at: number } | null = null;
  for (const line of res.stdout.split('\n')) {
    const m = /^([0-9a-f]{40}|[0-9a-f]{64}) (\d{1,12})$/.exec(line.trim());
    if (!m) continue;
    const at = Number(m[2]);
    if (best === null || at < best.at || (at === best.at && (m[1] as string) < best.sha)) {
      best = { sha: m[1] as string, at };
    }
  }
  return best !== null && rootShaSchema.safeParse(best.sha).success ? best.sha : null;
}

/** Schemes that name a network remote. `file://` (absolute path) and anything exotic is refused. */
const NETWORK_SCHEMES = new Set(['http', 'https', 'ssh', 'git', 'git+ssh', 'ssh+git']);
/** Well-known credential prefixes (GitHub, GitLab, Slack, npm, OpenAI-style, AWS). */
const TOKEN_PREFIX_RE =
  /^(?:gh[pousr]_|github_pat_|glpat-|glptt-|gldt-|xox[abeprs]-|npm_|sk-|pk_|rk_|AKIA|ASIA|AIza|ya29\.|eyJ)/i;

/** A path segment that looks like a credential rather than an org/repo name. Errs on the side
 *  of `null`: a missing hint only disables auto-bind, a leaked token reaches every peer. */
function tokenShapedSegment(seg: string): boolean {
  if (TOKEN_PREFIX_RE.test(seg)) return true;
  if (/^[0-9a-f]{32,}$/i.test(seg)) return true; // hex digest/key
  if (seg.length >= 40 && /^[A-Za-z0-9]+$/.test(seg)) return true; // long opaque run (hyphenated names are words)
  // 20+ chars mixing upper, lower and digits with no word separators: random, not a name.
  return (
    seg.length >= 20 && /^[A-Za-z0-9]+$/.test(seg) && /[a-z]/.test(seg) && /[A-Z]/.test(seg) && /[0-9]/.test(seg)
  );
}

/**
 * `origin` URL reduced to `host/org/repo`: scheme, userinfo (credentials!),
 * port, query/fragment and a trailing `.git` are dropped. Anything that does
 * not come out as a plain network `host/path` is rejected (`null`): absolute or
 * home-relative paths (`file://`, `host:/abs`, `C:/x`, `~user`), a host that
 * smuggles `user:secret`, empty/dot segments and token-shaped segments, so
 * neither a local path nor a credential can reach the synced `repos.yml`.
 */
export function originHintFromUrl(raw: string): string | null {
  let rest = raw.trim();
  if (rest === '' || rest.length > 500) return null;
  let host: string;
  let path: string;
  const scp = /^(?:[^@/:\s]+@)?([A-Za-z0-9.-]+):(?!\/\/)([^\s]+)$/.exec(rest);
  if (scp && !/^[a-z][a-z0-9+.-]*:\/\//i.test(rest)) {
    host = scp[1] as string;
    path = scp[2] as string;
  } else {
    const m = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/\s]*@)?([^/\s]+)\/([^?#\s]+)/i.exec(rest);
    if (!m || !NETWORK_SCHEMES.has((m[1] as string).toLowerCase())) return null;
    host = (m[2] as string).replace(/:\d{1,5}$/, '');
    path = m[3] as string;
  }
  // A one-letter "host" is a Windows drive (`C:/Users/..`), not a remote.
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(host) || host.length < 2) return null;
  path = path.replace(/\/+$/, '').replace(/\.git$/i, '');
  const segments = path.split('/');
  for (const seg of segments) {
    // empty = `host//abs` or `host:/abs`; `~x` = home dir; dot segments are traversal.
    if (seg === '' || seg === '.' || seg === '..' || seg.startsWith('~')) return null;
    if (tokenShapedSegment(seg)) return null;
  }
  rest = `${host}/${segments.join('/')}`;
  const hint = originHintSchema.safeParse(rest);
  return hint.success ? hint.data : null;
}

export async function readOriginHint(checkout: string): Promise<string | null> {
  const res = await git(checkout, ['config', '--get', 'remote.origin.url'], 5_000).catch(() => null);
  if (res === null || res.code !== 0) return null;
  return originHintFromUrl(res.stdout.split('\n')[0] ?? '');
}

/** Output separators. `spawn` refuses an argv entry containing a NUL byte, so
 *  the format string asks git to emit them via `%x00` / `%x01` instead. */
const NUL = '\u0000';
const RS = '\u0001';
const FORMAT = '%H%x00%h%x00%s%x00%cI%x00%B%x01';

/**
 * Commits in `range` (`a..b`, or a single rev), oldest first, with trailers and
 * changed files. One `git log` call for the metadata, one `diff --name-only`
 * per commit for the files — `--name-only` on `log` would interleave with the
 * custom format and is unparseable for merges.
 */
export async function readCommits(
  checkout: string,
  range: string,
  limit = 100,
): Promise<CommitInfo[]> {
  const res = await git(checkout, [
    'log',
    '--no-show-signature',
    `--max-count=${limit}`,
    '--reverse',
    '--no-merges',
    `--format=${FORMAT}`,
    range,
  ]);
  if (res.code !== 0) return [];
  const out: CommitInfo[] = [];
  for (const chunk of res.stdout.split(RS)) {
    const rec = chunk.replace(/^\n+/, '');
    if (rec.trim() === '') continue;
    const f = rec.split(NUL);
    const sha = (f[0] ?? '').trim();
    if (!/^[0-9a-f]{40}$/.test(sha)) continue;
    const bodyText = f[4] ?? '';
    out.push({
      sha,
      short: (f[1] ?? sha.slice(0, 7)).trim(),
      subject: sanitizeField(f[2] ?? '', 120),
      body: bodyText,
      at: (f[3] ?? '').trim(),
      files: await readCommitFiles(checkout, sha),
      closes: trailerIds(bodyText, 'Closes'),
      refs: trailerIds(bodyText, 'Refs'),
    });
  }
  return out;
}

/**
 * Recent commits that touched ONE path, newest first, without the
 * per-commit `diff --name-only` pass — the caller already knows the file.
 *
 * `--since` rather than a range: this runs on the PostToolUse path (capped at a
 * handful of files per session) and a date-bounded single-path log is the
 * cheapest question git can answer here. `--` separates the pathspec from revs
 * so a file named like a branch cannot be reinterpreted.
 */
export async function readPathCommits(
  checkout: string,
  relPath: string,
  sinceDays: number,
  limit = 10,
): Promise<Omit<CommitInfo, 'files'>[]> {
  const res = await git(
    checkout,
    [
      'log',
      '--no-show-signature',
      `--max-count=${limit}`,
      '--no-merges',
      `--since=${sinceDays}.days`,
      `--format=${FORMAT}`,
      '--',
      relPath,
    ],
    5_000,
  );
  if (res.code !== 0) return [];
  return parseLog(res.stdout);
}

/**
 * `ledger tidy`: every commit of HEAD since a point in time, ONE `git log`
 * for the whole repo (never one per item), newest first, without files. The
 * `--since` value is built here from a number, never from caller text.
 */
export async function readCommitsSince(
  checkout: string,
  sinceMs: number,
  limit = 500,
  timeoutMs = 8_000,
): Promise<Omit<CommitInfo, 'files'>[]> {
  if (!Number.isFinite(sinceMs)) return [];
  const res = await git(
    checkout,
    [
      'log',
      '--no-show-signature',
      `--max-count=${Math.max(1, Math.min(Math.trunc(limit), 2_000))}`,
      '--no-merges',
      `--since=${new Date(Math.max(0, sinceMs)).toISOString()}`,
      `--format=${FORMAT}`,
    ],
    timeoutMs,
  );
  if (res.code !== 0) return [];
  return parseLog(res.stdout);
}

/** Parse `git log --format=FORMAT` output into commits (no files). */
function parseLog(stdout: string): Omit<CommitInfo, 'files'>[] {
  const out: Omit<CommitInfo, 'files'>[] = [];
  for (const chunk of stdout.split(RS)) {
    const rec = chunk.replace(/^\n+/, '');
    if (rec.trim() === '') continue;
    const f = rec.split(NUL);
    const sha = (f[0] ?? '').trim();
    if (!/^[0-9a-f]{40}$/.test(sha)) continue;
    const bodyText = f[4] ?? '';
    out.push({
      sha,
      short: (f[1] ?? sha.slice(0, 7)).trim(),
      subject: sanitizeField(f[2] ?? '', 120),
      body: bodyText,
      at: (f[3] ?? '').trim(),
      closes: trailerIds(bodyText, 'Closes'),
      refs: trailerIds(bodyText, 'Refs'),
    });
  }
  return out;
}

/**
 * `ledger why`: the newest commits that touched a path, a directory or a simple
 * glob — no date window, a hard count instead. The pathspec is built HERE from
 * a repo-relative string the caller already validated: `:(literal)` makes a
 * file named `*.ts` or `:(top)x` mean exactly that file, `:(glob)` is the one
 * magic we hand out on purpose (`*`/`?` stay inside a segment, `**` crosses).
 * `--` ends the options before it either way. Failure is an empty answer.
 */
export async function readPathHistory(
  checkout: string,
  rel: string,
  mode: 'literal' | 'glob',
  limit: number,
): Promise<Omit<CommitInfo, 'files'>[]> {
  const res = await git(
    checkout,
    [
      'log',
      '--no-show-signature',
      `--max-count=${Math.max(1, Math.min(limit, 200))}`,
      '--no-merges',
      `--format=${FORMAT}`,
      '--',
      `:(${mode})${rel}`,
    ],
    5_000,
  );
  if (res.code !== 0) return [];
  return parseLog(res.stdout);
}

/**
 * Is `rel` (a plain repo-relative path, never a pathspec) matched by a
 * gitignore rule? `check-ignore -q` exits 0 = ignored, 1 = not ignored; a
 * tracked file is reported as not ignored. Anything else (git failure,
 * timeout, a path beyond a symlink) is `unknown` — the caller treats it like
 * `ignored`: a privacy filter must fail closed.
 */
export async function checkIgnored(
  checkout: string,
  rel: string,
): Promise<'ignored' | 'not-ignored' | 'unknown'> {
  try {
    const res = await git(checkout, ['check-ignore', '-q', '--', rel], 3_000);
    if (res.code === 0) return 'ignored';
    if (res.code === 1) return 'not-ignored';
    return 'unknown';
  } catch {
    return 'unknown';
  }
}

async function readCommitFiles(checkout: string, sha: string): Promise<string[]> {
  // `diff-tree` is not on the SPEC allow-list; `diff --name-only <sha>^!` is
  // the same information with an allowed command, and `^!` works on a root
  // commit too (it expands to "this commit against its parents").
  const res = await git(checkout, ['diff', '--name-only', `${sha}^!`]);
  if (res.code !== 0) return [];
  return res.stdout
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

/** `Closes: ACME-1, ACME-2` / one trailer per line, case-insensitive key. */
export function trailerIds(body: string, key: 'Closes' | 'Refs'): string[] {
  const out = new Set<string>();
  const re = new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'gim');
  for (const m of body.matchAll(re)) {
    // Fresh global regex per call (a shared /g regex carries `lastIndex`).
    for (const id of (m[1] ?? '').toUpperCase().matchAll(itemIdScanRe())) {
      out.add(id[0]);
    }
  }
  return [...out];
}

/**
 * Tracked files of a checkout, capped. Used to tell `app/src/**` (a
 * claim over a whole tree) from `app/src/billing/**`. Capped because the count
 * only has to answer "is this wider than ~200 files", and an unbounded
 * `ls-files` on a big monorepo is a 100k-line read for nothing.
 */
export async function listTrackedFiles(checkout: string, cap = 5_000): Promise<string[]> {
  const res = await git(checkout, ['ls-files', '-z']);
  if (res.code !== 0) return [];
  return res.stdout.split('\0').filter((p) => p !== '').slice(0, cap);
}

/**
 * "which of THESE paths are tracked?" — the targeted form of
 * `listTrackedFiles`.
 *
 * `listTrackedFiles`' two defences against a big monorepo are exactly what
 * broke `releaseCleanTouched`: the `cap` (5 000) silently truncates, so in a
 * 50 000-file repo a tracked-and-clean path that sorts past the cap looks
 * untracked and its `touched` lock is never released; and a failing/timing-out
 * `ls-files` returns `[]`, which makes EVERY path look untracked. Both fail in
 * the direction of "keep the lock forever", which is the bug an agent sees as
 * a permanent deny on a file nobody is editing.
 *
 * Asking only about the candidate paths removes both: the answer is bounded by
 * the number of `touched` rows (tens), not by repo size, so no cap is needed
 * and the cost does not grow with the checkout.
 *
 * `:(literal)` on every pathspec: a `touched` rel_path is a real filename, and
 * without it a file legitimately named `a[1].ts` or `*.ts` would be read as a
 * glob and could report a DIFFERENT file as tracked. Batched because the list
 * becomes argv; a batch that fails is retried ONE PATH AT A TIME
 * instead of leaving the whole batch "not proven tracked" — one malformed or
 * otherwise git-upsetting path must not hold the lock open for the other
 * ~199 unrelated `touched` rows in it. Each retried path keeps the same
 * fail-closed rule individually: a path whose solo `ls-files` call still
 * errors is still "not proven tracked".
 */
export async function listTrackedAmong(
  checkout: string,
  relPaths: readonly string[],
  batchSize = 200,
): Promise<Set<string>> {
  const wanted = relPaths.filter(
    (p) =>
      typeof p === 'string' &&
      p !== '' &&
      !p.includes('\0') &&
      !p.startsWith('/') &&
      !p.split('/').includes('..'),
  );
  const lookup = new Set(wanted);
  const out = new Set<string>();
  const collect = (stdout: string): void => {
    for (const p of stdout.split('\0')) {
      if (p !== '' && lookup.has(p)) out.add(p);
    }
  };
  for (let i = 0; i < wanted.length; i += batchSize) {
    const batch = wanted.slice(i, i + batchSize);
    const res = await git(checkout, ['ls-files', '-z', '--', ...batch.map((p) => `:(literal)${p}`)]);
    if (res.code === 0) {
      collect(res.stdout);
      continue;
    }
    // R5: shrink the blast radius from "whole batch" to "this path".
    for (const p of batch) {
      const single = await git(checkout, ['ls-files', '-z', '--', `:(literal)${p}`]);
      if (single.code !== 0) continue; // fail-closed per path, same as before
      collect(single.stdout);
    }
  }
  return out;
}

/** Merge git dirty files with `touched` ownership for the UI (SPEC §13). */
export function joinDirtyOwners(
  dirty: CheckoutStatus['dirty'],
  owners: Map<string, { session: string; via: TouchedVia; orphan: boolean }>,
): DirtyFileView[] {
  return dirty.map((d) => {
    const owner = owners.get(d.rel_path);
    return {
      rel_path: d.rel_path,
      code: d.code,
      staged: d.staged,
      untracked: d.untracked,
      owner: owner?.session ?? null,
      owner_short: owner ? owner.session.slice(0, 4) : null,
      via: owner?.via ?? null,
      orphan: owner?.orphan ?? false,
    };
  });
}
