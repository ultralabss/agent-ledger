/** Git via `spawn(<resolved absolute path>, [...])` — never a shell string,
 *  never a PATH-resolved `git` (SPEC §6.1, S6). */

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import type { Stats } from 'node:fs';
import { rmdirSync } from 'node:fs';
import { lstat, mkdtemp, readFile, readdir, realpath, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve as resolvePath, win32 as winPath } from 'node:path';
import {
  assertPrivateDir,
  assertTrustedAncestors,
  ensurePrivateDir,
  isOwnedByMe,
  resolveTrustedExecutable,
  TrustError,
} from '@agent-ledger/shared';

export interface GitResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Absolute-path candidates, preferred first. Resolved once and cached — a
 *  writable-by-group/other or not-owned-by-us/root binary is rejected. */
const POSIX_GIT_CANDIDATES = ['/usr/bin/git', '/opt/homebrew/bin/git', '/usr/local/bin/git'];

/**
 * win32: Git for Windows install locations built from env roots. An env var that is not
 * an absolute drive-rooted path (`C:\...`) is dropped, never resolved against the CWD or
 * PATH (T7). The binaries are then judged by `resolveTrustedExecutable` (SDDL: only
 * {me, SYSTEM, Administrators, TrustedInstaller} may write them or their directories).
 */
export function gitCandidates(
  platform: NodeJS.Platform = process.platform,
  env: Readonly<Record<string, string | undefined>> = process.env,
): string[] {
  if (platform !== 'win32') return [...POSIX_GIT_CANDIDATES];
  const roots: [string | undefined, string[]][] = [
    [env.ProgramW6432, ['Git', 'cmd', 'git.exe']],
    [env.ProgramFiles, ['Git', 'cmd', 'git.exe']],
    [env.LOCALAPPDATA, ['Programs', 'Git', 'cmd', 'git.exe']],
  ];
  const out: string[] = [];
  for (const [base, rest] of roots) {
    if (typeof base !== 'string' || !/^[A-Za-z]:\\/.test(base) || base.includes('\0')) continue;
    const candidate = winPath.join(base, ...rest);
    if (!out.includes(candidate)) out.push(candidate);
  }
  return out;
}

let resolvedGit: Promise<string> | null = null;

/** A8-4: an EXPLICIT decision about group-writable components, never a derived
 *  one. Unset (production, git and the managed gitleaks copy) means "a `g+w`
 *  component is not trusted" — no group membership is enumerated anywhere any
 *  more, see `bintrust.ts`. The only production caller that sets it is
 *  `claudebin.ts`, and only after the user ran
 *  `install.sh --trust-claude-group`. */
export interface TrustDeps {
  groupWritableOk?: (gid: number) => Promise<boolean>;
}

/** N1: a trustworthy file in an untrustworthy directory is not trustworthy —
 *  anyone who can write `/usr/local/bin` can `mv` their own `git` over it, and
 *  the file's own mode/owner would still look perfect. Every directory
 *  component from the root down must be owned by root or by us and must not be
 *  writable by anyone outside {root, us} (sticky dirs like `/tmp` are rejected
 *  too — we never expect a git binary there).
 *
 *  A8-4: `g+w` is disqualifying again. The earlier exception (accept `g+w` when
 *  the owning group enumerates to a subset of {root, us}) was not fail-closed —
 *  macOS group enumeration misses nested groups and non-local accounts — so it
 *  is gone. `deps.groupWritableOk` is now an explicit opt-in, set only by the
 *  claude binary path after `install.sh --trust-claude-group`. `o+w` is
 *  absolute and cannot be opted into. See `bintrust.ts`. */
export async function dirChainTrusted(
  file: string,
  uid: number | undefined,
  /** Highest directory to check, inclusive. `/` in production; tests bound it
   *  to their own sandbox, because a temp dir's ancestry (`/tmp`, `1777`) is
   *  legitimately world-writable and would make every case fail. */
  stopAt = '/',
  deps: TrustDeps = {},
): Promise<boolean> {
  // The decision itself lives in platformTrust (POSIX: the exact walk this used to be;
  // win32: SDDL of every ancestor). Any failure to decide is a "no" (I1).
  try {
    await assertTrustedAncestors(
      file,
      {
        stopAt,
        executable: true,
        ...(deps.groupWritableOk !== undefined ? { groupWritableOk: deps.groupWritableOk } : {}),
      },
      { getuid: () => uid },
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve an absolute, trustworthy path for one of `candidates`, applying the
 * exact same owner/mode/dir-chain rules the git binary has always used (N1).
 * Extracted verbatim from `resolveGitBinary` so `gitleaks.ts` cannot drift
 * into a weaker check — behaviour for git is unchanged.
 */
export interface TrustedBinaryInfo {
  /** The trusted absolute path, or `null` when nothing passed. */
  path: string | null;
  /** Candidates that exist on disk but failed the trust rules. */
  rejected: string[];
  /** Candidates that were not absolute (win32: drive-rooted) and were never looked at. */
  dropped: string[];
  candidates: readonly string[];
  /** Diagnostic only: `rejected` is non-empty, so a binary IS installed. */
  foundUntrusted: boolean;
  /** A8-4: true when a candidate failed ONLY because some component of its
   *  chain (or the file itself) is group-writable — i.e. it would pass if the
   *  caller consciously accepted `g+w`. Lets `claudebin.ts` print the precise
   *  "install into ~/.local or use --trust-claude-group" message instead of a
   *  generic "untrusted path". Never widens trust by itself. */
  groupWritable: boolean;
}

/**
 * The decision is byte-for-byte the one `resolveTrustedBinary` always
 * made — this only reports *why* nothing passed, so a caller can say "found,
 * but in an untrusted directory" instead of "not installed". Nothing here
 * widens trust.
 */
export async function resolveTrustedBinaryInfo(
  candidates: readonly string[],
  stopAt?: string,
  deps: TrustDeps = {},
): Promise<TrustedBinaryInfo> {
  const info = await resolveTrustedExecutable(candidates, {
    ...(stopAt !== undefined ? { stopAt } : {}),
    ...(deps.groupWritableOk !== undefined ? { groupWritableOk: deps.groupWritableOk } : {}),
  });
  return {
    path: info.path,
    rejected: info.rejected,
    dropped: info.dropped,
    candidates: info.candidates,
    foundUntrusted: info.foundUntrusted,
    groupWritable: info.groupWritable,
  };
}

export function trustedBinaryError(label: string, info: TrustedBinaryInfo): Error {
  return new Error(
    `${label}: no trusted binary found (tried: ${info.candidates.join(', ')}${
      info.rejected.length > 0 ? `; rejected: ${info.rejected.join(', ')}` : ''
    })`,
  );
}

export async function resolveTrustedBinary(
  candidates: readonly string[],
  label: string,
  /** Highest directory the chain check walks to. Production leaves this at `/`;
   *  a test bounds it to its own temp dir, because `tmpdir()` itself is sticky
   *  and world-writable and would (correctly) be rejected in production. */
  stopAt?: string,
  deps: TrustDeps = {},
): Promise<string> {
  const info = await resolveTrustedBinaryInfo(candidates, stopAt, deps);
  if (info.path !== null) return info.path;
  throw trustedBinaryError(label, info);
}

/** Was a verbatim copy of `resolveTrustedBinaryInfo`. Collapsed into the
 *  shared helper so git, gitleaks and the headless `claude` binary can never
 *  drift to three different definitions of "trusted". */
function resolveGitBinary(): Promise<string> {
  return resolveTrustedBinary(gitCandidates(), 'git');
}

function gitBinary(): Promise<string> {
  resolvedGit ??= resolveGitBinary();
  return resolvedGit;
}

/**
 * Global options prepended to EVERY invocation (SPEC §6.3):
 *  - `--no-optional-locks`: without it the hub takes `index.lock` and every
 *    session in that checkout starts failing with "index.lock exists".
 *  - `-c core.fsmonitor=false`: the config value is attacker-controlled in any
 *    repo we did not create (it is a shell command git would run for us), and
 *    `status` is exactly the command that honours it.
 *  - `-c core.hooksPath=/dev/null`: same reasoning for repo-local hooks.
 *  - `-c log.showSignature=false`: with it true (repo-local config) `git log`
 *    runs `gpg.program` (also repo-local) for every signed commit in history —
 *    arbitrary code execution from a checkout we did not create (UL-669 T1).
 */
export function buildGitGlobalArgs(hooksDir: string): string[] {
  return [
    '--no-optional-locks',
    '-c',
    'core.fsmonitor=false',
    '-c',
    `core.hooksPath=${hooksDir}`,
    '-c',
    'log.showSignature=false',
    // Ledger files are LF on disk and in git (I7); never let a user's global config
    // (Git for Windows defaults to autocrlf=true) rewrite them.
    '-c',
    'core.autocrlf=false',
    '-c',
    'core.eol=lf',
    '-c',
    'core.longpaths=true',
  ];
}

/* ---- hooks directory (I4) ------------------------------------------------------------
 * `core.hooksPath=/dev/null` is a POSIX idiom: Git for Windows resolves it to
 * `<drive>:\dev\null`, a path any user may create and fill with hooks. Instead EVERY OS
 * gets a verified private, EMPTY directory (platformTrust: real dir, ours, private ACL/mode)
 * that is re-asserted empty before each spawn. Hooks are looked up by fixed names, so only
 * our own capability probe file (`.ledger-fsprobe-*`) may ever be present. */

let configuredHooksDir: string | null = null;
let fallbackHooksDir: Promise<string> | null = null;
const verifiedHooksDirs = new Set<string>();
const PROBE_PREFIX = '.ledger-fsprobe-';

/** The hub points git at `<ledger>/.hub/empty-hooks` (called by `LedgerGit`). `null` resets. */
export function configureGitHooksDir(dir: string | null): void {
  configuredHooksDir = dir;
}

/** No ledger configured (CLI helpers, tests): a random private per-process temp dir. */
function processHooksDir(): Promise<string> {
  fallbackHooksDir ??= mkdtemp(join(tmpdir(), 'agent-ledger-hooks-')).then((dir) => {
    process.once('exit', () => {
      // best effort; a leftover empty private dir is harmless
      try {
        rmdirSync(dir);
      } catch {
        /* ignore */
      }
    });
    return dir;
  });
  return fallbackHooksDir;
}

/** Verify (and on first use create) the empty hooks dir; returns its path. Fail-closed. */
async function emptyHooksDir(): Promise<string> {
  const dir = configuredHooksDir ?? (await processHooksDir());
  try {
    const present = (await lstat(dir).catch(() => null)) !== null;
    if (!present || !verifiedHooksDirs.has(dir)) {
      await ensurePrivateDir(dir);
      verifiedHooksDirs.add(dir);
    } else {
      await assertPrivateDir(dir);
    }
    const entries = (await readdir(dir)).filter((e) => !e.startsWith(PROBE_PREFIX));
    if (entries.length > 0) {
      throw new Error(`git hooks directory ${dir} is not empty — refusing to run git`);
    }
  } catch (err) {
    verifiedHooksDirs.delete(dir);
    if (err instanceof TrustError) throw new Error(`git hooks directory refused: ${err.message}`);
    throw err;
  }
  return dir;
}

/** G1: a git child (e.g. `log` on a huge/adversarial repo) can produce
 *  unbounded stdout/stderr — accumulating it in JS strings without a cap is
 *  an OOM. Kill the child once either stream crosses this cap and resolve
 *  with `code: -1` instead of throwing, so callers (gitreader, repowatch,
 *  sessions) can treat it like any other failed git call. */
const GIT_OUTPUT_CAP_BYTES = 8 * 1024 * 1024;

/**
 * `spawn` with a `cwd` that no longer exists fails with
 * `spawn /usr/bin/git ENOENT` — a message that reads like "git is missing" and
 * sent several debugging sessions after the binary instead of after the
 * vanished worktree (15 of them in one hub.log). A removed checkout is normal
 * (a `git worktree remove` of an agent worktree, a renamed project dir), so it
 * gets its own type that callers can recognise.
 */
export class GitCwdMissingError extends Error {
  readonly cwd: string;

  constructor(cwd: string) {
    super(`git: working directory does not exist (${cwd})`);
    this.name = 'GitCwdMissingError';
    this.cwd = cwd;
  }
}

export async function git(cwd: string, args: string[], timeoutMs = 20_000): Promise<GitResult> {
  const bin = await gitBinary();
  // One `stat` before the spawn, so a vanished checkout is a typed
  // error instead of an ENOENT about the git binary — and no process is
  // started for a directory that cannot answer anything.
  const cwdStat = await stat(cwd).catch(() => null);
  if (cwdStat === null || !cwdStat.isDirectory()) throw new GitCwdMissingError(cwd);
  const hooksDir = await emptyHooksDir();
  return new Promise((resolvePromise, reject) => {
    const child = spawn(bin, [...buildGitGlobalArgs(hooksDir), ...args], {
      cwd,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let capped = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    const overCap = () => {
      if (capped) return;
      capped = true;
      child.kill('SIGKILL');
    };
    child.stdout.on('data', (d: Buffer) => {
      if (capped) return;
      stdoutBytes += d.length;
      if (stdoutBytes > GIT_OUTPUT_CAP_BYTES) {
        overCap();
        return;
      }
      stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d: Buffer) => {
      if (capped) return;
      stderrBytes += d.length;
      if (stderrBytes > GIT_OUTPUT_CAP_BYTES) {
        overCap();
        return;
      }
      stderr += d.toString('utf8');
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      if (capped) return;
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (capped) {
        resolvePromise({ code: -1, stdout, stderr: `${stderr}\ngit: output exceeded the cap of ${GIT_OUTPUT_CAP_BYTES} B, process killed` });
        return;
      }
      resolvePromise({ code: code ?? -1, stdout, stderr });
    });
  });
}

/**
 * realpath of the git toplevel for `dir`, or null when `dir` is not (inside)
 * a repo we're willing to trust.
 *
 * S10: `dir` can come straight from an API body (`POST /v1/repos`'s `path`)
 * for a directory the caller doesn't own on this machine. Spawning git in it
 * would read that repo's `.git/config` — `core.fsmonitor` / `include.path`
 * are attacker-controlled config in that scenario. Measured empirically:
 * `git --no-optional-locks rev-parse --show-toplevel` (the exact call this
 * used to make) does NOT invoke `core.fsmonitor` — only `git status` and
 * similar working-tree commands do — so the old code was not exploitable via
 * that specific vector. Fixed anyway, per the audit: walk up from `dir`
 * looking for a `.git` entry ourselves, no git process involved at all.
 */
export async function gitToplevel(dir: string): Promise<string | null> {
  return (await resolveCheckout(dir))?.checkout ?? null;
}

/** Where a checkout's metadata lives. All paths are realpath'd absolutes. */
export interface CheckoutLayout {
  /** Working-tree root (what `rev-parse --show-toplevel` would print). */
  checkout: string;
  /** `.git` of this checkout — for a worktree, the per-worktree dir. */
  gitDir: string;
  /** Shared dir (`rev-parse --git-common-dir`) — the repo identity (SPEC §2). */
  commonDir: string;
  /** True when `.git` is a file pointing into `<common>/worktrees/<name>`. */
  worktree: boolean;
}

/**
 * N2: decide "is this a git checkout?" from the filesystem alone — never by
 * spawning git in a directory the caller handed us (S6/S10: that reads the
 * repo's own `.git/config`, where `core.fsmonitor` is a command).
 *
 * Accepted shapes, and nothing else:
 *  - `.git/` directory that contains a `HEAD` file, or
 *  - `.git` *file* whose single line is `gitdir: <path>` and whose target is an
 *    existing directory containing `HEAD` (that is a linked worktree).
 *
 * A directory with a `.git` that is a dangling symlink, an empty file, a
 * socket, or a directory without `HEAD` is not a repo — F0 accepted all of
 * those and would have registered them.
 */
export async function resolveCheckout(dir: string): Promise<CheckoutLayout | null> {
  let current: string;
  try {
    current = await realpath(dir);
  } catch {
    return null;
  }
  for (;;) {
    const layout = await readGitEntry(current);
    if (layout) {
      const st = await safeStat(current);
      if (!st?.isDirectory()) return null;
      // Fail-closed (I1): unknown uid / unreadable owner = not ours. (`current` is a
      // realpath, so the lstat inside isOwnedByMe sees the directory itself.)
      if (!(await checkoutOwnedByMe(current))) return null;
      return layout;
    }
    const parent = dirname(current);
    if (parent === current) return null; // reached the filesystem root
    current = parent;
  }
}

/** win32 resolves ownership with a PowerShell call: remember positives for a minute. */
const ownedCache = new Map<string, number>();
const OWNED_CACHE_MS = 60_000;

async function checkoutOwnedByMe(dir: string): Promise<boolean> {
  if (process.platform === 'win32') {
    const at = ownedCache.get(dir);
    if (at !== undefined && Math.abs(Date.now() - at) < OWNED_CACHE_MS) return true;
    const ok = await isOwnedByMe(dir);
    if (ok) ownedCache.set(dir, Date.now());
    return ok;
  }
  return isOwnedByMe(dir);
}

async function safeStat(p: string): Promise<Stats | null> {
  try {
    return await stat(p);
  } catch {
    return null;
  }
}

async function isDirWithHead(p: string): Promise<boolean> {
  const st = await safeStat(p);
  if (!st?.isDirectory()) return false;
  const head = await safeStat(join(p, 'HEAD'));
  return head?.isFile() ?? false;
}

async function readGitEntry(checkout: string): Promise<CheckoutLayout | null> {
  const entry = join(checkout, '.git');
  const st = await safeStat(entry); // follows symlinks on purpose
  if (!st) return null;

  if (st.isDirectory()) {
    if (!(await isDirWithHead(entry))) return null;
    const gitDir = await realpath(entry);
    return { checkout, gitDir, commonDir: gitDir, worktree: false };
  }

  if (!st.isFile() || st.size > 4096) return null;
  let text: string;
  try {
    text = await readFile(entry, 'utf8');
  } catch {
    return null;
  }
  const m = /^gitdir:\s*(.+?)\s*$/m.exec(text);
  if (!m?.[1]) return null;
  const raw = m[1];
  const target = isAbsolute(raw) ? raw : resolvePath(checkout, raw);
  if (!(await isDirWithHead(target))) return null;
  const gitDir = await realpath(target);

  // `<gitdir>/commondir` points at the shared `.git` (usually `../..`).
  let commonDir = gitDir;
  try {
    const rel = (await readFile(join(gitDir, 'commondir'), 'utf8')).trim();
    if (rel !== '') {
      const candidate = isAbsolute(rel) ? rel : resolvePath(gitDir, rel);
      if (await isDirWithHead(candidate)) commonDir = await realpath(candidate);
    }
  } catch {
    // No `commondir` → treat the gitdir as its own common dir.
  }
  return { checkout, gitDir, commonDir, worktree: commonDir !== gitDir };
}

export interface LedgerGitStatus {
  enabled: boolean;
  pendingSummaries: number;
  lastCommit: string | null;
  lastCommitAt: string | null;
  lastPushAt: string | null;
  lastPushError: string | null;
  /** Read from the repo at boot so a restarted hub does not report
   *  `git — · push —` until it happens to commit something. */
  upstream: string | null;
  ahead: number | null;
  behind: number | null;
  /** Result of the last gitleaks run in front of a commit. */
  secretScan: {
    scanner: 'gitleaks' | null;
    blocked: boolean;
    blockedAt: string | null;
    note: string | null;
    /** When the next commit attempt is scheduled after an
     *  inconclusive scan (timeout / spawn error). `null` = nothing pending. */
    retryAt: string | null;
  };
  /** Active S1 hold. `leak` = proof the token reached git (token was
   *  rotated); `unsafe` = not ignored but not leaked (no rotation). `unsafe`
   *  lifts itself once a later check is clean; `leak` (A8-1) only lifts once
   *  rotation is confirmed on disk AND the token is absent from `git log --all`.
   *  `blockedDetail` (A8-8) is the current reason it is STILL blocked, kept
   *  separate from `reason` (why it was raised) and from `lastPushError`. */
  securityHold:
    | { kind: 'unsafe'; reason: string; since: string }
    | {
        kind: 'leak';
        reason: string;
        since: string;
        leakedHash: string | null;
        rotationOk: boolean;
        blockedDetail: string | null;
      }
    | null;
  /** Consecutive inconclusive S1 checks. These never cause a lockdown,
   *  but they do stop commits, so they must be visible. */
  tokenCheck: { consecutiveErrors: number; lastError: string | null; lastErrorAt: string | null };
}

export interface LedgerGitOptions {
  root: string;
  commitDebounceMs: number;
  pushIntervalMs: number;
  push: boolean;
  log: (line: string) => void;
  /** Append a ledger journal line for S1 security events. Optional and
   *  fail-soft — the hub must still lock down if journalling is unavailable. */
  journal?: (type: string, fields: string[]) => Promise<void>;
  /** Test seam. Defaults to the real gitleaks runner. */
  scanStaged?: (root: string) => Promise<{
    scanner: 'gitleaks' | null;
    blocked: boolean;
    note: string | null;
    /** The scan did not reach a verdict (timeout, spawn error) — the
     *  commit stays blocked, but it is worth retrying soon. */
    retryable?: boolean;
  }>;
  /** False right after a wake — the commit (and its gitleaks child,
   *  which is what timed out after every wake) waits for the gate. */
  heavyAllowed?: () => boolean;
  /** Ms until `heavyAllowed()` opens again. */
  heavyRetryInMs?: () => number;
}

/** Credentials embedded in a remote URL (`https://user:token@host/…`) must
 *  never reach a log, the brief or healthz. */
export function redactUrlCredentials(line: string): string {
  return line.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/\s@]*@/gi, '$1***@');
}

/** Path of the hub token, relative to the ledger root — must always stay
 *  git-ignored and untracked (S1). */
const TOKEN_REL_PATH = '.hub/token';
const TOKEN_REL_PATH_LOWER = TOKEN_REL_PATH.toLowerCase();

/** A8-9: APFS (default on macOS) is case-insensitive — `git add .hub/TOKEN`
 *  stages (and `git log`/`diff` report) a path git's own index keeps verbatim
 *  as given, not as the on-disk casing. A naive exact string compare against
 *  the lowercase `TOKEN_REL_PATH` constant then misses the leak entirely even
 *  though it is the exact same file on disk as the real token. */
function isTokenPath(line: string): boolean {
  return line.trim().toLowerCase() === TOKEN_REL_PATH_LOWER;
}

/** How many consecutive inconclusive S1 checks before we stop being
 *  quiet about it. One `index.lock` collision is normal; three in a row means
 *  the ledger has silently stopped being backed up and a human should look. */
export const CHECK_ERROR_WARN_AFTER = 3;

/**
 * Backoff after an INCONCLUSIVE gitleaks scan (timeout, spawn error).
 *
 * The commit stays blocked (fail-closed): a scanner that can be made to
 * time out must not be a way to get an unscanned commit through. But waiting
 * for the next random `touch()` meant the ledger could sit uncommitted for
 * hours after a wake, which is how the live hub stopped committing. So: retry
 * soon, then back off, then keep trying every 5 minutes.
 */
export const SCAN_RETRY_DELAYS_MS = [15_000, 60_000, 300_000] as const;

/** `streak` is 1 for the first retry. Caps at the last delay. */
export function scanRetryDelayMs(streak: number): number {
  const i = Math.min(Math.max(1, streak) - 1, SCAN_RETRY_DELAYS_MS.length - 1);
  return SCAN_RETRY_DELAYS_MS[i]!;
}

/** Outcome of the S1 check. Only `leak` is proof. */
type TokenInvariant =
  | { kind: 'ok' }
  | { kind: 'leak'; reason: string }
  | { kind: 'unsafe'; reason: string }
  | { kind: 'unknown'; reason: string };

/** Readable one-liner for a git call that produced no usable answer. */
function gitFailureNote(res: GitResult): string {
  const tail = res.stderr.trim().split('\n').slice(-1)[0] ?? '';
  return `exit ${res.code}${tail === '' ? '' : ` — ${redactUrlCredentials(tail)}`}`;
}

/** Batched commits (debounce) + throttled push. A push failure is never fatal:
 *  it is logged and surfaced in `/v1/healthz` (SPEC §4.8). */
export class LedgerGit {
  private readonly opts: LedgerGitOptions;
  private summaries: string[] = [];
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<void> = Promise.resolve();
  private lastPush = 0;
  private state: LedgerGitStatus;
  /** Hard disable: `git init` failed, there is no repo to commit to. Separate
   *  from the S1 hold below, which is recoverable. */
  private enabled = true;
  /** Recoverable S1 hold. In-memory on purpose — a restart re-evaluates
   *  from the repo instead of inheriting a verdict nobody can audit.
   *  A8-1: a `leak` hold additionally carries proof of rotation —
   *  `leakedHash` (sha256 of the token file at lockdown time, before rotation)
   *  and `rotationOk` (whether `onTokenLeak()` completed without throwing) —
   *  so it can never self-release just because the working tree went quiet. */
  private hold:
    | { kind: 'unsafe'; reason: string; since: string }
    | {
        kind: 'leak';
        reason: string;
        since: string;
        leakedHash: string | null;
        rotationOk: boolean;
        /** A8-1/A8-8: why the hold STILL hasn't lifted on the most recent
         *  check — distinct from `reason` (the original lockdown cause) so
         *  neither overwrites the other, and so healthz/brief can show the
         *  current remedy (e.g. "token is still in history") without losing
         *  why the lockdown happened in the first place. */
        blockedDetail: string | null;
      }
    | null = null;
  private checkErrors = 0;
  private lastCheckError: string | null = null;
  /** Called once, if ever, when the token-tracked invariant breaks (S1).
   *  A8-1: now returns whether rotation actually completed — a swallowed
   *  failure must not be indistinguishable from success. */
  private onTokenLeak: (() => Promise<boolean>) | null = null;
  /** Consecutive inconclusive gitleaks scans. Drives the backoff and
   *  keeps the SECURITY line to one per streak instead of one per attempt. */
  private scanStreak = 0;

  constructor(opts: LedgerGitOptions) {
    this.opts = opts;
    // Every git child of this hub runs with hooks disabled via a verified empty dir (I4).
    configureGitHooksDir(join(opts.root, '.hub', 'empty-hooks'));
    this.state = {
      enabled: true,
      pendingSummaries: 0,
      lastCommit: null,
      lastCommitAt: null,
      lastPushAt: null,
      lastPushError: null,
      upstream: null,
      ahead: null,
      behind: null,
      secretScan: { scanner: null, blocked: false, blockedAt: null, note: null, retryAt: null },
      securityHold: null,
      tokenCheck: { consecutiveErrors: 0, lastError: null, lastErrorAt: null },
    };
  }

  /** Wired from `server.ts` once the token is loaded — rotates it and
   *  refreshes the live guard token when the invariant below trips. A8-1:
   *  returns `true` only once the new token is actually in place. */
  setTokenLeakHandler(fn: () => Promise<boolean>): void {
    this.onTokenLeak = fn;
  }

  get status(): LedgerGitStatus {
    return {
      ...this.state,
      // `enabled === false` means "commits are not happening", whether
      // that is a dead repo or a live S1 hold. The reason is in `securityHold`.
      enabled: this.enabled && this.hold === null,
      pendingSummaries: this.summaries.length,
      securityHold: this.hold,
    };
  }

  async init(): Promise<void> {
    const inside = await git(this.opts.root, ['rev-parse', '--is-inside-work-tree']);
    if (inside.code !== 0 || inside.stdout.trim() !== 'true') {
      const res = await git(this.opts.root, ['init', '-b', 'main']);
      if (res.code !== 0) {
        this.enabled = false;
        this.opts.log(`git init failed: ${res.stderr.trim()}`);
        return;
      }
      this.opts.log('ledger: git repo initialised (main)');
    }
    await this.loadState();
  }

  /**
   * Recover the reportable git state from the repo itself.
   *
   * Before this, `lastCommit`/`lastPushAt` only ever came from commits this
   * *process* made, so every hub restart reset `ledger status` to `git — · push —`
   * and a session's brief lost the "when did the ledger last move" signal. All
   * of it is already durable in the repo: HEAD for the commit, the
   * `refs/remotes/origin/main` reflog for the last successful push (the reflog
   * entry is written by the push itself, so it is a fact, not a guess).
   *
   * Every failure here is non-fatal: a fresh ledger has no commits, no remote
   * and no reflog, and that is the normal first-run state.
   */
  async loadState(): Promise<void> {
    const head = await git(this.opts.root, [
      'log',
      '--no-show-signature',
      '-1',
      '--format=%h%x00%cI',
    ]).catch(() => null);
    if (head !== null && head.code === 0) {
      const [sha, when] = head.stdout.trim().split('\0');
      if (sha) this.state.lastCommit = sha;
      if (when) this.state.lastCommitAt = new Date(when).toISOString();
    }
    await this.loadRemoteState();
  }

  /** Upstream name + ahead/behind + last push time from the remote-tracking reflog. */
  private async loadRemoteState(): Promise<void> {
    const upstream = await this.upstreamRef();
    this.state.upstream = upstream;
    if (upstream === null) {
      this.state.ahead = null;
      this.state.behind = null;
      return;
    }
    const counts = await git(this.opts.root, [
      'rev-list',
      '--left-right',
      '--count',
      `HEAD...${upstream}`,
    ]).catch(() => null);
    if (counts !== null && counts.code === 0) {
      const [ahead, behind] = counts.stdout.trim().split(/\s+/).map((n) => Number.parseInt(n, 10));
      this.state.ahead = Number.isFinite(ahead) ? (ahead as number) : null;
      this.state.behind = Number.isFinite(behind) ? (behind as number) : null;
    }
    // The reflog of the remote-tracking ref only moves when a fetch or a push
    // actually updated it, so its newest entry is the last time our ledger
    // reached the remote. `-n 1` is the newest entry.
    const reflog = await git(this.opts.root, [
      'reflog',
      'show',
      '--date=iso-strict',
      '-n',
      '1',
      `refs/remotes/${upstream}`,
    ]).catch(() => null);
    if (reflog !== null && reflog.code === 0) {
      const at = /@\{([^}]+)\}/.exec(reflog.stdout);
      if (at?.[1]) {
        const parsed = new Date(at[1]);
        if (!Number.isNaN(parsed.getTime())) this.state.lastPushAt = parsed.toISOString();
      }
    }
  }

  /** `origin/main`-style name of the configured upstream, or null. */
  private async upstreamRef(): Promise<string | null> {
    const explicit = await git(this.opts.root, [
      'rev-parse',
      '--abbrev-ref',
      '--symbolic-full-name',
      '@{upstream}',
    ]).catch(() => null);
    const name = explicit?.code === 0 ? explicit.stdout.trim() : '';
    if (name !== '') return name;
    // No tracking branch configured, but a pushed ledger still has the ref.
    const fallback = await git(this.opts.root, [
      'rev-parse',
      '--verify',
      '--quiet',
      'refs/remotes/origin/main',
    ]).catch(() => null);
    return fallback?.code === 0 && fallback.stdout.trim() !== '' ? 'origin/main' : null;
  }

  /** Record a change and (re)arm the debounce. */
  touch(summary: string): void {
    if (!this.enabled) return;
    if (summary.trim() !== '' && !this.summaries.includes(summary)) this.summaries.push(summary);
    this.rearm(this.opts.commitDebounceMs);
  }

  /** (Re)arm the commit timer with an explicit delay — the debounce for a
   *  `touch()`, the backoff for a retry, the wake gate for a deferral. */
  private rearm(delayMs: number): void {
    if (!this.enabled) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, delayMs);
    this.timer.unref?.();
  }

  /** Commit now (used by tests and on shutdown). */
  flush(): Promise<void> {
    this.running = this.running.then(() => this.commit()).catch((err: unknown) => {
      this.opts.log(`ledger commit error: ${String(err)}`);
    });
    return this.running;
  }

  private summary(): string {
    const joined = this.summaries.join(', ');
    return joined.length > 160 ? `${joined.slice(0, 157)}…` : joined;
  }

  /**
   * S1 is now evidence-based, because fail-closed-on-error was itself
   * the outage.
   *
   * The old check returned a boolean: anything that was not a clean "ignored and
   * untracked" counted as "tracked" and triggered lockdown + token rotation.
   * `git` has plenty of ways to answer neither yes nor no — a concurrent session
   * holding `index.lock`, a 20 s timeout, exit 128, the output cap (`code: -1`),
   * a thrown spawn error. Each of those rotated the live token and disabled the
   * ledger's commit/push *permanently*, and because the condition reproduced on
   * every cycle, a hub restart did not help either. Observed live: the ledger
   * stopped being committed from 2026-10-02 while `.hub/token` had never been
   * tracked at all (`git log --all -- .hub/token` empty, `.gitignore:1:.hub/`).
   *
   * Three outcomes now, and only the first one is allowed to rotate a token:
   *  - `leak`    — positive proof: `ls-files --error-unmatch` exits 0 (tracked),
   *                or the path shows up in `diff --cached --name-only` (staged).
   *  - `unsafe`  — proven NOT ignored, but also not tracked and not staged. The
   *                token has not leaked, yet `add -A` would stage it next, so we
   *                refuse to commit. No rotation; clears itself once ignored.
   *  - `unknown` — git could not answer. Skip this cycle, keep the pending
   *                summaries, log once, retry on the next one.
   */
  private async tokenInvariant(): Promise<TokenInvariant> {
    // A8-9: a plain `ls-files --error-unmatch <pathspec>` does an exact
    // (case-sensitive) pathspec lookup regardless of `core.ignorecase` or the
    // filesystem — a `.hub/TOKEN` tracked on APFS answers "not found" to a
    // query for `.hub/token` even though it is the same file. List everything
    // tracked and compare case-insensitively ourselves instead.
    const tracked = await git(this.opts.root, ['ls-files']).catch(
      (err: unknown) => ({ code: -2, stdout: '', stderr: String(err) }),
    );
    if (tracked.code !== 0) {
      return { kind: 'unknown', reason: `ls-files: ${gitFailureNote(tracked)}` };
    }
    if (tracked.stdout.split('\n').some(isTokenPath)) {
      return { kind: 'leak', reason: 'is tracked by git' };
    }

    const staged = await git(this.opts.root, ['diff', '--cached', '--name-only']).catch(
      (err: unknown) => ({ code: -2, stdout: '', stderr: String(err) }),
    );
    if (staged.code !== 0) return { kind: 'unknown', reason: `diff --cached: ${gitFailureNote(staged)}` };
    if (staged.stdout.split('\n').some(isTokenPath)) {
      return { kind: 'leak', reason: 'is staged' };
    }

    // `check-ignore -q`: 0 = ignored, 1 = not ignored, 128 = error.
    const ignored = await git(this.opts.root, ['check-ignore', '-q', TOKEN_REL_PATH]).catch(
      (err: unknown) => ({ code: -2, stdout: '', stderr: String(err) }),
    );
    if (ignored.code === 0) return { kind: 'ok' };
    if (ignored.code === 1) {
      return { kind: 'unsafe', reason: 'is not in .gitignore — commit paused until fixed' };
    }
    return { kind: 'unknown', reason: `check-ignore: ${gitFailureNote(ignored)}` };
  }

  /** Proof that `.hub/token` reached git. Untrack it, rotate it, stop
   *  committing. NOT permanent any more — `commit()` re-checks on every cycle
   *  and lifts the hold once the invariant verifiably holds again (after the
   *  rotation the leaked value is dead, so there is nothing left to protect).
   *  Surfaced by `/v1/healthz` via `status.enabled` / `status.securityHold`. */
  private async lockdown(reason: string): Promise<void> {
    // A8-1: hash the leaked value BEFORE rotation overwrites the file — this is
    // the only proof later cycles have that a rotation actually happened.
    const leakedHash = await this.hashTokenFile();
    await git(this.opts.root, ['rm', '--cached', '--ignore-unmatch', TOKEN_REL_PATH]).catch(
      () => undefined,
    );
    // A8-8: the hold reason lives in `this.hold.reason` (surfaced via
    // `status.securityHold`) — it must never overwrite `lastPushError`, which
    // is `maybePush()`'s own field for an unrelated real push failure. The two
    // must be visible side by side, not one clobbering the other.
    this.hold = {
      kind: 'leak',
      reason,
      since: new Date().toISOString(),
      leakedHash,
      rotationOk: false,
      blockedDetail: null,
    };
    this.opts.log(`SECURITY: ${TOKEN_REL_PATH} ${reason} — git branch disabled, rotating token`);
    void this.journal('security', ['s1.lockdown', TOKEN_REL_PATH, reason]);
    let rotationOk = false;
    try {
      rotationOk = await this.onTokenLeak?.() ?? false;
    } catch (err) {
      this.opts.log(`token rotation failed: ${String(err)}`);
    }
    // `commit()` is serialised through `this.running`, so `this.hold` is still
    // the object set above — re-check the kind defensively before mutating.
    if (this.hold?.kind === 'leak') {
      this.hold = { ...this.hold, rotationOk };
    }
    if (!rotationOk) {
      this.opts.log(
        `SECURITY: token rotation not confirmed — ${TOKEN_REL_PATH} stays blocked until the new token and the history are verified`,
      );
    }
  }

  /** A8-1: sha256 of the current token file, or `null` if it cannot be read
   *  (missing, permissions) — never the raw value, not even in memory beyond
   *  this call's return. */
  private async hashTokenFile(): Promise<string | null> {
    try {
      const raw = await readFile(join(this.opts.root, TOKEN_REL_PATH), 'utf8');
      return createHash('sha256').update(raw).digest('hex');
    } catch {
      return null;
    }
  }

  /** A8-1: `git log --all` is the only source of truth for "was this value
   *  ever committed, anywhere, even on a branch nobody pushed yet". `true` =
   *  provably absent from every commit; `false` = present OR git could not
   *  answer (fail closed — an inconclusive history check must not look like
   *  a clean one). */
  private async tokenHistoryClean(): Promise<boolean> {
    const res = await git(this.opts.root, ['log', '--no-show-signature', '--all', '--format=%H', '--', TOKEN_REL_PATH]).catch(
      (err: unknown) => ({ code: -2, stdout: '', stderr: String(err) }),
    );
    if (res.code !== 0) return false;
    return res.stdout.trim() === '';
  }

  /** A8-1: the only gate that may lift a `leak` hold. Both conditions are
   *  required — rotation alone (A) means the live token is safe going
   *  forward but the OLD one is still readable by anyone who can `git log
   *  --all` the ledger; history-clean alone (B) proves nothing if the token
   *  on disk never actually changed. */
  private async checkLeakRelease(): Promise<boolean> {
    if (this.hold?.kind !== 'leak') return false;
    let hold = this.hold;
    if (!hold.rotationOk) {
      // A9-2: retry the rotation HERE, not only in the `leak` branch
      // of `commit()`.
      //
      // The old code retried only while `tokenInvariant()` still answered
      // `leak`. But `lockdown()` runs `git rm --cached` as its first step, so
      // from the very next cycle the invariant answers `ok` — the `leak` branch
      // is never taken again and a rotation that failed once (ENOSPC, EROFS, a
      // transient permission problem on `.hub/`) was never retried. The hold
      // then sat there until somebody restarted the hub, with commit AND push
      // of the ledger off the whole time. Observed exactly that way in A9-2.
      const retried = await this.retryRotation();
      if (!retried) {
        this.noteLeakBlocked(
          hold.reason,
          'token rotation not confirmed — retrying next cycle',
        );
        return false;
      }
      if (this.hold?.kind !== 'leak') return false;
      hold = this.hold;
    }
    const currentHash = await this.hashTokenFile();
    if (currentHash === null || currentHash === hold.leakedHash) {
      this.noteLeakBlocked(hold.reason, 'token on disk is unchanged from the leaked value');
      return false;
    }
    if (!(await this.tokenHistoryClean())) {
      this.noteLeakBlocked(
        hold.reason,
        `${TOKEN_REL_PATH} is still in history (git log --all) — push stays disabled until the history ` +
          'is repaired (rewrite the ledger history, or revert/drop the commit with the token before the next push) or run `ledger doctor`',
      );
      return false;
    }
    return true;
  }

  /** Throttle for the rotation retry. Without it a hub whose `.hub/`
   *  is read-only would call `rotateToken` on every single cycle and fill
   *  `hub.log`; with it the retry is periodic but cheap. */
  private lastRotationRetry = 0;
  /** How often a failed rotation is retried. Short enough that the hold
   *  lifts on its own within a minute of the cause being fixed, long enough not
   *  to be a hot loop. */
  static readonly ROTATION_RETRY_MS = 30_000;

  /**
   * A9-2: re-attempt the token rotation of an active `leak` hold.
   *
   * Returns `true` only when a rotation has now been confirmed (the hold's
   * `rotationOk` is set), which is what lets `checkLeakRelease()` continue to
   * the remaining checks. Throttled, and it never raises a second lockdown:
   * `git rm --cached` and the journal entry already happened.
   */
  private async retryRotation(): Promise<boolean> {
    if (this.hold?.kind !== 'leak') return false;
    const now = Date.now();
    if (now - this.lastRotationRetry < LedgerGit.ROTATION_RETRY_MS) return false;
    this.lastRotationRetry = now;
    let rotationOk = false;
    try {
      rotationOk = (await this.onTokenLeak?.()) ?? false;
    } catch (err) {
      this.opts.log(`token rotation (repeated attempt) failed: ${String(err)}`);
      return false;
    }
    if (!rotationOk) return false;
    if (this.hold?.kind !== 'leak') return false;
    this.hold = { ...this.hold, rotationOk: true };
    this.opts.log(`SECURITY: ${TOKEN_REL_PATH} — token rotation confirmed after a repeated attempt`);
    void this.journal('security', ['s1.rotation.retry', TOKEN_REL_PATH, 'confirmed']);
    return true;
  }

  /**
   * A periodic nudge for a hold that is waiting only on a retry.
   *
   * `commit()` runs off the write debounce, so a ledger with no writes would
   * never retry at all. `server.ts`'s sweep calls this; it is a no-op unless a
   * `leak` hold with an unconfirmed rotation is active, and it goes through the
   * same `running` chain as every other git operation so it cannot interleave.
   */
  retrySecurityHold(): Promise<void> {
    if (this.hold?.kind !== 'leak' || this.hold.rotationOk) return Promise.resolve();
    this.running = this.running
      .then(async () => {
        if (this.hold?.kind !== 'leak' || this.hold.rotationOk) return;
        if (await this.retryRotation()) {
          // Rotation is confirmed; the remaining release conditions (token
          // changed on disk, absent from all history) are `commit()`'s job.
          this.touch('');
        }
      })
      .catch((err: unknown) => {
        this.opts.log(`retry security hold: ${String(err)}`);
      });
    return this.running;
  }

  private leakBlockedReason: string | null = null;

  /** A8-8: records the current block reason on `this.hold.blockedDetail` (→
   *  `status.securityHold.blockedDetail`) so it stays on the hold itself,
   *  never on `lastPushError` — that field belongs to `maybePush()` and must
   *  keep reporting a real push failure even while a security hold is also
   *  active. Assignment, not concatenation: idempotent across cycles. */
  private noteLeakBlocked(_originalReason: string, detail: string): void {
    if (this.hold?.kind === 'leak') {
      this.hold = { ...this.hold, blockedDetail: detail };
    }
    if (this.leakBlockedReason !== detail) {
      this.leakBlockedReason = detail;
      this.opts.log(`SECURITY: ${TOKEN_REL_PATH} hold continues — ${detail}`);
    }
  }

  /** Pause without rotating — `.hub/token` is not ignored but has not
   *  reached git. Lifted automatically by the next clean check. */
  private holdUnsafe(reason: string): void {
    if (this.hold?.reason !== reason) {
      this.opts.log(`SECURITY: ${TOKEN_REL_PATH} ${reason}`);
      void this.journal('security', ['s1.hold', TOKEN_REL_PATH, reason]);
    }
    // A8-8: no `lastPushError` write here — the hold reason lives on
    // `this.hold.reason` / `status.securityHold`, kept separate so a real,
    // unrelated push failure recorded in `lastPushError` is not clobbered.
    this.hold = { kind: 'unsafe', reason, since: new Date().toISOString() };
  }

  /** Git itself could not answer. Never a lockdown, never a rotation —
   *  skip the cycle and keep the pending summaries so the next flush retries.
   *  Logged once per distinct reason; `CHECK_ERROR_WARN_AFTER` consecutive
   *  failures raise a warning in healthz and in the SessionStart brief. */
  private noteCheckError(reason: string): void {
    this.checkErrors += 1;
    this.state.tokenCheck = {
      consecutiveErrors: this.checkErrors,
      lastError: reason,
      lastErrorAt: new Date().toISOString(),
    };
    if (this.lastCheckError !== reason) {
      this.lastCheckError = reason;
      this.opts.log(
        `S1 check of ${TOKEN_REL_PATH} could not be evaluated (${reason}) — commit skipped, will retry next cycle`,
      );
    }
  }

  private clearCheckErrors(): void {
    this.checkErrors = 0;
    this.lastCheckError = null;
    this.state.tokenCheck = { consecutiveErrors: 0, lastError: null, lastErrorAt: null };
  }

  /** The hold must not outlive its cause. */
  private releaseHold(): void {
    const previous = this.hold;
    if (previous === null) return;
    this.hold = null;
    // A8-8: `lastPushError` is not ours to clear — it may hold a genuine,
    // still-current push failure unrelated to this hold.
    this.leakBlockedReason = null;
    this.opts.log(
      `S1 check of ${TOKEN_REL_PATH} is OK again (previously: ${previous.reason}) — git branch re-enabled`,
    );
    void this.journal('security', ['s1.release', TOKEN_REL_PATH, previous.reason]);
  }

  private async journal(type: string, fields: string[]): Promise<void> {
    try {
      await this.opts.journal?.(type, fields);
    } catch {
      // Journalling a security event must never be the thing that breaks it.
    }
  }

  /** Indirection: lazily imported so `git.ts` stays free of the gitleaks
   *  module for every consumer that never commits (gitreader, repowatch). */
  private async scan(): Promise<{
    scanner: 'gitleaks' | null;
    blocked: boolean;
    retryable?: boolean;
    note: string | null;
  }> {
    try {
      if (this.opts.scanStaged) return await this.opts.scanStaged(this.opts.root);
      const { scanStaged } = await import('./gitleaks.ts');
      return await scanStaged(this.opts.root);
    } catch (err) {
      // R7-1: this used to return `blocked: false` — "the runner threw,
      // so commit anyway". That makes every failure mode of the scanner module
      // (a bad import, an exception inside `scanStaged`, an injected runner that
      // throws) a way to get an unscanned commit, and it is reachable by
      // exactly the input the scan is meant to inspect. Fail CLOSED: the commit
      // is held and `commit()` keeps the pending summary, so the next cycle
      // retries without a hub restart. A scanner that was never installed stays
      // a warning — that is decided in `gitleaks.ts`, where "missing" is known.
      return {
        scanner: null,
        blocked: true,
        retryable: true,
        note:
          `could not run gitleaks (${String(err)}) — ledger commit is blocked, ` +
          'the next cycle will retry',
      };
    }
  }

  private async commit(): Promise<void> {
    if (!this.enabled) return;
    // Evaluated on EVERY cycle, including while a hold is active — that
    // is what makes the hold recoverable instead of a permanent state.
    const invariant = await this.tokenInvariant();
    switch (invariant.kind) {
      case 'leak':
        this.clearCheckErrors();
        if (this.hold?.kind !== 'leak') {
          await this.lockdown(invariant.reason);
        } else if (!this.hold.rotationOk) {
          // A8-1: first rotation attempt failed — retry every cycle. Still
          // the same proof, so no second `s1.lockdown` journal entry/log spam
          // beyond what `lockdown()` already does when it fails again.
          await this.lockdown(invariant.reason);
        }
        return;
      case 'unsafe':
        this.clearCheckErrors();
        this.holdUnsafe(invariant.reason);
        return;
      case 'unknown':
        // Deliberately NOT a lockdown and NOT a rotation. `summaries` is kept,
        // so the next flush commits everything this cycle would have.
        this.noteCheckError(invariant.reason);
        return;
      case 'ok':
        this.clearCheckErrors();
        // A8-1: a `leak` hold does not clear just because the working tree
        // looks clean again — that is exactly the state right after
        // `git rm --cached` and before the removal is committed/pushed. Only
        // `checkLeakRelease()` (rotation confirmed + absent from all history)
        // may lift it.
        if (this.hold?.kind === 'leak') {
          if (!(await this.checkLeakRelease())) return;
        }
        this.releaseHold();
        break;
    }
    // Right after a wake macOS starves this process and its children,
    // and the gitleaks child is the one that reliably hit its 10 s timeout on
    // every resume. The gate sits HERE, after the S1 token invariant above:
    // a leaked token must be locked down and rotated the moment it is seen,
    // whatever the machine is doing. Only the add/scan/commit/push part waits,
    // and nothing is lost by waiting — `summaries` is still untouched at this
    // point and the timer is re-armed for the moment the gate opens.
    if (this.opts.heavyAllowed && !this.opts.heavyAllowed()) {
      this.rearm(Math.max(1_000, this.opts.heavyRetryInMs?.() ?? 5_000));
      return;
    }
    const summary = this.summary() || 'changes';
    this.summaries = [];
    const add = await git(this.opts.root, ['add', '-A']).catch(
      (err: unknown) => ({ code: -2, stdout: '', stderr: String(err) }),
    );
    if (add.code !== 0) {
      this.summaries = summary === 'changes' ? [] : [summary];
      this.opts.log(`git add failed: ${gitFailureNote(add)}`);
      return;
    }
    const staged = await git(this.opts.root, ['diff', '--cached', '--name-only']).catch(
      (err: unknown) => ({ code: -2, stdout: '', stderr: String(err) }),
    );
    // A8-3: a non-zero/thrown `diff --cached` is NOT proof the tree is clean —
    // `staged.stdout` would just be empty, which used to fall through to the
    // "nothing staged" return below and silently skip the commit AND the S1
    // check on what `add -A` just staged. Treat it the same as the other
    // inconclusive-git cases: skip this cycle, keep the summary, retry next.
    if (staged.code !== 0) {
      this.summaries = summary === 'changes' ? [] : [summary];
      this.noteCheckError(`diff --cached po add -A: ${gitFailureNote(staged)}`);
      return;
    }
    // `add -A` just ran. Closes the window between the pre-flight check
    // and the add (a session could have un-ignored or force-added the token in
    // between). Seeing it here IS proof, so it locks down and rotates.
    if (staged.stdout.split('\n').some(isTokenPath)) {
      await this.lockdown('was staged by `add -A`');
      return;
    }
    if (staged.stdout.trim() === '') return;

    // Second line of defence, on what is actually staged. A finding
    // stops the commit and LEAVES the staged changes in place on purpose —
    // a human has to look at `git diff --cached` in the ledger. `summaries`
    // is restored so the next flush retries rather than losing the summary.
    const scan = await this.scan();
    const retryable = scan.blocked && scan.retryable === true;
    // An inconclusive scan is retried on a backoff instead of waiting
    // for the next random `touch()` (15 s → 60 s → every 5 min).
    const retryAt = retryable
      ? new Date(Date.now() + scanRetryDelayMs(this.scanStreak + 1)).toISOString()
      : null;
    this.state.secretScan = {
      scanner: scan.scanner,
      blocked: scan.blocked,
      blockedAt: scan.blocked ? new Date().toISOString() : null,
      note: scan.note,
      retryAt,
    };
    if (scan.blocked) {
      this.summaries = summary === 'changes' ? [] : [summary];
      // R7-1: a TRANSIENT scanner failure must not park the ledger
      // until the next unrelated write happens to re-arm the debounce — that is
      // how "commits quietly stopped" looked the last two times. Re-arm it here
      // so the retry is the hub's own job (on a backoff). A finding is
      // deliberately NOT re-armed: the staged diff waits for a human.
      if (retryable) {
        this.scanStreak += 1;
        // One line per streak. The old code logged the same SECURITY
        // line on every cycle, which is how a 10 s timeout after a wake turned
        // into hundreds of identical lines nobody read.
        if (this.scanStreak === 1) {
          this.opts.log(
            `SECURITY: gitleaks gave no verdict (${scan.note ?? 'no detail'}) — ledger commit ` +
              `blocked, retrying ${retryAt ?? 'later'}`,
          );
        }
        this.rearm(scanRetryDelayMs(this.scanStreak));
        return;
      }
      this.opts.log(
        // H6-1: `blocked` now also covers gitleaks itself erroring (fail-closed)
        // — do not claim a secret was found when the scanner may just have
        // choked; `scan.note` carries the actual reason either way.
        `SECURITY: gitleaks blocked the commit of the ledger's staged changes (${scan.note ?? 'no detail'})`,
      );
      return;
    }
    // A streak that ends leaves a line too — "the scanner is working
    // again" is exactly what a human reading the SECURITY line above needs.
    if (this.scanStreak > 0) {
      this.opts.log(
        `gitleaks passed again after ${this.scanStreak} failed attempts — ledger commit continues`,
      );
      this.scanStreak = 0;
    }
    if (scan.scanner === null && scan.note !== null) this.opts.log(scan.note);

    const res = await git(this.opts.root, ['commit', '--no-verify', '-m', `ledger: ${summary}`]);
    if (res.code !== 0) {
      this.opts.log(`git commit failed: ${res.stderr.trim()}`);
      return;
    }
    const head = await git(this.opts.root, ['rev-parse', '--short', 'HEAD']);
    this.state.lastCommit = head.stdout.trim() || null;
    this.state.lastCommitAt = new Date().toISOString();
    await this.maybePush();
  }

  private async maybePush(): Promise<void> {
    if (!this.opts.push) return;
    const remotes = await git(this.opts.root, ['remote']);
    if (!remotes.stdout.split('\n').some((r) => r.trim() === 'origin')) return;
    const now = Date.now();
    if (now - this.lastPush < this.opts.pushIntervalMs) return;
    this.lastPush = now;
    const res = await git(this.opts.root, ['push', '--no-verify', 'origin', 'HEAD'], 60_000);
    if (res.code !== 0) {
      // S-3: `lastPushError` is now the first line of the SessionStart brief.
      // git echoes the remote URL on failure, and an https remote carries
      // `user:token@` — redact at the source, so no reader has to remember to.
      this.state.lastPushError = redactUrlCredentials(
        res.stderr.trim().split('\n').slice(-1)[0] ?? 'push failed',
      );
      this.opts.log(`ledger push failed (non-fatal): ${this.state.lastPushError}`);
      return;
    }
    this.state.lastPushError = null;
    this.state.lastPushAt = new Date().toISOString();
    // Ahead/behind just changed — refresh rather than let it go stale.
    await this.loadRemoteState().catch(() => undefined);
  }

  async close(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    await this.flush();
  }
}
