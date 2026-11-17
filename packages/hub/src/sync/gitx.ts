/** Hardened git runner for the sync loop (docs/f3b-plan.md §1.5; threats S9-S12, S23; invariants 2, 13).
 *
 *  Threat model:
 *   - Actor: a compromised remote, a rogue peer device (hostile fetched content, hostile
 *     `.git/config` written by a synced file), or a hostile process environment
 *     (`GIT_SSH_COMMAND`, `GIT_CONFIG_COUNT`, `GIT_EXEC_PATH`, `GIT_ASKPASS`, ...).
 *   - Protected: code execution on this machine (hooks, filters, ssh `ProxyCommand`, `ext::`),
 *     the ref space (no force, no rewrite of `refs/heads/*`), credentials (never prompted,
 *     never from helpers), the host-key pin (own known_hosts, strict checking).
 *   - Failure modes: option injection through a URL or ref, a URL scheme that runs a helper,
 *     a config key that turns into a command, an unbounded child (hang / output flood).
 *   - Stance: allowlists everywhere. Env is rebuilt from a short allowlist, subcommands are
 *     an allowlist, URLs are an ssh-only allowlist, `.git/config` is an allowlist. Anything
 *     unknown is refused (fail-closed). Spawn is `execFile`-style: absolute binary,
 *     argv array, `shell: false`. Network commands exist only as dedicated methods that
 *     build their own fixed argv; the generic `run()` refuses them.
 */

import { spawn } from 'node:child_process';
import { lstat, readdir, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import {
  assertPrivateDir,
  assertPrivateFile,
  assertShimSafePath,
  ensurePrivateDir,
  resolveSshKeygen,
  resolveTrustedExecutable,
  sanitizeField,
  TrustError,
} from '@agent-ledger/shared';
import { buildGitGlobalArgs, gitCandidates, resolveTrustedBinary } from '../git.ts';

/* ---------------- errors and small validators ---------------- */

export type GitxErrorCode = 'URL' | 'ARGS' | 'BINARY' | 'SPAWN' | 'TIMEOUT' | 'CAPPED' | 'EXIT' | 'PRIVATE';

export class GitxError extends Error {
  readonly code: GitxErrorCode;
  constructor(code: GitxErrorCode, message: string) {
    super(message);
    this.name = 'GitxError';
    this.code = code;
  }
}

/** Object ids: sha1 (40) or sha256 (64) lowercase hex. Nothing else ever reaches a git argv as an object name. */
export const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const ZERO_SHA_RE = /^(?:0{40}|0{64})$/;

export function isSha(value: unknown): value is string {
  return typeof value === 'string' && SHA_RE.test(value);
}

export function assertSha(value: unknown, what = 'object id'): asserts value is string {
  if (!isSha(value)) throw new GitxError('ARGS', `${what}: not a 40/64 hex object id`);
}

export function isZeroSha(value: string): boolean {
  return ZERO_SHA_RE.test(value);
}

/** Refs the sync loop may name. `main` is the ledger branch, the other two are the scratch/accepted mirrors (§1.2). */
export const REF_MAIN = 'refs/heads/main';
export const REF_INCOMING = 'refs/ledger-sync/incoming';
export const REF_ACCEPTED = 'refs/ledger-sync/accepted';
const FETCH_SRC_RE = /^refs\/heads\/[A-Za-z0-9._\/-]{1,100}$/;
const FETCH_DST_RE = /^refs\/ledger-sync\/[a-z][a-z-]{0,30}$/;

function safeRefShape(ref: string): boolean {
  return ref.length <= 200 && !ref.includes('..') && !ref.includes('//') && !ref.endsWith('/') && !ref.endsWith('.lock');
}

/* ---------------- remote URL validator (S12) ---------------- */

export type RemoteKind = 'ssh' | 'scp' | 'local';

export interface ValidatedRemote {
  kind: RemoteKind;
  url: string;
}

const MAX_URL_CHARS = 512;
const USER = '([A-Za-z0-9_][A-Za-z0-9._-]{0,63})';
const HOST = '([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)';
const SSH_URL_RE = new RegExp(`^ssh://(?:${USER}@)?(\\[[0-9A-Fa-f:]{2,45}\\]|${HOST})(?::([0-9]{1,5}))?(/[A-Za-z0-9._~/-]+)$`);
const SCP_URL_RE = new RegExp(`^(?:${USER}@)?${HOST}:([A-Za-z0-9._~/][A-Za-z0-9._~/-]*)$`);

function pathSegmentsOk(path: string): boolean {
  const segs = path.split('/');
  // leading '/' (absolute) yields one empty first segment; every other empty segment is `//` or a trailing '/'
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i] as string;
    if (s === '') {
      if (i === 0 && path.startsWith('/')) continue;
      return false;
    }
    if (s === '.' || s === '..') return false;
  }
  return true;
}

const WIN_ABS_RE = /^[A-Za-z]:[\\/]/;

/**
 * `ssh://[user@]host[:port]/path` or scp form `[user@]host:path` only. Everything else is refused:
 * leading `-` (option injection), whitespace/control/non-ASCII, `ext::` / `fd::` (transport helpers),
 * `file://`, `http(s)://`, `git://`, bare paths. A local path is accepted solely when the
 * constructor's `testLocalRemotes` names exactly that string (tests; never from env).
 * Throws `GitxError('URL')` with a reason code, never the URL.
 */
export function validateRemoteUrl(url: unknown, testLocalRemotes: readonly string[] = []): ValidatedRemote {
  const bad = (reason: string): never => {
    throw new GitxError('URL', `remote url refused: ${reason}`);
  };
  if (typeof url !== 'string' || url === '') return bad('empty');
  if (url.length > MAX_URL_CHARS) return bad('too-long');
  if (testLocalRemotes.includes(url)) {
    if (/[\0-\x1f\x7f]/.test(url)) return bad('control');
    if (url.startsWith('-')) return bad('leading-dash');
    const abs = process.platform === 'win32' ? WIN_ABS_RE.test(url) : nodePath.posix.isAbsolute(url);
    if (!abs) return bad('local-not-absolute');
    return { kind: 'local', url };
  }
  if (url.startsWith('-')) return bad('leading-dash');
  if (!/^[\x21-\x7e]+$/.test(url)) return bad('whitespace-control-or-non-ascii');
  if (/^[A-Za-z][A-Za-z0-9+.-]*::/.test(url)) return bad('transport-helper');
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(url) && !url.startsWith('ssh://')) return bad('scheme');
  const ssh = SSH_URL_RE.exec(url);
  if (ssh !== null) {
    const host = ssh[2] as string;
    if (host.startsWith('-')) return bad('host-leading-dash');
    const port = ssh[4];
    if (port !== undefined) {
      const p = Number(port);
      if (!Number.isInteger(p) || p < 1 || p > 65535) return bad('port');
    }
    if (!pathSegmentsOk(ssh[5] as string)) return bad('path-segment');
    return { kind: 'ssh', url };
  }
  const scp = SCP_URL_RE.exec(url);
  if (scp !== null) {
    const host = scp[2] as string;
    if (host.length < 2) return bad('drive-letter-or-short-host'); // `C:/x` is a Windows path, not host C
    if (!pathSegmentsOk(scp[3] as string)) return bad('path-segment');
    return { kind: 'scp', url };
  }
  return bad('not-ssh-form');
}

/* ---------------- environment + ssh command ---------------- */

/** Inherited variables that may reach a git child. Everything else (all other `GIT_*` included) is dropped. */
const ENV_ALLOW = ['PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'TEMP'] as const;
const ENV_ALLOW_NET = ['SSH_AUTH_SOCK'] as const;
/** Per-call variables a caller may set explicitly (never inherited). */
export type ExtraGitEnvKey = 'GIT_INDEX_FILE' | 'GIT_AUTHOR_DATE' | 'GIT_COMMITTER_DATE';
const EXTRA_ENV_KEYS: readonly string[] = ['GIT_INDEX_FILE', 'GIT_AUTHOR_DATE', 'GIT_COMMITTER_DATE'];

export interface BuildEnvInput {
  source: Readonly<Record<string, string | undefined>>;
  platform: NodeJS.Platform;
  /** Empty private file used as `GIT_CONFIG_GLOBAL`. */
  emptyConfigFile: string;
  /** Network call: also keeps `SSH_AUTH_SOCK` and sets `GIT_SSH_COMMAND`. */
  sshCommand?: string;
  extra?: Readonly<Partial<Record<ExtraGitEnvKey, string>>>;
}

/** Pure. The ONLY place a git child's environment is made. */
export function buildGitEnv(i: BuildEnvInput): Record<string, string> {
  const out: Record<string, string> = {};
  const wanted: readonly string[] = i.sshCommand !== undefined ? [...ENV_ALLOW, ...ENV_ALLOW_NET] : ENV_ALLOW;
  const win = i.platform === 'win32';
  for (const [k, v] of Object.entries(i.source)) {
    if (typeof v !== 'string' || v.includes('\0')) continue;
    const name = wanted.find((w) => (win ? w.toLowerCase() === k.toLowerCase() : w === k));
    if (name !== undefined) out[name] = v;
  }
  out.GIT_CONFIG_NOSYSTEM = '1';
  out.GIT_CONFIG_GLOBAL = i.emptyConfigFile;
  out.GIT_TERMINAL_PROMPT = '0';
  out.GIT_ATTR_NOSYSTEM = '1';
  out.GIT_NO_REPLACE_OBJECTS = '1';
  out.GIT_NO_LAZY_FETCH = '1';
  out.GIT_OPTIONAL_LOCKS = '0';
  out.LC_ALL = 'C';
  if (i.sshCommand !== undefined) out.GIT_SSH_COMMAND = i.sshCommand;
  for (const [k, v] of Object.entries(i.extra ?? {})) {
    if (!EXTRA_ENV_KEYS.includes(k)) throw new GitxError('ARGS', 'env key not allowed');
    if (typeof v !== 'string' || /[\0\r\n]/.test(v)) throw new GitxError('ARGS', 'env value invalid');
    out[k] = v;
  }
  return out;
}

/** POSIX single-quote. Git hands `GIT_SSH_COMMAND` to a POSIX shell on every OS (MSYS `sh` on Git for Windows). */
function shQuote(s: string): string {
  if (/[\0\r\n]/.test(s)) throw new GitxError('ARGS', 'ssh command value contains NUL/CR/LF');
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export interface SshCommandInput {
  sshBin: string;
  knownHostsFile: string;
  keyFile?: string;
  platform?: NodeJS.Platform;
}

/** Fixed option set; nothing from env, request or remote content. UNVERIFIED on Windows: the null
 *  device (`NUL`) for `GlobalKnownHostsFile` and forward-slash paths under MSYS `sh` (plan §5). */
export function buildSshCommand(i: SshCommandInput): string {
  const platform = i.platform ?? process.platform;
  const win = platform === 'win32';
  const path = (p: string): string => {
    if (win) {
      assertShimSafePath(p);
      return p.replace(/\\/g, '/');
    }
    if (!nodePath.posix.isAbsolute(p)) throw new GitxError('ARGS', 'ssh command path must be absolute');
    return p;
  };
  const argv = [
    path(i.sshBin),
    '-F',
    'none',
    '-o',
    'BatchMode=yes',
    '-o',
    'IdentitiesOnly=yes',
    '-o',
    'StrictHostKeyChecking=yes',
    '-o',
    `UserKnownHostsFile=${path(i.knownHostsFile)}`,
    '-o',
    `GlobalKnownHostsFile=${win ? 'NUL' : '/dev/null'}`,
    '-o',
    'VerifyHostKeyDNS=no',
    '-o',
    'UpdateHostKeys=no',
    '-o',
    'ProxyCommand=none',
    '-o',
    'ControlMaster=no',
    '-o',
    'ControlPath=none',
    '-o',
    'ForwardAgent=no',
    '-o',
    'ForwardX11=no',
    '-o',
    'PermitLocalCommand=no',
    '-o',
    'ConnectTimeout=10',
    '-o',
    'ServerAliveInterval=5',
    '-o',
    'ServerAliveCountMax=3',
  ];
  if (i.keyFile !== undefined) argv.push('-i', path(i.keyFile));
  return argv.map(shQuote).join(' ');
}

/* ---------------- argv guards (invariants 2 and 13) ---------------- */

/** Local, non-network plumbing the sync modules may run through `run()`. */
const LOCAL_SUBCOMMANDS: ReadonlySet<string> = new Set([
  'init',
  'rev-parse',
  'rev-list',
  'merge-base',
  'ls-tree',
  'diff-tree',
  'diff-index',
  'cat-file',
  'hash-object',
  'write-tree',
  'commit-tree',
  'update-ref',
  'read-tree',
  'update-index',
  'for-each-ref',
  'show-ref',
  'symbolic-ref',
  'ls-files',
  'status',
  'mktree',
  'check-ref-format',
]);

/** `-c` keys a caller may add (identity + signing only). Everything security-relevant is fixed here. */
const EXTRA_CONFIG_KEYS: ReadonlySet<string> = new Set([
  'user.name',
  'user.email',
  'user.signingkey',
  'gpg.format',
  'gpg.ssh.program',
  'gpg.ssh.allowedsignersfile',
  'commit.gpgsign',
]);

const FORBIDDEN_LONG = /^--(?:force|force-with-lease|force-if-includes|mirror|prune|delete|upload-pack|receive-pack|exec|exec-path|config|config-env|git-dir|work-tree|namespace|ext-diff|textconv)(?:=|$)/;
const FETCH_FORCE_DST_RE = /^\+[A-Za-z0-9._/-]+:(refs\/ledger-sync\/[a-z][a-z-]{0,30})$/;

/**
 * Runtime assert for invariant 2: no `--force` / `-f` (any short cluster containing `f`), no `+` refspec
 * except `+refs/heads/<x>:refs/ledger-sync/<scratch>` (a scratch ref, never `refs/heads/*`), no
 * delete/mirror/prune, no global-option smuggling. Runs for every spawn, including the network methods.
 */
export function assertSafeArgv(args: readonly string[]): void {
  for (const a of args) {
    if (typeof a !== 'string' || a.includes('\0')) throw new GitxError('ARGS', 'argv contains a non-string or NUL');
    if (a === '--') continue;
    if (FORBIDDEN_LONG.test(a)) throw new GitxError('ARGS', `forbidden git option: ${sanitizeField(a.split('=')[0] ?? '', 40)}`);
    if (/^-[A-Za-z]*f[A-Za-z]*$/.test(a)) throw new GitxError('ARGS', 'forbidden git option: -f');
    if (a === '-c' || a === '-C' || a === '-d') throw new GitxError('ARGS', 'forbidden git option');
    if (a.startsWith('+') && !FETCH_FORCE_DST_RE.test(a)) throw new GitxError('ARGS', 'forbidden: "+" refspec outside refs/ledger-sync/');
    if (/:\+/.test(a)) throw new GitxError('ARGS', 'forbidden: "+" in refspec destination');
  }
}

/* ---------------- runner ---------------- */

export interface GitxOptions {
  /** `<ledger>/.hub/sync`: created or verified PRIVATE. Holds known_hosts, the empty config and the empty hooks dir. */
  syncDir: string;
  /** Deploy key passed as `ssh -i`. */
  keyFile?: string;
  /** Default `<syncDir>/known_hosts`. */
  knownHostsFile?: string;
  /** Test seam: absolute git binary (skips the trusted-path resolution). Production leaves it unset. */
  gitBin?: string;
  /** Test seam: absolute ssh binary. Production = trusted resolution. */
  sshBin?: string;
  /** Tests only: exact local paths accepted as remote (never read from env). */
  testLocalRemotes?: readonly string[];
  /** Source for the env allowlist. Default `process.env`. */
  env?: Readonly<Record<string, string | undefined>>;
}

export interface RunOptions {
  /** Working directory = the repo (or bare repo) the command acts on. Must exist. */
  cwd: string;
  timeoutMs?: number;
  input?: Uint8Array | string;
  maxStdoutBytes?: number;
  extraEnv?: Readonly<Partial<Record<ExtraGitEnvKey, string>>>;
  /** `key=value` pairs for `-c`; keys restricted to identity/signing. */
  extraConfig?: readonly string[];
}

export interface GitxResult {
  ok: boolean;
  code: number;
  stdout: Buffer;
  stderr: string;
  timedOut: boolean;
  capped: boolean;
}

export const DEFAULT_TIMEOUT_MS = 20_000;
export const DEFAULT_MAX_STDOUT = 8 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

const HARDENING_CONFIG: readonly string[] = [
  'protocol.allow=never',
  'protocol.ssh.allow=always',
  'protocol.ext.allow=never',
  'protocol.file.allow=never',
  'core.sshCommand=',
  'credential.helper=',
  'fetch.fsckObjects=true',
  'transfer.fsckObjects=true',
  'fetch.recurseSubmodules=false',
  'submodule.recurse=false',
  'gc.auto=0',
  'gc.autoDetach=false',
  'maintenance.auto=false',
];

function killGroup(pid: number | undefined, fallback: () => void): void {
  try {
    if (pid !== undefined && process.platform !== 'win32') process.kill(-pid, 'SIGKILL');
    else fallback();
  } catch {
    try {
      fallback();
    } catch {
      /* already gone */
    }
  }
}

interface SpawnInput {
  bin: string;
  argv: string[];
  cwd: string;
  env: Record<string, string>;
  input?: Uint8Array | string;
  timeoutMs: number;
  maxStdout: number;
}

function spawnCapture(i: SpawnInput): Promise<GitxResult> {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(i.bin, i.argv, {
        cwd: i.cwd,
        env: i.env,
        stdio: [i.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
        detached: process.platform !== 'win32', // own process group: the timeout kills ssh and helpers too
      });
    } catch {
      reject(new GitxError('SPAWN', 'git could not be started'));
      return;
    }
    const out: Buffer[] = [];
    let outBytes = 0;
    let err = '';
    let errBytes = 0;
    let timedOut = false;
    let capped = false;
    let settled = false;
    const kill = (): void => killGroup(child.pid, () => child.kill('SIGKILL'));
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, i.timeoutMs);
    child.stdout?.on('data', (d: Buffer) => {
      if (capped) return;
      outBytes += d.length;
      if (outBytes > i.maxStdout) {
        capped = true;
        kill();
        return;
      }
      out.push(d);
    });
    child.stderr?.on('data', (d: Buffer) => {
      if (errBytes >= MAX_STDERR_BYTES) return;
      errBytes += d.length;
      err += d.toString('utf8');
    });
    child.on('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new GitxError('SPAWN', 'git could not be started (missing binary or working directory)'));
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const bad = timedOut || capped;
      resolve({
        ok: !bad && code === 0,
        code: bad ? -1 : (code ?? -1),
        stdout: capped ? Buffer.alloc(0) : Buffer.concat(out),
        stderr: err.slice(0, MAX_STDERR_BYTES),
        timedOut,
        capped,
      });
    });
    if (i.input !== undefined && child.stdin !== null) {
      child.stdin.on('error', () => {
        /* EPIPE: the exit code tells the story */
      });
      child.stdin.end(typeof i.input === 'string' ? Buffer.from(i.input, 'utf8') : Buffer.from(i.input));
    }
  });
}

export function sshCandidates(
  platform: NodeJS.Platform = process.platform,
  env: Readonly<Record<string, string | undefined>> = process.env,
): string[] {
  if (platform !== 'win32') return ['/usr/bin/ssh', '/usr/local/bin/ssh', '/opt/homebrew/bin/ssh'];
  const roots: [string | undefined, string[]][] = [
    [env.SystemRoot, ['System32', 'OpenSSH', 'ssh.exe']],
    [env.ProgramW6432, ['Git', 'usr', 'bin', 'ssh.exe']],
    [env.ProgramFiles, ['Git', 'usr', 'bin', 'ssh.exe']],
  ];
  const out: string[] = [];
  for (const [base, rest] of roots) {
    if (typeof base !== 'string' || !/^[A-Za-z]:\\/.test(base) || base.includes('\0')) continue;
    const c = nodePath.win32.join(base, ...rest);
    if (!out.includes(c)) out.push(c);
  }
  return out;
}

function requireAbsolute(p: string, what: string): void {
  const abs = process.platform === 'win32' ? WIN_ABS_RE.test(p) : nodePath.posix.isAbsolute(p);
  if (!abs || /[\0\r\n]/.test(p)) throw new GitxError('ARGS', `${what} must be an absolute path`);
}

const PROBE_PREFIX = '.ledger-fsprobe-';

export class Gitx {
  readonly syncDir: string;
  readonly knownHostsFile: string;
  private readonly gitBin: string;
  private readonly hooksDir: string;
  private readonly emptyConfig: string;
  private readonly keyFile: string | undefined;
  private readonly sshBinOpt: string | undefined;
  private readonly testLocalRemotes: readonly string[];
  private readonly envSource: Readonly<Record<string, string | undefined>>;
  private sshResolved: Promise<string> | null = null;

  private constructor(
    o: GitxOptions,
    gitBin: string,
    hooksDir: string,
    emptyConfig: string,
  ) {
    this.syncDir = o.syncDir;
    this.knownHostsFile = o.knownHostsFile ?? nodePath.join(o.syncDir, 'known_hosts');
    this.gitBin = gitBin;
    this.hooksDir = hooksDir;
    this.emptyConfig = emptyConfig;
    this.keyFile = o.keyFile;
    this.sshBinOpt = o.sshBin;
    this.testLocalRemotes = o.testLocalRemotes ?? [];
    this.envSource = o.env ?? process.env;
  }

  static async open(o: GitxOptions): Promise<Gitx> {
    requireAbsolute(o.syncDir, 'syncDir');
    if (o.keyFile !== undefined) requireAbsolute(o.keyFile, 'keyFile');
    if (o.knownHostsFile !== undefined) requireAbsolute(o.knownHostsFile, 'knownHostsFile');
    if (o.gitBin !== undefined) requireAbsolute(o.gitBin, 'gitBin');
    if (o.sshBin !== undefined) requireAbsolute(o.sshBin, 'sshBin');
    try {
      await ensurePrivateDir(o.syncDir);
      const hooksDir = nodePath.join(o.syncDir, 'empty-hooks');
      await ensurePrivateDir(hooksDir);
      const emptyConfig = nodePath.join(o.syncDir, 'empty.gitconfig');
      await ensureEmptyPrivateFile(emptyConfig);
      const gitBin = o.gitBin ?? (await resolveTrustedBinary(gitCandidates(), 'git'));
      return new Gitx(o, gitBin, hooksDir, emptyConfig);
    } catch (err) {
      if (err instanceof TrustError) throw new GitxError('PRIVATE', `sync directory refused: ${err.message}`);
      throw err;
    }
  }

  /** Validate a remote with this runner's test allowance. */
  remote(url: unknown): ValidatedRemote {
    return validateRemoteUrl(url, this.testLocalRemotes);
  }

  /** Pure view for tests/doctor: the env a (network or local) call would get. */
  envFor(opts: { network?: { sshCommand: string }; extra?: RunOptions['extraEnv'] } = {}): Record<string, string> {
    return buildGitEnv({
      source: this.envSource,
      platform: process.platform,
      emptyConfigFile: this.emptyConfig,
      ...(opts.network !== undefined ? { sshCommand: opts.network.sshCommand } : {}),
      ...(opts.extra !== undefined ? { extra: opts.extra } : {}),
    });
  }

  /** Local plumbing only. Network subcommands are refused here on purpose. */
  async run(args: readonly string[], o: RunOptions): Promise<GitxResult> {
    const sub = args[0];
    if (typeof sub !== 'string' || !LOCAL_SUBCOMMANDS.has(sub)) {
      throw new GitxError('ARGS', 'git subcommand not allowed through run()');
    }
    return this.exec(args, o, null);
  }

  /** `run()` that throws `GitxError('EXIT'|'TIMEOUT'|'CAPPED')` instead of returning a failed result. */
  async mustRun(args: readonly string[], o: RunOptions): Promise<GitxResult> {
    return this.require(await this.run(args, o), args[0] ?? 'git');
  }

  private require(r: GitxResult, what: string): GitxResult {
    if (r.ok) return r;
    if (r.timedOut) throw new GitxError('TIMEOUT', `git ${what} timed out`);
    if (r.capped) throw new GitxError('CAPPED', `git ${what} output exceeded the cap`);
    throw new GitxError('EXIT', `git ${what} failed (exit ${r.code}): ${sanitizeField(r.stderr.trim().split('\n')[0] ?? '', 160)}`);
  }

  /** `fetch --no-tags --no-recurse-submodules --no-write-fetch-head -- <url> +<src>:<dst>`; dst is a scratch ref, never `refs/heads/*`. */
  async fetch(
    cwd: string,
    url: string,
    o: { src?: string; dst?: string; timeoutMs?: number } = {},
  ): Promise<GitxResult> {
    const remote = this.remote(url);
    const src = o.src ?? REF_MAIN;
    const dst = o.dst ?? REF_INCOMING;
    if (!FETCH_SRC_RE.test(src) || !safeRefShape(src)) throw new GitxError('ARGS', 'fetch source ref refused');
    if (!FETCH_DST_RE.test(dst)) throw new GitxError('ARGS', 'fetch destination must be a refs/ledger-sync/ scratch ref');
    return this.exec(
      ['fetch', '--no-tags', '--no-recurse-submodules', '--no-write-fetch-head', '--', remote.url, `+${src}:${dst}`],
      { cwd, ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}) },
      remote,
    );
  }

  /** `push --no-verify -- <url> <sha>:refs/heads/main`. By object id, never forced, never a remote name. */
  async push(cwd: string, url: string, sha: string, o: { timeoutMs?: number } = {}): Promise<GitxResult> {
    const remote = this.remote(url);
    assertSha(sha, 'push sha');
    return this.exec(
      ['push', '--no-verify', '--no-recurse-submodules', '--porcelain', '--', remote.url, `${sha}:${REF_MAIN}`],
      { cwd, ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}) },
      remote,
    );
  }

  /** `ls-remote -- <url> refs/heads/main`: used by doctor and join. Output `<sha>\trefs/heads/main`. */
  async lsRemote(cwd: string, url: string, o: { timeoutMs?: number } = {}): Promise<GitxResult> {
    const remote = this.remote(url);
    return this.exec(
      ['ls-remote', '--', remote.url, REF_MAIN],
      { cwd, ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}) },
      remote,
    );
  }

  /** `clone --no-checkout --no-tags --no-recurse-submodules -- <url> <dest>` (join). `cwd` = existing parent of `dest`. */
  async clone(cwd: string, url: string, dest: string, o: { timeoutMs?: number } = {}): Promise<GitxResult> {
    const remote = this.remote(url);
    requireAbsolute(dest, 'clone destination');
    return this.exec(
      ['clone', '--no-checkout', '--no-tags', '--no-recurse-submodules', '--', remote.url, dest],
      { cwd, timeoutMs: o.timeoutMs ?? 120_000 },
      remote,
    );
  }

  /** The network methods return a result; this turns a failure into a typed throw. */
  ensureOk(r: GitxResult, what: string): GitxResult {
    return this.require(r, what);
  }

  private async resolveSsh(): Promise<string> {
    if (this.sshBinOpt !== undefined) return this.sshBinOpt;
    this.sshResolved ??= (async () => {
      const info = await resolveTrustedExecutable(sshCandidates());
      if (info.path === null) {
        throw new GitxError('BINARY', `ssh: no trusted binary found (tried: ${info.candidates.join(', ') || 'none'})`);
      }
      return info.path;
    })().catch((err: unknown) => {
      this.sshResolved = null;
      throw err;
    });
    return this.sshResolved;
  }

  private async verifyHooksDir(): Promise<string> {
    try {
      await assertPrivateDir(this.hooksDir);
      const entries = (await readdir(this.hooksDir)).filter((e) => !e.startsWith(PROBE_PREFIX));
      if (entries.length > 0) throw new GitxError('PRIVATE', 'git hooks directory is not empty; refusing to run git');
    } catch (err) {
      if (err instanceof TrustError) throw new GitxError('PRIVATE', `git hooks directory refused: ${err.message}`);
      throw err;
    }
    return this.hooksDir;
  }

  private async exec(args: readonly string[], o: RunOptions, net: ValidatedRemote | null): Promise<GitxResult> {
    assertSafeArgv(args);
    const extraConfig = o.extraConfig ?? [];
    for (const kv of extraConfig) {
      const eq = kv.indexOf('=');
      const key = eq > 0 ? kv.slice(0, eq).toLowerCase() : '';
      if (!EXTRA_CONFIG_KEYS.has(key) || /[\0\r\n]/.test(kv)) throw new GitxError('ARGS', 'git -c key not allowed');
      const value = kv.slice(eq + 1);
      // `gpg.ssh.program` is a command git would run: it must be exactly the trusted, resolved ssh-keygen.
      if (key === 'gpg.ssh.program' && value !== (await resolveSshKeygen().catch(() => null))) {
        throw new GitxError('ARGS', 'gpg.ssh.program must be the trusted ssh-keygen');
      }
      if (key === 'gpg.format' && value !== 'ssh') throw new GitxError('ARGS', 'gpg.format must be ssh');
      if (key === 'commit.gpgsign' && value !== 'true') throw new GitxError('ARGS', 'commit.gpgsign must be true');
    }
    requireAbsolute(o.cwd, 'cwd');
    const hooksDir = await this.verifyHooksDir();
    let sshCommand: string | undefined;
    if (net !== null && net.kind !== 'local') {
      sshCommand = buildSshCommand({
        sshBin: await this.resolveSsh(),
        knownHostsFile: this.knownHostsFile,
        ...(this.keyFile !== undefined ? { keyFile: this.keyFile } : {}),
      });
    }
    const config = [
      ...buildGitGlobalArgs(hooksDir),
      ...HARDENING_CONFIG.flatMap((c) => ['-c', c]),
      '-c',
      `core.attributesFile=${this.emptyConfig}`,
    ];
    if (net?.kind === 'local') config.push('-c', 'protocol.file.allow=always');
    for (const kv of extraConfig) config.push('-c', kv);
    const env = buildGitEnv({
      source: this.envSource,
      platform: process.platform,
      emptyConfigFile: this.emptyConfig,
      ...(sshCommand !== undefined ? { sshCommand } : {}),
      ...(o.extraEnv !== undefined ? { extra: o.extraEnv } : {}),
    });
    // Git must not discover a repository above `cwd` (a ledger dir that lost its `.git` would
    // otherwise silently operate on whatever repo contains it).
    const parent = nodePath.dirname(o.cwd);
    if (parent !== o.cwd) env.GIT_CEILING_DIRECTORIES = parent;
    return spawnCapture({
      bin: this.gitBin,
      argv: [...config, ...args],
      cwd: o.cwd,
      env,
      ...(o.input !== undefined ? { input: o.input } : {}),
      timeoutMs: o.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxStdout: o.maxStdoutBytes ?? DEFAULT_MAX_STDOUT,
    });
  }
}

async function ensureEmptyPrivateFile(file: string): Promise<void> {
  const st = await lstat(file).catch(() => null);
  if (st === null) {
    await writeFile(file, '', { mode: 0o600, flag: 'wx' });
    return;
  }
  await assertPrivateFile(file);
  if (st.size !== 0) throw new GitxError('PRIVATE', 'empty gitconfig is not empty; refusing to run git');
}

/* ---------------- `.git/config` allowlist (S11) ---------------- */

export type GitConfigProblemCode =
  | 'parse'
  | 'include'
  | 'url-rewrite'
  | 'filter'
  | 'ssh-command'
  | 'gpg'
  | 'section'
  | 'key'
  | 'value';

export interface GitConfigProblem {
  code: GitConfigProblemCode;
  /** `section[.subsection].key`, sanitised and length-limited. NEVER the value. */
  name: string;
}

export interface GitConfigEntry {
  section: string;
  subsection: string | null;
  key: string;
  /** `null` = key without `=` (boolean true). */
  value: string | null;
}

const WS = new Set([' ', '\t', '\r', '\n']);

/** Faithful-enough git-config tokenizer. Any construct it cannot parse is a `parse` problem and stops
 *  parsing: the rest is unknown, so the caller halts (fail-closed). */
export function parseGitConfig(textIn: string): { entries: GitConfigEntry[]; parseError: boolean } {
  const entries: GitConfigEntry[] = [];
  const text = textIn.startsWith('\ufeff') ? textIn.slice(1) : textIn;
  const n = text.length;
  let i = 0;
  let section: string | null = null;
  let sub: string | null = null;
  const fail = () => ({ entries, parseError: true });
  if (text.includes('\0')) return fail();
  while (i < n) {
    const c = text[i] as string;
    if (WS.has(c)) {
      i++;
      continue;
    }
    if (c === '#' || c === ';') {
      while (i < n && text[i] !== '\n') i++;
      continue;
    }
    if (c === '[') {
      i++;
      let name = '';
      while (i < n && /[A-Za-z0-9.-]/.test(text[i] as string)) name += text[i++];
      if (name === '') return fail();
      if (text[i] === ' ' || text[i] === '\t') {
        while (text[i] === ' ' || text[i] === '\t') i++;
        if (text[i] !== '"') return fail();
        i++;
        let s = '';
        for (;;) {
          if (i >= n) return fail();
          const ch = text[i++] as string;
          if (ch === '\n') return fail();
          if (ch === '"') break;
          if (ch === '\\') {
            if (i >= n || text[i] === '\n') return fail();
            s += text[i++];
          } else s += ch;
        }
        section = name.toLowerCase();
        sub = s;
      } else {
        const dot = name.indexOf('.');
        if (dot > 0) {
          section = name.slice(0, dot).toLowerCase();
          sub = name.slice(dot + 1).toLowerCase();
        } else {
          section = name.toLowerCase();
          sub = null;
        }
      }
      if (text[i] !== ']') return fail();
      i++;
      continue;
    }
    // key line
    let key = '';
    if (!/[A-Za-z]/.test(c)) return fail();
    while (i < n && /[A-Za-z0-9-]/.test(text[i] as string)) key += text[i++];
    if (section === null) return fail();
    while (text[i] === ' ' || text[i] === '\t') i++;
    let value: string | null = null;
    if (text[i] === '=') {
      i++;
      while (text[i] === ' ' || text[i] === '\t') i++;
      let v = '';
      let quoted = false;
      let lastNonWs = 0;
      for (;;) {
        if (i >= n) {
          if (quoted) return fail();
          break;
        }
        const ch = text[i] as string;
        if (ch === '\n') {
          if (quoted) return fail();
          break;
        }
        i++;
        if (ch === '\\') {
          const nx = text[i];
          if (nx === undefined) return fail();
          i++;
          if (nx === '\n') continue;
          if (nx === '\r' && text[i] === '\n') {
            i++;
            continue;
          }
          const map: Record<string, string> = { n: '\n', t: '\t', b: '\b', '\\': '\\', '"': '"' };
          const mapped = map[nx];
          if (mapped === undefined) return fail();
          v += mapped;
          lastNonWs = v.length;
          continue;
        }
        if (ch === '"') {
          quoted = !quoted;
          lastNonWs = v.length;
          continue;
        }
        if (!quoted && (ch === ';' || ch === '#')) {
          while (i < n && text[i] !== '\n') i++;
          break;
        }
        v += ch;
        if (quoted || (ch !== ' ' && ch !== '\t' && ch !== '\r')) lastNonWs = v.length;
      }
      value = v.slice(0, lastNonWs);
    } else {
      // bare key: only whitespace, a comment or end of line may follow
      while (i < n && text[i] !== '\n') {
        const ch = text[i] as string;
        if (ch === '#' || ch === ';') {
          while (i < n && text[i] !== '\n') i++;
          break;
        }
        if (ch !== ' ' && ch !== '\t' && ch !== '\r') return fail();
        i++;
      }
    }
    entries.push({ section, subsection: sub, key: key.toLowerCase(), value });
  }
  return { entries, parseError: false };
}

const BOOL_RE = /^(?:true|false|yes|no|on|off|0|1)$/i;
const CORE_ALLOW: Readonly<Record<string, RegExp>> = {
  repositoryformatversion: /^[01]$/,
  filemode: BOOL_RE,
  bare: BOOL_RE,
  logallrefupdates: /^(?:true|false|yes|no|on|off|0|1|always)$/i,
  ignorecase: BOOL_RE,
  precomposeunicode: BOOL_RE,
  symlinks: BOOL_RE,
  longpaths: BOOL_RE,
  protectntfs: BOOL_RE,
  protecthfs: BOOL_RE,
  autocrlf: /^(?:true|false|yes|no|on|off|0|1|input)$/i,
  eol: /^(?:lf|crlf|native)$/i,
};
const FETCH_SPEC_RE = /^\+?refs\/heads\/(?:\*|[A-Za-z0-9._/-]+):refs\/remotes\/origin\/(?:\*|[A-Za-z0-9._/-]+)$/;
const WIN_LOCAL_RE = /^[A-Za-z]:[\\/][^\0-\x1f]*$/;

function configName(e: GitConfigEntry): string {
  return sanitizeField(`${e.section}${e.subsection !== null ? `.${e.subsection}` : ''}.${e.key}`, 80);
}

function originUrlOk(value: string, testLocalRemotes: readonly string[]): boolean {
  try {
    validateRemoteUrl(value, testLocalRemotes);
    return true;
  } catch {
    // A legacy backup `origin` may be a plain local path. It is inert here (every sync command names the
    // URL explicitly and `protocol.file.allow=never`), so a clean absolute path is tolerated, helpers are not.
    if (/[\0-\x1f\x7f]/.test(value) || value.startsWith('-') || /^[A-Za-z][A-Za-z0-9+.-]*::/.test(value)) return false;
    return nodePath.posix.isAbsolute(value) || WIN_LOCAL_RE.test(value);
  }
}

/** Policy over a parsed config: empty array = acceptable. `core.*` known keys, `remote "origin"` url/fetch,
 *  `branch "main"`, `extensions.objectformat`; no `url.*.insteadOf`, `include*`, `filter.*`, `core.sshCommand`, `gpg.*`. */
export function checkGitConfig(text: string, opts: { testLocalRemotes?: readonly string[] } = {}): GitConfigProblem[] {
  const { entries, parseError } = parseGitConfig(text);
  const problems: GitConfigProblem[] = [];
  const seen = new Set<string>();
  const add = (code: GitConfigProblemCode, name: string): void => {
    const k = `${code}\0${name}`;
    if (seen.has(k)) return;
    seen.add(k);
    problems.push({ code, name });
  };
  for (const e of entries) {
    const name = configName(e);
    const { section, subsection, key, value } = e;
    if (section === 'include' || section === 'includeif') add('include', name);
    else if (section === 'url') add('url-rewrite', name);
    else if (section === 'filter') add('filter', name);
    else if (section === 'gpg') add('gpg', name);
    else if (section === 'core' && key === 'sshcommand') add('ssh-command', name);
    else if (section === 'core' && subsection === null) {
      const re = CORE_ALLOW[key];
      if (re === undefined) add('key', name);
      else if (value !== null && !re.test(value)) add('value', name);
    } else if (section === 'remote' && subsection === 'origin') {
      if (key === 'url') {
        if (value === null || !originUrlOk(value, opts.testLocalRemotes ?? [])) add('value', name);
      } else if (key === 'fetch') {
        if (value === null || !FETCH_SPEC_RE.test(value)) add('value', name);
      } else add('key', name);
    } else if (section === 'branch' && subsection === 'main') {
      if (key === 'remote') {
        if (value !== 'origin') add('value', name);
      } else if (key === 'merge') {
        if (value !== REF_MAIN) add('value', name);
      } else if (key === 'vscode-merge-base') {
        if (value === null || !/^[A-Za-z0-9._/-]{1,200}$/.test(value)) add('value', name);
      } else add('key', name);
    } else if (section === 'extensions' && subsection === null) {
      if (key !== 'objectformat') add('key', name);
      else if (value === null || !/^(?:sha1|sha256)$/i.test(value)) add('value', name);
    } else add('section', sanitizeField(`${section}${subsection !== null ? `.${subsection}` : ''}`, 80));
  }
  if (parseError) problems.push({ code: 'parse', name: '' });
  return problems;
}
