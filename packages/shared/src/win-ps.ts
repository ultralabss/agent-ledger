/**
 * Windows backend plumbing for platformTrust: one locked-down PowerShell call per batch
 * (read-only inspection) and one `icacls` call (to SET the private ACL).
 *
 * Threat model: a hostile repo / other local account / env poisoning tries to make the
 * trust probe run attacker code or report a path as safe.
 *  - The PowerShell script is a FIXED constant. Paths travel as JSON in the env var
 *    `LEDGER_TRUST_PATHS` and are never interpolated into command text.
 *  - Absolute `System32` binaries only, `shell:false`, `windowsHide`, timeout, output cap,
 *    explicit working directory and a minimal environment (module path pinned to System32).
 *  - Anything unexpected (bad SystemRoot, missing exe, bad JSON, timeout) is PROBE_FAILED:
 *    the caller refuses, it never assumes "trusted".
 *
 * UNVERIFIED on a real Windows host: the script was written against Windows PowerShell 5.1
 * semantics and exercised only through injected fakes on non-Windows machines.
 */
import { execFile } from 'node:child_process';

// Cold start of Windows PowerShell 5.1 on a loaded CI runner can exceed 15 s; still fail-closed on timeout.
export const PS_TIMEOUT_MS = 45_000;
/** At most this many PowerShell probes at once per process (parallel cold starts starve each other). */
const PS_MAX_CONCURRENT = 2;
let psActive = 0;
const psWaiters: Array<() => void> = [];
async function psSlot<T>(fn: () => Promise<T>): Promise<T> {
  if (psActive >= PS_MAX_CONCURRENT) await new Promise<void>((r) => psWaiters.push(r));
  psActive += 1;
  try {
    return await fn();
  } finally {
    psActive -= 1;
    psWaiters.shift()?.();
  }
}

/** `-EncodedCommand` payload (UTF-16LE base64): no shell/CreateProcess quoting of the script can matter. */
export function encodePsCommand(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64');
}
export const PS_MAX_STDOUT = 1024 * 1024;
export const TRUST_PATHS_ENV = 'LEDGER_TRUST_PATHS';
const MAX_PATHS = 64;
const DIAG_MAX = 300;
const MAX_PATH_LEN = 4096;

export interface SpawnOpts {
  env: Record<string, string>;
  cwd: string;
  timeoutMs: number;
  maxBuffer: number;
}
export interface SpawnResult {
  /** Exit code, or null when the process did not run / was killed. */
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Output exceeded `maxBuffer` (the child was killed). */
  truncated: boolean;
  /** Spawn failure (ENOENT, EACCES, ...). */
  error?: string;
}
export type SpawnFile = (file: string, args: readonly string[], opts: SpawnOpts) => Promise<SpawnResult>;

/** Default runner: `execFile` (never a shell), hidden window, bounded time and output. */
export const defaultSpawnFile: SpawnFile = (file, args, opts) =>
  new Promise((resolve) => {
    const child = execFile(
      file,
      [...args],
      {
        env: opts.env,
        cwd: opts.cwd,
        timeout: opts.timeoutMs,
        maxBuffer: opts.maxBuffer,
        windowsHide: true,
        shell: false,
        encoding: 'utf8',
        killSignal: 'SIGKILL',
      },
      (err, stdout, stderr) => {
        if (err === null) {
          resolve({ code: 0, stdout: String(stdout), stderr: String(stderr), timedOut: false, truncated: false });
          return;
        }
        const e = err as NodeJS.ErrnoException & { killed?: boolean; code?: string | number };
        const truncated = e.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER';
        const timedOut = e.killed === true && !truncated;
        const spawnFailed = typeof e.code === 'string' && !truncated;
        resolve({
          code: typeof e.code === 'number' ? e.code : null,
          stdout: truncated ? '' : String(stdout ?? ''),
          stderr: String(stderr ?? ''),
          timedOut,
          truncated,
          ...(spawnFailed ? { error: String(e.code) } : {}),
        });
      },
    );
    // powershell.exe keeps reading an open stdin pipe and never exits (execFile leaves one open);
    // an immediate EOF makes the fixed script the only input. Never carries data.
    child.stdin?.on('error', () => undefined);
    child.stdin?.end();
  });

// ---- inputs ---------------------------------------------------------------------------

const SYSTEM_ROOT_RE = /^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+$/;
const WIN_ABS_RE = /^[A-Za-z]:\\/;
// eslint-disable-next-line no-control-regex
const BAD_PATH_CHARS = /[\u0000-\u001f*?"<>|:]/;

export class WinPsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WinPsError';
  }
}

/** `SystemRoot` must be a single-component drive-rooted path (spec: `^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+$`). */
export function validSystemRoot(raw: string | undefined): string {
  if (raw === undefined || !SYSTEM_ROOT_RE.test(raw)) throw new WinPsError('SystemRoot is missing or malformed');
  return raw;
}

/** Absolute drive-rooted path without wildcards, control chars or device/extended prefixes. */
export function assertWinPath(p: string): string {
  if (
    typeof p !== 'string' ||
    p.length > MAX_PATH_LEN ||
    !WIN_ABS_RE.test(p) ||
    BAD_PATH_CHARS.test(p.slice(2))
  ) {
    throw new WinPsError('not an absolute drive-rooted path');
  }
  return p;
}

export function powershellPath(systemRoot: string): string {
  return `${systemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
}
export function icaclsPath(systemRoot: string): string {
  return `${systemRoot}\\System32\\icacls.exe`;
}

// ---- the fixed script -----------------------------------------------------------------

/**
 * Fixed script. Reads `LEDGER_TRUST_PATHS` (JSON array of strings) and prints one JSON
 * object: own SID, elevated flag, and per path existence / reparse flag / directory flag /
 * SDDL / drive format / drive type / UNC flag. Paths are echoed by index only. Error
 * detail is the exception type name, never a message (messages can contain paths).
 */
export const WIN_PS_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  // No progress records: with redirected stderr they are serialized as '#< CLIXML' noise (CI 43765681408).
  "$ProgressPreference = 'SilentlyContinue'",
  '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
  // Windows PowerShell 5.1 emits a parsed JSON array as ONE object; piping to ForEach-Object unrolls it,
  // so N paths give N entries (CI 43750942946: 'probe returned the wrong number of paths').
  "$paths = @(ConvertFrom-Json -InputObject $env:LEDGER_TRUST_PATHS | ForEach-Object { $_ })",
  '$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()',
  '$pr = New-Object System.Security.Principal.WindowsPrincipal($id)',
  '$admin = [System.Security.Principal.WindowsBuiltInRole]::Administrator',
  '$list = New-Object System.Collections.ArrayList',
  'foreach ($p in $paths) {',
  '  $r = @{ exists = $false; reparse = $false; isDir = $false; sddl = $null; unc = $false; driveFormat = $null; driveType = $null; error = $null }',
  '  try {',
  '    $item = Get-Item -LiteralPath $p -Force',
  '    $r.exists = $true',
  '    $r.reparse = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)',
  '    $r.isDir = [bool]$item.PSIsContainer',
  '    $r.sddl = (Get-Acl -LiteralPath $p).Sddl',
  '    $root = [System.IO.Path]::GetPathRoot($item.FullName)',
  "    $r.unc = $root.StartsWith('\\\\')",
  '    if (-not $r.unc) {',
  '      $di = New-Object System.IO.DriveInfo($root)',
  '      $r.driveFormat = [string]$di.DriveFormat',
  '      $r.driveType = [string]$di.DriveType',
  '    }',
  '  } catch {',
  '    $r.error = $_.Exception.GetType().Name',
  '  }',
  '  [void]$list.Add($r)',
  '}',
  '$out = @{ sid = $id.User.Value; elevated = [bool]$pr.IsInRole($admin); paths = $list }',
  '$out | ConvertTo-Json -Compress -Depth 6',
].join('\n');

// ---- inspection -----------------------------------------------------------------------

export interface WinPathInfo {
  exists: boolean;
  reparse: boolean;
  isDir: boolean;
  sddl: string | null;
  unc: boolean;
  driveFormat: string | null;
  driveType: string | null;
  /** Exception type name when PowerShell could not read the path. */
  error: string | null;
}
export interface WinInspect {
  sid: string;
  elevated: boolean;
  paths: WinPathInfo[];
}

export interface WinPsContext {
  env: Readonly<Record<string, string | undefined>>;
  spawnFile: SpawnFile;
  /** Existence check of an absolute file (a regular file => true). */
  isFile: (p: string) => Promise<boolean>;
}

/** Variables forwarded to the child. Everything else (PATH, PSModulePath, profile hooks) is replaced. */
const FORWARD = [
  'USERPROFILE',
  'LOCALAPPDATA',
  'APPDATA',
  'TEMP',
  'TMP',
  'ProgramData',
  'ProgramFiles',
  'ProgramW6432',
  'USERNAME',
  'USERDOMAIN',
  'COMPUTERNAME',
  'HOMEDRIVE',
  'HOMEPATH',
  // Benign identity/platform vars some .NET paths consult; none carries code or a search path.
  'SystemDrive',
  'ALLUSERSPROFILE',
  'PUBLIC',
  'PROCESSOR_ARCHITECTURE',
  'NUMBER_OF_PROCESSORS',
  'OS',
  'PATHEXT',
  'ComSpec',
];

function minimalEnv(root: string, extra: Record<string, string>, src: WinPsContext['env']): Record<string, string> {
  const env: Record<string, string> = {};
  for (const k of FORWARD) {
    const v = src[k];
    if (typeof v === 'string' && !v.includes('\0')) env[k] = v;
  }
  env.SystemRoot = root;
  env.windir = root;
  env.PATH = `${root}\\System32`;
  // System32 modules first, then the stock machine-wide module dir (admin/TrustedInstaller-writable only),
  // built from the fixed `<drive of SystemRoot>:\\Program Files` name, never from caller-controlled env.
  // With System32 alone, Windows PowerShell 5.1 spends ~12 s on the first cmdlet (module discovery) for a
  // non-elevated user: every probe took 12-18 s (CI 43776805612). Adding this dir brings it to ~0.4 s.
  env.PSModulePath = `${root}\\System32\\WindowsPowerShell\\v1.0\\Modules;${root.slice(0, 2)}\\Program Files\\WindowsPowerShell\\Modules`;
  return { ...env, ...extra };
}

function isStr(v: unknown): v is string {
  return typeof v === 'string';
}
function strOrNull(v: unknown): string | null {
  return isStr(v) ? v : null;
}

/** Strict shape check of the script output; anything else is a failed probe. */
export function parseInspectOutput(stdout: string, expected: number): WinInspect {
  let raw: unknown;
  try {
    raw = JSON.parse(stdout);
  } catch {
    throw new WinPsError('probe output is not JSON');
  }
  if (typeof raw !== 'object' || raw === null) throw new WinPsError('probe output has the wrong shape');
  const o = raw as Record<string, unknown>;
  if (!isStr(o.sid) || !/^S-1-\d+(?:-\d+)+$/i.test(o.sid)) throw new WinPsError('probe returned no valid SID');
  if (typeof o.elevated !== 'boolean') throw new WinPsError('probe returned no elevation flag');
  // PowerShell collapses a one-element list in some versions: accept object or array.
  const list = Array.isArray(o.paths) ? o.paths : o.paths !== undefined && o.paths !== null ? [o.paths] : [];
  if (list.length !== expected) throw new WinPsError('probe returned the wrong number of paths');
  const paths = list.map((e): WinPathInfo => {
    if (typeof e !== 'object' || e === null) throw new WinPsError('probe path entry has the wrong shape');
    const r = e as Record<string, unknown>;
    if (typeof r.exists !== 'boolean') throw new WinPsError('probe path entry has the wrong shape');
    return {
      exists: r.exists,
      reparse: r.reparse === true,
      isDir: r.isDir === true,
      sddl: strOrNull(r.sddl),
      unc: r.unc === true,
      driveFormat: strOrNull(r.driveFormat),
      driveType: strOrNull(r.driveType),
      error: strOrNull(r.error),
    };
  });
  return { sid: o.sid.toUpperCase(), elevated: o.elevated, paths };
}

/**
 * Short, printable tail of what the child said, for the TrustError message (so a CI log shows
 * WHY a probe failed). The fixed script never prints secrets: only a SID, flags, SDDL and
 * exception type names; stderr is PowerShell's own text. Control chars stripped, length capped.
 */
function diag(res: SpawnResult): string {
  // eslint-disable-next-line no-control-regex
  const clean = (t: string): string => t.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, DIAG_MAX);
  const err = clean(res.stderr);
  const out = clean(res.stdout);
  const parts: string[] = [];
  if (err !== '') parts.push(`stderr: ${err}`);
  if (out !== '') parts.push(`stdout: ${out}`);
  return parts.length > 0 ? ` [${parts.join('; ')}]` : '';
}

/** Run the fixed script over `paths` (one process for the whole batch). */
export async function inspectWindowsPaths(paths: readonly string[], ctx: WinPsContext): Promise<WinInspect> {
  if (paths.length === 0 || paths.length > MAX_PATHS) throw new WinPsError('bad batch size');
  paths.forEach(assertWinPath);
  const root = validSystemRoot(ctx.env.SystemRoot);
  const exe = powershellPath(root);
  if (!(await ctx.isFile(exe).catch(() => false))) throw new WinPsError('powershell.exe not found under SystemRoot');
  const res = await psSlot(() =>
    ctx.spawnFile(
      exe,
      ['-NoProfile', '-NonInteractive', '-NoLogo', '-InputFormat', 'None', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodePsCommand(WIN_PS_SCRIPT)],
      {
        env: minimalEnv(root, { [TRUST_PATHS_ENV]: JSON.stringify(paths) }, ctx.env),
        cwd: root,
        timeoutMs: PS_TIMEOUT_MS,
        maxBuffer: PS_MAX_STDOUT,
      },
    ),
  );
  if (res.error !== undefined) throw new WinPsError(`powershell could not start (${res.error})`);
  if (res.timedOut) throw new WinPsError(`powershell timed out after ${PS_TIMEOUT_MS} ms${diag(res)}`);
  if (res.truncated) throw new WinPsError('powershell output too large');
  if (res.code !== 0) throw new WinPsError(`powershell exited with ${String(res.code)}${diag(res)}`);
  return parseInspectOutput(res.stdout.trim(), paths.length);
}

/**
 * `icacls <dir> /inheritance:r /grant:r *<me>:(OI)(CI)F *S-1-5-18:(OI)(CI)F` (exit code only).
 * `mySid` is validated as a SID; nothing else is interpolated.
 */
export async function setPrivateAcl(dir: string, mySid: string, ctx: WinPsContext): Promise<void> {
  assertWinPath(dir);
  if (!/^S-1-\d+(?:-\d+)+$/i.test(mySid)) throw new WinPsError('own SID is not a SID');
  const root = validSystemRoot(ctx.env.SystemRoot);
  const exe = icaclsPath(root);
  if (!(await ctx.isFile(exe).catch(() => false))) throw new WinPsError('icacls.exe not found under SystemRoot');
  const res = await ctx.spawnFile(
    exe,
    [dir, '/inheritance:r', '/grant:r', `*${mySid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F'],
    { env: minimalEnv(root, {}, ctx.env), cwd: root, timeoutMs: PS_TIMEOUT_MS, maxBuffer: PS_MAX_STDOUT },
  );
  if (res.error !== undefined || res.timedOut || res.truncated || res.code !== 0) {
    throw new WinPsError('icacls failed');
  }
}
