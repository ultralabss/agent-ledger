/**
 * Gitleaks as a second line of defence in front of every ledger commit.
 *
 * The hub's own secret scanner (`assertNoSecretsDeep`, `packages/shared/src/secrets.ts`)
 * runs on the API boundary and is the FIRST line: it rejects a value before it
 * ever reaches a markdown file. gitleaks runs on what actually got staged, so
 * it also covers content that arrived some other way (a human editing the
 * ledger by hand, an import, a journal written by an older hub).
 *
 * Deliberate design points:
 *  - A8-4: the binary is the install-managed copy in `<ledger>/.hub/bin`,
 *    verified (owner, mode, directory chain, sha256) by `managedbin.ts` before
 *    every spawn. Never PATH-resolved, never a Homebrew path, never a shell.
 *  - a MISSING gitleaks is a warning, not a block: the commit proceeds. The
 *    hub's own scanner already ran, and a ledger that stops committing is a
 *    worse failure than an unscanned commit.
 *  - a FINDING blocks the commit and leaves the staged changes in place, so a
 *    human can inspect `git diff --cached` in the ledger.
 *  - the finding text is never logged verbatim; gitleaks prints the matched
 *    secret in some versions. Only rule ids / file names are surfaced.
 */

import { spawn } from 'node:child_process';
import { dirname, join, win32 as winPath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveTrustedExecutable } from '@agent-ledger/shared';
import { verifyManagedBinary, type ManagedBinary } from './managedbin.ts';

/**
 * A8-4: the ONLY gitleaks the hub will execute — the copy `install.sh`
 * placed inside the ledger's own `.hub/bin` (0700 chain, 0500 file, owner us)
 * together with a recorded sha256. Homebrew's `/opt/homebrew/bin` is
 * `drwxrwxr-x <user>:admin` and is no longer a candidate: any admin account
 * could replace the scanner that is supposed to stop secrets from being
 * committed. `.hub/` is gitignored in the ledger, so the copy is never part of
 * what gets scanned or committed.
 */
export const GITLEAKS_REL_PATH = '.hub/bin/gitleaks';

/** The release asset for win32 is `gitleaks.exe`; CreateProcess does not apply PATHEXT to an absolute path. */
export function gitleaksPath(ledgerRoot: string, platform: NodeJS.Platform = process.platform): string {
  return join(ledgerRoot, platform === 'win32' ? `${GITLEAKS_REL_PATH}.exe` : GITLEAKS_REL_PATH);
}

const WIN_SYSTEM_ROOT_RE = /^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+$/;

/**
 * S7/I3: the scanner's environment. POSIX keeps the fixed minimal PATH. On win32 the PATH is
 * built from absolute, trust-checked locations only (the directory of the verified git.exe plus
 * `%SystemRoot%\System32`), never inherited — gitleaks execs `git` and must not find a planted one.
 * No value is taken from the hub environment except a validated `SystemRoot`.
 */
export function scanEnv(
  platform: NodeJS.Platform,
  hostEnv: NodeJS.ProcessEnv,
  cwd: string,
  gitDir: string | null,
): Record<string, string> {
  if (platform !== 'win32') return { PATH: '/usr/bin:/bin', HOME: cwd, GITLEAKS_NO_UPDATE: '1' };
  const env: Record<string, string> = { HOME: cwd, USERPROFILE: cwd, GITLEAKS_NO_UPDATE: '1' };
  const root = hostEnv.SystemRoot ?? hostEnv.SYSTEMROOT ?? '';
  if (WIN_SYSTEM_ROOT_RE.test(root)) {
    env.SystemRoot = root;
    const dirs = [gitDir, `${root}\\System32`].filter((d): d is string => d !== null && /^[A-Za-z]:\\/.test(d));
    env.PATH = dirs.join(';');
  }
  return env;
}

/** win32 only: directory of a trust-verified git.exe (same candidates as `git.ts`), else null. */
async function trustedWinGitDir(env: NodeJS.ProcessEnv): Promise<string | null> {
  const candidates = [
    env.ProgramW6432 === undefined ? undefined : `${env.ProgramW6432}\\Git\\cmd\\git.exe`,
    env.ProgramFiles === undefined ? undefined : `${env.ProgramFiles}\\Git\\cmd\\git.exe`,
    env.LOCALAPPDATA === undefined ? undefined : `${env.LOCALAPPDATA}\\Programs\\Git\\cmd\\git.exe`,
  ].filter((c): c is string => c !== undefined && /^[A-Za-z]:\\/.test(c));
  if (candidates.length === 0) return null;
  const info = await resolveTrustedExecutable(candidates);
  return info.path === null ? null : winPath.dirname(info.path);
}

const TIMEOUT_MS = 10_000;
const OUTPUT_CAP_BYTES = 4 * 1024 * 1024;

/** H6-1: shipped with the hub, never inside a scanned ledger — see the file
 *  itself for why `--config` always points here. */
const DEFAULT_CONFIG_PATH = fileURLToPath(new URL('./gitleaks-default.toml', import.meta.url));

export interface SecretScanResult {
  /** `null` when no trustworthy gitleaks binary exists on this machine. */
  scanner: 'gitleaks' | null;
  /** True when the commit must NOT proceed: a positive finding, or
   *  a scanner that was supposed to run and could not finish. */
  blocked: boolean;
  /** The block is a transient scanner failure (timeout, spawn,
   *  runner error), not a finding — so the ledger may re-arm itself and try
   *  again without a human and without a hub restart. A FINDING is
   *  never retryable: the staged diff has to be looked at. The ledger
   *  retries it on a backoff (15 s → 60 s → 5 min). */
  retryable?: boolean;
  /** Human-readable, secret-free note for the log / healthz / `ledger status`. */
  note: string | null;
}

export interface GitleaksRunner {
  (root: string): Promise<SecretScanResult>;
}

// H6-3: keyed by the exact (binPath, stopAt) the caller used. A single shared
// promise regardless of args would let one caller's resolution (e.g. a test's
// fake binary under its own tmpdir `stopAt`) leak into another caller's answer
// (e.g. the real ledger copy) within the same process, or vice versa.
const resolvedCache = new Map<string, Promise<ManagedBinary>>();

/** Last resolution, for the synchronous `/v1/healthz` + brief. `null`
 *  means nothing has probed yet (no commit attempt in this process). */
let lastInfo: ManagedBinary | null = null;

/**
 * R7-4: `mismatch` is no longer folded into `untrusted`.
 *
 * The two need different words in front of a human: `untrusted` = the copy's
 * owner/mode/directory chain is not exclusively ours (somebody else can write
 * it), `mismatch` = the bytes are not the ones the install recorded, which in
 * practice is almost always a `brew upgrade` nobody re-installed, and very
 * occasionally a swapped binary. Both mean "we did not run it", so the commit
 * policy is identical — but "stale copy, re-run install" and "possibly
 * tampered" are not the same message.
 */
export type GitleaksAvailability = 'unknown' | 'ok' | 'untrusted' | 'missing' | 'mismatch';

/** Synchronous view for healthz / the SessionStart brief. A8-4: a sha256
 *  mismatch is reported as `untrusted` — same consequence (we do not run it),
 *  different `detail`, and the commit policy for "no scanner" applies. */
export function gitleaksAvailability(): { state: GitleaksAvailability; detail: string | null } {
  if (lastInfo === null) return { state: 'unknown', detail: null };
  if (lastInfo.state === 'ok') return { state: 'ok', detail: lastInfo.path };
  if (lastInfo.state === 'missing') return { state: 'missing', detail: null };
  if (lastInfo.state === 'mismatch') return { state: 'mismatch', detail: lastInfo.detail };
  return { state: 'untrusted', detail: lastInfo.detail };
}

/** Full detail of the (cached) verification of the managed copy. */
export function gitleaksInfo(ledgerRoot: string, stopAt?: string): Promise<ManagedBinary> {
  return gitleaksInfoFor(gitleaksPath(ledgerRoot), stopAt);
}

/** Same, for an explicit binary path (tests, and `scanStaged`'s seam). */
export function gitleaksInfoFor(binPath: string, stopAt?: string): Promise<ManagedBinary> {
  const key = JSON.stringify([binPath, stopAt ?? null]);
  let p = resolvedCache.get(key);
  if (p === undefined) {
    p = verifyManagedBinary(binPath, { ...(stopAt === undefined ? {} : { stopAt }) }).catch(
      (): ManagedBinary => ({ path: null, state: 'untrusted', detail: 'check failed' }),
    );
    resolvedCache.set(key, p);
  }
  return p.then((info) => {
    lastInfo = info;
    return info;
  });
}

/** Resolved once per process PER (binPath, stopAt). A missing binary is cached
 *  as `null` — we do not re-probe the filesystem on every commit. */
export function gitleaksBinary(ledgerRoot: string, stopAt?: string): Promise<string | null> {
  return gitleaksInfo(ledgerRoot, stopAt).then((info) => info.path);
}

/** Test seam: forget the cached resolution(s). */
export function resetGitleaksCache(): void {
  resolvedCache.clear();
  lastInfo = null;
}

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function run(
  bin: string,
  args: string[],
  cwd: string,
  timeoutMs = TIMEOUT_MS,
  env: Record<string, string> = scanEnv(process.platform, process.env, cwd, null),
): Promise<RunResult> {
  return new Promise((resolvePromise) => {
    // `spawn` can throw SYNCHRONOUSLY (ENOEXEC on a file that passed
    // every permission check but is not a program, EACCES, ENOMEM) — the
    // `error` event never fires for those, so without this the exception flew
    // straight out of `scanStaged` and only `LedgerGit.scan()`'s catch stopped
    // it from being an unhandled rejection. Map it onto the same `-1` as an
    // async spawn failure, which is a fail-closed block below.
    let child;
    try {
      child = spawn(bin, args, {
        cwd,
        // Own process group, so the timeout below can kill the whole
        // tree. Measured before this: a child that spawned a sleeping grandchild
        // survived `child.kill()` (the grandchild kept our stdio pipes open), so
        // `close` — and with it the commit decision — arrived 30 s after a 10 s
        // timeout. `detached` changes nothing else here: the child is still
        // reaped by us and still gets the same minimal env.
        detached: true,
        // No inherited env beyond the minimum: gitleaks does not need our
        // secrets to look for secrets. H6-2: `HOME` is deliberately NOT the
        // real user's — scoped to the scanned root (same allowlist spirit as
        // `headless.ts`'s `ENV_ALLOWLIST`), so gitleaks cannot resolve `~` into
        // the actual user's home (global gitleaks config, shell rc files, etc).
        // See `scanEnv` (win32: absolute trust-checked PATH only).
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
      });
    } catch (err) {
      resolvePromise({ code: -1, stdout: '', stderr: `spawn failed: ${String(err)}` });
      return;
    }
    let stdout = '';
    let stderr = '';
    let bytes = 0;
    let killed = false;
    let settled = false;
    const settle = (res: RunResult): void => {
      if (settled) return;
      settled = true;
      resolvePromise(res);
    };
    /** SIGKILL the whole group, falling back to the child alone. */
    const killTree = (): void => {
      killed = true;
      try {
        if (child.pid !== undefined) process.kill(-child.pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    };
    const timer = setTimeout(() => {
      killTree();
      // Resolve HERE, not from `close`. The commit decision must be
      // bounded by the budget; waiting for the pipes to close made the real
      // wait as long as the slowest thing holding them.
      settle({ code: -2, stdout, stderr });
    }, timeoutMs);
    const take = (buf: Buffer, into: 'out' | 'err') => {
      bytes += buf.length;
      if (bytes > OUTPUT_CAP_BYTES) {
        killTree();
        // H55-A6: settle HERE, same as the timeout path above — otherwise a
        // child killed for exceeding the output cap, whose pipes never
        // close (or close late), left the promise pending instead of
        // failing closed (`code: -2` → `blocked: true, retryable: true`).
        clearTimeout(timer);
        settle({ code: -2, stdout, stderr });
        return;
      }
      if (into === 'out') stdout += buf.toString('utf8');
      else stderr += buf.toString('utf8');
    };
    child.stdout.on('data', (d: Buffer) => take(d, 'out'));
    child.stderr.on('data', (d: Buffer) => take(d, 'err'));
    child.on('error', () => {
      clearTimeout(timer);
      settle({ code: -1, stdout, stderr: 'spawn failed' });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      settle({ code: killed ? -2 : (code ?? -1), stdout, stderr });
    });
  });
}

/**
 * Summarise gitleaks output WITHOUT echoing the matched secret. gitleaks
 * prints lines like `Secret:      ghp_xxx` / `RuleID:      github-pat` /
 * `File:        foo.md` — we keep only rule ids and file names.
 */
export function summariseFindings(text: string): string {
  const rules = new Set<string>();
  const files = new Set<string>();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const rule = /^RuleID:\s*(.+)$/i.exec(line);
    if (rule?.[1]) rules.add(rule[1].trim().slice(0, 60));
    const file = /^File:\s*(.+)$/i.exec(line);
    if (file?.[1]) files.add(file[1].trim().slice(0, 120));
  }
  const parts: string[] = [];
  if (rules.size > 0) parts.push(`rules: ${[...rules].slice(0, 5).join(', ')}`);
  if (files.size > 0) parts.push(`files: ${[...files].slice(0, 5).join(', ')}`);
  return parts.length > 0 ? parts.join(' · ') : 'gitleaks reported a finding (details in the gitleaks log)';
}

/**
 * Scan the staged changes of the ledger repo at `root`.
 *
 * Version compatibility: gitleaks v8.19+ renamed `protect --staged` to
 * `git --staged`, and v8.28 deprecated `protect` entirely. We try `protect`
 * first and fall back to piping the staged diff through `gitleaks stdin` when
 * the subcommand is not recognised, exactly as the task describes.
 */
export async function scanStaged(
  root: string,
  /** `timeoutMs` is a TEST seam only — production always uses `TIMEOUT_MS`, so
   *  the budget cannot be widened by anything that reaches the hub. */
  opts: { binPath?: string; trustStopAt?: string; timeoutMs?: number } = {},
): Promise<SecretScanResult> {
  const info = await gitleaksInfoFor(opts.binPath ?? gitleaksPath(root), opts.trustStopAt);
  const bin = info.path;
  if (bin === null) {
    // A8-4: "install never copied it", "the copy is not exclusively
    // ours" and "the copy is not the bytes we recorded" need different fixes,
    // so they must not share a message. All three keep the existing policy for
    // a missing scanner: the commit proceeds with a warning.
    return {
      scanner: null,
      blocked: false,
      note:
        info.state === 'missing'
          ? `gitleaks is not in ${GITLEAKS_REL_PATH} — the ledger commit ran without a second check. ` +
            'Run `install.sh` (it installs gitleaks and copies it into the ledger).'
          : info.state === 'mismatch'
            ? `gitleaks in ${GITLEAKS_REL_PATH} does not match the recorded sha256 (${info.detail ?? '?'}) — ` +
              'the binary was NOT run, the ledger commit ran without a second check. ' +
              'After `brew upgrade gitleaks` re-running `install.sh` is enough; if you updated nothing, ' +
              'treat it as a tampered binary and investigate.'
            : `gitleaks in ${GITLEAKS_REL_PATH} is not trusted (${info.detail ?? '?'}) — ` +
              'the ledger commit ran without a second check. Run `install.sh`, ' +
              'which sets the directory and permissions up again.',
    };
  }

  // H6-1: `--config` is always explicit — see `gitleaks-default.toml` for why
  // a `.gitleaks.toml` planted inside the ledger must never be picked up.
  const configArgs = ['--config', DEFAULT_CONFIG_PATH];
  const budget = opts.timeoutMs ?? TIMEOUT_MS;
  const env = scanEnv(
    process.platform,
    process.env,
    root,
    process.platform === 'win32' ? await trustedWinGitDir(process.env) : null,
  );
  let res = await run(
    bin,
    ['protect', '--staged', '--no-banner', '--redact', ...configArgs],
    root,
    budget,
    env,
  );
  // Unknown subcommand (newer gitleaks): retry with the modern spelling.
  if (res.code !== 0 && res.code !== 1 && /unknown command|unknown flag/i.test(res.stderr)) {
    res = await run(bin, ['git', '--staged', '--no-banner', '--redact', ...configArgs], root, budget, env);
  }

  // A scanner that was supposed to run and did not finish is
  // NOT a clean scan. This used to return `blocked: false`, so a staged diff
  // large or crafted enough to blow the 10 s budget (or the 4 MB output cap)
  // committed itself unscanned — the one input an attacker controls was also
  // the switch that turned the check off. Fail closed instead: the commit is
  // held, the staged changes stay in place, and `LedgerGit` keeps the pending
  // summary so the next cycle retries on its own.
  // `LedgerGit` retries on a backoff (15 s → 60 s → 5 min); the
  // timeout itself is not lowered.
  if (res.code === -2) {
    return {
      scanner: 'gitleaks',
      blocked: true,
      retryable: true,
      note:
        `gitleaks did not finish within ${budget} ms (or exceeded the output limit) and was killed — ` +
        'the ledger commit is blocked, not let through. The next cycle tries again; ' +
        'if it keeps happening, check `git diff --cached` in the ledger and run gitleaks by hand',
    };
  }
  // R7-1: `code: -1` is a failed spawn (binary vanished between the
  // verification and the exec, EACCES, ENOMEM). Same reasoning — explicit so
  // it cannot silently drift into the "unknown exit" bucket below.
  if (res.code === -1) {
    return {
      scanner: 'gitleaks',
      blocked: true,
      retryable: true,
      note:
        'gitleaks could not be started (spawn failed) — the ledger commit is blocked. ' +
        'Run `install.sh` and check that the copy in .hub/bin exists and is executable',
    };
  }
  // 0 = clean, 1 = leaks found.
  if (res.code === 0) return { scanner: 'gitleaks', blocked: false, note: null };
  if (res.code === 1) {
    return {
      scanner: 'gitleaks',
      blocked: true,
      note: summariseFindings(`${res.stdout}\n${res.stderr}`),
    };
  }
  // H6-1: any other exit means gitleaks itself errored (bad flags, crash, a
  // malformed input engineered to make it fail) — fail CLOSED. A scanner an
  // attacker can make error out must not thereby let their commit through
  // unscanned; a missing binary (no scanner ever ran) stays a warning above,
  // this is a scanner that ran and choked.
  return {
    scanner: 'gitleaks',
    blocked: true,
    retryable: true,
    note: `gitleaks failed (code ${res.code}) — commit blocked, check \`git diff --cached\` in the ledger and run gitleaks by hand`,
  };
}
