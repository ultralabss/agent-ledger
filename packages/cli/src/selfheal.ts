/**
 * Bring the hub's launchd job back when it is not answering (only relevant if
 * the hub was installed as a launchd job by `install.sh`; otherwise this
 * finds no plist and does nothing).
 *
 * Why this exists: a `session-start` hook that cannot reach the hub prints
 * `AGENT-LEDGER DOWN` and the whole session then treats `QUEUED` as an error.
 * When the port really is dead, one `launchctl` call fixes it — so the CLI
 * makes that call itself instead of asking the user to paste one.
 *
 * Hard rules, all of them security- or latency-driven:
 *  - darwin only, `LEDGER_SELFHEAL=0` disables it everywhere.
 *  - rate limited through a marker file, written BEFORE the spawn, so a loop of
 *    failing hooks cannot turn into a loop of `launchctl` calls.
 *  - never `kickstart -k`: `-k` kills a *running* hub. A hub that is slow is
 *    not a hub that should be shot; we only ever start one that is not running.
 *  - the child is `detached` + `stdio: 'ignore'` + `.unref()`, never awaited on
 *    the tool-hook path (§10.1 latency budget).
 *  - everything in `argv` is a module constant except the plist path, which is
 *    derived from `os.userInfo().homedir` (not `$HOME`, which a caller can set)
 *    and validated with `lstat` before it is handed to `bootstrap`.
 *  - fail-open: this never throws and never prints.
 */

import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open as openFile, readFile } from 'node:fs/promises';
import { userInfo } from 'node:os';
import { dirname, join } from 'node:path';

/** Must match the default `Label` in `ops/launchd/*.plist.tmpl` and `install.sh` (AGENT_LEDGER_LABEL). */
export const HUB_LABEL = 'io.agent-ledger.hub';
const LAUNCHCTL = '/bin/launchctl';
const PLUTIL = '/usr/bin/plutil';
/** Two attempts inside 30 s would only ever fight each other: `ThrottleInterval`
 *  in the plist is 10 s and a cold hub needs ~1 s to listen. */
export const SELFHEAL_MIN_INTERVAL_MS = 30_000;

export interface SpawnedChild {
  unref(): void;
}

export type SpawnFn = (
  command: string,
  args: readonly string[],
  options: { stdio: 'ignore'; detached: boolean; shell: false },
) => SpawnedChild;

export interface StatFacts {
  isFile: boolean;
  isSymlink: boolean;
  uid: number;
  mode: number;
}

export interface SelfHealDeps {
  now: () => number;
  platform: string;
  getuid: () => number | undefined;
  homedir: () => string;
  spawnDetached: SpawnFn;
  capture: (
    command: string,
    args: readonly string[],
    timeoutMs: number,
  ) => Promise<{ code: number | null; stdout: string }>;
  readText: (path: string) => Promise<string>;
  writeMarker: (path: string, text: string) => Promise<void>;
  statOf: (path: string) => Promise<StatFacts>;
}

export interface SelfHealOpts {
  ledgerDir: string;
  /** The port this caller is talking to. In `mode: 'checked'` it is compared
   *  with the launchd job's own `LEDGER_HUB_PORT`: kicking a job that serves a
   *  different port/ledger can never fix *this* caller's hub (and it is how a
   *  test with a temp ledger avoids touching the installed instance). */
  port?: string;
  env?: NodeJS.ProcessEnv;
  /**
   * 'fast'    — tool hooks. Nothing is awaited and nothing is inspected first.
   * 'checked' — session-start, `ledger` commands, `ledger doctor --fix`. Asks
   *             `launchctl print` whether the job is loaded before choosing.
   */
  mode?: 'fast' | 'checked';
  deps?: Partial<SelfHealDeps>;
}

export interface SelfHealResult {
  attempted: boolean;
  /** Machine-readable, for `ledger doctor` and the tests. Never printed by hooks. */
  reason:
    | 'disabled'
    | 'not-darwin'
    | 'no-uid'
    | 'rate-limited'
    | 'other-instance'
    | 'kickstart'
    | 'bootstrap'
    | 'bootstrap+kickstart'
    | 'plist-rejected'
    | 'error';
  /** Set when `reason` is `plist-rejected`, for `ledger doctor`. */
  detail?: string;
}

export function selfHealMarker(ledgerDir: string): string {
  return join(ledgerDir, '.hub', 'selfheal.at');
}

export function hubPlistPath(deps?: Partial<SelfHealDeps>): string {
  const home = deps?.homedir?.() ?? userInfo().homedir;
  return join(home, 'Library', 'LaunchAgents', `${HUB_LABEL}.plist`);
}

/** `launchctl` target for the user's GUI domain — the only domain this job
 *  ever lives in, and the only one a non-root CLI may touch. */
export function guiTarget(uid: number): string {
  return `gui/${uid}/${HUB_LABEL}`;
}

function defaultDeps(): SelfHealDeps {
  return {
    now: () => Date.now(),
    platform: process.platform,
    getuid: () => process.getuid?.(),
    homedir: () => userInfo().homedir,
    spawnDetached: spawn as unknown as SpawnFn,
    capture: runCapture,
    readText: (p) => readFile(p, 'utf8'),
    // `writeFile(p, …, { mode: 0o600 })` only applies that mode when
    // IT creates the file, and it follows a symlink at `p` — another local
    // user could pre-create the marker path as a symlink or a world-writable
    // file and this would happily write through it. `O_NOFOLLOW` makes a
    // symlink ELOOP instead of being followed, and `fchmod` on the already-
    // open fd enforces 0600 even on a pre-existing file.
    writeMarker: async (p, text) => {
      await mkdir(dirname(p), { recursive: true, mode: 0o700 });
      const fh = await openFile(
        p,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | fsConstants.O_NOFOLLOW,
        0o600,
      );
      try {
        await fh.chmod(0o600);
        await fh.writeFile(text, 'utf8');
      } finally {
        await fh.close();
      }
    },
    statOf: async (p) => {
      const st = await lstat(p);
      return {
        isFile: st.isFile(),
        isSymlink: st.isSymbolicLink(),
        uid: st.uid,
        mode: st.mode,
      };
    },
  };
}

function merged(deps?: Partial<SelfHealDeps>): SelfHealDeps {
  return deps ? { ...defaultDeps(), ...deps } : defaultDeps();
}

/** Run a command and collect stdout. Used by `mode: 'checked'` and by
 *  `ledger doctor`; never on the tool-hook path. `shell: false`, absolute
 *  command, constant argv. */
export async function runCapture(
  command: string,
  args: readonly string[],
  timeoutMs: number,
): Promise<{ code: number | null; stdout: string }> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (code: number | null, stdout: string): void => {
      if (done) return;
      done = true;
      resolve({ code, stdout });
    };
    let child;
    try {
      child = spawn(command, [...args], {
        stdio: ['ignore', 'pipe', 'ignore'],
        shell: false,
        timeout: timeoutMs,
      });
    } catch {
      finish(null, '');
      return;
    }
    let out = '';
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      // Bounded: `launchctl print` output is a few KB, a broken pipe is not.
      if (out.length < 256 * 1024) out += chunk;
    });
    child.on('error', () => finish(null, out));
    child.on('close', (code) => finish(code, out));
  });
}

/**
 * Is the plist safe to hand to `launchctl bootstrap`?
 *
 * `bootstrap` reads the file and runs whatever `ProgramArguments` says, as this
 * user. So a plist that someone else can write is remote code execution with
 * extra steps. Rejected: a symlink (the target could be swapped after the
 * check), anything that is not a regular file, a file owned by another uid, and
 * any group- or other-writable mode. The containing directory gets the same
 * treatment — a writable `~/Library/LaunchAgents` makes the file's own mode
 * meaningless.
 *
 * Returns `null` when the path is acceptable, otherwise a short reason.
 */
export async function validatePlist(
  path: string,
  uid: number,
  deps?: Partial<SelfHealDeps>,
): Promise<string | null> {
  const d = merged(deps);
  // An earlier version only looked at `dirname(path)` and `path` — a
  // writable ancestor ANYWHERE between `$HOME` and the plist (e.g. a
  // tampered `~/Library`) defeated it exactly like a writable
  // `LaunchAgents` would. Walk every component from `$HOME` down to the
  // file, same test on each.
  const home = d.homedir();
  const chain: string[] = [path];
  let cur = dirname(path);
  for (;;) {
    chain.push(cur);
    if (cur === home) break;
    const parent = dirname(cur);
    if (parent === cur) break; // reached filesystem root without hitting $HOME
    cur = parent;
  }
  chain.reverse();
  for (const target of chain) {
    let st: StatFacts;
    try {
      st = await d.statOf(target);
    } catch {
      return `${target} cannot be read`;
    }
    if (st.isSymlink) return `${target} is a symlink`;
    if (st.uid !== uid) return `${target} is not owned by uid ${uid}`;
    if ((st.mode & 0o022) !== 0) return `${target} is writable by group/other`;
    if (target === path && !st.isFile) return `${target} is not a regular file`;
  }
  return null;
}

export async function lastSelfHealAt(
  ledgerDir: string,
  deps?: Partial<SelfHealDeps>,
): Promise<number | null> {
  const d = merged(deps);
  try {
    const raw = (await d.readText(selfHealMarker(ledgerDir))).trim();
    const ms = Number(raw);
    return Number.isFinite(ms) && ms > 0 ? ms : null;
  } catch {
    return null;
  }
}

/** Never throws, never prints. */
export async function triggerSelfHeal(opts: SelfHealOpts): Promise<SelfHealResult> {
  const d = merged(opts.deps);
  const env = opts.env ?? process.env;
  try {
    if (env.LEDGER_SELFHEAL?.trim() === '0') return { attempted: false, reason: 'disabled' };
    if (d.platform !== 'darwin') return { attempted: false, reason: 'not-darwin' };
    const uid = d.getuid();
    if (typeof uid !== 'number') return { attempted: false, reason: 'no-uid' };

    const marker = selfHealMarker(opts.ledgerDir);
    const last = await lastSelfHealAt(opts.ledgerDir, d);
    const now = d.now();
    // `now - last >= 0` let a future-dated marker (clock skew, or a
    // marker file tampered with) skip the rate limit entirely instead of
    // being the most-recently-healed case. `Math.abs` treats "far in the
    // future" the same as "far in the past" — still outside the window.
    if (last !== null && Math.abs(now - last) < SELFHEAL_MIN_INTERVAL_MS) {
      return { attempted: false, reason: 'rate-limited' };
    }
    // Before the spawn, on purpose: if the write fails we do not heal at all,
    // because an un-rate-limited heal is worse than no heal (every hook of a
    // broken session would spawn `launchctl` again).
    try {
      await d.writeMarker(marker, `${now}\n`);
    } catch {
      return { attempted: false, reason: 'error' };
    }

    const target = guiTarget(uid);
    const plist = hubPlistPath(d);

    if (opts.mode === 'checked') {
      const printed = await d.capture(LAUNCHCTL, ['print', target], 2_000);
      if (printed.code === 0) {
        if (mismatch(settingsOf(printed.stdout), opts)) {
          return { attempted: false, reason: 'other-instance' };
        }
        // Loaded. `kickstart` without `-k` starts it if it is not running and
        // is a no-op if it is — it can never interrupt a healthy hub.
        kick(d, target);
        return { attempted: true, reason: 'kickstart' };
      }
      const bad = await validatePlist(plist, uid, d);
      if (bad !== null) return { attempted: false, reason: 'plist-rejected', detail: bad };
      // The job is not loaded, so `launchctl print` had nothing to compare.
      // One `plutil` read instead — this path runs at most once per 30 s and
      // only when the job is genuinely absent.
      const fromPlist = await plistSettings(d, plist);
      if (fromPlist !== null && mismatch(fromPlist, opts)) {
        return { attempted: false, reason: 'other-instance' };
      }
      boot(d, uid, plist);
      return { attempted: true, reason: 'bootstrap' };
    }

    // 'fast': no `launchctl print` round trip (that is a process spawn plus a
    // wait, and this path runs inside a tool hook with a ~50 ms p95 budget).
    // Both verbs are fired detached and unawaited; whichever does not apply
    // fails harmlessly on its own stderr, which goes to /dev/null:
    //   job loaded, hub dead   → kickstart works, bootstrap says "already
    //                            bootstrapped" and exits non-zero
    //   job not loaded         → kickstart says "could not find service",
    //                            bootstrap loads it (RunAtLoad starts it)
    // `kickstart` goes first because the job being loaded is the common case.
    kick(d, target);
    const bad = await validatePlist(plist, uid, d);
    if (bad !== null) return { attempted: true, reason: 'plist-rejected', detail: bad };
    boot(d, uid, plist);
    return { attempted: true, reason: 'bootstrap+kickstart' };
  } catch {
    return { attempted: false, reason: 'error' };
  }
}

interface Settings {
  ledgerDir?: string | undefined;
  port?: string | undefined;
}

/** Pull `LEDGER_DIR` / `LEDGER_HUB_PORT` out of `launchctl print`'s
 *  `environment = { KEY => value }` block. */
function settingsOf(text: string): Settings {
  const read = (key: string): string | undefined =>
    new RegExp(`${key}\\s*=>\\s*(.+)`).exec(text)?.[1]?.trim();
  return { ledgerDir: read('LEDGER_DIR'), port: read('LEDGER_HUB_PORT') };
}

async function plistSettings(d: SelfHealDeps, plist: string): Promise<Settings | null> {
  const res = await d.capture(PLUTIL, ['-convert', 'json', '-o', '-', plist], 2_000);
  if (res.code !== 0) return null;
  try {
    const parsed = JSON.parse(res.stdout) as {
      EnvironmentVariables?: Record<string, unknown>;
    };
    const env = parsed.EnvironmentVariables ?? {};
    return {
      ledgerDir: typeof env.LEDGER_DIR === 'string' ? env.LEDGER_DIR : undefined,
      port: typeof env.LEDGER_HUB_PORT === 'string' ? env.LEDGER_HUB_PORT : undefined,
    };
  } catch {
    return null;
  }
}

/** Only a *parsed and differing* value skips the heal. Anything unknown falls
 *  through to healing: a parser that stops matching must not silently turn
 *  self-heal off in production. */
function mismatch(found: Settings, opts: SelfHealOpts): boolean {
  if (found.port !== undefined && opts.port !== undefined && found.port !== opts.port) return true;
  return found.ledgerDir !== undefined && found.ledgerDir !== opts.ledgerDir;
}

function kick(d: SelfHealDeps, target: string): void {
  fire(d, ['kickstart', target]);
}

function boot(d: SelfHealDeps, uid: number, plist: string): void {
  fire(d, ['bootstrap', `gui/${uid}`, plist]);
}

function fire(d: SelfHealDeps, args: readonly string[]): void {
  try {
    const child = d.spawnDetached(LAUNCHCTL, args, {
      stdio: 'ignore',
      detached: true,
      shell: false,
    });
    child.unref();
  } catch {
    // Fail-open: a self-heal that cannot spawn is still just a down hub.
  }
}
