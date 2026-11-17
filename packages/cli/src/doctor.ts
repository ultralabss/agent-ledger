/**
 * `ledger doctor`: why is the hub not answering, in about a dozen lines.
 *
 * Built for a failure that is easy to misread: `AGENT-LEDGER DOWN` at session
 * start with a hub that was running the whole time. The answer needs
 * a few facts next to each other — is the service loaded (launchd / systemd),
 * how fast does `/v1/healthz` answer *now*, does the answering hub serve THIS
 * ledger, and did the event loop stall recently — so they are all on one screen.
 *
 * Every probe produces a `Check` ({id, status ok|warn|fail|info, detail}); the
 * human output prints the `detail` lines, `--json` prints the same checks plus
 * a summary. A `fail` is a problem and drives exit 1; `warn` and `info` never do,
 * with one exception: a path running on a weak filesystem only because
 * `LEDGER_ALLOW_WEAK_FS=1` is a loud WARN block FIRST in the output and exit 2
 * (when nothing is down — a real problem keeps exit 1).
 *
 * Read-only by default: no `launchctl` verb other than `print`, no writes, no
 * self-heal. `--fix` is the one exception and it still goes through the normal
 * rate limit. No network except with `--online` (see doctor-checks.ts).
 */

import { access, constants, open, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  TrustError,
  createTrustDeps,
  detectMachinePlatform,
  deviceHealth,
  listDevices,
  probeFs,
  probeFsStatOnly,
  safeOutput,
  spoolDir,
  spoolStats,
  type FsCaps,
} from '@agent-ledger/shared';
import { bool, type Args } from './args.ts';
import type { CliEnvConfig } from './client.ts';
import {
  defaultCodeRepoDir,
  formatCheck,
  readGitRemotes,
  remoteCheck,
  syncGitVersionCheck,
  syncHaltCheck,
  syncPinnedFilesCheck,
  syncSlotsCheck,
  syncVerifyCheck,
  type Check,
  type CheckStatus,
} from './doctor-checks.ts';
import { linuxChecks } from './doctor-linux.ts';
import { win32Checks, wslChecks } from './doctor-win32.ts';
import { hubIdentityVerdict, hubServesLedger, type IdentityVerdict } from './identity.ts';
import {
  HUB_LABEL,
  guiTarget,
  hubPlistPath,
  lastSelfHealAt,
  runCapture,
  triggerSelfHeal,
  validatePlist,
} from './selfheal.ts';

const LAUNCHCTL = '/bin/launchctl';
const PLUTIL = '/usr/bin/plutil';
const HEALTHZ_TIMEOUT_MS = 1_500;
const SAMPLES = 3;
/** Loop stalls above this are what made session-start miss its 1 s window. */
const LOOP_WARN_MS = 500;
const MAX_LINES = 14;
/** Version of the `--json` document; bump on a breaking change. */
const JSON_SCHEMA = 1;

/** Structurally the CLI's `Io`, declared here so `index.ts` → `doctor.ts` stays
 *  a one-way import (no cycle). */
export interface DoctorIo {
  out: (line: string) => void;
  err: (line: string) => void;
  env: NodeJS.ProcessEnv;
}

interface HubDiag {
  startedAt?: string;
  lastWakeAt?: string | null;
  loopDelayMaxMs?: number;
  missingRepos?: string[];
  gitleaksRetryAt?: string | null;
}

/** Test seam: production passes nothing and probes the real machine. */
export interface DoctorDeps {
  platform?: string;
  uid?: number;
  capture?: typeof runCapture;
  /** Claude Code settings file probed by the optional adapter check. */
  claudeSettingsPath?: string;
  /** PATH searched for the `ledger` shim and the optional `graphify` probe (default: `process.env.PATH`). */
  searchPath?: string;
  /** Home directory (default `os.homedir()`); the default shim dir is `<home>/.local/bin`. */
  homeDir?: string;
  /** Code repository whose `origin` the ledger remote must differ from. */
  codeRepoDir?: string;
  /** Existence probe for the systemctl/loginctl binaries. */
  exists?: (path: string) => Promise<boolean>;
  fetchFn?: typeof fetch;
  /** Filesystem capability probe (default platformTrust `probeFs`). */
  probe?: typeof probeFs;
  /** Stat-only description of the checkout (default `probeFsStatOnly`; creates nothing there). */
  probeStat?: typeof probeFsStatOnly;
  /** Directory whose filesystem is probed as "the current checkout" (default `process.cwd()`). */
  cwd?: string;
  /** Force WSL on/off (default: detected). */
  wsl?: boolean;
  /** Entries of `/mnt/c/Users` for the WSL dual-ledger check (default: read the directory). */
  listWinUsers?: () => Promise<string[]>;
  /** Loader of the sync remote checks (`hub/src/sync/remotecheck.ts`, B4b). `null` = module unavailable. */
  loadRemoteChecks?: () => Promise<SyncRemoteChecksFn | null>;
}

/** What the adapter below hands to the hub's `remoteChecks` (docs/f3b-b4-plan.md §2.4). */
export type SyncRemoteChecksFn = (deps: { ledgerDir: string; online: boolean; codeRepoDir?: string }) => Promise<Check[]>;

const CHECK_STATUSES = new Set<string>(['ok', 'warn', 'fail', 'info']);

/** The sync remote checks live in the hub package (they share `Gitx` / `checkGitConfig` with enrolment). The CLI has
 *  no runtime dependency on the hub, so the modules are loaded from the repository checkout this file sits in, by
 *  absolute paths derived from `import.meta.url` (never from env or input); any failure = `null` (one warn line).
 *  The adapter opens `Gitx` only for `--online` (network checks) and reads the code repo's `origin` for the
 *  "remote differs from the code repository" check. */
async function defaultLoadRemoteChecks(): Promise<SyncRemoteChecksFn | null> {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const href = (...p: string[]): string => pathToFileURL(resolve(here, '..', '..', 'hub', 'src', 'sync', ...p)).href;
    const rc = (await import(href('remotecheck.ts'))) as { remoteChecks?: unknown };
    if (typeof rc.remoteChecks !== 'function') return null;
    const run = rc.remoteChecks as (d: Record<string, unknown>) => Promise<Check[]>;
    return async ({ ledgerDir, online, codeRepoDir }) => {
      let gitx: unknown;
      if (online) {
        const gx = (await import(href('gitx.ts'))) as { Gitx?: { open(o: { syncDir: string }): Promise<unknown> } };
        gitx = await gx.Gitx?.open({ syncDir: join(ledgerDir, '.hub', 'sync') });
      }
      const remotes = await readGitRemotes(codeRepoDir ?? defaultCodeRepoDir());
      const codeRepoRemote = remotes?.find((r) => r.name === 'origin')?.url ?? null;
      return run({ ledgerDir, online, codeRepoRemote, ...(gitx === undefined ? {} : { gitx }) });
    };
  } catch {
    return null;
  }
}

/** Sync section: only on an enrolled ledger (`.hub/sync.yml`) or one with an enrolment marker. Offline facts come
 *  from the shared device store; the remote / git-config / marker checks from `remoteChecks` (network only with
 *  `--online`). A missing module is ONE warn, never a crash. Every line passes `safeOutput`; no URL is printed. */
export async function syncChecks(ledgerDir: string, online: boolean, deps: DoctorDeps = {}, env: NodeJS.ProcessEnv = process.env): Promise<Check[]> {
  const enrolled = await exists(join(ledgerDir, '.hub', 'sync.yml'));
  const marker = await exists(join(ledgerDir, '.hub', 'sync', 'enrol.json'));
  if (!enrolled && !marker) return [];
  const out: Check[] = [];
  const seen = new Set<string>();
  const push = (c: Check): void => {
    if (seen.has(c.id) || out.length >= 40) return;
    seen.add(c.id);
    out.push({ id: c.id, status: c.status, detail: safeOutput(c.detail, 300) });
  };
  if (marker) push({ id: 'sync_enrol_marker', status: 'warn', detail: 'sync: an enrolment is in progress or was interrupted (the hub stays down): ledger sync init|join --continue, or --abort' });
  if (enrolled) {
    try {
      const rows = await listDevices(ledgerDir);
      const active = rows.filter((d) => d.status === 'active');
      const unapproved = active.filter((d) => !d.trusted && !d.self);
      if (unapproved.length > 0) {
        push({
          id: 'sync_devices_unapproved',
          status: 'warn',
          // No fingerprint in the hint (audit B4C-3): the owner must read it off the OTHER device, not copy it from here.
          detail: `sync: ${String(unapproved.length)} device(s) registered by a peer are not trusted here yet (${unapproved.map((d) => d.id).slice(0, 3).join(' · ')}): compare the fingerprint shown on that device, then ledger device approve <id> --fp <SHA256:…>`,
        });
      }
      push(syncSlotsCheck(rows));
      if (active.filter((d) => d.trusted).length <= 1) {
        push({ id: 'sync_single_trusted_device', status: 'warn', detail: 'sync: only one trusted device — losing it loses write access to the remote history; add a second (ledger device add)' });
      }
    } catch {
      push({ id: 'sync_devices_unreadable', status: 'warn', detail: 'sync: the device registry could not be read' });
    }
  }
  if (enrolled) {
    push(syncVerifyCheck(env.LEDGER_SYNC_VERIFY, env.LEDGER_SYNC));
    push(await syncHaltCheck(ledgerDir));
    push(await syncPinnedFilesCheck(ledgerDir));
    push(await syncGitVersionCheck({ platform: deps.platform ?? process.platform, exists: deps.exists ?? exists, capture: deps.capture ?? runCapture }));
  }
  const load = deps.loadRemoteChecks ?? defaultLoadRemoteChecks;
  let fn: SyncRemoteChecksFn | null = null;
  try {
    fn = await load();
  } catch {
    fn = null;
  }
  if (fn === null) {
    push({ id: 'sync_remote_checks', status: 'warn', detail: 'sync: remote checks are not available in this install (skipped)' });
    return out;
  }
  try {
    for (const c of await fn({ ledgerDir, online, ...(deps.codeRepoDir !== undefined ? { codeRepoDir: deps.codeRepoDir } : {}) })) {
      if (c !== null && typeof c === 'object' && typeof c.id === 'string' && /^[a-z0-9_]{1,40}$/.test(c.id) && CHECK_STATUSES.has(c.status) && typeof c.detail === 'string') push(c);
    }
  } catch {
    push({ id: 'sync_remote_checks', status: 'warn', detail: 'sync: the remote checks failed to run (skipped)' });
  }
  return out;
}

const WEAK_FS_FIX =
  'move it to a local filesystem (NTFS, ext4, APFS) and unset LEDGER_ALLOW_WEAK_FS';

/** One probe target of the FS section. */
interface FsTarget {
  id: string;
  label: string;
  dir: string;
  /** A directory we do not own (the user's checkout): never create/chmod anything there. */
  statOnly?: boolean;
}

/**
 * FS section: weak filesystems (bypass active => WARN block, no bypass => the hub refuses there =>
 * fail), permission errors with the fix, never anything for a missing directory beyond an info
 * line. `weak` is true when ANY path runs on the bypass (drives exit 2).
 */
export async function fsChecks(
  targets: readonly FsTarget[],
  probe: typeof probeFs,
  probeStat: typeof probeFsStatOnly = probeFsStatOnly,
): Promise<{ checks: Check[]; problems: string[]; weak: boolean }> {
  const warn: Check[] = [];
  const rest: Check[] = [];
  /** Healthy / not-yet-existing targets share ONE line (the doctor output has a line budget). */
  const fine: string[] = [];
  const problems: string[] = [];
  let weak = false;
  for (const t of targets) {
    let caps: FsCaps;
    try {
      caps = await (t.statOnly === true ? probeStat(t.dir) : probe(t.dir));
    } catch (err) {
      const code = (err as { code?: unknown } | null)?.code;
      if (code === 'ENOENT' || code === 'ENOTDIR') {
        fine.push(`${t.id} absent`);
      } else if (code === 'EACCES' || code === 'EPERM') {
        rest.push({
          id: `fs_${t.id}`,
          status: 'warn',
          detail: `fs ${t.id}: permission denied probing ${t.label} — your account must own and be able to write it (POSIX: chown -R "$USER" <dir> && chmod 700 <dir>; Windows: fix the folder ACL, do not run elevated)`,
        });
      } else if (err instanceof TrustError) {
        rest.push({ id: `fs_${t.id}`, status: 'fail', detail: `fs ${t.id}: ${err.message}` });
        problems.push(`${t.id} ${t.label} failed the trust check (${err.code})`);
      } else {
        rest.push({ id: `fs_${t.id}`, status: 'info', detail: `fs ${t.id}: not probed (${code === undefined ? 'error' : String(code)})` });
      }
      continue;
    }
    const why = caps.reasons.length > 0 ? caps.reasons.join(', ') : 'capabilities missing';
    if (caps.weak && caps.bypassed) {
      weak = true;
      warn.push({
        id: `fs_${t.id}`,
        status: 'warn',
        detail: `WARNING: weak filesystem ${t.label} (${caps.fsType}: ${why}) — LEDGER_ALLOW_WEAK_FS=1 is set, so private-permission checks are OFF there; ${WEAK_FS_FIX}`,
      });
    } else if (caps.weak) {
      rest.push({
        id: `fs_${t.id}`,
        status: 'fail',
        detail: `fs ${t.id}: ${t.label} is on ${caps.fsType} which cannot enforce private permissions (${why}); the hub refuses to run there — ${WEAK_FS_FIX.replace('and unset LEDGER_ALLOW_WEAK_FS', 'or, accepting the risk, set LEDGER_ALLOW_WEAK_FS=1')}`,
      });
      problems.push(`${t.id} ${t.label} is on a filesystem without private permissions`);
    } else {
      fine.push(`${t.id} ${caps.fsType}`);
    }
  }
  const line: Check[] =
    fine.length > 0 ? [{ id: 'fs', status: 'ok', detail: `fs: ${fine.join(' · ')}` }] : [];
  // The bypass block goes first; then the line for healthy targets, then everything else.
  return { checks: [...warn, ...line, ...rest], problems, weak };
}

type IdentityProbe = { state: 'unreachable' } | { state: 'answered'; verdict: IdentityVerdict };

/** Unauthenticated healthz, no token: who holds the port? (T12 — decided BEFORE the token is sent.) */
async function probeIdentity(baseUrl: string, ledgerDir: string): Promise<IdentityProbe> {
  try {
    const res = await fetch(`${baseUrl}/v1/healthz`, {
      redirect: 'manual',
      signal: AbortSignal.timeout(HEALTHZ_TIMEOUT_MS),
    });
    let body: unknown = null;
    if (res.ok) {
      try {
        body = JSON.parse((await res.text()).slice(0, 64 * 1024));
      } catch {
        body = null;
      }
    }
    return { state: 'answered', verdict: hubIdentityVerdict(body, ledgerDir) };
  } catch {
    return { state: 'unreachable' };
  }
}

/** First executable `name` found in `pathVar`, or `null`. No process is spawned. */
export async function findInPath(name: string, pathVar: string | undefined): Promise<string | null> {
  for (const dir of (pathVar ?? '').split(delimiter)) {
    if (dir === '') continue;
    const candidate = join(dir, name);
    try {
      await access(candidate, constants.X_OK);
      if ((await stat(candidate)).isFile()) return candidate;
    } catch {
      // not here
    }
  }
  return null;
}

export async function cmdDoctor(
  args: Args,
  cfg: CliEnvConfig,
  io: DoctorIo,
  deps: DoctorDeps = {},
): Promise<number> {
  const checks: Check[] = [];
  const problems: string[] = [];
  let suggestion = 'ledger doctor --fix';
  const platform = deps.platform ?? process.platform;
  const uid = deps.uid ?? createTrustDeps().getuid();
  const capture = deps.capture ?? runCapture;
  const add = (id: string, status: CheckStatus, detail: string): void => {
    checks.push({ id, status, detail });
  };

  /* ---- filesystem (weak/bypass WARN block goes first) ---- */
  const fsTargets: FsTarget[] = [];
  const hubDir = join(cfg.ledgerDir, '.hub');
  // `.hub` is the private, git-ignored part of the ledger: the probe file never reaches the repo.
  if (await exists(hubDir)) fsTargets.push({ id: 'ledger', label: cfg.ledgerDir, dir: hubDir });
  else fsTargets.push({ id: 'ledger', label: cfg.ledgerDir, dir: cfg.ledgerDir });
  const spool = spoolDir(io.env);
  fsTargets.push({ id: 'spool', label: spool, dir: spool });
  // W1/W4: the checkout is the user's, not ours — stat-only on POSIX (win32 inspection creates nothing).
  fsTargets.push({
    id: 'checkout',
    label: deps.cwd ?? process.cwd(),
    dir: deps.cwd ?? process.cwd(),
    statOnly: platform !== 'win32',
  });
  const fsr = await fsChecks(fsTargets, deps.probe ?? probeFs, deps.probeStat ?? probeFsStatOnly);
  checks.push(...fsr.checks);
  problems.push(...fsr.problems);

  if (bool(args, 'fix')) {
    const res = await triggerSelfHeal({
      ledgerDir: cfg.ledgerDir,
      port: new URL(cfg.baseUrl).port || '80',
      env: io.env,
      mode: 'checked',
    });
    add(
      'fix',
      'info',
      `--fix: ${res.attempted ? res.reason : `skipped (${res.reason})`}${res.detail ? ` — ${res.detail}` : ''}`,
    );
  }

  /* ---- service supervisor: launchd (macOS) / systemd user unit (Linux) ---- */
  if (platform === 'linux') {
    const linux = await linuxChecks({ capture, uid, env: io.env, exists: deps.exists });
    checks.push(...linux.checks);
    problems.push(...linux.problems);
    if (linux.suggestion !== null) suggestion = linux.suggestion;
    const isWsl = deps.wsl ?? detectMachinePlatform() === 'wsl';
    if (isWsl) {
      const wsl = await wslChecks({
        env: io.env,
        ledgerDir: cfg.ledgerDir,
        spoolDir: spool,
        exists: deps.exists ?? exists,
        ...(deps.listWinUsers === undefined ? {} : { listUsers: deps.listWinUsers }),
      });
      checks.push(...wsl.checks);
      problems.push(...wsl.problems);
      if (wsl.suggestion !== null) suggestion = wsl.suggestion;
    }
  } else if (platform === 'win32') {
    const win = await win32Checks({ capture, env: io.env, exists: deps.exists ?? exists });
    checks.push(...win.checks);
    problems.push(...win.problems);
    if (win.suggestion !== null) suggestion = win.suggestion;
  } else if (platform !== 'darwin' || typeof uid !== 'number') {
    add('service', 'info', `service: no supervisor probe on ${platform}`);
  } else {
    const printed = await capture(LAUNCHCTL, ['print', guiTarget(uid)], 3_000);
    if (printed.code !== 0) {
      add('launchd', 'fail', `launchd: ${HUB_LABEL} is not loaded in gui/${uid}`);
      problems.push('launchd job is not loaded');
      suggestion = 'ledger doctor --fix (or install.sh)';
    } else {
      const state = field(printed.stdout, 'state') ?? '?';
      const pid = field(printed.stdout, 'pid') ?? '-';
      const runs = field(printed.stdout, 'runs') ?? '-';
      const exit =
        /last exit (?:code|status) = (-?\d+)/.exec(printed.stdout)?.[1] ??
        field(printed.stdout, 'last exit code') ??
        '-';
      let bad = false;
      if (state !== 'running') {
        problems.push(`launchd state ${state}`);
        bad = true;
      }
      // `(never exited)` is launchd's wording for a job that has run once and is
      // still running — the healthy state right after a (re)start.
      if (exit !== '0' && exit !== '-' && !/never exited/.test(exit)) {
        problems.push(`last exit ${exit}`);
        bad = true;
      }
      add('launchd', bad ? 'fail' : 'ok', `launchd: loaded · state ${state} · pid ${pid} · runs ${runs} · last exit ${exit}`);
    }
  }

  /* ---- plist ---- */
  if (platform === 'darwin' && typeof uid === 'number') {
    const plist = hubPlistPath();
    const bad = await validatePlist(plist, uid);
    if (bad !== null) {
      add('plist', 'fail', `plist: ${bad}`);
      problems.push(`plist failed validation (${bad})`);
    } else {
      const parsed = await readPlist(plist, capture);
      if (parsed === null) {
        add('plist', 'fail', 'plist: cannot be read (plutil)');
        problems.push('plist cannot be parsed');
      } else {
        let failed = false;
        const env = (parsed.EnvironmentVariables ?? {}) as Record<string, unknown>;
        const argv = Array.isArray(parsed.ProgramArguments) ? parsed.ProgramArguments : [];
        const entry = pickEntryScript(argv);
        const entryOk = entry !== null && (await exists(entry));
        if (!entryOk) {
          problems.push(`ProgramArguments entry script does not exist (${entry ?? 'missing'})`);
          failed = true;
        }
        const type = typeof parsed.ProcessType === 'string' ? parsed.ProcessType : '-';
        const notes: string[] = [`ProcessType ${type}${type === 'Background' ? ' (low priority)' : ''}`];
        notes.push(entryOk ? 'entry ok' : 'entry MISSING');
        if (env.LEDGER_TRUST_CLAUDE_GROUP === '1') {
          const missing = ['LEDGER_TRUST_CLAUDE_GID', 'LEDGER_TRUST_CLAUDE_REALPATH'].filter(
            (k) => typeof env[k] !== 'string' || env[k] === '',
          );
          notes.push(
            missing.length === 0 ? 'trust-claude pinned' : `trust-claude without ${missing.join('+')}`,
          );
          if (missing.length > 0) {
            problems.push('LEDGER_TRUST_CLAUDE_GROUP=1 without pinned GID/REALPATH');
            failed = true;
          }
        }
        add('plist', failed ? 'fail' : 'ok', `plist: ${notes.join(' · ')}`);
      }
    }
  }

  /* ---- healthz ---- */
  // T12: the token is read and sent only to a hub that proved it is THIS machine's hub for THIS
  // ledger (platform + ledger_id from the unauthenticated healthz). Anything else gets no token.
  const ident = await probeIdentity(cfg.baseUrl, cfg.ledgerDir);
  const verified = ident.state === 'answered' && ident.verdict.ok;
  const token = verified ? await readToken(cfg.ledgerDir) : null;
  const samples: (number | null)[] = [];
  let diag: HubDiag | null = null;
  let reportedLedger: unknown;
  for (let i = 0; i < SAMPLES; i += 1) {
    const got = await sampleHealthz(cfg.baseUrl, token);
    samples.push(got.ms);
    if (got.diag !== null) diag = got.diag;
    if (got.ledger !== undefined) reportedLedger = got.ledger;
  }
  const ok = samples.filter((s) => s !== null).length;
  const healthzDetail = `healthz: ${ok}/${SAMPLES} ok · ${samples
    .map((s) => (s === null ? 'x' : `${s} ms`))
    .join(' / ')}`;
  if (ok === 0) {
    add('healthz', 'fail', healthzDetail);
    problems.push(`hub is not answering at ${cfg.baseUrl}/v1/healthz`);
  } else if (ok < SAMPLES) {
    add('healthz', 'fail', healthzDetail);
    problems.push('healthz answers unreliably');
  } else {
    add('healthz', 'ok', healthzDetail);
  }

  /* ---- identity: does the process on the port serve THIS ledger? ---- */
  // `ledger` is reported only to a caller with the right token, so a missing
  // value means an older hub or a hub of another ledger that rejected our token.
  if (ok > 0 && ident.state === 'answered' && !ident.verdict.ok) {
    if (ident.verdict.unidentified) {
      add(
        'identity',
        'warn',
        'identity: healthz did not name its platform/ledger — token not sent (older hub: restart it; or another service holds the port)',
      );
    } else {
      add(
        'identity',
        'fail',
        `identity: the hub on this port serves another ledger or platform (${ident.verdict.detail}) — token not sent`,
      );
      problems.push(`another hub owns ${cfg.baseUrl} (LEDGER_DIR / LEDGER_HUB_PORT mismatch, WSL vs Windows?)`);
    }
  } else if (ok > 0) {
    if (await hubServesLedger(reportedLedger, cfg.ledgerDir)) {
      add('identity', 'ok', 'identity: hub serves this ledger');
    } else if (typeof reportedLedger === 'string' && reportedLedger !== '') {
      add('identity', 'fail', `identity: the hub on this port serves another ledger (${reportedLedger})`);
      problems.push(`another hub owns ${cfg.baseUrl} (LEDGER_DIR / LEDGER_HUB_PORT mismatch)`);
    } else {
      add(
        'identity',
        'warn',
        'identity: healthz did not name its ledger (older hub, or a process that rejected this ledger token)',
      );
    }
  }

  /* ---- diag (optional, hub-side contract) ---- */
  if (diag !== null) {
    const parts = [`running since ${diag.startedAt ?? '?'}`];
    if (typeof diag.loopDelayMaxMs === 'number') parts.push(`loop max ${diag.loopDelayMaxMs} ms`);
    if (diag.lastWakeAt) parts.push(`wake ${diag.lastWakeAt}`);
    if (diag.missingRepos && diag.missingRepos.length > 0) {
      parts.push(`missing repos: ${diag.missingRepos.slice(0, 3).join(',')}`);
    }
    if (diag.gitleaksRetryAt) parts.push(`gitleaks retry ${diag.gitleaksRetryAt}`);
    const stalled = typeof diag.loopDelayMaxMs === 'number' && diag.loopDelayMaxMs > LOOP_WARN_MS;
    add('hub', stalled ? 'fail' : 'ok', `hub: ${parts.join(' · ')}`);
    if (stalled) problems.push(`event loop stalled for ${diag.loopDelayMaxMs} ms (hook timeout is 1000 ms)`);
  }

  /* ---- spool + self-heal ---- */
  const stats = await spoolStats(io.env).catch(() => ({ queued: 0, failed: 0 }));
  const healAt = await lastSelfHealAt(cfg.ledgerDir);
  add(
    'spool',
    stats.failed > 0 ? 'fail' : 'ok',
    `spool: ${stats.queued} queued · ${stats.failed} failed · self-heal ${
      healAt === null ? 'never' : `${Math.round((Date.now() - healAt) / 1000)} s ago`
    }`,
  );
  if (stats.failed > 0) problems.push(`${stats.failed} failed spool records`);

  /* ---- claude-code adapter (optional) ---- */
  // Informational only: never a problem. Skipped when Claude Code is not set up.
  const home = deps.homeDir ?? homedir();
  add('claude_code_adapter', 'info', await adapterLine(deps.claudeSettingsPath ?? join(home, '.claude', 'settings.json')));

  /* ---- graphify (optional, info only) ---- */
  // A missing graphify is never a problem: the ledger has no dependency on it.
  const searchPath = deps.searchPath ?? process.env.PATH;
  const gfy = await findInPath('graphify', searchPath);
  add('graphify', 'info', gfy === null ? 'graphify: not found (optional)' : `graphify: found (${gfy})`);

  /* ---- `ledger` shim on PATH ---- */
  checks.push(await pathCheck(searchPath, join(io.env.SHIM_DIR ?? join(home, '.local', 'bin'), 'ledger')));

  /* ---- ledger format + ledger remote (privacy) ---- */
  checks.push(await formatCheck(cfg.ledgerDir));
  checks.push(
    await remoteCheck({
      ledgerDir: cfg.ledgerDir,
      codeRepoDir: deps.codeRepoDir,
      online: bool(args, 'online'),
      fetchFn: deps.fetchFn,
    }),
  );

  /* ---- device key / signers / stale devices (only once device identity exists) ---- */
  for (const c of await deviceHealth(cfg.ledgerDir)) {
    checks.push(c);
    if (c.status === 'fail') problems.push(c.detail.slice(0, 120));
  }

  /* ---- sync (enrolled ledgers only) ---- */
  for (const c of await syncChecks(cfg.ledgerDir, bool(args, 'online'), deps, io.env)) {
    checks.push(c);
    if (c.status === 'fail') problems.push(c.detail.slice(0, 120));
  }

  /* ---- hub.log ---- */
  // A running hub reports `startedAt`: only its own lines matter then. A hub
  // that is down has none, and the previous run's last errors are the clue.
  const errs = await logErrors(cfg.ledgerDir, 3, diag?.startedAt ?? null);
  // Budget: the verdict line plus what is already queued. The log is the only
  // variable-length section, so it absorbs the cap.
  const room = Math.max(0, MAX_LINES - 1 - checks.length);
  for (const line of errs.slice(0, room)) add('log', 'warn', `log: ${line}`);

  // 1 = something is wrong; 2 = nothing is down but a path runs on the weak-FS bypass.
  const exit = problems.length > 0 ? 1 : fsr.weak ? 2 : 0;
  if (bool(args, 'json')) {
    const count = (s: CheckStatus): number => checks.filter((c) => c.status === s).length;
    io.out(
      JSON.stringify({
        schema: JSON_SCHEMA,
        platform,
        checks,
        summary: {
          ok: exit === 0,
          exit,
          weak_fs: fsr.weak,
          counts: { ok: count('ok'), warn: count('warn'), fail: count('fail'), info: count('info') },
          problems,
          suggestion: exit === 0 ? null : exit === 2 ? WEAK_FS_FIX : suggestion,
        },
      }),
    );
    return exit;
  }
  for (const c of checks) io.out(c.detail);
  if (exit === 0) {
    io.out('OK');
    return 0;
  }
  if (exit === 2) {
    io.out(`WEAK-FS BYPASS ACTIVE → ${WEAK_FS_FIX}`);
    return 2;
  }
  io.out(`DOWN: ${problems.slice(0, 3).join('; ')} → ${suggestion}`);
  return 1;
}

/** Is the `ledger` shim reachable? Found on PATH → ok; present in the install
 *  dir but that dir is not on PATH → warn; absent → warn. Never a problem. */
export async function pathCheck(pathVar: string | undefined, shim: string): Promise<Check> {
  const found = await findInPath('ledger', pathVar);
  if (found !== null) return { id: 'path', status: 'ok', detail: `path: ledger on PATH (${found})` };
  if (await exists(shim)) {
    return { id: 'path', status: 'warn', detail: `path: ledger shim at ${shim} but its directory is not on PATH` };
  }
  return { id: 'path', status: 'warn', detail: 'path: no ledger shim on PATH (run install.sh)' };
}

/** Optional "Claude Code adapter" probe: are `ledger hook` entries present in
 *  the agent host's settings? Info only; a missing file just means "skipped". */
async function adapterLine(settingsPath: string): Promise<string> {
  let text: string;
  try {
    text = await readFile(settingsPath, 'utf8');
  } catch {
    return 'claude-code adapter: skipped (no ~/.claude/settings.json)';
  }
  const hooks = (text.match(/ledger hook [a-z-]+/g) ?? []).length;
  return hooks > 0
    ? `claude-code adapter: ${hooks} ledger hook entries installed`
    : 'claude-code adapter: settings found, no ledger hooks (optional: adapters/claude-code/install-hooks.mjs)';
}

/**
 * `ProgramArguments[1]` was the entry script only while the plist
 * had no flags before it. It now also carries `--disable-warning=…` at
 * index 1, pushing the script to index 2 — pick the first argument after
 * `argv[0]` that is not a flag, so both the old and the new plist shape work.
 * Exported for a direct unit test — `cmdDoctor`'s plist branch only runs
 * against the real `~/Library/LaunchAgents` plist, which tests must not touch.
 */
export function pickEntryScript(argv: unknown[]): string | null {
  return argv.slice(1).find((a): a is string => typeof a === 'string' && !a.startsWith('-')) ?? null;
}

/** `launchctl print` emits `\tkey = value` lines. */
function field(text: string, key: string): string | null {
  const re = new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} = (.+)$`, 'm');
  return re.exec(text)?.[1]?.trim() ?? null;
}

async function readPlist(
  path: string,
  capture: typeof runCapture,
): Promise<Record<string, unknown> | null> {
  const res = await capture(PLUTIL, ['-convert', 'json', '-o', '-', path], 3_000);
  if (res.code !== 0) return null;
  try {
    const json = JSON.parse(res.stdout) as unknown;
    return json !== null && typeof json === 'object' ? (json as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function readToken(ledgerDir: string): Promise<string | null> {
  try {
    const fh = await open(`${ledgerDir}/.hub/token`, 'r');
    try {
      const buf = Buffer.alloc(256);
      const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
      const text = buf.subarray(0, bytesRead).toString('utf8').trim();
      return text === '' ? null : text;
    } finally {
      await fh.close();
    }
  } catch {
    return null;
  }
}

async function sampleHealthz(
  baseUrl: string,
  token: string | null,
): Promise<{ ms: number | null; diag: HubDiag | null; ledger?: string }> {
  const started = Date.now();
  try {
    const res = await fetch(`${baseUrl}/v1/healthz`, {
      headers: token === null ? {} : { 'x-hub-token': token },
      redirect: 'manual',
      signal: AbortSignal.timeout(HEALTHZ_TIMEOUT_MS),
    });
    const ms = Date.now() - started;
    if (!res.ok) return { ms: null, diag: null };
    const text = await res.text();
    let diag: HubDiag | null = null;
    let ledger: string | undefined;
    try {
      const body = JSON.parse(text) as { diag?: HubDiag; ledger?: unknown };
      // Optional by contract: an older hub simply has no `diag`.
      if (body.diag !== null && typeof body.diag === 'object') diag = body.diag ?? null;
      if (typeof body.ledger === 'string') ledger = body.ledger;
    } catch {
      diag = null;
    }
    return { ms, diag, ledger };
  } catch {
    return { ms: null, diag: null };
  }
}

/** Last error-looking lines of `<ledger>/.hub/hub.log`. Only the tail is read —
 *  the log is append-only and can be megabytes. Only ISO-timestamped lines
 *  (the hub's log format) count, so foreign lines never show up;
 *  with `since`, only lines from that run on. */
export async function logErrors(ledgerDir: string, max = 3, since: string | null = null): Promise<string[]> {
  const path = `${ledgerDir}/.hub/hub.log`;
  try {
    const st = await stat(path);
    const span = Math.min(st.size, 64 * 1024);
    const fh = await open(path, 'r');
    let text: string;
    try {
      const buf = Buffer.alloc(span);
      await fh.read(buf, 0, span, st.size - span);
      text = buf.toString('utf8');
    } finally {
      await fh.close();
    }
    return text
      .split('\n')
      .filter((l) => {
        const ts = /^(\d{4}-\d\d-\d\dT[\d:.]+Z) /.exec(l)?.[1];
        // Same ISO-UTC format on both sides, so string order is time order.
        return ts !== undefined && (since === null || ts >= since);
      })
      .filter((l) => /error|err:|failed|exception|EADDRINUSE|ECONN/i.test(l))
      .slice(-max)
      .map((l) => l.trim().slice(0, 160));
  } catch {
    return [];
  }
}
