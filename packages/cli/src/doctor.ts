/**
 * `ledger doctor`: why is the hub not answering, in ten lines or less.
 *
 * Built for a failure that is easy to misread: `AGENT-LEDGER DOWN` at session
 * start with a hub that was running the whole time. The answer needs
 * four facts next to each other — is the job loaded, is the plist what we
 * think it is, how fast does `/v1/healthz` answer *now*, and did the event loop
 * stall recently — so they are all on one screen.
 *
 * Read-only by default: no `launchctl` verb other than `print`, no writes, no
 * self-heal. `--fix` is the one exception and it still goes through the normal
 * rate limit.
 */

import { access, constants, open, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import { spoolStats } from '@agent-ledger/shared';
import { bool, type Args } from './args.ts';
import type { CliEnvConfig } from './client.ts';
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
const MAX_LINES = 10;

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
  /** PATH searched for the optional `graphify` probe (default: `process.env.PATH`). */
  searchPath?: string;
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
  const lines: string[] = [];
  const problems: string[] = [];
  let suggestion = 'ledger doctor --fix';
  const platform = deps.platform ?? process.platform;
  const uid = deps.uid ?? process.getuid?.();
  const capture = deps.capture ?? runCapture;

  if (bool(args, 'fix')) {
    const res = await triggerSelfHeal({
      ledgerDir: cfg.ledgerDir,
      port: new URL(cfg.baseUrl).port || '80',
      env: io.env,
      mode: 'checked',
    });
    lines.push(`--fix: ${res.attempted ? res.reason : `skipped (${res.reason})`}${
      res.detail ? ` — ${res.detail}` : ''
    }`);
  }

  /* ---- launchd ---- */
  if (platform !== 'darwin' || typeof uid !== 'number') {
    lines.push('launchd: n/a (macOS only)');
  } else {
    const printed = await capture(LAUNCHCTL, ['print', guiTarget(uid)], 3_000);
    if (printed.code !== 0) {
      lines.push(`launchd: ${HUB_LABEL} is not loaded in gui/${uid}`);
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
      lines.push(`launchd: loaded · state ${state} · pid ${pid} · runs ${runs} · last exit ${exit}`);
      if (state !== 'running') problems.push(`launchd state ${state}`);
      // `(never exited)` is launchd's wording for a job that has run once and is
      // still running — the healthy state right after a (re)start.
      if (exit !== '0' && exit !== '-' && !/never exited/.test(exit)) {
        problems.push(`last exit ${exit}`);
      }
    }
  }

  /* ---- plist ---- */
  if (platform === 'darwin' && typeof uid === 'number') {
    const plist = hubPlistPath();
    const bad = await validatePlist(plist, uid);
    if (bad !== null) {
      lines.push(`plist: ${bad}`);
      problems.push(`plist failed validation (${bad})`);
    } else {
      const parsed = await readPlist(plist, capture);
      if (parsed === null) {
        lines.push('plist: cannot be read (plutil)');
        problems.push('plist cannot be parsed');
      } else {
        const env = (parsed.EnvironmentVariables ?? {}) as Record<string, unknown>;
        const argv = Array.isArray(parsed.ProgramArguments) ? parsed.ProgramArguments : [];
        const entry = pickEntryScript(argv);
        const entryOk = entry !== null && (await exists(entry));
        if (!entryOk) problems.push(`ProgramArguments entry script does not exist (${entry ?? 'missing'})`);
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
          }
        }
        lines.push(`plist: ${notes.join(' · ')}`);
      }
    }
  }

  /* ---- healthz ---- */
  const token = await readToken(cfg.ledgerDir);
  const samples: (number | null)[] = [];
  let diag: HubDiag | null = null;
  for (let i = 0; i < SAMPLES; i += 1) {
    const got = await sampleHealthz(cfg.baseUrl, token);
    samples.push(got.ms);
    if (got.diag !== null) diag = got.diag;
  }
  const ok = samples.filter((s) => s !== null).length;
  lines.push(
    `healthz: ${ok}/${SAMPLES} ok · ${samples.map((s) => (s === null ? 'x' : `${s} ms`)).join(' / ')}`,
  );
  if (ok === 0) {
    problems.push(`hub is not answering at ${cfg.baseUrl}/v1/healthz`);
  } else if (ok < SAMPLES) {
    problems.push('healthz answers unreliably');
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
    lines.push(`hub: ${parts.join(' · ')}`);
    if (typeof diag.loopDelayMaxMs === 'number' && diag.loopDelayMaxMs > LOOP_WARN_MS) {
      problems.push(`event loop stalled for ${diag.loopDelayMaxMs} ms (hook timeout is 1000 ms)`);
    }
  }

  /* ---- spool + self-heal ---- */
  const stats = await spoolStats(io.env).catch(() => ({ queued: 0, failed: 0 }));
  const healAt = await lastSelfHealAt(cfg.ledgerDir);
  lines.push(
    `spool: ${stats.queued} queued · ${stats.failed} failed · self-heal ${
      healAt === null ? 'never' : `${Math.round((Date.now() - healAt) / 1000)} s ago`
    }`,
  );
  if (stats.failed > 0) problems.push(`${stats.failed} failed spool records`);

  /* ---- claude-code adapter (optional) ---- */
  // Informational only: never a problem. Skipped when Claude Code is not set up.
  lines.push(await adapterLine(deps.claudeSettingsPath ?? join(homedir(), '.claude', 'settings.json')));

  /* ---- graphify (optional, info only) ---- */
  // A missing graphify is never a problem: the ledger has no dependency on it.
  const gfy = await findInPath('graphify', deps.searchPath ?? process.env.PATH);
  lines.push(gfy === null ? 'graphify: not found (optional)' : `graphify: found (${gfy})`);

  /* ---- hub.log ---- */
  // A running hub reports `startedAt`: only its own lines matter then. A hub
  // that is down has none, and the previous run's last errors are the clue.
  const errs = await logErrors(cfg.ledgerDir, 3, diag?.startedAt ?? null);
  // Budget: the verdict line plus what is already queued. The log is the only
  // variable-length section, so it absorbs the cap.
  const room = Math.max(0, MAX_LINES - 1 - lines.length);
  for (const line of errs.slice(0, room)) lines.push(`log: ${line}`);

  for (const line of lines) io.out(line);
  if (problems.length === 0) {
    io.out('OK');
    return 0;
  }
  io.out(`DOWN: ${problems.slice(0, 3).join('; ')} → ${suggestion}`);
  return 1;
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
): Promise<{ ms: number | null; diag: HubDiag | null }> {
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
    try {
      const body = JSON.parse(text) as { diag?: HubDiag };
      // Optional by contract: an older hub simply has no `diag`.
      if (body.diag !== null && typeof body.diag === 'object') diag = body.diag ?? null;
    } catch {
      diag = null;
    }
    return { ms, diag };
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
