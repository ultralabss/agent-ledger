import { homedir } from 'node:os';
import { isAbsolute, resolve } from 'node:path';

export interface HubConfig {
  /** Absolute path to the ledger git repo. */
  ledgerDir: string;
  port: number;
  /** `LEDGER_PUSH=1` enables the throttled push to `origin`. Default OFF: the ledger never leaves the machine unless you ask. */
  push: boolean;
  /** Debounce before `git commit` (ms). */
  commitDebounceMs: number;
  /** Minimum gap between pushes (ms). */
  pushIntervalMs: number;
  /** Static UI root. `undefined` → `packages/web/dist` next to this package. */
  uiDir?: string | undefined;
  /** Periodic full reindex as a backstop for a missed `fs.watch` event (ms). */
  reindexIntervalMs: number;
  /** Periodic dead-session reap + git refresh (ms). */
  sweepIntervalMs: number;

  /* ---------------- F2 ---------------- */
  /** `LEDGER_HUB_GUARD=off` pins every guard to allow until restart (SPEC §10.4). */
  guardEnv: 'on' | 'off' | null;
  /**
   * PostToolUse output shape. `additionalContext` is the documented envelope;
   * `block` is the fallback for a Claude Code build that ignores it. The
   * orchestrator flips this after verifying on a real session.
   */
  postToolMode: 'additionalContext' | 'block';
  /**
   * Ignore `/tmp`, `/private/var/folders` and scratchpads for auto-registration
   * and `touched` (SPEC §10.11). Off in tests, whose repos live in `tmpdir()`.
   */
  excludeTemp: boolean;
  /** Roots a `transcript_path` may resolve into (Stop recap check, SPEC §10.2). */
  transcriptRoots: string[];
  /** Where `ledger-keeper.md` lives (copy it from `examples/agents/`). Unset → headless runs are unavailable. */
  agentsDir: string | null;

  /* ---------------- Optional features (all OFF by default) ---------------- */
  /** `LEDGER_INTRUDE=1` enables the cross-repo `intrude` lease protocol (SPEC §11). */
  intrude: boolean;
  /** `LEDGER_RECAP_GUARD=1` enables the Stop-hook recap check (SPEC §10.2). */
  recapGuard: boolean;
  /** `LEDGER_RECAP_TAGS` (comma list). Tags that must carry an item id on the same recap line. */
  recapTags: string[];
  /** `LEDGER_WEB_REPLIES=1` enables replies from the web UI routed back to agents (SPEC §8). */
  webReplies: boolean;
  /** `LEDGER_HEADLESS=1` allows the hub to spawn an agent CLI headlessly (triage, grooming, reply workers). */
  headless: boolean;

  /* ---------------- F3 ---------------- */
  /** Absolute path to the `claude` binary. Unset → headless triage is 503. */
  claudeBin: string | null;
  /** `LEDGER_TRUST_CLAUDE_GROUP=1`, written only by
   *  `install.sh --trust-claude-group`. Conscious acceptance that the
   *  claude binary lives in a group-writable directory (e.g. Homebrew's). */
  trustClaudeGroup: boolean;
  /** gid of the group-writable directory `install.sh
   *  --trust-claude-group` actually saw. The opt-in applies to this group and
   *  no other; `null` = no pin recorded → opt-in not honoured. */
  trustClaudeGid: number | null;
  /** realpath of the binary the installer saw. The opt-in
   *  applies to this path and no other. */
  trustClaudeRealpath: string | null;
  /** `LEDGER_GROOM_WEEKLY=1` arms the Monday 09:00 local grooming timer. */
  groomWeekly: boolean;
  /** Hard cap on one headless run (ms). */
  headlessTimeoutMs: number;
}

export function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return resolve(homedir(), p.slice(2));
  return isAbsolute(p) ? p : resolve(p);
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/** A non-finite or out-of-range env value silently falls back to
 *  `fallback` instead of producing `NaN`/an absurd interval (e.g. a
 *  multi-day debounce that never commits, or a sub-second push loop). */
function clampedMs(raw: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

/** A gid is a non-negative integer or nothing. No coercion of junk —
 *  an unparseable value means "no pin", which disables the opt-in. */
function gidOrNull(raw: string | undefined): number | null {
  const text = raw?.trim() ?? '';
  if (!/^[0-9]{1,10}$/.test(text)) return null;
  const n = Number(text);
  return Number.isSafeInteger(n) ? n : null;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): HubConfig {
  const rawPort = env.LEDGER_HUB_PORT?.trim();
  const port = rawPort && rawPort !== '' ? Number(rawPort) : 4747;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`LEDGER_HUB_PORT must be an integer 0–65535, got "${rawPort}"`);
  }
  return {
    ledgerDir: expandHome(env.LEDGER_DIR?.trim() || '~/.ledger'),
    port,
    push: env.LEDGER_PUSH?.trim() === '1',
    commitDebounceMs: clampedMs(env.LEDGER_COMMIT_DEBOUNCE_MS, 30_000, 0, 10 * MINUTE),
    pushIntervalMs: clampedMs(env.LEDGER_PUSH_INTERVAL_MS, 600_000, MINUTE, 24 * HOUR),
    uiDir: env.LEDGER_UI_DIR?.trim() ? expandHome(env.LEDGER_UI_DIR.trim()) : undefined,
    // `fs.watch` drops events (network volumes, editors that
    // replace a whole directory, macOS FSEvents coalescing). A full reindex is
    // cheap for a ledger this size, so run one every minute as a backstop —
    // the watcher stays the fast path.
    reindexIntervalMs: clampedMs(env.LEDGER_REINDEX_INTERVAL_MS, 60_000, 1_000, HOUR),
    sweepIntervalMs: clampedMs(env.LEDGER_SWEEP_INTERVAL_MS, 60_000, 1_000, HOUR),
    guardEnv: guardEnv(env.LEDGER_HUB_GUARD),
    postToolMode: env.LEDGER_HUB_POST_TOOL_MODE?.trim() === 'block' ? 'block' : 'additionalContext',
    excludeTemp: (env.LEDGER_HUB_EXCLUDE_TEMP?.trim() ?? '1') !== '0',
    transcriptRoots: transcriptRoots(env),
    agentsDir: env.LEDGER_AGENTS_DIR?.trim() ? expandHome(env.LEDGER_AGENTS_DIR.trim()) : null,
    intrude: env.LEDGER_INTRUDE?.trim() === '1',
    recapGuard: env.LEDGER_RECAP_GUARD?.trim() === '1',
    recapTags: recapTags(env.LEDGER_RECAP_TAGS),
    webReplies: env.LEDGER_WEB_REPLIES?.trim() === '1',
    headless: env.LEDGER_HEADLESS?.trim() === '1',
    // Absolute only: a bare name would be resolved through PATH, and this value
    // is spawned as a program. An empty/relative value behaves as "not set".
    claudeBin: absoluteOrNull(env.LEDGER_CLAUDE_BIN),
    trustClaudeGroup: env.LEDGER_TRUST_CLAUDE_GROUP?.trim() === '1',
    trustClaudeGid: gidOrNull(env.LEDGER_TRUST_CLAUDE_GID),
    // Absolute only, same reason as `claudeBin`: this value is compared
    // against a realpath, so a relative one could never match anything real.
    trustClaudeRealpath: absoluteOrNull(env.LEDGER_TRUST_CLAUDE_REALPATH),
    groomWeekly: env.LEDGER_GROOM_WEEKLY?.trim() === '1',
    headlessTimeoutMs: clampedMs(env.LEDGER_HEADLESS_TIMEOUT_MS, 5 * MINUTE, 1_000, 30 * MINUTE),
  };
}

function guardEnv(raw: string | undefined): 'on' | 'off' | null {
  const value = raw?.trim().toLowerCase();
  if (value === 'off' || value === '0' || value === 'false') return 'off';
  if (value === 'on' || value === '1' || value === 'true') return 'on';
  return null;
}

function absoluteOrNull(raw: string | undefined): string | null {
  const value = raw?.trim();
  if (!value || value === '') return null;
  const expanded = value.startsWith('~') ? expandHome(value) : value;
  return isAbsolute(expanded) ? expanded : null;
}

/** Claude Code adapter: `~/.claude/projects` (read-only; only used by the optional recap guard), plus `LEDGER_TRANSCRIPTS_DIR` for tests. */
function transcriptRoots(env: NodeJS.ProcessEnv): string[] {
  const roots = [resolve(homedir(), '.claude', 'projects')];
  const extra = env.LEDGER_TRANSCRIPTS_DIR?.trim();
  if (extra && extra !== '') roots.push(expandHome(extra));
  return roots;
}

const DEFAULT_RECAP_TAGS = ['BLOCKER', 'DEPLOY', 'RISK', 'UNVERIFIED'];

/** Tags are upper-case words; anything else in the list is dropped. */
function recapTags(raw: string | undefined): string[] {
  const tags = (raw ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter((t) => /^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(t));
  return tags.length > 0 ? tags : DEFAULT_RECAP_TAGS;
}
