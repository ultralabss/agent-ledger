/**
 * `ledger hook <event>` — the whole hook transport (Claude Code adapter protocol),
 * deliberately self-contained.
 *
 * This module imports nothing from the rest of the CLI. That is a latency
 * decision, not style: the agent host spawns a fresh `node` for every tool call,
 * and Node's type stripping costs real milliseconds per module in the graph.
 * Loading `index.ts` (arg parser + hub client + all command handlers) measured
 * ~6 ms more per hook than this file alone, on every Edit, Write and Bash.
 *
 * Contract (SPEC §10.1): exit 0 always, print nothing on any failure. The hub
 * being down, slow, unauthenticated or wrong must be indistinguishable from
 * "no hook configured".
 *
 * S2 note: the URL is built from `LEDGER_HUB_PORT` only — `LEDGER_HUB_URL` is
 * ignored here on purpose, so there is no env var that can aim a hook (and its
 * bearer token) at a non-loopback host.
 */

import { appendFile, readFile, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { isReadOnlyBash } from './hook-bash.ts';
import { inboxState, type InboxState } from './hook-inbox.ts';

const TIMEOUT_MS = 1_000;
/** `session-start` is not on the hot path — it happens once per session
 *  and its output is the briefing, so it can afford to wait, self-heal and
 *  retry rather than print `AGENT-LEDGER DOWN` after one 1 s miss. Tool hooks keep
 *  the 1 s single attempt untouched. */
const SESSION_TIMEOUT_MS = 2_500;
/** Hard ceiling for the whole session-start exchange (attempt + heal + retry). */
const SESSION_TOTAL_MS = 8_000;
const HEALTH_POLL_MS = 250;
const HEALTH_TIMEOUT_MS = 500;
/** How long we are willing to wait for the service manager to get the hub listening. */
const HEAL_WAIT_MS = 4_000;
/** Kept literal here rather than imported: this module deliberately imports
 *  nothing from the rest of the CLI (see the header — it is a latency budget). */
const HUB_DOWN_TEXT =
  'AGENT-LEDGER DOWN: ledger writes are queued and sent automatically. ' +
  'To get a notice once the hub is back, run in the background: ledger wait';
const MAX_STDIN = 1024 * 1024;
const EVENT_RE = /^[a-z][a-z-]{1,40}$/;
const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);
/** Walk-up bound — a repo root is never 40 levels above the file. */
const MAX_WALK = 40;

export interface HookIo {
  out: (line: string) => void;
  env: NodeJS.ProcessEnv;
  /** Test seam; production reads `process.stdin`. */
  stdin?: (() => Promise<string>) | undefined;
}

/** `'` → `'\''`, whole value single-quoted: safe for `export X=<value>`. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function ledgerDir(env: NodeJS.ProcessEnv): string {
  const raw = env.LEDGER_DIR?.trim();
  if (!raw || raw === '') return join(homedir(), '.ledger');
  if (raw === '~') return homedir();
  if (raw.startsWith('~/')) return join(homedir(), raw.slice(2));
  return raw;
}

function port(env: NodeJS.ProcessEnv): string {
  const raw = env.LEDGER_HUB_PORT?.trim();
  return raw && /^\d{1,5}$/.test(raw) ? raw : '4747';
}

async function readStdin(io: HookIo): Promise<string | null> {
  try {
    if (io.stdin) {
      const text = await io.stdin();
      return text.trim() === '' ? null : text.slice(0, MAX_STDIN);
    }
    if (process.stdin.isTTY) return null;
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      const buf = Buffer.from(chunk);
      size += buf.length;
      if (size > MAX_STDIN) return null;
      chunks.push(buf);
    }
    const text = Buffer.concat(chunks).toString('utf8');
    return text.trim() === '' ? null : text;
  } catch {
    return null;
  }
}

/** Append `export LEDGER_SESSION=…` / `LEDGER_REPO=…` to `$CLAUDE_ENV_FILE`.
 *  Claude Code sources that file before every Bash command of the session. */
async function writeEnvFile(
  env: NodeJS.ProcessEnv,
  session: string,
  repo: string | null,
): Promise<void> {
  const file = env.CLAUDE_ENV_FILE?.trim();
  if (!file) return;
  try {
    const lines = [`export LEDGER_SESSION=${shellQuote(session)}`];
    if (repo) lines.push(`export LEDGER_REPO=${shellQuote(repo)}`);
    await appendFile(file, `${lines.join('\n')}\n`, 'utf8');
  } catch {
    // Not fatal: the CLI falls back to `--repo` / cwd detection.
  }
}

/**
 * What PostToolUse should do with this tool call.
 *
 *   'skip'   nothing to tell the hub and nothing to hear: no request at all
 *   'nowait' send it, exit as soon as the body is flushed (no answer wanted)
 *   'sync'   today's behaviour — wait for the response and print it
 *
 * The decision is ordered so the cheap, certain cases win: a pending inbox
 * marker forces 'sync' before anything else, because a message the user is
 * waiting for outranks every millisecond saved here.
 */
async function postToolPlan(
  io: HookIo,
  parsed: Record<string, unknown> | null,
): Promise<'skip' | 'nowait' | 'sync'> {
  if (parsed === null) return 'sync';
  const tool = typeof parsed.tool_name === 'string' ? parsed.tool_name : '';
  const isBash = tool === 'Bash';
  // Any other tool keeps the old path: this change is scoped to the two that
  // dominate the call count and the two the hub actually does work for.
  if (!isBash && !EDIT_TOOLS.has(tool)) return 'sync';

  let state: InboxState = 'unknown';
  try {
    state = await inboxState(ledgerDir(io.env), parsed.session_id);
  } catch {
    state = 'unknown';
  }
  if (state === 'pending') return 'sync';

  if (isBash) {
    const input = parsed.tool_input as { command?: unknown } | undefined;
    // A provably read-only command leaves nothing for `attributeBash` to find,
    // so this is skippable even against an old hub ('unknown'): the worst case
    // is an inbox message arriving one tool call later, never a lost one.
    if (isReadOnlyBash(input?.command)) return 'skip';
  }
  // 'unknown' = hub without the marker directory → stay synchronous, otherwise
  // its PostToolUse output would be dropped on the floor.
  return state === 'empty' ? 'nowait' : 'sync';
}

/**
 * "Nothing is listening on the port" vs "the port answered too late".
 *
 * The difference decides everything downstream: a refused connection means the
 * request was never delivered (safe to self-heal and retry), a timeout means it
 * may have landed. `fetch` wraps the cause, sometimes twice and sometimes in an
 * `AggregateError` (happy-eyeballs over 127.0.0.1 + ::1), so the chain is
 * walked instead of matching a message.
 */
export function isRefused(err: unknown, depth = 0): boolean {
  if (err === null || typeof err !== 'object' || depth > 4) return false;
  const o = err as { code?: unknown; errors?: unknown; cause?: unknown };
  if (o.code === 'ECONNREFUSED') return true;
  if (Array.isArray(o.errors) && o.errors.some((e) => isRefused(e, depth + 1))) return true;
  return isRefused(o.cause, depth + 1);
}

export function isTimeout(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false;
  const name = (err as { name?: unknown }).name;
  return name === 'TimeoutError' || name === 'AbortError';
}

function postHook(
  portStr: string,
  event: string,
  token: string,
  payload: string,
  timeoutMs: number,
): Promise<Response> {
  return fetch(`http://127.0.0.1:${portStr}/v1/hooks/${event}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-hub-token': token },
    body: payload,
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
  });
}

/** Fire-and-forget. Deliberately not awaited anywhere: the import, the marker
 *  write and the `launchctl` spawn must never be on a hook's critical path. */
function fireSelfHeal(io: HookIo, mode: 'fast' | 'checked'): Promise<unknown> {
  return import('./selfheal.ts')
    .then(({ triggerSelfHeal }) =>
      triggerSelfHeal({ ledgerDir: ledgerDir(io.env), port: port(io.env), env: io.env, mode }),
    )
    .catch(() => undefined);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => {
    setTimeout(r, ms).unref?.();
  });
}

async function healthzUp(portStr: string): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${portStr}/v1/healthz`, {
      redirect: 'manual',
      signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * One session-start exchange, worth up to `SESSION_TOTAL_MS`.
 *
 *   refused → self-heal, poll `/v1/healthz`, retry once
 *   timeout → retry once, no heal (something IS listening)
 *
 * Retrying after a timeout is safe because the hub's handler converges on
 * `session_id`: `sessions.start()` goes through `store.upsertSession`, which
 * `UPDATE`s an existing row (PK = session id) and journals only on create or
 * revive (`packages/hub/src/db/store.ts`, `packages/hub/src/sessions.ts`). A
 * second delivery re-bumps `last_seen` and rebuilds the briefing; it cannot
 * create a duplicate session or a duplicate journal entry.
 */
async function sessionStartSend(
  io: HookIo,
  portStr: string,
  token: string,
  payload: string,
): Promise<Response> {
  const t0 = Date.now();
  try {
    return await postHook(portStr, 'session-start', token, payload, SESSION_TIMEOUT_MS);
  } catch (err) {
    if (isRefused(err)) {
      await fireSelfHeal(io, 'checked');
      const until = Math.min(
        t0 + SESSION_TIMEOUT_MS + HEAL_WAIT_MS,
        t0 + SESSION_TOTAL_MS - SESSION_TIMEOUT_MS,
      );
      while (Date.now() < until) {
        if (await healthzUp(portStr)) break;
        await sleep(HEALTH_POLL_MS);
      }
    } else if (!isTimeout(err)) {
      throw err;
    }
    const left = SESSION_TOTAL_MS - (Date.now() - t0);
    if (left < 300) throw err;
    return await postHook(
      portStr,
      'session-start',
      token,
      payload,
      Math.min(SESSION_TIMEOUT_MS, left),
    );
  }
}

/** Always resolves to 0. */
export async function runHook(event: string, io: HookIo): Promise<number> {
  let payload: string | null = null;
  const ev = event.trim();
  try {
    if (!EVENT_RE.test(ev)) return 0;
    // SPEC §10 rule 11: a headless run (the hub's own agent subprocess) must not
    // recurse into the hub through its own hooks.
    if (io.env.LEDGER_HUB_HEADLESS === '1') return 0;

    payload = await readStdin(io);
    if (payload === null) return 0;
    // Parsed once, and only when something actually needs the fields: a Write
    // payload carries the whole file contents, so `JSON.parse` is not free on
    // events that would throw the result away.
    let parsed: Record<string, unknown> | null = null;
    if (io.env.LEDGER_WORKER === '1' || ev === 'post-tool-use') {
      try {
        const value = JSON.parse(payload) as unknown;
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
          parsed = value as Record<string, unknown>;
        }
      } catch {
        /* not JSON — forwarded as-is below */
      }
    }
    // Mark a reply worker's own tool calls so the hub can apply the
    // stricter worker guard. `LEDGER_WORKER=1` is set by `replies.ts`'s
    // `childEnv`, never by the interactive CLI or the agent host itself.
    if (io.env.LEDGER_WORKER === '1' && parsed !== null) {
      parsed.worker = true;
      payload = JSON.stringify(parsed);
    }

    // Decide before touching the token file — a skipped command must
    // not even read from disk beyond the marker lookup.
    const plan = ev === 'post-tool-use' ? await postToolPlan(io, parsed) : 'sync';
    if (plan === 'skip') return 0;

    const token = await readFile(join(ledgerDir(io.env), '.hub', 'token'), 'utf8')
      .then((t) => t.trim())
      .catch(() => '');
    if (token === '') throw new Error('no token');

    if (plan === 'nowait') {
      // No response is read, which is sound only because PostToolUse never
      // carries `x-ledger-session` (the hub sets the env headers on session-start
      // only) and the marker said there is no text to print.
      const { sendNoWait } = await import('./hook-send.ts');
      await sendNoWait({
        port: port(io.env),
        event: ev,
        token,
        body: payload,
        timeoutMs: TIMEOUT_MS,
      });
      return 0;
    }

    let res: Response;
    if (ev === 'session-start') {
      res = await sessionStartSend(io, port(io.env), token, payload);
    } else {
      try {
        res = await postHook(port(io.env), ev, token, payload, TIMEOUT_MS);
      } catch (err) {
        // A refused connection on a tool hook is the one signal that is
        // both cheap and unambiguous — nothing is listening. Kick the service manager and
        // keep going; this hook stays silent either way (§10.1). A *timeout* is
        // explicitly not a trigger: a slow hub must not be restarted under load.
        if (isRefused(err)) void fireSelfHeal(io, 'fast');
        throw err;
      }
    }
    if (!res.ok) {
      // UL-650: 422 on a PreToolUse = the hub refused to scan/process the
      // payload (secret-like value). That is not "hub down": deny, don't skip the guard.
      if (ev === 'pre-tool-use' && res.status === 422) {
        io.out(
          JSON.stringify({
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'deny',
              permissionDecisionReason:
                'Hook payload was rejected by the hub (secret-like value in a path/cwd/session field); the edit guard cannot verify it.',
            },
          }),
        );
      }
      return 0;
    }

    const session = res.headers.get('x-ledger-session');
    if (session) await writeEnvFile(io.env, session, res.headers.get('x-ledger-repo'));

    const text = await res.text();
    if (text.trim() !== '') io.out(text.replace(/\n$/, ''));
    return 0;
  } catch (err) {
    // Timeout, ECONNREFUSED, unreadable token — the hub is not answering.
    // Fail-open everywhere EXCEPT §10.3 rule 5c: an edit that lands in a
    // different git repo than the session's cwd cannot be checked, and the spec
    // says that one case denies rather than guesses.
    const reason = isRefused(err) ? 'hub not running' : isTimeout(err) ? 'hub not answering' : '';
    return hubDownFallback(ev, payload, io, reason);
  }
}

/**
 * Rule 5c without a hub. Determined from the filesystem only — no `git`
 * process, because this runs on every tool call and because spawning git in a
 * directory handed to us by a hook reads that repo's config (S6/S10).
 */
async function hubDownFallback(
  event: string,
  payload: string | null,
  io: HookIo,
  reason = '',
): Promise<number> {
  // `session-start` is the one hook that SAYS the hub is down. Every
  // other hook stays silent (fail-open) — a warning on every tool call would be
  // unreadable — but a session that starts during a hub restart has to know its
  // writes are being queued, otherwise it treats `QUEUED` as an error later.
  if (event === 'session-start') {
    // The `AGENT-LEDGER DOWN:` prefix and the existing sentence stay byte-identical
    // (agent instructions and other tooling match on them); we only append which of
    // the two it was, because the fix differs: `not running` = start it,
    // `not answering` = something is wedged, look at `ledger doctor`.
    io.out(reason === '' ? HUB_DOWN_TEXT : `${HUB_DOWN_TEXT} (${reason})`);
    return 0;
  }
  if (event !== 'pre-tool-use' || payload === null) return 0;
  if (io.env.LEDGER_HUB_GUARD?.trim().toLowerCase() === 'off') return 0;
  try {
    const parsed = JSON.parse(payload) as {
      tool_name?: unknown;
      cwd?: unknown;
      tool_input?: { file_path?: unknown; notebook_path?: unknown };
    };
    const tool = typeof parsed.tool_name === 'string' ? parsed.tool_name : '';
    if (!EDIT_TOOLS.has(tool)) return 0;
    const cwd = typeof parsed.cwd === 'string' ? parsed.cwd : null;
    if (cwd === null) return 0;
    const file =
      typeof parsed.tool_input?.file_path === 'string'
        ? parsed.tool_input.file_path
        : typeof parsed.tool_input?.notebook_path === 'string'
          ? parsed.tool_input.notebook_path
          : null;
    if (file === null || !file.startsWith('/')) return 0;

    const here = await toplevelOf(cwd);
    const there = await toplevelOf(file);
    // Unknown on either side, or the same repo → fail-open (the vast majority).
    if (here === null || there === null || here === there) return 0;

    io.out(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason:
            `Hub is not running, so an edit in another repo cannot be verified (${there} ≠ ${here}). ` +
            'Start the hub (`ledger doctor --fix`) ' +
            'and then run `ledger who <repo>`, or ask the user. ' +
            'To disable guards: `LEDGER_HUB_GUARD=off`.',
        },
      }),
    );
    return 0;
  } catch {
    return 0;
  }
}

/** Nearest ancestor directory containing a `.git` entry, realpath'd. */
async function toplevelOf(p: string): Promise<string | null> {
  let current: string;
  try {
    current = await realpath(p);
  } catch {
    try {
      current = join(await realpath(dirname(p)), '');
    } catch {
      return null;
    }
  }
  const st = await stat(current).catch(() => null);
  if (st !== null && !st.isDirectory()) current = dirname(current);
  for (let i = 0; i < MAX_WALK; i += 1) {
    if (await exists(join(current, '.git'))) return current;
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
  return null;
}

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}
