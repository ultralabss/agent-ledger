/** `ledger` — thin client over the hub (SPEC §7).
 *
 *  Output is one line per record and never coloured, so hooks and agents can
 *  paste it straight into a recap.
 */

import { spawn } from 'node:child_process';
import { DONE_REF_HINT, isDoneRef, isItemId, TITLE_MAX, TITLE_WARN } from '@agent-ledger/shared';
import { bool, csv, flag, flagList, parseArgs, type Args } from './args.ts';
import { CliError, HubClient, readEnvConfig, type CliEnvConfig, type HubTimeouts } from './client.ts';
import { hubServesLedger } from './identity.ts';
import { OFFLINE_HEADER, offlineBrief, offlineLs, offlineShow } from './offline.ts';
import {
  SpoolError,
  enqueue,
  generateIdempotencyKey,
  isWriteMethod,
  queuedMessage,
  readFailedSpool,
  replaySpool,
  retryFailedSpool,
  spoolStats,
  type SpoolRecord,
} from '@agent-ledger/shared';

export interface Io {
  out: (line: string) => void;
  err: (line: string) => void;
  env: NodeJS.ProcessEnv;
  cwd: string;
  stdin?: () => Promise<string>;
  /** Whether stdin / stdout are terminals. Absent = not a TTY (tests, pipes). */
  tty?: { stdin: boolean; stdout: boolean };
  /** Interactive prompt (tests inject one; a real TTY gets readline). */
  ask?: (prompt: string) => Promise<string | null>;
}

const USAGE = `ledger — shared ledger and intake for parallel AI agent sessions

  ledger status                             hub status
  ledger brief [repo] [--full]              briefing (§9)
  ledger repo add <slug> --path <p> [--prefix XX] [--graphify <p>] [--docs a,b]
  ledger repo add <slug> --kind system|vps [--host <h>] [--prefix XX]   (no --path, no git)
  ledger repo bind <slug> <path>            point an existing repo at a checkout on THIS machine (verifies the root commit)
  ledger repo ls
  ledger intake "<text>" | - [--action triage|send_to_session|triage_and_run] [--to <session>]
                                          verbatim text into the intake bin
  ledger intake ls [--new]
  ledger intake show <id>
  ledger intake triage <id> --items A,B [--drop "text::reason"] [--status triaged|partial]
  ledger add "<title>" --repo <slug> --kind <K> --priority <P> [--owner <o>] [--area <a>]
           [--why <t>|-] [--rec <t>|-] [--step "<step>"]… [--intake <id>]
           [--requested-by <ID>] [--blocked-by A,B] [--proposed]
  ledger ls [--repo] [--status] [--owner] [--kind] [--priority] [--open]
  ledger show <ID> [--origin]               item; --origin adds session, intake, first commit, top files
  ledger tidy [--repo <slug>] [--json] [--limit N] [--bucket looks-done|abandoned|unknown|review|fresh]
                                          stale items with evidence; read-only (on a TTY: confirm each action)
  ledger claim <ID> [--paths "a/**,b/**"] [--intent "<what I change>"]
  ledger step <ID> <n> done|undo
  ledger note <ID> "<text>"
  ledger release <ID> [--why]   ·  ledger done <ID> [--ref]  ·  ledger drop <ID> --why
  ledger dup <ID> --into <ID>   ·  ledger block <ID> --by <ID>|--on human
  ledger reopen <ID> --why "<why>"
  ledger decide --repo <slug> "<title>" --why "<text>"
  ledger log --repo <slug> "<summary>"
  ledger history [--repo] [--since 7d] [--type <t>]
  ledger who <repo>                         who works there, files, checkout state
  ledger whose <path>                       owner of an uncommitted file
  ledger why <path|dir|glob> [--repo <slug>] [--json]
                                          who touched it and why (items, claims, decisions, git)
  ledger search "<q>" [--repo] [--limit]    full text
  ledger sessions [--repo] [--live]         live sessions
  ledger open [/path] [--print]             sign in to the web UI (one-time code)
  ledger onboard [--path <p>]               repo facts for onboarding
  ledger repo onboarded <slug>              the repo's ledger is ready
  ledger repo contract <slug> [--add <glob>] [--consumer <slug>] [--rm <glob>]
                                          contract paths and consumers
  ledger guard on|off|status                kill switch for guards (§10.3–10.4)
  ledger intrude begin --repo <r> [--item <ID>] --paths "a,b" [--intent] [--force]
  ledger intrude commit <sha> [--lease <id>] · ledger intrude end [--lease <id>]
                                          (optional: hub needs LEDGER_INTRUDE=1)
  ledger inbox [--all]                      unread messages
  ledger adopt <path|ID>                    take over an orphan
  ledger override <path> --reason "<why>"   deliberately override a lock
  ledger release-notes --repo <r> [--from <tag>] [--to <tag|HEAD>]
  ledger edit <ID> [--title] [--kind] [--priority] [--owner] [--area] [--force]
  ledger dups --repo <r> [--threshold 0.65] likely duplicates (grooming)
  ledger check "<text>" [--repo]            do we have this already? (writes nothing)
  ledger reply <ID> "<text>" [--mode auto|session|worker]
  ledger wait [--timeout 600]               wait for the hub to come up and flush the queue
  ledger doctor [--fix] [--json] [--online] hub diagnostics (service, healthz, identity, ledger remote)
  ledger device init|list|approve|revoke    this machine's device key and the device registry (local, no hub needed)
                                          init [--label <x>] [--root] · approve <id> · revoke <id> --reason "<why>"
  ledger spool failed                       failed spool records (method, path, time, body)
  ledger spool retry <file> --confirm       re-sign and resend the records of one failed file
  ledger hook <event>                       hook transport (Claude Code adapter protocol, §10)
  ledger setup --platform-init [--ledger-dir <abs>] [--port <n>]
                                          installer helper (install.ps1): private dirs, hub.env, shims; prints JSON

Exit: 0 ok · 2 conflict · 3 hub not running · 4 validation · 5 secret scanner
       (ledger hook always 0 — fail-open)
`;

export async function run(argv: string[], io: Io): Promise<number> {
  const args = parseArgs(argv);
  const cmd = args.positional[0];
  if (!cmd || bool(args, 'help') || cmd === 'help') {
    io.out(USAGE.trimEnd());
    return 0;
  }
  // `ledger hook` is on the hot path of every tool call and must NEVER surface an
  // error to the agent: a broken hub would otherwise flood the transcript or
  // (with a non-zero exit on PreToolUse) block the user's work. It does its own
  // transport, its own timeout, and always exits 0 (SPEC §10.1 fail-open).
  if (cmd === 'hook') {
    const { runHook } = await import('./hook.ts');
    return runHook(args.positional[1] ?? '', { out: io.out, env: io.env, stdin: io.stdin });
  }
  // `ledger setup` is the installer's node half: it runs before any hub exists, so it must not build
  // the hub client or drain the spool.
  if (cmd === 'setup') {
    const { cmdSetup } = await import('./setup.ts');
    return cmdSetup(args, io);
  }
  // `ledger device` is local file + ssh-keygen work (multi-device F2): no hub client, no spool drain.
  if (cmd === 'device') {
    const { cmdDevice } = await import('./device.ts');
    return cmdDevice(args, io);
  }
  // `cfg` is needed by the offline fallback in `catch`, but `readEnvConfig`
  // itself throws on a bad `LEDGER_HUB_URL` (S2) and that must stay a plain exit 4
  // — so it is read inside the try and captured for the handler.
  let cfg: CliEnvConfig | null = null;
  try {
    cfg = readEnvConfig(io.env);
    const client = new SpoolingClient(cfg, [cmd, ...args.positional.slice(1)].join(' '), io.env);
    // Every command drains the spool first. Cheap when it is empty (one
    // readdir) and it means the queue clears itself the moment the hub is back,
    // without a daemon or a timer.
    //
    // `wait` is excluded: it exists to report what it flushed, and a pre-drain
    // here would send the records and leave `wait` reporting zero. `doctor` is
    // excluded because it is a diagnosis: it must not change the queue it
    // reports on.
    if (cmd !== 'wait' && cmd !== 'doctor') await drainSpool(client, cfg, io, false);
    return await dispatch(cmd, args, client, cfg, io);
  } catch (err) {
    if (err instanceof QueuedWrite) {
      io.out(queuedMessage(err.record));
      return 0;
    }
    if (err instanceof SpoolError) {
      io.err(`ledger: ${err.message}`);
      return err.exitCode;
    }
    if (err instanceof CliError) {
      if (err.hubDown && cfg !== null) {
        const handled = await offlineFallback(cmd, args, cfg, io);
        if (handled !== null) return handled;
      }
      io.err(`ledger: ${err.message}`);
      return err.exitCode;
    }
    io.err(`ledger: ${err instanceof Error ? err.message : String(err)}`);
    return 4;
  }
}

async function dispatch(
  cmd: string,
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  switch (cmd) {
    case 'status':
      return cmdStatus(client, cfg, io, io.env);
    case 'brief':
      return cmdBrief(args, client, cfg, io);
    case 'repo':
      return cmdRepo(args, client, cfg, io);
    case 'intake':
      return cmdIntake(args, client, cfg, io);
    case 'add':
      return cmdAdd(args, client, cfg, io);
    case 'ls':
      return cmdLs(args, client, cfg, io);
    case 'show':
      return cmdShow(args, client, io);
    case 'claim':
      return cmdClaim(args, client, cfg, io);
    case 'step':
      return cmdStep(args, client, cfg, io);
    case 'note':
      return cmdNote(args, client, cfg, io);
    case 'release':
      return cmdSimple(args, client, cfg, io, 'release');
    case 'done':
      return cmdDone(args, client, cfg, io);
    case 'drop':
      return cmdDrop(args, client, cfg, io);
    case 'dup':
      return cmdDup(args, client, cfg, io);
    case 'block':
      return cmdBlock(args, client, cfg, io);
    case 'reopen':
      return cmdReopen(args, client, cfg, io);
    case 'decide':
      return cmdDecide(args, client, cfg, io);
    case 'log':
      return cmdLog(args, client, cfg, io);
    case 'history':
      return cmdHistory(args, client, cfg, io);
    case 'who':
      return cmdWho(args, client, cfg, io);
    case 'whose':
      return cmdWhose(args, client, io);
    case 'why':
      return cmdWhy(args, client, cfg, io);
    case 'tidy':
      return cmdTidy(args, client, cfg, io);
    case 'search':
      return cmdSearch(args, client, cfg, io);
    case 'sessions':
      return cmdSessions(args, client, cfg, io);
    case 'open':
      return (await import('./open.ts')).cmdOpen(args, client, cfg, io);
    case 'onboard':
      return cmdOnboard(args, client, io);
    case 'guard':
      return cmdGuard(args, client, cfg, io);
    case 'intrude':
      return cmdIntrude(args, client, cfg, io);
    case 'inbox':
      return cmdInbox(args, client, cfg, io);
    case 'adopt':
      return cmdAdopt(args, client, cfg, io);
    case 'override':
      return cmdOverride(args, client, cfg, io);
    case 'release-notes':
      return cmdReleaseNotes(args, client, cfg, io);
    case 'edit':
      return cmdEdit(args, client, cfg, io);
    case 'dups':
      return cmdDups(args, client, io);
    case 'check':
      return cmdCheck(args, client, cfg, io);
    case 'reply':
      return cmdReply(args, client, io);
    case 'wait':
      return cmdWait(args, client, cfg, io);
    case 'doctor': {
      const { cmdDoctor } = await import('./doctor.ts');
      return cmdDoctor(args, cfg, io);
    }
    case 'spool':
      return cmdSpool(args, client, io);
    default:
      throw new CliError(4, `unknown command "${cmd}" — \`ledger help\``);
  }
}

/* ---------------- spool, offline, wait ---------------- */

/** Thrown instead of returning, so a queued write cannot be mistaken for a
 *  successful one anywhere up the call chain. */
class QueuedWrite extends Error {
  readonly record: SpoolRecord;

  constructor(record: SpoolRecord) {
    super('queued');
    this.name = 'QueuedWrite';
    this.record = record;
  }
}

/**
 * `HubClient` that queues a write when the hub is not answering.
 *
 * Subclassing rather than wrapping: `request`/`get`/`post`/`patch` all funnel
 * through `requestKeyed`, so one override covers every call site including ones
 * added later. A *keyed* request is a replay and is never re-queued — that would
 * be an infinite loop.
 */
export class SpoolingClient extends HubClient {
  private readonly spoolCfg: CliEnvConfig;
  private readonly cmdLabel: string;
  private readonly spoolEnv: NodeJS.ProcessEnv;

  constructor(
    cfg: CliEnvConfig,
    cmdLabel: string,
    env: NodeJS.ProcessEnv,
    /** Test seam only — production never passes this (see `HubTimeouts`). */
    timeouts: HubTimeouts = {},
  ) {
    super(cfg, timeouts);
    this.spoolCfg = cfg;
    this.cmdLabel = cmdLabel;
    this.spoolEnv = env;
  }

  override async requestKeyed(
    method: string,
    path: string,
    payload?: unknown,
    idempotencyKey?: string,
  ): ReturnType<HubClient['requestKeyed']> {
    // A replay call already carries its key (set by `replaySpool`).
    // A fresh direct write has none yet — mint it here, BEFORE the first
    // send, so that if the send times out (request may have reached the hub
    // and been written) the later spool/replay reuses the SAME key. The
    // hub's Idempotency-Key guard then recognises the replay as the same
    // write and returns the original response instead of writing it twice.
    const isReplay = idempotencyKey !== undefined;
    const key = idempotencyKey ?? (isWriteMethod(method) ? generateIdempotencyKey() : undefined);
    try {
      return await super.requestKeyed(method, path, payload, key);
    } catch (err) {
      const spoolable = err instanceof CliError && err.hubDown && isWriteMethod(method) && !isReplay;
      if (!spoolable) throw err;
      // A secret in the body throws CliError(5) from here and nothing is written.
      const record = await enqueue(
        this.spoolCfg,
        { method, path, body: payload ?? {}, cmd: this.cmdLabel },
        this.spoolEnv,
        await this.readToken(),
        key,
      );
      throw new QueuedWrite(record);
    }
  }

  /** Token for `replaySpool`'s HMAC re-check — public only for
   *  `drainSpool`, which is outside this class. */
  async tokenForReplay(): Promise<string | null> {
    return this.readToken();
  }
}

/** Replay the spool. `loud` prints a summary; the implicit pre-command drain is
 *  silent unless something actually moved. */
async function drainSpool(
  client: SpoolingClient,
  cfg: CliEnvConfig,
  io: Io,
  loud: boolean,
): Promise<{ sent: number; failed: number; offline: boolean }> {
  void cfg;
  const res = await replaySpool(client, io.env, () => client.tokenForReplay()).catch(() => ({
    sent: 0,
    failed: 0,
    offline: true,
  }));
  if (loud || res.sent > 0 || res.failed > 0) {
    if (res.sent > 0 || res.failed > 0) {
      io.err(`ledger: queue flushed — ${res.sent} ok, ${res.failed} failed`);
    }
  }
  return res;
}

/**
 * Hub down on a READ command: answer from md where that is honest, else `null`
 * so the caller reports exit 3.
 */
async function offlineFallback(
  cmd: string,
  args: Args,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number | null> {
  if (cmd === 'ls') {
    io.out(
      await offlineLs(cfg.ledgerDir, {
        repo: flag(args, 'repo'),
        status: flag(args, 'status'),
        owner: flag(args, 'owner'),
        kind: flag(args, 'kind'),
        priority: flag(args, 'priority'),
        open: bool(args, 'open'),
      }),
    );
    return 0;
  }
  if (cmd === 'show') {
    const id = requireArg(args.positional[1], 'item ID').toUpperCase();
    const text = await offlineShow(cfg.ledgerDir, id);
    if (text === null) {
      io.err(`ledger: ${OFFLINE_HEADER} item ${id} not found in the ledger`);
      return 4;
    }
    io.out(text);
    return 0;
  }
  if (cmd === 'brief') {
    io.out(await offlineBrief(cfg.ledgerDir, flag(args, 'repo') ?? args.positional[1]));
    return 0;
  }
  return null;
}

/**
 * `ledger wait` — block until the hub answers, then flush the spool.
 *
 * Built for `run_in_background` in a session: the agent keeps working, and when
 * the hub comes back this prints one summary line. Polls `/v1/healthz` because
 * that is the one route that answers without a token.
 */
async function cmdWait(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const timeoutS = Number(flag(args, 'timeout') ?? '600');
  if (!Number.isFinite(timeoutS) || timeoutS <= 0 || timeoutS > 86_400) {
    throw new CliError(4, '--timeout must be 1–86400 seconds');
  }
  const deadline = Date.now() + timeoutS * 1000;
  const spooling = client as SpoolingClient;
  // `ledger wait` is started precisely because the hub looks down, so the
  // first thing it does is try to bring it back — once, rate-limited, and
  // without ever killing a hub that is merely slow. Then it polls as before.
  await client.selfHeal(io.env).catch(() => undefined);
  for (;;) {
    const up = await client
      .get('/v1/healthz')
      .then(() => true)
      .catch((err: unknown) => !(err instanceof CliError && err.hubDown));
    if (up) {
      const res = await drainSpool(spooling, cfg, io, false);
      io.out(`hub up · sent ${res.sent} · failed ${res.failed}`);
      return 0;
    }
    if (Date.now() >= deadline) {
      const stats = await spoolStats(io.env);
      io.err(
        `ledger: hub did not come up within ${timeoutS} s — queued ${stats.queued}, failed ${stats.failed}`,
      );
      return 3;
    }
    await sleep(2000);
  }
}

/** Deliberately NOT unref'd: `ledger wait` exists to keep the process alive until
 *  the hub answers. An unref'd timer lets Node exit with the promise unsettled. */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => {
    setTimeout(r, ms);
  });
}

/**
 * Recovery after a token rotation. `ledger spool failed` lists what is
 * stuck (never resends anything); `ledger spool retry <file> --confirm`
 * re-signs and resends the records in exactly one of those files. No
 * `--confirm` → nothing happens, not even a read of the file.
 */
async function cmdSpool(args: Args, client: HubClient, io: Io): Promise<number> {
  const sub = args.positional[1];
  if (sub === 'failed') return cmdSpoolFailed(io);
  if (sub === 'retry') return cmdSpoolRetry(args, client as SpoolingClient, io);
  throw new CliError(4, 'ledger spool: `ledger spool failed` or `ledger spool retry <file> --confirm`');
}

async function cmdSpoolFailed(io: Io): Promise<number> {
  const files = await readFailedSpool(io.env);
  const nonEmpty = files.filter((f) => f.records.length > 0);
  if (nonEmpty.length === 0) {
    io.out('spool: no failed records');
    return 0;
  }
  for (const f of nonEmpty) {
    io.out(`${f.file}:`);
    for (const r of f.records) {
      const when = new Date(r.failed_at).toISOString();
      const body = truncate(JSON.stringify(r.body ?? {}), 200);
      io.out(`  ${r.method} ${r.path} · ${when} · ${r.reason} · ${body}`);
    }
  }
  io.out('ledger spool retry <file> --confirm re-signs and resends the records of one file');
  return 0;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

async function cmdSpoolRetry(args: Args, client: SpoolingClient, io: Io): Promise<number> {
  const file = args.positional[2];
  if (file === undefined || file === '') {
    throw new CliError(4, 'ledger spool retry <file> --confirm — exact name from `ledger spool failed`');
  }
  if (!bool(args, 'confirm')) {
    io.err(
      'ledger: spool retry without --confirm does nothing — check the records with `ledger spool failed`, then repeat with --confirm',
    );
    return 4;
  }
  const res = await retryFailedSpool(client, file, true, io.env, () => client.tokenForReplay());
  io.out(
    `spool retry ${file}: requeued ${res.requeued} · sent ${res.sent} · failed ${res.failed} · outside allowlist ${res.skipped}` +
      (res.offline ? ' · hub not running, the rest stays queued (ledger wait)' : ''),
  );
  return res.failed > 0 ? 2 : 0;
}

/* ---------------- edit / dups / check commands ---------------- */

/** `ledger edit <ID>` — PATCH the fields a human actually retypes. */
async function cmdEdit(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const id = itemId(args);
  const payload: Record<string, unknown> = { session: session(cfg) };
  const title = flag(args, 'title');
  if (title !== undefined) {
    warnLongTitle(title, io);
    payload['title'] = title;
  }
  for (const key of ['kind', 'priority', 'owner', 'area'] as const) {
    const value = flag(args, key);
    if (value !== undefined) payload[key] = value;
  }
  // Same escape hatch `ledger add --force` has for a fresh item — skip
  // the near-duplicate check when renaming into something that looks like
  // an existing title.
  if (bool(args, 'force')) payload['force'] = true;
  if (Object.keys(payload).filter((k) => k !== 'session' && k !== 'force').length === 0) {
    throw new CliError(4, 'ledger edit: give at least one of --title/--kind/--priority/--owner/--area');
  }
  const res = await client.patch(`/v1/items/${encodeURIComponent(id)}`, payload);
  const item = (res.json as { item?: { id: string; title: string } }).item;
  io.out(item ? `${item.id} ${item.title}` : `${id} updated`);
  return 0;
}

async function cmdDups(args: Args, client: HubClient, io: Io): Promise<number> {
  const query = new URLSearchParams({ format: 'line' });
  const repo = flag(args, 'repo');
  if (!repo) {
    io.err('ledger dups: missing --repo <slug> (duplicates are searched within one repo)');
    return 4;
  }
  query.set('repo', repo);
  const threshold = flag(args, 'threshold');
  if (threshold) query.set('threshold', threshold);
  const text = (await client.get(`/v1/dups?${query.toString()}`)).text.trim();
  io.out(text === '' ? '— no likely duplicates —' : text);
  return 0;
}

/** "Do we already have this?" before an agent writes a candidate down. */
async function cmdCheck(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const title = requireArg(args.positional[1], 'text to check');
  const query = new URLSearchParams({ title, format: 'line' });
  const repo = flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io, true));
  if (repo) query.set('repo', repo);
  const threshold = flag(args, 'threshold');
  if (threshold) query.set('threshold', threshold);
  const text = (await client.get(`/v1/check?${query.toString()}`)).text.trim();
  io.out(text === '' ? '— nothing similar, safe to write down —' : text);
  return 0;
}

async function cmdReply(args: Args, client: HubClient, io: Io): Promise<number> {
  const id = itemId(args);
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/reply?format=line`, {
    text: args.positional[2] ?? '',
    mode: flag(args, 'mode') ?? 'auto',
  });
  printLines(res.text, io);
  return 0;
}

/** The hub refuses above 80; warn earlier so nobody hits the wall. */
function warnLongTitle(title: string, io: Io): void {
  if (title.length > TITLE_WARN && title.length <= TITLE_MAX) {
    io.err(
      `ledger: title is ${title.length} characters (recommended up to ${TITLE_WARN}, hard limit ${TITLE_MAX}) — details belong in --why`,
    );
  }
}

/* ---------------- helpers ---------------- */

function requireArg(value: string | undefined, what: string): string {
  if (!value || value.trim() === '') throw new CliError(4, `missing ${what}`);
  return value.trim();
}

function itemId(args: Args, at = 1): string {
  return requireArg(args.positional[at], 'item ID').toUpperCase();
}

async function readStdin(io: Io): Promise<string> {
  if (io.stdin) return io.stdin();
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

/** `--why -` / `--rec -` / `intake -` read the body from stdin. */
async function valueOrStdin(
  raw: string | undefined,
  io: Io,
): Promise<string | undefined> {
  if (raw === undefined) return undefined;
  if (raw === '-') return (await readStdin(io)).trim();
  return raw;
}

function gitToplevel(cwd: string): Promise<string | null> {
  return new Promise((resolvePromise) => {
    const child = spawn('git', ['--no-optional-locks', 'rev-parse', '--show-toplevel'], {
      cwd,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    let out = '';
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString('utf8');
    });
    child.on('error', () => resolvePromise(null));
    child.on('close', (code) => resolvePromise(code === 0 && out.trim() !== '' ? out.trim() : null));
  });
}

/** `--repo`, else `$LEDGER_REPO`, else cwd git toplevel ↔ repos.yml, else exit 4. */
async function resolveRepo(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
  optional = false,
): Promise<string | null> {
  const explicit = flag(args, 'repo') ?? io.env.LEDGER_REPO?.trim();
  if (explicit) return explicit;
  const top = await gitToplevel(io.cwd);
  if (top) {
    const res = await client.get('/v1/repos');
    const repos = ((res.json ?? {}) as { repos?: Record<string, { path?: string | null }> }).repos ?? {};
    const real = await realpathOf(top);
    for (const [slug, repo] of Object.entries(repos)) {
      if (!repo.path) continue;
      const p = expandTilde(repo.path, io.env);
      if (p === real || p === top) return slug;
    }
  }
  if (optional) return null;
  throw new CliError(4, 'unknown repo — `ledger repo add <slug> --path . --prefix XX`');
}

function expandTilde(p: string, env: NodeJS.ProcessEnv): string {
  if (p.startsWith('~/')) return `${env.HOME ?? ''}/${p.slice(2)}`;
  return p;
}

async function realpathOf(p: string): Promise<string> {
  const { realpath } = await import('node:fs/promises');
  try {
    return await realpath(p);
  } catch {
    return p;
  }
}

function session(cfg: CliEnvConfig): string | null {
  return cfg.session;
}

/* ---------------- commands ---------------- */

export { hubServesLedger };

async function cmdStatus(
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const res = await client.get('/v1/healthz');
  const h = res.json as {
    ok: boolean;
    port: number;
    ledger: string;
    repos: number;
    items: number;
    intakeNew: number;
    spool?: { queued: number; failed: number };
    git: {
      lastCommit: string | null;
      lastCommitAt?: string | null;
      lastPushAt: string | null;
      lastPushError: string | null;
      upstream?: string | null;
      ahead?: number | null;
      behind?: number | null;
      secretScan?: { scanner: string | null; blocked: boolean; note: string | null };
    };
    /** State of the install-managed gitleaks copy. */
    gitleaks?: { state: 'unknown' | 'ok' | 'untrusted' | 'missing' | 'mismatch'; detail: string | null };
    warnings: { file: string; reason: string }[];
  };
  if (!(await hubServesLedger(h.ledger, cfg.ledgerDir))) {
    // Never report success for a stranger on the port: nothing below would be
    // about THIS ledger. Exit 3 = "the hub (of this ledger) is not running".
    io.err(
      `status: ${cfg.baseUrl} does not answer for ledger ${cfg.ledgerDir}` +
        (typeof h.ledger === 'string' ? ` (it serves ${h.ledger})` : ' (it did not accept this ledger token)') +
        ' — another process or another hub owns the port; check LEDGER_DIR / LEDGER_HUB_PORT (`ledger doctor`)',
    );
    return 3;
  }
  io.out(
    `hub ${h.ok ? 'ok' : 'warnings'} · port ${h.port} · ledger ${h.ledger} · ${h.repos} repos · ${
      h.items
    } items · intake new ${h.intakeNew}`,
  );
  // Ahead/behind is the part a session actually acts on ("is the ledger
  // on the remote or only on this machine"), so it goes on the git line.
  const drift =
    typeof h.git.ahead === 'number' && typeof h.git.behind === 'number' && h.git.upstream
      ? ` · ${h.git.upstream} +${h.git.ahead}/-${h.git.behind}`
      : '';
  io.out(
    `git ${h.git.lastCommit ?? '—'}${h.git.lastCommitAt ? ` (${h.git.lastCommitAt})` : ''}` +
      ` · push ${h.git.lastPushAt ?? '—'}${drift}${
        h.git.lastPushError ? ` · error: ${h.git.lastPushError}` : ''
      }`,
  );
  /*
   * `ledger status` used to mention gitleaks only when a commit
   * had already been blocked — a MISSING or unverifiable scanner (the state
   * where no second check runs at all) was a note in `hub.log` and nothing
   * else. Say it here, with the fix, in one line per state.
   */
  const gl = h.gitleaks;
  if (gl !== undefined && gl.state !== 'ok') {
    const line =
      gl.state === 'missing'
        ? 'gitleaks MISSING in .hub/bin — ledger commits go without a second check; run install.sh'
        : gl.state === 'mismatch'
          ? 'gitleaks in .hub/bin is STALE/unverified — sha256 does not match the recorded one, the binary is not run; ' +
            'after `brew upgrade gitleaks` run install.sh'
          : gl.state === 'untrusted'
            ? `gitleaks in .hub/bin is UNTRUSTED (${gl.detail ?? '?'}) — the binary is not run; run install.sh`
            : 'gitleaks state unknown — the second check of ledger commits is not confirmed';
    io.out(line);
  }
  // A blocked commit means staged changes are sitting in the ledger.
  const scan = h.git.secretScan;
  if (scan?.blocked) {
    io.out(`gitleaks BLOCKED a ledger commit: ${scan.note ?? 'finding'} — check \`git diff --cached\` in the ledger`);
  } else if (scan && scan.scanner === null && scan.note) {
    io.out(`gitleaks warning: ${scan.note}`);
  }
  // Prefer the hub's own count, but fall back to reading the spool
  // locally — the hub only sees the spool dir it was configured with.
  const spool = h.spool ?? (await spoolStats(env).catch(() => ({ queued: 0, failed: 0 })));
  if (spool.queued > 0 || spool.failed > 0) {
    io.out(
      `spool ${spool.queued} queued · ${spool.failed} failed` +
        (spool.queued > 0 ? ' — `ledger wait` sends them' : ''),
    );
  }
  for (const w of h.warnings) io.out(`warning ${w.file}: ${w.reason}`);
  return 0;
}

async function cmdBrief(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const positional = args.positional[1];
  const repo = positional ?? (await resolveRepo(args, client, cfg, io, true));
  const query = new URLSearchParams();
  if (repo) query.set('repo', repo);
  if (bool(args, 'full')) query.set('full', '1');
  const res = await client.get(`/v1/brief?${query.toString()}`);
  io.out(res.text.replace(/\n$/, ''));
  return 0;
}

async function cmdRepo(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const sub = args.positional[1];
  if (sub === 'ls' || sub === undefined) {
    const res = await client.get('/v1/repos?format=line');
    printLines(res.text, io);
    return 0;
  }
  if (sub === 'onboarded') {
    const slug = requireArg(args.positional[2], 'repo slug');
    const res = await client.post(`/v1/repos/${encodeURIComponent(slug)}/onboarded`, {});
    const out = res.json as { slug: string };
    io.out(`${out.slug} onboarded`);
    return 0;
  }
  // Declare what counts as this repo's public contract and who
  // consumes it. Additive; `--rm` / `--rm-consumer` are the only subtractions.
  if (sub === 'contract') {
    const slug = requireArg(args.positional[2], 'repo slug');
    // `flagList`, not `csv`: a glob may legitimately contain a comma
    // (`src/**/*.{dto,entity}.ts`), so repeat the flag instead of splitting.
    const add = flagList(args, 'add');
    const consumer = csv(args, 'consumer');
    const rm = flagList(args, 'rm');
    const rmConsumer = csv(args, 'rm-consumer');
    if (add.length + consumer.length + rm.length + rmConsumer.length === 0) {
      // No flags = show, so `ledger repo contract <slug>` is a safe thing to type.
      const res = await client.get(`/v1/repos/${encodeURIComponent(slug)}`);
      const cfg = (res.json as { repo?: { contracts?: string[]; consumers?: string[] } }).repo ?? {};
      io.out(`contracts: ${cfg.contracts?.join(', ') ?? '—'}`);
      io.out(`consumers: ${cfg.consumers?.join(', ') ?? '—'}`);
      return 0;
    }
    // This is an owner-level setting (who gets paged on whose commit),
    // not a routine edit — say so before making the call, not just on a
    // server-side 403.
    io.err('ledger repo contract: changing contracts is a repo-owner-level setting, not a routine edit — do it deliberately and interactively');
    const res = await client.post(`/v1/repos/${encodeURIComponent(slug)}/contract`, {
      add,
      consumer,
      rm,
      rm_consumer: rmConsumer,
      session: session(cfg),
    });
    const out = res.json as { repo: { contracts?: string[]; consumers?: string[] } };
    io.out(
      `${slug} contracts: ${out.repo.contracts?.join(', ') ?? '—'} · consumers: ${
        out.repo.consumers?.join(', ') ?? '—'
      }`,
    );
    return 0;
  }
  if (sub === 'bind') {
    const slug = requireArg(args.positional[2], 'repo slug');
    const target = requireArg(args.positional[3], 'checkout path');
    const { resolve } = await import('node:path');
    const res = await client.post(`/v1/repos/${encodeURIComponent(slug)}/bind`, {
      path: resolve(io.cwd, target),
    });
    const out = res.json as { slug: string; repo: { path: string | null } };
    io.out(`${out.slug} bound → ${out.repo.path ?? '—'}`);
    return 0;
  }
  if (sub === 'rm') {
    const slug = requireArg(args.positional[2], 'repo slug');
    // `--archive` is accepted and is the ONLY behaviour — the flag
    // exists so the intent is explicit at the call site, never to offer a
    // destructive alternative. There is no way to hard-delete a repo's ledger.
    // `--force` overrides the 409 the hub returns for open claims/leases
    // or a live session in the repo — explicit opt-in, never the default.
    const force = bool(args, 'force');
    const res = await client.request(
      'DELETE',
      `/v1/repos/${encodeURIComponent(slug)}${force ? '?force=1' : ''}`,
      undefined,
    );
    const out = res.json as { slug: string; archived: string | null };
    io.out(`${out.slug} removed from repos.yml · archive ${out.archived ?? '—'}`);
    return 0;
  }
  if (sub !== 'add') throw new CliError(4, `unknown subcommand "ledger repo ${sub}"`);
  const slug = requireArg(args.positional[2], 'repo slug');
  const path = flag(args, 'path');
  // `--kind system|vps` = ledger entry with no git checkout.
  const kind = flag(args, 'kind');
  if (kind !== undefined && kind !== 'repo' && kind !== 'system' && kind !== 'vps') {
    throw new CliError(4, `--kind: expected repo|system|vps, got "${kind}"`);
  }
  if ((kind === 'system' || kind === 'vps') && path !== undefined) {
    throw new CliError(4, `--kind ${kind} has no path (no git checkout) — omit --path`);
  }
  const host = flag(args, 'host');
  if (host !== undefined && kind !== 'vps') {
    throw new CliError(4, '--host only goes with --kind vps');
  }
  const res = await client.post('/v1/repos', {
    slug,
    prefix: flag(args, 'prefix'),
    path: path === undefined ? null : path,
    ...(kind !== undefined ? { kind } : {}),
    ...(host !== undefined ? { host } : {}),
    graphify: flag(args, 'graphify') ?? null,
    docs: csv(args, 'docs'),
  });
  const out = res.json as {
    slug: string;
    repo: { prefix: string; path: string | null; kind?: string; host?: string };
  };
  const k = out.repo.kind ?? 'repo';
  io.out(
    k === 'repo'
      ? `${out.slug} ${out.repo.prefix} ${out.repo.path ?? '—'}`
      : `${out.slug} ${out.repo.prefix} ${k}${out.repo.host ? ` ${out.repo.host}` : ''}`,
  );
  return 0;
}

/** Words that are `ledger intake` SUBCOMMANDS, so a bare one-word text
 *  that spells one of them is a mistyped command, not a bin note. `list` and
 *  `process` are in here even though only `ls` is implemented — the typo is the
 *  thing being caught, not the dispatch. */
const INTAKE_SUBCOMMANDS = new Set(['show', 'ls', 'list', 'triage', 'process']);

interface IntakeShowView {
  id: string;
  at: string;
  channel: string;
  session: string | null;
  repo_hint: string | null;
  status: string;
  items: string[];
  text: string;
  triage?: { item: string; excerpt: string }[];
  dropped?: { text: string; reason: string }[];
}

async function cmdIntake(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const sub = args.positional[1];
  if (sub === 'ls') {
    const query = bool(args, 'new') ? '?status=new&format=line' : '?format=line';
    printLines((await client.get(`/v1/intake${query}`)).text, io);
    return 0;
  }
  if (sub === 'triage') {
    const id = requireArg(args.positional[2], 'intake record id');
    const dropped = flagList(args, 'drop').map((raw) => {
      const [text, reason] = raw.split('::');
      if (!text || !reason) {
        throw new CliError(4, `--drop expects the form "text::reason", got "${raw}"`);
      }
      return { text: text.trim(), reason: reason.trim() };
    });
    const res = await client.post(`/v1/intake/${encodeURIComponent(id)}/triage`, {
      items: csv(args, 'items').map((i) => i.toUpperCase()),
      dropped,
      status: flag(args, 'status'),
      session: session(cfg),
    });
    const rec = (res.json as { intake: { id: string; status: string; items: string[] } }).intake;
    io.out(`${rec.id} ${rec.status} → ${rec.items.join(',') || 'no items'}`);
    return 0;
  }
  if (sub === 'show') {
    const id = requireArg(args.positional[2], 'intake record id');
    const res = await client.get(`/v1/intake/${encodeURIComponent(id)}`);
    const rec = (res.json as { intake: IntakeShowView }).intake;
    io.out(
      `${rec.id} ${rec.status} ${rec.channel} ${rec.at}${
        rec.repo_hint ? ` ${rec.repo_hint}` : ''
      }${rec.session ? ` · ${rec.session}` : ''}`,
    );
    io.out(`items: ${rec.items.length > 0 ? rec.items.join(', ') : '—'}`);
    for (const t of rec.triage ?? []) io.out(`  ${t.item} ← ${t.excerpt}`);
    for (const d of rec.dropped ?? []) io.out(`  dropped: ${d.text} — ${d.reason}`);
    io.out('---');
    printLines(rec.text, io);
    return 0;
  }
  // `ledger intake show <id>` used to fall through to "create a record"
  // and stored the literal text "show" as a new intake entry. A one-word text that
  // IS a subcommand name is a typo, never a real bin note — refuse it, and say
  // how to force it through if somebody really meant the word.
  const firstWord = args.positional[1]?.trim().toLowerCase();
  if (firstWord !== undefined && INTAKE_SUBCOMMANDS.has(firstWord)) {
    throw new CliError(
      4,
      `"${args.positional[1]?.trim()}" is a subcommand, not intake text — nothing was saved. ` +
        `Did you mean "ledger intake ${firstWord} <id>"? Send real intake text via ` +
        `"ledger intake -" (stdin) or as several words.`,
    );
  }
  const text = requireArg(await valueOrStdin(args.positional[1], io), 'intake text');
  const repoHint = await resolveRepo(args, client, cfg, io, true);
  const action = flag(args, 'action') ?? 'triage';
  const res = await client.post('/v1/intake', {
    text,
    channel: 'chat',
    session: session(cfg),
    repo_hint: repoHint,
    action,
    // `send_to_session` needs an explicit target; default to this session
    // so `ledger intake … --action send_to_session --to <id>` is the only extra flag.
    ...(flag(args, 'to') ? { session: flag(args, 'to') } : {}),
  });
  const out = res.json as {
    id: string;
    redacted: number;
    intake?: { action?: string; target_title?: string | null };
  };
  const target = out.intake?.target_title;
  io.out(
    `${out.id} new${out.redacted > 0 ? ` · redacted ${out.redacted}` : ''}` +
      (action !== 'triage' ? ` · ${action}${target ? ` → "${target}"` : ''}` : ''),
  );
  return 0;
}

async function cmdAdd(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const title = requireArg(args.positional[1], 'item title');
  warnLongTitle(title, io);
  // `optional` is false, so this is a string — the overload just cannot say so.
  const repo = requireArg((await resolveRepo(args, client, cfg, io)) ?? undefined, 'repo');
  try {
    return await postItem(args, client, cfg, io, repo, title);
  } catch (err) {
    // A 409 here is actionable advice, not a failure to retry.
    const handled = explainDuplicate(err, io);
    if (handled !== null) return handled;
    throw err;
  }
}

async function postItem(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
  repo: string,
  title: string,
): Promise<number> {
  const res = await client.post('/v1/items?format=line', {
    repo,
    title,
    kind: flag(args, 'kind') ?? 'BACKLOG',
    priority: flag(args, 'priority') ?? 'P2',
    owner: flag(args, 'owner') ?? 'agent',
    area: flag(args, 'area') ?? null,
    why: await valueOrStdin(flag(args, 'why'), io),
    rec: await valueOrStdin(flag(args, 'rec'), io),
    steps: flagList(args, 'step'),
    blocked_by: csv(args, 'blocked-by').map((i) => i.toUpperCase()),
    requested_by: flag(args, 'requested-by')?.toUpperCase() ?? null,
    intake: flag(args, 'intake') ?? null,
    aliases: csv(args, 'alias'),
    proposed: bool(args, 'proposed'),
    session: session(cfg),
    agent: cfg.agent,
    force: bool(args, 'force'),
  });
  printLines(res.text, io);
  return 0;
}

/**
 * Turn a dedupe 409 into the next command to run.
 *
 * Exit 2 (conflict), not 4: the request was well formed and the hub is telling
 * us the work already exists. An agent that sees exit 2 here must NOT retry.
 */
function explainDuplicate(err: unknown, io: Io): number | null {
  if (!(err instanceof CliError)) return null;
  const extra = err.detail as
    | {
        error?: string;
        candidates?: {
          id: string;
          title: string;
          score: number;
          status?: string;
          closed_at?: string | null;
          closed_by_title?: string | null;
          closed_by_session?: string | null;
          commit?: string | null;
        }[];
      }
    | undefined;
  const candidates = extra?.candidates ?? [];
  if (extra?.error === 'ALREADY_DONE' && candidates.length > 0) {
    for (const c of candidates) {
      const who =
        c.closed_by_title !== null && c.closed_by_title !== undefined
          ? `session "${c.closed_by_title}"`
          : c.closed_by_session
            ? `session ${c.closed_by_session.slice(0, 4)}`
            : 'unknown session';
      io.err(
        `ledger: already resolved: ${c.id} (${c.status ?? 'done'}${
          c.closed_at ? ` ${c.closed_at}` : ''
        }, ${who}${c.commit ? `, ${c.commit.slice(0, 7)}` : ''}) — do not write it down;` +
          ` if it is a regression: ledger reopen ${c.id} --why "…"`,
      );
    }
    io.err('ledger: if it really is a new thing: `ledger add … --force`');
    return 2;
  }
  if (extra?.error === 'DUPLICATE' && candidates.length > 0) {
    io.err('ledger: a nearly identical open item already exists:');
    for (const c of candidates) {
      io.err(`  ${c.id} (${c.score.toFixed(2)}) ${c.title}`);
    }
    const first = candidates[0] as { id: string };
    io.err(`ledger: add to it: ledger note ${first.id} "<what you found>"`);
    io.err('ledger: if it really is a different thing: `ledger add … --force`');
    return 2;
  }
  return null;
}

async function cmdLs(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const query = new URLSearchParams({ format: 'line' });
  const repo = flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io, true));
  if (repo) query.set('repo', repo);
  for (const key of ['status', 'owner', 'kind', 'priority'] as const) {
    const value = flag(args, key);
    if (value) query.set(key, value);
  }
  if (bool(args, 'open')) query.set('open', '1');
  printLines((await client.get(`/v1/items?${query.toString()}`)).text, io);
  return 0;
}

async function cmdShow(args: Args, client: HubClient, io: Io): Promise<number> {
  const id = itemId(args);
  const res = await client.get(`/v1/items/${encodeURIComponent(id)}`);
  const data = res.json as {
    item: Record<string, unknown> & { id: string; title: string };
    detail: {
      why: string;
      rec: string;
      steps: { n: number; done: boolean; text: string }[];
      comments: { at: string; author: string; text: string }[];
      log: { at: string; session: string; text: string }[];
    };
  };
  const fm = data.item;
  io.out(
    `${fm.id} ${String(fm.status)} ${String(fm.priority)} [${String(fm.kind)}] ${String(
      fm.repo,
    )} @${String(fm.owner)} · ${fm.title}`,
  );
  if (Array.isArray(fm.blocked_by) && fm.blocked_by.length > 0) {
    io.out(`blocked_by: ${(fm.blocked_by as string[]).join(', ')}`);
  }
  if (data.detail.why) io.out(`why: ${oneLine(data.detail.why)}`);
  if (data.detail.rec) io.out(`recommendation: ${oneLine(data.detail.rec)}`);
  for (const s of data.detail.steps) io.out(`  ${s.done ? '[x]' : '[ ]'} ${s.n}. ${s.text}`);
  for (const cm of data.detail.comments) io.out(`  ${cm.at} ${cm.author}: ${oneLine(cm.text)}`);
  for (const l of data.detail.log) io.out(`  log ${l.at} ${l.session} ${l.text}`);
  if (bool(args, 'origin')) {
    const o = await client.get(`/v1/items/${encodeURIComponent(id)}/origin`);
    const { formatOrigin } = await import('./tidy.ts');
    for (const line of formatOrigin(o.json as import('@agent-ledger/shared').ItemOrigin, fm)) io.out(line);
  }
  return 0;
}

async function cmdClaim(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const id = itemId(args);
  // pid-ancestry session mapping is gone (unreliable — a reply worker
  // and its parent session share process ancestry, and so does anything else
  // spawned from the same terminal/tmux pane). Without `LEDGER_SESSION` there is
  // no reliable way to attribute this claim, so it is filed as `manual` and
  // the caller is told, on stderr, exactly why and how to fix it.
  if (session(cfg) === null) {
    io.err(
      'ledger: session unknown (LEDGER_SESSION is not set) — the claim is recorded as manual; restart the session so the hub knows it',
    );
  }
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/claim`, {
    session: session(cfg) ?? 'manual',
    paths: csv(args, 'paths'),
    intent: flag(args, 'intent'),
  });
  // An over-wide claim glob is not an error (globs block nothing), but
  // the suggestion to narrow it belongs on stderr where the agent reads it.
  const warnings = (res.json as { warnings?: unknown }).warnings;
  if (Array.isArray(warnings)) {
    for (const w of warnings) if (typeof w === 'string') io.err(`ledger: ${w}`);
  }
  return printItem(res.json, io);
}

async function cmdStep(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const id = itemId(args);
  const n = Number(requireArg(args.positional[2], 'step number'));
  const verb = requireArg(args.positional[3], 'done|undo');
  if (!Number.isInteger(n) || n < 1) throw new CliError(4, 'step number must be an integer ≥ 1');
  if (verb !== 'done' && verb !== 'undo') throw new CliError(4, 'step only accepts done|undo');
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/steps`, {
    n,
    done: verb === 'done',
    session: session(cfg),
  });
  const data = res.json as {
    item: { id: string };
    steps: { n: number; done: boolean; text: string }[];
  };
  const step = data.steps.find((s) => s.n === n);
  io.out(`${data.item.id} step ${n} ${step?.done ? 'done' : 'open'} · ${step?.text ?? ''}`);
  return 0;
}

async function cmdNote(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const id = itemId(args);
  const text = requireArg(await valueOrStdin(args.positional[2], io), 'note text');
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/comments`, {
    text,
    author: cfg.agent,
    session: session(cfg),
  });
  const data = res.json as { item: { id: string }; comment: string };
  io.out(`${data.item.id} comment c${data.comment} · ${cfg.agent}`);
  return 0;
}

async function cmdSimple(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
  action: 'release',
): Promise<number> {
  const id = itemId(args);
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/${action}`, {
    session: session(cfg),
    why: flag(args, 'why'),
  });
  return printItem(res.json, io);
}

async function cmdDone(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const id = itemId(args);
  const ref = flag(args, 'ref');
  // Catch prose in `--ref` here, so the hint names this item and the
  // sentence is not lost to a 422 from the far end of the spool.
  if (ref !== undefined && ref !== '' && !isDoneRef(ref)) {
    throw new CliError(4, DONE_REF_HINT.replace('<ID>', id));
  }
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/done`, {
    session: session(cfg),
    ref,
  });
  return printItem(res.json, io);
}

async function cmdDrop(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const id = itemId(args);
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/drop`, {
    session: session(cfg),
    why: requireArg(flag(args, 'why'), '--why "<reason>"'),
  });
  return printItem(res.json, io);
}

async function cmdDup(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const id = itemId(args);
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/dup`, {
    session: session(cfg),
    into: requireArg(flag(args, 'into'), '--into <ID>').toUpperCase(),
  });
  return printItem(res.json, io);
}

async function cmdBlock(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const id = itemId(args);
  const by = flag(args, 'by');
  const on = flag(args, 'on') ?? (args.bools.has('on') ? 'human' : undefined);
  if (!by && on !== 'human') throw new CliError(4, 'give --by <ID> or --on human');
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/block`, {
    session: session(cfg),
    by: by?.toUpperCase(),
    on: by ? undefined : 'human',
  });
  return printItem(res.json, io);
}

async function cmdReopen(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const id = itemId(args);
  const res = await client.post(`/v1/items/${encodeURIComponent(id)}/reopen`, {
    session: session(cfg),
    why: requireArg(flag(args, 'why'), '--why "<why>"'),
  });
  return printItem(res.json, io);
}

async function cmdDecide(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const title = requireArg(args.positional[1], 'decision title');
  const repo = await resolveRepo(args, client, cfg, io);
  const res = await client.post('/v1/decisions', {
    repo,
    title,
    why: requireArg(await valueOrStdin(flag(args, 'why'), io), '--why "<text>"'),
    related: csv(args, 'related'),
    session: session(cfg),
  });
  const d = (res.json as { decision: { n: number; date: string; title: string } }).decision;
  io.out(`D${d.n} ${d.date} ${repo} · ${d.title}`);
  return 0;
}

async function cmdLog(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const text = requireArg(await valueOrStdin(args.positional[1], io), 'summary text');
  const repo = await resolveRepo(args, client, cfg, io);
  const res = await client.post('/v1/journal', {
    repo,
    text,
    type: 'session.summary',
    session: session(cfg),
  });
  const ev = (res.json as { event: { at: string; session: string } }).event;
  io.out(`${ev.at} ${repo} ${ev.session} session.summary`);
  return 0;
}

async function cmdHistory(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const query = new URLSearchParams({ format: 'line', since: flag(args, 'since') ?? '7d' });
  const repo = flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io, true));
  if (repo) query.set('repo', repo);
  const type = flag(args, 'type');
  if (type) query.set('type', type);
  // `/timeline` is `/journal` plus the type filter and the DB-backed
  // session/commit events, so history reads from there now.
  printLines((await client.get(`/v1/timeline?${query.toString()}`)).text, io);
  return 0;
}

async function cmdWho(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const repo =
    args.positional[1] ?? flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io));
  const res = await client.get(`/v1/repos/${encodeURIComponent(repo as string)}/who`);
  printLines(res.text, io);
  return 0;
}

async function cmdWhose(args: Args, client: HubClient, io: Io): Promise<number> {
  const raw = requireArg(args.positional[1], 'file path');
  const { resolve } = await import('node:path');
  const abs = resolve(raw);
  const res = await client.get(`/v1/whose?format=line&path=${encodeURIComponent(abs)}`);
  printLines(res.text, io);
  return 0;
}

/**
 * `ledger why <path|dir|glob>` — metadata about a path, never its content. The
 * path is made absolute against the shell's cwd here (the hub does not know it)
 * and the hub re-validates it against the repo's real checkout. The output is
 * DATA from the ledger and git: it is sanitized again on this side and the
 * first line says it is not instructions.
 */
async function cmdWhy(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const raw = requireArg(args.positional[1], 'path, directory or glob');
  const repo = flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io));
  const { resolve } = await import('node:path');
  // The API takes `/`-separated paths only (it rejects backslashes); on Windows
  // `D:\\x\\y` goes over the wire as `D:/x/y`.
  const resolved = resolve(io.cwd, raw);
  const abs = process.platform === 'win32' ? resolved.replaceAll('\\', '/') : resolved;
  const res = await client.get(
    `/v1/repos/${encodeURIComponent(repo as string)}/why?path=${encodeURIComponent(abs)}`,
  );
  if (bool(args, 'json')) {
    io.out(JSON.stringify(res.json));
    return 0;
  }
  const { formatWhy } = await import('./why.ts');
  for (const line of formatWhy(res.json as import('@agent-ledger/shared').WhyView)) io.out(line);
  return 0;
}

/**
 * `ledger tidy` — stale items with evidence. Read-only unless stdin AND stdout
 * are terminals and `--json` is off; then each action is confirmed one by one.
 * `--apply` does not exist on purpose: nothing is ever closed unattended.
 */
async function cmdTidy(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  if (bool(args, 'apply') || flag(args, 'apply') !== undefined) {
    throw new CliError(4, '--apply is not supported (tidy never closes items non-interactively)');
  }
  const { TIDY_BUCKETS } = await import('@agent-ledger/shared');
  const tidy = await import('./tidy.ts');
  const repo = flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io));
  const query = new URLSearchParams();
  const limit = flag(args, 'limit');
  if (limit !== undefined) {
    if (!/^[1-9][0-9]{0,3}$/.test(limit)) throw new CliError(4, '--limit must be a positive integer');
    query.set('limit', limit);
  }
  const bucket = flag(args, 'bucket');
  if (bucket !== undefined) {
    if (!(TIDY_BUCKETS as readonly string[]).includes(bucket)) {
      throw new CliError(4, `--bucket must be one of ${TIDY_BUCKETS.join(', ')}`);
    }
    query.set('bucket', bucket);
  }
  const qs = query.toString();
  const res = await client.get(
    `/v1/repos/${encodeURIComponent(repo as string)}/tidy${qs ? `?${qs}` : ''}`,
  );
  if (bool(args, 'json')) {
    io.out(JSON.stringify(res.json));
    return 0;
  }
  const resp = res.json as import('@agent-ledger/shared').TidyResponse;
  const interactive = io.tty?.stdin === true && io.tty?.stdout === true;
  if (!interactive) {
    for (const line of tidy.formatTidy(resp)) io.out(line);
    return 0;
  }
  for (const line of tidy.formatTidyHeader(resp)) io.out(line);
  const entries = Array.isArray(resp.entries) ? resp.entries : [];
  if (entries.length === 0) {
    io.out('nothing to tidy');
    return 0;
  }
  const rl = io.ask ? null : await tidy.makeReadlineAsk();
  const ask = io.ask ?? (rl as NonNullable<typeof rl>).ask;
  try {
    await tidy.runTidyInteractive(entries, {
      ask,
      out: io.out,
      ctx: { interactive: true, session: session(cfg), agent: cfg.agent },
      exec: async (call) => {
        if (call.method === 'patch') await client.patch(call.path, call.body);
        else await client.post(call.path, call.body);
      },
    });
  } finally {
    rl?.close();
  }
  return 0;
}

async function cmdSearch(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const q = requireArg(args.positional[1], 'search query');
  const query = new URLSearchParams({ format: 'line', q });
  const repo = flag(args, 'repo') ?? (bool(args, 'all') ? null : null);
  if (repo) query.set('repo', repo);
  const limit = flag(args, 'limit');
  if (limit) query.set('limit', limit);
  void cfg;
  printLines((await client.get(`/v1/search?${query.toString()}`)).text, io);
  return 0;
}

async function cmdSessions(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const query = new URLSearchParams({ format: 'line' });
  const repo = flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io, true));
  if (repo) query.set('repo', repo);
  if (bool(args, 'live')) query.set('live', '1');
  printLines((await client.get(`/v1/sessions?${query.toString()}`)).text, io);
  return 0;
}

async function cmdOnboard(args: Args, client: HubClient, io: Io): Promise<number> {
  const { resolve } = await import('node:path');
  const path = resolve(flag(args, 'path') ?? io.cwd);
  printLines((await client.get(`/v1/onboard?path=${encodeURIComponent(path)}`)).text, io);
  return 0;
}

/* ---------------- guard, intrude, inbox, orphans ---------------- */

async function cmdGuard(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const sub = args.positional[1] ?? 'status';
  if (sub === 'status') {
    printLines((await client.get('/v1/guard?format=line')).text, io);
    return 0;
  }
  if (sub !== 'on' && sub !== 'off') {
    throw new CliError(4, 'ledger guard only accepts on|off|status');
  }
  const res = await client.post('/v1/guard?format=line', {
    state: sub,
    session: session(cfg),
    why: flag(args, 'why'),
  });
  printLines(res.text, io);
  return 0;
}

/**
 * `ledger intrude` (SPEC §11; optional — the hub must run with LEDGER_INTRUDE=1). A 409 arrives as `CliError(2)` from the client, but
 * the conflict detail only helps if the agent also sees what to do instead — so
 * this command re-reads the body and prints the `next` recipe before exiting 2.
 */
async function cmdIntrude(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const sub = args.positional[1];
  const me = session(cfg);
  if (!me) throw new CliError(4, 'LEDGER_SESSION is not set — an intrude must belong to a session');

  if (sub === 'begin') {
    const repo = requireArg(flag(args, 'repo'), '--repo <slug>');
    const paths = csv(args, 'paths');
    if (paths.length === 0) throw new CliError(4, 'missing --paths "a/**,b.ts"');
    try {
      const res = await client.post('/v1/intrude?format=line', {
        session: me,
        repo,
        item: flag(args, 'item')?.toUpperCase() ?? null,
        paths,
        intent: flag(args, 'intent'),
        force: bool(args, 'force'),
      });
      printLines(res.text, io);
      return 0;
    } catch (err) {
      if (err instanceof CliError && err.exitCode === 2) {
        io.err(`ledger: ${err.message}`);
        for (const line of conflictAdvice(repo, flag(args, 'item'))) io.err(line);
        return 2;
      }
      throw err;
    }
  }

  const leaseId = await resolveLease(args, client, me);
  if (sub === 'commit') {
    const sha = requireArg(args.positional[2] ?? flag(args, 'commit'), 'commit sha');
    const res = await client.post(
      `/v1/intrude/${encodeURIComponent(leaseId)}/commit?format=line`,
      { session: me, commit: sha, note: flag(args, 'note') },
    );
    printLines(res.text, io);
    return 0;
  }
  if (sub === 'end') {
    const res = await client.request(
      'DELETE',
      `/v1/intrude/${encodeURIComponent(leaseId)}?format=line`,
      { session: me },
    );
    printLines(res.text, io);
    return 0;
  }
  throw new CliError(4, 'ledger intrude only accepts begin|commit|end');
}

/** `--lease <id>`, else the session's newest open intrude lease. */
async function resolveLease(args: Args, client: HubClient, me: string): Promise<string> {
  const explicit = flag(args, 'lease');
  if (explicit) return explicit;
  const res = await client.get(`/v1/intrude?session=${encodeURIComponent(me)}`);
  const leases = ((res.json ?? {}) as { leases?: { id: string; repo: string }[] }).leases ?? [];
  const first = leases[0];
  if (!first) {
    throw new CliError(
      4,
      'no open intrude lease — first run `ledger intrude begin --repo <r> --paths …`',
    );
  }
  return first.id;
}

function conflictAdvice(repo: string, item: string | undefined): string[] {
  return [
    `ledger: per §11 change nothing in ${repo} — send a request instead:`,
    `  ledger add --repo ${repo} --owner agent --kind BACKLOG --priority P1${
      item ? ` --requested-by ${item.toUpperCase()}` : ''
    } "<what is needed>" --why "<why>" --rec "<how>"`,
    ...(item ? [`  ledger block ${item.toUpperCase()} --by <new ID>`] : []),
    `  ledger who ${repo}`,
    '  (if the user explicitly authorized it: `ledger intrude begin … --force`)',
  ];
}

async function cmdInbox(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const me = session(cfg) ?? flag(args, 'session');
  if (!me) throw new CliError(4, 'LEDGER_SESSION is not set (or pass --session <id>)');
  const query = new URLSearchParams({ format: 'line', session: me });
  if (bool(args, 'all')) query.set('all', '1');
  printLines((await client.get(`/v1/inbox?${query.toString()}`)).text, io);
  return 0;
}

async function cmdAdopt(args: Args, client: HubClient, cfg: CliEnvConfig, io: Io): Promise<number> {
  const me = session(cfg);
  if (!me) throw new CliError(4, 'LEDGER_SESSION is not set — adopt takes files over for a session');
  const target = requireArg(args.positional[1], 'path or item ID');
  const looksLikeId = isItemId(target.toUpperCase());
  const payload: Record<string, unknown> = { session: me };
  if (looksLikeId) {
    payload.item = target.toUpperCase();
  } else {
    const { resolve } = await import('node:path');
    payload.path = resolve(io.cwd, target);
  }
  printLines((await client.post('/v1/adopt?format=line', payload)).text, io);
  return 0;
}

async function cmdOverride(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const me = session(cfg);
  if (!me) throw new CliError(4, 'LEDGER_SESSION is not set');
  const target = requireArg(args.positional[1], 'file path');
  const reason = requireArg(flag(args, 'reason'), '--reason "<why, who authorized it>"');
  const { resolve } = await import('node:path');
  const res = await client.post('/v1/override?format=line', {
    session: me,
    path: resolve(io.cwd, target),
    reason,
  });
  printLines(res.text, io);
  return 0;
}

async function cmdReleaseNotes(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
): Promise<number> {
  const repo = flag(args, 'repo') ?? (await resolveRepo(args, client, cfg, io));
  const query = new URLSearchParams();
  const from = flag(args, 'from');
  if (from) query.set('from', from);
  const to = flag(args, 'to');
  if (to) query.set('to', to);
  const res = await client.get(
    `/v1/repos/${encodeURIComponent(repo as string)}/release-notes${
      query.size > 0 ? `?${query.toString()}` : ''
    }`,
  );
  printLines(res.text, io);
  return 0;
}

/* ---------------- hooks ---------------- */

// The transport lives in `./hook.ts` — self-contained so `bin.ts` can run it
// without loading this module (see the comment there). Re-exported so `run()`
// stays the single entry point for tests.
export { shellQuote } from './hook.ts';

/* ---------------- output ---------------- */

function printLines(text: string, io: Io): void {
  const trimmed = text.replace(/\n$/, '');
  if (trimmed.trim() === '') return;
  for (const line of trimmed.split('\n')) io.out(line);
}

function printItem(json: unknown, io: Io): number {
  const fm = (json as { item: Record<string, unknown> }).item;
  io.out(
    `${String(fm.id)} ${String(fm.status)} ${String(fm.priority)} [${String(fm.kind)}] ${String(
      fm.repo,
    )} @${String(fm.owner)} · ${String(fm.title)}`,
  );
  return 0;
}

function oneLine(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > 160 ? `${flat.slice(0, 159)}…` : flat;
}
