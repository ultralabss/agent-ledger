/**
 * Headless `ledger-keeper` runs (Claude Code adapter, optional: `LEDGER_HEADLESS=1`) — SPEC §8, §14.3, §15, F3.
 *
 * The hub shells out to the user's own `claude` CLI so intake triage runs on the
 * subscription, not on an API key. That is the whole reason for the flag choice:
 *   -p                      non-interactive, print and exit
 *   --append-system-prompt  the `ledger-keeper` role, verbatim from the agent file
 *   --allowedTools          `Bash(ledger *)` + `Read` scoped to the ledger dir,
 *                           plus `--disallowedTools` for `~/.ssh`, `~/.aws`,
 *                           `.env*`, `~/.claude` (§15, audit H3)
 *   --permission-mode default   no bypass — the allow-list is the permission
 *   --output-format json    a parseable result instead of a transcript
 * `--bare` is deliberately NOT used: it forces `ANTHROPIC_API_KEY` auth and
 * would fail on a subscription login.
 *
 * Safety properties this file is responsible for:
 *  - the binary comes from `LEDGER_CLAUDE_BIN` and must be an ABSOLUTE path (a
 *    bare name would be resolved through the hub's `PATH`, which launchd
 *    inherits from the user's shell — that is a code-execution hole, not a
 *    convenience),
 *  - `spawn` with an argv array and no shell, so nothing in the prompt can be
 *    read as shell syntax,
 *  - one run at a time (a queue, not a rejection: the web "Process now"
 *    button must not fail because a weekly groom happens to be running),
 *  - a hard timeout with SIGKILL, and stdout capped — a runaway agent must not
 *    grow the hub's heap or wedge the queue,
 *  - the result text is truncated to 2 KB before it touches the journal.
 */

import { spawn } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { HeadlessRun, HeadlessStatus } from '@agent-ledger/shared';
import { isoLocal, sanitizeField } from '@agent-ledger/shared';
import type { HubConfig } from './config.ts';
import { LedgerError } from './errors.ts';
import {
  claudeBinBlockReason,
  resolveClaudeBin,
  type ClaudeBinStatus,
  type ClaudeBinTrust,
} from './claudebin.ts';
import type { Ledger } from './ledger/ledger.ts';

/** Journalled result text cap (SPEC F3). */
const MAX_RESULT = 2048;
/** Stdout we are willing to buffer before killing the child. */
const MAX_STDOUT = 512 * 1024;
const AGENT_FILE = 'ledger-keeper.md';
/** Shown when `LEDGER_AGENTS_DIR` is unset: headless runs cannot find the role prompt. */
export const AGENTS_DIR_UNSET =
  'agents dir not configured (copy examples/agents/ledger-keeper.md and set LEDGER_AGENTS_DIR)';
/**
 * B1-7 — duplicate *proposals* a single weekly groom may raise. A
 * merge loses an item's history, so a headless run (triggered by a schedule,
 * not a human looking at the pair) never merges on its own — it proposes via
 * `ledger note` / a `--proposed` item and leaves the actual `ledger dup --into`
 * to the orchestrator once a human-reviewed session confirms it. This cap is
 * enforced server-side too (`POST /v1/items/:id/dup`, keyed on the
 * `headless-*` session) as the backstop for when the prompt is not enough.
 */
export const GROOM_SEMANTIC_DUP_CAP = 6;

export interface HeadlessDeps {
  ledger: Ledger;
  config: HubConfig;
  now?: () => number;
  /** Test seam: replaces `child_process.spawn`. */
  spawnFn?: typeof spawn;
  /** Test seam: extra env for the child. */
  env?: NodeJS.ProcessEnv;
  /** A8-4 test seam: bound the directory-chain walk to a sandbox root. */
  trustStopAt?: string;
}

export class HeadlessRunner {
  private readonly deps: HeadlessDeps;
  private chain: Promise<unknown> = Promise.resolve();
  private running = false;
  private waiting = 0;
  private last: HeadlessRun | null = null;
  private lastGroom: HeadlessRun | null = null;
  /** A8-4: ENFORCED — see `trust()`. */
  private binTrust: ClaudeBinTrust = 'unknown';
  private binTrustDetail: string | null = null;
  private trustProbe: Promise<ClaudeBinStatus> | null = null;

  constructor(deps: HeadlessDeps) {
    this.deps = deps;
  }

  get status(): HeadlessStatus {
    return {
      configured: this.deps.config.claudeBin !== null,
      busy: this.running,
      queued: this.waiting,
      last: this.last,
      last_groom: this.lastGroom,
      weekly: this.deps.config.groomWeekly,
      bin_trust: this.binTrust,
      bin_trust_detail:
        this.binTrustDetail ??
        (this.deps.config.claudeBin !== null && this.deps.config.agentsDir === null ? AGENTS_DIR_UNSET : null),
    };
  }

  /**
   * A8-4: the verdict is now a GATE, not a diagnostic. It was only reported before,
   * and softened it by enumerating the owning group — which is not fail-closed
   * (see `bintrust.ts`). A `claude` binary an attacker can replace is code
   * execution in the hub's uid, so an untrusted path turns the headless
   * features (triage, grooming, reply worker) off until the user fixes the
   * install or consciously opts in.
   *
   * Memoised: one filesystem probe per hub process, same as the git/gitleaks
   * resolutions. A restart re-probes.
   */
  private trust(): Promise<ClaudeBinStatus> {
    this.trustProbe ??= resolveClaudeBin(this.deps.config.claudeBin, {
      trustGroup: this.deps.config.trustClaudeGroup,
      // A9-1: the opt-in is only as wide as what the installer saw.
      pin: {
        gid: this.deps.config.trustClaudeGid,
        realpath: this.deps.config.trustClaudeRealpath,
      },
      ...(this.deps.trustStopAt === undefined ? {} : { stopAt: this.deps.trustStopAt }),
    }).then((status) => {
      this.binTrust = status.state;
      this.binTrustDetail = status.detail ?? claudeBinBlockReason(status);
      return status;
    });
    return this.trustProbe;
  }

  /** Resolve the trust verdict for healthz / the brief (no run involved). */
  async probeBinaryTrust(): Promise<void> {
    await this.trust().catch(() => undefined);
  }

  /** 503 with the exact fix when the binary is not configured, not there, or
   *  not trustworthy (A8-4). */
  private async binary(): Promise<string> {
    const bin = this.deps.config.claudeBin;
    if (bin === null) {
      throw new LedgerError(
        503,
        'UNAVAILABLE',
        'headless triage is not configured: LEDGER_CLAUDE_BIN is missing. ' +
          'Find the path (`command -v claude`) and set it in the hub environment ' +
          '(e.g. the EnvironmentVariables key of the launchd plist, or the systemd unit), ' +
          'then restart the hub. Or run `install.sh`, which fills it in for you.',
      );
    }
    const st = await stat(bin).catch(() => null);
    if (st === null || !st.isFile()) {
      throw new LedgerError(
        503,
        'UNAVAILABLE',
        `LEDGER_CLAUDE_BIN=${bin} is not a file — fix the path in the hub environment and restart the hub.`,
      );
    }
    // A8-4 gate.
    const status = await this.trust();
    const blocked = claudeBinBlockReason(status);
    if (status.state !== 'ok' || status.path === null) {
      throw new LedgerError(503, 'UNAVAILABLE', blocked ?? `LEDGER_CLAUDE_BIN=${bin} could not be verified.`);
    }
    // Spawn the verified realpath, not the (possibly symlinked) configured one.
    return status.path;
  }

  /** `ledger-keeper.md` without its frontmatter — the role text, nothing else. */
  async systemPrompt(): Promise<string> {
    const dir = this.deps.config.agentsDir;
    if (dir === null) throw new LedgerError(503, 'UNAVAILABLE', AGENTS_DIR_UNSET);
    const file = join(dir, AGENT_FILE);
    const raw = await readFile(file, 'utf8').catch(() => null);
    if (raw === null) {
      throw new LedgerError(
        503,
        'UNAVAILABLE',
        `${file} not found — headless triage needs the ledger-keeper agent (SPEC §14.3).`,
      );
    }
    return stripFrontmatter(raw).trim();
  }

  /* ---------------- public runs ---------------- */

  async runIntake(input: { ids: string[]; session?: string | null }): Promise<HeadlessRun> {
    const ids = input.ids.slice(0, 20);
    const prompt = [
      'Triage the intake of the ledger hub.',
      `Records to process: ${ids.join(', ')}.`,
      'Procedure: for each record `ledger intake ls --new` / `ledger show`, split the text into items',
      'by your rules (repo, kind, priority, owner, plan), dedupe before each `ledger add`',
      '(`ledger ls --repo <r> --open`), and close the record with',
      '`ledger intake triage <id> --items … [--drop "text::reason"] --status triaged|partial`.',
      'Do not perform the work the text describes — only record it. At the end print your Output contract.',
    ].join('\n');
    return this.enqueue('intake', ids.join(',') || null, prompt);
  }

  async runGroom(input: { repo?: string | null; session?: string | null } = {}): Promise<HeadlessRun> {
    const prompt = [
      'Groom the ledger as the ledger-keeper.',
      input.repo ? `Repo: ${input.repo}.` : 'All repos.',
      'Look at: `doing` with no movement for > 3 days → `ledger release` with a note · duplicates → `ledger dup`',
      '· BACKLOG with no movement for > 30 days → only report · `blocked` whose blockers are closed → report.',
      // The vocabulary in dedupe-vocab.ts catches the mechanical half of duplicates
      // at `ledger add` time. The rest ("Session rotation on sign-out" /
      // "Session invalidation after sign-out") needs reading, and reading is what
      // this run is for — but a merge is destructive, so the default on doubt is
      // a note, not a `dup`.
      'Then look for semantic duplicates that the vocabulary does not catch —',
      'the same problem written in different words.',
      // B1-7: a headless run never merges on its own — no human read the
      // pair, it was triggered by a schedule. Always propose, never `dup`.
      'NEVER merge a duplicate yourself (`ledger dup --into` does not belong here) — even for a',
      'clear-cut match only `ledger note <ID> "possible duplicate of <ID2>"` on both',
      'items, or record the second one as `--proposed`. The merge is done by the orchestrator',
      'after a human has looked at it and confirmed it in chat.',
      `At most ${GROOM_SEMANTIC_DUP_CAP} duplicate proposals per run — put the rest in the report.`,
      'Do not discard anything without a reason. At the end print your Output contract.',
    ].join('\n');
    return this.enqueue('groom', input.repo ?? null, prompt);
  }

  /* ---------------- queue + spawn ---------------- */

  /** At most one child at a time; callers line up behind the chain. */
  private enqueue(kind: 'intake' | 'groom', ref: string | null, prompt: string): Promise<HeadlessRun> {
    this.waiting += 1;
    const run = this.chain.then(
      async () => {
        this.waiting -= 1;
        return this.execute(kind, ref, prompt);
      },
      async () => {
        this.waiting -= 1;
        return this.execute(kind, ref, prompt);
      },
    );
    // The chain must never reject, or every later run would short-circuit.
    this.chain = run.catch(() => undefined);
    return run;
  }

  private async execute(
    kind: 'intake' | 'groom',
    ref: string | null,
    prompt: string,
  ): Promise<HeadlessRun> {
    const bin = await this.binary();
    const system = await this.systemPrompt();
    const started = (this.deps.now ?? Date.now)();
    this.running = true;
    try {
      const res = await this.spawnClaude(bin, prompt, system, kind);
      const text = sanitizeField(resultText(res.stdout) || res.stderr.trim(), MAX_RESULT);
      const run: HeadlessRun = {
        kind,
        ref,
        at: isoLocal(new Date(started)),
        ok: res.code === 0,
        text,
        exit_code: res.code,
        ms: (this.deps.now ?? Date.now)() - started,
      };
      this.last = run;
      if (kind === 'groom') this.lastGroom = run;
      await this.journal(kind, run);
      return run;
    } finally {
      this.running = false;
    }
  }

  private spawnClaude(
    bin: string,
    prompt: string,
    system: string,
    kind: 'intake' | 'groom',
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const spawnFn = this.deps.spawnFn ?? spawn;
    const args = buildHeadlessArgs(this.deps.ledger.paths.root, prompt, system);
    const env = childEnv(this.deps.env, {
      LEDGER_HUB_HEADLESS: '1',
      LEDGER_AGENT: 'ledger-keeper',
      LEDGER_SESSION: `headless-${kind}-${Date.now().toString(36)}`,
      LEDGER_DIR: this.deps.ledger.paths.root,
    });
    return new Promise((resolvePromise) => {
      const child = spawnFn(bin, args, {
        cwd: this.deps.ledger.paths.root,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
      });
      let stdout = '';
      let stderr = '';
      let killed = false;
      const timer = setTimeout(() => {
        killed = true;
        child.kill('SIGKILL');
      }, this.deps.config.headlessTimeoutMs);
      timer.unref?.();
      child.stdout?.on('data', (d: Buffer) => {
        if (stdout.length < MAX_STDOUT) stdout += d.toString('utf8');
        else if (!killed) {
          killed = true;
          child.kill('SIGKILL');
        }
      });
      child.stderr?.on('data', (d: Buffer) => {
        if (stderr.length < MAX_STDOUT) stderr += d.toString('utf8');
      });
      child.on('error', (err) => {
        clearTimeout(timer);
        resolvePromise({ code: -1, stdout, stderr: `${stderr}\n${String(err)}` });
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolvePromise({
          code: killed ? -1 : code,
          stdout,
          stderr: killed ? `${stderr}\ntimeout ${this.deps.config.headlessTimeoutMs} ms` : stderr,
        });
      });
    });
  }

  private async journal(kind: 'intake' | 'groom', run: HeadlessRun): Promise<void> {
    const type = kind === 'intake' ? 'intake.triaged' : 'groom';
    try {
      await this.deps.ledger.appendJournalEvent('ops', 'headless', type, [
        `headless ${kind}${run.ref ? ` ${run.ref}` : ''}`,
        run.ok ? 'ok' : `failed (exit ${run.exit_code})`,
        `${run.ms} ms`,
        run.text || '—',
      ]);
    } catch (err) {
      this.deps.ledger.log(`headless journal failed: ${String(err)}`);
    }
  }
}

/* ---------------- helpers ---------------- */

/**
 * The `--allowedTools`/`--disallowedTools` argv for the headless child —
 * audit H3/J2. `//<path>/**` is the absolute-path form of a Read rule
 * (relative patterns resolve against the settings file, not the cwd).
 *
 * The old blanket `Read(~/.claude/**)` deny was BROADER than intended: the
 * default ledger lives at `~/.ledger`, so it also shadowed the ledger
 * allow rule above it and the triage agent could read nothing at all (J2).
 *
 * K6: the fix was an enumerated denylist rather than "deny `~/.claude/**`,
 * allow the ledger back in" — that inversion is exactly the shape that broke
 * J2 in the first place, and nothing here proves a narrower allow always wins
 * over a broader deny for every future `claude` version. So the denylist
 * stays explicit, and instead is made to actually cover the whole known
 * `~/.claude` layout — settings (hook commands, permissions), credentials,
 * per-project transcripts, every other known state/cache subdir (agents,
 * agent-memory, backups, sessions, session-env, shell-snapshots, plans,
 * file-history, plugins, skills, paste-cache, cache, debug, ide), root-level
 * config files, and this hub's own `.hub` state dir (token, DB) inside the
 * ledger, wherever the ledger happens to live. A non-default ledger placed
 * inside one of these subdirs is out of scope (default install only).
 */
/**
 * R3-01/03: the same enumerated `~/.claude` denylist the headless triage
 * runner uses (K6 above), reused verbatim by the reply worker
 * (`replies.ts`) so both children treat "readable but not `~/.claude`
 * secrets/state, except the ledger" identically instead of drifting into two
 * slightly different lists over time.
 */
export const CLAUDE_HOME_READ_DENYLIST: readonly string[] = [
  'Read(~/.ssh/**)',
  'Read(~/.aws/**)',
  'Read(**/.env*)',
  'Read(~/.claude/settings*.json)',
  'Read(~/.claude/.credentials.json)',
  'Read(~/.claude/projects/**)',
  // K6: rest of the known `~/.claude` layout — same reasoning as `projects/`
  // above (agent transcripts, memory, session state, caches). Never the
  // `ledger` dir itself: that is where the allow rule above lives.
  'Read(~/.claude/agents/**)',
  'Read(~/.claude/agent-memory/**)',
  'Read(~/.claude/backups/**)',
  'Read(~/.claude/sessions/**)',
  'Read(~/.claude/session-env/**)',
  'Read(~/.claude/shell-snapshots/**)',
  'Read(~/.claude/plans/**)',
  'Read(~/.claude/file-history/**)',
  'Read(~/.claude/plugins/**)',
  'Read(~/.claude/skills/**)',
  'Read(~/.claude/paste-cache/**)',
  'Read(~/.claude/cache/**)',
  'Read(~/.claude/debug/**)',
  'Read(~/.claude/ide/**)',
  'Read(~/.claude/*.json)',
  'Read(~/.claude/*.jsonl)',
  'Read(~/.claude/*.md)',
  'Read(~/.ledger/.hub/**)',
  // `Read(~/.claude/settings*.json)` above anchors on the `.json`
  // suffix, so every backup this repo's own installer writes
  // (`settings.json.bak.<ts>`) fell OUTSIDE the deny list — a verbatim copy of
  // the settings file, including whatever tokens live in `env`. Unanchored.
  'Read(~/.claude/settings*)',
  // The rest of the `~/.claude` layout that the K6 sweep missed. Each
  // one holds either session state or prompt/telemetry history.
  'Read(~/.claude/skills-disabled/**)',
  'Read(~/.claude/todos/**)',
  'Read(~/.claude/commands/**)',
  'Read(~/.claude/logs/**)',
  'Read(~/.claude/statsig/**)',
  'Read(~/.claude/local/**)',
  // `Read(~/.ssh/**)` is the intended rule, but whether `**` covers a
  // file sitting DIRECTLY in `~/.ssh` (`config`, `id_ed25519`) rather than a
  // nested path is a Claude Code glob detail we do not control and cannot
  // pin. The single-star sibling costs nothing and removes the question.
  'Read(~/.ssh/*)',
  'Read(~/.aws/*)',
];

/**
 * Deny rules for shell constructs that turn an allowed command prefix
 * into an arbitrary one.
 *
 * The worker's allow list names command PREFIXES (`Bash(git status*)`). The
 * trailing `*` is the whole problem: `git status --porcelain | sh` matches that
 * prefix as a plain string, and if Claude Code compares the raw command line
 * rather than the parsed first command, the allow rule hands over a shell.
 * Deny wins over allow, so denying the constructs themselves closes it
 * regardless of which matching strategy the build uses.
 *
 * These are belt-and-braces: the audit could not get the model to emit the
 * command, which is evidence about the model, not about the sandbox.
 */
export const SHELL_ESCAPE_DENYLIST: readonly string[] = [
  // pipe into an interpreter
  'Bash(*|*sh *)',
  'Bash(*|*sh)',
  'Bash(*|*bash*)',
  'Bash(*|*zsh*)',
  'Bash(*|*python*)',
  'Bash(*|*perl*)',
  'Bash(*|*ruby*)',
  'Bash(*|*node*)',
  // command chaining past the allowed prefix
  'Bash(*;*)',
  'Bash(*&&*)',
  'Bash(*||*)',
  'Bash(*&)',
  // command substitution
  'Bash(*$(*)',
  'Bash(*`*)',
  // process/redirect tricks
  'Bash(*<(*)',
  'Bash(*>(*)',
  'Bash(*eval *)',
  'Bash(*exec *)',
  'Bash(*xargs*)',
  // git's own escape hatches: config/exec paths that run arbitrary binaries
  'Bash(*--upload-pack*)',
  'Bash(*--receive-pack*)',
  'Bash(*--exec-path*)',
  // NOT denied here: `git -c …` and `core.hooksPath` in general. The worker's
  // own allow rule is `Bash(git -c core.hooksPath=/dev/null commit -m *)` — it
  // disables repo hooks on purpose — and deny beats allow, so a blanket deny
  // would silently remove the worker's ability to commit at all.
  'Bash(*core.fsmonitor*)',
  'Bash(*core.sshCommand*)',
  'Bash(*core.pager*)',
  'Bash(*sequence.editor*)',
  'Bash(*GIT_SSH*)',
  'Bash(*GIT_EXTERNAL_DIFF*)',
  // H23-1: the allow rule is narrowed to `-m *`, but deny beats allow, so
  // belt-and-braces against a build that matches the allow prefix loosely —
  // `-F <file>`/`--file=<file>` reads an arbitrary file as the commit
  // message (e.g. `~/.ssh/id_ed25519`); `--gpg-sign`/`-S` and `--template`
  // are the same class of "commit flag runs something the worker doesn't
  // control".
  'Bash(*commit*-F*)',
  'Bash(*commit*--file*)',
  'Bash(*--gpg-sign*)',
  'Bash(*-S *)',
  'Bash(*--template*)',
];

export function buildHeadlessArgs(ledgerRoot: string, prompt: string, system: string): string[] {
  const ledgerRootAbs = ledgerRoot.replace(/^\/+/, '');
  return [
    '-p',
    prompt,
    '--append-system-prompt',
    system,
    // Variadic flag: each tool is its own argv entry, never one joined string.
    '--allowedTools',
    'Bash(ledger *)',
    `Read(//${ledgerRootAbs}/**)`,
    '--disallowedTools',
    ...CLAUDE_HOME_READ_DENYLIST,
    ...SHELL_ESCAPE_DENYLIST,
    `Read(//${ledgerRootAbs}/.hub/**)`,
    '--permission-mode',
    'default',
    '--output-format',
    'json',
  ];
}

/** Ambient env vars the headless `claude` child gets from the hub's own
 *  process — never the whole `process.env` (audit H2). This hub may hold
 *  `ANTHROPIC_API_KEY`, `GH_TOKEN`, `AWS_*` or other `*_TOKEN`/`*_SECRET`
 *  values for its own purposes; the child only needs to resolve a shell, log
 *  in via the subscription/keychain (no env var involved on macOS — that is
 *  an OS keychain ACL, not a credential we pass), reach `ledger`, and behave on
 *  a network that requires a proxy or a custom CA bundle (J5). */
const ENV_ALLOWLIST = new Set([
  'HOME', 'PATH', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'TMPDIR', 'TERM',
  'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy',
  'SSL_CERT_FILE', 'NODE_EXTRA_CA_CERTS',
]);

/**
 * Child env: an allowlist, never `process.env`. Shared with the reply
 * worker so both spawn paths have exactly one definition of what leaks into a
 * child (no `*_TOKEN`, no `*_KEY`).
 */
export function childEnv(extra: NodeJS.ProcessEnv | undefined, ledgerVars: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (ENV_ALLOWLIST.has(key) || key.startsWith('LC_') || key.startsWith('LEDGER_')) out[key] = value;
  }
  if (extra !== undefined) {
    for (const [key, value] of Object.entries(extra)) {
      if (value !== undefined) out[key] = value; // hub-injected (tests, config), not ambient
    }
  }
  return { ...out, ...ledgerVars };
}

/** `--- … ---` at the very top only. A `---` inside the body is a horizontal
 *  rule and must survive. */
export function stripFrontmatter(raw: string): string {
  if (!raw.startsWith('---')) return raw;
  const end = raw.indexOf('\n---', 3);
  if (end < 0) return raw;
  const after = raw.indexOf('\n', end + 1);
  return after < 0 ? '' : raw.slice(after + 1);
}

/** `--output-format json` gives `{ result, is_error, … }`; fall back to raw. */
export function resultText(stdout: string): string {
  const trimmed = stdout.trim();
  if (trimmed === '') return '';
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed) as { result?: unknown; error?: unknown };
      if (typeof parsed.result === 'string') return parsed.result;
      if (typeof parsed.error === 'string') return parsed.error;
    } catch {
      /* not JSON after all — fall through */
    }
  }
  return trimmed;
}

/**
 * Monday 09:00 local. Computed rather than "every 7 days" so a hub that runs for
 * months does not drift into Saturday night, and so a restart does not re-run a
 * groom that already happened today.
 */
export function nextMondayNine(from: Date): Date {
  const next = new Date(from.getTime());
  next.setHours(9, 0, 0, 0);
  const day = next.getDay(); // 0 Sun … 1 Mon
  let add = (1 - day + 7) % 7;
  if (add === 0 && next.getTime() <= from.getTime()) add = 7;
  next.setDate(next.getDate() + add);
  return next;
}
