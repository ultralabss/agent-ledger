/**
 * Agent hook handlers (Claude Code hook protocol) — SPEC §10.2, F1 subset.
 *
 * Verified against the current hook contract (code.claude.com/docs/en/hooks):
 *  - stdin JSON carries `session_id`, `transcript_path`, `cwd`,
 *    `hook_event_name`, `permission_mode`; SessionStart adds `source`,
 *    SessionEnd adds `reason`, Pre/PostToolUse add `tool_name` / `tool_input`
 *    (`file_path`, `notebook_path`, `command`) and PostToolUse `tool_response`.
 *    Inside a subagent there is also `agent_id` / `agent_type`, and
 *    `session_id` is the *parent's* — which is exactly why `touched` records
 *    `agent_type` separately instead of inventing a child session.
 *  - for SessionStart and UserPromptSubmit, plain stdout on exit 0 is appended
 *    to the model's context, so these handlers return TEXT, not JSON.
 *  - PostToolUse / PreToolUse / Stop produce nothing in F1. F2 will have
 *    PreToolUse return the `hookSpecificOutput.permissionDecision` envelope;
 *    the transport already passes any body through untouched, so that is a
 *    handler change only.
 *
 * Every handler is fail-soft: an unknown repo, an unreadable path or a git
 * error must never turn into a non-200, because the CLI treats any failure as
 * "hub is down" and the hook then silently stops recording.
 */

import type { HookEvent, HookInput } from '@agent-ledger/shared';
import { frameUntrusted, isOpen, repoKindOf, shortSession, untrustedSnippet } from '@agent-ledger/shared';
import type { RuntimeStore } from './db/store.ts';
import { buildBrief } from './brief.ts';
import { buildDelta } from './delta.ts';
import type { Coordination } from './coord.ts';
import type { EditGuard } from './guard/edit-guard.ts';
import type { GitGuard } from './guard/git-guard.ts';
import { isExcludedPath } from './guard/globs.ts';
import {
  postToolUseOutput,
  preToolUseDeny,
  stopBlock,
  RECAP_BLOCK_REASON,
  type PostToolMode,
} from './guard/output.ts';
import { checkRecap } from './guard/recap.ts';
import type { GuardSwitch } from './guard/switch.ts';
import { evaluateWorkerBash, isWorkerDeniedEditPath, WORKER_EDIT_DENY_REASON } from './guard/worker-guard.ts';
import type { Ledger } from './ledger/ledger.ts';
import { collectOnboardFacts, discoverRepos, type DiscoveredRepo } from './onboard.ts';
import type { GitCache } from './repowatch.ts';
import { realpathOrParent, slugify, type Sessions } from './sessions.ts';
import { resolveCheckout } from './git.ts';
import { relatedLines } from './related.ts';
import { fileMemory } from './filememory.ts';
import type { Summarizer } from './summary.ts';
import type { PendingMarks } from './pendingmark.ts';
import { staleContextLine } from './stalecontext.ts';

/** Tools whose PostToolUse means "this session edited this file". */
const EDIT_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'edit', 'write']);

/** SPEC §14.3: inside `ledger-keeper` the only allowed Bash is `ledger …`. */
const KEEPER_AGENT = 'ledger-keeper';

/** How long a finished Bash window stays comparable. */
const WINDOW_KEEP_MS = 60_000;

interface BashWindow {
  checkout: string;
  session: string;
  start: number;
  /** `MAX_SAFE_INTEGER` while the command is still running. */
  end: number;
}

export interface HookResult {
  /** Printed verbatim by `ledger hook` on stdout. Empty = print nothing. */
  body: string;
  /** SessionStart only — the CLI appends these to `$CLAUDE_ENV_FILE`. */
  env?: { session: string; repo: string | null };
}

export interface HooksDeps {
  ledger: Ledger;
  store: RuntimeStore;
  sessions: Sessions;
  gitCache: GitCache;
  /** Delay before the Bash `git status` attribution pass (SPEC §6.3: 2 s). */
  bashDelayMs?: number;
  /** Test seam: await the background Bash pass instead of firing and forgetting. */
  awaitBackground?: boolean;
  /* ---- F2 ---- */
  guard?: GuardSwitch;
  editGuard?: EditGuard;
  gitGuard?: GitGuard;
  coord?: Coordination;
  /** `additionalContext` (default) or the `decision: block` fallback. */
  postToolMode?: PostToolMode;
  /** Roots a `transcript_path` may resolve into (Stop recap check). */
  transcriptRoots?: string[];
  /** `LEDGER_RECAP_GUARD`: the Stop-hook recap check. Off (default) = Stop does nothing. */
  recapGuard?: boolean;
  /** `LEDGER_RECAP_TAGS`: state tags that need an item id on the same recap line. */
  recapTags?: readonly string[];
  /** False in tests, whose repos live under `tmpdir()`. */
  excludeTemp?: boolean;
  /** `⚠ hub: …` or null. Built in `server.ts` (one source for the
   *  brief, the hook and healthz). */
  health?: () => string | null;
  /* ---- v0.4.0 ---- */
  /** Rolling session summary. Optional so F0/F1 test configs still
   *  construct `Hooks` with nothing but the four core deps. */
  summarizer?: Summarizer;
  /** `<ledger>/.hub/inbox-pending/<session>`. */
  pending?: PendingMarks;
}

export class Hooks {
  private readonly deps: HooksDeps;
  /** Background Bash attribution passes — awaited by tests via `settled()`. */
  private background: Promise<unknown> = Promise.resolve();
  /**
   * Guard warnings raised in PreToolUse, handed to the next PostToolUse of the
   * same session. PreToolUse has no context channel of its own for an *allowed*
   * call, and a warning printed on stdout there would be read as a hook error.
   * Bounded per session and cleared on read, so a session that never edits again
   * costs one string.
   */
  private readonly pendingNotes = new Map<string, string[]>();
  /** Bash windows per checkout, newest last. See `attributeBash`. */
  private bashWindows: BashWindow[] = [];

  constructor(deps: HooksDeps) {
    this.deps = deps;
  }

  settled(): Promise<unknown> {
    return this.background;
  }

  async handle(event: HookEvent, input: HookInput): Promise<HookResult> {
    switch (event) {
      case 'session-start':
        return this.sessionStart(input);
      case 'user-prompt-submit':
        return this.userPromptSubmit(input);
      case 'post-tool-use':
        return this.postToolUse(input);
      case 'pre-tool-use':
        return this.preToolUse(input);
      case 'stop':
        return this.stop(input);
      case 'session-end':
        return this.sessionEnd(input);
      default:
        return { body: '' };
    }
  }

  /* ---------------- SessionStart ---------------- */

  private async sessionStart(input: HookInput): Promise<HookResult> {
    const started = await this.deps.sessions.start({
      id: input.session_id,
      cwd: input.cwd ?? null,
      transcript_path: input.transcript_path ?? null,
      source: input.source ?? null,
    });
    // Awaited here (unlike the other two hooks): SessionStart already does git
    // and ledger IO, and the brief below prints the live sessions — a title
    // that lands one hook later would leave the first brief nameless.
    await this.scheduleTitle(input);

    const blocks: string[] = [];

    // A degraded hub is the FIRST line a session sees. The git lockdown
    // that stopped the ledger from committing went unnoticed for a day because
    // it only ever appeared in hub.log.
    const health = this.deps.health?.() ?? null;
    if (health !== null) blocks.push(health);

    if (started.repo === null) {
      blocks.push(await this.noRepoBlock(input.cwd ?? null));
    } else {
      if (!this.deps.ledger.isOnboarded(started.repo)) {
        blocks.push(this.onboardingBlock(started.repo, started.autoRegistered));
      }
      if (started.checkout) {
        // Fresh git state for the header — the briefing is worthless with a
        // stale branch, and this is the one place latency does not matter.
        await this.deps.gitCache.refresh(started.checkout, started.repo);
      }
      // A `resume` whose ledger has not moved since this session's last
      // brief gets one line. Re-reading 30 unchanged lines after every
      // compaction was measured as the biggest single repeated cost in a
      // session, and the agent already has the content above it in context.
      const unchanged =
        input.source === 'resume' ? this.briefUnchanged(input.session_id, started.repo) : null;
      if (unchanged !== null) {
        blocks.push(unchanged);
      } else {
        blocks.push(
          await buildBrief(this.deps.ledger, {
            repo: started.repo,
            live: {
              sessions: this.deps.sessions.list({ repo: started.repo, liveOnly: true }),
              self: started.session.id,
              git: started.checkout ? this.headView(started.checkout) : null,
              orphans: this.deps.sessions.orphans({ repo: started.repo }),
            },
            staleContext: await this.staleContext(started.repo),
            // `startup` is the lean shape (3 queue rows). `clear` and
            // `compact` keep the full one — they are the cases where the agent
            // just lost its context and needs more, not less.
            lean: input.source === 'startup',
          }),
        );
      }
      this.markBrief(input.session_id, started.repo);
    }

    // A resumed session already has history — show it what moved while
    // it was away. A fresh `startup` gets the full brief instead, which already
    // covers the current state.
    if (input.source === 'resume') {
      const delta = this.deltaText(input.session_id);
      if (delta !== '') blocks.push(delta);
    }

    if (started.revived && started.returnedOrphans.length > 0) {
      blocks.push(
        `Revived session: you have ${started.returnedOrphans.length} uncommitted files back — ${started.returnedOrphans
          .slice(0, 5)
          .map((o) => o.rel_path)
          .join(', ')}`,
      );
    }

    const unprocessed = this.deps.ledger.listIntakeUnprocessed();
    if (unprocessed.length > 0) blocks.push(`Intake: ${unprocessed.length} unprocessed`);

    // SPEC §10: an off guard has to be visible, otherwise a session works
    // for an hour believing it is protected.
    if (this.deps.guard && !this.deps.guard.enabled) blocks.push(this.deps.guard.line());

    return {
      body: `${blocks.join('\n').replace(/\n+$/, '')}\n`,
      env: { session: started.session.id, repo: started.repo },
    };
  }

  /**
   * The one-line answer for a `resume` with nothing new, or null when a
   * full brief is owed.
   *
   * "Nothing new" is two comparisons: the change log has not advanced, and the
   * digest of what the brief would say (open/doing counts, the human queue, the
   * live sessions, the newest journal stamp) is identical. The change log alone
   * is not enough — a commit, an orphan or another session starting moves the
   * brief without writing an item change.
   */
  private briefUnchanged(session: string, repo: string): string | null {
    try {
      const mark = this.deps.store.getBriefMark(session, repo);
      if (mark === null) return null;
      if (mark.change_seq !== this.deps.store.latestChangeSeq()) return null;
      if (mark.digest !== this.briefDigest(repo)) return null;
      const mins = Math.round((Date.now() - mark.at) / 60_000);
      return `${repo}: ledger unchanged since ${hhmm(mark.at)} (${
        mins <= 1 ? 'just now' : `${mins} min ago`
      }) · ledger brief for details`;
    } catch {
      return null;
    }
  }

  private markBrief(session: string, repo: string): void {
    try {
      this.deps.store.putBriefMark({
        session,
        repo,
        change_seq: this.deps.store.latestChangeSeq(),
        digest: this.briefDigest(repo),
      });
    } catch {
      /* a missing mark only means the next resume gets the full brief */
    }
  }

  /** Cheap fingerprint of everything the repo brief renders. Not a hash of the
   *  brief text: building the brief to decide whether to build it would defeat
   *  the point. */
  private briefDigest(repo: string): string {
    const items = this.deps.ledger.listItems({ repo });
    let open = 0;
    let doing = 0;
    let human = 0;
    let updated = '';
    for (const i of items) {
      if (!isOpen(i.fm.status)) continue;
      open += 1;
      if (i.fm.status === 'doing') doing += 1;
      if (i.fm.owner === 'human') human += 1;
      if (i.fm.updated > updated) updated = i.fm.updated;
    }
    // `session.start` / `session.end` are excluded on purpose: the SessionStart
    // hook writes one *before* this runs, so counting them would make every
    // resume look changed and the lean path would never fire.
    const journal = this.deps.ledger
      .listJournal(repo)
      .filter((e) => e.type !== 'session.start' && e.type !== 'session.end');
    const live = this.deps.sessions.list({ repo, liveOnly: true }).length;
    const orphans = this.deps.sessions.orphans({ repo }).length;
    const intake = this.deps.ledger.listIntakeUnprocessed().length;
    return [
      items.length,
      open,
      doing,
      human,
      updated,
      journal.length,
      journal[0]?.at ?? '',
      live,
      orphans,
      intake,
    ].join('|');
  }

  /** Kept off the brief's synchronous path (it needs one `stat`). */
  private async staleContext(repo: string): Promise<string | null> {
    try {
      return await staleContextLine(
        { store: this.deps.store, paths: this.deps.ledger.paths },
        repo,
      );
    } catch {
      return null;
    }
  }

  /** ≤ 12 lines. The wording is an instruction to the agent, not a report. */
  private onboardingBlock(slug: string, justCreated: boolean): string {
    const cfg = this.deps.ledger.repo(slug);
    const kind = repoKindOf(cfg);
    const path =
      this.deps.ledger.repoPath(slug) ??
      (kind === 'repo' ? '—' : kind === 'system' ? 'system' : `vps${cfg.host ? ` ${cfg.host}` : ''}`);
    return [
      `ONBOARDING: for repo ${slug} (${path}) the ledger ${
        justCreated ? 'had nothing — just created' : 'is not finished yet'
      } (prefix ${cfg.prefix}).`,
      'Tell the user in one sentence that you are setting up the ledger for this repo, and do:',
      '  1) ledger onboard → facts about the repo',
      `  2) fill in ~/.ledger/${slug}/CONTEXT.md (use an exploration agent for the structure)`,
      '  3) existing TODO/BACKLOG files → ledger-keeper import',
      '  4) ledger log "onboarding"',
      `  5) ledger repo onboarded ${slug}`,
      "Then continue with the user's request.",
    ].join('\n');
  }

  /** cwd outside any git repo: say so, list what is nearby, say how to decide. */
  private async noRepoBlock(cwd: string | null): Promise<string> {
    const lines: string[] = [];
    const abs = cwd === null ? null : await realpathOrParent(cwd);
    lines.push(`NO REPO: cwd ${cwd ?? '?'} is not a git repo.`);
    if (abs !== null) {
      const found = await discoverRepos(abs, async (layout) =>
        this.deps.sessions.repoForCheckout(layout),
      );
      if (found.repos.length > 0) {
        lines.push('Git repos under cwd:');
        for (const r of found.repos) lines.push(`  ${r.path} — ${r.slug ?? 'unregistered'}`);
        if (found.truncated) lines.push(`  … +more (showing ${found.repos.length})`);
      } else {
        lines.push('No git repo found under cwd (depth 3).');
      }
    }
    const registered = Object.keys(this.deps.ledger.repos()).sort();
    if (registered.length > 0) lines.push(`Registered repos: ${registered.join(', ')}`);
    lines.push(
      'When the user gives work and the repo is unclear: ask (AskUserQuestion) which repo, or a new repo / monorepo / separate repos and stack; after the answer set it up (git init / ledger repo add) and do the ONBOARDING.',
    );
    return lines.join('\n');
  }

  private headView(checkout: string): {
    head: string | null;
    branch: string | null;
    ahead: number | null;
    behind: number | null;
    detached: boolean;
    refreshed_at: string | null;
  } | null {
    const row = this.deps.store.getGitCache(checkout);
    if (!row) return null;
    return {
      head: row.head,
      branch: row.branch,
      ahead: row.ahead,
      behind: row.behind,
      detached: row.branch === null,
      refreshed_at: new Date(row.refreshed_at).toISOString(),
    };
  }

  /* ---------------- UserPromptSubmit ---------------- */

  private userPromptSubmit(input: HookInput): HookResult {
    this.deps.sessions.heartbeat(input.session_id);
    void this.scheduleTitle(input);
    // Plain stdout on exit 0 is appended to the model's context for this event,
    // so the inbox travels as text — no envelope (SPEC §10.2).
    // The delta goes FIRST — it is context for whatever the inbox says.
    // The related-items block goes last: it is background, not an instruction, and it is the
    // one block that is usually absent.
    const blocks = [
      this.deltaText(input.session_id),
      this.inboxText(input.session_id),
      this.relatedText(input),
    ].filter((b) => b !== '');
    return { body: blocks.length === 0 ? '' : `${blocks.join('\n\n')}\n` };
  }

  /**
   * `Related: …` — on the first eligible message of a session
   * against the base threshold, on every later one against a higher bar, inside
   * a per-session budget (SPEC §9).
   *
   * The budget lives in `related.ts` (marks keyed by session id), not here, so
   * a hub restart mid-session cannot replay it. Fail-open: the prompt hook also
   * carries the delta and the inbox.
   */
  private relatedText(input: HookInput): string {
    try {
      const session = this.deps.store.getSession(input.session_id);
      return relatedLines(
        { ledger: this.deps.ledger, store: this.deps.store },
        {
          session: input.session_id,
          repo: session?.home_repo ?? null,
          checkout: session?.checkout ?? null,
          prompt: input.prompt,
        },
      );
    } catch (err) {
      this.deps.ledger.log(`related items failed: ${String(err)}`);
      return '';
    }
  }

  /**
   * What other sessions changed since this session's last message.
   *
   * The cursor is advanced even when the block is empty — that is how "first
   * prompt starts the clock" works — but only after the text is built, so a
   * throw cannot swallow a change. Fail-open: a broken delta must not break the
   * prompt hook.
   */
  private deltaText(session: string): string {
    if (this.deps.store === undefined) return '';
    try {
      const block = buildDelta(
        { ledger: this.deps.ledger, store: this.deps.store, sessions: this.deps.sessions },
        session,
      );
      if (block === null) return '';
      this.deps.store.setDeltaCursor(session, block.cursor);
      return block.text;
    } catch (err) {
      this.deps.ledger.log(`delta feed failed: ${String(err)}`);
      return '';
    }
  }

  /**
   * Refresh the session's sidebar title from its transcript.
   *
   * Runs on the background chain, never on the hook's critical path — a hook
   * has a ~1 s budget and a title is cosmetic. `Sessions.refreshTitle` owns the
   * once-per-minute throttle and swallows its own errors.
   */
  private scheduleTitle(input: HookInput): Promise<void> {
    const roots = this.deps.transcriptRoots ?? [];
    if (roots.length === 0) return Promise.resolve();
    const p = this.deps.sessions
      .refreshTitle({
        session: input.session_id,
        transcriptPath: input.transcript_path ?? null,
        roots,
      })
      .catch(() => undefined);
    this.background = this.background.then(() => p).catch(() => undefined);
    return p;
  }

  private inboxText(session: string): string {
    if (this.deps.coord) return this.deps.coord.deliver(session);
    const messages = this.deps.store.listInbox(session, true);
    if (messages.length === 0) return '';
    // B1-2: `m.body` is free text written by another session/agent
    // (or a contract notice built from a git subject) — framed once for the
    // whole block, with the body itself narrowed so it cannot fake the frame.
    // Same rule as `coord.inboxLine`: keyed off the server-set `origin`, not
    // `from_session == null` — hub-composed messages (web replies and
    // instructions, contract notices) pass through; `origin: 'session'` is
    // always framed as data, even when `from_session` happens to be null.
    const lines = messages.map(
      (m) =>
        `📥 ${shortSession(m.from_session ?? '')} ${m.repo ?? ''} ${m.item_id ?? ''} — ${
          m.origin === 'session' ? frameUntrusted(untrustedSnippet(m.body, 240)) : m.body
        }`,
    );
    this.deps.store.markInboxDelivered(messages.map((m) => m.id));
    return lines.join('\n');
  }

  /* ---------------- PreToolUse (SPEC §10.3, §10.4) ---------------- */

  /**
   * Deny prints the envelope; allow prints NOTHING (an empty body). The hook protocol
   * treats any non-JSON stdout on PreToolUse as context, so `{}` or a stray
   * newline would leak noise into every tool call.
   */
  private async preToolUse(input: HookInput): Promise<HookResult> {
    this.deps.sessions.heartbeat(input.session_id);
    const tool = input.tool_name ?? '';

    if (EDIT_TOOLS.has(tool)) {
      // R2-06: worker containment runs first and independently of the normal
      // edit guard — it must deny even when `editGuard` is undefined (F0/F1
      // test configs) or the switch is off, because it is not the lease guard.
      if (input.worker === true) {
        for (const raw of editPaths(input.tool_input)) {
          if (isWorkerDeniedEditPath(raw)) return { body: preToolUseDeny(WORKER_EDIT_DENY_REASON) };
        }
      }
      const guard = this.deps.editGuard;
      if (!guard) return { body: '' };
      const warnings: string[] = [];
      for (const raw of editPaths(input.tool_input)) {
        const res = await guard.evaluate({ session: input.session_id, absPath: raw });
        if (res.decision === 'deny' && res.reason !== null) return { body: preToolUseDeny(res.reason) };
        if (res.warning !== null) warnings.push(res.warning);
        if (res.autoLease !== null) this.noteAutoLease(input, res.autoLease);
      }
      // A rule-6 / auto-lease warning is not a denial — it rides along on the
      // PostToolUse output, where additionalContext is the documented channel.
      if (warnings.length > 0) {
        this.pendingNotes.set(input.session_id, warnings);
        // A parked note is output the hub owes, exactly like an inbox
        // message. Without this the next PostToolUse would skip the wait and
        // the note would die with the response nobody read.
        void this.deps.pending?.owe(input.session_id);
      }
      return { body: '' };
    }

    if (tool === 'Bash') {
      const command = typeof input.tool_input?.command === 'string' ? input.tool_input.command : undefined;
      if (input.worker === true && command !== undefined) {
        const workerDeny = evaluateWorkerBash(command, input.cwd ?? null);
        if (workerDeny !== null) return { body: preToolUseDeny(workerDeny) };
      }
      const keeper = this.keeperDeny(input.agent_type ?? null, command);
      if (keeper !== null) return { body: preToolUseDeny(keeper) };
      const guard = this.deps.gitGuard;
      if (!guard) return { body: '' };
      const res = await guard.evaluate({
        session: input.session_id,
        command,
        cwd: input.cwd ?? null,
      });
      if (res.decision === 'deny' && res.reason !== null) return { body: preToolUseDeny(res.reason) };
    }
    return { body: '' };
  }

  /** SPEC §14.3: a `ledger-keeper` subagent may run `ledger …` and nothing else. */
  private keeperDeny(agentType: string | null, command: string | undefined): string | null {
    if (agentType !== KEEPER_AGENT) return null;
    if (this.deps.guard && !this.deps.guard.enabled) return null;
    if (typeof command !== 'string' || command.trim() === '') return null;
    const segments = command
      .split(/&&|\|\||;|\n/)
      .map((s) => s.trim())
      .filter((s) => s !== '');
    if (segments.every((s) => /^ledger(\s|$)/.test(s))) return null;
    return (
      'ledger-keeper may run only `ledger …` in Bash (SPEC §14.3). ' +
      'Read the ledger with `ledger ls` / `ledger show` / `ledger search`, files with Read. ' +
      'Code repos and git are outside your boundaries — report it in your report.'
    );
  }

  /** Auto-lease (rule 5b) is journalled, but never on the hook's critical path. */
  private noteAutoLease(
    input: HookInput,
    lease: { repo: string; checkout: string; rel_path: string },
  ): void {
    const p = this.deps.ledger
      .appendJournalEvent(lease.repo, input.session_id, 'intrude.auto', [
        lease.rel_path,
        'auto-lease: no live session in the repo',
      ])
      .catch(() => undefined);
    this.background = this.background.then(() => p).catch(() => undefined);
  }

  /* ---------------- Stop (SPEC §10.2) ---------------- */

  private async stop(input: HookInput): Promise<HookResult> {
    this.deps.sessions.heartbeat(input.session_id);
    void this.scheduleTitle(input);
    // Already re-running because of an earlier block: blocking again is a loop.
    if (input.stop_hook_active === true) return { body: '' };
    if (this.deps.recapGuard !== true) return { body: '' };
    if (this.deps.guard && !this.deps.guard.enabled) return { body: '' };
    const roots = this.deps.transcriptRoots ?? [];
    if (roots.length === 0) return { body: '' };
    const res = await checkRecap(input.transcript_path ?? null, roots, this.deps.recapTags);
    // H3-2: `aliased`/`unreadable` are not routine — the transcript path
    // checked out under a trusted root but then failed identity/aliasing
    // verification (or vanished) between the check and the read. That is a
    // TOCTOU signal, not a quiet no-op, so it gets a log line either way.
    if (res.skipped === 'aliased' || res.skipped === 'unreadable') {
      this.deps.ledger.log(
        `recap check skipped for session ${input.session_id}: transcript ${res.skipped}`,
      );
    }
    if (!res.block) return { body: '' };
    return { body: stopBlock(RECAP_BLOCK_REASON) };
  }

  /* ---------------- PostToolUse ---------------- */

  private async postToolUse(input: HookInput): Promise<HookResult> {
    this.deps.sessions.heartbeat(input.session_id);
    const tool = input.tool_name ?? '';
    const agentType = input.agent_type ?? null;

    if (EDIT_TOOLS.has(tool)) {
      // Collected while recording, emitted below. One line per file the
      // session touches for the FIRST time, and only when the hub actually
      // knows something about it.
      const memory: string[] = [];
      for (const raw of editPaths(input.tool_input)) {
        // SPEC §10.11: a scratch file or anything under the ledger never
        // becomes somebody's uncommitted work.
        const resolvedForExclusion = await realpathOrParent(raw);
        if (
          resolvedForExclusion !== null &&
          isExcludedPath(resolvedForExclusion, {
            ledgerRoot: this.deps.ledger.paths.root,
            excludeTemp: this.deps.excludeTemp ?? true,
          })
        ) {
          continue;
        }
        const rec = await this.deps.sessions.recordEdit({
          session: input.session_id,
          absPath: raw,
          via: 'edit',
          agent_type: agentType,
        });
        if (!rec) continue;
        this.deps.gitCache.schedule(rec.checkout, rec.repo);
        this.deps.summarizer?.noteFiles(input.session_id, rec.repo, [rec.rel_path]);
        const line = await this.fileMemoryLine(input.session_id, rec);
        if (line !== '') memory.push(line);
      }
      return { body: this.postOutput(input.session_id, memory) };
    }

    if (tool === 'Bash') {
      const pass = this.attributeBash(input.session_id, agentType);
      this.background = this.background.then(() => pass).catch(() => undefined);
      if (this.deps.awaitBackground) await pass;
    }
    return { body: this.postOutput(input.session_id) };
  }

  /** Isolated so a git or ledger hiccup costs the line, not the edit. */
  private async fileMemoryLine(
    session: string,
    rec: { repo: string; checkout: string; rel_path: string },
  ): Promise<string> {
    try {
      return await fileMemory(
        { ledger: this.deps.ledger, store: this.deps.store, sessions: this.deps.sessions },
        { session, repo: rec.repo, checkout: rec.checkout, rel_path: rec.rel_path },
      );
    } catch (err) {
      this.deps.ledger.log(`file memory failed: ${String(err)}`);
      return '';
    }
  }

  /** Inbox + guard notes + file memory, in the one place that decides the
   *  PostToolUse shape. Also the one place that settles the pending marker: the
   *  debt is paid exactly when the text leaves here. */
  private postOutput(session: string, extra: readonly string[] = []): string {
    const parts: string[] = [];
    const inbox = this.inboxText(session);
    if (inbox !== '') parts.push(inbox);
    const notes = this.pendingNotes.get(session);
    if (notes !== undefined && notes.length > 0) {
      this.pendingNotes.delete(session);
      parts.push(...notes);
    }
    // Settle even when there was nothing to deliver. A marker left
    // behind by a message that was already read elsewhere (`/v1/inbox`, the
    // prompt hook) would make every later tool call wait for nothing.
    void this.deps.pending?.settle(session);
    parts.push(...extra.filter((e) => e !== ''));
    if (parts.length === 0) return '';
    return postToolUseOutput(parts.join(' · '), this.deps.postToolMode ?? 'additionalContext');
  }

  /**
   * SPEC §10.2: a Bash command (`sed`, a heredoc, a script) changes
   * files the Edit guard never sees, so attribution falls back to a `git status`
   * diff around the call. That diff is NOT evidence of who did it: with two
   * sessions in one checkout it reliably attributed session A's `Write` to
   * session B, whose Bash happened to run next.
   *
   * So the diff may only claim a path when nothing contradicts it:
   *  (a) no other session holds the path as `via: edit` — an editor write the
   *      hub actually saw always beats an inference, including a brand-new
   *      untracked file somebody else just wrote;
   *  (b) no other session's Bash ran in this checkout during our window — if it
   *      did, either of us could have done it, so the row becomes `ambiguous`
   *      (visible in `whose`, never denied by the guard).
   */
  private async attributeBash(session: string, agentType: string | null): Promise<void> {
    const row = this.deps.store.getSession(session);
    const checkout = row?.checkout ?? null;
    if (checkout === null) return;
    const repo = row?.home_repo ?? null;
    if (repo === null) return;
    const before = new Set(this.deps.gitCache.cachedDirty(checkout).map((d) => d.rel_path));
    const window: BashWindow = { checkout, session, start: Date.now(), end: Number.MAX_SAFE_INTEGER };
    this.openWindow(window);
    const delay = this.deps.bashDelayMs ?? 2_000;
    if (delay > 0) await new Promise((r) => setTimeout(r, delay).unref?.());
    await this.deps.gitCache.refresh(checkout, repo);
    window.end = Date.now();
    const concurrent = this.bashWindows.some(
      (w) =>
        w !== window &&
        w.checkout === checkout &&
        w.session !== session &&
        w.end >= window.start &&
        w.start <= window.end,
    );
    for (const entry of this.deps.gitCache.cachedDirty(checkout)) {
      if (before.has(entry.rel_path)) continue;
      const owners = this.deps.store.ownersOfPath(checkout, entry.rel_path);
      // (a) somebody's editor wrote this file — not ours to claim, ever.
      if (owners.some((o) => o.session_id !== session && o.via === 'edit')) continue;
      const via = concurrent ? 'ambiguous' : 'bash';
      if (concurrent) {
        // The other session's Bash row for the same path is just as uncertain.
        for (const o of owners) {
          if (o.via !== 'edit' && o.via !== 'ambiguous') this.deps.store.setTouchedVia(o.id, 'ambiguous');
        }
      }
      this.deps.store.touch({
        session_id: session,
        repo,
        checkout,
        rel_path: entry.rel_path,
        via,
        agent_type: agentType,
      });
    }
  }

  /** Bounded ring of recent Bash windows (ambiguity detection). */
  private openWindow(window: BashWindow): void {
    const cutoff = Date.now() - WINDOW_KEEP_MS;
    this.bashWindows = this.bashWindows.filter((w) => w.end >= cutoff || w.end === Number.MAX_SAFE_INTEGER);
    if (this.bashWindows.length > 400) this.bashWindows = this.bashWindows.slice(-200);
    this.bashWindows.push(window);
  }

  /* ---------------- SessionEnd ---------------- */

  private async sessionEnd(input: HookInput): Promise<HookResult> {
    this.pendingNotes.delete(input.session_id);
    // Summary trigger (a). Before `end()`: the summary names the session, and
    // after ending it the liveness view (and its title) is no longer "live".
    try {
      await this.deps.summarizer?.onSessionEnd(input.session_id);
    } catch (err) {
      this.deps.ledger.log(`session summary ${shortSession(input.session_id)}: ${String(err)}`);
    }
    await this.deps.sessions.end(input.session_id, input.reason ?? null);
    // Nothing can be delivered to a session that is gone.
    await this.deps.pending?.forget(input.session_id);
    return { body: '' };
  }

  /* ---------------- onboarding facts ---------------- */

  async onboardFacts(dir: string): Promise<ReturnType<typeof collectOnboardFacts>> {
    return collectOnboardFacts(dir, {
      lookup: async (layout) => {
        const slug = await this.deps.sessions.repoForCheckout(layout);
        if (slug === null) return null;
        return { slug, onboarded: this.deps.ledger.isOnboarded(slug) };
      },
      suggestSlug: slugify,
    });
  }

  /** Exposed for `GET /v1/onboard` when the caller is outside a repo. */
  async nearbyRepos(dir: string): Promise<{ repos: DiscoveredRepo[]; truncated: boolean }> {
    const abs = await realpathOrParent(dir);
    if (abs === null) return { repos: [], truncated: false };
    if (await resolveCheckout(abs)) {
      return { repos: [], truncated: false };
    }
    return discoverRepos(abs, async (layout) => this.deps.sessions.repoForCheckout(layout));
  }
}

function hhmm(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

/** Absolute paths out of a `tool_input`, whatever shape the tool used. */
export function editPaths(toolInput: Record<string, unknown> | undefined): string[] {
  if (!toolInput) return [];
  const out: string[] = [];
  const push = (v: unknown): void => {
    if (typeof v === 'string' && v.trim() !== '') out.push(v);
  };
  push(toolInput.file_path);
  push(toolInput.notebook_path);
  // MultiEdit carries one `file_path` plus an `edits` array; some clients put a
  // per-edit `file_path` inside it. Accept both, dedupe below.
  const edits = toolInput.edits;
  if (Array.isArray(edits)) {
    for (const e of edits) {
      if (e !== null && typeof e === 'object') push((e as Record<string, unknown>).file_path);
    }
  }
  return [...new Set(out)];
}
