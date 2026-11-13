/**
 * Session lifecycle + path attribution — SPEC §5, §10.2.
 *
 * Everything a hook needs to answer "which repo, which checkout, whose file" is
 * here, and every path it accepts is treated as hostile input: `realpath` first,
 * then it must land inside a registered repo's working tree, or it is dropped
 * without a write (SPEC §6.5). No `..` ever escapes, because the check is
 * "is the resolved path inside the resolved checkout", not a string prefix on
 * the raw input.
 */

import { realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, sep } from 'node:path';
import type {
  JournalEvent,
  LeaseView,
  SessionLiveness,
  SessionSource,
  SessionView,
  TouchedVia,
  TouchedView,
} from '@agent-ledger/shared';
import { isoLocal, sanitizeField, shortSession, slugSchema } from '@agent-ledger/shared';
import {
  ACTIVE_MS,
  IDLE_MS,
  LEASE_IDLE_MS,
  STALE_OWNER_MS,
  type LeaseRow,
  type RuntimeStore,
  type SessionRow,
  type TouchedRow,
} from './db/store.ts';
import type { EventBus } from './events.ts';
import { resolveCheckout, type CheckoutLayout } from './git.ts';
import type { Ledger } from './ledger/ledger.ts';
import { matchAny, toPosix } from './guard/globs.ts';
import { readTranscriptTitle } from './transcript.ts';

export interface ResolvedPath {
  repo: string;
  layout: CheckoutLayout;
  rel_path: string;
  abs: string;
}

export interface SessionStartResult {
  session: SessionView;
  repo: string | null;
  checkout: string | null;
  created: boolean;
  revived: boolean;
  /** Files this session gets back because `resume` un-ended it (SPEC §5). */
  returnedOrphans: TouchedView[];
  /** True when the hub had to register the repo itself (SPEC §4.2). */
  autoRegistered: boolean;
}

/** Cap on repos (real path, i.e. one RepoWatcher target each) the hub
 *  will register via auto-registration + manual `ledger repo add` combined. */
export const AUTO_REGISTER_LIMIT = 64;

export interface SessionsDeps {
  ledger: Ledger;
  store: RuntimeStore;
  bus: EventBus;
  now?: () => number;
}

/**
 * How a session is named in human-facing text.
 *
 * `61e0` alone is unreadable in a deny reason or a change line — the user knows
 * their sessions by the sidebar name, not by a hex prefix.
 *
 * Two forms, because the surrounding prose differs and existing output must not
 * shift:
 *  - {@link sessionTag} is the bare name, for places that already print the word
 *    "session" themselves or use a `Live:` column (`brief`, `who`),
 *  - {@link sessionLabel} includes the word, for prose ("File held by …").
 *
 * The title is untrusted text already single-lined and capped by
 * `transcript.ts`; it is truncated again here because a deny reason is read in a
 * terminal, not a table.
 */
/** A denylist of instruction-shaped phrases (`ledger override`, `ignore
 *  …`, `system …`) is trivially bypassable — any other wording reads into a
 *  deny reason, the brief, the delta feed and the inbox unmarked, exactly as
 *  prose. There is no safe allowlist of "definitely not an instruction"
 *  titles either, so every non-null title is unconditionally quoted and
 *  labelled untrusted, with no exception. */
export function sessionTag(s: Pick<SessionView, 'short' | 'title'>, max = 40): string {
  if (s.title === null || s.title === '') return s.short;
  const cap = max;
  const t = s.title.length > cap ? `${s.title.slice(0, cap - 1).trimEnd()}…` : s.title;
  return `"${t}" (session title, unverified) (${s.short})`;
}

/** Idleness for an agent-facing line — minutes under an hour, else hours. */
export function idleText(ms: number): string {
  const mins = Math.round(ms / 60_000);
  if (mins < 60) return `${mins}m`;
  return `${Math.round(mins / 6) / 10}h`;
}

/** `sessionTag` with the word "session" in front. */
export function sessionLabel(s: Pick<SessionView, 'short' | 'title'>, max = 40): string {
  return `session ${sessionTag(s, max)}`;
}

/** At most one transcript read per session per minute. */
export const TITLE_REFRESH_MS = 60_000;

/** How far back `list()` reports ended sessions (contract: 30 days). */
export const ENDED_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

export class Sessions {
  private readonly ledger: Ledger;
  private readonly store: RuntimeStore;
  private readonly bus: EventBus;
  private readonly nowFn: () => number;
  /** commonDir → slug. Rebuilt whenever `repos.yml` changes shape. */
  private repoByCommonDir = new Map<string, string>();
  private repoIndexKey = '';

  constructor(deps: SessionsDeps) {
    this.ledger = deps.ledger;
    this.store = deps.store;
    this.bus = deps.bus;
    this.nowFn = deps.now ?? Date.now;
    this.migrateWeakTouched();
  }

  /**
   * One-shot startup migration. Rows written by the old Bash-diff rules
   * cannot be trusted: a `bash` row for a path another session wrote with an
   * editor is wrong by construction, and the rest cannot be confirmed after the
   * fact, so they are downgraded to `ambiguous` (informative, never deny). The
   * clean-file half happens on the first git-cache refresh of each checkout.
   */
  private migrateWeakTouched(): void {
    try {
      const res = this.store.migrateWeakTouched();
      if (res.droppedOwnedByEdit + res.requalified === 0) return;
      this.ledger.log(
        `touched migration: deleted bash rows owned by an edit ${res.droppedOwnedByEdit}, ` +
          `requalified to ambiguous ${res.requalified}`,
      );
    } catch (err) {
      this.ledger.log(`touched migration failed: ${String(err)}`);
    }
  }

  private now(): number {
    return this.nowFn();
  }

  /* ---------------- views ---------------- */

  liveness(row: SessionRow, now = this.now()): SessionLiveness {
    if (row.ended_at !== null) return 'ended';
    const idle = now - row.last_seen;
    if (idle < ACTIVE_MS) return 'active';
    if (idle < IDLE_MS) return 'idle';
    return 'ended';
  }

  view(row: SessionRow, now = this.now()): SessionView {
    const leases = this.store.listLeases({ session: row.id, active: true });
    const touched = this.store.listTouched({ session: row.id });
    const agents = [...new Set(touched.map((t) => t.agent_type).filter((a): a is string => !!a))];
    // Union of the `leases` table and the md `claimed_by` field. The lease row
    // is the SPEC §5 record, but md is the source of truth and survives a lost
    // `hub.sqlite` (or a hand-edited item), so a claim visible in md counts
    // even when no lease row exists.
    const items = new Set(
      leases.filter((l) => l.kind === 'claim' && l.item_id).map((l) => l.item_id as string),
    );
    for (const item of this.ledger.listItems()) {
      if (item.fm.status === 'doing' && item.fm.claimed_by?.session === row.id) items.add(item.fm.id);
    }
    return {
      id: row.id,
      home_repo: row.home_repo,
      cwd: row.cwd,
      checkout: row.checkout,
      branch: row.branch,
      transcript_path: row.transcript_path,
      title: row.title,
      title_source: row.title_source,
      started_at: isoLocal(new Date(row.started_at)),
      last_seen: isoLocal(new Date(row.last_seen)),
      ended_at: row.ended_at === null ? null : isoLocal(new Date(row.ended_at)),
      source: row.source,
      liveness: this.liveness(row, now),
      idle_ms: Math.max(0, now - row.last_seen),
      short: shortSession(row.id),
      items: [...items].sort(),
      agents,
      touched_count: touched.length,
    };
  }

  touchedView(row: TouchedRow, now = this.now()): TouchedView {
    const owner = this.store.getSession(row.session_id);
    const orphan = owner === null || this.liveness(owner, now) === 'ended';
    return {
      id: row.id,
      session: row.session_id,
      repo: row.repo,
      checkout: row.checkout,
      rel_path: row.rel_path,
      via: row.via,
      agent_type: row.agent_type,
      first_at: isoLocal(new Date(row.first_at)),
      last_at: isoLocal(new Date(row.last_at)),
      committed_sha: row.committed_sha,
      orphan,
    };
  }

  leaseView(row: LeaseRow): LeaseView {
    let paths: string[] = [];
    try {
      const parsed: unknown = JSON.parse(row.paths);
      if (Array.isArray(parsed)) paths = parsed.filter((p): p is string => typeof p === 'string');
    } catch {
      paths = [];
    }
    return {
      id: row.id,
      session: row.session_id,
      repo: row.repo,
      checkout: row.checkout,
      kind: row.kind,
      item_id: row.item_id,
      paths,
      intent: row.intent,
      created_at: isoLocal(new Date(row.created_at)),
      released_at: row.released_at === null ? null : isoLocal(new Date(row.released_at)),
    };
  }

  /**
   * Live = not ended and seen within 24 h (SPEC §5: idle still holds files).
   *
   * Without `liveOnly` the list also carries the ended tail, bounded to
   * {@link ENDED_WINDOW_MS}: the UI wants "what ran here recently", and an
   * unbounded tail would return every session the machine ever had.
   */
  list(
    filter: { repo?: string; repos?: readonly string[]; liveOnly?: boolean } = {},
  ): SessionView[] {
    const now = this.now();
    const rows = this.store.listSessions({
      repo: filter.repo,
      repos: filter.repos,
      includeEnded: !filter.liveOnly,
      seenSince: filter.liveOnly ? undefined : now - ENDED_WINDOW_MS,
    });
    return rows
      .map((r) => this.view(r, now))
      .filter((v) => (filter.liveOnly ? v.liveness !== 'ended' : true));
  }

  /* ---------------- session title ---------------- */

  /**
   * Re-read the sidebar title from the transcript, at most once per
   * {@link TITLE_REFRESH_MS} per session.
   *
   * Called from session-start, user-prompt-submit and stop. The throttle is
   * stamped even when nothing is found, so a transcript without a title costs
   * one read per minute rather than one per hook. Never throws: a hook that
   * fails because a title could not be read would be a regression, not a fix.
   */
  async refreshTitle(input: {
    session: string;
    transcriptPath?: string | null;
    roots: readonly string[];
    force?: boolean;
    now?: number;
  }): Promise<void> {
    const now = input.now ?? this.now();
    const row = this.store.getSession(input.session);
    if (row === null) return;
    if (
      input.force !== true &&
      row.title_read_at !== null &&
      now - row.title_read_at < TITLE_REFRESH_MS
    ) {
      return;
    }
    const path = input.transcriptPath ?? row.transcript_path;
    let found: Awaited<ReturnType<typeof readTranscriptTitle>> = null;
    try {
      found = await readTranscriptTitle(path, input.roots);
    } catch {
      found = null;
    }
    // A later read that finds nothing must not erase a title we already have:
    // Claude Code writes `custom-title` once, and a tail read after a very long
    // session can scroll past it.
    if (found === null && row.title !== null) {
      this.store.setSessionTitle({
        id: row.id,
        title: row.title,
        title_source: row.title_source,
        now,
      });
      return;
    }
    if (found !== null && found.title === row.title && found.source === row.title_source) {
      this.store.setSessionTitle({ id: row.id, title: row.title, title_source: row.title_source, now });
      return;
    }
    this.store.setSessionTitle({
      id: row.id,
      title: found?.title ?? null,
      title_source: found?.source ?? null,
      now,
    });
    const fresh = this.store.getSession(row.id);
    if (fresh !== null) this.bus.emit('session.heartbeat', fresh.home_repo, this.view(fresh, now));
  }

  get(id: string): SessionView | null {
    const row = this.store.getSession(id);
    return row === null ? null : this.view(row);
  }

  orphans(filter: { repo?: string; checkout?: string } = {}): TouchedView[] {
    const now = this.now();
    return this.store
      .listTouched({ repo: filter.repo, checkout: filter.checkout })
      .map((r) => this.touchedView(r, now))
      .filter((v) => v.orphan);
  }

  touchedFor(filter: { session?: string; repo?: string; checkout?: string }): TouchedView[] {
    const now = this.now();
    return this.store.listTouched(filter).map((r) => this.touchedView(r, now));
  }

  /* ---------------- repo/path resolution ---------------- */

  /** `repos.yml` → commonDir index. Cheap to rebuild, so it is keyed on the
   *  serialized slug→path map and rebuilt the moment that changes. */
  private async repoIndex(): Promise<Map<string, string>> {
    const repos = this.ledger.repos();
    const key = Object.entries(repos)
      .map(([slug, cfg]) => `${slug}=${cfg.path ?? ''}`)
      .sort()
      .join('|');
    if (key === this.repoIndexKey) return this.repoByCommonDir;
    const next = new Map<string, string>();
    for (const slug of Object.keys(repos)) {
      const path = this.ledger.repoPath(slug);
      if (!path) continue;
      const layout = await resolveCheckout(path);
      if (layout) next.set(layout.commonDir, slug);
    }
    this.repoByCommonDir = next;
    this.repoIndexKey = key;
    return next;
  }

  /** Slug for a checkout (main or worktree), or null when unregistered. */
  async repoForCheckout(layout: CheckoutLayout): Promise<string | null> {
    const index = await this.repoIndex();
    return index.get(layout.commonDir) ?? null;
  }

  /**
   * Resolve a path coming out of a hook (`cwd`, `file_path`, `notebook_path`).
   * Returns null — and the caller writes nothing — when the path is outside
   * every registered repo, is not a repo at all, or would escape its checkout.
   */
  async resolvePath(raw: string): Promise<ResolvedPath | null> {
    if (typeof raw !== 'string' || raw.trim() === '' || !isAbsolute(raw)) return null;
    const abs = await realpathOrParent(raw);
    if (abs === null) return null;
    // `resolveCheckout` starts with `realpath`, so it cannot answer for a file
    // that does not exist yet — and a PreToolUse(Write) for a new file is
    // precisely the case the guard must not miss. Fall back to the nearest
    // ancestor that DOES exist; containment is then checked textually below,
    // against the realpath'd checkout, so nothing escapes.
    const layout = (await resolveCheckout(abs)) ?? (await resolveCheckout(await nearestExistingDir(abs)));
    if (!layout) return null;
    const repo = await this.repoForCheckout(layout);
    if (!repo) return null;
    const rel = relative(layout.checkout, abs);
    // `relative` gives `..` (or an absolute path on another volume) exactly when
    // `abs` is not inside `checkout` — that is the traversal check.
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
      // A hook on the checkout root itself is legitimate for `cwd`.
      if (rel !== '') return null;
    }
    return { repo, layout, rel_path: rel.split(sep).join('/'), abs };
  }

  /**
   * SessionStart in an unknown git repo: register it (SPEC §4.2). Slug from the
   * toplevel directory name, `-2`/`-3` on collision, prefix derived and unique,
   * `CONTEXT.md` + `DECISIONS.md` from the template.
   *
   * Every registered repo with a path gets its own RepoWatcher target
   * (fs.watch handle + periodic git poll), and auto-registration is driven
   * entirely by whatever `cwd` a hook happens to report — unbounded, that is
   * an unbounded number of watchers/handles from hook traffic alone. Cap it,
   * and refuse to ever auto-register `$HOME` itself or a directory this
   * process does not own (registering it would poll a checkout the hub has
   * no business reading).
   */
  async autoRegisterRepo(layout: CheckoutLayout): Promise<string | null> {
    const base = slugify(basename(layout.checkout));
    if (base === null) return null;
    if (layout.checkout === homedir()) {
      this.ledger.log(`repo auto-registration refused: ${layout.checkout} is $HOME`);
      return null;
    }
    const existing = this.ledger.repos();
    const registeredWithPath = Object.values(existing).filter((cfg) => cfg.path !== null).length;
    if (registeredWithPath >= AUTO_REGISTER_LIMIT) {
      this.ledger.log(
        `repo auto-registration refused: limit of ${AUTO_REGISTER_LIMIT} registered repos reached`,
      );
      return null;
    }
    const uid = process.getuid?.();
    if (uid !== undefined) {
      try {
        const st = await stat(layout.checkout);
        if (st.uid !== uid) {
          this.ledger.log(`repo auto-registration refused: ${layout.checkout} does not belong to this user`);
          return null;
        }
      } catch {
        return null;
      }
    }
    let slug = base;
    for (let n = 2; n < 100 && Object.hasOwn(existing, slug); n += 1) slug = `${base}-${n}`;
    if (Object.hasOwn(existing, slug)) return null;
    try {
      // Register against the *checkout* we were given: for a linked worktree
      // that is the worktree dir, which is wrong as the repo's canonical path.
      // Use the common dir's parent instead when it looks like `<top>/.git`.
      const canonical = canonicalCheckout(layout);
      await this.ledger.registerRepo({ slug, path: canonical });
      this.repoIndexKey = ''; // force a rebuild
      this.ledger.log(`repo auto-registered ${slug} → ${canonical}`);
      return slug;
    } catch (err) {
      this.ledger.log(`repo auto-registration failed (${slug}): ${String(err)}`);
      return null;
    }
  }

  /* ---------------- lifecycle ---------------- */

  async start(input: {
    id: string;
    cwd: string | null;
    transcript_path: string | null;
    source: string | null;
  }): Promise<SessionStartResult> {
    const now = this.now();
    let repo: string | null = null;
    let checkout: string | null = null;
    let autoRegistered = false;

    if (input.cwd) {
      const abs = await realpathOrParent(input.cwd);
      const layout = abs === null ? null : await resolveCheckout(abs);
      if (layout) {
        checkout = layout.checkout;
        repo = await this.repoForCheckout(layout);
        if (!repo) {
          repo = await this.autoRegisterRepo(layout);
          autoRegistered = repo !== null;
        }
      }
    }

    const source = normalizeSource(input.source);
    const branch = checkout ? (this.store.getGitCache(checkout)?.branch ?? null) : null;

    // Orphans are "uncommitted files of an ended session", so the list has to be
    // taken BEFORE the upsert un-ends the row.
    const before = this.store.getSession(input.id);
    const wasEnded = before !== null && this.liveness(before, now) === 'ended';
    const orphanRows = wasEnded ? this.store.listTouched({ session: input.id }) : [];

    const res = this.store.tx(() =>
      this.store.upsertSession({
        id: input.id,
        home_repo: repo,
        cwd: input.cwd,
        checkout,
        branch,
        transcript_path: input.transcript_path,
        source,
        now,
      }),
    );

    const view = this.view(res.row, now);
    const returnedOrphans = orphanRows.map((r) => ({ ...this.touchedView(r, now), orphan: false }));

    if (res.created || wasEnded) {
      await this.journal(repo, input.id, 'session.start', [
        source,
        checkout ? shortPath(checkout) : 'no repo',
        ...(wasEnded ? [`revived · ${returnedOrphans.length} files back`] : []),
      ]);
    }
    this.bus.emit('session.start', repo, view);
    return {
      session: view,
      repo,
      checkout,
      created: res.created,
      revived: wasEnded,
      returnedOrphans,
      autoRegistered,
    };
  }

  heartbeat(id: string): boolean {
    const ok = this.store.heartbeat(id, this.now());
    if (ok) this.bus.emit('session.heartbeat', null, { id, at: isoLocal() });
    return ok;
  }

  /**
   * SessionEnd (or the 24 h reaper). One transaction for the DB side, then the
   * md side (journal + `doing → open`) which has its own serial queue.
   */
  async end(id: string, reason: string | null): Promise<{ orphans: TouchedView[]; released: number; reopened: string[] }> {
    const now = this.now();
    const row = this.store.getSession(id);
    if (row === null) return { orphans: [], released: 0, reopened: [] };

    const touched = this.store.listTouched({ session: id });
    const claims = this.store.listLeases({ session: id, active: true });

    const released = this.store.tx(() => {
      this.store.endSession(id, now);
      return this.store.releaseLeases({ session: id }, now);
    });

    const orphans = touched.map((r) => ({ ...this.touchedView(r, now), orphan: true }));

    // Items this session left in `doing` go back to `open` (SPEC §5) — the md
    // write is the ledger's job, and a failure there must not abort the rest.
    const reopened: string[] = [];
    const doingIds = new Set<string>();
    for (const lease of claims) if (lease.item_id) doingIds.add(lease.item_id);
    for (const item of this.ledger.listItems()) {
      if (item.fm.status !== 'doing') continue;
      if (item.fm.claimed_by?.session === id) doingIds.add(item.fm.id);
    }
    for (const itemId of doingIds) {
      try {
        const item = this.ledger.getItem(itemId).item;
        if (item.fm.status !== 'doing') continue;
        if (item.fm.claimed_by !== null && item.fm.claimed_by.session !== id) continue;
        await this.ledger.release(itemId, {
          session: id,
          why: `session ${shortSession(id)} ended (${sanitizeField(reason ?? 'no reason', 40)})`,
        });
        reopened.push(itemId);
      } catch (err) {
        this.ledger.log(`session ${shortSession(id)}: ${itemId} doing→open failed: ${String(err)}`);
      }
    }

    await this.journal(row.home_repo, id, 'session.end', [
      sanitizeField(reason ?? 'other', 40),
      `orphans ${orphans.length}`,
      `claims ${released}`,
      ...(reopened.length > 0 ? [`open: ${reopened.join(', ')}`] : []),
    ]);
    for (const o of orphans) {
      await this.journal(o.repo, id, 'orphan', [o.rel_path, `via ${o.via}`]);
    }
    this.bus.emit('session.end', row.home_repo, { id, orphans: orphans.length, reopened });
    return { orphans, released, reopened };
  }

  /** Periodic: end every session that has been silent for > 24 h (SPEC §5). */
  async reap(): Promise<string[]> {
    const dead = this.store.listDeadSessions(this.now());
    const ended: string[] = [];
    for (const row of dead) {
      await this.end(row.id, 'timeout 24h');
      ended.push(row.id);
    }
    await this.expireIdleLeases();
    return ended;
  }

  /**
   * A claim of a session that stopped sending heartbeats 4 h ago is not
   * intent any more, it is stale data that `who`, the brief and the coordination
   * notes keep repeating. Released and journalled, so the next session sees why.
   */
  async expireIdleLeases(): Promise<LeaseRow[]> {
    const rows = this.store.expireIdleLeases(LEASE_IDLE_MS, this.now());
    for (const row of rows) {
      await this.journal(row.repo, row.session_id, 'lease.expire', [
        row.kind,
        row.item_id ?? 'no item',
        `idle > ${Math.round(LEASE_IDLE_MS / 3_600_000)} h`,
      ]);
    }
    if (rows.length > 0) this.ledger.log(`expired leases of idle sessions: ${rows.length}`);
    return rows;
  }

  /**
   * `ledger whose`: the agent needs the *source* of the ownership, not
   * just a name — `edit` is a lock, `bash`/`ambiguous` is a hint — plus whether
   * the guard would actually deny right now.
   */
  whoseLine(input: {
    repo: string;
    rel_path: string;
    owner: TouchedView | null;
    claims: { session: string; pattern: string; item_id: string | null }[];
  }): string {
    const { owner } = input;
    const claims = input.claims
      .map((c) => `${shortSession(c.session)}:${c.pattern}${c.item_id ? `(${c.item_id})` : ''}`)
      .join(' ');
    // Column order is the F1 one (`<path> <short> <via> …`) — `ledger whose` is
    // read by agents and parsed by tests; later changes only append columns.
    if (owner === null) {
      return (
        `${input.rel_path} — nobody (manual change?) guard:open ${input.repo}` +
        `${claims ? ` · claim: ${claims}` : ''}`
      );
    }
    const row = this.store.getSession(owner.session);
    const view = row === null ? null : this.view(row, this.now());
    const idle = view === null ? '—' : idleText(view.idle_ms);
    const who = view === null ? 'session unknown' : sessionLabel(view);
    const blocks = this.guardBlocks(owner, view);
    return (
      `${input.rel_path} ${shortSession(owner.session)} ${owner.via} ${who} ` +
      `${view?.liveness ?? 'ended'} ${idle} guard:${blocks ? 'blocks' : 'open'}` +
      `${owner.orphan ? ' ORPHAN' : ''} ${input.repo}${claims ? ` · claim: ${claims}` : ''}`
    );
  }

  /** Live claim globs covering a path — intent, never a lock. */
  claimsOfPath(
    checkout: string,
    rel: string,
  ): { session: string; pattern: string; item_id: string | null }[] {
    const now = this.now();
    const out: { session: string; pattern: string; item_id: string | null }[] = [];
    for (const lease of this.store.listLeases({ active: true })) {
      if (lease.kind !== 'claim') continue;
      if (lease.checkout !== null && lease.checkout !== checkout) continue;
      // Parsed here rather than imported from `edit-guard` — that module imports
      // this one, and a cycle between them is not worth one JSON.parse.
      const pattern = matchAny(this.leaseView(lease).paths, toPosix(rel));
      if (pattern === null) continue;
      const row = this.store.getSession(lease.session_id);
      if (row === null || this.liveness(row, now) === 'ended') continue;
      out.push({ session: lease.session_id, pattern, item_id: lease.item_id });
    }
    return out;
  }

  /** The single place that answers "would rule 3/4 deny this now?". */
  guardBlocks(owner: TouchedView, view: SessionView | null): boolean {
    if (owner.via !== 'edit') return false;
    if (view === null || view.liveness === 'ended') return true; // rule 4, orphan
    return view.idle_ms <= STALE_OWNER_MS;
  }

  /* ---------------- touched ---------------- */

  /** Record an editor write. Returns null when the path is not ours to record. */
  async recordEdit(input: {
    session: string;
    absPath: string;
    via: TouchedVia;
    agent_type?: string | null;
  }): Promise<TouchedView | null> {
    const resolved = await this.resolvePath(input.absPath);
    if (!resolved || resolved.rel_path === '') return null;
    const now = this.now();
    this.store.touch({
      session_id: input.session,
      repo: resolved.repo,
      checkout: resolved.layout.checkout,
      rel_path: resolved.rel_path,
      via: input.via,
      agent_type: input.agent_type ?? null,
      now,
    });
    const rows = this.store.ownersOfPath(resolved.layout.checkout, resolved.rel_path);
    const mine = rows.find((r) => r.session_id === input.session);
    const view = mine ? this.touchedView(mine, now) : null;
    this.bus.emit('repo.dirty', resolved.repo, {
      repo: resolved.repo,
      checkout: resolved.layout.checkout,
      rel_path: resolved.rel_path,
      session: input.session,
      via: input.via,
    });
    return view;
  }

  private async journal(
    repo: string | null,
    session: string,
    type: string,
    fields: string[],
  ): Promise<void> {
    const slug = repo ?? 'ops';
    try {
      await this.ledger.appendJournalEvent(slug, session, type, fields);
    } catch (err) {
      this.ledger.log(`journal ${type} (${slug}) failed: ${String(err)}`);
    }
  }

  /** Journal entries that mention this session (for `GET /v1/sessions/:id`). */
  eventsFor(id: string, limit = 50): JournalEvent[] {
    const short = shortSession(id);
    return this.ledger
      .listJournal()
      .filter((ev) => ev.session === short || ev.session.startsWith(short))
      .slice(0, limit);
  }
}

/* ---------------- helpers ---------------- */

/**
 * `realpath`, falling back to the nearest ANCESTOR that does exist plus the
 * remaining segments. A `Write` reports its `file_path` before the file is
 * there, and often before its directory is either (`src/auth/new/guard.ts`);
 * resolving only one level up left such a path unresolvable, which made the
 * guard treat a brand-new file as "outside every repo" and allow it — a hole in
 * rule 5 exactly when a session starts new work in a foreign repo.
 *
 * Symlink safety is unchanged: every existing component is resolved by
 * `realpath`, so a symlinked parent cannot smuggle the result out of its
 * checkout. Only the non-existent tail is appended literally, and it is checked
 * against the checkout by `resolvePath`.
 */
export async function realpathOrParent(raw: string): Promise<string | null> {
  try {
    return await realpath(raw);
  } catch {
    /* fall through */
  }
  const rest: string[] = [];
  let current = raw;
  // Bounded: a path deeper than this is not a real edit target.
  for (let i = 0; i < 64; i += 1) {
    const parent = dirname(current);
    if (parent === current) return null; // reached the root without a hit
    rest.unshift(basename(current));
    try {
      return join(await realpath(parent), ...rest);
    } catch {
      current = parent;
    }
  }
  return null;
}

/** Deepest ancestor of `abs` that exists as a directory (root in the worst case). */
async function nearestExistingDir(abs: string): Promise<string> {
  let current = dirname(abs);
  for (let i = 0; i < 64; i += 1) {
    try {
      const st = await stat(current);
      if (st.isDirectory()) return current;
    } catch {
      /* keep walking up */
    }
    const parent = dirname(current);
    if (parent === current) return current;
    current = parent;
  }
  return current;
}

function canonicalCheckout(layout: CheckoutLayout): string {
  if (!layout.worktree) return layout.checkout;
  // `<top>/.git` → `<top>`; anything else (bare repo, `--separate-git-dir`) is
  // left as the worktree we saw, which is still a valid checkout.
  const parent = dirname(layout.commonDir);
  return basename(layout.commonDir) === '.git' ? parent : layout.checkout;
}

/** Directory name → ledger slug, or null when nothing usable is left. */
export function slugify(name: string): string | null {
  const slug = name
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return slugSchema.safeParse(slug).success ? slug : null;
}

function normalizeSource(raw: string | null): SessionSource {
  switch (raw) {
    case 'startup':
    case 'resume':
    case 'clear':
    case 'compact':
      return raw;
    default:
      return 'unknown';
  }
}

function shortPath(p: string): string {
  const parts = p.split(sep).filter((x) => x !== '');
  return parts.slice(-2).join('/') || p;
}
