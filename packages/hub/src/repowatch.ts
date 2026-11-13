/**
 * Git cache refresh + commit/tag watcher — SPEC §6.3 and §12.
 *
 * Two jobs, one file because they share the same "which checkouts exist" walk:
 *
 *  1. `GitCache`: keeps `git_cache` fresh — 2 s debounce after a PostToolUse,
 *     every 60 s for checkouts with a live session, and on demand for
 *     `GET /v1/repos/:slug`.
 *  2. `RepoWatcher`: watches `<common>/logs/HEAD`, `<common>/worktrees/*\/logs/HEAD`,
 *     `<common>/refs/tags` and `<common>/packed-refs`. A new commit closes
 *     `Closes:` items, logs `Refs:` ones, clears the commit's files from
 *     `touched` and writes a `commit` journal event. A new `v*` tag writes a
 *     `release` event and back-fills `done.version`.
 *
 * Both are best-effort by construction: git can fail, a repo can vanish, a
 * worktree can be pruned mid-walk. Nothing here is allowed to throw into the
 * caller or to stop the hub.
 */

import { watch, type FSWatcher } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { shortSession } from '@agent-ledger/shared';
import type { RuntimeStore } from './db/store.ts';
import type { EventBus } from './events.ts';
import { GitCwdMissingError, resolveCheckout, type CheckoutLayout } from './git.ts';
import {
  listTrackedAmong,
  readCommits,
  readLastRelease,
  readStatus,
  readTags,
  readWorktrees,
  revParse,
  type CommitInfo,
} from './gitreader.ts';
import type { Ledger } from './ledger/ledger.ts';
import { notifyContractChange } from './contracts.ts';
import { recordCommitFiles } from './related-paths.ts';
import { structuralReason, topLevelDirs } from './stalecontext.ts';
import type { Summarizer } from './summary.ts';
import type { Sessions } from './sessions.ts';

export interface RepoTarget {
  slug: string;
  layout: CheckoutLayout;
}

export interface GitCacheDeps {
  ledger: Ledger;
  store: RuntimeStore;
  bus: EventBus;
  /** Debounce after a Bash/Edit tool call (SPEC §6.3: 2 s). */
  debounceMs?: number;
  /** Periodic refresh for live checkouts (SPEC §6.3: 60 s). */
  intervalMs?: number;
  /** False right after a wake — the periodic `git status` walk waits.
   *  An on-demand refresh (a request, a PostToolUse debounce) is NOT gated. */
  heavyAllowed?: () => boolean;
}

export class GitCache {
  private readonly ledger: Ledger;
  private readonly store: RuntimeStore;
  private readonly bus: EventBus;
  private readonly debounceMs: number;
  private readonly intervalMs: number;
  private readonly heavyAllowed: () => boolean;
  private timers = new Map<string, NodeJS.Timeout>();
  private inflight = new Map<string, Promise<void>>();
  /** Checkouts already reported as gone, so they log once. */
  private missingLogged = new Set<string>();
  private ticker: NodeJS.Timeout | null = null;

  constructor(deps: GitCacheDeps) {
    this.ledger = deps.ledger;
    this.store = deps.store;
    this.bus = deps.bus;
    this.debounceMs = deps.debounceMs ?? 2_000;
    this.intervalMs = deps.intervalMs ?? 60_000;
    this.heavyAllowed = deps.heavyAllowed ?? ((): boolean => true);
  }

  start(): void {
    if (this.ticker) return;
    this.ticker = setInterval(() => {
      // The periodic walk skips a cycle while the wake gate is closed
      // — the next tick is 60 s away and there is nothing to catch up on, the
      // cache is refreshed on demand anyway. And `.catch`: an unhandled
      // rejection here (a vanished checkout used to throw ENOENT from spawn)
      // took the whole hub down under launchd.
      if (!this.heavyAllowed()) return;
      void this.refreshLive().catch((err: unknown) =>
        this.ledger.log(`git cache tick: ${String(err)}`),
      );
    }, this.intervalMs);
    this.ticker.unref?.();
  }

  stop(): void {
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
  }

  /** Coalesced refresh — many edits in one tool call cost one `git status`. */
  schedule(checkout: string, repo: string | null): void {
    const existing = this.timers.get(checkout);
    if (existing) clearTimeout(existing);
    const t = setTimeout(() => {
      this.timers.delete(checkout);
      void this.refresh(checkout, repo);
    }, this.debounceMs);
    t.unref?.();
    this.timers.set(checkout, t);
  }

  /** One `git status` per checkout at a time; concurrent callers share it. */
  refresh(checkout: string, repo: string | null): Promise<void> {
    const running = this.inflight.get(checkout);
    if (running) return running;
    const p = this.doRefresh(checkout, repo).finally(() => this.inflight.delete(checkout));
    this.inflight.set(checkout, p);
    return p;
  }

  private async doRefresh(checkout: string, repo: string | null): Promise<void> {
    try {
      // A8-5: captured BEFORE `git status` runs — `releaseCleanTouched` uses
      // this to ignore any `touched` row whose edit lands after this instant,
      // since this snapshot cannot possibly know about it yet.
      const snapshotAt = Date.now();
      const status = await readStatus(checkout);
      if (status === null) return;
      const worktrees = await readWorktrees(checkout);
      const before = this.store.getGitCache(checkout);
      const dirtyJson = JSON.stringify(status.dirty);
      this.store.putGitCache({
        checkout,
        repo,
        head: status.head,
        branch: status.branch,
        ahead: status.ahead,
        behind: status.behind,
        dirty: dirtyJson,
        worktrees: JSON.stringify(worktrees),
      });
      // The dirty set is also the only honest answer to "is this lock
      // still backed by a change?". A reverted edit or a commit made outside the
      // watched path used to leave a `touched` row denying edits for hours.
      // A8-6: a gitignored file never appears in `dirty`, so "not dirty"
      // alone cannot tell a reverted edit apart from a file git cannot see at
      // all — only release a path that is confirmed TRACKED-and-clean, or
      // (original case) no longer EXISTS on disk at all. A path that
      // still exists, is untracked, and absent from `dirty` is exactly what a
      // gitignored file looks like and is left locked here on purpose.
      // Ask about the CANDIDATES, not about the whole checkout.
      // `listTrackedFiles` is capped at 5 000 paths and returns `[]` on any git
      // error, so in a large monorepo a tracked-and-clean candidate past the
      // cap read as "untracked" and kept its `touched` lock forever. The
      // targeted query is bounded by the number of touched rows instead of by
      // repo size, so the verdict no longer depends on how big the repo is.
      const dirtySet = new Set(status.dirty.map((d) => d.rel_path));
      const candidates = this.store
        .listTouched({ checkout })
        .map((r) => r.rel_path)
        .filter((p) => !dirtySet.has(p));
      const trackedSet = await listTrackedAmong(checkout, candidates);
      const safeToRelease: string[] = [];
      for (const relPath of candidates) {
        if (trackedSet.has(relPath)) {
          safeToRelease.push(relPath);
          continue;
        }
        const exists = await stat(join(checkout, relPath)).catch(() => null);
        if (exists === null) safeToRelease.push(relPath);
      }
      const released = this.store.releaseCleanTouched(checkout, safeToRelease, snapshotAt);
      if (released.length > 0) {
        const paths = released.map((r) => r.rel_path);
        this.ledger.log(
          `touched released (clean files) in ${checkout}: ${released.length} — ${paths.slice(0, 5).join(' ')}`,
        );
        for (const row of released) {
          void this.ledger
            .appendJournalEvent(row.repo, row.session_id, 'touched.release', [
              row.rel_path,
              'file is clean in git',
            ])
            .catch(() => undefined);
        }
      }
      if (before?.dirty !== dirtyJson) {
        this.bus.emit('repo.dirty', repo, { repo, checkout, dirty: status.dirty.length });
      }
      this.missingLogged.delete(checkout);
    } catch (err) {
      // A checkout that no longer exists is not an error worth a line
      // per cycle — it used to produce one `spawn /usr/bin/git ENOENT` per
      // refresh for every removed agent worktree.
      if (err instanceof GitCwdMissingError) {
        if (!this.missingLogged.has(checkout)) {
          this.missingLogged.add(checkout);
          this.ledger.log(`git cache ${checkout}: checkout missing — skipping`);
        }
        return;
      }
      this.ledger.log(`git cache ${checkout}: ${String(err)}`);
    }
  }

  /** Every checkout that currently hosts a live session (SPEC §6.3). */
  async refreshLive(): Promise<void> {
    for (const row of this.store.liveCheckouts()) {
      await this.refresh(row.checkout, row.repo);
    }
  }

  /** Dirty paths from the cache, without touching git. */
  cachedDirty(checkout: string): { rel_path: string; code: string; staged: boolean; untracked: boolean }[] {
    const row = this.store.getGitCache(checkout);
    if (!row) return [];
    try {
      const parsed: unknown = JSON.parse(row.dirty);
      return Array.isArray(parsed) ? (parsed as ReturnType<GitCache['cachedDirty']>) : [];
    } catch {
      return [];
    }
  }
}

/* ---------------- commit & tag watcher ---------------- */

export interface RepoWatcherDeps {
  ledger: Ledger;
  store: RuntimeStore;
  bus: EventBus;
  gitCache: GitCache;
  /** Resolve a checkout to a registered slug. */
  repoForCheckout: (layout: CheckoutLayout) => Promise<string | null>;
  debounceMs?: number;
  /* ---- v0.4.0 ---- */
  /** needs the live sessions of a consumer repo to address the inbox.
   *  Optional so F0/F1 watcher tests keep their four-dep construction. */
  sessions?: Sessions;
  /** trigger (c): the commit updates the rolling summary. */
  summarizer?: Summarizer;
  /* ---- wake gate ---- */
  /** False right after a wake — a debounced pass reschedules itself. */
  heavyAllowed?: () => boolean;
  /** ms until `heavyAllowed()` opens again. */
  heavyRetryInMs?: () => number;
}

export class RepoWatcher {
  private readonly deps: RepoWatcherDeps;
  private watchers: FSWatcher[] = [];
  private timer: NodeJS.Timeout | null = null;
  private pending: Promise<void> = Promise.resolve();
  private targets: RepoTarget[] = [];
  private readonly debounceMs: number;
  /**
   * Slug → path of a registered repo whose checkout is not there right
   * now (removed, renamed, an external volume not mounted yet). In memory on
   * purpose: it is a fact about this machine at this moment, and a restart
   * re-derives it. Kept so the state change logs ONCE in each direction —
   * before this, a missing checkout was a silent `continue` in `start()`, so
   * "the hub stopped watching that repo" was invisible, and a vanished one
   * produced one `spawn /usr/bin/git ENOENT` per pass instead.
   */
  private missing = new Map<string, string>();

  constructor(deps: RepoWatcherDeps) {
    this.deps = deps;
    this.debounceMs = deps.debounceMs ?? 250;
  }

  /** (Re)build the watch set from `repos.yml`. Safe to call repeatedly. */
  async start(): Promise<void> {
    this.closeWatchers();
    this.targets = [];
    const repos = this.deps.ledger.repos();
    for (const slug of Object.keys(repos)) {
      const path = this.deps.ledger.repoPath(slug);
      if (!path) continue; // virtual repo (`ops`)
      const layout = await resolveCheckout(path);
      if (!layout) {
        this.noteMissing(slug, path);
        continue;
      }
      this.noteBack(slug);
      this.targets.push({ slug, layout });
      this.watchTarget(layout);
      await this.seedTopDirs(slug, layout.checkout);
    }
    // First pass records the current refs without replaying history — a fresh
    // hub must not close items from commits that landed months ago.
    await this.sync({ silent: true });
  }

  private watchTarget(layout: CheckoutLayout): void {
    const common = layout.commonDir;
    const paths = [
      join(common, 'logs', 'HEAD'),
      join(common, 'worktrees'),
      join(common, 'refs', 'tags'),
      join(common, 'packed-refs'),
      join(common, 'refs', 'heads'),
    ];
    for (const p of paths) {
      try {
        const w = watch(p, { recursive: true, persistent: false }, () => this.schedule());
        w.on('error', () => undefined);
        this.watchers.push(w);
      } catch {
        // The path may not exist yet (`packed-refs`, `worktrees`) — the parent
        // dir watch on `refs`/`logs` picks the creation up.
      }
    }
    try {
      const w = watch(common, { persistent: false }, (_e, name) => {
        if (name && /packed-refs|HEAD/.test(name.toString())) this.schedule();
      });
      w.on('error', () => undefined);
      this.watchers.push(w);
    } catch {
      /* ignore */
    }
  }

  private schedule(): void {
    if (this.timer) clearTimeout(this.timer);
    // While the wake gate is closed, push the pass out to just after it
    // opens instead of running a full ref walk into the post-wake storm. The fs
    // event is not lost — refs are compared against `seen_ref`, so a later pass
    // sees exactly the same difference.
    const gateDelay = this.deps.heavyAllowed?.() === false ? (this.deps.heavyRetryInMs?.() ?? 5_000) : 0;
    this.timer = setTimeout(() => {
      this.timer = null;
      if (this.deps.heavyAllowed?.() === false) {
        this.schedule();
        return;
      }
      this.pending = this.sync().catch((err: unknown) => {
        this.deps.ledger.log(`repo watcher: ${String(err)}`);
      });
    }, this.debounceMs + gateDelay);
    this.timer.unref?.();
  }

  /** Resolves once every pending pass has finished (tests). */
  async settled(): Promise<void> {
    await this.pending;
  }

  /** Force a pass now (tests, and `GET /v1/repos/:slug`). */
  async sync(opts: { silent?: boolean } = {}): Promise<void> {
    await this.recheckMissing(opts.silent ?? false);
    for (const target of [...this.targets]) {
      // A checkout can disappear between two passes (`git worktree
      // remove`, a renamed project dir). Then every git call in the pass throws
      // `GitCwdMissingError`, so the repo is dropped from the watch set, logged
      // once, and picked up again by `recheckMissing` if it comes back.
      if (!(await this.checkoutAlive(target.layout.checkout))) {
        this.dropTarget(target.slug, target.layout.checkout);
        continue;
      }
      try {
        const checkouts = await this.checkoutsOf(target);
        for (const checkout of checkouts) {
          await this.syncHead(target.slug, checkout, opts.silent ?? false);
        }
        await this.syncTags(target.slug, target.layout.checkout, opts.silent ?? false);
      } catch (err) {
        if (err instanceof GitCwdMissingError) {
          this.dropTarget(target.slug, target.layout.checkout);
          continue;
        }
        throw err;
      }
    }
  }

  /** Registered repos whose checkout is currently missing (healthz diag). */
  missingRepos(): string[] {
    return [...this.missing.keys()].sort();
  }

  /** Has a known-missing checkout come back? One `stat`-level probe per
   *  repo per pass, no git process involved (`resolveCheckout` walks the fs). */
  private async recheckMissing(silent: boolean): Promise<void> {
    for (const [slug, path] of [...this.missing]) {
      const layout = await resolveCheckout(path);
      if (!layout) continue;
      this.noteBack(slug);
      this.targets.push({ slug, layout });
      this.watchTarget(layout);
      await this.seedTopDirs(slug, layout.checkout);
      if (!silent) {
        // Record the current refs without replaying what happened while the
        // checkout was gone — the same rule as a fresh hub in `start()`.
        await this.syncHead(slug, layout.checkout, true).catch(() => undefined);
      }
    }
  }

  private async checkoutAlive(checkout: string): Promise<boolean> {
    const st = await stat(checkout).catch(() => null);
    return st !== null && st.isDirectory();
  }

  private dropTarget(slug: string, path: string): void {
    this.targets = this.targets.filter((t) => t.slug !== slug);
    this.noteMissing(slug, path);
  }

  private noteMissing(slug: string, path: string): void {
    if (this.missing.has(slug)) return;
    this.missing.set(slug, path);
    this.deps.ledger.log(`repo ${slug}: checkout missing (${path}) — skipping`);
  }

  private noteBack(slug: string): void {
    if (!this.missing.delete(slug)) return;
    this.deps.ledger.log(`repo ${slug}: checkout is back`);
  }

  private async checkoutsOf(target: RepoTarget): Promise<string[]> {
    const out = new Set<string>([target.layout.checkout]);
    for (const wt of await readWorktrees(target.layout.checkout)) {
      if (wt.bare || !wt.path) continue;
      // `git worktree list` keeps listing a worktree whose directory is
      // gone (prunable until someone runs `git worktree prune`). Running git in
      // it is guaranteed to fail, so it is skipped here rather than producing
      // one error line per pass forever.
      if (!(await this.checkoutAlive(wt.path))) continue;
      out.add(wt.path);
    }
    return [...out];
  }

  private async syncHead(slug: string, checkout: string, silent: boolean): Promise<void> {
    const head = await revParse(checkout, 'HEAD');
    if (head === null) return;
    const key = `HEAD:${checkout}`;
    const last = this.deps.store.getSeenRef(checkout, key);
    if (last === head) return;
    this.deps.store.putSeenRef(checkout, key, head);
    if (silent || last === null) return; // first observation: remember, replay nothing

    const commits = await readCommits(checkout, `${last}..${head}`, 50);
    for (const commit of commits) {
      await this.applyCommit(slug, checkout, commit);
    }
    this.deps.gitCache.schedule(checkout, slug);
  }

  private async applyCommit(slug: string, checkout: string, commit: CommitInfo): Promise<void> {
    // Attribute the commit to whoever had the most of its files open, BEFORE
    // the rows are marked committed — afterwards the ownership is gone.
    const session = this.attributeSession(checkout, commit.files);
    this.deps.store.markCommitted(checkout, commit.files, commit.short);
    this.deps.store.pruneCommitted();
    // Remember which files the items named in the trailers live in.
    // Only ids of THIS repo — a `Refs: ACME-1` in another repo's commit lists
    // paths that mean nothing there.
    recordCommitFiles(
      this.deps.store,
      slug,
      [...commit.closes, ...commit.refs].filter((id) => this.deps.ledger.repoForItemId(id) === slug),
      commit.files,
    );

    for (const id of commit.closes) {
      try {
        await this.deps.ledger.closeByCommit(slug, id, { ...commit, session });
      } catch (err) {
        this.deps.ledger.log(`commit ${commit.short}: Closes ${id} failed: ${String(err)}`);
      }
    }
    for (const id of commit.refs) {
      if (commit.closes.includes(id)) continue;
      try {
        await this.deps.ledger.logItem(slug, id, session, `commit ${commit.short} · ${commit.subject}`);
      } catch (err) {
        this.deps.ledger.log(`commit ${commit.short}: Refs ${id} failed: ${String(err)}`);
      }
    }
    await this.deps.ledger
      .appendJournalEvent(slug, session, 'commit', [
        commit.short,
        commit.subject,
        ...(commit.closes.length > 0 ? [`closes ${commit.closes.join(', ')}`] : []),
        ...(commit.refs.length > 0 ? [`refs ${commit.refs.join(', ')}`] : []),
      ])
      .catch((err: unknown) => this.deps.ledger.log(`journal commit: ${String(err)}`));
    this.deps.bus.emit('journal.appended', slug, {
      type: 'commit',
      repo: slug,
      sha: commit.short,
      subject: commit.subject,
      closes: commit.closes,
      session: session === null ? null : shortSession(session),
    });

    // v0.4.0 feeds. Each one is independent and each one is allowed to fail on
    // its own: a contract notification must never be the reason `Closes:`
    // stopped closing items, which is why they run after the block above and
    // every call is wrapped.
    this.noteStructural(slug, commit);
    await this.notifyContracts(slug, commit);
    if (this.deps.summarizer && session !== null) {
      try {
        await this.deps.summarizer.onCommit(session, slug, commit);
      } catch (err) {
        this.deps.ledger.log(`session summary after commit ${commit.short}: ${String(err)}`);
      }
    }
  }

  /** Remember a commit that changed the shape of the repo. */
  private noteStructural(slug: string, commit: CommitInfo): void {
    try {
      const newDirs = topLevelDirs(commit.files).filter((dir) =>
        this.deps.store.markOnce('topdir', `${slug}:${dir}`),
      );
      const reason = structuralReason(commit.files, newDirs);
      if (reason === null) return;
      const at = Date.parse(commit.at);
      this.deps.store.addStructCommit(
        slug,
        commit.short,
        `${reason.kind}:${reason.detail}`,
        Number.isFinite(at) ? at : Date.now(),
      );
    } catch (err) {
      this.deps.ledger.log(`structural commit ${commit.short}: ${String(err)}`);
    }
  }

  /** Tell the consumer repos when a contract path moved. */
  private async notifyContracts(slug: string, commit: CommitInfo): Promise<void> {
    const sessions = this.deps.sessions;
    if (sessions === undefined) return;
    try {
      await notifyContractChange(
        { ledger: this.deps.ledger, store: this.deps.store, sessions },
        slug,
        commit,
      );
    } catch (err) {
      this.deps.ledger.log(`contract change ${slug} ${commit.short}: ${String(err)}`);
    }
  }

  /**
   * Seed the known top-level dirs of a repo from its working tree, so
   * the first sync after an upgrade does not report every existing directory as
   * new. Called from `start()`, before any commit is replayed.
   */
  private async seedTopDirs(slug: string, checkout: string): Promise<void> {
    if (!this.deps.store.markOnce('topdir-seeded', slug)) return;
    try {
      for (const entry of await readdir(checkout, { withFileTypes: true })) {
        if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
        this.deps.store.markOnce('topdir', `${slug}:${entry.name}`);
      }
    } catch (err) {
      this.deps.ledger.log(`structure seed ${slug}: ${String(err)}`);
    }
  }

  /** Session that owned the most files in this commit, or null. */
  private attributeSession(checkout: string, files: string[]): string | null {
    const tally = new Map<string, number>();
    for (const rel of files) {
      for (const row of this.deps.store.ownersOfPath(checkout, rel)) {
        tally.set(row.session_id, (tally.get(row.session_id) ?? 0) + 1);
      }
    }
    let best: string | null = null;
    let bestCount = 0;
    for (const [session, count] of tally) {
      if (count > bestCount) {
        best = session;
        bestCount = count;
      }
    }
    return best;
  }

  private async syncTags(slug: string, checkout: string, silent: boolean): Promise<void> {
    const tags = await readTags(checkout);
    for (let i = 0; i < tags.length; i += 1) {
      const tag = tags[i];
      if (!tag) continue;
      const key = `tag:${tag.tag}`;
      if (this.deps.store.getSeenRef(checkout, key) !== null) continue;
      this.deps.store.putSeenRef(checkout, key, tag.sha ?? tag.tag);
      if (silent) continue;

      // `tags` is newest-first, so the previous release is the next entry.
      const previous = tags[i + 1];
      const range = previous ? `${previous.tag}..${tag.tag}` : tag.tag;
      const commits = await readCommits(checkout, range, 500);
      const shas = commits.map((c) => c.sha);
      const closed = this.deps.ledger.itemsClosedByCommits(slug, shas);
      for (const item of closed) {
        await this.deps.ledger
          .setDoneVersion(item.fm.id, tag.tag)
          .catch((err: unknown) =>
            this.deps.ledger.log(`release ${tag.tag}: ${item.fm.id} failed: ${String(err)}`),
          );
      }
      await this.deps.ledger
        .appendJournalEvent(slug, null, 'release', [
          tag.tag,
          `${commits.length} commits`,
          ...(closed.length > 0 ? [`closed ${closed.map((i) => i.fm.id).join(', ')}`] : []),
        ])
        .catch((err: unknown) => this.deps.ledger.log(`journal release: ${String(err)}`));
      this.deps.bus.emit('journal.appended', slug, {
        type: 'release',
        repo: slug,
        tag: tag.tag,
        items: closed.map((i) => i.fm.id),
      });
    }
  }

  /** Latest `v*` tag for the repo view. */
  lastRelease(checkout: string): ReturnType<typeof readLastRelease> {
    return readLastRelease(checkout);
  }

  private closeWatchers(): void {
    for (const w of this.watchers) {
      try {
        w.close();
      } catch {
        /* already closed */
      }
    }
    this.watchers = [];
  }

  /**
   * Stop watching one repo, without disturbing the others.
   *
   * `fs.watch` handles are not per-target here (one repo can contribute
   * several paths), so the honest implementation is: drop the target and
   * rebuild the watch set from the ledger, which by now no longer lists the
   * removed slug. Called BEFORE the ledger dir moves, so a late fs event
   * cannot re-register the repo mid-removal.
   */
  async forget(slug: string): Promise<void> {
    this.targets = this.targets.filter((t) => t.slug !== slug);
    // A removed repo is not a missing checkout — it must not reappear
    // in the healthz diag, and `recheckMissing` must not re-adopt it.
    this.missing.delete(slug);
    this.closeWatchers();
    for (const t of this.targets) this.watchTarget(t.layout);
  }

  close(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.closeWatchers();
  }
}
