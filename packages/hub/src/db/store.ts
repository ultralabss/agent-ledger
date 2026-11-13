/**
 * `RuntimeStore` — the only thing in the hub that talks SQL (SPEC §5).
 *
 * Every method is synchronous (`node:sqlite` is sync by design) and every
 * multi-statement mutation runs inside an explicit `BEGIN IMMEDIATE` /
 * `COMMIT`: a hook that registers a session, releases its leases and reassigns
 * its touched files must be all-or-nothing, otherwise a crash mid-hook leaves a
 * session that owns files it can no longer release.
 */

import { chmodSync } from 'node:fs';
import type { DatabaseSync, StatementSync } from 'node:sqlite';
import type {
  InboxMessage,
  InboxOrigin,
  LeaseKind,
  SearchEngine,
  SearchHit,
  SearchKind,
  ReplyMode,
  ReplyStatus,
  SessionSource,
  TouchedVia,
} from '@agent-ledger/shared';
import { generate, isoLocal } from '@agent-ledger/shared';
import { openDb } from './schema.ts';

/* ---------------- row shapes ---------------- */

export interface SessionRow {
  id: string;
  row_id: string;
  home_repo: string | null;
  cwd: string | null;
  checkout: string | null;
  branch: string | null;
  transcript_path: string | null;
  started_at: number;
  last_seen: number;
  ended_at: number | null;
  source: SessionSource;
  /** Sidebar name recovered from the transcript. */
  title: string | null;
  title_source: 'claude' | 'summary' | 'prompt' | null;
  /** ms of the last transcript read — throttles re-reads to once per minute. */
  title_read_at: number | null;
  /** Highest `changes.seq` already shown to this session. */
  delta_cursor: number | null;
}

export interface TouchedRow {
  id: string;
  session_id: string;
  repo: string;
  checkout: string;
  rel_path: string;
  via: TouchedVia;
  agent_type: string | null;
  first_at: number;
  last_at: number;
  committed_sha: string | null;
}

export interface LeaseRow {
  id: string;
  session_id: string;
  repo: string;
  checkout: string | null;
  kind: LeaseKind;
  item_id: string | null;
  paths: string;
  intent: string | null;
  created_at: number;
  released_at: number | null;
}

export interface GitCacheRow {
  checkout: string;
  repo: string | null;
  head: string | null;
  branch: string | null;
  ahead: number | null;
  behind: number | null;
  dirty: string;
  worktrees: string;
  refreshed_at: number;
}

export interface SearchDoc {
  kind: SearchKind;
  ref: string;
  repo: string;
  title: string;
  body: string;
}

/** SPEC §5 liveness thresholds. */
export const ACTIVE_MS = 10 * 60_000;
export const IDLE_MS = 24 * 3_600_000;
/** Past this idleness the owner's lock only warns, never denies. */
export const STALE_OWNER_MS = 2 * 3_600_000;
/** Leases of a session idle this long are released by the sweep. */
export const LEASE_IDLE_MS = 4 * 3_600_000;

export class RuntimeStore {
  readonly engine: SearchEngine;
  private readonly db: DatabaseSync;
  private readonly cache = new Map<string, StatementSync>();

  constructor(file: string) {
    const opened = openDb(file);
    this.db = opened.db;
    this.engine = opened.engine;
    // The DB mirrors the ledger (item titles, paths, session cwds) — same 0600
    // as every other file under `.hub/`. WAL/SHM siblings inherit the mode from
    // the process umask, so tighten them explicitly once they exist.
    for (const suffix of ['', '-wal', '-shm']) {
      try {
        chmodSync(`${file}${suffix}`, 0o600);
      } catch {
        /* not created yet — the next open will catch it */
      }
    }
  }

  /** `node:sqlite` types every column as `SQLOutputValue`; the schema above is
   *  the contract, so a row cast is the honest boundary. Routed through
   *  `unknown` because the shapes do not structurally overlap. */
  private rows<T>(sql: string, params: (string | number | null)[]): T[] {
    return this.stmt(sql).all(...params) as unknown as T[];
  }

  private row<T>(sql: string, params: (string | number | null)[]): T | null {
    return (this.stmt(sql).get(...params) as unknown as T | undefined) ?? null;
  }

  private stmt(sql: string): StatementSync {
    let s = this.cache.get(sql);
    if (!s) {
      s = this.db.prepare(sql);
      this.cache.set(sql, s);
    }
    return s;
  }

  /** Explicit transaction boundary — no implicit autocommit half-writes. */
  tx<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* already rolled back */
      }
      throw err;
    }
  }

  /** The WAL only shrinks when something checkpoints it. A hub that
   *  lives for weeks is never closed, so its WAL grew without bound. */
  checkpoint(): void {
    try {
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch {
      /* best effort — a reader holding the WAL just means we retry next sweep */
    }
  }

  close(): void {
    try {
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch {
      /* best effort */
    }
    this.cache.clear();
    this.db.close();
  }

  /* ---------------- sessions ---------------- */

  getSession(id: string): SessionRow | null {
    return this.row<SessionRow>('SELECT * FROM sessions WHERE id = ?', [id]);
  }

  /**
   * Register or revive. `source: 'resume'` on an ended session un-ends it,
   * which is what gives the session its orphaned files back (SPEC §5) — the
   * files were never reassigned, they only *looked* orphaned because the owner
   * had `ended_at` set.
   */
  upsertSession(input: {
    id: string;
    home_repo: string | null;
    cwd: string | null;
    checkout: string | null;
    branch: string | null;
    transcript_path: string | null;
    source: SessionSource;
    now?: number;
  }): { row: SessionRow; created: boolean; revived: boolean } {
    const now = input.now ?? Date.now();
    const existing = this.getSession(input.id);
    if (!existing) {
      this.stmt(
        `INSERT INTO sessions
           (id, row_id, home_repo, cwd, checkout, branch, transcript_path,
            started_at, last_seen, ended_at, source)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
      ).run(
        input.id,
        generate(),
        input.home_repo,
        input.cwd,
        input.checkout,
        input.branch,
        input.transcript_path,
        now,
        now,
        input.source,
      );
      return { row: this.getSession(input.id) as SessionRow, created: true, revived: false };
    }
    const revived = existing.ended_at !== null;
    this.stmt(
      `UPDATE sessions SET
         home_repo = COALESCE(?, home_repo),
         cwd = COALESCE(?, cwd),
         checkout = COALESCE(?, checkout),
         branch = COALESCE(?, branch),
         transcript_path = COALESCE(?, transcript_path),
         last_seen = ?, ended_at = NULL, source = ?
       WHERE id = ?`,
    ).run(
      input.home_repo,
      input.cwd,
      input.checkout,
      input.branch,
      input.transcript_path,
      now,
      input.source,
      input.id,
    );
    return { row: this.getSession(input.id) as SessionRow, created: false, revived };
  }

  /**
   * Store the recovered sidebar title.
   *
   * `title_read_at` is stamped even when `title` is `null`, so a transcript with
   * no title (or one the secret scanner rejected) is not re-read on every hook —
   * the throttle has to cost the same whether the read succeeded or not.
   */
  setSessionTitle(input: {
    id: string;
    title: string | null;
    title_source: 'claude' | 'summary' | 'prompt' | null;
    now?: number;
  }): void {
    this.stmt(
      'UPDATE sessions SET title = ?, title_source = ?, title_read_at = ? WHERE id = ?',
    ).run(input.title, input.title_source, input.now ?? Date.now(), input.id);
  }

  /** Append one item change. Called from the item routes, which are the
   *  only places an item can change through the API. */
  recordChange(input: {
    repo: string;
    item_id: string;
    kind: string;
    actor: string | null;
    title: string;
    commit_sha?: string | null;
    now?: number;
  }): void {
    this.stmt(
      `INSERT INTO changes (repo, item_id, kind, actor, title, commit_sha, at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      input.repo,
      input.item_id,
      input.kind,
      input.actor,
      input.title,
      input.commit_sha ?? null,
      input.now ?? Date.now(),
    );
  }

  /** Newest `seq`, for starting a session's cursor without replaying history. */
  latestChangeSeq(): number {
    const row = this.row<{ seq: number | null }>('SELECT MAX(seq) AS seq FROM changes', []);
    return Number(row?.seq ?? 0);
  }

  /** Changes after `afterSeq` in the given repos, oldest first. */
  listChanges(repos: readonly string[], afterSeq: number, limit = 50): ChangeRow[] {
    if (repos.length === 0) return [];
    return this.rows<ChangeRow>(
      `SELECT * FROM changes
        WHERE seq > ? AND repo IN (${repos.map(() => '?').join(', ')})
        ORDER BY seq
        LIMIT ?`,
      [afterSeq, ...repos, limit],
    );
  }

  /** Advance the delta cursor after a block has actually been printed. */
  setDeltaCursor(id: string, cursor: number): void {
    this.stmt('UPDATE sessions SET delta_cursor = ? WHERE id = ?').run(cursor, id);
  }

  /** Repos this session has a stake in: its home, plus anything it touched or
   *  claimed. Used to decide which repos' changes are worth showing it. */
  sessionRepos(id: string): string[] {
    const rows = this.rows<{ repo: string }>(
      `SELECT home_repo AS repo FROM sessions WHERE id = ? AND home_repo IS NOT NULL
       UNION SELECT repo FROM touched WHERE session_id = ?
       UNION SELECT repo FROM leases WHERE session_id = ?`,
      [id, id, id],
    );
    return rows.map((r) => r.repo).filter((r) => r !== null);
  }

  /** Heartbeat. Never resurrects an explicitly ended session — a stray hook
   *  after SessionEnd must not make a dead session hold files again. */
  heartbeat(id: string, now = Date.now()): boolean {
    const res = this.stmt('UPDATE sessions SET last_seen = ? WHERE id = ? AND ended_at IS NULL').run(
      now,
      id,
    );
    return Number(res.changes) > 0;
  }

  endSession(id: string, now = Date.now()): boolean {
    const res = this.stmt(
      'UPDATE sessions SET ended_at = ?, last_seen = ? WHERE id = ? AND ended_at IS NULL',
    ).run(now, now, id);
    return Number(res.changes) > 0;
  }

  /**
   * `repos` accepts a list so `GET /v1/sessions?repo=a,b` is one query, not one
   * per slug. `seenSince` bounds the ended tail (the API asks for 30 days) so
   * the list does not grow forever on a long-lived machine.
   */
  listSessions(
    filter: { repo?: string; repos?: readonly string[]; includeEnded?: boolean; seenSince?: number } = {},
  ): SessionRow[] {
    const where: string[] = [];
    const params: (string | number)[] = [];
    const repos = filter.repos ?? (filter.repo ? [filter.repo] : []);
    if (repos.length > 0) {
      // Placeholders are generated from the array length only — every slug
      // itself is bound, never interpolated.
      where.push(`home_repo IN (${repos.map(() => '?').join(', ')})`);
      params.push(...repos);
    }
    if (!filter.includeEnded) where.push('ended_at IS NULL');
    if (filter.seenSince !== undefined) {
      where.push('last_seen >= ?');
      params.push(filter.seenSince);
    }
    const sql = `SELECT * FROM sessions${
      where.length > 0 ? ` WHERE ${where.join(' AND ')}` : ''
    } ORDER BY last_seen DESC`;
    return this.rows<SessionRow>(sql, params);
  }

  /** Sessions with no signal for > 24 h that nobody ever ended (SPEC §5). */
  listDeadSessions(now = Date.now()): SessionRow[] {
    return this.rows<SessionRow>(
      'SELECT * FROM sessions WHERE ended_at IS NULL AND last_seen < ? ORDER BY last_seen',
      [now - IDLE_MS],
    );
  }

  /** Checkouts that currently host a live session — the 60 s git refresh set. */
  liveCheckouts(now = Date.now()): { checkout: string; repo: string | null }[] {
    return this.rows<{ checkout: string; repo: string | null }>(
      `SELECT DISTINCT checkout, home_repo AS repo FROM sessions
        WHERE ended_at IS NULL AND last_seen >= ? AND checkout IS NOT NULL`,
      [now - IDLE_MS],
    );
  }

  /* ---------------- touched ---------------- */

  /** Idempotent per (session, checkout, rel_path): re-editing bumps `last_at`
   *  and clears a stale `committed_sha` (the file is dirty again). */
  touch(input: {
    session_id: string;
    repo: string;
    checkout: string;
    rel_path: string;
    via: TouchedVia;
    agent_type?: string | null;
    now?: number;
  }): void {
    const now = input.now ?? Date.now();
    this.stmt(
      `INSERT INTO touched
         (id, session_id, repo, checkout, rel_path, via, agent_type, first_at, last_at, committed_sha)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
       ON CONFLICT(session_id, checkout, rel_path) DO UPDATE SET
         last_at = excluded.last_at,
         --  : edit > ambiguous > bash. A Bash diff may never
         -- overwrite an editor write, and an ambiguous verdict (two sessions
         -- could have done it) is not re-confirmed by a later Bash.
         via = CASE
                 WHEN touched.via = 'edit' THEN 'edit'
                 WHEN excluded.via = 'edit' THEN 'edit'
                 WHEN touched.via = 'ambiguous' OR excluded.via = 'ambiguous' THEN 'ambiguous'
                 ELSE excluded.via
               END,
         agent_type = COALESCE(excluded.agent_type, touched.agent_type),
         committed_sha = NULL`,
    ).run(
      generate(),
      input.session_id,
      input.repo,
      input.checkout,
      input.rel_path,
      input.via,
      input.agent_type ?? null,
      now,
      now,
    );
  }

  listTouched(filter: {
    session?: string;
    repo?: string;
    checkout?: string;
    uncommittedOnly?: boolean;
  }): TouchedRow[] {
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (filter.session) {
      where.push('session_id = ?');
      params.push(filter.session);
    }
    if (filter.repo) {
      where.push('repo = ?');
      params.push(filter.repo);
    }
    if (filter.checkout) {
      where.push('checkout = ?');
      params.push(filter.checkout);
    }
    if (filter.uncommittedOnly !== false) where.push('committed_sha IS NULL');
    const sql = `SELECT * FROM touched${
      where.length > 0 ? ` WHERE ${where.join(' AND ')}` : ''
    } ORDER BY last_at DESC`;
    return this.rows<TouchedRow>(sql, params);
  }

  /** Who holds this exact path in this exact checkout (SPEC §10.3 rule 3). */
  ownersOfPath(checkout: string, rel_path: string): TouchedRow[] {
    return this.rows<TouchedRow>(
      `SELECT * FROM touched
        WHERE checkout = ? AND rel_path = ? AND committed_sha IS NULL
        ORDER BY last_at DESC`,
      [checkout, rel_path],
    );
  }

  /**
   * A `touched` row only means something while the file is actually
   * dirty. A reverted edit, a commit made outside the watched path, a `git
   * checkout --` — all leave a lock that denies edits for hours with nothing
   * behind it. Called on every git-cache refresh with the current dirty set.
   * Returns the rows it dropped so the caller can journal them.
   *
   * A8-5: `dirty`/`tracked` are a snapshot of `git status`/`git ls-files` as
   * of `snapshotAt` (captured by the caller BEFORE running git) — a row
   * touched AFTER that moment cannot have been seen by that snapshot yet, so
   * it must survive to be judged by the NEXT, fresher snapshot instead of
   * being deleted on the strength of stale information.
   *
   * A8-6: `git status` never lists a gitignored path at all (not even as
   * untracked), so "absent from `dirty`" is NOT proof of "clean" — it is
   * ALSO what every gitignored file looks like, forever. The caller
   * (`repowatch.ts`) is the one with both git AND filesystem access, so it
   * decides what is safe to release: a path that is TRACKED and clean, or a
   * path that no longer EXISTS on disk at all (a reverted/deleted untracked
   * file — original case). A path that still exists, is untracked
   * and absent from `dirty` is exactly what a gitignored file looks like, so
   * it is left alone here; it can only go away via a commit, `SessionEnd`,
   * or lease/lock expiry. `safeToRelease` is that final, caller-decided set.
   */
  releaseCleanTouched(checkout: string, safeToRelease: Iterable<string>, snapshotAt: number): TouchedRow[] {
    const safe = new Set(safeToRelease);
    const rows = this.rows<TouchedRow>(
      'SELECT * FROM touched WHERE checkout = ? AND committed_sha IS NULL AND last_at < ?',
      [checkout, snapshotAt],
    ).filter((r) => safe.has(r.rel_path));
    if (rows.length === 0) return [];
    const del = this.stmt('DELETE FROM touched WHERE id = ?');
    for (const r of rows) del.run(r.id);
    return rows;
  }

  /** Rows for one exact path in one checkout, by via. */
  setTouchedVia(id: string, via: TouchedVia): void {
    this.stmt('UPDATE touched SET via = ? WHERE id = ?').run(via, id);
  }

  /**
   * startup migration. Pure SQL, so it runs without git:
   *  1. a `bash` row for a path another session holds as `edit` is wrong by
   *     construction (the editor write is the source of truth) → delete,
   *  2. every remaining `bash` row predates the attribution rules and cannot be
   *     confirmed now → `ambiguous` (informative, never denies).
   * The clean-file half is handled by `releaseCleanTouched` on the first
   * refresh of each checkout.
   */
  migrateWeakTouched(): { droppedOwnedByEdit: number; requalified: number } {
    const dropped = Number(
      this.stmt(
        `DELETE FROM touched WHERE via = 'bash' AND committed_sha IS NULL AND EXISTS (
           SELECT 1 FROM touched e
            WHERE e.checkout = touched.checkout AND e.rel_path = touched.rel_path
              AND e.session_id <> touched.session_id AND e.via = 'edit'
              AND e.committed_sha IS NULL)`,
      ).run().changes,
    );
    const requalified = Number(
      this.stmt(
        `UPDATE touched SET via = 'ambiguous' WHERE via = 'bash' AND committed_sha IS NULL`,
      ).run().changes,
    );
    return { droppedOwnedByEdit: dropped, requalified };
  }

  /**
   * Leases (claim, intrude, override) of a session that has not sent a
   * heartbeat in `idleMs`, or has ended. A claim that outlives its session
   * blocks nothing any more (globs are informative now) but it still
   * shows up in `who`/brief as live intent, which is worse than no data.
   */
  expireIdleLeases(idleMs: number, now = Date.now()): LeaseRow[] {
    // A8-11: `JOIN` silently drops a lease whose `sessions` row is gone
    // (hard-deleted, never written, a foreign-key edge case) — that lease
    // then never expires, since it is invisible to this whole query. A
    // missing session is the most idle a session can possibly be, so treat
    // `s.id IS NULL` the same as "ended" rather than excluding the row.
    const rows = this.rows<LeaseRow>(
      `SELECT l.* FROM leases l LEFT JOIN sessions s ON s.id = l.session_id
        WHERE l.released_at IS NULL AND (s.id IS NULL OR s.ended_at IS NOT NULL OR s.last_seen < ?)`,
      [now - idleMs],
    );
    for (const row of rows) this.releaseLease(row.id, now);
    return rows;
  }

  /** A commit landed: the listed paths are no longer uncommitted work. */
  markCommitted(checkout: string, relPaths: string[], sha: string, now = Date.now()): number {
    if (relPaths.length === 0) return 0;
    let changed = 0;
    const stmt = this.stmt(
      `UPDATE touched SET committed_sha = ?, last_at = ?
        WHERE checkout = ? AND rel_path = ? AND committed_sha IS NULL`,
    );
    for (const rel of relPaths) {
      changed += Number(stmt.run(sha, now, checkout, rel).changes);
    }
    return changed;
  }

  /**
   * `ledger adopt` (SPEC §10, bod 7): hand an ended session's uncommitted files to
   * a live one. The row MOVES rather than being copied — two owners of the same
   * uncommitted file is exactly the state the guard exists to prevent. The
   * UNIQUE(session_id, checkout, rel_path) constraint means the new owner may
   * already hold the path, so a collision deletes the old row instead of
   * failing the whole adopt.
   */
  reassignTouched(
    input: { checkout: string; rel_path: string; from?: string; to: string },
    now = Date.now(),
  ): boolean {
    const rows = this.ownersOfPath(input.checkout, input.rel_path).filter(
      (r) => input.from === undefined || r.session_id === input.from,
    );
    if (rows.length === 0) return false;
    let moved = false;
    for (const row of rows) {
      if (row.session_id === input.to) {
        moved = true;
        continue;
      }
      const clash = this.row<{ id: string }>(
        'SELECT id FROM touched WHERE session_id = ? AND checkout = ? AND rel_path = ?',
        [input.to, input.checkout, input.rel_path],
      );
      if (clash !== null) {
        this.stmt('DELETE FROM touched WHERE id = ?').run(row.id);
        this.stmt('UPDATE touched SET last_at = ?, committed_sha = NULL WHERE id = ?').run(
          now,
          clash.id,
        );
      } else {
        this.stmt(
          'UPDATE touched SET session_id = ?, last_at = ?, committed_sha = NULL WHERE id = ?',
        ).run(input.to, now, row.id);
      }
      moved = true;
    }
    return moved;
  }

  /**
   * B4-3: drop the ownership of a path entirely instead of moving it.
   *
   * `reassignTouched` always needs a destination session, so "a human released
   * this lock from the web UI" had to invent one (`manual`), and an invented
   * session is never live — the file reappeared in the orphan list on the next
   * poll, which is the bug. Deleting the row is the honest representation: the
   * path has no owner, which is exactly what the user asked for.
   *
   * Returns the number of rows removed (0 = nobody held it).
   */
  releaseTouched(
    input: { checkout: string; rel_path: string; session?: string },
  ): number {
    const rows = this.ownersOfPath(input.checkout, input.rel_path).filter(
      (r) => input.session === undefined || r.session_id === input.session,
    );
    const del = this.stmt('DELETE FROM touched WHERE id = ?');
    let removed = 0;
    for (const row of rows) removed += Number(del.run(row.id).changes);
    return removed;
  }

  /** Committed rows are history the journal already carries — drop them so
   *  `touched` stays "uncommitted work" and never grows without bound. */
  pruneCommitted(): number {
    return Number(this.stmt('DELETE FROM touched WHERE committed_sha IS NOT NULL').run().changes);
  }

  /* ---------------- leases ---------------- */

  addLease(input: {
    session_id: string;
    repo: string;
    checkout: string | null;
    kind: LeaseKind;
    item_id: string | null;
    paths: string[];
    intent: string | null;
    now?: number;
  }): string {
    const id = generate();
    this.stmt(
      `INSERT INTO leases
         (id, session_id, repo, checkout, kind, item_id, paths, intent, created_at, released_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    ).run(
      id,
      input.session_id,
      input.repo,
      input.checkout,
      input.kind,
      input.item_id,
      JSON.stringify(input.paths),
      input.intent,
      input.now ?? Date.now(),
    );
    return id;
  }

  listLeases(filter: { session?: string; repo?: string; item?: string; active?: boolean }): LeaseRow[] {
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (filter.session) {
      where.push('session_id = ?');
      params.push(filter.session);
    }
    if (filter.repo) {
      where.push('repo = ?');
      params.push(filter.repo);
    }
    if (filter.item) {
      where.push('item_id = ?');
      params.push(filter.item);
    }
    if (filter.active !== false) where.push('released_at IS NULL');
    const sql = `SELECT * FROM leases${
      where.length > 0 ? ` WHERE ${where.join(' AND ')}` : ''
    } ORDER BY created_at DESC`;
    return this.rows<LeaseRow>(sql, params);
  }

  /**
   * Drop every runtime row belonging to a removed repo.
   *
   * One transaction: a half-cleared repo would leave `who`/`whose` answering
   * about a repo that no longer exists, which is worse than not clearing at
   * all.
   */
  forgetRepo(slug: string, checkouts: readonly string[] = []): void {
    this.tx(() => {
      this.stmt('DELETE FROM leases WHERE repo = ?').run(slug);
      this.stmt('DELETE FROM touched WHERE repo = ?').run(slug);
      this.stmt('DELETE FROM inbox WHERE repo = ?').run(slug);
      // Sessions are not deleted — a live session simply loses its home repo,
      // and killing the row would orphan its delta cursor and title.
      this.stmt('UPDATE sessions SET home_repo = NULL WHERE home_repo = ?').run(slug);
      this.stmt('DELETE FROM git_cache WHERE repo = ?').run(slug);
      // A checkout registered before the repo got its slug has `repo` NULL.
      for (const checkout of checkouts) {
        this.stmt('DELETE FROM git_cache WHERE checkout = ?').run(checkout);
      }
    });
  }

  getLease(id: string): LeaseRow | null {
    return this.row<LeaseRow>('SELECT * FROM leases WHERE id = ?', [id]);
  }

  /** Replace a lease's path set — the auto-lease (SPEC §10.3 rule 5b) grows as
   *  the session touches more files instead of inserting a row per file. */
  setLeasePaths(id: string, paths: string[]): void {
    this.stmt('UPDATE leases SET paths = ? WHERE id = ? AND released_at IS NULL').run(
      JSON.stringify(paths),
      id,
    );
  }

  releaseLease(id: string, now = Date.now()): boolean {
    return (
      Number(
        this.stmt('UPDATE leases SET released_at = ? WHERE id = ? AND released_at IS NULL').run(
          now,
          id,
        ).changes,
      ) > 0
    );
  }

  releaseLeases(filter: { session?: string; item?: string; kind?: LeaseKind }, now = Date.now()): number {
    const where = ['released_at IS NULL'];
    const params: (string | number)[] = [now];
    if (filter.session) {
      where.push('session_id = ?');
      params.push(filter.session);
    }
    if (filter.item) {
      where.push('item_id = ?');
      params.push(filter.item);
    }
    if (filter.kind) {
      where.push('kind = ?');
      params.push(filter.kind);
    }
    return Number(
      this.stmt(`UPDATE leases SET released_at = ? WHERE ${where.join(' AND ')}`).run(...params)
        .changes,
    );
  }

  /* ---------------- inbox (table only in F1) ---------------- */

  addInbox(input: {
    to_session: string;
    from_session: string | null;
    repo: string | null;
    item_id: string | null;
    body: string;
    // B2-1: required at this layer — every caller must say who
    // actually composed the message, so the column can never silently fall
    // back to a value a client controls.
    origin: InboxOrigin;
    now?: number;
  }): string {
    const id = generate();
    this.stmt(
      `INSERT INTO inbox (id, to_session, from_session, repo, item_id, body, origin, created_at, delivered_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    ).run(
      id,
      input.to_session,
      input.from_session,
      input.repo,
      input.item_id,
      input.body,
      input.origin,
      input.now ?? Date.now(),
    );
    // One place that knows "the hub now owes this session output", so
    // the marker cannot drift out of sync with the five callers of `addInbox`.
    // Fire-and-forget on purpose: the marker is an optimisation, and `addInbox`
    // is synchronous by contract (it returns the id).
    this.onInbox?.(input.to_session);
    return id;
  }

  /** Set by `server.ts` to `PendingMarks.owe`. Never throws — the
   *  implementation swallows its own IO errors. */
  onInbox: ((to_session: string) => void) | null = null;

  listInbox(to_session: string, undeliveredOnly = true): InboxMessage[] {
    const rows = this.rows<
      Omit<InboxMessage, 'created_at' | 'delivered_at'> & {
        created_at: number;
        delivered_at: number | null;
      }
    >(
      `SELECT * FROM inbox WHERE to_session = ?${
        undeliveredOnly ? ' AND delivered_at IS NULL' : ''
      } ORDER BY created_at`,
      [to_session],
    );
    return rows.map((r) => ({
      ...r,
      created_at: isoLocal(new Date(r.created_at)),
      delivered_at: r.delivered_at === null ? null : isoLocal(new Date(r.delivered_at)),
    }));
  }

  markInboxDelivered(ids: string[], now = Date.now()): void {
    const stmt = this.stmt('UPDATE inbox SET delivered_at = ? WHERE id = ? AND delivered_at IS NULL');
    for (const id of ids) stmt.run(now, id);
  }

  /* ---------------- git cache ---------------- */

  putGitCache(row: Omit<GitCacheRow, 'refreshed_at'> & { refreshed_at?: number }): void {
    this.stmt(
      `INSERT INTO git_cache (checkout, repo, head, branch, ahead, behind, dirty, worktrees, refreshed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(checkout) DO UPDATE SET
         repo = excluded.repo, head = excluded.head, branch = excluded.branch,
         ahead = excluded.ahead, behind = excluded.behind, dirty = excluded.dirty,
         worktrees = excluded.worktrees, refreshed_at = excluded.refreshed_at`,
    ).run(
      row.checkout,
      row.repo,
      row.head,
      row.branch,
      row.ahead,
      row.behind,
      row.dirty,
      row.worktrees,
      row.refreshed_at ?? Date.now(),
    );
  }

  getGitCache(checkout: string): GitCacheRow | null {
    return this.row<GitCacheRow>('SELECT * FROM git_cache WHERE checkout = ?', [checkout]);
  }

  /* ---------------- seen refs (commit watcher) ---------------- */

  getSeenRef(checkout: string, ref: string): string | null {
    const row = this.row<{ value: string }>(
      'SELECT value FROM seen_refs WHERE checkout = ? AND ref = ?',
      [checkout, ref],
    );
    return row?.value ?? null;
  }

  putSeenRef(checkout: string, ref: string, value: string, now = Date.now()): void {
    this.stmt(
      `INSERT INTO seen_refs (checkout, ref, value, seen_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(checkout, ref) DO UPDATE SET value = excluded.value, seen_at = excluded.seen_at`,
    ).run(checkout, ref, value, now);
  }

  /* ---------------- idempotency (spool replay) ---------------- */

  /**
   * Remember what a keyed write produced, so replaying it returns the first
   * answer instead of doing the work twice.
   *
   * `INSERT OR IGNORE`: two replays racing must not throw on the PK; the first
   * writer wins and the second reads its row back.
   */
  rememberIdempotent(input: {
    key: string;
    method: string;
    path: string;
    status: number;
    response: string;
    bodyHash: string;
    now?: number;
  }): void {
    this.stmt(
      `INSERT OR IGNORE INTO idempotency (key, method, path, status, response, body_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      input.key,
      input.method,
      input.path,
      input.status,
      input.response,
      input.bodyHash,
      input.now ?? Date.now(),
    );
  }

  getIdempotent(key: string): IdempotencyRow | null {
    return this.row<IdempotencyRow>('SELECT * FROM idempotency WHERE key = ?', [key]);
  }

  /* ---------------- replies ---------------- */

  insertReply(input: {
    item_id: string;
    repo: string;
    target_session: string | null;
    mode: ReplyMode;
    text: string;
    recommended: boolean;
    status: ReplyStatus;
    /** B3-1: who actually reached the endpoint — 'web' for a UI cookie
     *  caller, anything else (e.g. 'agent') for a token caller. Drives the
     *  inbox `origin` on delivery; never a constant. */
    author: string;
    now?: number;
  }): ReplyRow {
    const id = generate();
    this.stmt(
      `INSERT INTO replies
         (id, item_id, repo, target_session, mode, text, recommended, status,
          result, created_at, delivered_at, finished_at, author)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL, ?)`,
    ).run(
      id,
      input.item_id,
      input.repo,
      input.target_session,
      input.mode,
      input.text,
      input.recommended ? 1 : 0,
      input.status,
      input.now ?? Date.now(),
      input.author,
    );
    return this.getReply(id) as ReplyRow;
  }

  getReply(id: string): ReplyRow | null {
    return this.row<ReplyRow>('SELECT * FROM replies WHERE id = ?', [id]);
  }

  listRepliesForItem(itemId: string): ReplyRow[] {
    return this.rows<ReplyRow>(
      'SELECT * FROM replies WHERE item_id = ? ORDER BY created_at DESC',
      [itemId],
    );
  }

  /**
   * Newest reply per item, for a whole page of items in ONE query.
   *
   * This exists precisely so the items list does not do a query per row. The
   * `GROUP BY` + `MAX(created_at)` form is the bare-columns trick SQLite
   * documents: with an aggregate, the other columns come from the row that
   * produced the max, so no self-join or window function is needed.
   */
  lastRepliesFor(itemIds: readonly string[]): Map<string, ReplyRow> {
    const out = new Map<string, ReplyRow>();
    if (itemIds.length === 0) return out;
    // Chunked: SQLite's default parameter ceiling is 999 and a ledger page can
    // exceed that. Still O(1) queries per chunk, never per item.
    const CHUNK = 500;
    for (let i = 0; i < itemIds.length; i += CHUNK) {
      const chunk = itemIds.slice(i, i + CHUNK);
      const rows = this.rows<ReplyRow>(
        `SELECT *, MAX(created_at) AS _max FROM replies
          WHERE item_id IN (${chunk.map(() => '?').join(', ')})
          GROUP BY item_id`,
        [...chunk],
      );
      for (const r of rows) out.set(r.item_id, r);
    }
    return out;
  }

  /** Replies a session still has to act on, for the delivered/working walk. */
  listRepliesForSession(session: string, statuses: readonly ReplyStatus[]): ReplyRow[] {
    if (statuses.length === 0) return [];
    return this.rows<ReplyRow>(
      `SELECT * FROM replies
        WHERE target_session = ? AND status IN (${statuses.map(() => '?').join(', ')})
        ORDER BY created_at`,
      [session, ...statuses],
    );
  }

  listRepliesByStatus(statuses: readonly ReplyStatus[]): ReplyRow[] {
    if (statuses.length === 0) return [];
    return this.rows<ReplyRow>(
      `SELECT * FROM replies WHERE status IN (${statuses.map(() => '?').join(', ')})
        ORDER BY created_at`,
      [...statuses],
    );
  }

  /**
   * Status transition. `delivered_at` / `finished_at` are stamped by the status
   * they belong to rather than by the caller, so a transition cannot land with
   * a missing timestamp.
   */
  updateReply(input: {
    id: string;
    status: ReplyStatus;
    result?: string | null;
    now?: number;
  }): ReplyRow | null {
    const now = input.now ?? Date.now();
    const terminal =
      input.status === 'done' || input.status === 'failed' || input.status === 'needs_chat_auth';
    this.stmt(
      `UPDATE replies SET
         status = ?,
         result = COALESCE(?, result),
         delivered_at = CASE WHEN delivered_at IS NULL AND ? IN ('delivered','working','done')
                             THEN ? ELSE delivered_at END,
         finished_at = CASE WHEN ? = 1 THEN ? ELSE finished_at END
       WHERE id = ?`,
    ).run(
      input.status,
      input.result ?? null,
      input.status,
      now,
      terminal ? 1 : 0,
      now,
      input.id,
    );
    return this.getReply(input.id);
  }

  /** How many worker runs are in flight — the concurrency gate (max 2). */
  countRunningReplies(): number {
    const row = this.row<{ n: number }>(
      "SELECT COUNT(*) AS n FROM replies WHERE mode = 'worker' AND status = 'working'",
      [],
    );
    return Number(row?.n ?? 0);
  }

  /* ---------------- v0.4.0 context feeds ---------------- */

  /**
   * once-only guard. Returns true the FIRST time a key is seen.
   *
   * This is the whole token budget story: every v0.4.0 feed asks `markOnce`
   * before it writes anything into an agent's context, so a reminder costs its
   * characters once per session (or once per commit+consumer), never once per
   * hook call.
   */
  markOnce(kind: string, key: string, now = Date.now()): boolean {
    const res = this.stmt(
      'INSERT OR IGNORE INTO marks (kind, key, created_at) VALUES (?, ?, ?)',
    ).run(kind, key, now);
    return Number(res.changes ?? 0) > 0;
  }

  /** B1-9: undo a `markOnce` claim when the side effect it guarded failed —
   *  so a redelivered event (watcher restart, retried commit) gets a real
   *  retry instead of being silently treated as already-handled. */
  clearMark(kind: string, key: string): void {
    this.stmt('DELETE FROM marks WHERE kind = ? AND key = ?').run(kind, key);
  }

  /** How many keys of a kind exist — the per-session caps (5 files). */
  countMarks(kind: string, prefix: string): number {
    const row = this.row<{ n: number }>(
      "SELECT COUNT(*) AS n FROM marks WHERE kind = ? AND key LIKE ? ESCAPE '\\'",
      [kind, `${prefix.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`],
    );
    return Number(row?.n ?? 0);
  }

  /* ---- running session facts ---- */

  getSessionFacts(session: string, repo: string): SessionFactsRow | null {
    return this.row<SessionFactsRow>(
      'SELECT * FROM session_facts WHERE session = ? AND repo = ?',
      [session, repo],
    );
  }

  /** `ledger why`: the most recently active session summaries of a repo. */
  sessionFactsRecent(repo: string, limit: number): SessionFactsRow[] {
    return this.rows<SessionFactsRow>(
      'SELECT * FROM session_facts WHERE repo = ? ORDER BY last_at DESC LIMIT ?',
      [repo, limit],
    );
  }

  /**
   * Record activity for the rolling summary. Commits are merged as a set (a
   * redelivered commit must not double up) and `why` only ever overwrites when
   * the caller passes one, so a later edit cannot erase a `ledger log`.
   *
   * One explicit transaction per call: the read-modify-write of `commits` would
   * otherwise interleave with a concurrent hook on the same session.
   */
  addSessionFact(input: {
    session: string;
    repo: string;
    files?: string[];
    commits?: { sha: string; subject: string }[];
    why?: string | null;
    now?: number;
  }): void {
    const now = input.now ?? Date.now();
    this.tx(() => {
      const prev = this.getSessionFacts(input.session, input.repo);
      const commits = JSON.stringify(
        dedupeCommits([...parseCommits(prev?.commits), ...(input.commits ?? [])]).slice(-20),
      );
      const known = new Set(parseList(prev?.files));
      const added = (input.files ?? []).filter((f) => !known.has(f));
      const files = JSON.stringify([...known, ...added].slice(0, FACT_FILES_CAP));
      const fileCount = Number(prev?.file_count ?? 0) + added.length;
      const why = input.why === undefined ? (prev?.why ?? null) : input.why;
      if (prev === null) {
        this.stmt(
          `INSERT INTO session_facts
             (session, repo, first_at, last_at, files, file_count, commits, why)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(input.session, input.repo, now, now, files, fileCount, commits, why);
        return;
      }
      this.stmt(
        `UPDATE session_facts
            SET last_at = ?, files = ?, file_count = ?, commits = ?, why = ?
          WHERE session = ? AND repo = ?`,
      ).run(now, files, fileCount, commits, why, input.session, input.repo);
    });
  }

  /** Item activity of one session, newest last. Derived from `changes`
   *  so nothing has to be mirrored at every item route. */
  changesByActor(actor: string, sinceMs: number, limit = 200): ChangeRow[] {
    return this.rows<ChangeRow>(
      'SELECT * FROM changes WHERE actor = ? AND at >= ? ORDER BY seq LIMIT ?',
      [actor, sinceMs, limit],
    );
  }

  /** Mark a summary as written. `flushed_last` pins the `last_at` it covered,
   *  so "has anything happened since the last summary?" is one comparison. */
  markSummaryFlushed(session: string, repo: string, coveredLastAt: number, now = Date.now()): void {
    this.stmt(
      'UPDATE session_facts SET flushed_at = ?, flushed_last = ? WHERE session = ? AND repo = ?',
    ).run(now, coveredLastAt, session, repo);
  }

  /**  b): sessions idle longer than `idleMs` with activity since their
   *  last summary. Ordered oldest first so a backlog drains deterministically. */
  summariesDue(idleMs: number, now = Date.now()): SessionFactsRow[] {
    return this.rows<SessionFactsRow>(
      `SELECT * FROM session_facts
        WHERE last_at <= ?
          AND (flushed_last IS NULL OR flushed_last < last_at)
        ORDER BY last_at
        LIMIT 50`,
      [now - idleMs],
    );
  }

  forgetSessionFacts(session: string, repo?: string): void {
    if (repo === undefined) {
      this.stmt('DELETE FROM session_facts WHERE session = ?').run(session);
      return;
    }
    this.stmt('DELETE FROM session_facts WHERE session = ? AND repo = ?').run(session, repo);
  }

  /* ---- where in the code an item lives ---- */

  /** Files of a commit that named `itemId` in `Refs:`/`Closes:`. Rows are a
   *  set per (repo, item, path); `n` counts commits. Capped per item so a long
   *  lived item cannot grow without bound — the oldest paths go first. */
  addItemFiles(repo: string, itemId: string, files: readonly string[], now = Date.now()): void {
    if (files.length === 0) return;
    this.tx(() => {
      const upsert = this.stmt(
        `INSERT INTO item_files (repo, item_id, path, n, last_at) VALUES (?, ?, ?, 1, ?)
         ON CONFLICT(repo, item_id, path) DO UPDATE SET n = n + 1, last_at = excluded.last_at`,
      );
      for (const f of files) upsert.run(repo, itemId, f, now);
      this.stmt(
        `DELETE FROM item_files WHERE repo = ? AND item_id = ? AND path NOT IN (
           SELECT path FROM item_files WHERE repo = ? AND item_id = ?
            ORDER BY last_at DESC, n DESC, path LIMIT ?)`,
      ).run(repo, itemId, repo, itemId, ITEM_FILES_CAP);
    });
  }

  /** Newest first, then the most-touched. */
  itemFiles(repo: string, itemId: string, limit = ITEM_FILES_CAP): { path: string; n: number }[] {
    return this.rows<{ path: string; n: number }>(
      'SELECT path, n FROM item_files WHERE repo = ? AND item_id = ? ORDER BY last_at DESC, n DESC, path LIMIT ?',
      [repo, itemId, limit],
    );
  }

  /** `ledger why`: item files whose path starts with `prefix` (plain string, LIKE
   *  wildcards escaped; SQLite LIKE is ASCII case-insensitive, so the caller
   *  re-matches exactly). Newest first, capped. Scans one repo's rows — the table
   *  is `ITEM_FILES_CAP` rows per item, and there is deliberately no new index
   *  (no schema change for a read-only lookup). */
  itemFilesUnder(
    repo: string,
    prefix: string,
    limit: number,
  ): { item_id: string; path: string; n: number; last_at: number }[] {
    return this.rows<{ item_id: string; path: string; n: number; last_at: number }>(
      `SELECT item_id, path, n, last_at FROM item_files
        WHERE repo = ? AND path LIKE ? ESCAPE '\\'
        ORDER BY last_at DESC, n DESC LIMIT ?`,
      [repo, `${prefix.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`, limit],
    );
  }

  /** Sessions that claimed or closed the item, newest first — the link from an
   *  item to the `session_facts` rows that say what those sessions touched. */
  itemWorkers(repo: string, itemId: string, limit = 3): string[] {
    return this.rows<{ actor: string }>(
      `SELECT actor FROM changes
        WHERE repo = ? AND item_id = ? AND actor IS NOT NULL AND kind IN ('claimed', 'done')
        GROUP BY actor ORDER BY MAX(seq) DESC LIMIT ?`,
      [repo, itemId, limit],
    ).map((r) => r.actor);
  }

  /** Keys of one mark kind under a prefix — for budgets that need the keys'
   *  payload (  the characters it spent in the key). */
  markKeys(kind: string, prefix: string): string[] {
    return this.rows<{ key: string }>(
      "SELECT key FROM marks WHERE kind = ? AND key LIKE ? ESCAPE '\\'",
      [kind, `${prefix.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`],
    ).map((r) => r.key);
  }

  /* ---- structural commits ---- */

  addStructCommit(repo: string, sha: string, reason: string, at = Date.now()): void {
    this.stmt(
      'INSERT OR IGNORE INTO struct_commits (repo, sha, at, reason) VALUES (?, ?, ?, ?)',
    ).run(repo, sha, at, reason);
  }

  structCommitsSince(repo: string, sinceMs: number): { sha: string; at: number; reason: string }[] {
    return this.rows<{ sha: string; at: number; reason: string }>(
      'SELECT sha, at, reason FROM struct_commits WHERE repo = ? AND at > ? ORDER BY at',
      [repo, sinceMs],
    );
  }

  /* ---- brief marks ---- */

  getBriefMark(session: string, repo: string): BriefMarkRow | null {
    return this.row<BriefMarkRow>('SELECT * FROM brief_marks WHERE session = ? AND repo = ?', [
      session,
      repo,
    ]);
  }

  putBriefMark(input: {
    session: string;
    repo: string;
    change_seq: number;
    digest: string;
    now?: number;
  }): void {
    this.stmt(
      `INSERT INTO brief_marks (session, repo, at, change_seq, digest)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(session, repo) DO UPDATE SET
         at = excluded.at, change_seq = excluded.change_seq, digest = excluded.digest`,
    ).run(input.session, input.repo, input.now ?? Date.now(), input.change_seq, input.digest);
  }

  /* ---------------- search ---------------- */

  /** Full rebuild. md is the source of truth (SPEC §5): the index is thrown
   *  away and rewritten rather than diffed, which keeps deletes correct for
   *  free and takes milliseconds for a ledger of this size. */
  rebuildSearch(docs: SearchDoc[]): void {
    const table = this.engine === 'fts5' ? 'fts' : 'fts_like';
    this.tx(() => {
      this.db.exec(`DELETE FROM ${table}`);
      const stmt = this.stmt(
        `INSERT INTO ${table} (kind, ref, repo, title, body) VALUES (?, ?, ?, ?, ?)`,
      );
      for (const d of docs) stmt.run(d.kind, d.ref, d.repo, d.title, d.body);
    });
  }

  search(q: string, limit: number, repo?: string): SearchHit[] {
    return this.engine === 'fts5' ? this.searchFts(q, limit, repo) : this.searchLike(q, limit, repo);
  }

  /**
   * `search` plus the raw BM25 score, which the relevance threshold
   * needs. Kept separate from `search` so the `/v1/search` response contract
   * does not grow a column nobody asked for.
   *
   * BM25 in SQLite is NEGATIVE and smaller is better; the LIKE fallback has no
   * score at all, so it reports `null` and the caller falls back to keyword
   * overlap alone. Restricted to the kinds that carry a "why" a human would
   * recognise — `context` and `intake` docs are whole files and match almost
   * any prompt, which is exactly the noise this feature must not add.
   */
  searchScored(
    q: string,
    limit: number,
    opts: { repo?: string | undefined; kinds?: readonly string[] | undefined } = {},
  ): ScoredHit[] {
    // OR, not AND. `ftsQuery` builds the implicit-AND query `/v1/search` wants
    // ("find the doc with all these words"); a 10-word prompt would then match
    // nothing at all.   the opposite question — "which docs share
    // words with this prompt" — and the threshold is what filters, not the
    // query. This was a real bug: the feed silently returned zero hits.
    const match = ftsAnyQuery(q);
    if (match === '') return [];
    const kinds = opts.kinds ?? [];
    const kindSql = kinds.length > 0 ? ` AND kind IN (${kinds.map(() => '?').join(', ')})` : '';
    if (this.engine !== 'fts5') {
      // No ranking available: hand back candidates and let the caller score.
      const needle = `%${q.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
      const params: (string | number | null)[] = [needle, needle];
      if (opts.repo) params.push(opts.repo);
      params.push(...kinds, limit);
      return this.rows<ScoredHit>(
        `SELECT kind, ref, repo, title, substr(body, 1, 400) AS excerpt, NULL AS score
           FROM fts_like
          WHERE (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')${
            opts.repo ? ' AND repo = ?' : ''
          }${kindSql}
          LIMIT ?`,
        params,
      );
    }
    const params: (string | number | null)[] = [match];
    if (opts.repo) params.push(opts.repo);
    params.push(...kinds, limit);
    return this.rows<ScoredHit>(
      `SELECT kind, ref, repo, title,
              snippet(fts, 4, '', '', '…', 10) AS excerpt,
              bm25(fts, 0, 0, 0, 4.0, 1.0) AS score
         FROM fts
        WHERE fts MATCH ?${opts.repo ? ' AND repo = ?' : ''}${kindSql}
        ORDER BY score
        LIMIT ?`,
      params,
    );
  }

  /** FTS5 `MATCH`. The query is quoted as a phrase per token so user input can
   *  never be read as FTS syntax (`NEAR`, `*`, `:` column filters, `-`). */
  private searchFts(q: string, limit: number, repo?: string): SearchHit[] {
    const match = ftsQuery(q);
    if (match === '') return [];
    return this.rows<SearchHit>(
      `SELECT kind, ref, repo, title,
              snippet(fts, 4, '', '', '…', 12) AS excerpt
         FROM fts
        WHERE fts MATCH ?${repo ? ' AND repo = ?' : ''}
        ORDER BY bm25(fts, 0, 0, 0, 4.0, 1.0)
        LIMIT ?`,
      repo ? [match, repo, limit] : [match, limit],
    );
  }

  private searchLike(q: string, limit: number, repo?: string): SearchHit[] {
    const needle = `%${q.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
    return this.rows<SearchHit>(
      `SELECT kind, ref, repo, title, substr(body, 1, 200) AS excerpt
         FROM fts_like
        WHERE (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')${repo ? ' AND repo = ?' : ''}
        LIMIT ?`,
      repo ? [needle, needle, repo, limit] : [needle, needle, limit],
    );
  }
}

/* ---------------- v0.4.0 row shapes + list helpers ---------------- */

/** Paths kept verbatim per session summary. Beyond this only `file_count`
 *  grows — the summary prints a count and top directories, never the list. */
export const FACT_FILES_CAP = 200;
/** Paths remembered per item. */
export const ITEM_FILES_CAP = 30;

export interface SessionFactsRow {
  session: string;
  repo: string;
  first_at: number;
  last_at: number;
  /** JSON array of rel paths, capped at `FACT_FILES_CAP`. */
  files: string;
  /** Total distinct paths seen, including the ones past the cap. */
  file_count: number;
  /** JSON array of `{ sha, subject }`. */
  commits: string;
  why: string | null;
  flushed_at: number | null;
  flushed_last: number | null;
}

export interface BriefMarkRow {
  session: string;
  repo: string;
  at: number;
  change_seq: number;
  digest: string;
}

export interface ScoredHit extends SearchHit {
  /** BM25 (negative, lower is better) or null on the LIKE fallback. */
  score: number | null;
}

/** A corrupt JSON column is a cache miss, never a throw on the hook path. */
export function parseList(raw: string | undefined | null): string[] {
  if (typeof raw !== 'string' || raw === '') return [];
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function parseCommits(raw: string | undefined | null): { sha: string; subject: string }[] {
  if (typeof raw !== 'string' || raw === '') return [];
  try {
    const v: unknown = JSON.parse(raw);
    if (!Array.isArray(v)) return [];
    return v.flatMap((x) => {
      if (x === null || typeof x !== 'object') return [];
      const o = x as Record<string, unknown>;
      if (typeof o.sha !== 'string') return [];
      return [{ sha: o.sha, subject: typeof o.subject === 'string' ? o.subject : '' }];
    });
  } catch {
    return [];
  }
}

function dedupeCommits(list: { sha: string; subject: string }[]): { sha: string; subject: string }[] {
  const seen = new Set<string>();
  const out: { sha: string; subject: string }[] = [];
  for (const c of list) {
    if (seen.has(c.sha)) continue;
    seen.add(c.sha);
    out.push(c);
  }
  return out;
}

/** `auth token` → `"auth" "token"` — every token becomes a literal phrase. */
export function ftsQuery(raw: string): string {
  const tokens = raw
    .split(/[\s]+/)
    .map((t) => t.replace(/["]/g, '').trim())
    // G8: a token with no alphanumeric char (e.g. bare `-`) is FTS5 syntax
    // (column filter / NOT-prefix) with nothing to quote around it — quoting
    // still leaves an empty `""` that FTS5 rejects as a syntax error (500).
    // Drop it instead of passing it through.
    .filter((t) => /[\p{L}\p{N}]/u.test(t));
  if (tokens.length === 0) return '';
  return tokens.map((t) => `"${t}"`).join(' ');
}

/** `auth token` → `"auth" OR "token"` — same quoting rules as `ftsQuery`, but
 *  any single token is enough to be a candidate. */
export function ftsAnyQuery(raw: string): string {
  const quoted = ftsQuery(raw);
  if (quoted === '') return '';
  return quoted.split(' ').join(' OR ');
}

/* ---------------- row shapes ---------------- */

export interface ReplyRow {
  id: string;
  item_id: string;
  repo: string;
  target_session: string | null;
  mode: ReplyMode;
  text: string;
  /** SQLite has no boolean — 0/1. */
  recommended: number;
  status: ReplyStatus;
  result: string | null;
  created_at: number;
  delivered_at: number | null;
  finished_at: number | null;
  /** B3-1: 'web' for a UI cookie caller, anything else for a token caller. */
  author: string;
}

export interface ChangeRow {
  seq: number;
  repo: string;
  item_id: string;
  kind: string;
  actor: string | null;
  title: string;
  commit_sha: string | null;
  at: number;
}

export interface IdempotencyRow {
  key: string;
  method: string;
  path: string;
  status: number;
  response: string;
  body_hash: string | null;
  created_at: number;
}
