/**
 * Runtime state schema — SPEC §5. `<ledger>/.hub/hub.sqlite`, `node:sqlite`.
 *
 * This DB holds only *live* state (sessions, touched files, leases, inbox, git
 * cache) plus a rebuildable search index. Losing it costs the live view and
 * nothing else: md under the ledger stays the source of truth and `rebuild()`
 * repopulates search from it. That is why there is no migration that has to
 * preserve data — but `PRAGMA user_version` is still stepped one migration at a
 * time inside an explicit transaction, so a half-applied schema is impossible.
 *
 * Time columns are epoch milliseconds (INTEGER), not text: the ledger's ISO
 * form carries a local offset, which sorts and compares wrong across a DST
 * change. The API converts to `isoLocal()` on the way out.
 */

import { DatabaseSync } from 'node:sqlite';
import type { SearchEngine } from '@agent-ledger/shared';

export interface OpenDbResult {
  db: DatabaseSync;
  engine: SearchEngine;
}

const MIGRATIONS: readonly ((db: DatabaseSync) => void)[] = [
  // 1 — SPEC §5 tables.
  (db) => {
    db.exec(`
      CREATE TABLE sessions (
        id              TEXT PRIMARY KEY,
        row_id          TEXT NOT NULL,
        home_repo       TEXT,
        cwd             TEXT,
        checkout        TEXT,
        branch          TEXT,
        transcript_path TEXT,
        started_at      INTEGER NOT NULL,
        last_seen       INTEGER NOT NULL,
        ended_at        INTEGER,
        source          TEXT NOT NULL DEFAULT 'startup'
      );
      CREATE INDEX sessions_repo  ON sessions(home_repo, ended_at);
      CREATE INDEX sessions_seen  ON sessions(last_seen);

      CREATE TABLE touched (
        id            TEXT PRIMARY KEY,
        session_id    TEXT NOT NULL,
        repo          TEXT NOT NULL,
        checkout      TEXT NOT NULL,
        rel_path      TEXT NOT NULL,
        via           TEXT NOT NULL,
        agent_type    TEXT,
        first_at      INTEGER NOT NULL,
        last_at       INTEGER NOT NULL,
        committed_sha TEXT,
        UNIQUE(session_id, checkout, rel_path)
      );
      CREATE INDEX touched_path    ON touched(checkout, rel_path, committed_sha);
      CREATE INDEX touched_session ON touched(session_id, committed_sha);
      CREATE INDEX touched_repo    ON touched(repo, committed_sha);

      CREATE TABLE leases (
        id          TEXT PRIMARY KEY,
        session_id  TEXT NOT NULL,
        repo        TEXT NOT NULL,
        checkout    TEXT,
        kind        TEXT NOT NULL,
        item_id     TEXT,
        paths       TEXT NOT NULL DEFAULT '[]',
        intent      TEXT,
        created_at  INTEGER NOT NULL,
        released_at INTEGER
      );
      CREATE INDEX leases_session ON leases(session_id, released_at);
      CREATE INDEX leases_repo    ON leases(repo, released_at);
      CREATE INDEX leases_item    ON leases(item_id, released_at);

      CREATE TABLE inbox (
        id           TEXT PRIMARY KEY,
        to_session   TEXT NOT NULL,
        from_session TEXT,
        repo         TEXT,
        item_id      TEXT,
        body         TEXT NOT NULL,
        created_at   INTEGER NOT NULL,
        delivered_at INTEGER
      );
      CREATE INDEX inbox_to ON inbox(to_session, delivered_at);

      CREATE TABLE git_cache (
        checkout     TEXT PRIMARY KEY,
        repo         TEXT,
        head         TEXT,
        branch       TEXT,
        ahead        INTEGER,
        behind       INTEGER,
        dirty        TEXT NOT NULL DEFAULT '[]',
        worktrees    TEXT NOT NULL DEFAULT '[]',
        refreshed_at INTEGER NOT NULL
      );

      /* Last HEAD the commit watcher processed, per checkout (SPEC §12). */
      CREATE TABLE seen_refs (
        checkout TEXT NOT NULL,
        ref      TEXT NOT NULL,
        value    TEXT NOT NULL,
        seen_at  INTEGER NOT NULL,
        PRIMARY KEY (checkout, ref)
      );
    `);
  },

  // 2 — idempotency, session titles, replies.
  //
  // Additive only: new columns are nullable with no default backfill needed,
  // and the new tables start empty. An older hub binary against this schema
  // keeps working (it just ignores the columns), which is what makes the
  // migration forward-compatible rather than a flag day.
  (db) => {
    db.exec(`
      /* Session name as shown in the agent UI sidebar, recovered
         from the transcript. Untrusted text — single-lined, capped and secret
         scanned before it is ever written here. */
      ALTER TABLE sessions ADD COLUMN title TEXT;
      /* 'claude' | 'summary' | 'prompt' | NULL — NULL iff title IS NULL. */
      ALTER TABLE sessions ADD COLUMN title_source TEXT;
      /* Last transcript read, ms. Throttles the re-read to once per 60 s. */
      ALTER TABLE sessions ADD COLUMN title_read_at INTEGER;

      /* Replay ledger. A spooled CLI write carries an Idempotency-Key;
         the hub remembers the key with the response it produced, so a double
         replay returns the first answer instead of creating a second item.
         Pruned to 30 days on open — a key older than that cannot still be in
         any spool file we would accept. */
      CREATE TABLE idempotency (
        key         TEXT PRIMARY KEY,
        method      TEXT NOT NULL,
        path        TEXT NOT NULL,
        status      INTEGER NOT NULL,
        response    TEXT NOT NULL,
        created_at  INTEGER NOT NULL
      );
      CREATE INDEX idempotency_created ON idempotency(created_at);

      /* A user reply typed in the web UI, routed to the session that
         owns the item or to a headless worker. */
      CREATE TABLE replies (
        id             TEXT PRIMARY KEY,
        item_id        TEXT NOT NULL,
        repo           TEXT NOT NULL,
        target_session TEXT,
        mode           TEXT NOT NULL,
        text           TEXT NOT NULL,
        recommended    INTEGER NOT NULL DEFAULT 0,
        status         TEXT NOT NULL,
        result         TEXT,
        created_at     INTEGER NOT NULL,
        delivered_at   INTEGER,
        finished_at    INTEGER
      );
      CREATE INDEX replies_item    ON replies(item_id, created_at);
      CREATE INDEX replies_session ON replies(target_session, status);
      CREATE INDEX replies_status  ON replies(status, created_at);
    `);
  },

  // 3 — delta feed: an append-only change log plus a per-session cursor.
  //
  // Why a sequence and not a timestamp: the ledger's `updated` field is
  // second-resolution ISO (`isoLocal`), so a millisecond cursor taken at
  // 10:31:11.450 sorts AFTER a change made at 10:31:11.800 (which stamps as
  // …:11.000). That silently dropped every change made in the same second as the
  // cursor — exactly the parallel-session case the feature exists for. A rowid
  // is monotonic by construction, so there is no resolution to get wrong and a
  // change can never be reported twice.
  (db) => {
    db.exec(`
      CREATE TABLE changes (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        repo       TEXT NOT NULL,
        item_id    TEXT NOT NULL,
        /* created | done | dropped | claimed | reopened | released | updated */
        kind       TEXT NOT NULL,
        /* Full session id of whoever made the change, when known. */
        actor      TEXT,
        title      TEXT NOT NULL,
        commit_sha TEXT,
        at         INTEGER NOT NULL
      );
      CREATE INDEX changes_repo ON changes(repo, seq);

      /* Highest changes.seq already shown to this session. NULL = nothing shown
         yet, which makes the first prompt start the clock rather than replay the
         whole backlog. */
      ALTER TABLE sessions ADD COLUMN delta_cursor INTEGER;
    `);
  },

  // 4 — R2-04: an `Idempotency-Key` replay is only the SAME request replayed.
  // Without a body hash, a key reused with a different method/path/body (a
  // collision, or a client bug) silently returned the FIRST response instead
  // of re-validating — `body_hash` lets the guard 422 a mismatch instead.
  // Nullable: rows written before this migration have no hash and are treated
  // as "cannot verify, so mismatch" by the app layer, never as a free pass.
  (db) => {
    db.exec(`ALTER TABLE idempotency ADD COLUMN body_hash TEXT;`);
  },

  // 5 — v0.4.0 context feeds: "did we already say this?" marks,
  // running session facts, contract-change dedupe,
  // structural commits, per-session brief marks.
  //
  // Additive only (new tables, nothing altered). Every one of them is *cache*:
  // dropping the file costs at most one duplicated context line, never a
  // ledger fact, which is why none of them is written to md.
  (db) => {
    db.exec(`
      /* "this text was already shown / this item already made".
         One row per (kind, key); inserts are OR IGNORE so the caller learns
         from "changes" whether it was the first one. */
      CREATE TABLE marks (
        kind       TEXT NOT NULL,
        key        TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (kind, key)
      );
      CREATE INDEX marks_age ON marks(created_at);

      /* Bookkeeping for the rolling session summary. Item activity is
         NOT duplicated here — it is derived from "changes", which every item
         route already writes. Only the two facts with no other home live here:
         the commits attributed to the session (JSON [{sha, subject}]) and the
         "ledger log" text that becomes the summary's "why". flushed_last pins
         the last_at the written summary covered, which is the whole
         "has anything happened since?" test.

         files is here rather than read back from "touched" because
         pruneCommitted deletes a row the moment its file is committed — the
         summary has to remember what the session touched, not what it still
         holds. Capped at 200 paths; past that only the count keeps growing. */
      CREATE TABLE session_facts (
        session        TEXT NOT NULL,
        repo           TEXT NOT NULL,
        first_at       INTEGER NOT NULL,
        last_at        INTEGER NOT NULL,
        files          TEXT NOT NULL DEFAULT '[]',
        file_count     INTEGER NOT NULL DEFAULT 0,
        commits        TEXT NOT NULL DEFAULT '[]',
        why            TEXT,
        flushed_at     INTEGER,
        flushed_last   INTEGER,
        PRIMARY KEY (session, repo)
      );
      CREATE INDEX session_facts_last ON session_facts(last_at, flushed_last);

      /* Commits that changed the shape of a repo (top-level dirs,
         workspace/script manifests, docker, CI). Pruned by age, counted
         against the mtime of <repo>/CONTEXT.md. */
      CREATE TABLE struct_commits (
        repo    TEXT NOT NULL,
        sha     TEXT NOT NULL,
        at      INTEGER NOT NULL,
        reason  TEXT NOT NULL,
        PRIMARY KEY (repo, sha)
      );
      CREATE INDEX struct_commits_repo ON struct_commits(repo, at);

      /* What the last brief for this session+repo was built from, so a
         resume with nothing new can answer in one line. */
      CREATE TABLE brief_marks (
        session    TEXT NOT NULL,
        repo       TEXT NOT NULL,
        at         INTEGER NOT NULL,
        change_seq INTEGER NOT NULL,
        digest     TEXT NOT NULL,
        PRIMARY KEY (session, repo)
      );
    `);
  },

  // 6 — B2-1: who composed an inbox message, set by the server, not
  // inferred from `from_session == null` (which a client can forge by simply
  // omitting `from` in `POST /v1/inbox`). Backfilled to 'session' — every row
  // written before this migration came from the free-text session path and
  // must stay frame-untrusted on delivery.
  (db) => {
    db.exec(`ALTER TABLE inbox ADD COLUMN origin TEXT NOT NULL DEFAULT 'session';`);
  },

  // 7 — B3-1: who actually wrote a reply, set by the server from which auth
  // path reached the endpoint (the guard's resolved `authPath` —
  // `token` → 'agent', `cookie` → 'web' — not the presence of a header), never
  // a constant. A row written before this migration cannot be re-derived, so
  // it is backfilled to 'agent' — the worker-reply path predates the
  // cookie UI and token callers were the only ones reachable then.
  (db) => {
    db.exec(`ALTER TABLE replies ADD COLUMN author TEXT NOT NULL DEFAULT 'agent';`);
  },

  // 8 — which files the commits that carry `Refs:`/`Closes: <ID>`
  // changed, so the "Related:" hit can say WHERE in the code an item lives
  // without the next session running Explore. One row per (repo, item, path);
  // `n` counts the commits that touched it. Cache like the rest of v0.4.0:
  // dropping it costs paths in a context line, never a ledger fact.
  (db) => {
    db.exec(`
      CREATE TABLE item_files (
        repo    TEXT NOT NULL,
        item_id TEXT NOT NULL,
        path    TEXT NOT NULL,
        n       INTEGER NOT NULL DEFAULT 1,
        last_at INTEGER NOT NULL,
        PRIMARY KEY (repo, item_id, path)
      );
      CREATE INDEX item_files_age ON item_files(last_at);
    `);
  },
];

/** Keys older than this cannot match a spool record we would still
 *  replay, so keeping them only grows the file. */
const IDEMPOTENCY_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** marks: a mark older than this guards nothing — the session it
 *  belonged to is long gone and the commit is no longer "recent". */
const MARK_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** only ever asks "since CONTEXT.md was last written", and a CONTEXT.md
 *  untouched for a quarter is stale on age alone. */
const STRUCT_TTL_MS = 90 * 24 * 60 * 60 * 1000;

/** Paths of an item untouched for half a year are more likely moved
 *  than informative — and the hit marks them "maybe moved" anyway. */
const ITEM_FILES_TTL_MS = 180 * 24 * 60 * 60 * 1000;

/** FTS5 is compiled into the `node:sqlite` build shipped with Node 22/24, but
 *  that is a build-time flag we do not control — probe it and degrade to LIKE
 *  instead of refusing to start. */
function ensureSearch(db: DatabaseSync): SearchEngine {
  try {
    db.exec(
      `CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(
         kind UNINDEXED, ref UNINDEXED, repo UNINDEXED, title, body,
         tokenize = "unicode61 remove_diacritics 2"
       );`,
    );
    return 'fts5';
  } catch {
    db.exec(`
      CREATE TABLE IF NOT EXISTS fts_like (
        kind  TEXT NOT NULL,
        ref   TEXT NOT NULL,
        repo  TEXT NOT NULL,
        title TEXT NOT NULL,
        body  TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS fts_like_repo ON fts_like(repo);
    `);
    return 'like';
  }
}

function migrate(db: DatabaseSync): void {
  const row = db.prepare('PRAGMA user_version').get() as { user_version?: number } | undefined;
  const version = Number(row?.user_version ?? 0);
  for (let i = version; i < MIGRATIONS.length; i += 1) {
    db.exec('BEGIN IMMEDIATE');
    try {
      (MIGRATIONS[i] as (d: DatabaseSync) => void)(db);
      // `user_version` takes a literal only — `i + 1` is a loop counter, never
      // user input, so there is nothing to bind here.
      db.exec(`PRAGMA user_version = ${i + 1}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
}

export function openDb(file: string): OpenDbResult {
  const db = new DatabaseSync(file);
  // WAL: the hub is one writer plus many short readers (HTTP, hooks). WAL keeps
  // a read from ever blocking the hook that is writing `touched`.
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = NORMAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA busy_timeout = 4000');
  migrate(db);
  // Cheap, bounded, and it keeps `idempotency` from growing without limit on a
  // machine that has been offline a lot. Runs once per hub start, not per write.
  //
  // Tolerant on purpose: a DB whose `user_version` is AHEAD of us (a downgrade,
  // which `migrate` deliberately leaves alone) may not have this table, and
  // failing to open a readable DB over a cache prune would be absurd.
  try {
    db.prepare('DELETE FROM idempotency WHERE created_at < ?').run(Date.now() - IDEMPOTENCY_TTL_MS);
  } catch {
    /* table not present on a schema we did not migrate — nothing to prune */
  }
  // v0.4.0 caches. Same reasoning as above: bounded, once per boot. A pruned
  // mark can at most re-show one context line; a pruned struct commit can at
  // most under-count the CONTEXT.md staleness, which fails quiet, not loud.
  try {
    db.prepare('DELETE FROM marks WHERE created_at < ?').run(Date.now() - MARK_TTL_MS);
    db.prepare('DELETE FROM struct_commits WHERE at < ?').run(Date.now() - STRUCT_TTL_MS);
    db.prepare('DELETE FROM item_files WHERE last_at < ?').run(Date.now() - ITEM_FILES_TTL_MS);
  } catch {
    /* pre-migration-5 schema — nothing to prune */
  }
  const engine = ensureSearch(db);
  return { db, engine };
}
