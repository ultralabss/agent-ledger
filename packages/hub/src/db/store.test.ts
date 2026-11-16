/** SQLite runtime state: migrations, WAL, FTS5 detection, transactions. */

import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { openDb } from './schema.ts';
import { ftsQuery, RuntimeStore } from './store.ts';

async function tempDb(): Promise<{ file: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-db-'));
  return {
    file: join(dir, 'hub.sqlite'),
    cleanup: () => rm(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 }),
  };
}

test('openDb: WAL, user_version and idempotent migrations', async (t) => {
  const tmp = await tempDb();
  t.after(tmp.cleanup);

  const first = openDb(tmp.file);
  const mode = first.db.prepare('PRAGMA journal_mode').get() as { journal_mode: string };
  assert.equal(mode.journal_mode, 'wal');
  const v1 = (first.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  assert.ok(v1 >= 1, 'migrations ran');
  const tables = (
    first.db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as {
      name: string;
    }[]
  ).map((r) => r.name);
  for (const expected of ['sessions', 'touched', 'leases', 'inbox', 'git_cache', 'seen_refs']) {
    assert.ok(tables.includes(expected), `table ${expected} is missing (SPEC §5)`);
  }
  first.db.close();

  // Reopening must not re-run anything and must not change the version.
  const second = openDb(tmp.file);
  const v2 = (second.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  assert.equal(v2, v1, 'a second open does not change user_version');
  second.db.close();
});

test('FTS5 is available in node:sqlite (otherwise LIKE fallback)', async (t) => {
  const tmp = await tempDb();
  t.after(tmp.cleanup);
  const store = new RuntimeStore(tmp.file);
  t.after(() => store.close());
  // Both engines are supported; record which one this Node build gives us.
  assert.ok(['fts5', 'like'].includes(store.engine));

  store.rebuildSearch([
    { kind: 'item', ref: 'ACME-1', repo: 'acme', title: 'refactor auth', body: 'guard and strategy' },
    { kind: 'decision', ref: 'D1', repo: 'acme', title: 'allowlist', body: 'no e-mails' },
  ]);
  assert.equal(store.search('refactor', 10).length, 1);
  assert.equal(store.search('auth', 10).length, 1);
  assert.equal(store.search('allowlist', 10)[0]?.kind, 'decision');
  assert.equal(store.search('refactor', 10, 'other-repo').length, 0, 'filter by repo');
  assert.equal(store.search('not-there', 10).length, 0);

  // A rebuild replaces the whole index — deletes included.
  store.rebuildSearch([
    { kind: 'item', ref: 'ACME-2', repo: 'acme', title: 'naïve', body: 'x' },
  ]);
  assert.equal(store.search('refactor', 10).length, 0, 'rebuild deletes the old ones');
  assert.equal(store.search('naïve', 10).length, 1);
});

test('ftsQuery: user input is always a literal, never FTS syntax', () => {
  assert.equal(ftsQuery('auth token'), '"auth" "token"');
  assert.equal(ftsQuery('auth OR token'), '"auth" "OR" "token"');
  assert.equal(ftsQuery('a*b'), '"a*b"');
  assert.equal(ftsQuery('"injected"'), '"injected"');
  assert.equal(ftsQuery('   '), '');
});

/* G8: a token with no alphanumeric character (bare `-`, `*`, `"`, `--`) has
 * nothing to quote around it. Quoting it anyway used to hand FTS5 a bare
 * `""`, which is a MATCH syntax error, not an empty match. */
test('G8: ftsQuery drops tokens without alphanumerics, never returns an empty quoted token', () => {
  assert.equal(ftsQuery('-'), '');
  assert.equal(ftsQuery('--'), '');
  assert.equal(ftsQuery('*'), '');
  assert.equal(ftsQuery('- token'), '"token"');
});

test('search survives FTS metacharacters in the query', async (t) => {
  const tmp = await tempDb();
  const store = new RuntimeStore(tmp.file);
  t.after(async () => {
    store.close();
    await tmp.cleanup();
  });
  store.rebuildSearch([{ kind: 'item', ref: 'ACME-1', repo: 'r', title: 'auth', body: 'x' }]);
  for (const q of ['auth OR *', 'NEAR(a b)', 'title:auth', '"', '((', 'a AND', '-auth', '-', '--', '*']) {
    assert.doesNotThrow(() => store.search(q, 10), `query "${q}" made search throw`);
  }
  // G8: a query that's pure punctuation resolves to empty, never a thrown FTS5 syntax error.
  assert.deepEqual(store.search('-', 10), []);
});

test('the DB file is 0600 (it holds a mirror of the ledger)', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const tmp = await tempDb();
  const store = new RuntimeStore(tmp.file);
  t.after(async () => {
    store.close();
    await tmp.cleanup();
  });
  const st = await stat(tmp.file);
  assert.equal(st.mode & 0o777, 0o600, 'hub.sqlite must not be readable by group/other');
});

test('tx: an error in the middle of a transaction writes nothing (no autocommit half-state)', async (t) => {
  const tmp = await tempDb();
  const store = new RuntimeStore(tmp.file);
  t.after(async () => {
    store.close();
    await tmp.cleanup();
  });
  store.upsertSession({
    id: 's1',
    home_repo: 'r',
    cwd: '/x',
    checkout: '/x',
    branch: 'main',
    transcript_path: null,
    source: 'startup',
  });
  assert.throws(() =>
    store.tx(() => {
      store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: 'a.ts', via: 'edit' });
      throw new Error('bum');
    }),
  );
  assert.equal(store.listTouched({ session: 's1' }).length, 0, 'rollback also removed the first write');

  // And the store is still usable afterwards (no dangling transaction).
  store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: 'b.ts', via: 'edit' });
  assert.equal(store.listTouched({ session: 's1' }).length, 1);
});

test('touch is idempotent and edit never degrades to bash', async (t) => {
  const tmp = await tempDb();
  const store = new RuntimeStore(tmp.file);
  t.after(async () => {
    store.close();
    await tmp.cleanup();
  });
  store.upsertSession({
    id: 's1',
    home_repo: 'r',
    cwd: '/x',
    checkout: '/x',
    branch: null,
    transcript_path: null,
    source: 'startup',
  });
  store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: 'a.ts', via: 'edit', agent_type: 'web-dev' });
  store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: 'a.ts', via: 'bash' });
  const rows = store.listTouched({ session: 's1' });
  assert.equal(rows.length, 1, 'one row per (session, checkout, path)');
  assert.equal(rows[0]?.via, 'edit', 'exact attribution from Edit wins over the heuristic from Bash');
  assert.equal(rows[0]?.agent_type, 'web-dev', 'agent_type is not lost');

  // A commit clears it; a later edit makes it dirty again.
  store.markCommitted('/x', ['a.ts'], 'abc1234');
  assert.equal(store.listTouched({ session: 's1' }).length, 0);
  store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: 'a.ts', via: 'edit' });
  assert.equal(store.listTouched({ session: 's1' })[0]?.committed_sha, null);
});

test('A8-5: releaseCleanTouched does not delete rows newer than the git status snapshot', async (t) => {
  const tmp = await tempDb();
  const store = new RuntimeStore(tmp.file);
  t.after(async () => {
    store.close();
    await tmp.cleanup();
  });
  store.upsertSession({
    id: 's1',
    home_repo: 'r',
    cwd: '/x',
    checkout: '/x',
    branch: null,
    transcript_path: null,
    source: 'startup',
  });

  // Snapshot taken BEFORE the edit — exactly the race: a session edits the
  // file after `git status` already ran for this cycle, so this snapshot
  // cannot possibly know about it. Before A8-1/A8-5 this still deleted the
  // row (nothing else distinguished "reverted" from "not seen yet").
  const snapshotAt = Date.now();
  store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: 'a.ts', via: 'edit' });

  // The caller (repowatch.ts) has already decided 'a.ts' is safe to release
  // (tracked-and-clean, or gone from disk) — but the snapshot it decided that
  // from predates this edit, so the row must still survive.
  const releasedTooEarly = store.releaseCleanTouched('/x', ['a.ts'], snapshotAt);
  assert.equal(releasedTooEarly.length, 0, 'an edit after the snapshot must survive');
  assert.equal(store.listTouched({ checkout: '/x' }).length, 1);

  // A later, fresher snapshot (taken after the edit) correctly judges it clean.
  const laterSnapshot = Date.now() + 1;
  const released = store.releaseCleanTouched('/x', ['a.ts'], laterSnapshot);
  assert.equal(released.length, 1, 'a newer snapshot may release');
  assert.equal(store.listTouched({ checkout: '/x' }).length, 0);
});

/**
 * A8-6 (store-level contract): `releaseCleanTouched` now only deletes a row
 * whose path the CALLER explicitly put in `safeToRelease` — it has no git or
 * filesystem knowledge of its own any more, so it cannot be tricked into
 * releasing a path nobody vouched for. The actual "gitignored file must stay
 * locked, deleted untracked file must be released" decision now lives in
 * `repowatch.ts` and is covered end-to-end in `hub39.test.ts` (A8-6 and
 * "the lock disappears once the file is clean in git again").
 */
test('A8-6: releaseCleanTouched deletes only rows the caller explicitly marked as safe', async (t) => {
  const tmp = await tempDb();
  const store = new RuntimeStore(tmp.file);
  t.after(async () => {
    store.close();
    await tmp.cleanup();
  });
  store.upsertSession({
    id: 's1',
    home_repo: 'r',
    cwd: '/x',
    checkout: '/x',
    branch: null,
    transcript_path: null,
    source: 'startup',
  });
  store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: '.env', via: 'edit' });
  store.touch({ session_id: 's1', repo: 'r', checkout: '/x', rel_path: 'b.ts', via: 'edit' });
  const snapshotAt = Date.now() + 1;

  // Only 'b.ts' is in the safe set — '.env' (e.g. gitignored, per the
  // caller's own git+fs check) must survive untouched.
  const released = store.releaseCleanTouched('/x', ['b.ts'], snapshotAt);
  assert.deepEqual(released.map((r) => r.rel_path), ['b.ts']);
  const remaining = store.listTouched({ checkout: '/x' }).map((r) => r.rel_path);
  assert.deepEqual(remaining, ['.env'], 'only what was not in safeToRelease remains');
});

test('A8-11: expireIdleLeases releases the lease even without a row in sessions (LEFT JOIN)', async (t) => {
  const tmp = await tempDb();
  const store = new RuntimeStore(tmp.file);
  t.after(async () => {
    store.close();
    await tmp.cleanup();
  });
  store.upsertSession({
    id: 's1',
    home_repo: 'r',
    cwd: '/x',
    checkout: '/x',
    branch: null,
    transcript_path: null,
    source: 'startup',
  });
  const leaseId = store.addLease({
    session_id: 's1',
    repo: 'r',
    checkout: '/x',
    kind: 'claim',
    item_id: 'ACME-1',
    paths: ['**'],
    intent: 'test',
  });

  // The session row is gone — a hard delete, a missed write, a foreign-key
  // edge case. A plain `JOIN` drops this lease from the query entirely, so
  // it can never be seen as idle and never expires, no matter `idleMs`.
  (store as unknown as { db: { prepare: (sql: string) => { run: (...a: unknown[]) => void } } }).db
    .prepare('DELETE FROM sessions WHERE id = ?')
    .run('s1');

  // A huge idleMs proves the release is NOT coming from the time-based
  // branch — only a missing session can explain it.
  const expired = store.expireIdleLeases(1_000_000_000_000);
  assert.deepEqual(expired.map((l) => l.id), [leaseId]);
  assert.equal(store.listLeases({ session: 's1', active: true }).length, 0);
});

test('a migration is not applied to a DB with a higher version (no downgrade)', async (t) => {
  const tmp = await tempDb();
  t.after(tmp.cleanup);
  const raw = new DatabaseSync(tmp.file);
  raw.exec('PRAGMA user_version = 99');
  raw.close();
  // Nothing to apply, and `ensureSearch` must still work on the empty schema.
  const opened = openDb(tmp.file);
  const version = (opened.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;
  assert.equal(version, 99, 'a future version is not wound backwards');
  opened.db.close();
});
