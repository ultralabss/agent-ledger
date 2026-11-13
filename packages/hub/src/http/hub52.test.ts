/**
 * / audit B4-3 — "adopt" from the web UI must actually remove the lock.
 *
 * The bug: a cookie caller named no session, so the route substituted
 * `session: 'manual'`. `manual` is not a registered session and never
 * heartbeats, so the orphan detector (no LIVE owner → orphan) listed the same
 * file again on the next poll. The user clicked, the row came back, nothing
 * had been fixed.
 *
 * The invariant now: cookie (human) → the `touched` row is deleted and the
 * path reappears in neither the orphan list nor anybody's owned set. Token
 * (agent session) → unchanged takeover.
 */

import assert from 'node:assert/strict';
import { mkdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';

import { uiCookieValue, UI_COOKIE_NAME } from '../security/index.ts';
import { makeCommittedRepo, startTestHub, type HubFixture } from '../test-helpers.ts';

function cookieHeaders(fx: HubFixture): Record<string, string> {
  const cookie = uiCookieValue(fx);
  assert.ok(cookie !== null);
  return {
    cookie: `${UI_COOKIE_NAME}=${cookie}`,
    origin: `http://127.0.0.1:${fx.hub.port}`,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
  };
}

/** Same list the web UI's `OrphanRow` renders (`GET /v1/repos/:slug`). */
async function orphanPaths(fx: HubFixture, repo: string): Promise<string[]> {
  const res = await fx.api('GET', `/v1/repos/${repo}`);
  const files = (res.json?.orphans ?? []) as { rel_path: string }[];
  return files.map((f) => f.rel_path);
}

/**
 * The state the orphan list is DERIVED from: who holds an uncommitted edit of
 * this path. Asserted directly, because that is where the bug lived — a row
 * owned by the non-existent session `manual` is what made the file look like an
 * orphan again, and a row that is gone cannot come back as one.
 */
function ownersOf(fx: HubFixture, repoPath: string, rel: string): string[] {
  return fx.hub.store.ownersOfPath(repoPath, rel).map((o) => o.session_id);
}

/** The edit has to land on DISK too: `orphan` is only set for a path `git
 *  status` still reports as dirty (an uncommitted change nobody owns). */
async function didEdit(fx: HubFixture, session: string, file: string): Promise<void> {
  await mkdir(join(file, '..'), { recursive: true });
  await writeFile(file, 'x\n', 'utf8');
  await fx.hook('post-tool-use', {
    session_id: session,
    hook_event_name: 'PostToolUse',
    tool_name: 'Edit',
    tool_input: { file_path: file },
  });
}

/** One ended session that left an uncommitted edit behind = one orphan. */
async function setup(fx: HubFixture, repoPath: string, name = 'orphaned.ts'): Promise<string> {
  await fx.api('POST', '/v1/repos', { slug: 'acme', prefix: 'ACME', path: repoPath });
  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: repoPath });
  const file = join(repoPath, 'src', name);
  await didEdit(fx, 'aaaa1111', file);
  await fx.hook('session-end', {
    session_id: 'aaaa1111',
    hook_event_name: 'SessionEnd',
    reason: 'other',
  });
  // `GET /v1/repos/:slug` is what refreshes the git cache in production; the
  // first call warms it so the second sees the dirty path.
  await orphanPaths(fx, 'acme');
  return file;
}

test('adopt from the UI (cookie) releases the lock — the file no longer looks like an orphan', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('hub52');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  const file = await setup(fx, repo.path);
  // macOS: `tmpdir()` is `/var/...`, a symlink to `/private/var/...`; the store
  // keys on the realpath the hub resolved, so the test must use the same one.
  const checkout = await realpath(repo.path);
  assert.deepEqual(
    ownersOf(fx, checkout, 'src/orphaned.ts'),
    ['aaaa1111'],
    'before the release an ended session holds the file',
  );

  const res = await fetch(`${fx.url}/v1/adopt`, {
    method: 'POST',
    headers: cookieHeaders(fx),
    body: JSON.stringify({ path: file }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  const json = (await res.json()) as { session: string; released?: string[] };
  assert.equal(json.session, '', 'nobody holds the file');
  assert.deepEqual(json.released, ['src/orphaned.ts']);

  // The regression itself: the row is GONE. Before the fix it was still there,
  // owned by `manual`, which no heartbeat matches → orphan again on next poll.
  assert.deepEqual(
    ownersOf(fx, checkout, 'src/orphaned.ts'),
    [],
    'after the release nobody holds the file',
  );
  assert.deepEqual(await orphanPaths(fx, 'acme'), [], 'a released file is not returned as an orphan');
  const sessions = await fx.api('GET', '/v1/sessions');
  assert.ok(!sessions.text.includes('"manual"'), 'no fictitious `manual` session is created');
});

test('a release from the UI is written to the journal as a user action', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('hub52j');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  const file = await setup(fx, repo.path);
  const res = await fetch(`${fx.url}/v1/adopt`, {
    method: 'POST',
    headers: cookieHeaders(fx),
    body: JSON.stringify({ path: file }),
  });
  assert.equal(res.status, 200, await res.clone().text());

  const timeline = await fx.api('GET', '/v1/timeline?repo=acme');
  assert.match(timeline.text, /released by the user from the web/);
});

test('a token caller (live session) still takes over on adopt, does not release', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('hub52t');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  const file = await setup(fx, repo.path);
  // A second, live session takes the file over — the CLI path, unchanged.
  await fx.hook('session-start', { session_id: 'bbbb2222', cwd: repo.path });
  const res = await fx.api('POST', '/v1/adopt', { session: 'bbbb2222', path: file });
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.session, 'bbbb2222');
  assert.equal(res.json.released, undefined, 'a takeover is not a release');
  assert.deepEqual(
    (res.json.adopted as { rel_path: string }[]).map((f) => f.rel_path),
    ['src/orphaned.ts'],
  );
});

test('releasing a live session lock via the cookie path is refused — that is what override is for', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('hub52l');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.api('POST', '/v1/repos', { slug: 'acme', prefix: 'ACME', path: repo.path });
  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: repo.path });
  const file = join(repo.path, 'src', 'live.ts');
  await didEdit(fx, 'aaaa1111', file);
  // No session-end: the owner is alive.
  const res = await fetch(`${fx.url}/v1/adopt`, {
    method: 'POST',
    headers: cookieHeaders(fx),
    body: JSON.stringify({ path: file }),
  });
  assert.equal(res.status, 409, await res.clone().text());
  assert.match(await res.text(), /override/);
});
