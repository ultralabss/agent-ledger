/**
 * Pid-ancestry session mapping removed.
 *
 * The whole approach (`pidmap.ts`/`proctree.ts`, `POST /v1/sessions/resolve`,
 * `ManualClaims`) was unreliable: sessions sharing a terminal/tmux pane, and a
 * reply worker whose parent process IS the hub, share process ancestry — so a
 * pid chain could resolve to the wrong session (or let a worker adopt another
 * session's `manual` claim). These tests cover what replaced it: `ledger claim`
 * without `LEDGER_SESSION` stays `manual` and says so on stderr, and
 * `mode: auto` on `/items/:id/reply` refuses to silently spawn a worker for a
 * target session that is `manual`/unknown/dead.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { makeCodeRepo, startTestHub } from './test-helpers.ts';

test('H21-1: POST /v1/sessions/resolve no longer exists', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const res = await fx.api('POST', '/v1/sessions/resolve', { pid: 1, ppid: 1 });
  assert.equal(res.status, 404, JSON.stringify(res.json));
});

test('H21-1: a claim carrying pid/ppid is accepted (fields are just ignored, not an error)', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });
  const created = await fx.api('POST', '/v1/items', { repo: 'app', title: 'x' });
  const id = created.json.item.id as string;
  const res = await fx.api('POST', `/v1/items/${id}/claim`, {
    session: 'sess-1',
    paths: [],
    pid: 12345,
    ppid: 1,
  });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.item.claimed_by.session, 'sess-1');
});

test('H21-4: reply mode auto against a `manual` claim is 409 NO_SESSION, not a silent worker spawn', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });
  const created = await fx.api('POST', '/v1/items', { repo: 'app', title: 'bez session' });
  const id = created.json.item.id as string;
  // No `session` given → defaults to the literal `manual` (claimSchema).
  await fx.api('POST', `/v1/items/${id}/claim`, { paths: [] });

  const res = await fx.api('POST', `/v1/items/${id}/reply`, { text: 'x' });
  assert.equal(res.status, 409, JSON.stringify(res.json));
  assert.equal(res.json.error, 'NO_SESSION');
  assert.match(res.json.message ?? JSON.stringify(res.json), /Background worker|in chat/);
});

test('H21-4: reply mode auto against a dead (ended) session is 409 NO_SESSION', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });
  await fx.hook('session-start', { session_id: 'dead1111', cwd: repo.path });
  const created = await fx.api('POST', '/v1/items', { repo: 'app', title: 'session ended' });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'dead1111', paths: [] });
  await fx.hook('session-end', { session_id: 'dead1111', reason: 'logout' });

  const res = await fx.api('POST', `/v1/items/${id}/reply`, { text: 'x' });
  assert.equal(res.status, 409, JSON.stringify(res.json));
  assert.equal(res.json.error, 'NO_SESSION');
});

test('H21-4: explicit mode: worker still works against a `manual` claim (only `auto` is restricted)', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });
  const created = await fx.api('POST', '/v1/items', { repo: 'app', title: 'bez session' });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { paths: [] });

  // No fake claude binary configured in this fixture → worker mode itself may
  // 409 for an unrelated reason (no `claudeBin`), but it must NOT be
  // `NO_SESSION` — that code is specific to the `auto` guard this fix adds.
  const res = await fx.api('POST', `/v1/items/${id}/reply`, { text: 'x', mode: 'worker' });
  assert.notEqual(res.json.error, 'NO_SESSION', JSON.stringify(res.json));
});
