/** `DELETE /v1/repos/:slug`: archive, never delete. Contract test. */

import assert from 'node:assert/strict';
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { makeCodeRepo, startTestHub, type HubFixture } from './test-helpers.ts';

async function withRepo(
  t: { after: (fn: () => unknown) => void },
): Promise<{ fx: HubFixture; slug: string; path: string }> {
  const fx = await startTestHub();
  t.after(() => fx.cleanup());
  const repo = await makeCodeRepo('hubrm');
  t.after(() => repo.cleanup());
  const slug = 'hubrm';
  const res = await fx.api('POST', '/v1/repos', { slug, prefix: 'HRM', path: repo.path });
  assert.equal(res.status, 201, JSON.stringify(res.json));
  return { fx, slug, path: repo.path };
}

test('repo rm archives the ledger dir and drops it from repos.yml', async (t) => {
  const { fx, slug } = await withRepo(t);
  const repoDir = join(fx.dir, slug);
  assert.ok(await stat(repoDir).then(() => true).catch(() => false), 'precondition: dir exists');

  const res = await fx.api('DELETE', `/v1/repos/${slug}`);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.slug, slug);
  assert.ok(typeof res.json.archived === 'string', 'archive path is returned');

  // Gone from the registry…
  const list = await fx.api('GET', '/v1/repos');
  assert.ok(!(slug in list.json.repos), 'repo must be gone from repos.yml');
  // …and from its old place…
  assert.equal(await stat(repoDir).then(() => true).catch(() => false), false);
  // …but the ledger content still exists under `.archive/`.
  const archived = res.json.archived as string;
  assert.match(archived, /\.archive\//);
  const entries = await readdir(archived);
  assert.ok(entries.length > 0, 'the archived ledger must keep its files');
});

test('a removed repo is really gone for reads', async (t) => {
  const { fx, slug } = await withRepo(t);
  await fx.api('DELETE', `/v1/repos/${slug}`);
  const after = await fx.api('GET', `/v1/items?repo=${slug}`);
  assert.equal(after.status, 404, 'reading a removed repo must 404, not return stale rows');
});

test('runtime rows (leases) for the repo are cleared', async (t) => {
  const { fx, slug } = await withRepo(t);
  const created = await fx.api('POST', '/v1/items', {
    repo: slug,
    title: 'item to delete',
    kind: 'BACKLOG',
    priority: 'P2',
  });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'sess-x', paths: ['src/**'] });

  // H8-1: an open claim now blocks removal unless `force` — see the
  // dedicated H8-1 tests below for the 409 itself.
  await fx.api('DELETE', `/v1/repos/${slug}?force=1`);

  // `who` must not still answer about a repo that no longer exists.
  const sessions = await fx.api('GET', '/v1/sessions');
  const leaked = JSON.stringify(sessions.json).includes(id);
  assert.equal(leaked, false, 'no lease/touched row may survive the removal');
});

test('`ops` cannot be removed', async (t) => {
  const fx = await startTestHub();
  t.after(() => fx.cleanup());
  const res = await fx.api('DELETE', '/v1/repos/ops');
  assert.ok(res.status >= 400, 'removing the hub own bookkeeping repo must fail');
  assert.match(JSON.stringify(res.json), /ops/);
  const list = await fx.api('GET', '/v1/repos');
  assert.ok('ops' in list.json.repos, 'ops must still be registered');
});

test('an unknown slug is a 404, nothing is touched', async (t) => {
  const fx = await startTestHub();
  t.after(() => fx.cleanup());
  const res = await fx.api('DELETE', '/v1/repos/missing');
  assert.equal(res.status, 404);
});

test('H8-1: an open claim blocks removal with 409 unless --force', async (t) => {
  const { fx, slug } = await withRepo(t);
  const created = await fx.api('POST', '/v1/items', { repo: slug, title: 'has a claim' });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'sess-holder', paths: ['src/**'] });

  const blocked = await fx.api('DELETE', `/v1/repos/${slug}`);
  assert.equal(blocked.status, 409, JSON.stringify(blocked.json));
  assert.match(JSON.stringify(blocked.json), /sess-holder/, 'the holder must be named');

  // Repo must still be fully registered — a 409 must not half-remove it.
  const list = await fx.api('GET', '/v1/repos');
  assert.ok(slug in list.json.repos, 'repo must still be registered after a blocked removal');

  const forced = await fx.api('DELETE', `/v1/repos/${slug}?force=1`);
  assert.equal(forced.status, 200, JSON.stringify(forced.json));
});

test('H8-1: a live session in the repo blocks removal with 409 unless --force', async (t) => {
  const { fx, slug, path } = await withRepo(t);
  await fx.hook('session-start', { session_id: 'live-sess', cwd: path });

  const blocked = await fx.api('DELETE', `/v1/repos/${slug}`);
  assert.equal(blocked.status, 409, JSON.stringify(blocked.json));
  assert.match(JSON.stringify(blocked.json), /live-sess/, 'the live session must be named');

  const forced = await fx.api('DELETE', `/v1/repos/${slug}?force=1`);
  assert.equal(forced.status, 200, JSON.stringify(forced.json));
});

test('removing the same slug twice archives to distinct dirs', async (t) => {
  const { fx, slug } = await withRepo(t);
  const first = await fx.api('DELETE', `/v1/repos/${slug}`);
  const repo2 = await makeCodeRepo('hubrm2');
  t.after(() => repo2.cleanup());
  await fx.api('POST', '/v1/repos', { slug, prefix: 'HRM', path: repo2.path });
  const second = await fx.api('DELETE', `/v1/repos/${slug}`);
  assert.equal(second.status, 200);
  assert.notEqual(first.json.archived, second.json.archived, 'the second archive must not clobber the first');
});
