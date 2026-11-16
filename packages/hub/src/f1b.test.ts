/** AL-5 F1 batch 2: slot-letter ids in every parser, root_sha binding wired to
 *  SessionStart and `POST /v1/repos/:slug/bind`. */

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import test from 'node:test';
import { parseIntake, serializeIntake, type IntakeRecord } from '@agent-ledger/shared';
import { git } from './git.ts';
import { trailerIds } from './gitreader.ts';
import { offendingLines } from './guard/recap.ts';
import { mentionedIds } from './relevance.ts';
import { compareIds } from './releasenotes.ts';
import { makeCodeRepo, startTestHub } from './test-helpers.ts';

/** Distinct root commit per call (`makeCommittedRepo` makes byte-identical ones). */
async function distinctRepo(label: string): Promise<{ path: string; cleanup: () => Promise<void>; root: string }> {
  const repo = await makeCodeRepo(label);
  const res = await git(repo.path, [
    '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '--allow-empty', '-q', '-m', `root of ${label}`,
  ]);
  assert.equal(res.code, 0, res.stderr);
  const root = (await git(repo.path, ['rev-list', '--max-parents=0', 'HEAD'])).stdout.trim();
  return { ...repo, root };
}

/* ---------------- F1.1 parsers ---------------- */

test('F1.1: trailers Closes:/Refs: accept slot ids and keep plain ones', () => {
  const body = 'fix thing\n\nCloses: ACME-12, ACME-W3\nRefs: ACME-V10\nrefs: acme-w4\nRefs: ACME-I5 ACME-0\n';
  assert.deepEqual(trailerIds(body, 'Closes').sort(), ['ACME-12', 'ACME-W3']);
  assert.deepEqual(trailerIds(body, 'Refs').sort(), ['ACME-V10', 'ACME-W4']);
  // repeated calls give the same answer (no shared /g regex state)
  assert.deepEqual(trailerIds(body, 'Closes').sort(), ['ACME-12', 'ACME-W3']);
});

test('F1.1: intake triage lines with slot ids round-trip', () => {
  const rec: IntakeRecord = {
    id: '7241889432101351425',
    at: '2026-10-05T12:00:00+02:00',
    channel: 'chat',
    session: '61e0b33d',
    repo_hint: 'acme',
    status: 'triaged',
    items: ['ACME-12', 'ACME-W3'],
    text: 'verbatim dump',
    triage: [
      { item: 'ACME-12', excerpt: 'plain' },
      { item: 'ACME-W3', excerpt: 'from the windows box' },
    ],
    dropped: [],
  };
  const back = parseIntake(serializeIntake(rec)).rec;
  assert.deepEqual(back.triage, rec.triage);
  assert.deepEqual(back.items, rec.items);
});

test('F1.1: relevance mentionedIds sees slot ids, ignores I/O slots', () => {
  assert.deepEqual(
    [...mentionedIds('see acme-12 and ACME-w3, not ACME-I3 or ACME-0')].sort(),
    ['ACME-12', 'ACME-W3'],
  );
});

test('F1.1: compareIds — numeric, primary slot before letters, then number', () => {
  const ids = ['ACME-W2', 'ACME-10', 'ACME-W10', 'ACME-9', 'ACME-V1', 'ACME-W1'];
  assert.deepEqual(ids.sort(compareIds), ['ACME-9', 'ACME-10', 'ACME-V1', 'ACME-W1', 'ACME-W2', 'ACME-W10']);
  assert.ok(compareIds('ACME-5', 'WEB-1') < 0, 'different prefixes fall back to string order');
  assert.equal(compareIds('ACME-W3', 'ACME-W3'), 0);
});

test('F1.1: recap check counts a slot id as an item id', () => {
  assert.deepEqual(offendingLines('- [BLOCKER] ACME-W7 needs a decision'), []);
  assert.deepEqual(offendingLines('- [BLOCKER] ACME-12 needs a decision'), []);
  assert.equal(offendingLines('- [BLOCKER] ACME-I7 is not an id').length, 1);
});

/* ---------------- F1.3 wiring ---------------- */

async function syncedRepos(fx: Awaited<ReturnType<typeof startTestHub>>, body: string): Promise<void> {
  await writeFile(fx.hub.ledger.paths.reposYml, body, 'utf8');
  await fx.hub.ledger.queue.run(() => fx.hub.ledger.reindex());
}

test('F1.3: SessionStart in a checkout that matches an unbound repo binds it, no new slug', async (t) => {
  const fx = await startTestHub();
  const mine = await distinctRepo('f1b-mine');
  t.after(async () => {
    await fx.cleanup();
    await mine.cleanup();
  });
  await syncedRepos(fx, `ops:\n  kind: system\n  prefix: OPS\napp:\n  prefix: APP\n  identity:\n    root_sha: ${mine.root}\n`);
  const before = Object.keys((await fx.api('GET', '/v1/repos')).json.repos).sort();
  assert.equal(fx.hub.ledger.repos().app?.path, null);

  const res = await fx.hook('session-start', { session_id: 'f1b00001', cwd: mine.path, source: 'startup' });
  assert.equal(res.status, 200);
  assert.equal(res.repo, 'app', 'bound to the existing slug');
  const after = await fx.api('GET', '/v1/repos');
  assert.deepEqual(Object.keys(after.json.repos).sort(), before, 'no slug was created');
  assert.ok(after.json.repos.app.path, 'path is bound locally');
});

test('F1.3: SessionStart in an unrelated checkout still auto-registers a fresh slug', async (t) => {
  const fx = await startTestHub();
  const mine = await distinctRepo('f1b-a');
  const other = await distinctRepo('f1b-b');
  t.after(async () => {
    await fx.cleanup();
    await mine.cleanup();
    await other.cleanup();
  });
  await syncedRepos(fx, `ops:\n  kind: system\n  prefix: OPS\napp:\n  prefix: APP\n  identity:\n    root_sha: ${mine.root}\n`);
  const res = await fx.hook('session-start', { session_id: 'f1b00002', cwd: other.path, source: 'startup' });
  assert.ok(res.repo && res.repo !== 'app');
  assert.equal(fx.hub.ledger.repos().app?.path, null, 'the unrelated checkout did not take the slug');
});

test('F1.3: POST /v1/repos/:slug/bind — token required, root commit verified, bad input 4xx', async (t) => {
  const fx = await startTestHub();
  const mine = await distinctRepo('f1b-bind');
  const wrong = await distinctRepo('f1b-wrong');
  t.after(async () => {
    await fx.cleanup();
    await mine.cleanup();
    await wrong.cleanup();
  });
  await syncedRepos(fx, `ops:\n  kind: system\n  prefix: OPS\napp:\n  prefix: APP\n  identity:\n    root_sha: ${mine.root}\n`);

  const anon = await fetch(`${fx.url}/v1/repos/app/bind`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ path: mine.path }),
  });
  assert.ok(anon.status === 401 || anon.status === 403, `unauthenticated bind refused (${anon.status})`);
  assert.equal(fx.hub.ledger.repos().app?.path, null);

  assert.equal((await fx.api('POST', '/v1/repos/app/bind', { path: wrong.path })).status, 409, 'other root commit');
  assert.equal((await fx.api('POST', '/v1/repos/app/bind', {})).status, 422, 'path required');
  assert.equal((await fx.api('POST', '/v1/repos/nope/bind', { path: mine.path })).status, 404);
  assert.equal((await fx.api('POST', '/v1/repos/app/bind', { path: '/definitely/not/a/repo' })).status, 422);
  assert.equal(fx.hub.ledger.repos().app?.path, null, 'every refusal left the repo unbound');

  const ok = await fx.api('POST', '/v1/repos/app/bind', { path: mine.path });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.slug, 'app');
  assert.ok(ok.json.repo.path);
});
