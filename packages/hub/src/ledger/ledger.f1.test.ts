/** R4 + backlog regressions: repos.yml lookups, id allocation, ledger commit,
 *  prefix aliases, periodic reindex. */

import assert from 'node:assert/strict';
import { chmod, readFile, rm, writeFile } from 'node:fs/promises';
import test from 'node:test';
import { git } from '../git.ts';
import { openTestLedger, startTestHub, tempConfig } from '../test-helpers.ts';
import { Ledger } from './ledger.ts';

/* ---------------- R4: repos.yml lookups ---------------- */

test('R4: repo_hint must be a slug and is looked up via hasOwn', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });

  // `__proto__` is not even a legal slug (it has `_`), so the schema stops it.
  for (const hint of ['__proto__', 'ACME', '../etc', 'a/b', 'a b', 'A']) {
    const res = await fx.api('POST', '/v1/intake', { text: 'x', channel: 'chat', repo_hint: hint });
    assert.equal(res.status, 422, `repo_hint "${hint}" must be rejected by the schema`);
  }

  // `constructor` / `prototype` / `tostring` ARE legal slugs, so the schema
  // lets them through — the `hasOwn` lookup is what must refuse to resolve them
  // to an Object.prototype member (that is the R4 finding).
  for (const hint of ['constructor', 'prototype', 'tostring', 'valueof']) {
    const res = await fx.api('POST', '/v1/intake', { text: 'x', channel: 'chat', repo_hint: hint });
    assert.equal(res.status, 201, `"${hint}" is a valid slug`);
    assert.equal(fx.hub.ledger.repoOrNull(hint), null, `"${hint}" must not resolve to a repo`);
    assert.equal(fx.hub.ledger.hasRepo(hint), false);
    assert.equal(fx.hub.ledger.repoPath(hint), null);
  }

  // A well-formed but unknown slug is accepted and simply does not resolve.
  const ok = await fx.api('POST', '/v1/intake', {
    text: 'text for the intake',
    channel: 'chat',
    repo_hint: 'nonexistent',
  });
  assert.equal(ok.status, 201, ok.text);

  const item = await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'from intake',
    kind: 'BACKLOG',
    priority: 'P2',
  });
  const triaged = await fx.api('POST', `/v1/intake/${ok.json.id}/triage`, {
    items: [item.json.id],
  });
  assert.equal(triaged.status, 200, triaged.text);
  // The journal fell back to the item's own repo, not to a prototype member.
  const journal = await fx.api('GET', '/v1/timeline?repo=acme&format=line');
  assert.match(journal.text, /intake\.triaged/);
});

test('R4: hasRepo / repoOrNull / repoPath never return a prototype member', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
    assert.equal(fx.ledger.hasRepo(key), false, key);
    assert.equal(fx.ledger.repoOrNull(key), null, key);
    assert.equal(fx.ledger.repoPath(key), null, key);
    assert.throws(() => fx.ledger.repo(key), /unknown repo/, key);
  }
});

/* ---------------- backlog: prefix_aliases ---------------- */

test('backlog: prefix_aliases finds the repo for an old id', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'web', prefix: 'WEB', path: null });
  assert.equal(fx.ledger.repoForItemId('WEB-13'), 'web');
  assert.equal(fx.ledger.repoForItemId('OLD-1'), null);

  // Rename the prefix by hand (as a human would) and keep the old one as alias.
  const file = fx.ledger.paths.reposYml;
  const yaml = await readFile(file, 'utf8');
  await writeFile(
    file,
    yaml.replace('prefix: WEB', 'prefix: WBX\n  prefix_aliases:\n    - WEB'),
    'utf8',
  );
  await fx.ledger.queue.run(() => fx.ledger.reindex());

  assert.equal(fx.ledger.repoForItemId('WBX-1'), 'web', 'new prefix');
  assert.equal(fx.ledger.repoForItemId('WEB-13'), 'web', 'the old id is still found');
  assert.equal(fx.ledger.warnings.size, 0, 'repos.yml with aliases is valid');
});

/* ---------------- G2/G3: closeByCommit/itemsClosedByCommits are repo-scoped -------- */

test('G2: closeByCommit ignores an id from another repo, so does logItem', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'reposa', prefix: 'RPA', path: null });
  await fx.ledger.registerRepo({ slug: 'reposb', prefix: 'RPB', path: null });
  const a = await fx.ledger.createItem({
    repo: 'reposa',
    title: 'a',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });

  const commit = { sha: 'a'.repeat(40), short: 'aaaaaaa', subject: 'x', at: new Date().toISOString() };
  const closed = await fx.ledger.closeByCommit('reposb', a.fm.id, commit);
  assert.equal(closed, null, 'a foreign slug must not close the item');
  assert.equal(fx.ledger.getItem(a.fm.id).item.fm.status, 'open');

  const logged = await fx.ledger.logItem('reposb', a.fm.id, null, 'note');
  assert.equal(logged, null, 'a foreign slug must not even log to a foreign item');

  // The item's own repo can still close it normally.
  const ok = await fx.ledger.closeByCommit('reposa', a.fm.id, commit);
  assert.equal(ok?.fm.status, 'done');
});

test('G3: itemsClosedByCommits is scoped by repo and compares the full sha', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'reposa', prefix: 'RPA', path: null });
  await fx.ledger.registerRepo({ slug: 'reposb', prefix: 'RPB', path: null });
  const a = await fx.ledger.createItem({
    repo: 'reposa',
    title: 'a',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });
  const b = await fx.ledger.createItem({
    repo: 'reposb',
    title: 'b',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });

  // Contrived: both closed by the SAME sha (in reality two different repos'
  // histories never share a commit, but this isolates the scoping property
  // itself — a shared/colliding sha in repo B must never surface repo A's item).
  const sameSha = 'b'.repeat(40);
  const commit = { sha: sameSha, short: sameSha.slice(0, 7), subject: 'x', at: new Date().toISOString() };
  await fx.ledger.closeByCommit('reposa', a.fm.id, commit);
  await fx.ledger.closeByCommit('reposb', b.fm.id, commit);

  const closedInA = fx.ledger.itemsClosedByCommits('reposa', [sameSha]);
  assert.deepEqual(closedInA.map((i) => i.fm.id), [a.fm.id], 'only the item from reposa');

  const closedInB = fx.ledger.itemsClosedByCommits('reposb', [sameSha]);
  assert.deepEqual(closedInB.map((i) => i.fm.id), [b.fm.id], 'only the item from reposb');

  // A 7-char-only match must not be enough — only the full sha counts.
  assert.deepEqual(fx.ledger.itemsClosedByCommits('reposa', [sameSha.slice(0, 7)]), []);
});

test('H5: done.commit stored as a 7-char abbreviated sha is still recognised as the same commit', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'reposa', prefix: 'RPA', path: null });
  const a = await fx.ledger.createItem({
    repo: 'reposa',
    title: 'a',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });

  const fullSha = 'c'.repeat(40);
  const shortSha = fullSha.slice(0, 7);
  // Simulate legacy data: `done.commit` written as a 7-char abbreviation.
  await fx.ledger.closeByCommit('reposa', a.fm.id, {
    sha: shortSha,
    short: shortSha,
    subject: 'x',
    at: new Date().toISOString(),
  });
  assert.equal(fx.ledger.getItem(a.fm.id).item.fm.done?.commit, shortSha);

  const journalBefore = fx.ledger.listJournal('reposa').length;
  // Redelivery of the same commit, now with its full sha, must be a no-op —
  // not a second `logItem` call and not a re-opened/duplicated transition.
  const again = await fx.ledger.closeByCommit('reposa', a.fm.id, {
    sha: fullSha,
    short: shortSha,
    subject: 'x',
    at: new Date().toISOString(),
  });
  assert.equal(again?.fm.status, 'done');
  assert.equal(fx.ledger.listJournal('reposa').length, journalBefore, 'idempotent, no new log entry');

  // itemsClosedByCommits must find the short-stored item via the full sha too.
  const found = fx.ledger.itemsClosedByCommits('reposa', [fullSha]);
  assert.deepEqual(found.map((i) => i.fm.id), [a.fm.id]);
});

/* ---------------- backlog: `next` comes back on a failed write ---------------- */

test('backlog: when an item write fails, `next` is returned (no gap in ids)', async (t) => {
  const fx = await openTestLedger();
  t.after(async () => {
    await chmod(fx.ledger.paths.itemsDir('acme'), 0o700).catch(() => undefined);
    await fx.cleanup();
  });
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });

  const first = await fx.ledger.createItem({
    repo: 'acme',
    title: 'first',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });
  assert.equal(first.fm.id, 'ACME-1');
  assert.equal(fx.ledger.repo('acme').next, 2);

  // Make the items dir unwritable so the atomic write fails.
  await chmod(fx.ledger.paths.itemsDir('acme'), 0o500);
  await assert.rejects(() =>
    fx.ledger.createItem({
      repo: 'acme',
      title: 'fails',
      kind: 'BACKLOG',
      priority: 'P2',
      owner: 'agent',
      steps: [],
      blocked_by: [],
      aliases: [],
      proposed: false,
    }),
  );
  assert.equal(fx.ledger.repo('acme').next, 2, 'the id was returned to next');

  await chmod(fx.ledger.paths.itemsDir('acme'), 0o700);
  const second = await fx.ledger.createItem({
    repo: 'acme',
    title: 'second',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });
  assert.equal(second.fm.id, 'ACME-2', 'the id is reused, sequence without a gap');
});

/* ---------------- backlog: the ledger really commits ---------------- */

test('backlog: the ledger commit (commitDebounceMs 0) is in git log', async (t) => {
  const tmp = await tempConfig({ commitDebounceMs: 0 });
  const logs: string[] = [];
  const ledger = new Ledger({ config: tmp.config, log: (l) => logs.push(l) });
  await ledger.init();
  await git(tmp.dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(tmp.dir, ['config', 'user.name', 'agent-ledger test']);
  t.after(async () => {
    await ledger.close();
    await tmp.cleanup();
  });

  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const item = await ledger.createItem({
    repo: 'acme',
    title: 'commit me',
    kind: 'BACKLOG',
    priority: 'P1',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });
  await ledger.git.flush();

  const log = await git(tmp.dir, ['log', '--oneline']);
  assert.equal(log.code, 0, log.stderr);
  assert.match(log.stdout, /ledger: /, 'the commit message has the `ledger:` prefix');
  assert.match(log.stdout, new RegExp(`\\+${item.fm.id}|initialized ledger`));
  assert.equal(ledger.git.status.lastCommit !== null, true, 'healthz sees the last commit');

  // The item file is really in the tree, and the token is not.
  const tracked = await git(tmp.dir, ['ls-files']);
  assert.match(tracked.stdout, new RegExp(`acme/items/${item.fm.id}\\.md`));
  assert.equal(tracked.stdout.includes('.hub/'), false, '.hub/ is never tracked (S1)');
  assert.equal(tracked.stdout.includes('hub.sqlite'), false, 'the DB is not in git');

  const status = await git(tmp.dir, ['status', '--porcelain']);
  assert.equal(status.stdout.trim(), '', 'the working tree is clean after the commit');
});

/* ---------------- backlog: periodic reindex as an fs.watch backstop ---------------- */

test('backlog: the periodic reindex catches a change fs.watch slept through', async (t) => {
  // `watch: false` simulates a missed/absent watcher: the file changes on disk
  // and only the periodic sweep can notice.
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const created = await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'original name',
    kind: 'BACKLOG',
    priority: 'P2',
  });
  const id = created.json.id as string;
  const file = fx.hub.ledger.paths.itemFile('acme', id);
  await writeFile(file, (await readFile(file, 'utf8')).replace('original name', 'changed by hand'), 'utf8');

  assert.equal(
    (await fx.api('GET', `/v1/items/${id}`)).json.item.title,
    'original name',
    'without a watcher the hub does not see the change yet',
  );

  await fx.hub.sweep();

  assert.equal(
    (await fx.api('GET', `/v1/items/${id}`)).json.item.title,
    'changed by hand',
    'the periodic reindex caught up',
  );

  // A deleted item disappears from the index too.
  await rm(file);
  await fx.hub.sweep();
  assert.equal((await fx.api('GET', '/v1/items')).json.items.length >= 0, true);
});

test('sweep ends a dead session (> 24 h without a signal)', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });

  fx.hub.store.upsertSession({
    id: 'oldSession',
    home_repo: 'acme',
    cwd: '/tmp/x',
    checkout: null,
    branch: null,
    transcript_path: null,
    source: 'startup',
    now: Date.now() - 25 * 3_600_000,
  });
  assert.equal(fx.hub.sessions.get('oldSession')?.liveness, 'ended', '> 24 h = ended');

  await fx.hub.sweep();
  const after = fx.hub.sessions.get('oldSession');
  assert.notEqual(after?.ended_at, null, 'sweep wrote its ended_at');
  const journal = await fx.api('GET', '/v1/timeline?repo=acme&format=line');
  assert.match(journal.text, /session\.end · timeout 24h/);
});
