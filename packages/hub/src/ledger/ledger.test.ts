import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import test from 'node:test';
import { parseJournal, parseItem, repoKindOf, type RepoConfig } from '@agent-ledger/shared';
import { tempConfig } from '../test-helpers.ts';
import { Ledger } from './ledger.ts';
import { openTestLedger, makeCodeRepo } from '../test-helpers.ts';

const base = {
  kind: 'BACKLOG',
  priority: 'P2',
  owner: 'agent',
  steps: [] as string[],
  blocked_by: [] as string[],
  aliases: [] as string[],
  proposed: false,
};

test('init: directory, git, .gitignore, repos.yml with the virtual ops repo', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const repos = fx.ledger.repos();
  assert.deepEqual(repos.ops, { kind: 'system', prefix: 'OPS', path: null, next: 1 });
  assert.match(await readFile(fx.ledger.paths.gitignore, 'utf8'), /^\.hub\/$/m);
  assert.match(await readFile(fx.ledger.paths.contextFile('ops'), 'utf8'), /## Pitfalls/);
  assert.equal((await readFile(fx.ledger.paths.decisionsFile('ops'), 'utf8')).includes('###'), false);
});

test('S1: an existing .gitignore without .hub/ gets the missing lines at boot', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  // A human-written .gitignore that predates agent-ledger — no `.hub/`, no `*.tmp`.
  await mkdir(tmp.dir, { recursive: true });
  await writeFile(`${tmp.dir}/.gitignore`, 'node_modules/\n*.log\n', 'utf8');

  const logs: string[] = [];
  const ledger = new Ledger({ config: tmp.config, log: (line) => logs.push(line) });
  await ledger.init();
  t.after(() => ledger.close());

  const text = await readFile(ledger.paths.gitignore, 'utf8');
  assert.match(text, /^node_modules\/$/m, 'the original content stayed');
  assert.match(text, /^\*\.log$/m, 'the original content stayed');
  assert.match(text, /^\.hub\/$/m, 'the missing line was added');
  assert.match(text, /^\*\.tmp$/m, 'the missing line was added');

  // Idempotent: running it again does not duplicate the lines.
  await ledger.init();
  const again = await readFile(ledger.paths.gitignore, 'utf8');
  assert.equal(again.split('\n').filter((l) => l === '.hub/').length, 1);
});

test('repo add: path must be a git toplevel, prefix is unique', async (t) => {
  const fx = await openTestLedger();
  const code = await makeCodeRepo();
  t.after(fx.cleanup);
  t.after(code.cleanup);

  await assert.rejects(
    fx.ledger.registerRepo({ slug: 'nothing', path: `${code.path}-missing` }),
    /is not a git repo/,
  );
  const res = await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: code.path });
  assert.equal(res.cfg.prefix, 'ACME');
  assert.equal(res.cfg.next, 1);
  await assert.rejects(
    fx.ledger.registerRepo({ slug: 'other', prefix: 'ACME', path: null }),
    /prefix "ACME" is already used/,
  );
  await assert.rejects(fx.ledger.registerRepo({ slug: 'acme' }), /already exists/);
  assert.equal(await fx.ledger.repoForPath(code.path), 'acme');
  assert.match(await readFile(fx.ledger.paths.contextFile('acme'), 'utf8'), /## Stack/);
});

test('system / vps without a path and without a git check, path+kind = error', async (t) => {
  const fx = await openTestLedger();
  const code = await makeCodeRepo();
  t.after(fx.cleanup);
  t.after(code.cleanup);

  const sys = await fx.ledger.registerRepo({ slug: 'infra', prefix: 'INF', kind: 'system' });
  assert.equal(sys.cfg.kind, 'system');
  assert.equal(sys.cfg.path, null);
  assert.equal(fx.ledger.repoPath('infra'), null);

  const vps = await fx.ledger.registerRepo({
    slug: 'vps-prod',
    prefix: 'VPS',
    kind: 'vps',
    host: 'app-host',
  });
  assert.equal(vps.cfg.kind, 'vps');
  assert.equal(vps.cfg.host, 'app-host');
  assert.equal(vps.cfg.path, null);

  // Not even an existing git checkout may be attached; a non-git path is
  // refused for the kind, not for "is not a git repository" (no git check runs).
  await assert.rejects(
    fx.ledger.registerRepo({ slug: 'x1', prefix: 'XA', kind: 'system', path: code.path }),
    /has no path/,
  );
  await assert.rejects(
    fx.ledger.registerRepo({ slug: 'x2', prefix: 'XB', kind: 'vps', path: '/nonexistent/zzz' }),
    /has no path/,
  );
  await assert.rejects(
    fx.ledger.registerRepo({ slug: 'x3', prefix: 'XC', kind: 'system', host: 'h' }),
    /only be set for kind "vps"/,
  );
  assert.equal(fx.ledger.hasRepo('x1'), false);

  // Reload from disk: kind/host survive; items work without any path.
  await fx.ledger.reindex();
  assert.equal(fx.ledger.repos()['vps-prod']?.host, 'app-host');
  const item = await fx.ledger.createItem({ ...base, repo: 'vps-prod', title: 'rotate logs', why: '' });
  assert.match(item.fm.id, /^VPS-1$/);
});

test('an old repos.yml without kind loads as repo (also with path: null)', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await writeFile(
    fx.ledger.paths.reposYml,
    'virt:\n  prefix: VR\n  path: null\n  next: 3\nold:\n  prefix: OL\n  path: ~/nowhere\n  next: 1\n',
    'utf8',
  );
  await fx.ledger.reindex();
  const repos = fx.ledger.repos();
  assert.equal(repos.virt?.kind, undefined);
  assert.equal(repoKindOf(repos.virt as RepoConfig), 'repo');
  assert.equal(repoKindOf(repos.old as RepoConfig), 'repo');
  assert.equal(repos.virt?.path, null);
  assert.equal(fx.ledger.warnings.size, 0);
});

test('add: item per §4.3, log and journal', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const item = await fx.ledger.createItem({
    ...base,
    repo: 'acme',
    title: 'OAuth tab',
    kind: 'DEPLOY',
    priority: 'P0',
    owner: 'human',
    area: 'web',
    why: 'it does not work without this',
    rec: 'add a handler',
    steps: ['first step', 'second step'],
    session: '61e0b33d',
    agent: 'orchestrator',
  });
  assert.equal(item.fm.id, 'ACME-1');
  assert.equal(item.fm.status, 'open');
  assert.deepEqual(item.steps.map((s) => s.n), [1, 2]);
  assert.equal(item.log[0]?.session, '61e0');

  const onDisk = await readFile(fx.ledger.paths.itemFile('acme', 'ACME-1'), 'utf8');
  const parsed = parseItem(onDisk).item;
  assert.deepEqual(parsed.fm, item.fm);
  assert.match(onDisk, /^## Why$/m);

  const journalText = await readFile(
    fx.ledger.paths.journalFile('acme', new Date().toISOString().slice(0, 7)),
    'utf8',
  );
  const events = parseJournal(journalText, 'acme');
  assert.equal(events[0]?.type, 'item.created');
  assert.equal(events[0]?.session, '61e0');
  assert.match(journalText, /^- \d{4}-\d{2}-\d{2} \d{2}:\d{2} · 61e0 · item\.created · ACME-1 · /m);
  assert.equal(fx.ledger.repos().acme?.next, 2);
});

test('50 parallel adds → unique ids without gaps', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const items = await Promise.all(
    Array.from({ length: 50 }, (_unused, i) =>
      fx.ledger.createItem({ ...base, repo: 'acme', title: `parallel ${i}` }),
    ),
  );
  const ids = items.map((i) => i.fm.id).sort((a, b) => Number(a.slice(5)) - Number(b.slice(5)));
  assert.equal(new Set(ids).size, 50);
  assert.deepEqual(ids, Array.from({ length: 50 }, (_unused, i) => `ACME-${i + 1}`));
  assert.equal(fx.ledger.repos().acme?.next, 51);
  assert.equal(fx.ledger.listItems({ repo: 'acme' }).length, 50);
});

test('transitions: an invalid transition is 409, a valid one rewrites the md', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const item = await fx.ledger.createItem({ ...base, repo: 'acme', title: 'task' });
  const id = item.fm.id;

  await assert.rejects(fx.ledger.release(id, {}), (err: any) => err.status === 409);

  const claimed = await fx.ledger.claim(id, { session: 'abcd1234', paths: ['src/**'], intent: 'refactor' });
  assert.equal(claimed.fm.status, 'doing');
  assert.equal(claimed.fm.claimed_by?.session, 'abcd1234');
  assert.deepEqual(claimed.fm.paths, ['src/**']);
  await assert.rejects(
    fx.ledger.claim(id, { session: 'other-session', paths: [] }),
    (err: any) => err.status === 409 && /is already held by session/.test(err.message),
  );

  const released = await fx.ledger.release(id, { session: 'abcd1234' });
  assert.equal(released.fm.status, 'open');
  assert.equal(released.fm.claimed_by, null);

  const done = await fx.ledger.done(id, { session: 'abcd1234', ref: 'v0.26.0' });
  assert.equal(done.fm.status, 'done');
  assert.equal(done.fm.done?.version, 'v0.26.0');
  await assert.rejects(fx.ledger.claim(id, { session: 'x', paths: [] }), (err: any) => err.status === 409);

  const reopened = await fx.ledger.reopen(id, { why: 'needs rework' });
  assert.equal(reopened.fm.status, 'open');
  assert.equal(reopened.fm.done, null);
  assert.ok(reopened.log.some((l) => l.text.includes('reopen — needs rework')));
});

test('closing a blocking item unblocks the dependents', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const a = await fx.ledger.createItem({ ...base, repo: 'acme', title: 'blocker A' });
  const b = await fx.ledger.createItem({ ...base, repo: 'acme', title: 'blocker B' });
  const c = await fx.ledger.createItem({
    ...base,
    repo: 'acme',
    title: 'dependent C',
    blocked_by: [a.fm.id, b.fm.id],
  });
  assert.equal(c.fm.status, 'blocked');
  assert.deepEqual(fx.ledger.getItem(a.fm.id).item.fm.blocks, [c.fm.id]);

  await fx.ledger.done(a.fm.id, {});
  assert.equal(fx.ledger.getItem(c.fm.id).item.fm.status, 'blocked');

  await fx.ledger.drop(b.fm.id, { why: 'disproved' });
  const unblocked = fx.ledger.getItem(c.fm.id).item;
  assert.equal(unblocked.fm.status, 'open');
  assert.ok(unblocked.log.some((l) => l.text.startsWith('unblocked')));
});

test('dup merges into the target, block --on human overrides the owner', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const a = await fx.ledger.createItem({ ...base, repo: 'acme', title: 'A' });
  const b = await fx.ledger.createItem({ ...base, repo: 'acme', title: 'B' });
  const dropped = await fx.ledger.dup(a.fm.id, { into: b.fm.id });
  assert.equal(dropped.fm.status, 'dropped');
  assert.deepEqual(fx.ledger.getItem(b.fm.id).item.fm.aliases, [a.fm.id]);

  const blocked = await fx.ledger.block(b.fm.id, { on: 'human' });
  assert.equal(blocked.fm.status, 'blocked');
  assert.equal(blocked.fm.owner, 'human');
});

test('intake: triage links items, dropped pieces carry a reason', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const intake = await fx.ledger.createIntake({
    text: 'OAuth tab with buttons\nThe app must recognise the error',
    channel: 'chat',
    session: '61e0b33d',
    repo_hint: 'acme',
  });
  assert.equal(intake.status, 'new');
  assert.match(intake.id, /^[1-9]\d+$/);

  const item = await fx.ledger.createItem({
    ...base,
    repo: 'acme',
    title: 'OAuth tab',
    intake: intake.id,
  });
  const triaged = await fx.ledger.triage(intake.id, {
    items: [item.fm.id],
    dropped: [{ text: 'this is already done', reason: 'done in ACME-131' }],
    session: '61e0b33d',
  });
  assert.equal(triaged.status, 'triaged');
  assert.deepEqual(triaged.items, [item.fm.id]);
  assert.deepEqual(triaged.dropped, [{ text: 'this is already done', reason: 'done in ACME-131' }]);
  assert.equal(fx.ledger.getItem(item.fm.id).item.fm.intake, intake.id);

  const events = fx.ledger.listJournal('acme');
  assert.ok(events.some((e) => e.type === 'intake.triaged'));
});

test('createItem with intake marks the intake record itself (intake.linked, triaged)', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const intake = await fx.ledger.createIntake({
    text: 'two pieces of work in one dump',
    channel: 'chat',
    session: '61e0b33d',
    repo_hint: 'acme',
  });

  const first = await fx.ledger.createItem({
    ...base,
    repo: 'acme',
    title: 'first piece',
    intake: intake.id,
    session: '61e0b33d',
  });
  let rec = fx.ledger.getIntake(intake.id);
  assert.equal(rec.status, 'triaged', 'a record without items → triaged');
  assert.deepEqual(rec.items, [first.fm.id]);
  assert.deepEqual(rec.triage, [{ item: first.fm.id, excerpt: 'first piece' }]);
  assert.ok(fx.ledger.listJournal('acme').some((e) => e.type === 'intake.linked'));

  // A second item from the same intake record: it is appended, the status never falls back to `new`.
  const second = await fx.ledger.createItem({
    ...base,
    repo: 'acme',
    title: 'second piece',
    intake: intake.id,
    session: '61e0b33d',
  });
  rec = fx.ledger.getIntake(intake.id);
  assert.equal(rec.status, 'triaged');
  assert.deepEqual(rec.items, [first.fm.id, second.fm.id]);

  // Explicit triage keeps working — only it can do `partial` and `--drop`.
  const partial = await fx.ledger.triage(intake.id, {
    items: [],
    dropped: [{ text: 'the rest', reason: 'out of scope' }],
    status: 'partial',
    session: '61e0b33d',
  });
  assert.equal(partial.status, 'partial');

  // …and another `add --intake` moves it back to triaged, never to new.
  await fx.ledger.createItem({
    ...base,
    repo: 'acme',
    title: 'third piece',
    intake: intake.id,
    session: '61e0b33d',
  });
  assert.equal(fx.ledger.getIntake(intake.id).status, 'triaged');

  // An unknown intake id does not fail the item.
  const orphan = await fx.ledger.createItem({
    ...base,
    repo: 'acme',
    title: 'without intake',
    intake: '7241889432101351425',
  });
  assert.equal(orphan.fm.intake, '7241889432101351425');
});

test('listIntakeUnprocessed — no items, no triage, older than 10 min', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const fresh = await fx.ledger.createIntake({
    text: 'just dropped in, triage in progress',
    channel: 'chat',
    session: '61e0b33d',
    repo_hint: 'acme',
  });
  // Triage in progress in the same session does not nag.
  assert.deepEqual(fx.ledger.listIntakeUnprocessed().map((r) => r.id), []);
  // 11 minutes later it does.
  const later = Date.now() + 11 * 60_000;
  assert.deepEqual(fx.ledger.listIntakeUnprocessed(later).map((r) => r.id), [fresh.id]);

  // A bare `--drop` (without items) is also a decision → it is no longer unprocessed.
  await fx.ledger.triage(fresh.id, {
    items: [],
    dropped: [{ text: 'none of it', reason: 'duplicate' }],
    status: 'new',
    session: '61e0b33d',
  });
  assert.equal(fx.ledger.getIntake(fresh.id).status, 'new', 'status stayed new');
  assert.deepEqual(fx.ledger.listIntakeUnprocessed(later).map((r) => r.id), []);
});

test('decide: D<n> sequentially, the journal gets an event', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const d1 = await fx.ledger.createDecision({
    repo: 'acme',
    title: 'Integer cents',
    why: 'No float rounding in totals.',
    related: ['ACME-88'],
  });
  const d2 = await fx.ledger.createDecision({
    repo: 'acme',
    title: 'Second',
    why: 'because',
    related: [],
  });
  assert.equal(d1.n, 1);
  assert.equal(d2.n, 2);
  const text = await readFile(fx.ledger.paths.decisionsFile('acme'), 'utf8');
  assert.match(text, /^### D1 · \d{4}-\d{2}-\d{2} · Integer cents$/m);
  assert.match(text, /Related: ACME-88/);
  assert.equal(fx.ledger.listDecisions('acme').length, 2);
});

test('manual md edit: invalid frontmatter = warning, the last good version stays', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const item = await fx.ledger.createItem({ ...base, repo: 'acme', title: 'original title' });
  const file = fx.ledger.paths.itemFile('acme', item.fm.id);

  await writeFile(file, '---\nid: ACME-1\nstatus: invented\n---\n## Why\nbroken\n', 'utf8');
  await fx.ledger.reindex();
  assert.equal(fx.ledger.warnings.size, 1);
  assert.equal(fx.ledger.getItem(item.fm.id).item.fm.title, 'original title');

  await writeFile(
    file,
    (await readFile(file, 'utf8')).replace('status: invented', 'status: open'),
    'utf8',
  );
  await fx.ledger.reindex();
  assert.equal(fx.ledger.warnings.size, 1); // required fields are still missing
  await writeFile(file, parseItemFixture(item.fm.id), 'utf8');
  await fx.ledger.reindex();
  assert.equal(fx.ledger.warnings.size, 0);
  assert.equal(fx.ledger.getItem(item.fm.id).item.fm.title, 'rewritten by hand');
});

test('S8: repo("__proto__" and similar) is a 404, not prototype pollution', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  for (const slug of ['__proto__', 'constructor', 'toString']) {
    assert.throws(() => fx.ledger.repo(slug), /unknown repo/, slug);
    assert.throws(() => fx.ledger.listItems({ repo: slug }), /unknown repo/, slug);
  }
  // and a legitimate repo keeps working
  assert.equal(fx.ledger.repo('ops').prefix, 'OPS');
});

function parseItemFixture(id: string): string {
  return `---
id: ${id}
title: rewritten by hand
status: open
kind: BACKLOG
priority: P2
owner: agent
repo: acme
area: null
paths: []
blocks: []
blocked_by: []
requested_by: null
intake: null
aliases: []
claimed_by: null
source:
  session: null
  agent: null
  commit: null
done: null
created: 2026-09-28T14:02:00+02:00
updated: 2026-09-28T14:02:00+02:00
---

## Why
manual

## Plan

## Recommendation

## Comments

## Log
- 2026-09-28 14:02 · — · manual edit
`;
}

test('B3: init writes .gitattributes `* text eol=lf`; existing file is kept, line prepended once', async (t) => {
  const fresh = await openTestLedger();
  t.after(fresh.cleanup);
  assert.equal(await readFile(fresh.ledger.paths.gitattributes, 'utf8'), '* text eol=lf\n');

  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await mkdir(tmp.dir, { recursive: true });
  await writeFile(`${tmp.dir}/.gitattributes`, '*.png binary\r\n', 'utf8');
  const ledger = new Ledger({ config: tmp.config, log: () => {} });
  await ledger.init();
  t.after(() => ledger.close());
  const text = await readFile(ledger.paths.gitattributes, 'utf8');
  assert.equal(text, '* text eol=lf\n*.png binary\r\n', 'user content untouched, our line first so theirs win');

  await ledger.init(); // idempotent
  assert.equal(await readFile(ledger.paths.gitattributes, 'utf8'), text);
});
