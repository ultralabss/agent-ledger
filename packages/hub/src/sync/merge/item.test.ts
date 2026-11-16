import assert from 'node:assert/strict';
import test from 'node:test';
import { parseItem } from '@agent-ledger/shared';
import { mergeItem, mergeStatus } from './item.ts';
import { baseText, ctxOf, DEV_A, DEV_B, edit, MARKERS, T0 } from './testkit.ts';

const T1 = '2026-11-10T10:00:00+01:00';
const T2 = '2026-11-10T11:00:00+01:00';

const CA = ctxOf(DEV_A, DEV_B);
const CB = ctxOf(DEV_B, DEV_A, false);

function run(a: string, b: string, base: string | null = baseText()) {
  const ab = mergeItem(base, a, b, CA);
  const ba = mergeItem(base, b, a, CB);
  assert.equal(ab.merged, ba.merged, 'commutative');
  assert.deepEqual(ab.notes, ba.notes, 'notes commutative');
  assert.ok(!MARKERS.test(ab.merged), 'no conflict markers');
  return { ...ab, item: parseItem(ab.merged).item };
}

test('scalars: only one side changed -> applied, no note', () => {
  const a = edit(baseText(), (i) => { i.fm.title = 'A'; i.fm.updated = T1; });
  const b = edit(baseText(), (i) => { i.fm.priority = 'P0'; i.fm.updated = T1; });
  const r = run(a, b);
  assert.equal(r.item.fm.title, 'A');
  assert.equal(r.item.fm.priority, 'P0');
  assert.equal(r.notes.length, 0);
});

test('scalars: both changed -> newer updated wins, loser in Log + sync.conflict', () => {
  const a = edit(baseText(), (i) => { i.fm.title = 'from A'; i.fm.updated = T1; });
  const b = edit(baseText(), (i) => { i.fm.title = 'from B'; i.fm.updated = T2; });
  const r = run(a, b);
  assert.equal(r.item.fm.title, 'from B');
  assert.equal(r.item.fm.updated, T2);
  assert.equal(r.notes[0]?.type, 'sync.conflict');
  assert.equal(r.notes[0]?.field, 'title');
  assert.equal(r.notes[0]?.device, DEV_A);
  assert.ok(r.item.log.some((l) => l.text.startsWith('sync: title') && l.text.includes('from A')));
});

test('scalars: updated tie -> lower device_id wins', () => {
  const a = edit(baseText(), (i) => { i.fm.priority = 'P0'; i.fm.updated = T1; });
  const b = edit(baseText(), (i) => { i.fm.priority = 'P3'; i.fm.updated = T1; });
  assert.equal(run(a, b).item.fm.priority, 'P0'); // DEV_A < DEV_B
});

test('status precedence: done > dropped > blocked > doing > open > proposed', () => {
  const order = ['done', 'dropped', 'blocked', 'doing', 'open', 'proposed'] as const;
  for (let i = 0; i < order.length; i += 1) {
    for (let j = i + 1; j < order.length; j += 1) {
      assert.equal(mergeStatus('proposed', order[j]!, order[i]!), order[i]);
      assert.equal(mergeStatus('proposed', order[i]!, order[j]!), order[i]);
    }
  }
});

test('status: single-side change from base is taken even if lower rank', () => {
  assert.equal(mergeStatus('doing', 'open', 'doing'), 'open');
  assert.equal(mergeStatus('doing', 'doing', 'open'), 'open');
});

test('status: reopen of terminal base beats the stale terminal side', () => {
  assert.equal(mergeStatus('done', 'open', 'dropped'), 'open');
  assert.equal(mergeStatus('dropped', 'done', 'open'), 'open');
  assert.equal(mergeStatus('done', 'open', 'doing'), 'doing'); // both reopened -> precedence
});

test('item: done side wins, done object + claim cleared, other side doing claim lost with note', () => {
  const claim = { session: 'sess-b', since: T1 };
  const a = edit(baseText(), (i) => {
    i.fm.status = 'done';
    i.fm.done = { commit: 'abc1234', version: null, at: T1 };
    i.fm.updated = T1;
  });
  const b = edit(baseText(), (i) => { i.fm.status = 'doing'; i.fm.claimed_by = claim; i.fm.updated = T2; });
  const r = run(a, b);
  assert.equal(r.item.fm.status, 'done');
  assert.equal(r.item.fm.done?.commit, 'abc1234');
  assert.equal(r.item.fm.claimed_by, null);
  const lost = r.notes.find((n) => n.type === 'sync.claim-lost');
  assert.equal(lost?.session, 'sess-b');
  assert.equal(lost?.device, DEV_B);
});

test('claimed_by: both claim -> the side already on remote wins, loser notified', () => {
  const ca = { session: 'sess-a', since: T1 };
  const cb = { session: 'sess-b', since: T1 };
  const a = edit(baseText(), (i) => { i.fm.status = 'doing'; i.fm.claimed_by = ca; i.fm.updated = T2; });
  const b = edit(baseText(), (i) => { i.fm.status = 'doing'; i.fm.claimed_by = cb; i.fm.updated = T1; });
  // theirs (B) is on remote: B wins although A is newer
  const ab = mergeItem(baseText(), a, b, ctxOf(DEV_A, DEV_B, true));
  assert.equal(parseItem(ab.merged).item.fm.claimed_by?.session, 'sess-b');
  assert.equal(ab.notes.find((n) => n.type === 'sync.claim-lost')?.session, 'sess-a');
  // same facts, sides swapped
  const ba = mergeItem(baseText(), b, a, ctxOf(DEV_B, DEV_A, false));
  assert.equal(ba.merged, ab.merged);
  // remote is A -> A wins
  const ab2 = mergeItem(baseText(), a, b, ctxOf(DEV_A, DEV_B, false));
  assert.equal(parseItem(ab2.merged).item.fm.claimed_by?.session, 'sess-a');
});

test('sets: 3-way add/remove on paths, blocks, blocked_by, aliases', () => {
  const base = edit(baseText(), (i) => { i.fm.paths = ['a/x', 'a/y']; i.fm.aliases = ['old']; });
  const a = edit(base, (i) => { i.fm.paths = ['a/x', 'a/z']; i.fm.blocks = ['ACME-2']; i.fm.updated = T1; });
  const b = edit(base, (i) => { i.fm.paths = ['a/x', 'a/y', 'a/w']; i.fm.blocked_by = ['ACME-3']; i.fm.aliases = []; i.fm.updated = T1; });
  const r = run(a, b, base);
  assert.deepEqual(r.item.fm.paths, ['a/w', 'a/x', 'a/z']); // y removed by A, z added by A, w added by B
  assert.deepEqual(r.item.fm.blocks, ['ACME-2']);
  assert.deepEqual(r.item.fm.blocked_by, ['ACME-3']);
  assert.deepEqual(r.item.fm.aliases, []);
});

test('updated = max, created = min', () => {
  const a = edit(baseText(), (i) => { i.fm.updated = T2; i.fm.title = 'A'; });
  const b = edit(baseText(), (i) => { i.fm.updated = T1; i.fm.priority = 'P1'; });
  assert.equal(run(a, b).item.fm.updated, T2);
});

test('plan: checkbox OR, new steps from both sides, text conflict keeps winner + sync comment', () => {
  const a = edit(baseText(), (i) => {
    i.steps[0]!.done = true;
    i.steps[1]!.text = 'second (A)';
    i.steps.push({ n: 3, done: false, text: 'third A' });
    i.fm.updated = T1;
  });
  const b = edit(baseText(), (i) => {
    i.steps[1]!.done = true;
    i.steps[1]!.text = 'second (B)';
    i.steps.push({ n: 4, done: true, text: 'fourth B' });
    i.fm.updated = T2;
  });
  const r = run(a, b);
  assert.deepEqual(
    r.item.steps.map((s) => [s.n, s.done, s.text]),
    [[1, true, 'first'], [2, true, 'second (B)'], [3, false, 'third A'], [4, true, 'fourth B']],
  );
  const sync = r.item.comments.find((c) => c.author === 'sync');
  assert.ok(sync?.text.includes('second (A)'));
  assert.equal(r.notes.find((n) => n.field === 'plan.2')?.type, 'sync.conflict');
});

test('plan: step deleted by one side is honoured only if the other never touched it', () => {
  const a = edit(baseText(), (i) => { i.steps = [i.steps[0]!]; i.fm.updated = T1; });
  const untouched = edit(baseText(), (i) => { i.fm.priority = 'P1'; i.fm.updated = T1; });
  assert.equal(run(a, untouched).item.steps.length, 1);
  const touched = edit(baseText(), (i) => { i.steps[1]!.done = true; i.fm.updated = T1; });
  assert.equal(run(a, touched).item.steps.length, 2);
});

test('why: disjoint line edits merge cleanly', () => {
  const a = edit(baseText(), (i) => { i.why = 'L0\nl1\nl2\nl3\nl4'; i.fm.updated = T1; });
  const b = edit(baseText(), (i) => { i.why = 'l0\nl1\nl2\nl3\nL4'; i.fm.updated = T1; });
  const r = run(a, b);
  assert.equal(r.item.why, 'L0\nl1\nl2\nl3\nL4');
  assert.equal(r.notes.length, 0);
});

test('why/rec: conflict keeps newer side, other side preserved as sync comment, no markers', () => {
  const a = edit(baseText(), (i) => { i.why = 'l0\nA-version\nl2\nl3\nl4'; i.rec = 'r0\nr1\nREC-A'; i.fm.updated = T1; });
  const b = edit(baseText(), (i) => { i.why = 'l0\nB-version\nl2\nl3\nl4'; i.rec = 'r0\nr1\nREC-B'; i.fm.updated = T2; });
  const r = run(a, b);
  assert.equal(r.item.why, 'l0\nB-version\nl2\nl3\nl4');
  assert.equal(r.item.rec, 'r0\nr1\nREC-B');
  const texts = r.item.comments.filter((c) => c.author === 'sync').map((c) => c.text);
  assert.equal(texts.length, 2);
  assert.ok(texts.some((x) => x.includes('A-version')));
  assert.ok(texts.some((x) => x.includes('REC-A')));
});

test('comments: union by Snowflake id (numeric order), never delete, same exact entry deduped', () => {
  const a = edit(baseText(), (i) => {
    i.comments.push({ at: '2026-11-10 10:00', author: 'a', id: '2000', text: 'from a' });
    i.fm.updated = T1;
  });
  const b = edit(baseText(), (i) => {
    i.comments.push({ at: '2026-11-10 10:01', author: 'b', id: '999', text: 'from b' });
    i.comments = i.comments.filter((c) => c.id !== '1000'); // a delete must not stick
    i.fm.updated = T1;
  });
  const r = run(a, b);
  assert.deepEqual(r.item.comments.map((c) => c.id), ['999', '1000', '2000']);
});

test('log: union by exact line, sorted by time, base order kept within a minute, sync lines never lost', () => {
  const a = edit(baseText(), (i) => {
    i.log.push({ at: '2026-11-10 09:05', session: 'sa', text: 'zz' });
    i.log.push({ at: '2026-11-10 09:05', session: 'sa', text: 'shared' });
    i.fm.updated = T1;
  });
  const b = edit(baseText(), (i) => {
    i.log.push({ at: '2026-11-10 09:05', session: 'sa', text: 'shared' });
    i.log.push({ at: '2026-11-10 09:01', session: 'sb', text: 'early' });
    i.fm.updated = T1;
  });
  const r = run(a, b);
  assert.deepEqual(
    r.item.log.map((l) => l.text),
    ['created', 'early', 'shared', 'zz'],
  );
});

test('unknown section and unknown frontmatter key survive; different item throws', () => {
  const withExtra = (s: string): string => s.replace(/\n---\n/, '\nx_custom: 1\n---\n') + '\n## Notes\nkeep me\n';
  const base = withExtra(baseText());
  const a = edit(base, (i) => { i.fm.title = 'A'; i.fm.updated = T1; });
  const b = edit(base, (i) => { i.fm.priority = 'P0'; i.fm.updated = T1; });
  const r = run(a, b, base);
  assert.ok(r.merged.includes('x_custom: 1'));
  assert.ok(r.merged.includes('## Notes\nkeep me'));
  const other = edit(baseText(), (i) => { i.fm.id = 'ACME-9'; i.fm.updated = T1; });
  assert.throws(() => mergeItem(baseText(), a, other, CA), /different items/);
});

test('shortcuts: untouched side returns the other byte for byte; garbage side throws', () => {
  const a = edit(baseText(), (i) => { i.fm.title = 'A'; i.fm.updated = T1; });
  assert.equal(mergeItem(baseText(), baseText(), a, CA).merged, a);
  assert.equal(mergeItem(baseText(), a, baseText(), CA).merged, a);
  assert.throws(() => mergeItem(baseText(), a, 'not an item', CA));
  assert.ok(T0 < T1);
});

test('no base (both created the same file): conflicting scalars still resolve, nothing lost', () => {
  const a = edit(baseText(), (i) => { i.fm.title = 'A'; i.fm.updated = T1; });
  const b = edit(baseText(), (i) => { i.fm.title = 'B'; i.fm.updated = T2; });
  const r = run(a, b, null);
  assert.equal(r.item.fm.title, 'B');
  assert.ok(r.item.log.some((l) => l.text.includes('dropped A')));
});
