import assert from 'node:assert/strict';
import test from 'node:test';
import { mergeContext, mergeCounters, mergeDecisions, mergeIntake, mergeJournal } from './files.ts';
import { MARKERS } from './testkit.ts';

test('journal: line union, deduped, sorted by time; base order kept in a minute; CRLF normalised', () => {
  const base = '- 2026-11-10 09:00 · s0 · item.created · ACME-1\n- 2026-11-10 09:00 · s0 · item.status · ACME-1 · open→doing\n';
  const a = `${base}- 2026-11-10 09:30 · sa · item.comment · ACME-1\n`;
  const b = `${base.replace(/\n/g, '\r\n')}- 2026-11-10 09:10 · sb · item.comment · ACME-1\r\n- 2026-11-10 09:30 · sa · item.comment · ACME-1\r\n`;
  const r = mergeJournal(base, a, b);
  assert.deepEqual(r.merged.trim().split('\n'), [
    '- 2026-11-10 09:00 · s0 · item.created · ACME-1',
    '- 2026-11-10 09:00 · s0 · item.status · ACME-1 · open→doing',
    '- 2026-11-10 09:10 · sb · item.comment · ACME-1',
    '- 2026-11-10 09:30 · sa · item.comment · ACME-1',
  ]);
  assert.equal(mergeJournal(base, b, a).merged, r.merged);
});

test('journal: empty sides', () => {
  assert.equal(mergeJournal(null, '', '').merged, '');
});

const D = (id: string, body: string): string => `### ${id} · 2026-11-10 · title ${id}\n${body}\n`;

test('decisions: union by id, ordered by number then slot; edit on one side applies', () => {
  const base = `${D('D1', 'one')}\n${D('D2', 'two')}`;
  const a = `${D('D1', 'one edited')}\n${D('D2', 'two')}\n${D('D3', 'three')}`;
  const b = `${base}\n${D('DW1', 'win one')}`;
  const r = mergeDecisions(base, a, b);
  assert.deepEqual(r.merged.match(/^### (D\S+)/gm), ['### D1', '### DW1', '### D2', '### D3']);
  assert.ok(r.merged.includes('one edited'));
  assert.ok(!r.merged.includes('\none\n'));
  assert.equal(r.notes.length, 0);
  assert.equal(mergeDecisions(base, b, a).merged, r.merged);
});

test('decisions: same id, different body on both sides -> both kept + note', () => {
  const base = D('D1', 'one');
  const a = D('D1', 'ours');
  const b = D('D1', 'theirs');
  const r = mergeDecisions(base, a, b);
  assert.equal((r.merged.match(/^### D1/gm) ?? []).length, 2);
  assert.ok(r.merged.includes('ours') && r.merged.includes('theirs'));
  assert.equal(r.notes[0]?.type, 'sync.decision-conflict');
  assert.equal(r.notes[0]?.item, 'D1');
  assert.equal(mergeDecisions(base, b, a).merged, r.merged);
  // re-merging the result is stable and silent
  const again = mergeDecisions(base, r.merged, b);
  assert.equal(again.merged, r.merged);
  assert.equal(again.notes.length, 0);
});

test('decisions: a deleted block comes back (append-only)', () => {
  const base = `${D('D1', 'one')}\n${D('D2', 'two')}`;
  const r = mergeDecisions(base, D('D1', 'one'), base);
  assert.ok(r.merged.includes('### D2'));
});

test('counters: per-key max, sorted, invalid input fails closed', () => {
  const r = mergeCounters('acme: 3\n', 'acme: 5\nweb: 1\n', 'acme: 4\nweb: 9\nzed: 2\n');
  assert.equal(r.merged, 'acme: 5\nweb: 9\nzed: 2\n');
  assert.equal(mergeCounters(null, 'a: 1\n', 'b: 2\n').merged, mergeCounters(null, 'b: 2\n', 'a: 1\n').merged);
  assert.throws(() => mergeCounters(null, 'a: -1\n', 'a: 1\n'));
  assert.throws(() => mergeCounters(null, 'A_B: 1\n', 'a: 1\n'));
  assert.throws(() => mergeCounters(null, '- 1\n', 'a: 1\n'));
});

const intake = (status: string, items: string[], extra = ''): string =>
  `---\nid: '123'\nat: 2026-11-10T09:00:00+01:00\nchannel: chat\nsession: null\nrepo_hint: null\nstatus: ${status}\nitems: [${items.join(', ')}]\n---\nraw text${extra}\n`;

test('intake: status triaged > partial > new, items set-union, commutative', () => {
  const base = intake('new', []);
  const a = intake('partial', ['ACME-1']);
  const b = intake('new', ['ACME-2']);
  const r = mergeIntake(base, a, b);
  assert.match(r.merged, /status: partial/);
  assert.match(r.merged, /ACME-1/);
  assert.match(r.merged, /ACME-2/);
  assert.equal(mergeIntake(base, b, a).merged, r.merged);
  const c = intake('triaged', ['ACME-1']);
  assert.match(mergeIntake(base, a, c).merged, /status: triaged/);
  assert.throws(() => mergeIntake(base, a, intake('new', []).replace("'123'", "'124'")));
});

test('context: disjoint edits merge; conflict keeps local and returns proposedItem', () => {
  const base = '# Ctx\nline1\nline2\nline3\n';
  const a = '# Ctx\nLOCAL\nline2\nline3\n';
  const b = '# Ctx\nREMOTE\nline2\nline3\nadded\n';
  const r = mergeContext(base, a, b);
  assert.equal(r.merged, '# Ctx\nLOCAL\nline2\nline3\nadded\n');
  assert.equal(r.notes[0]?.type, 'sync.context-conflict');
  assert.equal(r.proposedItem?.why, 'REMOTE');
  assert.equal(r.proposedItem?.otherVersion, b);
  assert.ok(!MARKERS.test(r.merged));
  const clean = mergeContext(base, '# Ctx\nline1\nline2\nline3\nx\n', '# Ctx\nY\nline2\nline3\n');
  assert.equal(clean.proposedItem, null);
  assert.equal(clean.merged, '# Ctx\nY\nline2\nline3\nx\n');
});
