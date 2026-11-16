import assert from 'node:assert/strict';
import test from 'node:test';
import { diffHunks, merge3Lines, mergeText, splitLines } from './diff3.ts';

const L = (s: string): string[] => (s === '' ? [] : s.split(' '));

test('splitLines: CRLF, trailing newline, empty', () => {
  assert.deepEqual(splitLines(''), []);
  assert.deepEqual(splitLines('a\r\nb\r\n'), ['a', 'b']);
  assert.deepEqual(splitLines('a\n\nb'), ['a', '', 'b']);
});

test('diffHunks: insert, delete, replace, identical', () => {
  assert.deepEqual(diffHunks(L('a b c'), L('a b c')), []);
  assert.deepEqual(diffHunks(L('a b c'), L('a x b c')), [{ start: 1, end: 1, lines: ['x'] }]);
  assert.deepEqual(diffHunks(L('a b c'), L('a c')), [{ start: 1, end: 2, lines: [] }]);
  assert.deepEqual(diffHunks(L('a b c'), L('a x c')), [{ start: 1, end: 2, lines: ['x'] }]);
});

test('merge3Lines: disjoint edits merge, same edit merges, adjacent edits conflict', () => {
  const base = L('a b c d e');
  const r1 = merge3Lines(base, L('A b c d e'), L('a b c d E'));
  assert.ok(r1.every((r) => r.kind === 'ok'));
  assert.deepEqual(
    r1.flatMap((r) => (r.kind === 'ok' ? r.lines : [])),
    L('A b c d E'),
  );
  const same = merge3Lines(base, L('a X c d e'), L('a X c d e'));
  assert.ok(same.every((r) => r.kind === 'ok'));
  const adj = merge3Lines(base, L('a X c d e'), L('a b Y d e'));
  assert.ok(adj.some((r) => r.kind === 'conflict'));
});

test('mergeText: conflict resolves to preferred side, loser block returned, no markers', () => {
  const base = 'a\nb\nc';
  const o = 'a\nOURS\nc';
  const t = 'a\nTHEIRS\nc\nd';
  const r1 = mergeText(base, o, t, true);
  assert.equal(r1.text, 'a\nOURS\nc\nd');
  assert.deepEqual(r1.loserBlocks, ['THEIRS']);
  const r2 = mergeText(base, o, t, false);
  assert.equal(r2.text, 'a\nTHEIRS\nc\nd');
  assert.deepEqual(r2.loserBlocks, ['OURS']);
  assert.ok(!/<<<<<<<|>>>>>>>/.test(r1.text + r2.text));
});

test('mergeText: no base = both inserted; identical sides short-circuit', () => {
  assert.equal(mergeText(null, 'x', 'x', true).text, 'x');
  assert.equal(mergeText(null, 'x', 'y', true).conflict, true);
  assert.equal(mergeText('b', 'b', 'y', true).text, 'y');
});

test('mergeText: huge middle falls back to one hunk instead of exploding', () => {
  const big = Array.from({ length: 3000 }, (_, i) => `l${i}`);
  const a = big.map((l, i) => (i % 2 ? `${l}a` : l)).join('\n');
  const b = big.map((l, i) => (i % 2 ? l : `${l}b`)).join('\n');
  const r = mergeText(big.join('\n'), a, b, true);
  assert.equal(r.conflict, true);
});
