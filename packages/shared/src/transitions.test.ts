import assert from 'node:assert/strict';
import test from 'node:test';
import { canTransition, isOpen, targetStatus } from './item.ts';
import { ITEM_STATUSES, type ItemStatus } from './types.ts';

test('transitions §4.4: allowed paths', () => {
  assert.ok(canTransition('proposed', 'open'));
  assert.ok(canTransition('open', 'claim'));
  assert.ok(canTransition('doing', 'release'));
  assert.ok(canTransition('open', 'block'));
  assert.ok(canTransition('doing', 'block'));
  assert.ok(canTransition('blocked', 'unblock'));
  assert.ok(canTransition('done', 'reopen'));
  assert.ok(canTransition('dropped', 'reopen'));
  for (const from of ['proposed', 'open', 'doing', 'blocked'] as ItemStatus[]) {
    assert.ok(canTransition(from, 'done'), `${from}→done`);
    assert.ok(canTransition(from, 'drop'), `${from}→dropped`);
  }
});

test('transitions §4.4: forbidden paths', () => {
  assert.equal(canTransition('done', 'claim'), false);
  assert.equal(canTransition('dropped', 'claim'), false);
  assert.equal(canTransition('open', 'release'), false);
  assert.equal(canTransition('proposed', 'claim'), false);
  assert.equal(canTransition('open', 'reopen'), false);
  assert.equal(canTransition('done', 'done'), false);
  assert.equal(canTransition('blocked', 'release'), false);
});

test('target statuses and openness', () => {
  assert.equal(targetStatus('claim'), 'doing');
  assert.equal(targetStatus('drop'), 'dropped');
  const open = ITEM_STATUSES.filter(isOpen);
  assert.deepEqual(open, ['proposed', 'open', 'doing', 'blocked']);
});
