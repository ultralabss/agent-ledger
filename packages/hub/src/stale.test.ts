/** Staleness: thresholds and their edges, what counts as activity, the
 *  `blocked` rule, env override, clock skew. Pure — no hub, no git. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { isoLocal, type Item } from '@agent-ledger/shared';
import { NOW, mk } from './stale-fixtures.ts';
import {
  DAY_MS,
  lastActivity,
  staleThresholds,
  staleness,
  stalenessResolver,
} from './stale.ts';

const ENV = {};

test('P0/P1: 6 d fresh, 7 d stale, 8 d stale (the threshold itself is stale)', () => {
  for (const p of ['P0', 'P1'] as const) {
    assert.equal(staleness(mk({ priority: p, ageDays: 6 }), NOW, ENV).stale, false);
    const at7 = staleness(mk({ priority: p, ageDays: 7 }), NOW, ENV);
    assert.deepEqual(at7, { ageDays: 7, thresholdDays: 7, stale: true });
    assert.equal(staleness(mk({ priority: p, ageDays: 8 }), NOW, ENV).stale, true);
  }
});

test('P2/P3: 20 d fresh, 21 d stale, 22 d stale', () => {
  for (const p of ['P2', 'P3'] as const) {
    assert.equal(staleness(mk({ priority: p, ageDays: 20 }), NOW, ENV).stale, false);
    assert.deepEqual(staleness(mk({ priority: p, ageDays: 21 }), NOW, ENV), {
      ageDays: 21,
      thresholdDays: 21,
      stale: true,
    });
    assert.equal(staleness(mk({ priority: p, ageDays: 22 }), NOW, ENV).stale, true);
  }
});

test('proposed: 7 d whatever the priority', () => {
  assert.equal(staleness(mk({ status: 'proposed', priority: 'P3', ageDays: 6 }), NOW, ENV).stale, false);
  const at7 = staleness(mk({ status: 'proposed', priority: 'P3', ageDays: 7 }), NOW, ENV);
  assert.equal(at7.stale, true);
  assert.equal(at7.thresholdDays, 7);
});

test('doing and open age like any open item; done and dropped never go stale', () => {
  assert.equal(staleness(mk({ status: 'doing', ageDays: 30 }), NOW, ENV).stale, true);
  assert.equal(staleness(mk({ status: 'open', ageDays: 30 }), NOW, ENV).stale, true);
  assert.equal(staleness(mk({ status: 'done', ageDays: 400 }), NOW, ENV).stale, false);
  assert.equal(staleness(mk({ status: 'dropped', ageDays: 400 }), NOW, ENV).stale, false);
});

test('LEDGER_STALE_DAYS: one number N → P0/P1 and proposed N, P2/P3 3×N; junk falls back', () => {
  assert.deepEqual(staleThresholds({}), { hot: 7, cold: 21, proposed: 7 });
  assert.deepEqual(staleThresholds({ LEDGER_STALE_DAYS: '10' }), { hot: 10, cold: 30, proposed: 10 });
  for (const junk of ['0', '-3', 'abc', '7.5', '', '99999', '1e3']) {
    assert.deepEqual(staleThresholds({ LEDGER_STALE_DAYS: junk }), { hot: 7, cold: 21, proposed: 7 }, junk);
  }
  const env = { LEDGER_STALE_DAYS: '3' };
  assert.equal(staleness(mk({ ageDays: 2 }), NOW, env).stale, false);
  assert.equal(staleness(mk({ ageDays: 3 }), NOW, env).stale, true);
  assert.equal(staleness(mk({ priority: 'P2', ageDays: 8 }), NOW, env).stale, false);
  assert.equal(staleness(mk({ priority: 'P2', ageDays: 9 }), NOW, env).stale, true);
});

test('a `tidy: kept` log line or comment resets the age', () => {
  const stale = mk({ ageDays: 40 });
  assert.equal(staleness(stale, NOW, ENV).stale, true);

  const keptLog = mk({ ageDays: 40, log: [{ daysAgo: 0, text: 'tidy: kept — waiting for the vendor' }] });
  const a = staleness(keptLog, NOW, ENV);
  assert.equal(a.stale, false);
  assert.equal(a.ageDays, 0);

  const keptNote = mk({ ageDays: 40, comments: [{ daysAgo: 2, text: 'tidy: kept — still wanted' }] });
  const b = staleness(keptNote, NOW, ENV);
  assert.equal(b.stale, false);
  assert.equal(b.ageDays, 2);
});

test('lastActivity: newest of updated, log, comments, item_files and leases', () => {
  const item = mk({
    ageDays: 30,
    log: [{ daysAgo: 20, text: 'x' }],
    comments: [{ daysAgo: 15, text: 'y' }],
  });
  const base = lastActivity(item, {}, NOW);
  assert.equal(Math.round((NOW - base) / DAY_MS), 15);
  const files = lastActivity(item, { itemFilesLastAt: NOW - 9 * DAY_MS }, NOW);
  assert.equal(Math.round((NOW - files) / DAY_MS), 9);
  const lease = lastActivity(item, { itemFilesLastAt: NOW - 9 * DAY_MS, lastLeaseAt: NOW - 2 * DAY_MS }, NOW);
  assert.equal(Math.round((NOW - lease) / DAY_MS), 2);
  const none = staleness(item, NOW, ENV, { activity: { lastLeaseAt: NOW - 2 * DAY_MS } });
  assert.equal(none.stale, false);
});

test('a clock that jumped: far-future timestamps are ignored, age is never negative', () => {
  const item = mk({ ageDays: 30 });
  item.fm.updated = isoLocal(new Date(NOW + 400 * DAY_MS));
  // The bogus `updated` must not keep the item fresh forever; `created` still says 30 d.
  assert.equal(staleness(item, NOW, ENV).stale, true);
  const skew = mk({ ageDays: 0 });
  skew.fm.updated = isoLocal(new Date(NOW + 3_600_000));
  assert.equal(staleness(skew, NOW, ENV).ageDays, 0);
});

test('blocked: stale only when every open blocker is stale too', () => {
  const blocked = mk({ id: 'ACME-9', status: 'blocked', ageDays: 30, blocked_by: ['ACME-2', 'ACME-3'] });
  const freshBlocker = mk({ id: 'ACME-2', ageDays: 1 });
  const staleBlocker = mk({ id: 'ACME-3', ageDays: 30 });
  const closed = mk({ id: 'ACME-4', status: 'done', ageDays: 1 });
  const world = (...items: Item[]) => (id: string) => items.find((i) => i.fm.id === id);
  const resolve = (...items: Item[]) =>
    stalenessResolver(world(blocked, ...items), () => ({}), NOW, ENV);

  assert.equal(resolve(freshBlocker, staleBlocker)(blocked).stale, false, 'one blocker moves');
  assert.equal(resolve(staleBlocker, { ...freshBlocker, fm: { ...freshBlocker.fm, status: 'done' } } as Item)(blocked).stale, true, 'the live blocker closed');
  assert.equal(resolve(staleBlocker, freshBlocker)(staleBlocker).stale, true, 'blockers themselves');

  const both = mk({ id: 'ACME-9', status: 'blocked', ageDays: 30, blocked_by: ['ACME-3'] });
  assert.equal(stalenessResolver(world(both, staleBlocker), () => ({}), NOW, ENV)(both).stale, true);

  const orphan = mk({ id: 'ACME-9', status: 'blocked', ageDays: 30, blocked_by: ['ACME-4', 'ACME-404'] });
  assert.equal(
    stalenessResolver(world(orphan, closed), () => ({}), NOW, ENV)(orphan).stale,
    true,
    'closed / unknown blockers do not shield it — its own age decides',
  );
  const young = mk({ id: 'ACME-9', status: 'blocked', ageDays: 2, blocked_by: ['ACME-3'] });
  assert.equal(stalenessResolver(world(young, staleBlocker), () => ({}), NOW, ENV)(young).stale, false);
});

test('blocked: a blocker cycle terminates and counts as stale', () => {
  const a = mk({ id: 'ACME-1', status: 'blocked', ageDays: 30, blocked_by: ['ACME-2'] });
  const b = mk({ id: 'ACME-2', status: 'blocked', ageDays: 30, blocked_by: ['ACME-1'] });
  const resolve = stalenessResolver((id) => [a, b].find((i) => i.fm.id === id), () => ({}), NOW, ENV);
  assert.equal(resolve(a).stale, true);
  assert.equal(resolve(b).stale, true);
});
