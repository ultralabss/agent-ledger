/** F1.1 / F1.4 (multi-device): slot-letter item ids and the snowflake worker. */

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  configureSnowflakeWorker,
  formatItemId,
  isItemId,
  itemIdSchema,
  itemIdScanRe,
  originHintSchema,
  parseItemId,
  RESERVED_SYNC_WORKER,
  relPathSchema,
  repoIdentitySchema,
  reposSyncedFileSchema,
  Snowflake,
  SLOT_LETTERS,
  slotSchema,
  slotWorkerId,
  snowflake,
  parseSnowflake,
  generate,
} from './index.ts';

test('item id regex: today ids keep working, slot letter is optional, I and O are not slots', () => {
  for (const ok of ['ACME-1', 'UL-142', 'ABCD-99', 'ACME-W1', 'ACME-V10', 'AB-A7', 'AB-Z1']) {
    assert.equal(isItemId(ok), true, ok);
    assert.equal(itemIdSchema.safeParse(ok).success, true, ok);
  }
  for (const bad of [
    'ACME-I1', // I is not a slot letter
    'ACME-O1', // nor O
    'ACME-0', // no zero, no leading zero
    'ACME-01',
    'ACME-W0',
    'ACME-WW1', // one letter only
    'ACME-w1', // upper case only
    'A-1',
    'ACMEE-1',
    'ACME-',
    'ACME-W',
    'ACME-1 ',
    ' ACME-1',
    'ACME-1\n',
    '../ACME-1',
    'ACME-1/../x',
  ]) {
    assert.equal(isItemId(bad), false, JSON.stringify(bad));
    assert.equal(itemIdSchema.safeParse(bad).success, false, JSON.stringify(bad));
  }
});

test('parseItemId / formatItemId round-trip, slot "" is the legacy id', () => {
  assert.deepEqual(parseItemId('ACME-142'), { prefix: 'ACME', slot: '', n: 142 });
  assert.deepEqual(parseItemId('ACME-W7'), { prefix: 'ACME', slot: 'W', n: 7 });
  assert.equal(parseItemId('ACME-I7'), null);
  assert.equal(parseItemId('acme-7'), null);
  assert.equal(parseItemId('ACME-99999999999999999999'), null, 'unsafe integer');
  assert.equal(formatItemId('ACME', '', 143), 'ACME-143');
  assert.equal(formatItemId('ACME', 'W', 1), 'ACME-W1');
  assert.throws(() => formatItemId('ACME', 'I', 1));
  assert.throws(() => formatItemId('ACME', '', 0));
  assert.throws(() => formatItemId('acme', '', 1));
});

test('scan regex finds slot ids in free text (trailers) and is independent per call', () => {
  const text = 'Refs: ACME-12, ACME-W3 and UL-9; not ACME-I3, not ACME-0.';
  const found = [...text.matchAll(itemIdScanRe())].map((m) => m[0]);
  assert.deepEqual(found, ['ACME-12', 'ACME-W3', 'UL-9']);
  // a /g regex shared between calls would carry lastIndex over
  assert.equal([...text.matchAll(itemIdScanRe())].length, 3);
});

test('slot schema and the slot alphabet agree', () => {
  assert.equal(SLOT_LETTERS.length, 24);
  assert.equal(SLOT_LETTERS.includes('I') || SLOT_LETTERS.includes('O'), false);
  for (const ch of SLOT_LETTERS) assert.equal(slotSchema.safeParse(ch).success, true, ch);
  for (const bad of ['I', 'O', 'a', 'AA', '1', ' ']) assert.equal(slotSchema.safeParse(bad).success, false, bad);
  assert.equal(slotSchema.safeParse('').success, true);
});

test('snowflake worker derives from the slot: "" = today (1), letters are distinct', () => {
  assert.equal(slotWorkerId(''), 1);
  const seen = new Set<number>([1]);
  for (const ch of SLOT_LETTERS) {
    const w = slotWorkerId(ch);
    assert.equal(seen.has(w), false, `${ch} collides`);
    assert.ok(w >= 2 && w <= 25);
    seen.add(w);
  }
  assert.throws(() => slotWorkerId('I'));
  assert.throws(() => slotWorkerId('WW'));
});

test('configureSnowflakeWorker re-points the process generator; "" restores the default', () => {
  const before = snowflake.workerId;
  try {
    configureSnowflakeWorker('W');
    assert.equal(snowflake.workerId, slotWorkerId('W'));
    assert.equal(parseSnowflake(generate()).worker, slotWorkerId('W'));
    configureSnowflakeWorker('');
    assert.equal(snowflake.workerId, 1, 'single-machine ledger: unchanged worker id');
    assert.equal(parseSnowflake(generate()).worker, 1);
  } finally {
    snowflake.setWorkerId(before);
  }
});

test('F3b: worker 1023 is reserved; env 1023 is rejected, state untouched, no slot maps to it', () => {
  assert.equal(RESERVED_SYNC_WORKER, 1023);
  const before = snowflake.workerId;
  const prevEnv = process.env.SNOWFLAKE_WORKER_ID;
  try {
    process.env.SNOWFLAKE_WORKER_ID = '1023';
    assert.throws(() => configureSnowflakeWorker(''), /reserved for hub-synthesised sync records/);
    assert.equal(snowflake.workerId, before, 'failed configure leaves the worker id alone');
    process.env.SNOWFLAKE_WORKER_ID = '1022';
    configureSnowflakeWorker('');
    assert.equal(snowflake.workerId, 1022);
    // a lettered slot ignores the env entirely, and never lands on 1023
    process.env.SNOWFLAKE_WORKER_ID = '1023';
    configureSnowflakeWorker('W');
    assert.equal(snowflake.workerId, slotWorkerId('W'));
    for (const ch of SLOT_LETTERS) assert.notEqual(slotWorkerId(ch), RESERVED_SYNC_WORKER);
    assert.notEqual(slotWorkerId(''), RESERVED_SYNC_WORKER);
  } finally {
    if (prevEnv === undefined) delete process.env.SNOWFLAKE_WORKER_ID;
    else process.env.SNOWFLAKE_WORKER_ID = prevEnv;
    snowflake.setWorkerId(before);
  }
});

test('two slots can never mint the same snowflake at the same instant', () => {
  const now = () => 1_800_000_000_000;
  const a = new Snowflake({ workerId: slotWorkerId(''), now });
  const b = new Snowflake({ workerId: slotWorkerId('W'), now });
  const ids = new Set<string>();
  for (let i = 0; i < 50; i += 1) {
    ids.add(a.generate());
    ids.add(b.generate());
  }
  assert.equal(ids.size, 100);
});

test('synced repos.yml schema: identity, no absolute path in portable fields', () => {
  const sha = 'a'.repeat(40);
  assert.equal(repoIdentitySchema.safeParse({ root_sha: sha, origin_hint: 'github.com/o/r' }).success, true);
  assert.equal(repoIdentitySchema.safeParse({ root_sha: sha }).success, true);
  assert.equal(repoIdentitySchema.safeParse({ root_sha: 'A'.repeat(40) }).success, false);
  assert.equal(repoIdentitySchema.safeParse({ root_sha: 'abc' }).success, false);
  for (const bad of ['https://u:p@h/x', 'a b', '../x', 'h/../x', 'x@h', '']) {
    assert.equal(originHintSchema.safeParse(bad).success, false, bad);
  }
  for (const bad of ['/abs', 'C:\\x', 'C:/x', '~/x', '\\\\srv\\x', '../x', 'a/../b', 'a\\b']) {
    assert.equal(relPathSchema.safeParse(bad).success, false, bad);
  }
  assert.equal(relPathSchema.safeParse('graphify-out').success, true);
  const ok = reposSyncedFileSchema.safeParse({ acme: { prefix: 'ACME', identity: { root_sha: sha } } });
  assert.equal(ok.success, true);
  // legacy keys stay readable so format 1 can be migrated
  assert.equal(
    reposSyncedFileSchema.safeParse({ acme: { prefix: 'ACME', path: '/x', next: 4, graphify: null } }).success,
    true,
  );
});
