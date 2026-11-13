/** One-time login codes, TTL, rate limit and `next` validation. */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { inspect } from 'node:util';
import { FailureLimiter, LoginCodeStore, safeNextPath } from './logincode.ts';

test('login code: 32 B base64url, one-time', () => {
  const codes = new LoginCodeStore();
  const code = codes.issue();
  assert.match(code, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(code, 'base64url').length, 32);
  assert.equal(codes.consume(code), true, 'first use passes');
  assert.equal(codes.consume(code), false, 'second use never');
  assert.equal(codes.live, 0);
});

test('login code: two codes do not mix, foreign/malformed input is rejected', () => {
  const codes = new LoginCodeStore();
  const a = codes.issue();
  const b = codes.issue();
  assert.notEqual(a, b);
  assert.equal(codes.consume(b), true);
  assert.equal(codes.consume(a), true);
  for (const bad of [
    '',
    'x',
    'a'.repeat(43), // correct length, never issued
    'a'.repeat(44),
    `${a.slice(0, 42)}=`,
    ' '.repeat(43),
    undefined,
    null,
    42,
    { toString: () => a },
  ]) {
    assert.equal(codes.consume(bad as unknown), false, JSON.stringify(String(bad)));
  }
});

test('login code: TTL 60 s, invalid after expiry and not kept in memory', () => {
  let now = 1_000_000;
  const codes = new LoginCodeStore({ now: () => now });
  assert.equal(codes.ttlMs, 60_000);
  const code = codes.issue();
  now += 59_999;
  assert.equal(codes.live, 1);
  now += 2;
  assert.equal(codes.consume(code), false, 'after 60 s the code is dead');
  assert.equal(codes.live, 0, 'an expired code is removed from memory');
});

test('login code: only the hash is in memory, never the raw value', () => {
  const codes = new LoginCodeStore();
  const code = codes.issue();
  // The whole store including hidden properties: the code must not be found in it in any
  // common encoding (utf8 / base64url / hex).
  const dump = `${inspect(codes, { depth: 10, showHidden: true, breakLength: Infinity })}
${JSON.stringify(codes)}`;
  for (const form of [
    code,
    Buffer.from(code, 'utf8').toString('hex'),
    Buffer.from(code, 'base64url').toString('hex'),
    Buffer.from(code, 'base64url').toString('base64url'),
  ]) {
    assert.equal(dump.includes(form), false, 'the code must not be readable from the store');
  }
  // …and the hash, conversely, is there (proof the store really holds and compares hashes).
  const entries = (codes as unknown as { entries: { hash: Buffer }[] }).entries;
  assert.equal(entries.length, 1);
  assert.equal(
    entries[0]?.hash.equals(createHash('sha256').update(code, 'utf8').digest()),
    true,
    'the SHA-256 of the code is in memory',
  );
  assert.equal(codes.consume(code), true);
});

test('login code: the live-code cap keeps memory bounded', () => {
  const codes = new LoginCodeStore({ maxLive: 3 });
  const issued = [codes.issue(), codes.issue(), codes.issue(), codes.issue()];
  assert.equal(codes.live, 3);
  assert.equal(codes.consume(issued[0] as string), false, 'the oldest was dropped');
  for (const code of issued.slice(1)) assert.equal(codes.consume(code as string), true);
});

test('rate limit: 10 failures / min, then block; success empties the window', () => {
  let now = 0;
  const limiter = new FailureLimiter({ now: () => now });
  assert.equal(limiter.limit, 10);
  for (let i = 0; i < 9; i += 1) limiter.fail();
  assert.equal(limiter.blocked, false);
  limiter.fail();
  assert.equal(limiter.blocked, true, 'the 10th failure blocks');
  now += 60_001;
  assert.equal(limiter.blocked, false, 'the window moves on');
  for (let i = 0; i < 10; i += 1) limiter.fail();
  assert.equal(limiter.blocked, true);
  limiter.reset();
  assert.equal(limiter.blocked, false);
});

test('safeNextPath: only a relative path on this origin passes', () => {
  for (const ok of [
    '/',
    '/r/acme',
    '/i/ACME-12',
    '/timeline?repo=acme&since=7d',
    '/s/61e0b33d#log',
    '/inbox',
  ]) {
    assert.equal(safeNextPath(ok), ok, ok);
  }
  for (const bad of [
    '//evil.com',
    '///evil.com',
    '/\\evil.com',
    '/%5cevil.com',
    '/%2f%2fevil.com',
    'https://evil.com',
    'http://127.0.0.1:4747/r/x',
    '//127.0.0.1:4747/',
    'javascript:alert(1)',
    'data:text/html,x',
    '/r/x\nSet-Cookie: a=b',
    '/r/x\r\nLocation: http://evil',
    '/r/x%0d%0aSet-Cookie:%20a=b',
    '/r/ x',
    '/r/x\0',
    'r/x',
    '',
    `/${'a'.repeat(300)}`,
    '/%zz',
    undefined,
    null,
    42,
    ['/r/x'],
  ]) {
    assert.equal(safeNextPath(bad as unknown), null, JSON.stringify(String(bad)));
  }
});
