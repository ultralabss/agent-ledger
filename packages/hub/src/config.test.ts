import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from './config.ts';

const base = { LEDGER_DIR: '/tmp/agent-ledger-config-test', LEDGER_HUB_PORT: '0' };

/* A non-finite or out-of-range debounce/push interval must fall back to
 *  the default instead of producing NaN or an absurd wait. */
test('commitDebounceMs and pushIntervalMs: NaN/out of range falls back to default', () => {
  for (const bad of ['abc', 'NaN', 'Infinity', '-1', String(11 * 60_000)]) {
    assert.equal(
      loadConfig({ ...base, LEDGER_COMMIT_DEBOUNCE_MS: bad }).commitDebounceMs,
      30_000,
      bad,
    );
  }
  for (const bad of ['abc', 'Infinity', '0', '-1', String(25 * 60 * 60_000)]) {
    assert.equal(
      loadConfig({ ...base, LEDGER_PUSH_INTERVAL_MS: bad }).pushIntervalMs,
      600_000,
      bad,
    );
  }
  // valid boundary values pass through unchanged
  assert.equal(loadConfig({ ...base, LEDGER_COMMIT_DEBOUNCE_MS: '0' }).commitDebounceMs, 0);
  assert.equal(
    loadConfig({ ...base, LEDGER_COMMIT_DEBOUNCE_MS: String(10 * 60_000) }).commitDebounceMs,
    10 * 60_000,
  );
  assert.equal(
    loadConfig({ ...base, LEDGER_PUSH_INTERVAL_MS: String(60_000) }).pushIntervalMs,
    60_000,
  );
});

test('optional features and push are all OFF by default', () => {
  const c = loadConfig(base);
  assert.equal(c.push, false);
  assert.equal(c.intrude, false);
  assert.equal(c.recapGuard, false);
  assert.equal(c.webReplies, false);
  assert.equal(c.headless, false);
  assert.equal(c.agentsDir, null);
  assert.deepEqual(c.recapTags, ['BLOCKER', 'DEPLOY', 'RISK', 'UNVERIFIED']);
});

test('feature flags turn on only with exactly 1', () => {
  const on = loadConfig({
    ...base,
    LEDGER_PUSH: '1',
    LEDGER_INTRUDE: '1',
    LEDGER_RECAP_GUARD: '1',
    LEDGER_WEB_REPLIES: '1',
    LEDGER_HEADLESS: '1',
  });
  assert.equal(on.push, true);
  assert.equal(on.intrude, true);
  assert.equal(on.recapGuard, true);
  assert.equal(on.webReplies, true);
  assert.equal(on.headless, true);
  for (const junk of ['0', 'true', 'yes', '', '2']) {
    const c = loadConfig({
      ...base,
      LEDGER_PUSH: junk,
      LEDGER_INTRUDE: junk,
      LEDGER_RECAP_GUARD: junk,
      LEDGER_WEB_REPLIES: junk,
      LEDGER_HEADLESS: junk,
    });
    assert.equal(c.push, false, junk);
    assert.equal(c.intrude, false, junk);
    assert.equal(c.recapGuard, false, junk);
    assert.equal(c.webReplies, false, junk);
    assert.equal(c.headless, false, junk);
  }
});

test('LEDGER_RECAP_TAGS: parses a list, drops junk, falls back to defaults', () => {
  assert.deepEqual(loadConfig({ ...base, LEDGER_RECAP_TAGS: 'BLOCKER, ASK ,my-tag' }).recapTags, [
    'BLOCKER',
    'ASK',
    'my-tag',
  ]);
  // junk entries are dropped, valid ones kept
  assert.deepEqual(
    loadConfig({ ...base, LEDGER_RECAP_TAGS: '1bad,,;rm -rf,OK,' + 'x'.repeat(40) }).recapTags,
    ['OK'],
  );
  // nothing valid left, so defaults apply
  const defaults = ['BLOCKER', 'DEPLOY', 'RISK', 'UNVERIFIED'];
  assert.deepEqual(loadConfig({ ...base, LEDGER_RECAP_TAGS: '1,;;,' }).recapTags, defaults);
  assert.deepEqual(loadConfig({ ...base, LEDGER_RECAP_TAGS: '' }).recapTags, defaults);
});

test('LEDGER_AGENTS_DIR is expanded, empty means null', () => {
  assert.equal(loadConfig({ ...base, LEDGER_AGENTS_DIR: '/opt/agents' }).agentsDir, '/opt/agents');
  assert.equal(loadConfig({ ...base, LEDGER_AGENTS_DIR: '  ' }).agentsDir, null);
});
