import assert from 'node:assert/strict';
import test from 'node:test';
import { INTAKE_UNPROCESSED_AFTER_MS, isIntakeUnprocessed } from './intake.ts';
import { KNOWN_TYPES } from './journal.ts';
import type { IntakeRecord } from './types.ts';

const NOW = Date.parse('2026-10-05T12:00:00+02:00');

function rec(over: Partial<IntakeRecord> = {}): IntakeRecord {
  return {
    id: '7241889432101351425',
    at: new Date(NOW - 60 * 60_000).toISOString(),
    channel: 'chat',
    session: '61e0b33d',
    repo_hint: 'agent-ledger',
    status: 'new',
    items: [],
    text: 'verbatim dump',
    triage: [],
    dropped: [],
    ...over,
  };
}

test('unprocessed = new, no items, no triage, older than 10 min', () => {
  assert.equal(isIntakeUnprocessed(rec(), NOW), true);
  assert.equal(isIntakeUnprocessed(rec({ status: 'triaged' }), NOW), false);
  assert.equal(isIntakeUnprocessed(rec({ status: 'partial' }), NOW), false);
  assert.equal(isIntakeUnprocessed(rec({ items: ['ACME-1'] }), NOW), false);
  // Old records: status stayed `new` although items were cut from them.
  assert.equal(
    isIntakeUnprocessed(rec({ triage: [{ item: 'ACME-1', excerpt: 'chunk' }] }), NOW),
    false,
  );
  assert.equal(
    isIntakeUnprocessed(rec({ dropped: [{ text: 'nothing', reason: 'duplicate' }] }), NOW),
    false,
  );
});

test('10-minute window — a triage in progress in the same session does not nag', () => {
  const justNow = rec({ at: new Date(NOW).toISOString() });
  assert.equal(isIntakeUnprocessed(justNow, NOW), false);
  assert.equal(isIntakeUnprocessed(justNow, NOW + INTAKE_UNPROCESSED_AFTER_MS - 1), false);
  assert.equal(isIntakeUnprocessed(justNow, NOW + INTAKE_UNPROCESSED_AFTER_MS), true);
  // Broken `at` from a hand-edited md → still counted, never silently hidden.
  assert.equal(isIntakeUnprocessed(rec({ at: 'sometime' }), NOW), true);
});

test('contract: intake.linked is a known journal type', () => {
  assert.ok(KNOWN_TYPES.includes('intake.linked'));
  assert.ok(KNOWN_TYPES.includes('intake.triaged'));
});
