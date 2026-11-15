import assert from 'node:assert/strict';
import test from 'node:test';
import { journalLine, parseJournal, parseJournalLine } from './journal.ts';
import { parseDecisions, nextDecisionNumber, serializeDecision } from './decisions.ts';
import { parseSince, shortSession, stamp } from './time.ts';

test('journal: line format per §4.5', () => {
  const line = journalLine({
    at: '2026-09-28 13:12',
    session: '61e0',
    type: 'session.summary',
    fields: ['OAuth tab, Keys tab, 6 migrations'],
  });
  assert.equal(line, '- 2026-09-28 13:12 · 61e0 · session.summary · OAuth tab, Keys tab, 6 migrations');
});

test('journal: missing session is —', () => {
  const line = journalLine({ session: shortSession(null), type: 'release', fields: ['v0.26.0'] });
  assert.match(line, /^- \d{4}-\d{2}-\d{2} \d{2}:\d{2} · — · release · v0\.26\.0$/);
  assert.equal(stamp(new Date(2026, 8, 28, 14, 2)), '2026-09-28 14:02');
});

test('journal: parser tolerates · in the session field', () => {
  const ev = parseJournalLine(
    '- 2026-09-28 14:02 · a9f2 (acme · ACME-13) · intrude.commit · c3d4e5f · oauth/errors.ts',
    'acme',
  );
  assert.ok(ev);
  assert.equal(ev.type, 'intrude.commit');
  assert.equal(ev.session, 'a9f2 (acme · ACME-13)');
  assert.deepEqual(ev.fields, ['c3d4e5f', 'oauth/errors.ts']);
});

test('journal: garbage lines are skipped, no throw', () => {
  const events = parseJournal(
    '# acme — journal 2026-09\n\nblah blah\n- 2026-09-28 13:40 · — · release · v0.26.0\n',
    'acme',
  );
  assert.equal(events.length, 1);
  assert.equal(events[0]?.type, 'release');
});

test('decisions: sequential numbering and round-trip', () => {
  const text = `# acme — decisions

### D11 · 2026-09-20 · First
body one

### D12 · 2026-09-23 · Prices are integer cents
No float rounding in totals.
Related: ACME-88 · apps/web/docs/copy.md
`;
  const decisions = parseDecisions(text, 'acme');
  assert.equal(decisions.length, 2);
  assert.equal(nextDecisionNumber(decisions), 13);
  assert.match(decisions[1]?.body ?? '', /Related: ACME-88/);
  assert.match(serializeDecision(decisions[1]!), /^### D12 · 2026-09-23 · Prices are integer cents/);
});

test('time: parseSince understands 7d/36h/90m', () => {
  assert.equal(parseSince('7d'), 7 * 86_400_000);
  assert.equal(parseSince('36h'), 36 * 3_600_000);
  assert.equal(parseSince('90m'), 90 * 60_000);
  assert.throws(() => parseSince('tomorrow'), /cannot parse/);
});

test('B3: CRLF journal text parses every event (no `\\r` drops the line)', () => {
  const text =
    '# acme — journal 2026-09\r\n' +
    '- 2026-09-28 13:12 · 61e0 · session.summary · did a thing\r\n' +
    '- 2026-09-28 13:15 · a9f2 (acme · ACME-13) · item.status · ACME-13 · open → done\r\n';
  const evs = parseJournal(text, 'acme');
  assert.equal(evs.length, 2);
  assert.equal(evs[0]?.type, 'session.summary');
  assert.deepEqual(evs[0]?.fields, ['did a thing']);
  assert.equal(evs[1]?.session, 'a9f2 (acme · ACME-13)');
  assert.deepEqual(evs[1]?.fields, ['ACME-13', 'open → done']);
  // single CRLF line too, and CRLF parse equals LF parse
  assert.equal(parseJournalLine('- 2026-09-28 13:12 · 61e0 · commit · x\r', 'acme')?.fields[0], 'x');
  assert.deepEqual(parseJournal(text, 'acme'), parseJournal(text.replace(/\r\n/g, '\n'), 'acme'));
});

test('B3: writers emit LF only', () => {
  assert.equal(journalLine({ session: '61e0', type: 'commit', fields: ['a'] }).includes('\r'), false);
});
