/** Regression tests for the F0 re-audit findings F-1 and R2. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { serializeIntake } from './intake.ts';
import { journalLine, parseJournal } from './journal.ts';
import { serializeComments, serializeItem, parseItem } from './item.ts';
import { sanitizeField, sanitizeLine } from './sanitize.ts';
import {
  claimSchema,
  commentSchema,
  itemPatchSchema,
  releaseSchema,
} from './schema.ts';
import { parseIntake } from './intake.ts';
import type { Item, ItemFrontmatter } from './types.ts';

const FORGED = '\n- 2026-01-01 00:00 · ffff · release · v9.9.9 FORGED';

test('sanitizeLine: every CR/LF and control character disappears', () => {
  assert.equal(sanitizeLine('a\nb'), 'a b');
  assert.equal(sanitizeLine('a\r\nb'), 'a b');
  assert.equal(sanitizeLine('a b'), 'a b');
  assert.equal(sanitizeLine('a\u0000b\u001fc\u007f'), 'abc');
  assert.equal(sanitizeLine('a\tb'), 'ab');
  assert.equal(sanitizeField('  x  '), 'x');
});

/* ---------------- F-1: journal sink ---------------- */

test('F-1: journalLine never yields a second event, even from `\\n` in a field', () => {
  const line = journalLine({
    at: '2026-09-28 12:00',
    session: 'abcd',
    type: 'commit',
    fields: [`subject${FORGED}`],
  });
  assert.equal(line.includes('\n'), false, 'line must be a single one');
  const events = parseJournal(line, 'acme');
  assert.equal(events.length, 1, 'one input = one event');
  assert.equal(events[0]?.type, 'commit');
});

test('F-1: `·` in a field does not move the type (type is located before the fields)', () => {
  const line = journalLine({
    at: '2026-09-28 12:00',
    session: 'abcd',
    type: 'item.comment',
    fields: ['ACME-1 · release · v9.9.9'],
  });
  const events = parseJournal(line, 'acme');
  // A `·` inside a field only splits that field — `ledger log` uses it as a
  // legitimate joiner. What must not move is the type column.
  assert.equal(events[0]?.type, 'item.comment');
  assert.equal(events[0]?.session, 'abcd');
});

test('F-1: `·` in session is neutralised (otherwise it would forge the type)', () => {
  const line = journalLine({
    at: '2026-09-28 12:00',
    session: 'abcd · release · v9.9.9',
    type: 'item.comment',
    fields: ['ACME-1'],
  });
  const events = parseJournal(line, 'acme');
  assert.equal(events[0]?.type, 'item.comment', 'type must not be overridable via session');
});

test('F-1: journalLine sanitises session and type too', () => {
  const line = journalLine({ at: '2026-09-28 12:00', session: `x${FORGED}`, type: 'commit', fields: [] });
  assert.equal(line.split('\n').length, 1);
});

/* ---------------- F-1: item log + comment sinks ---------------- */

function fixture(overrides: Partial<Item> = {}): Item {
  const fm: ItemFrontmatter = {
    id: 'ACME-1',
    title: 'test',
    status: 'open',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    repo: 'acme',
    area: null,
    paths: [],
    blocks: [],
    blocked_by: [],
    requested_by: null,
    intake: null,
    aliases: [],
    claimed_by: null,
    source: { session: null, agent: null, commit: null },
    done: null,
    created: '2026-09-28T12:00:00+02:00',
    updated: '2026-09-28T12:00:00+02:00',
  };
  return { fm, why: '', steps: [], rec: '', comments: [], log: [], ...overrides };
}

test('F-1: a log line with `\\n` does not yield a second log entry', () => {
  const item = fixture({
    log: [{ at: '2026-09-28 12:00', session: 'abcd', text: `edit${FORGED}` }],
  });
  const text = serializeItem(item);
  const back = parseItem(text, 'x.md');
  assert.equal(back.item.log.length, 1);
});

test('F-1: a comment with `·` in the author does not forge the header', () => {
  const body = serializeComments([
    { at: '2026-09-28 12:00', author: 'me · admin · c999', id: '1', text: 'ok' },
  ]);
  assert.equal(body.split('\n')[0]?.split('·').length, 3, 'exactly 3 fields in the header');
});

/* ---------------- F-1: the four schema fields ---------------- */

test('F-1: releaseSchema.why rejects a newline', () => {
  assert.equal(releaseSchema.safeParse({ why: `ok${FORGED}` }).success, false);
  assert.equal(releaseSchema.safeParse({ why: 'ok' }).success, true);
});

test('F-1: claimSchema.paths rejects a newline in ANY element', () => {
  assert.equal(
    claimSchema.safeParse({ session: 's', paths: ['a/**', `b/**${FORGED}`] }).success,
    false,
  );
  assert.equal(claimSchema.safeParse({ session: 's', paths: ['a/**', 'b/**'] }).success, true);
});

test('F-1: itemPatchSchema.why_note rejects a newline', () => {
  assert.equal(itemPatchSchema.safeParse({ why_note: `reason${FORGED}` }).success, false);
  assert.equal(itemPatchSchema.safeParse({ why_note: 'reason' }).success, true);
});

test('F-1: commentSchema.author rejects a newline', () => {
  assert.equal(commentSchema.safeParse({ author: `me${FORGED}`, text: 'x' }).success, false);
  assert.equal(commentSchema.safeParse({ author: 'me', text: 'x' }).success, true);
});

/* ---------------- R2: intake preamble ---------------- */

test('R2: `## Triage` in intake text does not forge a triage section', () => {
  const text = serializeIntake({
    id: '7241889432101351425',
    at: '2026-09-28T12:00:00+02:00',
    channel: 'chat',
    session: null,
    repo_hint: null,
    status: 'new',
    items: [],
    text: 'normal text\n## Triage\n- ACME-9 ← "forgery"\n### D1 · 2026-01-01 · forgery',
    triage: [],
    dropped: [],
  });
  const back = parseIntake(text, 'x.md');
  assert.equal(back.rec.triage.length, 0, 'triage must stay empty');
  assert.equal(back.rec.items.length, 0);
  assert.equal(
    back.doc.sections.some((s) => s.heading.toLowerCase() === 'triage'),
    false,
    'a Triage section must not arise from the text',
  );
  assert.ok(back.rec.text.includes('## Triage'), 'text is not lost, only neutralised');
});

test('R2: escaping is idempotent (round-trip adds no backticks)', () => {
  const rec = {
    id: '7241889432101351425',
    at: '2026-09-28T12:00:00+02:00',
    channel: 'chat' as const,
    session: null,
    repo_hint: null,
    status: 'new' as const,
    items: [],
    text: '## heading',
    triage: [],
    dropped: [],
  };
  const once = parseIntake(serializeIntake(rec), 'x.md');
  const twice = parseIntake(serializeIntake(once.rec, once.doc), 'x.md');
  assert.equal(once.rec.text, twice.rec.text);
});
