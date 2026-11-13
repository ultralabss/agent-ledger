import assert from 'node:assert/strict';
import test from 'node:test';
import { parseMd, serializeMd, setSection } from './md.ts';
import { applyItem, itemFromDoc, parseItem, serializeItem } from './item.ts';

const SAMPLE = `---
id: ACME-13
title: Map error_description=registration_paused and app_locked
status: open
kind: DEPLOY
priority: P1
owner: agent
repo: acme
area: web
paths: []
blocks: []
blocked_by:
  - WEB-142
requested_by: null
intake: "7243950112345678901"
aliases: []
claimed_by: null
source:
  session: 61e0b33d
  agent: orchestrator
  commit: null
done: null
created: 2026-09-28T14:02:00+02:00
updated: 2026-09-28T14:02:00+02:00
---

## Why
Without the mapping the app shows the user a generic error.

## Plan
- [ ] 1. add the mapping next to \`not_on_allowlist\`
- [x] 2. test both codes

## Recommendation
Add the mapping in the OAuth callback handler of the acme repo.

## Comments
### 2026-09-28 14:10 · you · c7243950112345678999
Mind mobile too.

## Log
- 2026-09-28 14:02 · 61e0 · created from intake
`;

test('md: frontmatter and sections parse', () => {
  const doc = parseMd(SAMPLE);
  assert.equal(doc.frontmatter.id, 'ACME-13');
  assert.deepEqual(
    doc.sections.map((s) => s.heading),
    ['Why', 'Plan', 'Recommendation', 'Comments', 'Log'],
  );
});

test('md: serialize(parse(x)) is stable (round-trip)', () => {
  const once = serializeMd(parseMd(SAMPLE));
  const twice = serializeMd(parseMd(once));
  assert.equal(once, twice);
  assert.deepEqual(parseMd(once).frontmatter, parseMd(SAMPLE).frontmatter);
});

test('item: round-trip keeps plan, comments and log', () => {
  const { item } = parseItem(SAMPLE);
  assert.equal(item.fm.id, 'ACME-13');
  assert.equal(item.fm.intake, '7243950112345678901');
  assert.deepEqual(item.fm.blocked_by, ['WEB-142']);
  assert.deepEqual(item.steps, [
    { n: 1, done: false, text: 'add the mapping next to `not_on_allowlist`' },
    { n: 2, done: true, text: 'test both codes' },
  ]);
  assert.equal(item.comments.length, 1);
  assert.equal(item.comments[0]?.id, '7243950112345678999');
  assert.equal(item.comments[0]?.text, 'Mind mobile too.');
  assert.equal(item.log.length, 1);
  assert.equal(item.log[0]?.session, '61e0');

  const again = parseItem(serializeItem(item, parseMd(SAMPLE))).item;
  assert.deepEqual(again, item);
});

test('item: rewrite keeps unknown sections and their order', () => {
  const withExtra = SAMPLE.replace(
    '## Log',
    '## QA notes\nhand-written section\n\n## Log',
  );
  const { item, doc } = parseItem(withExtra);
  item.fm.title = 'new title';
  const out = serializeItem(item, doc);
  assert.match(out, /## QA notes\nhand-written section/);
  assert.deepEqual(
    parseMd(out).sections.map((s) => s.heading),
    ['Why', 'Plan', 'Recommendation', 'Comments', 'QA notes', 'Log'],
  );
  assert.equal(parseMd(out).frontmatter.title, 'new title');
});

test('item: invalid frontmatter throws, not an empty item', () => {
  assert.throws(() => parseItem(SAMPLE.replace('status: open', 'status: finished')), /frontmatter/);
  assert.throws(() => parseMd('---\nid: [\n---\n'), /YAML/);
});

test('md: setSection replaces the body, not the heading', () => {
  const doc = parseMd(SAMPLE);
  setSection(doc, 'Why', 'another why');
  assert.equal(itemFromDoc(applyItem(doc, itemFromDoc(doc))).why, 'another why');
});

/* ---------- S4: md/log injection via free text ---------- */

test('S4: an injected "## Log" in Why/Recommendation does not create a new section', () => {
  const doc = parseMd(SAMPLE);
  const item = itemFromDoc(doc);
  item.why = 'legit reason\n## Log\n- 2020-01-01 00:00 · x · forged';
  item.rec = 'normal\n### D99 · 2020-01-01 · forgery';
  const out = serializeMd(applyItem(doc, item));
  assert.deepEqual(
    parseMd(out).sections.map((s) => s.heading),
    ['Why', 'Plan', 'Recommendation', 'Comments', 'Log'],
  );
  // the original Log has exactly one line; nothing forged was added to it
  const reparsed = itemFromDoc(parseMd(out));
  assert.equal(reparsed.log.length, 1);
});

test('S4: a forged comment heading inside comment text does not split into two comments', () => {
  const doc = parseMd(SAMPLE);
  const item = itemFromDoc(doc);
  item.comments.push({
    at: '2026-09-29 10:00',
    author: 'attacker',
    id: '999',
    text: 'normal text\n### 2026-09-29 10:01 · attacker · c1000\nforged second comment',
  });
  const out = serializeItem(item, doc);
  const reparsed = parseItem(out).item;
  assert.equal(reparsed.comments.length, 2); // the original from SAMPLE + the one added
  assert.equal(reparsed.comments[1]?.author, 'attacker');
  assert.match(reparsed.comments[1]?.text ?? '', /`### 2026-09-29 10:01/);
});

test('S4: a forged log line inside log entry text does not create a fake third entry', () => {
  const doc = parseMd(SAMPLE);
  const item = itemFromDoc(doc);
  item.log.push({
    at: '2026-09-29 10:00',
    session: 'abcd',
    text: 'original text\n- 2020-01-01 00:00 · forgery · fake entry',
  });
  const out = serializeItem(item, doc);
  // the raw serialized Log section carries the escaped (harmless) line...
  assert.match(out, /`- 2020-01-01 00:00 · forgery · fake entry/);
  const reparsed = parseItem(out).item;
  // ...but a log entry is fundamentally one physical line: the embedded
  // newline can't become a second forged entry (still 2, not 3) nor silently
  // merge into fabricated content — the escaped line is simply unparseable
  // and dropped, exactly like a stray line in a hand-edited file would be.
  assert.equal(reparsed.log.length, 2);
  assert.equal(reparsed.log[1]?.text, 'original text');
  assert.equal(
    reparsed.log.some((l) => l.text.includes('forgery')),
    false,
  );
});

test('S4: round-trip with structural input is stable (idempotent escaping)', () => {
  const doc = parseMd(SAMPLE);
  const item = itemFromDoc(doc);
  item.why = 'x\n## Fake';
  const once = serializeItem(item, doc);
  const twice = serializeItem(itemFromDoc(parseMd(once)), parseMd(once));
  assert.equal(once, twice);
});
