import assert from 'node:assert/strict';
import test from 'node:test';
import { nextDecisionNumber, parseDecisions, serializeDecision } from './decisions.ts';

/* S4: a fake "### D99 · ..." inside a decision body must not bump nextDecisionNumber
 *  nor be split out as a separate decision on the next parse. */
test('S4: forged "### D99" inside a decision body stays part of the original D1', () => {
  const evilBody = 'legitimate reason\n### D99 · 2020-01-01 · forgery to make nextDecisionNumber skip ahead';
  const d1 = { n: 1, date: '2026-09-28', title: 'First', body: evilBody, repo: 'ops' };
  const text = `${serializeDecision(d1)}\n`;

  const reparsed = parseDecisions(text, 'ops');
  assert.equal(reparsed.length, 1, 'forgery did not split into a second decision');
  assert.equal(reparsed[0]?.n, 1);
  assert.match(reparsed[0]?.body ?? '', /`### D99/);
  assert.equal(nextDecisionNumber(reparsed), 2);

  const d2 = { n: nextDecisionNumber(reparsed), date: '2026-09-29', title: 'Second', body: 'ok', repo: 'ops' };
  const again = `${text}\n${serializeDecision(d2)}`;
  const all = parseDecisions(again, 'ops');
  assert.equal(all.length, 2);
  assert.equal(all[1]?.n, 2);
});

test('B3: CRLF DECISIONS.md parses like LF', () => {
  const lf = '### D1 · 2026-01-02 · first\nbody a\nbody b\n\n### D2 · 2026-01-03 · second\nbody c\n';
  const crlf = lf.replace(/\n/g, '\r\n');
  const out = parseDecisions(crlf, 'acme');
  assert.deepEqual(out, parseDecisions(lf, 'acme'));
  assert.equal(out.length, 2);
  assert.equal(out[0]?.title, 'first');
  assert.equal(out[0]?.body.includes('\r'), false);
  assert.equal(nextDecisionNumber(out), 3);
});
