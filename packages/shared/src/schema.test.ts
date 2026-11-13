import assert from 'node:assert/strict';
import test from 'node:test';
import {
  claimSchema,
  decisionCreateSchema,
  doneActionSchema,
  dropSchema,
  itemCreateSchema,
  reopenSchema,
} from './schema.ts';

/* S4: single-line fields (title, owner, session, agent, drop/reopen why, ref,
 *  intent, plan steps, decision title) reject \n/\r/control characters (422). */
test('S4: single-line fields reject an embedded newline', () => {
  assert.equal(
    itemCreateSchema.safeParse({ repo: 'ops', title: 'ok\n## Fake' }).success,
    false,
    'title',
  );
  assert.equal(
    itemCreateSchema.safeParse({ repo: 'ops', title: 'ok', owner: "human\n### fake" }).success,
    false,
    'owner',
  );
  assert.equal(
    itemCreateSchema.safeParse({ repo: 'ops', title: 'ok', session: 'a\nb' }).success,
    false,
    'session',
  );
  assert.equal(
    itemCreateSchema.safeParse({ repo: 'ops', title: 'ok', agent: 'a\nb' }).success,
    false,
    'agent',
  );
  assert.equal(
    itemCreateSchema.safeParse({ repo: 'ops', title: 'ok', steps: ['step\n## fake'] }).success,
    false,
    'steps',
  );
  assert.equal(dropSchema.safeParse({ why: 'reason\n## fake' }).success, false, 'drop.why');
  assert.equal(reopenSchema.safeParse({ why: 'reason\n## fake' }).success, false, 'reopen.why');
  assert.equal(doneActionSchema.safeParse({ ref: 'v1\n## fake' }).success, false, 'ref');
  assert.equal(claimSchema.safeParse({ intent: 'refactor\n## fake' }).success, false, 'intent');
  assert.equal(
    decisionCreateSchema.safeParse({ repo: 'ops', title: 'title\n## fake', why: 'ok' }).success,
    false,
    'decision title',
  );

  // a normal single-line value still passes
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: 'ok', owner: 'human' }).success, true);
});
