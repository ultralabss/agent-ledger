/** Hook output envelopes (SPEC §10.2/§10.3). The JSON shape is the contract
 *  with the Claude Code hook protocol — a typo here turns a deny into a silent allow. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { postToolUseOutput, preToolUseDeny, RECAP_BLOCK_REASON, stopBlock } from './output.ts';

test('preToolUseDeny: exact envelope, reason on a single line', () => {
  const parsed = JSON.parse(preToolUseDeny('file held by session 61e0')) as Record<string, any>;
  assert.deepEqual(parsed, {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: 'file held by session 61e0',
    },
  });
  // A multi-line reason is flattened: a `\n` in the reason breaks the line in the transcript.
  const multi = JSON.parse(preToolUseDeny('first\nsecond\r\nthird')) as Record<string, any>;
  assert.equal(multi.hookSpecificOutput.permissionDecisionReason.includes('\n'), false);
  assert.match(multi.hookSpecificOutput.permissionDecisionReason, /first second third/);
  assert.match(preToolUseDeny('x'), /\n$/, 'terminated by a newline');
  // A long reason is truncated, not rejected.
  const long = JSON.parse(preToolUseDeny('a'.repeat(5_000))) as Record<string, any>;
  assert.ok(long.hookSpecificOutput.permissionDecisionReason.length <= 1_200);
});

test('postToolUseOutput: two modes from one function, empty text = nothing', () => {
  const ctx = JSON.parse(postToolUseOutput('📥 message', 'additionalContext')) as Record<string, any>;
  assert.deepEqual(ctx, {
    hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: '📥 message' },
  });
  assert.deepEqual(JSON.parse(postToolUseOutput('📥 message', 'block')), {
    decision: 'block',
    reason: '📥 message',
  });
  assert.equal(postToolUseOutput('', 'additionalContext'), '');
  assert.equal(postToolUseOutput('   ', 'block'), '');
  // The default mode is the documented `additionalContext`.
  assert.match(postToolUseOutput('x'), /additionalContext/);
});

test('stopBlock: the only shape the recap check sends', () => {
  assert.deepEqual(JSON.parse(stopBlock(RECAP_BLOCK_REASON)), {
    decision: 'block',
    reason: 'Write the leftovers to the ledger (ledger add) and reference the ID in the recap.',
  });
});
