/** `LEDGER_INTRUDE` off: cross-repo edits stay denied, no lease is ever taken,
 *  and the hint says the protocol is disabled instead of naming `ledger intrude`. */

import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { makeCommittedRepo, startTestHub, type HubFixture } from '../test-helpers.ts';

async function startSession(fx: HubFixture, id: string, cwd: string): Promise<void> {
  await fx.hook('session-start', { session_id: id, cwd, hook_event_name: 'SessionStart', source: 'startup' });
}

async function tryEdit(fx: HubFixture, session: string, file: string): Promise<Record<string, any>> {
  return fx.hookJson('pre-tool-use', {
    session_id: session,
    hook_event_name: 'PreToolUse',
    tool_name: 'Edit',
    tool_input: { file_path: file },
  });
}

function denied(out: Record<string, any>): string {
  assert.equal(out.hookSpecificOutput?.permissionDecision, 'deny', JSON.stringify(out));
  return String(out.hookSpecificOutput?.permissionDecisionReason ?? '');
}

test('intrude off: a live session in the other repo → deny, hint says the protocol is disabled', async (t) => {
  const fx = await startTestHub({ intrude: false });
  const x = await makeCommittedRepo('xoff');
  const z = await makeCommittedRepo('zoff');
  t.after(async () => {
    await fx.cleanup();
    await x.cleanup();
    await z.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: x.path, onboarded: true });
  await fx.hub.ledger.registerRepo({ slug: 'web', prefix: 'WEB', path: z.path, onboarded: true });
  await startSession(fx, 'aaaa1111', x.path);
  await startSession(fx, 'bbbb2222', z.path);

  const reason = denied(await tryEdit(fx, 'bbbb2222', join(x.path, 'docs', 'api.md')));
  assert.match(reason, /another repo acme/);
  assert.match(reason, /aaaa/, 'names the live session');
  assert.match(reason, /protocol is disabled/);
  assert.doesNotMatch(reason, /ledger intrude/, 'never tells the agent to run a disabled command');
});

test('intrude off: nobody in the other repo → still a deny, and no auto-lease is taken', async (t) => {
  const fx = await startTestHub({ intrude: false });
  const x = await makeCommittedRepo('xoff2');
  const z = await makeCommittedRepo('zoff2');
  t.after(async () => {
    await fx.cleanup();
    await x.cleanup();
    await z.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: x.path, onboarded: true });
  await fx.hub.ledger.registerRepo({ slug: 'web', prefix: 'WEB', path: z.path, onboarded: true });
  await startSession(fx, 'bbbb2222', z.path);

  const reason = denied(await tryEdit(fx, 'bbbb2222', join(x.path, 'docs', 'api.md')));
  assert.match(reason, /protocol is disabled/);
  assert.doesNotMatch(reason, /ledger intrude/);
  const leases = await fx.api('GET', '/v1/intrude?session=bbbb2222');
  assert.equal(leases.json?.leases?.length ?? 0, 0, 'no lease can exist while the protocol is off');
});

test('intrude on (default of the test fixture): the same edit is still the auto-lease allow', async (t) => {
  const fx = await startTestHub();
  const x = await makeCommittedRepo('xon');
  const z = await makeCommittedRepo('zon');
  t.after(async () => {
    await fx.cleanup();
    await x.cleanup();
    await z.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: x.path, onboarded: true });
  await fx.hub.ledger.registerRepo({ slug: 'web', prefix: 'WEB', path: z.path, onboarded: true });
  await startSession(fx, 'bbbb2222', z.path);
  assert.deepEqual(await tryEdit(fx, 'bbbb2222', join(x.path, 'docs', 'api.md')), {});
});
