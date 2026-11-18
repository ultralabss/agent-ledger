/** Smoke test for the B6 threat helpers (threatkit.ts). */

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { runCycle } from './cycle.ts';
import { assertNoLeak, assertQuarantined, assertUntouched, bothModes, collectTexts, ctx, haltOf, revokeText, skipSync, snapshot, withRig } from './threatkit.ts';

test('skipSync is a string only on win32 without the lift', () => {
  const expected = process.platform === 'win32' && process.env.LEDGER_TEST_SYNC_WIN32 !== '1';
  assert.equal(skipSync !== false, expected);
});

test('snapshot / assertUntouched: identical -> ok, a worktree byte -> throws; allow works', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const a = await snapshot(r.lh);
    assert.equal(a.main, r.fleet.base);
    assert.equal(a.accepted, r.fleet.base);
    const b = await snapshot(r.lh);
    assertUntouched(a, b);
    await writeFile(nodePath.join(r.lh.dir, 'acme', 'CONTEXT.md'), '# acme\nchanged\n');
    const c = await snapshot(r.lh);
    assert.throws(() => assertUntouched(a, c), /worktree file changed: acme\/CONTEXT\.md/);
    // state is volatile only through lastCycle, which snapshot strips; a real state change needs `allow`
    await r.lh.state.update((s) => {
      s.backoff.failures = 1;
    });
    const d = await snapshot(r.lh);
    assert.throws(() => assertUntouched(c, d), /state\.json changed/);
    assertUntouched(c, d, { allow: ['state'] });
  });
});

test('hostile symlink tip: assertQuarantined + assertUntouched (allow incoming/state) + collectTexts + assertNoLeak', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const before = await snapshot(r.lh);
    const bad = await r.kit.remote.pushSymlink(r.other.hub, 'acme/link', '/etc/passwd');
    const { deps, flaky, host } = r.mk();
    const res = await runCycle(deps);
    await assertQuarantined(r.lh, res, /^quarantine:tree:symlink$/, { tip: bad, before, flaky });
    assert.equal((await haltOf(r.lh))?.tip, bad);
    assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
    const texts = await collectTexts(r.lh, host);
    assert.ok(texts.length > 0);
    assertNoLeak(texts, ['leak-marker.invalid']);
    assert.throws(() => assertNoLeak(['x leak-marker.invalid y'], ['leak-marker.invalid']), /leaked/);
  });
});

test('revokeText + bothModes run both verify modes in order', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    assert.match(revokeText(r.fleet, 1, 0), /revoked:/);
    const seen: string[] = [];
    await bothModes(async (m) => {
      seen.push(m);
    });
    assert.deepEqual(seen, ['warn', 'enforce']);
    await assert.rejects(
      bothModes(async (m) => {
        assert.equal(m, 'warn');
      }),
      /\[verify=enforce\]/,
    );
  });
});

test('withRig/mk wires a flaky remote (argv recorded, no force flag)', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nedit\n')]);
    const { deps, flaky } = r.mk();
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'applied');
    assert.ok(flaky.argv.length > 0 && flaky.fetchCalls === 1);
    assert.ok(!flaky.argv.flat().some((a) => a === '--force' || a === '-f' || (a.startsWith('+') && !/^\+refs\/heads\/[^:]+:refs\/ledger-sync\//.test(a))));
  });
});
