/** B6 threat suite: a revoked (stolen / lost) device key (S15, F3b invariants 5-6, risk 2). 3-hub fleet: A = root,
 *  B = the victim hub that runs the cycles, C = the device whose key is revoked / forged. END-TO-END through the
 *  real `runCycle`: nothing from the revoked key (or from a commit that only LOOKS like it) may be applied. */

import assert from 'node:assert/strict';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { runCycle } from './cycle.ts';
import type { LedgerHub } from './testkit-remote.ts';
import { assertQuarantined, assertUntouched, bothModes, ctx, revokeText, skipSync, snapshot, withRig, type Rig } from './threatkit.ts';

const signersOf = (lh: LedgerHub): Promise<string> => readFile(nodePath.join(lh.dir, '.hub', 'allowed_signers'), 'utf8');

/** One cycle on hub `i`; the tip must be quarantined (rule `re`), nothing moved, never pushed. */
async function expectQuarantine(r: Rig, i: number, mode: 'warn' | 'enforce', tip: string, re: RegExp): Promise<void> {
  const lh = r.hubOf(i);
  await lh.state.update((s) => {
    s.halt = null; // each hostile tip is judged afresh (a same-tip halt would short-circuit the validation)
  });
  const before = await snapshot(lh);
  const { deps, flaky } = r.mk(i, { verify: mode });
  const res = await runCycle(deps);
  await assertQuarantined(lh, res, re, { tip, before, flaky });
  assertUntouched(before, await snapshot(lh), { allow: ['incoming', 'state'] });
}

test('(a) A revokes C: B applies it, C leaves B\'s allowed_signers, and a signed commit by C on top is quarantined (warn AND enforce)', { skip: skipSync }, async () => {
  await bothModes(async (mode) => {
    await withRig(3, async (r) => {
      const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
      const R = await r.kit.remote.pushSigned(A.hub, [{ path: 'devices.yml', content: revokeText(r.fleet, 2, 0) }]);
      assert.equal((await runCycle(r.mk(1, { verify: mode }).deps)).outcome, 'applied');
      assert.equal(await B.hub.main(), R);
      const signers = await signersOf(B);
      assert.ok(!signers.includes(C.hub.deviceId), 'the revoked key left the allowed signers');
      assert.ok(signers.includes(A.hub.deviceId) && signers.includes(B.hub.deviceId), 'the others stay trusted');
      // C keeps signing on top of the revocation
      const bad = await r.kit.remote.pushSigned(C.hub, [ctx('# acme\nfrom the revoked device\n')]);
      await expectQuarantine(r, 1, mode, bad, /^quarantine:revoked-signer$/);
      // C tries to undo its own revocation
      const unrevoke = await r.kit.remote.rawCommit({ parents: [R], files: [{ path: 'devices.yml', content: r.fleet.devicesText }], signer: C.hub, message: 'un-revoke myself' });
      await expectQuarantine(r, 1, mode, unrevoke, /^quarantine:/);
      assert.equal(await B.hub.main(), R, 'B never left the revocation commit');
      assert.ok(!(await signersOf(B)).includes(C.hub.deviceId));
    });
  });
});

test('(b) C forks BEFORE the revocation; a merge that carries the side branch (unsigned, or signed by a trusted device) is quarantined', { skip: skipSync }, async () => {
  await bothModes(async (mode) => {
    await withRig(3, async (r) => {
      const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
      // C's side branch exists from before the revocation (signed while C was still trusted)
      const S = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [ctx('# acme\nfrom the fork\n')], signer: C.hub, setMain: false, message: 'fork' });
      const R = await r.kit.remote.pushSigned(A.hub, [{ path: 'devices.yml', content: revokeText(r.fleet, 2, 0) }]);
      assert.equal((await runCycle(r.mk(1, { verify: mode }).deps)).outcome, 'applied');
      assert.equal(await B.hub.main(), R);
      // an UNSIGNED merge [R, S] (the typed merge of the two sides: devices from R, context from S)
      const unsigned = await r.kit.remote.rawCommit({ parents: [R, S], files: [ctx('# acme\nfrom the fork\n')], signer: null, message: 'merge (unsigned)' });
      await expectQuarantine(r, 1, mode, unsigned, /^quarantine:(revoked-current|unsigned-devices|unsigned)$/);
      // the same merge signed by the trusted root cannot launder C's commit either
      const signed = await r.kit.remote.rawCommit({ parents: [R, S], files: [ctx('# acme\nfrom the fork\n')], signer: A.hub, message: 'merge (signed by A)' });
      await expectQuarantine(r, 1, mode, signed, /^quarantine:revoked-current$/);
      assert.equal(await B.hub.main(), R, 'nothing was applied');
      assert.equal(await B.hub.store.isAncestor(S, R), false, 'the fork never entered B\'s history');
    });
  });
});

test('(c) ratchet: a device seen signing cannot be impersonated by an unsigned commit (warn quarantines it, enforce too)', { skip: skipSync }, async () => {
  await bothModes(async (mode) => {
    await withRig(3, async (r) => {
      const [B, C] = [r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub];
      await r.kit.remote.pushSigned(C.hub, [ctx('# acme\nsigned by c\n')]);
      assert.equal((await runCycle(r.mk(1, { verify: mode }).deps)).outcome, 'applied');
      assert.deepEqual((await B.state.read()).seenSigning, [C.hub.deviceId], 'C is now a device that signs');
      const forged = await r.kit.remote.rawCommit({ files: [ctx('# acme\nunsigned, claims to be c\n')], signer: null, identity: C.hub.identity, message: 'forged' });
      await expectQuarantine(r, 1, mode, forged, mode === 'warn' ? /^quarantine:unsigned-ratchet$/ : /^quarantine:unsigned$/);
      // the e-mail claim of a signing device is not enough with an invalid signature either (bad signature = unsigned)
      assert.equal(await B.hub.main(), await B.state.read().then((s) => s.accepted), 'accepted == main: nothing moved');
    });
  });
});

test('(c2) warn mode: an unsigned commit from a device that never signed is accepted with ONE note (rate limited); enforce quarantines the same tip', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B] = [r.hubOf(0), r.hubOf(1)] as [LedgerHub, LedgerHub];
    const U1 = await r.kit.remote.rawCommit({ files: [ctx('# acme\nunsigned one\n')], signer: null, identity: A.hub.identity, message: 'unsigned one' });
    await expectQuarantine(r, 1, 'enforce', U1, /^quarantine:unsigned$/);
    await B.state.update((s) => {
      s.halt = null;
    });
    const warn = r.mk(1, { verify: 'warn' });
    assert.equal((await runCycle(warn.deps)).outcome, 'applied');
    assert.equal(await B.hub.main(), U1);
    assert.equal(warn.host.localNotes.length, 1, 'one note');
    assert.equal(warn.host.localNotes[0]?.[0]?.rule, 'unsigned');
    // a second unsigned commit within 24 h: accepted, no second note, nothing pushed by us
    const U2 = await r.kit.remote.rawCommit({ files: [ctx('# acme\nunsigned two\n')], signer: null, identity: A.hub.identity, message: 'unsigned two' });
    assert.equal((await runCycle(warn.deps)).outcome, 'applied');
    assert.equal(await B.hub.main(), U2);
    assert.equal(warn.host.localNotes.length, 1, 'same (rule, device) inside 24 h: no second note');
    assert.equal(warn.flaky.pushCalls, 0);
    assert.equal((await B.state.read()).halt, null);
  });
});

test('(d) verifier outage (missing / failing ssh-keygen) is never an accept: transient, nothing applied, recovers afterwards', { skip: skipSync }, async () => {
  await bothModes(async (mode) => {
    await withRig(3, async (r) => {
      const [A, B] = [r.hubOf(0), r.hubOf(1)] as [LedgerHub, LedgerHub];
      const tip = await r.kit.remote.pushSigned(A.hub, [ctx('# acme\nhonest edit\n')]);
      // missing binary: transient with backoff, nothing quarantined
      let before = await snapshot(B);
      const gone = r.mk(1, { verify: mode, sshKeygenBin: '/nonexistent/ssh-keygen' });
      const res = await runCycle(gone.deps);
      assert.equal(res.outcome, 'transient:verifier');
      assert.equal(res.applied, undefined);
      const st = await B.state.read();
      assert.equal(st.halt, null);
      assert.equal(st.backoff.failures, 1);
      assertUntouched(before, await snapshot(B), { allow: ['incoming', 'state'] });
      assert.equal(gone.flaky.pushCalls, 0);
      // a verifier that always fails (exit 1): a signature that cannot be proven counts as absent; never accepted
      const stub = nodePath.join(r.kit.root, 'failing-ssh-keygen.sh');
      await writeFile(stub, '#!/bin/sh\nexit 1\n', { mode: 0o755 });
      await chmod(stub, 0o755);
      before = await snapshot(B);
      const failing = r.mk(1, { verify: 'enforce', sshKeygenBin: stub });
      const res2 = await runCycle(failing.deps);
      assert.notEqual(res2.applied, true, `a failing verifier must not accept (outcome ${res2.outcome})`);
      assert.equal(await B.hub.main(), before.main);
      assertUntouched(before, await snapshot(B), { allow: ['incoming', 'state'] });
      // the real verifier is back: the honest tip is applied
      await B.state.update((s) => {
        s.halt = null;
      });
      assert.equal((await runCycle(r.mk(1, { verify: mode }).deps)).outcome, 'applied');
      assert.equal(await B.hub.main(), tip);
    });
  });
});
