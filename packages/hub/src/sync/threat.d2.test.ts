/** B6 threat suite: D2 (a revocation of the root or of this device needs a human) and the time evidence around it
 *  (S20-21, F3b invariants 7-8, T-B3-9, T-B4-2). END-TO-END: a stolen non-root key revokes the root -> the hub halts
 *  WITHOUT any network contact until a human confirms the exact (commit, device, fingerprint); backdated or future
 *  evidence, foreign `last_seen`, and a skewed local clock change nothing about what is accepted. 3-hub fleet:
 *  A = root, B = the "stolen" key, C = the victim hub that runs the cycles. */

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { parseDevicesYaml, renderDevicesYaml, type DeviceEntry } from '@agent-ledger/shared';
import { runCycle } from './cycle.ts';
import { SyncLoop } from './loop.ts';
import type { LedgerHub, TestHub } from './testkit-remote.ts';
import { assertQuarantined, assertUntouched, bothModes, ctx, devicesWith, nowIso, revokeText, skipSync, snapshot, withRig, type Rig } from './threatkit.ts';

let seq = 0;
const uniq = (what: string): string => `${what} #${String((seq += 1))}`;
const iso = (ms: number): string => new Date(ms).toISOString().replace(/\.\d+Z$/, '.000Z');
const signersOf = (lh: LedgerHub): Promise<string> => readFile(nodePath.join(lh.dir, '.hub', 'allowed_signers'), 'utf8');
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** `text` with `victim` revoked by `by` (on top of whatever `text` already holds). */
function revokeOn(text: string, victim: string, by: string, at = nowIso()): string {
  return renderDevicesYaml({ devices: parseDevicesYaml(text).devices.map((d) => (d.id === victim ? { ...d, revoked: { at, by, reason: 'lost' } } : d)) });
}

async function expectQuarantine(r: Rig, i: number, mode: 'warn' | 'enforce', tip: string, re: RegExp, name: string): Promise<void> {
  const lh = r.hubOf(i);
  await lh.state.update((s) => {
    s.halt = null;
  });
  const before = await snapshot(lh);
  const { deps, flaky } = r.mk(i, { verify: mode });
  const res = await runCycle(deps);
  try {
    await assertQuarantined(lh, res, re, { tip, before, flaky });
    assertUntouched(before, await snapshot(lh), { allow: ['incoming', 'state'] });
  } catch (err) {
    if (err instanceof Error) err.message = `[${name}] ${err.message}`;
    throw err;
  }
}

const isNetwork = (argv: readonly string[]): boolean => argv[0] === 'fetch' || argv[0] === 'push' || argv[0] === 'ls-remote';

test('(a) a stolen key revokes the root: HALT, then 5 cycles make ZERO network calls and move nothing (warn and enforce)', { skip: skipSync }, async () => {
  await bothModes(async (mode) => {
    await withRig(3, async (r) => {
      const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
      const F = await r.kit.remote.pushSigned(B.hub, [{ path: 'devices.yml', content: revokeText(r.fleet, 0, 1) }]);
      const before = await snapshot(C);
      const first = r.mk(2, { verify: mode });
      const res = await runCycle(first.deps);
      const halt = await assertQuarantined(C, res, /^quarantine:revocation-root$/, { tip: F, before, flaky: first.flaky });
      assert.equal(halt.cls, 'd2');
      assert.deepEqual(halt.d2, { commit: F, deviceIds: [A.hub.deviceId], kind: 'root' });
      const settled = await snapshot(C);
      assertUntouched(before, settled, { allow: ['incoming', 'state'] });
      for (let i = 0; i < 5; i += 1) {
        const q = r.mk(2, { verify: mode });
        const again = await runCycle(q.deps);
        assert.equal(again.outcome, 'halted', `cycle ${String(i + 1)}`);
        assert.equal(q.flaky.fetchCalls, 0, 'D2 halt: no remote contact');
        assert.equal(q.flaky.pushCalls, 0);
        assert.deepEqual(q.flaky.argv.filter(isNetwork), [], 'no network git command at all');
      }
      assertUntouched(settled, await snapshot(C)); // strict: registry, signers, refs, worktree, state.json
      assert.ok((await signersOf(C)).includes(A.hub.deviceId), 'the root key is still trusted until a human decides');
      assert.equal(await C.hub.main(), r.fleet.base);
    });
  });
});

test('(b) confirmations bind to (commit, device, fingerprint): wrong ones change nothing; the right one is idempotent and never carries over to a NEW revoking commit', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const rootRevoked = revokeText(r.fleet, 0, 1); // one text: the second commit must carry the SAME revocation record
    const F = await r.kit.remote.pushSigned(B.hub, [{ path: 'devices.yml', content: rootRevoked }]);
    assert.equal((await runCycle(r.mk(2).deps)).halted, 'quarantine:revocation-root');
    const loop = new SyncLoop({ deps: r.mk(2).deps, intervalMs: 3_600_000, cycle: async () => ({ outcome: 'noop', refetches: 0, ms: 0 }) });
    const stillHalted = async (what: string): Promise<void> => {
      const q = r.mk(2);
      assert.equal((await runCycle(q.deps)).outcome, 'halted', what);
      assert.equal(q.flaky.fetchCalls, 0, what);
      assert.equal(await C.hub.main(), r.fleet.base, `${what}: nothing applied`);
    };
    try {
      // through the human route: wrong fingerprint, a device the halt does not name
      assert.deepEqual(await loop.confirmRevocation(A.hub.deviceId, `SHA256:${'A'.repeat(43)}`), { ok: false, reason: 'fingerprint-mismatch' });
      assert.deepEqual(await loop.confirmRevocation(A.hub.deviceId, B.hub.pub.fingerprint), { ok: false, reason: 'fingerprint-mismatch' });
      assert.deepEqual(await loop.confirmRevocation(B.hub.deviceId, B.hub.pub.fingerprint), { ok: false, reason: 'unknown-device' });
      assert.equal((await C.state.read()).confirmations.length, 0);
      await stillHalted('refused confirmations');
      // confirmations written straight into state.json that do not match (commit, device, kind) exactly
      const stamp = new Date().toISOString();
      await C.state.update((s) => {
        s.confirmations.push({ kind: 'root', device_id: A.hub.deviceId, commit: 'a'.repeat(40), fp: A.hub.pub.fingerprint, at: stamp }); // other commit
        s.confirmations.push({ kind: 'root', device_id: B.hub.deviceId, commit: F, fp: B.hub.pub.fingerprint, at: stamp }); // other device
        s.confirmations.push({ kind: 'self', device_id: A.hub.deviceId, commit: F, fp: A.hub.pub.fingerprint, at: stamp }); // other kind
      });
      await stillHalted('mismatched confirmations');
      // the right one, twice: idempotent
      assert.deepEqual(await loop.confirmRevocation(A.hub.deviceId, A.hub.pub.fingerprint), { ok: true });
      assert.deepEqual(await loop.confirmRevocation(A.hub.deviceId, A.hub.pub.fingerprint), { ok: true });
      const mine = (await C.state.read()).confirmations.filter((c) => c.kind === 'root' && c.commit === F && c.device_id === A.hub.deviceId);
      assert.equal(mine.length, 1, 'one confirmation per (commit, device)');
      const go = r.mk(2);
      const done = await runCycle(go.deps);
      assert.equal(done.outcome, 'd2-confirmed');
      assert.equal(go.flaky.fetchCalls, 0, 'the re-gate used the stored tip, no network');
      assert.equal(await C.hub.main(), F);
      assert.ok(!(await signersOf(C)).includes(A.hub.deviceId), 'the confirmed revocation pruned the key');
      assert.equal((await C.state.read()).halt, null);
      // a NEW revoking commit (this device, signed by B): the old root confirmation must not carry over
      const F2 = await r.kit.remote.rawCommit({ parents: [F], files: [{ path: 'devices.yml', content: revokeOn(rootRevoked, C.hub.deviceId, B.hub.deviceId) }], signer: B.hub, message: uniq('revoke C') });
      const second = r.mk(2);
      const res = await runCycle(second.deps);
      assert.equal(res.halted, 'quarantine:revocation-self');
      assert.equal(await C.hub.main(), F, 'F2 was not applied');
      const st = await C.state.read();
      assert.equal(st.halt?.tip, F2);
      assert.equal(st.halt?.cls, 'd2');
      const q = r.mk(2);
      assert.equal((await runCycle(q.deps)).outcome, 'halted');
      assert.equal(q.flaky.fetchCalls, 0);
    } finally {
      await loop.stop();
    }
  });
});

test('(c) backdated / future evidence is quarantined: `revoked.at` and `added` must be within 15 min of the commit time (+-1 day, +-16 min refused; -10 min accepted)', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const X = await r.kit.makeHub(9);
    const now = Date.now();
    const revokeC = (at: string): string => revokeOn(r.fleet.devicesText, C.hub.deviceId, B.hub.deviceId, at);
    const addX = (added: string): string => devicesWith(r.fleet, (ds) => [...ds, { id: X.deviceId, label: 'x-device', slot: 'D', pubkey: X.pub.line, added, added_by: B.hub.deviceId, revoked: null, role: 'owner' as const } satisfies DeviceEntry]);
    const cases: { name: string; content: string; date?: Date }[] = [
      { name: 'revoked.at 1 day in the past', content: revokeC(iso(now - DAY)) },
      { name: 'revoked.at 1 day in the future', content: revokeC(iso(now + DAY)) },
      { name: 'revoked.at 16 min in the past', content: revokeC(iso(now - 16 * 60_000)) },
      { name: 'revoked.at right, commit backdated 1 day', content: revokeC(iso(now)), date: new Date(now - DAY) },
      { name: 'added 1 day in the past', content: addX(iso(now - DAY)) },
      { name: 'added 1 day in the future', content: addX(iso(now + DAY)) },
      { name: 'added 16 min in the future', content: addX(iso(now + 16 * 60_000)) },
    ];
    await bothModes(async (mode) => {
      for (const c of mode === 'warn' ? cases.slice(0, 2) : cases) {
        const tip = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'devices.yml', content: c.content }], signer: B.hub, ...(c.date !== undefined ? { date: c.date } : {}), message: uniq(`${mode} ${c.name}`) });
        await expectQuarantine(r, 0, mode, tip, /^quarantine:devices:time-unbound$/, `${mode}: ${c.name}`);
      }
    });
    // control: 10 minutes off is inside the window and is applied
    const ok = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'devices.yml', content: revokeC(iso(now - 10 * 60_000)) }], signer: B.hub, message: uniq('within the window') });
    await A.state.update((s) => {
      s.halt = null;
    });
    assert.equal((await runCycle(r.mk(0).deps)).outcome, 'applied');
    assert.equal(await A.hub.main(), ok);
  });
});

test('(d) last_seen may only be written on the signer\'s OWN entry (and never on a new entry)', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const X = await r.kit.makeHub(9);
    const seen = nowIso();
    const cases: { name: string; content: string }[] = [
      { name: 'B sets last_seen on A', content: devicesWith(r.fleet, (ds) => ds.map((d) => (d.id === A.hub.deviceId ? { ...d, last_seen: seen } : d))) },
      { name: 'B sets last_seen on C', content: devicesWith(r.fleet, (ds) => ds.map((d) => (d.id === C.hub.deviceId ? { ...d, last_seen: seen } : d))) },
      { name: 'B adds a device that already carries last_seen', content: devicesWith(r.fleet, (ds) => [...ds, { id: X.deviceId, label: 'x-device', slot: 'D', pubkey: X.pub.line, added: seen, added_by: B.hub.deviceId, revoked: null, role: 'owner' as const, last_seen: seen }]) },
    ];
    await bothModes(async (mode) => {
      for (const c of cases) {
        const tip = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'devices.yml', content: c.content }], signer: B.hub, message: uniq(`${mode} ${c.name}`) });
        await expectQuarantine(r, 2, mode, tip, /^quarantine:devices:last-seen-foreign$/, `${mode}: ${c.name}`);
      }
    });
    // control: B's own heartbeat
    const own = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'devices.yml', content: devicesWith(r.fleet, (ds) => ds.map((d) => (d.id === B.hub.deviceId ? { ...d, last_seen: seen } : d))) }], signer: B.hub, message: uniq('own last_seen') });
    await C.state.update((s) => {
      s.halt = null;
    });
    assert.equal((await runCycle(r.mk(2).deps)).outcome, 'applied');
    assert.equal(await C.hub.main(), own);
  });
});

test('(e) the local clock (10 years ahead or behind) does not change what an honest range is: accepted, nothing quarantined', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const TEN_YEARS = 10 * 365 * DAY;
    // 10 years ahead: a plain commit, then a registry change whose evidence matches the COMMIT time
    const t1 = await r.kit.remote.pushSigned(A.hub, [ctx('# acme\nhonest\n')]);
    const ahead = r.mk(2, { now: () => new Date(Date.now() + TEN_YEARS) });
    assert.equal((await runCycle(ahead.deps)).outcome, 'applied');
    assert.equal(await C.hub.main(), t1);
    assert.equal((await C.state.read()).halt, null);
    // 10 years behind: an honest registry change (B revokes... nobody sensitive: it adds a device) still passes
    const X = await r.kit.makeHub(9);
    const t2 = await r.kit.remote.pushSigned(B.hub, [{ path: 'devices.yml', content: devicesWith(r.fleet, (ds) => [...ds, { id: X.deviceId, label: 'x-device', slot: 'D', pubkey: X.pub.line, added: nowIso(), added_by: B.hub.deviceId, revoked: null, role: 'owner' as const }]) }]);
    const behind = r.mk(2, { now: () => new Date(Date.now() - TEN_YEARS) });
    assert.equal((await runCycle(behind.deps)).outcome, 'applied');
    assert.equal(await C.hub.main(), t2);
    const st = await C.state.read();
    assert.equal(st.halt, null);
    assert.equal(st.backoff.failures, 0);
  });
});
