/** B6 threat suite: device slots keep ids and counters collision-free across devices (S18, F3b invariants 11 and 17,
 *  T-B4-4 hostile side). END-TO-END: a hostile peer (valid, trusted key) tries to write another device's counters, mint
 *  ids in another device's slot, reuse a slot, use the reserved sync worker or lower a counter inside a merge commit ->
 *  real `runCycle` -> quarantine, nothing moved. 3-hub fleet: A = slot "" (root), B = slot "B", C = slot "C". */

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { serializeIntake } from '@agent-ledger/shared';
import { runCycle } from './cycle.ts';
import type { LedgerHub, TestHub } from './testkit-remote.ts';
import { assertQuarantined, assertUntouched, bothModes, devicesWith, item, nowIso, skipSync, snapshot, withRig, type Rig } from './threatkit.ts';

let seq = 0;
const uniq = (what: string): string => `${what} #${String((seq += 1))}`;
const counterPath = (h: TestHub): string => `counters/${h.deviceId}.yml`;

/** Hub `i` runs a cycle in `mode` against hostile tip `tip`: quarantined (`re`), nothing moved, never pushed. */
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

test('(a) a peer writing ANOTHER device\'s counters file is quarantined; so is an unowned counters write', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    await bothModes(async (mode) => {
      const foreignA = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: counterPath(A.hub), content: 'acme: 5\n' }], signer: B.hub, message: uniq(`${mode} B writes A's counters`) });
      await expectQuarantine(r, 0, mode, foreignA, /^quarantine:counters-foreign$/, `${mode}: B writes A's counters`);
      const foreignC = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: counterPath(C.hub), content: 'acme: 5\n' }], signer: B.hub, message: uniq(`${mode} B writes C's counters`) });
      await expectQuarantine(r, 0, mode, foreignC, /^quarantine:counters-foreign$/, `${mode}: B writes C's counters`);
      // no identifiable owner (unsigned, no device e-mail): counters belong to a slot, so not even warn lets it through
      const unowned = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: counterPath(B.hub), content: 'acme: 5\n' }], signer: null, message: uniq(`${mode} unowned counters`) });
      await expectQuarantine(r, 0, mode, unowned, /^quarantine:unowned$/, `${mode}: unowned counters`);
    });
    // control: B writing its OWN counters is fine
    const own = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: counterPath(B.hub), content: 'acme: 5\n' }], signer: B.hub, message: uniq('own counters') });
    await r.hubOf(0).state.update((s) => {
      s.halt = null;
    });
    assert.equal((await runCycle(r.mk(0).deps)).outcome, 'applied');
    assert.equal(await A.hub.main(), own);
  });
});

test('(b) a peer creating an item id that carries ANOTHER device\'s slot is quarantined (own slot passes)', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B] = [r.hubOf(0), r.hubOf(1)] as [LedgerHub, LedgerHub];
    await bothModes(async (mode) => {
      for (const id of ['ACME-7', 'ACME-C3']) {
        const tip = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: `acme/items/${id}.md`, content: item(id) }], signer: B.hub, message: uniq(`${mode} ${id}`) });
        await expectQuarantine(r, 0, mode, tip, /^quarantine:item-slot$/, `${mode}: B creates ${id}`);
      }
    });
    const own = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'acme/items/ACME-B3.md', content: item('ACME-B3') }], signer: B.hub, message: uniq('own slot') });
    await A.state.update((s) => {
      s.halt = null;
    });
    assert.equal((await runCycle(r.mk(0).deps)).outcome, 'applied');
    assert.equal(await A.hub.main(), own);
  });
});

test('(c) two concurrent adds of the SAME slot: the merge conflicts, the registry never picks a winner, nothing is pushed', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B] = [r.hubOf(0), r.hubOf(1)] as [LedgerHub, LedgerHub];
    const X1 = await r.kit.makeHub(9);
    const X2 = await r.kit.makeHub(10);
    const entry = (x: TestHub, by: TestHub): Parameters<typeof devicesWith>[1] => (ds) => [
      ...ds,
      { id: x.deviceId, label: 'new-device', slot: 'D', pubkey: x.pub.line, added: nowIso(), added_by: by.deviceId, revoked: null, role: 'owner' as const },
    ];
    // A adds X1 locally (slot D), B adds X2 (slot D) and pushes first
    const L = await A.commitLocal([{ path: 'devices.yml', content: devicesWith(r.fleet, entry(X1, A.hub)) }], { message: 'A adds X1' });
    const F = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'devices.yml', content: devicesWith(r.fleet, entry(X2, B.hub)) }], signer: B.hub, message: 'B adds X2' });
    await bothModes(async (mode) => {
      await expectQuarantine(r, 0, mode, F, /^quarantine:merge:/, `${mode}: same slot on two branches`);
    });
    assert.equal(await A.hub.main(), L, 'local work kept');
    assert.equal(await r.kit.remote.main(), F, 'the remote was not touched');
    const text = await readFile(nodePath.join(A.dir, 'devices.yml'), 'utf8');
    assert.ok(text.includes(X1.deviceId) && !text.includes(X2.deviceId), 'neither side won: the local registry is unchanged');
  });
});

test('(d) a revoked slot is retired forever: re-issuing it (duplicate slot, or drop-and-reuse) is quarantined', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const X = await r.kit.makeHub(9);
    const revoked = devicesWith(r.fleet, (ds) => ds.map((d) => (d.id === C.hub.deviceId ? { ...d, revoked: { at: nowIso(), by: A.hub.deviceId, reason: 'lost' } } : d)));
    const R = await r.kit.remote.pushSigned(A.hub, [{ path: 'devices.yml', content: revoked }]);
    assert.equal((await runCycle(r.mk(0).deps)).outcome, 'applied');
    // a text no renderer would write: X takes slot C while C's revoked entry is still there
    const withX = devicesWith(r.fleet, (ds) => [...ds, { id: X.deviceId, label: 'x-device', slot: 'D', pubkey: X.pub.line, added: nowIso(), added_by: B.hub.deviceId, revoked: null, role: 'owner' as const }]);
    const cases: { name: string; content: string }[] = [
      { name: 'duplicate slot next to the revoked entry', content: withX.replace(`slot: D`, 'slot: C') },
      { name: 'revoked entry dropped, slot reused', content: devicesWith(r.fleet, (ds) => ds.filter((d) => d.id !== C.hub.deviceId).concat({ id: X.deviceId, label: 'x-device', slot: 'C', pubkey: X.pub.line, added: nowIso(), added_by: B.hub.deviceId, revoked: null, role: 'owner' as const })) },
    ];
    await bothModes(async (mode) => {
      for (const c of cases) {
        const tip = await r.kit.remote.rawCommit({ parents: [R], files: [{ path: 'devices.yml', content: c.content }], signer: B.hub, message: uniq(`${mode} ${c.name}`) });
        await expectQuarantine(r, 0, mode, tip, /^quarantine:/, `${mode}: ${c.name}`);
      }
    });
    assert.equal(await A.hub.main(), R);
  });
});

test('(e) an intake id minted by the reserved sync worker (1023) is quarantined; any other worker passes', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B] = [r.hubOf(0), r.hubOf(1)] as [LedgerHub, LedgerHub];
    const intake = (worker: number): { path: string; content: string } => {
      const id = String((1789130426000n << 22n) | (BigInt(worker) << 12n) | 5n);
      const content = serializeIntake({ id, at: '2026-11-16T10:00:00.000Z', channel: 'chat', session: null, repo_hint: 'acme', status: 'new', items: [], text: 'do a thing', triage: [], dropped: [] });
      return { path: `intake/2026-11/${id}.md`, content };
    };
    await bothModes(async (mode) => {
      const tip = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [intake(1023)], signer: B.hub, message: uniq(`${mode} worker 1023`) });
      await expectQuarantine(r, 0, mode, tip, /^quarantine:tree:reserved-worker$/, `${mode}: worker 1023`);
    });
    const fine = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [intake(7)], signer: B.hub, message: uniq('worker 7') });
    await A.state.update((s) => {
      s.halt = null;
    });
    assert.equal((await runCycle(r.mk(0).deps)).outcome, 'applied');
    assert.equal(await A.hub.main(), fine);
  });
});

test('(f) a merge commit that LOWERS (or raises) a counter below/above the per-key max of its parents is quarantined', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const cp = counterPath(A.hub);
    const journal = { path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' };
    const P = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: cp, content: 'acme: 5\n' }], signer: A.hub, message: 'A counters 5' });
    assert.equal((await runCycle(r.mk(2).deps)).outcome, 'applied');
    assert.equal(await C.hub.main(), P);
    const X1 = await r.kit.remote.rawCommit({ parents: [P], files: [{ path: cp, content: 'acme: 7\n' }], signer: A.hub, setMain: false, message: 'A counters 7' });
    const X2 = await r.kit.remote.rawCommit({ parents: [P], files: [journal], signer: B.hub, setMain: false, message: 'B journal' });
    await bothModes(async (mode) => {
      for (const wrong of ['acme: 3\n', 'acme: 9\n']) {
        const M = await r.kit.remote.rawCommit({ parents: [X1, X2], files: [{ path: cp, content: wrong }, journal], signer: B.hub, message: uniq(`${mode} merge with counter ${wrong.trim()}`) });
        await expectQuarantine(r, 2, mode, M, /^quarantine:merge-counters$/, `${mode}: ${wrong.trim()}`);
      }
    });
    // control: the typed merge (max of both sides) is accepted
    const ok = await r.kit.remote.rawCommit({ parents: [X1, X2], files: [{ path: cp, content: 'acme: 7\n' }, journal], signer: B.hub, message: uniq('honest merge') });
    await C.state.update((s) => {
      s.halt = null;
    });
    assert.equal((await runCycle(r.mk(2).deps)).outcome, 'applied');
    assert.equal(await C.hub.main(), ok);
  });
});
