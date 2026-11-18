/** B6 threat suite: the device registry (`devices.yml`) is a trust root that only a trusted, registered, approved
 *  device may extend, and only by adding (S16-17, S19, F3b invariant 5, T-B4-12). END-TO-END: raw hostile commits on
 *  the remote -> real `runCycle` in warn AND enforce -> quarantine, nothing moved, `allowed_signers` byte-identical.
 *  The golden test at the bottom is UNGATED (pure functions, runs on Windows too). */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { parseDevicesYaml, parseEd25519Pub, renderAllowedSigners, renderDevicesYaml, type DeviceEntry } from '@agent-ledger/shared';
import { runCycle } from './cycle.ts';
import { mergeDevices } from './merge/devices.ts';
import type { LedgerHub, TestHub } from './testkit-remote.ts';
import { assertQuarantined, assertUntouched, bothModes, ctx, devicesWith, nowIso, skipSync, snapshot, withRig, type Rig } from './threatkit.ts';

let seq = 0;
const uniq = (what: string): string => `${what} #${String((seq += 1))}`;
const signersPath = (lh: LedgerHub): string => nodePath.join(lh.dir, '.hub', 'allowed_signers');

/** A registry entry for `x` (a hub whose key nobody registered, unless the case registers it). */
const entryOf = (x: TestHub, slot: string, addedBy: string, over: Partial<DeviceEntry> = {}): DeviceEntry => ({
  id: x.deviceId,
  label: 'x-device',
  slot,
  pubkey: x.pub.line,
  added: nowIso(),
  added_by: addedBy,
  revoked: null,
  role: 'owner',
  ...over,
});

/** Hub `i` runs a cycle in `mode` against hostile tip `tip`: quarantined (`re`), nothing moved, signers byte-identical. */
async function expectQuarantine(r: Rig, i: number, mode: 'warn' | 'enforce', tip: string, re: RegExp, name: string): Promise<void> {
  const lh = r.hubOf(i);
  await lh.state.update((s) => {
    s.halt = null; // judge each hostile tip afresh
  });
  const signersBefore = await readFile(signersPath(lh));
  const before = await snapshot(lh);
  const { deps, flaky } = r.mk(i, { verify: mode });
  const res = await runCycle(deps);
  try {
    await assertQuarantined(lh, res, re, { tip, before, flaky });
    assertUntouched(before, await snapshot(lh), { allow: ['incoming', 'state'] });
    assert.ok(signersBefore.equals(await readFile(signersPath(lh))), 'allowed_signers changed');
  } catch (err) {
    if (err instanceof Error) err.message = `[${name}] ${err.message}`;
    throw err;
  }
}

/* ---------------- hostile registry edits on top of the fleet base ---------------- */

test('hostile devices.yml edits (self-add, un-approved add, removal, key swap, deletion, role, slot, added_by, e-mail lie) are quarantined in warn and enforce', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const X = await r.kit.makeHub(9); // a key nobody registered
    const Y = await r.kit.makeHub(10);
    const text = r.fleet.devicesText;
    type Case = { name: string; signer: TestHub | null; files: ({ path: string; content: string } | { path: string; remove: true })[]; re: RegExp; identity?: TestHub['identity'] };
    const dev = (content: string): { path: string; content: string }[] => [{ path: 'devices.yml', content }];
    const cases: Case[] = [
      { name: 'self-add by an unregistered key', signer: X, files: dev(devicesWith(r.fleet, (ds) => [...ds, entryOf(X, 'D', A.hub.deviceId)])), re: /^quarantine:unknown-devices$/ },
      { name: 'self-add naming itself as adder', signer: X, files: dev(devicesWith(r.fleet, (ds) => [...ds, entryOf(X, 'D', C.hub.deviceId)])), re: /^quarantine:unknown-devices$/ },
      { name: 'unsigned registry change', signer: null, files: dev(devicesWith(r.fleet, (ds) => [...ds, entryOf(X, 'D', A.hub.deviceId)])), re: /^quarantine:unsigned-devices$/ },
      { name: 'entry removal', signer: A.hub, files: dev(devicesWith(r.fleet, (ds) => ds.filter((d) => d.id !== C.hub.deviceId))), re: /^quarantine:devices:entry-removed$/ },
      { name: 'pubkey swap (id kept)', signer: A.hub, files: dev(text.replace(C.hub.pub.line, X.pub.line)), re: /^quarantine:/ },
      { name: 'identity swap (slot reassigned to another key)', signer: A.hub, files: dev(devicesWith(r.fleet, (ds) => ds.map((d) => (d.id === C.hub.deviceId ? entryOf(X, d.slot, A.hub.deviceId) : d)))), re: /^quarantine:devices:entry-removed$/ },
      { name: 'devices.yml deleted', signer: A.hub, files: [{ path: 'devices.yml', remove: true }], re: /^quarantine:tree:delete-protected$/ },
      { name: 'role change', signer: A.hub, files: dev(text.replace('role: owner', 'role: admin')), re: /^quarantine:/ },
      { name: 'slot change', signer: A.hub, files: dev(devicesWith(r.fleet, (ds) => ds.map((d) => (d.id === C.hub.deviceId ? { ...d, slot: 'D' } : d)))), re: /^quarantine:devices:entry-modified$/ },
      { name: 'added_by forged (not the signer)', signer: A.hub, files: dev(devicesWith(r.fleet, (ds) => [...ds, entryOf(X, 'D', B.hub.deviceId)])), re: /^quarantine:devices:added-by-mismatch$/ },
      { name: 'new entry already revoked', signer: A.hub, files: dev(devicesWith(r.fleet, (ds) => [...ds, entryOf(X, 'D', A.hub.deviceId, { revoked: { at: nowIso(), by: A.hub.deviceId, reason: 'x' } })])), re: /^quarantine:devices:new-entry-revoked$/ },
      { name: 'committer e-mail names another device', signer: C.hub, identity: A.hub.identity, files: [ctx('# acme\nfrom c as a\n')], re: /^quarantine:email-mismatch$/ },
    ];
    await bothModes(async (mode) => {
      // registry rows are mode independent (a registry change is strict in both): `warn` samples five cases (time budget)
      const picked = mode === 'warn' ? cases.filter((_, i) => [0, 2, 3, 6, cases.length - 1].includes(i)) : cases;
      for (const c of picked) {
        const tip = await r.kit.remote.rawCommit({
          parents: [r.fleet.base],
          files: c.files,
          signer: c.signer,
          ...(c.identity !== undefined ? { identity: c.identity } : {}),
          message: uniq(`${mode} ${c.name}`),
        });
        await expectQuarantine(r, 1, mode, tip, c.re, `${mode}: ${c.name}`);
      }
    });
  });
});

test('registered-but-not-approved signer: a registry change from it is quarantined (and it cannot extend the registry in warn either)', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const X = await r.kit.makeHub(9);
    // B approved A and itself only: C is registered in devices.yml but its key is not approved on B
    await writeFile(signersPath(B), renderAllowedSigners([A, B].map((h) => ({ id: h.hub.deviceId, pubkey: h.hub.pub.line }))), { mode: 0o600 });
    await chmod(signersPath(B), 0o600);
    await bothModes(async (mode) => {
      const add = await r.kit.remote.rawCommit({
        parents: [r.fleet.base],
        files: [{ path: 'devices.yml', content: devicesWith(r.fleet, (ds) => [...ds, entryOf(X, 'D', C.hub.deviceId)]) }],
        signer: C.hub,
        message: uniq(`${mode} add by unapproved`),
      });
      await expectQuarantine(r, 1, mode, add, /^quarantine:unapproved-devices$/, `${mode}: add by an unapproved registered key`);
    });
    // enforce additionally refuses its plain commits; warn accepts them with a note (documented behaviour)
    const plain = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [ctx('# acme\nfrom unapproved c\n')], signer: C.hub, message: uniq('plain') });
    await expectQuarantine(r, 1, 'enforce', plain, /^quarantine:unapproved$/, 'enforce: plain commit by an unapproved key');
  });
});

/* ---------------- after a revocation ---------------- */

test('on top of a revocation: un-revoke, tamper with the revocation record, or re-issue the slot is quarantined (warn and enforce)', { skip: skipSync }, async () => {
  await withRig(3, async (r) => {
    const [A, B, C] = [r.hubOf(0), r.hubOf(1), r.hubOf(2)] as [LedgerHub, LedgerHub, LedgerHub];
    const X = await r.kit.makeHub(9);
    const revoked = devicesWith(r.fleet, (ds) => ds.map((d) => (d.id === C.hub.deviceId ? { ...d, revoked: { at: nowIso(), by: A.hub.deviceId, reason: 'lost' } } : d)));
    const R = await r.kit.remote.pushSigned(A.hub, [{ path: 'devices.yml', content: revoked }]);
    assert.equal((await runCycle(r.mk(1).deps)).outcome, 'applied');
    assert.equal(await B.hub.main(), R);
    const cases: { name: string; content: string; re: RegExp }[] = [
      { name: 'un-revoke', content: r.fleet.devicesText, re: /^quarantine:devices:unrevoke$/ },
      { name: 'revocation record rewritten', content: revoked.replace('reason: lost', 'reason: forgiven'), re: /^quarantine:devices:entry-modified$/ },
      { name: 'revoked slot re-issued to a new key', content: devicesWith(r.fleet, (ds) => ds.filter((d) => d.id !== C.hub.deviceId).concat(entryOf(X, 'C', A.hub.deviceId))), re: /^quarantine:devices:/ },
    ];
    await bothModes(async (mode) => {
      for (const c of cases) {
        const tip = await r.kit.remote.rawCommit({ parents: [R], files: [{ path: 'devices.yml', content: c.content }], signer: A.hub, message: uniq(`${mode} ${c.name}`) });
        await expectQuarantine(r, 1, mode, tip, c.re, `${mode}: ${c.name}`);
      }
    });
    assert.equal(await B.hub.main(), R);
    assert.ok(!(await readFile(signersPath(B), 'utf8')).includes(C.hub.deviceId), 'the revoked key stays out of allowed_signers');
    const reg = parseDevicesYaml(await readFile(nodePath.join(B.dir, 'devices.yml'), 'utf8'));
    assert.notEqual(reg.devices.find((d) => d.id === C.hub.deviceId)?.revoked, null, 'the revocation is still in the registry');
  });
});

/* ---------------- golden (UNGATED: pure functions) ---------------- */

/** ssh-ed25519 wire blob prefix: string "ssh-ed25519" + length 32. */
const WIRE_PREFIX = Buffer.from('0000000b7373682d6564323535313900000020', 'hex');
const fixedKey = (name: string): string => `ssh-ed25519 ${Buffer.concat([WIRE_PREFIX, createHash('sha256').update(`agent-ledger golden ${name}`).digest()]).toString('base64')}`;

function golden(name: string, slot: string, addedBy: string | null, over: Partial<DeviceEntry> = {}): DeviceEntry {
  const line = fixedKey(name);
  const id = (parseEd25519Pub(line) as { deviceId: string }).deviceId;
  return { id, label: name, slot, pubkey: line, added: '2026-11-01T00:00:00.000Z', added_by: addedBy ?? id, revoked: null, role: 'owner', ...over };
}

const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex');

test('golden: the byte form of devices.yml (renderDevicesYaml) and of the typed merge is pinned (not gated; also runs on Windows)', () => {
  const root = golden('root', '', null);
  const b = golden('b', 'B', root.id);
  const c = golden('c', 'C', root.id);
  const d = golden('d', 'D', b.id, { added: '2026-11-02T08:30:00.000Z' });
  const base = renderDevicesYaml({ devices: [root, b, c] });
  const p1 = renderDevicesYaml({ devices: [root, { ...b, last_seen: '2026-11-03T09:00:00.000Z' }, c, d] });
  const p2 = renderDevicesYaml({ devices: [root, b, { ...c, revoked: { at: '2026-11-02T10:00:00.000Z', by: root.id, reason: 'lost phone' } }] });
  const full = renderDevicesYaml({ devices: [root, b, c, d] });
  const merged = mergeDevices(base, p1, p2);
  assert.equal(merged.ok, true);
  const mergedText = merged.ok ? merged.merged : '';
  const got = { full: sha256(full), base: sha256(base), merged: sha256(mergedText), mergedSwapped: sha256((mergeDevices(base, p2, p1) as { merged: string }).merged) };
  assert.deepEqual(got, {
    full: GOLDEN_FULL,
    base: GOLDEN_BASE,
    merged: GOLDEN_MERGED,
    mergedSwapped: GOLDEN_MERGED,
  });
  // the merge does not depend on which side is "ours"
  assert.equal(got.merged, got.mergedSwapped);
  // and it round-trips through the strict parser unchanged
  assert.equal(renderDevicesYaml(parseDevicesYaml(mergedText)), mergedText);
});

const GOLDEN_FULL = '2348dcac1da7cbd2296d0f501f88a69cfaa06bb0f088de4358dc3f610a62694a';
const GOLDEN_BASE = 'b6f86c3eb6588979941260a9bdf80f0cce75e0c8a549ed5d4d7f9c7ed852b358';
const GOLDEN_MERGED = '2de81dcc1b7c7121262bb6619b3326f615af4412a041f5b485993fdc94cdae52';
