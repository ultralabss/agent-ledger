/** Table-driven §2.3 matrix of docs/f3b-plan.md: every row in warn AND enforce, the
 *  OQ-4 ratchet, D2 holds, ownership (S18), merge-commit rule, hostile input. */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { parseEd25519Pub, renderDevicesYaml, type DeviceEntry } from '@agent-ledger/shared';
import { stringify as stringifyYaml } from 'yaml';
import {
  claimedDeviceFromEmail,
  gateCommit,
  gateRange,
  type GateAction,
  type GateInput,
  type GateVerdict,
  type VerifyMode,
} from './gate.ts';
import { mergeDevices } from './merge/devices.ts';
import { confirmationKey } from './state.ts';

const WIRE = Buffer.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32]);
function key(): { pub: string; id: string } {
  const pub = `ssh-ed25519 ${Buffer.concat([WIRE, randomBytes(32)]).toString('base64')}`;
  const p = parseEd25519Pub(pub);
  assert.ok(p);
  return { pub, id: p.deviceId };
}
const KA = key(); // root, trusted, slot ""
const KB = key(); // trusted, slot B (the local device in these tests)
const KU = key(); // registered, NOT approved locally, slot U
const KR = key(); // registered, revoked, slot R
const KX = key(); // not registered at all
const KN = key(); // new device to add
const T0 = '2026-11-16T10:00:00.000Z';
const T0_MS = Date.parse(T0);
const SHA = 'a'.repeat(40);

const ent = (k: { pub: string; id: string }, over: Partial<DeviceEntry> = {}): DeviceEntry => ({
  id: k.id, label: 'dev', slot: '', pubkey: k.pub, added: T0, added_by: k.id, revoked: null, role: 'owner', ...over,
});
const eA = (o: Partial<DeviceEntry> = {}): DeviceEntry => ent(KA, o);
const eB = (o: Partial<DeviceEntry> = {}): DeviceEntry => ent(KB, { slot: 'B', label: 'b', added_by: KA.id, ...o });
const eU = (o: Partial<DeviceEntry> = {}): DeviceEntry => ent(KU, { slot: 'U', label: 'u', added_by: KA.id, ...o });
const eR = (o: Partial<DeviceEntry> = {}): DeviceEntry =>
  ent(KR, { slot: 'R', label: 'r', added_by: KA.id, revoked: { at: T0, by: KA.id, reason: 'lost' }, ...o });
const eN = (o: Partial<DeviceEntry> = {}): DeviceEntry => ent(KN, { slot: 'N', label: 'n', added_by: KA.id, ...o });
const dev = (...d: DeviceEntry[]): string => renderDevicesYaml({ devices: d });
const PARENT = dev(eA(), eB(), eU(), eR());

const sig = (k: { pub: string } | null, valid = true): GateInput['signature'] =>
  k === null ? { valid: false, pubkey: null, reason: 'no signature' } : { valid, pubkey: k.pub, reason: valid ? 'ok' : 'bad' };

function base(over: Partial<GateInput> = {}): GateInput {
  return {
    mode: 'warn',
    sha: SHA,
    commitTimeMs: T0_MS,
    signature: sig(KA),
    claimedDevice: null,
    localDevice: KB.id,
    trusted: new Set([KA.pub, KB.pub, KR.pub]),
    seenSigning: new Set<string>(),
    parentDevices: [PARENT],
    devicesText: PARENT,
    currentDevices: PARENT,
    confirmedRevocations: new Set<string>(),
    changes: [{ path: 'acme/items/ACME-1.md', status: 'M' }],
    ingress: { accepted: ['acme/items/ACME-1.md'], rejected: [] },
    ...over,
  };
}
const run = (mode: VerifyMode, over: Partial<GateInput>): GateVerdict => gateCommit(base({ ...over, mode }));

interface Row {
  row: string;
  over: Partial<GateInput>;
  warn: GateAction;
  enforce: GateAction;
  rule?: string | [string, string];
  noteType?: string;
}

const rejectedIngress = (rule: string, path = 'x'): GateInput['ingress'] => ({ accepted: [], rejected: [{ path, rule }] });
const ownA = { claimedDevice: null };

const ROWS: Row[] = [
  // --- rows 1/2/3: content rules, any signature
  { row: '1 symlink, trusted signer', over: { ingress: rejectedIngress('symlink') }, warn: 'quarantine', enforce: 'quarantine', rule: 'ingress:symlink' },
  { row: '1 hub-path, unsigned', over: { signature: sig(null), ingress: rejectedIngress('hub-path', '.hub/x') }, warn: 'quarantine', enforce: 'quarantine' },
  { row: '1 delete-protected (non-item delete)', over: { ingress: rejectedIngress('delete-protected', 'devices.yml') }, warn: 'quarantine', enforce: 'quarantine' },
  { row: '1 format downgrade', over: { ingress: rejectedIngress('format', 'ledger.format') }, warn: 'quarantine', enforce: 'quarantine' },
  { row: '1 pinned file differs', over: { ingress: rejectedIngress('gitignore', '.gitignore') }, warn: 'quarantine', enforce: 'quarantine' },
  { row: '1 unknown future rule fails closed', over: { ingress: rejectedIngress('brand-new-rule') }, warn: 'quarantine', enforce: 'quarantine' },
  { row: '1 beats 2 when both fire', over: { ingress: { accepted: [], rejected: [{ path: 'a', rule: 'secret' }, { path: 'b', rule: 'exec' }] } }, warn: 'quarantine', enforce: 'quarantine', rule: 'ingress:exec' },
  { row: '2 secret, trusted signer', over: { ingress: rejectedIngress('secret', 'acme/CONTEXT.md') }, warn: 'quarantine', enforce: 'quarantine', rule: 'secret', noteType: 'sync.secret' },
  { row: '2 secret, unsigned', over: { signature: sig(null), ingress: rejectedIngress('secret') }, warn: 'quarantine', enforce: 'quarantine', rule: 'secret' },
  { row: '3 only item deletes, trusted', over: { ingress: rejectedIngress('delete', 'acme/items/ACME-1.md') }, warn: 'forced-merge-keep-items', enforce: 'forced-merge-keep-items', rule: 'item-delete' },
  { row: '3 only item deletes + devices change', over: { ingress: rejectedIngress('delete', 'acme/items/ACME-1.md'), devicesText: dev(eA(), eB(), eU(), eR(), eN()) }, warn: 'quarantine', enforce: 'quarantine', rule: 'delete-with-devices' },
  { row: '3 item delete does not launder an unsigned commit', over: { signature: sig(null), ingress: rejectedIngress('delete', 'acme/items/ACME-1.md') }, warn: 'forced-merge-keep-items', enforce: 'quarantine' },
  { row: '3 item delete does not launder a revoked key', over: { signature: sig(KR), ingress: rejectedIngress('delete', 'acme/items/ACME-1.md') }, warn: 'quarantine', enforce: 'quarantine', rule: 'revoked-signer' },
  // --- row 4: revoked key
  { row: '4 valid, key revoked in a parent', over: { signature: sig(KR) }, warn: 'quarantine', enforce: 'quarantine', rule: 'revoked-signer' },
  // --- row 5: trusted+active, no devices change
  { row: '5 trusted+active, ok content', over: {}, warn: 'accept', enforce: 'accept', rule: 'ok' },
  { row: '5 second trusted device', over: { signature: sig(KB) }, warn: 'accept', enforce: 'accept' },
  // --- row 6: valid devices change, not root/self revocation
  { row: '6 add a device (time bound)', over: { devicesText: dev(eA(), eB(), eU(), eR(), eN()) }, warn: 'accept', enforce: 'accept' },
  { row: '6 revoke a non-root, non-local device', over: { devicesText: dev(eA(), eB(), eU({ revoked: { at: T0, by: KA.id, reason: 'stolen' } }), eR()) }, warn: 'accept', enforce: 'accept' },
  { row: '6 own last_seen', over: { devicesText: dev(eA({ last_seen: T0 }), eB(), eU(), eR()) }, warn: 'accept', enforce: 'accept' },
  // --- row 7: D2 holds
  { row: '7 revokes the root', over: { signature: sig(KB), devicesText: dev(eA({ revoked: { at: T0, by: KB.id, reason: 'lost' } }), eB(), eU(), eR()) }, warn: 'halt', enforce: 'halt', rule: 'revocation-root' },
  { row: '7 revokes THIS device', over: { devicesText: dev(eA(), eB({ revoked: { at: T0, by: KA.id, reason: 'lost' } }), eU(), eR()) }, warn: 'halt', enforce: 'halt', rule: 'revocation-self' },
  // --- row 8: invalid change by trusted signer
  { row: '8 un-revoke', over: { devicesText: dev(eA(), eB(), eU(), eR({ revoked: null })) }, warn: 'quarantine', enforce: 'quarantine', rule: 'devices:unrevoke' },
  { row: '8 removal', over: { devicesText: dev(eA(), eB(), eR()) }, warn: 'quarantine', enforce: 'quarantine', rule: 'devices:entry-removed' },
  { row: '8 foreign last_seen', over: { devicesText: dev(eA(), eB({ last_seen: T0 }), eU(), eR()) }, warn: 'quarantine', enforce: 'quarantine', rule: 'devices:last-seen-foreign' },
  { row: '8 time unbound (+1 day)', over: { devicesText: dev(eA(), eB(), eU(), eR(), eN({ added: '2026-11-17T10:00:00.000Z' })) }, warn: 'quarantine', enforce: 'quarantine', rule: 'devices:time-unbound' },
  { row: '8 slot reuse (invalid file)', over: { devicesText: stringifyYaml({ devices: [eA(), eB(), eU(), eR(), eN({ slot: 'U' })] }) }, warn: 'quarantine', enforce: 'quarantine', rule: 'devices:invalid-incoming' },
  { row: '8 pubkey swap', over: { devicesText: dev(eA(), eB({ pubkey: KN.pub, id: KN.id }), eU(), eR()) }, warn: 'quarantine', enforce: 'quarantine' },
  { row: '8 deleted devices.yml', over: { devicesText: null }, warn: 'quarantine', enforce: 'quarantine', rule: 'devices:deleted' },
  { row: '8 self-added entry (added_by mismatch)', over: { devicesText: dev(eA(), eB(), eU(), eR(), eN({ added_by: KB.id })) }, warn: 'quarantine', enforce: 'quarantine', rule: 'devices:added-by-mismatch' },
  // --- rows 9/10: registered, not approved locally
  { row: '9 registered, not approved, no devices change', over: { signature: sig(KU) }, warn: 'accept-warn', enforce: 'quarantine', rule: ['unapproved', 'unapproved'], noteType: 'sync.unverified' },
  { row: '10 registered, not approved, devices change', over: { signature: sig(KU), devicesText: dev(eA(), eB(), eU(), eR(), eN({ added_by: KU.id })) }, warn: 'quarantine', enforce: 'quarantine', rule: 'unapproved-devices' },
  // --- row 11: valid but unknown key
  { row: '11 valid, unknown key, no devices change', over: { signature: sig(KX) }, warn: 'accept-warn', enforce: 'quarantine', noteType: 'sync.warning' },
  // --- row 12: unsigned / bad, ratchet
  { row: '12 unsigned, no claim', over: { signature: sig(null) }, warn: 'accept-warn', enforce: 'quarantine', rule: ['unsigned', 'unsigned'] },
  { row: '12 bad signature', over: { signature: sig(KA, false) }, warn: 'accept-warn', enforce: 'quarantine' },
  { row: '12 unsigned claiming a device never seen signing', over: { signature: sig(null), claimedDevice: KB.id }, warn: 'accept-warn', enforce: 'quarantine' },
  { row: '12 unsigned claiming a device seen signing (OQ-4 ratchet)', over: { signature: sig(null), claimedDevice: KB.id, seenSigning: new Set([KB.id]) }, warn: 'quarantine', enforce: 'quarantine', rule: ['unsigned-ratchet', 'unsigned'] },
  { row: '12 bad signature claiming a seen device', over: { signature: sig(KA, false), claimedDevice: KA.id, seenSigning: new Set([KA.id]) }, warn: 'quarantine', enforce: 'quarantine' },
  // --- row 13: unsigned/unknown/bad + devices change
  { row: '13 unsigned + devices change', over: { signature: sig(null), devicesText: dev(eA(), eB(), eU(), eR(), eN()) }, warn: 'quarantine', enforce: 'quarantine', rule: 'unsigned-devices' },
  { row: '13 unknown key + devices change', over: { signature: sig(KX), devicesText: stringifyYaml({ devices: [eA(), eB(), eU(), eR(), eN({ added_by: KX.id })] }) }, warn: 'quarantine', enforce: 'quarantine', rule: 'unknown-devices' },
  { row: '13 bad signature + devices change', over: { signature: sig(KA, false), devicesText: dev(eA(), eB(), eU(), eR(), eN()) }, warn: 'quarantine', enforce: 'quarantine' },
  // --- row 14: ownership (S18)
  { row: '14 own counter file', over: { changes: [{ path: `counters/${KA.id}.yml`, status: 'M' }] }, warn: 'accept', enforce: 'accept' },
  { row: '14 counter file of another device', over: { changes: [{ path: `counters/${KB.id}.yml`, status: 'M' }] }, warn: 'quarantine', enforce: 'quarantine', rule: 'counters-foreign' },
  { row: '14 deleting another device counter', over: { changes: [{ path: `counters/${KB.id}.yml`, status: 'D' }] }, warn: 'quarantine', enforce: 'quarantine', rule: 'counters-foreign' },
  { row: '14 item id with own slot (primary: no letter)', over: { changes: [{ path: 'acme/items/ACME-7.md', status: 'A' }] }, warn: 'accept', enforce: 'accept' },
  { row: '14 item id with another slot', over: { changes: [{ path: 'acme/items/ACME-B7.md', status: 'A' }] }, warn: 'quarantine', enforce: 'quarantine', rule: 'item-slot' },
  { row: '14 secondary device, its own slot', over: { signature: sig(KB), changes: [{ path: 'acme/items/ACME-B7.md', status: 'A' }] }, warn: 'accept', enforce: 'accept' },
  { row: '14 secondary device, primary-slot id', over: { signature: sig(KB), changes: [{ path: 'acme/items/ACME-7.md', status: 'A' }] }, warn: 'quarantine', enforce: 'quarantine', rule: 'item-slot' },
  { row: '14 modifying a foreign-slot item is fine', over: { changes: [{ path: 'acme/items/ACME-B7.md', status: 'M' }] }, warn: 'accept', enforce: 'accept' },
  { row: '14 unsigned commit claiming A touches B counters', over: { signature: sig(null), claimedDevice: KA.id, changes: [{ path: `counters/${KB.id}.yml`, status: 'M' }] }, warn: 'quarantine', enforce: 'quarantine', rule: 'counters-foreign' },
  // --- S19
  { row: 'S19 committer e-mail names another device than the key', over: { claimedDevice: KB.id }, warn: 'quarantine', enforce: 'quarantine', rule: 'email-mismatch' },
  { row: 'S19 e-mail matches the key', over: { claimedDevice: KA.id }, warn: 'accept', enforce: 'accept' },
];

for (const r of ROWS) {
  test(`matrix: ${r.row}`, () => {
    for (const mode of ['warn', 'enforce'] as const) {
      const want = mode === 'warn' ? r.warn : r.enforce;
      const v = run(mode, r.over);
      assert.equal(v.action, want, `${mode}: ${v.action} (${v.rule})`);
      const wantRule = Array.isArray(r.rule) ? r.rule[mode === 'warn' ? 0 : 1] : r.rule;
      if (wantRule !== undefined && !(mode === 'enforce' && !Array.isArray(r.rule) && r.warn !== r.enforce)) {
        assert.equal(v.rule, wantRule, `${mode} rule`);
      }
      if (want === 'halt') assert.ok(v.haltReason?.startsWith('quarantine:revocation-'));
      else assert.equal(v.haltReason, undefined);
      if (want === 'quarantine') assert.ok(v.notes.length > 0 && v.notes.every((n) => n.type === 'sync.reject' || n.type === 'sync.secret'));
      if (r.noteType !== undefined && want !== 'quarantine') assert.ok(v.notes.some((n) => n.type === r.noteType));
    }
  });
}

test('D2 reasons are distinct and identical in both modes', () => {
  const root = ROWS.find((r) => r.row === '7 revokes the root') as Row;
  const self = ROWS.find((r) => r.row === '7 revokes THIS device') as Row;
  for (const mode of ['warn', 'enforce'] as const) {
    assert.equal(run(mode, root.over).haltReason, 'quarantine:revocation-root');
    assert.equal(run(mode, self.over).haltReason, 'quarantine:revocation-self');
  }
});

test('revoked / invalid / D2 verdicts are identical in warn and enforce (inv 5, 6, 7)', () => {
  for (const r of ROWS.filter((x) => /^(4|7|8|1|2) /.test(x.row))) {
    const w = run('warn', r.over);
    const e = run('enforce', r.over);
    assert.equal(w.action, e.action, r.row);
    assert.equal(w.rule, e.rule, r.row);
  }
});

test('secret quarantine carries path + rule only', () => {
  const v = run('enforce', { ingress: { accepted: [], rejected: [{ path: 'acme/CONTEXT.md', rule: 'secret' }] } });
  assert.equal(v.notes.length, 1);
  assert.equal(v.notes[0]?.type, 'sync.secret');
  assert.equal(v.notes[0]?.path, 'acme/CONTEXT.md');
  assert.match(v.notes[0]?.detail ?? '', /^secret scanner hit \(commit a{12}\)$/);
});

test('an unknown mode is treated as enforce (fail closed)', () => {
  const v = gateCommit(base({ mode: 'yolo' as never, signature: sig(null) }));
  assert.equal(v.action, 'quarantine');
});

test('trusted set uses canonical keys; a key with a comment never matches', () => {
  const v = gateCommit(base({ mode: 'enforce', trusted: new Set([`${KA.pub} laptop`]) }));
  assert.equal(v.action, 'quarantine');
});

/* ---------------- merge commits ---------------- */

// B and R registered on both sides (a merge author must be known to both parents); U only on side 2.
const MP1 = dev(eA(), eB(), eR());
const MP2 = dev(eA(), eB(), eR(), eU());
const MBASE = dev(eA(), eB(), eR());
const MERGED = (() => {
  const r = mergeDevices(MBASE, MP1, MP2);
  assert.ok(r.ok);
  return r.merged;
})();
const m = (c: Record<string, string>): ReadonlyMap<string, string> => new Map(Object.entries(c));
const CTR = `counters/${KB.id}.yml`;
function mergeInput(over: Partial<GateInput> = {}, mergedCounters = 'acme: 3\n'): Partial<GateInput> {
  return {
    parentDevices: [MP1, MP2],
    devicesText: MERGED,
    changes: [],
    merge: {
      baseDevices: MBASE,
      baseCounters: m({ [CTR]: 'acme: 1\n' }),
      parentCounters: [m({ [CTR]: 'acme: 2\n' }), m({ [CTR]: 'acme: 3\n' })],
      mergedCounters: m({ [CTR]: mergedCounters }),
      addedVsBoth: [],
    },
    ...over,
  };
}

test('merge commit: devices.yml == mergeDevices result and counters == per-key max -> accept (any author)', () => {
  for (const mode of ['warn', 'enforce'] as const) {
    assert.equal(run(mode, mergeInput()).action, 'accept');
    assert.equal(run(mode, { ...mergeInput(), signature: sig(KB) }).action, 'accept', 'merge author may touch other devices counters');
  }
});

test('merge commit: devices.yml not the typed merge -> quarantine (both modes)', () => {
  for (const mode of ['warn', 'enforce'] as const) {
    assert.equal(run(mode, mergeInput({ devicesText: dev(eA(), eB(), eR(), eN()) })).rule, 'merge-devices');
    assert.equal(run(mode, mergeInput({ devicesText: MP1 })).rule, 'merge-devices', 'dropping the other side entry');
    assert.equal(run(mode, mergeInput({ devicesText: null })).action, 'quarantine');
  }
});

test('merge commit: signer revoked in ONE of the two parents -> quarantine; un-revoking via merge text -> quarantine', () => {
  const p2 = dev(eA(), eB({ revoked: { at: T0, by: KA.id, reason: 'x' } }));
  const mm = mergeDevices(MP1, MP1, p2);
  assert.ok(mm.ok);
  const merged = mm.ok ? mm.merged : '';
  const input = { ...mergeInput(), parentDevices: [MP1, p2], devicesText: merged, signature: sig(KB) } as Partial<GateInput>;
  input.merge = { ...(mergeInput().merge as NonNullable<GateInput['merge']>), baseDevices: MP1 };
  for (const mode of ['warn', 'enforce'] as const) assert.equal(run(mode, input).rule, 'revoked-signer');
  // same merge but authored by A (not revoked) is fine, and a text that un-revokes B is not
  const byA = { ...input, signature: sig(KA) } as Partial<GateInput>;
  assert.equal(run('enforce', byA).action, 'accept');
  const unrevoked = { ...byA, devicesText: MP1 } as Partial<GateInput>;
  assert.equal(run('enforce', unrevoked).rule, 'merge-devices');
});

test('merge commit: counters below per-key max / extra key / foreign garbage -> quarantine', () => {
  assert.equal(run('enforce', mergeInput({}, 'acme: 2\n')).rule, 'merge-counters');
  assert.equal(run('enforce', mergeInput({}, 'acme: 3\nevil: 9\n')).rule, 'merge-counters');
  assert.equal(run('enforce', mergeInput({}, 'acme: -1\n')).rule, 'merge-counters');
  assert.equal(run('warn', mergeInput({}, 'acme: 99\n')).rule, 'merge-counters');
});

test('merge commit: missing merge input / octopus -> quarantine', () => {
  assert.equal(run('warn', { ...mergeInput(), merge: undefined }).rule, 'merge-input-missing');
  assert.equal(run('warn', { parentDevices: [MP1, MP2, MP1] }).rule, 'merge-octopus');
});

test('merge commit: signer must still pass the signature rows (revoked / unsigned)', () => {
  assert.equal(run('warn', { ...mergeInput(), signature: sig(KR) }).action, 'quarantine');
  assert.equal(run('enforce', { ...mergeInput(), signature: sig(null) }).action, 'quarantine');
  // devices.yml(M) != devices.yml(P1) -> registry change -> unsigned quarantined in warn too (B12-1, inv 5)
  for (const mode of ['warn', 'enforce'] as const) assert.equal(run(mode, { ...mergeInput(), signature: sig(null) }).rule, 'unsigned-devices');
});

test('B12-1: merge changing the registry vs ANY parent needs a trusted signer in both modes', () => {
  for (const mode of ['warn', 'enforce'] as const) {
    assert.equal(run(mode, { ...mergeInput(), signature: sig(KX) }).rule, 'unknown-devices');
    assert.equal(run(mode, { ...mergeInput(), signature: sig(KA, false) }).rule, 'unsigned-devices');
    assert.equal(run(mode, mergeInput()).action, 'accept', 'trusted signer: honest merge');
  }
  // parents identical to M on P1 but different on P2 only is still a change
  const m2 = mergeDevices(MP2, MP1, MP2);
  assert.ok(m2.ok);
  const one = mergeInput({ parentDevices: [MP2, MP1], devicesText: m2.ok ? m2.merged : '' });
  one.merge = { ...(one.merge as NonNullable<GateInput['merge']>), baseDevices: MP2 };
  for (const mode of ['warn', 'enforce'] as const) {
    assert.equal(run(mode, { ...one, signature: sig(null) }).rule, 'unsigned-devices');
    assert.equal(run(mode, one).action, 'accept');
  }
});

test('B12-1: honest unsigned merge with devices unchanged vs both parents -> accept-warn in warn (as before)', () => {
  const same = mergeInput({ parentDevices: [MP1, MP1], devicesText: MP1 });
  same.merge = { ...(same.merge as NonNullable<GateInput['merge']>), baseDevices: MP1 };
  assert.equal(run('warn', { ...same, signature: sig(null) }).action, 'accept-warn');
  assert.equal(run('enforce', { ...same, signature: sig(null) }).rule, 'unsigned');
  assert.equal(run('warn', same).action, 'accept');
});

test('B12-1 exploit: revoked key X forks pre-revocation; unsigned merge of its registry change is quarantined (both modes)', () => {
  // tip registry: X(=KR) revoked. fork commit C1 (parent B predates revocation) signed by KR revokes U.
  const PRE = dev(eA(), eB(), eU(), eR({ revoked: null }));
  const TIP = dev(eA(), eB(), eU(), eR());
  const C1 = dev(eA(), eB(), eU({ revoked: { at: T0, by: KR.id, reason: 'x' } }), eR({ revoked: null }));
  // (a) C1 itself: key active by ancestry, rejected by the current registry
  for (const mode of ['warn', 'enforce'] as const) {
    const v = run(mode, { signature: sig(KR), parentDevices: [PRE], devicesText: C1, currentDevices: TIP });
    assert.equal(v.action, 'quarantine');
    assert.equal(v.rule, 'revoked-current');
    // AL-46: the current registry is REQUIRED, a missing one is a quarantine, never a skipped check
    assert.equal(run(mode, { signature: sig(KR), parentDevices: [PRE], devicesText: C1, currentDevices: undefined as never }).rule, 'malformed-input');
    // a key not revoked in the current registry is unaffected
    assert.equal(run(mode, { currentDevices: TIP }).action, 'accept');
    assert.equal(run(mode, { currentDevices: null }).action, 'accept');
    assert.equal(run(mode, { signature: sig(KB), currentDevices: '{{{' }).rule, 'revoked-current', 'unparseable current registry fails closed');
  }
  // (b) unsigned merge M(tip, C1) taking C1's registry change via the typed merge, no device e-mail
  const mr = mergeDevices(PRE, TIP, C1);
  assert.ok(mr.ok);
  const M = mr.ok ? mr.merged : '';
  assert.notEqual(M, TIP);
  const input: Partial<GateInput> = {
    parentDevices: [TIP, C1], devicesText: M, signature: sig(null), claimedDevice: null, changes: [],
    merge: { baseDevices: PRE, baseCounters: m({}), parentCounters: [m({}), m({})], mergedCounters: m({}), addedVsBoth: [] },
  };
  for (const mode of ['warn', 'enforce'] as const) {
    const v = run(mode, input);
    assert.equal(v.action, 'quarantine', `${mode}: ${v.rule}`);
    assert.equal(v.rule, 'unsigned-devices');
  }
});

/* ---------------- hostile input / range ---------------- */

test('never throws on hostile input: quarantine', () => {
  const hostile: unknown[] = [
    null, undefined, 5, 'x', [], {},
    { ...base(), ingress: null },
    { ...base(), ingress: { rejected: 'no' } },
    { ...base(), changes: null },
    { ...base(), parentDevices: null },
    { ...base(), trusted: null },
    { ...base(), signature: null },
    { ...base(), seenSigning: { has() { throw new Error('boom'); } }, signature: sig(null), claimedDevice: KA.id },
    { ...base(), commitTimeMs: Number.NaN, devicesText: dev(eA(), eB(), eU(), eR(), eN()) },
    { ...base(), parentDevices: ['{{{'], devicesText: 'also {{{', signature: sig(KA) },
    { ...base(), devicesText: '\u0000'.repeat(100_000), signature: sig(KA) },
    { ...base(), ingress: { rejected: [null, 5, { path: {}, rule: {} }] } },
  ];
  for (const h of hostile) {
    let v: GateVerdict | undefined;
    assert.doesNotThrow(() => { v = gateCommit(h as GateInput); });
    assert.ok(v !== undefined && ['quarantine', 'halt', 'accept', 'accept-warn', 'forced-merge-keep-items'].includes(v.action));
  }
  for (const h of hostile.slice(0, 13)) {
    assert.equal(gateCommit(h as GateInput).action, 'quarantine', JSON.stringify(h)?.slice(0, 60));
  }
});

test('hostile input 2: throwing getters, garbage members, huge lists, bad merge maps -> verdict, never an exception', () => {
  const boom = (): never => { throw new Error('boom'); };
  const throwing = (field: string): unknown => Object.defineProperty({ ...base() }, field, { get: boom, enumerable: true });
  const cases: unknown[] = [
    ...['signature', 'trusted', 'parentDevices', 'devicesText', 'changes', 'ingress', 'commitTimeMs', 'claimedDevice'].map(throwing),
    { ...base(), mode: { toString: boom } },
    { ...base(), sha: { toString: boom } },
    { ...base(), changes: [null, 5, 'x', { path: {}, status: [] }, { path: `counters/${KA.id}.yml` }] },
    { ...base(), changes: Array.from({ length: 50_000 }, (_, i) => ({ path: `counters/${KB.id}.yml#${i}`, status: 'M' })) },
    { ...base(), ingress: { rejected: Array.from({ length: 5_000 }, (_, i) => ({ path: `p${i}`, rule: 'symlink' })) } },
    { ...base(), ingress: { rejected: [{ path: 'a\u0000\u202e\u001b[31m', rule: 'x'.repeat(10_000) }] } },
    { ...base(), trusted: new Set([5, null, {}, 'ssh-ed25519 !!!']), signature: sig(KB) },
    { ...base(), signature: { valid: true, pubkey: 5, reason: 7 } },
    { ...base(), signature: { valid: true, pubkey: 'ssh-ed25519 AAAA', reason: '' } },
    { ...base(), claimedDevice: { x: 1 }, signature: sig(KA) },
    { ...base(), parentDevices: [5, {}, null] },
    { ...base(), parentDevices: [PARENT, PARENT], merge: null, devicesText: PARENT },
    { ...base(), parentDevices: [PARENT, PARENT], merge: { baseDevices: 5, baseCounters: null, parentCounters: [null, null], mergedCounters: 'x' } },
    { ...base(), parentDevices: [PARENT, PARENT], merge: { baseDevices: null, baseCounters: new Map([[5, 6]]), parentCounters: [new Map(), new Map()], mergedCounters: new Map([['counters/x.yml', 5]]) } },
  ];
  for (const mode of ['warn', 'enforce', 'bogus']) {
    for (const c of cases) {
      let v: GateVerdict | undefined;
      assert.doesNotThrow(() => { v = gateCommit(Object.create(c as object, { mode: { value: mode, enumerable: true } }) as GateInput); }, `mode ${mode}`);
      assert.ok(v !== undefined && Array.isArray(v.notes) && v.notes.length <= 20, 'verdict + bounded notes');
      // a hostile commit must never be silently accepted as a clean commit in enforce mode unless it is the untouched base case
      if (mode !== 'warn' && c !== cases[0]) assert.notEqual(v?.action, 'accept-warn');
    }
  }
  // fail closed: anything that is not exactly 'warn' behaves like enforce
  assert.equal(gateCommit(base({ mode: 'bogus' as VerifyMode, signature: sig(null) })).action, 'quarantine');
});

test('unparseable parent devices.yml: signer is unknown, never trusted', () => {
  const v = gateCommit(base({ mode: 'enforce', parentDevices: ['{{{'], devicesText: '{{{' }));
  assert.equal(v.action, 'quarantine');
});

test('no parent (root of range) cannot establish trust', () => {
  const v = gateCommit(base({ mode: 'enforce', parentDevices: [], devicesText: dev(eA()) }));
  assert.equal(v.action, 'quarantine');
});

test('gateRange: halt > quarantine > forced > accept-warn > accept; notes concatenated', () => {
  const ok = run('warn', {});
  const warn = run('warn', { signature: sig(null) });
  const forced = run('warn', { ingress: rejectedIngress('delete', 'acme/items/ACME-1.md') });
  const q = run('warn', { ingress: rejectedIngress('symlink') });
  const h = run('warn', ROWS.find((r) => r.row === '7 revokes THIS device')?.over as Partial<GateInput>);
  assert.equal(gateRange([]).action, 'accept');
  assert.equal(gateRange([ok, warn]).action, 'accept-warn');
  assert.equal(gateRange([warn, forced, ok]).action, 'forced-merge-keep-items');
  assert.equal(gateRange([forced, q, warn]).action, 'quarantine');
  const all = gateRange([q, h, forced]);
  assert.equal(all.action, 'halt');
  assert.equal(all.haltReason, 'quarantine:revocation-self');
  assert.equal(all.notes.length, q.notes.length + h.notes.length + forced.notes.length);
});

test('claimedDeviceFromEmail: only the exact hub identity form', () => {
  assert.equal(claimedDeviceFromEmail(`${KA.id}@devices.agent-ledger.invalid`), KA.id);
  for (const bad of [`${KA.id}@evil.example`, `x${KA.id}@devices.agent-ledger.invalid`, 'a@b', '', null, 5, `${KA.id}@devices.agent-ledger.invalid\n`]) {
    assert.equal(claimedDeviceFromEmail(bad), null);
  }
  void ownA;
});

/* ---------------- B3a: AL-46 / AL-45 / AL-40 / AL-43 ---------------- */

test('AL-46: currentDevices is REQUIRED: undefined / non-string quarantines (malformed-input), null is fine', () => {
  for (const mode of ['warn', 'enforce'] as const) {
    for (const bad of [undefined, 5, {}, [], true]) {
      const v = run(mode, { currentDevices: bad as never });
      assert.equal(v.action, 'quarantine', `${mode} ${String(bad)}`);
      assert.equal(v.rule, 'malformed-input');
    }
    // even a commit that would otherwise be an untouched accept / an unsigned warn
    assert.equal(run(mode, { currentDevices: undefined as never, signature: sig(null) }).rule, 'malformed-input');
    const rest = base({ mode });
    delete (rest as Partial<GateInput>).currentDevices;
    assert.equal(gateCommit(rest).rule, 'malformed-input');
    assert.equal(run(mode, { currentDevices: null }).action, 'accept', 'no registry at the tip: nothing is revoked there');
  }
});

test('AL-46: the commit sha must be a real object id (a D2 halt binds to it)', () => {
  for (const sha of ['', 'xyz', 'A'.repeat(40), 'a'.repeat(39), 5 as never, null as never]) {
    assert.equal(run('enforce', { sha }).rule, 'malformed-input', String(sha));
  }
  assert.equal(run('enforce', { sha: 'a'.repeat(64) }).action, 'accept');
});

test('AL-46: side-branch stolen key — a merge signed by a key revoked at the local tip is quarantined (revoked-current), both modes', () => {
  // the key is active in BOTH parents (a side branch that predates the revocation) and the merge keeps the registry equal
  const PRE = dev(eA(), eB(), eU(), eR({ revoked: null }));
  const TIP = dev(eA(), eB(), eU(), eR());
  const input = (over: Partial<GateInput> = {}): Partial<GateInput> => ({
    parentDevices: [PRE, PRE], devicesText: PRE, signature: sig(KR), currentDevices: TIP, changes: [],
    merge: { baseDevices: PRE, baseCounters: m({}), parentCounters: [m({}), m({})], mergedCounters: m({}), addedVsBoth: [] },
    ...over,
  });
  for (const mode of ['warn', 'enforce'] as const) {
    const v = run(mode, input());
    assert.equal(v.action, 'quarantine');
    assert.equal(v.rule, 'revoked-current');
    assert.equal(run(mode, input({ signature: sig(KB) })).action, 'accept', 'an unrevoked signer is unaffected');
  }
});

test('AL-40 regression: an unsigned or untrusted merge whose devices.yml differs from EITHER parent is quarantined (both modes)', () => {
  const m2 = mergeDevices(MBASE, MP1, MP2);
  assert.ok(m2.ok);
  const mk = (over: Partial<GateInput>): Partial<GateInput> => ({ ...mergeInput(), ...over });
  for (const mode of ['warn', 'enforce'] as const) {
    assert.equal(run(mode, mk({ signature: sig(null) })).rule, 'unsigned-devices');
    assert.equal(run(mode, mk({ signature: sig(KU) })).rule, 'unknown-devices', 'key registered on one side only');
    // registered in BOTH parents but not approved locally
    const q1 = dev(eA(), eB(), eR(), eU());
    const q2 = dev(eA(), eB(), eR(), eU(), eN());
    const qm = mergeDevices(q1, q1, q2);
    assert.ok(qm.ok);
    const unapproved = mk({ parentDevices: [q1, q2], devicesText: qm.ok ? qm.merged : '', signature: sig(KU) });
    unapproved.merge = { ...(unapproved.merge as NonNullable<GateInput['merge']>), baseDevices: q1 };
    assert.equal(run(mode, unapproved).rule, 'unapproved-devices', 'registered but not approved locally');
    assert.equal(run(mode, mk({ signature: sig(KX) })).rule, 'unknown-devices');
    assert.equal(run(mode, mk({ signature: sig(KA, false) })).rule, 'unsigned-devices', 'bad signature');
    // differs from P2 only (M == P1)
    const one = mk({ parentDevices: [MERGED, MP1], devicesText: MERGED, signature: sig(null) });
    one.merge = { ...(one.merge as NonNullable<GateInput['merge']>), baseDevices: MP1 };
    assert.equal(run(mode, one).rule, 'unsigned-devices');
  }
});

test('AL-43: no identifiable owner (unsigned/unknown key, no device e-mail) + counters change or new item -> quarantine unowned, even in warn', () => {
  const cases: [string, Partial<GateInput>][] = [
    ['unsigned counters', { signature: sig(null), changes: [{ path: `counters/${KA.id}.yml`, status: 'M' }] }],
    ['unsigned counters delete', { signature: sig(null), changes: [{ path: `counters/${KB.id}.yml`, status: 'D' }] }],
    ['unsigned new item', { signature: sig(null), changes: [{ path: 'acme/items/ACME-9.md', status: 'A' }] }],
    ['unknown-key counters', { signature: sig(KX), changes: [{ path: `counters/${KA.id}.yml`, status: 'A' }] }],
    ['unknown-key new item', { signature: sig(KX), changes: [{ path: 'acme/items/ACME-B9.md', status: 'A' }] }],
    ['bad signature new item', { signature: sig(KA, false), changes: [{ path: 'acme/items/ACME-9.md', status: 'A' }] }],
  ];
  for (const [name, over] of cases) {
    for (const mode of ['warn', 'enforce'] as const) {
      const v = run(mode, over);
      assert.equal(v.action, 'quarantine', `${name} ${mode}`);
      assert.equal(v.rule, 'unowned', `${name} ${mode}`);
    }
  }
  // unchanged behaviour: modifying an item without an owner is still the ordinary warn/enforce row
  const mod = { signature: sig(null), changes: [{ path: 'acme/items/ACME-1.md', status: 'M' }] };
  assert.equal(run('warn', mod).action, 'accept-warn');
  assert.equal(run('enforce', mod).rule, 'unsigned');
  // an owner (device e-mail naming a registered device) keeps the slot rule instead
  assert.equal(run('warn', { signature: sig(null), claimedDevice: KA.id, changes: [{ path: 'acme/items/ACME-7.md', status: 'A' }] }).action, 'accept-warn');
  assert.equal(run('warn', { signature: sig(null), claimedDevice: KA.id, changes: [{ path: 'acme/items/ACME-B7.md', status: 'A' }] }).rule, 'item-slot');
  // a trusted, registered signer is its own owner
  assert.equal(run('enforce', { changes: [{ path: `counters/${KA.id}.yml`, status: 'M' }, { path: 'acme/items/ACME-7.md', status: 'A' }] }).action, 'accept');
});

test('AL-43: a merge commit that ADDS an item absent from both parents is quarantined (merge-item-new); other additions and a missing input are handled', () => {
  const withAdded = (addedVsBoth: unknown): Partial<GateInput> => {
    const i = mergeInput();
    i.merge = { ...(i.merge as NonNullable<GateInput['merge']>), addedVsBoth: addedVsBoth as readonly string[] };
    return i;
  };
  for (const mode of ['warn', 'enforce'] as const) {
    assert.equal(run(mode, withAdded(['acme/items/ACME-9.md'])).rule, 'merge-item-new');
    assert.equal(run(mode, withAdded(['acme/journal/2026-11.md', 'acme/items/ACME-B3.md'])).rule, 'merge-item-new');
    assert.equal(run(mode, { ...withAdded(['acme/items/ACME-9.md']), signature: sig(KB) }).rule, 'merge-item-new', 'signed by a trusted device too');
    assert.equal(run(mode, withAdded([])).action, 'accept');
    assert.equal(run(mode, withAdded(['acme/journal/2026-11.md', `counters/${KB.id}.yml`])).action, 'accept', 'journal lines / counters are the merger\'s job');
    for (const bad of [undefined, null, 'acme/items/ACME-9.md', {}, [5], [null]]) {
      assert.equal(run(mode, withAdded(bad)).rule, 'merge-input-missing', JSON.stringify(bad));
    }
  }
});

/* D2: confirmation bound to (commit sha, device id); self revocation never accepted */

const ROOT_REVOKE: Partial<GateInput> = ROWS.find((r) => r.row === '7 revokes the root')?.over as Partial<GateInput>;
const SELF_REVOKE: Partial<GateInput> = ROWS.find((r) => r.row === '7 revokes THIS device')?.over as Partial<GateInput>;

test('D2: an unconfirmed root revocation halts with the d2 payload (commit, root ids), both modes', () => {
  for (const mode of ['warn', 'enforce'] as const) {
    const v = run(mode, ROOT_REVOKE);
    assert.equal(v.action, 'halt');
    assert.equal(v.haltReason, 'quarantine:revocation-root');
    assert.deepEqual(v.d2, { kind: 'root', commit: SHA, deviceIds: [KA.id] });
    const s = run(mode, SELF_REVOKE);
    assert.equal(s.haltReason, 'quarantine:revocation-self');
    assert.deepEqual(s.d2, { kind: 'self', commit: SHA, deviceIds: [KB.id] });
  }
});

test('D2: a confirmation for (this commit, the root id) accepts the root revocation as revocation-confirmed', () => {
  for (const mode of ['warn', 'enforce'] as const) {
    const v = run(mode, { ...ROOT_REVOKE, confirmedRevocations: new Set([confirmationKey(SHA, KA.id)]) });
    assert.equal(v.action, 'accept');
    assert.equal(v.rule, 'revocation-confirmed');
    assert.equal(v.haltReason, undefined);
    assert.equal(v.d2, undefined);
    assert.ok(v.notes.some((n) => n.rule === 'revocation-confirmed'));
    // still gated by everything else: the same change from an unsigned commit is a quarantine, confirmed or not
    const unsigned = run(mode, { ...ROOT_REVOKE, signature: sig(null), confirmedRevocations: new Set([confirmationKey(SHA, KA.id)]) });
    assert.equal(unsigned.action, 'quarantine');
    // an invalid devices change by a trusted signer stays refused even with a confirmation
    const bad = run(mode, {
      signature: sig(KB),
      devicesText: dev(eA({ revoked: { at: '2026-11-17T10:00:00.000Z', by: KB.id, reason: 'x' } }), eB(), eU(), eR()), // time-unbound
      confirmedRevocations: new Set([confirmationKey(SHA, KA.id)]),
    });
    assert.equal(bad.rule, 'devices:time-unbound');
  }
});

test('D2: a confirmation for another commit, another id, or nothing never accepts (halt stays)', () => {
  const OTHER = 'b'.repeat(40);
  const sets: [string, ReadonlySet<string>][] = [
    ['other commit', new Set([confirmationKey(OTHER, KA.id)])],
    ['other id', new Set([confirmationKey(SHA, KB.id), confirmationKey(SHA, KU.id)])],
    ['empty', new Set()],
    ['raw sha', new Set([SHA])],
    ['raw id', new Set([KA.id])],
    ['swapped order', new Set([`${KA.id}:${SHA}`])],
  ];
  for (const mode of ['warn', 'enforce'] as const) {
    for (const [name, confirmedRevocations] of sets) {
      const v = run(mode, { ...ROOT_REVOKE, confirmedRevocations });
      assert.equal(v.action, 'halt', `${mode} ${name}`);
      assert.equal(v.haltReason, 'quarantine:revocation-root');
    }
  }
});

test('D2: hostile confirmedRevocations never accepts: missing / junk halts, a throwing set is a quarantine', () => {
  const boom = { has(): never { throw new Error('boom'); } };
  for (const mode of ['warn', 'enforce'] as const) {
    for (const junk of [undefined, null, {}, [confirmationKey(SHA, KA.id)], 'x', 5]) {
      const v = run(mode, { ...ROOT_REVOKE, confirmedRevocations: junk as never });
      assert.equal(v.action, 'halt', `${mode} ${JSON.stringify(junk)}`);
    }
    const t = run(mode, { ...ROOT_REVOKE, confirmedRevocations: boom as never });
    assert.notEqual(t.action, 'accept');
    assert.notEqual(t.action, 'accept-warn');
  }
});

test('D2: revoking THIS device is never accepted from a peer, confirmed or not (the cycle turns a confirmed one into detached)', () => {
  for (const mode of ['warn', 'enforce'] as const) {
    for (const confirmedRevocations of [new Set<string>(), new Set([confirmationKey(SHA, KB.id)]), new Set([confirmationKey(SHA, KB.id), confirmationKey(SHA, KA.id)])]) {
      const v = run(mode, { ...SELF_REVOKE, confirmedRevocations });
      assert.equal(v.action, 'halt');
      assert.equal(v.haltReason, 'quarantine:revocation-self');
      assert.equal(v.rule, 'revocation-self');
    }
  }
  // root AND this device in one commit: self wins, the root confirmation does not help
  const both = {
    devicesText: dev(eA({ revoked: { at: T0, by: KA.id, reason: 'x' } }), eB({ revoked: { at: T0, by: KA.id, reason: 'x' } }), eU(), eR()),
    confirmedRevocations: new Set([confirmationKey(SHA, KA.id), confirmationKey(SHA, KB.id)]),
  };
  for (const mode of ['warn', 'enforce'] as const) {
    const v = run(mode, both);
    assert.equal(v.haltReason, 'quarantine:revocation-self');
    assert.deepEqual(v.d2, { kind: 'self', commit: SHA, deviceIds: [KB.id] });
  }
});

test('D2: a confirmed root revocation together with a non-root, non-local revocation is accepted; confirming only the non-root id is not enough', () => {
  const devicesText = dev(eA({ revoked: { at: T0, by: KB.id, reason: 'x' } }), eB(), eU({ revoked: { at: T0, by: KB.id, reason: 'x' } }), eR());
  for (const mode of ['warn', 'enforce'] as const) {
    const ok = run(mode, { signature: sig(KB), devicesText, confirmedRevocations: new Set([confirmationKey(SHA, KA.id)]) });
    assert.equal(ok.action, 'accept');
    assert.equal(ok.rule, 'revocation-confirmed');
    const no = run(mode, { signature: sig(KB), devicesText, confirmedRevocations: new Set([confirmationKey(SHA, KU.id)]) });
    assert.equal(no.action, 'halt');
    assert.deepEqual(no.d2, { kind: 'root', commit: SHA, deviceIds: [KA.id] });
  }
});

test('gateRange carries the d2 payload of the deciding halt', () => {
  const root = run('enforce', ROOT_REVOKE);
  const ok = run('enforce', {});
  const q = run('enforce', { ingress: rejectedIngress('symlink') });
  const r = gateRange([ok, q, root, ok]);
  assert.equal(r.action, 'halt');
  assert.deepEqual(r.d2, { kind: 'root', commit: SHA, deviceIds: [KA.id] });
  assert.equal(gateRange([ok, q]).d2, undefined);
  // a confirmed root revocation inside a range is an accept
  const confirmed = run('enforce', { ...ROOT_REVOKE, confirmedRevocations: new Set([confirmationKey(SHA, KA.id)]) });
  assert.equal(gateRange([ok, confirmed]).action, 'accept');
});

test('never relaxes: every existing quarantine still quarantines when the new inputs are supplied', () => {
  const confirmed = new Set([confirmationKey(SHA, KA.id), confirmationKey(SHA, KB.id)]);
  for (const r of ROWS.filter((x) => x.warn === 'quarantine' || x.enforce === 'quarantine')) {
    for (const mode of ['warn', 'enforce'] as const) {
      const before = run(mode, r.over);
      const after = run(mode, { ...r.over, confirmedRevocations: confirmed });
      if (before.action === 'quarantine') assert.equal(after.action, 'quarantine', `${r.row} ${mode}`);
    }
  }
});
