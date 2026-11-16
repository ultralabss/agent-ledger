/** F2.2 / F2.3 — devices.yml schema + invariants, allowed_signers format, and the pure
 *  `acceptDevicesChange` rule (T1, T9, T16). No ssh-keygen needed: keys are structurally valid fakes. */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  DEVICES_MAX_ENTRIES,
  DevicesError,
  acceptDevicesChange,
  parseAllowedSigners,
  parseDevicesYaml,
  renderAllowedSigners,
  renderDevicesYaml,
  type DeviceEntry,
  type DevicesFile,
} from './devices.ts';
import { parseEd25519Pub } from './sshkey.ts';

const WIRE = Buffer.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32]);

function fakeKey(): { pub: string; id: string } {
  const pub = `ssh-ed25519 ${Buffer.concat([WIRE, randomBytes(32)]).toString('base64')}`;
  const parsed = parseEd25519Pub(pub);
  assert.ok(parsed);
  return { pub, id: parsed.deviceId };
}

const T0 = '2026-11-16T10:00:00.000Z';

function entry(k: { pub: string; id: string }, over: Partial<DeviceEntry> = {}): DeviceEntry {
  return {
    id: k.id, label: 'mac', slot: '', pubkey: k.pub, added: T0, added_by: k.id, revoked: null, role: 'owner',
    ...over,
  };
}

const A = fakeKey();
const B = fakeKey();
const C = fakeKey();
const base = (): DevicesFile => ({ devices: [entry(A)] });
const asB = (): DeviceEntry => entry(B, { slot: 'W', label: 'win', added_by: A.id });
const trust = (...keys: { pub: string }[]): Set<string> => new Set(keys.map((k) => k.pub));

function reason(r: ReturnType<typeof acceptDevicesChange>): string {
  return r.ok ? `ok:${r.kind}` : r.reason;
}

/* ---------------- schema + invariants ---------------- */

test('devices.yml: round trip, strict fields, size cap, no aliases', () => {
  const file: DevicesFile = { devices: [entry(A), asB()] };
  assert.deepEqual(parseDevicesYaml(renderDevicesYaml(file)), file);
  assert.throws(() => parseDevicesYaml('devices:\n  - {id: x}\n'), DevicesError);
  const extra = renderDevicesYaml(file).replace('role: owner', 'role: owner\n    sudo: true');
  assert.throws(() => parseDevicesYaml(extra), DevicesError, 'unknown field');
  assert.throws(() => parseDevicesYaml(`devices: []\n# ${'x'.repeat(70_000)}`), /exceeds/);
  assert.deepEqual(parseDevicesYaml(''), { devices: [] });
  assert.throws(() => parseDevicesYaml('devices: &a []\nmore: *a\n'), DevicesError);
});

test('devices.yml: pubkey must be canonical (no options/comment), role owner only, ids allowlisted', () => {
  const ok = renderDevicesYaml(base());
  assert.throws(() => parseDevicesYaml(ok.replace(A.pub, `command="x" ${A.pub}`)), DevicesError);
  assert.throws(() => parseDevicesYaml(ok.replace(A.pub, `${A.pub} laptop`)), DevicesError);
  assert.throws(() => parseDevicesYaml(ok.replace('role: owner', 'role: member')), DevicesError);
  assert.throws(() => parseDevicesYaml(ok.split(A.id).join('d_../../etc')), DevicesError);
  assert.throws(() => parseDevicesYaml(renderDevicesYaml({ devices: [entry(A), asB()] }).replace('slot: W', 'slot: I')), DevicesError, 'I/O are not slot letters');
});

test('devices.yml: duplicate id / slot / pubkey and misplaced primary are refused', () => {
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), entry(A)] }), /duplicate/);
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), { ...asB(), slot: '' }] }), /slot ""/);
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), { ...asB(), pubkey: A.pub }] }), /duplicate/);
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), asB(), { ...entry(C), slot: 'W', added_by: A.id }] }), /duplicate slot/);
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), entry(B, { slot: 'W' })] }), /registered itself/, 'self-added non-root');
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), { ...asB(), added_by: C.id }] }), /not in the file/);
  const many = Array.from({ length: DEVICES_MAX_ENTRIES + 1 }, () => entry(fakeKey()));
  assert.throws(() => renderDevicesYaml({ devices: many }), Error);
});

test('revoke reason: single line, bounded', () => {
  const rev = (reason: string): DevicesFile => ({
    devices: [entry(A), { ...asB(), revoked: { at: T0, by: A.id, reason } }],
  });
  assert.ok(renderDevicesYaml(rev('lost phone')));
  assert.throws(() => renderDevicesYaml(rev('a\nb')), Error);
  assert.throws(() => renderDevicesYaml(rev('')), Error);
  assert.throws(() => renderDevicesYaml(rev('x'.repeat(201))), Error);
});

/* ---------------- allowed_signers ---------------- */

test('allowed_signers: exact format, strict parse, no silent drop of odd lines', () => {
  const text = renderAllowedSigners([{ id: B.id, pubkey: B.pub }, { id: A.id, pubkey: A.pub }]);
  const [first] = text.split('\n');
  assert.match(first ?? '', /^d_[a-z2-7]{10} namespaces="agent-ledger-v1,git" ssh-ed25519 [A-Za-z0-9+/]{68}$/);
  assert.deepEqual(parseAllowedSigners(text).map((s) => s.id).sort(), [A.id, B.id].sort());
  assert.equal(renderAllowedSigners([]), '');
  assert.deepEqual(parseAllowedSigners(''), []);
  for (const bad of [
    `${A.id} cert-authority namespaces="agent-ledger-v1,git" ${A.pub}\n`,
    `${A.id} namespaces="*" ${A.pub}\n`,
    `* namespaces="agent-ledger-v1,git" ${A.pub}\n`,
    `${A.id} namespaces="agent-ledger-v1,git" ${A.pub} extra\n`,
    `${text}${text}`,
  ]) assert.throws(() => parseAllowedSigners(bad), DevicesError, bad.slice(0, 40));
  assert.throws(() => renderAllowedSigners([{ id: '../x', pubkey: A.pub }]), DevicesError);
  assert.throws(() => renderAllowedSigners([{ id: A.id, pubkey: `${A.pub} c` }]), DevicesError);
});

/* ---------------- acceptDevicesChange ---------------- */

test('accept: a peer file is never a root; the local root needs allowRoot and a self-signed single primary', () => {
  assert.equal(reason(acceptDevicesChange(null, base(), A.pub, trust(A))), 'no-root');
  assert.equal(reason(acceptDevicesChange(null, base(), A.pub, trust(), { allowRoot: true })), 'ok:root');
  assert.equal(reason(acceptDevicesChange(null, base(), B.pub, trust(), { allowRoot: true })), 'bad-root', 'signed by someone else');
  assert.equal(reason(acceptDevicesChange(null, { devices: [entry(A), asB()] }, A.pub, trust(), { allowRoot: true })), 'bad-root', 'two entries');
  assert.equal(reason(acceptDevicesChange(null, { devices: [entry(A, { slot: 'W', added_by: B.id })] }, A.pub, trust(), { allowRoot: true })), 'invalid-incoming');
});

test('T16: self-signed addition is rejected (signer not approved), also when its key is trusted but unregistered', () => {
  const incoming: DevicesFile = { devices: [entry(A), asB()] };
  // B signs the commit that adds B.
  assert.equal(reason(acceptDevicesChange(base(), incoming, B.pub, trust(A))), 'signer-untrusted');
  // Even if some local approval of B exists, B is not in the current registry.
  assert.equal(reason(acceptDevicesChange(base(), incoming, B.pub, trust(A, B))), 'signer-unregistered');
  // B writes itself in "as its own adder" — fails the file invariants before any trust question.
  const selfAdded: DevicesFile = { devices: [entry(A), entry(B, { slot: 'W' })] };
  assert.equal(reason(acceptDevicesChange(base(), selfAdded, B.pub, trust(A, B))), 'invalid-incoming');
  assert.equal(reason(acceptDevicesChange(base(), incoming, B.pub, trust())), 'signer-untrusted');
  assert.equal(reason(acceptDevicesChange(base(), incoming, 'ssh-ed25519 AAAA', trust(A))), 'signer-invalid');
});

test('trusted signer may add a device whose id derives from its own key', () => {
  const incoming: DevicesFile = { devices: [entry(A), asB()] };
  assert.equal(reason(acceptDevicesChange(base(), incoming, A.pub, trust(A))), 'ok:update');
  assert.equal(reason(acceptDevicesChange(base(), base(), A.pub, trust(A))), 'ok:noop');
  // id squatting: an id that is not sha256(pubkey)
  assert.equal(reason(acceptDevicesChange(base(), { devices: [entry(A), { ...asB(), id: C.id }] }, A.pub, trust(A))), 'id-not-derived');
  // added_by must be the signer, not another registered device
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const withC: DevicesFile = { devices: [entry(A), asB(), entry(C, { slot: 'V', added_by: B.id })] };
  assert.equal(reason(acceptDevicesChange(two, withC, A.pub, trust(A))), 'added-by-mismatch');
  assert.equal(reason(acceptDevicesChange(base(), { devices: [entry(A), { ...asB(), revoked: { at: T0, by: A.id, reason: 'x' } }] }, A.pub, trust(A))), 'new-entry-revoked');
});

test('T9/T16: other devices\' keys and identity fields cannot be changed; entries cannot vanish', () => {
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const swap: DevicesFile = { devices: [entry(A), { ...asB(), pubkey: C.pub }] };
  assert.equal(reason(acceptDevicesChange(two, swap, A.pub, trust(A))), 'entry-modified');
  const reslot: DevicesFile = { devices: [entry(A), { ...asB(), slot: 'X' }] };
  assert.equal(reason(acceptDevicesChange(two, reslot, A.pub, trust(A))), 'entry-modified');
  assert.equal(reason(acceptDevicesChange(two, base(), A.pub, trust(A))), 'entry-removed');
  // overwriting the primary's own key is the same attack
  const rotate: DevicesFile = { devices: [entry(A, { pubkey: C.pub }), asB()] };
  assert.equal(reason(acceptDevicesChange(two, rotate, A.pub, trust(A))), 'entry-modified');
});

test('T1/T9: revocation is monotonic; revoked signer is dead; a retired slot is never re-issued', () => {
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const rev = { at: T0, by: A.id, reason: 'lost phone' };
  const revoked: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }] };
  assert.equal(reason(acceptDevicesChange(two, revoked, A.pub, trust(A))), 'ok:update');
  // un-revoke
  assert.equal(reason(acceptDevicesChange(revoked, two, A.pub, trust(A))), 'unrevoke');
  // rewrite the record (hide the reason)
  const edited: DevicesFile = { devices: [entry(A), { ...asB(), revoked: { ...rev, reason: 'oops' } }] };
  assert.equal(reason(acceptDevicesChange(revoked, edited, A.pub, trust(A))), 'entry-modified');
  // revoked.by must be the signer
  const forged: DevicesFile = { devices: [entry(A), { ...asB(), revoked: { ...rev, by: B.id } }] };
  assert.equal(reason(acceptDevicesChange(two, forged, A.pub, trust(A))), 'revoke-invalid');
  // the revoked device's later commits, even if its key is still in a stale allowed_signers
  const next: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }, entry(C, { slot: 'V', added_by: B.id })] };
  assert.equal(reason(acceptDevicesChange(revoked, next, B.pub, trust(A, B))), 'signer-revoked');
  // slot W is retired: a new device cannot take it
  const reuse: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }, entry(C, { slot: 'W', added_by: A.id })] };
  assert.equal(reason(acceptDevicesChange(revoked, reuse, A.pub, trust(A))), 'invalid-incoming');
  // the revoked key cannot come back under a new id either
  const again: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }, { ...entry(C, { slot: 'V', added_by: A.id }), pubkey: B.pub }] };
  assert.equal(reason(acceptDevicesChange(revoked, again, A.pub, trust(A))), 'invalid-incoming');
});

test('invalid base / incoming are rejected, not trusted', () => {
  const bad = { devices: [entry(A), entry(A)] } as DevicesFile;
  assert.equal(reason(acceptDevicesChange(bad, base(), A.pub, trust(A))), 'invalid-base');
  assert.equal(reason(acceptDevicesChange(base(), bad, A.pub, trust(A))), 'invalid-incoming');
});
