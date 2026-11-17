/** F2.2 / F2.3 — devices.yml schema + invariants, allowed_signers format, and the pure
 *  `acceptDevicesChange` rule (T1, T9, T16). No ssh-keygen needed: keys are structurally valid fakes. */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  DEVICES_MAX_ENTRIES,
  DEVICES_TIME_BOUND_MS,
  DEVICE_EMAIL_DOMAIN,
  DevicesError,
  acceptDevicesChange,
  deviceEmail,
  deviceIdFromEmail,
  planAddDevice,
  devicesInvariantProblem,
  safeOutput,
  parseAllowedSigners,
  parseDevicesYaml,
  renderAllowedSigners,
  renderDevicesYaml,
  type DeviceEntry,
  type DevicesFile,
} from './devices.ts';
import { SLOT_LETTERS } from './snowflake.ts';
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

/** Commit time that matches T0 (the timestamp every fixture entry carries). */
const T0_MS = Date.parse(T0);
const AT = { commitTimeMs: T0_MS };

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
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), { ...asB(), pubkey: A.pub }] }), /not derived|duplicate/);
  assert.throws(() => renderDevicesYaml({ devices: [entry(A), { ...entry(A), id: B.id, slot: 'W', added_by: A.id }] }), /not derived/, 'same key under another id');
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
  assert.equal(reason(acceptDevicesChange(base(), incoming, B.pub, trust(A), AT)), 'signer-untrusted');
  // Even if some local approval of B exists, B is not in the current registry.
  assert.equal(reason(acceptDevicesChange(base(), incoming, B.pub, trust(A, B), AT)), 'signer-unregistered');
  // B writes itself in "as its own adder" — fails the file invariants before any trust question.
  const selfAdded: DevicesFile = { devices: [entry(A), entry(B, { slot: 'W' })] };
  assert.equal(reason(acceptDevicesChange(base(), selfAdded, B.pub, trust(A, B), AT)), 'invalid-incoming');
  assert.equal(reason(acceptDevicesChange(base(), incoming, B.pub, trust(), AT)), 'signer-untrusted');
  assert.equal(reason(acceptDevicesChange(base(), incoming, 'ssh-ed25519 AAAA', trust(A), AT)), 'signer-invalid');
});

test('trusted signer may add a device whose id derives from its own key', () => {
  const incoming: DevicesFile = { devices: [entry(A), asB()] };
  assert.equal(reason(acceptDevicesChange(base(), incoming, A.pub, trust(A), AT)), 'ok:update');
  assert.equal(reason(acceptDevicesChange(base(), base(), A.pub, trust(A), AT)), 'ok:noop');
  // id squatting: an id that is not sha256(pubkey)
  assert.equal(reason(acceptDevicesChange(base(), { devices: [entry(A), { ...asB(), id: C.id }] }, A.pub, trust(A), AT)), 'invalid-incoming');
  // added_by must be the signer, not another registered device
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const withC: DevicesFile = { devices: [entry(A), asB(), entry(C, { slot: 'V', added_by: B.id })] };
  assert.equal(reason(acceptDevicesChange(two, withC, A.pub, trust(A), AT)), 'added-by-mismatch');
  assert.equal(reason(acceptDevicesChange(base(), { devices: [entry(A), { ...asB(), revoked: { at: T0, by: A.id, reason: 'x' } }] }, A.pub, trust(A), AT)), 'new-entry-revoked');
});

test('T9/T16: other devices\' keys and identity fields cannot be changed; entries cannot vanish', () => {
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const swap: DevicesFile = { devices: [entry(A), { ...asB(), pubkey: C.pub }] };
  assert.equal(reason(acceptDevicesChange(two, swap, A.pub, trust(A), AT)), 'invalid-incoming', 'key swap breaks id ↔ key derivation');
  const reslot: DevicesFile = { devices: [entry(A), { ...asB(), slot: 'X' }] };
  assert.equal(reason(acceptDevicesChange(two, reslot, A.pub, trust(A), AT)), 'entry-modified');
  assert.equal(reason(acceptDevicesChange(two, base(), A.pub, trust(A), AT)), 'entry-removed');
  // overwriting the primary's own key is the same attack
  const rotate: DevicesFile = { devices: [entry(A, { pubkey: C.pub }), asB()] };
  assert.equal(reason(acceptDevicesChange(two, rotate, A.pub, trust(A), AT)), 'invalid-incoming');
});

test('T1/T9: revocation is monotonic; revoked signer is dead; a retired slot is never re-issued', () => {
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const rev = { at: T0, by: A.id, reason: 'lost phone' };
  const revoked: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }] };
  assert.equal(reason(acceptDevicesChange(two, revoked, A.pub, trust(A), AT)), 'ok:update');
  // un-revoke
  assert.equal(reason(acceptDevicesChange(revoked, two, A.pub, trust(A), AT)), 'unrevoke');
  // rewrite the record (hide the reason)
  const edited: DevicesFile = { devices: [entry(A), { ...asB(), revoked: { ...rev, reason: 'oops' } }] };
  assert.equal(reason(acceptDevicesChange(revoked, edited, A.pub, trust(A), AT)), 'entry-modified');
  // revoked.by must be the signer
  const forged: DevicesFile = { devices: [entry(A), { ...asB(), revoked: { ...rev, by: B.id } }] };
  assert.equal(reason(acceptDevicesChange(two, forged, A.pub, trust(A), AT)), 'revoke-invalid');
  // the revoked device's later commits, even if its key is still in a stale allowed_signers
  const next: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }, entry(C, { slot: 'V', added_by: B.id })] };
  assert.equal(reason(acceptDevicesChange(revoked, next, B.pub, trust(A, B), AT)), 'signer-revoked');
  // slot W is retired: a new device cannot take it
  const reuse: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }, entry(C, { slot: 'W', added_by: A.id })] };
  assert.equal(reason(acceptDevicesChange(revoked, reuse, A.pub, trust(A), AT)), 'invalid-incoming');
  // the revoked key cannot come back under a new id either
  const again: DevicesFile = { devices: [entry(A), { ...asB(), revoked: rev }, { ...entry(C, { slot: 'V', added_by: A.id }), pubkey: B.pub }] };
  assert.equal(reason(acceptDevicesChange(revoked, again, A.pub, trust(A), AT)), 'invalid-incoming');
});

test('invalid base / incoming are rejected, not trusted', () => {
  const bad = { devices: [entry(A), entry(A)] } as DevicesFile;
  assert.equal(reason(acceptDevicesChange(bad, base(), A.pub, trust(A), AT)), 'invalid-base');
  assert.equal(reason(acceptDevicesChange(base(), bad, A.pub, trust(A), AT)), 'invalid-incoming');
});

/* ---------------- B0a: DK-1 / DK-2 / DK-4 / DK-7, D2 ---------------- */

test('DK-1/DK-7: every id (root included) must be sha256(pubkey); a squatted or random id is invalid', () => {
  assert.equal(devicesInvariantProblem(base()), null);
  assert.match(devicesInvariantProblem({ devices: [entry(A, { id: C.id })] }) ?? '', /not derived/, 'root with a foreign id');
  assert.match(devicesInvariantProblem({ devices: [entry(A, { id: 'd_abcdefghij' })] }) ?? '', /not derived/, 'F1 random root id');
  assert.throws(() => renderDevicesYaml({ devices: [entry(A, { id: 'd_abcdefghij' })] }), /not derived/);
  const yaml = renderDevicesYaml(base()).split(A.id).join('d_abcdefghij');
  assert.throws(() => parseDevicesYaml(yaml), /not derived/);
  // a peer cannot slip a squatted id in through acceptDevicesChange either
  assert.equal(reason(acceptDevicesChange(base(), { devices: [entry(A), { ...asB(), id: C.id }] }, A.pub, trust(A), AT)), 'invalid-incoming');
});

test('DK-4: pubkey is valid only when it is byte-for-byte the canonical line', () => {
  const ok = renderDevicesYaml(base());
  for (const bad of [
    `${A.pub} `, // trailing space
    `${A.pub}  `,
    ` ${A.pub}`, // leading space
    `${A.pub}\n`, // trailing newline (YAML double quoted)
    `${A.pub}\t`,
    `${A.pub} comment`,
    `${A.pub}\u0000`,
    A.pub.replace('ssh-ed25519', 'ssh-ed25519 '), // double space
    A.pub.replace('ssh-ed25519', 'SSH-ED25519'),
  ]) {
    const text = ok.replace(`pubkey: ${A.pub}`, `pubkey: ${JSON.stringify(bad)}`);
    assert.notEqual(text, ok);
    assert.throws(() => parseDevicesYaml(text), DevicesError, JSON.stringify(bad));
    assert.throws(() => renderDevicesYaml({ devices: [entry(A, { pubkey: bad })] }), DevicesError);
  }
  assert.ok(parseDevicesYaml(ok));
});

test('DK-2: schema errors are fixed codes + field path; hostile YAML (ANSI, bidi, newline) never reaches the message', () => {
  const ESC = '\u001b';
  const hostile = `${ESC}[31mPWNED${ESC}[0m ‮evil‬​`;
  const cases: string[] = [
    // value in a typed field
    renderDevicesYaml(base()).replace('label: mac', `label: ${JSON.stringify(hostile)}`),
    renderDevicesYaml(base()).replace(`id: ${A.id}`, `id: ${JSON.stringify(hostile)}`),
    renderDevicesYaml(base()).replace(`pubkey: ${A.pub}`, `pubkey: ${JSON.stringify(hostile)}`),
    renderDevicesYaml(base()).replace('role: owner', `role: ${JSON.stringify(hostile)}`),
    // hostile key NAME (strict object)
    renderDevicesYaml(base()).replace('role: owner', `role: owner\n    ${JSON.stringify(hostile)}: 1`),
    `devices:\n  - ${JSON.stringify(hostile)}\n`,
    `${JSON.stringify(hostile)}: 1\n`,
  ];
  for (const text of cases) {
    let msg = '';
    try {
      parseDevicesYaml(text);
    } catch (err) {
      assert.ok(err instanceof DevicesError);
      msg = err.message;
    }
    assert.notEqual(msg, '', 'must be refused');
    assert.match(msg, /^devices\.yml: invalid field [A-Za-z0-9_.()[\]? -]+$/, msg);
    assert.ok(!msg.includes('PWNED') && !msg.includes(ESC) && !/[‪-‮​\n\r]/.test(msg), 'no input bytes in the message');
    assert.equal(safeOutput(msg), msg, 'already clean');
  }
  // path is precise
  assert.throws(
    () => parseDevicesYaml(renderDevicesYaml({ devices: [entry(A), asB()] }).replace('slot: W', 'slot: Z9')),
    /^DevicesError: devices\.yml: invalid field devices\[1\]\.slot \(format\)$|invalid field devices\[1\]\.slot/,
  );
  // invariant problems carry only schema-validated tokens
  assert.throws(() => parseDevicesYaml(renderDevicesYaml(base()).replace(`added_by: ${A.id}`, `added_by: ${B.id}`)), /slot ""/);
});

test('DK-2: safeOutput strips CSI/OSC sequences, control, bidi and zero-width characters, and stays on one line', () => {
  const ESC = '\u001b';
  assert.equal(safeOutput(`a${ESC}[31;1mred${ESC}[0m b`), 'ared b');
  assert.equal(safeOutput(`x${ESC}]0;title\u0007y`), 'xy', 'OSC window-title');
  assert.equal(safeOutput(`x${ESC}]8;;http://evil\u001b\\link${ESC}]8;;\u001b\\`), 'xlink', 'OSC-8 hyperlink');
  assert.equal(safeOutput('ab‮cd⁦ef​﻿g'), 'abcdefg', 'bidi / zero-width');
  assert.equal(safeOutput('l1\nl2\r\nl3 l4'), 'l1 l2 l3 l4');
  assert.equal(safeOutput('a\u0007b\u009bc\u007f'), 'abc');
  assert.equal(safeOutput('x'.repeat(1000), 50).length, 50);
  assert.equal(safeOutput(''), '');
  assert.equal(safeOutput(safeOutput(`${ESC}[1m‮z`)), 'z', 'idempotent');
});

/* ---- D2 ---- */

const REV = (by: string, at = T0): { at: string; by: string; reason: string } => ({ at, by, reason: 'lost' });
const iso = (ms: number): string => new Date(ms).toISOString();

test('D2: accepted changes classify what they revoke (root flag + sorted ids)', () => {
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const r1 = acceptDevicesChange(two, { devices: [entry(A), { ...asB(), revoked: REV(A.id) }] }, A.pub, trust(A), AT);
  assert.deepEqual(r1.ok && r1.revokes, { root: false, ids: [B.id] });
  // B (registered, trusted) revokes the root A
  const r2 = acceptDevicesChange(two, { devices: [entry(A, { revoked: REV(B.id) }), asB()] }, B.pub, trust(A, B), AT);
  assert.deepEqual(r2.ok && r2.revokes, { root: true, ids: [A.id] });
  // self revocation by the signer is classified too (the caller decides about "local device")
  const r3 = acceptDevicesChange(two, { devices: [entry(A), { ...asB(), revoked: REV(B.id) }] }, B.pub, trust(A, B), AT);
  assert.deepEqual(r3.ok && r3.revokes, { root: false, ids: [B.id] });
  // plain add / noop / root revoke nothing
  assert.deepEqual(acceptDevicesChange(base(), { devices: [entry(A), asB()] }, A.pub, trust(A), AT).ok && true, true);
  const add = acceptDevicesChange(base(), { devices: [entry(A), asB()] }, A.pub, trust(A), AT);
  assert.deepEqual(add.ok && add.revokes, { root: false, ids: [] });
  const noop = acceptDevicesChange(two, two, A.pub, trust(A), {});
  assert.deepEqual(noop.ok && noop.kind, 'noop', 'a no-change file needs no commit time');
  const root = acceptDevicesChange(null, base(), A.pub, trust(), { allowRoot: true });
  assert.deepEqual(root.ok && root.revokes, { root: false, ids: [] });
  // already-revoked entries are not "newly" revoked again
  const revoked: DevicesFile = { devices: [entry(A), { ...asB(), revoked: REV(A.id) }] };
  const again = acceptDevicesChange(revoked, revoked, A.pub, trust(A), {});
  assert.deepEqual(again.ok && again.revokes, { root: false, ids: [] });
});

test('D2/S21: added and revoked.at are bound to the commit time (±15 min), backdated or future → time-unbound', () => {
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const win = DEVICES_TIME_BOUND_MS;
  const addAt = (ms: number): DevicesFile => ({ devices: [entry(A), asB(), entry(C, { slot: 'V', added_by: A.id, added: iso(ms) })] });
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS), A.pub, trust(A), AT)), 'ok:update');
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS + win), A.pub, trust(A), AT)), 'ok:update', 'edge inclusive');
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS - win), A.pub, trust(A), AT)), 'ok:update');
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS + win + 1000), A.pub, trust(A), AT)), 'time-unbound', 'future');
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS - win - 1000), A.pub, trust(A), AT)), 'time-unbound', 'backdated');
  // revocation record
  const revAt = (ms: number): DevicesFile => ({ devices: [entry(A), { ...asB(), revoked: REV(A.id, iso(ms)) }] });
  assert.equal(reason(acceptDevicesChange(two, revAt(T0_MS), A.pub, trust(A), AT)), 'ok:update');
  assert.equal(reason(acceptDevicesChange(two, revAt(T0_MS - 3 * win), A.pub, trust(A), AT)), 'time-unbound', 'backdated revocation');
  assert.equal(reason(acceptDevicesChange(two, revAt(T0_MS + 3 * win), A.pub, trust(A), AT)), 'time-unbound', 'future revocation');
  // fail closed: no / invalid commit time on a change that needs one
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS), A.pub, trust(A))), 'time-unbound');
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS), A.pub, trust(A), { commitTimeMs: Number.NaN })), 'time-unbound');
  assert.equal(reason(acceptDevicesChange(two, revAt(T0_MS), A.pub, trust(A), { commitTimeMs: Number.POSITIVE_INFINITY })), 'time-unbound');
  // the local clock plays no role: a commit time of "now" does not rescue a year-old `added`
  assert.equal(reason(acceptDevicesChange(two, addAt(T0_MS), A.pub, trust(A), { commitTimeMs: Date.now() })), 'time-unbound');
  // the new device is still checked for the other rules first/after
  assert.equal(reason(acceptDevicesChange(two, revAt(T0_MS), B.pub, trust(A, B), AT)), 'revoke-invalid', 'by must be the signer');
});

test('D2/F-11: last_seen may change only on the signer\'s own entry; a new entry cannot carry one', () => {
  const two: DevicesFile = { devices: [entry(A), asB()] };
  const seen = iso(T0_MS + 60_000);
  // A touches its own → ok; A touches B's → rejected; B touches own → ok; B touches A's → rejected
  assert.equal(reason(acceptDevicesChange(two, { devices: [entry(A, { last_seen: seen }), asB()] }, A.pub, trust(A), AT)), 'ok:update');
  assert.equal(reason(acceptDevicesChange(two, { devices: [entry(A), { ...asB(), last_seen: seen }] }, A.pub, trust(A), AT)), 'last-seen-foreign');
  assert.equal(reason(acceptDevicesChange(two, { devices: [entry(A), { ...asB(), last_seen: seen }] }, B.pub, trust(A, B), AT)), 'ok:update');
  assert.equal(reason(acceptDevicesChange(two, { devices: [entry(A, { last_seen: seen }), asB()] }, B.pub, trust(A, B), AT)), 'last-seen-foreign');
  // removing / rewinding another device's last_seen is just as foreign
  const withSeen: DevicesFile = { devices: [entry(A), { ...asB(), last_seen: seen }] };
  assert.equal(reason(acceptDevicesChange(withSeen, two, A.pub, trust(A), AT)), 'last-seen-foreign');
  assert.equal(reason(acceptDevicesChange(withSeen, { devices: [entry(A), { ...asB(), last_seen: iso(T0_MS) }] }, A.pub, trust(A), AT)), 'last-seen-foreign');
  // a brand-new entry cannot be introduced with a last_seen
  const newWithSeen: DevicesFile = { devices: [entry(A), asB(), entry(C, { slot: 'V', added_by: A.id, last_seen: seen })] };
  assert.equal(reason(acceptDevicesChange(two, newWithSeen, A.pub, trust(A), AT)), 'last-seen-foreign');
  // a root claiming a last_seen is not a plain root
  assert.equal(reason(acceptDevicesChange(null, { devices: [entry(A, { last_seen: seen })] }, A.pub, trust(), { allowRoot: true })), 'bad-root');
  // unchanged last_seen of others is fine
  assert.equal(reason(acceptDevicesChange(withSeen, withSeen, A.pub, trust(A), AT)), 'ok:noop');
});

test('D2: root with a commit time is bound too; without one (local init) it is accepted', () => {
  assert.equal(reason(acceptDevicesChange(null, base(), A.pub, trust(), { allowRoot: true, commitTimeMs: T0_MS })), 'ok:root');
  assert.equal(reason(acceptDevicesChange(null, base(), A.pub, trust(), { allowRoot: true, commitTimeMs: T0_MS + 2 * DEVICES_TIME_BOUND_MS })), 'time-unbound');
});

/* ---------------- B4a: deviceEmail, planAddDevice ---------------- */

test('deviceEmail / deviceIdFromEmail: one producer, one strict parser, fixed domain', () => {
  assert.equal(DEVICE_EMAIL_DOMAIN, 'devices.agent-ledger.invalid');
  assert.equal(deviceEmail(A.id), `${A.id}@devices.agent-ledger.invalid`);
  assert.equal(deviceIdFromEmail(deviceEmail(A.id)), A.id);
  for (const bad of ['', 'd_short', 'D_ABCDEFGHIJ', `${A.id}\n`, 'x@y', `${A.id}@evil.invalid`, `${A.id.toUpperCase()}`, 'd_abcdefghi1', `../${A.id}`, 5, null, undefined]) {
    assert.throws(() => deviceEmail(bad as string), (e: unknown) => e instanceof DevicesError && e.code === 'ID_INVALID', String(bad));
  }
  for (const bad of [
    `${A.id}@devices.agent-ledger.invalid.evil`, `x${A.id}@devices.agent-ledger.invalid`, ` ${A.id}@devices.agent-ledger.invalid`,
    `${A.id}@devices.agent-ledger.invalid\n`, `${A.id}@devicesXagent-ledger.invalid`, `${A.id}@DEVICES.agent-ledger.invalid`,
    `${A.id}@devices.agent-ledger.invalid>`, 'd_abcdefghi1@devices.agent-ledger.invalid', '', null, 5, {}, undefined,
  ]) {
    assert.equal(deviceIdFromEmail(bad), null, String(bad));
  }
});

test('planAddDevice: pure; lowest never-used slot; retired slots stay retired; `added` is the given commit time', () => {
  const root = base();
  const frozen = JSON.stringify(root);
  const p1 = planAddDevice(root, A.id, parseEd25519Pub(B.pub) as NonNullable<ReturnType<typeof parseEd25519Pub>>, 'win', T0_MS);
  assert.equal(JSON.stringify(root), frozen, 'input is not mutated');
  assert.equal(p1.entry.slot, SLOT_LETTERS[0]);
  assert.equal(p1.entry.id, B.id);
  assert.equal(p1.entry.added, T0);
  assert.equal(p1.entry.added_by, A.id);
  assert.equal(p1.entry.revoked, null);
  assert.equal(p1.entry.role, 'owner');
  assert.deepEqual(p1.next.devices, [...root.devices, p1.entry]);
  assert.equal(devicesInvariantProblem(p1.next), null);
  assert.equal(reason(acceptDevicesChange(root, p1.next, A.pub, trust(A), AT)), 'ok:update', 'a peer accepts exactly this change');
  // a revoked entry keeps its slot forever: the next device gets the next letter
  const withRevoked: DevicesFile = {
    devices: [entry(A), { ...p1.entry, revoked: { at: T0, by: A.id, reason: 'lost' } }],
  };
  const p2 = planAddDevice(withRevoked, A.id, parseEd25519Pub(C.pub) as NonNullable<ReturnType<typeof parseEd25519Pub>>, 'tab', T0_MS);
  assert.equal(p2.entry.slot, SLOT_LETTERS[1]);
  // same input, same output
  assert.deepEqual(planAddDevice(root, A.id, parseEd25519Pub(B.pub) as NonNullable<ReturnType<typeof parseEd25519Pub>>, 'win', T0_MS), p1);
});

test('planAddDevice: DEVICE_EXISTS (id or key), SLOTS_EXHAUSTED, LABEL_INVALID, bad time', () => {
  const pubB = parseEd25519Pub(B.pub) as NonNullable<ReturnType<typeof parseEd25519Pub>>;
  const err = (c: string) => (e: unknown): boolean => e instanceof DevicesError && e.code === c;
  assert.throws(() => planAddDevice(base(), A.id, parseEd25519Pub(A.pub) as typeof pubB, 'x', T0_MS), err('DEVICE_EXISTS'));
  assert.throws(() => planAddDevice({ devices: [entry(A), asB()] }, A.id, pubB, 'again', T0_MS), err('DEVICE_EXISTS'));
  for (const label of ['', 'Upper', 'has space', '-lead', 'a'.repeat(33), 'x\ny', 'ünï']) {
    assert.throws(() => planAddDevice(base(), A.id, pubB, label, T0_MS), err('LABEL_INVALID'), JSON.stringify(label));
  }
  const full: DeviceEntry[] = [entry(A)];
  for (const slot of SLOT_LETTERS) {
    const k = fakeKey();
    full.push(entry(k, { slot, label: `d-${slot.toLowerCase()}`, added_by: A.id }));
  }
  assert.equal(devicesInvariantProblem({ devices: full }), null);
  assert.throws(() => planAddDevice({ devices: full }, A.id, pubB, 'late', T0_MS), err('SLOTS_EXHAUSTED'));
  assert.throws(() => planAddDevice(base(), A.id, pubB, 'win', Number.NaN), err('ADD_REFUSED'));
});
