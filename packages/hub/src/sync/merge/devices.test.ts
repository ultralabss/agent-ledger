import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  parseDevicesYaml,
  parseEd25519Pub,
  renderDevicesYaml,
  type DeviceEntry,
  type DevicesFile,
} from '@agent-ledger/shared';
import { mergeDevices, mergeDevicesNullable } from './devices.ts';
import { rng } from './testkit.ts';

const WIRE = Buffer.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32]);
export function fakeKey(): { pub: string; id: string } {
  const pub = `ssh-ed25519 ${Buffer.concat([WIRE, randomBytes(32)]).toString('base64')}`;
  const parsed = parseEd25519Pub(pub);
  assert.ok(parsed);
  return { pub, id: parsed.deviceId };
}
type K = ReturnType<typeof fakeKey>;

const T0 = '2026-11-16T10:00:00.000Z';
const ent = (k: K, over: Partial<DeviceEntry> = {}): DeviceEntry => ({
  id: k.id, label: 'mac', slot: '', pubkey: k.pub, added: T0, added_by: k.id, revoked: null, role: 'owner', ...over,
});
const A = fakeKey();
const B = fakeKey();
const C = fakeKey();
const D = fakeKey();
const eA = (over: Partial<DeviceEntry> = {}): DeviceEntry => ent(A, over);
const eB = (over: Partial<DeviceEntry> = {}): DeviceEntry => ent(B, { slot: 'B', label: 'b', added_by: A.id, ...over });
const eC = (over: Partial<DeviceEntry> = {}): DeviceEntry => ent(C, { slot: 'C', label: 'c', added_by: A.id, ...over });
const eD = (over: Partial<DeviceEntry> = {}): DeviceEntry => ent(D, { slot: 'D', label: 'd', added_by: A.id, ...over });
const text = (...d: DeviceEntry[]): string => renderDevicesYaml({ devices: d });
const rev = (at: string, by = A.id, reason = 'lost'): DeviceEntry['revoked'] => ({ at, by, reason });

function ok(base: string | null, o: string, t: string): string {
  const r = mergeDevices(base, o, t);
  assert.ok(r.ok, r.ok ? '' : r.detail);
  return r.merged;
}
const files = (s: string): DevicesFile => parseDevicesYaml(s);

test('additions on both sides: union, sorted by slot, side independent', () => {
  const base = text(eA());
  const o = text(eA(), eB());
  const t = text(eA(), eC());
  const m = ok(base, o, t);
  assert.deepEqual(files(m).devices.map((d) => d.slot), ['', 'B', 'C']);
  assert.equal(ok(base, t, o), m);
  assert.ok(!m.includes('\r'));
});

test('no-op side: other side verbatim; identical sides verbatim', () => {
  const base = text(eA());
  const o = text(eA(), eB());
  assert.equal(ok(base, base, o), o);
  assert.equal(ok(base, o, base), o);
  assert.equal(ok(base, o, o), o);
});

test('revocation is monotonic: union of revoked, never un-revoked by a stale side', () => {
  const base = text(eA(), eB(), eC());
  const o = text(eA(), eB({ revoked: rev('2026-11-16T10:05:00.000Z') }), eC());
  const t = text(eA(), eB(), eC({ revoked: rev('2026-11-16T10:06:00.000Z') }));
  const m = files(ok(base, o, t));
  assert.ok(m.devices.find((d) => d.id === B.id)?.revoked);
  assert.ok(m.devices.find((d) => d.id === C.id)?.revoked);
  assert.equal(ok(base, o, t), ok(base, t, o));
});

test('both revoked the same device: earliest at wins, tie -> total order on the record', () => {
  const base = text(eA(), eB());
  const early = text(eA(), eB({ revoked: rev('2026-11-16T10:01:00.000Z', A.id, 'zzz') }));
  const late = text(eA(), eB({ revoked: rev('2026-11-16T10:09:00.000Z', A.id, 'aaa') }));
  assert.equal(files(ok(base, early, late)).devices[1]?.revoked?.at, '2026-11-16T10:01:00.000Z');
  assert.equal(ok(base, early, late), ok(base, late, early));
  const tieA = text(eA(), eB({ revoked: rev('2026-11-16T10:01:00.000Z', A.id, 'bbb') }));
  const tieB = text(eA(), eB({ revoked: rev('2026-11-16T10:01:00.000Z', A.id, 'aaa') }));
  assert.equal(files(ok(base, tieA, tieB)).devices[1]?.revoked?.reason, 'aaa');
  assert.equal(ok(base, tieA, tieB), ok(base, tieB, tieA));
});

test('last_seen: per entry max of valid timestamps; absent on one side is fine', () => {
  const base = text(eA(), eB());
  const o = text(eA({ last_seen: '2026-11-16T11:00:00.000Z' }), eB());
  const t = text(eA({ last_seen: '2026-11-16T12:00:00.000Z' }), eB({ last_seen: '2026-11-16T09:00:00.000Z' }));
  const m = files(ok(base, o, t));
  assert.equal(m.devices[0]?.last_seen, '2026-11-16T12:00:00.000Z');
  assert.equal(m.devices[1]?.last_seen, '2026-11-16T09:00:00.000Z');
  assert.equal(ok(base, o, t), ok(base, t, o));
});

test('slot clash between concurrent additions -> conflict signal, no winner picked', () => {
  const base = text(eA());
  const o = text(eA(), eB({ slot: 'W' }));
  const t = text(eA(), eC({ slot: 'W' }));
  for (const [x, y] of [[o, t], [t, o]] as const) {
    const r = mergeDevices(base, x, y);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.rule, 'devices-conflict');
  }
});

test('identity divergence of one id (pubkey/slot/label swap) -> conflict', () => {
  const base = text(eA(), eB());
  const o = text(eA(), eB({ label: 'renamed' }));
  const t = text(eA(), eB({ slot: 'W' }));
  const r = mergeDevices(base, o, t);
  assert.equal(r.ok, false);
});

test('invalid input never throws: parse failure is a signal', () => {
  const good = text(eA());
  for (const bad of ['{{{', 'devices: 5', 'devices:\n  - {id: x}\n', `devices: []\n# ${'x'.repeat(70_000)}`, '\u0000']) {
    for (const r of [mergeDevices(good, bad, good), mergeDevices(good, good, bad), mergeDevices(bad, good, text(eA(), eB()))]) {
      if (!r.ok) assert.ok(r.rule === 'devices-parse' || r.rule === 'devices-conflict');
    }
  }
  const r = mergeDevices(good, '{{{', good);
  assert.equal(r.ok, false);
});

test('CRLF input: merged output is LF only', () => {
  const base = text(eA());
  const o = text(eA(), eB()).replace(/\n/g, '\r\n');
  const t = text(eA(), eC());
  assert.ok(!ok(base, o, t).includes('\r'));
});

test('null base (unrelated histories) and a missing side', () => {
  assert.deepEqual(files(ok(null, text(eA(), eB()), text(eA(), eC()))).devices.length, 3);
  const n = mergeDevicesNullable(null, null, null);
  assert.ok(n.ok && n.merged === null);
  const one = mergeDevicesNullable(null, text(eA()), null);
  assert.ok(one.ok && one.merged === text(eA()));
  assert.equal(mergeDevicesNullable(null, '{{{', null).ok, false);
});

test('determinism: permuted additions / revocations / last_seen over many seeds give identical bytes', () => {
  const r = rng(7);
  const pool = [eB, eC, eD];
  for (let n = 0; n < 40; n += 1) {
    const base = text(eA());
    const mk = (): string => {
      const chosen = pool.filter(() => r.chance(0.6));
      return text(
        eA(r.chance(0.5) ? { last_seen: `2026-11-16T1${r.int(10)}:00:00.000Z` } : {}),
        ...chosen.map((f) => f(r.chance(0.3) ? { revoked: rev(`2026-11-16T10:0${r.int(9)}:00.000Z`) } : {})),
      );
    };
    const x = mk();
    const y = mk();
    const xy = mergeDevices(base, x, y);
    const yx = mergeDevices(base, y, x);
    assert.equal(xy.ok, yx.ok);
    if (xy.ok && yx.ok) assert.equal(xy.merged, yx.merged);
  }
});
