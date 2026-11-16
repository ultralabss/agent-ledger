/** F2.1 / F2.3 / F2.5 — `device init` (idempotent, F1 identity kept), approve/revoke state
 *  machine on disk, doctor health. Real ssh-keygen; POSIX modes (win32 skipped, NOT verified there). */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { parse as parseYaml } from 'yaml';
import { parseAllowedSigners, renderDevicesYaml, type DevicesFile } from './devices.ts';
import {
  approveDevice,
  deviceHealth,
  deviceLayout,
  initDevice,
  listDevices,
  readDevices,
  readSigners,
  revokeDevice,
} from './devicestore.ts';
import { parseEd25519Pub } from './sshkey.ts';
import { skipOnWin32 } from './testing.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

async function ledger(t: { after: (fn: () => unknown) => void }, tag = 'a'): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `ledger-dev-${tag}-`));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

const sha = async (p: string): Promise<string> => createHash('sha256').update(await readFile(p)).digest('hex');
const mode = async (p: string): Promise<number> => (await stat(p)).mode & 0o777;

/** Second machine: its own ledger dir + key; we only need its public facts. */
async function otherDevice(t: { after: (fn: () => unknown) => void }): Promise<{ id: string; pub: string }> {
  const dir = await ledger(t, 'b');
  const r = await initDevice(dir, { label: 'win' });
  const l = deviceLayout(dir);
  const pub = parseEd25519Pub(await readFile(l.pubFile, 'utf8'), { allowComment: true });
  assert.ok(pub);
  return { id: r.deviceId, pub: pub.line };
}

/** Root device on `dir` + a registered second device (what F3 would sync in). */
async function twoDevices(t: { after: (fn: () => unknown) => void }): Promise<{ dir: string; self: string; other: { id: string; pub: string } }> {
  const dir = await ledger(t);
  const r = await initDevice(dir, { root: true });
  const other = await otherDevice(t);
  const l = deviceLayout(dir);
  const file = (await readDevices(l)) as DevicesFile;
  file.devices.push({
    id: other.id, label: 'win', slot: 'W', pubkey: other.pub, added: '2026-11-16T10:00:00.000Z',
    added_by: r.deviceId, revoked: null, role: 'owner',
  });
  await writeFile(l.devicesYml, renderDevicesYaml(file), { mode: 0o600 });
  return { dir, self: r.deviceId, other };
}

test('init on a fresh install: key 0600 in a 0700 dir, id derived from the pubkey, nothing printed or leaked', { skip }, async (t) => {
  const dir = await ledger(t);
  const r = await initDevice(dir, { label: 'vps' });
  const l = deviceLayout(dir);
  assert.equal(r.keyCreated, true);
  assert.equal(r.label, 'vps');
  assert.equal(r.slot, '');
  assert.equal(await mode(l.deviceDir), 0o700);
  assert.equal(await mode(l.keyFile), 0o600);
  assert.equal(await mode(l.pubFile), 0o600);
  assert.equal(await mode(l.deviceYml), 0o600);
  assert.deepEqual((await readdir(l.deviceDir)).sort(), ['key', 'key.pub'], 'no generation leftovers');
  const pub = parseEd25519Pub(await readFile(l.pubFile, 'utf8'));
  assert.equal(r.deviceId, pub?.deviceId, 'device_id = d_ + sha256(pubkey)');
  const dev = parseYaml(await readFile(l.deviceYml, 'utf8')) as Record<string, string>;
  assert.deepEqual(dev, { device_id: r.deviceId, label: 'vps', slot: '', key_fp: pub?.fingerprint });
  assert.ok(!JSON.stringify(r).includes('PRIVATE'));
  assert.equal(r.registeredRoot, false, 'no devices.yml unless --root');
  assert.equal(await readDevices(l), null);
});

test('init is idempotent: the key is never regenerated', { skip }, async (t) => {
  const dir = await ledger(t);
  const first = await initDevice(dir);
  const l = deviceLayout(dir);
  const [k, p, d] = [await sha(l.keyFile), await sha(l.pubFile), await sha(l.deviceYml)];
  const second = await initDevice(dir);
  const third = await initDevice(dir, { root: true });
  const fourth = await initDevice(dir, { root: true });
  assert.equal(second.keyCreated, false);
  assert.equal(second.deviceId, first.deviceId);
  assert.equal(await sha(l.keyFile), k);
  assert.equal(await sha(l.pubFile), p);
  assert.equal(await sha(l.deviceYml), d, 'device.yml untouched when nothing changes');
  assert.equal(third.registeredRoot, true);
  assert.equal(fourth.registeredRoot, false);
  assert.equal(await sha(l.keyFile), k);
});

test('F1 device.yml: the random device_id and slot are kept, the counters file is not touched', { skip }, async (t) => {
  const dir = await ledger(t);
  const l = deviceLayout(dir);
  await mkdir(l.hubDir, { recursive: true, mode: 0o700 });
  await mkdir(join(dir, 'counters'));
  await writeFile(l.deviceYml, 'device_id: d_abcdefghij\nlabel: mac\nslot: ""\n', { mode: 0o600 });
  await writeFile(join(dir, 'counters', 'd_abcdefghij.yml'), 'ops: 7\n', { mode: 0o600 });
  const countersBefore = await sha(join(dir, 'counters', 'd_abcdefghij.yml'));

  const r = await initDevice(dir, { root: true });
  assert.equal(r.deviceId, 'd_abcdefghij', 'existing id is never replaced by the pubkey-derived one');
  assert.equal(r.deviceYmlCreated, false);
  const dev = parseYaml(await readFile(l.deviceYml, 'utf8')) as Record<string, string>;
  assert.equal(dev.device_id, 'd_abcdefghij');
  assert.match(dev.key_fp ?? '', /^SHA256:/);
  assert.equal(await sha(join(dir, 'counters', 'd_abcdefghij.yml')), countersBefore);
  assert.equal((await readdir(join(dir, 'counters'))).length, 1);
  const root = (await readDevices(l))?.devices[0];
  assert.equal(root?.id, 'd_abcdefghij', 'root entry carries the F1 id (the only place id ≠ derived is allowed)');
});

test('init refuses instead of regenerating: invalid device.yml, other fingerprint, orphan key.pub, loose key', { skip }, async (t) => {
  // invalid device.yml
  const bad = await ledger(t);
  const lb = deviceLayout(bad);
  await mkdir(lb.hubDir, { recursive: true, mode: 0o700 });
  await writeFile(lb.deviceYml, 'device_id: nope\n', { mode: 0o600 });
  await assert.rejects(initDevice(bad), /device\.yml is invalid/);
  assert.deepEqual(await readdir(lb.hubDir), ['device.yml'], 'no key created next to a broken identity');

  // device.yml records another key
  const dir = await ledger(t);
  await initDevice(dir);
  const l = deviceLayout(dir);
  const dev = (await readFile(l.deviceYml, 'utf8')).replace(/SHA256:\S+/, `SHA256:${'A'.repeat(43)}`);
  await writeFile(l.deviceYml, dev);
  await assert.rejects(initDevice(dir), /different key fingerprint/);

  // key.pub without the private key
  const orphan = await ledger(t);
  await initDevice(orphan);
  const lo = deviceLayout(orphan);
  await rm(lo.keyFile);
  await assert.rejects(initDevice(orphan), /private key is missing/);

  // private key readable by others
  const loose = await ledger(t);
  await initDevice(loose);
  await chmod(deviceLayout(loose).keyFile, 0o644);
  await assert.rejects(initDevice(loose));
});

test('init refuses symlinked key material and an unsafe label; --label cannot rename a registered device', { skip }, async (t) => {
  const dir = await ledger(t);
  await assert.rejects(initDevice(dir, { label: '../evil' }), /label/);
  await assert.rejects(initDevice(dir, { label: 'UPPER' }), /label/);
  await initDevice(dir, { label: 'mac' });
  await assert.rejects(initDevice(dir, { label: 'other' }), /label is part of its registration/);

  const sym = await ledger(t);
  await initDevice(sym);
  const l = deviceLayout(sym);
  await rm(l.deviceYml);
  await writeFile(join(sym, 'elsewhere'), 'device_id: d_abcdefghij\nlabel: x\nslot: ""\n');
  await symlink(join(sym, 'elsewhere'), l.deviceYml);
  await assert.rejects(initDevice(sym), /symlink/);
});

test('init --root: first device becomes TOFU root and trusts itself; a foreign devices.yml is refused', { skip }, async (t) => {
  const dir = await ledger(t);
  const r = await initDevice(dir, { root: true });
  const l = deviceLayout(dir);
  assert.equal(r.registeredRoot, true);
  const devices = await readDevices(l);
  assert.equal(devices?.devices.length, 1);
  assert.equal(devices?.devices[0]?.added_by, r.deviceId);
  assert.deepEqual((await readSigners(l)).map((s) => s.id), [r.deviceId]);
  assert.equal(await mode(l.allowedSigners), 0o600);

  const foreign = await ledger(t);
  const lf = deviceLayout(foreign);
  await writeFile(lf.devicesYml, await readFile(l.devicesYml, 'utf8'));
  await assert.rejects(initDevice(foreign, { root: true }), /already exists/);
});

test('approve → trusted key lands in allowed_signers (0600); idempotent; unknown / bad ids refused', { skip }, async (t) => {
  const { dir, other, self } = await twoDevices(t);
  const l = deviceLayout(dir);
  assert.deepEqual((await readSigners(l)).map((s) => s.id), [self]);
  assert.deepEqual(await approveDevice(dir, other.id), { added: true });
  assert.deepEqual(await approveDevice(dir, other.id), { added: false });
  const signers = parseAllowedSigners(await readFile(l.allowedSigners, 'utf8'));
  assert.deepEqual(signers.map((s) => s.id).sort(), [self, other.id].sort());
  assert.equal(signers.find((s) => s.id === other.id)?.pubkey, other.pub);
  assert.equal(await mode(l.allowedSigners), 0o600);
  await assert.rejects(approveDevice(dir, 'd_aaaaaaaaaa'), /not in devices\.yml/);
  for (const bad of ['../../etc/passwd', 'D_AAAAAAAAAA', 'd_short', '']) await assert.rejects(approveDevice(dir, bad), /device id/);
  const rows = await listDevices(dir);
  assert.deepEqual(rows.map((r) => [r.slot, r.trusted, r.self]), [['', true, true], ['W', true, false]]);
});

test('approve needs a registered member: an unregistered machine cannot approve anyone', { skip }, async (t) => {
  const { other } = await twoDevices(t);
  const stranger = await ledger(t, 'c');
  await initDevice(stranger); // key, but no devices.yml
  await assert.rejects(approveDevice(stranger, other.id), /not registered/);
});

test('revoke: permanent, key leaves allowed_signers, never approvable again, self-revoke refused', { skip }, async (t) => {
  const { dir, other, self } = await twoDevices(t);
  const l = deviceLayout(dir);
  await approveDevice(dir, other.id);

  await assert.rejects(revokeDevice(dir, other.id, ''), /--reason/);
  await assert.rejects(revokeDevice(dir, other.id, 'a\nb'), /--reason/);
  await assert.rejects(revokeDevice(dir, other.id, 'x'.repeat(201)), /--reason/);
  await assert.rejects(revokeDevice(dir, self, 'oops'), /itself/);
  await assert.rejects(revokeDevice(dir, 'd_aaaaaaaaaa', 'nope'), /not in devices\.yml/);

  await revokeDevice(dir, other.id, 'lost phone', new Date('2026-11-17T08:00:00.000Z'));
  assert.deepEqual((await readSigners(l)).map((s) => s.id), [self], 'untrusted');
  const rec = (await readDevices(l))?.devices.find((d) => d.id === other.id)?.revoked;
  assert.deepEqual(rec, { at: '2026-11-17T08:00:00.000Z', by: self, reason: 'lost phone' });

  await assert.rejects(revokeDevice(dir, other.id, 'again'), /already revoked/);
  await assert.rejects(approveDevice(dir, other.id), /revoked/);
  assert.deepEqual((await readSigners(l)).map((s) => s.id), [self]);
  // the registry still carries it: the slot stays retired
  assert.equal((await readDevices(l))?.devices.length, 2);
  assert.equal((await listDevices(dir)).find((r) => r.id === other.id)?.status, 'revoked');
});

test('a revoked device cannot approve or revoke anyone', { skip }, async (t) => {
  const { dir, self, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  const file = (await readDevices(l)) as DevicesFile;
  const me = file.devices.find((d) => d.id === self);
  assert.ok(me);
  // simulate: another device revoked us (synced in F3)
  me.revoked = { at: '2026-11-17T08:00:00.000Z', by: other.id, reason: 'compromised' };
  await writeFile(l.devicesYml, renderDevicesYaml(file));
  await assert.rejects(approveDevice(dir, other.id), /revoked/);
  await assert.rejects(revokeDevice(dir, other.id, 'x'), /revoked/);
});

test('doctor health: silent without identity; ok after init --root; fails on loose key, key mismatch, revoked-but-trusted', { skip }, async (t) => {
  const empty = await ledger(t);
  assert.deepEqual(await deviceHealth(empty), []);

  const { dir, other, self } = await twoDevices(t);
  const l = deviceLayout(dir);
  let checks = await deviceHealth(dir);
  assert.deepEqual(checks.map((c) => [c.id, c.status]), [['device_key', 'ok'], ['device_signers', 'ok']]);
  assert.ok(!checks.some((c) => /PRIVATE|BEGIN/.test(c.detail)));

  // approved device then revoked by hand-editing signers back in: doctor flags the contradiction
  await approveDevice(dir, other.id);
  await revokeDevice(dir, other.id, 'lost');
  const signersText = await readFile(l.allowedSigners, 'utf8');
  await writeFile(l.allowedSigners, `${signersText}${signersText.replace(self, other.id).replace(/ssh-ed25519 \S+/, `ssh-ed25519 ${other.pub.split(' ')[1]}`)}`);
  checks = await deviceHealth(dir);
  assert.equal(checks.find((c) => c.id === 'device_signers')?.status, 'fail');
  await writeFile(l.allowedSigners, signersText);

  // key permissions
  await chmod(l.keyFile, 0o640);
  checks = await deviceHealth(dir);
  assert.equal(checks.find((c) => c.id === 'device_key')?.status, 'fail');
  assert.match(checks.find((c) => c.id === 'device_key')?.detail ?? '', /not private/);
  await chmod(l.keyFile, 0o600);

  // this device's registry entry carries a different key
  const third = await otherDevice(t);
  const file = (await readDevices(l)) as DevicesFile;
  const mine = file.devices.find((d) => d.id === self);
  assert.ok(mine);
  mine.pubkey = third.pub;
  await writeFile(l.devicesYml, renderDevicesYaml(file));
  checks = await deviceHealth(dir);
  assert.match(checks.find((c) => c.id === 'device_key')?.detail ?? '', /differs from this device/);
  assert.equal(checks.find((c) => c.id === 'device_key')?.status, 'fail');

  // a corrupted registry never reads as ok
  await writeFile(l.devicesYml, 'devices: [{id: x}]\n');
  checks = await deviceHealth(dir);
  assert.equal(checks[0]?.status, 'fail');
});

test('doctor health: missing private key of a registered device fails; unseen > 30 days warns (clock-skew safe)', { skip }, async (t) => {
  const { dir, self, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  const file = (await readDevices(l)) as DevicesFile;
  const o = file.devices.find((d) => d.id === other.id);
  assert.ok(o);
  o.last_seen = '2026-09-01T00:00:00.000Z';
  await writeFile(l.devicesYml, renderDevicesYaml(file));
  const now = Date.parse('2026-11-16T00:00:00.000Z');
  let stale = (await deviceHealth(dir, now)).find((c) => c.id === 'devices_stale');
  assert.equal(stale?.status, 'warn');
  assert.ok(stale?.detail.includes(other.id));
  // a clock far in the past makes the same device look "future": distance is absolute, still stale
  stale = (await deviceHealth(dir, Date.parse('2026-01-01T00:00:00.000Z'))).find((c) => c.id === 'devices_stale');
  assert.equal(stale?.status, 'warn');
  stale = (await deviceHealth(dir, Date.parse('2026-09-10T00:00:00.000Z'))).find((c) => c.id === 'devices_stale');
  assert.equal(stale?.status, 'ok');

  await rm(l.keyFile);
  const key = (await deviceHealth(dir, now)).find((c) => c.id === 'device_key');
  assert.equal(key?.status, 'fail');
  assert.match(key?.detail ?? '', /MISSING/);
  void self;
});

test('no last_seen anywhere → no devices_stale line', { skip }, async (t) => {
  const { dir } = await twoDevices(t);
  assert.equal((await deviceHealth(dir)).some((c) => c.id === 'devices_stale'), false);
});
