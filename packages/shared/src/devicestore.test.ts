/** F2.1 / F2.3 / F2.5 — `device init` (idempotent, F1 identity kept), approve/revoke state
 *  machine on disk, doctor health. Real ssh-keygen; POSIX modes (win32 skipped, NOT verified there). */

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import { parse as parseYaml } from 'yaml';
import { DevicesError, acceptDevicesChange, parseAllowedSigners, renderDevicesYaml, type DevicesFile } from './devices.ts';
import {
  addDevice,
  adoptSlot,
  approveDevice,
  deviceHealth,
  deviceLayout,
  initDevice,
  listDevices,
  pruneRevokedSigners,
  readDevices,
  readSigners,
  rekeyLegacyDeviceId,
  revokeDevice,
  withDeviceLock,
} from './devicestore.ts';
import { SLOT_LETTERS } from './snowflake.ts';
import { parseEd25519Pub } from './sshkey.ts';
import { skipOnWin32 } from './testing.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

async function ledger(t: { after: (fn: () => unknown) => void }, tag = 'a'): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `ledger-dev-${tag}-`));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

const fpOf = (pub: string): string => parseEd25519Pub(pub)?.fingerprint ?? '';
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

test('DK-7: a legacy random id is kept by plain init, refused as root, and re-keyed only on request (counters follow)', { skip }, async (t) => {
  const dir = await ledger(t);
  const l = deviceLayout(dir);
  await mkdir(l.hubDir, { recursive: true, mode: 0o700 });
  await mkdir(join(dir, 'counters'));
  await writeFile(l.deviceYml, 'device_id: d_abcdefghij\nlabel: mac\nslot: ""\n', { mode: 0o600 });
  await writeFile(join(dir, 'counters', 'd_abcdefghij.yml'), 'ops: 7\n', { mode: 0o600 });

  const plain = await initDevice(dir);
  assert.equal(plain.deviceId, 'd_abcdefghij', 'plain init never replaces an existing id');
  assert.equal(plain.deviceYmlCreated, false);
  const dev = parseYaml(await readFile(l.deviceYml, 'utf8')) as Record<string, string>;
  assert.equal(dev.device_id, 'd_abcdefghij');
  assert.match(dev.key_fp ?? '', /^SHA256:/);

  // as root: refused, nothing registered, nothing renamed
  await assert.rejects(initDevice(dir, { root: true }), (e: unknown) => e instanceof DevicesError && e.code === 'LEGACY_ID');
  assert.equal(await readDevices(l), null);
  assert.deepEqual(await readdir(join(dir, 'counters')), ['d_abcdefghij.yml']);
  await assert.rejects(initDevice(dir, { rekeyLegacy: true }), (e: unknown) => e instanceof DevicesError && e.code === 'REKEY_REFUSED', 'rekey without root');

  // explicit migration
  const r = await initDevice(dir, { root: true, rekeyLegacy: true });
  const derived = parseEd25519Pub(await readFile(l.pubFile, 'utf8'))?.deviceId ?? '';
  assert.match(derived, /^d_/);
  assert.equal(r.deviceId, derived);
  assert.equal(r.registeredRoot, true);
  assert.equal((parseYaml(await readFile(l.deviceYml, 'utf8')) as Record<string, string>).device_id, derived);
  assert.deepEqual(await readdir(join(dir, 'counters')), [`${derived}.yml`], 'counters file renamed, content kept');
  assert.equal(await readFile(join(dir, 'counters', `${derived}.yml`), 'utf8'), 'ops: 7\n');
  assert.equal((await readDevices(l))?.devices[0]?.id, derived, 'root id is derived from the key');
  assert.equal(await mode(join(dir, 'counters', `${derived}.yml`)), 0o600);
  // idempotent afterwards
  assert.equal((await initDevice(dir, { root: true })).registeredRoot, false);
});

test('DK-7: rekeyLegacyDeviceId — null when already derived; refuses when a devices.yml exists or the target counters differ', { skip }, async (t) => {
  const fresh = await ledger(t);
  await initDevice(fresh);
  assert.equal(await rekeyLegacyDeviceId(fresh), null);

  const dir = await ledger(t);
  const l = deviceLayout(dir);
  await initDevice(dir);
  const derived = (await initDevice(dir)).deviceId;
  await writeFile(l.deviceYml, `device_id: d_abcdefghij\nlabel: mac\nslot: ""\nkey_fp: ${parseEd25519Pub(await readFile(l.pubFile, 'utf8'))?.fingerprint ?? ''}\n`, { mode: 0o600 });
  await mkdir(join(dir, 'counters'));
  await writeFile(join(dir, 'counters', 'd_abcdefghij.yml'), 'ops: 7\n', { mode: 0o600 });
  await writeFile(join(dir, 'counters', `${derived}.yml`), 'ops: 9\n', { mode: 0o600 });
  await assert.rejects(rekeyLegacyDeviceId(dir), (e: unknown) => e instanceof DevicesError && e.code === 'REKEY_CONFLICT');
  assert.match(await readFile(l.deviceYml, 'utf8'), /d_abcdefghij/, 'device.yml untouched on conflict');
  assert.deepEqual((await readdir(join(dir, 'counters'))).sort(), ['d_abcdefghij.yml', `${derived}.yml`].sort());
  // identical content at the target is fine (a crash after the copy)
  await writeFile(join(dir, 'counters', `${derived}.yml`), 'ops: 7\n', { mode: 0o600 });
  assert.deepEqual(await rekeyLegacyDeviceId(dir), { from: 'd_abcdefghij', to: derived });
  assert.deepEqual(await readdir(join(dir, 'counters')), [`${derived}.yml`]);

  // a registered ledger is never re-keyed
  const reg = await ledger(t);
  const lr = deviceLayout(reg);
  await initDevice(reg, { root: true });
  const devYml = await readFile(lr.deviceYml, 'utf8');
  await writeFile(lr.deviceYml, devYml.replace(/device_id: \S+/, 'device_id: d_abcdefghij'));
  await assert.rejects(rekeyLegacyDeviceId(reg), (e: unknown) => e instanceof DevicesError && e.code === 'REKEY_REFUSED');
  // a foreign fingerprint is refused
  const mism = await ledger(t);
  await initDevice(mism);
  const lm = deviceLayout(mism);
  await writeFile(lm.deviceYml, (await readFile(lm.deviceYml, 'utf8')).replace(/SHA256:\S+/, `SHA256:${'A'.repeat(43)}`));
  await assert.rejects(rekeyLegacyDeviceId(mism), /different key fingerprint/);
});

test('DK-7: init --root on a ledger whose root entry is REVOKED is refused and does not re-trust the key', { skip }, async (t) => {
  const { dir, self, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  const file = (await readDevices(l)) as DevicesFile;
  const me = file.devices.find((d) => d.id === self);
  assert.ok(me);
  me.revoked = { at: '2026-11-17T08:00:00.000Z', by: other.id, reason: 'compromised' };
  await writeFile(l.devicesYml, renderDevicesYaml(file));
  await writeFile(l.allowedSigners, '', { mode: 0o600 }); // revocation already took the key out
  await assert.rejects(initDevice(dir, { root: true }), (e: unknown) => e instanceof DevicesError && e.code === 'ROOT_REVOKED');
  assert.deepEqual(await readSigners(l), [], 'the revoked key was not put back into allowed_signers');
  // plain init (no --root) still works and never touches trust
  await initDevice(dir);
  assert.deepEqual(await readSigners(l), []);
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
  assert.deepEqual(await approveDevice(dir, other.id, fpOf(other.pub)), { added: true });
  assert.deepEqual(await approveDevice(dir, other.id, fpOf(other.pub)), { added: false });
  const signers = parseAllowedSigners(await readFile(l.allowedSigners, 'utf8'));
  assert.deepEqual(signers.map((s) => s.id).sort(), [self, other.id].sort());
  assert.equal(signers.find((s) => s.id === other.id)?.pubkey, other.pub);
  assert.equal(await mode(l.allowedSigners), 0o600);
  await assert.rejects(approveDevice(dir, 'd_aaaaaaaaaa', fpOf(other.pub)), /not in devices\.yml/);
  for (const bad of ['../../etc/passwd', 'D_AAAAAAAAAA', 'd_short', '']) await assert.rejects(approveDevice(dir, bad, fpOf(other.pub)), /device id/);
  const rows = await listDevices(dir);
  assert.deepEqual(rows.map((r) => [r.slot, r.trusted, r.self]), [['', true, true], ['W', true, false]]);
});

test('approve needs a registered member: an unregistered machine cannot approve anyone', { skip }, async (t) => {
  const { other } = await twoDevices(t);
  const stranger = await ledger(t, 'c');
  await initDevice(stranger); // key, but no devices.yml
  await assert.rejects(approveDevice(stranger, other.id, fpOf(other.pub)), /not registered/);
});

test('revoke: permanent, key leaves allowed_signers, never approvable again, self-revoke refused', { skip }, async (t) => {
  const { dir, other, self } = await twoDevices(t);
  const l = deviceLayout(dir);
  await approveDevice(dir, other.id, fpOf(other.pub));

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
  await assert.rejects(approveDevice(dir, other.id, fpOf(other.pub)), /revoked/);
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
  await assert.rejects(approveDevice(dir, other.id, fpOf(other.pub)), /revoked/);
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
  await approveDevice(dir, other.id, fpOf(other.pub));
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
  const mineKey = parseEd25519Pub((await readFile(l.pubFile, 'utf8')).trim())?.line ?? '';
  assert.ok(self !== '' && mineKey !== '');
  await writeFile(l.devicesYml, (await readFile(l.devicesYml, 'utf8')).replace(mineKey, third.pub));
  checks = await deviceHealth(dir);
  // id is derived from the key (DK-1): a swapped key under the same id no longer parses at all
  assert.match(checks.find((c) => c.id === 'device_key')?.detail ?? '', /not derived/);
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

/* ---------------- B0a: DK-1 approve needs the fingerprint ---------------- */

test('DK-1: approve refuses a missing, malformed or wrong fingerprint and leaves allowed_signers untouched', { skip }, async (t) => {
  const { dir, other, self } = await twoDevices(t);
  const l = deviceLayout(dir);
  const before = await sha(l.allowedSigners);
  const mine = (await readdir(l.hubDir)).sort();
  const wrongButWellFormed = fpOf(parseEd25519Pub(`ssh-ed25519 ${Buffer.concat([Buffer.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32]), randomBytes(32)]).toString('base64')}`)?.line ?? '');
  for (const [fp, code] of [
    ['', 'FP_REQUIRED'],
    [undefined as unknown as string, 'FP_REQUIRED'],
    ['SHA256:', 'FP_MISMATCH'],
    [fpOf(other.pub).slice(7), 'FP_MISMATCH'], // without the SHA256: prefix
    [`${fpOf(other.pub)} `, 'FP_MISMATCH'],
    [fpOf(other.pub).toLowerCase(), 'FP_MISMATCH'],
    [wrongButWellFormed, 'FP_MISMATCH'],
    [`SHA256:${'A'.repeat(43)}`, 'FP_MISMATCH'],
  ] as const) {
    await assert.rejects(approveDevice(dir, other.id, fp), (e: unknown) => e instanceof DevicesError && e.code === code, `${fp} → ${code}`);
  }
  // the error never echoes the expected fingerprint
  await assert.rejects(approveDevice(dir, other.id, wrongButWellFormed), (e: unknown) => e instanceof Error && !e.message.includes(fpOf(other.pub)));
  assert.equal(await sha(l.allowedSigners), before);
  assert.deepEqual((await readSigners(l)).map((x) => x.id), [self]);
  assert.deepEqual((await readdir(l.hubDir)).sort(), mine, 'no lock file left behind');
  // the correct one works
  assert.deepEqual(await approveDevice(dir, other.id, fpOf(other.pub)), { added: true });
});

test('DK-1: a devices.yml whose entry id is not sha256(its key) is refused when read from disk', { skip }, async (t) => {
  const { dir, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  const text = (await readFile(l.devicesYml, 'utf8')).split(other.id).join('d_abcdefghij');
  await writeFile(l.devicesYml, text);
  await assert.rejects(readDevices(l), /not derived/);
  await assert.rejects(approveDevice(dir, 'd_abcdefghij', fpOf(other.pub)), /not derived/);
});

/* ---------------- DK-2: output hygiene ---------------- */

test('DK-2: doctor and list never print raw bytes from a hostile devices.yml', { skip }, async (t) => {
  const { dir } = await twoDevices(t);
  const l = deviceLayout(dir);
  const ESC = '\u001b';
  const hostile = `${ESC}[2J${ESC}]0;pwned\u0007 ‮evil‬`;
  const good = await readFile(l.devicesYml, 'utf8');
  await writeFile(l.devicesYml, good.replace('label: win', `label: ${JSON.stringify(hostile)}`));
  const checks = await deviceHealth(dir);
  assert.equal(checks[0]?.status, 'fail');
  for (const c of checks) {
    assert.ok(!/[\u0000-\u001f\u007f-\u009f‪-‮​]/.test(c.detail), c.detail);
    assert.ok(!c.detail.includes('pwned') && !c.detail.includes('evil'), c.detail);
  }
  await assert.rejects(listDevices(dir), (e: unknown) => e instanceof DevicesError && !/pwned|evil/.test(e.message));
});

/* ---------------- DK-5: allowed_signers is owner/mode-checked; one lock ---------------- */

test('DK-5: a 0666 / group-writable / symlinked allowed_signers is refused before it is parsed; doctor flags it', { skip }, async (t) => {
  const { dir, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  await chmod(l.allowedSigners, 0o666);
  await assert.rejects(readSigners(l), /permissions|PERMS|loose/i);
  await assert.rejects(approveDevice(dir, other.id, fpOf(other.pub)), /permissions|PERMS|loose/i);
  await assert.rejects(revokeDevice(dir, other.id, 'x'), /permissions|PERMS|loose/i);
  await assert.rejects(listDevices(dir), /permissions|PERMS|loose/i);
  const sig = (await deviceHealth(dir)).find((c) => c.id === 'device_signers');
  assert.equal(sig?.status, 'fail');
  assert.match(sig?.detail ?? '', /not private \(PERMS\)/);
  await chmod(l.allowedSigners, 0o620);
  await assert.rejects(readSigners(l), /permissions|PERMS|loose/i);
  await chmod(l.allowedSigners, 0o600);
  assert.equal((await readSigners(l)).length, 1);

  // symlink
  const real = join(dir, 'signers.real');
  await writeFile(real, await readFile(l.allowedSigners, 'utf8'), { mode: 0o600 });
  await rm(l.allowedSigners);
  await symlink(real, l.allowedSigners);
  await assert.rejects(readSigners(l), /symlink|SYMLINK/i);
  assert.equal((await deviceHealth(dir)).find((c) => c.id === 'device_signers')?.status, 'fail');
});

test('DK-5: approve racing revoke never resurrects a revoked key (single lock, inputs re-read inside it)', { skip }, async (t) => {
  for (let round = 0; round < 6; round++) {
    const { dir, other } = await twoDevices(t);
    const l = deviceLayout(dir);
    const results = await Promise.allSettled([
      approveDevice(dir, other.id, fpOf(other.pub)),
      revokeDevice(dir, other.id, 'lost'),
      approveDevice(dir, other.id, fpOf(other.pub)),
      revokeDevice(dir, other.id, 'lost again'),
    ]);
    assert.ok(results.some((r) => r.status === 'fulfilled'));
    const revoked = (await readDevices(l))?.devices.find((d) => d.id === other.id)?.revoked;
    const trusted = (await readSigners(l)).some((x) => x.id === other.id);
    if (revoked !== null) assert.equal(trusted, false, `round ${String(round)}: revoked key is still trusted`);
    // whatever order won, the file pair is consistent for doctor
    assert.notEqual((await deviceHealth(dir)).find((c) => c.id === 'device_signers')?.status, 'fail', `round ${String(round)}`);
    assert.ok(!(await readdir(l.hubDir)).includes('device.lock'), 'lock released');
  }
});

test('DK-5: the lock — stale (dead holder) is taken over, a symlink at the lock path is refused, a live fresh lock blocks (LOCKED)', { skip }, async (t) => {
  const { dir, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  const lock = join(l.hubDir, 'device.lock');
  const old = new Date(Date.now() - 60_000);

  // dead holder (pid way above any real one) + old mtime → taken over, then removed
  await writeFile(lock, '2147480000 1 deadbeef\n', { mode: 0o600 });
  await utimes(lock, old, old);
  assert.deepEqual(await approveDevice(dir, other.id, fpOf(other.pub)), { added: true });
  assert.ok(!(await readdir(l.hubDir)).includes('device.lock'));

  // garbage / empty lock that is old → stale
  await writeFile(lock, '', { mode: 0o600 });
  await utimes(lock, old, old);
  assert.deepEqual(await approveDevice(dir, other.id, fpOf(other.pub)), { added: false });

  // symlink at the lock path is never followed or removed
  const target = join(dir, 'victim');
  await writeFile(target, 'keep', { mode: 0o600 });
  await symlink(target, lock);
  await assert.rejects(approveDevice(dir, other.id, fpOf(other.pub)), /symlink/i);
  assert.equal(await readFile(target, 'utf8'), 'keep');
  await rm(lock);

  // a lock held by a LIVE process (this one) and fresh is respected: the waiter gives up with LOCKED
  await writeFile(lock, `${String(process.pid)} ${String(Date.now())} cafe\n`, { mode: 0o600 });
  const started = Date.now();
  await assert.rejects(approveDevice(dir, other.id, fpOf(other.pub)), (e: unknown) => e instanceof DevicesError && e.code === 'LOCKED');
  assert.ok(Date.now() - started >= 9000, 'waited for the holder before giving up');
  assert.match(await readFile(lock, 'utf8'), /cafe/, 'the foreign lock was not deleted');
});

/* ---------------- DK-6 ---------------- */

test('DK-6: init sweeps .gen-* directories older than 10 min, keeps fresh ones, never follows symlinks or touches other names', { skip }, async (t) => {
  const dir = await ledger(t);
  await initDevice(dir);
  const l = deviceLayout(dir);
  const stale = join(l.deviceDir, '.gen-aaaaaaaaaaaa');
  const staleWithFiles = join(l.deviceDir, '.gen-bbbbbbbbbbbb');
  const fresh = join(l.deviceDir, '.gen-cccccccccccc');
  const future = join(l.deviceDir, '.gen-dddddddddddd'); // clock jump: |Δ| is what counts
  const lookalike = join(l.deviceDir, '.gen-notours');
  const linkName = join(l.deviceDir, '.gen-eeeeeeeeeeee');
  const victim = join(dir, 'victim');
  for (const d of [stale, staleWithFiles, fresh, future, lookalike, victim]) await mkdir(d, { mode: 0o700 });
  await writeFile(join(staleWithFiles, 'key'), 'x', { mode: 0o600 });
  await writeFile(join(victim, 'precious'), 'x');
  await symlink(victim, linkName);
  const ago = (ms: number): Date => new Date(Date.now() - ms);
  await utimes(stale, ago(11 * 60_000), ago(11 * 60_000));
  await utimes(staleWithFiles, ago(3 * 3600_000), ago(3 * 3600_000));
  await utimes(fresh, ago(60_000), ago(60_000));
  await utimes(future, ago(-3 * 3600_000), ago(-3 * 3600_000));
  await utimes(lookalike, ago(3 * 3600_000), ago(3 * 3600_000));

  const keyBefore = await sha(l.keyFile);
  await initDevice(dir);
  const left = (await readdir(l.deviceDir)).sort();
  assert.deepEqual(left, ['.gen-cccccccccccc', '.gen-eeeeeeeeeeee', '.gen-notours', 'key', 'key.pub'].sort(), left.join(','));
  assert.equal(await readFile(join(victim, 'precious'), 'utf8'), 'x', 'symlink target untouched');
  assert.equal(await sha(l.keyFile), keyBefore);
});

/* ---------------- DK-7: derived root id ---------------- */

test('DK-7: init --root on a fresh install registers the key-derived id', { skip }, async (t) => {
  const dir = await ledger(t);
  const r = await initDevice(dir, { root: true });
  const l = deviceLayout(dir);
  assert.equal((await readDevices(l))?.devices[0]?.id, parseEd25519Pub(await readFile(l.pubFile, 'utf8'))?.deviceId);
  assert.equal(r.deviceId, (await readDevices(l))?.devices[0]?.id);
});

/* ---------------- enrolment: addDevice / adoptSlot ---------------- */

const entriesFor = (n: number, root: string): DevicesFile['devices'] =>
  Array.from({ length: n }, (_, i) => {
    const wire = Buffer.concat([Buffer.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32]), randomBytes(32)]);
    const pub = `ssh-ed25519 ${wire.toString('base64')}`;
    return {
      id: parseEd25519Pub(pub)?.deviceId ?? '', label: `dev-${String(i)}`, slot: SLOT_LETTERS[i] ?? '', pubkey: pub,
      added: '2026-11-16T10:00:00.000Z', added_by: root, revoked: null, role: 'owner' as const,
    };
  });

test('addDevice: lowest free slot, derived id, added_by = this device, fp must match, NOT auto-approved', { skip }, async (t) => {
  const dir = await ledger(t);
  const root = await initDevice(dir, { root: true });
  const l = deviceLayout(dir);
  const joiner = await otherDevice(t);
  const now = new Date('2026-11-16T12:00:00.000Z');

  const r = await addDevice(dir, joiner.pub, 'win', fpOf(joiner.pub), now);
  assert.deepEqual(r, { id: joiner.id, label: 'win', slot: 'A', fingerprint: fpOf(joiner.pub) });
  const entry = (await readDevices(l))?.devices.find((d) => d.id === joiner.id);
  assert.deepEqual(entry, { id: joiner.id, label: 'win', slot: 'A', pubkey: joiner.pub, added: now.toISOString(), added_by: root.deviceId, revoked: null, role: 'owner' });
  assert.deepEqual((await readSigners(l)).map((x) => x.id), [root.deviceId], 'adding does not trust the key');
  assert.equal((await listDevices(dir)).find((d) => d.id === joiner.id)?.trusted, false);
  assert.ok(!(await readdir(l.hubDir)).includes('device.lock'));
  // a peer would accept exactly this change (root signed it; commit time = now)
  const before = { devices: [(await readDevices(l))?.devices[0] as DevicesFile['devices'][number]] };
  const verdict = acceptDevicesChange(before, (await readDevices(l)) as DevicesFile, parseEd25519Pub(await readFile(l.pubFile, 'utf8'))?.line ?? '', new Set([before.devices[0]?.pubkey ?? '']), { commitTimeMs: now.getTime() });
  assert.equal(verdict.ok, true);

  // second device gets the next slot; a revoked device's slot is never reused
  const third = await otherDevice(t);
  assert.equal((await addDevice(dir, third.pub, 'phone', fpOf(third.pub), now)).slot, 'B');
  await approveDevice(dir, joiner.id, fpOf(joiner.pub));
  await revokeDevice(dir, joiner.id, 'lost', now);
  const fourth = await otherDevice(t);
  assert.equal((await addDevice(dir, fourth.pub, 'tab', fpOf(fourth.pub), now)).slot, 'C', 'A stays retired');
});

test('addDevice: refuses fingerprint mismatch, non-canonical key, bad label, duplicates, non-members, invalid fp', { skip }, async (t) => {
  const dir = await ledger(t);
  await initDevice(dir, { root: true });
  const l = deviceLayout(dir);
  const joiner = await otherDevice(t);
  const other = await otherDevice(t);
  const before = await sha(l.devicesYml);
  const code = (c: string) => (e: unknown): boolean => e instanceof DevicesError && e.code === c;

  await assert.rejects(addDevice(dir, joiner.pub, 'win', ''), code('FP_REQUIRED'));
  await assert.rejects(addDevice(dir, joiner.pub, 'win', fpOf(other.pub)), code('FP_MISMATCH'), 'fingerprint of another key');
  await assert.rejects(addDevice(dir, joiner.pub, 'win', 'SHA256:short'), code('FP_MISMATCH'));
  await assert.rejects(addDevice(dir, `${joiner.pub} laptop`, 'win', fpOf(joiner.pub)), code('KEY_INVALID'), 'comment');
  await assert.rejects(addDevice(dir, `${joiner.pub}\n`, 'win', fpOf(joiner.pub)), code('KEY_INVALID'), 'newline');
  await assert.rejects(addDevice(dir, `command="x" ${joiner.pub}`, 'win', fpOf(joiner.pub)), code('KEY_INVALID'), 'options');
  await assert.rejects(addDevice(dir, 'ssh-rsa AAAA', 'win', fpOf(joiner.pub)), code('KEY_INVALID'));
  await assert.rejects(addDevice(dir, joiner.pub, 'Bad Label!', fpOf(joiner.pub)), code('LABEL_INVALID'));
  await assert.rejects(addDevice(dir, joiner.pub, '../x', fpOf(joiner.pub)), code('LABEL_INVALID'));
  assert.equal(await sha(l.devicesYml), before, 'nothing written on refusal');

  await addDevice(dir, joiner.pub, 'win', fpOf(joiner.pub));
  await assert.rejects(addDevice(dir, joiner.pub, 'win2', fpOf(joiner.pub)), code('DEVICE_EXISTS'));
  // the root's own key
  const rootPub = (await readFile(l.pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
  await assert.rejects(addDevice(dir, rootPub, 'dup', fpOf(rootPub)), code('DEVICE_EXISTS'));

  // an unregistered machine and a revoked member cannot add
  const stranger = await ledger(t, 'c');
  await initDevice(stranger);
  await assert.rejects(addDevice(stranger, other.pub, 'x', fpOf(other.pub)), code('NOT_MEMBER'));
});

test('addDevice: a revoked acting device cannot add; an acting key that is not approved locally is refused by the self-check', { skip }, async (t) => {
  const { dir, self, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  const joiner = await otherDevice(t);
  // allowed_signers loses the acting device's own key → acceptDevicesChange (signer-untrusted) refuses
  await writeFile(l.allowedSigners, '', { mode: 0o600 });
  await assert.rejects(addDevice(dir, joiner.pub, 'win2', fpOf(joiner.pub)), (e: unknown) => e instanceof DevicesError && e.code === 'ADD_REFUSED' && /signer-untrusted/.test(e.message));
  // revoked acting device
  const file = (await readDevices(l)) as DevicesFile;
  const me = file.devices.find((d) => d.id === self);
  assert.ok(me);
  me.revoked = { at: '2026-11-17T08:00:00.000Z', by: other.id, reason: 'x' };
  await writeFile(l.devicesYml, renderDevicesYaml(file));
  await assert.rejects(addDevice(dir, joiner.pub, 'win2', fpOf(joiner.pub)), /revoked/);
});

test('DK-8: slots are exhausted after 24 letters (25 devices incl. the primary); the last free letter is still handed out', { skip }, async (t) => {
  const dir = await ledger(t);
  const root = await initDevice(dir, { root: true });
  const l = deviceLayout(dir);
  const file = (await readDevices(l)) as DevicesFile;
  const fake = entriesFor(SLOT_LETTERS.length - 1, root.deviceId); // A..X (23 letters), Y free... SLOT_LETTERS has 24
  file.devices.push(...fake);
  await writeFile(l.devicesYml, renderDevicesYaml(file));
  const j1 = await otherDevice(t);
  const last = await addDevice(dir, j1.pub, 'last', fpOf(j1.pub));
  assert.equal(last.slot, SLOT_LETTERS[SLOT_LETTERS.length - 1], 'the 24th letter is available');
  assert.equal((await readDevices(l))?.devices.length, SLOT_LETTERS.length + 1);
  const j2 = await otherDevice(t);
  const before = await sha(l.devicesYml);
  await assert.rejects(addDevice(dir, j2.pub, 'one-too-many', fpOf(j2.pub)), (e: unknown) => e instanceof DevicesError && e.code === 'SLOTS_EXHAUSTED');
  assert.equal(await sha(l.devicesYml), before);
  // revoked devices keep their slot: still exhausted
  await revokeDevice(dir, last.id, 'gone').catch(() => undefined);
  await assert.rejects(addDevice(dir, j2.pub, 'one-too-many', fpOf(j2.pub)), (e: unknown) => e instanceof DevicesError && e.code === 'SLOTS_EXHAUSTED');
});

test('adoptSlot: joiner takes the registered label + slot; idempotent; refused when not registered / id mismatch / revoked / ids already minted / other slot', { skip }, async (t) => {
  const trusted = await ledger(t, 't');
  await initDevice(trusted, { root: true });
  const joinerDir = await ledger(t, 'j');
  const j = await initDevice(joinerDir, { label: 'phone' });
  const lj = deviceLayout(joinerDir);
  const jpub = (await readFile(lj.pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
  const code = (c: string) => (e: unknown): boolean => e instanceof DevicesError && e.code === c;

  // no devices.yml yet
  await assert.rejects(adoptSlot(joinerDir), code('NOT_FOUND'));
  // synced in, but this key is not registered
  await writeFile(lj.devicesYml, await readFile(deviceLayout(trusted).devicesYml, 'utf8'));
  await assert.rejects(adoptSlot(joinerDir), code('NOT_REGISTERED'));

  // the trusted side registers it (label differs from the joiner's local one on purpose)
  await addDevice(trusted, jpub, 'pixel', fpOf(jpub));
  await writeFile(lj.devicesYml, await readFile(deviceLayout(trusted).devicesYml, 'utf8'));
  const r = await adoptSlot(joinerDir);
  assert.deepEqual(r, { id: j.deviceId, label: 'pixel', slot: 'A', changed: true });
  const dev = parseYaml(await readFile(lj.deviceYml, 'utf8')) as Record<string, string>;
  assert.deepEqual(dev, { device_id: j.deviceId, label: 'pixel', slot: 'A', key_fp: fpOf(jpub) });
  assert.equal(await mode(lj.deviceYml), 0o600);
  assert.deepEqual(await adoptSlot(joinerDir), { id: j.deviceId, label: 'pixel', slot: 'A', changed: false });
  assert.ok(!(await readdir(lj.hubDir)).includes('device.lock'));

  // another slot in the registry than the one already held → refused, file untouched
  const reg = (await readDevices(lj)) as DevicesFile;
  const mine = reg.devices.find((d) => d.id === j.deviceId);
  assert.ok(mine);
  mine.slot = 'B';
  await writeFile(lj.devicesYml, renderDevicesYaml(reg));
  await assert.rejects(adoptSlot(joinerDir), code('SLOT_CONFLICT'));
  mine.slot = 'A';
  mine.revoked = { at: '2026-11-17T08:00:00.000Z', by: reg.devices[0]?.id ?? '', reason: 'lost' };
  await writeFile(lj.devicesYml, renderDevicesYaml(reg));
  await assert.rejects(adoptSlot(joinerDir), code('REVOKED'));

  // ids already minted under slot "" → refuse to switch
  const used = await ledger(t, 'u');
  const u = await initDevice(used);
  const lu = deviceLayout(used);
  await mkdir(join(used, 'counters'));
  await writeFile(join(used, 'counters', `${u.deviceId}.yml`), 'ops: 1\n', { mode: 0o600 });
  const upub = (await readFile(lu.pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
  await addDevice(trusted, upub, 'used', fpOf(upub));
  await writeFile(lu.devicesYml, await readFile(deviceLayout(trusted).devicesYml, 'utf8'));
  await assert.rejects(adoptSlot(used), code('ADOPT_USED'));
  assert.equal((parseYaml(await readFile(lu.deviceYml, 'utf8')) as Record<string, string>).slot, '');

  // legacy random id on the joiner can never match the derived registered id
  const legacy = await ledger(t, 'l');
  await initDevice(legacy);
  const ll = deviceLayout(legacy);
  await writeFile(ll.deviceYml, 'device_id: d_abcdefghij\nlabel: mac\nslot: ""\n', { mode: 0o600 });
  const lpub = (await readFile(ll.pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
  await addDevice(trusted, lpub, 'legacy', fpOf(lpub));
  await writeFile(ll.devicesYml, await readFile(deviceLayout(trusted).devicesYml, 'utf8'));
  await assert.rejects(adoptSlot(legacy), code('ID_MISMATCH'));

  // a loose private key is refused before anything is adopted
  await chmod(lu.keyFile, 0o644);
  await assert.rejects(adoptSlot(used));
});

/* ---------------- B3a: exported lock (AL-23), AL-16 takeover, pruneRevokedSigners (AL-45) ---------------- */

const lockFile = (dir: string): string => join(deviceLayout(dir).hubDir, 'device.lock');

test('AL-23: withDeviceLock serialises in-process callers and releases the lock', { skip }, async (t) => {
  const dir = await ledger(t);
  const order: string[] = [];
  const hold = (tag: string): Promise<void> =>
    withDeviceLock(dir, async () => {
      order.push(`in-${tag}`);
      await new Promise((r) => setTimeout(r, 30));
      order.push(`out-${tag}`);
    });
  await Promise.all([hold('a'), hold('b'), hold('c')]);
  for (let i = 0; i < order.length; i += 2) assert.equal(order[i]?.slice(3), order[i + 1]?.slice(4), `interleaved: ${order.join(',')}`);
  assert.ok(!(await readdir(deviceLayout(dir).hubDir)).some((n) => n.startsWith('device.lock')), 'lock + takeover mutex released');
  // returns fn's value, propagates its error, still releases
  assert.equal(await withDeviceLock(dir, async () => 7), 7);
  await assert.rejects(withDeviceLock(dir, async () => { throw new Error('boom'); }), /boom/);
  assert.equal(await withDeviceLock(dir, async () => 8, { waitMs: 0 }), 8);
});

test('AL-23: waitMs is honoured (LOCKED after ~waitMs, not the 10 s default); 0 and negative = no wait', { skip }, async (t) => {
  const dir = await ledger(t);
  await ensureLockDir(dir);
  await writeFile(lockFile(dir), `${String(process.pid)} ${String(Date.now())} cafe\n`, { mode: 0o600 }); // live holder (us), fresh
  const isLocked = (e: unknown): boolean => e instanceof DevicesError && e.code === 'LOCKED';
  let t0 = Date.now();
  await assert.rejects(withDeviceLock(dir, async () => 1, { waitMs: 200 }), isLocked);
  let took = Date.now() - t0;
  assert.ok(took >= 150 && took < 3000, `waited ${String(took)} ms`);
  t0 = Date.now();
  await assert.rejects(withDeviceLock(dir, async () => 1, { waitMs: 0 }), isLocked);
  took = Date.now() - t0;
  assert.ok(took < 1000, `waitMs 0 must not wait (${String(took)} ms)`);
  t0 = Date.now();
  await assert.rejects(withDeviceLock(dir, async () => 1, { waitMs: -5 }), isLocked); // negative = 0, never a long wait
  assert.ok(Date.now() - t0 < 1000);
  assert.match(await readFile(lockFile(dir), 'utf8'), /cafe/, 'the foreign lock was not deleted');
});

async function ensureLockDir(dir: string): Promise<void> {
  await mkdir(deviceLayout(dir).hubDir, { recursive: true, mode: 0o700 });
}

const CHILD = `
import { writeFile, readFile, rm } from 'node:fs/promises';
const [mod, dir, startAt, n] = process.argv.slice(1);
const { withDeviceLock } = await import(mod);
while (Date.now() < Number(startAt)) await new Promise((r) => setTimeout(r, 1));
let violations = 0;
for (let i = 0; i < Number(n); i += 1) {
  await withDeviceLock(dir, async () => {
    let created = false;
    try { await writeFile(dir + '/holder', String(process.pid), { flag: 'wx' }); created = true; } catch { violations += 1; }
    const cur = Number(await readFile(dir + '/counter', 'utf8'));
    await new Promise((r) => setTimeout(r, 2));
    await writeFile(dir + '/counter', String(cur + 1));
    if (created) await rm(dir + '/holder', { force: true });
  }, { waitMs: 30000 });
}
console.log(JSON.stringify({ violations }));
`;

function runChild(mod: string, dir: string, startAt: number, n: number): Promise<{ violations: number }> {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ['--input-type=module', '-e', CHILD, mod, dir, String(startAt), String(n)], { timeout: 60_000 }, (err, stdout, stderr) => {
      if (err !== null) reject(new Error(`child failed: ${stderr.slice(0, 500)}`));
      else resolve(JSON.parse(stdout.trim().split('\n').pop() as string) as { violations: number });
    });
  });
}

test('AL-16: 8 processes race on one STALE lock: exactly one holder at a time, no lost update, no leftovers', { skip }, async (t) => {
  const mod = pathToFileURL(fileURLToPath(new URL('./devicestore.ts', import.meta.url))).href;
  const old = new Date(Date.now() - 60_000);
  for (let round = 0; round < 3; round++) {
    const dir = await ledger(t, `lk${String(round)}`);
    await ensureLockDir(dir);
    await writeFile(join(dir, 'counter'), '0');
    const lock = lockFile(dir);
    await writeFile(lock, round === 1 ? '' : '2147480000 1 deadbeef\n', { mode: 0o600 }); // dead holder / empty file
    await utimes(lock, old, old);
    const startAt = Date.now() + 1500;
    const per = 3;
    const out = await Promise.all(Array.from({ length: 8 }, () => runChild(mod, dir, startAt, per)));
    assert.deepEqual(out.map((o) => o.violations), Array(8).fill(0), `round ${String(round)}: two holders at once`);
    assert.equal(Number(await readFile(join(dir, 'counter'), 'utf8')), 8 * per, `round ${String(round)}: lost update`);
    const left = (await readdir(deviceLayout(dir).hubDir)).filter((n) => n.startsWith('device.lock'));
    assert.deepEqual(left, [], 'no lock or takeover mutex left behind');
  }
});

test('AL-16: a takeover mutex held by someone else defers the takeover; a crashed (old) mutex is cleared and the stale lock then taken', { skip }, async (t) => {
  const dir = await ledger(t);
  await ensureLockDir(dir);
  const lock = lockFile(dir);
  const old = new Date(Date.now() - 60_000);
  await writeFile(lock, '2147480000 1 deadbeef\n', { mode: 0o600 });
  await utimes(lock, old, old);
  await writeFile(`${lock}.takeover`, `${String(process.pid)} ${String(Date.now())} beef\n`, { mode: 0o600 }); // fresh = a live taker
  await assert.rejects(withDeviceLock(dir, async () => 1, { waitMs: 150 }), (e: unknown) => e instanceof DevicesError && e.code === 'LOCKED');
  assert.match(await readFile(lock, 'utf8'), /deadbeef/, 'stale lock untouched while another process takes it over');
  // the taker crashed long ago: its mutex is cleared, then the stale lock is taken over
  await utimes(`${lock}.takeover`, old, old);
  assert.equal(await withDeviceLock(dir, async () => 'ok', { waitMs: 3000 }), 'ok');
  assert.deepEqual((await readdir(deviceLayout(dir).hubDir)).filter((n) => n.startsWith('device.lock')), []);
});

test('AL-16: a fresh lock, or an old lock of a LIVE pid, is never removed by the takeover path', { skip }, async (t) => {
  const dir = await ledger(t);
  await ensureLockDir(dir);
  const lock = lockFile(dir);
  const old = new Date(Date.now() - 60_000);
  // fresh LIVE lock (as if another process just won the takeover and created its lock): never removed
  await writeFile(lock, `${String(process.pid)} ${String(Date.now())} fresh\n`, { mode: 0o600 });
  await assert.rejects(withDeviceLock(dir, async () => 1, { waitMs: 100 }), (e: unknown) => e instanceof DevicesError && e.code === 'LOCKED');
  assert.match(await readFile(lock, 'utf8'), /fresh/);
  // an old but LIVE-pid lock is only abandoned after 5 min (recycled pid must not wedge, a live one must not be robbed early)
  await utimes(lock, old, old);
  await assert.rejects(withDeviceLock(dir, async () => 1, { waitMs: 100 }), (e: unknown) => e instanceof DevicesError && e.code === 'LOCKED');
});

test('AL-45: pruneRevokedSigners removes ONLY revoked signers, by id or key; never adds; idempotent; touches nothing when clean', { skip }, async (t) => {
  const { dir, self, other } = await twoDevices(t);
  const l = deviceLayout(dir);
  assert.deepEqual(await pruneRevokedSigners(dir), { removed: [] }, 'nothing revoked');
  await approveDevice(dir, other.id, fpOf(other.pub));
  const before = await sha(l.allowedSigners);
  assert.deepEqual(await pruneRevokedSigners(dir), { removed: [] });
  assert.equal(await sha(l.allowedSigners), before, 'clean prune does not rewrite the file');
  // the remote revocation lands in devices.yml (APPLY) but allowed_signers still trusts the key
  const reg = (await readDevices(l)) as DevicesFile;
  const o = reg.devices.find((d) => d.id === other.id);
  assert.ok(o);
  o.revoked = { at: '2026-11-17T08:00:00.000Z', by: self, reason: 'lost' };
  await writeFile(l.devicesYml, renderDevicesYaml(reg), { mode: 0o600 });
  assert.deepEqual((await readSigners(l)).map((x) => x.id).sort(), [self, other.id].sort());
  assert.deepEqual(await pruneRevokedSigners(dir), { removed: [other.id] });
  assert.deepEqual((await readSigners(l)).map((x) => x.id), [self]);
  assert.equal(await mode(l.allowedSigners), 0o600);
  assert.deepEqual(await pruneRevokedSigners(dir), { removed: [] }, 'idempotent');
  // never adds: an ACTIVE registered device that was never approved stays unapproved
  const third = await otherDevice(t);
  const reg2 = (await readDevices(l)) as DevicesFile;
  reg2.devices.push({ id: third.id, label: 'x', slot: 'X', pubkey: third.pub, added: '2026-11-17T08:00:00.000Z', added_by: self, revoked: null, role: 'owner' });
  await writeFile(l.devicesYml, renderDevicesYaml(reg2), { mode: 0o600 });
  await pruneRevokedSigners(dir);
  assert.deepEqual((await readSigners(l)).map((x) => x.id), [self]);
  // no devices.yml / no allowed_signers: removes nothing, creates nothing
  const bare = await ledger(t, 'bare');
  assert.deepEqual(await pruneRevokedSigners(bare), { removed: [] });
  assert.ok(!(await readdir(bare)).includes('.hub'), 'no files created');
});

test('AL-45: pruneRevokedSigners fails closed on an invalid devices.yml / allowed_signers (throws, signers untouched)', { skip }, async (t) => {
  const { dir, other, self } = await twoDevices(t);
  const l = deviceLayout(dir);
  await approveDevice(dir, other.id, fpOf(other.pub));
  const before = await readFile(l.allowedSigners, 'utf8');
  await writeFile(l.devicesYml, '{{{ not yaml', { mode: 0o600 });
  await assert.rejects(pruneRevokedSigners(dir));
  assert.equal(await readFile(l.allowedSigners, 'utf8'), before);
  void self;
});

test('AL-45: approve racing prune (both under the device lock) never resurrects a revoked key', { skip }, async (t) => {
  for (let round = 0; round < 6; round++) {
    const { dir, self, other } = await twoDevices(t);
    const l = deviceLayout(dir);
    const reg = (await readDevices(l)) as DevicesFile;
    const o = reg.devices.find((d) => d.id === other.id);
    assert.ok(o);
    o.revoked = { at: '2026-11-17T08:00:00.000Z', by: self, reason: 'lost' };
    await writeFile(l.devicesYml, renderDevicesYaml(reg), { mode: 0o600 });
    const jobs = [
      approveDevice(dir, other.id, fpOf(other.pub)),
      withDeviceLock(dir, () => pruneRevokedSigners(dir)),
      approveDevice(dir, other.id, fpOf(other.pub)),
      withDeviceLock(dir, () => pruneRevokedSigners(dir)),
    ];
    if (round % 2 === 1) jobs.reverse();
    const res = await Promise.allSettled(jobs);
    for (const r of res) if (r.status === 'rejected') assert.ok(r.reason instanceof DevicesError && r.reason.code === 'REVOKED', `round ${String(round)}: ${String(r.reason)}`);
    assert.equal((await readSigners(l)).some((x) => x.id === other.id), false, `round ${String(round)}: revoked key trusted`);
  }
});
