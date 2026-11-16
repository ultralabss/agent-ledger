/** Multi-device F2 on the hub side: `device init` and the hub agree on one identity, and the
 *  key material can never reach git (`.hub/` is ignored). docs/multi-device-spec.md §2.1, §8 T1/T10. */

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { deviceLayout, initDevice } from '@agent-ledger/shared';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { git } from '../git.ts';
import { tempConfig } from '../test-helpers.ts';
import { Ledger } from './ledger.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

async function boot(dir: string, config: Awaited<ReturnType<typeof tempConfig>>['config']): Promise<Ledger> {
  const ledger = new Ledger({ config, log: () => undefined });
  await ledger.init();
  await git(dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(dir, ['config', 'user.name', 'agent-ledger test']);
  return ledger;
}

test('fresh install: `device init` first → the hub adopts the key-derived device_id', { skip }, async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const r = await initDevice(tmp.dir, { label: 'mac' });
  const ledger = await boot(tmp.dir, tmp.config);
  t.after(() => ledger.close());
  assert.equal(ledger.device.device_id, r.deviceId);
  assert.equal(ledger.device.slot, '');
});

test('hub booted first (F1 random id) → `device init --root` is refused (LEGACY_ID); explicit rekeyLegacy re-keys to the key-derived id', { skip }, async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const first = await boot(tmp.dir, tmp.config);
  const f1Id = first.device.device_id;
  await first.close();

  await assert.rejects(() => initDevice(tmp.dir, { root: true }), /LEGACY_ID|legacy random id/);
  const r = await initDevice(tmp.dir, { root: true, rekeyLegacy: true });
  assert.notEqual(r.deviceId, f1Id, 're-keyed to the key-derived id');

  const again = await boot(tmp.dir, tmp.config);
  t.after(() => again.close());
  assert.equal(again.device.device_id, r.deviceId);
  assert.match(await readFile(deviceLayout(tmp.dir).deviceYml, 'utf8'), /key_fp: SHA256:/);
});

test('key material never reaches git: `.hub/` is ignored, devices.yml (public) is not', { skip }, async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const ledger = await boot(tmp.dir, tmp.config);
  await ledger.close();
  await initDevice(tmp.dir, { root: true, rekeyLegacy: true });

  for (const p of ['.hub/device/key', '.hub/device/key.pub', '.hub/device.yml', '.hub/allowed_signers', '.hub/tmp/x']) {
    const res = await git(tmp.dir, ['check-ignore', '-q', p]);
    assert.equal(res.code, 0, `${p} must be gitignored`);
  }
  const add = await git(tmp.dir, ['add', '-A']);
  assert.equal(add.code, 0, add.stderr);
  const staged = (await git(tmp.dir, ['ls-files'])).stdout.split('\n');
  assert.ok(staged.includes('devices.yml'), 'public registry is synced');
  assert.deepEqual(staged.filter((f) => f.startsWith('.hub/') || /(^|\/)key(\.pub)?$/.test(f)), []);
  const text = await readFile(join(tmp.dir, 'devices.yml'), 'utf8');
  assert.ok(!/PRIVATE|BEGIN OPENSSH/.test(text));
});
