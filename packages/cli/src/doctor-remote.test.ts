/** `ledger doctor` sync section (docs/f3b-b4-plan.md §2.4, §2.5, OQ-6): only on an enrolled ledger (or one with an enrol
 *  marker), offline facts from the shared store, remote checks from an injected `remoteChecks` (the hub module of B4b is
 *  loaded lazily; a missing one is ONE warn), hostile text sanitised, nothing network without `--online`. */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { deviceLayout, readDevices, renderDevicesYaml, type DevicesFile } from '@agent-ledger/shared';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { parseArgs } from './args.ts';
import { cmdDoctor, syncChecks, type SyncRemoteChecksFn } from './doctor.ts';
import { run, type Io } from './index.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

async function ledger(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-doctor-sync-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function cli(dir: string, argv: string[]): Promise<{ code: number; out: string[] }> {
  const out: string[] = [];
  const io: Io = { out: (l) => out.push(l), err: (l) => out.push(l), env: { LEDGER_DIR: dir, LEDGER_HUB_URL: 'http://127.0.0.1:9' }, cwd: dir };
  return { code: await run(argv, io), out };
}

async function enrolled(dir: string): Promise<void> {
  await mkdir(join(dir, '.hub'), { recursive: true, mode: 0o700 });
  await writeFile(join(dir, '.hub', 'sync.yml'), 'v: 1\nremote: git@example.com:me/ledger.git\n', { mode: 0o600 });
}

test('not enrolled and no marker: no sync checks at all', { skip }, async (t) => {
  const dir = await ledger(t);
  await cli(dir, ['device', 'init', '--root']);
  assert.deepEqual(await syncChecks(dir, false, { loadRemoteChecks: async () => { throw new Error('must not load'); } }), []);
});

test('enrolled: single trusted device warns; a peer-registered device that is not approved warns with the exact command (OQ-6)', { skip }, async (t) => {
  const dir = await ledger(t);
  const init = await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  const single = await syncChecks(dir, false, { loadRemoteChecks: async () => null });
  assert.deepEqual(single.map((c) => [c.id, c.status]), [['sync_single_trusted_device', 'warn'], ['sync_remote_checks', 'warn']]);

  // a second machine registered by a peer (devices.yml only), NOT approved here
  const dir2 = await ledger(t);
  const other = await cli(dir2, ['device', 'init', '--label', 'win']);
  const otherId = /d_[a-z2-7]{10}/.exec(other.out.join('\n'))?.[0] as string;
  const fp = other.out[1]?.match(/SHA256:\S{43}/)?.[0] as string;
  const pub = (await readFile(deviceLayout(dir2).pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
  const l = deviceLayout(dir);
  const file = (await readDevices(l)) as DevicesFile;
  file.devices.push({ id: otherId, label: 'win', slot: 'W', pubkey: pub, added: '2026-11-16T10:00:00.000Z', added_by: /d_[a-z2-7]{10}/.exec(init.out.join('\n'))?.[0] as string, revoked: null, role: 'owner' });
  await writeFile(l.devicesYml, renderDevicesYaml(file));
  const unapproved = await syncChecks(dir, false, { loadRemoteChecks: async () => null });
  const u = unapproved.find((c) => c.id === 'sync_devices_unapproved');
  assert.equal(u?.status, 'warn');
  assert.ok(u?.detail.includes(`ledger device approve ${otherId} --fp ${fp}`));
  assert.ok(!unapproved.some((c) => c.detail.includes('example.com') || c.detail.includes('me/ledger')), 'no URL');
  // after approving, the warning is gone and two trusted devices are fine
  assert.equal((await cli(dir, ['device', 'approve', otherId, '--fp', fp])).code, 0);
  assert.deepEqual((await syncChecks(dir, false, { loadRemoteChecks: async () => null })).map((c) => c.id), ['sync_remote_checks']);
});

test('remote checks: injected module output is validated, sanitised, de-duplicated and capped; `--online` reaches it; failures are one warn', { skip }, async (t) => {
  const dir = await ledger(t);
  await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  const seen: { online: boolean; ledgerDir: string }[] = [];
  const fn: SyncRemoteChecksFn = async (d) => {
    seen.push({ online: d.online, ledgerDir: d.ledgerDir });
    return [
      { id: 'sync_remote_anonymous', status: 'fail', detail: 'remote answers without a credential \u001b[31mPUBLIC‮' },
      { id: 'sync_remote_anonymous', status: 'ok', detail: 'duplicate id is dropped' },
      { id: 'BAD ID', status: 'ok', detail: 'bad id is dropped' },
      { id: 'sync_x', status: 'weird' as never, detail: 'bad status is dropped' },
      { id: 'sync_git_config', status: 'warn', detail: 'origin is a local path (tolerated)' },
    ];
  };
  const out = await syncChecks(dir, true, { loadRemoteChecks: async () => fn });
  assert.deepEqual(seen, [{ online: true, ledgerDir: dir }]);
  const ids = out.map((c) => c.id);
  assert.ok(ids.includes('sync_remote_anonymous') && ids.includes('sync_git_config'));
  assert.ok(!ids.includes('BAD ID') && !ids.includes('sync_x'));
  assert.equal(ids.filter((i) => i === 'sync_remote_anonymous').length, 1);
  assert.ok(!/[\u001b‮]/.test(out.map((c) => c.detail).join('\n')));
  await syncChecks(dir, false, { loadRemoteChecks: async () => fn });
  assert.equal(seen[1]?.online, false, 'no network flag without --online');

  const boom = await syncChecks(dir, false, { loadRemoteChecks: async () => async () => { throw new Error('boom'); } });
  assert.ok(boom.some((c) => c.id === 'sync_remote_checks' && c.status === 'warn'));
  const loaderBoom = await syncChecks(dir, false, { loadRemoteChecks: async () => { throw new Error('boom'); } });
  assert.ok(loaderBoom.some((c) => c.id === 'sync_remote_checks' && c.status === 'warn'), 'a missing module is a warn, never a crash');
});

test('an enrolment marker alone (hub kept down) is reported, and the doctor run wires the section in; a `fail` makes the run fail', { skip }, async (t) => {
  const dir = await ledger(t);
  await mkdir(join(dir, '.hub', 'sync'), { recursive: true, mode: 0o700 });
  await writeFile(join(dir, '.hub', 'sync', 'enrol.json'), '{}', { mode: 0o600 });
  assert.deepEqual((await syncChecks(dir, false, { loadRemoteChecks: async () => null })).map((c) => c.id), ['sync_enrol_marker', 'sync_remote_checks']);

  await rm(join(dir, '.hub', 'sync'), { recursive: true });
  await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  const cfg = { baseUrl: 'http://127.0.0.1:9', ledgerDir: dir, session: null, agent: 'test' };
  const out: string[] = [];
  const code = await cmdDoctor(
    parseArgs(['--json']),
    cfg,
    { out: (l) => out.push(l), err: (l) => out.push(l), env: { LEDGER_SPOOL_DIR: join(dir, 'spool') } as NodeJS.ProcessEnv },
    {
      platform: 'linux', exists: async () => false, cwd: dir, wsl: false, homeDir: dir, codeRepoDir: dir, searchPath: '',
      capture: async () => ({ code: null, stdout: '' }), claudeSettingsPath: join(dir, 'none.json'),
      loadRemoteChecks: async () => async () => [{ id: 'sync_remote_anonymous', status: 'fail', detail: 'remote answers without a credential' }],
    },
  );
  const checks = (JSON.parse(out[0] ?? '{}') as { checks: { id: string; status: string }[] }).checks;
  assert.equal(checks.find((c) => c.id === 'sync_remote_anonymous')?.status, 'fail');
  assert.ok(checks.some((c) => c.id === 'sync_single_trusted_device'));
  assert.equal(code, 1);
});
