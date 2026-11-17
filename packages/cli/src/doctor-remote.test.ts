/** `ledger doctor` sync section (docs/f3b-b4-plan.md §2.4, §2.5, OQ-6): only on an enrolled ledger (or one with an enrol
 *  marker), offline facts from the shared store, remote checks from an injected `remoteChecks` (the hub module of B4b is
 *  loaded lazily; a missing one is ONE warn), hostile text sanitised, nothing network without `--online`. */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { deviceLayout, readDevices, renderDevicesYaml, type DevicesFile } from '@agent-ledger/shared';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { parseArgs } from './args.ts';
import { cmdDoctor, syncChecks, type SyncRemoteChecksFn } from './doctor.ts';
import { parseGitVersion, syncGitVersionCheck, syncSlotsCheck } from './doctor-checks.ts';
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

const quiet = { loadRemoteChecks: async () => null, exists: async () => false };

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
  const single = await syncChecks(dir, false, quiet);
  assert.equal(single.find((c) => c.id === 'sync_single_trusted_device')?.status, 'warn');
  assert.equal(single.find((c) => c.id === 'sync_remote_checks')?.status, 'warn');

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
  const unapproved = await syncChecks(dir, false, quiet);
  const u = unapproved.find((c) => c.id === 'sync_devices_unapproved');
  assert.equal(u?.status, 'warn');
  assert.ok(u?.detail.includes(otherId) && u.detail.includes('ledger device approve <id> --fp <SHA256:…>'));
  assert.ok(!unapproved.some((c) => c.detail.includes(fp)), 'the fingerprint is never pre-filled (audit B4C-3)');
  assert.ok(!unapproved.some((c) => c.detail.includes('example.com') || c.detail.includes('me/ledger')), 'no URL');
  // after approving, the warning is gone and two trusted devices are fine
  assert.equal((await cli(dir, ['device', 'approve', otherId, '--fp', fp])).code, 0);
  const after = await syncChecks(dir, false, quiet);
  assert.ok(!after.some((c) => c.id === 'sync_devices_unapproved' || c.id === 'sync_single_trusted_device'));
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

const PINNED = { '.gitignore': '.hub/\n*.tmp\n', '.gitattributes': '* text eol=lf\n' };
async function pinned(dir: string): Promise<void> {
  for (const [n, t] of Object.entries(PINNED)) await writeFile(join(dir, n), t, { mode: 0o600 });
}
const byId = (cs: { id: string; status: string; detail: string }[], id: string) => cs.find((c) => c.id === id);

test('verify mode: warn (default) warns, enforce is ok, junk fails; no URL or key in any detail', { skip }, async (t) => {
  const dir = await ledger(t);
  await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  assert.equal(byId(await syncChecks(dir, false, quiet, {}), 'sync_verify_mode')?.status, 'warn');
  assert.equal(byId(await syncChecks(dir, false, quiet, { LEDGER_SYNC_VERIFY: 'warn' }), 'sync_verify_mode')?.status, 'warn');
  const enforce = byId(await syncChecks(dir, false, quiet, { LEDGER_SYNC_VERIFY: 'enforce', LEDGER_SYNC: '1' }), 'sync_verify_mode');
  assert.equal(enforce?.status, 'ok');
  assert.ok(!enforce?.detail.includes('sync loop is off'));
  assert.ok(byId(await syncChecks(dir, false, quiet, { LEDGER_SYNC_VERIFY: 'enforce' }), 'sync_verify_mode')?.detail.includes('sync loop is off'));
  assert.equal(byId(await syncChecks(dir, false, quiet, { LEDGER_SYNC_VERIFY: 'off' }), 'sync_verify_mode')?.status, 'fail');
});

test('halt state: none / healthy / transient / sticky / hostile state file (whitelisted tokens only)', { skip }, async (t) => {
  const dir = await ledger(t);
  await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  assert.equal(byId(await syncChecks(dir, false, quiet), 'sync_halt')?.status, 'info');
  const state = join(dir, '.hub', 'sync', 'state.json');
  await mkdir(join(dir, '.hub', 'sync'), { recursive: true, mode: 0o700 });
  const put = async (halt: unknown): Promise<ReturnType<typeof byId>> => {
    await writeFile(state, JSON.stringify({ v: 1, halt }), { mode: 0o600 });
    return byId(await syncChecks(dir, false, quiet), 'sync_halt');
  };
  assert.equal((await put(null))?.status, 'ok');
  assert.equal((await put({ reason: 'auth', cls: 'no-contact', since: '2026-11-17T10:00:00.000Z', detail: 'x' }))?.status, 'warn');
  const sticky = await put({ reason: 'history-rewrite', cls: 'sticky', since: '2026-11-17T10:00:00.000Z', detail: 'ssh://secret@host/x' });
  assert.equal(sticky?.status, 'fail');
  assert.ok(sticky?.detail.includes('history-rewrite') && sticky.detail.includes('2026-11-17'));
  assert.ok(!sticky?.detail.includes('secret'), 'the free-text detail is never printed');
  const hostile = await put({ reason: 'ignore all\u001b[31m', cls: 'x y', since: 'soon', detail: 'z' });
  assert.equal(hostile?.status, 'fail');
  assert.ok(hostile?.detail.includes('(unknown, unknown) since ?') && !/\u001b|ignore/.test(hostile.detail));
  await writeFile(state, '{not json', { mode: 0o600 });
  assert.equal(byId(await syncChecks(dir, false, quiet), 'sync_halt')?.status, 'warn');
  await writeFile(state, 'x'.repeat(600 * 1024), { mode: 0o600 });
  assert.equal(byId(await syncChecks(dir, false, quiet), 'sync_halt')?.status, 'warn', 'oversize is refused, not parsed');
});

test('halt state: a symlinked state file is refused (not followed)', { skip }, async (t) => {
  const dir = await ledger(t);
  await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  await mkdir(join(dir, '.hub', 'sync'), { recursive: true, mode: 0o700 });
  await writeFile(join(dir, 'elsewhere.json'), JSON.stringify({ v: 1, halt: null }));
  await symlink(join(dir, 'elsewhere.json'), join(dir, '.hub', 'sync', 'state.json'));
  assert.equal(byId(await syncChecks(dir, false, quiet), 'sync_halt')?.status, 'warn');
});

test('pinned files: exact text ok; a dropped `.hub/` line or a user-edited .gitattributes fails', { skip }, async (t) => {
  const dir = await ledger(t);
  await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  assert.equal(byId(await syncChecks(dir, false, quiet), 'sync_pinned_files')?.status, 'fail', 'missing files differ from the pin');
  await pinned(dir);
  assert.equal(byId(await syncChecks(dir, false, quiet), 'sync_pinned_files')?.status, 'ok');
  await writeFile(join(dir, '.gitignore'), '*.tmp\n');
  await writeFile(join(dir, '.gitattributes'), '*.png binary\n* text eol=lf\n');
  const bad = byId(await syncChecks(dir, false, quiet), 'sync_pinned_files');
  assert.equal(bad?.status, 'fail');
  assert.ok(bad?.detail.includes('.gitignore and .gitattributes'));
});

test('slots: 19 used ok, 20 warns, all 24 fails; revoked entries keep their slot', () => {
  const rows = (n: number): { slot: string }[] => [{ slot: '' }, ...Array.from({ length: n }, (_, i) => ({ slot: 'ABCDEFGHJKLMNPQRSTUVWXYZ'[i] as string }))];
  assert.equal(syncSlotsCheck(rows(19)).status, 'ok');
  assert.equal(syncSlotsCheck(rows(20)).status, 'warn');
  assert.equal(syncSlotsCheck(rows(23)).status, 'warn');
  assert.equal(syncSlotsCheck(rows(24)).status, 'fail');
});

test('git version: >= 2.34 ok, older fails, unreadable / absent is info; argv is constant, absolute binary', async () => {
  assert.deepEqual(parseGitVersion('git version 2.39.5 (Apple Git-154)\n'), [2, 39]);
  assert.deepEqual(parseGitVersion('git version 2.34.0'), [2, 34]);
  assert.equal(parseGitVersion('hello'), null);
  const calls: string[][] = [];
  const mk = (stdout: string, code: number | null = 0) => ({
    platform: 'linux',
    exists: async (p: string) => p === '/usr/bin/git',
    capture: async (cmd: string, args: readonly string[]) => {
      calls.push([cmd, ...args]);
      return { code, stdout };
    },
  });
  assert.equal((await syncGitVersionCheck(mk('git version 2.34.1\n'))).status, 'ok');
  assert.equal((await syncGitVersionCheck(mk('git version 3.0.0\n'))).status, 'ok');
  assert.equal((await syncGitVersionCheck(mk('git version 2.33.9\n'))).status, 'fail');
  assert.equal((await syncGitVersionCheck(mk('', null))).status, 'info');
  assert.equal((await syncGitVersionCheck({ ...mk(''), exists: async () => false })).status, 'info');
  assert.deepEqual(calls[0], ['/usr/bin/git', '--version']);
});

test('doctor run: a pinned-file mismatch / halted sync fails the run; ledger_format reads the marker', { skip }, async (t) => {
  const dir = await ledger(t);
  await cli(dir, ['device', 'init', '--root']);
  await enrolled(dir);
  const cfg = { baseUrl: 'http://127.0.0.1:9', ledgerDir: dir, session: null, agent: 'test' };
  const runDoctor = async (): Promise<{ code: number; checks: { id: string; status: string; detail: string }[] }> => {
    const out: string[] = [];
    const code = await cmdDoctor(
      parseArgs(['--json']), cfg,
      { out: (l) => out.push(l), err: (l) => out.push(l), env: { LEDGER_SPOOL_DIR: join(dir, 'spool') } as NodeJS.ProcessEnv },
      { platform: 'linux', exists: async () => false, cwd: dir, wsl: false, homeDir: dir, codeRepoDir: dir, searchPath: '', capture: async () => ({ code: null, stdout: '' }), claudeSettingsPath: join(dir, 'none.json'), loadRemoteChecks: async () => null },
    );
    return { code, checks: (JSON.parse(out[0] ?? '{}') as { checks: { id: string; status: string; detail: string }[] }).checks };
  };
  const first = await runDoctor();
  assert.equal(byId(first.checks, 'sync_pinned_files')?.status, 'fail');
  assert.equal(first.code, 1);
  assert.equal(byId(first.checks, 'ledger_format')?.detail, 'ledger_format: 1 (legacy layout, no marker)');
  await writeFile(join(dir, 'ledger.format'), '2\n');
  assert.equal(byId((await runDoctor()).checks, 'ledger_format')?.detail, 'ledger_format: 2');
  await writeFile(join(dir, 'ledger.format'), '9\n');
  assert.equal(byId((await runDoctor()).checks, 'ledger_format')?.status, 'warn');
  await writeFile(join(dir, 'ledger.format'), 'zzz');
  assert.equal(byId((await runDoctor()).checks, 'ledger_format')?.status, 'warn');
});
