/** `ledger device …` end to end through the real CLI entry (no hub, no network), plus the
 *  doctor wiring. Real ssh-keygen; POSIX modes (win32 skipped, NOT verified there). */

import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { deviceLayout, readDevices, renderDevicesYaml, type DevicesFile } from '@agent-ledger/shared';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { parseArgs } from './args.ts';
import { cmdDoctor } from './doctor.ts';
import { run, type Io } from './index.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

async function ledger(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-clidev-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function ledgerCli(dir: string, argv: string[]): Promise<{ code: number; out: string[]; err: string[] }> {
  const out: string[] = [];
  const err: string[] = [];
  const io: Io = { out: (l) => out.push(l), err: (l) => err.push(l), env: { LEDGER_DIR: dir, LEDGER_HUB_URL: 'http://127.0.0.1:9' }, cwd: dir };
  const code = await run(argv, io);
  return { code, out, err };
}

const id = (lines: string[]): string => /d_[a-z2-7]{10}/.exec(lines.join('\n'))?.[0] ?? '';

test('F2.1 device init: output has id + fingerprint only (no key material); second run keeps the key', { skip }, async (t) => {
  const dir = await ledger(t);
  const a = await ledgerCli(dir, ['device', 'init', '--label', 'mac']);
  assert.equal(a.code, 0, a.err.join('\n'));
  assert.match(a.out[0] ?? '', /^device d_[a-z2-7]{10} \(mac, slot -\)$/);
  assert.match(a.out[1] ?? '', /^key SHA256:\S{43} — created$/);
  const l = deviceLayout(dir);
  const priv = await readFile(l.keyFile, 'utf8');
  const body = priv.split('\n').slice(1, -2).join('');
  const all = [...a.out, ...a.err].join('\n');
  assert.ok(!all.includes(body.slice(0, 20)) && !all.includes('PRIVATE KEY'));
  const b = await ledgerCli(dir, ['device', 'init']);
  assert.equal(b.code, 0);
  assert.match(b.out[1] ?? '', /already present, kept$/);
  assert.equal(await readFile(l.keyFile, 'utf8'), priv);
  assert.equal(id(a.out), id(b.out));
});

test('F2.1 device init: bad label / unknown subcommand → exit 4, nothing created', { skip }, async (t) => {
  const dir = await ledger(t);
  const bad = await ledgerCli(dir, ['device', 'init', '--label', '../x']);
  assert.equal(bad.code, 4);
  assert.match(bad.err.join('\n'), /label/);
  const unknown = await ledgerCli(dir, ['device', 'frobnicate']);
  assert.equal(unknown.code, 4);
  assert.match(unknown.err.join('\n'), /ledger device init/);
});

test('F2.3 device list / approve / revoke through the CLI; revoke is permanent', { skip }, async (t) => {
  const dir = await ledger(t);
  const init = await ledgerCli(dir, ['device', 'init', '--root']);
  assert.equal(init.code, 0, init.err.join('\n'));
  const selfId = id(init.out);

  // a second machine (its own ledger dir), registered here the way F3 sync would deliver it
  const dir2 = await ledger(t);
  const other = await ledgerCli(dir2, ['device', 'init', '--label', 'win']);
  const otherId = id(other.out);
  const pub = (await readFile(deviceLayout(dir2).pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
  const l = deviceLayout(dir);
  const file = (await readDevices(l)) as DevicesFile;
  file.devices.push({ id: otherId, label: 'win', slot: 'W', pubkey: pub, added: '2026-11-16T10:00:00.000Z', added_by: selfId, revoked: null, role: 'owner' });
  await writeFile(l.devicesYml, renderDevicesYaml(file));

  let list = await ledgerCli(dir, ['device', 'list']);
  assert.equal(list.code, 0);
  assert.match(list.out.join('\n'), new RegExp(`${otherId} slot W win active NOT-APPROVED SHA256:`));
  assert.match(list.out.join('\n'), new RegExp(`${selfId} slot - mac active \\(this device\\) trusted`));

  const fp = (await ledgerCli(dir2, ['device', 'init'])).out[1]?.match(/SHA256:\S{43}/)?.[0] ?? '';
  assert.match(fp, /^SHA256:/);
  // DK-1: no fingerprint / wrong fingerprint → exit 4, nothing trusted
  const noFp = await ledgerCli(dir, ['device', 'approve', otherId]);
  assert.equal(noFp.code, 4);
  assert.match(noFp.err.join('\n'), /usage: ledger device approve <id> --fp/);
  const wrongFp = await ledgerCli(dir, ['device', 'approve', otherId, '--fp', `SHA256:${'A'.repeat(43)}`]);
  assert.equal(wrongFp.code, 4);
  assert.match(wrongFp.err.join('\n'), /does not match/);
  assert.match((await ledgerCli(dir, ['device', 'list'])).out.join('\n'), new RegExp(`${otherId} slot W win active NOT-APPROVED`));
  assert.equal((await ledgerCli(dir, ['device', 'approve', otherId, '--fp', `${fp} `])).code, 4, 'trailing space');

  const approve = await ledgerCli(dir, ['device', 'approve', otherId, '--fp', fp]);
  assert.equal(approve.code, 0, approve.err.join('\n'));
  assert.match(approve.out[0] ?? '', /now trusted/);
  assert.match((await ledgerCli(dir, ['device', 'approve', otherId, `--fp=${fp}`])).out[0] ?? '', /already approved/);
  assert.equal((await ledgerCli(dir, ['device', 'approve', '../../etc/passwd', '--fp', fp])).code, 4);
  assert.equal((await ledgerCli(dir, ['device', 'approve'])).code, 4);

  const noReason = await ledgerCli(dir, ['device', 'revoke', otherId]);
  assert.equal(noReason.code, 4);
  assert.equal((await ledgerCli(dir, ['device', 'revoke', otherId, '--reason', ''])).code, 4);
  assert.equal((await ledgerCli(dir, ['device', 'revoke', selfId, '--reason', 'x'])).code, 4, 'self-revoke refused');
  const rev = await ledgerCli(dir, ['device', 'revoke', otherId, '--reason', 'lost phone']);
  assert.equal(rev.code, 0, rev.err.join('\n'));
  assert.match(rev.out[0] ?? '', /no longer trusted/);

  assert.equal((await ledgerCli(dir, ['device', 'revoke', otherId, '--reason', 'again'])).code, 4);
  const back = await ledgerCli(dir, ['device', 'approve', otherId, '--fp', fp]);
  assert.equal(back.code, 4);
  assert.match(back.err.join('\n'), /revoked/);
  list = await ledgerCli(dir, ['device', 'list', '--json']);
  const rows = JSON.parse(list.out[0] ?? '[]') as { id: string; status: string; trusted: boolean }[];
  assert.deepEqual(rows.find((r) => r.id === otherId), { ...rows.find((r) => r.id === otherId), status: 'revoked', trusted: false });
});

test('F2.3 approve/revoke on a machine that is not a registered member → exit 4', { skip }, async (t) => {
  const dir = await ledger(t);
  await ledgerCli(dir, ['device', 'init']);
  const r = await ledgerCli(dir, ['device', 'approve', 'd_aaaaaaaaaa', '--fp', `SHA256:${'A'.repeat(43)}`]);
  assert.equal(r.code, 4);
  assert.match(r.err.join('\n'), /not registered/);
});

test('F2.5 ledger doctor: device checks appear only after init, and a loose key fails the run', { skip }, async (t) => {
  const dir = await ledger(t);
  const cfg = { baseUrl: 'http://127.0.0.1:9', ledgerDir: dir, session: null, agent: 'test' };
  const doctor = async (): Promise<{ checks: { id: string; status: string }[]; code: number }> => {
    const out: string[] = [];
    const code = await cmdDoctor(
      parseArgs(['--json']),
      cfg,
      { out: (l) => out.push(l), err: (l) => out.push(l), env: { LEDGER_SPOOL_DIR: join(dir, 'spool') } as NodeJS.ProcessEnv },
      {
        platform: 'linux', exists: async () => false, cwd: dir, wsl: false, homeDir: dir, codeRepoDir: dir, searchPath: '',
        capture: async () => ({ code: null, stdout: '' }), claudeSettingsPath: join(dir, 'none.json'),
      },
    );
    return { checks: (JSON.parse(out[0] ?? '{}') as { checks: { id: string; status: string }[] }).checks, code };
  };
  assert.equal((await doctor()).checks.some((c) => c.id.startsWith('device_')), false);
  await ledgerCli(dir, ['device', 'init', '--root']);
  const ok = await doctor();
  assert.deepEqual(ok.checks.filter((c) => c.id.startsWith('device_')).map((c) => [c.id, c.status]), [['device_key', 'ok'], ['device_signers', 'ok']]);
  const { chmod } = await import('node:fs/promises');
  await chmod(deviceLayout(dir).keyFile, 0o644);
  const bad = await doctor();
  assert.equal(bad.checks.find((c) => c.id === 'device_key')?.status, 'fail');
  assert.equal(bad.code, 1);
});

test('DK-2: hostile devices.yml → clean one-line CLI error (no ANSI / bidi / echo of the input)', { skip }, async (t) => {
  const dir = await ledger(t);
  await ledgerCli(dir, ['device', 'init', '--root']);
  const l = deviceLayout(dir);
  const ESC = '\u001b';
  const hostile = `${ESC}[2J${ESC}]0;pwned\u0007\u202eevil`;
  const good = await readFile(l.devicesYml, 'utf8');
  for (const text of [
    good.replace('label: mac', `label: ${JSON.stringify(hostile)}`),
    good.replace('role: owner', `role: owner\n  ${JSON.stringify(hostile)}: 1`),
    good.replace(/pubkey: \S+ \S+/, `pubkey: ${JSON.stringify(`${hostile}`)}`),
  ]) {
    await writeFile(l.devicesYml, text);
    for (const argv of [['device', 'list'], ['device', 'approve', 'd_aaaaaaaaaa', '--fp', `SHA256:${'A'.repeat(43)}`], ['device', 'revoke', 'd_aaaaaaaaaa', '--reason', 'x']]) {
      const r = await ledgerCli(dir, argv);
      assert.equal(r.code, 4);
      const all = [...r.out, ...r.err].join('\n');
      assert.ok(!all.includes(ESC) && !/[\u0007\u202a-\u202e]/.test(all) && !all.includes('pwned') && !all.includes('evil'), all);
      assert.equal(r.err.length, 1, 'one line');
    }
  }
});
