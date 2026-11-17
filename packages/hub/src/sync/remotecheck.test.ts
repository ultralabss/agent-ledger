/** F3b B4b: remote probes + doctor checks (docs/f3b-b4-plan.md §2.4, T-B4-1, T-B4-13). Network is faked through the
 *  probe seams (no ssh); the anonymous probe must pass ONLY on an explicit permission-denied answer. POSIX only. */

import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import test from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { Gitx, type GitxResult } from './gitx.ts';
import { pinHostKey } from './hostkey.ts';
import { classifyProbe, pinnedFingerprint, probeRemote, remoteChecks, remoteHostPort, remoteIdentity, type RemoteCheckDeps } from './remotecheck.ts';
import { writeEnrolMarker, writeSyncConfig } from './state.ts';
import { makeKit, makeLegacyLedger } from './testkit-remote.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

const res = (stderr: string, over: Partial<GitxResult> = {}): GitxResult => ({ ok: false, code: 128, stdout: Buffer.alloc(0), stderr, timedOut: false, capped: false, ...over });
const okRes = (stdout = ''): GitxResult => ({ ok: true, code: 0, stdout: Buffer.from(stdout), stderr: '', timedOut: false, capped: false });
const DENIED = 'git@git.example.invalid: Permission denied (publickey).\nfatal: Could not read from remote repository.';
const SHA = 'a'.repeat(40);

test('remoteHostPort / remoteIdentity: ssh and scp forms, user and port, case, .git suffix; local and IPv6 literal are not pinnable', () => {
  assert.deepEqual(remoteHostPort('ssh://git@Git.Example.Invalid:2222/o/r.git', 'ssh'), { host: 'git.example.invalid', port: 2222 });
  assert.deepEqual(remoteHostPort('ssh://git.example.invalid/o/r.git', 'ssh'), { host: 'git.example.invalid', port: 22 });
  assert.deepEqual(remoteHostPort('git@git.example.invalid:o/r.git', 'scp'), { host: 'git.example.invalid', port: 22 });
  assert.equal(remoteHostPort('ssh://git@[::1]/o/r.git', 'ssh'), null);
  assert.equal(remoteHostPort('/abs/path', 'local'), null);
  assert.equal(remoteIdentity('git@Host.Example:o/r.git'), remoteIdentity('ssh://other@host.example/o/r'));
  assert.notEqual(remoteIdentity('ssh://h.example:2222/o/r'), remoteIdentity('ssh://h.example/o/r'));
  assert.notEqual(remoteIdentity('h.example:o/r'), remoteIdentity('h.example:o/other'));
  assert.equal(remoteIdentity('/abs/path'), null);
});

test('classifyProbe: denied ONLY for an explicit refusal; refused connection / DNS / timeout / host key / junk are never "denied"', () => {
  assert.equal(classifyProbe(okRes()), 'ok');
  assert.equal(classifyProbe(res(DENIED)), 'denied');
  assert.equal(classifyProbe(res('ERROR: Repository not found.\nfatal: Could not read from remote repository.')), 'denied');
  const notDenied: [string, GitxResult][] = [
    ['refused', res('ssh: connect to host h port 22: Connection refused\nfatal: Could not read from remote repository.')],
    ['dns', res('ssh: Could not resolve hostname h: nodename nor servname provided\nfatal: Could not read from remote repository.')],
    ['unreachable', res('ssh: connect to host h port 22: Network is unreachable\nfatal: Could not read from remote repository.')],
    ['timed out', res('ssh: connect to host h port 22: Operation timed out')],
    ['timeout flag', res('', { timedOut: true })],
    ['capped', res('', { capped: true })],
    ['junk', res('fatal: something odd happened')],
    ['hostkey', res('Host key verification failed.\nfatal: Could not read from remote repository.')],
    ['denied but network', res('Permission denied ... Connection reset by peer')],
  ];
  for (const [name, r] of notDenied) assert.notEqual(classifyProbe(r), 'denied', name);
  assert.equal(classifyProbe(res('Host key verification failed.')), 'hostkey');
});

test('probeRemote: anonymous success = public; only an explicit refusal = denied; everything else inconclusive; local = not-applicable', { skip }, async () => {
  const kit = await makeKit();
  try {
    const gitx = await Gitx.open({ syncDir: nodePath.join(kit.root, 'p-sync'), testLocalRemotes: [kit.remote.path] });
    const base = { gitx, cwd: kit.root, url: 'ssh://git@git.example.invalid/o/r.git', kind: 'ssh' as const };
    const authEmpty = async (): Promise<GitxResult> => okRes('');
    assert.equal((await probeRemote({ ...base, anonymous: async () => okRes(''), authenticated: authEmpty })).anonymous, 'public');
    assert.equal((await probeRemote({ ...base, anonymous: async () => res(DENIED), authenticated: authEmpty })).anonymous, 'denied');
    for (const r of [res('Connection refused'), res('', { timedOut: true }), res('Host key verification failed.'), res('odd')]) {
      assert.equal((await probeRemote({ ...base, anonymous: async () => r, authenticated: authEmpty })).anonymous, 'inconclusive');
    }
    // a real local remote (tests only): nothing to test
    const local = await probeRemote({ gitx, cwd: kit.root, url: kit.remote.path, kind: 'local' });
    assert.deepEqual(local, { anonymous: 'not-applicable', remote: 'empty', tip: null });
    // authenticated side
    const A = async (): Promise<GitxResult> => res(DENIED);
    const probe = (authenticated: () => Promise<GitxResult>) => probeRemote({ ...base, anonymous: A, authenticated });
    assert.deepEqual((await probe(async () => okRes(`${SHA}\trefs/heads/main\n`))).remote, 'has-main');
    assert.equal((await probe(async () => okRes(`${SHA}\trefs/heads/main\n`))).tip, SHA);
    assert.equal((await probe(async () => okRes(''))).remote, 'empty');
    assert.equal((await probe(async () => res(DENIED))).remote, 'denied');
    assert.equal((await probe(async () => res('Host key verification failed.'))).remote, 'hostkey');
    assert.equal((await probe(async () => res('Connection refused'))).remote, 'unreachable');
    // hostile output: not the one expected line, or too much
    for (const out of [`${SHA}\trefs/heads/other\n`, `${SHA} refs/heads/main\n`, `${SHA}\trefs/heads/main\n${SHA}\trefs/heads/main\n`, 'garbage\n', `${SHA}\trefs/heads/main\n${'x'.repeat(5000)}`]) {
      assert.equal((await probe(async () => okRes(out))).remote, 'unreachable', out.slice(0, 20));
    }
  } finally {
    await kit.cleanup();
  }
});

test('pinnedFingerprint: reads the fingerprint of the pinned key for host:port (case-insensitive); absent / foreign / oversize = null', { skip }, async () => {
  const d = await realpath(await mkdtemp(nodePath.join(await realpath(tmpdir()), 'agl-rc-')));
  try {
    await chmod(d, 0o700);
    const sd = nodePath.join(d, 'sync');
    assert.equal(await pinnedFingerprint(sd, 'h.example', 22), null);
    const blob = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, 7)]).toString('base64');
    const line = `ssh-ed25519 ${blob}`;
    await pinHostKey(sd, 'H.Example', 22, line);
    const fp = await pinnedFingerprint(sd, 'h.example', 22);
    assert.match(fp ?? '', /^SHA256:[A-Za-z0-9+/]{43}$/);
    assert.equal(await pinnedFingerprint(sd, 'H.EXAMPLE', 22), fp);
    assert.equal(await pinnedFingerprint(sd, 'h.example', 2222), null, 'another port is another host');
    assert.equal(await pinnedFingerprint(sd, 'other.example', 22), null);
    await writeFile(nodePath.join(sd, 'known_hosts'), 'x'.repeat(9000), { mode: 0o600 });
    assert.equal(await pinnedFingerprint(sd, 'h.example', 22), null);
  } finally {
    await rm(d, { recursive: true, force: true });
  }
});

const byId = (cs: { id: string; status: string; detail: string }[], id: string): { id: string; status: string; detail: string } => {
  const c = cs.find((x) => x.id === id);
  assert.ok(c !== undefined, `check ${id} present`);
  return c;
};

test('remoteChecks: every plan id is present; anonymous success = fail; "could not tell" = warn; offline = info; no URL / key / stderr in any detail', { skip }, async () => {
  const kit = await makeKit();
  const led = await makeLegacyLedger(1);
  try {
    const url = 'ssh://git@git.example.invalid/owner/secret-repo.git';
    const gitx = await Gitx.open({ syncDir: nodePath.join(led.dir, '.hub', 'sync') });
    const deps = (over: Partial<RemoteCheckDeps> = {}): RemoteCheckDeps => ({ ledgerDir: led.dir, url, online: false, ...over });
    const IDS = ['sync_remote_scheme', 'sync_hostkey_pinned', 'sync_remote_anonymous', 'sync_remote_reachable', 'sync_remote_distinct', 'sync_git_config', 'sync_enrol_marker', 'sync_devices_unapproved', 'sync_single_trusted_device'];
    const offline = await remoteChecks(deps());
    for (const id of IDS) byId(offline, id);
    assert.equal(byId(offline, 'sync_remote_anonymous').status, 'info');
    assert.equal(byId(offline, 'sync_remote_reachable').status, 'info');
    assert.equal(byId(offline, 'sync_remote_scheme').status, 'ok');
    assert.equal(byId(offline, 'sync_hostkey_pinned').status, 'fail', 'no pin yet');
    assert.equal(byId(offline, 'sync_enrol_marker').status, 'ok');
    assert.equal(byId(offline, 'sync_git_config').status, 'ok');
    // distinct from the code repository
    assert.equal(byId(await remoteChecks(deps({ codeRepoRemote: 'git@git.example.invalid:owner/secret-repo.git' })), 'sync_remote_distinct').status, 'fail');
    assert.equal(byId(await remoteChecks(deps({ codeRepoRemote: 'git@git.example.invalid:owner/code.git' })), 'sync_remote_distinct').status, 'ok');
    assert.equal(byId(offline, 'sync_remote_distinct').status, 'info');
    // network checks
    const online = (anonymous: () => Promise<GitxResult>, authenticated: () => Promise<GitxResult>): Promise<ReturnType<typeof byId>[]> =>
      remoteChecks(deps({ online: true, gitx, probe: { anonymous, authenticated } })) as never;
    const pub = await online(async () => okRes(''), async () => okRes(''));
    assert.equal(byId(pub, 'sync_remote_anonymous').status, 'fail');
    assert.match(byId(pub, 'sync_remote_anonymous').detail, /WITHOUT credentials/);
    const priv = await online(async () => res(DENIED), async () => okRes(`${SHA}\trefs/heads/main\n`));
    assert.equal(byId(priv, 'sync_remote_anonymous').status, 'ok');
    assert.equal(byId(priv, 'sync_remote_reachable').status, 'ok');
    const unsure = await online(async () => res('Connection refused'), async () => res('Connection refused'));
    assert.equal(byId(unsure, 'sync_remote_anonymous').status, 'warn');
    assert.equal(byId(unsure, 'sync_remote_reachable').status, 'fail');
    // a bad scheme
    assert.equal(byId(await remoteChecks(deps({ url: 'https://example.invalid/o/r.git' })), 'sync_remote_scheme').status, 'fail');
    // nothing leaks
    for (const cs of [offline, pub, priv, unsure]) {
      const text = JSON.stringify(cs);
      assert.ok(!text.includes('secret-repo') && !text.includes('owner/') && !text.includes('Connection refused') && !text.includes('BEGIN'), 'no URL, stderr or key');
    }
    // the host token (and only that) may appear
    assert.match(byId(offline, 'sync_remote_scheme').detail, /git\.example\.invalid/);
    void kit;
  } finally {
    await led.cleanup();
    await kit.cleanup();
  }
});

test('remoteChecks: the enrol marker (live = warn, stale = fail), the .git/config policy (https origin = fail with the removal hint, local-path origin = warn), the registry rows', { skip }, async () => {
  const led = await makeLegacyLedger(1);
  try {
    const dir = led.dir;
    const url = 'ssh://git@git.example.invalid/o/r.git';
    await writeSyncConfig(dir, url);
    const marker = { v: 1 as const, kind: 'join' as const, stage: 'awaiting-add', startedAt: new Date().toISOString(), remote: url, F0: SHA };
    await writeEnrolMarker(dir, marker);
    const live = await remoteChecks({ ledgerDir: dir, online: false });
    assert.equal(byId(live, 'sync_enrol_marker').status, 'warn');
    assert.match(byId(live, 'sync_enrol_marker').detail, /awaiting-add/);
    const stale = await remoteChecks({ ledgerDir: dir, online: false, pidAlive: () => false });
    assert.equal(byId(stale, 'sync_enrol_marker').status, 'fail');
    assert.equal(byId(await remoteChecks({ ledgerDir: dir, online: false, now: () => Date.now() + 25 * 3_600_000 }), 'sync_enrol_marker').status, 'fail');
    await writeFile(nodePath.join(dir, '.hub', 'sync', 'enrol.json'), '{ not json', { mode: 0o600 });
    assert.equal(byId(await remoteChecks({ ledgerDir: dir, online: false }), 'sync_enrol_marker').status, 'fail', 'a corrupt marker is a failure, never "ok"');
    await rm(nodePath.join(dir, '.hub', 'sync', 'enrol.json'));
    // .git/config
    const cfg = nodePath.join(dir, '.git', 'config');
    const original = await readFile(cfg, 'utf8');
    await writeFile(cfg, `${original}[remote "origin"]\n\turl = /legacy/backup.git\n`);
    assert.equal(byId(await remoteChecks({ ledgerDir: dir, online: false }), 'sync_git_config').status, 'warn');
    await writeFile(cfg, `${original}[remote "origin"]\n\turl = https://example.invalid/o/r.git\n`);
    const https = byId(await remoteChecks({ ledgerDir: dir, online: false }), 'sync_git_config');
    assert.equal(https.status, 'fail');
    assert.match(https.detail, /git remote remove origin/);
    assert.ok(!https.detail.includes('example.invalid'), 'the URL is not echoed');
    await writeFile(cfg, `${original}[url "https://x/"]\n\tinsteadOf = ssh://y/\n`);
    assert.equal(byId(await remoteChecks({ ledgerDir: dir, online: false }), 'sync_git_config').status, 'fail');
    // no registry yet: nothing unapproved, single device only matters once enrolled
    assert.equal(byId(await remoteChecks({ ledgerDir: dir, online: false }), 'sync_devices_unapproved').status, 'ok');
  } finally {
    await led.cleanup();
  }
});
