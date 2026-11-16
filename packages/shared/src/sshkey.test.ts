/** F2.4 — ssh-keygen wrapper: strict public-key parsing, sign/verify round trip,
 *  fail-closed behaviour, private scratch cleanup, git signing recipe.
 *  Needs a real OpenSSH `ssh-keygen` (macOS/Linux); win32 is skipped (NOT verified there). */

import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import {
  DEVICE_ID_RE,
  SIGN_NAMESPACE,
  SshKeygenError,
  generateKeyPair,
  gitSigningArgs,
  parseEd25519Pub,
  publicKeyOf,
  resolveSshKeygen,
  sshKeygenCandidates,
  signPayload,
  verifyPayload,
} from './sshkey.ts';
import { skipOnWin32 } from './testing.ts';

const exec = promisify(execFile);
const skip = skipOnWin32('needs OpenSSH ssh-keygen + POSIX modes');

async function scratch(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-sshkey-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function newKey(dir: string, name = 'key'): Promise<string> {
  const keyFile = join(dir, name);
  await generateKeyPair(keyFile);
  return keyFile;
}

/** Raw `ssh-keygen -Y sign` with an arbitrary namespace (what git itself would produce). */
async function signWithNamespace(ns: string, keyFile: string, payload: Buffer): Promise<string> {
  const bin = await resolveSshKeygen();
  return new Promise((resolve, reject) => {
    const c = spawn(bin, ['-Y', 'sign', '-n', ns, '-f', keyFile], { stdio: ['pipe', 'pipe', 'ignore'], shell: false });
    let out = '';
    c.stdout.on('data', (d: Buffer) => (out += d.toString('utf8')));
    c.on('error', reject);
    c.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`sign exit ${String(code)}`))));
    c.stdin.end(payload);
  });
}

const goodPub = async (keyFile: string): Promise<string> => (await publicKeyOf(keyFile)).line;

test('parseEd25519Pub: fingerprint equals `ssh-keygen -l`, id is d_<10 base32>', { skip }, async (t) => {
  const dir = await scratch(t);
  const keyFile = await newKey(dir);
  const text = await readFile(`${keyFile}.pub`, 'utf8');
  const pub = parseEd25519Pub(text, { allowComment: true });
  assert.ok(pub);
  const { stdout } = await exec(await resolveSshKeygen(), ['-lf', `${keyFile}.pub`]);
  assert.equal(stdout.split(' ')[1], pub.fingerprint);
  assert.match(pub.deviceId, DEVICE_ID_RE);
  assert.equal(parseEd25519Pub(text, { allowComment: true })?.deviceId, pub.deviceId); // deterministic
});

test('parseEd25519Pub: strict — options, comments, newlines, other types, bad blobs are refused', { skip }, async (t) => {
  const dir = await scratch(t);
  const line = await goodPub(await newKey(dir));
  const b64 = line.split(' ')[1] ?? '';
  assert.ok(parseEd25519Pub(line));
  assert.equal(parseEd25519Pub(`${line} laptop`), null, 'comment needs allowComment');
  assert.ok(parseEd25519Pub(`${line} laptop`, { allowComment: true }));
  assert.equal(parseEd25519Pub(`command="rm -rf /" ${line}`), null, 'authorized_keys options');
  assert.equal(parseEd25519Pub(`${line}\nssh-ed25519 ${b64}`), null, 'second line');
  assert.equal(parseEd25519Pub(`${line} a\nb`, { allowComment: true }), null);
  assert.equal(parseEd25519Pub(`ssh-rsa ${b64}`), null);
  assert.equal(parseEd25519Pub(`ssh-ed25519 ${b64.slice(0, -4)}`), null);
  assert.equal(parseEd25519Pub(`ssh-ed25519 ${'A'.repeat(68)}`), null, 'wrong wire header');
  assert.equal(parseEd25519Pub(`ssh-ed25519  ${b64}`), null, 'double space');
  assert.equal(parseEd25519Pub(''), null);
});

test('sign → verify round trip; any change of payload, key or namespace fails', { skip }, async (t) => {
  const dir = await scratch(t);
  const tmpRoot = join(dir, 'tmp');
  const keyA = await newKey(dir, 'a');
  const keyB = await newKey(dir, 'b');
  const pubA = await goodPub(keyA);
  const pubB = await goodPub(keyB);
  const payload = Buffer.from('sync: counters/d_aaaaaaaaaa.yml\n');

  const sig = await signPayload(payload, { keyFile: keyA });
  assert.match(sig, /^-----BEGIN SSH SIGNATURE-----\n/);
  assert.equal(await verifyPayload(payload, sig, pubA, { tmpRoot }), true);
  assert.equal(await verifyPayload(Buffer.from('tampered'), sig, pubA, { tmpRoot }), false, 'payload');
  assert.equal(await verifyPayload(payload, sig, pubB, { tmpRoot }), false, 'foreign key');
  assert.equal(await verifyPayload(payload, 'not a signature', pubA, { tmpRoot }), false, 'garbage');
  assert.equal(await verifyPayload(payload, sig.replace(/\n(?=-----END)/, 'AAAA\n'), pubA, { tmpRoot }), false, 'mangled');

  // Same key, different namespace (as a commit signature would be) must not verify as ours.
  const foreign = await signWithNamespace('git', keyA, payload);
  assert.equal(await verifyPayload(payload, foreign, pubA, { tmpRoot }), false, 'namespace');
  await assert.rejects(verifyPayload(payload, sig, `${pubA} comment`, { tmpRoot }), SshKeygenError);
  assert.deepEqual(await readdir(tmpRoot), [], 'scratch dirs are always removed');
});

test('verify: scratch dir is removed even when ssh-keygen cannot start', { skip }, async (t) => {
  const dir = await scratch(t);
  const tmpRoot = join(dir, 'tmp');
  const key = await newKey(dir);
  const pub = await goodPub(key);
  const sig = await signPayload(Buffer.from('x'), { keyFile: key });
  await assert.rejects(
    verifyPayload(Buffer.from('x'), sig, pub, { tmpRoot, bin: '/nonexistent/ssh-keygen' }),
    (e: unknown) => e instanceof SshKeygenError && e.code === 'FAILED',
  );
  assert.deepEqual(await readdir(tmpRoot), []);
});

test('timeout kills the process group and surfaces TIMEOUT (never "verified")', { skip }, async (t) => {
  const dir = await scratch(t);
  const stub = join(dir, 'slow-keygen');
  await writeFile(stub, '#!/bin/sh\nsleep 30 &\nsleep 30\n', { mode: 0o700 });
  const key = await newKey(dir);
  const pub = await goodPub(key);
  const sig = await signPayload(Buffer.from('x'), { keyFile: key });
  const t0 = Date.now();
  await assert.rejects(
    verifyPayload(Buffer.from('x'), sig, pub, { tmpRoot: join(dir, 'tmp'), bin: stub, timeoutMs: 300 }),
    (e: unknown) => e instanceof SshKeygenError && e.code === 'TIMEOUT',
  );
  assert.ok(Date.now() - t0 < 5_000, 'did not wait for the grandchild');
  await assert.rejects(signPayload(Buffer.from('x'), { keyFile: key, bin: stub, timeoutMs: 300 }), /timed out/);
});

test('signPayload: a key file that others can read is refused BEFORE ssh-keygen starts', { skip }, async (t) => {
  const dir = await scratch(t);
  const key = await newKey(dir);
  await chmod(key, 0o644);
  await assert.rejects(
    signPayload(Buffer.from('x'), { keyFile: key, bin: '/nonexistent/ssh-keygen' }),
    (e: unknown) => e instanceof SshKeygenError && /refused/.test(e.message),
  );
  await assert.rejects(signPayload(Buffer.from('x'), { keyFile: 'relative/key' }), /absolute/);
  await assert.rejects(signPayload(Buffer.alloc(9 * 1024 * 1024), { keyFile: key }), /too large/);
});

test('fail closed: no trusted ssh-keygen → MISSING with a clear message, no silent skip', async () => {
  await assert.rejects(
    resolveSshKeygen(['/nonexistent/dir/ssh-keygen', 'relative/ssh-keygen']),
    (e: unknown) => e instanceof SshKeygenError && e.code === 'MISSING' && /install OpenSSH/.test(e.message),
  );
});

test('sshKeygenCandidates: absolute only; win32 drops env roots that are not drive-rooted', () => {
  for (const c of sshKeygenCandidates('linux')) assert.ok(c.startsWith('/'));
  assert.deepEqual(sshKeygenCandidates('win32', { SystemRoot: 'relative\\win', ProgramFiles: 'C:\\Program Files' }), [
    'C:\\Program Files\\Git\\usr\\bin\\ssh-keygen.exe',
  ]);
});

test('generateKeyPair refuses to overwrite an existing key', { skip }, async (t) => {
  const dir = await scratch(t);
  const key = await newKey(dir);
  const before = await readFile(key);
  await assert.rejects(generateKeyPair(key), SshKeygenError);
  assert.ok((await readFile(key)).equals(before));
});

test('gitSigningArgs: ssh format, absolute program, no PATH lookup; relative paths refused', () => {
  const args = gitSigningArgs({ sshKeygenBin: '/usr/bin/ssh-keygen', keyFile: '/l/.hub/device/key', allowedSignersFile: '/l/.hub/allowed_signers' });
  assert.deepEqual(args, [
    '-c', 'gpg.format=ssh',
    '-c', 'gpg.ssh.program=/usr/bin/ssh-keygen',
    '-c', 'user.signingkey=/l/.hub/device/key',
    '-c', 'gpg.ssh.allowedSignersFile=/l/.hub/allowed_signers',
    '-c', 'commit.gpgsign=true',
  ]);
  assert.throws(() => gitSigningArgs({ sshKeygenBin: 'ssh-keygen', keyFile: '/k', allowedSignersFile: '/a' }), SshKeygenError);
  assert.throws(() => gitSigningArgs({ sshKeygenBin: '/b', keyFile: '/k\nuser.name=x', allowedSignersFile: '/a' }), SshKeygenError);
});

test('gitSigningArgs: the recipe really produces a commit that git verifies', { skip }, async (t) => {
  const dir = await scratch(t);
  const keyFile = await newKey(dir);
  const pub = await goodPub(keyFile);
  const repo = join(dir, 'repo');
  await mkdir(repo);
  const allowed = join(dir, 'allowed_signers');
  // git matches the principal against the committer e-mail.
  await writeFile(allowed, `dev@ledger.invalid namespaces="git" ${pub}\n`, { mode: 0o600 });
  const gitBin = '/usr/bin/git';
  const env = {
    PATH: '/usr/bin:/bin',
    HOME: dir,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 'dev@ledger.invalid',
    GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 'dev@ledger.invalid',
  };
  const sign = gitSigningArgs({ sshKeygenBin: await resolveSshKeygen(), keyFile, allowedSignersFile: allowed });
  await exec(gitBin, ['init', '-q', repo], { env });
  await writeFile(join(repo, 'f'), 'x');
  await exec(gitBin, ['-C', repo, 'add', 'f'], { env });
  await exec(gitBin, ['-C', repo, ...sign, 'commit', '-q', '-m', 'signed'], { env });
  const ok = await exec(gitBin, ['-C', repo, '-c', 'gpg.format=ssh', '-c', `gpg.ssh.allowedSignersFile=${allowed}`, 'verify-commit', 'HEAD'], { env }).then(() => true, () => false);
  assert.equal(ok, true);
  // A different key is not accepted by the same allowed_signers.
  const stranger = await goodPub(await newKey(dir, 'stranger'));
  await writeFile(allowed, `dev@ledger.invalid namespaces="git" ${stranger}\n`, { mode: 0o600 });
  const bad = await exec(gitBin, ['-C', repo, '-c', 'gpg.format=ssh', '-c', `gpg.ssh.allowedSignersFile=${allowed}`, 'verify-commit', 'HEAD'], { env }).then(() => true, () => false);
  assert.equal(bad, false);
});
