/** F3b B4a: first-contact host key scan + pin (docs/f3b-b4-plan.md §2.1, E-5, T-B4-8). Fake scanner binaries
 *  (POSIX); the real `ssh-keyscan` / `ssh-keygen` only for flag acceptance and the `known_hosts` token form. */

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import test from 'node:test';
import { parseEd25519Pub, resolveSshKeygen } from '@agent-ledger/shared';
import { HostKeyError, KEYSCAN_MAX_OUTPUT, fingerprintOf, hostToken, pinHostKey, scanHostKeys } from './hostkey.ts';

const posix = process.platform !== 'win32';

function str(s: string): Buffer {
  const b = Buffer.alloc(4 + s.length);
  b.writeUInt32BE(s.length, 0);
  b.write(s, 4, 'latin1');
  return b;
}
function bytes(n: number): Buffer {
  const b = Buffer.alloc(4 + n);
  b.writeUInt32BE(n, 0);
  randomBytes(n).copy(b, 4);
  return b;
}
const ed = (): string => `ssh-ed25519 ${Buffer.concat([str('ssh-ed25519'), bytes(32)]).toString('base64')}`;
const ec = (): string => `ecdsa-sha2-nistp256 ${Buffer.concat([str('ecdsa-sha2-nistp256'), str('nistp256'), bytes(65)]).toString('base64')}`;
const rsa = (): string => `ssh-rsa ${Buffer.concat([str('ssh-rsa'), bytes(3), bytes(256)]).toString('base64')}`;
const keyOf = (line: string): string => line.split(' ').slice(-2).join(' ');
const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

async function tmp(): Promise<string> {
  const d = await realpath(await mkdtemp(nodePath.join(await realpath(tmpdir()), 'agl-hostkey-')));
  await chmod(d, 0o700);
  return d;
}

async function withTmp<T>(fn: (d: string) => Promise<T>): Promise<T> {
  const d = await tmp();
  try {
    return await fn(d);
  } finally {
    await rm(d, { recursive: true, force: true });
  }
}

async function fakeScanner(d: string, body: string, name = 'keyscan'): Promise<string> {
  const p = nodePath.join(d, name);
  await writeFile(p, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  await chmod(p, 0o755);
  return p;
}

const code = (c: string) => (e: unknown): boolean => e instanceof HostKeyError && e.code === c;

/* ---------------- fingerprintOf ---------------- */

test('fingerprintOf: SHA256 of the blob (equals the ed25519 fingerprint sshkey.ts computes); known_hosts or bare form', () => {
  const k = ed();
  const fp = fingerprintOf(k);
  assert.match(fp ?? '', FP_RE);
  assert.equal(fp, parseEd25519Pub(k)?.fingerprint);
  assert.equal(fingerprintOf(`example.invalid ${k}`), fp);
  assert.equal(fingerprintOf(`[example.invalid]:2222 ${k}`), fp);
  assert.match(fingerprintOf(ec()) ?? '', FP_RE);
  assert.match(fingerprintOf(rsa()) ?? '', FP_RE);
});

test('fingerprintOf: anything that is not exactly `[host] type base64` of a consistent key is null', () => {
  const k = ed();
  const [type, b64] = k.split(' ') as [string, string];
  const mislabelled = `ssh-rsa ${b64}`; // blob says ssh-ed25519
  const bad: unknown[] = [
    '', 'x', k + ' comment', `h ${k} comment`, `cert-authority h ${k}`, `command="id" ${k}`, mislabelled, `ecdsa-sha2-nistp384 ${b64}`,
    `${type} ${b64.slice(0, -4)}`, `${type} ${b64}\n`, `${type}\t${b64}`, `${type} ${b64.replace(/.$/, '=')}`, `${type}  ${b64}`, `h ${type} ${b64}\u0000`,
    `hé ${k}`, `${type} !!!notbase64!!!`, `ssh-ed25519 ${Buffer.concat([str('ssh-ed25519')]).toString('base64')}`, 5, null, undefined, 'a'.repeat(9000),
  ];
  for (const b of bad) assert.equal(fingerprintOf(b), null, JSON.stringify(b)?.slice(0, 60));
});

test('hostToken: plain host for 22, [host]:port otherwise, lowercase; hostile host and port refused', () => {
  assert.equal(hostToken('Example.Invalid', 22), 'example.invalid');
  assert.equal(hostToken('example.invalid', 2222), '[example.invalid]:2222');
  for (const h of ['', '-oProxyCommand=x', 'a b', 'h:22', '[::1]', 'h\n', 'a'.repeat(300), '.x', 'x.', 'h/../x', 'h;id', 5]) {
    assert.throws(() => hostToken(h as string, 22), code('HOST'), String(h).slice(0, 20));
  }
  for (const p of [0, -1, 65536, 1.5, NaN, '22']) assert.throws(() => hostToken('h.example', p as number), code('PORT'));
});

/* ---------------- scanHostKeys ---------------- */

test('scanHostKeys: keeps only grammar-valid lines for exactly the asked host; order ed25519, ecdsa, rsa; fixed argv', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const e = ed();
    const c = ec();
    const r = rsa();
    const log = nodePath.join(d, 'argv.log');
    const out = [
      '# example.invalid:22 SSH-2.0-OpenSSH_9.6',
      `example.invalid ${r}`,
      `other.invalid ${ed()}`, // another host: dropped
      `example.invalid ${c}`,
      `example.invalid ${e}`,
      `example.invalid ${ed()}`, // second ed25519: ignored
      `example.invalid ssh-ed25519 !!!`,
      `example.invalid ${e} trailing-comment`,
      `example.invalid ecdsa-sha2-nistp384 ${keyOf(e).split(' ')[1]}`,
      `|1|hashed|host ${ed()}`,
      '\u001b[31mexample.invalid evil',
      '',
    ].join('\\n');
    const bin = await fakeScanner(d, `for a in "$@"; do printf '%s\\n' "$a" >> '${log}'; done\nprintf '${out}\\n'`);
    const keys = await scanHostKeys('Example.Invalid', 22, { bin });
    assert.deepEqual(keys.map((k) => k.type), ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa']);
    assert.equal(keys[0]?.line, `example.invalid ${e}`);
    assert.equal(keys[0]?.fingerprint, fingerprintOf(e));
    for (const k of keys) assert.ok(k.host === 'example.invalid' && k.port === 22 && FP_RE.test(k.fingerprint));
    assert.deepEqual((await readFile(log, 'utf8')).trim().split('\n'), ['-T', '10', '-t', 'ed25519,ecdsa,rsa', '-p', '22', '--', 'example.invalid']);
  });
});

test('scanHostKeys: a non-default port is matched and returned as [host]:port', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const e = ed();
    const bin = await fakeScanner(d, `printf '[example.invalid]:2222 ${e}\\nexample.invalid ${ed()}\\n'`);
    const keys = await scanHostKeys('example.invalid', 2222, { bin });
    assert.equal(keys.length, 1);
    assert.equal(keys[0]?.line, `[example.invalid]:2222 ${e}`);
    assert.equal(keys[0]?.port, 2222);
  });
});

test('scanHostKeys: no usable key = NO_KEYS (exit 0) / FAILED (exit != 0); nothing from stderr or stdout is put in the error', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const secret = 'SECRET-STDERR-TEXT';
    const empty = await fakeScanner(d, `echo ${secret} >&2; printf '# example.invalid:22 SSH-2.0-x\\nother.invalid ${ed()}\\n'`, 'empty');
    await assert.rejects(scanHostKeys('example.invalid', 22, { bin: empty }), (x: unknown) => {
      assert.ok(x instanceof HostKeyError && x.code === 'NO_KEYS' && !x.message.includes(secret) && !x.message.includes('other.invalid'));
      return true;
    });
    const failing = await fakeScanner(d, `echo ${secret} >&2; exit 1`, 'failing');
    await assert.rejects(scanHostKeys('example.invalid', 22, { bin: failing }), code('FAILED'));
    await assert.rejects(scanHostKeys('example.invalid', 22, { bin: nodePath.join(d, 'absent') }), code('SPAWN'));
  });
});

test('scanHostKeys: output cap and timeout kill the child (whole group); a relative scanner path is refused', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const flood = await fakeScanner(d, `head -c ${String(KEYSCAN_MAX_OUTPUT * 4)} /dev/zero | tr '\\0' 'a'`, 'flood');
    await assert.rejects(scanHostKeys('example.invalid', 22, { bin: flood }), code('OUTPUT'));
    const pidFile = nodePath.join(d, 'child.pid');
    const slow = await fakeScanner(d, `sleep 30 &\necho $! > '${pidFile}'\nwait`, 'slow');
    const t0 = Date.now();
    await assert.rejects(scanHostKeys('example.invalid', 22, { bin: slow, timeoutMs: 1000 }), code('TIMEOUT'));
    assert.ok(Date.now() - t0 < 8000, 'returns at the timeout, not at the child');
    await new Promise((r) => setTimeout(r, 200));
    const pid = Number((await readFile(pidFile, 'utf8')).trim());
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' }, 'the grandchild died with the group');
    await assert.rejects(scanHostKeys('example.invalid', 22, { bin: 'keyscan' }), code('BINARY'));
  });
});

test('scanHostKeys: hostile host / port never reach a spawn', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const log = nodePath.join(d, 'ran');
    const bin = await fakeScanner(d, `echo ran >> '${log}'`);
    for (const h of ['-oProxyCommand=touch pwn', 'a b', '', 'h:22', 'h;id', '$(id)']) await assert.rejects(scanHostKeys(h, 22, { bin }), code('HOST'));
    for (const p of [0, 70000, 2.5]) await assert.rejects(scanHostKeys('h.example', p, { bin }), code('PORT'));
    await assert.rejects(stat(log), { code: 'ENOENT' });
  });
});

test('real ssh-keyscan: the pinned flag set is accepted (a closed local port is FAILED/NO_KEYS, never a usage error or a hang)', { skip: !posix }, async () => {
  // UNVERIFIED on Windows; this only proves the argv is well-formed for the binary found on this machine.
  const t0 = Date.now();
  try {
    await scanHostKeys('127.0.0.1', 1, { timeoutMs: 3000 });
    assert.fail('port 1 must not answer with a key');
  } catch (err) {
    if (err instanceof HostKeyError && err.code === 'BINARY') return; // no ssh-keyscan on this machine
    assert.ok(err instanceof HostKeyError && ['FAILED', 'NO_KEYS', 'TIMEOUT'].includes(err.code), String(err));
  }
  assert.ok(Date.now() - t0 < 10_000);
});

/* ---------------- pinHostKey ---------------- */

test('pinHostKey: private dir + file, plain token for 22, [host]:port otherwise, one line per host, atomic', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    const a = ed();
    const b = ec();
    const r1 = await pinHostKey(sd, 'Example.Invalid', 22, a);
    assert.deepEqual(r1, { written: true, fingerprint: fingerprintOf(a) });
    await pinHostKey(sd, 'example.invalid', 2222, b);
    const file = nodePath.join(sd, 'known_hosts');
    assert.equal((await stat(sd)).mode & 0o777, 0o700);
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.equal(await readFile(file, 'utf8'), `example.invalid ${a}\n[example.invalid]:2222 ${b}\n`);
    assert.deepEqual((await readdir(sd)).filter((n) => n.includes('.tmp')), []);
  });
});

test('pinHostKey: the same key again is a no-op; a DIFFERENT key is refused without repin (file untouched), replaced with repin', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    const file = nodePath.join(sd, 'known_hosts');
    const a = ed();
    const evil = ed();
    await pinHostKey(sd, 'example.invalid', 22, a);
    await pinHostKey(sd, 'other.invalid', 22, ed());
    const before = await readFile(file, 'utf8');
    assert.deepEqual(await pinHostKey(sd, 'example.invalid', 22, `example.invalid ${a}`), { written: false, fingerprint: fingerprintOf(a) });
    assert.equal(await readFile(file, 'utf8'), before);
    await assert.rejects(pinHostKey(sd, 'example.invalid', 22, evil), (e: unknown) => {
      assert.ok(e instanceof HostKeyError && e.code === 'REPIN_REFUSED');
      assert.ok(!e.message.includes(keyOf(evil).split(' ')[1] as string));
      return true;
    });
    await assert.rejects(pinHostKey(sd, 'example.invalid', 22, ec()), code('REPIN_REFUSED'), 'a different TYPE is a different key too');
    assert.equal(await readFile(file, 'utf8'), before, 'refusal leaves the file byte-identical');
    assert.deepEqual(await pinHostKey(sd, 'example.invalid', 22, evil, { repin: true }), { written: true, fingerprint: fingerprintOf(evil) });
    const lines = (await readFile(file, 'utf8')).trim().split('\n');
    assert.equal(lines.length, 2, 'still one line per host');
    assert.ok(lines.includes(`example.invalid ${evil}`) && lines.some((l) => l.startsWith('other.invalid ')));
  });
});

test('pinHostKey: the stored host token is always recomputed; a line naming another host, options, comments or a bad blob are refused', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    const k = ed();
    const bad = [
      `other.invalid ${k}`, `${k} comment`, `cert-authority example.invalid ${k}`, `@revoked example.invalid ${k}`, `example.invalid ${k}\n`,
      `example.invalid ${keyOf(k).replace('ssh-ed25519', 'ssh-rsa')}`, 'example.invalid ssh-ed25519 AAAA', '', 'x', `example.invalid,other.invalid ${k}`,
    ];
    for (const l of bad) await assert.rejects(pinHostKey(sd, 'example.invalid', 22, l), code('LINE'), JSON.stringify(l).slice(0, 40));
    await assert.rejects(pinHostKey(sd, '-oProxyCommand=x', 22, k), code('HOST'));
    await assert.rejects(pinHostKey(sd, 'example.invalid', 0, k), code('PORT'));
    await assert.rejects(pinHostKey('relative/dir', 'example.invalid', 22, k), code('IO'));
    await assert.rejects(stat(nodePath.join(sd, 'known_hosts')), { code: 'ENOENT' }, 'nothing written on refusal');
    // a bare key (no host field) is pinned under the computed token
    await pinHostKey(sd, 'example.invalid', 2222, k);
    assert.equal(await readFile(nodePath.join(sd, 'known_hosts'), 'utf8'), `[example.invalid]:2222 ${k}\n`);
  });
});

test('pinHostKey: an existing file that is not exactly our format, a symlink, or an oversize file is refused and never rewritten', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    const file = nodePath.join(sd, 'known_hosts');
    const k = ed();
    await pinHostKey(sd, 'first.invalid', 22, ed());
    for (const content of [`# comment\nfirst.invalid ${ed()}\n`, `|1|abc|def ${ed()}\n`, `first.invalid ${ed()} extra\n`, `x ${ed()}\nx ${ed()}\n`, 'a'.repeat(9000)]) {
      await writeFile(file, content, { mode: 0o600 });
      await assert.rejects(pinHostKey(sd, 'second.invalid', 22, k), code('CORRUPT'), content.slice(0, 20));
      assert.equal(await readFile(file, 'utf8'), content);
    }
    await rm(file);
    const victim = nodePath.join(d, 'victim');
    await writeFile(victim, 'keep', { mode: 0o600 });
    await symlink(victim, file);
    await assert.rejects(pinHostKey(sd, 'second.invalid', 22, k), code('UNSAFE'));
    assert.equal(await readFile(victim, 'utf8'), 'keep');
    assert.ok((await lstat(file)).isSymbolicLink());
  });
});

test('pinHostKey: real ssh-keygen finds the pinned entry (plain form for 22, [host]:port otherwise); a foreign host is not found', { skip: !posix }, async (t) => {
  let keygen: string;
  try {
    keygen = await resolveSshKeygen();
  } catch {
    t.skip('no ssh-keygen');
    return;
  }
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    const file = nodePath.join(sd, 'known_hosts');
    await pinHostKey(sd, 'example.invalid', 22, ed());
    await pinHostKey(sd, 'example.invalid', 2222, ed());
    const find = (host: string): Promise<number> =>
      new Promise((resolve) => {
        execFile(keygen, ['-F', host, '-f', file], (err) => resolve(err === null ? 0 : ((err as { code?: number }).code ?? 1)));
      });
    assert.equal(await find('example.invalid'), 0);
    assert.equal(await find('[example.invalid]:2222'), 0);
    assert.notEqual(await find('[example.invalid]:2223'), 0);
    assert.notEqual(await find('other.invalid'), 0);
  });
});

test('pinHostKey (AL-61d): racing FIRST pins never replace each other (link + re-read); the loser decides against what the winner wrote', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    // two different hosts racing the very first creation: both end up in the file
    const [a, b, c] = [ed(), ec(), ed()];
    const res = await Promise.all([pinHostKey(sd, 'one.invalid', 22, a), pinHostKey(sd, 'two.invalid', 22, b), pinHostKey(sd, 'three.invalid', 2222, c)]);
    for (const r of res) assert.equal(r.written, true);
    const file = nodePath.join(sd, 'known_hosts');
    const lines = (await readFile(file, 'utf8')).trim().split('\n').sort();
    assert.deepEqual(lines, [`[three.invalid]:2222 ${c}`, `one.invalid ${a}`, `two.invalid ${b}`].sort(), 'no pin was lost');
    assert.deepEqual((await readdir(sd)).filter((n) => n.includes('.tmp')), []);
  });
});

test('pinHostKey (AL-61d): two racing first pins for the SAME host: exactly one key wins, the other is REPIN_REFUSED', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    const x = ed();
    const y = ed();
    const out = await Promise.allSettled([pinHostKey(sd, 'same.invalid', 22, x), pinHostKey(sd, 'same.invalid', 22, y)]);
    assert.equal(out.filter((o) => o.status === 'fulfilled').length, 1);
    const lost = out.find((o) => o.status === 'rejected');
    assert.ok(lost?.status === 'rejected' && lost.reason instanceof HostKeyError && lost.reason.code === 'REPIN_REFUSED');
    const lines = (await readFile(nodePath.join(sd, 'known_hosts'), 'utf8')).trim().split('\n');
    assert.equal(lines.length, 1);
    assert.ok(lines[0] === `same.invalid ${x}` || lines[0] === `same.invalid ${y}`);
  });
});

test('pinHostKey (AL-61d): the token is matched case-insensitively; a mixed-case duplicate line in the file is CORRUPT, never a second pin', { skip: !posix }, async () => {
  await withTmp(async (d) => {
    const sd = nodePath.join(d, 'sync');
    const file = nodePath.join(sd, 'known_hosts');
    const a = ed();
    const evil = ed();
    await pinHostKey(sd, 'example.invalid', 22, a);
    // somebody wrote an upper-case row for the same host by hand: it IS the pinned row, a different key is refused
    await writeFile(file, `Example.Invalid ${a}\n`, { mode: 0o600 });
    assert.deepEqual(await pinHostKey(sd, 'EXAMPLE.invalid', 22, a), { written: false, fingerprint: fingerprintOf(a) });
    await assert.rejects(pinHostKey(sd, 'example.invalid', 22, evil), code('REPIN_REFUSED'));
    await writeFile(file, `Example.Invalid ${a}\nexample.invalid ${evil}\n`, { mode: 0o600 });
    await assert.rejects(pinHostKey(sd, 'example.invalid', 22, a), code('CORRUPT'));
    // the rewrite of a mixed-case file stores lowercase tokens only
    await writeFile(file, `Example.Invalid ${a}\n`, { mode: 0o600 });
    await pinHostKey(sd, 'other.invalid', 22, evil);
    assert.equal(await readFile(file, 'utf8'), `example.invalid ${a}\nother.invalid ${evil}\n`);
  });
});
