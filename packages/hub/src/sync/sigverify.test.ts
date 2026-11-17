/** Commit signature verification (docs/f3b-plan.md §3: valid / tampered / wrong namespace / key mismatch / malformed armor; S16, S19). */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import nodePath from 'node:path';
import test from 'node:test';
import { resolveSshKeygen, signPayload } from '@agent-ledger/shared';
import { MAX_COMMIT_BYTES } from './objects.ts';
import { makeKit, type Kit, type TestHub } from './testkit-remote.ts';
import { parseSshSignature, splitCommit, verifyCommitSignature } from './sigverify.ts';

const posix = process.platform !== 'win32';

async function withKit<T>(fn: (kit: Kit) => Promise<T>): Promise<T> {
  const kit = await makeKit();
  try {
    return await fn(kit);
  } finally {
    await kit.cleanup();
  }
}

const tmpRootOf = (hub: TestHub): string => nodePath.join(hub.syncDir, 'tmp');

/** `ssh-keygen -Y sign -n <ns>` over `payload`. */
async function sshSign(hub: TestHub, namespace: string, payload: Buffer): Promise<string> {
  const bin = await resolveSshKeygen();
  return new Promise((resolve, reject) => {
    const child = spawn(bin, ['-Y', 'sign', '-n', namespace, '-f', hub.keyFile], { stdio: ['pipe', 'pipe', 'pipe'] });
    const out: Buffer[] = [];
    child.stdout.on('data', (d: Buffer) => out.push(d));
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve(Buffer.concat(out).toString('utf8')) : reject(new Error(`ssh-keygen exit ${String(code)}`))));
    child.stdin.end(payload);
  });
}

/** Insert `gpgsig` after the last header, the way git does. */
function embedSig(payload: Buffer, armor: string, header = 'gpgsig'): Buffer {
  const idx = payload.indexOf('\n\n');
  assert.ok(idx > 0);
  const head = payload.subarray(0, idx + 1);
  const rest = payload.subarray(idx + 1);
  const lines = armor.replace(/\n$/, '').split('\n');
  const sig = `${header} ${lines[0] as string}\n${lines.slice(1).map((l) => ` ${l}\n`).join('')}`;
  return Buffer.concat([head, Buffer.from(sig, 'latin1'), rest]);
}

function reArmor(blob: Buffer): string {
  const b64 = blob.toString('base64');
  const lines = b64.match(/.{1,70}/g) ?? [];
  return `-----BEGIN SSH SIGNATURE-----\n${lines.join('\n')}\n-----END SSH SIGNATURE-----\n`;
}

function blobOf(armor: string): Buffer {
  const body = armor.replace('-----BEGIN SSH SIGNATURE-----', '').replace('-----END SSH SIGNATURE-----', '').replace(/\n/g, '');
  return Buffer.from(body, 'base64');
}

async function signedRaw(hub: TestHub, message = 'signed one'): Promise<Buffer> {
  const sha = await hub.commit([{ path: 'a.md', content: `${message}\n` }], { message });
  return hub.store.readCommitRaw(sha);
}

test('valid: a git-signed commit verifies against exactly the key inside the signature', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const raw = await signedRaw(hub);
    const v = await verifyCommitSignature(raw, { tmpRoot: tmpRootOf(hub) });
    assert.equal(v.valid, true);
    assert.equal(v.reason, 'ok');
    assert.equal(v.pubkeyLine, hub.pub.line);
    assert.equal(v.headers?.committerName, 'hub1');
    assert.equal(v.headers?.committerEmail, `${hub.deviceId}@devices.agent-ledger.invalid`);
    assert.ok((v.headers?.committerTime ?? 0) > 1_700_000_000);
    assert.deepEqual(v.headers?.parents, []);
  });
});

test('valid: our payload split equals the bytes git signed (independent ssh-keygen -Y sign -n git over the split payload)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const unsignedSha = await hub.commit([{ path: 'a.md', content: 'x\n' }], { signed: false, message: 'plain' });
    const unsigned = await hub.store.readCommitRaw(unsignedSha);
    const armor = await sshSign(hub, 'git', unsigned);
    const manual = embedSig(unsigned, armor);
    const v = await verifyCommitSignature(manual, { tmpRoot: tmpRootOf(hub) });
    assert.equal(v.valid, true, v.reason);
    assert.ok(splitCommit(manual).payload.equals(unsigned), 'payload = commit minus the gpgsig block, byte for byte');
    // and the commit git itself signed splits into a payload that an independent signature over it also covers
    const gitSigned = await signedRaw(hub, 'git signed');
    const split = splitCommit(gitSigned);
    const indep = await sshSign(hub, 'git', split.payload);
    const again = await verifyCommitSignature(embedSig(split.payload, indep), { tmpRoot: tmpRootOf(hub) });
    assert.equal(again.valid, true);
  });
});

test('tampered: any change to the signed bytes fails verification', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const raw = await signedRaw(hub);
    const text = raw.toString('latin1');
    const variants: Buffer[] = [
      Buffer.from(text.replace('signed one', 'signed onE'), 'latin1'),
      Buffer.from(text.replace(/^tree ([0-9a-f])/, (_m, c: string) => `tree ${c === 'a' ? 'b' : 'a'}`), 'latin1'),
      Buffer.from(text.replace(/(committer hub1 <[^>]*> )(\d+)/, (_m, a: string, n: string) => `${a}${String(Number(n) + 1)}`), 'latin1'),
      Buffer.from(text.replace('author hub1', 'author hub2'), 'latin1'),
      Buffer.from(`${text}extra`, 'latin1'),
      Buffer.from(text.replace('\n\nsigned one\n', '\n\nsigned one\n\n'), 'latin1'),
    ];
    for (const [i, t] of variants.entries()) {
      assert.notEqual(t.toString('latin1'), text, `variant ${i} changed something`);
      const v = await verifyCommitSignature(t, { tmpRoot: tmpRootOf(hub) });
      assert.equal(v.valid, false, `variant ${i}`);
      assert.equal(v.reason, 'bad-signature', `variant ${i}: ${v.reason}`);
      assert.equal(v.pubkeyLine, hub.pub.line, 'claimed key is reported (untrusted) for diagnostics');
    }
    // a flipped signature byte
    const armor = splitCommit(raw).armor as string;
    const blob = blobOf(armor);
    blob[blob.length - 3] = (blob[blob.length - 3] as number) ^ 0x01;
    const flipped = embedSig(splitCommit(raw).payload, reArmor(blob));
    const v = await verifyCommitSignature(flipped, { tmpRoot: tmpRootOf(hub) });
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'bad-signature');
  });
});

test('wrong namespace: an agent-ledger-v1 signature never verifies as a commit signature', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const unsignedSha = await hub.commit([{ path: 'a.md', content: 'x\n' }], { signed: false });
    const unsigned = await hub.store.readCommitRaw(unsignedSha);
    const wrongNs = await signPayload(unsigned, { keyFile: hub.keyFile });
    const v = await verifyCommitSignature(embedSig(unsigned, wrongNs), { tmpRoot: tmpRootOf(hub) });
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'namespace');
    assert.equal(v.pubkeyLine, hub.pub.line);
    for (const ns of ['file', 'git2', 'GIT', 'git ']) {
      let armor: string;
      try {
        armor = await sshSign(hub, ns, unsigned);
      } catch {
        continue; // ssh-keygen refused that namespace string
      }
      const r = await verifyCommitSignature(embedSig(unsigned, armor), { tmpRoot: tmpRootOf(hub) });
      assert.equal(r.valid, false, ns);
      assert.equal(r.reason, 'namespace', ns);
    }
  });
});

test('key mismatch: the signer is the key inside the signature, never the committer e-mail or a swapped key', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const a = await kit.makeHub(1);
    const b = await kit.makeHub(2);
    // A signs, but the commit claims to be B (committer e-mail = B's device id)
    const claimsB = await a.trees.commitTree({
      tree: await a.trees.buildTree(null, [{ path: 'a.md', content: 'x\n' }]),
      parents: [],
      message: 'claims to be b',
      identity: { name: 'b', email: `${b.deviceId}@devices.agent-ledger.invalid` },
      signing: a.signing,
    });
    const v = await verifyCommitSignature(await a.store.readCommitRaw(claimsB), { tmpRoot: tmpRootOf(a) });
    assert.equal(v.valid, true);
    assert.equal(v.pubkeyLine, a.pub.line, 'authority is the key in the signature');
    assert.notEqual(v.pubkeyLine, b.pub.line);
    assert.equal(v.headers?.committerEmail, `${b.deviceId}@devices.agent-ledger.invalid`);

    // attacker swaps B's public key into A's signature blob: verification against B's key fails
    const raw = await a.store.readCommitRaw(claimsB);
    const split = splitCommit(raw);
    const blob = blobOf(split.armor as string);
    const bWire = Buffer.from(b.pub.line.split(' ')[1] as string, 'base64');
    assert.equal(bWire.length, 51);
    bWire.copy(blob, 14);
    const swapped = await verifyCommitSignature(embedSig(split.payload, reArmor(blob)), { tmpRoot: tmpRootOf(a) });
    assert.equal(swapped.valid, false);
    assert.equal(swapped.reason, 'bad-signature');
    assert.equal(swapped.pubkeyLine, b.pub.line);

    // a signature by B over the commit verifies as B, never as A
    const unsignedSha = await a.commit([{ path: 'q.md', content: 'q\n' }], { signed: false });
    const unsigned = await a.store.readCommitRaw(unsignedSha);
    const byB = await verifyCommitSignature(embedSig(unsigned, await sshSign(b, 'git', unsigned)), { tmpRoot: tmpRootOf(a) });
    assert.equal(byB.valid, true);
    assert.equal(byB.pubkeyLine, b.pub.line);
  });
});

test('foreign-signed remote commit: cryptographically valid for ITS key (trust is the gate\'s job, not this module\'s)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const known = await kit.makeHub(1);
    const stranger = await kit.makeHub(2);
    const sha = await kit.remote.pushSigned(stranger, [{ path: 'a.md', content: 'x\n' }]);
    const raw = await kit.remote.store.readCommitRaw(sha);
    const v = await verifyCommitSignature(raw, { tmpRoot: tmpRootOf(known) });
    assert.equal(v.valid, true);
    assert.equal(v.pubkeyLine, stranger.pub.line);
    assert.notEqual(v.pubkeyLine, known.pub.line);
  });
});

test('unsigned and multiple-signature commits', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const sha = await kit.remote.pushUnsigned([{ path: 'a.md', content: 'x\n' }], 'gpgsig not a header');
    const raw = await kit.remote.store.readCommitRaw(sha);
    const v = await verifyCommitSignature(raw, { tmpRoot: tmpRootOf(hub) });
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'unsigned');
    assert.equal(v.pubkeyLine, null);
    assert.ok(v.headers !== null, 'headers still parsed for the ratchet');

    const msgTrick = Buffer.concat([raw.subarray(0, raw.indexOf('\n\n') + 2), Buffer.from('gpgsig -----BEGIN SSH SIGNATURE-----\n -----END SSH SIGNATURE-----\n')]);
    assert.equal((await verifyCommitSignature(msgTrick, { tmpRoot: tmpRootOf(hub) })).reason, 'unsigned', 'a "gpgsig" in the message body is not a signature');

    const signed = await signedRaw(hub);
    const split = splitCommit(signed);
    const twice = embedSig(embedSig(split.payload, split.armor as string), split.armor as string);
    const m = await verifyCommitSignature(twice, { tmpRoot: tmpRootOf(hub) });
    assert.equal(m.valid, false);
    assert.equal(m.reason, 'multiple-signatures');
  });
});

test('malformed armor is invalid and never throws', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const raw = await signedRaw(hub);
    const split = splitCommit(raw);
    const good = blobOf(split.armor as string);
    const wrap = (armor: string): Buffer => embedSig(split.payload, armor);
    const b64 = good.toString('base64');
    const cases: [string, string][] = [
      ['not armor at all', 'garbage\n'],
      ['empty body', '-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n'],
      ['non-base64 character', `-----BEGIN SSH SIGNATURE-----\n${b64.slice(0, 40)}!${b64.slice(41)}\n-----END SSH SIGNATURE-----\n`],
      ['missing END', `-----BEGIN SSH SIGNATURE-----\n${b64}\n`],
      ['length not a multiple of 4', `-----BEGIN SSH SIGNATURE-----\n${b64.slice(0, -1)}\n-----END SSH SIGNATURE-----\n`],
      ['truncated blob', reArmor(good.subarray(0, 40))],
      ['truncated in the signature string', reArmor(good.subarray(0, good.length - 5))],
      ['bad magic', reArmor(Buffer.concat([Buffer.from('XSHSIG'), good.subarray(6)]))],
      ['version 2', reArmor(Buffer.concat([good.subarray(0, 6), Buffer.from([0, 0, 0, 2]), good.subarray(10)]))],
      ['trailing bytes', reArmor(Buffer.concat([good, Buffer.from([1, 2, 3])]))],
      ['oversized (> 4096 chars)', reArmor(Buffer.concat([good, Buffer.alloc(5000, 7)]))],
      ['length field larger than the blob', reArmor(Buffer.concat([good.subarray(0, 10), Buffer.from([0x7f, 0xff, 0xff, 0xff]), good.subarray(14)]))],
      ['non-canonical base64 padding', `-----BEGIN SSH SIGNATURE-----\n${b64.replace(/=*$/, '')}==\n-----END SSH SIGNATURE-----\n`],
    ];
    for (const [name, armor] of cases) {
      const v = await verifyCommitSignature(wrap(armor), { tmpRoot: tmpRootOf(hub) });
      assert.equal(v.valid, false, name);
      assert.ok(v.reason === 'malformed-armor' || v.reason === 'malformed-commit', `${name}: ${v.reason}`);
    }
    // unsupported key type: corrupt the type string inside the embedded public key blob
    const notEd = Buffer.from(good);
    notEd.write('ssh-rsaXXXX', 18, 'latin1');
    const u = await verifyCommitSignature(wrap(reArmor(notEd)), { tmpRoot: tmpRootOf(hub) });
    assert.equal(u.valid, false);
    assert.equal(u.reason, 'unsupported-key');
  });
});

test('parseSshSignature: namespace, hash algorithm and key out of a real signature', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const raw = await signedRaw(hub);
    const info = parseSshSignature(splitCommit(raw).armor as string);
    assert.ok(!('error' in info));
    if ('error' in info) return;
    assert.equal(info.namespace, 'git');
    assert.equal(info.hashAlgorithm, 'sha512');
    assert.equal(info.pubkeyLine, hub.pub.line);
    assert.deepEqual(parseSshSignature(''), { error: 'malformed-armor' });
    assert.deepEqual(parseSshSignature(undefined as never), { error: 'malformed-armor' });
  });
});

test('splitCommit: gpgsig and its continuation lines are removed, everything else kept byte for byte', () => {
  const sig = ['gpgsig -----BEGIN SSH SIGNATURE-----', ' AAAA', ' ', ' BBBB', ' -----END SSH SIGNATURE-----'];
  const headers = [
    `tree ${'a'.repeat(40)}`,
    `parent ${'b'.repeat(40)}`,
    `parent ${'c'.repeat(40)}`,
    'author A <a@x.invalid> 1700000000 +0100',
    'committer C <c@x.invalid> 1700000001 -0530',
  ];
  const mergetag = ['mergetag object ' + 'd'.repeat(40), ' type commit', ' tag v1', ' ', ' tag body'];
  const withSig = Buffer.from([...headers, ...mergetag, ...sig, 'gpgsig-sha256 keep me', '', 'message\r\nbody\n'].join('\n'), 'latin1');
  const s = splitCommit(withSig);
  assert.equal(s.signatureCount, 1);
  assert.equal(s.armor, '-----BEGIN SSH SIGNATURE-----\nAAAA\n\nBBBB\n-----END SSH SIGNATURE-----\n');
  assert.equal(s.payload.toString('latin1'), [...headers, ...mergetag, 'gpgsig-sha256 keep me', '', 'message\r\nbody\n'].join('\n'));
  assert.deepEqual(s.headers?.parents, ['b'.repeat(40), 'c'.repeat(40)]);
  assert.equal(s.headers?.committerTime, 1700000001);
  assert.equal(s.headers?.committerTz, '-0530');
  assert.equal(s.headers?.committerName, 'C');
  // non-UTF-8 message bytes survive in the payload
  const bin = Buffer.concat([Buffer.from([...headers, ''].join('\n') + '\n'), Buffer.from([0xff, 0x00, 0xfe])]);
  assert.ok(splitCommit(bin).payload.equals(bin));
});

test('splitCommit: malformed commits yield no headers, never an exception', () => {
  const t = `tree ${'a'.repeat(40)}`;
  const au = 'author A <a@x.invalid> 1 +0000';
  const co = 'committer C <c@x.invalid> 1 +0000';
  for (const text of [
    '',
    'garbage',
    `${t}\n${au}\n${co}\nno blank line`,
    `${au}\n${t}\n${co}\n\nm`,
    `${t}\n${t}\n${au}\n${co}\n\nm`,
    `${t}\n${au}\n${co}\n${co}\n\nm`,
    `${t}\n${au}\n\nm`,
    `${t}\n${au}\n${co}\nparent ${'b'.repeat(40)}\n\nm`,
    `tree XYZ\n${au}\n${co}\n\nm`,
    `${t}\nparent zzz\n${au}\n${co}\n\nm`,
    `${t}\n${au}\ncommitter C <c@x.invalid> notanumber +0000\n\nm`,
    `${t}\n${au}\ncommitter no-angle-brackets 1 +0000\n\nm`,
    `${t}\n${au}\ncommitter C <c@x.invalid> 1 +00\n\nm`,
  ]) {
    assert.equal(splitCommit(Buffer.from(text, 'latin1')).headers, null, JSON.stringify(text));
  }
  assert.notEqual(splitCommit(Buffer.from(`${t}\n${au}\n${co}\n\nm`)).headers, null);
});

test('oversized and empty input, and a broken verifier environment, are invalid (never thrown)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const tmpRoot = tmpRootOf(hub);
    assert.equal((await verifyCommitSignature(Buffer.alloc(0), { tmpRoot })).reason, 'malformed-commit');
    assert.equal((await verifyCommitSignature(Buffer.alloc(MAX_COMMIT_BYTES + 1, 97), { tmpRoot })).reason, 'malformed-commit');
    assert.equal((await verifyCommitSignature('not a buffer' as never, { tmpRoot })).valid, false);
    const raw = await signedRaw(hub);
    const noBin = await verifyCommitSignature(raw, { tmpRoot, bin: '/nonexistent/ssh-keygen' });
    assert.equal(noBin.valid, false);
    assert.equal(noBin.reason, 'verifier-error');
    const badRoot = await verifyCommitSignature(raw, { tmpRoot: 'relative/tmp' });
    assert.equal(badRoot.valid, false);
    assert.equal(badRoot.reason, 'verifier-error');
    const slow = await verifyCommitSignature(raw, { tmpRoot, timeoutMs: 1 }).catch(() => 'threw');
    assert.notEqual(slow, 'threw');
    assert.ok(typeof slow === 'object');
  });
});

test('fuzz: mutated and random commits never throw and never verify unless byte-identical to a signed commit', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const raw = await signedRaw(hub);
    let seed = 0x2545f491;
    const rnd = (n: number): number => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed % n;
    };
    for (let i = 0; i < 120; i++) {
      const m = Buffer.from(raw);
      const flips = 1 + rnd(3);
      for (let f = 0; f < flips; f++) m[rnd(m.length)] = rnd(256);
      const cut = rnd(4) === 0 ? m.subarray(0, rnd(m.length)) : m;
      const v = await verifyCommitSignature(cut, { tmpRoot: tmpRootOf(hub) });
      assert.equal(typeof v.valid, 'boolean');
      if (v.valid) assert.ok(cut.equals(raw) || splitCommit(cut).payload.equals(splitCommit(raw).payload), 'valid only when the signed payload is unchanged');
    }
    for (let i = 0; i < 60; i++) {
      const junk = Buffer.alloc(rnd(400));
      for (let k = 0; k < junk.length; k++) junk[k] = rnd(256);
      const v = await verifyCommitSignature(junk, { tmpRoot: tmpRootOf(hub) });
      assert.equal(v.valid, false);
    }
  });
});
