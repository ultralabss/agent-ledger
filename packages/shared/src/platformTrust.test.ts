/**
 * platformTrust: POSIX backend (real temp dirs + injected fake probes), weak-filesystem
 * bypass semantics, invariants I1/I5, and the win32 backend driven through fake
 * fs / spawnFile / path.win32 (so it runs on any host). Real-Windows tests are skipped
 * elsewhere with a reason.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import {
  assertPrivateDir,
  assertPrivateFile,
  assertTrustedAncestors,
  createTrustDeps,
  ELEVATED_MESSAGE,
  ensurePrivateDir,
  fsTypeFor,
  invalidateFsProbeCache,
  isOwnedByMe,
  isRootOwnedTrustedParent,
  isStatOwnedByMe,
  nodeTrustFs,
  openPrivate,
  parseMountInfo,
  posixWriteBitsTrusted,
  probeCaseInsensitive,
  probeFs,
  probeFsStatOnly,
  resolveTrustedExecutable,
  TrustError,
  type StatLike,
  type TrustCode,
  type TrustDeps,
  type TrustFs,
  type TrustHandle,
} from './platformTrust.ts';
import { WIN_PS_SCRIPT, type SpawnFile, type SpawnResult, type WinPathInfo } from './win-ps.ts';

const NOT_POSIX = process.platform === 'win32' ? 'needs POSIX filesystem semantics (win32 host)' : false;
const NOT_WIN32 = process.platform !== 'win32' ? 'win32 only' : false;
const UID = userInfo().uid;

async function rejectsWith(p: Promise<unknown>, code: TrustCode, msg?: RegExp): Promise<TrustError> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof TrustError, `expected TrustError(${code}), got ${String(err)}`);
    assert.equal(err.code, code, err.message);
    if (msg !== undefined) assert.match(err.message, msg);
    return err;
  }
  assert.fail(`expected TrustError(${code}), but it resolved`);
}

async function sandbox(): Promise<string> {
  const base = await mkdtemp(join(tmpdir(), 'ptrust-'));
  return base;
}

function posixDeps(over: Partial<TrustDeps> = {}): Partial<TrustDeps> {
  return {
    platform: 'linux',
    getuid: () => UID,
    env: {},
    cache: new Map(),
    homedir: () => '/nonexistent-home',
    release: () => '6.1.0',
    constants: { ...createTrustDeps().constants, O_NOFOLLOW: createTrustDeps().constants.O_NOFOLLOW ?? 0x20000 },
    ...over,
  };
}

const isProbe = (p: string): boolean => p.includes('.ledger-fsprobe-');
function wrapFs(over: Partial<TrustFs>): TrustFs {
  return { ...nodeTrustFs, ...over };
}
/** Fake the probe file's handle (the probe works ONLY through its descriptor, W1). */
function probeHandleFs(over: Partial<TrustHandle> | ((h: TrustHandle) => Partial<TrustHandle>)): TrustFs {
  return wrapFs({
    open: async (p, f, m) => {
      const h = await nodeTrustFs.open(p, f, m);
      return isProbe(p) ? { ...h, ...(typeof over === 'function' ? over(h) : over) } : h;
    },
  });
}
function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

// ---- weak-filesystem fakes (probe results forced) --------------------------------------

const WEAK_FAKES: Record<string, { fs: TrustFs; cap: 'posixModes' | 'ownerMatches' | 'hardlinks' }> = {
  'mode bits read back as 0777': {
    cap: 'posixModes',
    fs: probeHandleFs((h) => ({ stat: async () => ({ ...(await h.stat()), mode: 0o100777 }) })),
  },
  'files owned by uid 65534': {
    cap: 'ownerMatches',
    fs: probeHandleFs((h) => ({ stat: async () => ({ ...(await h.stat()), uid: 65534 }) })),
  },
  'chmod is a silent no-op': { cap: 'posixModes', fs: probeHandleFs({ chmod: async () => undefined }) },
  'link() fails with ENOTSUP': {
    cap: 'hardlinks',
    fs: wrapFs({
      link: async () => {
        throw errno('ENOTSUP');
      },
    }),
  },
};

// ---- POSIX: ensurePrivateDir / assertPrivateDir ----------------------------------------

test('posix: ensurePrivateDir creates a real 0700 dir on a strong filesystem', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const dir = join(base, 'a', 'spool');
  const caps = await ensurePrivateDir(dir, posixDeps());
  assert.equal(caps.weak, false);
  assert.equal(caps.bypassed, false);
  assert.deepEqual([caps.posixModes, caps.ownerMatches, caps.hardlinks], [true, true, true]);
  assert.equal((await stat(dir)).mode & 0o022, 0);
  await assertPrivateDir(dir, {}, posixDeps());
  await rm(base, { recursive: true, force: true });
});

test('posix: the capability probe cleans up after itself', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  await probeFs(base, posixDeps());
  const { readdir } = await import('node:fs/promises');
  assert.deepEqual(await readdir(base), []);
  await rm(base, { recursive: true, force: true });
});

// ---- W1: the probe only acts through the descriptor of the file it created ----------------

test('W1: a probe name swapped for a symlink mid-probe is never chmod-ed or followed', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const victim = join(base, 'victim-secret');
  await writeFile(victim, 'keep', { mode: 0o600 });
  await chmod(victim, 0o600);
  const dir = join(base, 'probed');
  await mkdir(dir, { mode: 0o700 });
  const planting = wrapFs({
    open: async (p, f, m) => {
      const h = await nodeTrustFs.open(p, f, m);
      if (isProbe(p) && !p.endsWith('.l')) {
        // the attacker wins the race right after our O_EXCL create: name -> symlink to the victim
        await rm(p);
        await symlink(victim, p);
      }
      return h;
    },
  });
  const caps = await probeFs(dir, posixDeps({ fs: planting }));
  assert.equal(caps.posixModes, true, 'modes are judged on our own descriptor');
  assert.equal((await stat(victim)).mode & 0o777, 0o600, 'the symlink target mode must be untouched');
  assert.equal(await readFile(victim, 'utf8'), 'keep');
  const { readdir } = await import('node:fs/promises');
  assert.deepEqual(await readdir(dir), [], 'probe leftovers (incl. the planted link) are removed');
  await rm(base, { recursive: true, force: true });
});

test('W1: a dir not owned by us is never probed (OWNER at once), even under the weak-FS bypass', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const dir = await realpath(base);
  await chmod(dir, 0o777);
  let created = 0;
  const foreign = (uid: number, mode?: number): TrustFs =>
    wrapFs({
      lstat: async (p) => {
        const st = await nodeTrustFs.lstat(p);
        return p === dir ? { ...st, uid, ...(mode === undefined ? {} : { mode }) } : st;
      },
      open: async (p, f, m) => {
        if (isProbe(p)) created += 1;
        return nodeTrustFs.open(p, f, m);
      },
    });
  const env = { LEDGER_ALLOW_WEAK_FS: '1' };
  await rejectsWith(probeFs(dir, posixDeps({ fs: foreign(UID + 1) })), 'OWNER');
  await rejectsWith(probeFs(dir, posixDeps({ fs: foreign(UID + 1), env })), 'OWNER');
  await rejectsWith(probeFs(dir, posixDeps({ fs: foreign(0, 0o40777), env })), 'OWNER', undefined); // root-owned but world-writable, not sticky
  await rejectsWith(assertPrivateDir(dir, {}, posixDeps({ fs: foreign(UID + 1), env })), 'OWNER');
  await rejectsWith(ensurePrivateDir(dir, posixDeps({ fs: foreign(UID + 1) })), 'OWNER');
  assert.equal(created, 0, 'no probe file may be created in a directory that is not ours');
  // root-owned sticky parent (/tmp-like) under the bypass: probing is allowed (nobody can plant there)
  const c = await probeFs(dir, posixDeps({ fs: foreign(0, 0o41777), env, cache: new Map() }));
  assert.equal(created, 1);
  assert.equal(c.weak, false);
  await rm(base, { recursive: true, force: true });
});

test('W1: probeFsStatOnly creates, chmods and links nothing', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const writes: string[] = [];
  const spy = wrapFs({
    open: async (p) => { writes.push(`open ${p}`); throw errno('EACCES'); },
    mkdir: async (p) => { writes.push(`mkdir ${p}`); },
    link: async (a) => { writes.push(`link ${a}`); },
    rm: async (p) => { writes.push(`rm ${p}`); },
  });
  const caps = await probeFsStatOnly(base, posixDeps({ fs: spy }));
  assert.deepEqual(writes, []);
  assert.equal(typeof caps.caseInsensitive, 'boolean');
  const { readdir } = await import('node:fs/promises');
  assert.deepEqual(await readdir(base), []);
  await rm(base, { recursive: true, force: true });
});

test('posix: a symlinked leaf, or symlinked parent outside $HOME, is refused', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const target = join(base, 'real');
  await mkdir(target, { mode: 0o700 });
  await symlink(target, join(base, 'link'));
  await rejectsWith(assertPrivateDir(join(base, 'link'), {}, posixDeps()), 'SYMLINK');
  await rejectsWith(ensurePrivateDir(join(base, 'link', 'child'), posixDeps()), 'SYMLINK');
  await rm(base, { recursive: true, force: true });
});

test('posix: group-writable dir is PERMS, and the weak-FS env flag does not rescue a fixable misconfig (I5)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const dir = join(base, 'g');
  await mkdir(dir, { mode: 0o700 });
  await chmod(dir, 0o775);
  await rejectsWith(assertPrivateDir(dir, {}, posixDeps()), 'PERMS', /writable by group\/other/);
  await rejectsWith(assertPrivateDir(dir, {}, posixDeps({ env: { LEDGER_ALLOW_WEAK_FS: '1' } })), 'PERMS');
  await rejectsWith(ensurePrivateDir(dir, posixDeps({ env: { LEDGER_ALLOW_WEAK_FS: '1' } })), 'PERMS');
  await rm(base, { recursive: true, force: true });
});

test('posix: secret dir also refuses group/other READ (0750), a plain private dir accepts it', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const dir = join(base, 'r');
  await mkdir(dir, { mode: 0o700 });
  await chmod(dir, 0o750);
  await assertPrivateDir(dir, {}, posixDeps());
  await rejectsWith(assertPrivateDir(dir, { secret: true }, posixDeps()), 'PERMS');
  await rm(base, { recursive: true, force: true });
});

test('posix: directory owned by someone else is OWNER on a strong filesystem', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const dir = join(base, 'o');
  await mkdir(dir, { mode: 0o700 });
  const foreign = wrapFs({
    lstat: async (p) => {
      const s = await nodeTrustFs.lstat(p);
      return p === dir ? { ...s, uid: UID + 1 } : s;
    },
  });
  await rejectsWith(assertPrivateDir(dir, {}, posixDeps({ fs: foreign })), 'OWNER');
  await rm(base, { recursive: true, force: true });
});

test('posix: a path that is a regular file is not a directory (IDENTITY)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  await writeFile(join(base, 'f'), 'x');
  await rejectsWith(assertPrivateDir(join(base, 'f'), {}, posixDeps()), 'IDENTITY');
  await rm(base, { recursive: true, force: true });
});

test('posix: ensurePrivateDir inside $HOME asserts every component (a group-writable ancestor is refused)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const mid = join(base, 'mid');
  await mkdir(mid, { mode: 0o700 });
  await chmod(mid, 0o770);
  await rejectsWith(ensurePrivateDir(join(mid, 'spool'), posixDeps({ homedir: () => base })), 'PERMS');
  await chmod(mid, 0o700);
  const caps = await ensurePrivateDir(join(mid, 'spool'), posixDeps({ homedir: () => base }));
  assert.equal(caps.weak, false);
  await rm(base, { recursive: true, force: true });
});

test('posix: parent root-owned sticky/ not-writable rule', () => {
  assert.equal(isRootOwnedTrustedParent({ uid: 0, mode: 0o41777 }), true);
  assert.equal(isRootOwnedTrustedParent({ uid: 0, mode: 0o40755 }), true);
  assert.equal(isRootOwnedTrustedParent({ uid: 0, mode: 0o40777 }), false);
  assert.equal(isRootOwnedTrustedParent({ uid: 0, mode: 0o40775 }), false);
  assert.equal(isRootOwnedTrustedParent({ uid: 1234, mode: 0o41777 }), false);
});

test('posixWriteBitsTrusted: o+w never, g+w only through the explicit opt-in', async () => {
  assert.equal(await posixWriteBitsTrusted(0o775, 20), false);
  assert.equal(await posixWriteBitsTrusted(0o755, 20), true);
  assert.equal(await posixWriteBitsTrusted(0o777, 20, async () => true), false);
  assert.equal(await posixWriteBitsTrusted(0o1777, 20, async () => true), false);
  assert.equal(await posixWriteBitsTrusted(0o775, 20, async () => true), true);
  assert.equal(await posixWriteBitsTrusted(0o775, 20, async () => false), false);
});

// ---- POSIX: files ---------------------------------------------------------------------

test('posix: assertPrivateFile(secret) - 0600 ok, 0644 PERMS, hard link IDENTITY, symlink SYMLINK, foreign OWNER', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const f = join(base, 'token');
  await writeFile(f, 'x', { mode: 0o600 });
  await chmod(f, 0o600);
  await assertPrivateFile(f, { secret: true }, posixDeps());
  await chmod(f, 0o644);
  await rejectsWith(assertPrivateFile(f, { secret: true }, posixDeps()), 'PERMS');
  await assertPrivateFile(f, {}, posixDeps()); // non-secret: only group/other WRITE matters
  await chmod(f, 0o664);
  await rejectsWith(assertPrivateFile(f, {}, posixDeps()), 'PERMS');
  await chmod(f, 0o600);
  await link(f, join(base, 'second-name'));
  await rejectsWith(assertPrivateFile(f, { secret: true }, posixDeps()), 'IDENTITY', /hard links/);
  await symlink(f, join(base, 'sym'));
  await rejectsWith(assertPrivateFile(join(base, 'sym'), { secret: true }, posixDeps()), 'SYMLINK');
  const g = join(base, 'other');
  await writeFile(g, 'x', { mode: 0o600 });
  const foreign = wrapFs({
    lstat: async (p) => {
      const s = await nodeTrustFs.lstat(p);
      return p === g ? { ...s, uid: UID + 1 } : s;
    },
  });
  await rejectsWith(assertPrivateFile(g, { secret: true }, posixDeps({ fs: foreign })), 'OWNER');
  await rm(base, { recursive: true, force: true });
});

test('posix: openPrivate append/excl/trunc/read semantics, 0600 on create', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const f = join(base, 'log.jsonl');
  const a = await openPrivate(f, 'append', 0o600, posixDeps());
  await a.writeFile('one\n');
  await a.close();
  const b = await openPrivate(f, 'append', 0o600, posixDeps());
  await b.writeFile('two\n');
  await b.close();
  assert.equal(await readFile(f, 'utf8'), 'one\ntwo\n');
  assert.equal((await stat(f)).mode & 0o777, 0o600);
  await assert.rejects(openPrivate(f, 'excl', 0o600, posixDeps()), (e: NodeJS.ErrnoException) => e.code === 'EEXIST');
  const t = await openPrivate(f, 'trunc', 0o600, posixDeps());
  await t.writeFile('new');
  await t.close();
  assert.equal(await readFile(f, 'utf8'), 'new');
  const r = await openPrivate(f, 'read', 0o600, posixDeps());
  assert.equal(await r.readText(), 'new');
  await r.close();
  await assert.rejects(openPrivate(join(base, 'missing'), 'read', 0o600, posixDeps()), (e: NodeJS.ErrnoException) => e.code === 'ENOENT');
  await rm(base, { recursive: true, force: true });
});

test('posix: openPrivate on a planted symlink is SYMLINK and writes nothing through it (T2)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const victim = join(base, 'victim');
  await writeFile(victim, 'keep');
  const f = join(base, 'session.jsonl');
  await symlink(victim, f);
  for (const mode of ['append', 'trunc', 'read'] as const) {
    await rejectsWith(openPrivate(f, mode, 0o600, posixDeps()), 'SYMLINK');
  }
  assert.equal(await readFile(victim, 'utf8'), 'keep', 'the symlink target must be untouched (trunc must not run before the check)');
  await rm(base, { recursive: true, force: true });
});

test('posix: openPrivate refuses a file owned by someone else, and trunc does not truncate it first', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const f = join(base, 'x');
  await writeFile(f, 'precious');
  const foreign = wrapFs({
    open: async (p, fl, m) => {
      const h = await nodeTrustFs.open(p, fl, m);
      return p === f ? { ...h, stat: async () => ({ ...(await h.stat()), uid: UID + 1 }) } : h;
    },
  });
  await rejectsWith(openPrivate(f, 'trunc', 0o600, posixDeps({ fs: foreign })), 'OWNER');
  assert.equal(await readFile(f, 'utf8'), 'precious');
  await rm(base, { recursive: true, force: true });
});

test('posix: openPrivate fake lstat/fstat mismatch on a directory path is IDENTITY (not a regular file)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  await mkdir(join(base, 'd'));
  await assert.rejects(openPrivate(join(base, 'd'), 'read', 0o600, posixDeps()));
  await rm(base, { recursive: true, force: true });
});

// ---- I1: never fail-open ---------------------------------------------------------------

test('I1: no uid => every POSIX trust decision refuses instead of passing', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const f = join(base, 'f');
  await writeFile(f, 'x', { mode: 0o600 });
  const d = posixDeps({ getuid: () => undefined });
  await rejectsWith(ensurePrivateDir(join(base, 'new'), d), 'PROBE_FAILED', /user id/);
  await rejectsWith(assertPrivateDir(base, {}, d), 'PROBE_FAILED');
  await rejectsWith(assertPrivateFile(f, {}, d), 'PROBE_FAILED');
  await rejectsWith(openPrivate(f, 'read', 0o600, d), 'PROBE_FAILED');
  await rejectsWith(probeFs(base, d), 'PROBE_FAILED');
  assert.equal(isStatOwnedByMe({ uid: 0 }, d), false);
  assert.equal(isStatOwnedByMe({ uid: UID }, d), false);
  assert.equal(await isOwnedByMe(f, d), false);
  await rm(base, { recursive: true, force: true });
});

test('I1: no O_NOFOLLOW => refuse (PROBE_FAILED), never open without link protection', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const f = join(base, 'f');
  await writeFile(f, 'x', { mode: 0o600 });
  const consts = { ...createTrustDeps().constants, O_NOFOLLOW: undefined };
  const d = posixDeps({ constants: consts });
  await rejectsWith(openPrivate(f, 'read', 0o600, d), 'PROBE_FAILED', /O_NOFOLLOW/);
  await rejectsWith(probeFs(base, d), 'PROBE_FAILED', /O_NOFOLLOW/);
  await rm(base, { recursive: true, force: true });
});

test('I1: a probe that cannot even create its file is PROBE_FAILED, not "weak" (and not bypassable)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const denying = wrapFs({
    open: async (p, f, m) => {
      if (isProbe(p)) throw errno('EACCES');
      return nodeTrustFs.open(p, f, m);
    },
  });
  await rejectsWith(probeFs(base, posixDeps({ fs: denying })), 'PROBE_FAILED');
  await rejectsWith(probeFs(base, posixDeps({ fs: denying, env: { LEDGER_ALLOW_WEAK_FS: '1' } })), 'PROBE_FAILED');
  await rm(base, { recursive: true, force: true });
});

// ---- T13: weak filesystem + bypass semantics -------------------------------------------

for (const [name, fake] of Object.entries(WEAK_FAKES)) {
  test(`weak FS (${name}): probe says weak, ensurePrivateDir refuses with WEAK_FS (T13)`, { skip: NOT_POSIX }, async () => {
    const base = await sandbox();
    const caps = await probeFs(base, posixDeps({ fs: fake.fs }));
    assert.equal(caps.weak, true);
    assert.equal(caps.bypassed, false);
    assert.equal(caps[fake.cap], false);
    for (const other of ['posixModes', 'ownerMatches', 'hardlinks'] as const) {
      if (other !== fake.cap && !(fake.cap === 'posixModes' && other === 'posixModes')) {
        assert.equal(caps[other], true, `${other} must be probed independently`);
      }
    }
    assert.ok(caps.reasons.length >= 1);
    await rejectsWith(ensurePrivateDir(join(base, 'd'), posixDeps({ fs: fake.fs })), 'WEAK_FS', /LEDGER_ALLOW_WEAK_FS=1/);
    await rejectsWith(assertPrivateDir(base, {}, posixDeps({ fs: fake.fs })), 'WEAK_FS');
    await rm(base, { recursive: true, force: true });
  });
}

test('bypass: exactly "1" relaxes; every other value is no bypass at all (T13)', { skip: NOT_POSIX }, async () => {
  const fake = WEAK_FAKES['link() fails with ENOTSUP']!.fs;
  const base = await sandbox();
  const ok = posixDeps({ fs: fake, env: { LEDGER_ALLOW_WEAK_FS: '1' } });
  const caps = await probeFs(base, ok);
  assert.deepEqual([caps.weak, caps.bypassed], [true, true]);
  const made = await ensurePrivateDir(join(base, 'spool'), ok);
  assert.equal(made.bypassed, true);
  for (const v of [undefined, '', '0', 'true', 'yes', 'TRUE', 'on', ' 1', '1 ', '01', '1\n', 'one', '2']) {
    const d = posixDeps({ fs: fake, env: { LEDGER_ALLOW_WEAK_FS: v } });
    const c = await probeFs(base, d);
    assert.equal(c.weak, true);
    assert.equal(c.bypassed, false, `value ${JSON.stringify(v)} must not bypass`);
    await rejectsWith(ensurePrivateDir(join(base, 'other'), d), 'WEAK_FS');
  }
  await rm(base, { recursive: true, force: true });
});

test('bypass: a strong filesystem is never reported as bypassed, even with the flag set', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const caps = await probeFs(base, posixDeps({ env: { LEDGER_ALLOW_WEAK_FS: '1' } }));
  assert.deepEqual([caps.weak, caps.bypassed], [false, false]);
  await rm(base, { recursive: true, force: true });
});

test('I5: under bypass only the missing capability is relaxed; symlink / not-a-dir / other violations still refuse', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const env = { LEDGER_ALLOW_WEAK_FS: '1' };
  // mode bits unenforceable: a 0777 dir is tolerated ...
  const modeFake = WEAK_FAKES['mode bits read back as 0777']!.fs;
  const dir = join(base, 'loose');
  await mkdir(dir, { mode: 0o700 });
  await chmod(dir, 0o777);
  await assertPrivateDir(dir, {}, posixDeps({ fs: modeFake, env }));
  // ... but only because of that capability: without the flag it is WEAK_FS
  await rejectsWith(assertPrivateDir(dir, {}, posixDeps({ fs: modeFake })), 'WEAK_FS');
  // ... a foreign owner is NOT relaxed when ownership is still expressible
  const foreignOnModeWeak = wrapFs({
    lstat: async (p) => {
      const s = await modeFake.lstat(p);
      return p === dir ? { ...s, uid: UID + 1 } : s;
    },
    open: modeFake.open,
  });
  await rejectsWith(assertPrivateDir(dir, {}, posixDeps({ fs: foreignOnModeWeak, env })), 'OWNER');
  // a symlink is never relaxed
  await symlink(dir, join(base, 'sym'));
  await rejectsWith(assertPrivateDir(join(base, 'sym'), {}, posixDeps({ fs: modeFake, env })), 'SYMLINK');
  // a regular file is never a directory
  await writeFile(join(base, 'file'), 'x');
  await rejectsWith(assertPrivateDir(join(base, 'file'), {}, posixDeps({ fs: modeFake, env })), 'IDENTITY');
  await rm(base, { recursive: true, force: true });
});

test('I5: owner mismatch is tolerated only when ownership is the missing capability (uid 65534 fake)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const fake = WEAK_FAKES['files owned by uid 65534']!.fs;
  const f = join(base, 'x');
  await writeFile(f, 'x', { mode: 0o600 });
  const uidFake = wrapFs({
    // the FILE reads as foreign-owned; the directory stays ours (a foreign dir is never probed, W1)
    lstat: async (p) => ({ ...(await nodeTrustFs.lstat(p)), ...(p === f ? { uid: 65534 } : {}) }),
    open: async (p, fl, m) => {
      const h = await nodeTrustFs.open(p, fl, m);
      return { ...h, stat: async () => ({ ...(await h.stat()), uid: 65534 }) };
    },
  });
  void fake;
  const env = { LEDGER_ALLOW_WEAK_FS: '1' };
  await rejectsWith(openPrivate(f, 'read', 0o600, posixDeps({ fs: uidFake })), 'WEAK_FS');
  const h = await openPrivate(f, 'read', 0o600, posixDeps({ fs: uidFake, env }));
  await h.close();
  await assertPrivateFile(f, { secret: true }, posixDeps({ fs: uidFake, env }));
  // symlink still refused under bypass
  await symlink(f, join(base, 'sym'));
  await rejectsWith(openPrivate(join(base, 'sym'), 'read', 0o600, posixDeps({ fs: uidFake, env })), 'SYMLINK');
  await rm(base, { recursive: true, force: true });
});

test('I5: hard links relaxed only when the filesystem has no hard links', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const f = join(base, 'token');
  await writeFile(f, 'x', { mode: 0o600 });
  await link(f, join(base, 'alias'));
  const noLinks = WEAK_FAKES['link() fails with ENOTSUP']!.fs;
  await rejectsWith(assertPrivateFile(f, { secret: true }, posixDeps()), 'IDENTITY');
  await rejectsWith(assertPrivateFile(f, { secret: true }, posixDeps({ fs: noLinks })), 'WEAK_FS');
  await assertPrivateFile(f, { secret: true }, posixDeps({ fs: noLinks, env: { LEDGER_ALLOW_WEAK_FS: '1' } }));
  await rm(base, { recursive: true, force: true });
});

// ---- WSL / mountinfo -------------------------------------------------------------------

test('parseMountInfo / fsTypeFor: octal escapes, longest prefix, unknown', () => {
  const text = [
    '22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw',
    '40 22 0:50 / /mnt/c rw,noatime - 9p C:\\134 rw,aname=drvfs',
    '41 22 0:51 / /mnt/with\\040space rw - drvfs D:\\134 rw',
    'garbage line',
  ].join('\n');
  const m = parseMountInfo(text);
  assert.equal(m.length, 3);
  assert.equal(fsTypeFor('/home/u/.ledger', m), 'ext4');
  assert.equal(fsTypeFor('/mnt/c/Users/u', m), '9p');
  assert.equal(fsTypeFor('/mnt/c', m), '9p');
  assert.equal(fsTypeFor('/mnt/cc/x', m), 'ext4', 'prefix match must respect path boundaries');
  assert.equal(fsTypeFor('/mnt/with space/x', m), 'drvfs');
  assert.equal(fsTypeFor('/x', []), 'unknown');
});

function mappedFs(from: string, to: string, mountinfo: string): TrustFs {
  const m = (p: string): string => (p.startsWith(from) ? to + p.slice(from.length) : p);
  return {
    lstat: (p) => nodeTrustFs.lstat(m(p)),
    stat: (p) => nodeTrustFs.stat(m(p)),
    mkdir: (p, mode, r) => nodeTrustFs.mkdir(m(p), mode, r),
    rmdir: (p) => nodeTrustFs.rmdir(m(p)),
    rm: (p) => nodeTrustFs.rm(m(p)),
    open: (p, f, mo) => nodeTrustFs.open(m(p), f, mo),
    link: (a, b) => nodeTrustFs.link(m(a), m(b)),
    readdir: (p) => nodeTrustFs.readdir(m(p)),
    realpath: async (p) => (p.startsWith(from) ? p : nodeTrustFs.realpath(p)),
    readText: async (p) => {
      if (p === '/proc/self/mountinfo') return mountinfo;
      if (p.startsWith('/proc/')) throw errno('ENOENT');
      return nodeTrustFs.readText(m(p));
    },
  };
}

test('WSL: DrvFs/9p mounts and /mnt/<x> are weak even when the behavioural probe passes (T12/T13)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const wslRelease = (): string => '5.15.90.1-microsoft-standard-WSL2';
  // /mnt/c path, mountinfo unreadable (typical DrvFs failure to enumerate): the path alone is enough
  const noInfo = mappedFs('/mnt/c/proj', base, '');
  const c1 = await probeFs('/mnt/c/proj', posixDeps({ fs: noInfo, release: wslRelease }));
  assert.equal(c1.weak, true);
  assert.match(c1.reasons.join(' '), /WSL/);
  // 9p mount somewhere else on WSL
  const info9p = `50 22 0:50 / /home/u/share rw - 9p share rw`;
  const c2 = await probeFs('/home/u/share', posixDeps({ fs: mappedFs('/home/u/share', base, info9p), release: wslRelease }));
  assert.equal(c2.weak, true);
  assert.equal(c2.fsType, '9p');
  // the same 9p mount on plain Linux is judged by behaviour only
  const c3 = await probeFs('/home/u/share', posixDeps({ fs: mappedFs('/home/u/share', base, info9p), cache: new Map() }));
  assert.equal(c3.weak, false);
  assert.equal(c3.fsType, '9p');
  // weak on WSL => ensure refuses, flag "1" is the only way in
  await rejectsWith(ensurePrivateDir('/mnt/c/proj/ledger', posixDeps({ fs: noInfo, release: wslRelease, cache: new Map() })), 'WEAK_FS');
  await rm(base, { recursive: true, force: true });
});

// ---- cache (T8) ------------------------------------------------------------------------

test('probe cache: reused, reprobed on ctime change and on a clock jump in either direction (T8)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  let probes = 0;
  const counting = wrapFs({
    open: async (p, f, m) => {
      if (isProbe(p)) probes += 1;
      return nodeTrustFs.open(p, f, m);
    },
  });
  let now = 10_000_000;
  const d = posixDeps({ fs: counting, now: () => now });
  await probeFs(base, d);
  await probeFs(base, d);
  assert.equal(probes, 1, 'second call must come from the cache');
  await chmod(base, 0o750);
  await chmod(base, 0o700);
  await probeFs(base, d);
  assert.equal(probes, 2, 'a ctime change must force a re-probe');
  now += 11 * 60 * 1000;
  await probeFs(base, d);
  assert.equal(probes, 3, 'expired entry');
  now -= 30 * 60 * 1000; // sleep/wake or NTP step backwards
  await probeFs(base, d);
  assert.equal(probes, 4, 'a backwards clock jump must not keep a stale entry alive');
  invalidateFsProbeCache(d);
  await probeFs(base, d);
  assert.equal(probes, 5);
  await rm(base, { recursive: true, force: true });
});

test('probe cache: our own appends do not make every open re-probe', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  let probes = 0;
  const counting = wrapFs({
    open: async (p, f, m) => {
      if (isProbe(p)) probes += 1;
      return nodeTrustFs.open(p, f, m);
    },
  });
  const d = posixDeps({ fs: counting });
  for (let i = 0; i < 4; i += 1) {
    const h = await openPrivate(join(base, `s${String(i)}.jsonl`), 'append', 0o600, d);
    await h.close();
  }
  assert.equal(probes, 1);
  await rm(base, { recursive: true, force: true });
});

// ---- case probe ------------------------------------------------------------------------

test('probeCaseInsensitive: stat-only, identity of the case-swapped path decides', async () => {
  const st = (ino: bigint): StatLike => ({
    isSymbolicLink: () => false, isDirectory: () => true, isFile: () => false,
    uid: 0, gid: 0, mode: 0o40755, nlink: 1, dev: 1n, ino, ctimeNs: 1n,
  });
  const same = wrapFs({ stat: async () => st(5n) });
  assert.equal(await probeCaseInsensitive('/Work/Repo', { platform: 'darwin', fs: same }), true);
  const different = wrapFs({ stat: async (p) => st(p === '/Work/Repo' ? 5n : 6n) });
  assert.equal(await probeCaseInsensitive('/Work/Repo', { platform: 'linux', fs: different }), false);
  const missing = wrapFs({
    stat: async (p) => {
      if (p === '/Work/Repo') return st(5n);
      throw errno('ENOENT');
    },
  });
  assert.equal(await probeCaseInsensitive('/Work/Repo', { platform: 'linux', fs: missing }), false);
  assert.equal(await probeCaseInsensitive('/', { platform: 'linux', fs: same }), false, 'no letters: nothing to swap');
  assert.equal(await probeCaseInsensitive('C:\\Work', { platform: 'win32' }), true);
});

// ---- POSIX: ancestors + executables ----------------------------------------------------

test('posix: assertTrustedAncestors - chain bounded at stopAt; group/other-writable or symlinked component refused', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const mid = join(base, 'mid');
  const bin = join(mid, 'bin');
  await mkdir(bin, { recursive: true });
  const exe = join(bin, 'tool');
  await writeFile(exe, '#!/bin/sh\n', { mode: 0o755 });
  const d = posixDeps();
  await assertTrustedAncestors(exe, { stopAt: base }, d);
  await chmod(mid, 0o775);
  await rejectsWith(assertTrustedAncestors(exe, { stopAt: base }, d), 'CHAIN', /writable by someone other/);
  await assertTrustedAncestors(exe, { stopAt: base, groupWritableOk: async () => true }, d);
  await chmod(mid, 0o777);
  await rejectsWith(assertTrustedAncestors(exe, { stopAt: base, groupWritableOk: async () => true }, d), 'CHAIN');
  await chmod(mid, 0o755);
  await rm(bin, { recursive: true });
  await symlink(mid, join(base, 'alias'));
  await mkdir(join(mid, 'bin'));
  await writeFile(join(mid, 'bin', 'tool'), 'x', { mode: 0o755 });
  await rejectsWith(assertTrustedAncestors(join(base, 'alias', 'bin', 'tool'), { stopAt: base }, d), 'CHAIN', /not a real directory/);
  await rm(base, { recursive: true, force: true });
});

test('posix: assertTrustedAncestors with no uid trusts root only (fail-closed)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  await writeFile(join(base, 'tool'), 'x', { mode: 0o755 });
  if (UID === 0) return;
  await rejectsWith(assertTrustedAncestors(join(base, 'tool'), { stopAt: base }, posixDeps({ getuid: () => undefined })), 'CHAIN');
  await rm(base, { recursive: true, force: true });
});

test('posix: resolveTrustedExecutable - first trusted wins, relative/empty dropped, g+w diagnosed but never accepted (T7)', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  const good = join(base, 'bin', 'git');
  await mkdir(join(base, 'bin'));
  await writeFile(good, 'x', { mode: 0o755 });
  const gw = join(base, 'gbin', 'git');
  await mkdir(join(base, 'gbin'));
  await writeFile(gw, 'x', { mode: 0o755 });
  await chmod(join(base, 'gbin'), 0o775);
  const d = posixDeps();
  const cands = ['', 'git', './git', 'relative/git', join(base, 'nope', 'git'), gw, good];
  const info = await resolveTrustedExecutable(cands, { stopAt: base }, d);
  assert.equal(info.path, await (await import('node:fs/promises')).realpath(good).then(() => good));
  assert.deepEqual(info.dropped, ['', 'git', './git', 'relative/git']);
  assert.equal(info.rejected.length, 1);
  assert.match(info.rejected[0] ?? '', /gbin\/git \(target directory is writable/);
  assert.equal(info.groupWritable, true, 'diagnosis only');
  const onlyBad = await resolveTrustedExecutable([gw], { stopAt: base }, d);
  assert.equal(onlyBad.path, null);
  assert.equal(onlyBad.foundUntrusted, true);
  const optIn = await resolveTrustedExecutable([gw], { stopAt: base, groupWritableOk: async () => true }, d);
  assert.equal(optIn.path, gw);
  // world-writable file
  await chmod(gw, 0o777);
  const ww = await resolveTrustedExecutable([gw], { stopAt: base, groupWritableOk: async () => true }, d);
  assert.equal(ww.path, null);
  await rm(base, { recursive: true, force: true });
});

test('posix: resolveTrustedExecutable follows a symlink only when BOTH chains are trusted', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  await mkdir(join(base, 'real'));
  await mkdir(join(base, 'links'));
  await writeFile(join(base, 'real', 'tool'), 'x', { mode: 0o755 });
  await symlink(join(base, 'real', 'tool'), join(base, 'links', 'tool'));
  const d = posixDeps();
  const ok = await resolveTrustedExecutable([join(base, 'links', 'tool')], { stopAt: base }, d);
  assert.ok(ok.path?.endsWith('/real/tool'));
  await chmod(join(base, 'links'), 0o777);
  const bad = await resolveTrustedExecutable([join(base, 'links', 'tool')], { stopAt: base }, d);
  assert.equal(bad.path, null);
  assert.match(bad.rejected[0] ?? '', /symlink directory/);
  await rm(base, { recursive: true, force: true });
});

test('isOwnedByMe (posix): own file true, missing false', { skip: NOT_POSIX }, async () => {
  const base = await sandbox();
  await writeFile(join(base, 'f'), 'x');
  assert.equal(await isOwnedByMe(join(base, 'f'), posixDeps()), true);
  assert.equal(await isOwnedByMe(join(base, 'nope'), posixDeps()), false);
  assert.equal(isStatOwnedByMe({ uid: UID }, posixDeps()), true);
  assert.equal(isStatOwnedByMe({ uid: UID + 1 }, posixDeps()), false);
  await rm(base, { recursive: true, force: true });
});

// =====================================================================================
// win32 backend through fakes (runs on any host: path.win32 + injected fs / spawnFile)
// =====================================================================================

const ME = 'S-1-5-21-1111111111-2222222222-3333333333-1001';
const GRP = 'S-1-5-21-1111111111-2222222222-3333333333-513';
const TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
const SYSROOT = 'C:\\Windows';
const PS_EXE = `${SYSROOT}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const ICACLS_EXE = `${SYSROOT}\\System32\\icacls.exe`;
const LA = 'C:\\Users\\me\\AppData\\Local';
const LEDGER = `${LA}\\agent-ledger`;

const C_ROOT =
  'O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;LC;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1200a9;;;WD)';
const C_USERS =
  'O:SYG:SYD:PAI(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;WD)';
const PROFILE = `O:${ME}G:${GRP}D:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`;
const APPDATA = `O:${ME}G:DUD:(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)`;
const PRIVATE_DIR = `O:${ME}G:${GRP}D:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)`;
const TOKEN_OK = `O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FA;;;SY)`;
const GIT_DIR = `O:${TI}G:SYD:PAI(A;;FA;;;${TI})(A;CIIO;GA;;;${TI})(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;CO)`;
const GIT_EXE = `O:${TI}G:${TI}D:PAI(A;;FA;;;${TI})(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)`;
const GIT = 'C:\\Program Files\\Git\\cmd\\git.exe';

interface Entry { type: 'dir' | 'file' | 'symlink'; ino: bigint; nlink?: number; entries?: string[] }

function winStat(e: Entry): StatLike {
  return {
    isSymbolicLink: () => e.type === 'symlink',
    isDirectory: () => e.type === 'dir',
    isFile: () => e.type === 'file',
    uid: 0, gid: 0, mode: 0o100666, nlink: e.nlink ?? 1, dev: 7n, ino: e.ino, ctimeNs: 1n,
  };
}

interface WinWorld {
  entries: Map<string, Entry>;
  sddl: Map<string, string>;
  info: Map<string, Partial<WinPathInfo>>;
  log: string[];
  spawns: { file: string; args: readonly string[]; env: Record<string, string> }[];
  next: bigint;
  sid: string;
  elevated: boolean;
  icaclsExit: number;
  /** What the directory looks like after icacls ran (default: the correct private DACL). */
  afterIcacls: string | null;
  entriesAfterMkdir: string[];
  openIno: bigint | null;
  fs: TrustFs;
  spawnFile: SpawnFile;
}

function winWorld(): WinWorld {
  const w: WinWorld = {
    entries: new Map(),
    sddl: new Map(),
    info: new Map(),
    log: [],
    spawns: [],
    next: 100n,
    sid: ME,
    elevated: false,
    icaclsExit: 0,
    afterIcacls: PRIVATE_DIR,
    entriesAfterMkdir: [],
    openIno: null,
    fs: undefined as unknown as TrustFs,
    spawnFile: undefined as unknown as SpawnFile,
  };
  const dir = (p: string, sddl: string): void => {
    w.entries.set(p, { type: 'dir', ino: w.next++ });
    w.sddl.set(p, sddl);
  };
  dir('C:\\', C_ROOT);
  dir('C:\\Users', C_USERS);
  dir('C:\\Users\\me', PROFILE);
  dir('C:\\Users\\me\\AppData', APPDATA);
  dir(LA, APPDATA);
  w.entries.set(PS_EXE, { type: 'file', ino: w.next++ });
  w.entries.set(ICACLS_EXE, { type: 'file', ino: w.next++ });
  const get = (p: string): Entry => {
    const e = w.entries.get(p);
    if (e === undefined) throw errno('ENOENT');
    return e;
  };
  w.fs = {
    lstat: async (p) => winStat(get(p)),
    stat: async (p) => winStat(get(p)),
    mkdir: async (p) => {
      if (w.entries.has(p)) throw errno('EEXIST');
      w.log.push(`mkdir ${p}`);
      w.entries.set(p, { type: 'dir', ino: w.next++, entries: [...w.entriesAfterMkdir] });
    },
    rmdir: async (p) => {
      w.log.push(`rmdir ${p}`);
      w.entries.delete(p);
    },
    rm: async (p) => {
      w.entries.delete(p);
    },
    open: async (p) => {
      w.log.push(`open ${p}`);
      const e = w.entries.get(p) ?? { type: 'file' as const, ino: w.next++ };
      w.entries.set(p, e);
      return {
        stat: async () => winStat({ ...e, ino: w.openIno ?? e.ino }),
        writeFile: async () => undefined,
        readText: async () => '',
        truncate: async () => undefined,
        chmod: async () => undefined,
        sync: async () => undefined,
        close: async () => {
          w.log.push(`close ${p}`);
        },
      };
    },
    link: async () => {
      throw errno('ENOTSUP');
    },
    readdir: async (p) => get(p).entries ?? [],
    realpath: async (p) => p,
    readText: async () => {
      throw errno('ENOENT');
    },
  };
  w.spawnFile = async (file, args, opts): Promise<SpawnResult> => {
    w.spawns.push({ file, args, env: opts.env });
    const ok = (stdout: string, code = 0): SpawnResult => ({ code, stdout, stderr: '', timedOut: false, truncated: false });
    if (file === ICACLS_EXE) {
      if (w.icaclsExit === 0 && w.afterIcacls !== null) w.sddl.set(args[0] ?? '', w.afterIcacls);
      return ok('', w.icaclsExit);
    }
    const paths = JSON.parse(opts.env.LEDGER_TRUST_PATHS ?? '[]') as string[];
    const out = paths.map((p) => {
      const e = w.entries.get(p);
      if (e === undefined) return { exists: false };
      const base: WinPathInfo = {
        exists: true,
        reparse: e.type === 'symlink',
        isDir: e.type === 'dir',
        sddl: w.sddl.get(p) ?? null,
        unc: false,
        driveFormat: 'NTFS',
        driveType: 'Fixed',
        error: null,
      };
      return { ...base, ...(w.info.get(p) ?? {}) };
    });
    return ok(JSON.stringify({ sid: w.sid, elevated: w.elevated, paths: out }));
  };
  return w;
}

function winDeps(w: WinWorld, env: Record<string, string | undefined> = { SystemRoot: SYSROOT }): Partial<TrustDeps> {
  return { platform: 'win32', fs: w.fs, spawnFile: w.spawnFile, env, getuid: () => undefined, now: () => 1_000_000, cache: new Map() };
}

test('win32: assertPrivateDir passes on the DACL ensurePrivateDir produces; one PowerShell call, paths only in env (never in the script)', async () => {
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  const caps = await assertPrivateDir(LEDGER, {}, winDeps(w));
  assert.equal(caps.weak, false);
  assert.equal(caps.acl, true);
  assert.equal(caps.fsType, 'NTFS');
  assert.equal(w.spawns.length, 1);
  const call = w.spawns[0]!;
  assert.equal(call.file, PS_EXE);
  assert.deepEqual(call.args, ['-NoProfile', '-NonInteractive', '-NoLogo', '-Command', WIN_PS_SCRIPT]);
  assert.deepEqual(JSON.parse(call.env.LEDGER_TRUST_PATHS ?? ''), [LEDGER, LA, 'C:\\Users\\me\\AppData', 'C:\\Users\\me', 'C:\\Users', 'C:\\']);
  assert.ok(!call.args.join(' ').includes('agent-ledger'), 'paths must not be interpolated into the command line');
  assert.equal(call.env.PSModulePath, `${SYSROOT}\\System32\\WindowsPowerShell\\v1.0\\Modules`);
  assert.equal(call.env.SystemRoot, SYSROOT);
});

test('win32: the fixed script reads its input from the env var and never builds a command from data', () => {
  assert.match(WIN_PS_SCRIPT, /\$env:LEDGER_TRUST_PATHS/);
  assert.doesNotMatch(WIN_PS_SCRIPT, /Invoke-Expression|iex\b|Start-Process|-Command|Add-Type/i);
  assert.match(WIN_PS_SCRIPT, /Get-Acl -LiteralPath/);
  assert.match(WIN_PS_SCRIPT, /Get-Item -LiteralPath/);
});

test('win32: malformed SystemRoot / missing powershell.exe => PROBE_FAILED and nothing is spawned (T7)', async () => {
  const bad = ['', undefined, 'C:Windows', 'Windows', 'C:\\Windows\\System32', 'C:\\', '\\\\evil\\share', 'C:\\Win*dows', 'C:\\Windows\r\n', 'C:\\a:b', '..\\Windows', 'C:\\Windows\\..'];
  for (const root of bad) {
    const w = winWorld();
    w.entries.set(LEDGER, { type: 'dir', ino: 9n });
    w.sddl.set(LEDGER, PRIVATE_DIR);
    await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w, { SystemRoot: root })), 'PROBE_FAILED', /SystemRoot/);
    assert.equal(w.spawns.length, 0, `no process may start for SystemRoot=${JSON.stringify(root)}`);
  }
  const w = winWorld();
  w.entries.delete(PS_EXE);
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w)), 'PROBE_FAILED', /powershell\.exe/);
  assert.equal(w.spawns.length, 0);
});

test('win32: powershell failure, timeout, oversize output and garbage output are all PROBE_FAILED (fail-closed)', async () => {
  const mk = (res: Partial<SpawnResult>) => {
    const w = winWorld();
    w.entries.set(LEDGER, { type: 'dir', ino: 9n });
    w.sddl.set(LEDGER, PRIVATE_DIR);
    const spawnFile: SpawnFile = async () => ({ code: 0, stdout: '', stderr: '', timedOut: false, truncated: false, ...res });
    return { ...winDeps(w), spawnFile };
  };
  const w0 = winWorld();
  w0.entries.set(LEDGER, { type: 'dir', ino: 9n });
  for (const res of [
    { code: 1 },
    { code: null, error: 'ENOENT' },
    { timedOut: true, code: null },
    { truncated: true },
    { stdout: 'not json' },
    { stdout: '{}' },
    { stdout: JSON.stringify({ sid: 'nope', elevated: false, paths: [] }) },
    { stdout: JSON.stringify({ sid: ME, elevated: false, paths: [{ exists: true }] }) },
    { stdout: JSON.stringify({ sid: ME, paths: [] }) },
  ] as Partial<SpawnResult>[]) {
    await rejectsWith(assertPrivateDir(LEDGER, {}, mk(res)), 'PROBE_FAILED');
  }
});

test('win32: a git.exe probe that times out is REJECTED with the real reason in the message (CI 43713437446: "trust probe failed" hid it)', async () => {
  const w = winWorld();
  w.entries.set(GIT, { type: 'file', ino: 12n });
  w.sddl.set(GIT, GIT_EXE);
  const spawnFile: SpawnFile = async () => ({ code: null, stdout: '', stderr: 'Windows PowerShell\r\n\u0000boom', timedOut: true, truncated: false });
  const info = await resolveTrustedExecutable([GIT], {}, { ...winDeps(w), spawnFile });
  assert.equal(info.path, null, 'fail-closed: no binary is trusted when the probe does not finish');
  assert.equal(info.rejected.length, 1);
  assert.match(info.rejected[0] ?? '', /windows trust probe failed: powershell timed out after 15000 ms \[stderr: Windows PowerShell boom\]/);
});

test('win32: UNC / device / relative paths are refused before any process runs', async () => {
  const w = winWorld();
  for (const p of ['\\\\server\\share\\x', '\\\\?\\C:\\x', '\\\\.\\C:\\x', 'relative\\x', 'C:x', 'C:\\bad*name']) {
    await rejectsWith(assertPrivateDir(p, {}, winDeps(w)), 'PROBE_FAILED');
  }
  assert.equal(w.spawns.length, 0);
});

test('win32: elevated is refused everywhere (T14)', async () => {
  const w = winWorld();
  w.elevated = true;
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  w.entries.set(`${LEDGER}\\token`, { type: 'file', ino: 11n });
  w.sddl.set(`${LEDGER}\\token`, TOKEN_OK);
  w.entries.set(GIT, { type: 'file', ino: 12n });
  w.sddl.set(GIT, GIT_EXE);
  const d = winDeps(w);
  const e1 = await rejectsWith(assertPrivateDir(LEDGER, {}, d), 'PERMS', /elevated/);
  assert.equal(e1.message, ELEVATED_MESSAGE);
  await rejectsWith(ensurePrivateDir(`${LA}\\new`, d), 'PERMS', /elevated/);
  await rejectsWith(assertPrivateFile(`${LEDGER}\\token`, { secret: true }, d), 'PERMS', /elevated/);
  await rejectsWith(openPrivate(`${LEDGER}\\token`, 'read', 0o600, d), 'PERMS', /elevated/);
  await rejectsWith(assertTrustedAncestors(LEDGER, {}, d), 'PERMS', /elevated/);
  await rejectsWith(resolveTrustedExecutable([GIT], {}, d), 'PERMS', /elevated/);
  await rejectsWith(isOwnedByMe(LEDGER, d), 'PERMS', /elevated/);
  await rejectsWith(probeFs(LEDGER, d), 'PERMS', /elevated/);
  assert.ok(!w.log.some((l) => l.startsWith('mkdir')), 'nothing may be created while elevated');
});

test('win32: junction (reparse point) is REPARSE, a symlink in lstat is SYMLINK (T2)', async () => {
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  w.info.set(LEDGER, { reparse: true });
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w)), 'REPARSE');
  w.entries.set(LEDGER, { type: 'symlink', ino: 9n });
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w)), 'SYMLINK');
  // a junction among the ancestors
  const w2 = winWorld();
  w2.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w2.sddl.set(LEDGER, PRIVATE_DIR);
  w2.info.set('C:\\Users\\me', { reparse: true });
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w2)), 'REPARSE', /ancestor/);
});

test('win32: DACL problems on the directory are ACL; ownership is OWNER (T1/T8)', async () => {
  const cases: [string, TrustCode][] = [
    [`O:${ME}G:DUD:AI(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;SY)`, 'ACL'], // inheriting, no P
    [`O:${ME}G:DUD:PAI(A;OICI;FA;;;${ME})(A;OICI;0x1301bf;;;AU)`, 'ACL'], // AU Modify
    [`O:${ME}G:DUD:PAI(A;OICI;FA;;;${ME})(A;OICI;GR;;;WD)`, 'ACL'], // Everyone read
    [`O:${ME}G:DU`, 'ACL'], // NULL DACL
    [`O:${ME}G:DUD:P(XA;;FA;;;WD;(@User.x==1))`, 'ACL'], // conditional
    [`O:BAG:BAD:PAI(A;OICI;FA;;;${ME})`, 'OWNER'],
    ['O:SYG:SYD:P(A;;FA;;;', 'ACL'], // unparseable
  ];
  for (const [sddl, code] of cases) {
    const w = winWorld();
    w.entries.set(LEDGER, { type: 'dir', ino: 9n });
    w.sddl.set(LEDGER, sddl);
    await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w)), code);
  }
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  w.info.set(LEDGER, { sddl: null, error: 'UnauthorizedAccessException' });
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w)), 'ACL');
});

test('win32: an untrusted writer on any ancestor is CHAIN', async () => {
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  w.sddl.set(LA, `O:${ME}G:DUD:(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;SY)(A;;0x1301bf;;;AU)`);
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w)), 'CHAIN', /can modify/);
  const w2 = winWorld();
  w2.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w2.sddl.set(LEDGER, PRIVATE_DIR);
  w2.sddl.set('C:\\Users\\me', `O:S-1-5-21-9-9-9-1500G:SYD:PAI(A;OICI;FA;;;SY)`);
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w2)), 'CHAIN', /owner/);
});

test('win32: non-NTFS / network volumes are weak: WEAK_FS, and only exactly "1" lets the ACL step be skipped (I5, T13)', async () => {
  for (const vol of [
    { driveFormat: 'exFAT', driveType: 'Removable' },
    { driveFormat: 'FAT32', driveType: 'Fixed' },
    { driveFormat: 'NTFS', driveType: 'Network' },
    { driveFormat: 'NTFS', driveType: 'Fixed', unc: true },
  ]) {
    const w = winWorld();
    w.entries.set(LEDGER, { type: 'dir', ino: 9n });
    w.info.set(LEDGER, { ...vol, sddl: null });
    const caps = await probeFs(LEDGER, winDeps(w));
    assert.equal(caps.weak, true);
    assert.equal(caps.bypassed, false);
    await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w)), 'WEAK_FS');
    for (const v of ['true', 'yes', '', '0', ' 1']) {
      await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w, { SystemRoot: SYSROOT, LEDGER_ALLOW_WEAK_FS: v })), 'WEAK_FS');
    }
    const ok = await assertPrivateDir(LEDGER, {}, winDeps(w, { SystemRoot: SYSROOT, LEDGER_ALLOW_WEAK_FS: '1' }));
    assert.equal(ok.bypassed, true);
    // never relaxed: reparse, symlink
    w.info.set(LEDGER, { ...vol, sddl: null, reparse: true });
    await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w, { SystemRoot: SYSROOT, LEDGER_ALLOW_WEAK_FS: '1' })), 'REPARSE');
  }
});

test('win32: ensurePrivateDir - ancestors, mkdir, exact icacls argv (SIDs, absolute exe), SDDL re-read, emptiness (T1/T8)', async () => {
  const w = winWorld();
  const caps = await ensurePrivateDir(LEDGER, winDeps(w));
  assert.equal(caps.weak, false);
  assert.deepEqual(w.log, [`mkdir ${LEDGER}`]);
  const ic = w.spawns.filter((s) => s.file === ICACLS_EXE);
  assert.equal(ic.length, 1);
  assert.deepEqual(ic[0]!.args, [LEDGER, '/inheritance:r', '/grant:r', `*${ME}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F']);
  assert.ok(w.spawns.filter((s) => s.file === PS_EXE).length >= 2, 'ancestors before, SDDL verification after');
  // existing dir: verify only - no mkdir, no icacls, never re-ACL somebody else's directory
  const w2 = winWorld();
  w2.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w2.sddl.set(LEDGER, `O:${ME}G:DUD:AI(A;OICIID;FA;;;${ME})`);
  await rejectsWith(ensurePrivateDir(LEDGER, winDeps(w2)), 'ACL');
  assert.deepEqual(w2.log, []);
  assert.equal(w2.spawns.filter((s) => s.file === ICACLS_EXE).length, 0);
});

test('win32: ensurePrivateDir creates missing intermediates one by one, each locked down', async () => {
  const w = winWorld();
  const leaf = `${LEDGER}\\spool`;
  w.afterIcacls = PRIVATE_DIR;
  await ensurePrivateDir(leaf, winDeps(w));
  assert.deepEqual(w.log, [`mkdir ${LEDGER}`, `mkdir ${leaf}`]);
  assert.equal(w.spawns.filter((s) => s.file === ICACLS_EXE).length, 2);
});

test('win32: C:\\ is refused as the direct parent of a new dir, before anything is created (T1)', async () => {
  const w = winWorld();
  await rejectsWith(ensurePrivateDir('C:\\ledger-test', winDeps(w)), 'CHAIN', /inherit/);
  assert.deepEqual(w.log, []);
  assert.equal(w.spawns.filter((s) => s.file === ICACLS_EXE).length, 0);
});

test('win32: ensurePrivateDir rolls back (rmdir) and refuses when icacls fails, the DACL is wrong, or the dir is not empty', async () => {
  const w1 = winWorld();
  w1.icaclsExit = 5;
  await rejectsWith(ensurePrivateDir(LEDGER, winDeps(w1)), 'PROBE_FAILED', /icacls/);
  assert.deepEqual(w1.log, [`mkdir ${LEDGER}`, `rmdir ${LEDGER}`]);
  assert.equal(w1.entries.has(LEDGER), false);

  const w2 = winWorld();
  w2.afterIcacls = `O:${ME}G:DUD:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;AU)`;
  await rejectsWith(ensurePrivateDir(LEDGER, winDeps(w2)), 'ACL');
  assert.deepEqual(w2.log, [`mkdir ${LEDGER}`, `rmdir ${LEDGER}`]);

  const w3 = winWorld();
  w3.entriesAfterMkdir = ['planted.txt'];
  await rejectsWith(ensurePrivateDir(LEDGER, winDeps(w3)), 'IDENTITY', /not empty/);
  assert.deepEqual(w3.log, [`mkdir ${LEDGER}`, `rmdir ${LEDGER}`]);

  // owner after creation is not us (inherited from an Administrators-owned creation context)
  const w4 = winWorld();
  w4.afterIcacls = `O:BAG:BAD:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)`;
  await rejectsWith(ensurePrivateDir(LEDGER, winDeps(w4)), 'OWNER');
  assert.deepEqual(w4.log, [`mkdir ${LEDGER}`, `rmdir ${LEDGER}`]);
});

test('win32: ensurePrivateDir refuses a symlink leaf/ancestor and a raced pre-existing dir', async () => {
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'symlink', ino: 9n });
  await rejectsWith(ensurePrivateDir(`${LEDGER}\\x`, winDeps(w)), 'SYMLINK');
  const w2 = winWorld();
  const raced: TrustFs = { ...w2.fs, mkdir: async () => { throw errno('EEXIST'); } };
  await rejectsWith(ensurePrivateDir(LEDGER, { ...winDeps(w2), fs: raced }), 'IDENTITY', /raced/);
});

test('win32: assertPrivateFile - secret ok; Everyone read => ACL (rotate); other-writable => ACL; nlink 2; reparse (T3)', async () => {
  const f = `${LEDGER}\\token`;
  const mk = (sddl: string, extra: Partial<Entry> = {}, info: Partial<WinPathInfo> = {}) => {
    const w = winWorld();
    w.entries.set(LEDGER, { type: 'dir', ino: 9n });
    w.sddl.set(LEDGER, PRIVATE_DIR);
    w.entries.set(f, { type: 'file', ino: 10n, ...extra });
    w.sddl.set(f, sddl);
    w.info.set(f, info);
    return winDeps(w);
  };
  await assertPrivateFile(f, { secret: true }, mk(TOKEN_OK));
  await rejectsWith(assertPrivateFile(f, { secret: true }, mk(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FR;;;WD)`)), 'ACL', /read access/);
  await rejectsWith(assertPrivateFile(f, { secret: true }, mk(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;0x1200a9;;;S-1-5-32-545)`)), 'ACL');
  await assertPrivateFile(f, {}, mk(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FR;;;WD)`)); // non-secret: reading is fine
  await rejectsWith(assertPrivateFile(f, {}, mk(`O:${ME}G:DUD:(A;ID;FA;;;${ME})(A;ID;FW;;;BU)`)), 'ACL', /write/);
  await rejectsWith(assertPrivateFile(f, { secret: true }, mk(TOKEN_OK, { nlink: 2 })), 'IDENTITY', /hard links/);
  await rejectsWith(assertPrivateFile(f, { secret: true }, mk(TOKEN_OK, {}, { reparse: true })), 'REPARSE');
  await rejectsWith(assertPrivateFile(f, { secret: true }, mk(TOKEN_OK, { type: 'symlink' })), 'SYMLINK');
  await rejectsWith(assertPrivateFile(f, { secret: true }, mk(`O:BAG:DUD:(A;ID;FA;;;${ME})`)), 'OWNER');
});

test('win32: openPrivate - dir verified (cached), identity compared across lstat/open/fstat/lstat (T2)', async () => {
  const f = `${LEDGER}\\log.jsonl`;
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  const d = winDeps(w);
  const h = await openPrivate(f, 'append', 0o600, d);
  await h.close();
  const psCalls = w.spawns.length;
  const h2 = await openPrivate(f, 'append', 0o600, d);
  await h2.close();
  assert.equal(w.spawns.length, psCalls, 'the verified directory is cached: no new PowerShell process per open');
  // swapped between open and the second lstat
  w.openIno = 4242n;
  await rejectsWith(openPrivate(f, 'append', 0o600, d), 'IDENTITY', /changed/);
  assert.ok(w.log.at(-1)?.startsWith('close'), 'the handle must be closed on refusal');
  w.openIno = null;
  // symlink at the target
  w.entries.set(f, { type: 'symlink', ino: 77n });
  await rejectsWith(openPrivate(f, 'read', 0o600, d), 'SYMLINK');
  // unverifiable dir => refuse before opening anything
  const w2 = winWorld();
  w2.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w2.sddl.set(LEDGER, `O:${ME}G:DUD:AI(A;OICIID;FA;;;${ME})`);
  await rejectsWith(openPrivate(f, 'append', 0o600, winDeps(w2)), 'ACL');
  assert.ok(!w2.log.some((l) => l.startsWith('open')));
});

test('win32: openPrivate refuses a stable-id-less file (ino 0) on an ACL volume', async () => {
  const f = `${LEDGER}\\x`;
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  w.entries.set(f, { type: 'file', ino: 0n });
  await rejectsWith(openPrivate(f, 'read', 0o600, winDeps(w)), 'IDENTITY', /file id/);
});

test('win32: directory cache is invalidated by a ctime change (T8: fixture without P refused after the ACL changed)', async () => {
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  const d = winDeps(w);
  await assertPrivateDir(LEDGER, {}, d);
  const n = w.spawns.length;
  await assertPrivateDir(LEDGER, {}, d);
  assert.equal(w.spawns.length, n);
  // ACL replaced (ctime moves): the stale approval must not be reused
  w.sddl.set(LEDGER, `O:${ME}G:DUD:AI(A;OICIID;FA;;;${ME})`);
  const e = w.entries.get(LEDGER)!;
  const orig = w.fs.lstat;
  const moved: TrustFs = { ...w.fs, lstat: async (p) => (p === LEDGER ? { ...(await orig(p)), ctimeNs: 2n } : orig(p)) };
  void e;
  await rejectsWith(assertPrivateDir(LEDGER, {}, { ...d, fs: moved }), 'ACL');
});

test('win32: assertTrustedAncestors - normal chain ok; newChild under C:\\ refused; executable kind accepts TrustedInstaller', async () => {
  const w = winWorld();
  await assertTrustedAncestors(`${LA}\\agent-ledger`, {}, winDeps(w));
  await assertTrustedAncestors('C:\\Users', {}, winDeps(w));
  await assertTrustedAncestors(`${LA}\\agent-ledger`, { newChild: true }, winDeps(w));
  await rejectsWith(assertTrustedAncestors('C:\\ledger', { newChild: true }, winDeps(w)), 'CHAIN', /inherit/);
  await assertTrustedAncestors('C:\\ledger', {}, winDeps(w)); // C:\ is fine as an ancestor
  w.entries.set('C:\\Program Files', { type: 'dir', ino: 50n });
  w.sddl.set('C:\\Program Files', GIT_DIR);
  w.entries.set('C:\\Program Files\\Git', { type: 'dir', ino: 51n });
  w.sddl.set('C:\\Program Files\\Git', GIT_DIR);
  w.entries.set('C:\\Program Files\\Git\\cmd', { type: 'dir', ino: 52n });
  w.sddl.set('C:\\Program Files\\Git\\cmd', GIT_DIR);
  await assertTrustedAncestors(GIT, { executable: true }, winDeps(w));
});

test('win32: resolveTrustedExecutable - Git under Program Files ok; relative/env-style/UNC dropped; write access / junction / owner refused (T7)', async () => {
  const w = winWorld();
  for (const p of ['C:\\Program Files', 'C:\\Program Files\\Git', 'C:\\Program Files\\Git\\cmd']) {
    w.entries.set(p, { type: 'dir', ino: w.next++ });
    w.sddl.set(p, GIT_DIR);
  }
  w.entries.set(GIT, { type: 'file', ino: w.next++ });
  w.sddl.set(GIT, GIT_EXE);
  const d = winDeps(w);
  const cands = ['', 'git.exe', '.\\git.exe', '%ProgramFiles%\\Git\\cmd\\git.exe', '\\\\server\\share\\git.exe', '/usr/bin/git', 'C:git.exe', GIT];
  const info = await resolveTrustedExecutable(cands, {}, d);
  assert.equal(info.path, GIT);
  assert.deepEqual(info.dropped, ['', 'git.exe', '.\\git.exe', '%ProgramFiles%\\Git\\cmd\\git.exe', '\\\\server\\share\\git.exe', '/usr/bin/git', 'C:git.exe']);

  w.sddl.set(GIT, `O:${TI}G:${TI}D:PAI(A;;FA;;;${TI})(A;;FW;;;BU)`);
  const writable = await resolveTrustedExecutable([GIT], {}, d);
  assert.equal(writable.path, null);
  assert.match(writable.rejected[0] ?? '', /write access/);
  assert.equal(writable.foundUntrusted, true);

  w.sddl.set(GIT, GIT_EXE);
  w.sddl.set('C:\\Program Files\\Git', `O:${TI}G:SYD:PAI(A;;FA;;;${TI})(A;;0x1301bf;;;BU)`);
  assert.equal((await resolveTrustedExecutable([GIT], {}, d)).path, null, 'a writable directory above the binary');

  w.sddl.set('C:\\Program Files\\Git', GIT_DIR);
  w.info.set(GIT, { reparse: true });
  assert.equal((await resolveTrustedExecutable([GIT], {}, d)).path, null);
  w.info.delete(GIT);
  w.entries.set(GIT, { type: 'symlink', ino: 9n });
  assert.equal((await resolveTrustedExecutable([GIT], {}, d)).path, null);
  w.entries.set(GIT, { type: 'file', ino: 9n });
  w.sddl.set(GIT, `O:S-1-5-21-9-9-9-1500G:SYD:PAI(A;;FA;;;SY)`);
  assert.equal((await resolveTrustedExecutable([GIT], {}, d)).path, null);
  w.sddl.set(GIT, GIT_EXE);
  w.info.set(GIT, { driveFormat: 'exFAT' });
  assert.equal((await resolveTrustedExecutable([GIT], {}, d)).path, null, 'bypass never applies to executables');
  assert.equal((await resolveTrustedExecutable([GIT], {}, winDeps(w, { SystemRoot: SYSROOT, LEDGER_ALLOW_WEAK_FS: '1' }))).path, null);
});

test('win32: probe failure while resolving an executable is a rejection, not a pass', async () => {
  const w = winWorld();
  w.entries.set(GIT, { type: 'file', ino: 9n });
  const failing: SpawnFile = async () => ({ code: 1, stdout: '', stderr: '', timedOut: false, truncated: false });
  const info = await resolveTrustedExecutable([GIT], {}, { ...winDeps(w), spawnFile: failing });
  assert.equal(info.path, null);
  assert.equal(info.foundUntrusted, true);
});

test('win32: isOwnedByMe compares the SDDL owner with our SID; isStatOwnedByMe never trusts a win32 stat', async () => {
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, PRIVATE_DIR);
  assert.equal(await isOwnedByMe(LEDGER, winDeps(w)), true);
  w.sddl.set(LEDGER, `O:BAG:BAD:PAI(A;OICI;FA;;;${ME})`);
  assert.equal(await isOwnedByMe(LEDGER, winDeps(w)), false);
  w.sddl.set(LEDGER, 'garbage');
  assert.equal(await isOwnedByMe(LEDGER, winDeps(w)), false);
  assert.equal(await isOwnedByMe(`${LA}\\missing`, winDeps(w)), false);
  assert.equal(isStatOwnedByMe({ uid: 0 }, winDeps(w)), false);
});

test('win32: weak-FS bypass flag set in the env of a strong NTFS volume changes nothing', async () => {
  const w = winWorld();
  w.entries.set(LEDGER, { type: 'dir', ino: 9n });
  w.sddl.set(LEDGER, `O:${ME}G:DUD:AI(A;OICIID;FA;;;${ME})`);
  await rejectsWith(assertPrivateDir(LEDGER, {}, winDeps(w, { SystemRoot: SYSROOT, LEDGER_ALLOW_WEAK_FS: '1' })), 'ACL');
});

// ---- real Windows (skipped elsewhere) ---------------------------------------------------

test('real win32: ensurePrivateDir yields a protected DACL for {me, SYSTEM}; C:\\ledger-test is refused', { skip: NOT_WIN32 }, async (t) => {
  const base = process.env.LOCALAPPDATA;
  if (base === undefined) return t.skip('LOCALAPPDATA not set');
  const dir = join(base, `agent-ledger-trust-test-${String(process.pid)}`);
  try {
    let caps;
    try {
      caps = await ensurePrivateDir(dir);
    } catch (err) {
      // GitHub-hosted runners run as an elevated Administrator: refusing is the specified behaviour.
      if (err instanceof TrustError && err.message === ELEVATED_MESSAGE) return t.skip('elevated session (refusal is the specified behaviour)');
      throw err;
    }
    assert.equal(caps.weak, false);
    await assertPrivateDir(dir);
    await rejectsWith(ensurePrivateDir('C:\\ledger-test'), 'CHAIN');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
