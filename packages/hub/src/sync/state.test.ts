/** F3b B3a: durable sync state. Atomic writes, fail-closed corruption, strict schema, list caps,
 *  the grow-only ratchet, backoff bounds, inflight marker path validation, `sync.yml`. */

import assert from 'node:assert/strict';
import { lstat, mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, truncate, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import test from 'node:test';
import {
  MAX_INFLIGHT_PATHS,
  MAX_NOTED,
  StateError,
  StateStore,
  confirmationKey,
  emptyState,
  clearEnrolMarker,
  nextBackoff,
  readEnrolMarker,
  readSyncConfig,
  writeEnrolMarker,
  writeSyncConfig,
  type EnrolMarker,
  type HaltState,
  type Inflight,
  type SyncState,
} from './state.ts';

const posix = process.platform !== 'win32';
const A = 'a'.repeat(40);
const B = 'b'.repeat(40);
const C = 'c'.repeat(40);
const D = 'd'.repeat(40);
const E = 'e'.repeat(40);
const DEV1 = 'd_abcdefgh23';
const DEV2 = 'd_zzzzzzzz22';
const NOW = '2026-11-17T10:00:00.000Z';
const FP = `SHA256:${'A'.repeat(43)}`;

async function withDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(nodePath.join(tmpdir(), 'ledger-state-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const isState = (code: string) => (e: unknown): boolean => e instanceof StateError && e.code === code;
const syncDir = (dir: string): string => nodePath.join(dir, '.hub', 'sync');

function halt(over: Partial<HaltState> = {}): HaltState {
  return { reason: 'auth', cls: 'no-contact', since: NOW, tip: null, rule: null, detail: 'authentication failed', d2: null, ...over };
}

function marker(over: Partial<Inflight> = {}): Inflight {
  return {
    v: 1, id: 'abcdef0123456789', createdAt: NOW, mode: 'merge',
    A, L: B, M: C, F: D, treeL: E, treeM: A,
    changed: ['acme/items/ACME-1.md', 'devices.yml'],
    notes: { inbox: [], releaseLeases: [], proposed: [] },
    stage: 'prepared',
    ...over,
  };
}

test('open creates a private sync dir; an absent file reads as the empty state', { skip: !posix }, async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    assert.equal((await stat(syncDir(dir))).mode & 0o777, 0o700);
    assert.deepEqual(await store.read(), emptyState());
    assert.equal(store.inflightPath, nodePath.join(syncDir(dir), 'inflight.json'));
    assert.equal(await store.readInflight(), null);
    assert.deepEqual(await readdir(syncDir(dir)), [], 'reading creates nothing');
  });
});

test('update: atomic durable write (0600, no tmp left), round trip, returns what was written', { skip: !posix }, async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    const out = await store.update((s) => {
      s.accepted = A;
      s.halt = halt({ tip: B });
      s.seenSigning.push(DEV1);
    });
    assert.equal(out.accepted, A);
    const again = await (await StateStore.open(dir)).read();
    assert.deepEqual(again, out);
    assert.equal((await stat(store.statePath)).mode & 0o777, 0o600);
    assert.deepEqual(await readdir(syncDir(dir)), ['state.json']);
    // returning a fresh object is allowed too
    const next = await store.update((s) => ({ ...s, accepted: B }));
    assert.equal(next.accepted, B);
  });
});

test('concurrent updates are serialised (no lost update) and a failing update never breaks the chain', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    const jobs: Promise<unknown>[] = [];
    for (let i = 0; i < 25; i++) jobs.push(store.update((s) => { s.backoff.failures += 1; }));
    jobs.push(store.update(() => { throw new Error('boom'); }).catch(() => 'swallowed'));
    for (let i = 0; i < 5; i++) jobs.push(store.update((s) => { s.backoff.failures += 1; }));
    await Promise.all(jobs);
    assert.equal((await store.read()).backoff.failures, 30);
  });
});

test('corrupt state fails closed: read and update THROW CORRUPT, the file is not replaced', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    await store.update((s) => { s.accepted = A; });
    const good = await readFile(store.statePath, 'utf8');
    const bad = [
      '', '{', 'null', '[]', '{"v":2}', good.slice(0, good.length >> 1),
      good.replace('"v":1', '"v":1,"extra":true'), // strict: unknown key
      good.replace(A, 'zz'), // not a sha
      good.replace('"failures":0', '"failures":-1'),
      JSON.stringify({ ...emptyState(), halt: halt({ cls: 'local' }) }), // class does not follow from the reason
      JSON.stringify({ ...emptyState(), halt: halt({ detail: 'a\nb' }) }), // control char in detail
      JSON.stringify({ ...emptyState(), halt: halt({ reason: 'quarantine:revocation-root', cls: 'd2', d2: null }) }),
      JSON.stringify({ ...emptyState(), halt: halt({ d2: { commit: A, deviceIds: [DEV1], kind: 'root' } }) }), // d2 on a non-d2 reason
      JSON.stringify({ ...emptyState(), seenSigning: ['x'] }),
      JSON.stringify({ ...emptyState(), confirmations: [{ kind: 'root', device_id: DEV1, commit: A, fp: 'nope', at: NOW }] }),
      JSON.stringify({ ...emptyState(), halt: halt({ reason: 'quarantine:Bad Token' as never, cls: 'probe' }) }),
    ];
    for (const text of bad) {
      await writeFile(store.statePath, text, { mode: 0o600 });
      await assert.rejects(store.read(), isState('CORRUPT'), text.slice(0, 50));
      await assert.rejects(store.update((s) => { s.accepted = B; }), isState('CORRUPT'));
      assert.equal(await readFile(store.statePath, 'utf8'), text, 'never overwritten');
    }
    // too large
    await writeFile(store.statePath, '{"v":1}', { mode: 0o600 });
    await truncate(store.statePath, 600 * 1024);
    await assert.rejects(store.read(), isState('CORRUPT'));
  });
});

test('a symlinked or non-regular state file is refused (UNSAFE) and never followed', { skip: !posix }, async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    const victim = nodePath.join(dir, 'victim');
    await writeFile(victim, JSON.stringify(emptyState()));
    await symlink(victim, store.statePath);
    await assert.rejects(store.read(), isState('UNSAFE'));
    await assert.rejects(store.update((s) => { s.accepted = A; }), isState('UNSAFE'));
    assert.equal(await readFile(victim, 'utf8'), JSON.stringify(emptyState()), 'target untouched');
    await rm(store.statePath);
    await mkdir(store.statePath);
    await assert.rejects(store.read(), isState('UNSAFE'));
  });
});

test('update refuses an invalid result (INVALID) and writes nothing', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    await store.update((s) => { s.accepted = A; });
    const before = await readFile(store.statePath, 'utf8');
    const attempts: ((s: SyncState) => void)[] = [
      (s) => { s.accepted = 'nope'; },
      (s) => { s.halt = halt({ reason: 'auth', cls: 'probe' }); },
      (s) => { s.halt = halt({ detail: 'x'.repeat(201) }); },
      (s) => { s.backoff.failures = 1.5; },
      (s) => { (s as unknown as Record<string, unknown>).secret = 'x'; },
    ];
    for (const a of attempts) {
      await assert.rejects(store.update(a), isState('INVALID'));
      assert.equal(await readFile(store.statePath, 'utf8'), before);
    }
  });
});

test('list caps keep the NEWEST entries (noted 200, overrides 16, confirmations 64)', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    const out = await store.update((s) => {
      for (let i = 0; i < 250; i++) s.noted.push({ key: `k${String(i)}`, at: NOW });
      for (let i = 0; i < 20; i++) s.overrides.push({ tip: A, at: NOW, ...(i === 19 ? { secretAck: true } : {}) });
      for (let i = 0; i < 70; i++) s.confirmations.push({ kind: 'root', device_id: DEV1, commit: A, fp: FP, at: `2026-11-17T10:00:${String(i % 60).padStart(2, '0')}.${String(i).padStart(3, '0')}Z` });
    });
    assert.equal(out.noted.length, MAX_NOTED);
    assert.equal(out.noted[0]?.key, 'k50');
    assert.equal(out.noted[199]?.key, 'k249');
    assert.equal(out.overrides.length, 16);
    assert.equal(out.overrides[15]?.secretAck, true);
    assert.equal(out.confirmations.length, 64);
    assert.deepEqual(await store.read(), out);
  });
});

test('seenSigning only grows: dropping an id is refused (INVARIANT), adding is fine, order is free', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    await store.update((s) => { s.seenSigning = [DEV1, DEV2]; });
    await assert.rejects(store.update((s) => { s.seenSigning = [DEV1]; }), isState('INVARIANT'));
    await assert.rejects(store.update((s) => { s.seenSigning = []; }), isState('INVARIANT'));
    await assert.rejects(store.update((s) => ({ ...emptyState(), accepted: A, seenSigning: s.seenSigning.slice(1) })), isState('INVARIANT'));
    assert.deepEqual((await store.read()).seenSigning, [DEV1, DEV2]);
    const out = await store.update((s) => { s.seenSigning = [DEV2, DEV1, 'd_abcdefgh24']; });
    assert.equal(out.seenSigning.length, 3);
  });
});

test('nextBackoff: 30 s doubling, 15 min cap, +-20 % jitter, junk-safe', () => {
  assert.equal(nextBackoff(1, () => 0.5), 30_000);
  assert.equal(nextBackoff(2, () => 0.5), 60_000);
  assert.equal(nextBackoff(3, () => 0.5), 120_000);
  assert.equal(nextBackoff(1, () => 0), 24_000);
  assert.equal(nextBackoff(1, () => 1), 36_000);
  let prev = 0;
  for (let f = 1; f <= 12; f++) {
    const mid = nextBackoff(f, () => 0.5);
    assert.ok(mid >= prev && mid <= 900_000, `f=${String(f)} ${String(mid)}`);
    prev = mid;
  }
  for (const f of [10, 50, 1e9, Number.POSITIVE_INFINITY]) {
    for (const r of [0, 0.25, 0.999]) {
      const v = nextBackoff(f, () => r);
      assert.ok(v >= 720_000 && v <= 1_080_000, `f=${String(f)} r=${String(r)} -> ${String(v)}`);
    }
  }
  for (let i = 0; i < 200; i++) {
    const v = nextBackoff(4);
    assert.ok(v >= 192_000 && v <= 288_000, String(v));
  }
  for (const f of [0, -3, Number.NaN, 1.9]) assert.ok(nextBackoff(f, () => 0.5) === 30_000, String(f));
  for (const r of [Number.NaN, -1, 7, Number.POSITIVE_INFINITY]) {
    const v = nextBackoff(1, () => r);
    assert.ok(v >= 24_000 && v <= 36_000, `rnd ${String(r)} -> ${String(v)}`);
  }
});

test('confirmationKey binds (commit, device id) and refuses malformed parts', () => {
  assert.equal(confirmationKey(A, DEV1), `${A}:${DEV1}`);
  assert.notEqual(confirmationKey(A, DEV1), confirmationKey(B, DEV1));
  assert.notEqual(confirmationKey(A, DEV1), confirmationKey(A, DEV2));
  for (const [c, d] of [['', DEV1], [A, ''], ['zz', DEV1], [A, 'd_bad'], [`${A}:x`, DEV1], [A, `${DEV1}:y`], [5, DEV1], [A, null]] as [unknown, unknown][]) {
    assert.throws(() => confirmationKey(c as string, d as string), isState('INVALID'));
  }
});

test('inflight marker: durable round trip, idempotent clear, validated before write and after read', { skip: !posix }, async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    await store.writeInflight(marker());
    assert.equal((await stat(store.inflightPath)).mode & 0o777, 0o600);
    assert.deepEqual(await store.readInflight(), marker());
    await store.writeInflight(marker({ stage: 'ref-moved', mode: 'ff', M: D }));
    assert.equal((await store.readInflight())?.stage, 'ref-moved');
    assert.deepEqual((await readdir(syncDir(dir))).sort(), ['inflight.json']);
    await store.clearInflight();
    await store.clearInflight();
    assert.equal(await store.readInflight(), null);
    // corrupt marker is evidence, never ignored
    await writeFile(store.inflightPath, '{"v":1', { mode: 0o600 });
    await assert.rejects(store.readInflight(), isState('CORRUPT'));
    await assert.rejects(store.writeInflight(marker({ L: 'x' })), isState('INVALID'));
  });
});

test('inflight marker: every changed path must be a plain ledger path (assertTreePath)', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    const bad = ['../x', '/abs', 'a/../b', '.hub/device/key', '.HUB/x', '.git/config', 'a\\b', 'a//b', 'a/', '', 'x\u0000y', 'GIT~1/x', 'a/.git ', 'a/./b'];
    for (const p of bad) {
      await assert.rejects(store.writeInflight(marker({ changed: ['ok.md', p] })), isState('INVALID'), JSON.stringify(p));
      await writeFile(store.inflightPath, JSON.stringify(marker({ changed: [p] })), { mode: 0o600 });
      await assert.rejects(store.readInflight(), isState('CORRUPT'), JSON.stringify(p));
    }
    await rm(store.inflightPath, { force: true });
    await store.writeInflight(marker({ changed: Array.from({ length: MAX_INFLIGHT_PATHS }, (_, i) => `acme/items/ACME-${String(i + 1)}.md`) }));
    assert.equal((await store.readInflight())?.changed.length, MAX_INFLIGHT_PATHS);
    await assert.rejects(store.writeInflight(marker({ changed: Array.from({ length: MAX_INFLIGHT_PATHS + 1 }, (_, i) => `a/${String(i)}.md`) })), isState('INVALID'));
  });
});

test('inflight marker: mode and shas must fit (FF: M==F; merge: M!=F; L!=M); unknown keys refused', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    const bad: Partial<Inflight>[] = [
      { mode: 'ff', M: C, F: D }, // ff but M != F
      { mode: 'merge', M: D, F: D }, // merge but M == F
      { L: C, M: C },
      { A: 'nope' },
      { stage: 'done' as never },
      { mode: 'rebase' as never },
      { id: 'short' },
      { notes: { inbox: Array.from({ length: 21 }, () => ({ to_session: 's', repo: null, item_id: null, body: 'x', origin: 'hub' as const })), releaseLeases: [], proposed: [] } },
      { notes: { inbox: [{ to_session: 's', repo: 'Bad Slug', item_id: null, body: 'x', origin: 'hub' }], releaseLeases: [], proposed: [] } },
      { notes: { inbox: [{ to_session: 's', repo: null, item_id: null, body: 'x\u0000y', origin: 'hub' }], releaseLeases: [], proposed: [] } },
      { extra: 1 } as never,
    ];
    for (const over of bad) await assert.rejects(store.writeInflight(marker(over)), isState('INVALID'), JSON.stringify(over).slice(0, 60));
    await store.writeInflight(marker({ mode: 'ff', M: D, F: D }));
    const ok = marker({
      notes: {
        inbox: [{ to_session: 'sess-1', repo: 'acme', item_id: 'ACME-1', body: 'line one\nline two', origin: 'hub' }],
        releaseLeases: [{ item: 'ACME-1', session: 'sess-1' }],
        proposed: [{ title: 'follow up' }],
      },
    });
    await store.writeInflight(ok);
    assert.deepEqual(await store.readInflight(), ok);
  });
});

test('stale tmp leftovers of a crashed write are swept at open; fresh ones and other names stay', { skip: !posix }, async () => {
  await withDir(async (dir) => {
    await StateStore.open(dir);
    const sd = syncDir(dir);
    const old = new Date(Date.now() - 3_600_000);
    const stale = nodePath.join(sd, 'state.json.123.0123456789ab.tmp');
    const fresh = nodePath.join(sd, 'inflight.json.123.0123456789ab.tmp');
    const other = nodePath.join(sd, 'known_hosts');
    for (const p of [stale, fresh, other]) await writeFile(p, 'x', { mode: 0o600 });
    for (const p of [stale, other]) await utimes(p, old, old);
    await StateStore.open(dir);
    assert.deepEqual((await readdir(sd)).sort(), ['inflight.json.123.0123456789ab.tmp', 'known_hosts']);
  });
});

test('readSyncConfig: absent = null; strict schema, <= 4 KB, no YAML aliases, hostile remotes refused', async () => {
  await withDir(async (dir) => {
    assert.equal(await readSyncConfig(dir), null);
    const file = nodePath.join(dir, '.hub', 'sync.yml');
    await mkdir(nodePath.dirname(file), { recursive: true, mode: 0o700 });
    const put = (t: string): Promise<void> => writeFile(file, t, { mode: 0o600 });
    await put('v: 1\nremote: ssh://git@example.invalid/owner/ledger.git\n');
    assert.deepEqual(await readSyncConfig(dir), { v: 1, remote: 'ssh://git@example.invalid/owner/ledger.git' });
    const bad = [
      '', 'remote: x\n', 'v: 2\nremote: ssh://h/p\n', 'v: 1\n', 'v: 1\nremote: 5\n',
      'v: 1\nremote: ssh://h/p\nextra: 1\n',
      'v: 1\nremote: -oProxyCommand=evil\n',
      'v: 1\nremote: "ssh://h/p with space"\n',
      'v: 1\nremote: "ssh://h/p\\u0000x"\n',
      'v: 1\nremote: ""\n',
      'v: 1\nremote: &a ssh://h/p\nx: *a\n',
      '- a\n- b\n', 'null\n', '{{{',
      `v: 1\nremote: ssh://h/${'a'.repeat(5000)}\n`,
      `v: 1\nremote: ssh://h/${'a'.repeat(1100)}\n`,
    ];
    for (const t of bad) {
      await put(t);
      await assert.rejects(readSyncConfig(dir), isState('CORRUPT'), t.slice(0, 40));
    }
  });
});

test('seenSigning past its cap evicts the OLDEST ids (never throws, never silently empties); other shrinks stay refused', async () => {
  await withDir(async (dir) => {
    const store = await StateStore.open(dir);
    const b32 = 'abcdefghijklmnopqrstuvwxyz234567';
    const id = (i: number): string => `d_${b32[Math.floor(i / 32)] as string}${b32[i % 32] as string}aaaaaaaa`;
    const full = Array.from({ length: 64 }, (_, i) => id(i));
    await store.update((s) => { s.seenSigning = full; });
    const out = await store.update((s) => { s.seenSigning = [...s.seenSigning, id(100), id(101)]; });
    assert.equal(out.seenSigning.length, 64);
    assert.deepEqual(out.seenSigning.slice(-2), [id(100), id(101)], 'newest kept');
    assert.equal(out.seenSigning.includes(id(0)), false, 'oldest evicted');
    assert.deepEqual(await store.read(), out);
    await assert.rejects(store.update((s) => { s.seenSigning = s.seenSigning.slice(1); }), isState('INVARIANT'), 'an explicit shrink below the cap is still refused');
  });
});

/* ---------------- B4a: writeSyncConfig, enrol marker ---------------- */

const REMOTE = 'ssh://git@example.invalid/owner/ledger.git';

test('writeSyncConfig: atomic private write that readSyncConfig reads back; the file replaces, never follows, a symlink', async () => {
  await withDir(async (dir) => {
    await writeSyncConfig(dir, REMOTE);
    assert.deepEqual(await readSyncConfig(dir), { v: 1, remote: REMOTE });
    const file = nodePath.join(dir, '.hub', 'sync.yml');
    if (posix) assert.equal((await stat(file)).mode & 0o777, 0o600);
    await writeSyncConfig(dir, 'git@host.example:o/r.git');
    assert.deepEqual(await readSyncConfig(dir), { v: 1, remote: 'git@host.example:o/r.git' });
    assert.deepEqual((await readdir(nodePath.join(dir, '.hub'))).filter((n) => n.endsWith('.tmp')), [], 'no tmp leftovers');
    if (posix) {
      const victim = nodePath.join(dir, 'victim.txt');
      await writeFile(victim, 'keep');
      await rm(file);
      await symlink(victim, file);
      await writeSyncConfig(dir, REMOTE);
      assert.equal(await readFile(victim, 'utf8'), 'keep', 'the symlink target is untouched');
      assert.ok(!(await lstat(file)).isSymbolicLink());
      assert.deepEqual(await readSyncConfig(dir), { v: 1, remote: REMOTE });
    }
  });
});

test('writeSyncConfig: re-validates the remote (ssh/scp only, no credentials, no option injection) and never echoes it', async () => {
  await withDir(async (dir) => {
    const hostile = [
      'https://host.example/o/r.git', 'file:///etc/passwd', 'ext::sh -c id', '-oProxyCommand=evil', 'ssh://-oProxyCommand=x/r',
      'ssh://user:secret-pw@host.example/o/r.git', 'user:secret-pw@host.example:o/r.git', 'relative/path', '/abs/local/path', '',
      'ssh://h/p with space', 'ssh://h/p\nv: 2', `ssh://h/${'a'.repeat(600)}`,
    ];
    for (const u of hostile) {
      await assert.rejects(writeSyncConfig(dir, u), (e: unknown) => {
        assert.ok(e instanceof StateError && e.code === 'INVALID', u.slice(0, 30));
        assert.ok(!e.message.includes('secret-pw') && !e.message.includes('example'), 'message carries no URL');
        return true;
      });
    }
    await assert.rejects(writeSyncConfig(dir, 5 as unknown as string), isState('INVALID'));
    await assert.rejects(stat(nodePath.join(dir, '.hub', 'sync.yml')), { code: 'ENOENT' }, 'nothing written on refusal');
    // the test seam is explicit and exact, never ambient
    await assert.rejects(writeSyncConfig(dir, '/abs/local/path'), isState('INVALID'));
    await writeSyncConfig(dir, '/abs/local/path', { testLocalRemotes: ['/abs/local/path'] });
  });
});

function enrol(over: Partial<EnrolMarker> = {}): EnrolMarker {
  return { v: 1, kind: 'init', stage: 'start', pid: process.pid, startedAt: new Date().toISOString(), remote: REMOTE, ...over };
}
const alive = (v: boolean) => ({ pidAlive: () => v });

test('enrol marker: absent = null; written private; stage advance by the same pid and kind; read back strictly', async () => {
  await withDir(async (dir) => {
    assert.equal(await readEnrolMarker(dir), null);
    const m = enrol();
    await writeEnrolMarker(dir, m);
    assert.deepEqual(await readEnrolMarker(dir), m);
    const file = nodePath.join(syncDir(dir), 'enrol.json');
    if (posix) assert.equal((await stat(file)).mode & 0o777, 0o600);
    await writeEnrolMarker(dir, { ...m, stage: 'committed' });
    assert.equal((await readEnrolMarker(dir))?.stage, 'committed');
    const j = enrol({ kind: 'join', pid: 4_000_001, stage: 'awaiting-add', F0: A });
    await clearEnrolMarker(dir);
    await writeEnrolMarker(dir, j);
    assert.deepEqual(await readEnrolMarker(dir), j);
    assert.deepEqual((await readdir(syncDir(dir))).filter((n) => n.includes('.tmp') || n.includes('.stale')), []);
  });
});

test('enrol marker: invalid input is refused before anything touches the disk; invalid files are CORRUPT (fail closed)', async () => {
  await withDir(async (dir) => {
    const bad: unknown[] = [
      enrol({ kind: 'x' as 'init' }), enrol({ stage: 'Bad Stage' }), enrol({ stage: '' }), enrol({ pid: 0 }), enrol({ pid: 1.5 }),
      enrol({ pid: -3 }), enrol({ startedAt: 'yesterday' }), enrol({ remote: '' }), enrol({ remote: 'a b' }), enrol({ remote: '-oProxyCommand=x' }),
      enrol({ remote: `ssh://h/${'a'.repeat(1100)}` }), enrol({ F0: 'xyz' }), { ...enrol(), extra: 1 }, { ...enrol(), v: 2 }, null, 'x',
    ];
    for (const b of bad) await assert.rejects(writeEnrolMarker(dir, b as EnrolMarker), isState('INVALID'));
    assert.equal(await readEnrolMarker(dir), null);
    await writeEnrolMarker(dir, enrol());
    const file = nodePath.join(syncDir(dir), 'enrol.json');
    const put = (t: string): Promise<void> => writeFile(file, t, { mode: 0o600 });
    for (const t of ['', '{', 'null', '[]', JSON.stringify({ ...enrol(), extra: 1 }), JSON.stringify({ ...enrol(), pid: 'x' }), `{"v":1,"pad":"${'a'.repeat(5000)}"}`]) {
      await put(t);
      await assert.rejects(readEnrolMarker(dir), isState('CORRUPT'), t.slice(0, 30));
      await assert.rejects(writeEnrolMarker(dir, enrol({ pid: 4_000_002 })), isState('CORRUPT'), 'a corrupt marker is never overwritten silently');
    }
    // the human --abort can still remove it
    await clearEnrolMarker(dir, { force: true });
    assert.equal(await readEnrolMarker(dir), null);
  });
});

test('enrol marker: a live foreign owner is BUSY (no URL in the message); a dead pid or a > 24 h marker is taken over', async () => {
  await withDir(async (dir) => {
    const other = enrol({ pid: 4_000_003, kind: 'join', stage: 'awaiting-add', F0: B });
    await writeEnrolMarker(dir, other);
    await assert.rejects(writeEnrolMarker(dir, enrol(), alive(true)), (e: unknown) => {
      assert.ok(e instanceof StateError && e.code === 'BUSY');
      assert.ok(!e.message.includes('example'));
      return true;
    });
    assert.deepEqual(await readEnrolMarker(dir), other, 'the live marker is untouched');
    // same pid, other kind, owner alive: not an "advance"
    await assert.rejects(writeEnrolMarker(dir, enrol({ pid: 4_000_003, kind: 'init' }), alive(true)), isState('BUSY'));
    // dead owner
    await writeEnrolMarker(dir, enrol(), alive(false));
    assert.equal((await readEnrolMarker(dir))?.pid, process.pid);
    assert.deepEqual((await readdir(syncDir(dir))).filter((n) => n.includes('.stale')), [], 'no stale leftovers');
    // alive owner but old: pid reuse must not wedge enrolment (distance, in both directions: clocks jump)
    const t0 = Date.parse('2026-11-17T10:00:00.000Z');
    for (const skew of [25 * 3_600_000, -25 * 3_600_000]) {
      await clearEnrolMarker(dir, { force: true });
      await writeEnrolMarker(dir, enrol({ pid: 4_000_004, startedAt: new Date(t0).toISOString() }));
      await assert.rejects(writeEnrolMarker(dir, enrol(), { ...alive(true), now: () => t0 + 23 * 3_600_000 }), isState('BUSY'));
      await writeEnrolMarker(dir, enrol(), { ...alive(true), now: () => t0 + skew });
      assert.equal((await readEnrolMarker(dir))?.pid, process.pid);
    }
  });
});

test('enrol marker: creation is exclusive: of two racing creators exactly one wins', async () => {
  await withDir(async (dir) => {
    await StateStore.open(dir);
    const results = await Promise.allSettled([
      writeEnrolMarker(dir, enrol({ pid: 4_000_005 }), alive(true)),
      writeEnrolMarker(dir, enrol({ pid: 4_000_006 }), alive(true)),
      writeEnrolMarker(dir, enrol({ pid: 4_000_007 }), alive(true)),
    ]);
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    for (const r of results) if (r.status === 'rejected') assert.ok(r.reason instanceof StateError && r.reason.code === 'BUSY');
    const m = await readEnrolMarker(dir);
    assert.ok(m !== null && [4_000_005, 4_000_006, 4_000_007].includes(m.pid));
  });
});

test('enrol marker: clear = no-op without a marker, allowed for the owner / a dead owner, BUSY for a live foreign one; a symlink is UNSAFE', async () => {
  await withDir(async (dir) => {
    await clearEnrolMarker(dir);
    await writeEnrolMarker(dir, enrol());
    await clearEnrolMarker(dir);
    assert.equal(await readEnrolMarker(dir), null);
    await writeEnrolMarker(dir, enrol({ pid: 4_000_008 }));
    await assert.rejects(clearEnrolMarker(dir, alive(true)), isState('BUSY'));
    assert.equal((await readEnrolMarker(dir))?.pid, 4_000_008);
    await clearEnrolMarker(dir, alive(false));
    assert.equal(await readEnrolMarker(dir), null);
    if (posix) {
      const file = nodePath.join(syncDir(dir), 'enrol.json');
      const victim = nodePath.join(dir, 'victim.json');
      await writeFile(victim, JSON.stringify(enrol()), { mode: 0o600 });
      await symlink(victim, file);
      await assert.rejects(readEnrolMarker(dir), isState('UNSAFE'));
      await assert.rejects(writeEnrolMarker(dir, enrol()), isState('UNSAFE'));
      await clearEnrolMarker(dir, { force: true });
      assert.equal(await readFile(victim, 'utf8') !== '', true, 'force removes the link, never the target');
    }
  });
});
