/** APPLY crash windows W0-W7 (docs/f3b-b3-plan.md §2, T-B3-3). Written FIRST: every crash point, FF and merge,
 *  is thrown through the `crashAt` seam, then a fresh process-like replay (fresh deps, fresh host) must leave
 *  tree(main) == tree(M), a clean worktree, no marker, a reindexed index, and no commit on top of L in between.
 *
 *  Also pins the three UNVERIFIED `read-tree` behaviours the replay relies on. */

import assert from 'node:assert/strict';
import { chmod, readFile, stat, utimes, writeFile, mkdir } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { journalLine, parseDevicesYaml, renderDevicesYaml } from '@agent-ledger/shared';
import { CrashError, applyRemote, replayGitPhase, replayInflight, sweepSyncTmp, type CrashPoint } from './apply.ts';
import { REF_MAIN } from './gitx.ts';
import { splitCommit } from './sigverify.ts';
import { StateStore } from './state.ts';
import { ObjectStore } from './objects.ts';
import { TreeBuilder } from './treebuild.ts';
import { fakeHost, flakyRemote, makeFleet, makeLedgerHub, type Fleet, type LedgerHub } from './testkit-remote.ts';
import { makeKit, type Kit } from './testkit-remote.ts';

const posix = process.platform !== 'win32';
const POINTS: CrashPoint[] = ['marker', 'read-tree', 'update-ref', 'reindex', 'notes', 'marker-delete'];

const JOURNAL = `# acme — journal 2026-11\n${journalLine({ at: '2026-11-01 10:00', session: 'remote', type: 'note', fields: ['from the other device'] })}\n`;
const DECISIONS = '# acme decisions\n';

async function withKit<T>(fn: (kit: Kit) => Promise<T>): Promise<T> {
  const kit = await makeKit();
  try {
    return await fn(kit);
  } finally {
    await kit.cleanup();
  }
}

interface Scene {
  fleet: Fleet;
  lh: LedgerHub;
  A: string;
  F: string;
  /** Local tip before the apply (merge scenes have a local commit on top of A). */
  L: string;
}

async function scene(kit: Kit, mode: 'ff' | 'merge', n = 2): Promise<Scene> {
  const fleet = await makeFleet(kit, n);
  const lh = fleet.hubs[0] as LedgerHub;
  const other = fleet.hubs[1] as LedgerHub;
  const F = await kit.remote.pushSigned(other.hub, [
    { path: 'acme/journal/2026-11.md', content: JOURNAL },
    { path: 'acme/CONTEXT.md', content: '# acme\nremote edit\n' },
  ]);
  await lh.hub.fetchIncoming(kit.remote);
  let L = fleet.base;
  if (mode === 'merge') L = await lh.commitLocal([{ path: 'acme/DECISIONS.md', content: DECISIONS }], { message: 'local work' });
  return { fleet, lh, A: fleet.base, F, L };
}

const read = (lh: LedgerHub, rel: string): Promise<string> => readFile(nodePath.join(lh.dir, ...rel.split('/')), 'utf8');
async function parents(lh: LedgerHub, sha: string): Promise<string[]> {
  return splitCommit(await lh.hub.store.readCommitRaw(sha)).headers?.parents ?? [];
}
async function treeOf(lh: LedgerHub, sha: string): Promise<string> {
  return (await lh.hub.gitx.mustRun(['rev-parse', `${sha}^{tree}`], { cwd: lh.dir })).stdout.toString('utf8').trim();
}
const plan = (s: Scene): { A: string; F: string; forcedMerge: boolean; tipDevice: string | null } => ({ A: s.A, F: s.F, forcedMerge: false, tipDevice: null });

for (const mode of ['ff', 'merge'] as const) {
  for (const point of POINTS) {
    test(`crash at ${point} (${mode}): replay completes the apply exactly once`, { skip: !posix }, async () => {
      await withKit(async (kit) => {
        const s = await scene(kit, mode);
        const { lh } = s;
        const host = fakeHost(lh);
        await assert.rejects(
          applyRemote(host, lh.applyDeps({ crashAt: (p) => { if (p === point) throw new CrashError(p); } }), plan(s)),
          (err: unknown) => err instanceof CrashError && err.point === point,
        );
        assert.deepEqual(host.violations, [], 'lock order respected up to the crash');

        // a fresh process: new state store, new deps, new host
        const state = await StateStore.open(lh.dir);
        const marker = await state.readInflight();
        if (point === 'marker-delete') assert.equal(marker, null, 'W7: nothing left to replay');
        else assert.notEqual(marker, null);
        const host2 = fakeHost(lh);
        const res = await replayInflight(host2, lh.applyDeps({ state }));
        assert.equal(res.kind, marker === null ? 'none' : 'completed');

        const main = (await lh.hub.main()) as string;
        if (mode === 'ff') assert.equal(main, s.F);
        else assert.deepEqual(await parents(lh, main), [s.L, s.F], 'remote parent kept, local parent first');
        if (marker !== null) {
          assert.equal(main, marker.M);
          assert.equal(await treeOf(lh, main), marker.treeM);
          assert.ok(host2.reindexed.some((p) => p.length > 0), 'index follows the files');
          assert.deepEqual(host2.reindexed[0]?.slice().sort(), marker.changed.slice().sort());
        }
        assert.equal(
          (await lh.hub.gitx.mustRun(['rev-list', '--count', `${s.L}..${main}`], { cwd: lh.dir })).stdout.toString().trim(),
          mode === 'ff' ? '1' : '2',
          'no commit was made on L in between (merge: F and M only)',
        );
        assert.deepEqual(await lh.dirty(), [], 'clean worktree and index');
        assert.equal(await state.readInflight(), null, 'marker deleted');
        assert.equal(await read(lh, 'acme/journal/2026-11.md'), JOURNAL);
        assert.equal(await read(lh, 'acme/CONTEXT.md'), '# acme\nremote edit\n');
        if (mode === 'merge') assert.equal(await read(lh, 'acme/DECISIONS.md'), DECISIONS);
        assert.deepEqual(host2.violations, []);
        assert.equal((await lh.hub.store.lsTree(main)).some((e) => e.path.startsWith('.hub')), false, 'never a .hub path in main');
      });
    });
  }
}

test('uninterrupted apply: FF and merge end clean, in R then Q order, with the notes delivered once', { skip: !posix }, async () => {
  for (const mode of ['ff', 'merge'] as const) {
    await withKit(async (kit) => {
      const s = await scene(kit, mode);
      const host = fakeHost(s.lh);
      const out = await applyRemote(host, s.lh.applyDeps(), plan(s));
      assert.equal(out.kind, 'applied');
      assert.deepEqual(host.violations, []);
      assert.equal(host.delivered.length, 1);
      assert.equal(host.reindexed.length, 1);
      assert.equal(await s.lh.state.readInflight(), null);
      assert.deepEqual(await s.lh.dirty(), []);
      const again = await applyRemote(host, s.lh.applyDeps(), plan(s));
      assert.equal(again.kind, 'noop', 'F is now an ancestor of main');
    });
  }
});

test('crash between update-ref and prune: replay reruns pruneRevokedSigners (audit: allowed_signers)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const fleet = await makeFleet(kit, 3);
    const lh = fleet.hubs[0] as LedgerHub;
    const victim = fleet.hubs[2] as LedgerHub;
    const allowed = nodePath.join(lh.dir, '.hub', 'allowed_signers');
    assert.ok((await readFile(allowed, 'utf8')).includes(victim.hub.deviceId), 'victim approved before');
    const parsed = parseDevicesYaml(fleet.devicesText);
    const revoked = renderDevicesYaml({
      devices: parsed.devices.map((d) => (d.id === victim.hub.deviceId ? { ...d, revoked: { at: '2026-11-02T00:00:00.000Z', by: lh.hub.deviceId, reason: 'lost' } } : d)),
    });
    const F = await kit.remote.pushSigned(lh.hub, [{ path: 'devices.yml', content: revoked }]);
    await lh.hub.fetchIncoming(kit.remote);
    const host = fakeHost(lh);
    await assert.rejects(
      applyRemote(host, lh.applyDeps({ crashAt: (p) => { if (p === 'update-ref') throw new CrashError(p); } }), { A: fleet.base, F, forcedMerge: false, tipDevice: null }),
      CrashError,
    );
    assert.ok((await readFile(allowed, 'utf8')).includes(victim.hub.deviceId), 'crash left the revoked key approved');
    const state = await StateStore.open(lh.dir);
    const res = await replayInflight(fakeHost(lh), lh.applyDeps({ state }));
    assert.equal(res.kind, 'completed');
    const after = await readFile(allowed, 'utf8');
    assert.equal(after.includes(victim.hub.deviceId), false, 'replay removed the revoked signer');
    assert.ok(after.includes(lh.hub.deviceId), 'prune only removes');
  });
});

test('W1: M is not in the object store -> roll back, marker cleared, nothing touched', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    const { lh } = s;
    const L = (await lh.hub.main()) as string;
    await lh.state.writeInflight({
      v: 1, id: 'abcdefgh12345678', createdAt: '2026-11-17T10:00:00.000Z', mode: 'merge',
      A: s.A, L, M: 'f'.repeat(40), F: 'e'.repeat(40), treeL: await treeOf(lh, L), treeM: 'd'.repeat(40),
      changed: ['acme/CONTEXT.md'], notes: { inbox: [], releaseLeases: [], proposed: [] }, stage: 'prepared',
    });
    const r = await replayGitPhase(lh.applyDeps());
    assert.equal(r.kind, 'rolled-back');
    assert.equal(await lh.state.readInflight(), null);
    assert.equal(await lh.hub.main(), L);
    assert.deepEqual(await lh.dirty(), []);
  });
});

test('foreign edit during replay halts `inflight`, touches nothing (edit on a changed path and outside it)', { skip: !posix }, async () => {
  for (const target of ['acme/journal/2026-11.md', 'acme/CONTEXT.md', 'unrelated.md']) {
    await withKit(async (kit) => {
      const s = await scene(kit, 'ff');
      const { lh } = s;
      const host = fakeHost(lh);
      await assert.rejects(applyRemote(host, lh.applyDeps({ crashAt: (p) => { if (p === 'marker') throw new CrashError(p); } }), plan(s)), CrashError);
      const abs = nodePath.join(lh.dir, ...target.split('/'));
      await mkdir(nodePath.dirname(abs), { recursive: true });
      await writeFile(abs, 'precious local edit\n');
      const r = await replayGitPhase(lh.applyDeps());
      assert.equal(r.kind, 'halt');
      if (r.kind === 'halt') assert.equal(r.reason, 'inflight');
      assert.equal(await readFile(abs, 'utf8'), 'precious local edit\n', 'the edit survives');
      assert.equal(await lh.hub.main(), s.L, 'main untouched');
      assert.notEqual(await lh.state.readInflight(), null, 'marker kept for a human');
    });
  }
});

test('main is neither L nor M -> halt inflight without mutation', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    const { lh } = s;
    await assert.rejects(applyRemote(fakeHost(lh), lh.applyDeps({ crashAt: (p) => { if (p === 'marker') throw new CrashError(p); } }), plan(s)), CrashError);
    const other = await lh.hub.commit([{ path: 'acme/x.md', content: 'x\n' }]); // main moved behind the marker's back
    const r = await replayGitPhase(lh.applyDeps());
    assert.equal(r.kind, 'halt');
    assert.equal(await lh.hub.main(), other);
  });
});

test('stale index.lock (>30 s) is removed, a young one is waited for then halts inflight', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    const { lh } = s;
    await assert.rejects(applyRemote(fakeHost(lh), lh.applyDeps({ crashAt: (p) => { if (p === 'marker') throw new CrashError(p); } }), plan(s)), CrashError);
    const lock = nodePath.join(lh.dir, '.git', 'index.lock');
    await writeFile(lock, '');
    const young = await replayGitPhase(lh.applyDeps({ timing: { indexLockWaitMs: 250, indexLockStaleMs: 30_000 } }));
    assert.equal(young.kind, 'halt');
    assert.ok((await stat(lock)).isFile(), 'a young lock is never removed');
    assert.equal(await lh.hub.main(), s.L);
    const old = new Date(Date.now() - 60_000);
    await utimes(lock, old, old);
    const r = await replayInflight(fakeHost(lh), lh.applyDeps());
    assert.equal(r.kind, 'completed');
    await assert.rejects(stat(lock), 'stale lock removed');
    assert.equal(await lh.hub.main(), s.F);
  });
});

test('a held device lock aborts BEFORE any mutation (transient device-lock)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    const lockPath = nodePath.join(s.lh.dir, '.hub', 'device.lock');
    await writeFile(lockPath, `${process.pid} ${Date.now()} deadbeefdeadbeef\n`, { mode: 0o600 });
    const out = await applyRemote(fakeHost(s.lh), s.lh.applyDeps({ timing: { lockWaitMs: 150 } }), plan(s));
    assert.deepEqual(out, { kind: 'transient', why: 'device-lock' });
    assert.equal(await s.lh.state.readInflight(), null, 'no marker without the lock');
    assert.equal(await s.lh.hub.main(), s.L);
    assert.deepEqual(await s.lh.dirty(), []);
  });
});

test('dirty worktree: transient dirty, nothing touched, no marker', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    await writeFile(nodePath.join(s.lh.dir, 'acme', 'scratch.md'), 'uncommitted\n');
    const host = fakeHost(s.lh);
    host.commitOutcome = 'clean'; // the host says clean; the apply still checks the real tree
    const out = await applyRemote(host, s.lh.applyDeps(), plan(s));
    assert.deepEqual(out, { kind: 'transient', why: 'dirty' });
    assert.equal(await s.lh.state.readInflight(), null);
    assert.equal(await s.lh.hub.main(), s.L);
  });
});

test('commitNow answering held/deferred/inflight/error -> transient local-hold, nothing touched', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    for (const oc of ['held', 'deferred', 'inflight', 'error'] as const) {
      const host = fakeHost(s.lh);
      host.commitOutcome = oc;
      assert.deepEqual(await applyRemote(host, s.lh.applyDeps(), plan(s)), { kind: 'transient', why: 'local-hold' });
    }
    assert.equal(await s.lh.hub.main(), s.L);
  });
});

test('merge of unrelated histories quarantines `unrelated`; nothing applied', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'merge');
    const rewritten = await kit.remote.rewriteHistory((s.fleet.hubs[1] as LedgerHub).hub, [{ path: 'acme/CONTEXT.md', content: '# other\n' }]);
    await s.lh.hub.fetchIncoming(kit.remote);
    const out = await applyRemote(fakeHost(s.lh), s.lh.applyDeps(), { A: s.A, F: rewritten, forcedMerge: false, tipDevice: null });
    assert.deepEqual(out, { kind: 'quarantine', rule: 'unrelated' });
    assert.equal(await s.lh.state.readInflight(), null);
    assert.equal(await s.lh.hub.main(), s.L);
  });
});

test('sweepSyncTmp removes only old scratch dirs (W0)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const lh = await makeLedgerHub(kit, 1);
    const tmp = nodePath.join(lh.dir, '.hub', 'sync', 'tmp');
    await mkdir(nodePath.join(tmp, 'old'), { recursive: true, mode: 0o700 });
    await mkdir(nodePath.join(tmp, 'fresh'), { recursive: true, mode: 0o700 });
    const past = new Date(Date.now() - 3_600_000);
    await utimes(nodePath.join(tmp, 'old'), past, past);
    assert.equal(await sweepSyncTmp(lh.dir), 1);
    await assert.rejects(stat(nodePath.join(tmp, 'old')));
    assert.ok((await stat(nodePath.join(tmp, 'fresh'))).isDirectory());
  });
});

/* ---------------- pins: the UNVERIFIED git behaviours the replay relies on ---------------- */

test('PIN 1: `read-tree -m -u L M` verifies every path before touching any', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    const { lh } = s;
    // M adds acme/journal/2026-11.md and edits acme/CONTEXT.md; an UNTRACKED file blocks the add
    await mkdir(nodePath.join(lh.dir, 'acme', 'journal'), { recursive: true });
    await writeFile(nodePath.join(lh.dir, 'acme', 'journal', '2026-11.md'), 'mine\n');
    const r = await lh.hub.gitx.run(['read-tree', '-m', '-u', s.L, s.F], { cwd: lh.dir });
    assert.equal(r.ok, false, 'git refuses to overwrite the untracked file');
    assert.equal(await read(lh, 'acme/CONTEXT.md'), '# acme\n', 'the other path was NOT updated first');
    assert.equal(await read(lh, 'acme/journal/2026-11.md'), 'mine\n');
    const idx = await lh.hub.gitx.run(['diff-index', '--cached', '--quiet', s.L, '--'], { cwd: lh.dir });
    assert.equal(idx.code, 0, 'index still equals L');
  });
});

test('PIN 2: `read-tree --reset -u M` is a hard reset for tracked paths', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    const { lh } = s;
    await writeFile(nodePath.join(lh.dir, 'acme', 'CONTEXT.md'), 'locally edited\n');
    const r = await lh.hub.gitx.run(['read-tree', '--reset', '-u', s.F], { cwd: lh.dir });
    assert.equal(r.ok, true);
    assert.equal(await read(lh, 'acme/CONTEXT.md'), '# acme\nremote edit\n');
    assert.equal(await read(lh, 'acme/journal/2026-11.md'), JOURNAL);
    assert.equal((await lh.hub.gitx.run(['diff-index', '--cached', '--quiet', s.F, '--'], { cwd: lh.dir })).code, 0, 'index = M');
  });
});

test('PIN 3: an existing index.lock makes read-tree fail (replay waits for it); a KILLED read-tree leaving one is UNVERIFIED', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'ff');
    const { lh } = s;
    await writeFile(nodePath.join(lh.dir, '.git', 'index.lock'), '');
    await chmod(nodePath.join(lh.dir, '.git', 'index.lock'), 0o600);
    const r = await lh.hub.gitx.run(['read-tree', '-m', '-u', s.L, s.F], { cwd: lh.dir });
    assert.equal(r.ok, false);
    assert.equal(await lh.hub.main(), s.L);
    assert.equal(await read(lh, 'acme/CONTEXT.md'), '# acme\n', 'nothing was written');
  });
});

test('apply never moves main before read-tree and never uses a forbidden git option (argv audit)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const s = await scene(kit, 'merge');
    const f = flakyRemote(s.lh.hub.gitx);
    const dir = s.lh.dir;
    const out = await applyRemote(
      fakeHost(s.lh),
      s.lh.applyDeps({ gitx: f.gitx, store: new ObjectStore(f.gitx, dir), trees: new TreeBuilder(f.gitx, dir, nodePath.join(s.lh.hub.syncDir, 'tmp')) }),
      plan(s),
    );
    assert.equal(out.kind, 'applied');
    const seq = f.argv.map((a) => a[0]);
    assert.ok(seq.indexOf('read-tree') !== -1 && seq.indexOf('update-ref') > seq.lastIndexOf('read-tree'), 'read-tree precedes update-ref');
    for (const a of f.argv.flat()) {
      assert.ok(!/^--force|^-f$|^\+refs\/heads/.test(a), `no force flag (${a})`);
    }
    assert.equal(f.argv.filter((a) => a[0] === 'update-ref').every((a) => a.length >= 5), true, 'update-ref always carries the expected old value');
    void REF_MAIN;
  });
});
