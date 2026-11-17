/** Two REAL ledgers (Ledger + LedgerGit signing + SyncLoop wired like `startHub`) and one bare remote
 *  (docs/f3b-b3-plan.md §6, T-B3-3/4/5/11). Slow on purpose: this is the end-to-end of B3. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import test from 'node:test';
import { addDevice, approveDevice, adoptSlot, deviceLayout, initDevice, readDevices } from '@agent-ledger/shared';
import { Ledger } from '../ledger/ledger.ts';
import type { RuntimeStore } from '../db/store.ts';
import { tempConfig } from '../test-helpers.ts';
import { replayGitPhase } from './apply.ts';
import { Gitx, REF_ACCEPTED, REF_MAIN } from './gitx.ts';
import { SyncLoop } from './loop.ts';
import { ObjectStore } from './objects.ts';
import { StateStore } from './state.ts';
import { TreeBuilder } from './treebuild.ts';
import { bootReplayGit, bootReplayNotes, startSync } from './wire.ts';
import { makeKit, type Kit } from './testkit-remote.ts';

const posix = process.platform !== 'win32';
const FAKE_STORE = { addInbox: () => 'x', releaseLeases: () => 0 } as unknown as RuntimeStore;
const base = { kind: 'BACKLOG', priority: 'P2', owner: 'agent', steps: [] as string[], blocked_by: [] as string[], aliases: [] as string[], proposed: false };

interface Node {
  ledger: Ledger;
  dir: string;
  gitx: Gitx;
  loop: SyncLoop;
  logs: string[];
  deviceId: string;
  close(): Promise<void>;
}

interface World {
  kit: Kit;
  a: Node;
  b: Node;
  base: string;
  cleanup(): Promise<void>;
}

const git = async (gitx: Gitx, dir: string, args: string[]): Promise<string> => (await gitx.mustRun(args, { cwd: dir })).stdout.toString('utf8').trim();

async function bringUp(kit: Kit, dir: string, role: 'a' | 'b', remote: string, seed: string): Promise<Node> {
  const logs: string[] = [];
  const tmp = await tempConfig({ sync: true, ledgerDir: dir, commitDebounceMs: 3_600_000 });
  const ledger = new Ledger({ config: tmp.config, log: (l) => logs.push(l) });
  await ledger.init();
  await writeFile(nodePath.join(dir, '.hub', 'sync.yml'), `v: 1\nremote: ${remote}\n`, { mode: 0o600 });
  const gitx = await Gitx.open({ syncDir: nodePath.join(dir, '.hub', 'sync'), testLocalRemotes: [remote] });
  const trees = new TreeBuilder(gitx, dir, nodePath.join(dir, '.hub', 'sync', 'tmp'));
  await trees.createRef(REF_ACCEPTED, seed);
  const state = await StateStore.open(dir);
  await state.update((s) => {
    s.accepted = seed;
  });
  const loop = await startSync({ ledger, store: FAKE_STORE, config: tmp.config, log: (l) => logs.push(`${role}: ${l}`), start: false, testLocalRemotes: [remote] });
  assert.notEqual(loop, null, `sync enabled for ${role}: ${logs.join(' | ')}`);
  void kit;
  return { ledger, dir, gitx, loop: loop as SyncLoop, logs, deviceId: ledger.device.device_id, close: async () => { await loop?.stop(); await ledger.close().catch(() => undefined); await tmp.cleanup(); } };
}

async function world(): Promise<World> {
  const kit = await makeKit();
  const rootTmp = await realpath(await mkdtemp(nodePath.join(await realpath(tmpdir()), 'agl-int-')));
  await chmod(rootTmp, 0o700);
  const remote = kit.remote.path;
  const dirA = nodePath.join(rootTmp, 'a');
  const dirB = nodePath.join(rootTmp, 'b');
  await mkdir(dirA, { mode: 0o700 });
  // ---- A: the root (TOFU), key + devices.yml first so every commit is signed from the very first one
  await initDevice(dirA, { root: true, label: 'a' });
  const tmpA0 = await tempConfig({ sync: true, ledgerDir: dirA, commitDebounceMs: 3_600_000 });
  const l0 = new Ledger({ config: tmpA0.config, log: () => undefined });
  await l0.init();
  await l0.git.flush();
  await l0.close();
  await tmpA0.cleanup();
  const gitxA = await Gitx.open({ syncDir: nodePath.join(dirA, '.hub', 'sync'), testLocalRemotes: [remote] });
  const c0 = await git(gitxA, dirA, ['rev-parse', REF_MAIN]);
  const pushed = await gitxA.push(dirA, remote, c0);
  assert.equal(pushed.ok, true, 'base pushed');
  // ---- B: init + fetch of the base (AL-52: no `clone`), its own key
  await rm(dirB, { recursive: true, force: true });
  await mkdir(dirB, { mode: 0o700 });
  const gitxB0 = await Gitx.open({ syncDir: nodePath.join(rootTmp, 'b-clone-sync'), testLocalRemotes: [remote] });
  await gitxB0.initRepo(dirB);
  assert.equal((await gitxB0.fetch(dirB, remote)).ok, true);
  const f0 = await git(gitxB0, dirB, ['rev-parse', '--verify', 'refs/ledger-sync/incoming']);
  await git(gitxB0, dirB, ['update-ref', REF_MAIN, f0, '0'.repeat(40)]);
  await git(gitxB0, dirB, ['read-tree', '--reset', '-u', REF_MAIN]);
  const gitxB = await Gitx.open({ syncDir: nodePath.join(dirB, '.hub', 'sync'), testLocalRemotes: [remote] });
  const initB = await initDevice(dirB, { label: 'b' });
  const pubB = (await readFile(deviceLayout(dirB).pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
  // ---- A registers and approves B (trusted side of enrolment), commits it signed, pushes
  await addDevice(dirA, pubB, 'b', initB.fingerprint);
  await approveDevice(dirA, initB.deviceId, initB.fingerprint);
  const tmpA1 = await tempConfig({ sync: true, ledgerDir: dirA, commitDebounceMs: 3_600_000 });
  const lA = new Ledger({ config: tmpA1.config, log: () => undefined });
  await lA.init();
  lA.git.touch('devices');
  await lA.git.flush();
  await lA.close();
  await tmpA1.cleanup();
  const c1 = await git(gitxA, dirA, ['rev-parse', REF_MAIN]);
  assert.notEqual(c1, c0, 'devices.yml committed');
  assert.equal((await gitxA.push(dirA, remote, c1)).ok, true);
  // ---- B takes the registered slot and approves A
  await gitxB.fetch(dirB, remote);
  await git(gitxB, dirB, ['update-ref', '--no-deref', REF_MAIN, c1, c0]);
  await git(gitxB, dirB, ['read-tree', '--reset', '-u', c1]);
  await adoptSlot(dirB);
  const aPub = (await readDevices(deviceLayout(dirA)))?.devices[0];
  assert.ok(aPub);
  await approveDevice(dirB, aPub.id, (await import('@agent-ledger/shared')).parseEd25519Pub(aPub.pubkey)?.fingerprint as string);
  const a = await bringUp(kit, dirA, 'a', remote, c1);
  const b = await bringUp(kit, dirB, 'b', remote, c1);
  return {
    kit,
    a,
    b,
    base: c1,
    async cleanup() {
      await a.close().catch(() => undefined);
      await b.close().catch(() => undefined);
      await kit.cleanup();
      await rm(rootTmp, { recursive: true, force: true }).catch(() => undefined);
    },
  };
}

async function settle(loop: SyncLoop): Promise<void> {
  loop.trigger('manual');
  for (let i = 0; i < 600; i += 1) {
    await new Promise((r) => setTimeout(r, 25));
    const s = await loop.status();
    if (!s.running && !s.pending) return;
  }
  throw new Error('loop did not settle');
}

const titles = (n: Node): string[] => n.ledger.listItems().map((i) => i.fm.title).sort();

test('two real ledgers: concurrent createItem on both sides converges, no item lost, ids distinct', { skip: !posix }, async () => {
  const w = await world();
  try {
    await Promise.all([
      ...[1, 2, 3].map((i) => w.a.ledger.createItem({ ...base, repo: 'ops', title: `from a ${String(i)}` })),
      ...[1, 2, 3].map((i) => w.b.ledger.createItem({ ...base, repo: 'ops', title: `from b ${String(i)}` })),
    ]);
    await settle(w.a.loop); // commits A's items (signed), pushes
    await settle(w.b.loop); // commits B's, fetches A's, MERGES, pushes
    await settle(w.a.loop); // fetches the merge, FF
    const want = ['from a 1', 'from a 2', 'from a 3', 'from b 1', 'from b 2', 'from b 3'];
    for (const n of [w.a, w.b]) {
      const have = titles(n).filter((t) => t.startsWith('from '));
      assert.deepEqual(have, want, `every item present (${n.logs.filter((l) => /sync|halt/i.test(l)).join(' | ')})`);
      assert.equal(new Set(n.ledger.listItems().map((i) => i.fm.id)).size, n.ledger.listItems().length, 'unique ids');
      const s = await n.loop.status();
      assert.equal(s.halt, null);
    }
    const remoteMain = await git(w.a.gitx, w.a.dir, ['ls-remote', '--', w.kit.remote.path]).catch(() => '');
    void remoteMain;
    const mainA = await git(w.a.gitx, w.a.dir, ['rev-parse', REF_MAIN]);
    const mainB = await git(w.b.gitx, w.b.dir, ['rev-parse', REF_MAIN]);
    assert.equal(mainA, mainB, 'same tip');
    assert.equal(mainA, await w.kit.remote.main());
    for (const n of [w.a, w.b]) {
      const dirty = (await n.gitx.mustRun(['status', '--porcelain=v1', '-z', '--untracked-files=all'], { cwd: n.dir })).stdout.toString('utf8');
      assert.equal(dirty, '', 'clean worktree');
      await assert.rejects(stat(nodePath.join(n.dir, '.hub', 'sync', 'inflight.json')), 'no marker left');
    }
  } finally {
    await w.cleanup();
  }
});

test('revokeDevice in a CHILD PROCESS racing the apply never loses the revocation and never half-applies', { skip: !posix }, async () => {
  const w = await world();
  try {
    await w.b.ledger.createItem({ ...base, repo: 'ops', title: 'from b racing' });
    await settle(w.b.loop); // B pushes a signed commit that A will apply
    const shared = nodePath.resolve(import.meta.dirname, '..', '..', '..', 'shared', 'src', 'index.ts');
    const script = `import { revokeDevice } from ${JSON.stringify(shared)};
      await new Promise((r) => setTimeout(r, ${String(Math.floor(Math.random() * 120))}));
      try { await revokeDevice(${JSON.stringify(w.a.dir)}, ${JSON.stringify(w.b.deviceId)}, 'lost phone'); process.stdout.write('revoked'); } catch (e) { process.stdout.write('refused:' + (e && e.code)); }`;
    const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d: Buffer) => { out += d.toString(); });
    const exit = new Promise<number | null>((r) => child.on('close', r));
    await settle(w.a.loop);
    assert.equal(await exit, 0);
    assert.equal(out, 'revoked', 'the child revoked B');
    // whatever order they ran in: the registry on disk says B is revoked, and the apply left no marker behind
    const devs = await readDevices(deviceLayout(w.a.dir));
    assert.notEqual(devs?.devices.find((d) => d.id === w.b.deviceId)?.revoked ?? null, null, 'revocation not lost');
    await settle(w.a.loop); // a second tick settles whatever the race postponed
    await assert.rejects(stat(nodePath.join(w.a.dir, '.hub', 'sync', 'inflight.json')), 'no half-applied marker');
    const signers = await readFile(deviceLayout(w.a.dir).allowedSigners, 'utf8');
    assert.equal(signers.includes(w.b.deviceId), false, 'a revoked key never stays in allowed_signers');
  } finally {
    await w.cleanup();
  }
});

test('LEDGER_SYNC=0: no loop, no network contact, no sync dir; but a crashed apply is still replayed before init', { skip: !posix }, async () => {
  const w = await world();
  try {
    // 1. sync off -> startSync is a no-op
    const off = await tempConfig({ sync: false, ledgerDir: w.a.dir });
    const none = await startSync({ ledger: w.a.ledger, store: FAKE_STORE, config: off.config, log: () => undefined, start: true });
    assert.equal(none, null);
    await off.cleanup();
    // 2. a crash in the middle of an apply (marker + main == L) is replayed by the boot phase with sync OFF
    await w.b.ledger.createItem({ ...base, repo: 'ops', title: 'remote item' });
    await settle(w.b.loop);
    const F = await w.kit.remote.main();
    assert.ok(F !== null);
    await w.a.gitx.fetch(w.a.dir, w.kit.remote.path);
    const { CrashError, applyRemote } = await import('./apply.ts');
    const deps = {
      ledgerDir: w.a.dir,
      gitx: w.a.gitx,
      store: new ObjectStore(w.a.gitx, w.a.dir),
      trees: new TreeBuilder(w.a.gitx, w.a.dir, nodePath.join(w.a.dir, '.hub', 'sync', 'tmp')),
      state: await StateStore.open(w.a.dir),
      identity: { name: 'a', email: `${w.a.deviceId}@devices.agent-ledger.invalid` },
      signing: { sshKeygenBin: await (await import('@agent-ledger/shared')).resolveSshKeygen(), keyFile: deviceLayout(w.a.dir).keyFile, allowedSignersFile: deviceLayout(w.a.dir).allowedSigners },
      localDevice: w.a.deviceId,
      maxFormat: 2,
      crashAt: (p: string) => { if (p === 'read-tree') throw new CrashError(p as 'read-tree'); },
    };
    const host = {
      runExclusive: (fn: (x: { commitNow(): Promise<'clean'> }) => Promise<never>) => fn({ commitNow: async () => 'clean' as const }),
      queueRun: <T>(fn: () => Promise<T>) => fn(),
      reindexPaths: async () => undefined,
      deliver: async () => undefined,
      log: () => undefined,
    };
    let crashed = false;
    let out: unknown = null;
    try {
      out = await applyRemote(host as never, deps as never, { A: w.base, F: F as string, forcedMerge: false, tipDevice: null });
    } catch (err) {
      crashed = err instanceof CrashError;
    }
    assert.equal(crashed, true, `the apply must reach read-tree (got ${JSON.stringify(out)})`);
    const marker = await deps.state.readInflight();
    assert.notEqual(marker, null);
    await w.a.close(); // the "process" dies
    const cfg = await tempConfig({ sync: false, ledgerDir: w.a.dir });
    const ledger2 = new Ledger({ config: cfg.config, log: () => undefined }); // constructed, NOT initialised
    const boot = await bootReplayGit(ledger2, () => undefined);
    assert.equal(boot.result?.kind, 'forward', 'replayed before init, with LEDGER_SYNC=0');
    await bootReplayNotes(boot, FAKE_STORE, () => undefined);
    await assert.rejects(stat(nodePath.join(w.a.dir, '.hub', 'sync', 'inflight.json')), 'marker cleared');
    const store = new ObjectStore(w.a.gitx, w.a.dir);
    assert.equal(await store.revParse(REF_MAIN), marker?.M);
    await ledger2.init();
    assert.ok(ledger2.listItems().some((i) => i.fm.title === 'remote item'), 'the boot reindex sees the applied remote work');
    await ledger2.close();
    await cfg.cleanup();
    void replayGitPhase;
  } finally {
    await w.cleanup();
  }
});
