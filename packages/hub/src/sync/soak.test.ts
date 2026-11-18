/** Randomised soak of the whole sync stack (F3b B6, docs/f3b-b6-plan.md "soak.test.ts"; test-only).
 *
 *  Three REAL ledgers (A root, B, C: Ledger + LedgerGit signing + SyncLoop wired like `startHub`) share one bare
 *  remote. A seeded PRNG drives honest operations only (create/mutate items, journal events, local commits,
 *  cycles - also concurrent ones - network faults, simulated process death at every APPLY crash point, device
 *  adds). No deletes and no hostile commits. After the last op faults go off, the nodes cycle until they are
 *  quiet and then ten invariants are checked.
 *
 *  Reproduce:  SOAK_SEED=<n> [SOAK_ITERATIONS=<n>] node --test packages/hub/src/sync/soak.test.ts
 *  The seed is ALWAYS printed (diagnostic at the start and in every failure message, with the last 30 ops).
 *  Env: SOAK_SEED (default random), SOAK_ITERATIONS (default 30), SOAK_BUDGET_MS (default 20000: stops op
 *  generation early on a slow machine). POSIX-gated like every real-git sync test; LEDGER_TEST_SYNC_WIN32=1 lifts it.
 *
 *  Known soft spots this test is meant to poke (reported, not fixed here): a crash + restart (ledger.close() after
 *  a CrashError inside the queue may hang, notes may be replayed twice, addDeviceSynced crashAt('pushed') restart),
 *  createItem concurrent with an APPLY, honest 3-way adds producing devices-conflict. */

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import test from 'node:test';
import {
  addDevice,
  adoptSlot,
  approveDevice,
  deviceLayout,
  generateKeyPair,
  initDevice,
  publicKeyOf,
  readDevices,
  readSigners,
  resolveSshKeygen,
} from '@agent-ledger/shared';
import type { RuntimeStore } from '../db/store.ts';
import { Ledger } from '../ledger/ledger.ts';
import { readAllCounters } from '../ledger/device.ts';
import { tempConfig, type TempLedger } from '../test-helpers.ts';
import { CrashError, type CrashPoint } from './apply.ts';
import { runCycle, type CycleDeps, type CycleResult } from './cycle.ts';
import { addDeviceSynced } from './deviceadd.ts';
import { Gitx, REF_ACCEPTED, REF_INCOMING, REF_MAIN } from './gitx.ts';
import type { SyncLoop } from './loop.ts';
import { ExclusiveOpError } from './loop.ts';
import { rng, type Rng } from './merge/testkit.ts';
import { ObjectStore } from './objects.ts';
import { verifyCommitSignature } from './sigverify.ts';
import { StateStore } from './state.ts';
import { flakyRemote, makeKit, type FlakyRemote, type Kit } from './testkit-remote.ts';
import { TreeBuilder } from './treebuild.ts';
import { bootReplayGit, bootReplayNotes, startSync } from './wire.ts';

/** The real-git sync tests are POSIX-gated; `LEDGER_TEST_SYNC_WIN32=1` lifts the gate (CI Windows, report-only). */
const skipSync = process.platform === 'win32' && process.env.LEDGER_TEST_SYNC_WIN32 !== '1' ? 'POSIX-gated (LEDGER_TEST_SYNC_WIN32=1 lifts)' : false;

const envInt = (name: string, dflt: number): number => {
  const v = process.env[name];
  if (v === undefined || v === '') return dflt;
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 ? n : dflt;
};
const SEED = envInt('SOAK_SEED', Math.floor(Math.random() * 0x7fffffff));
const ITERATIONS = envInt('SOAK_ITERATIONS', 30);
const BUDGET_MS = envInt('SOAK_BUDGET_MS', 20_000);

const FAKE_STORE = { addInbox: () => 'x', releaseLeases: () => 0 } as unknown as RuntimeStore;
const base = { kind: 'BACKLOG', priority: 'P2', owner: 'agent', steps: [] as string[], blocked_by: [] as string[], aliases: [] as string[], proposed: false };
const PRIOS = ['P0', 'P1', 'P2', 'P3'] as const;
const FAULT = { stderr: 'Connection reset by peer', code: 128 };
const MAX_ADDS = 4;

interface Node {
  name: string;
  dir: string;
  tmp: TempLedger;
  logs: string[];
  ledger: Ledger;
  loop: SyncLoop;
  /** The ONE documented cast: the loop's own deps object, re-pointed at a flaky gitx so every cycle (also the
   *  loop's own and `exclusiveOp`'s) goes through the argv audit and the fault injector. */
  deps: CycleDeps;
  deviceId: string;
  /** Inspection runner (own sync dir), never faulty. */
  insp: Gitx;
  store: ObjectStore;
  flakies: FlakyRemote[];
  flaky: FlakyRemote;
  /** Per repo slug: highest counter ever sampled on this node. */
  counterMax: Map<string, number>;
}

interface World {
  kit: Kit;
  root: string;
  nodes: Node[];
  base: string;
  cleanup(): Promise<void>;
}

const sh = async (gitx: Gitx, dir: string, args: string[]): Promise<string> => (await gitx.mustRun(args, { cwd: dir })).stdout.toString('utf8').trim();

/* ---------------- world ---------------- */

async function startNode(n: Node, remote: string, seed: string | null): Promise<void> {
  // the boot order of `startHub` (server.ts): new Ledger -> bootReplayGit -> init -> bootReplayNotes -> startSync
  const log = (l: string): void => {
    n.logs.push(`${n.name}: ${l}`);
  };
  n.ledger = new Ledger({ config: n.tmp.config, log });
  const boot = await bootReplayGit(n.ledger, log);
  await n.ledger.init();
  if (seed !== null) {
    await writeFile(nodePath.join(n.dir, '.hub', 'sync.yml'), `v: 1\nremote: ${remote}\n`, { mode: 0o600 });
    const gitx = await Gitx.open({ syncDir: nodePath.join(n.dir, '.hub', 'sync'), testLocalRemotes: [remote] });
    await new TreeBuilder(gitx, n.dir, nodePath.join(n.dir, '.hub', 'sync', 'tmp')).createRef(REF_ACCEPTED, seed);
    await (await StateStore.open(n.dir)).update((s) => {
      s.accepted = seed;
    });
  }
  await bootReplayNotes(boot, FAKE_STORE, log);
  const loop = await startSync({ ledger: n.ledger, store: FAKE_STORE, config: n.tmp.config, log, start: false, testLocalRemotes: [remote] });
  assert.notEqual(loop, null, `sync enabled for ${n.name}: ${n.logs.join(' | ')}`);
  n.loop = loop as SyncLoop;
  n.ledger.git.setOnCommitted(null); // cycles run only when the soak says so
  n.deviceId = n.ledger.device.device_id;
  n.deps = (n.loop as unknown as { deps: CycleDeps }).deps;
  realGitx.set(n, n.deps.gitx); // the loop is new: its gitx is still the real hardened runner
  freshFlaky(n, n.deps.gitx);
}

const realGitx = new WeakMap<Node, Gitx>();

/** A new fault injector for the node (drops any unconsumed scripted failure) and re-point the deps at it. */
function freshFlaky(n: Node, real: Gitx): void {
  n.flaky = flakyRemote(real);
  n.flakies.push(n.flaky);
  const syncDir = nodePath.join(n.dir, '.hub', 'sync');
  n.deps.gitx = n.flaky.gitx;
  n.deps.store = new ObjectStore(n.flaky.gitx, n.dir);
  n.deps.trees = new TreeBuilder(n.flaky.gitx, n.dir, nodePath.join(syncDir, 'tmp'));
}

function resetFaults(n: Node): void {
  const g = realGitx.get(n);
  assert.ok(g, 'real gitx known');
  freshFlaky(n, g);
}

async function world(): Promise<World> {
  const kit = await makeKit();
  const root = await realpath(await mkdtemp(nodePath.join(await realpath(tmpdir()), 'agl-soak-')));
  await chmod(root, 0o700);
  const remote = kit.remote.path;
  const dirs = { a: nodePath.join(root, 'a'), b: nodePath.join(root, 'b'), c: nodePath.join(root, 'c') };
  await mkdir(dirs.a, { mode: 0o700 });
  // ---- A: the root (TOFU): key + devices.yml first so every commit is signed from the very first one
  const initA = await initDevice(dirs.a, { root: true, label: 'a' });
  const t0 = await tempConfig({ sync: true, ledgerDir: dirs.a, commitDebounceMs: 3_600_000 });
  const l0 = new Ledger({ config: t0.config, log: () => undefined });
  await l0.init();
  await l0.git.flush();
  await l0.close();
  await t0.cleanup();
  const gitxA = await Gitx.open({ syncDir: nodePath.join(dirs.a, '.hub', 'sync'), testLocalRemotes: [remote] });
  const c0 = await sh(gitxA, dirs.a, ['rev-parse', REF_MAIN]);
  assert.equal((await gitxA.push(dirs.a, remote, c0)).ok, true, 'base pushed');
  // ---- B and C: init + fetch of the base (no `clone`), own keys
  const joiners: { dir: string; init: Awaited<ReturnType<typeof initDevice>>; pub: string }[] = [];
  for (const [label, dir] of [['b', dirs.b], ['c', dirs.c]] as const) {
    await rm(dir, { recursive: true, force: true });
    await mkdir(dir, { mode: 0o700 });
    const g0 = await Gitx.open({ syncDir: nodePath.join(root, `${label}-clone-sync`), testLocalRemotes: [remote] });
    await g0.initRepo(dir);
    assert.equal((await g0.fetch(dir, remote)).ok, true);
    const f0 = await sh(g0, dir, ['rev-parse', '--verify', REF_INCOMING]);
    await sh(g0, dir, ['update-ref', REF_MAIN, f0, '0'.repeat(40)]);
    await sh(g0, dir, ['read-tree', '--reset', '-u', REF_MAIN]);
    const init = await initDevice(dir, { label });
    const pub = (await readFile(deviceLayout(dir).pubFile, 'utf8')).trim().split(' ').slice(0, 2).join(' ');
    joiners.push({ dir, init, pub });
  }
  const [jb, jc] = joiners as [(typeof joiners)[number], (typeof joiners)[number]];
  // ---- A registers and approves B and C (trusted side of the enrolment), commits it signed, pushes
  for (const [label, j] of [['b', jb], ['c', jc]] as const) {
    await addDevice(dirs.a, j.pub, label, j.init.fingerprint);
    await approveDevice(dirs.a, j.init.deviceId, j.init.fingerprint);
  }
  const t1 = await tempConfig({ sync: true, ledgerDir: dirs.a, commitDebounceMs: 3_600_000 });
  const lA = new Ledger({ config: t1.config, log: () => undefined });
  await lA.init();
  lA.git.touch('devices');
  await lA.git.flush();
  await lA.close();
  await t1.cleanup();
  const c1 = await sh(gitxA, dirs.a, ['rev-parse', REF_MAIN]);
  assert.notEqual(c1, c0, 'devices.yml committed');
  assert.equal((await gitxA.push(dirs.a, remote, c1)).ok, true);
  // ---- B and C take their registered slots and approve themselves, each other and A
  for (const [j, other] of [[jb, jc], [jc, jb]] as const) {
    const g = await Gitx.open({ syncDir: nodePath.join(j.dir, '.hub', 'sync'), testLocalRemotes: [remote] });
    await g.fetch(j.dir, remote);
    await sh(g, j.dir, ['update-ref', '--no-deref', REF_MAIN, c1, c0]);
    await sh(g, j.dir, ['read-tree', '--reset', '-u', c1]);
    await adoptSlot(j.dir);
    await approveDevice(j.dir, j.init.deviceId, j.init.fingerprint); // a joiner trusts its own key (enrol.ts:959)
    await approveDevice(j.dir, initA.deviceId, initA.fingerprint);
    await approveDevice(j.dir, other.init.deviceId, other.init.fingerprint);
  }
  // ---- bring the three ledgers up
  const nodes: Node[] = [];
  for (const [name, dir] of [['A', dirs.a], ['B', dirs.b], ['C', dirs.c]] as const) {
    const tmp = await tempConfig({ sync: true, ledgerDir: dir, commitDebounceMs: 3_600_000, syncVerify: 'enforce' });
    const n = { name, dir, tmp, logs: [] as string[], flakies: [] as FlakyRemote[], counterMax: new Map<string, number>() } as unknown as Node;
    n.insp = await Gitx.open({ syncDir: nodePath.join(dir, '.hub', 'sync'), testLocalRemotes: [remote] });
    n.store = new ObjectStore(n.insp, dir);
    await startNode(n, remote, c1);
    nodes.push(n);
  }
  return {
    kit,
    root,
    nodes,
    base: c1,
    async cleanup() {
      for (const n of nodes) {
        await n.loop.stop().catch(() => undefined);
        await n.ledger.close().catch(() => undefined);
        await n.tmp.cleanup().catch(() => undefined);
      }
      await kit.cleanup();
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    },
  };
}

/* ---------------- helpers ---------------- */

async function waitIdle(loop: SyncLoop, ms = 60_000): Promise<void> {
  const t0 = Date.now();
  for (;;) {
    const s = await loop.status();
    if (!s.running && !s.pending) return;
    if (Date.now() - t0 > ms) throw new Error('loop did not go idle');
    await new Promise((r) => setTimeout(r, 20));
  }
}

async function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | null = null;
  const t = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`${what} (timeout ${String(ms)} ms)`)), ms);
  });
  try {
    return await Promise.race([p, t]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

const dirtyOf = async (n: Node): Promise<string> => (await n.insp.mustRun(['status', '--porcelain=v1', '-z', '--untracked-files=all'], { cwd: n.dir })).stdout.toString('utf8');
const mainOf = (n: Node): Promise<string> => sh(n.insp, n.dir, ['rev-parse', REF_MAIN]);

async function sampleCounters(n: Node, globalMax: Map<string, number>): Promise<void> {
  const now = await readAllCounters(nodePath.join(n.dir, 'counters'));
  for (const [k, v] of n.counterMax) {
    assert.ok((now.get(k) ?? 0) >= v, `counter ${k} on ${n.name} decreased: ${String(v)} -> ${String(now.get(k) ?? 0)}`);
  }
  for (const [k, v] of now) {
    if (v > (n.counterMax.get(k) ?? 0)) n.counterMax.set(k, v);
    if (v > (globalMax.get(k) ?? 0)) globalMax.set(k, v);
  }
}

async function assertNoHalt(n: Node, res: CycleResult | null): Promise<void> {
  const st = await n.deps.state.read();
  assert.equal(st.halt, null, `${n.name} halted: ${JSON.stringify(st.halt)} (cycle ${res?.outcome ?? '-'})`);
}

function weighted<T>(r: Rng, items: readonly (readonly [T, number])[]): T {
  const total = items.reduce((s, [, w]) => s + w, 0);
  let x = r.next() * total;
  for (const [it, w] of items) {
    x -= w;
    if (x < 0) return it;
  }
  return (items[items.length - 1] as readonly [T, number])[0];
}

async function throwawayKey(root: string, k: number): Promise<{ line: string; fingerprint: string }> {
  const bin = await resolveSshKeygen();
  const dir = nodePath.join(root, `soak-key-${String(k)}`);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await generateKeyPair(nodePath.join(dir, 'key'), bin);
  return publicKeyOf(nodePath.join(dir, 'key'), bin);
}

/* ---------------- the soak ---------------- */

type Op = 'create' | 'mutate' | 'flush' | 'cycle' | 'concurrent' | 'double' | 'fault' | 'crash' | 'add';
const OPS: readonly (readonly [Op, number])[] = [
  ['create', 30],
  ['mutate', 15],
  ['flush', 10],
  ['cycle', 20],
  ['concurrent', 8],
  ['double', 3],
  ['fault', 7],
  ['crash', 5],
  ['add', 2],
];

test(
  'soak: 3 real ledgers, random honest ops + faults + crashes, converge with every invariant intact',
  { skip: skipSync, timeout: BUDGET_MS + 150_000 },
  async (t) => {
    t.diagnostic(`SOAK_SEED=${String(SEED)} SOAK_ITERATIONS=${String(ITERATIONS)} SOAK_BUDGET_MS=${String(BUDGET_MS)}`);
    const w = await world();
    const r = rng(SEED);
    const trail: string[] = [];
    const created: { title: string; node: Node; id: string; prio: string }[] = [];
    const globalCounters = new Map<string, number>();
    let seq = 0;
    let executed = 0;
    let adds = 0;
    let addsLanded = 0;
    const note = (s: string): void => {
      trail.push(`#${String(executed)} ${s}`);
    };
    const nodeOf = (): Node => r.pick(w.nodes);
    for (const n of w.nodes) n.deps.rnd = () => r.next();

    const cycleOn = async (n: Node): Promise<CycleResult> => {
      const res = await runCycle(n.deps);
      await assertNoHalt(n, res);
      await sampleCounters(n, globalCounters);
      return res;
    };
    const makeItem = async (n: Node): Promise<void> => {
      seq += 1;
      const title = `soak ${String(seq)} on ${n.name}`;
      const item = await n.ledger.createItem({ ...base, repo: 'ops', title });
      created.push({ title, node: n, id: item.fm.id, prio: item.fm.priority });
      note(`create ${n.name} ${item.fm.id}`);
    };
    /** "Process death": stop the loop, close the ledger (must not hang), boot like `startHub`. */
    const restart = async (n: Node): Promise<void> => {
      await n.loop.stop();
      await withTimeout(n.ledger.close(), 30_000, `ledger.close() after a crash on ${n.name} hung`).catch((e: unknown) => {
        if (e instanceof Error && /hung/.test(e.message)) throw e;
        n.logs.push(`${n.name}: close after crash failed (${e instanceof Error ? e.name : 'error'})`);
      });
      await startNode(n, w.kit.remote.path, null);
      n.deps.rnd = () => r.next();
    };

    const doOp = async (op: Op): Promise<void> => {
      switch (op) {
        case 'create': {
          await makeItem(nodeOf());
          return;
        }
        case 'mutate': {
          const n = nodeOf();
          const mine = created.filter((c) => c.node === n);
          if (mine.length === 0 || r.chance(0.35)) {
            await n.ledger.appendJournalEvent('ops', 'soak', 'soak.note', [`n${String(executed)}`, n.name]);
            note(`journal ${n.name}`);
            return;
          }
          const c = r.pick(mine);
          const next = PRIOS.filter((p) => p !== c.prio)[r.int(PRIOS.length - 1)] as string;
          await n.ledger.patchItem(c.id, { priority: next });
          c.prio = next;
          note(`mutate ${n.name} ${c.id} -> ${next}`);
          return;
        }
        case 'flush': {
          const n = nodeOf();
          await n.ledger.git.flush();
          note(`flush ${n.name}`);
          return;
        }
        case 'cycle': {
          const n = nodeOf();
          if (r.chance(0.4)) {
            // a write racing a cycle on the same node is wanted
            seq += 1;
            const title = `soak ${String(seq)} racing ${n.name}`;
            const [res, item] = await Promise.all([cycleOn(n), n.ledger.createItem({ ...base, repo: 'ops', title })]);
            created.push({ title, node: n, id: item.fm.id, prio: item.fm.priority });
            note(`cycle+create ${n.name} -> ${res.outcome}`);
          } else {
            note(`cycle ${n.name} -> ${(await cycleOn(n)).outcome}`);
          }
          return;
        }
        case 'concurrent': {
          const k = 2 + r.int(2);
          const picked = [...w.nodes].sort(() => r.next() - 0.5).slice(0, k);
          note(`concurrent ${picked.map((n) => n.name).join('+')}`);
          const res = await Promise.all(picked.map((n) => runCycle(n.deps)));
          for (const [i, n] of picked.entries()) {
            await assertNoHalt(n, res[i] as CycleResult);
            await sampleCounters(n, globalCounters);
          }
          return;
        }
        case 'double': {
          const n = nodeOf();
          note(`double-trigger + exclusiveOp ${n.name}`);
          n.loop.trigger('manual');
          n.loop.trigger('manual');
          try {
            await n.loop.exclusiveOp((_d, ctx) => ctx.cycle());
          } catch (e) {
            if (!(e instanceof ExclusiveOpError)) throw e;
            note(`  exclusiveOp refused ${e.code}`);
          }
          await waitIdle(n.loop);
          await assertNoHalt(n, null);
          await sampleCounters(n, globalCounters);
          return;
        }
        case 'fault': {
          const n = nodeOf();
          const kind = r.pick(['fetch', 'push', 'lie'] as const);
          resetFaults(n);
          if (kind === 'lie') n.flaky.lieAboutPush = FAULT;
          else n.flaky.failNext(kind, FAULT);
          note(`fault ${kind} on ${n.name}`);
          try {
            note(`  -> ${(await cycleOn(n)).outcome}`);
          } finally {
            resetFaults(n); // drops an unconsumed scripted failure, never 3 in a row against one tip
          }
          return;
        }
        case 'crash': {
          const x = nodeOf();
          const y = r.pick(w.nodes.filter((n) => n !== x));
          await makeItem(y);
          await cycleOn(y); // the remote is now ahead of x: x's cycle has something to apply
          const point = r.pick(['marker', 'read-tree', 'update-ref', 'reindex', 'notes', 'marker-delete'] as const satisfies readonly CrashPoint[]);
          x.deps.crashAt = (p) => {
            if (p === point) throw new CrashError(p);
          };
          let crashed = false;
          try {
            await runCycle(x.deps);
          } catch (e) {
            if (!(e instanceof CrashError)) throw e;
            crashed = true;
          } finally {
            x.deps.crashAt = undefined;
          }
          note(`crash ${x.name} at ${point}: ${crashed ? 'died' : 'not reached'}`);
          if (crashed) await restart(x);
          await assertNoHalt(x, null);
          return;
        }
        case 'add': {
          if (adds >= MAX_ADDS) return;
          const n = nodeOf();
          adds += 1;
          const key = await throwawayKey(w.root, adds);
          const crashPushed = r.chance(0.4);
          let hit = false;
          const res = await addDeviceSynced(
            n.loop,
            { pubkey: key.line, label: `soak${String(adds)}`, fp: key.fingerprint },
            crashPushed
              ? {
                  crashAt: (p) => {
                    if (p === 'pushed') {
                      hit = true;
                      throw new Error('soak: crash after the push');
                    }
                  },
                }
              : {},
          );
          note(`add ${n.name} #${String(adds)}${crashPushed ? ' (crash at pushed)' : ''} -> ${JSON.stringify(res.ok ? { ok: true, existing: res.existing, applied: res.applied } : res)}`);
          if (hit) {
            addsLanded += 1;
            await restart(n);
          } else {
            assert.equal(res.ok, true, `addDeviceSynced refused on a quiet fleet: ${JSON.stringify(res)}`);
            if (res.ok && !res.existing) addsLanded += 1;
          }
          await assertNoHalt(n, null);
          return;
        }
      }
    };

    const fail = (err: unknown): Error => {
      const msg = `SOAK_SEED=${String(SEED)} SOAK_ITERATIONS=${String(executed)} -- ${err instanceof Error ? err.message : String(err)}\nlast ops:\n${trail.slice(-30).join('\n')}`;
      t.diagnostic(msg);
      return new Error(msg, { cause: err });
    };

    try {
      const t0 = Date.now();
      for (; executed < ITERATIONS && Date.now() - t0 < BUDGET_MS; ) {
        executed += 1;
        await doOp(weighted(r, OPS));
      }
      t.diagnostic(`ops executed: ${String(executed)} in ${String(Date.now() - t0)} ms (adds landed ${String(addsLanded)})`);

      /* ---- quiescence: faults off, flush + cycle on A, B, C until a whole round is up to date ---- */
      for (const n of w.nodes) {
        resetFaults(n);
        n.deps.crashAt = undefined;
      }
      trail.push('--- quiescence');
      let quiet = false;
      for (let round = 0; round < 8 && !quiet; round += 1) {
        const outcomes: string[] = [];
        for (const n of w.nodes) {
          await n.ledger.git.flush();
          outcomes.push((await cycleOn(n)).outcome);
        }
        trail.push(`round ${String(round)}: ${outcomes.join(',')}`);
        quiet = outcomes.every((o) => o === 'up-to-date');
      }
      assert.equal(quiet, true, 'no quiescence within 8 rounds');
      await checkInvariants(w, created, globalCounters, addsLanded);
    } catch (err) {
      throw fail(err);
    } finally {
      await w.cleanup();
    }
  },
);

/* ---------------- invariants ---------------- */

async function listFiles(dir: string, sub: string): Promise<string[]> {
  return (await readdir(nodePath.join(dir, sub)).catch(() => [])).sort();
}

async function checkInvariants(
  w: World,
  created: { title: string; node: Node; id: string; prio: string }[],
  globalCounters: Map<string, number>,
  addsLanded: number,
): Promise<void> {
  const [a] = w.nodes as [Node, ...Node[]];
  const remoteMain = await w.kit.remote.main();
  // (1) one history everywhere
  const mains = await Promise.all(w.nodes.map(mainOf));
  for (const [i, m] of mains.entries()) assert.equal(m, remoteMain, `(1) main of ${(w.nodes[i] as Node).name} == remote main`);
  const trees = await Promise.all(w.nodes.map((n) => sh(n.insp, n.dir, ['rev-parse', `${REF_MAIN}^{tree}`])));
  assert.equal(new Set(trees).size, 1, '(1) main^{tree} equal');
  for (const n of w.nodes) {
    assert.equal(await n.store.revParse(REF_ACCEPTED), remoteMain, `(1) accepted == main on ${n.name}`);
    assert.equal((await n.deps.state.read()).accepted, remoteMain, `(1) state mirror == main on ${n.name}`);
  }
  // (2) clean worktrees, no markers, empty tmp
  for (const n of w.nodes) {
    assert.equal(await dirtyOf(n), '', `(2) clean worktree on ${n.name}`);
    for (const f of ['inflight.json', 'enrol.json']) await assert.rejects(stat(nodePath.join(n.dir, '.hub', 'sync', f)), `(2) no ${f} on ${n.name}`);
    assert.deepEqual(await listFiles(n.dir, nodePath.join('.hub', 'sync', 'tmp')), [], `(2) .hub/sync/tmp empty on ${n.name}`);
  }
  // (3) no halt, no rejects/secrets in any journal, nothing blocked
  for (const n of w.nodes) {
    const s = await n.loop.status();
    assert.equal(s.halt, null, `(3) no halt on ${n.name}`);
    assert.equal(s.pushBlocked, null, `(3) pushBlocked null on ${n.name}`);
    const journals = (await sh(n.insp, n.dir, ['ls-files', '-z'])).split('\0').filter((p) => /(^|\/)journal\//.test(p));
    for (const j of journals) {
      const text = await readFile(nodePath.join(n.dir, j), 'utf8');
      assert.equal(/sync\.(reject|secret)/.test(text), false, `(3) no sync.reject / sync.secret in ${j} on ${n.name}`);
    }
  }
  // (4) every created title everywhere, ids unique, listItems equal
  const views = w.nodes.map((n) => n.ledger.listItems().map((i) => `${i.fm.id}|${i.fm.title}|${i.fm.priority}`).sort());
  for (const [i, v] of views.entries()) assert.deepEqual(v, views[0], `(4) listItems of ${(w.nodes[i] as Node).name} equals A's`);
  for (const n of w.nodes) {
    const items = n.ledger.listItems();
    assert.equal(new Set(items.map((x) => x.fm.id)).size, items.length, `(4) ids unique on ${n.name}`);
    const have = new Map(items.map((x) => [x.fm.title, x]));
    for (const c of created) {
      const got = have.get(c.title);
      assert.ok(got, `(4) "${c.title}" present on ${n.name}`);
      assert.equal(got.fm.priority, c.prio, `(4) last mutation of ${c.id} present on ${n.name}`);
    }
  }
  // (5) counters never went down (sampled in the run); final = max seen
  for (const n of w.nodes) {
    await sampleCounters(n, globalCounters);
    const now = await readAllCounters(nodePath.join(n.dir, 'counters'));
    for (const [k, v] of globalCounters) assert.equal(now.get(k) ?? 0, v, `(5) final counter ${k} on ${n.name} == max seen`);
  }
  // (6) one device registry
  const texts = await Promise.all(w.nodes.map((n) => readFile(nodePath.join(n.dir, 'devices.yml'), 'utf8')));
  assert.equal(new Set(texts).size, 1, '(6) devices.yml identical everywhere');
  const reg = await readDevices(deviceLayout(a.dir));
  assert.ok(reg);
  assert.equal(reg.devices.length, 3 + addsLanded, '(6) device count = 3 + landed adds');
  assert.equal(new Set(reg.devices.map((d) => d.id)).size, reg.devices.length, '(6) device ids unique');
  assert.equal(new Set(reg.devices.map((d) => d.slot)).size, reg.devices.length, '(6) slots unique');
  assert.equal(new Set(reg.devices.map((d) => d.pubkey)).size, reg.devices.length, '(6) keys unique');
  const revoked = reg.devices.filter((d) => d.revoked !== null).map((d) => d.pubkey);
  for (const n of w.nodes) {
    const signers = (await readSigners(deviceLayout(n.dir))).map((s) => s.pubkey);
    for (const k of revoked) assert.equal(signers.includes(k), false, `(6) revoked key not in allowed_signers on ${n.name}`);
  }
  // (7) every commit since the base is signed and none touches .hub/**
  const range = `${w.base}..${REF_MAIN}`;
  const shas = (await sh(a.insp, a.dir, ['rev-list', range])).split('\n').filter((l) => l !== '');
  for (const sha of shas) {
    const v = await verifyCommitSignature(await a.store.readCommitRaw(sha), { tmpRoot: nodePath.join(a.dir, '.hub', 'sync', 'tmp'), bin: a.deps.signing.sshKeygenBin });
    assert.equal(v.valid, true, `(7) commit ${sha.slice(0, 12)} signed`);
    const touched = (await sh(a.insp, a.dir, ['diff-tree', '-r', '-m', '--no-commit-id', '--name-only', sha])).split('\n');
    assert.equal(touched.some((p) => p.startsWith('.hub/')), false, `(7) commit ${sha.slice(0, 12)} touches .hub/**`);
  }
  assert.equal((await sh(a.insp, a.dir, ['ls-tree', '-r', '--name-only', REF_MAIN])).split('\n').some((p) => p.startsWith('.hub/')), false, '(7) no .hub/** in main');
  // (8) nothing secret in logs, journals, state.json
  const needles: { label: string; value: string }[] = [{ label: 'remote path', value: w.kit.remote.path }];
  for (const n of w.nodes) {
    const key = await readFile(deviceLayout(n.dir).keyFile, 'utf8');
    for (const line of key.split('\n')) if (line.length >= 20 && !line.startsWith('-----')) needles.push({ label: `private key body of ${n.name}`, value: line });
    const tok = await readFile(n.ledger.paths.tokenPath, 'utf8').catch(() => '');
    if (tok.trim().length >= 16) needles.push({ label: `hub token of ${n.name}`, value: tok.trim() });
  }
  for (const n of w.nodes) {
    const haystacks: { label: string; text: string }[] = [
      { label: `logs of ${n.name}`, text: n.logs.join('\n') },
      { label: `state.json of ${n.name}`, text: await readFile(nodePath.join(n.dir, '.hub', 'sync', 'state.json'), 'utf8').catch(() => '') },
    ];
    for (const j of (await sh(n.insp, n.dir, ['ls-files', '-z'])).split('\0').filter((p) => /(^|\/)journal\//.test(p))) {
      haystacks.push({ label: `journal ${j} of ${n.name}`, text: await readFile(nodePath.join(n.dir, j), 'utf8') });
    }
    for (const h of haystacks) for (const nd of needles) assert.equal(h.text.includes(nd.value), false, `(8) ${nd.label} leaked into ${h.label}`);
  }
  // (9) never a forced push, a `+` push refspec or a fetch outside the scratch namespace
  for (const n of w.nodes) {
    for (const f of n.flakies) {
      for (const argv of f.argv) {
        const cmd = argv.find((x) => !x.startsWith('-') && ['push', 'fetch'].includes(x));
        if (cmd === 'push') {
          assert.equal(argv.some((x) => x === '--force' || x === '-f' || x.startsWith('--force-with-lease') || x.startsWith('+')), false, `(9) forced push on ${n.name}`);
        }
        if (cmd === 'fetch') {
          const spec = argv.find((x) => /^\+?refs\/.*:refs\//.test(x));
          assert.ok(spec === undefined || spec.endsWith(`:${REF_INCOMING}`), `(9) fetch outside refs/ledger-sync on ${n.name}`);
        }
      }
    }
  }
  // (10) the only refs: main, accepted, incoming
  for (const n of w.nodes) {
    const refs = (await sh(n.insp, n.dir, ['for-each-ref', '--format=%(refname)'])).split('\n').filter((l) => l !== '').sort();
    assert.deepEqual(refs, [REF_ACCEPTED, REF_INCOMING, REF_MAIN].sort(), `(10) refs on ${n.name}`);
  }
}
