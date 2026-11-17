/** `addDeviceSynced` — push-first slot CAS (docs/f3b-b4-plan.md §1.3; T-B4-4, T-B4-7, T-B4-9, T-B4-13).
 *  Real git + ssh-keygen, a bare remote, a fleet of ledger hubs (testkit). The approval step is a seam in all but
 *  one test (the fleet hubs have no `.hub/device.yml`). POSIX only (OpenSSH, modes). */

import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { deviceEmail, generateKeyPair, parseDevicesYaml, publicKeyOf, resolveSshKeygen, type Ed25519Pub } from '@agent-ledger/shared';
import { runCycle } from './cycle.ts';
import { addDeviceSynced, type AddSyncedOptions, type AddSyncedResult } from './deviceadd.ts';
import { REF_ACCEPTED, REF_MAIN } from './gitx.ts';
import { SyncLoop } from './loop.ts';
import { cycleDeps, fakeHost, flakyRemote, makeFleet, makeKit, type FakeHost, type FlakyRemote, type Fleet, type Kit, type LedgerHub } from './testkit-remote.ts';
import { verifyCommitSignature } from './sigverify.ts';

const posix = process.platform !== 'win32';

interface Node {
  lh: LedgerHub;
  host: FakeHost;
  flaky: FlakyRemote;
  loop: SyncLoop;
  approvals: string[];
  opts: AddSyncedOptions;
}

let joinerSeq = 0;
async function joiner(kit: Kit): Promise<Ed25519Pub> {
  const bin = await resolveSshKeygen();
  joinerSeq += 1;
  const dir = nodePath.join(kit.root, `joiner${String(joinerSeq)}`);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await generateKeyPair(nodePath.join(dir, 'key'), bin);
  return publicKeyOf(nodePath.join(dir, 'key'), bin);
}

function node(kit: Kit, lh: LedgerHub, o: { approveFails?: boolean } = {}): Node {
  const host = fakeHost(lh);
  const flaky = flakyRemote(lh.hub.gitx);
  const approvals: string[] = [];
  const deps = cycleDeps(lh, kit, { host, gitx: flaky.gitx });
  const loop = new SyncLoop({ deps, intervalMs: 3_600_000, cycle: runCycle });
  const opts: AddSyncedOptions = {
    approve: async (_d, id) => {
      if (o.approveFails === true) throw new Error('approve unavailable');
      approvals.push(id);
      return { added: true };
    },
  };
  return { lh, host, flaky, loop, approvals, opts };
}

async function withFleet<T>(n: number, fn: (f: Fleet, kit: Kit) => Promise<T>): Promise<T> {
  const kit = await makeKit();
  try {
    return await fn(await makeFleet(kit, n), kit);
  } finally {
    await kit.cleanup();
  }
}

const add = (n: Node, pub: Ed25519Pub, label: string, fp?: string): Promise<AddSyncedResult> =>
  addDeviceSynced(n.loop, { pubkey: pub.line, label, fp: fp ?? pub.fingerprint }, n.opts);

async function refs(lh: LedgerHub): Promise<string[]> {
  const r = await lh.hub.gitx.mustRun(['for-each-ref', '--format=%(refname)'], { cwd: lh.dir });
  return r.stdout.toString('utf8').split('\n').filter((x) => x !== '').sort();
}

async function devicesAt(lh: LedgerHub, sha: string): Promise<ReturnType<typeof parseDevicesYaml>> {
  const entries = await lh.hub.store.lsTree(sha);
  const f = entries.find((e) => e.path === 'devices.yml');
  assert.ok(f);
  return parseDevicesYaml((await lh.hub.store.readObject(f.sha, 'blob')).toString('utf8'));
}

const BASE_REFS = [REF_MAIN, REF_ACCEPTED, 'refs/ledger-sync/incoming'].sort();

test('happy path: one signed devices.yml-only commit is pushed first, then applied by the standard cycle, then approved', { skip: !posix }, async () => {
  await withFleet(3, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const pub = await joiner(kit);
    const before = await kit.remote.main();
    const res = await add(a, pub, 'laptop');
    assert.equal(res.ok, true);
    if (!res.ok) return;
    assert.equal(res.slot, 'A', 'lowest never-used slot (B and C are taken)');
    assert.equal(res.id, pub.deviceId);
    assert.equal(res.fp, pub.fingerprint);
    assert.equal(res.applied, true);
    assert.equal(res.approved, true);
    assert.equal(res.existing, false);
    assert.deepEqual(a.approvals, [pub.deviceId]);
    const C = res.commit as string;
    assert.equal(await kit.remote.main(), C, 'the remote accepted exactly that commit');
    assert.equal(await a.lh.hub.main(), C);
    assert.equal(await a.lh.hub.store.revParse(REF_ACCEPTED), C);
    assert.equal((await a.lh.state.read()).accepted, C);
    // content: parent = the old tip, ONLY devices.yml changed, signed by this device, identity from the helper
    const raw = (await a.lh.hub.store.readCommitRaw(C)).toString('utf8');
    assert.match(raw, new RegExp(`^parent ${before as string}$`, 'm'));
    assert.deepEqual((await a.lh.hub.store.diffTreeRaw(before as string, C)).map((d) => d.path), ['devices.yml']);
    assert.ok(raw.includes(`<${deviceEmail(a.lh.hub.deviceId)}>`));
    const sig = await verifyCommitSignature(await a.lh.hub.store.readCommitRaw(C), { tmpRoot: nodePath.join(a.lh.dir, '.hub', 'sync', 'tmp') });
    assert.equal(sig.valid, true);
    assert.equal(sig.pubkeyLine, a.lh.hub.pub.line);
    const entry = (await devicesAt(a.lh, C)).devices.find((d) => d.id === pub.deviceId);
    assert.equal(entry?.slot, 'A');
    assert.equal(entry?.added_by, a.lh.hub.deviceId);
    assert.equal(entry?.label, 'laptop');
    // the worktree follows (APPLY), nothing is left dirty, no stray refs
    assert.deepEqual(await a.lh.dirty(), []);
    assert.ok((await readFile(nodePath.join(a.lh.dir, 'devices.yml'), 'utf8')).includes(pub.line));
    assert.deepEqual(await refs(a.lh), BASE_REFS);
    // a peer converges through its ordinary cycle
    const b = node(kit, f.hubs[1] as LedgerHub);
    await runCycle(cycleDeps(b.lh, kit, { host: b.host }));
    assert.equal(await b.lh.hub.main(), C);
    // T-B4-13: nothing from the remote URL reaches logs or results
    assert.ok(!a.host.logs.join('\n').includes(kit.remote.path));
    assert.ok(!JSON.stringify(res).includes(kit.remote.path));
  });
});

test('wrong fingerprint, comment/options in the key, bad label: refused before anything is pushed (T-B4-9)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const pub = await joiner(kit);
    const other = await joiner(kit);
    const tip = await kit.remote.main();
    assert.deepEqual(await add(a, pub, 'laptop', other.fingerprint), { ok: false, code: 'FP_MISMATCH' });
    assert.deepEqual(await addDeviceSynced(a.loop, { pubkey: `${pub.line} me@host`, label: 'laptop', fp: pub.fingerprint }, a.opts), { ok: false, code: 'INVALID' });
    assert.deepEqual(await addDeviceSynced(a.loop, { pubkey: `command="x" ${pub.line}`, label: 'laptop', fp: pub.fingerprint }, a.opts), { ok: false, code: 'INVALID' });
    assert.deepEqual(await add(a, pub, 'Bad Label'), { ok: false, code: 'INVALID' });
    assert.deepEqual(await addDeviceSynced(a.loop, { pubkey: pub.line, label: 'laptop', fp: 'SHA256:nope' }, a.opts), { ok: false, code: 'INVALID' });
    assert.equal(a.flaky.pushCalls, 0);
    assert.equal(await kit.remote.main(), tip);
    assert.deepEqual(a.approvals, []);
  });
});

test('replay: the same add twice registers once; the second call is idempotent and pushes nothing', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const pub = await joiner(kit);
    const first = await add(a, pub, 'laptop');
    assert.equal(first.ok, true);
    const tip = await kit.remote.main();
    const pushes = a.flaky.pushCalls;
    const second = await add(a, pub, 'laptop');
    assert.equal(second.ok, true);
    if (!second.ok || !first.ok) return;
    assert.equal(second.existing, true);
    assert.equal(second.commit, null);
    assert.equal(second.slot, first.slot);
    assert.equal(second.approved, true);
    assert.equal(a.flaky.pushCalls, pushes, 'no second push');
    assert.equal(await kit.remote.main(), tip);
  });
});

test('slot race: the loser of the remote CAS leaves no ref, takes a fresh slot, and never moved main before its push (T-B4-4)', { skip: !posix }, async () => {
  await withFleet(3, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const b = node(kit, f.hubs[1] as LedgerHub);
    const pa = await joiner(kit);
    const pb = await joiner(kit);
    const L = await kit.remote.main();
    let mainAtPush: string | null = null;
    let raceLost = false;
    b.flaky.beforePush = async () => {
      if (raceLost) return;
      raceLost = true;
      mainAtPush = await b.lh.hub.main();
      const ra = await add(a, pa, 'one'); // hub A wins the slot first
      assert.equal(ra.ok && ra.slot, 'A');
    };
    const rb = await add(b, pb, 'two');
    assert.equal(rb.ok, true);
    if (!rb.ok) return;
    assert.equal(mainAtPush, L, 'main did not move before the successful push');
    assert.equal(rb.slot, 'D', 'fresh slot after the lost race (A is taken by the winner)');
    assert.equal(b.flaky.pushCalls, 2);
    // no orphan: the lost commit is not referenced by ANY ref of hub B
    assert.deepEqual(await refs(b.lh), BASE_REFS);
    const tip = (await kit.remote.main()) as string;
    assert.equal(await b.lh.hub.main(), tip);
    const slots = (await devicesAt(b.lh, tip)).devices.map((d) => d.slot);
    assert.equal(new Set(slots).size, slots.length, 'slots are unique');
    // hub A converges and sees both devices
    await runCycle(cycleDeps(a.lh, kit, { host: a.host }));
    assert.equal(await a.lh.hub.main(), tip);
  });
});

test('slot race, seeded rounds with real concurrency: distinct slots, one linear history, no stray refs', { skip: !posix }, async () => {
  await withFleet(3, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const b = node(kit, f.hubs[1] as LedgerHub);
    let seed = 0x9e3779b9;
    const rnd = (): number => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const slots = new Set<string>();
    for (let round = 0; round < 6; round += 1) {
      const pa = await joiner(kit);
      const pb = await joiner(kit);
      const delay = (): Promise<void> => new Promise((r) => setTimeout(r, Math.floor(rnd() * 40)));
      const [ra, rb] = await Promise.all([
        delay().then(() => add(a, pa, `a${String(round)}`)),
        delay().then(() => add(b, pb, `b${String(round)}`)),
      ]);
      assert.equal(ra.ok && rb.ok, true, `round ${String(round)} ${JSON.stringify([ra, rb])} ${a.host.logs.join('|')} ${b.host.logs.join('|')}`);
      if (!ra.ok || !rb.ok) return;
      assert.notEqual(ra.slot, rb.slot);
      for (const s of [ra.slot, rb.slot]) {
        assert.ok(!slots.has(s), `slot ${s} is never re-issued`);
        slots.add(s);
      }
      // converge both hubs, then compare
      await runCycle(cycleDeps(a.lh, kit, { host: a.host }));
      await runCycle(cycleDeps(b.lh, kit, { host: b.host }));
      const tip = (await kit.remote.main()) as string;
      assert.equal(await a.lh.hub.main(), tip);
      assert.equal(await b.lh.hub.main(), tip);
      assert.deepEqual(await refs(a.lh), BASE_REFS);
      assert.deepEqual(await refs(b.lh), BASE_REFS);
    }
    const tip = (await kit.remote.main()) as string;
    const all = (await devicesAt(a.lh, tip)).devices.map((d) => d.slot);
    assert.equal(new Set(all).size, all.length);
    assert.equal(all.length, 3 + 12);
  });
});

test('unknown push outcome: the fetch decides (landed -> applied; never reached -> dropped and retried)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const p1 = await joiner(kit);
    a.flaky.lieAboutPush = { timedOut: true }; // the push reaches the remote, the answer is lost
    const r1 = await add(a, p1, 'one');
    a.flaky.lieAboutPush = null;
    assert.equal(r1.ok, true);
    if (!r1.ok) return;
    assert.equal(r1.applied, true);
    assert.equal(await kit.remote.main(), r1.commit);
    assert.equal(a.flaky.pushCalls, 1, 'not pushed again');
    const p2 = await joiner(kit);
    a.flaky.failNext('push', { timedOut: true }); // never reached the remote
    const r2 = await add(a, p2, 'two');
    assert.equal(r2.ok, true);
    if (!r2.ok) return;
    assert.notEqual(r2.slot, r1.slot);
    assert.equal(a.flaky.pushCalls, 3);
    assert.deepEqual(await refs(a.lh), BASE_REFS);
    assert.equal(new Set((await devicesAt(a.lh, (await kit.remote.main()) as string)).devices.map((d) => d.slot)).size, 4);
  });
});

test('three lost races -> SLOT_BUSY, nothing changed locally', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const other = f.hubs[1] as LedgerHub;
    const pub = await joiner(kit);
    let n = 0;
    a.flaky.beforePush = async () => {
      n += 1;
      await kit.remote.pushSigned(other.hub, [{ path: 'acme/CONTEXT.md', content: `# acme\nrace ${String(n)}\n` }]);
    };
    const res = await add(a, pub, 'laptop');
    assert.deepEqual(res, { ok: false, code: 'SLOT_BUSY' });
    assert.equal(a.flaky.pushCalls, 3, 'max 3 attempts');
    assert.ok(!(await readFile(nodePath.join(a.lh.dir, 'devices.yml'), 'utf8')).includes(pub.line));
    assert.deepEqual(a.approvals, []);
    assert.deepEqual(await refs(a.lh), BASE_REFS);
  });
});

test('a halted loop or a held local write refuses without touching the remote', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const pub = await joiner(kit);
    const tip = await kit.remote.main();
    await a.lh.state.update((s) => {
      s.halt = { reason: 'quarantine:unsigned', cls: 'probe', since: '2026-11-17T09:00:00.000Z', tip: 'b'.repeat(40), rule: 'unsigned', detail: 'x', d2: null };
    });
    assert.deepEqual(await add(a, pub, 'laptop'), { ok: false, code: 'HALTED' });
    await a.lh.state.update((s) => {
      s.halt = null;
    });
    await writeFile(nodePath.join(a.lh.dir, 'acme', 'dirty.md'), 'uncommitted\n');
    assert.deepEqual(await add(a, pub, 'laptop'), { ok: false, code: 'NOT_SYNCED' });
    assert.equal(a.flaky.pushCalls, 0);
    assert.equal(await kit.remote.main(), tip);
  });
});

test('a crash after the push (A1): the next cycle applies it, a re-run approves idempotently', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub);
    const pub = await joiner(kit);
    const L = await a.lh.hub.main();
    a.opts.crashAt = (point) => {
      if (point === 'pushed') throw new Error('test crash');
    };
    const res = await add(a, pub, 'laptop');
    assert.deepEqual(res, { ok: false, code: 'LOCAL' });
    const C = (await kit.remote.main()) as string;
    assert.notEqual(C, L, 'the push landed');
    assert.equal(await a.lh.hub.main(), L, 'main is untouched until APPLY');
    assert.deepEqual(a.approvals, []);
    delete a.opts.crashAt;
    await runCycle(cycleDeps(a.lh, kit, { host: a.host })); // the ordinary cycle fast-forwards
    assert.equal(await a.lh.hub.main(), C);
    const again = await add(a, pub, 'laptop');
    assert.equal(again.ok && again.existing, true);
    assert.deepEqual(a.approvals, [pub.deviceId]);
  });
});

test('an approval that fails after a landed push is reported as applied-but-not-approved (re-run approves)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const a = node(kit, f.hubs[0] as LedgerHub, { approveFails: true });
    const pub = await joiner(kit);
    const res = await add(a, pub, 'laptop');
    assert.equal(res.ok, true);
    if (!res.ok) return;
    assert.equal(res.applied, true);
    assert.equal(res.approved, false);
    const tip = (await kit.remote.main()) as string;
    assert.ok((await devicesAt(a.lh, tip)).devices.some((d) => d.id === pub.deviceId));
  });
});

test('the real approval runs under the device lock on the ledger (no seam)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const lh = f.hubs[0] as LedgerHub;
    const host = fakeHost(lh);
    const loop = new SyncLoop({ deps: cycleDeps(lh, kit, { host }), intervalMs: 3_600_000, cycle: runCycle });
    // the fleet hubs carry their key elsewhere: give this one a real `.hub/device.yml` + `key.pub`
    await mkdir(nodePath.join(lh.dir, '.hub', 'device'), { recursive: true, mode: 0o700 });
    await writeFile(nodePath.join(lh.dir, '.hub', 'device.yml'), `device_id: ${lh.hub.deviceId}\nlabel: ${lh.hub.label}\nslot: ""\n`, { mode: 0o600 });
    await writeFile(nodePath.join(lh.dir, '.hub', 'device', 'key.pub'), `${lh.hub.pub.line}\n`, { mode: 0o600 });
    const pub = await joiner(kit);
    const res = await addDeviceSynced(loop, { pubkey: pub.line, label: 'laptop', fp: pub.fingerprint });
    assert.equal(res.ok && res.approved, true);
    assert.ok((await readFile(nodePath.join(lh.dir, '.hub', 'allowed_signers'), 'utf8')).includes(pub.line));
  });
});

test('device lock discipline: withDeviceLock wraps ONLY the approval (never a push, fetch or prompt) — source scan', async () => {
  const src = await readFile(new URL('./deviceadd.ts', import.meta.url), 'utf8');
  const code = src.split('\n').filter((l) => !l.trim().startsWith('*') && !l.trim().startsWith('//')).join('\n');
  const uses = [...code.matchAll(/withDeviceLock\(/g)];
  assert.equal(uses.length, 1);
  const at = code.indexOf('withDeviceLock(');
  const call = code.slice(at, code.indexOf('\n', at));
  assert.ok(call.includes('approveLocked'));
  assert.ok(!/\b(push|fetch|ask|confirm)\(/.test(call));
  assert.ok(!/--force|\+refs|force-with-lease/.test(code), 'no force anywhere');
});
