/** F3b B6 threat suite: resource exhaustion (S6-8, T-B3-7, T-B4-7, master risk 5; docs/f3b-b6-plan.md file 3).
 *  A hostile remote tries to make the hub burn CPU / disk / log space or trade commits forever; the real `runCycle`
 *  (and, for the schedule, the real `SyncLoop`) must answer with a bounded, quiet, one-line reaction. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { runCycle } from './cycle.ts';
import { SyncLoop, type LoopClock } from './loop.ts';
import { fakeHost, type TestRemote } from './testkit-remote.ts';
import { assertQuarantined, assertUntouched, ctx, item, skipSync, snapshot, withRig, type Rig } from './threatkit.ts';

/** `n` empty commits on top of `from`, main moved onto the last one: one `git fast-import` process, not 2000 spawns.
 *  Test-only plumbing straight into the bare remote (the hostile side). Returns the new tip. */
async function floodCommits(remote: TestRemote, from: string, n: number): Promise<string> {
  let stream = '';
  for (let i = 0; i < n; i += 1) {
    const msg = `flood ${String(i)}\n`;
    stream += `commit refs/heads/main\ncommitter flood <flood@devices.agent-ledger.invalid> ${String(1_700_000_000 + i)} +0000\ndata ${String(Buffer.byteLength(msg))}\n${msg}${i === 0 ? `from ${from}\n` : ''}\n`;
  }
  await new Promise<void>((resolve, reject) => {
    const p = spawn('git', ['fast-import', '--quiet', '--force'], {
      cwd: remote.path,
      env: { PATH: process.env.PATH ?? '', HOME: remote.path, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' },
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    let err = '';
    p.stderr.on('data', (d: Buffer) => {
      err += d.toString('utf8');
    });
    p.on('error', reject);
    p.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`fast-import failed (${String(code)}): ${err.slice(0, 200)}`))));
    p.stdin.end(stream);
  });
  const tip = await remote.main();
  assert.ok(tip !== null);
  return tip;
}

const count = (argv: readonly (readonly string[])[], sub: string): number => argv.filter((a) => a[0] === sub).length;

async function remoteCommitCount(r: Rig): Promise<number> {
  const out = await r.kit.remote.gitx.mustRun(['rev-list', '--count', 'refs/heads/main'], { cwd: r.kit.remote.path });
  return Number(out.stdout.toString('utf8').trim());
}

test('2001-commit range: quarantine oversize, bounded work, the same tip is not read again', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const flood = await floodCommits(r.kit.remote, r.fleet.base, 2001);
    const before = await snapshot(r.lh);
    const a = r.mk();
    const t0 = performance.now();
    const res = await runCycle(a.deps);
    const ms = performance.now() - t0;
    await assertQuarantined(r.lh, res, /^quarantine:oversize$/, { tip: flood, before, flaky: a.flaky });
    assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
    assert.ok(ms < 15_000, `oversize range took ${String(Math.round(ms))} ms`);
    // bounded: one rev-list capped by --max-count, never one cat-file per commit
    assert.equal(count(a.flaky.argv, 'rev-list') >= 1, true);
    const cat = count(a.flaky.argv, 'cat-file');
    assert.ok(cat < 50, `a refused range was read object by object (${String(cat)} cat-file calls)`);
    assert.ok(a.flaky.argv.some((x) => x[0] === 'rev-list' && x.some((y) => /^--max-count=\d+$/.test(y))), 'rev-list is capped');
    // second cycle: fetch only (the tip is the same), no validation work at all
    const b = r.mk();
    const again = await runCycle(b.deps);
    assert.equal(again.outcome, 'halted-same-tip');
    assert.equal(b.flaky.fetchCalls, 1);
    for (const sub of ['rev-list', 'cat-file', 'ls-tree', 'log', 'diff-tree']) assert.equal(count(b.flaky.argv, sub), 0, `second cycle ran ${sub}`);
    assert.equal(b.flaky.pushCalls, 0);
    // exactly 2000 commits is the largest honest range: nothing here proves it, the unit test does (validate.test.ts)
  });
});

test('oversize blobs: a > 5 MB file and a > 256 KB item are quarantined, the worktree is untouched', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const big = `# acme — journal 2026-11\n${`${'a'.repeat(99)}\n`.repeat(55_000)}`; // ~5.5 MB, every line short
    assert.ok(Buffer.byteLength(big) > 5 * 1024 * 1024);
    const cases: { name: string; files: { path: string; content: string }[] }[] = [
      { name: '5 MB journal', files: [{ path: 'acme/journal/2026-11.md', content: big }] },
      { name: '300 KB item', files: [{ path: 'acme/items/OPS-1.md', content: `${item('OPS-1', 'huge')}${`${'b'.repeat(99)}\n`.repeat(3100)}` }] },
    ];
    for (const c of cases) {
      const before = await snapshot(r.lh);
      const bad = await r.kit.remote.pushSigned(r.other.hub, c.files);
      const a = r.mk();
      const res = await runCycle(a.deps);
      await assertQuarantined(r.lh, res, /^quarantine:/, { tip: bad, before, flaky: a.flaky });
      assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
      assert.equal((await runCycle(r.mk().deps)).outcome, 'halted-same-tip', c.name);
      // an honest descendant of the SAME base clears the quarantine (the hostile tip was a probe halt, not a lockout)
      const fix = await r.kit.remote.rawCommit({ parents: [(await r.lh.hub.main()) as string], files: [ctx(`# acme\nfixed after ${c.name}\n`)], signer: r.other.hub });
      assert.equal((await runCycle(r.mk().deps)).outcome, 'applied', c.name);
      assert.equal(await r.lh.hub.main(), fix);
    }
  });
});

test('ping-pong: two warn-mode hubs with local work and an unsigned remote commit settle; the commit count stops growing', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushUnsigned([ctx('# acme\nunsigned remote\n')]);
    await r.hubOf(0).commitLocal([{ path: 'acme/DECISIONS.md', content: '# a decisions\n' }]);
    await r.hubOf(1).commitLocal([{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }]);
    const hosts = [fakeHost(r.hubOf(0)), fakeHost(r.hubOf(1))];
    const counts: number[] = [];
    const outcomes: string[] = [];
    for (let i = 0; i < 6; i += 1) {
      const who = i % 2;
      const { deps } = r.mk(who, { verify: 'warn', host: hosts[who] as ReturnType<typeof fakeHost> });
      outcomes.push((await runCycle(deps)).outcome);
      counts.push(await remoteCommitCount(r));
    }
    // base + unsigned + 2 local + at most 2 merges
    assert.ok((counts.at(-1) as number) <= 6, `commit count ${counts.join(',')}`);
    assert.equal(counts[5], counts[3], `still growing: ${counts.join(',')} (${outcomes.join(',')})`);
    assert.equal(counts[4], counts[3]);
    // everyone converged, and one more round changes nothing
    for (const who of [0, 1, 0, 1]) {
      const { deps } = r.mk(who, { verify: 'warn', host: hosts[who] as ReturnType<typeof fakeHost> });
      const res = await runCycle(deps);
      assert.equal(res.outcome, 'up-to-date', `hub ${String(who)}: ${res.outcome}`);
    }
    const tip = await r.kit.remote.main();
    assert.equal(await r.hubOf(0).hub.main(), tip);
    assert.equal(await r.hubOf(1).hub.main(), tip);
    assert.equal(await remoteCommitCount(r), counts[5]);
    // warn notes are local lines at most: <= 1 per (rule, device) per hub, never commits
    for (const h of hosts) assert.ok(h.localNotes.flat().length <= 2, `notes: ${JSON.stringify(h.localNotes)}`);
  });
});

/** A clock for `SyncLoop` that only moves when told (loop.test.ts has the full fake; this is the 10-line one). */
function manualClock(t0: number): LoopClock & { set(t: number): void } {
  let t = t0;
  return {
    now: () => t,
    setTimeout: () => null,
    clearTimeout: () => undefined,
    set: (x) => {
      t = x;
    },
  };
}

async function idle(loop: SyncLoop): Promise<void> {
  for (let i = 0; i < 400; i += 1) {
    if (!(await loop.status()).running) return;
    await new Promise((res) => setTimeout(res, 5));
  }
  throw new Error('loop did not go idle');
}

test('a push that is rejected forever: exactly 3 refetches per cycle, then a growing backoff the loop respects', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    await r.lh.commitLocal([ctx('# acme\nlocal\n')]);
    const T0 = Date.parse('2026-11-17T10:00:00.000Z');
    const clock = manualClock(T0);
    const rejected = { stderr: '! refs/heads/main:refs/heads/main [rejected] (non-fast-forward)', code: 1 };
    const { deps, flaky } = r.mk(0, { now: () => new Date(clock.now()) });
    flaky.failNext('push', rejected, 200);
    const loop = new SyncLoop({ deps, intervalMs: 60_000, clock, cycle: runCycle });
    const expectMs = [30_000, 60_000, 120_000, 240_000, 480_000]; // rnd = 0.5 -> exactly the base
    for (let n = 1; n <= expectMs.length; n += 1) {
      const pushes = flaky.pushCalls;
      const fetches = flaky.fetchCalls;
      loop.trigger('tick');
      await idle(loop);
      assert.equal(flaky.pushCalls - pushes, 3, `cycle ${String(n)}: pushes`);
      assert.equal(flaky.fetchCalls - fetches, 3, `cycle ${String(n)}: refetches`);
      const st = await r.lh.state.read();
      assert.equal(st.backoff.failures, n);
      assert.equal(st.backoff.lastError, 'push-rejected');
      assert.equal(st.halt, null, 'a lost race is never a halt');
      assert.equal(Date.parse(st.backoff.nextAt as string) - clock.now(), expectMs[n - 1], `cycle ${String(n)}: backoff`);
      // inside the window the loop makes NO contact at all (a hostile peer cannot make us spin)
      clock.set(clock.now() + (expectMs[n - 1] as number) - 1000);
      const calls = flaky.fetchCalls + flaky.pushCalls;
      loop.trigger('tick');
      await idle(loop);
      assert.equal(flaky.fetchCalls + flaky.pushCalls, calls, `cycle ${String(n)}: contact inside the backoff window`);
      clock.set(clock.now() + 2000); // past nextAt
    }
    assert.equal(await r.kit.remote.main(), r.fleet.base, 'nothing ever landed');
    assert.ok(!flaky.argv.flat().some((a) => a === '--force' || a === '-f'));
  });
});

test('one quarantined tip over 5 cycles: ONE local note; a new tip with the same rule inside 24 h adds none; after 24 h one more', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const host = fakeHost(r.lh);
    let now = Date.parse('2026-11-17T10:00:00.000Z');
    const run = async (): ReturnType<typeof runCycle> => runCycle(r.mk(0, { host, now: () => new Date(now) }).deps);
    const bad1 = await r.kit.remote.pushSymlink(r.other.hub, 'acme/link', '/etc/passwd');
    const first = await run();
    await assertQuarantined(r.lh, first, /^quarantine:tree:symlink$/, { tip: bad1 });
    for (let i = 0; i < 4; i += 1) assert.equal((await run()).outcome, 'halted-same-tip');
    const notes = (): { type: string; rule: string }[] => host.localNotes.flat();
    assert.equal(notes().length, 1, `notes after 5 cycles: ${JSON.stringify(notes())}`);
    assert.equal(notes()[0]?.type, 'sync.reject');
    // a second hostile tip, same rule, same day: re-quarantined, but no second line
    const bad2 = await r.kit.remote.pushSymlink(r.other.hub, 'acme/link2', '/etc/shadow');
    await assertQuarantined(r.lh, await run(), /^quarantine:tree:symlink$/, { tip: bad2 });
    assert.equal(notes().length, 1);
    // a day later the rule may speak once more
    now += 25 * 3600 * 1000;
    const bad3 = await r.kit.remote.pushSymlink(r.other.hub, 'acme/link3', '/etc/hosts');
    await assertQuarantined(r.lh, await run(), /^quarantine:tree:symlink$/, { tip: bad3 });
    assert.equal(notes().length, 2);
    // a clock that jumps BACK by an hour still rate-limits (|now - noted| window), it does not reopen the floodgate
    now -= 3600 * 1000;
    const bad4 = await r.kit.remote.pushSymlink(r.other.hub, 'acme/link4', '/etc/group');
    await assertQuarantined(r.lh, await run(), /^quarantine:tree:symlink$/, { tip: bad4 });
    assert.equal(notes().length, 2, `notes after a backwards clock: ${String(notes().length)}`);
  });
});

test.todo('object growth cap (50 MB) before validation: a fetch that stores gigabytes of unreachable-from-main objects is not bounded yet (production gap, master risk 5)');
