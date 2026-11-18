/** F3b B6 threat suite: rollback / history rewrite (S1-3, T-B3-1; docs/f3b-b6-plan.md file 1). END-TO-END: a hostile
 *  or lossy remote -> the real `runCycle` -> nothing moved, nothing re-seeded, nothing force-pushed. The rule logic is
 *  covered at unit level (cycle.test.ts:269,400,424,526); this file proves the cycle holds under the odd sequences. */

import assert from 'node:assert/strict';
import { rm } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { runCycle } from './cycle.ts';
import { REF_ACCEPTED, REF_INCOMING, REF_MAIN } from './gitx.ts';
import { PINNED_GITATTRIBUTES, PINNED_GITIGNORE } from './testkit-remote.ts';
import { assertUntouched, ctx, haltOf, skipSync, snapshot, withRig, type Rig } from './threatkit.ts';

/** invariant 2: no `--force` / `-f`, no `+` refspec unless its destination is a `refs/ledger-sync/` scratch ref. */
function assertNoForce(argv: readonly (readonly string[])[]): void {
  assert.ok(argv.length > 0, 'no argv recorded');
  for (const a of argv.flat()) {
    assert.ok(!/^--force/.test(a) && !/^-[A-Za-z]*f[A-Za-z]*$/.test(a), `force flag in argv: ${a}`);
    if (a.startsWith('+')) assert.match(a, /^\+[A-Za-z0-9._/-]+:refs\/ledger-sync\//, `"+" refspec outside refs/ledger-sync/: ${a}`);
    assert.ok(!/:\+/.test(a), `"+" in a destination: ${a}`);
  }
}

const refOf = async (r: Rig, ref: string): Promise<string | null> => r.lh.hub.store.revParse(ref);

/** Hub 0 has applied one honest remote commit; returns it. */
async function applyOne(r: Rig): Promise<string> {
  const F1 = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\none\n')]);
  assert.equal((await runCycle(r.mk().deps)).outcome, 'applied');
  assert.equal(await refOf(r, REF_ACCEPTED), F1);
  return F1;
}

test('rollback to an ancestor of accepted: HALT history-rewrite on EVERY cycle, local commit kept and never pushed over it', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const F1 = await applyOne(r);
    const L = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# local work\n' }]);
    await r.kit.remote.forceMain(r.fleet.base); // the hostile rollback: remote main is now an ANCESTOR of accepted
    const before = await snapshot(r.lh);
    const all: string[][] = [];
    for (let i = 0; i < 3; i += 1) {
      const { deps, flaky } = r.mk();
      const res = await runCycle(deps);
      all.push(...flaky.argv);
      assert.equal(res.halted, 'history-rewrite', `cycle ${String(i)}`);
      assert.equal(res.outcome, 'halt:history-rewrite');
      assert.equal(flaky.pushCalls, 0, 'a rolled-back remote must never be pushed to (L would fast-forward it)');
      const h = await haltOf(r.lh);
      assert.equal(h?.reason, 'history-rewrite');
      assert.equal(h?.cls, 'sticky');
      assert.equal(h?.tip, r.fleet.base);
    }
    assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
    assert.equal(await r.lh.hub.main(), L, 'local commits are kept');
    assert.equal(await refOf(r, REF_ACCEPTED), F1, 'accepted did not move backwards');
    assert.equal(await r.kit.remote.main(), r.fleet.base, 'the remote was not repaired by us');
    assertNoForce(all);
    // the history-rewrite halt does not touch the network class: it stays sticky, never "cleared" by a failing probe
    assert.equal((await r.lh.state.read()).halt?.cls, 'sticky');
  });
});

test('signed rewrite by a TRUSTED hub with an IDENTICAL tree is still a history-rewrite HALT (no signature or tree equality excuses it)', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const sameTree = [
      { path: '.gitignore', content: PINNED_GITIGNORE },
      { path: '.gitattributes', content: PINNED_GITATTRIBUTES },
      { path: 'ledger.format', content: '2\n' },
      { path: 'devices.yml', content: r.fleet.devicesText },
      { path: 'acme/CONTEXT.md', content: '# acme\n' },
    ];
    const rewritten = await r.kit.remote.rewriteHistory(r.other.hub, sameTree);
    const tree = async (sha: string): Promise<string> => (await r.kit.remote.gitx.mustRun(['rev-parse', `${sha}^{tree}`], { cwd: r.kit.remote.path })).stdout.toString('utf8').trim();
    assert.equal(await tree(rewritten), await tree(r.fleet.base), 'fixture: the rewritten root has the same tree as base');
    assert.notEqual(rewritten, r.fleet.base);
    const before = await snapshot(r.lh);
    const { deps, flaky } = r.mk();
    const res = await runCycle(deps);
    assert.equal(res.halted, 'history-rewrite');
    assert.equal((await haltOf(r.lh))?.tip, rewritten);
    assert.equal(flaky.pushCalls, 0);
    assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
    assertNoForce(flaky.argv);
  });
});

test('remote DROPS an accepted push: the next fetch lacks accepted -> HALT history-rewrite, local commits kept, no re-push', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const L = await r.lh.commitLocal([ctx('# acme\nlocal\n')]);
    const first = r.mk();
    assert.equal((await runCycle(first.deps)).outcome, 'pushed');
    assert.equal(await r.kit.remote.main(), L);
    assert.equal(await refOf(r, REF_ACCEPTED), L, 'accepted advanced with the push');
    await r.kit.remote.forceMain(r.fleet.base); // the remote loses the accepted push (restore from backup, hostile reset)
    const L2 = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# more local work\n' }]);
    const before = await snapshot(r.lh);
    const { deps, flaky } = r.mk();
    const res = await runCycle(deps);
    assert.equal(res.halted, 'history-rewrite');
    assert.equal(flaky.pushCalls, 0);
    assert.equal(await r.kit.remote.main(), r.fleet.base, 'we did not "heal" the remote');
    assert.equal(await r.lh.hub.main(), L2, 'both local commits are kept');
    assert.equal(await refOf(r, REF_ACCEPTED), L);
    assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
    assertNoForce([...first.flaky.argv, ...flaky.argv]);
  });
});

test('accepted ref deleted / moved backwards / mirror ahead of the ref: HALT config, the ref is never re-seeded, no contact', { skip: skipSync }, async () => {
  type Tamper = { name: string; run: (r: Rig, F1: string) => Promise<void>; expectRef: (r: Rig, F1: string) => string | null };
  const cases: Tamper[] = [
    {
      name: 'deleted',
      run: async (r) => {
        await rm(nodePath.join(r.lh.dir, '.git', 'refs', 'ledger-sync', 'accepted'), { force: true });
      },
      expectRef: () => null,
    },
    {
      name: 'moved backwards (mirror ahead)',
      run: async (r, F1) => {
        await r.lh.hub.gitx.mustRun(['update-ref', '--no-deref', REF_ACCEPTED, r.fleet.base, F1], { cwd: r.lh.dir });
      },
      expectRef: (r) => r.fleet.base,
    },
    {
      name: 'mirror names an object we never had',
      run: async (r) => {
        await r.lh.state.update((s) => {
          s.accepted = 'b'.repeat(40);
        });
      },
      expectRef: (_r, F1) => F1,
    },
  ];
  for (const c of cases) {
    await withRig(2, async (r) => {
      const F1 = await applyOne(r);
      await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\ntwo\n')]); // something to apply, were it not halted
      await c.run(r, F1);
      const mainBefore = await r.lh.hub.main();
      const used = r.mk();
      for (let i = 0; i < 2; i += 1) {
        const res = await runCycle(used.deps);
        assert.equal(res.halted, 'config', `${c.name}: cycle ${String(i)}`);
        assert.equal((await haltOf(r.lh))?.cls, 'local');
      }
      assert.equal(used.flaky.fetchCalls, 0, `${c.name}: a config halt contacts nobody`);
      assert.equal(used.flaky.pushCalls, 0);
      assert.equal(await refOf(r, REF_ACCEPTED), c.expectRef(r, F1), `${c.name}: the accepted ref was re-seeded`);
      assert.equal(await r.lh.hub.main(), mainBefore, `${c.name}: main moved`);
      assertNoForce(used.flaky.argv.length === 0 ? [['(no git call)']] : used.flaky.argv);
    });
  }
});

test('git argv audit across a mixed history (FF, merge + push, lost push race, rollback): no force flag, only scratch-ref "+" refspecs', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const argv: string[][] = [];
    const run = async (over: Parameters<Rig['mk']>[1] = {}): ReturnType<typeof runCycle> => {
      const { deps, flaky } = r.mk(0, over);
      const res = await runCycle(deps);
      argv.push(...flaky.argv);
      return res;
    };
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]);
    assert.equal((await run()).outcome, 'applied');
    await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# d\n' }]);
    assert.equal((await run()).outcome, 'pushed');
    // a lost race: the remote moves after our fetch, the push is rejected by git (no force), the refetch merges
    await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# d2\n' }]);
    const raced = r.mk();
    let moved = false;
    raced.flaky.afterFetch = async () => {
      if (moved) return;
      moved = true;
      const tip = (await r.kit.remote.main()) as string;
      await r.kit.remote.rawCommit({ parents: [tip], files: [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }], signer: r.other.hub });
    };
    const res = await runCycle(raced.deps);
    argv.push(...raced.flaky.argv);
    assert.equal(res.outcome, 'pushed');
    assert.equal(res.refetches, 1);
    await r.kit.remote.forceMain(r.fleet.base);
    assert.equal((await run()).halted, 'history-rewrite');
    assertNoForce(argv);
    const pushes = argv.filter((a) => a[0] === 'push');
    assert.ok(pushes.length >= 3, `expected the pushes to be recorded, got ${String(pushes.length)}`);
    for (const p of pushes) assert.ok(p.includes('--no-verify') && p.some((a) => a.endsWith(`:${REF_MAIN}`)), 'push shape: <sha>:refs/heads/main');
    const fetches = argv.filter((a) => a[0] === 'fetch');
    assert.ok(fetches.length >= 4);
    for (const f of fetches) assert.ok(f.includes(`+${REF_MAIN}:${REF_INCOMING}`), 'fetch shape: +refs/heads/main:refs/ledger-sync/incoming');
  });
});
