/** F3b B6 threat suite: TOCTOU between validate and apply / push (S4, T-B3-2, T-B4-6; docs/f3b-b6-plan.md file 2).
 *  Hostile act in a seam of the cycle (a moved scratch ref, a raced local write, a swapped worktree file, a remote
 *  tip that changes before the push) -> the real `runCycle`. The applied bytes are the VALIDATED object, never a
 *  re-read ref or a worktree file. Covered elsewhere: cycle.test.ts:176,196,216,233. */

import assert from 'node:assert/strict';
import { lstat, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { runCycle } from './cycle.ts';
import { REF_INCOMING } from './gitx.ts';
import { hubRawCommit } from './testkit-remote.ts';
import { assertQuarantined, ctx, haltOf, skipSync, snapshot, withRig, type Rig } from './threatkit.ts';

function assertNoForce(argv: readonly (readonly string[])[]): void {
  for (const a of argv.flat()) {
    assert.ok(!/^--force/.test(a) && !/^-[A-Za-z]*f[A-Za-z]*$/.test(a), `force flag in argv: ${a}`);
    if (a.startsWith('+')) assert.match(a, /^\+[A-Za-z0-9._/-]+:refs\/ledger-sync\//, `"+" refspec outside refs/ledger-sync/: ${a}`);
  }
}

const read = (r: Rig, rel: string): Promise<string> => readFile(nodePath.join(r.lh.dir, rel), 'utf8');

async function blobAt(r: Rig, commit: string, path: string): Promise<string> {
  const e = (await r.lh.hub.store.lsTree(commit)).find((x) => x.path === path);
  assert.ok(e !== undefined, `${path} missing in ${commit.slice(0, 7)}`);
  return (await r.lh.hub.store.readObject(e.sha, 'blob')).toString('utf8');
}

test('scratch ref moved to a hostile tip AFTER validation: the applied tree is the validated F, the hostile sha never enters main', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nvalidated\n')]);
    const hostile = await hubRawCommit(r.lh.hub, { parents: [r.fleet.base], files: [{ path: 'acme/link', content: '/etc/passwd', mode: '120000' }], signer: r.other.hub });
    const { deps, host, flaky } = r.mk();
    let swapped = false;
    host.beforeExclusive = async () => {
      // runs after validateRange returned and before the host takes R: the window the apply must not trust the ref in
      swapped = true;
      await r.lh.hub.gitx.mustRun(['update-ref', '--no-deref', REF_INCOMING, hostile], { cwd: r.lh.dir });
    };
    const res = await runCycle(deps);
    assert.ok(swapped, 'fixture: the seam ran');
    assert.equal(res.outcome, 'applied');
    assert.equal(await r.lh.hub.main(), F, 'main is exactly the validated F');
    assert.equal(await r.lh.hub.store.isAncestor(hostile, F), false);
    assert.equal(await r.lh.hub.store.isAncestor(hostile, (await r.lh.hub.main()) as string), false, 'hostile sha is not in main ancestry');
    await assert.rejects(lstat(nodePath.join(r.lh.dir, 'acme', 'link')), /ENOENT/, 'no symlink in the worktree');
    assert.equal(await read(r, 'acme/CONTEXT.md'), '# acme\nvalidated\n');
    assert.equal((await r.lh.state.read()).accepted, F, 'accepted follows the validated tip, not the swapped ref');
    assert.deepEqual(await r.lh.dirty(), []);
    assertNoForce(flaky.argv);
    // the next cycle fetches the real remote again: the scratch ref is simply overwritten, nothing carried over
    assert.equal((await runCycle(r.mk().deps)).outcome, 'up-to-date');
    assert.equal(await r.lh.hub.store.revParse(REF_INCOMING), F);
  });
});

test('local write on a path F changes, raced into the apply: transient, no bytes lost, nothing half-merged', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote edit\n')]);
    const a = r.mk();
    const mine = '# acme\nMY UNCOMMITTED WORK\n';
    a.host.beforeFn = async () => {
      a.host.beforeFn = null;
      await writeFile(nodePath.join(r.lh.dir, 'acme', 'CONTEXT.md'), mine);
    };
    const before = await snapshot(r.lh);
    const res = await runCycle(a.deps);
    assert.match(res.outcome, /^transient:/, `outcome ${res.outcome}`);
    assert.notEqual(res.applied, true);
    assert.equal(await read(r, 'acme/CONTEXT.md'), mine, 'the raced write survived byte for byte');
    assert.equal(await r.lh.hub.main(), before.main, 'main did not move');
    assert.equal(await r.lh.hub.store.revParse('refs/ledger-sync/accepted'), before.accepted);
    assert.equal((await haltOf(r.lh)), null, 'a local race is never a halt');
    assert.equal(a.flaky.pushCalls, 0);
    assert.deepEqual(a.host.violations, []);
    // still dirty next time, same answer, same bytes
    const b = r.mk();
    assert.match((await runCycle(b.deps)).outcome, /^transient:/);
    assert.equal(await read(r, 'acme/CONTEXT.md'), mine);
  });
});

test('worktree devices.yml swapped for a hostile file in the apply window: the merge input is the OBJECT, the hostile bytes never reach main or the remote', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const marker = 'toctou-marker-9f3a';
    const hostileYml = `${r.fleet.devicesText}# ${marker}\n`;
    const F = await r.kit.remote.pushSigned(r.other.hub, [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }]);
    const L = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# decisions\n' }]);
    // honest host: the dirty worktree is held, nothing is merged, the swapped file is not lost
    const honest = r.mk();
    honest.host.beforeFn = async () => {
      honest.host.beforeFn = null;
      await writeFile(nodePath.join(r.lh.dir, 'devices.yml'), hostileYml);
    };
    const res = await runCycle(honest.deps);
    assert.match(res.outcome, /^transient:/);
    assert.equal(await r.lh.hub.main(), L);
    assert.equal(await read(r, 'devices.yml'), hostileYml, 'no bytes lost');
    assert.equal(await r.kit.remote.main(), F, 'nothing was pushed');
    // lying host: it claims the tree is clean although devices.yml was swapped. The merge still reads objects only.
    const liar = r.mk();
    liar.host.commitOutcome = 'clean';
    const res2 = await runCycle(liar.deps);
    assert.equal(res2.outcome, 'transient:dirty', 'the apply re-checks the worktree itself, whatever the host says');
    assert.equal(await r.lh.hub.main(), L);
    assert.equal(await read(r, 'devices.yml'), hostileYml, 'still no bytes lost');
    const remoteMain = (await r.kit.remote.main()) as string;
    assert.equal(remoteMain, F);
    for (const sha of [L, remoteMain]) assert.ok(!(await blobAt(r, sha, 'devices.yml')).includes(marker), `marker reached ${sha.slice(0, 7)}`);
  });
});

test('tracked file swapped for a symlink to an outside file in the apply window: the apply never writes through it', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const outside = nodePath.join(r.kit.root, 'outside-target');
    await mkdir(outside, { recursive: true });
    const victim = nodePath.join(outside, 'victim.txt');
    await writeFile(victim, 'OUTSIDE BYTES\n');
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote edit\n')]);
    const a = r.mk();
    a.host.commitOutcome = 'clean'; // a host that lets the apply proceed over a swapped worktree
    a.host.beforeFn = async () => {
      a.host.beforeFn = null;
      await rm(nodePath.join(r.lh.dir, 'acme', 'CONTEXT.md'), { force: true });
      await symlink(victim, nodePath.join(r.lh.dir, 'acme', 'CONTEXT.md'));
    };
    const res = await runCycle(a.deps);
    assert.equal(res.outcome, 'transient:dirty');
    assert.equal(await readFile(victim, 'utf8'), 'OUTSIDE BYTES\n', 'the apply wrote through a swapped symlink');
  });
});

test('remote tip replaced between fetch and push by a quarantinable commit: the push loses, the refetch QUARANTINES it, no force push', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const L = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# decisions\n' }]);
    const { deps, flaky } = r.mk();
    let bad = '';
    flaky.beforePush = async () => {
      flaky.beforePush = null;
      bad = await r.kit.remote.pushSymlink(r.other.hub, 'acme/link', '/etc/passwd');
    };
    const before = await snapshot(r.lh);
    const res = await runCycle(deps);
    assert.ok(bad !== '', 'fixture: the remote moved before the push');
    await assertQuarantined(r.lh, res, /^quarantine:tree:symlink$/, { tip: bad });
    assert.equal(res.refetches, 1);
    assert.equal(flaky.pushCalls, 1, 'the one push git rejected; no second attempt over the hostile tip');
    assert.equal(await r.kit.remote.main(), bad, 'we did not overwrite the remote');
    assert.equal(await r.lh.hub.main(), L);
    assert.equal(await r.lh.hub.main(), before.main);
    await assert.rejects(lstat(nodePath.join(r.lh.dir, 'acme', 'link')), /ENOENT/);
    assert.deepEqual(await r.lh.dirty(), []);
    assertNoForce(flaky.argv);
    assert.ok(flaky.argv.some((a) => a[0] === 'push'));
  });
});
