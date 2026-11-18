/** F3b B6 threat suite: egress (S26, inv 12; docs/f3b-b6-plan.md file 11). The hub must never push a range its own
 *  ingress would reject, and with sync on the ONLY push is `Gitx.push` from the sync cycle. A hostile local commit
 *  (a buggy tool, a compromised agent writing into the ledger) is put into local history with plumbing, then the
 *  real `runCycle` runs: nothing may reach the remote, local work must go on. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { git } from '../git.ts';
import { Ledger } from '../ledger/ledger.ts';
import { tempConfig } from '../test-helpers.ts';
import { runCycle } from './cycle.ts';
import { hubRawCommit, makeKit, type RawFile } from './testkit-remote.ts';
import { ctx, haltOf, skipSync, withRig, type Rig } from './threatkit.ts';

function assertNoForce(argv: readonly (readonly string[])[]): void {
  for (const a of argv.flat()) {
    assert.ok(!/^--force/.test(a) && !/^-[A-Za-z]*f[A-Za-z]*$/.test(a), `force flag in argv: ${a}`);
    if (a.startsWith('+')) assert.match(a, /^\+[A-Za-z0-9._/-]+:refs\/ledger-sync\//, `"+" refspec outside refs/ledger-sync/: ${a}`);
  }
}

/** A signed local commit built with plumbing (anything git accepts) and adopted as `main`, index and worktree. */
async function hostileLocal(r: Rig, files: readonly RawFile[], o: { signed?: boolean } = {}): Promise<string> {
  const hub = r.lh.hub;
  const sha = await hubRawCommit(hub, { files, signer: o.signed === false ? null : hub, identity: hub.identity, message: 'hostile local commit' });
  await r.lh.adopt(sha);
  return sha;
}

// built from parts so this file itself is not a secret-scanner hit
const PEM = `-----BEGIN ${'OPENSSH'} PRIVATE KEY-----\n${'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQ'}\n-----END ${'OPENSSH'} PRIVATE KEY-----\n`;
const TOKEN = `ghp_${'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'}`;

/** `inbound: false`: the hostile worktree itself is dirty (a `.gitignore` without `.hub/` makes `.hub/` untracked), so the
 *  host holds the apply: that is the correct answer, not what this row is about. */
const HOSTILE: readonly { name: string; files: RawFile[]; rule: RegExp; inbound?: boolean }[] = [
  { name: 'symlink', files: [{ path: 'acme/link', content: '/etc/passwd', mode: '120000' }], rule: /symlink/ },
  { name: 'exec bit', files: [{ path: 'acme/CONTEXT.md', content: '# acme\nexec\n', mode: '100755' }], rule: /exec|mode/ },
  { name: '.hub/x', files: [{ path: '.hub/x', content: 'x\n' }], rule: /hub/ },
  { name: 'pinned .gitignore changed', files: [{ path: '.gitignore', content: '*.tmp\n' }], rule: /gitignore|pinned/, inbound: false },
  { name: 'pinned .gitattributes driver', files: [{ path: '.gitattributes', content: '* filter=evil\n' }], rule: /gitattributes|pinned|driver/ },
  { name: 'ledger.format out of range', files: [{ path: 'ledger.format', content: '99\n' }], rule: /format/ },
  { name: 'private key in DECISIONS.md', files: [{ path: 'acme/DECISIONS.md', content: `# d\n${PEM}` }], rule: /secret/ },
  { name: 'token in CONTEXT.md', files: [{ path: 'acme/CONTEXT.md', content: `# acme\n${TOKEN}\n` }], rule: /secret/ },
];

test('every hostile LOCAL commit is push-blocked: no push, remote unchanged, local work continues, stacking does not launder it', { skip: skipSync }, async () => {
  for (const c of HOSTILE) {
    await withRig(2, async (r) => {
      const bad = await hostileLocal(r, c.files);
      const a = r.mk();
      const res = await runCycle(a.deps);
      const tag = `[${c.name}]`;
      assert.equal(res.outcome, 'push-blocked', `${tag} outcome ${res.outcome}`);
      assert.equal(a.flaky.pushCalls, 0, `${tag} a push was attempted`);
      assert.equal(await r.kit.remote.main(), r.fleet.base, `${tag} remote moved`);
      const st = await r.lh.state.read();
      assert.ok(st.pushBlocked !== null, `${tag} pushBlocked missing`);
      assert.match(st.pushBlocked.rule, c.rule, `${tag} rule ${st.pushBlocked.rule}`);
      assert.equal(st.pushBlocked.tip, bad);
      assert.equal(st.halt, null, `${tag} egress is not a halt: local work and inbound sync go on`);
      assert.equal(await r.lh.hub.main(), bad, `${tag} local main must not be rewritten`);
      assertNoForce(a.flaky.argv);
      // local work goes on: a new honest commit on top is still blocked (it carries the hostile one), still no push
      const L2 = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# honest\n' }]);
      const b = r.mk();
      const res2 = await runCycle(b.deps);
      assert.equal(res2.outcome, 'push-blocked', `${tag} stacking: ${res2.outcome}`);
      assert.equal(b.flaky.pushCalls, 0, `${tag} stacking pushed`);
      assert.equal(await r.kit.remote.main(), r.fleet.base);
      assert.equal((await r.lh.state.read()).pushBlocked?.tip, L2);
      if (c.inbound === false) return;
      // inbound sync still works while the push is blocked (the remote's honest commit is merged, not refused)
      const F = await r.kit.remote.pushSigned(r.other.hub, [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }]);
      const d = r.mk();
      const res3 = await runCycle(d.deps);
      assert.equal(res3.outcome, 'push-blocked', `${tag} inbound: ${res3.outcome}`);
      assert.equal(res3.applied, true, `${tag} the honest remote commit was not applied`);
      assert.equal(d.flaky.pushCalls, 0);
      assert.equal(await r.kit.remote.main(), F);
      assert.equal(await haltOf(r.lh), null);
    });
  }
});

test('an UNSIGNED local commit in sync mode is never pushed', { skip: skipSync, todo: 'PRODUCTION GAP: egressSelfCheck (validate.ts:485) checks content rules only; it never checks that A..L is signed, so a hostile/odd unsigned local commit IS pushed (enforce-mode peers then quarantine it). Repro: this test.' }, async () => {
  await withRig(2, async (r) => {
    const unsigned = await hostileLocal(r, [ctx('# acme\nunsigned local\n')], { signed: false });
    const a = r.mk();
    const res = await runCycle(a.deps);
    assert.equal(a.flaky.pushCalls, 0, `an unsigned local commit was pushed (outcome ${res.outcome}); enforce-mode peers will quarantine it`);
    assert.equal(await r.kit.remote.main(), r.fleet.base);
    assert.equal(await r.lh.hub.main(), unsigned);
  });
});

test('ledger.format DOWNGRADE in a local commit is push-blocked (the hub rejects the same commit on ingress)', { skip: skipSync, todo: 'PRODUCTION GAP: egressSelfCheck passes no baseFormat to validateIncoming (validate.ts:506), so a local 2 -> 1 downgrade is not an egress hit although the hub quarantines the same commit on ingress (ingress.ts:346). Repro: this test.' }, async () => {
  await withRig(2, async (r) => {
    await hostileLocal(r, [{ path: 'ledger.format', content: '1\n' }]);
    const a = r.mk();
    const res = await runCycle(a.deps);
    assert.equal(a.flaky.pushCalls, 0, `a format downgrade was pushed (outcome ${res.outcome})`);
    assert.equal(await r.kit.remote.main(), r.fleet.base);
  });
});

test('sync on: the legacy `git push origin HEAD` path spawns nothing (real Ledger, a real `origin`, push enabled)', { skip: skipSync }, async () => {
  const kit = await makeKit();
  const tmp = await tempConfig({ sync: true, push: true, pushIntervalMs: 0, commitDebounceMs: 3_600_000 });
  const logs: string[] = [];
  const ledger = new Ledger({ config: tmp.config, log: (l) => logs.push(l) });
  try {
    await ledger.init();
    const add = await git(tmp.dir, ['remote', 'add', 'origin', kit.remote.path]);
    assert.equal(add.code, 0, add.stderr);
    assert.equal((await kit.remote.main()), null);
    await ledger.createItem({ repo: 'ops', title: 'egress item', kind: 'BACKLOG', priority: 'P2', owner: 'agent', steps: [], blocked_by: [], aliases: [], proposed: false });
    await ledger.git.flush();
    await ledger.git.flush();
    const refs = await kit.remote.gitx.mustRun(['for-each-ref'], { cwd: kit.remote.path });
    assert.equal(refs.stdout.toString('utf8').trim(), '', 'the legacy path pushed to origin');
    assert.equal(ledger.git.status.lastPushAt, null);
    assert.equal(logs.filter((l) => /legacy push disabled/.test(l)).length, 1, 'one explanatory line, no push');
  } finally {
    await ledger.close().catch(() => undefined);
    await tmp.cleanup();
    await kit.cleanup();
  }
});
