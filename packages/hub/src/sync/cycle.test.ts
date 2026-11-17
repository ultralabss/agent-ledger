/** The sync cycle end to end against a local bare remote (docs/f3b-b3-plan.md §1.4, §4, §6; T-B3-1..11).
 *  Real git, real ssh-keygen signatures, a fake `Ledger` host (R/Q ordering is asserted by the fake). */

import assert from 'node:assert/strict';
import { appendFile, readFile, rm, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { itemFrontmatterSchema, newItemDoc, parseDevicesYaml, renderDevicesYaml, serializeMd } from '@agent-ledger/shared';
import { CrashError } from './apply.ts';
import { classifyNetError, runCycle, type CycleDeps } from './cycle.ts';
import { REF_ACCEPTED, REF_MAIN, type GitxResult } from './gitx.ts';
import { ObjectStore } from './objects.ts';
import { splitCommit } from './sigverify.ts';
import { TreeBuilder } from './treebuild.ts';
import { cycleDeps, fakeHost, flakyRemote, makeFleet, makeKit, type FakeHost, type FlakyRemote, type Fleet, type Kit, type LedgerHub } from './testkit-remote.ts';

const posix = process.platform !== 'win32';

interface Rig {
  kit: Kit;
  fleet: Fleet;
  lh: LedgerHub;
  other: LedgerHub;
  hubOf(i: number): LedgerHub;
  /** Deps for hub `i` (default 0) with a scripted remote and a fake host. */
  mk(i?: number, over?: Partial<CycleDeps>): { deps: CycleDeps; flaky: FlakyRemote; host: FakeHost };
}

async function withRig<T>(n: number, fn: (r: Rig) => Promise<T>, extra: { path: string; content: string }[] = []): Promise<T> {
  const kit = await makeKit();
  try {
    const fleet = await makeFleet(kit, n, extra);
    const hubOf = (i: number): LedgerHub => fleet.hubs[i] as LedgerHub;
    const rig: Rig = {
      kit,
      fleet,
      lh: hubOf(0),
      other: hubOf(1),
      hubOf,
      mk(i = 0, over = {}) {
        const lh = hubOf(i);
        const flaky = flakyRemote(lh.hub.gitx);
        const host = (over.host as FakeHost | undefined) ?? fakeHost(lh);
        const deps = cycleDeps(lh, kit, {
          gitx: flaky.gitx,
          store: new ObjectStore(flaky.gitx, lh.dir),
          trees: new TreeBuilder(flaky.gitx, lh.dir, nodePath.join(lh.hub.syncDir, 'tmp')),
          host,
          ...over,
        });
        return { deps, flaky, host };
      },
    };
    return await fn(rig);
  } finally {
    await kit.cleanup();
  }
}

const ctx = (text: string): { path: string; content: string } => ({ path: 'acme/CONTEXT.md', content: text });
const ref = (lh: LedgerHub, name: string): Promise<string | null> => lh.hub.store.revParse(name);
async function parentsOf(lh: LedgerHub, sha: string): Promise<string[]> {
  return splitCommit(await lh.hub.store.readCommitRaw(sha)).headers?.parents ?? [];
}
const item = (id: string, title = 'a title'): string => {
  const fm = itemFrontmatterSchema.parse({ id, title, status: 'open', kind: 'BACKLOG', priority: 'P2', owner: 'agent', repo: 'acme', created: '2026-11-16T10:00:00.000Z', updated: '2026-11-16T10:00:00.000Z' });
  return serializeMd(newItemDoc(fm as never));
};
const nowIso = (): string => new Date().toISOString().replace(/\.\d+Z$/, '.000Z');

function revoke(f: Fleet, victim: number, by: number): string {
  const file = parseDevicesYaml(f.devicesText);
  const id = (f.hubs[victim] as LedgerHub).hub.deviceId;
  return renderDevicesYaml({ devices: file.devices.map((d) => (d.id === id ? { ...d, revoked: { at: nowIso(), by: (f.hubs[by] as LedgerHub).hub.deviceId, reason: 'lost' } } : d)) });
}

/* ---------------- happy paths ---------------- */

test('FF: remote moved, local did not -> applied, accepted follows, nothing pushed, no extra commit', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote edit\n')]);
    const { deps, flaky, host } = r.mk();
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'applied');
    assert.equal(res.applied, true);
    assert.equal(await r.lh.hub.main(), F, 'FF to exactly the remote commit (no commit made by the cycle)');
    assert.equal(await ref(r.lh, REF_ACCEPTED), F);
    const st = await r.lh.state.read();
    assert.equal(st.accepted, F);
    assert.equal(st.halt, null);
    assert.deepEqual(st.seenSigning, [r.other.hub.deviceId], 'signer feeds the ratchet');
    assert.equal(st.lastCycle?.outcome, 'applied');
    assert.equal(flaky.pushCalls, 0);
    assert.deepEqual(host.violations, []);
    assert.equal(await readFile(nodePath.join(r.lh.dir, 'acme', 'CONTEXT.md'), 'utf8'), '# acme\nremote edit\n');
    assert.deepEqual(await r.lh.dirty(), []);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'up-to-date');
  });
});

test('merge: both sides moved -> merge commit [L,F], signed, pushed, accepted = pushed tip', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }]);
    const L = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# decisions\n' }]);
    const { deps, flaky } = r.mk();
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'pushed');
    const M = (await r.lh.hub.main()) as string;
    assert.deepEqual(await parentsOf(r.lh, M), [L, F]);
    assert.equal(await r.kit.remote.main(), M, 'remote has the merge');
    assert.equal(await ref(r.lh, REF_ACCEPTED), M);
    assert.equal((await r.lh.state.read()).accepted, M);
    assert.equal(flaky.pushCalls, 1);
    assert.deepEqual(await r.lh.dirty(), []);
    // the merge commit verifies with the device key (signing is mandatory)
    const v = await (await import('./sigverify.ts')).verifyCommitSignature(await r.lh.hub.store.readCommitRaw(M), { tmpRoot: nodePath.join(r.lh.hub.syncDir, 'tmp') });
    assert.equal(v.valid, true);
  });
});

test('local-only commits are pushed (nothing to fetch); a second cycle is up to date', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const L = await r.lh.commitLocal([ctx('# acme\nlocal\n')]);
    const res = await runCycle(r.mk().deps);
    assert.equal(res.outcome, 'pushed');
    assert.equal(await r.kit.remote.main(), L);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'up-to-date');
  });
});

test('short-circuit: crash after APPLY (W7) then the next cycle only moves accepted; crash after push (W8)', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote edit\n')]);
    await assert.rejects(runCycle(r.mk(0, { crashAt: (p) => { if (p === 'marker-delete') throw new CrashError(p); } }).deps), CrashError);
    assert.equal(await ref(r.lh, REF_ACCEPTED), r.fleet.base, 'accepted not moved yet');
    assert.equal(await r.lh.hub.main(), F);
    const { deps, flaky } = r.mk();
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'up-to-date');
    assert.equal(await ref(r.lh, REF_ACCEPTED), F, 'W7: CAS A -> F');
    assert.equal(flaky.pushCalls, 0, 'nothing to push');
  });
  await withRig(2, async (r) => {
    const L = await r.lh.commitLocal([ctx('# acme\nlocal\n')]);
    const a = r.mk();
    a.flaky.lieAboutPush = { timedOut: true };
    const res = await runCycle(a.deps);
    assert.equal(res.outcome, 'transient:push-unknown', 'unknown outcome is never retried blindly');
    assert.equal(await r.kit.remote.main(), L, 'the push DID arrive');
    assert.equal(await ref(r.lh, REF_ACCEPTED), r.fleet.base, 'accepted still behind (W8)');
    const next = await runCycle(r.mk().deps);
    assert.equal(next.outcome, 'up-to-date');
    assert.equal(await ref(r.lh, REF_ACCEPTED), L, 'next fetch decides: CAS F -> M');
  });
});

test('push non-ff x3 -> refetch each time, then backoff (state keeps failures, nextAt, lastError token)', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.lh.commitLocal([ctx('# acme\nlocal\n')]);
    const { deps, flaky } = r.mk();
    flaky.failNext('push', { stderr: 'error: failed to push some refs', code: 1 }, 0);
    flaky.failNext('push', { stderr: '! refs/heads/main:refs/heads/main [rejected] (non-fast-forward)', code: 1 }, 3);
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'transient:push-rejected');
    assert.equal(flaky.pushCalls, 3);
    assert.equal(flaky.fetchCalls, 3);
    assert.equal(res.refetches, 3);
    const st = await r.lh.state.read();
    assert.equal(st.backoff.failures, 1);
    assert.notEqual(st.backoff.nextAt, null);
    assert.equal(st.backoff.lastError, 'push-rejected');
    assert.equal(st.halt, null, 'a lost race is never a halt');
  });
});

test('remote moves between fetch and apply: the stale F is applied, the push loses the race, the refetch merges the rest', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F1 = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\none\n')]);
    const { deps, flaky } = r.mk();
    let moved = false;
    flaky.afterFetch = async () => {
      if (moved) return;
      moved = true;
      await r.kit.remote.rawCommit({ parents: [F1], files: [{ path: 'acme/DECISIONS.md', content: '# decisions\n' }], signer: r.other.hub });
    };
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'applied', 'first round applied F1, FF; nothing to push yet');
    // the next cycle sees the moved remote
    const res2 = await runCycle(r.mk().deps);
    assert.equal(res2.outcome, 'applied');
    assert.equal(await readFile(nodePath.join(r.lh.dir, 'acme', 'DECISIONS.md'), 'utf8'), '# decisions\n');
    assert.equal(await r.lh.hub.main(), await r.kit.remote.main());
  });
});

test('REAL non-ff: the remote moves after our fetch, the push is rejected by git, the refetch merges and the retry lands', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const L = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# decisions\n' }]);
    const { deps, flaky } = r.mk();
    let remoteTip = '';
    flaky.afterFetch = async () => {
      if (remoteTip !== '') return;
      remoteTip = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }], signer: r.other.hub });
    };
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'pushed');
    assert.equal(res.refetches, 1);
    assert.equal(flaky.pushCalls, 2, 'first push rejected by git, second lands');
    const M = (await r.lh.hub.main()) as string;
    assert.deepEqual(await parentsOf(r.lh, M), [L, remoteTip]);
    assert.equal(await r.kit.remote.main(), M);
    assert.equal(await ref(r.lh, REF_ACCEPTED), M);
  });
});

test('local write between validate and apply is merged, not lost (L is read inside R+Q)', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }]);
    const { deps, host } = r.mk();
    let L2 = '';
    host.beforeExclusive = async () => {
      host.beforeExclusive = null;
      L2 = await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# raced\n' }]);
    };
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'pushed');
    const M = (await r.lh.hub.main()) as string;
    assert.deepEqual(await parentsOf(r.lh, M), [L2, F]);
    assert.equal(await readFile(nodePath.join(r.lh.dir, 'acme', 'DECISIONS.md'), 'utf8'), '# raced\n');
  });
});

test('held local commit / dirty worktree -> transient, nothing applied', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]);
    const a = r.mk();
    a.host.commitOutcome = 'held';
    assert.equal((await runCycle(a.deps)).outcome, 'transient:local-hold');
    const b = r.mk();
    b.host.commitOutcome = 'clean';
    await writeFile(nodePath.join(r.lh.dir, 'acme', 'scratch.md'), 'edit\n');
    assert.equal((await runCycle(b.deps)).outcome, 'transient:dirty');
    assert.equal(await r.lh.hub.main(), r.fleet.base);
    assert.equal((await r.lh.state.read()).halt, null);
  });
});

/* ---------------- halts ---------------- */

test('auth / hostkey failures HALT and are never retried (no contact afterwards, inv 14)', { skip: !posix }, async () => {
  for (const [stderr, reason] of [['git@host: Permission denied (publickey).', 'auth'], ['Host key verification failed.', 'hostkey']] as const) {
    await withRig(2, async (r) => {
      const a = r.mk();
      a.flaky.failNext('fetch', { stderr, code: 128 });
      const res = await runCycle(a.deps);
      assert.equal(res.halted, reason);
      const st = await r.lh.state.read();
      assert.equal(st.halt?.reason, reason);
      assert.equal(st.halt?.cls, 'no-contact');
      assert.ok(!JSON.stringify(st).includes('Permission') && !JSON.stringify(st).includes('Host key'), 'no stderr text in state');
      const b = r.mk();
      const again = await runCycle(b.deps);
      assert.equal(again.outcome, 'halted');
      assert.equal(b.flaky.fetchCalls, 0, 'no network contact while halted');
    });
  }
});

test('history rewrite and rollback HALT history-rewrite (sticky) with the tip; local work untouched', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.rewriteHistory(r.other.hub);
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'history-rewrite');
    const st = await r.lh.state.read();
    assert.equal(st.halt?.cls, 'sticky');
    assert.equal(await r.lh.hub.main(), r.fleet.base);
    assert.equal(await ref(r.lh, REF_ACCEPTED), r.fleet.base);
  });
  await withRig(2, async (r) => {
    const F1 = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\none\n')]);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'applied');
    await r.kit.remote.forceMain(r.fleet.base); // rollback
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'history-rewrite');
    assert.equal(await r.lh.hub.main(), F1, 'we keep our work');
    // the remote is repaired: the next probe passes the ancestry check again and the halt clears
    await r.kit.remote.forceMain(F1);
    const back = await runCycle(r.mk().deps);
    assert.equal(back.halted, undefined);
    assert.equal((await r.lh.state.read()).halt, null);
  });
});

test('layer T quarantine: probe class, same tip is not re-validated, a new passing tip clears it', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const bad = await r.kit.remote.pushSymlink(r.other.hub, 'acme/link', '/etc/passwd');
    const res = await runCycle(r.mk().deps);
    assert.match(res.halted ?? '', /^quarantine:tree:symlink$/);
    const st = await r.lh.state.read();
    assert.equal(st.halt?.cls, 'probe');
    assert.equal(st.halt?.tip, bad);
    assert.equal(await r.lh.hub.main(), r.fleet.base, 'nothing applied');
    assert.deepEqual(await r.lh.dirty(), []);
    const again = await runCycle(r.mk().deps);
    assert.equal(again.outcome, 'halted-same-tip');
    const fixed = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [ctx('# acme\nfixed\n')], signer: r.other.hub });
    const ok = await runCycle(r.mk().deps);
    assert.equal(ok.outcome, 'applied');
    assert.equal(await r.lh.hub.main(), fixed);
    assert.equal((await r.lh.state.read()).halt, null, 'auto-cleared by a passing tip');
  });
});

test('provenance quarantine (unsigned, enforce) + operator override accepts; warn mode accepts with a note', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const bad = await r.kit.remote.pushUnsigned([ctx('# acme\nunsigned\n')]);
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'quarantine:unsigned');
    await r.lh.state.update((s) => { s.overrides.push({ tip: bad, at: new Date().toISOString() }); });
    const ok = await runCycle(r.mk().deps);
    assert.equal(ok.outcome, 'applied');
    assert.equal(await r.lh.hub.main(), bad);
    assert.equal((await r.lh.state.read()).halt, null);
  });
});

test('warn-notes create no commits and are rate limited; two warn hubs settle at once', { skip: !posix }, async () => {
  await withRig(3, async (r) => {
    const U1 = await r.kit.remote.pushUnsigned([ctx('# acme\nunsigned one\n')]);
    const a = r.mk(0, { verify: 'warn' });
    const b = r.mk(2, { verify: 'warn' });
    assert.equal((await runCycle(a.deps)).outcome, 'applied');
    assert.equal(await r.lh.hub.main(), U1, 'FF to the remote commit: the cycle made no commit for the warning');
    assert.equal(a.host.localNotes.length, 1);
    assert.equal(a.host.localNotes[0]?.[0]?.rule, 'unsigned');
    assert.equal((await runCycle(b.deps)).outcome, 'applied');
    for (let i = 0; i < 2; i += 1) {
      assert.equal((await runCycle(a.deps)).outcome, 'up-to-date');
      assert.equal((await runCycle(b.deps)).outcome, 'up-to-date');
    }
    assert.equal(await r.kit.remote.main(), U1, 'nothing was pushed by either hub');
    const U2 = await r.kit.remote.pushUnsigned([ctx('# acme\nunsigned two\n')]);
    assert.equal((await runCycle(a.deps)).outcome, 'applied');
    assert.equal(a.host.localNotes.length, 1, 'same (rule, device) inside 24 h: no second note');
    assert.equal(await r.lh.hub.main(), U2);
  });
});

test('D2 end to end: root revocation halts (no contact), a confirmation for (commit,id) applies it offline and prunes the key', { skip: !posix }, async () => {
  await withRig(3, async (r) => {
    const localHub = r.hubOf(2);
    const root = r.hubOf(0);
    const F = await r.kit.remote.pushSigned(r.other.hub, [{ path: 'devices.yml', content: revoke(r.fleet, 0, 1) }]);
    const a = r.mk(2);
    const res = await runCycle(a.deps);
    assert.equal(res.halted, 'quarantine:revocation-root');
    const st = await localHub.state.read();
    assert.equal(st.halt?.cls, 'd2');
    assert.deepEqual(st.halt?.d2, { commit: F, deviceIds: [root.hub.deviceId], kind: 'root' });
    assert.equal(await localHub.hub.main(), r.fleet.base);
    const quiet = r.mk(2);
    assert.equal((await runCycle(quiet.deps)).outcome, 'halted');
    assert.equal(quiet.flaky.fetchCalls, 0, 'D2 halt: no remote contact');
    // wrong commit: still halted
    await localHub.state.update((s) => {
      s.confirmations.push({ kind: 'root', device_id: root.hub.deviceId, commit: 'a'.repeat(40), fp: root.hub.pub.fingerprint, at: new Date().toISOString() });
    });
    assert.equal((await runCycle(r.mk(2).deps)).outcome, 'halted');
    await localHub.state.update((s) => {
      s.confirmations.push({ kind: 'root', device_id: root.hub.deviceId, commit: F, fp: root.hub.pub.fingerprint, at: new Date().toISOString() });
    });
    const go = r.mk(2);
    const done = await runCycle(go.deps);
    assert.equal(done.outcome, 'd2-confirmed');
    assert.equal(go.flaky.fetchCalls, 0, 'the re-gate used the stored tip, no network');
    assert.equal(await localHub.hub.main(), F);
    assert.equal(await ref(localHub, REF_ACCEPTED), F);
    assert.equal((await localHub.state.read()).halt, null);
    const allowed = await readFile(nodePath.join(localHub.dir, '.hub', 'allowed_signers'), 'utf8');
    assert.equal(allowed.includes(root.hub.deviceId), false, 'the revoked root key left allowed_signers');
  });
});

test('revocation of THIS device stays halted even with a matching confirmation (self)', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [{ path: 'devices.yml', content: revoke(r.fleet, 0, 1) }]);
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'quarantine:revocation-self');
    await r.lh.state.update((s) => {
      s.confirmations.push({ kind: 'self', device_id: r.lh.hub.deviceId, commit: F, fp: r.lh.hub.pub.fingerprint, at: new Date().toISOString() });
    });
    const after = await runCycle(r.mk().deps);
    assert.equal(after.outcome, 'halted');
    assert.equal(after.halted, 'detached', 'a confirmed self revocation detaches (terminal)');
    assert.equal((await r.lh.state.read()).halt?.cls, 'terminal');
    assert.equal(await r.lh.hub.main(), r.fleet.base);
  });
});

test('config halts: missing accepted ref, mirror mismatch, hostile git config; each clears when fixed', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await rm(nodePath.join(r.lh.dir, '.git', 'refs', 'ledger-sync', 'accepted'), { force: true }); // loose ref (the hardened runner refuses `-d`)
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'config');
    assert.equal((await r.lh.state.read()).halt?.cls, 'local');
    await r.lh.hub.trees.createRef(REF_ACCEPTED, r.fleet.base);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'up-to-date', 'auto when fixed');
    assert.equal((await r.lh.state.read()).halt, null);
  });
  await withRig(2, async (r) => {
    const other = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nx\n')]);
    await r.lh.state.update((s) => { s.accepted = other; }); // the mirror disagrees with the ref and is NOT behind it
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'config');
  });
  await withRig(2, async (r) => {
    await appendFile(nodePath.join(r.lh.dir, '.git', 'config'), '[url "ssh://evil/"]\n\tinsteadOf = https://x/\n');
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'config');
    assert.equal(r.mk().flaky.fetchCalls, 0);
  });
});

test('accepted mirror BEHIND the ref (crash between the CAS and the mirror write) is repaired, not halted', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'applied');
    await r.lh.state.update((s) => { s.accepted = r.fleet.base; });
    assert.equal(await ref(r.lh, REF_ACCEPTED), F);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'up-to-date');
    assert.equal((await r.lh.state.read()).accepted, F);
  });
});

test('format newer than this hub -> HALT format (sticky)', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushSigned(r.other.hub, [{ path: 'ledger.format', content: '3\n' }]);
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'format');
    assert.equal((await r.lh.state.read()).halt?.cls, 'sticky');
    assert.equal(await r.lh.hub.main(), r.fleet.base);
  });
});

test('inflight marker: a foreign edit halts `inflight`; after the human fixes it the next tick replays and clears', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    const F = await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]);
    await assert.rejects(runCycle(r.mk(0, { crashAt: (p) => { if (p === 'marker') throw new CrashError(p); } }).deps), CrashError);
    const abs = nodePath.join(r.lh.dir, 'acme', 'CONTEXT.md');
    await writeFile(abs, 'precious\n');
    const res = await runCycle(r.mk().deps);
    assert.equal(res.halted, 'inflight');
    assert.equal(await readFile(abs, 'utf8'), 'precious\n');
    assert.equal((await r.lh.state.read()).halt?.cls, 'local');
    await writeFile(abs, '# acme\n'); // the human restores L's content
    const ok = await runCycle(r.mk().deps);
    assert.equal(ok.halted, undefined);
    assert.equal(await r.lh.hub.main(), F);
    assert.equal(await r.lh.state.readInflight(), null);
    assert.equal((await r.lh.state.read()).halt, null);
  });
});

test('a merger that cannot merge quarantines the range; nothing applied, worktree untouched', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    // base has an item; the LOCAL side corrupts it, the remote side edits it validly: the item merger throws
  }, []);
  const kit = await makeKit();
  try {
    const fleet = await makeFleet(kit, 2, [{ path: 'acme/items/ACME-A1.md', content: item('ACME-A1') }]);
    const lh = fleet.hubs[0] as LedgerHub;
    await kit.remote.pushSigned((fleet.hubs[1] as LedgerHub).hub, [{ path: 'acme/items/ACME-A1.md', content: item('ACME-A1', 'edited remotely') }]);
    const L = await lh.commitLocal([{ path: 'acme/items/ACME-A1.md', content: 'this is not an item\n' }]);
    const res = await runCycle(cycleDeps(lh, kit));
    assert.match(res.halted ?? '', /^quarantine:merge:/);
    assert.equal(await lh.hub.main(), L);
    assert.equal(await lh.state.readInflight(), null);
    assert.deepEqual(await lh.dirty(), []);
  } finally {
    await kit.cleanup();
  }
});

test('egress self-check: a local commit the peers would reject sets pushBlocked (not a halt) and is never pushed', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.lh.commitLocal([ctx('-----BEGIN OPENSSH PRIVATE KEY-----\n')]);
    const { deps, flaky } = r.mk();
    const res = await runCycle(deps);
    assert.equal(res.outcome, 'push-blocked');
    assert.equal(flaky.pushCalls, 0);
    const st = await r.lh.state.read();
    assert.equal(st.pushBlocked?.rule, 'secret');
    assert.equal(st.halt, null);
    assert.equal(await r.kit.remote.main(), r.fleet.base);
  });
});

test('a verifier outage is transient with backoff: nothing quarantined, nothing applied (AL-43)', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]);
    const res = await runCycle(r.mk(0, { sshKeygenBin: '/nonexistent/ssh-keygen' }).deps);
    assert.equal(res.outcome, 'transient:verifier');
    const st = await r.lh.state.read();
    assert.equal(st.halt, null);
    assert.equal(st.backoff.failures, 1);
    assert.equal(await r.lh.hub.main(), r.fleet.base);
  });
});

test('three timeouts against the same tip quarantine `timeout`', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]);
    let n = 0;
    for (; n < 3; n += 1) {
      const a = r.mk();
      const real = a.deps.store;
      a.deps.store = Object.create(real, { revList: { value: async () => { throw Object.assign(new (await import('./gitx.ts')).GitxError('TIMEOUT', 'slow'), {}); } } }) as ObjectStore;
      const res = await runCycle(a.deps);
      if (n < 2) assert.equal(res.outcome, 'transient:timeout');
      else assert.equal(res.halted, 'quarantine:timeout');
    }
    assert.equal((await r.lh.state.read()).halt?.cls, 'probe');
  });
});

test('runCycle never throws and never calls a forbidden git option', { skip: !posix }, async () => {
  await withRig(2, async (r) => {
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]);
    await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# d\n' }]);
    const a = r.mk();
    const res = await runCycle(a.deps);
    assert.equal(res.outcome, 'pushed');
    for (const arg of a.flaky.argv.flat()) {
      assert.ok(!/^--force|^-f$|^--delete|^--mirror/.test(arg), `forbidden option ${arg}`);
      assert.ok(!/^\+refs\/heads\/[^:]*:refs\/heads\//.test(arg), 'no forced update of refs/heads');
    }
    assert.ok(a.flaky.argv.some((x) => x[0] === 'push'), 'a push happened');
    assert.ok(a.flaky.argv.filter((x) => x[0] === 'push').every((x) => /^[0-9a-f]{40}:refs\/heads\/main$/.test(x[x.length - 1] as string)), 'push by sha, never a remote name');
    // hostile deps: a store that explodes, a host that explodes
    const b = r.mk();
    b.host.flushLocal = async () => { throw new Error('boom'); };
    assert.equal((await runCycle(b.deps)).outcome, 'transient:local-git');
    const c = r.mk();
    c.deps.store = { revParse: async () => { throw new Error('boom'); } } as unknown as ObjectStore;
    const bad = await runCycle(c.deps);
    assert.ok(bad.outcome === 'error' || bad.outcome.startsWith('halt') || bad.outcome.startsWith('transient'), `ended with ${bad.outcome}`);
  });
});

test('classifyNetError: patterns, never the text', () => {
  const r = (stderr: string, o: Partial<GitxResult> = {}): GitxResult => ({ ok: false, code: 128, stdout: Buffer.alloc(0), stderr, timedOut: false, capped: false, ...o });
  assert.equal(classifyNetError(r('Host key verification failed.')), 'hostkey');
  assert.equal(classifyNetError(r('@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@')), 'hostkey');
  assert.equal(classifyNetError(r('git@x: Permission denied (publickey).')), 'auth');
  assert.equal(classifyNetError(r('ERROR: Repository not found.')), 'auth');
  assert.equal(classifyNetError(r('', { stdout: Buffer.from('!\trefs/heads/main:refs/heads/main\t[rejected] (non-fast-forward)') })), 'non-ff');
  assert.equal(classifyNetError(r('error: object abc is corrupt')), 'fsck');
  assert.equal(classifyNetError(r('fatal: unable to connect')), 'transient');
  assert.equal(classifyNetError(r('Permission denied', { timedOut: true })), 'transient');
  void REF_MAIN;
});

test('source scan: the sync modules never use a forced push/fetch, never shell out through git(), never call flush/close inside the queue', async () => {
  const dir = nodePath.dirname(new URL(import.meta.url).pathname);
  for (const f of ['apply.ts', 'cycle.ts', 'validate.ts', 'loop.ts', 'wire.ts']) {
    const src = await readFile(nodePath.join(dir, f), 'utf8');
    const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
    assert.ok(!/['"`]--force|['"`]-f['"`]|['"`]\+refs\/heads|--force-with-lease|--mirror|--delete/.test(code), `${f}: no force flag`);
    assert.ok(!/import\s+\{[^}]*\bgit\b[^}]*\}\s+from\s+['"]\.\.\/git\.ts['"]/.test(code), `${f}: no raw git() wrapper (all git via Gitx)`);
  }
  const apply = await readFile(nodePath.join(dir, 'apply.ts'), 'utf8');
  const crit = apply.slice(apply.indexOf('async function critical'), apply.indexOf('/* ---------------- replay'));
  assert.ok(!/\.flush\(|\.close\(|\.runExclusive\(/.test(crit), 'nothing inside the critical section awaits flush/close/runExclusive (deadlock)');
});
