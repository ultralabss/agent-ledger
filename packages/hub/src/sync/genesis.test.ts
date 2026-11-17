/** F3b B4b: `validateGenesis` (docs/f3b-b4-plan.md §2.3, T-B4-8, T-B4-3). Real signed commits in a bare repository;
 *  every hostile shape of the plan's table plus the merge / time-binding / cap rules. POSIX only (OpenSSH). */

import assert from 'node:assert/strict';
import nodePath from 'node:path';
import test from 'node:test';
import { renderDevicesYaml, type DeviceEntry } from '@agent-ledger/shared';
import { stringify as stringifyYaml } from 'yaml';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { fullTreeProblem, registryAt, validateGenesis, type GenesisResult } from './genesis.ts';
import { makeKit, type Kit, type TestHub } from './testkit-remote.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

const T0 = new Date('2026-11-10T10:00:00.000Z');
const at = (min: number): Date => new Date(T0.getTime() + min * 60_000);
const PIN = [
  { path: '.gitignore', content: '.hub/\n*.tmp\n' },
  { path: '.gitattributes', content: '* text eol=lf\n' },
  { path: 'ledger.format', content: '2\n' },
];

const root = (h: TestHub, when: Date): DeviceEntry => ({ id: h.deviceId, label: h.label, slot: '', pubkey: h.pub.line, added: when.toISOString(), added_by: h.deviceId, revoked: null, role: 'owner' });
const member = (h: TestHub, by: TestHub, slot: string, when: Date, revoked: DeviceEntry['revoked'] = null): DeviceEntry => ({ id: h.deviceId, label: h.label, slot, pubkey: h.pub.line, added: when.toISOString(), added_by: by.deviceId, revoked, role: 'owner' });
const reg = (...e: DeviceEntry[]): string => renderDevicesYaml({ devices: e });
/** Bypasses the renderer's invariants: a hostile file a peer could write by hand. */
const rawReg = (...e: DeviceEntry[]): string => stringifyYaml({ devices: e }, { lineWidth: 0 });

interface Ctx {
  kit: Kit;
  h: [TestHub, TestHub, TestHub, TestHub];
  /** `validateGenesis` over the kit remote's repository. */
  check(tip: string, over?: { maxCommits?: number; sshKeygenBin?: string }): Promise<GenesisResult>;
  commit(files: { path: string; content: string }[], parents: string[], signer: TestHub | null, when: Date, extra?: { remove?: string[] }): Promise<string>;
}

async function ctx(): Promise<Ctx> {
  const kit = await makeKit();
  const hubs = [await kit.makeHub(1), await kit.makeHub(2), await kit.makeHub(3), await kit.makeHub(4)] as Ctx['h'];
  return {
    kit,
    h: hubs,
    check: (tip, over = {}) =>
      validateGenesis(kit.remote.store, tip, {
        gitx: kit.remote.gitx,
        cwd: kit.remote.path,
        tmpRoot: nodePath.join(kit.root, 'remote-sync', 'tmp'),
        maxFormat: 2,
        ...over,
      }),
    commit: (files, parents, signer, when, extra = {}) =>
      kit.remote.rawCommit({ files: [...files, ...(extra.remove ?? []).map((path) => ({ path, remove: true as const }))], parents, signer, date: when, setMain: false }),
  };
}

const rule = (r: GenesisResult): string => (r.ok ? 'ok' : r.rule);

test('an honest chain: unsigned legacy commits, a signed root registration, a trusted add, a revocation — accepted, root / devices / signers reported', { skip }, async () => {
  const c = await ctx();
  try {
    const [a, b, d] = c.h;
    const legacy1 = await c.commit([...PIN, { path: 'acme/CONTEXT.md', content: '# acme\n' }], [], null, at(-600));
    const legacy2 = await c.commit([{ path: 'acme/DECISIONS.md', content: '# d\n' }], [legacy1], null, at(-300));
    const intro = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0))) }], [legacy2], a, at(1));
    const add = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(10))) }], [intro], a, at(10));
    const addD = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(10)), member(d, b, 'B', at(20))) }], [add], b, at(20));
    const revoke = await c.commit(
      [{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(10)), member(d, b, 'B', at(20), { at: at(30).toISOString(), by: b.deviceId, reason: 'lost' })) }],
      [addD],
      b,
      at(30),
    );
    const tip = await c.commit([{ path: 'acme/items/ACME-1.md', content: '---\nid: x\n---\n' }], [revoke], a, at(40)).catch(() => revoke);
    void tip;
    const r = await c.check(revoke);
    assert.ok(r.ok, rule(r));
    if (r.ok) {
      assert.equal(r.root.id, a.deviceId);
      assert.equal(r.devices.devices.length, 3);
      assert.deepEqual(r.signers, [a.pub.line, b.pub.line].sort(), 'the revoked key is not a signer');
    }
  } finally {
    await c.kit.cleanup();
  }
});

test('registration rules: unsigned / wrongly signed / two-entry introduction, a registry planted before the "root", two roots, none at all', { skip }, async () => {
  const c = await ctx();
  try {
    const [a, b] = c.h;
    const base = await c.commit([...PIN], [], null, at(-10));
    assert.equal(rule(await c.check(base)), 'no-registry');
    const unsigned = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0))) }], [base], null, at(0));
    assert.equal(rule(await c.check(unsigned)), 'root-unsigned');
    const wrong = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0))) }], [base], b, at(0));
    assert.equal(rule(await c.check(wrong)), 'root-signer');
    const two = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(0))) }], [base], a, at(0));
    assert.equal(rule(await c.check(two)), 'root-shape');
    // a registry planted (unsigned) first, the honest-looking signed one later: the FIRST introduction is the root
    const planted = await c.commit([{ path: 'devices.yml', content: reg(root(b, at(-5))) }], [base], null, at(-5));
    const later = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0))) }], [planted], a, at(0));
    assert.equal(rule(await c.check(later)), 'root-unsigned', 'the planted registry has no valid signature: it is the introduction');
    // two roots: two unrelated introductions merged
    const r1 = await c.commit([...PIN, { path: 'devices.yml', content: reg(root(a, at(0))) }], [], a, at(0));
    const r2 = await c.commit([{ path: 'devices.yml', content: reg(root(b, at(0))) }], [], b, at(0));
    const joined = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0))) }], [r1, r2], a, at(1));
    assert.ok(['multiple-roots', 'merge-devices'].includes(rule(await c.check(joined))), rule(await c.check(joined)));
    // time binding of the introduction (±15 min)
    const late = await c.commit([...PIN, { path: 'devices.yml', content: reg(root(a, at(-120))) }], [], a, at(0));
    assert.equal(rule(await c.check(late)), 'root-time-unbound');
  } finally {
    await c.kit.cleanup();
  }
});

test('later registry changes: unsigned, unregistered / revoked signer, forged slot, removed or modified entry, time binding, removed registry', { skip }, async () => {
  const c = await ctx();
  try {
    const [a, b, d, evil] = c.h;
    const intro = await c.commit([...PIN, { path: 'devices.yml', content: reg(root(a, at(0))) }], [], a, at(0));
    const add = (signer: TestHub | null, when: Date, entry: DeviceEntry = member(b, a, 'A', when)): Promise<string> =>
      c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), entry) }], [intro], signer, when);
    assert.equal(rule(await c.check(await add(a, at(5)))), 'ok');
    assert.equal(rule(await c.check(await add(null, at(5)))), 'devices-unsigned');
    assert.equal(rule(await c.check(await add(evil, at(5)))), 'devices-signer-unregistered');
    // added_by names somebody else than the signer
    assert.equal(rule(await c.check(await c.commit([{ path: 'devices.yml', content: rawReg(root(a, at(0)), member(b, d, 'A', at(5))) }], [intro], a, at(5)))), 'content:schema', 'added_by must be in the file (the tip registry is itself invalid)');
    // time binding: `added` an hour away from the commit
    assert.equal(rule(await c.check(await add(a, at(5), member(b, a, 'A', at(65))))), 'devices-time-unbound');
    // a registry entry modified / removed on top of a good one
    const good = await add(a, at(5));
    const modified = await c.commit([{ path: 'devices.yml', content: reg({ ...root(a, at(0)), label: 'renamed' }, member(b, a, 'A', at(5))) }], [good], a, at(6));
    assert.equal(rule(await c.check(modified)), 'devices-entry-modified');
    const removed = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0))) }], [good], a, at(6));
    assert.equal(rule(await c.check(removed)), 'devices-entry-removed');
    const gone = await c.commit([], [good], a, at(6), { remove: ['devices.yml'] });
    assert.equal(rule(await c.check(gone)), 'registry-removed');
    // a signer revoked in the PARENT cannot sign a later change
    const revoked = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(5), { at: at(7).toISOString(), by: a.deviceId, reason: 'lost' })) }], [good], a, at(7));
    const byRevoked = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(5), { at: at(7).toISOString(), by: a.deviceId, reason: 'lost' }), member(d, b, 'B', at(9))) }], [revoked], b, at(9));
    assert.equal(rule(await c.check(byRevoked)), 'devices-signer-revoked');
    // the tip must be signed by a live key of ITS registry
    const tipByRevoked = await c.commit([{ path: 'acme/CONTEXT.md', content: '# x\n' }], [revoked], b, at(8));
    assert.equal(rule(await c.check(tipByRevoked)), 'tip-signer-revoked');
    const tipUnsigned = await c.commit([{ path: 'acme/CONTEXT.md', content: '# x\n' }], [good], null, at(8));
    assert.equal(rule(await c.check(tipUnsigned)), 'tip-unsigned');
    const tipForeign = await c.commit([{ path: 'acme/CONTEXT.md', content: '# x\n' }], [good], evil, at(8));
    assert.equal(rule(await c.check(tipForeign)), 'tip-signer-unregistered');
  } finally {
    await c.kit.cleanup();
  }
});

test('merges: the typed merge of two valid sides is accepted, any other registry in a merge commit is refused', { skip }, async () => {
  const c = await ctx();
  try {
    const [a, b, d] = c.h;
    const intro = await c.commit([...PIN, { path: 'devices.yml', content: reg(root(a, at(0))) }], [], a, at(0));
    const left = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(5))) }], [intro], a, at(5));
    const right = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(d, a, 'B', at(6))) }], [intro], a, at(6));
    const typed = reg(root(a, at(0)), member(b, a, 'A', at(5)), member(d, a, 'B', at(6)));
    const ok = await c.commit([{ path: 'devices.yml', content: typed }], [left, right], a, at(7));
    const r = await c.check(ok);
    assert.ok(r.ok, rule(r));
    if (r.ok) assert.equal(r.devices.devices.length, 3);
    const bogus = await c.commit([{ path: 'devices.yml', content: reg(root(a, at(0)), member(b, a, 'A', at(5))) }], [left, right], a, at(7));
    assert.equal(rule(await c.check(bogus)), 'merge-devices', 'a merge that drops one side is not the typed merge');
    const octopus = await c.commit([{ path: 'devices.yml', content: typed }], [left, right, intro], a, at(7));
    assert.equal(rule(await c.check(octopus)), 'merge-octopus');
  } finally {
    await c.kit.cleanup();
  }
});

test('the tip tree: symlink, gitlink-ish modes, .hub paths, a driver in .gitattributes, a changed pinned file, case collisions — refused with a tree / content token', { skip }, async () => {
  const c = await ctx();
  try {
    const [a] = c.h;
    const intro = await c.commit([...PIN, { path: 'devices.yml', content: reg(root(a, at(0))) }], [], a, at(0));
    assert.equal(rule(await c.check(intro)), 'ok');
    const tipOn = async (files: { path: string; content: string; mode?: '100644' | '100755' | '120000' }[]): Promise<string> =>
      c.kit.remote.rawCommit({ files, parents: [intro], signer: a, date: at(3), setMain: false });
    assert.equal(rule(await c.check(await tipOn([{ path: 'acme/l.md', content: '/etc/passwd', mode: '120000' }]))), 'tree:symlink');
    assert.equal(rule(await c.check(await tipOn([{ path: 'acme/x.sh', content: '#!/bin/sh\n', mode: '100755' }]))), 'tree:exec');
    assert.equal(rule(await c.check(await tipOn([{ path: '.hub/token', content: 'x\n' }]))), 'tree:hub-path');
    assert.equal(rule(await c.check(await tipOn([{ path: '.gitattributes', content: '* filter=evil\n' }]))), 'content:gitattributes-driver');
    assert.equal(rule(await c.check(await tipOn([{ path: '.gitignore', content: '*.tmp\n' }]))), 'content:gitignore');
    assert.equal(rule(await c.check(await tipOn([{ path: 'ledger.format', content: '9\n' }]))), 'content:format');
    assert.equal(rule(await c.check(await tipOn([{ path: 'unknown/dir/file.bin', content: 'x' }]))), 'tree:layout');
    // the same check, callable on its own
    const bad = await tipOn([{ path: '.hub/x', content: 'x\n' }]);
    assert.equal(await fullTreeProblem(c.kit.remote.store, bad, 2), 'tree:hub-path');
    assert.equal(await fullTreeProblem(c.kit.remote.store, intro, 2), null);
    assert.equal((await registryAt(c.kit.remote.store, c.kit.remote.gitx, c.kit.remote.path, intro))?.devices.length, 1);
    assert.equal(await registryAt(c.kit.remote.store, c.kit.remote.gitx, c.kit.remote.path, await c.commit([...PIN], [], null, at(-1))), null);
  } finally {
    await c.kit.cleanup();
  }
});

test('caps and robustness: oversize history, bad input, a verifier outage — a token, never a throw, never an accept', { skip }, async () => {
  const c = await ctx();
  try {
    const [a] = c.h;
    let tip = await c.commit([...PIN, { path: 'devices.yml', content: reg(root(a, at(0))) }], [], a, at(0));
    for (let i = 1; i <= 6; i += 1) tip = await c.commit([{ path: 'acme/CONTEXT.md', content: `${String(i)}\n` }], [tip], a, at(i));
    assert.equal(rule(await c.check(tip)), 'ok');
    assert.equal(rule(await c.check(tip, { maxCommits: 5 })), 'oversize');
    for (const bad of ['', 'HEAD', 'zz', '--upload-pack=x', `${'a'.repeat(40)}`, null as unknown as string]) {
      const r = await c.check(bad);
      assert.equal(r.ok, false, String(bad));
    }
    // a missing / broken verifier is NOT "unsigned": it is its own (local) token and still never accepts
    const r = await c.check(tip, { sshKeygenBin: nodePath.join(c.kit.root, 'no-such-ssh-keygen') });
    assert.equal(r.ok, false);
    assert.ok(['verifier', 'unreadable'].includes(rule(r)), rule(r));
  } finally {
    await c.kit.cleanup();
  }
});
