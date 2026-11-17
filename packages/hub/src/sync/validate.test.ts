/** `validateRange` / `classifySyncError` / `egressSelfCheck` (docs/f3b-b3-plan.md §1.2, §6; T-B3-6/8, AL-23/36/43/45/46).
 *  Real git objects through the testkit: hostile commits are written straight into the bare remote. */

import assert from 'node:assert/strict';
import nodePath from 'node:path';
import test from 'node:test';
import { itemFrontmatterSchema, newItemDoc, parseDevicesYaml, renderDevicesYaml, serializeMd } from '@agent-ledger/shared';
import { GitxError } from './gitx.ts';
import { mergeDevicesNullable } from './merge/devices.ts';
import { ObjectsError, type ObjectStore } from './objects.ts';
import { confirmationKey } from './state.ts';
import { makeFleet, type Fleet, type LedgerHub } from './testkit-remote.ts';
import { makeKit, type Kit } from './testkit-remote.ts';
import { classifySyncError, egressSelfCheck, isOverridableRule, validateRange, type RangeInput, type RangeOutcome } from './validate.ts';

const posix = process.platform !== 'win32';

async function withFleet<T>(n: number, fn: (f: Fleet, kit: Kit) => Promise<T>): Promise<T> {
  const kit = await makeKit();
  try {
    return await fn(await makeFleet(kit, n), kit);
  } finally {
    await kit.cleanup();
  }
}

const hubOf = (f: Fleet, i: number): LedgerHub => f.hubs[i] as LedgerHub;

async function range(f: Fleet, F: string, over: Partial<RangeInput> = {}): Promise<RangeOutcome> {
  const lh = hubOf(f, 0);
  await lh.hub.fetchIncoming(f.kit.remote);
  const L = (await lh.hub.main()) as string;
  return validateRange({
    store: lh.hub.store,
    tmpRoot: nodePath.join(lh.hub.syncDir, 'tmp'),
    A: f.base,
    L,
    F,
    mode: 'enforce',
    localDevice: lh.hub.deviceId,
    trusted: new Set(f.hubs.map((h) => h.hub.pub.line)),
    seenSigning: new Set<string>(),
    confirmedRevocations: new Set<string>(),
    maxFormat: 2,
    ...over,
  });
}

const item = (id: string, repo = 'acme'): string => {
  const fm = itemFrontmatterSchema.parse({ id, title: 'a title', status: 'open', kind: 'BACKLOG', priority: 'P2', owner: 'agent', repo, created: '2026-11-16T10:00:00.000Z', updated: '2026-11-16T10:00:00.000Z' });
  return serializeMd(newItemDoc(fm as never));
};

const ctxFile = (text: string): { path: string; content: string } => ({ path: 'acme/CONTEXT.md', content: text });
const nowIso = (): string => new Date().toISOString().replace(/\.\d+Z$/, '.000Z');

function revoke(f: Fleet, victim: number, by: number): string {
  const file = parseDevicesYaml(f.devicesText);
  const id = hubOf(f, victim).hub.deviceId;
  return renderDevicesYaml({ devices: file.devices.map((d) => (d.id === id ? { ...d, revoked: { at: nowIso(), by: hubOf(f, by).hub.deviceId, reason: 'lost' } } : d)) });
}

test('honest signed range: ok, signer recorded, no forced merge', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const F = await kit.remote.pushSigned(hubOf(f, 1).hub, [ctxFile('# acme\nedited\n')]);
    const out = await range(f, F);
    assert.equal(out.kind, 'ok');
    if (out.kind === 'ok') {
      assert.deepEqual(out.signers, [hubOf(f, 1).hub.deviceId]);
      assert.equal(out.forcedMerge, false);
      assert.equal(out.tipDevice, hubOf(f, 1).hub.deviceId);
    }
  });
});

test('unsigned commit: enforce quarantines (provenance); warn accepts with a note unless the ratchet knows the device', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const F = await kit.remote.pushUnsigned([ctxFile('# acme\nunsigned\n')]);
    const enforce = await range(f, F);
    assert.equal(enforce.kind, 'quarantine');
    if (enforce.kind === 'quarantine') {
      assert.equal(enforce.rule, 'unsigned');
      assert.equal(enforce.layer, 'provenance');
      assert.equal(enforce.commit, F);
    }
    const warn = await range(f, F, { mode: 'warn' });
    assert.equal(warn.kind, 'ok');
    if (warn.kind === 'ok') assert.ok(warn.notes.some((n) => n.type === 'sync.warning' && n.rule === 'unsigned'));
  });
});

test('unsigned commit on a SIDE branch is caught (first-parent walk would miss it, AL-46)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    const c1 = await kit.remote.rawCommit({ parents: [f.base], files: [ctxFile('# acme\nmain side\n')], signer: h2, setMain: false });
    const s1 = await kit.remote.rawCommit({ parents: [f.base], files: [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }], signer: null, setMain: false });
    const m = await kit.remote.rawCommit({
      parents: [c1, s1],
      files: [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }],
      signer: h2,
    });
    const out = await range(f, m);
    assert.equal(out.kind, 'quarantine');
    if (out.kind === 'quarantine') {
      assert.equal(out.rule, 'unsigned');
      assert.equal(out.commit, s1);
    }
  });
});

test('side-branch ROOT revocation halts D2 (AL-46); a human confirmation for exactly (commit,id) accepts', { skip: !posix }, async () => {
  await withFleet(3, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    const rootId = hubOf(f, 0).hub.deviceId;
    const revokedText = revoke(f, 0, 1);
    const c1 = await kit.remote.rawCommit({ parents: [f.base], files: [ctxFile('# acme\nmain side\n')], signer: h2, setMain: false });
    const s1 = await kit.remote.rawCommit({ parents: [f.base], files: [{ path: 'devices.yml', content: revokedText }], signer: h2, setMain: false });
    const merged = mergeDevicesNullable(f.devicesText, f.devicesText, revokedText);
    assert.ok(merged.ok);
    const m = await kit.remote.rawCommit({ parents: [c1, s1], files: [{ path: 'devices.yml', content: (merged.ok ? merged.merged : '') ?? '' }], signer: h2 });
    const local = hubOf(f, 2).hub.deviceId; // the revoked root is NOT this device
    const out = await range(f, m, { localDevice: local });
    assert.equal(out.kind, 'halt-d2');
    if (out.kind === 'halt-d2') {
      assert.equal(out.reason, 'quarantine:revocation-root');
      assert.equal(out.commit, s1);
      assert.deepEqual(out.deviceIds, [rootId]);
      assert.equal(out.d2Kind, 'root');
    }
    const wrong = await range(f, m, { localDevice: local, confirmedRevocations: new Set([confirmationKey(c1, rootId)]) });
    assert.equal(wrong.kind, 'halt-d2', 'a confirmation for another commit confirms nothing');
    const ok = await range(f, m, { localDevice: local, confirmedRevocations: new Set([confirmationKey(s1, rootId)]) });
    assert.equal(ok.kind, 'ok');
  });
});

test('revocation of THIS device is held even with a confirmation (self)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const F = await kit.remote.pushSigned(hubOf(f, 1).hub, [{ path: 'devices.yml', content: revoke(f, 0, 1) }]);
    const out = await range(f, F, { confirmedRevocations: new Set([confirmationKey(F, hubOf(f, 0).hub.deviceId)]) });
    assert.equal(out.kind, 'halt-d2');
    if (out.kind === 'halt-d2') assert.equal(out.reason, 'quarantine:revocation-self');
  });
});

test('limits: too many commits -> oversize; missing object, big blob, huge commit quarantine; none throws', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    const c1 = await kit.remote.pushSigned(h2, [ctxFile('# acme\none\n')]);
    const c2 = await kit.remote.pushSigned(h2, [ctxFile('# acme\ntwo\n')]);
    const c3 = await kit.remote.pushSigned(h2, [ctxFile('# acme\nthree\n')]);
    void c1;
    void c2;
    const many = await range(f, c3, { maxCommits: 2 });
    assert.equal(many.kind, 'quarantine');
    if (many.kind === 'quarantine') assert.equal(many.rule, 'oversize');
    assert.equal((await range(f, c3, { maxCommits: 3 })).kind, 'ok');

    const big = await kit.remote.pushSigned(h2, [{ path: 'acme/big.md', content: 'x'.repeat(300_000) }]);
    const bigOut = await range(f, big);
    assert.equal(bigOut.kind, 'quarantine');
    if (bigOut.kind === 'quarantine') assert.equal(bigOut.rule, 'oversize');

    const huge = await kit.remote.rawCommit({ parents: [f.base], files: [ctxFile('# acme\nx\n')], signer: h2, message: 'm'.repeat(70_000) });
    const hugeOut = await range(f, huge);
    assert.equal(hugeOut.kind, 'quarantine');
    if (hugeOut.kind === 'quarantine') assert.equal(hugeOut.rule, 'oversize');
  });
});

test('a tree that names a missing blob quarantines `objects:missing` (hostile objects never throw out of validateRange)', { skip: !posix }, async () => {
  await withFleet(2, async (f) => {
    const lh = hubOf(f, 0);
    const git = lh.hub.gitx;
    const tree = (await git.mustRun(['mktree', '--missing'], { cwd: lh.dir, input: `100644 blob ${'1'.repeat(40)}\tledger.format\n` })).stdout.toString('utf8').trim();
    const sha = (
      await git.mustRun(['commit-tree', tree, '-p', f.base, '-m', 'hostile'], { cwd: lh.dir, extraConfig: ['user.name=x', `user.email=${lh.hub.deviceId}@devices.agent-ledger.invalid`] })
    ).stdout.toString('utf8').trim();
    const out = await validateRange({
      store: lh.hub.store,
      tmpRoot: nodePath.join(lh.hub.syncDir, 'tmp'),
      A: f.base, L: f.base, F: sha, mode: 'enforce', localDevice: lh.hub.deviceId,
      trusted: new Set(), seenSigning: new Set(), confirmedRevocations: new Set(), maxFormat: 2,
    });
    assert.equal(out.kind, 'quarantine');
    if (out.kind === 'quarantine') {
      assert.match(out.rule, /^objects:missing$/);
      assert.equal(out.layer, 'tree', 'object-level failures are never overridable');
    }
  });
});

test('verifier failure is transient, never an accept and never a quarantine (AL-43)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const F = await kit.remote.pushSigned(hubOf(f, 1).hub, [ctxFile('# acme\nedited\n')]);
    for (const mode of ['warn', 'enforce'] as const) {
      const out = await range(f, F, { mode, sshKeygenBin: '/nonexistent/ssh-keygen' });
      assert.deepEqual(out, { kind: 'transient', why: 'verifier' }, mode);
    }
  });
});

test('baseFormat downgrade INSIDE the range is refused per commit even when the final tree is fine (AL-23)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    await kit.remote.pushSigned(h2, [{ path: 'ledger.format', content: '1\n' }]);
    const F = await kit.remote.pushSigned(h2, [{ path: 'ledger.format', content: '2\n' }]);
    const out = await range(f, F);
    assert.equal(out.kind, 'quarantine');
    if (out.kind === 'quarantine') {
      assert.equal(out.rule, 'ingress:format');
      assert.equal(out.layer, 'provenance');
    }
  });
});

test('ledger.format newer than this hub -> format outcome', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const F = await kit.remote.pushSigned(hubOf(f, 1).hub, [{ path: 'ledger.format', content: '3\n' }]);
    const out = await range(f, F);
    assert.equal(out.kind, 'format');
  });
});

test('root commit and octopus merge in the range quarantine', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    const c1 = await kit.remote.rawCommit({ parents: [f.base], files: [ctxFile('# acme\nc1\n')], signer: h2, setMain: false });
    const root = await kit.remote.rawCommit({ parents: [], files: [ctxFile('# other\n')], signer: h2, setMain: false });
    const withRoot = await kit.remote.rawCommit({ parents: [c1, root], files: [], signer: h2 });
    const a = await range(f, withRoot);
    assert.equal(a.kind, 'quarantine');
    if (a.kind === 'quarantine') assert.equal(a.rule, 'root-commit');
    const s1 = await kit.remote.rawCommit({ parents: [f.base], files: [{ path: 'acme/DECISIONS.md', content: '# d\n' }], signer: h2, setMain: false });
    const s2 = await kit.remote.rawCommit({ parents: [f.base], files: [{ path: 'acme/journal/2026-11.md', content: '# j\n' }], signer: h2, setMain: false });
    const octo = await kit.remote.rawCommit({ parents: [c1, s1, s2], files: [], signer: h2 });
    const b = await range(f, octo);
    assert.equal(b.kind, 'quarantine');
    if (b.kind === 'quarantine') assert.equal(b.rule, 'merge-octopus');
  });
});

test('honest merge whose merge-base (A) lies outside the range is ok; a merge that invents an item is quarantined (AL-43)', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    const c1 = await kit.remote.rawCommit({ parents: [f.base], files: [ctxFile('# acme\nmain side\n')], signer: h2, setMain: false });
    const journal = { path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' };
    const s1 = await kit.remote.rawCommit({ parents: [f.base], files: [journal], signer: h2, setMain: false });
    const good = await kit.remote.rawCommit({ parents: [c1, s1], files: [journal], signer: h2 });
    assert.equal((await range(f, good)).kind, 'ok');
    const bad = await kit.remote.rawCommit({ parents: [c1, s1], files: [journal, { path: 'acme/items/ACME-B1.md', content: item('ACME-B1') }], signer: h2 });
    const out = await range(f, bad);
    assert.equal(out.kind, 'quarantine');
    if (out.kind === 'quarantine') assert.equal(out.rule, 'merge-item-new');
  });
});

test('layer T (final tree) is never overridable; revoked-current stays final too', { skip: !posix }, async () => {
  await withFleet(3, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    const link = await kit.remote.pushSymlink(h2, 'acme/link', '/etc/passwd');
    const t = await range(f, link, { override: { secretAck: true } });
    assert.equal(t.kind, 'quarantine');
    if (t.kind === 'quarantine') {
      assert.equal(t.layer, 'tree');
      assert.equal(isOverridableRule(t.rule), false);
    }
    // stolen-key fork: hub 3 is revoked in the LOCAL tip, its commit forks off the older base
    await kit.remote.forceMain(f.base);
    const lh = hubOf(f, 0);
    await lh.commitLocal([{ path: 'devices.yml', content: revoke(f, 2, 0) }], { message: 'revoke 3' });
    const stolen = await kit.remote.pushSigned(hubOf(f, 2).hub, [ctxFile('# acme\nstolen\n')]);
    const r = await range(f, stolen, { override: { secretAck: true } });
    assert.equal(r.kind, 'quarantine');
    if (r.kind === 'quarantine') assert.equal(r.rule, 'revoked-current');
  });
});

test('operator override (OQ-B): signature rows pass, with a note; email-mismatch too', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const F = await kit.remote.pushUnsigned([ctxFile('# acme\nunsigned\n')]);
    const out = await range(f, F, { override: { secretAck: false } });
    assert.equal(out.kind, 'ok');
    if (out.kind === 'ok') {
      assert.equal(out.overrideUsed, true);
      assert.ok(out.notes.some((n) => n.rule === 'override'));
    }
    const lie = await kit.remote.rawCommit({
      parents: [f.base],
      files: [ctxFile('# acme\nliar\n')],
      signer: hubOf(f, 1).hub,
      identity: { name: 'x', email: `${hubOf(f, 0).hub.deviceId}@devices.agent-ledger.invalid` },
    });
    const refused = await range(f, lie);
    assert.equal(refused.kind, 'quarantine');
    if (refused.kind === 'quarantine') assert.equal(refused.rule, 'email-mismatch');
    assert.equal((await range(f, lie, { override: { secretAck: false } })).kind, 'ok');
  });
});

test('operator override (OQ-C): a secret removed by a later commit needs secretAck', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const h2 = hubOf(f, 1).hub;
    await kit.remote.pushSigned(h2, [ctxFile('-----BEGIN OPENSSH PRIVATE KEY-----\n')]);
    const F = await kit.remote.pushSigned(h2, [ctxFile('# acme\nclean again\n')]);
    const plain = await range(f, F);
    assert.equal(plain.kind, 'quarantine');
    if (plain.kind === 'quarantine') {
      assert.equal(plain.rule, 'secret');
      assert.equal(plain.layer, 'provenance');
      assert.ok(plain.notes.every((n) => !JSON.stringify(n).includes('PRIVATE KEY')), 'never the matched text');
    }
    assert.equal((await range(f, F, { override: { secretAck: false } })).kind, 'quarantine');
    assert.equal((await range(f, F, { override: { secretAck: true } })).kind, 'ok');
  });
});

test('a secret that is STILL in the final tree is layer T: not overridable even with secretAck', { skip: !posix }, async () => {
  await withFleet(2, async (f, kit) => {
    const F = await kit.remote.pushSigned(hubOf(f, 1).hub, [ctxFile('-----BEGIN OPENSSH PRIVATE KEY-----\n')]);
    const out = await range(f, F, { override: { secretAck: true } });
    assert.equal(out.kind, 'quarantine');
    if (out.kind === 'quarantine') assert.equal(out.layer, 'tree');
  });
});

test('warn mode: unknown signer accepted with a note, NOT added to the ratchet signer list', { skip: !posix }, async () => {
  const kit = await makeKit();
  try {
    const f = await makeFleet(kit, 2);
    const stranger = await kit.makeHub(9);
    const F = await kit.remote.pushSigned(stranger, [ctxFile('# acme\nfrom a stranger\n')]);
    const out = await range(f, F, { mode: 'warn' });
    assert.equal(out.kind, 'ok');
    if (out.kind === 'ok') {
      assert.deepEqual(out.signers, [], 'an unregistered key never feeds the ratchet');
      assert.ok(out.notes.some((n) => n.rule === 'unknown-key'));
    }
  } finally {
    await kit.cleanup();
  }
});

test('item delete in the range -> forcedMerge (never an FF that would drop the item)', { skip: !posix }, async () => {
  const kit = await makeKit();
  try {
    const h2seed = await makeFleet(kit, 2, [{ path: 'acme/items/ACME-A1.md', content: item('ACME-A1') }]);
    const F = await kit.remote.rawCommit({ files: [{ path: 'acme/items/ACME-A1.md', remove: true }], signer: hubOf(h2seed, 1).hub });
    const out = await range(h2seed, F);
    assert.equal(out.kind, 'ok');
    if (out.kind === 'ok') assert.equal(out.forcedMerge, true);
  } finally {
    await kit.cleanup();
  }
});

test('never throws: bad ids are transient; a throwing store quarantines `internal` (remote) or is transient (local)', async () => {
  const dummy = {} as unknown as ObjectStore;
  const base = { store: dummy, tmpRoot: '/x', mode: 'enforce' as const, localDevice: 'd_aaaaaaaaaa', trusted: new Set<string>(), seenSigning: new Set<string>(), confirmedRevocations: new Set<string>(), maxFormat: 2 };
  const bad = await validateRange({ ...base, A: 'nope', L: 'a'.repeat(40), F: 'b'.repeat(40) });
  assert.deepEqual(bad, { kind: 'transient', why: 'bad-input' });
  const boom = { revList: async () => { throw new Error('boom'); } } as unknown as ObjectStore;
  const q = await validateRange({ ...base, store: boom, A: 'a'.repeat(40), L: 'a'.repeat(40), F: 'b'.repeat(40) });
  assert.equal(q.kind, 'quarantine');
  if (q.kind === 'quarantine') assert.equal(q.rule, 'internal');
  const weird = { revList: async () => { throw 'a string, not an Error'; } } as unknown as ObjectStore;
  assert.equal((await validateRange({ ...base, store: weird, A: 'a'.repeat(40), L: 'a'.repeat(40), F: 'b'.repeat(40) })).kind, 'quarantine');
});

test('classifySyncError: remote -> quarantine tokens, TIMEOUT transient, local never quarantines', () => {
  assert.deepEqual(classifySyncError(new ObjectsError('LIMIT', 'x'), 'remote'), { kind: 'quarantine', rule: 'oversize' });
  assert.deepEqual(classifySyncError(new ObjectsError('MISSING', 'x'), 'remote'), { kind: 'quarantine', rule: 'objects:missing' });
  assert.deepEqual(classifySyncError(new GitxError('CAPPED', 'x'), 'remote'), { kind: 'quarantine', rule: 'oversize' });
  assert.deepEqual(classifySyncError(new GitxError('TIMEOUT', 'x'), 'remote'), { kind: 'transient', why: 'timeout' });
  assert.deepEqual(classifySyncError(new GitxError('BINARY', 'x'), 'remote'), { kind: 'transient', why: 'local-git' });
  assert.deepEqual(classifySyncError(new Error('?'), 'remote'), { kind: 'quarantine', rule: 'internal' });
  for (const e of [new ObjectsError('LIMIT', 'x'), new GitxError('CAPPED', 'x'), new Error('?')]) {
    assert.equal(classifySyncError(e, 'local').kind, 'transient');
  }
});

test('egressSelfCheck: clean local range passes; a secret or symlink we are about to push is blocked; deletes are fine', { skip: !posix }, async () => {
  const kit = await makeKit();
  try {
    const f = await makeFleet(kit, 1, [{ path: 'acme/items/ACME-A1.md', content: item('ACME-A1') }]);
    const lh = hubOf(f, 0);
    const store = lh.hub.store;
    const ok = await lh.commitLocal([ctxFile('# acme\nlocal edit\n')]);
    assert.deepEqual(await egressSelfCheck(store, { A: f.base, L: ok, maxFormat: 2 }), { ok: true });
    const del = await lh.commitLocal([{ path: 'acme/items/ACME-A1.md', remove: true }]);
    assert.deepEqual(await egressSelfCheck(store, { A: f.base, L: del, maxFormat: 2 }), { ok: true }, 'a delete alone is not a block');
    const leak = await lh.commitLocal([ctxFile('-----BEGIN OPENSSH PRIVATE KEY-----\n')]);
    assert.deepEqual(await egressSelfCheck(store, { A: f.base, L: leak, maxFormat: 2 }), { ok: false, rule: 'secret' });
  } finally {
    await kit.cleanup();
  }
});
