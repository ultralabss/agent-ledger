/** Merge-output builder (docs/f3b-plan.md §3: `--no-filters` with a hostile filter, temp index isolation, CAS failure; S10, invariants 1, 3). */

import assert from 'node:assert/strict';
import { appendFile, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { GitxError, REF_ACCEPTED, REF_MAIN } from './gitx.ts';
import { ObjectStore } from './objects.ts';
import { verifyCommitSignature } from './sigverify.ts';
import { makeKit, type Kit, type TestHub } from './testkit-remote.ts';
import { TreeBuildError, assertTreePath } from './treebuild.ts';

const posix = process.platform !== 'win32';
const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

async function withKit<T>(fn: (kit: Kit) => Promise<T>): Promise<T> {
  const kit = await makeKit();
  try {
    return await fn(kit);
  } finally {
    await kit.cleanup();
  }
}

async function snapshot(hub: TestHub): Promise<{ index: string | null; worktree: string[]; refs: string }> {
  const index = await readFile(nodePath.join(hub.dir, '.git', 'index')).then((b) => b.toString('hex'), () => null);
  const worktree = (await readdir(hub.dir, { recursive: true })).filter((p) => !p.startsWith('.git')).sort();
  const refs = (await hub.gitx.mustRun(['for-each-ref'], { cwd: hub.dir })).stdout.toString();
  return { index, worktree, refs };
}

test('buildTree from nothing: exact bytes, deterministic, nested paths', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const changes = [
      { path: 'items/a.md', content: 'line1\r\nline2\r\n' },
      { path: 'b.bin', content: Buffer.from([0, 1, 2, 255, 10, 13]) },
      { path: 'sub/dir/c.md', content: '' },
    ];
    const t1 = await hub.trees.buildTree(null, changes);
    const t2 = await hub.trees.buildTree(null, [...changes].reverse());
    assert.equal(t1, t2, 'order of changes does not matter');
    const entries = await hub.store.lsTree(t1);
    assert.deepEqual(entries.map((e) => [e.path, e.mode, e.size]), [
      ['b.bin', '100644', 6],
      ['items/a.md', '100644', 14],
      ['sub/dir/c.md', '100644', 0],
    ]);
    const blobs = await hub.store.catFileBatch(entries.map((e) => e.sha));
    const a = entries.find((e) => e.path === 'items/a.md');
    assert.equal(blobs.get(a?.sha as string)?.content.toString(), 'line1\r\nline2\r\n', 'no EOL conversion');
    assert.equal(await hub.trees.buildTree(null, []), EMPTY_TREE);
    assert.equal(await hub.trees.buildTree(null, [{ path: 'gone.md', remove: true }]), EMPTY_TREE);
  });
});

test('buildTree on a base: replace, add, remove, remove of a missing path, base may be a tree id', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([
      { path: 'a.md', content: '1\n' },
      { path: 'b.md', content: '1\n' },
      { path: 'keep/k.md', content: 'k\n' },
    ]);
    const t = await hub.trees.buildTree(c1, [
      { path: 'a.md', content: '2\n' },
      { path: 'b.md', remove: true },
      { path: 'new/n.md', content: 'n\n' },
      { path: 'never-existed.md', remove: true },
    ]);
    assert.deepEqual((await hub.store.lsTree(t)).map((e) => e.path), ['a.md', 'keep/k.md', 'new/n.md']);
    const baseTree = (await hub.store.lsTree(c1)).length;
    assert.equal(baseTree, 3);
    const viaTree = await hub.trees.buildTree(t, [{ path: 'a.md', remove: true }]);
    assert.deepEqual((await hub.store.lsTree(viaTree)).map((e) => e.path), ['keep/k.md', 'new/n.md']);
    const removedAll = await hub.trees.buildTree(c1, [
      { path: 'a.md', remove: true },
      { path: 'b.md', remove: true },
      { path: 'keep/k.md', remove: true },
    ]);
    assert.equal(removedAll, EMPTY_TREE);
  });
});

test('temp index isolation: real index, worktree and refs are untouched; temp dir is removed, also on failure', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    await hub.commit([{ path: 'a.md', content: '1\n' }]);
    await writeFile(nodePath.join(hub.dir, 'stray.txt'), 'uncommitted\n');
    await hub.gitx.mustRun(['update-index', '--add', 'stray.txt'], { cwd: hub.dir });
    await mkdir(nodePath.join(hub.dir, 'untracked-dir'));
    await writeFile(nodePath.join(hub.dir, 'untracked-dir', 'u.md'), 'u\n');
    const before = await snapshot(hub);
    assert.ok(before.index !== null, 'a real index exists');
    const base = await hub.main();
    await hub.trees.buildTree(base, [
      { path: 'a.md', content: 'changed\n' },
      { path: 'x/new.md', content: 'new\n' },
      { path: 'stray.txt', remove: true },
    ]);
    assert.deepEqual(await snapshot(hub), before);
    assert.equal(await readFile(nodePath.join(hub.dir, 'stray.txt'), 'utf8'), 'uncommitted\n');
    const tmp = nodePath.join(hub.syncDir, 'tmp');
    assert.deepEqual(await readdir(tmp), []);
    await assert.rejects(hub.trees.buildTree('e'.repeat(40), [{ path: 'a.md', content: 'x' }]), GitxError);
    assert.deepEqual(await readdir(tmp), []);
    assert.deepEqual(await snapshot(hub), before);
  });
});

test('hostile filter / attributes config cannot run code or alter bytes (--no-filters)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const marker = nodePath.join(kit.root, 'FILTER-RAN');
    await appendFile(
      nodePath.join(hub.dir, '.git', 'config'),
      `[filter "evil"]\n\tclean = "sh -c 'touch ${marker}; cat'"\n\tsmudge = "sh -c 'touch ${marker}; cat'"\n\trequired = true\n[diff "evil"]\n\ttextconv = "sh -c 'touch ${marker}; cat' --"\n`,
    );
    await mkdir(nodePath.join(hub.dir, '.git', 'info'), { recursive: true });
    await writeFile(nodePath.join(hub.dir, '.git', 'info', 'attributes'), '* filter=evil text diff=evil\n');
    const raw = 'a\r\nb\r\n';

    // control: the very same input DOES trigger the filter when filters are not disabled
    const control = await hub.gitx.mustRun(['hash-object', '-w', '--stdin', '--path=a.md'], { cwd: hub.dir, input: raw });
    assert.ok((await stat(marker).catch(() => null)) !== null, 'control: the hostile filter is live');
    await rm(marker, { force: true });
    const controlBlob = await hub.store.catFileBatch([control.stdout.toString().trim()]);
    assert.notEqual([...controlBlob.values()][0]?.content.toString(), raw, 'control: filters would have rewritten the bytes');

    const tree = await hub.trees.buildTree(null, [{ path: 'a.md', content: raw }]);
    assert.equal(await stat(marker).catch(() => null), null, 'no filter, driver or textconv ran while building');
    const [entry] = await hub.store.lsTree(tree);
    assert.equal((await hub.store.catFileBatch([entry?.sha as string])).get(entry?.sha as string)?.content.toString(), raw);
    // reading by id and diffing do not run drivers either
    await hub.store.diffTreeRaw(null, tree);
    const commit = await hub.trees.commitTree({ tree, parents: [], message: 'm', identity: hub.identity });
    await hub.store.lsTree(commit);
    await hub.store.readCommitRaw(commit);
    assert.equal(await stat(marker).catch(() => null), null);
  });
});

test('assertTreePath refuses everything that is not a plain relative ledger path', () => {
  for (const ok of ['a.md', 'items/ACME-1.md', 'sub/dir/file.txt', '.gitignore', '.gitattributes', 'counters/d_abcdefghij.yml', 'x/.hidden']) {
    assertTreePath(ok);
  }
  for (const bad of [
    '',
    '/abs',
    'a/',
    'a//b',
    './a',
    'a/./b',
    '../a',
    'a/../b',
    'a/..',
    '.git',
    '.git/config',
    '.GIT/config',
    'x/.git/hooks/pre-commit',
    'x/.Git',
    'GIT~1/x',
    '.git./x',
    '.git /x',
    '.hub',
    '.hub/device/key',
    '.HUB/x',
    'a\\b',
    'a\0b',
    'a\nb',
    'a\x1bb',
    'a\x7fb',
    'a'.repeat(513),
  ]) {
    assert.throws(() => assertTreePath(bad), (e: unknown) => e instanceof TreeBuildError && e.code === 'PATH', JSON.stringify(bad));
  }
  assert.throws(() => assertTreePath(undefined), TreeBuildError);
  assert.throws(() => assertTreePath(7), TreeBuildError);
});

test('buildTree: bad paths, duplicates, oversize and bad base are refused before anything is written', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const before = await snapshot(hub);
    for (const path of ['.git/config', '../x', '.hub/key', '/abs', 'a\\b']) {
      await assert.rejects(hub.trees.buildTree(null, [{ path, content: 'x' }]), (e: unknown) => e instanceof TreeBuildError && e.code === 'PATH', path);
      await assert.rejects(hub.trees.buildTree(null, [{ path, remove: true }]), TreeBuildError, `remove ${path}`);
    }
    await assert.rejects(hub.trees.buildTree(null, [{ path: 'a', content: '1' }, { path: 'a', content: '2' }]), (e: unknown) => e instanceof TreeBuildError && e.code === 'PATH');
    await assert.rejects(hub.trees.buildTree(null, [{ path: 'a', content: '1' }, { path: 'a', remove: true }]), TreeBuildError);
    await assert.rejects(hub.trees.buildTree(null, [{ path: 'big', content: Buffer.alloc(8 * 1024 * 1024 + 1) }]), (e: unknown) => e instanceof TreeBuildError && e.code === 'LIMIT');
    await assert.rejects(hub.trees.buildTree('HEAD', []), GitxError);
    await assert.rejects(hub.trees.buildTree('--help', []), GitxError);
    assert.deepEqual(await snapshot(hub), before);
  });
});

test('buildTree can only write regular files: modes and symlinks cannot be expressed', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const hostile = { path: 'l', content: 'target', mode: '120000' } as unknown as { path: string; content: string };
    const tree = await hub.trees.buildTree(null, [hostile]);
    assert.deepEqual((await hub.store.lsTree(tree)).map((e) => e.mode), ['100644']);
  });
});

test('commitTree: identity, parents, trailing newline, date', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const tree = await hub.trees.buildTree(null, [{ path: 'a.md', content: 'x\n' }]);
    const p1 = await hub.trees.commitTree({ tree, parents: [], message: 'root', identity: hub.identity });
    const date = new Date('2026-11-16T10:00:00Z');
    const c = await hub.trees.commitTree({ tree, parents: [p1], message: 'second', identity: hub.identity, date });
    const raw = (await hub.store.readCommitRaw(c)).toString('utf8');
    assert.ok(raw.includes(`parent ${p1}\n`));
    assert.ok(raw.includes(`author hub1 <${hub.deviceId}@devices.agent-ledger.invalid> ${Math.floor(date.getTime() / 1000)} +0000\n`));
    assert.ok(raw.includes(`committer hub1 <${hub.deviceId}@devices.agent-ledger.invalid> ${Math.floor(date.getTime() / 1000)} +0000\n`));
    assert.ok(raw.endsWith('\n\nsecond\n'));
    assert.ok(!raw.includes('gpgsig'), 'unsigned unless a signing input is given');
    assert.deepEqual((await hub.store.revList(null, c)).map((x) => x.sha), [p1, c]);
  });
});

test('commitTree with signing: a real SSH signature that verifies against the device key only (namespace git)', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const other = await kit.makeHub(2);
    const sha = await hub.commit([{ path: 'a.md', content: 'x\n' }], { message: 'signed one' });
    const raw = await hub.store.readCommitRaw(sha);
    const v = await verifyCommitSignature(raw, { tmpRoot: nodePath.join(hub.syncDir, 'tmp') });
    assert.equal(v.valid, true, v.reason);
    assert.equal(v.pubkeyLine, hub.pub.line);
    assert.notEqual(v.pubkeyLine, other.pub.line);
    const unsigned = await hub.commit([{ path: 'b.md', content: 'y\n' }], { signed: false });
    const v2 = await verifyCommitSignature(await hub.store.readCommitRaw(unsigned), { tmpRoot: nodePath.join(hub.syncDir, 'tmp') });
    assert.equal(v2.valid, false);
    assert.equal(v2.reason, 'unsigned');
  });
});

test('commitTree refuses hostile identities, parents, trees and messages', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const tree = await hub.trees.buildTree(null, [{ path: 'a.md', content: 'x\n' }]);
    const base = { tree, parents: [] as string[], message: 'm', identity: hub.identity };
    for (const identity of [
      { name: 'a<b', email: 'a@b.invalid' },
      { name: 'a>b', email: 'a@b.invalid' },
      { name: 'a\nb', email: 'a@b.invalid' },
      { name: '', email: 'a@b.invalid' },
      { name: ' padded', email: 'a@b.invalid' },
      { name: 'x'.repeat(101), email: 'a@b.invalid' },
      { name: 'ok', email: 'no-at-sign' },
      { name: 'ok', email: 'a@b.invalid\nCommitter: x' },
      { name: 'ok', email: 'a b@c.invalid' },
      { name: 'ok', email: '<a@b.invalid>' },
    ]) {
      await assert.rejects(hub.trees.commitTree({ ...base, identity }), (e: unknown) => e instanceof TreeBuildError && e.code === 'IDENTITY', JSON.stringify(identity));
    }
    await assert.rejects(hub.trees.commitTree({ ...base, tree: 'HEAD' }), GitxError);
    await assert.rejects(hub.trees.commitTree({ ...base, parents: ['--root'] }), GitxError);
    await assert.rejects(hub.trees.commitTree({ ...base, parents: [tree, tree] }), (e: unknown) => e instanceof TreeBuildError && e.code === 'ARGS');
    await assert.rejects(hub.trees.commitTree({ ...base, message: 'a\0b' }), TreeBuildError);
    await assert.rejects(hub.trees.commitTree({ ...base, message: 'm'.repeat(5000) }), TreeBuildError);
    await assert.rejects(hub.trees.commitTree({ ...base, date: new Date(-5) }), TreeBuildError);
  });
});

test('updateRef: compare-and-swap, old id required, zero id refused, must be a fast-forward, only main/accepted', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([{ path: 'a.md', content: '1\n' }]);
    const c2 = await hub.commit([{ path: 'a.md', content: '2\n' }]);
    const c3 = await hub.commit([{ path: 'a.md', content: '3\n' }]);
    // main is c3 now; rewind the ref (test setup) to c1 and move it forward with CAS
    await hub.gitx.mustRun(['update-ref', REF_MAIN, c1], { cwd: hub.dir });
    await hub.trees.updateRef(REF_MAIN, c2, c1);
    assert.equal(await hub.main(), c2);

    // lost race: expected old (c1) is an ancestor of the new tip but not the current value => CAS error, main unchanged
    await assert.rejects(hub.trees.updateRef(REF_MAIN, c3, c1), (e: unknown) => e instanceof TreeBuildError && e.code === 'CAS');
    assert.equal(await hub.main(), c2);

    // old id missing / zero / malformed => refused without touching git
    for (const old of [undefined, '', '0'.repeat(40), 'HEAD', 'e'.repeat(39)]) {
      await assert.rejects(hub.trees.updateRef(REF_MAIN, c3, old as never), (e: unknown) => e instanceof TreeBuildError || e instanceof GitxError, String(old));
    }
    await assert.rejects(hub.trees.updateRef(REF_MAIN, '0'.repeat(40), c2), TreeBuildError);
    assert.equal(await hub.main(), c2);

    // not a fast-forward: new tip does not descend from old
    const orphan = await hub.trees.commitTree({ tree: await hub.trees.buildTree(null, [{ path: 'z.md', content: 'z\n' }]), parents: [], message: 'orphan', identity: hub.identity });
    await assert.rejects(hub.trees.updateRef(REF_MAIN, orphan, c2), (e: unknown) => e instanceof TreeBuildError && e.code === 'NOT_FF');
    await assert.rejects(hub.trees.updateRef(REF_MAIN, c1, c2), (e: unknown) => e instanceof TreeBuildError && e.code === 'NOT_FF', 'rollback refused');
    assert.equal(await hub.main(), c2);

    // refs other than main / accepted cannot be named
    for (const ref of ['refs/heads/other', 'refs/heads/main2', 'refs/ledger-sync/incoming', 'HEAD', '--delete', 'refs/tags/x']) {
      await assert.rejects(hub.trees.updateRef(ref, c3, c2), (e: unknown) => e instanceof TreeBuildError && e.code === 'REF', ref);
    }
    await hub.trees.updateRef(REF_MAIN, c3, c2);
    assert.equal(await hub.main(), c3);
  });
});

test('updateRef: of two racing writers from the same old tip exactly one wins', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([{ path: 'a.md', content: '1\n' }]);
    const t = await hub.trees.buildTree(c1, [{ path: 'a.md', content: 'x\n' }]);
    const left = await hub.trees.commitTree({ tree: t, parents: [c1], message: 'left', identity: hub.identity });
    const right = await hub.trees.commitTree({ tree: t, parents: [c1], message: 'right', identity: hub.identity });
    const results = await Promise.allSettled([hub.trees.updateRef(REF_MAIN, left, c1), hub.trees.updateRef(REF_MAIN, right, c1)]);
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    const rejected = results.find((r) => r.status === 'rejected');
    assert.ok(rejected?.status === 'rejected' && rejected.reason instanceof TreeBuildError && rejected.reason.code === 'CAS');
    const tip = await hub.main();
    assert.ok(tip === left || tip === right);
  });
});

test('accepted ref: createRef only creates, updateRef then moves it forward', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([{ path: 'a.md', content: '1\n' }]);
    const c2 = await hub.commit([{ path: 'a.md', content: '2\n' }]);
    const store = new ObjectStore(hub.gitx, hub.dir);
    assert.equal(await store.revParse(REF_ACCEPTED), null);
    await hub.trees.createRef(REF_ACCEPTED, c1);
    assert.equal(await store.revParse(REF_ACCEPTED), c1);
    await assert.rejects(hub.trees.createRef(REF_ACCEPTED, c2), (e: unknown) => e instanceof TreeBuildError && e.code === 'CAS', 'never overwrites');
    assert.equal(await store.revParse(REF_ACCEPTED), c1);
    await hub.trees.updateRef(REF_ACCEPTED, c2, c1);
    assert.equal(await store.revParse(REF_ACCEPTED), c2);
    await assert.rejects(hub.trees.createRef(REF_MAIN, c2), (e: unknown) => e instanceof TreeBuildError && e.code === 'REF');
    await assert.rejects(hub.trees.updateRef(REF_ACCEPTED, c1, c2), (e: unknown) => e instanceof TreeBuildError && e.code === 'NOT_FF');
  });
});
