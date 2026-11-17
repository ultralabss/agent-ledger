/** Read-only object access by id (docs/f3b-plan.md §3: batch caps, strict ids; S4, S6, invariant 4). */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import nodePath from 'node:path';
import test from 'node:test';
import { withPrivateTmp } from '@agent-ledger/shared';
import { GitxError, isSha, assertSha, type Gitx } from './gitx.ts';
import { MAX_COMMIT_BYTES, ObjectStore, ObjectsError } from './objects.ts';
import { makeKit, type Kit } from './testkit-remote.ts';

const posix = process.platform !== 'win32';

async function withKit<T>(fn: (kit: Kit) => Promise<T>): Promise<T> {
  const kit = await makeKit();
  try {
    return await fn(kit);
  } finally {
    await kit.cleanup();
  }
}

/** Commit built from raw `update-index --index-info` records: for shapes the production builders refuse. */
async function commitFromIndexInfo(gitx: Gitx, cwd: string, tmpRoot: string, records: Buffer[], parent?: string): Promise<string> {
  return withPrivateTmp(tmpRoot, async (dir) => {
    const extraEnv = { GIT_INDEX_FILE: nodePath.join(dir, 'index') } as const;
    if (parent !== undefined) await gitx.mustRun(['read-tree', parent], { cwd, extraEnv });
    await gitx.mustRun(['update-index', '-z', '--index-info'], { cwd, extraEnv, input: Buffer.concat(records) });
    const tree = (await gitx.mustRun(['write-tree'], { cwd, extraEnv })).stdout.toString().trim();
    const args = ['commit-tree', tree, ...(parent !== undefined ? ['-p', parent] : []), '-F', '-'];
    const out = await gitx.mustRun(args, {
      cwd,
      input: 'raw\n',
      extraConfig: ['user.name=t', 'user.email=t@devices.agent-ledger.invalid'],
    });
    return out.stdout.toString().trim();
  });
}

async function blobSha(gitx: Gitx, cwd: string, bytes: Buffer): Promise<string> {
  return (await gitx.mustRun(['hash-object', '-w', '--no-filters', '--stdin'], { cwd, input: bytes })).stdout.toString().trim();
}

test('isSha / assertSha accept only lowercase 40/64 hex', () => {
  assert.equal(isSha('a'.repeat(40)), true);
  assert.equal(isSha('0123456789abcdef'.repeat(4)), true);
  for (const bad of ['', 'a'.repeat(39), 'a'.repeat(41), 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(40), `${'a'.repeat(39)}g`, `${'a'.repeat(40)}\n`, ` ${'a'.repeat(40)}`, '--upload-pack=x', 'HEAD', 'refs/heads/main', 'main^{commit}', '-'.repeat(40), 42, null, undefined]) {
    assert.equal(isSha(bad), false, JSON.stringify(bad));
  }
  assert.throws(() => assertSha('HEAD'), GitxError);
});

test('revParse resolves a ref once, null when missing, and refuses hostile names', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    assert.equal(await hub.store.revParse('refs/heads/main'), null);
    const c1 = await hub.commit([{ path: 'a.md', content: 'x\n' }]);
    assert.equal(await hub.store.revParse('refs/heads/main'), c1);
    assert.equal(await hub.store.revParse('refs/ledger-sync/incoming'), null);
    for (const bad of ['--upload-pack=x', '-x', 'HEAD', 'main', 'refs/../x', 'refs//x', 'refs/heads/', 'refs/heads/x.lock', 'refs/heads/a b', 'refs/heads/a\nb', `refs/heads/${'a'.repeat(300)}`, c1]) {
      await assert.rejects(hub.store.revParse(bad), (e: unknown) => e instanceof ObjectsError && e.code === 'REF', JSON.stringify(bad));
    }
  });
});

test('hasCommit', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([{ path: 'a.md', content: 'x\n' }]);
    assert.equal(await hub.store.hasCommit(c1), true);
    assert.equal(await hub.store.hasCommit('e'.repeat(40)), false);
    await assert.rejects(hub.store.hasCommit('HEAD'), GitxError);
  });
});

test('revList: oldest first with parents, range semantics, cap throws instead of truncating', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const shas: string[] = [];
    for (let i = 0; i < 5; i++) shas.push(await hub.commit([{ path: 'a.md', content: `v${i}\n` }]));
    const all = await hub.store.revList(null, shas[4] as string);
    assert.deepEqual(all.map((c) => c.sha), shas);
    assert.deepEqual(all[0]?.parents, []);
    assert.deepEqual(all[3]?.parents, [shas[2]]);
    const range = await hub.store.revList(shas[1] as string, shas[4] as string);
    assert.deepEqual(range.map((c) => c.sha), shas.slice(2));
    assert.deepEqual(await hub.store.revList(shas[4] as string, shas[4] as string), []);
    await assert.rejects(hub.store.revList(null, shas[4] as string, 3), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT');
    assert.equal((await hub.store.revList(null, shas[4] as string, 5)).length, 5);
    await assert.rejects(hub.store.revList('--all', shas[4] as string), GitxError);
    await assert.rejects(hub.store.revList(null, 'refs/heads/main'), GitxError);
  });
});

test('revList: merge commits list both parents', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const root = await hub.commit([{ path: 'a.md', content: 'x\n' }]);
    assert.equal((await hub.pushMain(kit.remote)).ok, true);
    const right = await kit.remote.rawCommit({ files: [{ path: 'r.md', content: 'r\n' }], parents: [root] });
    const left = await hub.commit([{ path: 'l.md', content: 'l\n' }]);
    assert.equal(await hub.fetchIncoming(kit.remote), right);
    const merge = await hub.trees.commitTree({
      tree: await hub.trees.buildTree(left, [{ path: 'r.md', content: 'r\n' }]),
      parents: [left, right],
      message: 'merge',
      identity: hub.identity,
    });
    const list = await hub.store.revList(root, merge);
    const m = list.find((c) => c.sha === merge);
    assert.deepEqual(m?.parents, [left, right]);
    assert.equal(list[list.length - 1]?.sha, merge, 'merge comes after its parents');
  });
});

test('isAncestor and mergeBase', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([{ path: 'a.md', content: '1\n' }]);
    const c2 = await hub.commit([{ path: 'a.md', content: '2\n' }]);
    assert.equal(await hub.store.isAncestor(c1, c2), true);
    assert.equal(await hub.store.isAncestor(c2, c1), false);
    assert.equal(await hub.store.isAncestor(c1, c1), true);
    assert.equal(await hub.store.mergeBase(c1, c2), c1);
    const other = await hub.trees.commitTree({ tree: await hub.trees.buildTree(null, [{ path: 'z.md', content: 'z\n' }]), parents: [], message: 'unrelated', identity: hub.identity });
    assert.equal(await hub.store.isAncestor(c1, other), false);
    assert.equal(await hub.store.mergeBase(c2, other), null);
    await assert.rejects(hub.store.isAncestor('e'.repeat(40), c1), GitxError, 'unknown object is an error, not "no"');
    await assert.rejects(hub.store.isAncestor('HEAD', c1), GitxError);
  });
});

test('lsTree: sizes, modes, nested paths, submodule entry, non-UTF-8 path flagged', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const base = await hub.commit([
      { path: 'items/a.md', content: 'hello\n' },
      { path: 'z.md', content: '' },
    ]);
    const entries = await hub.store.lsTree(base);
    assert.deepEqual(entries.map((e) => [e.path, e.mode, e.type, e.size, e.badUtf8]), [
      ['items/a.md', '100644', 'blob', 6, false],
      ['z.md', '100644', 'blob', 0, false],
    ]);
    assert.ok(entries.every((e) => isSha(e.sha)));

    const sym = await blobSha(hub.gitx, hub.dir, Buffer.from('../../etc/passwd'));
    const odd = await blobSha(hub.gitx, hub.dir, Buffer.from('odd\n'));
    const tricky = await commitFromIndexInfo(
      hub.gitx,
      hub.dir,
      nodePath.join(hub.syncDir, 'tmp'),
      [
        Buffer.from(`120000 ${sym}\tlink\0`),
        Buffer.from(`160000 ${'d'.repeat(40)}\tsub\0`),
        Buffer.concat([Buffer.from(`100644 ${odd}\tbad-`), Buffer.from([0xff, 0xfe]), Buffer.from('.md\0')]),
        Buffer.from(`100755 ${odd}\texec.sh\0`),
      ],
      base,
    );
    const t = await hub.store.lsTree(tricky);
    const byPath = new Map(t.map((e) => [e.path, e]));
    assert.equal(byPath.get('link')?.mode, '120000');
    assert.equal(byPath.get('sub')?.mode, '160000');
    assert.equal(byPath.get('sub')?.type, 'commit');
    assert.equal(byPath.get('sub')?.size, null);
    assert.equal(byPath.get('exec.sh')?.mode, '100755');
    assert.ok(t.some((e) => e.badUtf8), 'a non-UTF-8 path must be flagged for the validator');
    assert.ok(t.some((e) => e.path === 'items/a.md' && !e.badUtf8));

    await assert.rejects(hub.store.lsTree(tricky, 3), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT');
    await assert.rejects(hub.store.lsTree('HEAD'), GitxError);
  });
});

test('diffTreeRaw: A/M/D, modes, against the empty tree, cap', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([
      { path: 'a.md', content: '1\n' },
      { path: 'b.md', content: '1\n' },
    ]);
    const c2 = await hub.commit([
      { path: 'a.md', content: '2\n' },
      { path: 'b.md', remove: true },
      { path: 'sub/c.md', content: 'c\n' },
    ]);
    const rootDiff = await hub.store.diffTreeRaw(null, c1);
    assert.deepEqual(rootDiff.map((d) => [d.status, d.path, d.srcMode, d.dstMode]), [
      ['A', 'a.md', '000000', '100644'],
      ['A', 'b.md', '000000', '100644'],
    ]);
    const d = await hub.store.diffTreeRaw(c1, c2);
    assert.deepEqual(d.map((x) => [x.status, x.path]), [
      ['M', 'a.md'],
      ['D', 'b.md'],
      ['A', 'sub/c.md'],
    ]);
    assert.ok(d.every((x) => isSha(x.srcSha) && isSha(x.dstSha) && !x.badUtf8));
    assert.deepEqual(await hub.store.diffTreeRaw(c2, c2), []);
    // a symlink and an exec bit are visible as modes (ingress rejects them later)
    const hostile = await kit.remote.rawCommit({
      files: [
        { path: 'l', content: 'target', mode: '120000' },
        { path: 'x.sh', content: '#!/bin/sh\n', mode: '100755' },
      ],
      parents: [],
      setMain: false,
    });
    const hd = await kit.remote.store.diffTreeRaw(null, hostile);
    assert.deepEqual(hd.map((x) => [x.path, x.dstMode]), [
      ['l', '120000'],
      ['x.sh', '100755'],
    ]);
    await assert.rejects(hub.store.diffTreeRaw(null, c2, 1), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT');
    await assert.rejects(hub.store.diffTreeRaw('--cached', c2), GitxError);
  });
});

test('catFileBatch: exact bytes (binary, NUL, newlines), dedupes, preserves types', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const bin = Buffer.concat([randomBytes(2000), Buffer.from('\n\0\n\n'), randomBytes(500)]);
    const sha = await blobSha(hub.gitx, hub.dir, bin);
    const empty = await blobSha(hub.gitx, hub.dir, Buffer.alloc(0));
    const text = await blobSha(hub.gitx, hub.dir, Buffer.from('line1\r\nline2\r\n'));
    const m = await hub.store.catFileBatch([sha, empty, text, sha], { expectType: 'blob' });
    assert.equal(m.size, 3);
    assert.ok(m.get(sha)?.content.equals(bin));
    assert.equal(m.get(empty)?.size, 0);
    assert.equal(m.get(text)?.content.toString(), 'line1\r\nline2\r\n', 'no CRLF conversion on read');
    assert.equal(m.get(sha)?.type, 'blob');
    assert.equal((await hub.store.catFileBatch([])).size, 0);
  });
});

test('catFileBatch: count, per-object and total caps, missing object, wrong type, bad ids', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const big = await blobSha(hub.gitx, hub.dir, Buffer.alloc(300_000, 0x61));
    const a = await blobSha(hub.gitx, hub.dir, Buffer.alloc(100_000, 0x62));
    const b = await blobSha(hub.gitx, hub.dir, Buffer.alloc(100_000, 0x63));
    const c1 = await hub.commit([{ path: 'a.md', content: 'x\n' }]);

    await assert.rejects(hub.store.catFileBatch([big]), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT', 'default per-object cap is 256 KiB');
    assert.equal((await hub.store.catFileBatch([big], { maxObjectBytes: 400_000, maxTotalBytes: 400_000 })).get(big)?.size, 300_000);
    await assert.rejects(hub.store.catFileBatch([a, b], { maxTotalBytes: 150_000 }), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT');
    assert.equal((await hub.store.catFileBatch([a, b], { maxTotalBytes: 200_000 })).size, 2);
    await assert.rejects(hub.store.catFileBatch([a, b], { maxCount: 1 }), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT');
    await assert.rejects(hub.store.catFileBatch(['f'.repeat(40)]), (e: unknown) => e instanceof ObjectsError && e.code === 'MISSING');
    await assert.rejects(hub.store.catFileBatch([c1], { expectType: 'blob' }), (e: unknown) => e instanceof ObjectsError && e.code === 'TYPE');
    for (const bad of ['HEAD', 'A'.repeat(40), `${a}\n${b}`, `${a} ${b}`, '--batch', '']) {
      await assert.rejects(hub.store.catFileBatch([bad]), GitxError, JSON.stringify(bad));
    }
  });
});

test('the size check happens before content is read: an over-cap object makes the stdout cap irrelevant', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const huge = await blobSha(hub.gitx, hub.dir, Buffer.alloc(3 * 1024 * 1024, 0x61));
    const t0 = Date.now();
    await assert.rejects(hub.store.catFileBatch([huge], { maxObjectBytes: 1024 }), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT');
    assert.ok(Date.now() - t0 < 5000);
  });
});

test('readCommitRaw returns the exact commit bytes and refuses non-commits and oversized commits', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([{ path: 'a.md', content: 'x\n' }], { message: 'hello' });
    const raw = await hub.store.readCommitRaw(c1);
    assert.match(raw.toString('latin1'), /^tree [0-9a-f]{40}\n(?:parent [0-9a-f]{40}\n)*author hub1 <d_[a-z2-7]{10}@devices\.agent-ledger\.invalid> \d+ [+-]\d{4}\ncommitter /);
    assert.ok(raw.toString('latin1').includes('gpgsig -----BEGIN SSH SIGNATURE-----'));
    const blob = await blobSha(hub.gitx, hub.dir, Buffer.from('x'));
    await assert.rejects(hub.store.readCommitRaw(blob), (e: unknown) => e instanceof ObjectsError && e.code === 'TYPE');
    const tree = await hub.trees.buildTree(null, [{ path: 'a.md', content: 'x' }]);
    const fat = await kit.remote.gitx.mustRun(['commit-tree', tree, '-F', '-'], {
      cwd: hub.dir,
      input: 'm'.repeat(MAX_COMMIT_BYTES + 10),
      extraConfig: ['user.name=t', 'user.email=t@devices.agent-ledger.invalid'],
    });
    await assert.rejects(hub.store.readCommitRaw(fat.stdout.toString().trim()), (e: unknown) => e instanceof ObjectsError && e.code === 'LIMIT');
  });
});

test('reads are by id: moving a ref afterwards does not change what an earlier id resolves to', { skip: !posix }, async () => {
  await withKit(async (kit) => {
    const hub = await kit.makeHub(1);
    const c1 = await hub.commit([{ path: 'a.md', content: 'one\n' }]);
    const tipAtStart = await hub.store.revParse('refs/heads/main');
    const c2 = await hub.commit([{ path: 'a.md', content: 'two\n' }]);
    assert.equal(tipAtStart, c1);
    const entries = await hub.store.lsTree(c1);
    const blob = await hub.store.catFileBatch([entries[0]?.sha as string]);
    assert.equal(blob.get(entries[0]?.sha as string)?.content.toString(), 'one\n');
    assert.notEqual(c1, c2);
  });
});
