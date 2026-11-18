/** B6 threat suite: `.hub/` never crosses the wire and the pinned `.gitignore` / `.gitattributes` never change
 *  (S13-14, F3b invariants 9-10). END-TO-END: hostile remote tip or local commit -> real `runCycle` -> nothing moved;
 *  and a REAL `Ledger` with sync on never stages `.hub/**` even when `.gitignore` lost its `.hub/` line. */

import assert from 'node:assert/strict';
import { readFile, realpath, stat, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { deviceLayout, gitSigningArgs, initDevice } from '@agent-ledger/shared';
import { Ledger } from '../ledger/ledger.ts';
import { tempConfig } from '../test-helpers.ts';
import { runCycle, type CycleResult } from './cycle.ts';
import { Gitx, REF_MAIN } from './gitx.ts';
import { hubRawCommit, type FlakyRemote, type Kit, type TestHub } from './testkit-remote.ts';
import { assertQuarantined, assertUntouched, bothModes, skipSync, snapshot, withRig, type Rig, type Snapshot } from './threatkit.ts';

let seq = 0;
const uniq = (what: string): string => `${what} #${String((seq += 1))}`;

/** One hostile tip -> one cycle in `mode` -> quarantined, nothing moved, never pushed, `.hub/x` absent. */
async function expectQuarantine(r: Rig, mode: 'warn' | 'enforce', tip: string, re: RegExp): Promise<void> {
  const before: Snapshot = await snapshot(r.lh);
  const { deps, flaky } = r.mk(0, { verify: mode });
  const res: CycleResult = await runCycle(deps);
  await assertQuarantined(r.lh, res, re, { tip, before, flaky });
  assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
  await assert.rejects(stat(nodePath.join(r.lh.dir, '.hub', 'x')), '.hub/x must not exist in the worktree');
}

/* ---------------- (a) `.hub` path variants on the remote ---------------- */

async function mktree(kit: Kit, lines: readonly string[]): Promise<string> {
  const out = await kit.remote.gitx.mustRun(['mktree', '-z'], { cwd: kit.remote.path, input: Buffer.from(lines.map((l) => `${l}\0`).join('')) });
  return out.stdout.toString('utf8').trim();
}

/** Signed commit on `base` whose tree is `base` + entries that `update-index` refuses to take (`a/../.hub`). */
async function treeTip(kit: Kit, signer: TestHub, base: string, rootLines: readonly string[], message: string): Promise<string> {
  const g = kit.remote.gitx;
  const cwd = kit.remote.path;
  const baseTree = (await g.mustRun(['rev-parse', `${base}^{tree}`], { cwd })).stdout.toString('utf8').trim();
  const ls = (await g.mustRun(['ls-tree', '-z', baseTree], { cwd })).stdout;
  const tree = (await g.mustRun(['mktree', '-z'], { cwd, input: Buffer.concat([ls, Buffer.from(rootLines.map((l) => `${l}\0`).join(''))]) })).stdout.toString('utf8').trim();
  const s = gitSigningArgs(signer.signing);
  const extraConfig = [`user.name=${signer.identity.name}`, `user.email=${signer.identity.email}`];
  for (let k = 1; k < s.length; k += 2) extraConfig.push(s[k] as string);
  const sha = (await g.mustRun(['commit-tree', tree, '-p', base, '-S', '-F', '-'], { cwd, input: `${message}\n`, extraConfig })).stdout.toString('utf8').trim();
  await kit.remote.forceMain(sha);
  return sha;
}

test('remote `.hub` path variants (case, trailing dot/space, any segment, traversal) are quarantined in warn and enforce', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const variants = ['.hub/x', '.HUB/x', '.Hub/x', '.hub./x', '.hub /x', 'acme/.hub/x', 'acme/.Hub./x', 'acme/items/.hub/x'];
    await bothModes(async (mode) => {
      // the tree layer is mode independent: `warn` samples two variants (time budget), `enforce` runs them all
      for (const path of mode === 'warn' ? variants.slice(0, 2) : variants) {
        const tip = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path, content: 'hostile\n' }], signer: r.other.hub, message: uniq(`${mode} ${path}`) });
        await expectQuarantine(r, mode, tip, /^quarantine:tree:hub-path$/);
      }
      // unsigned hub path: the tree layer wins before any provenance row
      const unsigned = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: '.hub/x', content: 'hostile\n' }], signer: null, message: uniq(`${mode} unsigned`) });
      await expectQuarantine(r, mode, unsigned, /^quarantine:tree:hub-path$/);
      // `a/../.hub/x` and `.hub` as a tree name that update-index refuses: built with mktree
      const x = (await r.kit.remote.gitx.mustRun(['hash-object', '-w', '--no-filters', '-t', 'blob', '--stdin'], { cwd: r.kit.remote.path, input: 'hostile\n' })).stdout.toString('utf8').trim();
      const hub = await mktree(r.kit, [`100644 blob ${x}\tx`]);
      const dotdot = await mktree(r.kit, [`040000 tree ${hub}\t.hub`]);
      const nested = await mktree(r.kit, [`040000 tree ${dotdot}\t..`]);
      const t1 = await treeTip(r.kit, r.other.hub, r.fleet.base, [`040000 tree ${nested}\ta`], uniq(`${mode} a/../.hub`));
      await expectQuarantine(r, mode, t1, /^quarantine:(fsck|tree:)/).catch(async (err: unknown) => {
        // a transport-level fsck refusal has no halt.tip: accept that outcome explicitly, never anything else
        const halt = (await r.lh.state.read()).halt;
        if (halt?.reason !== 'quarantine:fsck') throw err;
      });
    });
    // the honest tip after all of that still applies (the hostile tips were isolated, nothing is stuck)
    const ok = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: 'acme/CONTEXT.md', content: '# acme\nfine\n' }], signer: r.other.hub, message: uniq('honest') });
    const res = await runCycle(r.mk().deps);
    assert.equal(res.outcome, 'applied');
    assert.equal(await r.lh.hub.main(), ok);
  });
});

/* ---------------- (b) pinned files ---------------- */

test('remote .gitignore without the `.hub/` line, or any change to .gitattributes, is quarantined in warn and enforce', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    type Case = { name: string; files: ({ path: string; content: string } | { path: string; remove: true })[]; re: RegExp };
    const cases: Case[] = [
      { name: 'gitignore drops .hub/', files: [{ path: '.gitignore', content: '*.tmp\n' }], re: /^quarantine:tree:gitignore$/ },
      { name: 'gitignore empty', files: [{ path: '.gitignore', content: '' }], re: /^quarantine:tree:gitignore$/ },
      { name: 'gitignore commented', files: [{ path: '.gitignore', content: '# .hub/\n*.tmp\n' }], re: /^quarantine:tree:gitignore$/ },
      { name: 'gitignore negates', files: [{ path: '.gitignore', content: '.hub/\n*.tmp\n!.hub/device/key\n' }], re: /^quarantine:tree:gitignore$/ },
      { name: 'gitignore deleted', files: [{ path: '.gitignore', remove: true }], re: /^quarantine:tree:delete-protected$/ },
      { name: 'gitattributes crlf', files: [{ path: '.gitattributes', content: '* text eol=crlf\n' }], re: /^quarantine:tree:gitattributes$/ },
      { name: 'gitattributes driver', files: [{ path: '.gitattributes', content: '* text eol=lf\n* filter=evil\n' }], re: /^quarantine:tree:gitattributes-driver$/ },
      { name: 'gitattributes deleted', files: [{ path: '.gitattributes', remove: true }], re: /^quarantine:tree:delete-protected$/ },
      {
        name: 'both at once',
        files: [
          { path: '.gitignore', content: '*.tmp\n' },
          { path: '.gitattributes', content: '* -text\n' },
        ],
        re: /^quarantine:tree:git(ignore|attributes)$/,
      },
    ];
    await bothModes(async (mode) => {
      for (const c of mode === 'warn' ? cases.slice(0, 3) : cases) {
        const tip = await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: c.files, signer: r.other.hub, message: uniq(`${mode} ${c.name}`) });
        await expectQuarantine(r, mode, tip, c.re).catch((err: unknown) => {
          if (err instanceof Error) err.message = `[${c.name}] ${err.message}`;
          throw err;
        });
      }
    });
  });
});

/* ---------------- (c) REAL ledger, sync on ---------------- */

const ITEM = { kind: 'BACKLOG', priority: 'P2', owner: 'agent', steps: [] as string[], blocked_by: [] as string[], aliases: [] as string[], proposed: false } as const;

test('real Ledger (sync on): a worktree .gitignore without `.hub/` never gets .hub/** tracked or into any commit object', { skip: skipSync }, async () => {
  const tmp = await tempConfig({ sync: true, commitDebounceMs: 3_600_000 });
  const dir = await realpath(tmp.dir);
  let ledger: Ledger | null = null;
  try {
    await initDevice(dir, { root: true, label: 'a' });
    ledger = new Ledger({ config: { ...tmp.config, ledgerDir: dir }, log: () => undefined });
    await ledger.init();
    await ledger.git.flush();
    const gitx = await Gitx.open({ syncDir: nodePath.join(dir, '.hub', 'sync') });
    const git = async (args: string[]): Promise<string> => (await gitx.mustRun(args, { cwd: dir })).stdout.toString('utf8');
    const layout = deviceLayout(dir);
    const secretFiles = [layout.keyFile, nodePath.join(dir, '.hub', 'token')];
    const hashes: string[] = [];
    for (const f of secretFiles) {
      if (await stat(f).then(() => true, () => false)) hashes.push((await git(['hash-object', '--no-filters', '--', f])).trim());
    }
    assert.ok(hashes.length >= 1, 'the device key exists (otherwise the test proves nothing)');
    const keyText = await readFile(layout.keyFile, 'utf8');

    await ledger.createItem({ ...ITEM, repo: 'ops', title: 'item written while .gitignore is hostile' });
    await writeFile(nodePath.join(dir, '.gitignore'), '*.tmp\n'); // the `.hub/` line is gone
    ledger.git.touch('hostile gitignore');
    await ledger.git.flush();
    // the hostile file is still what the worktree holds: a plain `git add -A` WOULD have staged .hub/device/key
    assert.equal(await readFile(nodePath.join(dir, '.gitignore'), 'utf8'), '*.tmp\n');

    const tracked = (await git(['ls-files', '-z'])).split('\0').filter((p) => p !== '');
    assert.deepEqual(tracked.filter((p) => p.toLowerCase().replace(/[. ]+$/, '').startsWith('.hub')), [], 'the index (ls-files) lists nothing under .hub/');
    const objects = (await git(['rev-list', '--objects', '--all'])).split('\n').map((l) => l.split(' ')[0] as string);
    for (const h of hashes) assert.ok(!objects.includes(h), 'a secret blob is reachable from a ref');
    // and no blob content anywhere equals the key text (loose objects are zlib-compressed: compare by hash above, by path here)
    const paths = (await git(['rev-list', '--objects', '--all'])).split('\n').map((l) => l.slice(41));
    assert.ok(!paths.some((p) => p.toLowerCase().startsWith('.hub')), 'no object is named .hub/...');
    assert.ok(keyText.length > 0);
  } finally {
    await ledger?.close().catch(() => undefined);
    await tmp.cleanup();
  }
});

/* ---------------- (d) local raw commit staging .hub/** ---------------- */

test('a LOCAL commit that stages .hub/device/key (or any .hub path) is push-blocked and never pushed', { skip: skipSync }, async () => {
  for (const path of ['.hub/device/key', 'acme/.hub/leak']) {
    await withRig(2, async (r) => {
      const sha = await hubRawCommit(r.lh.hub, { files: [{ path, content: 'hostile\n' }], signer: r.lh.hub, identity: r.lh.hub.identity, message: 'stage a hub path' });
      await r.lh.adopt(sha);
      assert.equal(await r.lh.hub.main(), sha);
      const remoteBefore = await r.kit.remote.main();
      const { deps, flaky }: { deps: Parameters<typeof runCycle>[0]; flaky: FlakyRemote } = r.mk(0);
      const res = await runCycle(deps);
      assert.equal(res.outcome, 'push-blocked', path);
      assert.equal(flaky.pushCalls, 0, `${path}: never pushed`);
      assert.equal(await r.kit.remote.main(), remoteBefore, 'remote unchanged');
      const st = await r.lh.state.read();
      assert.equal(st.pushBlocked?.rule, 'hub-path', path);
      assert.equal(st.halt, null, 'egress is a hold, not a halt: local work continues');
      assert.equal(await r.lh.hub.main(), sha, 'local commit kept');
      // a second cycle stays blocked and still does not push
      const again = r.mk(0);
      assert.equal((await runCycle(again.deps)).outcome, 'push-blocked');
      assert.equal(again.flaky.pushCalls, 0);
      void REF_MAIN;
    });
  }
});
