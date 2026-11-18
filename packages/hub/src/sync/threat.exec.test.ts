/** B6 threat suite: code execution (S9-11, F3b invariant 13). END-TO-END: a hostile hook / attribute / git config /
 *  tree shape / process environment -> real `runCycle` -> a CANARY file must never appear.
 *
 *  Canary design: every vector is armed so that, if it ran, it would `touch <kit.root>/canary-<name>`. The tests
 *  assert that no `canary-*` entry exists after the FF, merge and push cycles. A sanity step proves the armed
 *  scripts really would create the canary (so an absent canary is not a vacuous pass).
 *  UNVERIFIED: Windows (the scripts are `/bin/sh`; the suite is POSIX-gated unless LEDGER_TEST_SYNC_WIN32=1). */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { gitSigningArgs } from '@agent-ledger/shared';
import { runCycle, type CycleResult } from './cycle.ts';
import type { FlakyRemote, Kit, TestHub } from './testkit-remote.ts';
import { assertUntouched, ctx, skipSync, snapshot, withRig, type Rig, type Snapshot } from './threatkit.ts';

/* ---------------- canaries ---------------- */

const canaryFile = (kit: Kit, name: string): string => nodePath.join(kit.root, `canary-${name}`);

/** `/bin/sh` script that creates the canary. */
async function armScript(file: string, canary: string): Promise<void> {
  await writeFile(file, `#!/bin/sh\ntouch '${canary}'\n`, { mode: 0o755 });
  await chmod(file, 0o755);
}

async function assertNoCanary(kit: Kit): Promise<void> {
  const hits = (await readdir(kit.root)).filter((n) => n.startsWith('canary-'));
  assert.deepEqual(hits, [], 'a canary was created: something executed hostile configuration');
}

/** Proof the armed script works (so "no canary" means "not executed"), then the canary is removed again. */
async function sanity(kit: Kit, script: string, canary: string): Promise<void> {
  if (process.platform === 'win32') return;
  const r = spawnSync('/bin/sh', [script], { stdio: 'ignore' });
  assert.equal(r.status, 0, 'armed script runs');
  await stat(canary);
  await rm(canary);
  await assertNoCanary(kit);
}

/* ---------------- hostile remote tips built with plumbing ---------------- */

let seq = 0;

async function blobOf(kit: Kit, text: string): Promise<string> {
  const out = await kit.remote.gitx.mustRun(['hash-object', '-w', '--no-filters', '-t', 'blob', '--stdin'], { cwd: kit.remote.path, input: text });
  return out.stdout.toString('utf8').trim();
}

async function mktree(kit: Kit, lines: readonly string[]): Promise<string> {
  const out = await kit.remote.gitx.mustRun(['mktree', '-z'], { cwd: kit.remote.path, input: Buffer.from(lines.map((l) => `${l}\0`).join('')) });
  return out.stdout.toString('utf8').trim();
}

/** Signed commit on top of `base` whose tree = base + `index` entries (`<mode> <sha>\t<path>`, update-index rules)
 *  + `root` entries (`<mode> <type> <sha>\t<name>`, `mktree` rules: ANY name, e.g. `.GIT`). `main` moves to it. */
async function tipFrom(kit: Kit, signer: TestHub, base: string, o: { index?: readonly string[]; root?: readonly string[]; message: string }): Promise<string> {
  const g = kit.remote.gitx;
  const cwd = kit.remote.path;
  const extraEnv = { GIT_INDEX_FILE: nodePath.join(kit.root, `rawidx-${String((seq += 1))}`) } as const;
  await g.mustRun(['read-tree', base], { cwd, extraEnv });
  if (o.index !== undefined && o.index.length > 0) {
    await g.mustRun(['update-index', '-z', '--index-info'], { cwd, extraEnv, input: Buffer.from(o.index.map((l) => `${l}\0`).join('')) });
  }
  let tree = (await g.mustRun(['write-tree'], { cwd, extraEnv })).stdout.toString('utf8').trim();
  if (o.root !== undefined && o.root.length > 0) {
    const ls = (await g.mustRun(['ls-tree', '-z', tree], { cwd })).stdout;
    const input = Buffer.concat([ls, Buffer.from(o.root.map((l) => `${l}\0`).join(''))]);
    tree = (await g.mustRun(['mktree', '-z'], { cwd, input })).stdout.toString('utf8').trim();
  }
  const s = gitSigningArgs(signer.signing);
  const extraConfig = [`user.name=${signer.identity.name}`, `user.email=${signer.identity.email}`];
  for (let k = 1; k < s.length; k += 2) extraConfig.push(s[k] as string);
  const out = await g.mustRun(['commit-tree', tree, '-p', base, '-S', '-F', '-'], { cwd, input: `${o.message}\n`, extraConfig });
  const sha = out.stdout.toString('utf8').trim();
  await kit.remote.forceMain(sha);
  return sha;
}

async function assertHeld(r: Rig, res: CycleResult, before: Snapshot, flaky: FlakyRemote, re: RegExp, what = ''): Promise<void> {
  assert.match(res.halted ?? '', re, `${what}: outcome=${res.outcome} halted=${res.halted ?? '-'}`);
  assert.notEqual(res.applied, true, 'nothing applied');
  assert.equal(flaky.pushCalls, 0, 'a held tip is never pushed');
  assert.equal(await r.lh.hub.main(), before.main, 'main moved');
  assertUntouched(before, await snapshot(r.lh), { allow: ['incoming', 'state'] });
}

/* ---------------- (a) hooks ---------------- */

const HOOKS = [
  'post-merge',
  'post-checkout',
  'reference-transaction',
  'pre-push',
  'post-index-change',
  'post-commit',
  'pre-commit',
  'commit-msg',
  'prepare-commit-msg',
  'post-rewrite',
  'pre-merge-commit',
  'update',
  'post-update',
  'pre-auto-gc',
  'fsmonitor-watchman',
] as const;

test('executable hooks in .git/hooks never run: FF, merge+push and local push cycles', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const dir = nodePath.join(r.lh.dir, '.git', 'hooks');
    await mkdir(dir, { recursive: true });
    for (const h of HOOKS) await armScript(nodePath.join(dir, h), canaryFile(r.kit, `hook-${h}`));
    await sanity(r.kit, nodePath.join(dir, 'pre-push'), canaryFile(r.kit, 'hook-pre-push'));
    // FF: remote moved, local did not (update-ref / read-tree run; reference-transaction would fire)
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote edit\n')]);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'applied');
    await assertNoCanary(r.kit);
    // merge: both moved -> merge commit (commit-tree), update-ref, push (pre-push)
    await r.kit.remote.pushSigned(r.other.hub, [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }]);
    await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# decisions\n' }]);
    const merged = r.mk();
    assert.equal((await runCycle(merged.deps)).outcome, 'pushed');
    assert.equal(merged.flaky.pushCalls, 1);
    await assertNoCanary(r.kit);
    // local-only commit pushed
    await r.lh.commitLocal([ctx('# acme\nlocal only\n')]);
    assert.equal((await runCycle(r.mk().deps)).outcome, 'pushed');
    await assertNoCanary(r.kit);
    assert.equal(await r.kit.remote.main(), await r.lh.hub.main());
  });
});

/* ---------------- (b) attributes (remote) and git config (local) ---------------- */

test('remote .gitattributes with filter / merge / diff drivers is quarantined (never applied, nothing executes)', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const variants: [string, RegExp][] = [
      ['* filter=evil\n', /^quarantine:tree:gitattributes-driver$/],
      ['* merge=evil\n', /^quarantine:tree:gitattributes-driver$/],
      ['*.md diff=evil\n', /^quarantine:tree:gitattributes-driver$/],
      ['* text eol=lf\n* filter=lfs\n', /^quarantine:tree:gitattributes-driver$/],
      ['* text eol=crlf\n', /^quarantine:tree:gitattributes$/],
      ['', /^quarantine:tree:gitattributes$/],
    ];
    for (const [text, re] of variants) {
      const before = await snapshot(r.lh);
      await r.kit.remote.rawCommit({ parents: [r.fleet.base], files: [{ path: '.gitattributes', content: text }], signer: r.other.hub, message: `attrs ${String(seq += 1)}` });
      const { deps, flaky } = r.mk();
      await assertHeld(r, await runCycle(deps), before, flaky, re, text);
    }
    await assertNoCanary(r.kit);
  });
});

/** Local `.git/config` constructs that would turn into a command or redirect the remote (S11): HALT config, no contact. */
const CONFIG_CASES: readonly [string, (c: string, root: string) => string][] = [
  ['filter', (c) => `[filter "evil"]\n\tclean = touch '${c}'\n\tsmudge = touch '${c}'\n`],
  ['merge driver', (c) => `[merge "evil"]\n\tdriver = touch '${c}' %O\n`],
  ['core.fsmonitor', (c) => `[core]\n\tfsmonitor = touch '${c}'\n`],
  ['core.sshCommand', (c) => `[core]\n\tsshCommand = touch '${c}'\n`],
  ['core.hooksPath', (_c, root) => `[core]\n\thooksPath = ${root}/hooks-evil\n`],
  ['url.insteadOf', () => '[url "ssh://evil.invalid/"]\n\tinsteadOf = https://x/\n'],
  ['include.path', (_c, root) => `[include]\n\tpath = ${root}/evil.cfg\n`],
  ['includeIf', (_c, root) => `[includeIf "gitdir:/"]\n\tpath = ${root}/evil.cfg\n`],
  ['alias', (c) => `[alias]\n\tpush = !touch '${c}'\n`],
  ['diff.external', (c) => `[diff]\n\texternal = touch '${c}'\n`],
  ['gpg.ssh.program', (c) => `[gpg "ssh"]\n\tprogram = touch '${c}'\n`],
  ['credential.helper', (c) => `[credential]\n\thelper = !touch '${c}'\n`],
  ['unparseable', () => '[core\n\tbare = false\n'],
];

test('hostile local .git/config (filter, merge, fsmonitor, sshCommand, hooksPath, url, include, ...) -> HALT config with no contact; fixed -> clears', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const cfgPath = nodePath.join(r.lh.dir, '.git', 'config');
    const original = await readFile(cfgPath, 'utf8');
    await armScript(nodePath.join(r.kit.root, 'evil.sh'), canaryFile(r.kit, 'sanity'));
    await sanity(r.kit, nodePath.join(r.kit.root, 'evil.sh'), canaryFile(r.kit, 'sanity'));
    await r.kit.remote.pushSigned(r.other.hub, [ctx('# acme\nremote\n')]); // something to fetch, were the halt not enforced
    for (const [name, make] of CONFIG_CASES) {
      const before = await snapshot(r.lh);
      await writeFile(cfgPath, `${original}${make(canaryFile(r.kit, `cfg-${name}`), r.kit.root)}`);
      const { deps, flaky } = r.mk();
      const res = await runCycle(deps);
      assert.equal(res.halted, 'config', `${name}: outcome=${res.outcome}`);
      assert.equal(flaky.fetchCalls, 0, `${name}: no remote contact`);
      assert.equal(flaky.pushCalls, 0);
      assert.equal((await r.lh.state.read()).halt?.cls, 'local', name);
      await writeFile(cfgPath, original); // restore first: `snapshot` runs git, which cannot read an unparseable config
      assertUntouched(before, await snapshot(r.lh), { allow: ['state'] });
    }
    await assertNoCanary(r.kit);
    // fixed config: the halt clears by itself and the pending remote commit is applied
    assert.equal((await runCycle(r.mk().deps)).outcome, 'applied');
    assert.equal((await r.lh.state.read()).halt, null);
    await assertNoCanary(r.kit);
  });
});

/* ---------------- (c) hostile tree shapes ---------------- */

test('remote tip with .gitmodules, a gitlink, nested .gitconfig or a .GIT tree is held (tree rule or transport fsck); worktree untouched', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const g = r.kit;
    const sub = await blobOf(g, '[submodule "x"]\n\tpath = vendor\n\turl = ssh://evil.invalid/x.git\n');
    const plain = await blobOf(g, '[core]\n\tfsmonitor = true\n');
    const inner = await mktree(g, [`100644 blob ${plain}\tconfig`]);
    type Variant = { name: string; index?: string[]; root?: string[]; re: RegExp };
    const variants: Variant[] = [
      { name: '.gitmodules', index: [`100644 ${sub}\t.gitmodules`], re: /^quarantine:tree:/ },
      { name: 'gitlink', index: [`160000 ${'1'.repeat(40)}\tvendor`], re: /^quarantine:tree:submodule$/ },
      { name: 'gitlink + .gitmodules', index: [`160000 ${'2'.repeat(40)}\tvendor`, `100644 ${sub}\t.gitmodules`], re: /^quarantine:tree:/ },
      { name: 'nested .gitconfig', index: [`100644 ${plain}\tacme/.gitconfig`], re: /^quarantine:tree:git-name$/ },
      { name: 'root .gitconfig', index: [`100644 ${plain}\t.gitconfig`], re: /^quarantine:tree:git-name$/ },
      { name: '.gitmodules symlink', root: [`120000 blob ${sub}\t.gitmodules`], re: /^quarantine:(fsck|tree:)/ },
      { name: '.GIT/config', root: [`040000 tree ${inner}\t.GIT`], re: /^quarantine:(fsck|tree:)/ },
      { name: '.git/config', root: [`040000 tree ${inner}\t.git`], re: /^quarantine:(fsck|tree:)/ },
    ];
    for (const v of variants) {
      const before = await snapshot(r.lh);
      await tipFrom(r.kit, r.other.hub, r.fleet.base, { ...(v.index !== undefined ? { index: v.index } : {}), ...(v.root !== undefined ? { root: v.root } : {}), message: v.name });
      const { deps, flaky } = r.mk();
      await assertHeld(r, await runCycle(deps), before, flaky, v.re, v.name);
    }
    await assertNoCanary(r.kit);
  });
});

/* ---------------- (d) hostile process environment ---------------- */

async function withEnv<T>(vars: Readonly<Record<string, string>>, fn: () => Promise<T>): Promise<T> {
  const prev = new Map<string, string | undefined>();
  for (const [k, v] of Object.entries(vars)) {
    prev.set(k, process.env[k]);
    process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of prev) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('hostile process environment (GIT_DIR, GIT_SSH_COMMAND, GIT_CONFIG_*, GIT_EXTERNAL_DIFF, ...) has no effect on FF and merge cycles', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const k = r.kit;
    const script = nodePath.join(k.root, 'envscript.sh');
    await armScript(script, canaryFile(k, 'env'));
    await sanity(k, script, canaryFile(k, 'env'));
    const decoy = nodePath.join(k.root, 'decoy.git');
    await mkdir(decoy, { recursive: true, mode: 0o700 });
    await k.remote.gitx.mustRun(['init', '-q', '--bare'], { cwd: decoy });
    const emptyExec = nodePath.join(k.root, 'empty-exec');
    await mkdir(emptyExec);
    const hostile: Record<string, string> = {
      GIT_DIR: decoy,
      GIT_WORK_TREE: nodePath.join(k.root, 'decoy-worktree'),
      GIT_INDEX_FILE: nodePath.join(k.root, 'decoy-index'),
      GIT_OBJECT_DIRECTORY: nodePath.join(k.root, 'decoy-objects'),
      GIT_ALTERNATE_OBJECT_DIRECTORIES: nodePath.join(k.root, 'decoy-alt'),
      GIT_EXEC_PATH: emptyExec,
      GIT_SSH_COMMAND: script,
      GIT_SSH: script,
      GIT_PROXY_COMMAND: script,
      GIT_ASKPASS: script,
      SSH_ASKPASS: script,
      GIT_EDITOR: script,
      GIT_PAGER: script,
      PAGER: script,
      GIT_EXTERNAL_DIFF: script,
      GIT_CONFIG_COUNT: '2',
      GIT_CONFIG_KEY_0: 'core.fsmonitor',
      GIT_CONFIG_VALUE_0: script,
      GIT_CONFIG_KEY_1: 'core.sshCommand',
      GIT_CONFIG_VALUE_1: script,
      GIT_CONFIG_PARAMETERS: `'core.fsmonitor=${script}' 'core.hooksPath=${emptyExec}'`,
      GIT_TRACE: nodePath.join(k.root, 'trace.log'),
    };
    // FF
    await k.remote.pushSigned(r.other.hub, [ctx('# acme\nremote edit\n')]);
    const ff = r.mk();
    assert.equal((await withEnv(hostile, () => runCycle(ff.deps))).outcome, 'applied');
    assert.equal(await r.lh.hub.main(), await k.remote.main());
    // merge + push
    await k.remote.pushSigned(r.other.hub, [{ path: 'acme/journal/2026-11.md', content: '# acme — journal 2026-11\n' }]);
    await r.lh.commitLocal([{ path: 'acme/DECISIONS.md', content: '# decisions\n' }]);
    const mg = r.mk();
    assert.equal((await withEnv(hostile, () => runCycle(mg.deps))).outcome, 'pushed');
    assert.equal(mg.flaky.pushCalls, 1);
    assert.equal(await k.remote.main(), await r.lh.hub.main());
    await assertNoCanary(k);
    // the decoy repository / decoy index / object dirs were never touched
    assert.equal((await k.remote.gitx.mustRun(['for-each-ref'], { cwd: decoy })).stdout.length, 0, 'decoy repository received refs');
    for (const n of ['decoy-index', 'decoy-objects', 'decoy-alt', 'decoy-worktree', 'trace.log']) {
      await assert.rejects(stat(nodePath.join(k.root, n)), `${n} must not exist`);
    }
    assert.deepEqual(await r.lh.dirty(), []);
  });
});
