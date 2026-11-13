/** Regression tests for the F0 re-audit findings N1 and N2. */

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { dirChainTrusted, git, gitToplevel, resolveCheckout } from './git.ts';
import { startTestHub } from './test-helpers.ts';

/* ---------------- N1: the git binary's directory ---------------- */

test('N1: a candidate in a directory writable by group/other is rejected', async (t) => {
  const base = await mkdtemp(join(tmpdir(), 'agent-ledger-n1-'));
  t.after(() => rm(base, { recursive: true, force: true }));
  const uid = process.getuid?.();

  const safe = join(base, 'safe');
  await mkdir(safe, { mode: 0o755 });
  const safeBin = join(safe, 'git');
  await writeFile(safeBin, '#!/bin/sh\n', { mode: 0o755 });
  // `stopAt` bounds the walk at the sandbox: a temp dir's real ancestry
  // (`/tmp` is 1777) is legitimately world-writable.
  assert.equal(await dirChainTrusted(safeBin, uid, safe), true, 'a 0755 directory is fine');

  // The file itself is perfect; only its directory is writable by others. That
  // is enough for anyone to swap the binary, so the candidate must be refused.
  const loose = join(base, 'loose');
  await mkdir(loose, { mode: 0o777 });
  const looseBin = join(loose, 'git');
  await writeFile(looseBin, '#!/bin/sh\n', { mode: 0o755 });
  await chmod(loose, 0o777);
  assert.equal(
    await dirChainTrusted(looseBin, uid, loose),
    false,
    'world-writable directory = untrusted',
  );

  // Group-writable: the bit alone is not the verdict — the
  // question is whether the owning group can hold anyone but root/us. The
  // decision is injected here on purpose, so this assertion does not depend on
  // what `admin`/`staff` happen to contain on the machine running the test.
  const groupy = join(base, 'groupy');
  await mkdir(groupy, { mode: 0o775 });
  await chmod(groupy, 0o775);
  const groupyBin = join(groupy, 'git');
  await writeFile(groupyBin, '#!/bin/sh\n', { mode: 0o755 });
  assert.equal(
    await dirChainTrusted(groupyBin, uid, groupy, { groupWritableOk: async () => false }),
    false,
    'group-writable directory with a foreign/unknown group = untrusted',
  );
  assert.equal(
    await dirChainTrusted(groupyBin, uid, groupy, { groupWritableOk: async () => true }),
    true,
    'group-writable directory whose group is a subset of {root, us} is fine',
  );

  // An intermediate component being loose poisons a tight leaf too.
  const nested = join(loose, 'tight');
  await mkdir(nested, { mode: 0o755 });
  const nestedBin = join(nested, 'git');
  await writeFile(nestedBin, '#!/bin/sh\n', { mode: 0o755 });
  assert.equal(
    await dirChainTrusted(nestedBin, uid, loose),
    false,
    'one loose component in the path is enough',
  );

  // The real system path the resolver actually uses must pass unbounded.
  assert.equal(await dirChainTrusted('/usr/bin/git', uid), true, '/usr/bin is trusted');
});

test('N1: git is still run by absolute path and works', async (t) => {
  const repo = await mkdtemp(join(tmpdir(), 'agent-ledger-n1run-'));
  t.after(() => rm(repo, { recursive: true, force: true }));
  const res = await git(repo, ['init', '-q', '-b', 'main']);
  assert.equal(res.code, 0, res.stderr);
});

/* ---------------- N2: what counts as a repo ---------------- */

test('N2: a `.git` directory must have HEAD, otherwise it is not a repo', async (t) => {
  const base = await mkdtemp(join(tmpdir(), 'agent-ledger-n2-'));
  t.after(() => rm(base, { recursive: true, force: true }));

  const notARepo = join(base, 'empty-dotgit');
  await mkdir(join(notARepo, '.git'), { recursive: true });
  assert.equal(await gitToplevel(notARepo), null, '.git without HEAD is not a repo');

  const fileDotGit = join(base, 'garbage-dotgit');
  await mkdir(fileDotGit, { recursive: true });
  await writeFile(join(fileDotGit, '.git'), 'this is not a gitdir\n', 'utf8');
  assert.equal(await gitToplevel(fileDotGit), null, '.git file without gitdir: is not a repo');

  const danglingWorktree = join(base, 'dangling');
  await mkdir(danglingWorktree, { recursive: true });
  await writeFile(join(danglingWorktree, '.git'), 'gitdir: /nope/nope/nope\n', 'utf8');
  assert.equal(await gitToplevel(danglingWorktree), null, 'gitdir: pointing at a nonexistent directory');

  const gitdirNoHead = join(base, 'nohead');
  await mkdir(join(base, 'meta'), { recursive: true });
  await mkdir(gitdirNoHead, { recursive: true });
  await writeFile(join(gitdirNoHead, '.git'), `gitdir: ${join(base, 'meta')}\n`, 'utf8');
  assert.equal(await gitToplevel(gitdirNoHead), null, 'gitdir without HEAD');

  const symlinked = join(base, 'symlinked');
  await mkdir(symlinked, { recursive: true });
  await symlink('/nope/nope', join(symlinked, '.git'));
  assert.equal(await gitToplevel(symlinked), null, 'dangling .git symlink');

  // A real repo still resolves, and so does a subdirectory of it.
  const real = join(base, 'real');
  await mkdir(join(real, 'deep', 'deeper'), { recursive: true });
  await git(real, ['init', '-q', '-b', 'main']);
  const layout = await resolveCheckout(join(real, 'deep', 'deeper'));
  assert.ok(layout);
  assert.equal(layout?.worktree, false);
  assert.equal(layout?.gitDir, layout?.commonDir);
});

test('N2: POST /v1/repos rejects a path that is not a git repo', async (t) => {
  const fx = await startTestHub();
  const base = await mkdtemp(join(tmpdir(), 'agent-ledger-n2api-'));
  t.after(async () => {
    await fx.cleanup();
    await rm(base, { recursive: true, force: true });
  });

  const fake = join(base, 'fake');
  await mkdir(join(fake, '.git'), { recursive: true });
  const res = await fx.api('POST', '/v1/repos', { slug: 'fake', prefix: 'FK', path: fake });
  assert.equal(res.status, 422, res.text);
  assert.match(res.json.message, /is not a git repository/);

  const real = join(base, 'real');
  await mkdir(real, { recursive: true });
  await git(real, ['init', '-q', '-b', 'main']);
  const ok = await fx.api('POST', '/v1/repos', { slug: 'real', prefix: 'RL', path: real });
  assert.equal(ok.status, 201, ok.text);
  assert.equal(ok.json.repo.onboarded, false, 'a new repo waits for onboarding');
});

test('N2: auto-registration does not register a directory that merely looks like a repo', async (t) => {
  const fx = await startTestHub();
  const base = await mkdtemp(join(tmpdir(), 'agent-ledger-n2auto-'));
  t.after(async () => {
    await fx.cleanup();
    await rm(base, { recursive: true, force: true });
  });
  const fake = join(base, 'looks-like-repo');
  await mkdir(join(fake, '.git'), { recursive: true }); // no HEAD

  const before = Object.keys((await fx.api('GET', '/v1/repos')).json.repos).length;
  const res = await fx.hook('session-start', {
    session_id: 'n2n20001',
    cwd: fake,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
  assert.equal(res.repo, null, 'nothing got registered');
  assert.match(res.text, /NO REPO/);
  const after = Object.keys((await fx.api('GET', '/v1/repos')).json.repos).length;
  assert.equal(after, before);
});
