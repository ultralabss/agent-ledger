/**
 * S5 / I4 / T5 / T7: git never runs planted or repo-supplied hooks, and the candidate
 * list never trusts a relative environment root.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, stat, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildGitGlobalArgs, configureGitHooksDir, git, gitCandidates } from './git.ts';

const posixOnly = process.platform === 'win32' && 'POSIX hook scripts / mode bits';

async function exists(p: string): Promise<boolean> {
  return stat(p).then(
    () => true,
    () => false,
  );
}

async function plantedRepo(tag: string): Promise<{ repo: string; hooks: string; marker: string }> {
  const repo = await mkdtemp(join(tmpdir(), `agent-ledger-hooks-${tag}-`));
  const marker = join(repo, 'HOOK-RAN');
  const hooks = join(repo, 'planted-hooks');
  await mkdir(hooks);
  for (const name of ['pre-commit', 'commit-msg', 'post-commit', 'reference-transaction', 'pre-push']) {
    const file = join(hooks, name);
    await writeFile(file, `#!/bin/sh\necho ${name} >> "${marker}"\nexit 0\n`);
    await chmod(file, 0o755);
  }
  return { repo, hooks, marker };
}

async function setupRepo(repo: string, hooks: string): Promise<void> {
  assert.equal((await git(repo, ['init', '-b', 'main'])).code, 0);
  await git(repo, ['config', 'user.email', 't@example.invalid']);
  await git(repo, ['config', 'user.name', 'T']);
  await git(repo, ['config', 'commit.gpgsign', 'false']);
  // Repo-local config pointing at planted hooks, AND the default .git/hooks location.
  await git(repo, ['config', 'core.hooksPath', hooks]);
}

test('T5: buildGitGlobalArgs has no /dev/null and carries the verified dir + eol flags', () => {
  const args = buildGitGlobalArgs('/some/private/empty-hooks');
  assert.ok(!args.some((a) => a.includes('/dev/null')));
  assert.ok(args.includes('core.hooksPath=/some/private/empty-hooks'));
  for (const flag of ['core.autocrlf=false', 'core.eol=lf', 'core.longpaths=true', 'core.fsmonitor=false']) {
    assert.ok(args.includes(flag), flag);
  }
});

test('T5: planted pre-commit / commit-msg / reference-transaction / pre-push never run through git()', { skip: posixOnly }, async () => {
  const { repo, hooks, marker } = await plantedRepo('run');
  await setupRepo(repo, hooks);
  const res = await git(repo, ['commit', '--allow-empty', '-m', 'x']);
  assert.equal(res.code, 0, res.stderr);
  await git(repo, ['update-ref', 'refs/heads/other', 'HEAD']);
  assert.equal(await exists(marker), false, 'a hook ran');
});

test('T5 control: the same planted hooks DO run when git is invoked without our global args', { skip: posixOnly }, async (t) => {
  const { repo, hooks, marker } = await plantedRepo('ctl');
  try {
    execFileSync('git', ['init', '-b', 'main'], { cwd: repo, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 't@example.invalid'], { cwd: repo });
    execFileSync('git', ['config', 'user.name', 'T'], { cwd: repo });
    execFileSync('git', ['config', 'commit.gpgsign', 'false'], { cwd: repo });
    execFileSync('git', ['config', 'core.hooksPath', hooks], { cwd: repo });
    execFileSync('git', ['commit', '--allow-empty', '-m', 'x'], { cwd: repo, stdio: 'ignore' });
  } catch {
    t.skip('no usable git on PATH for the control run');
    return;
  }
  assert.equal(await exists(marker), true, 'control: hooks must run without the hardening, else the test above proves nothing');
});

test('T5: a non-empty hooks directory blocks every git call (fail-closed)', { skip: posixOnly }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-hooks-dirty-'));
  const repo = await mkdtemp(join(tmpdir(), 'agent-ledger-hooks-repo-'));
  t.after(() => configureGitHooksDir(null));
  configureGitHooksDir(join(dir, 'empty-hooks'));
  assert.equal((await git(repo, ['init', '-b', 'main'])).code, 0, 'first call creates the empty dir');
  await writeFile(join(dir, 'empty-hooks', 'pre-commit'), '#!/bin/sh\nexit 0\n');
  await assert.rejects(() => git(repo, ['status']), /not empty/);
});

test('T5: the hooks directory is private (0700) and recreated when removed', { skip: posixOnly }, async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-hooks-mode-'));
  const repo = await mkdtemp(join(tmpdir(), 'agent-ledger-hooks-repo2-'));
  t.after(() => configureGitHooksDir(null));
  const hooks = join(dir, 'empty-hooks');
  configureGitHooksDir(hooks);
  await git(repo, ['init', '-b', 'main']);
  assert.equal((await stat(hooks)).mode & 0o777, 0o700);
});

test('T7: win32 candidates come only from absolute drive-rooted env roots', () => {
  const env = {
    ProgramW6432: 'C:\\Program Files',
    ProgramFiles: 'relative\\Program Files',
    LOCALAPPDATA: 'C:\\Users\\me\\AppData\\Local',
  };
  assert.deepEqual(gitCandidates('win32', env), [
    'C:\\Program Files\\Git\\cmd\\git.exe',
    'C:\\Users\\me\\AppData\\Local\\Programs\\Git\\cmd\\git.exe',
  ]);
  assert.deepEqual(gitCandidates('win32', { ProgramFiles: '' }), []);
  assert.deepEqual(gitCandidates('win32', { ProgramFiles: '\\\\server\\share' }), []);
  assert.deepEqual(gitCandidates('win32', { ProgramFiles: 'C:\\Program Files', ProgramW6432: 'C:\\Program Files' }), [
    'C:\\Program Files\\Git\\cmd\\git.exe',
  ]);
  assert.ok(gitCandidates('linux', {}).every((c) => c.startsWith('/')));
});

test('T5: LedgerGit commit and push pass --no-verify', async () => {
  const src = await readFile(fileURLToPath(new URL('./git.ts', import.meta.url)), 'utf8');
  assert.match(src, /\['commit', '--no-verify', '-m'/);
  assert.match(src, /\['push', '--no-verify', 'origin', 'HEAD'\]/);
});
