import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeGitPath, samePathGit, toPosix } from './gitpath.ts';
import { IGNORE } from './watcher.ts';

test('B4: toPosix converts backslashes on win32 only', () => {
  assert.equal(toPosix('a\\b\\c', 'win32'), 'a/b/c');
  assert.equal(toPosix('a\\b', 'linux'), 'a\\b');
});

test('B4: watcher IGNORE matches `.hub\\x` / `.git\\x` once converted (win32 filenames)', () => {
  for (const f of ['.hub\\token', 'repos\\.git\\HEAD', 'a\\b.md.tmp']) {
    assert.ok(IGNORE.test(toPosix(f, 'win32')), f);
    assert.equal(IGNORE.test(f), f.endsWith('.tmp'), `raw backslash name is not matched: ${f}`);
  }
  assert.equal(IGNORE.test(toPosix('acme\\items\\ACME-1.md', 'win32')), false);
});

test('B4: normalizeGitPath win32 turns git `C:/x/y` into `C:\\x\\y`, drops trailing sep', () => {
  assert.equal(normalizeGitPath('C:/Users/me/repo', 'win32'), 'C:\\Users\\me\\repo');
  assert.equal(normalizeGitPath('C:/Users/me/repo/', 'win32'), 'C:\\Users\\me\\repo');
  assert.equal(normalizeGitPath('C:/Users//me/./repo', 'win32'), 'C:\\Users\\me\\repo');
  assert.equal(normalizeGitPath('C:/', 'win32'), 'C:\\');
});

test('B4: samePathGit casefolds and mixes separators on win32', () => {
  assert.ok(samePathGit('C:\\Users\\Me\\Repo', 'c:/users/me/repo/', 'win32'));
  assert.equal(samePathGit('C:\\Users\\Me\\Repo', 'C:\\Users\\Me\\Other', 'win32'), false);
});

test('B4: POSIX behaviour unchanged (identity, case-sensitive, no slash rewriting)', () => {
  for (const p of ['/Users/me/repo', '/Users/me/repo/', 'C:/x\\y']) {
    assert.equal(normalizeGitPath(p, 'linux'), p);
    assert.equal(normalizeGitPath(p, 'darwin'), p);
  }
  assert.equal(samePathGit('/a/B', '/a/b', 'linux'), false);
  assert.equal(samePathGit('/a/b', '/a/b/', 'darwin'), false);
  assert.ok(samePathGit('/a/b', '/a/b', 'linux'));
});
