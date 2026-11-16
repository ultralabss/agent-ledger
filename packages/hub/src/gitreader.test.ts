/** F1 audit A4: `originHintFromUrl` never emits an absolute path, userinfo or a token-shaped segment. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { originHintFromUrl } from './gitreader.ts';

test('A4: ordinary remotes still reduce to host/org/repo', () => {
  const ok: [string, string][] = [
    ['https://github.com/acme/app.git', 'github.com/acme/app'],
    ['git@github.com:acme/app.git', 'github.com/acme/app'],
    ['ssh://git@git.example.com:2222/team/repo.git', 'git.example.com/team/repo'],
    ['https://gitlab.com/group/sub/group/repo/', 'gitlab.com/group/sub/group/repo'],
    ['https://github.com/my-org/a-fairly-long-hyphenated-repository-name', 'github.com/my-org/a-fairly-long-hyphenated-repository-name'],
    ['git://host.example/o/r.git', 'host.example/o/r'],
  ];
  for (const [raw, want] of ok) assert.equal(originHintFromUrl(raw), want, raw);
});

test('A4: absolute / home-relative / drive paths are never emitted', () => {
  for (const raw of [
    '/home/me/repo',
    'file:///home/me/repo',
    'file://localhost/home/me/repo',
    'server:/home/me/repo', // scp form with an absolute path
    'server.example:/srv/git/repo.git',
    'host.example:~me/repo',
    'ssh://host.example/~me/repo',
    'C:/Users/me/repo',
    'C:\\Users\\me\\repo',
    'https://host.example//abs/path',
    'ssh://host.example/a//b',
    'host.example:../x',
    'https://host.example/a/./b',
    'https://host.example/a/../b',
    'ftp://host.example/o/r',
    '\\\\srv\\share\\repo',
  ]) {
    assert.equal(originHintFromUrl(raw), null, raw);
  }
});

test('A4: userinfo never survives, including a host that smuggles user:secret', () => {
  assert.equal(originHintFromUrl('https://user:ghp_SECRETTOKEN123@github.com/acme/app.git'), 'github.com/acme/app');
  assert.equal(originHintFromUrl('https://x-access-token:abc@host.example:8443/o/r/'), 'host.example/o/r');
  // password containing a slash, or no `@` at all: the credential would land in the host slot
  for (const raw of [
    'https://user:pa/ss@host.example/o/r',
    'https://user:topsecretvalue/o/r',
    'https://tok@en@host.example/o/r',
    'https://host.example:notaport/o/r',
    'https://[::1]/o/r',
  ]) {
    const got = originHintFromUrl(raw);
    assert.equal(got === null || !/secret|pa\/ss|tok|user/i.test(got), true, `${raw} -> ${String(got)}`);
    assert.equal(got === null || !got.includes('@'), true, raw);
  }
  assert.equal(originHintFromUrl('https://user:topsecretvalue/o/r'), null);
});

test('A4: token-shaped path segments yield null', () => {
  const tokens = [
    'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
    'github_pat_11ABCDEFG0abcdefghijkl',
    'glpat-abcdefghij1234567890',
    'xoxb-1234-abcd',
    'npm_abcdefghijklmnopqrstuvwxyz0123456789',
    'sk-abcdefghijklmnopqrstuvwxyz',
    'AKIAIOSFODNN7EXAMPLE',
    'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0', // 40 hex
    'Zk3Qm9Xv2LpR7sTn4WyB8cDe', // 24 mixed-case alnum, no separators
    'eyJhbGciOiJIUzI1NiJ9',
  ];
  for (const t of tokens) {
    assert.equal(originHintFromUrl(`https://host.example/${t}/repo`), null, `org=${t}`);
    assert.equal(originHintFromUrl(`https://host.example/org/${t}`), null, `repo=${t}`);
    assert.equal(originHintFromUrl(`git@host.example:org/${t}.git`), null, `scp repo=${t}`);
  }
});
