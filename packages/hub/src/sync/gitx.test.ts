/** Hardened git runner (docs/f3b-plan.md §3: S12, S9-S11, invariants 2 and 13). */

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import test from 'node:test';
import {
  Gitx,
  GitxError,
  assertSafeArgv,
  buildGitEnv,
  buildSshCommand,
  checkGitConfig,
  parseGitConfig,
  validateRemoteUrl,
} from './gitx.ts';
import { gitCandidates, resolveTrustedBinary } from '../git.ts';
import { makeKit } from './testkit-remote.ts';

const posix = process.platform !== 'win32';

async function tmpRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(nodePath.join(await realpath(tmpdir()), 'agl-gitx-')));
  await chmod(root, 0o700);
  return root;
}

async function fakeBin(root: string, name: string, body: string): Promise<string> {
  const p = nodePath.join(root, name);
  await writeFile(p, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  await chmod(p, 0o755);
  return p;
}

const DUMP = `for a in "$@"; do printf 'ARG\\t%s\\n' "$a"; done\nenv | sed 's/^/ENV\\t/'`;

function parseDump(stdout: Buffer): { args: string[]; env: Map<string, string> } {
  const args: string[] = [];
  const env = new Map<string, string>();
  for (const line of stdout.toString('utf8').split('\n')) {
    if (line.startsWith('ARG\t')) args.push(line.slice(4));
    else if (line.startsWith('ENV\t')) {
      const kv = line.slice(4);
      const eq = kv.indexOf('=');
      env.set(kv.slice(0, eq), kv.slice(eq + 1));
    }
  }
  return { args, env };
}

const HOSTILE_ENV: Record<string, string> = {
  PATH: '/usr/bin:/bin',
  HOME: '/home/someone',
  GIT_DIR: '/nonexistent/.git',
  GIT_WORK_TREE: '/nonexistent',
  GIT_CONFIG_COUNT: '1',
  GIT_CONFIG_KEY_0: 'core.hooksPath',
  GIT_CONFIG_VALUE_0: '/tmp/evil-hooks',
  GIT_CONFIG_PARAMETERS: "'core.sshcommand=evil'",
  GIT_SSH_COMMAND: 'touch /tmp/pwned',
  GIT_SSH: '/tmp/evil-ssh',
  GIT_EXEC_PATH: '/tmp/evil-exec',
  GIT_ASKPASS: '/tmp/evil-askpass',
  GIT_EXTERNAL_DIFF: '/tmp/evil-diff',
  GIT_PROXY_COMMAND: '/tmp/evil-proxy',
  GIT_TEMPLATE_DIR: '/tmp/evil-template',
  SSH_ASKPASS: '/tmp/evil-askpass',
  SSH_AUTH_SOCK: '/tmp/agent.sock',
  EDITOR: 'evil',
  SECRET_TOKEN: 'hunter2',
  LD_PRELOAD: '/tmp/evil.so',
  http_proxy: 'http://evil',
};

/* ---------------- URL validator (S12) ---------------- */

test('validateRemoteUrl: ssh and scp forms are accepted', () => {
  for (const [url, kind] of [
    ['ssh://git@host.example/owner/repo.git', 'ssh'],
    ['ssh://host.example:2222/repo.git', 'ssh'],
    ['ssh://[2001:db8::1]:22/repo', 'ssh'],
    ['ssh://u_1@10.0.0.1/~/ledger', 'ssh'],
    ['git@github.com:owner/repo.git', 'scp'],
    ['host.example:ledger.git', 'scp'],
    ['host:/srv/git/ledger.git', 'scp'],
  ] as const) {
    assert.equal(validateRemoteUrl(url).kind, kind, url);
  }
});

test('validateRemoteUrl: hostile and non-ssh forms are refused', () => {
  const bad = [
    '',
    '-oProxyCommand=touch /tmp/x',
    '--upload-pack=evil',
    'ssh://-oProxyCommand=x/repo',
    'ssh://user@-host/repo',
    '-host:repo',
    'user@-host:repo',
    'ssh://host/repo with space',
    'ssh://host/repo\n',
    'ssh://host/repo\t',
    'ssh://host/re\x00po',
    'ssh://host/re\x1bpo',
    ' ssh://host/repo',
    'ssh://host/repo ',
    'ext::sh -c touch /tmp/x',
    'ext::ssh://host/repo',
    'fd::3',
    'fd::3/repo',
    'file:///etc',
    'file://host/repo',
    'http://host/repo.git',
    'https://host/repo.git',
    'git://host/repo.git',
    'ftp://host/repo',
    'ssh+git://host/repo',
    'git+ssh://host/repo',
    'ssh://',
    'ssh://host',
    'ssh://host/',
    'ssh://host:0/repo',
    'ssh://host:65536/repo',
    'ssh://host:99999999/repo',
    'ssh://host/../etc',
    'ssh://host/a/../b',
    'ssh://host//repo',
    'ssh://host/repo/',
    'ssh://host/%2e%2e/x',
    'host:../x',
    'host:a/../b',
    'host:a//b',
    '/abs/path/repo.git',
    './rel/repo',
    '../rel/repo',
    'rel/repo',
    '~/repo',
    'C:\\x\\repo',
    'C:/x/repo',
    '\\\\server\\share\\repo',
    'ssh://hôst/repo',
    'ssh://host/répo',
    'host:rép',
    'user:pw@host:repo',
    'ssh://user:pw@host/repo',
    'a b:c',
    'ssh://host:22:22/repo',
  ];
  for (const url of bad) {
    assert.throws(() => validateRemoteUrl(url), (e: unknown) => e instanceof GitxError && e.code === 'URL', JSON.stringify(url));
  }
  assert.throws(() => validateRemoteUrl(undefined), GitxError);
  assert.throws(() => validateRemoteUrl(42), GitxError);
  assert.throws(() => validateRemoteUrl(`ssh://host/${'a'.repeat(600)}`), GitxError);
});

test('validateRemoteUrl: a local path is accepted only when the constructor option names exactly it', () => {
  const p = '/tmp/some/remote.git';
  assert.throws(() => validateRemoteUrl(p), GitxError);
  assert.equal(validateRemoteUrl(p, [p]).kind, 'local');
  assert.throws(() => validateRemoteUrl(`${p}/..`, [p]), GitxError);
  assert.throws(() => validateRemoteUrl('-x', ['-x']), GitxError, 'even if allowed: no leading dash');
  assert.throws(() => validateRemoteUrl('rel/path', ['rel/path']), GitxError, 'even if allowed: absolute only');
});

test('error message never contains the URL', () => {
  try {
    validateRemoteUrl('ext::sh -c touch /tmp/SECRETMARK');
    assert.fail('should throw');
  } catch (e) {
    assert.ok(e instanceof GitxError);
    assert.ok(!e.message.includes('SECRETMARK'));
  }
});

/* ---------------- environment scrub (invariant 13) ---------------- */

test('buildGitEnv: allowlist only, every other GIT_* dropped, fixed hardening vars set', () => {
  const env = buildGitEnv({ source: HOSTILE_ENV, platform: 'linux', emptyConfigFile: '/priv/empty.gitconfig' });
  assert.equal(env.PATH, '/usr/bin:/bin');
  assert.equal(env.HOME, '/home/someone');
  assert.equal(env.GIT_CONFIG_NOSYSTEM, '1');
  assert.equal(env.GIT_CONFIG_GLOBAL, '/priv/empty.gitconfig');
  assert.equal(env.GIT_TERMINAL_PROMPT, '0');
  for (const k of [
    'GIT_DIR',
    'GIT_WORK_TREE',
    'GIT_CONFIG_COUNT',
    'GIT_CONFIG_KEY_0',
    'GIT_CONFIG_VALUE_0',
    'GIT_CONFIG_PARAMETERS',
    'GIT_SSH_COMMAND',
    'GIT_SSH',
    'GIT_EXEC_PATH',
    'GIT_ASKPASS',
    'GIT_EXTERNAL_DIFF',
    'GIT_PROXY_COMMAND',
    'GIT_TEMPLATE_DIR',
    'SSH_ASKPASS',
    'SSH_AUTH_SOCK',
    'EDITOR',
    'SECRET_TOKEN',
    'LD_PRELOAD',
    'http_proxy',
  ]) {
    assert.ok(!(k in env), `${k} must not reach git`);
  }
});

test('buildGitEnv: network calls keep SSH_AUTH_SOCK and set the fixed GIT_SSH_COMMAND, nothing inherited', () => {
  const env = buildGitEnv({ source: HOSTILE_ENV, platform: 'linux', emptyConfigFile: '/e', sshCommand: "'/usr/bin/ssh' '-F' 'none'" });
  assert.equal(env.SSH_AUTH_SOCK, '/tmp/agent.sock');
  assert.equal(env.GIT_SSH_COMMAND, "'/usr/bin/ssh' '-F' 'none'");
  assert.ok(!('SSH_ASKPASS' in env));
});

test('buildGitEnv: extra env is restricted to three explicit keys', () => {
  const ok = buildGitEnv({ source: {}, platform: 'linux', emptyConfigFile: '/e', extra: { GIT_INDEX_FILE: '/x/index' } });
  assert.equal(ok.GIT_INDEX_FILE, '/x/index');
  assert.throws(
    () => buildGitEnv({ source: {}, platform: 'linux', emptyConfigFile: '/e', extra: { GIT_DIR: '/x' } as never }),
    GitxError,
  );
  assert.throws(
    () => buildGitEnv({ source: {}, platform: 'linux', emptyConfigFile: '/e', extra: { GIT_INDEX_FILE: 'a\nb' } }),
    GitxError,
  );
});

test('buildGitEnv: windows env names are matched case-insensitively and canonicalised', () => {
  const env = buildGitEnv({
    source: { Path: 'C:\\Windows', SYSTEMROOT: 'C:\\Windows', Temp: 'C:\\T', UserProfile: 'C:\\U', GIT_DIR: 'x' },
    platform: 'win32',
    emptyConfigFile: 'C:\\e',
  });
  assert.equal(env.PATH, 'C:\\Windows');
  assert.equal(env.SystemRoot, 'C:\\Windows');
  assert.equal(env.TEMP, 'C:\\T');
  assert.equal(env.USERPROFILE, 'C:\\U');
  assert.ok(!('GIT_DIR' in env));
});

test('spawned child sees a scrubbed env, fixed -c hardening before the subcommand, `--` before positionals', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const fake = await fakeBin(root, 'fakegit', DUMP);
    const gitx = await Gitx.open({
      syncDir: nodePath.join(root, 'sync'),
      gitBin: fake,
      sshBin: '/usr/bin/ssh',
      keyFile: nodePath.join(root, 'key'),
      env: HOSTILE_ENV,
    });
    // local call
    const local = parseDump((await gitx.run(['rev-parse', '--show-toplevel'], { cwd: root })).stdout);
    assert.ok(!local.env.has('GIT_DIR') || local.env.get('GIT_DIR') === undefined);
    for (const k of local.env.keys()) {
      if (k.startsWith('GIT_')) {
        assert.ok(
          [
            'GIT_CONFIG_NOSYSTEM',
            'GIT_CONFIG_GLOBAL',
            'GIT_TERMINAL_PROMPT',
            'GIT_ATTR_NOSYSTEM',
            'GIT_NO_REPLACE_OBJECTS',
            'GIT_NO_LAZY_FETCH',
            'GIT_OPTIONAL_LOCKS',
            'GIT_CEILING_DIRECTORIES',
          ].includes(k),
          `unexpected ${k}`,
        );
      }
    }
    for (const k of ['SECRET_TOKEN', 'EDITOR', 'LD_PRELOAD', 'SSH_ASKPASS', 'SSH_AUTH_SOCK', 'http_proxy']) {
      assert.ok(!local.env.has(k), `${k} leaked into a local call`);
    }
    assert.equal(local.env.get('GIT_CONFIG_GLOBAL'), nodePath.join(root, 'sync', 'empty.gitconfig'));
    assert.equal(local.env.get('GIT_CONFIG_NOSYSTEM'), '1');
    assert.equal(local.env.get('GIT_TERMINAL_PROMPT'), '0');
    assert.equal(local.env.get('HOME'), '/home/someone');
    const sub = local.args.indexOf('rev-parse');
    assert.ok(sub > 0, 'subcommand after the -c options');
    const cfg = local.args.slice(0, sub);
    for (const want of [
      'protocol.allow=never',
      'protocol.ssh.allow=always',
      'protocol.ext.allow=never',
      'core.sshCommand=',
      'credential.helper=',
      'fetch.fsckObjects=true',
      'transfer.fsckObjects=true',
      'gc.auto=0',
      'core.fsmonitor=false',
      'core.fsync=all',
    ]) {
      assert.ok(cfg.includes(want), `missing -c ${want}`);
    }
    assert.ok(cfg.some((a) => a === `core.hooksPath=${nodePath.join(root, 'sync', 'empty-hooks')}`));

    // network call
    const net = parseDump(
      (await gitx.fetch(root, 'ssh://git@example.invalid/owner/repo.git')).stdout,
    );
    assert.equal(net.env.get('SSH_AUTH_SOCK'), '/tmp/agent.sock');
    const ssh = net.env.get('GIT_SSH_COMMAND') ?? '';
    assert.notEqual(ssh, 'touch /tmp/pwned');
    assert.equal(
      ssh,
      buildSshCommand({
        sshBin: '/usr/bin/ssh',
        knownHostsFile: nodePath.join(root, 'sync', 'known_hosts'),
        keyFile: nodePath.join(root, 'key'),
      }),
    );
    for (const want of ["'-F' 'none'", "'BatchMode=yes'", "'IdentitiesOnly=yes'", "'StrictHostKeyChecking=yes'", "'-i'"]) {
      assert.ok(ssh.includes(want), `ssh command missing ${want}`);
    }
    assert.ok(ssh.includes(`'UserKnownHostsFile=${nodePath.join(root, 'sync', 'known_hosts')}'`));
    assert.ok(ssh.includes("'GlobalKnownHostsFile=/dev/null'"));
    const dd = net.args.indexOf('--');
    assert.ok(dd > 0);
    assert.equal(net.args[dd + 1], 'ssh://git@example.invalid/owner/repo.git');
    assert.equal(net.args[dd + 2], '+refs/heads/main:refs/ledger-sync/incoming');
    assert.ok(net.args.slice(0, dd).includes('--no-tags'));
    assert.ok(net.args.slice(0, dd).includes('--no-recurse-submodules'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the ssh command, run through sh, is parsed by ssh with the pinned options (paths with spaces survive)', { skip: !posix }, async (t) => {
  const sshBin = ['/usr/bin/ssh', '/usr/local/bin/ssh', '/opt/homebrew/bin/ssh'].find((p) => existsSync(p));
  if (sshBin === undefined) return t.skip('no ssh binary');
  const root = await tmpRoot();
  try {
    const dir = nodePath.join(root, 'dir with space');
    await mkdir(dir);
    await writeFile(nodePath.join(dir, 'id key'), 'x', { mode: 0o600 }); // ssh drops -i files that do not exist
    const cmd = buildSshCommand({
      sshBin,
      knownHostsFile: nodePath.join(dir, 'known hosts'),
      keyFile: nodePath.join(dir, 'id key'),
    });
    const out = await new Promise<string>((resolve, reject) => {
      execFile('/bin/sh', ['-c', `${cmd} -G example.invalid`], { env: { PATH: '/usr/bin:/bin', HOME: root } }, (err, stdout) => {
        if (err) reject(err);
        else resolve(stdout);
      });
    });
    const cfg = new Map<string, string>();
    const identityFiles: string[] = [];
    for (const l of out.split('\n')) {
      const sp = l.indexOf(' ');
      if (sp > 0) cfg.set(l.slice(0, sp), l.slice(sp + 1));
      if (l.startsWith('identityfile ')) identityFiles.push(l.slice('identityfile '.length));
    }
    assert.equal(cfg.get('batchmode'), 'yes');
    assert.equal(cfg.get('identitiesonly'), 'yes');
    assert.equal(cfg.get('stricthostkeychecking'), 'true');
    assert.equal(cfg.get('userknownhostsfile'), nodePath.join(dir, 'known hosts'));
    assert.equal(cfg.get('globalknownhostsfile'), '/dev/null');
    assert.ok(identityFiles.includes(nodePath.join(dir, 'id key')), JSON.stringify(identityFiles));
    assert.equal(cfg.get('forwardagent'), 'no');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('buildSshCommand: hostile characters in paths are refused or inert (single-quoted)', () => {
  assert.throws(() => buildSshCommand({ sshBin: '/usr/bin/ssh', knownHostsFile: '/x/known\nhosts' }), GitxError);
  assert.throws(() => buildSshCommand({ sshBin: 'ssh', knownHostsFile: '/x/kh' }), GitxError, 'relative ssh path refused');
  const cmd = buildSshCommand({ sshBin: '/usr/bin/ssh', knownHostsFile: "/x/it's;$(touch pwn)/kh" });
  assert.ok(cmd.includes(`'UserKnownHostsFile=/x/it'\\''s;$(touch pwn)/kh'`), cmd);
});

/* ---------------- argv guards (invariant 2) ---------------- */

test('assertSafeArgv: force, delete, "+" refspecs and option smuggling are refused', () => {
  for (const argv of [
    ['push', '--force'],
    ['push', '-f'],
    ['push', '-fu'],
    ['push', '-uf'],
    ['fetch', '--force'],
    ['push', '--force-with-lease'],
    ['push', '--force-with-lease=main:abc'],
    ['push', '--force-if-includes'],
    ['push', '--mirror'],
    ['push', '--prune'],
    ['push', '--delete'],
    ['push', '-d'],
    ['push', '+refs/heads/main:refs/heads/main'],
    ['push', '+abc'],
    ['fetch', '+refs/heads/main:refs/heads/main'],
    ['fetch', '+refs/heads/main:refs/remotes/origin/main'],
    ['fetch', '+refs/heads/*:refs/heads/*'],
    ['push', 'abc:+refs/heads/main'],
    ['fetch', '--upload-pack=evil'],
    ['push', '--receive-pack=evil'],
    ['fetch', '--exec=evil'],
    ['rev-parse', '-c', 'core.sshCommand=evil'],
    ['rev-parse', '--git-dir=/x'],
    ['rev-parse', '--work-tree=/x'],
    ['diff-tree', '--ext-diff'],
    ['diff-tree', '--textconv'],
    ['x', 'a\0b'],
  ]) {
    assert.throws(() => assertSafeArgv(argv), GitxError, JSON.stringify(argv));
  }
  for (const argv of [
    ['fetch', '--no-tags', '--', 'ssh://h/r', '+refs/heads/main:refs/ledger-sync/incoming'],
    ['push', '--no-verify', '--', 'ssh://h/r', `${'a'.repeat(40)}:refs/heads/main`],
    ['ls-tree', '-r', '-l', '-z', '--full-tree', 'a'.repeat(40)],
    ['diff-tree', '-r', '--raw', '-z', '--no-renames', '--no-abbrev', 'a'.repeat(40), 'b'.repeat(40)],
    ['commit-tree', 'a'.repeat(40), '-p', 'b'.repeat(40), '-F', '-'],
    ['update-ref', '--no-deref', 'refs/heads/main', 'a'.repeat(40), 'b'.repeat(40)],
    ['hash-object', '-w', '--no-filters', '--stdin'],
  ]) {
    assertSafeArgv(argv);
  }
});

test('run() refuses network and unknown subcommands, global options, and non-allowlisted -c keys', async () => {
  const root = await tmpRoot();
  try {
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync'), gitBin: '/bin/echo' });
    for (const sub of ['fetch', 'push', 'pull', 'clone', 'ls-remote', 'remote', 'config', 'submodule', 'gc', 'filter-branch', 'merge', 'checkout', 'reset', 'stash', 'rebase', 'commit', '-c', '--exec-path=/x', '']) {
      await assert.rejects(gitx.run([sub], { cwd: root }), (e: unknown) => e instanceof GitxError && e.code === 'ARGS', sub);
    }
    await assert.rejects(gitx.run([], { cwd: root }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root, extraConfig: ['core.sshCommand=evil'] }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root, extraConfig: ['core.hooksPath=/evil'] }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root, extraConfig: ['protocol.allow=always'] }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root, extraConfig: ['user.name=a\nb'] }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root, extraConfig: ['gpg.ssh.program=/bin/sh'] }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root, extraConfig: ['gpg.format=openpgp'] }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root, extraConfig: ['commit.gpgsign=false'] }), GitxError);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: 'relative/dir' }), GitxError);
    await assert.rejects(gitx.fetch(root, 'ext::sh -c id'), (e: unknown) => e instanceof GitxError && e.code === 'URL');
    await assert.rejects(gitx.fetch(root, 'ssh://h/r', { dst: 'refs/heads/main' }), GitxError);
    await assert.rejects(gitx.fetch(root, 'ssh://h/r', { dst: 'refs/remotes/origin/main' }), GitxError);
    await assert.rejects(gitx.fetch(root, 'ssh://h/r', { src: '--upload-pack=x' }), GitxError);
    await assert.rejects(gitx.push(root, 'ssh://h/r', 'main'), GitxError);
    await assert.rejects(gitx.push(root, 'ssh://h/r', '--force'), GitxError);
    await assert.rejects(gitx.push(root, 'ssh://h/r', 'A'.repeat(40)), GitxError, 'uppercase hex refused');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('network methods never put force, a "+" on refs/heads/*, or a remote name into argv', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const fake = await fakeBin(root, 'fakegit', DUMP);
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync'), gitBin: fake, sshBin: '/usr/bin/ssh' });
    const url = 'git@example.invalid:owner/repo.git';
    const sha = 'c'.repeat(40);
    const runs = [
      await gitx.fetch(root, url),
      await gitx.push(root, url, sha),
      await gitx.lsRemote(root, url),
      await gitx.lsRemoteAnonymous(root, url),
    ];
    for (const r of runs) {
      const { args } = parseDump(r.stdout);
      for (const a of args) {
        assert.ok(!/^--?force/.test(a) && a !== '-f', a);
        assert.ok(!a.startsWith('+') || /^\+refs\/heads\/main:refs\/ledger-sync\/incoming$/.test(a), a);
        assert.notEqual(a, 'origin');
      }
    }
    const push = parseDump(runs[1]?.stdout ?? Buffer.alloc(0)).args;
    const dd = push.indexOf('--');
    assert.deepEqual(push.slice(dd + 1), [url, `${sha}:refs/heads/main`]);
    assert.ok(push.includes('--no-verify'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('no sync source file builds a force flag or a "+" refspec on refs/heads/*', async () => {
  const dir = nodePath.dirname(new URL(import.meta.url).pathname);
  for (const f of ['objects.ts', 'treebuild.ts', 'sigverify.ts', 'testkit-remote.ts']) {
    const src = await readFile(nodePath.join(dir, f), 'utf8');
    assert.ok(!/--force|'-f'|"-f"|\+refs\/heads/.test(src), `${f} contains a force flag or a + refspec`);
  }
  const gitx = await readFile(nodePath.join(dir, 'gitx.ts'), 'utf8');
  assert.ok(!/\+refs\/heads\/\*:refs\/heads/.test(gitx));
  assert.ok(!/`\+\$\{[a-z]+\}:\$\{(?!dst)/.test(gitx), 'fetch refspec must name the validated scratch dst');
});

/* ---------------- timeouts and caps (S6) ---------------- */

test('timeout kills the whole process group, including grandchildren', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const pidFile = nodePath.join(root, 'pid');
    const fake = await fakeBin(root, 'slowgit', `sleep 30 &\necho $! > '${pidFile}'\nsleep 30`);
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync'), gitBin: fake });
    const t0 = Date.now();
    const r = await gitx.run(['rev-parse'], { cwd: root, timeoutMs: 400 });
    assert.equal(r.timedOut, true);
    assert.equal(r.ok, false);
    assert.equal(r.code, -1);
    assert.ok(Date.now() - t0 < 10_000);
    const pid = Number((await readFile(pidFile, 'utf8')).trim());
    assert.ok(pid > 1);
    let alive = true;
    for (let i = 0; i < 40 && alive; i++) {
      try {
        process.kill(pid, 0);
        await new Promise((r2) => setTimeout(r2, 50));
      } catch {
        alive = false;
      }
    }
    assert.equal(alive, false, 'grandchild must be dead');
    await assert.rejects(gitx.mustRun(['rev-parse'], { cwd: root, timeoutMs: 300 }), (e: unknown) => e instanceof GitxError && e.code === 'TIMEOUT');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('stdout cap kills the child and reports capped, never a huge buffer', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const fake = await fakeBin(root, 'floodgit', 'yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync'), gitBin: fake });
    const r = await gitx.run(['rev-parse'], { cwd: root, maxStdoutBytes: 100_000, timeoutMs: 10_000 });
    assert.equal(r.capped, true);
    assert.equal(r.ok, false);
    assert.equal(r.stdout.length, 0);
    await assert.rejects(gitx.mustRun(['rev-parse'], { cwd: root, maxStdoutBytes: 1000 }), (e: unknown) => e instanceof GitxError && e.code === 'CAPPED');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('stderr is capped and a missing cwd is a typed SPAWN error', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const fake = await fakeBin(root, 'noisy', 'head -c 300000 /dev/zero | tr "\\0" "e" >&2; exit 3');
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync'), gitBin: fake });
    const r = await gitx.run(['rev-parse'], { cwd: root });
    assert.equal(r.code, 3);
    assert.ok(r.stderr.length <= 64 * 1024);
    await assert.rejects(gitx.run(['rev-parse'], { cwd: nodePath.join(root, 'gone') }), (e: unknown) => e instanceof GitxError && e.code === 'SPAWN');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a non-empty hooks directory or a non-empty config file makes the runner refuse', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const sync = nodePath.join(root, 'sync');
    const gitx = await Gitx.open({ syncDir: sync, gitBin: '/bin/echo' });
    await writeFile(nodePath.join(sync, 'empty-hooks', 'pre-commit'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    await assert.rejects(gitx.run(['rev-parse'], { cwd: root }), (e: unknown) => e instanceof GitxError && e.code === 'PRIVATE');
    await rm(nodePath.join(sync, 'empty-hooks', 'pre-commit'));
    await writeFile(nodePath.join(sync, 'empty.gitconfig'), '[core]\n\tsshCommand = evil\n');
    await assert.rejects(Gitx.open({ syncDir: sync, gitBin: '/bin/echo' }), (e: unknown) => e instanceof GitxError && e.code === 'PRIVATE');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/* ---------------- real git against a local bare remote ---------------- */

test('real git: hostile process env does not reach git; honest push/fetch work; force and rewrites are not possible', { skip: !posix }, async () => {
  const kit = await makeKit();
  try {
    const hub = await kit.makeHub(1);
    // A GIT_DIR pointing nowhere would break every command if inherited.
    const hostile = await Gitx.open({
      syncDir: nodePath.join(kit.root, 'hostile-sync'),
      testLocalRemotes: [kit.remote.path],
      env: { ...HOSTILE_ENV, PATH: process.env.PATH ?? '/usr/bin:/bin' },
    });
    const c1 = await hub.commit([{ path: 'a.md', content: 'one\n' }]);
    const r = await hostile.mustRun(['rev-parse', '--verify', 'refs/heads/main'], { cwd: hub.dir });
    assert.equal(r.stdout.toString().trim(), c1);

    const push1 = await hub.pushMain(kit.remote);
    assert.equal(push1.ok, true, push1.stderr);
    assert.equal(await kit.remote.main(), c1);

    const c2 = await hub.commit([{ path: 'a.md', content: 'two\n' }]);
    assert.equal((await hub.pushMain(kit.remote)).ok, true);
    assert.equal(await kit.remote.main(), c2);

    // remote history rewritten: a fresh root. A non-forced push of our tip must be rejected, remote untouched.
    const rewritten = await kit.remote.rewriteHistory(null);
    assert.equal(await kit.remote.main(), rewritten);
    const c3 = await hub.commit([{ path: 'a.md', content: 'three\n' }]);
    const push3 = await hub.pushMain(kit.remote);
    assert.equal(push3.ok, false);
    assert.equal(await kit.remote.main(), rewritten, 'push must never overwrite');
    assert.notEqual(c3, rewritten);

    // fetch lands in the scratch ref and never touches refs/heads/main
    const before = await hub.main();
    const incoming = await hub.fetchIncoming(kit.remote);
    assert.equal(incoming, rewritten);
    assert.equal(await hub.main(), before);

    // fetch into a branch name is impossible by construction
    await assert.rejects(hub.gitx.fetch(hub.dir, kit.remote.path, { dst: 'refs/heads/main' }), GitxError);
  } finally {
    await kit.cleanup();
  }
});

test('real git: git does not climb out of the working directory to find a repository', { skip: !posix }, async () => {
  const kit = await makeKit();
  try {
    const hub = await kit.makeHub(1);
    const inner = nodePath.join(hub.dir, 'not-a-repo');
    await mkdir(inner);
    const ok = await hub.gitx.run(['rev-parse', '--show-toplevel'], { cwd: hub.dir });
    assert.equal(ok.ok, true);
    const climb = await hub.gitx.run(['rev-parse', '--show-toplevel'], { cwd: inner });
    assert.equal(climb.ok, false, 'a subdirectory must not silently resolve to the parent repository');
  } finally {
    await kit.cleanup();
  }
});

test('real git: a fresh ledger repo config passes the allowlist; hostile additions do not', { skip: !posix }, async () => {
  const kit = await makeKit();
  try {
    const hub = await kit.makeHub(1);
    const cfgFile = nodePath.join(hub.dir, '.git', 'config');
    const text = await readFile(cfgFile, 'utf8');
    assert.deepEqual(checkGitConfig(text), []);
    assert.deepEqual(
      checkGitConfig(`${text}[remote "origin"]\n\turl = git@example.invalid:o/r.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n`),
      [],
    );
    assert.ok(checkGitConfig(`${text}[core]\n\tfsmonitor = touch pwn\n`).some((p) => p.code === 'key'));
  } finally {
    await kit.cleanup();
  }
});

/* ---------------- `.git/config` allowlist (S11) ---------------- */

const BASE = '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n';

test('checkGitConfig: accepts the usual config', () => {
  assert.deepEqual(checkGitConfig(BASE), []);
  assert.deepEqual(checkGitConfig(`${BASE}[remote "origin"]\n\turl = ssh://git@host.example/o/r.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n`), []);
  assert.deepEqual(checkGitConfig(`${BASE}# comment\n; another\n\n[extensions]\n\tobjectformat = sha256\n`), []);
  assert.deepEqual(checkGitConfig(`\ufeff${BASE}`), []);
  assert.deepEqual(checkGitConfig(`${BASE.replace(/\n/g, '\r\n')}`), []);
});

test('checkGitConfig: refuses insteadOf, include, filter, sshCommand, gpg and other command-bearing keys', () => {
  const cases: [string, string][] = [
    [`${BASE}[url "ssh://evil/"]\n\tinsteadOf = ssh://good/\n`, 'url-rewrite'],
    [`${BASE}[url "ssh://evil/"]\n\tpushInsteadOf = ssh://good/\n`, 'url-rewrite'],
    [`${BASE}[include]\n\tpath = /tmp/evil\n`, 'include'],
    [`${BASE}[includeIf "gitdir:/"]\n\tpath = /tmp/evil\n`, 'include'],
    [`${BASE}[INCLUDE]\n\tpath = x\n`, 'include'],
    [`${BASE}[filter "x"]\n\tclean = touch pwn\n`, 'filter'],
    [`${BASE}[core]\n\tsshCommand = touch pwn\n`, 'ssh-command'],
    [`${BASE}[CORE]\n\tSSHCOMMAND = touch pwn\n`, 'ssh-command'],
    [`${BASE}[core] sshCommand = touch pwn\n`, 'ssh-command'],
    [`${BASE}[gpg]\n\tprogram = evil\n`, 'gpg'],
    [`${BASE}[gpg "ssh"]\n\tprogram = evil\n`, 'gpg'],
    [`${BASE}[core]\n\tfsmonitor = evil\n`, 'key'],
    [`${BASE}[core]\n\thooksPath = /evil\n`, 'key'],
    [`${BASE}[core]\n\tpager = evil\n`, 'key'],
    [`${BASE}[core]\n\tgitProxy = evil\n`, 'key'],
    [`${BASE}[core]\n\tattributesFile = /evil\n`, 'key'],
    [`${BASE}[core]\n\tworktree = /evil\n`, 'key'],
    [`${BASE}[core]\n\tfilemode = $(touch pwn)\n`, 'value'],
    [`${BASE}[remote "origin"]\n\turl = ext::sh -c touch pwn\n`, 'value'],
    [`${BASE}[remote "origin"]\n\turl = -oProxyCommand=evil\n`, 'value'],
    [`${BASE}[remote "origin"]\n\turl = https://host/r.git\n`, 'value'],
    [`${BASE}[remote "origin"]\n\tvcs = evil\n`, 'key'],
    [`${BASE}[remote "origin"]\n\tpushurl = ssh://x/y\n`, 'key'],
    [`${BASE}[remote "origin"]\n\tproxy = evil\n`, 'key'],
    [`${BASE}[remote "origin"]\n\tuploadpack = evil\n`, 'key'],
    [`${BASE}[remote "origin"]\n\tfetch = +refs/heads/*:refs/heads/*\n`, 'value'],
    [`${BASE}[remote "evil"]\n\turl = ssh://x/y\n`, 'section'],
    [`${BASE}[branch "other"]\n\tremote = origin\n`, 'section'],
    [`${BASE}[branch "main"]\n\tremote = evil\n`, 'value'],
    [`${BASE}[branch "main"]\n\trebase = true\n`, 'key'],
    [`${BASE}[alias]\n\tx = !touch pwn\n`, 'section'],
    [`${BASE}[user]\n\tname = x\n`, 'section'],
    [`${BASE}[credential]\n\thelper = evil\n`, 'section'],
    [`${BASE}[diff "x"]\n\ttextconv = evil\n`, 'section'],
    [`${BASE}[merge "x"]\n\tdriver = evil\n`, 'section'],
    [`${BASE}[extensions]\n\tworktreeConfig = true\n`, 'key'],
    [`${BASE}[http]\n\tproxy = evil\n`, 'section'],
    [`${BASE}[protocol]\n\tallow = always\n`, 'section'],
  ];
  for (const [text, code] of cases) {
    const problems = checkGitConfig(text);
    assert.ok(problems.some((p) => p.code === code), `${code}: ${JSON.stringify(text.slice(BASE.length))} -> ${JSON.stringify(problems)}`);
  }
});

test('checkGitConfig: continuation lines, quoting and comments cannot hide a key', () => {
  // value continued over a line: the "key" on the continuation line is part of the value, not a key
  assert.deepEqual(checkGitConfig(`${BASE}[core]\n\tfilemode = true \\\n\tsshCommand = touch pwn\n`).map((p) => p.code), ['value']);
  // a quoted ; or # is data, an unquoted one starts a comment
  assert.deepEqual(checkGitConfig(`${BASE}[core]\n\tfilemode = true ; sshCommand = x\n`), []);
  assert.ok(checkGitConfig(`${BASE}[core]\n\tfilemode = "true ; x"\n`).some((p) => p.code === 'value'));
  // a comment ending in backslash does not continue
  assert.ok(checkGitConfig(`${BASE}# note \\\n[core]\n\tsshCommand = x\n`).some((p) => p.code === 'ssh-command'));
  // header followed by a key on the same line
  assert.ok(checkGitConfig('[core]\tsshCommand = x\n').some((p) => p.code === 'ssh-command'));
  // quoted subsection with escapes
  assert.ok(checkGitConfig(`${BASE}[remote "or\\"igin"]\n\turl = ssh://x/y\n`).some((p) => p.code === 'section'));
  // dotted legacy section header
  assert.deepEqual(checkGitConfig(`${BASE}[remote.origin]\n\turl = ssh://git@host.example/r\n`), []);
  assert.ok(checkGitConfig(`${BASE}[url.evil]\n\tinsteadof = x\n`).some((p) => p.code === 'url-rewrite'));
});

test('checkGitConfig: anything it cannot parse is a problem (fail closed), and values are never echoed', () => {
  for (const text of [
    '[core\n\tfilemode = true\n',
    '[core]\n\tfilemode = "unterminated\n',
    '[core]\n\tfilemode = true \\q\n',
    'filemode = true\n',
    '[core]\n\t= true\n',
    '[core]\n\t9bad = true\n',
    '[core]\n\tbare garbage\n',
    '[]\n',
    '[core "x]\n',
    '[core]\n\tfilemode = true\0\n',
  ]) {
    assert.ok(checkGitConfig(text).some((p) => p.code === 'parse'), JSON.stringify(text));
  }
  const problems = checkGitConfig(`${BASE}[core]\n\tfilemode = SECRETVALUE\u001b[31m\n[evil\u202e "sub\u001b"]\n\tkey = v\n`);
  for (const p of problems) {
    assert.ok(!p.name.includes('SECRETVALUE'));
    // eslint-disable-next-line no-control-regex
    assert.ok(!/[\u0000-\u001f\u202e]/.test(p.name), JSON.stringify(p.name));
  }
});

test('parseGitConfig: parsed values follow git semantics', () => {
  const { entries, parseError } = parseGitConfig('[Core]\n\tFileMode = "tr"ue  ; c\n[remote "origin"]\n\turl=a\\\nb\n\tflag\n');
  assert.equal(parseError, false);
  assert.deepEqual(entries[0], { section: 'core', subsection: null, key: 'filemode', value: 'true' });
  assert.deepEqual(entries[1], { section: 'remote', subsection: 'origin', key: 'url', value: 'ab' });
  assert.deepEqual(entries[2], { section: 'remote', subsection: 'origin', key: 'flag', value: null });
});

/* ---------------- B4a: initRepo (AL-52), anonymous probe, D3 matrix (AL-38) ---------------- */

test('buildSshCommand / buildGitEnv: anonymous mode has no -i, no public-key auth, no agent', () => {
  const named = buildSshCommand({ sshBin: '/usr/bin/ssh', knownHostsFile: '/x/kh', keyFile: '/x/key' });
  assert.ok(named.includes("'-i' '/x/key'"));
  assert.ok(!named.includes('PubkeyAuthentication'));
  const anon = buildSshCommand({ sshBin: '/usr/bin/ssh', knownHostsFile: '/x/kh', keyFile: '/x/key', anonymous: true });
  assert.ok(!anon.includes("'-i'") && !anon.includes('/x/key'), anon);
  assert.ok(anon.includes("'PubkeyAuthentication=no'") && anon.includes("'IdentityAgent=none'"), anon);
  const env = buildGitEnv({ source: HOSTILE_ENV, platform: 'linux', emptyConfigFile: '/e', sshCommand: 'x', noAgent: true });
  assert.ok(!('SSH_AUTH_SOCK' in env));
  assert.equal(env.GIT_SSH_COMMAND, 'x');
});

test('lsRemoteAnonymous: argv like lsRemote, but no -i, no SSH_AUTH_SOCK, no public-key auth', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const fake = await fakeBin(root, 'fakegit', DUMP);
    const gitx = await Gitx.open({
      syncDir: nodePath.join(root, 'sync'),
      gitBin: fake,
      sshBin: '/usr/bin/ssh',
      keyFile: nodePath.join(root, 'key'),
      env: { ...HOSTILE_ENV, PATH: process.env.PATH ?? '/usr/bin:/bin' },
    });
    const url = 'git@example.invalid:owner/repo.git';
    const named = parseDump((await gitx.lsRemote(root, url)).stdout);
    const anon = parseDump((await gitx.lsRemoteAnonymous(root, url)).stdout);
    assert.ok((named.env.get('GIT_SSH_COMMAND') ?? '').includes("'-i'"));
    assert.equal(named.env.get('SSH_AUTH_SOCK'), '/tmp/agent.sock');
    const cmd = anon.env.get('GIT_SSH_COMMAND') ?? '';
    assert.ok(cmd !== '' && !cmd.includes("'-i'") && !cmd.includes('/key'), cmd);
    assert.ok(cmd.includes("'PubkeyAuthentication=no'"));
    assert.ok(!anon.env.has('SSH_AUTH_SOCK'));
    const dd = anon.args.indexOf('--');
    assert.deepEqual(anon.args.slice(dd - 1), ['ls-remote', '--', url, 'refs/heads/main']);
    assert.deepEqual(anon.args.slice(dd), named.args.slice(named.args.indexOf('--')));
    await assert.rejects(gitx.lsRemoteAnonymous(root, '-oProxyCommand=x'), (e: unknown) => e instanceof GitxError && e.code === 'URL');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('real git: initRepo makes a main repo whose config passes the allowlist, with no remote.* and no templates', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync') });
    const dir = nodePath.join(root, 'ledger');
    await mkdir(dir, { mode: 0o700 });
    await gitx.initRepo(dir);
    const cfg = await readFile(nodePath.join(dir, '.git', 'config'), 'utf8');
    assert.deepEqual(checkGitConfig(cfg), []);
    assert.ok(!/\[remote/i.test(cfg) && !/tagOpt/i.test(cfg), 'init writes no remote.*');
    assert.equal((await readFile(nodePath.join(dir, '.git', 'HEAD'), 'utf8')).trim(), 'ref: refs/heads/main');
    const hooks = nodePath.join(dir, '.git', 'hooks');
    assert.ok(!existsSync(hooks) || (await readdir(hooks)).length === 0, 'no template hooks copied');
    // never reinitialises an existing repository
    await assert.rejects(gitx.initRepo(dir), (e: unknown) => e instanceof GitxError && e.code === 'ARGS');
    // relative / missing directories are typed errors
    await assert.rejects(gitx.initRepo('relative/dir'), GitxError);
    await assert.rejects(gitx.initRepo(nodePath.join(root, 'absent')), (e: unknown) => e instanceof GitxError && e.code === 'SPAWN');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('real git: initRepo falls back to init + symbolic-ref when git does not know --initial-branch (exit 129)', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const real = await resolveTrustedBinary(gitCandidates(), 'git');
    const old = await fakeBin(
      root,
      'oldgit',
      `for a in "$@"; do if [ "$a" = "--initial-branch=main" ]; then echo "error: unknown option" >&2; exit 129; fi; done\nexec '${real}' "$@"`,
    );
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync'), gitBin: old });
    const dir = nodePath.join(root, 'ledger');
    await mkdir(dir, { mode: 0o700 });
    await gitx.initRepo(dir);
    assert.equal((await readFile(nodePath.join(dir, '.git', 'HEAD'), 'utf8')).trim(), 'ref: refs/heads/main');
    assert.deepEqual(checkGitConfig(await readFile(nodePath.join(dir, '.git', 'config'), 'utf8')), []);
    // any other failure is NOT retried as a fallback
    const broken = await fakeBin(root, 'brokengit', 'echo boom >&2; exit 1');
    const g2 = await Gitx.open({ syncDir: nodePath.join(root, 'sync2'), gitBin: broken });
    const d2 = nodePath.join(root, 'ledger2');
    await mkdir(d2, { mode: 0o700 });
    await assert.rejects(g2.initRepo(d2), (e: unknown) => e instanceof GitxError && e.code === 'EXIT');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('AL-52: no code path spawns `clone` (the method is gone, run() refuses it, recorded argv never holds it)', { skip: !posix }, async () => {
  const root = await tmpRoot();
  try {
    const log = nodePath.join(root, 'argv.log');
    const rec = await fakeBin(root, 'recgit', `for a in "$@"; do printf '%s\\n' "$a" >> '${log}'; done`);
    const gitx = await Gitx.open({ syncDir: nodePath.join(root, 'sync'), gitBin: rec, sshBin: '/usr/bin/ssh' });
    assert.equal((gitx as unknown as Record<string, unknown>).clone, undefined);
    await assert.rejects(gitx.run(['clone', '--', 'ssh://h/r', root], { cwd: root }), (e: unknown) => e instanceof GitxError && e.code === 'ARGS');
    const url = 'git@example.invalid:owner/repo.git';
    const dir = nodePath.join(root, 'work');
    await mkdir(dir, { mode: 0o700 });
    await gitx.initRepo(dir);
    await gitx.fetch(root, url);
    await gitx.push(root, url, 'c'.repeat(40));
    await gitx.lsRemote(root, url);
    await gitx.lsRemoteAnonymous(root, url);
    const args = (await readFile(log, 'utf8')).split('\n');
    assert.ok(args.includes('init') && args.includes('fetch') && args.includes('ls-remote'));
    assert.ok(!args.includes('clone'));
    const src = await readFile(new URL('./gitx.ts', import.meta.url), 'utf8');
    assert.ok(!/['"`]clone['"`]/.test(src), 'gitx.ts must not name a clone subcommand');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('AL-38 D3: a legacy `remote.origin.url` is tolerated only as a clean absolute path or a valid ssh URL', () => {
  // git writes a backslash in a config value as `\\` (a raw `\b` is a backspace escape)
  const cfg = (url: string): string => `${BASE}[remote "origin"]\n\turl = ${url.replace(/\\/g, '\\\\')}\n`;
  const ok = (url: string): boolean => checkGitConfig(cfg(url)).length === 0;
  const posixOk = process.platform === 'win32' ? [] : ['/abs/path/to/backup.git', '/srv/git/ledger'];
  for (const u of [...posixOk, 'C:\\backup\\ledger.git', 'C:/backup/ledger.git', 'git@host.example:o/r.git', 'ssh://git@host.example/o/r.git']) {
    assert.ok(ok(u), `${u} must be tolerated`);
  }
  for (const u of [
    'relative/path',
    './rel',
    '../up',
    'file:///abs/path',
    'https://host.example/o/r.git',
    'http://host.example/o/r.git',
    'git://host.example/o/r.git',
    'ext::sh -c id',
    'fd::3',
    '-oProxyCommand=x',
    '--upload-pack=x',
    '/abs/with\u0001control',
    '/abs/with\u007fdel',
    'C:\\x\u0007bell',
  ]) {
    const problems = checkGitConfig(cfg(u));
    assert.ok(problems.length > 0, `${JSON.stringify(u)} must be refused`);
    assert.ok(!JSON.stringify(problems).includes(u.slice(0, 5)) || u.length <= 5, 'the value is never echoed');
  }
});
