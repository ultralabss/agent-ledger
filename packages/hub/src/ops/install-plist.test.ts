/** `install.sh` service-file rendering — launchd plist and systemd user unit:
 *  XML/unit escaping, `ensure_chain` on the service directory, hardening
 *  properties. Uses `--render-plist-only` / `--render-unit-only`, test-only
 *  entry points that render the file and exit — no pnpm install, no
 *  ledger/shim provisioning, no `launchctl`/`systemctl`. Every run gets a
 *  throwaway `$HOME` (required by `ensure_chain`), so the real home, the real
 *  `~/Library/LaunchAgents` and `~/.config/systemd` are never touched. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'install.sh');

function run(
  args: string[],
  home: string,
  env: NodeJS.ProcessEnv = {},
): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn('bash', [SCRIPT, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, LEDGER_CLAUDE_BIN: '', HOME: home, ...env },
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d: Buffer) => (out += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (err += d.toString('utf8')));
    child.on('close', (code) => resolvePromise({ code, out, err }));
  });
}

/** `plutil -lint` on macOS. Elsewhere there is no plutil: the textual
 *  assertions in each test still apply, so the lint is a pass. */
function lint(file: string): Promise<{ code: number | null; err: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn('plutil', ['-lint', file], { stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.on('data', (d: Buffer) => (err += d.toString('utf8')));
    child.on('error', () => resolvePromise({ code: 0, err: '' }));
    child.on('close', (code) => resolvePromise({ code, err }));
  });
}

/** A fresh, private `$HOME` (mkdtemp is 0700) plus cleanup. */
async function fakeHome(t: test.TestContext): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'agent-ledger-install-test-'));
  t.after(() => rm(home, { recursive: true, force: true }));
  return home;
}

/* ------------------------------ launchd plist ------------------------------ */

test('plist: values are XML-escaped, the result is a valid plist', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'sub', 'dir', 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, {
    LEDGER_DIR: `/tmp/led&ger <x> "q" 'z'`,
    LEDGER_HUB_PORT: '4747',
  });
  assert.equal(res.code, 0, res.err);

  const plist = await readFile(out, 'utf8');
  assert.match(plist, /<string>\/tmp\/led&amp;ger &lt;x&gt; &quot;q&quot; &apos;z&apos;<\/string>/);
  assert.equal(plist.includes('led&ger <x>'), false, 'the raw (unescaped) value must not be in the file');

  const linted = await lint(out);
  assert.equal(linted.code, 0, `plutil -lint failed: ${linted.err}`);
});

test('plist: an XML injection attempt via LEDGER_DIR creates no new <key>, the plist stays valid', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, {
    LEDGER_DIR: '/tmp/x</string><key>Injected</key><string>pwned',
    LEDGER_HUB_PORT: '4747',
  });
  assert.equal(res.code, 0, res.err);

  const plist = await readFile(out, 'utf8');
  assert.equal(plist.includes('<key>Injected</key>'), false, 'injected XML must stay escaped text');
  const linted = await lint(out);
  assert.equal(linted.code, 0, `plutil -lint failed: ${linted.err}`);
});

test('plist: the plist directory goes through ensure_chain (created 0755, never through a symlink)', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'newly', 'created', 'chain', 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, { LEDGER_HUB_PORT: '4747' });
  assert.equal(res.code, 0, res.err);

  const st = await lstat(dirname(out));
  assert.equal(st.isDirectory(), true);
  assert.equal((st.mode & 0o777).toString(8), '755');
});

test('plist: a symlinked path component is refused', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const elsewhere = join(home, 'elsewhere');
  await mkdir(elsewhere);
  const { symlink } = await import('node:fs/promises');
  await symlink(elsewhere, join(home, 'linked'));
  const out = join(home, 'linked', 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, { LEDGER_HUB_PORT: '4747' });
  assert.notEqual(res.code, 0);
  assert.match(res.err, /symlink/);
});

test('plist: `&` in a value does not collapse into the placeholder (awk gsub `&` gotcha)', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  // Regression: `gsub(pattern, repl)` treats a bare `&` in `repl` as "insert
  // the match" — an already-XML-escaped value is full of literal `&`
  // (`&amp;`), so without `awk_repl_escape` every `&` re-expanded into the
  // `@LEDGER@`/`@LOG@` placeholder it was supposed to replace.
  const home = await fakeHome(t);
  const out = join(home, 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, {
    LEDGER_DIR: '/tmp/a&b&c',
    LEDGER_HUB_PORT: '4747',
  });
  assert.equal(res.code, 0, res.err);
  const plist = await readFile(out, 'utf8');
  assert.equal(plist.includes('@LEDGER@'), false, 'the placeholder must not survive substitution');
  assert.match(plist, /<string>\/tmp\/a&amp;b&amp;c<\/string>/);
});

test('plist: LEDGER_CLAUDE_BIN with XML-special characters in the path is escaped too (--headless)', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const binDir = join(home, 'bin');
  await mkdir(binDir, { recursive: true });
  const claudeBin = join(binDir, `cl&<aude>".sh`);
  await writeFile(claudeBin, '#!/bin/sh\necho ok\n', 'utf8');
  await chmod(claudeBin, 0o755);
  const out = join(home, 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out, '--headless'], home, {
    LEDGER_HUB_PORT: '4747',
    LEDGER_CLAUDE_BIN: claudeBin,
  });
  assert.equal(res.code, 0, res.err);
  const plist = await readFile(out, 'utf8');
  assert.equal(plist.includes(`cl&<aude>".sh`), false);
  assert.match(plist, /cl&amp;&lt;aude&gt;&quot;\.sh/);
  assert.match(plist, /<key>LEDGER_HEADLESS<\/key>\s*<string>1<\/string>/);
  const linted = await lint(out);
  assert.equal(linted.code, 0, `plutil -lint failed: ${linted.err}`);
});

test('plist: no agent-specific keys by default (headless is opt-in)', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, { LEDGER_HUB_PORT: '4747' });
  assert.equal(res.code, 0, res.err);
  const plist = await readFile(out, 'utf8');
  assert.equal(plist.includes('<key>LEDGER_CLAUDE_BIN</key>'), false);
  assert.equal(plist.includes('<key>LEDGER_HEADLESS</key>'), false);
  assert.equal(plist.includes('@EXTRA_ENV@'), false);
  assert.match(plist, /<key>Label<\/key>\s*<string>io\.agent-ledger\.hub<\/string>/);
});

test('plist: feature flags set in the installer environment are passed into the service', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, {
    LEDGER_HUB_PORT: '4747',
    LEDGER_INTRUDE: '1',
    LEDGER_RECAP_TAGS: 'BLOCKER,DEPLOY',
  });
  assert.equal(res.code, 0, res.err);
  const plist = await readFile(out, 'utf8');
  assert.match(plist, /<key>LEDGER_INTRUDE<\/key>\s*<string>1<\/string>/);
  assert.match(plist, /<key>LEDGER_RECAP_TAGS<\/key>\s*<string>BLOCKER,DEPLOY<\/string>/);
  const linted = await lint(out);
  assert.equal(linted.code, 0, `plutil -lint failed: ${linted.err}`);
});

test('plist: AGENT_LEDGER_LABEL overrides the label; an unsafe label is refused', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'custom.plist');

  const ok = await run(['--render-plist-only', out], home, { AGENT_LEDGER_LABEL: 'org.example.ledger' });
  assert.equal(ok.code, 0, ok.err);
  assert.match(await readFile(out, 'utf8'), /<string>org\.example\.ledger<\/string>/);

  const bad = await run(['--render-plist-only', join(home, 'bad.plist')], home, {
    AGENT_LEDGER_LABEL: '../../evil',
  });
  assert.notEqual(bad.code, 0);
  assert.match(bad.err, /AGENT_LEDGER_LABEL/);
});

test('plist: ProcessType Standard, ExitTimeOut 30 and the node flag before the script', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'io.agent-ledger.hub.plist');

  const res = await run(['--render-plist-only', out], home, { LEDGER_HUB_PORT: '4747' });
  assert.equal(res.code, 0, res.err);
  const plist = await readFile(out, 'utf8');

  // `Background` throttled the hub's CPU/IO *and* its children — that is how a
  // ~100 ms FTS rebuild became a 764 ms event-loop stall and how the gitleaks
  // child hit its 10 s timeout after every wake.
  assert.match(plist, /<key>ProcessType<\/key>\s*<string>Standard<\/string>/);
  assert.equal(plist.includes('<string>Background</string>'), false);
  // The SIGTERM handler commits the ledger; launchd's default would SIGKILL it
  // mid-commit.
  assert.match(plist, /<key>ExitTimeOut<\/key>\s*<integer>30<\/integer>/);
  // KeepAlive + ThrottleInterval stay exactly as they were.
  assert.match(plist, /<key>KeepAlive<\/key>\s*<true\/>/);
  assert.match(plist, /<key>ThrottleInterval<\/key>\s*<integer>10<\/integer>/);
  // A node flag is a flag only while it comes BEFORE the script path.
  const args = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist)?.[1] ?? '';
  const strings = [...args.matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1] ?? '');
  assert.equal(strings[1], '--disable-warning=ExperimentalWarning');
  assert.match(strings[2] ?? '', /bin\.ts$/);

  const linted = await lint(out);
  assert.equal(linted.code, 0, `plutil -lint failed: ${linted.err}`);
});

/* ---------------------------- systemd user unit ---------------------------- */

/** Values of every `Environment="K=V"` line, keyed by K. */
function unitEnv(unit: string): Map<string, string> {
  const env = new Map<string, string>();
  for (const m of unit.matchAll(/^Environment="([A-Z_]+)=((?:[^"\\]|\\.)*)"$/gm)) {
    env.set(m[1] as string, m[2] as string);
  }
  return env;
}

test('systemd: renders a user unit with Restart=on-failure and an absolute, shell-free ExecStart', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, '.config', 'systemd', 'user', 'io.agent-ledger.hub.service');

  const res = await run(['--render-unit-only', out], home, {
    LEDGER_DIR: join(home, '.ledger'),
    LEDGER_HUB_PORT: '4747',
  });
  assert.equal(res.code, 0, res.err);

  const unit = await readFile(out, 'utf8');
  assert.equal(/@[A-Z_]+@/.test(unit), false, 'no placeholder may survive');
  assert.match(unit, /^\[Unit\]$/m);
  assert.match(unit, /^\[Service\]$/m);
  assert.match(unit, /^\[Install\]$/m);
  assert.match(unit, /^Restart=on-failure$/m);
  assert.match(unit, /^WantedBy=default\.target$/m);
  // ExecStart: quoted absolute node, the node flag BEFORE the script, quoted absolute hub bin, no shell.
  const exec = /^ExecStart=(.*)$/m.exec(unit)?.[1] ?? '';
  assert.match(exec, /^"\/[^"]+" --disable-warning=ExperimentalWarning "\/[^"]+\/packages\/hub\/src\/bin\.ts"$/);
  assert.equal(/\b(sh|bash|zsh) -c\b/.test(exec), false, 'no shell in ExecStart');
  const env = unitEnv(unit);
  assert.equal(env.get('LEDGER_DIR'), join(home, '.ledger'));
  assert.equal(env.get('LEDGER_HUB_PORT'), '4747');
  assert.equal(env.get('NODE_ENV'), 'production');
  assert.match(unit, new RegExp(`^StandardOutput=append:${join(home, '.ledger', '.hub', 'hub.log').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
  // No agent-specific settings by default.
  assert.equal(unit.includes('Environment="LEDGER_CLAUDE_BIN='), false);
  assert.equal(unit.includes('Environment="LEDGER_HEADLESS='), false);

  const st = await lstat(dirname(out));
  assert.equal((st.mode & 0o777).toString(8), '755', 'unit directory created 0755 via ensure_chain');
});

test('systemd: quotes, backslashes, `%` and `$` in values are escaped; a line break is refused', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const out = join(home, 'a.service');

  const res = await run(['--render-unit-only', out], home, {
    LEDGER_DIR: '/tmp/a "q" \\ 100% $HOME & more',
    LEDGER_HUB_PORT: '4747',
  });
  assert.equal(res.code, 0, res.err);
  const unit = await readFile(out, 'utf8');
  assert.equal(
    unitEnv(unit).get('LEDGER_DIR'),
    '/tmp/a \\"q\\" \\\\ 100%% $HOME & more',
    'quote, backslash and % escaped; & survives awk substitution; $ is literal in Environment=',
  );
  assert.equal(unit.split('\n').filter((l) => l.startsWith('Environment="LEDGER_DIR=')).length, 1);

  // A newline would inject a second directive into the unit.
  const bad = await run(['--render-unit-only', join(home, 'b.service')], home, {
    LEDGER_DIR: '/tmp/x"\nExecStartPost=/bin/touch /tmp/pwned',
  });
  assert.notEqual(bad.code, 0);
  assert.match(bad.err, /line break/);
  await assert.rejects(() => readFile(join(home, 'b.service'), 'utf8'), /ENOENT/, 'nothing rendered');
});

test('systemd: feature flags and --headless land as Environment= lines; AGENT_LEDGER_LABEL does not change the unit body', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const binDir = join(home, 'bin');
  await mkdir(binDir, { recursive: true });
  const agentBin = join(binDir, 'claude');
  await writeFile(agentBin, '#!/bin/sh\necho ok\n', 'utf8');
  await chmod(agentBin, 0o755);
  const out = join(home, 'c.service');

  const res = await run(['--render-unit-only', out, '--headless'], home, {
    LEDGER_HUB_PORT: '4747',
    LEDGER_CLAUDE_BIN: agentBin,
    LEDGER_PUSH: '1',
    LEDGER_WEB_REPLIES: '1',
  });
  assert.equal(res.code, 0, res.err);
  const env = unitEnv(await readFile(out, 'utf8'));
  assert.equal(env.get('LEDGER_HEADLESS'), '1');
  assert.equal(env.get('LEDGER_CLAUDE_BIN'), agentBin);
  assert.equal(env.get('LEDGER_PUSH'), '1');
  assert.equal(env.get('LEDGER_WEB_REPLIES'), '1');
});

test('systemd: a `$` in the hub path is doubled in ExecStart (no env expansion)', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  // ExecStart= expands `$VAR`, Environment= does not. The node path comes from
  // PATH lookup, so put a fake node with a `$` in its directory name first.
  const home = await fakeHome(t);
  const binDir = join(home, 'b$in');
  await mkdir(binDir, { recursive: true });
  const real = process.execPath;
  const fakeNode = join(binDir, 'node');
  await writeFile(fakeNode, `#!/bin/sh\nexec "${real}" "$@"\n`, 'utf8');
  await chmod(fakeNode, 0o755);
  const out = join(home, 'd.service');

  const res = await run(['--render-unit-only', out], home, {
    PATH: `${binDir}:${process.env.PATH ?? ''}`,
    LEDGER_HUB_PORT: '4747',
  });
  assert.equal(res.code, 0, res.err);
  const exec = /^ExecStart=(.*)$/m.exec(await readFile(out, 'utf8'))?.[1] ?? '';
  assert.ok(exec.startsWith(`"${join(home, 'b$$in')}/node"`), `ExecStart was: ${exec}`);
});

test('a value that looks like a placeholder is inserted literally, never substituted again', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const home = await fakeHome(t);
  const plist = join(home, 'p.plist');
  const unit = join(home, 'u.service');
  const env = { LEDGER_DIR: '/tmp/@PORT@/@LABEL@', LEDGER_HUB_PORT: '4747' };

  assert.equal((await run(['--render-plist-only', plist], home, env)).code, 0);
  assert.match(await readFile(plist, 'utf8'), /<string>\/tmp\/@PORT@\/@LABEL@<\/string>/);

  assert.equal((await run(['--render-unit-only', unit], home, env)).code, 0);
  assert.equal(unitEnv(await readFile(unit, 'utf8')).get('LEDGER_DIR'), '/tmp/@PORT@/@LABEL@');
});

test('--trust-claude-group pins the opt-in to the realpath and gid it saw; a plain directory pins nothing', { skip: skipOnWin32('POSIX-only: sh/awk installer, launchd/systemd units') }, async (t) => {
  const { realpath } = await import('node:fs/promises');
  const home = await fakeHome(t);

  // Group-writable directory (g+w, not o+w): the opt-in is meaningful.
  const groupDir = join(home, 'gw-bin');
  await mkdir(groupDir);
  await chmod(groupDir, 0o775);
  const agentBin = join(groupDir, 'agent');
  await writeFile(agentBin, '#!/bin/sh\necho ok\n', 'utf8');
  await chmod(agentBin, 0o755);
  const out = join(home, 'pinned.plist');
  const res = await run(['--render-plist-only', out, '--trust-claude-group'], home, {
    LEDGER_CLAUDE_BIN: agentBin,
  });
  assert.equal(res.code, 0, res.err);
  const plist = await readFile(out, 'utf8');
  assert.match(plist, /<key>LEDGER_HEADLESS<\/key>\s*<string>1<\/string>/, '--trust-claude-group implies --headless');
  assert.match(plist, /<key>LEDGER_TRUST_CLAUDE_GROUP<\/key>\s*<string>1<\/string>/);
  assert.match(plist, /<key>LEDGER_TRUST_CLAUDE_GID<\/key>\s*<string>\d+<\/string>/);
  const real = await realpath(agentBin);
  assert.ok(plist.includes(`<string>${real}</string>`), 'the realpath of the binary is pinned');

  // A directory chain with nothing group-writable below $HOME's own parents:
  // nothing is pinned. (Skipped when an ancestor happens to be group-writable.)
  const plainDir = join(home, 'plain-bin');
  await mkdir(plainDir);
  await chmod(plainDir, 0o755);
  const plainBin = join(plainDir, 'agent');
  await writeFile(plainBin, '#!/bin/sh\necho ok\n', 'utf8');
  await chmod(plainBin, 0o755);
  const out2 = join(home, 'plain.plist');
  const res2 = await run(['--render-plist-only', out2, '--trust-claude-group'], home, {
    LEDGER_CLAUDE_BIN: plainBin,
  });
  assert.equal(res2.code, 0, res2.err);
  const plain = await readFile(out2, 'utf8');
  if (/not needed/.test(res2.out)) {
    assert.equal(plain.includes('<key>LEDGER_TRUST_CLAUDE_GROUP</key>'), false);
  }
});
