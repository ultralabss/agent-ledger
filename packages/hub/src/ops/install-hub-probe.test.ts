/** `install.sh` hub identity, port handling and the brew consent gate.
 *
 *  The functions are extracted from `install.sh` by marker (never a copy), so
 *  the test runs the real source without pnpm, a service manager or the real
 *  home directory. Fake hubs listen on 127.0.0.1:0. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const INSTALL_SH = join(ROOT, 'install.sh');
const UNINSTALL_SH = join(ROOT, 'uninstall.sh');

interface Res {
  code: number | null;
  out: string;
  err: string;
}

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<Res> {
  return new Promise((resolvePromise) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], env });
    let out = '';
    let err = '';
    child.stdout.on('data', (d: Buffer) => (out += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (err += d.toString('utf8')));
    child.on('close', (code) => resolvePromise({ code, out, err }));
  });
}

async function tmp(t: test.TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-probe-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** `validate_port() … # <<< hub-probe`, by marker. */
async function probeBlock(): Promise<string> {
  const src = await readFile(INSTALL_SH, 'utf8');
  const start = src.indexOf('validate_port() {');
  const endMarker = '# <<< hub-probe';
  const end = src.indexOf(endMarker, start);
  assert.notEqual(start, -1, 'validate_port marker not found in install.sh');
  assert.notEqual(end, -1, 'hub-probe end marker not found in install.sh');
  return src.slice(start, end + endMarker.length);
}

async function listen(t: test.TestContext, handler: Parameters<typeof createServer>[1]): Promise<number> {
  const server: Server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  t.after(
    () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  );
  const addr = server.address();
  return typeof addr === 'object' && addr !== null ? addr.port : 0;
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
  await new Promise<void>((r) => server.close(() => r()));
  return port;
}

/** Runs `body` with the extracted functions and the variables install.sh would have set. */
async function withBlock(
  body: string,
  vars: { port: number; ledger: string; shim?: string; allowBrew?: 0 | 1 },
  path = process.env.PATH ?? '',
): Promise<Res> {
  const script = [
    'set -euo pipefail',
    'die() { echo "install: $*" >&2; exit 1; }',
    `NODE=${JSON.stringify(process.execPath)}`,
    `PORT=${vars.port}`,
    `LEDGER=${JSON.stringify(vars.ledger)}`,
    `SHIM=${JSON.stringify(vars.shim ?? '/nonexistent/shim')}`,
    `ALLOW_BREW=${vars.allowBrew ?? 0}`,
    await probeBlock(),
    body,
  ].join('\n');
  return run('/bin/bash', ['-c', script], { PATH: path, HOME: tmpdir() });
}

/** A ledger dir with a token, and a fake hub that answers like the real one. */
async function ledgerWithHub(t: test.TestContext): Promise<{ dir: string; port: number }> {
  const dir = await tmp(t);
  await mkdir(join(dir, '.hub'), { recursive: true });
  await writeFile(join(dir, '.hub', 'token'), 't'.repeat(43), { mode: 0o600 });
  const port = await listen(t, (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      req.headers['x-hub-token'] === 't'.repeat(43) ? JSON.stringify({ ok: true, ledger: dir }) : '{"ok":true}',
    );
  });
  return { dir, port };
}

async function fakeShim(t: test.TestContext): Promise<{ shim: string; marker: string }> {
  const dir = await tmp(t);
  const shim = join(dir, 'ledger');
  const marker = join(dir, 'ran');
  await writeFile(shim, `#!/bin/sh\necho "$LEDGER_HUB_PORT:$LEDGER_DIR" > "${marker}"\necho "hub ok (fake)"\n`);
  await chmod(shim, 0o755);
  return { shim, marker };
}

test('probe_hub: free port → 10, this ledger → 0, stranger/other ledger → 11', async (t) => {
  const mine = await ledgerWithHub(t);
  const stranger = await listen(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });
  const notHttp = await listen(t, (_req, res) => {
    res.writeHead(200);
    res.end('hello');
  });

  const code = async (port: number, ledger: string): Promise<number> => {
    const res = await withBlock('rc=0; probe_hub || rc=$?; echo "rc=$rc"', { port, ledger });
    return Number(/rc=(\d+)/.exec(res.out)?.[1]);
  };
  assert.equal(await code(await freePort(), mine.dir), 10);
  assert.equal(await code(mine.port, mine.dir), 0);
  assert.equal(await code(stranger, mine.dir), 11);
  assert.equal(await code(notHttp, mine.dir), 11);
  // Same hub, but the installer is pointed at a different ledger directory.
  const other = await tmp(t);
  assert.equal(await code(mine.port, other), 11);
});

test('ensure_port_available: free ok · own hub ok (re-install) · stranger → fail, never a silent skip', async (t) => {
  const mine = await ledgerWithHub(t);
  const stranger = await listen(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });

  const free = await withBlock('ensure_port_available', { port: await freePort(), ledger: mine.dir });
  assert.equal(free.code, 0, free.err);

  const own = await withBlock('ensure_port_available', { port: mine.port, ledger: mine.dir });
  assert.equal(own.code, 0, own.err);
  assert.match(own.out, /re-install/);

  const busy = await withBlock('ensure_port_available', { port: stranger, ledger: mine.dir });
  assert.equal(busy.code, 1);
  assert.match(busy.err, new RegExp(`port ${stranger} is in use by another process`));
  assert.match(busy.err, /--port <n>/);
});

test('wait_for_hub: a stranger on the port is a failure; our hub is a success and gets the right env', async (t) => {
  const mine = await ledgerWithHub(t);
  const stranger = await listen(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });

  const bad = await fakeShim(t);
  const failed = await withBlock('wait_for_hub', { port: stranger, ledger: mine.dir, shim: bad.shim });
  assert.equal(failed.code, 1);
  assert.match(failed.err, /something else answers/);
  await assert.rejects(stat(bad.marker), 'ledger status must not be reported for a stranger');

  const good = await fakeShim(t);
  const ok = await withBlock('wait_for_hub', { port: mine.port, ledger: mine.dir, shim: good.shim });
  assert.equal(ok.code, 0, ok.err);
  assert.match(ok.out, /hub ok \(fake\)/);
  assert.equal((await readFile(good.marker, 'utf8')).trim(), `${mine.port}:${mine.dir}`);
});

test('brew gitleaks: never without consent; --allow-brew runs it; an existing gitleaks wins', async (t) => {
  const dir = await tmp(t);
  const bin = join(dir, 'bin');
  await mkdir(bin);
  const marker = join(dir, 'brew-called');
  await writeFile(join(bin, 'brew'), `#!/bin/sh\necho "$@" > "${marker}"\n`);
  await chmod(join(bin, 'brew'), 0o755);
  const vars = { port: 1, ledger: dir };

  const denied = await withBlock('brew_gitleaks_if_allowed', { ...vars, allowBrew: 0 }, bin);
  assert.equal(denied.code, 0, denied.err);
  assert.match(denied.out, /--allow-brew/);
  await assert.rejects(stat(marker), 'brew must not run without consent');

  const allowed = await withBlock('brew_gitleaks_if_allowed', { ...vars, allowBrew: 1 }, bin);
  assert.equal(allowed.code, 0, allowed.err);
  assert.equal((await readFile(marker, 'utf8')).trim(), 'install gitleaks');

  await rm(marker);
  await writeFile(join(bin, 'gitleaks'), '#!/bin/sh\nexit 0\n');
  await chmod(join(bin, 'gitleaks'), 0o755);
  const present = await withBlock('brew_gitleaks_if_allowed', { ...vars, allowBrew: 1 }, bin);
  assert.equal(present.code, 0, present.err);
  await assert.rejects(stat(marker), 'brew must not run when gitleaks is already in PATH');
});

test('install.sh: --port validation, busy port fails before any work, --no-service skips the check', async (t) => {
  const home = await tmp(t);
  const fakeBin = join(home, 'fakebin');
  await mkdir(fakeBin);
  const marker = join(home, 'pnpm-called');
  await writeFile(join(fakeBin, 'pnpm'), `#!/bin/sh\ntouch "${marker}"\nexit 1\n`);
  await chmod(join(fakeBin, 'pnpm'), 0o755);
  const env = { ...process.env, HOME: home, PATH: `${fakeBin}:${process.env.PATH ?? ''}`, LEDGER_HUB_PORT: '' };

  const help = await run('bash', [INSTALL_SH, '--help'], env);
  assert.equal(help.code, 0);
  assert.match(help.out, /--allow-brew/);
  assert.match(help.out, /--port <n>/);

  const bad = await run('bash', [INSTALL_SH, '--port', 'abc'], env);
  assert.equal(bad.code, 1);
  assert.match(bad.err, /invalid port "abc"/);

  const stranger = await listen(t, (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });
  const busy = await run('bash', [INSTALL_SH, '--port', String(stranger)], env);
  assert.equal(busy.code, 1);
  assert.match(busy.err, new RegExp(`port ${stranger} is (in use|taken)`));
  await assert.rejects(stat(marker), 'pnpm must not run when the port is taken');

  const noService = await run('bash', [INSTALL_SH, '--no-service', '--port', String(stranger)], env);
  assert.notEqual(noService.code, 0, 'fake pnpm fails the run');
  await stat(marker); // got as far as pnpm: the port check does not apply without a service
});

test('uninstall.sh removes the Claude Code hooks (non-interactive) and leaves the ledger alone', async (t) => {
  const home = await tmp(t);
  const settings = join(home, '.claude', 'settings.json');
  const env = {
    ...process.env,
    HOME: home,
    // Never the real service: a unique label, so `bootout` / `disable` hit nothing.
    AGENT_LEDGER_LABEL: `io.agent-ledger.test-${process.pid}-${Date.now()}`,
  };
  const hooks = join(ROOT, 'adapters', 'claude-code', 'install-hooks.mjs');

  const installed = await run(process.execPath, [hooks, '--yes'], env);
  assert.equal(installed.code, 0, installed.err);
  assert.match(await readFile(settings, 'utf8'), /ledger hook session-start/);

  await mkdir(join(home, '.ledger'));
  const res = await run('bash', [UNINSTALL_SH], env);
  assert.equal(res.code, 0, res.err);
  assert.match(res.out, /hooks: done/);
  assert.doesNotMatch(await readFile(settings, 'utf8'), /ledger hook/);
  await stat(join(home, '.ledger'));
});
