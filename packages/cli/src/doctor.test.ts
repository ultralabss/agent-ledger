/** `ledger doctor` must stay read-only, fit in ten lines, and exit 1
 *  when something is actually wrong. */

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { CliEnvConfig } from './client.ts';
import { cmdDoctor, findInPath, logErrors, pickEntryScript, type DoctorDeps } from './doctor.ts';
import { linuxChecks } from './doctor-linux.ts';
import { parseRemoteUrl, remoteCheck } from './doctor-checks.ts';
import { parseArgs } from './args.ts';
import { selfHealMarker } from './selfheal.ts';

interface Captured {
  code: number;
  out: string[];
}

/** Hermetic deps: no systemctl, no real home, no real code checkout. */
function hermetic(dir: string, extra: DoctorDeps = {}): DoctorDeps {
  return {
    platform: 'linux',
    exists: async () => false,
    homeDir: dir,
    codeRepoDir: dir,
    searchPath: '',
    capture: async () => ({ code: null, stdout: '' }),
    ...extra,
  };
}

async function doctor(cfg: CliEnvConfig, argv: string[] = []): Promise<Captured> {
  const out: string[] = [];
  // platform: 'linux' — the launchd/plist probes are about the installed
  // instance, not about this temp ledger, so they stay out of the assertions.
  const code = await cmdDoctor(
    parseArgs(argv),
    cfg,
    {
      out: (l) => out.push(l),
      err: (l) => out.push(l),
      // A temp spool dir keeps `spoolStats` away from the real queue.
      env: { LEDGER_SPOOL_DIR: join(cfg.ledgerDir, 'spool') } as NodeJS.ProcessEnv,
    },
    hermetic(cfg.ledgerDir, { claudeSettingsPath: join(cfg.ledgerDir, 'no-such-settings.json') }),
  );
  return { code, out };
}

async function ledger(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-doctor-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, '.hub'), { recursive: true });
  await writeFile(join(dir, '.hub', 'token'), 'z'.repeat(43), { mode: 0o600 });
  return dir;
}

test('doctor: live hub with diag → OK, exit 0, at most 14 lines', async (t) => {
  const dir = await ledger(t);
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        ok: true,
        diag: {
          startedAt: '2026-10-11T08:00:00.000Z',
          lastWakeAt: null,
          loopDelayMaxMs: 12,
          missingRepos: [],
          gitleaksRetryAt: null,
        },
      }),
    );
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  t.after(
    () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  );
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? String(addr.port) : '0';

  await writeFile(selfHealMarker(dir), `${Date.now() - 5_000}\n`, { mode: 0o600 });
  const res = await doctor({
    baseUrl: `http://127.0.0.1:${port}`,
    ledgerDir: dir,
    session: null,
    agent: 'test',
  });
  const text = res.out.join('\n');
  assert.ok(res.out.length <= 14, `${res.out.length} lines:\n${text}`);
  assert.match(text, /healthz: 3\/3 ok/);
  assert.match(text, /loop max 12 ms/);
  assert.match(text, /self-heal \d+ s ago/);
  assert.equal(res.out.at(-1), 'OK');
  assert.equal(res.code, 0);
});

test('doctor: dead port → DOWN with a suggestion, exit 1, nothing written', async (t) => {
  const dir = await ledger(t);
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const addr = probe.address();
  const port = typeof addr === 'object' && addr !== null ? String(addr.port) : '0';
  await new Promise<void>((r) => probe.close(() => r()));

  const res = await doctor({
    baseUrl: `http://127.0.0.1:${port}`,
    ledgerDir: dir,
    session: null,
    agent: 'test',
  });
  assert.equal(res.code, 1);
  assert.ok(res.out.length <= 14, res.out.join('\n'));
  assert.match(res.out.at(-1) ?? '', /^DOWN: .* → /);
  assert.match(res.out.join('\n'), /healthz: 0\/3 ok/);
  // Read-only: no `--fix`, so no self-heal marker may appear.
  await assert.rejects(() => rm(selfHealMarker(dir), { force: false }));
});

test('doctor: an older hub without `diag` is tolerated', async (t) => {
  const dir = await ledger(t);
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true,"port":4747}');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  t.after(
    () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  );
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? String(addr.port) : '0';

  const res = await doctor({
    baseUrl: `http://127.0.0.1:${port}`,
    ledgerDir: dir,
    session: null,
    agent: 'test',
  });
  assert.equal(res.out.some((l) => l.startsWith('hub: ')), false, 'no hub line without diag');
  assert.equal(res.code, 0);
});

test('entry script is found after flags, not only at fixed index 1', () => {
  // Old plist shape: argv[0] is node, argv[1] is the script.
  assert.equal(pickEntryScript(['/usr/bin/node', '/opt/agent-ledger/bin.js']), '/opt/agent-ledger/bin.js');
  // New plist shape: argv[1] is a flag, the script is at index 2.
  assert.equal(
    pickEntryScript(['/usr/bin/node', '--disable-warning=ExperimentalWarning', '/opt/agent-ledger/bin.js']),
    '/opt/agent-ledger/bin.js',
  );
  // Several flags before the script.
  assert.equal(
    pickEntryScript(['/usr/bin/node', '--a', '--b', '/opt/agent-ledger/bin.js']),
    '/opt/agent-ledger/bin.js',
  );
  // No non-flag argument after argv[0].
  assert.equal(pickEntryScript(['/usr/bin/node', '--only-flags']), null);
  assert.equal(pickEntryScript(['/usr/bin/node']), null);
});

test('logErrors: only ISO-timestamped lines, with `since` only from the current run', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'doctor-log-'));
  try {
    await mkdir(join(dir, '.hub'), { recursive: true });
    await writeFile(
      join(dir, '.hub', 'hub.log'),
      [
        'repo watcher: Error: spawn /usr/bin/git ENOENT',
        '2026-10-11T17:00:00.000Z repo watcher: Error: old run',
        '2026-10-11T18:00:57.508Z agent-ledger listening on http://127.0.0.1:4747',
        '2026-10-11T18:01:00.000Z git commit failed: new run',
        '',
      ].join('\n'),
    );
    assert.deepEqual(await logErrors(dir), [
      '2026-10-11T17:00:00.000Z repo watcher: Error: old run',
      '2026-10-11T18:01:00.000Z git commit failed: new run',
    ]);
    assert.deepEqual(await logErrors(dir, 3, '2026-10-11T18:00:57.508Z'), [
      '2026-10-11T18:01:00.000Z git commit failed: new run',
    ]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('doctor: claude-code adapter check is info only (skipped without settings, counted with them)', async (t) => {
  const dir = await ledger(t);
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const addr = probe.address();
  const port = typeof addr === 'object' && addr !== null ? String(addr.port) : '0';
  await new Promise<void>((r) => probe.close(() => r()));
  const cfg: CliEnvConfig = {
    baseUrl: `http://127.0.0.1:${port}`,
    ledgerDir: dir,
    session: null,
    agent: 'test',
  };
  const run = async (settings: string): Promise<string[]> => {
    const out: string[] = [];
    await cmdDoctor(
      parseArgs([]),
      cfg,
      {
        out: (l) => out.push(l),
        err: (l) => out.push(l),
        env: { LEDGER_SPOOL_DIR: join(dir, 'spool') } as NodeJS.ProcessEnv,
      },
      hermetic(dir, { claudeSettingsPath: settings }),
    );
    return out;
  };

  const missing = await run(join(dir, 'nope.json'));
  assert.ok(missing.some((l) => /^claude-code adapter: skipped/.test(l)), missing.join('\n'));

  const settings = join(dir, 'settings.json');
  await writeFile(
    settings,
    JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ command: '/x/ledger hook pre-tool-use' }] }] } }),
  );
  const present = await run(settings);
  assert.ok(present.some((l) => /1 ledger hook entries installed/.test(l)), present.join('\n'));
  // Informational only: the verdict is driven by the hub being dead, not by the adapter line.
  assert.match(present.at(-1) ?? '', /^DOWN: .*hub is not answering/);
});

test('doctor: graphify line is info only — found / not found, never a problem', async (t) => {
  const dir = await ledger(t);
  const bin = join(dir, 'bin');
  await mkdir(bin, { recursive: true });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const addr = probe.address();
  const port = typeof addr === 'object' && addr !== null ? String(addr.port) : '0';
  await new Promise<void>((r) => probe.close(() => r()));
  const cfg: CliEnvConfig = {
    baseUrl: `http://127.0.0.1:${port}`,
    ledgerDir: dir,
    session: null,
    agent: 'test',
  };
  const run = async (searchPath: string): Promise<string[]> => {
    const out: string[] = [];
    await cmdDoctor(
      parseArgs([]),
      cfg,
      {
        out: (l) => out.push(l),
        err: (l) => out.push(l),
        env: { LEDGER_SPOOL_DIR: join(dir, 'spool') } as NodeJS.ProcessEnv,
      },
      hermetic(dir, { claudeSettingsPath: join(dir, 'nope.json'), searchPath }),
    );
    return out;
  };

  const none = await run(bin);
  assert.ok(none.includes('graphify: not found (optional)'), none.join('\n'));
  assert.doesNotMatch(none.at(-1) ?? '', /graphify/, 'a missing graphify must not show up as a problem');

  await writeFile(join(bin, 'graphify'), '#!/bin/sh\nexit 0\n');
  await chmod(join(bin, 'graphify'), 0o755);
  const found = await run(bin);
  assert.ok(found.includes(`graphify: found (${join(bin, 'graphify')})`), found.join('\n'));
  assert.equal(await findInPath('graphify', ''), null);
});

/* ---------------- identity, json, linux, remote ---------------- */

async function serve(
  t: { after: (fn: () => unknown) => void },
  body: unknown,
): Promise<string> {
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  t.after(
    () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  );
  const addr = server.address();
  return `http://127.0.0.1:${typeof addr === 'object' && addr !== null ? addr.port : 0}`;
}

function run(cfg: CliEnvConfig, argv: string[], deps: DoctorDeps, env: NodeJS.ProcessEnv = {}) {
  const out: string[] = [];
  return cmdDoctor(
    parseArgs(argv),
    cfg,
    {
      out: (l) => out.push(l),
      err: (l) => out.push(l),
      env: { LEDGER_SPOOL_DIR: join(cfg.ledgerDir, 'spool'), ...env } as NodeJS.ProcessEnv,
    },
    deps,
  ).then((code) => ({ code, out }));
}

test('doctor: hub of ANOTHER ledger on the port → identity fail, exit 1', async (t) => {
  const dir = await ledger(t);
  const baseUrl = await serve(t, { ok: true, ledger: '/somewhere/else/.ledger' });
  const res = await run({ baseUrl, ledgerDir: dir, session: null, agent: 'test' }, [], hermetic(dir));
  assert.equal(res.code, 1);
  assert.ok(res.out.some((l) => /^identity: .*another ledger/.test(l)), res.out.join('\n'));
  assert.match(res.out.at(-1) ?? '', /^DOWN: another hub owns/);
});

test('doctor: hub naming OUR ledger → identity ok; unnamed → warn, exit stays 0', async (t) => {
  const dir = await ledger(t);
  const named = await serve(t, { ok: true, ledger: dir });
  const a = await run({ baseUrl: named, ledgerDir: dir, session: null, agent: 'test' }, [], hermetic(dir));
  assert.ok(a.out.includes('identity: hub serves this ledger'), a.out.join('\n'));
  assert.equal(a.code, 0);
  const unnamed = await serve(t, { ok: true });
  const b = await run({ baseUrl: unnamed, ledgerDir: dir, session: null, agent: 'test' }, [], hermetic(dir));
  assert.ok(b.out.some((l) => /^identity: healthz did not name/.test(l)), b.out.join('\n'));
  assert.equal(b.code, 0);
});

test('doctor --json: stable structure, same exit code as the text mode', async (t) => {
  const dir = await ledger(t);
  const baseUrl = await serve(t, { ok: true, ledger: dir });
  const cfg = { baseUrl, ledgerDir: dir, session: null, agent: 'test' };
  const res = await run(cfg, ['--json'], hermetic(dir));
  assert.equal(res.out.length, 1);
  const doc = JSON.parse(res.out[0] ?? '') as {
    schema: number;
    platform: string;
    checks: { id: string; status: string; detail: string }[];
    summary: { ok: boolean; exit: number; counts: Record<string, number>; problems: string[] };
  };
  assert.equal(doc.schema, 1);
  assert.equal(doc.platform, 'linux');
  for (const c of doc.checks) {
    assert.match(c.id, /^[a-z_]+$/);
    assert.ok(['ok', 'warn', 'fail', 'info'].includes(c.status));
    assert.equal(typeof c.detail, 'string');
  }
  const ids = doc.checks.map((c) => c.id);
  for (const id of ['healthz', 'identity', 'spool', 'path', 'ledger_format', 'ledger_remote']) {
    assert.ok(ids.includes(id), `${id} in ${ids.join(',')}`);
  }
  assert.equal(doc.checks.find((c) => c.id === 'ledger_format')?.status, 'info');
  assert.equal(doc.summary.ok, true);
  assert.equal(doc.summary.exit, res.code);
  assert.equal(res.code, 0);

  const dead = await run({ ...cfg, baseUrl: 'http://127.0.0.1:1' }, ['--json'], hermetic(dir));
  const bad = JSON.parse(dead.out[0] ?? '') as { summary: { ok: boolean; exit: number; problems: string[] } };
  assert.equal(dead.code, 1);
  assert.equal(bad.summary.exit, 1);
  assert.ok(bad.summary.problems.length > 0);
});

test('linux: active unit + linger on → ok (mocked systemctl/loginctl, argv is constant)', async () => {
  const calls: { cmd: string; args: readonly string[] }[] = [];
  const r = await linuxChecks({
    uid: 1000,
    env: {},
    exists: async () => true,
    capture: async (cmd, args) => {
      calls.push({ cmd, args });
      return cmd.endsWith('systemctl')
        ? { code: 0, stdout: 'LoadState=loaded\nActiveState=active\nSubState=running\nNRestarts=0\nExecMainStatus=0\n' }
        : { code: 0, stdout: 'Linger=yes\n' };
    },
  });
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.checks.map((c) => [c.id, c.status]), [['systemd', 'ok'], ['linger', 'ok']]);
  assert.equal(calls[0]?.cmd, '/usr/bin/systemctl');
  assert.equal(calls[0]?.args[2], 'io.agent-ledger.hub.service');
  assert.deepEqual(calls[1]?.args, ['show-user', '1000', '-p', 'Linger']);
});

test('linux: failed / not-installed unit → problem; linger off → warn only; hostile label ignored', async () => {
  const mk = (stdout: string, linger: string, env: NodeJS.ProcessEnv = {}) =>
    linuxChecks({
      uid: 1000,
      env,
      exists: async () => true,
      capture: async (cmd, args) => {
        if (cmd.endsWith('systemctl')) {
          assert.ok(!args.some((a) => a.includes(';') || a.includes('$')), args.join(' '));
          return { code: 0, stdout };
        }
        return { code: 0, stdout: linger };
      },
    });
  const failed = await mk('LoadState=loaded\nActiveState=failed\nSubState=failed\nNRestarts=5\nExecMainStatus=1\n', 'Linger=no\n');
  assert.equal(failed.checks[0]?.status, 'fail');
  assert.equal(failed.checks[1]?.status, 'warn');
  assert.equal(failed.problems.length, 1);
  const missing = await mk('LoadState=not-found\nActiveState=inactive\n', 'Linger=yes\n', { AGENT_LEDGER_LABEL: 'x;rm -rf ~' });
  assert.equal(missing.checks[0]?.status, 'fail');
  assert.match(missing.checks[0]?.detail ?? '', /io\.agent-ledger\.hub\.service is not installed/);
});

test('linux: missing systemctl or unreachable user bus → info, never a failure', async () => {
  const none = await linuxChecks({ uid: 1000, env: {}, exists: async () => false, capture: async () => ({ code: 0, stdout: '' }) });
  assert.deepEqual(none.checks.map((c) => [c.id, c.status]), [['systemd', 'info']]);
  assert.deepEqual(none.problems, []);
  const nobus = await linuxChecks({ uid: 1000, env: {}, exists: async () => true, capture: async () => ({ code: 1, stdout: '' }) });
  assert.equal(nobus.checks[0]?.status, 'info');
  assert.equal(nobus.checks.length, 1, 'linger is skipped without a user session');
  assert.deepEqual(nobus.problems, []);
});

test('path: shim on PATH ok; shim dir not on PATH warns; neither warns', async (t) => {
  const dir = await ledger(t);
  const bin = join(dir, 'bin');
  await mkdir(bin, { recursive: true });
  const baseUrl = await serve(t, { ok: true, ledger: dir });
  const cfg = { baseUrl, ledgerDir: dir, session: null, agent: 'test' };
  const line = async (searchPath: string): Promise<string> =>
    (await run(cfg, [], hermetic(dir, { searchPath }), { SHIM_DIR: bin })).out.find((l) => l.startsWith('path:')) ?? '';
  assert.match(await line(bin), /^path: no ledger shim/);
  await writeFile(join(bin, 'ledger'), '#!/bin/sh\n');
  await chmod(join(bin, 'ledger'), 0o755);
  assert.match(await line(bin), /^path: ledger on PATH/);
  assert.match(await line(join(dir, 'elsewhere')), /directory is not on PATH/);
});

async function gitDir(dir: string, remotes: Record<string, string>): Promise<void> {
  await mkdir(join(dir, '.git'), { recursive: true });
  const cfg = Object.entries(remotes).map(([n, u]) => `[remote "${n}"]\n\turl = ${u}\n\tfetch = +refs/heads/*:refs/remotes/${n}/*\n`);
  await writeFile(join(dir, '.git', 'config'), `[core]\n\tbare = false\n${cfg.join('')}`);
}

test('remote: URL parsing strips credentials; scp and https forms compare equal', () => {
  const a = parseRemoteUrl('https://user:tok3n@github.com/Org/Repo.git');
  assert.equal(a.credentialed, true);
  assert.ok(!a.display.includes('tok3n') && !a.display.includes('user'));
  assert.equal(a.norm, parseRemoteUrl('git@github.com:org/repo').norm);
  assert.equal(parseRemoteUrl('ssh://git@host.example/x/y.git').credentialed, false);
});

test('remote: same as code remote → warn; public-looking https → warn; private ssh → ok; none → info', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ledger-remote-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const led = join(root, 'ledger');
  const code = join(root, 'code');
  await mkdir(led);
  await mkdir(code);
  assert.equal((await remoteCheck({ ledgerDir: led, codeRepoDir: code })).status, 'info');
  await gitDir(led, {});
  assert.match((await remoteCheck({ ledgerDir: led, codeRepoDir: code })).detail, /none \(local only\)/);

  await gitDir(code, { origin: 'git@github.com:acme/code.git' });
  await gitDir(led, { origin: 'https://github.com/acme/code' });
  const same = await remoteCheck({ ledgerDir: led, codeRepoDir: code });
  assert.equal(same.status, 'warn');
  assert.match(same.detail, /SAME as the code repo remote/);

  await gitDir(led, { origin: 'https://github.com/acme/ledger.git' });
  const pub = await remoteCheck({ ledgerDir: led, codeRepoDir: code });
  assert.equal(pub.status, 'warn');
  assert.match(pub.detail, /verify it is private/);

  await gitDir(led, { origin: 'git@github.com:acme/ledger.git' });
  const ok = await remoteCheck({ ledgerDir: led, codeRepoDir: code });
  assert.equal(ok.status, 'ok');
  assert.match(ok.detail, /not verified/);
});

test('remote: network only with online; public → fail, 404 → ok', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ledger-remote-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await gitDir(root, { origin: 'git@github.com:acme/ledger.git' });
  let calls = 0;
  const mk = (status: number): typeof fetch =>
    (async () => {
      calls += 1;
      return new Response('{}', { status });
    }) as typeof fetch;
  await remoteCheck({ ledgerDir: root, codeRepoDir: root + '-none', fetchFn: mk(200) });
  assert.equal(calls, 0, 'no request without --online');
  const pub = await remoteCheck({ ledgerDir: root, codeRepoDir: root + '-none', online: true, fetchFn: mk(200) });
  assert.equal(pub.status, 'fail');
  const priv = await remoteCheck({ ledgerDir: root, codeRepoDir: root + '-none', online: true, fetchFn: mk(404) });
  assert.equal(priv.status, 'ok');
  assert.equal(calls, 2);
});
