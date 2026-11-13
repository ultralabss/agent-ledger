/** `ledger doctor` must stay read-only, fit in ten lines, and exit 1
 *  when something is actually wrong. */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { CliEnvConfig } from './client.ts';
import { cmdDoctor, logErrors, pickEntryScript } from './doctor.ts';
import { parseArgs } from './args.ts';
import { selfHealMarker } from './selfheal.ts';

interface Captured {
  code: number;
  out: string[];
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
    { platform: 'linux', claudeSettingsPath: join(cfg.ledgerDir, 'no-such-settings.json') },
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

test('doctor: live hub with diag → OK, exit 0, at most 10 lines', async (t) => {
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
  assert.ok(res.out.length <= 10, `${res.out.length} lines:\n${text}`);
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
  assert.ok(res.out.length <= 10, res.out.join('\n'));
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
      { platform: 'linux', claudeSettingsPath: settings },
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
