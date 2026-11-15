/** PostToolUse transport: skip / fire-and-forget / synchronous.
 *
 *  These run against a real loopback server instead of a mocked fetch, because
 *  the whole claim of the fast path is about the socket: the hub must receive
 *  the *complete* request even though this process stops caring about the
 *  answer. Only a real server can show that. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { type TestContext } from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { runHook } from './hook.ts';
import { inboxState } from './hook-inbox.ts';

interface Stub {
  port: string;
  /** Bodies the server finished reading, in order. */
  seen: string[];
  close: () => Promise<void>;
}

/** `delayMs` is how long the server sits on the response AFTER reading the
 *  whole request body — i.e. exactly the wait the fast path must not pay. */
async function stubHub(delayMs: number, body = ''): Promise<Stub> {
  const seen: string[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push(Buffer.concat(chunks).toString('utf8'));
      const send = (): void => {
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(body);
      };
      if (delayMs === 0) send();
      else setTimeout(send, delayMs).unref();
    });
    // The client is expected to walk away mid-response: that must not throw.
    req.on('error', () => undefined);
    res.on('error', () => undefined);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? String(addr.port) : '0';
  return {
    port,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

/** `markers: null` = no `inbox-pending` directory at all (an older hub). */
async function ledger(t: TestContext, markers: string[] | null): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-hook-send-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, '.hub'), { recursive: true });
  await writeFile(join(dir, '.hub', 'token'), 'x'.repeat(43), { mode: 0o600 });
  if (markers !== null) {
    const pending = join(dir, '.hub', 'inbox-pending');
    await mkdir(pending, { mode: 0o700, recursive: true });
    for (const m of markers) await writeFile(join(pending, m), '', { mode: 0o600 });
  }
  return dir;
}

const SESSION = 'ses-0001';

function payload(tool: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    session_id: SESSION,
    cwd: '/tmp',
    tool_name: tool,
    tool_input: { file_path: '/tmp/x.ts', ...extra },
  });
}

async function call(
  event: string,
  stdin: string,
  env: NodeJS.ProcessEnv,
): Promise<{ code: number; out: string[]; ms: number }> {
  const out: string[] = [];
  const started = Date.now();
  const code = await runHook(event, { out: (l) => out.push(l), env, stdin: async () => stdin });
  return { code, out, ms: Date.now() - started };
}

/** Give a fire-and-forget request the few ms it needs to land server-side. */
async function waitForSeen(stub: Stub, n: number): Promise<void> {
  for (let i = 0; i < 200 && stub.seen.length < n; i += 1) {
    await new Promise((r) => setTimeout(r, 10).unref());
  }
}

test('inboxState: three states and refusal of a symlink (marker contract)', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const withDir = await ledger(t, [SESSION]);
  assert.equal(await inboxState(withDir, SESSION), 'pending');
  assert.equal(await inboxState(withDir, 'ses-other'), 'empty');
  // Invalid session id is never turned into a path lookup.
  assert.equal(await inboxState(withDir, '../token'), 'unknown');
  assert.equal(await inboxState(withDir, ''), 'unknown');
  assert.equal(await inboxState(withDir, undefined), 'unknown');

  const old = await ledger(t, null);
  assert.equal(await inboxState(old, SESSION), 'unknown', 'older hub → unknown');

  // A symlink where the marker should be: not followed, not trusted.
  const linked = await ledger(t, []);
  await symlink(join(linked, '.hub', 'token'), join(linked, '.hub', 'inbox-pending', 'ses-link'));
  assert.equal(await inboxState(linked, 'ses-link'), 'unknown');
});

test('post-tool-use Edit: fire-and-forget — does not wait for the answer, the hub gets the whole body', async (t) => {
  const stub = await stubHub(2_000, 'ODPOVED');
  t.after(() => stub.close());
  const dir = await ledger(t, []); // directory present, no marker for us
  const body = payload('Edit');

  const res = await call('post-tool-use', body, {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: stub.port,
  } as NodeJS.ProcessEnv);

  assert.equal(res.code, 0);
  assert.deepEqual(res.out, [], 'the answer is not read, nothing is printed');
  assert.ok(res.ms < 1_000, `did not wait for the slow answer, took ${res.ms} ms`);
  await waitForSeen(stub, 1);
  assert.equal(stub.seen.length, 1, 'request dorazil');
  assert.deepEqual(JSON.parse(stub.seen[0] ?? 'null'), JSON.parse(body), 'the body is whole and unchanged');
});

test('post-tool-use Edit: a large body arrives whole even without waiting', async (t) => {
  const stub = await stubHub(1_500);
  t.after(() => stub.close());
  const dir = await ledger(t, []);
  // A Write payload carries the file contents: ~300 kB is well past one TCP
  // segment and past Node's internal buffer, so this exercises the real flush.
  const body = payload('Write', { content: 'ü'.repeat(150_000) });

  const res = await call('post-tool-use', body, {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: stub.port,
  } as NodeJS.ProcessEnv);

  assert.equal(res.code, 0);
  await waitForSeen(stub, 1);
  assert.equal(stub.seen[0]?.length, body.length, 'no truncated bytes');
  assert.equal(stub.seen[0] === body, true, 'the body is identical byte for byte');
});

test('post-tool-use: inbox marker → synchronous path, the message is printed', async (t) => {
  const stub = await stubHub(0, 'INBOX: reply from the web\n');
  t.after(() => stub.close());
  const dir = await ledger(t, [SESSION]);

  const res = await call('post-tool-use', payload('Edit'), {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: stub.port,
  } as NodeJS.ProcessEnv);

  assert.equal(res.code, 0);
  assert.deepEqual(res.out, ['INBOX: reply from the web']);
  assert.equal(stub.seen.length, 1);
});

test('post-tool-use: an older hub without the directory → always synchronous (nothing is lost)', async (t) => {
  const stub = await stubHub(0, 'INBOX: old path\n');
  t.after(() => stub.close());
  const dir = await ledger(t, null);

  const res = await call('post-tool-use', payload('Edit'), {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: stub.port,
  } as NodeJS.ProcessEnv);

  assert.deepEqual(res.out, ['INBOX: old path'], 'the answer is still read');
  assert.equal(stub.seen.length, 1);
});

test('post-tool-use Bash: a read-only command is not sent to the hub at all', async (t) => {
  const stub = await stubHub(0, 'NEMALO BY SA VYPISAT');
  t.after(() => stub.close());
  const dir = await ledger(t, []);

  const res = await call(
    'post-tool-use',
    JSON.stringify({
      session_id: SESSION,
      tool_name: 'Bash',
      tool_input: { command: 'git status --short | wc -l' },
    }),
    { LEDGER_DIR: dir, LEDGER_HUB_PORT: stub.port } as NodeJS.ProcessEnv,
  );

  assert.equal(res.code, 0);
  assert.deepEqual(res.out, []);
  await new Promise((r) => setTimeout(r, 50).unref());
  assert.deepEqual(stub.seen, [], 'no HTTP request');
});

test('post-tool-use Bash: a read-only command + a pending message → it is sent after all', async (t) => {
  const stub = await stubHub(0, 'INBOX: message\n');
  t.after(() => stub.close());
  const dir = await ledger(t, [SESSION]);

  const res = await call(
    'post-tool-use',
    JSON.stringify({ session_id: SESSION, tool_name: 'Bash', tool_input: { command: 'ls' } }),
    { LEDGER_DIR: dir, LEDGER_HUB_PORT: stub.port } as NodeJS.ProcessEnv,
  );

  assert.deepEqual(res.out, ['INBOX: message'], 'delivery takes precedence over latency');
  assert.equal(stub.seen.length, 1);
});

test('post-tool-use Bash: a writing command goes to the hub (fire-and-forget)', async (t) => {
  const stub = await stubHub(1_500);
  t.after(() => stub.close());
  const dir = await ledger(t, []);
  const body = JSON.stringify({
    session_id: SESSION,
    tool_name: 'Bash',
    tool_input: { command: 'sed -i "" s/a/b/ src/x.ts' },
  });

  const res = await call('post-tool-use', body, {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: stub.port,
  } as NodeJS.ProcessEnv);

  assert.ok(res.ms < 1_000, `did not wait, took ${res.ms} ms`);
  await waitForSeen(stub, 1);
  assert.deepEqual(JSON.parse(stub.seen[0] ?? 'null'), JSON.parse(body));
});

test('post-tool-use: a tool other than Edit/Bash stays synchronous', async (t) => {
  const stub = await stubHub(0, 'INBOX: read\n');
  t.after(() => stub.close());
  const dir = await ledger(t, []);

  const res = await call(
    'post-tool-use',
    JSON.stringify({ session_id: SESSION, tool_name: 'Read', tool_input: { file_path: '/tmp/a' } }),
    { LEDGER_DIR: dir, LEDGER_HUB_PORT: stub.port } as NodeJS.ProcessEnv,
  );

  assert.deepEqual(res.out, ['INBOX: read']);
});

test('pre-tool-use is unchanged: the guard sees read-only Bash too and waits for the verdict', async (t) => {
  const stub = await stubHub(0, '{"hookSpecificOutput":{"permissionDecision":"deny"}}');
  t.after(() => stub.close());
  const dir = await ledger(t, []);

  const res = await call(
    'pre-tool-use',
    JSON.stringify({ session_id: SESSION, tool_name: 'Bash', tool_input: { command: 'ls' } }),
    { LEDGER_DIR: dir, LEDGER_HUB_PORT: stub.port } as NodeJS.ProcessEnv,
  );

  assert.equal(stub.seen.length, 1, 'PreToolUse always goes to the hub');
  assert.match(res.out[0] ?? '', /permissionDecision/);
});

test('fire-and-forget: hub not running → exit 0, silent', async (t) => {
  const dir = await ledger(t, []);
  const res = await call('post-tool-use', payload('Edit'), {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: '1', // nothing listens on port 1
  } as NodeJS.ProcessEnv);
  assert.equal(res.code, 0);
  assert.deepEqual(res.out, []);
  assert.ok(res.ms < 1_000, `failed fast, took ${res.ms} ms`);
  void t;
});

/**
 * The in-process tests above keep the socket alive simply because the test
 * runner keeps running. The real hook exits immediately after the flush, so the
 * only honest proof is a child process that is already gone by the time the
 * (deliberately slow) hub would have answered.
 */
test('fire-and-forget in a real process: the hook exits before the answer, the body arrives whole', async (t) => {
  const stub = await stubHub(2_000, 'ODPOVED KTORU NIKTO NECITA');
  t.after(() => stub.close());
  const dir = await ledger(t, []);
  const body = payload('Write', { content: 'x'.repeat(200_000) });
  const bin = join(import.meta.dirname, 'bin.ts');

  const started = Date.now();
  const code = await new Promise<number | null>((resolve) => {
    const child = spawn(process.execPath, [bin, 'hook', 'post-tool-use'], {
      env: {
        ...process.env,
        LEDGER_DIR: dir,
        LEDGER_HUB_PORT: stub.port,
        LEDGER_WORKER: '',
        CLAUDE_ENV_FILE: '',
      },
      stdio: ['pipe', 'ignore', 'ignore'],
    });
    child.stdin.end(body);
    child.on('exit', (c) => resolve(c));
  });
  const ms = Date.now() - started;

  assert.equal(code, 0, 'exit 0');
  assert.ok(ms < 1_500, `the process exited before the hub answered (${ms} ms)`);
  await waitForSeen(stub, 1);
  assert.equal(stub.seen[0] === body, true, 'the hub read the whole body even after the process exited');
});

test('LEDGER_WORKER=1: the worker: true marker survives the fire-and-forget path', async (t) => {
  const stub = await stubHub(800);
  t.after(() => stub.close());
  const dir = await ledger(t, []);

  await call('post-tool-use', payload('Edit'), {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: stub.port,
    LEDGER_WORKER: '1',
  } as NodeJS.ProcessEnv);

  await waitForSeen(stub, 1);
  const sent = JSON.parse(stub.seen[0] ?? 'null') as { worker?: unknown };
  assert.equal(sent.worker, true);
});
