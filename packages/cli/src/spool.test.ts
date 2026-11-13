/**
 * The offline spool, end to end through the real `ledger` binary.
 *
 * The whole point of this feature is what happens when the hub is *not* there,
 * so every test here starts by pointing the CLI at a dead port and only then
 * brings a hub up. Spool dir is always a temp dir (`LEDGER_SPOOL_DIR`) — the real
 * the default spool directory is never touched.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { startTestHub } from '@agent-ledger/hub/test-helpers';
import { computeSpoolHmac } from '@agent-ledger/shared';
import type { CliEnvConfig } from './client.ts';
import { SpoolingClient } from './index.ts';

const BIN = join(import.meta.dirname, 'bin.ts');
/** Nothing listens on port 1 — the reliable "hub is down" address. */
const DEAD_URL = 'http://127.0.0.1:1';

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

function ledger(args: string[], env: NodeJS.ProcessEnv): Promise<Run> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd: tmpdir(),
      env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (code) => resolvePromise({ code: code ?? -1, stdout, stderr }));
  });
}

async function spoolLines(dir: string): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  for (const name of (await readdir(dir).catch(() => [] as string[])).sort()) {
    if (!name.endsWith('.jsonl')) continue;
    const text = await readFile(join(dir, name), 'utf8');
    for (const line of text.split('\n')) {
      if (line.trim() !== '') out.push(JSON.parse(line) as Record<string, unknown>);
    }
  }
  return out;
}

test('writes during an outage go to the spool and are replayed once the hub is up', async (t) => {
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const base = {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_SESSION: 'aaaa1111',
  };
  const down = { ...base, LEDGER_HUB_URL: DEAD_URL };
  const up = { ...base, LEDGER_HUB_URL: fx.url };

  // --- hub down: three writes queue, all exit 0 ---
  const add = await ledger(['add', 'offline task', '--repo', 'ops'], down);
  assert.equal(add.code, 0, add.stderr);
  assert.match(add.stdout, /^QUEUED [0-9a-f]{8} /);
  assert.match(add.stdout, /\bID\b/, 'add without an ID must say so clearly');
  assert.match(add.stdout, /ledger wait/);

  // A second queued write. Note it stays DOWN the whole time: any command that
  // reaches the hub drains the spool first, which would empty it before the
  // assertion below (that drain is tested separately, further down).
  const note = await ledger(['add', 'second offline', '--repo', 'ops'], down);
  assert.equal(note.code, 0, note.stderr);
  assert.match(note.stdout, /^QUEUED /);

  const queued = await spoolLines(spool);
  assert.equal(queued.length, 2, 'two writes in the queue');
  assert.ok(
    queued.every((r) => typeof r['key'] === 'string' && (r['key'] as string).length === 32),
    'every record has a 128-bit key',
  );

  // --- token never reaches the spool ---
  const raw = JSON.stringify(queued);
  assert.ok(!raw.includes(fx.token), 'the token must not reach the spool');
  assert.ok(!/x-hub-token/i.test(raw), 'nor the token header name');

  // --- permissions ---
  const dirStat = await stat(spool);
  assert.equal(dirStat.mode & 0o777, 0o700, 'spool directory 0700');
  const files = (await readdir(spool)).filter((f) => f.endsWith('.jsonl'));
  for (const f of files) {
    assert.equal((await stat(join(spool, f))).mode & 0o777, 0o600, `${f} must be 0600`);
  }

  // --- hub up: the next command drains the spool ---
  const ls = await ledger(['ls', '--repo', 'ops'], up);
  assert.equal(ls.code, 0, ls.stderr);
  assert.match(ls.stderr, /queue flushed — 2 ok, 0 failed/);

  const after = await fx.api('GET', '/v1/items?repo=ops');
  const titles = (after.json.items as { title: string }[]).map((i) => i.title);
  assert.ok(titles.includes('offline task'), `replayed: ${titles.join(' | ')}`);
  assert.ok(titles.includes('second offline'), `replayed: ${titles.join(' | ')}`);
  assert.equal(await spoolLines(spool).then((r) => r.length), 0, 'the spool is empty');
});

test('a double replay does not create a duplicate (Idempotency-Key)', async (t) => {
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const env = {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_SESSION: 'bbbb2222',
    LEDGER_HUB_URL: fx.url,
  };

  // Hand-write a spool record, then replay it twice with the SAME key. The
  // second replay must return the first response, not create a second item.
  // A hand-written record has to carry a valid HMAC (signed with the
  // hub's own token, same as `enqueue` would) or the replay-side integrity
  // check quarantines it into `failed/` instead of sending it.
  const key = 'a'.repeat(32);
  const ts = Date.now();
  const session = 'bbbb2222';
  const method = 'POST';
  const path = '/v1/items';
  const body = { repo: 'ops', title: 'idempotent thing', kind: 'BACKLOG', priority: 'P2' };
  const record = {
    key,
    ts,
    session,
    method,
    path,
    body,
    cmd: 'add idempotent thing',
    hmac: computeSpoolHmac(fx.token, { method, path, body, key, ts, session }),
  };
  await writeFile(join(spool, 'replay.jsonl'), `${JSON.stringify(record)}\n`, { mode: 0o600 });
  const first = await ledger(['ls', '--repo', 'ops'], env);
  assert.equal(first.code, 0, first.stderr);

  await writeFile(join(spool, 'replay.jsonl'), `${JSON.stringify(record)}\n`, { mode: 0o600 });
  const second = await ledger(['ls', '--repo', 'ops'], env);
  assert.equal(second.code, 0, second.stderr);

  const items = await fx.api('GET', '/v1/items?repo=ops');
  const matching = (items.json.items as { title: string }[]).filter(
    (i) => i.title === 'idempotent thing',
  );
  assert.equal(matching.length, 1, 'the same key creates the item exactly once');
});

test('a record the hub rejects (422) goes to failed/', async (t) => {
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const env = {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_HUB_URL: fx.url,
  };
  // `priority: 'P9'` is not a valid enum value → 422, forever. Retrying it would
  // be an infinite loop, so it must be quarantined.
  const record = {
    key: 'b'.repeat(32),
    ts: Date.now(),
    session: null,
    method: 'POST',
    path: '/v1/items',
    body: { repo: 'ops', title: 'invalid', priority: 'P9' },
    cmd: 'add invalid',
  };
  await writeFile(join(spool, 'bad.jsonl'), `${JSON.stringify(record)}\n`, { mode: 0o600 });

  const run = await ledger(['ls', '--repo', 'ops'], env);
  assert.equal(run.code, 0, run.stderr);
  assert.match(run.stderr, /queue flushed — 0 ok, 1 failed/);

  const failed = await readdir(join(spool, 'failed'));
  assert.equal(failed.length, 1, 'one failed file');
  const text = await readFile(join(spool, 'failed', failed[0] as string), 'utf8');
  assert.match(text, /"reason":/, 'the failed record carries a reason');
  assert.equal(await spoolLines(spool).then((r) => r.length), 0, 'removed from the queue');
});

test('a secret does not reach even the spool (exit 5)', async (t) => {
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const secret = await ledger(
    ['add', `deploy with ghp_${'A1bCdEfGhIjKlMnOpQrStUvWxYz01'}`, '--repo', 'ops'],
    { LEDGER_DIR: fx.dir, LEDGER_SPOOL_DIR: spool, LEDGER_HUB_URL: DEAD_URL },
  );
  assert.equal(secret.code, 5, secret.stderr);
  assert.match(secret.stderr, /secret scanner/);
  assert.equal(await spoolLines(spool).then((r) => r.length), 0, 'nothing was written');
});

test('offline ls and show read md, other reads are exit 3', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const created = await ledger(['add', 'thing to read', '--repo', 'ops'], {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_HUB_URL: fx.url,
  });
  const id = /\b(OPS-\d+)\b/.exec(created.stdout)?.[1] as string;
  assert.ok(id);

  const down = { LEDGER_DIR: fx.dir, LEDGER_SPOOL_DIR: spool, LEDGER_HUB_URL: DEAD_URL };

  const ls = await ledger(['ls', '--repo', 'ops'], down);
  assert.equal(ls.code, 0, ls.stderr);
  assert.match(ls.stdout, /^\(offline — from the ledger, no live data\)/);
  assert.match(ls.stdout, /thing to read/);

  const show = await ledger(['show', id], down);
  assert.equal(show.code, 0, show.stderr);
  assert.match(show.stdout, /offline — from the ledger/);
  assert.match(show.stdout, new RegExp(id));

  const brief = await ledger(['brief', 'ops'], down);
  assert.equal(brief.code, 0, brief.stderr);
  assert.match(brief.stdout, /offline — from the ledger/);

  // Live-only: nothing in md to fall back to.
  for (const cmd of [['sessions'], ['who', 'ops'], ['status']]) {
    const run = await ledger(cmd, down);
    assert.equal(run.code, 3, `${cmd.join(' ')} should be exit 3, was ${run.code}: ${run.stderr}`);
  }
});

test('ledger wait exits 3 after the timeout and prints the queue state', async (t) => {
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await ledger(['add', 'waiting', '--repo', 'ops'], {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_HUB_URL: DEAD_URL,
  });

  const wait = await ledger(['wait', '--timeout', '1'], {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_HUB_URL: DEAD_URL,
  });
  assert.equal(wait.code, 3, wait.stderr);
  assert.match(wait.stderr, /hub did not come up within 1 s/);
  assert.match(wait.stderr, /queued 1/);
});

test('ledger wait against a live hub sends the queue and exits 0', async (t) => {
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await ledger(['add', 'to send', '--repo', 'ops'], {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_HUB_URL: DEAD_URL,
  });

  const wait = await ledger(['wait', '--timeout', '30'], {
    LEDGER_DIR: fx.dir,
    LEDGER_SPOOL_DIR: spool,
    LEDGER_HUB_URL: fx.url,
  });
  assert.equal(wait.code, 0, wait.stderr);
  assert.match(wait.stdout, /hub up · sent 1 · failed 0/);
});

test('session-start hook during an outage says writes are being queued', async () => {
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-'));
  const run = await new Promise<Run>((resolvePromise, reject) => {
    const child = spawn(process.execPath, [BIN, 'hook', 'session-start'], {
      cwd: tmpdir(),
      env: {
        PATH: process.env.PATH ?? '',
        HOME: process.env.HOME ?? '',
        LEDGER_DIR: join(spool, 'no-ledger'),
        LEDGER_SPOOL_DIR: spool,
        // Port 1: the hook builds its URL from the port only (S2).
        LEDGER_HUB_PORT: '1',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (code) => resolvePromise({ code: code ?? -1, stdout, stderr: '' }));
    child.stdin.end(JSON.stringify({ session_id: 'cccc3333', cwd: tmpdir() }));
  });
  // Fail-open: still exit 0, but with the warning text.
  assert.equal(run.code, 0);
  assert.match(run.stdout, /AGENT-LEDGER DOWN: ledger writes are queued/);
  assert.match(run.stdout, /ledger wait/);
});

test('a write that merely timed out is spooled with the SAME Idempotency-Key the direct attempt already carried', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const spool = await mkdtemp(join(tmpdir(), 'ledger-spool-timeout-'));

  // A bare server, not the real hub: request 1 never answers inside the
  // client's timeout (so the client must abort and spool it); request 2 (the
  // replay) answers fast. We only care what Idempotency-Key header each one
  // carried.
  const seenKeys: (string | undefined)[] = [];
  let hits = 0;
  const server = createServer((req, res) => {
    hits += 1;
    const n = hits;
    seenKeys.push(req.headers['idempotency-key'] as string | undefined);
    req.on('data', () => {});
    req.on('end', () => {
      if (n === 1) {
        // Deliberately slower than the client's `requestMs` below — the
        // direct attempt must time out and never get this response.
        setTimeout(() => {
          res.writeHead(201, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ item: { id: 'late' } }));
        }, 300);
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ item: { id: 'ok' } }));
    });
  });
  await new Promise<void>((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  t.after(() => new Promise((resolveClose) => server.close(() => resolveClose(undefined))));
  const addr = server.address();
  const port = addr !== null && typeof addr === 'object' ? addr.port : 0;

  const cfg: CliEnvConfig = {
    baseUrl: `http://127.0.0.1:${port}`,
    ledgerDir: fx.dir,
    session: 'a1test',
    agent: 'test',
  };
  const env = { ...process.env, LEDGER_SPOOL_DIR: spool };
  // Test seam: `requestMs: 50` is far below the server's 300 ms delay above,
  // so the direct attempt reliably times out without a 300 ms-plus test.
  const client = new SpoolingClient(cfg, 'add offline task', env, { requestMs: 50 });

  let queuedKey: unknown;
  try {
    await client.request('POST', '/v1/items', { title: 'x' });
    assert.fail('expected the slow direct attempt to be queued, not to succeed');
  } catch (err) {
    assert.equal((err as { name?: string }).name, 'QueuedWrite');
    queuedKey = (err as { record?: { key?: unknown } }).record?.key;
  }

  assert.equal(typeof seenKeys[0], 'string', 'the direct attempt must already carry an Idempotency-Key');
  assert.equal(
    seenKeys[0],
    queuedKey,
    'the spooled record must have the SAME key as the direct attempt — otherwise the replay writes twice',
  );
});
