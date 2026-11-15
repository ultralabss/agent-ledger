import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { hubIdentity } from '@agent-ledger/shared';
import { CliError, HubClient, readEnvConfig, type CliEnvConfig } from './client.ts';

/* S2: LEDGER_HUB_URL must stay http: + loopback — rejected (exit 4) before the
 *  token is ever read, so a hostile URL can never exfiltrate the token. */
test('S2: LEDGER_HUB_URL must be http: and 127.0.0.1/localhost', () => {
  assert.throws(
    () => readEnvConfig({ LEDGER_HUB_URL: 'https://127.0.0.1:4747' }),
    (err: unknown) => err instanceof CliError && err.exitCode === 4,
  );
  assert.throws(
    () => readEnvConfig({ LEDGER_HUB_URL: 'http://evil.example.com:4747' }),
    (err: unknown) => err instanceof CliError && err.exitCode === 4,
  );
  assert.throws(
    () => readEnvConfig({ LEDGER_HUB_URL: 'not a url' }),
    (err: unknown) => err instanceof CliError && err.exitCode === 4,
  );
  assert.doesNotThrow(() => readEnvConfig({ LEDGER_HUB_URL: 'http://127.0.0.1:4747' }));
  assert.doesNotThrow(() => readEnvConfig({ LEDGER_HUB_URL: 'http://localhost:4747' }));
  assert.doesNotThrow(() => readEnvConfig({}));
});

/* ---------------- timeouts and the refused-only retry ---------------- */

async function ledger(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-client-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, '.hub'), { recursive: true });
  await writeFile(join(dir, '.hub', 'token'), 'y'.repeat(43), { mode: 0o600 });
  return dir;
}

function cfgFor(dir: string, port: string): CliEnvConfig {
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    ledgerDir: dir,
    session: null,
    agent: 'test',
  };
}

async function hangingServer(t: { after: (fn: () => unknown) => void }, dir: string) {
  let hits = 0;
  const server = createServer((req, res) => {
    if (req.url === '/v1/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, ...hubIdentity(dir) }));
      return;
    }
    hits += 1;
    req.resume();
    void res; // deliberately never answered
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
  return {
    port: typeof addr === 'object' && addr !== null ? String(addr.port) : '0',
    hits: () => hits,
  };
}

test('a write after a timeout is NOT retried (it may have landed)', async (t) => {
  const dir = await ledger(t);
  const srv = await hangingServer(t, dir);
  const client = new HubClient(cfgFor(dir, srv.port), { requestMs: 300 });
  await assert.rejects(
    () => client.post('/v1/items', { title: 'x' }),
    (err: unknown) => err instanceof CliError && err.exitCode === 3 && err.hubDown,
  );
  // One delivery, full stop: a second POST could create a second item.
  assert.equal(srv.hits(), 1);
});

test('healthz has a shorter timeout than a normal request', async (t) => {
  const dir = await ledger(t);
  const srv = await hangingServer(t, dir);
  // The hanging server answers /v1/healthz, so point at a dead port instead:
  // what is measured here is which budget the path picks, not the server.
  const client = new HubClient(cfgFor(dir, srv.port), { requestMs: 5_000, healthzMs: 200 });
  const started = Date.now();
  await assert.rejects(() => client.get('/v1/hooks/healthz'));
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 1_500, `healthz budget was not used (${elapsed} ms)`);
});

test('refused connection → one retry after the hub comes up', async (t) => {
  const dir = await ledger(t);
  // Grab a port, release it, then bring a server up during the heal poll.
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r));
  const addr = probe.address();
  const port = typeof addr === 'object' && addr !== null ? String(addr.port) : '0';
  await new Promise<void>((r) => probe.close(() => r()));

  let hits = 0;
  const server = createServer((req, res) => {
    // Healthz is the identity/heal poll, not a delivery — counted separately (not at all).
    if (req.url !== '/v1/healthz') hits += 1;
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(req.url === '/v1/healthz' ? JSON.stringify({ ok: true, ...hubIdentity(dir) }) : '{"ok":true}');
  });
  t.after(
    () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  );
  const timer = setTimeout(() => server.listen(Number(port), '127.0.0.1'), 250);
  t.after(() => clearTimeout(timer));

  const client = new HubClient(cfgFor(dir, port), {
    requestMs: 1_000,
    healthzMs: 300,
    healPollTotalMs: 2_000,
    healPollStepMs: 100,
  });
  // The retry logic is under test, not the service manager: no restart attempt from a unit test.
  const prev = process.env.LEDGER_SELFHEAL;
  process.env.LEDGER_SELFHEAL = '0';
  t.after(() => {
    if (prev === undefined) delete process.env.LEDGER_SELFHEAL;
    else process.env.LEDGER_SELFHEAL = prev;
  });

  // First attempt is refused (nothing listening) → heal → poll → one retry.
  const res = await client.post('/v1/items', { title: 'x' });
  assert.equal(res.status, 200);
  assert.equal(hits, 1, 'exactly one delivered write');
});

/* ---------------- optional hub features that are switched off ---------------- */

test('403 feature_disabled maps to a clear "set LEDGER_<FLAG>=1" message', async (t) => {
  const dir = await ledger(t);
  const server = createServer((req, res) => {
    req.resume();
    if (req.url === '/v1/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, ...hubIdentity(dir) }));
      return;
    }
    res.writeHead(403, { 'content-type': 'application/json' });
    const feature = req.url?.includes('headless')
      ? 'headless'
      : req.url?.includes('replies')
        ? 'web_replies'
        : req.url?.includes('recap')
          ? 'recap_guard'
          : 'intrude';
    res.end(JSON.stringify({ error: 'feature_disabled', feature }));
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
  const client = new HubClient(cfgFor(dir, port));
  const cases: [string, string, string][] = [
    ['/v1/intrude', 'intrude', 'LEDGER_INTRUDE'],
    ['/v1/replies', 'web_replies', 'LEDGER_WEB_REPLIES'],
    ['/v1/headless', 'headless', 'LEDGER_HEADLESS'],
    ['/v1/recap', 'recap_guard', 'LEDGER_RECAP_GUARD'],
  ];
  for (const [path, feature, flag] of cases) {
    await assert.rejects(
      () => client.post(path, {}),
      (err: unknown) =>
        err instanceof CliError &&
        err.exitCode === 4 &&
        !err.hubDown &&
        err.message === `${feature} is disabled on this hub (set ${flag}=1 and restart the hub)`,
    );
  }
});

/* ---------------- T12: identity is checked BEFORE the bearer is attached ---------------- */

/** A hub-shaped server that records every request's headers. */
async function recordingServer(
  t: { after: (fn: () => unknown) => void },
  healthz: unknown,
) {
  const seen: { url: string; token: string | undefined; auth: string | undefined }[] = [];
  const server = createServer((req, res) => {
    seen.push({
      url: req.url ?? '',
      token: req.headers['x-hub-token'] as string | undefined,
      auth: req.headers.authorization,
    });
    req.resume();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(req.url === '/v1/healthz' ? JSON.stringify(healthz) : '{"ok":true}');
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
  return { port: typeof addr === 'object' && addr !== null ? String(addr.port) : '0', seen };
}

test('T12: matching platform + ledger → the bearer is sent, after one unauthenticated healthz', async (t) => {
  const dir = await ledger(t);
  const srv = await recordingServer(t, { ok: true, ...hubIdentity(dir) });
  const res = await new HubClient(cfgFor(dir, srv.port)).post('/v1/items', { title: 'x' });
  assert.equal(res.status, 200);
  assert.equal(srv.seen[0]?.url, '/v1/healthz');
  assert.equal(srv.seen[0]?.token, undefined, 'the identity probe carries no token');
  assert.equal(srv.seen[1]?.token, 'y'.repeat(43));
});

test('T12: another platform (WSL vs Windows) → CliError 3, NO bearer ever sent, not spoolable', async (t) => {
  const dir = await ledger(t);
  const mine = hubIdentity(dir);
  const other = mine.platform === 'win32' ? 'wsl' : 'win32';
  const srv = await recordingServer(t, { ok: true, platform: other, ledger_id: mine.ledger_id });
  await assert.rejects(
    () => new HubClient(cfgFor(dir, srv.port)).post('/v1/items', { title: 'x' }),
    (err: unknown) =>
      err instanceof CliError &&
      err.exitCode === 3 &&
      !err.hubDown &&
      /port held by another agent-ledger \(WSL vs Windows\?\)/.test(err.message),
  );
  assert.deepEqual(
    srv.seen.map((r) => r.url),
    ['/v1/healthz'],
    'only the identity probe reached the server',
  );
  for (const r of srv.seen) assert.equal(r.token ?? r.auth, undefined, 'no Authorization / x-hub-token header');
});

test('T12: a different ledger directory is refused the same way', async (t) => {
  const dir = await ledger(t);
  const srv = await recordingServer(t, { ok: true, ...hubIdentity(join(dir, 'elsewhere')) });
  await assert.rejects(
    () => new HubClient(cfgFor(dir, srv.port)).get('/v1/items'),
    (err: unknown) => err instanceof CliError && err.exitCode === 3 && /another agent-ledger/.test(err.message),
  );
  assert.ok(srv.seen.every((r) => r.token === undefined));
});

test('T12: fail-closed when healthz names nothing (older hub / stranger) — no bearer', async (t) => {
  const dir = await ledger(t);
  for (const body of [{ ok: true }, { ok: true, platform: 'linux' }, 'nope', null]) {
    const srv = await recordingServer(t, body);
    await assert.rejects(
      () => new HubClient(cfgFor(dir, srv.port)).get('/v1/items'),
      (err: unknown) => err instanceof CliError && err.exitCode === 3 && !err.hubDown,
    );
    assert.ok(srv.seen.every((r) => r.token === undefined), JSON.stringify(body));
  }
});
