/** LH-1: the hub binds `::1` on the same port as `127.0.0.1`, fail-closed.
 *
 *  `ledger open` prints `http://ledger.localhost:<port>/login?code=…`; a client
 *  may resolve that name to `::1`. If `[::1]:<port>` were free, another local
 *  account could listen there and receive the one-time code.
 */

import assert from 'node:assert/strict';
import { request } from 'node:http';
import { createServer, type Server } from 'node:net';
import test from 'node:test';
import { startTestHub } from '../test-helpers.ts';

function listen(host: string, port: number): Promise<Server> {
  return new Promise((resolvePromise, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen({ host, port }, () => resolvePromise(s));
  });
}
const closeSrv = (s: Server): Promise<void> => new Promise((r) => s.close(() => r()));

const hasV6 = await listen('::1', 0).then(
  (s) => closeSrv(s).then(() => true),
  () => false,
);
const skip = hasV6 ? false : 'no IPv6 loopback on this machine';

function rawGet(
  host: string,
  port: number,
  path: string,
  hostHeader: string,
): Promise<{ status: number; cookie: string | undefined }> {
  return new Promise((resolvePromise, reject) => {
    const req = request({ host, port, path, method: 'GET', headers: { host: hostHeader } }, (res) => {
      res.resume();
      res.on('end', () =>
        resolvePromise({ status: res.statusCode ?? 0, cookie: res.headers['set-cookie']?.[0] }),
      );
    });
    req.on('error', reject);
    req.end();
  });
}

async function mintCode(fx: { url: string; token: string }): Promise<string> {
  const res = await fetch(`${fx.url}/v1/ui/login-code`, {
    method: 'POST',
    headers: { 'x-hub-token': fx.token, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(res.status, 200);
  return new URL(((await res.json()) as { url: string }).url).searchParams.get('code') ?? '';
}

test('LH-1: hub binds both 127.0.0.1 and ::1 on the same port', { skip }, async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const port = fx.hub.port;
  // Both ports are taken: a second listener on either address fails.
  await assert.rejects(listen('127.0.0.1', port), { code: 'EADDRINUSE' });
  await assert.rejects(listen('::1', port), { code: 'EADDRINUSE' });
});

test('LH-1: a squatter on [::1]:P makes hub start fail, not succeed silently', { skip }, async () => {
  let squat: Server | undefined;
  let port = 0;
  for (let i = 0; i < 10 && !squat; i++) {
    const s = await listen('::1', 0);
    port = (s.address() as { port: number }).port;
    // The v4 side of the same port must be free, or the test proves nothing.
    try {
      await closeSrv(await listen('127.0.0.1', port));
      squat = s;
    } catch {
      await closeSrv(s);
    }
  }
  assert.ok(squat, 'found a port free on v4 and taken on v6');
  try {
    await assert.rejects(startTestHub({ port }), /already in use on ::1/);
  } finally {
    await closeSrv(squat);
  }
  // v4 was released again by the failed start.
  await closeSrv(await listen('127.0.0.1', port));
});

test('LH-1: ledger.localhost over ::1 passes the guard like over IPv4; foreign Host is refused', { skip }, async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const port = fx.hub.port;

  const bad = await rawGet('::1', port, `/login?code=${await mintCode(fx)}`, 'evil.example.com');
  assert.equal(bad.status, 403);
  assert.equal(bad.cookie, undefined);

  // Same outcome over both loopbacks for the allowed name.
  const via6 = await rawGet('::1', port, `/login?code=${await mintCode(fx)}`, `ledger.localhost:${port}`);
  const via4 = await rawGet('127.0.0.1', port, `/login?code=${await mintCode(fx)}`, `ledger.localhost:${port}`);
  assert.equal(via6.status, 303);
  assert.equal(via4.status, 303);
  assert.match(via6.cookie ?? '', /^hub_ui=/);

  // Health over ::1 behaves as over IPv4.
  const h6 = await rawGet('::1', port, '/v1/healthz', `127.0.0.1:${port}`);
  const h4 = await rawGet('127.0.0.1', port, '/v1/healthz', `127.0.0.1:${port}`);
  assert.equal(h6.status, h4.status);
});
