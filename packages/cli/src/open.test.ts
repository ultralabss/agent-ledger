/** `ledger open` — one-time code, no token in the URL, no shell, no open
 *  redirect. Against a real hub; the browser is never launched in tests. */

import assert from 'node:assert/strict';
import { request } from 'node:http';
import test from 'node:test';
import { startTestHub } from '@agent-ledger/hub/test-helpers';
import { parseArgs } from './args.ts';
import { CliError, HubClient, readEnvConfig, type CliEnvConfig } from './client.ts';
import type { Io } from './index.ts';
import { cmdOpen, safeUiPath } from './open.ts';

function io(): Io & { lines: string[]; errs: string[] } {
  const lines: string[] = [];
  const errs: string[] = [];
  return {
    lines,
    errs,
    out: (l) => lines.push(l),
    err: (l) => errs.push(l),
    env: {},
    cwd: process.cwd(),
  };
}

/** GET `url` the way a browser on that URL would: the socket goes to the local
 *  hub, the `Host` header is the URL's authority. */
function getAs(url: string): Promise<{ status: number; headers: Record<string, string[] | string | undefined> & { 'set-cookie'?: string[]; location?: string } }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = request(
      { host: '127.0.0.1', port: Number(u.port), path: `${u.pathname}${u.search}`, headers: { host: u.host } },
      (res) => {
        res.resume();
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

function setup(fx: { url: string; dir: string }): { client: HubClient; cfg: CliEnvConfig } {
  const cfg = readEnvConfig({ LEDGER_HUB_URL: fx.url, LEDGER_DIR: fx.dir });
  return { client: new HubClient(cfg), cfg };
}

test('ledger open --print: URL with a one-time code, without the token', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const { client, cfg } = setup(fx);
  const o = io();

  assert.equal(await cmdOpen(parseArgs(['open', '--print']), client, cfg, o), 0);
  const url = o.lines[0] ?? '';
  assert.equal(url.startsWith(`http://ledger.localhost:${fx.hub.port}/login?code=`), true);
  assert.equal(url.includes(fx.token), false, 'token never in the URL');
  const code = new URL(url).searchParams.get('code') ?? '';
  assert.match(code, /^[A-Za-z0-9_-]{43}$/);

  // The code really signs in — and not a second time. The socket goes to
  // 127.0.0.1 (the test must not depend on the machine's `*.localhost`
  // resolver); the `Host` is the one the browser would send.
  const first = await getAs(url);
  assert.equal(first.status, 303);
  const cookie = first.headers['set-cookie']?.[0] ?? '';
  assert.match(cookie, /^hub_ui=/);
  assert.equal(/domain=/i.test(cookie), false, 'host-only cookie: no Domain attribute');
  const second = await getAs(url);
  assert.equal(second.status, 401);
});

test('ledger open /r/slug: the path goes as next, the browser gets an argument array', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const { client, cfg } = setup(fx);
  const o = io();
  const launched: string[] = [];

  assert.equal(
    await cmdOpen(parseArgs(['open', '/r/acme']), client, cfg, o, {
      launch: async (url) => {
        launched.push(url);
      },
    }),
    0,
  );
  assert.equal(launched.length, 1);
  const url = launched[0] ?? '';
  assert.equal(new URL(url).searchParams.get('next'), '/r/acme');
  const res = await getAs(url);
  assert.equal(res.status, 303);
  assert.equal(res.headers.location, '/r/acme');
  // Without `--print` the code is printed nowhere.
  assert.equal(o.lines.join('\n').includes(new URL(url).searchParams.get('code') ?? 'x'), false);
  assert.match(o.lines[0] ?? '', /opened in the browser/);
});

test('ledger open: an unsafe path ends with exit 4 and the hub issues nothing', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const { client, cfg } = setup(fx);
  const launched: string[] = [];
  const launch = async (url: string): Promise<void> => {
    launched.push(url);
  };

  for (const bad of [
    '//evil.com',
    '/\\evil.com',
    '/%5cevil.com',
    '/%2f%2fevil.com',
    'https://evil.com',
    'javascript:alert(1)',
    'r/acme',
    '/r/x\nSet-Cookie: a=b',
  ]) {
    const err = await cmdOpen(parseArgs(['open', bad]), client, cfg, io(), { launch }).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof CliError, bad);
    assert.equal(err.exitCode, 4, bad);
  }
  assert.deepEqual(launched, [], 'the browser was never launched');
});

const FAKE_CFG = readEnvConfig({ LEDGER_HUB_URL: 'http://127.0.0.1:4747' });

test('ledger open: a hub outside loopback / another port / without a code is not opened', async () => {
  const launched: string[] = [];
  const launch = async (url: string): Promise<void> => {
    launched.push(url);
  };
  const fake = (url: unknown): HubClient =>
    ({ post: async () => ({ status: 200, json: { url }, text: '' }) }) as unknown as HubClient;

  for (const url of [
    'https://evil.com/login?code=x',
    'http://evil.com/login?code=x',
    'http://127.0.0.1:4747/pwn?code=x',
    'http://127.0.0.1:4747/login',
    'http://127.0.0.1:4848/login?code=x',
    'http://localhost:9999/login?code=x',
    'http://evil.localhost:4747/login?code=x',
    'http://ledger.localhost.evil.com:4747/login?code=x',
    'http://xledger.localhost:4747/login?code=x',
    'http://ledger.localhost:4848/login?code=x',
    'http://ledger.localhost:4747/pwn?code=x',
    'file:///etc/passwd',
    'javascript:alert(1)',
    '',
    null,
    42,
  ]) {
    const err = await cmdOpen(parseArgs(['open']), fake(url), FAKE_CFG, io(), { launch }).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof CliError, String(url));
    assert.equal(err.exitCode, 4, String(url));
  }
  assert.deepEqual(launched, []);
});

test('ledger open: every loopback spelling the hub may return opens on ledger.localhost', async () => {
  for (const url of [
    'http://127.0.0.1:4747/login?code=abc',
    'http://localhost:4747/login?code=abc',
    'http://ledger.localhost:4747/login?code=abc',
    'http://LEDGER.localhost:4747/login?code=abc',
  ]) {
    const launched: string[] = [];
    const fake = { post: async () => ({ status: 200, json: { url }, text: '' }) } as unknown as HubClient;
    await cmdOpen(parseArgs(['open']), fake, FAKE_CFG, io(), {
      launch: async (u) => {
        launched.push(u);
      },
    });
    assert.deepEqual(launched, ['http://ledger.localhost:4747/login?code=abc'], url);
  }
});

test('safeUiPath: only a relative path on the hub origin passes', () => {
  for (const ok of ['/', '/r/acme', '/i/ACME-12', '/timeline?since=7d', '/s/61e0b33d#log']) {
    assert.equal(safeUiPath(ok), ok, ok);
  }
  for (const bad of ['//evil', '/\\evil', '/%2f%2fevil', 'https://evil', 'x', '', '/a b', '/%zz']) {
    assert.equal(safeUiPath(bad), null, bad);
  }
});
