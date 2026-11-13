/** UI login with a one-time code (SPEC §6.5, §13) — HTTP level.
 *
 *  What these tests hold: the token never reaches the URL, the code is one-time,
 *  only `/login` issues the cookie, `next` never redirects to a foreign origin and
 *  failures are rate limited. TTL and memory contents are covered by
 *  `../security/logincode.test.ts` (needs a fake clock).
 */

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { request } from 'node:http';
import { join } from 'node:path';
import test from 'node:test';
import { git } from '../git.ts';
import { UI_COOKIE_NAME, uiCookieValue } from '../security/index.ts';
import { startTestHub } from '../test-helpers.ts';
import { LOGIN_CODE_PATH } from './ui.ts';

interface LoginCodeBody {
  url?: unknown;
  expiresInSeconds?: unknown;
  error?: unknown;
}

async function loginCode(
  fx: { url: string; token: string },
  body?: unknown,
): Promise<{ status: number; json: LoginCodeBody }> {
  const res = await fetch(`${fx.url}/v1/ui/login-code`, {
    method: 'POST',
    headers: { 'x-hub-token': fx.token, 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  return { status: res.status, json: (await res.json()) as LoginCodeBody };
}

function codeOf(url: string): string {
  return new URL(url).searchParams.get('code') ?? '';
}

/** GET with an arbitrary `Host` header — `fetch` does not allow overriding it. */
function rawGet(
  port: number,
  path: string,
  host: string,
): Promise<{ status: number; cookie: string | undefined }> {
  return new Promise((resolvePromise, reject) => {
    const req = request(
      { host: '127.0.0.1', port, path, method: 'GET', headers: { host } },
      (res) => {
        res.resume();
        res.on('end', () =>
          resolvePromise({
            status: res.statusCode ?? 0,
            cookie: res.headers['set-cookie']?.[0],
          }),
        );
      },
    );
    req.on('error', reject);
    req.end();
  });
}

test('login: code → cookie → 303 to /, the code is one-time', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const issued = await loginCode(fx);
  assert.equal(issued.status, 200);
  const url = issued.json.url as string;
  assert.equal(
    url.startsWith(`http://127.0.0.1:${fx.hub.port}/login?code=`),
    true,
    `unexpected URL: ${url.replace(/code=[^&]*/, 'code=REDACTED')}`,
  );
  assert.match(codeOf(url), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(codeOf(url).includes(fx.token), false, 'the code is not the token');
  assert.equal(issued.json.expiresInSeconds, 60);

  const res = await fetch(url, { redirect: 'manual' });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  const cookie = res.headers.get('set-cookie') ?? '';
  assert.match(cookie, new RegExp(`^${UI_COOKIE_NAME}=`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Max-Age=43200/);
  assert.equal(cookie.includes(fx.token), false, 'the cookie is not the raw token');
  assert.equal(cookie.split('=')[1]?.split(';')[0], uiCookieValue(fx));

  // The cookie authorizes reading…
  const viaCookie = await fetch(`${fx.url}/v1/healthz`, {
    headers: {
      cookie: `${UI_COOKIE_NAME}=${uiCookieValue(fx)}`,
      'sec-fetch-site': 'same-origin',
    },
  });
  const health = (await viaCookie.json()) as { ledger?: string };
  assert.equal(health.ledger, fx.dir, 'the cookie authorizes reading');

  // …and the same code a second time does not (link in history, reload).
  const again = await fetch(url, { redirect: 'manual' });
  assert.equal(again.status, 401);
  assert.equal(again.headers.get('set-cookie'), null);
  assert.match(again.headers.get('content-type') ?? '', /text\/html/);
  assert.match(await again.text(), /ledger open/);
});

test('login: invalid code, HEAD does not consume the code, foreign Host fails', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  for (const bad of ['', 'x', 'a'.repeat(43), encodeURIComponent(fx.token)]) {
    const res = await fetch(`${fx.url}/login?code=${bad}`, { redirect: 'manual' });
    assert.equal(res.status, 401, bad.slice(0, 8));
    assert.equal(res.headers.get('set-cookie'), null, 'a failure never issues a cookie');
    assert.equal(res.headers.get('cache-control'), 'no-store');
  }
  const res = await fetch(`${fx.url}/login`, { redirect: 'manual' });
  assert.equal(res.status, 401, 'missing code');

  // HEAD (prefetch, scanner) must not burn the one-time code.
  const url = (await loginCode(fx)).json.url as string;
  const head = await fetch(url, { method: 'HEAD', redirect: 'manual' });
  assert.equal(head.status, 404);
  assert.equal(head.headers.get('set-cookie'), null);
  const ok = await fetch(url, { redirect: 'manual' });
  assert.equal(ok.status, 303, 'the code is still valid after HEAD');

  // DNS rebinding: `/login` is outside the guard, it checks Host itself. `fetch`
  // does not allow overriding the `Host` header (forbidden header), hence raw `node:http`.
  const rebound = await rawGet(fx.hub.port, `/login?code=${codeOf(url)}`, 'evil.example.com');
  assert.equal(rebound.status, 403);
  assert.equal(rebound.cookie, undefined);
  const loopback = await rawGet(fx.hub.port, `/login?code=${'c'.repeat(43)}`, `localhost:${fx.hub.port}`);
  assert.equal(loopback.status, 401, 'a loopback Host gets through to the code check');
});

test('login: ledger.localhost:<port> signs in, every other .localhost name does not', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const mint = async (): Promise<string> => {
    const res = await fetch(`${fx.url}/v1/ui/login-code`, {
      method: 'POST',
      headers: { 'x-hub-token': fx.token, 'content-type': 'application/json' },
      body: '{}',
    });
    assert.equal(res.status, 200);
    return codeOf(((await res.json()) as { url: string }).url);
  };
  const code = await mint();

  // (A wrong port is not tested here: the test hub has `guard.port === 0`, where
  // `/login` accepts any loopback port by design; `isAllowedHost` covers it.)
  for (const bad of [
    'ledger.localhost',
    'evil.localhost:' + fx.hub.port,
    `ledger.localhost.evil.com:${fx.hub.port}`,
    `xledger.localhost:${fx.hub.port}`,
    `ledger.localhost.:${fx.hub.port}`,
  ]) {
    const res = await rawGet(fx.hub.port, `/login?code=${code}`, bad);
    assert.equal(res.status, 403, bad);
    assert.equal(res.cookie, undefined, bad);
  }

  // The rejected attempts did not burn the code.
  // (Lower case only: the HTTP server itself answers 400 to a Host whose
  // hostname is not already lower case; `isAllowedHost` is case-insensitive anyway.)
  const ok = await rawGet(fx.hub.port, `/login?code=${code}`, `ledger.localhost:${fx.hub.port}`);
  assert.equal(ok.status, 303);
  assert.match(ok.cookie ?? '', /^hub_ui=/);
  assert.equal(/domain\s*=/i.test(ok.cookie ?? ''), false, 'host-only cookie');
});

test('UI cookie from ledger.localhost reads /v1 and writes with a ledger.localhost Origin', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const res = await fetch(`${fx.url}/v1/ui/login-code`, {
    method: 'POST',
    headers: { 'x-hub-token': fx.token, 'content-type': 'application/json' },
    body: '{}',
  });
  const code = codeOf(((await res.json()) as { url: string }).url);
  const host = `ledger.localhost:${fx.hub.port}`;
  const login = await rawGet(fx.hub.port, `/login?code=${code}`, host);
  const cookie = (login.cookie ?? '').split(';')[0] ?? '';
  assert.match(cookie, /^hub_ui=/);

  const send = (method: string, path: string, origin?: string): Promise<number> =>
    new Promise((resolvePromise, reject) => {
      const req = request(
        {
          host: '127.0.0.1',
          port: fx.hub.port,
          path,
          method,
          headers: {
            host,
            cookie,
            'sec-fetch-site': 'same-origin',
            ...(origin ? { origin } : {}),
            ...(method === 'GET' ? {} : { 'content-type': 'application/json' }),
          },
        },
        (r) => {
          r.resume();
          r.on('end', () => resolvePromise(r.statusCode ?? 0));
        },
      );
      req.on('error', reject);
      req.end(method === 'GET' ? undefined : '{}');
    });

  assert.equal(await send('GET', '/v1/repos'), 200, 'cookie read from ledger.localhost');
  // A write: past the auth gates the body is rejected by validation (not 401/403).
  const own = await send('POST', '/v1/items', `http://ledger.localhost:${fx.hub.port}`);
  assert.notEqual(own, 401);
  assert.notEqual(own, 403);
  assert.equal(await send('POST', '/v1/items', 'http://evil.localhost:' + fx.hub.port), 401);
  assert.equal(await send('POST', '/v1/items'), 401, 'no Origin');
});

test('login-code: requires X-Hub-Token, a cookie is not enough', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const anon = await fetch(`${fx.url}/v1/ui/login-code`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(anon.status, 401);

  // Cookie + Origin passes the guard (it is a valid UI session), but issues no code —
  // so an XSS in the UI cannot mint a new, longer-lived login artifact.
  const viaCookie = await fetch(`${fx.url}/v1/ui/login-code`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: `http://127.0.0.1:${fx.hub.port}`,
      cookie: `${UI_COOKIE_NAME}=${uiCookieValue(fx)}`,
    },
    body: '{}',
  });
  assert.equal(viaCookie.status, 401);
  assert.equal((await viaCookie.text()).includes(fx.token), false);

  const badToken = await fetch(`${fx.url}/v1/ui/login-code`, {
    method: 'POST',
    headers: { 'x-hub-token': 'a'.repeat(43), 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(badToken.status, 401);
});

test('login: `next` only a relative path, no open redirect', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const good = await loginCode(fx, { next: '/r/acme' });
  assert.equal(good.status, 200);
  const url = good.json.url as string;
  assert.equal(new URL(url).searchParams.get('next'), '/r/acme');
  const res = await fetch(url, { redirect: 'manual' });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/r/acme');

  for (const bad of [
    '//evil.com',
    '/\\evil.com',
    '/%5cevil.com',
    '/%2f%2fevil.com',
    'https://evil.com',
    'http://127.0.0.1:1/x',
    'javascript:alert(1)',
    'r/x',
    '/r/x\r\nSet-Cookie: a=b',
  ]) {
    const out = await loginCode(fx, { next: bad });
    assert.equal(out.status, 400, bad);
    assert.equal(out.json.error, 'VALIDATION', bad);
  }

  // Even if someone uses the code with a tampered `next` in the URL, the redirect stays home.
  const fresh = (await loginCode(fx)).json.url as string;
  const tampered = await fetch(`${fresh}&next=${encodeURIComponent('//evil.com')}`, {
    redirect: 'manual',
  });
  assert.equal(tampered.status, 303);
  assert.equal(tampered.headers.get('location'), '/', 'invalid next → /');
});

test('login: rate limit 10 failures / min → 429', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  for (let i = 0; i < 10; i += 1) {
    const res = await fetch(`${fx.url}/login?code=${'b'.repeat(43)}`, { redirect: 'manual' });
    assert.equal(res.status, 401, `attempt ${i + 1}`);
  }
  const blocked = await fetch(`${fx.url}/login?code=${'b'.repeat(43)}`, { redirect: 'manual' });
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get('retry-after'), '60');
  assert.equal(blocked.headers.get('set-cookie'), null);
  assert.match(await blocked.text(), /Too many attempts/);

  // A valid code passes even during a block. `/login` has no auth, so
  // a foreign page in the browser can exhaust the limit from outside — if the block ran before
  // code verification, it would lock the user out of the UI.
  const url = (await loginCode(fx)).json.url as string;
  const stillWorks = await fetch(url, { redirect: 'manual' });
  assert.equal(stillWorks.status, 303, 'the block must not lock out login');
  assert.match(stillWorks.headers.get('set-cookie') ?? '', new RegExp(`^${UI_COOKIE_NAME}=`));
  // Success empties the window → the next failure is 401 again, not 429.
  const after = await fetch(`${fx.url}/login?code=${'b'.repeat(43)}`, { redirect: 'manual' });
  assert.equal(after.status, 401);
});

test('login: a duplicate `code` in the URL does not smuggle a second use', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const url = (await loginCode(fx)).json.url as string;
  const code = codeOf(url);
  // Whether Hono takes the first or the last occurrence — the code may pass at most once.
  const smuggle = await fetch(`${fx.url}/login?code=${'d'.repeat(43)}&code=${code}`, {
    redirect: 'manual',
  });
  assert.equal([303, 401].includes(smuggle.status), true, `status ${smuggle.status}`);
  const consumed = smuggle.status === 303;
  assert.equal(
    consumed,
    (smuggle.headers.get('set-cookie') ?? '') !== '',
    'cookie only for a consumed code',
  );
  const replay = await fetch(url, { redirect: 'manual' });
  assert.equal(replay.status, consumed ? 401 : 303, 'the code is valid exactly once');
  const third = await fetch(url, { redirect: 'manual' });
  assert.equal(third.status, 401);
  assert.equal(third.headers.get('set-cookie'), null);
});

test('removed `?token=`: a token in the URL opens nothing any more', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  for (const path of [
    `/?token=${encodeURIComponent(fx.token)}`,
    `/r/acme?token=${encodeURIComponent(fx.token)}`,
    `/index.html?token=${encodeURIComponent(fx.token)}`,
  ]) {
    const res = await fetch(`${fx.url}${path}`, { redirect: 'manual' });
    assert.equal(res.status, 200, path);
    assert.equal(res.headers.get('set-cookie'), null, `${path}: no cookie from a URL token`);
    assert.equal(res.headers.get('location'), null, `${path}: no bootstrap redirect`);
  }

  // A valid `X-Hub-Token` on HTML does not issue a cookie either — only `/login` does.
  for (const path of ['/', '/r/acme', '/v1/repos']) {
    const res = await fetch(`${fx.url}${path}`, { headers: { 'x-hub-token': fx.token } });
    assert.equal(res.headers.get('set-cookie'), null, `${path}: cookie only from /login`);
  }
});

/* ---------- UI login audit: token rotation invalidates codes and cookies ---------- */

test('token rotation: an unconsumed code burns and `uiHandler` takes the new token', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  // A code issued against the old token.
  const issued = await fetch(`${fx.url}${LOGIN_CODE_PATH}`, {
    method: 'POST',
    headers: { 'x-hub-token': fx.token, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(issued.status, 200);
  const url = ((await issued.json()) as { url: string }).url;
  const oldToken = fx.token;

  // Force a real rotation through the same path as production: `.hub/token`
  // tracked by git → lockdown → `setTokenLeakHandler` (server.ts) rotates the token
  // and flushes the login codes.
  await fx.hub.ledger.git.flush();
  await git(fx.dir, ['add', '-f', '.hub/token']);
  assert.equal((await git(fx.dir, ['commit', '-m', 'oops: tracked token'])).code, 0);
  fx.hub.ledger.git.touch('ordinary change');
  await fx.hub.ledger.git.flush();

  const newToken = (await readFile(join(fx.dir, '.hub', 'token'), 'utf8')).trim();
  assert.notEqual(newToken, oldToken, 'the token was really rotated');

  // 1) A code issued before the rotation no longer gets a cookie.
  const redeem = await fetch(url, { redirect: 'manual' });
  assert.equal(redeem.status, 401, 'a code from the old-token era is dead');
  assert.equal(redeem.headers.get('set-cookie'), null);

  // 2) The old token no longer authorizes, the new one does — `uiHandler` and the guard read the live
  //    value, not a copy from the time the app was created.
  assert.equal(
    (await fetch(`${fx.url}/v1/repos`, { headers: { 'x-hub-token': oldToken } })).status,
    401,
  );
  assert.equal(
    (await fetch(`${fx.url}/v1/repos`, { headers: { 'x-hub-token': newToken } })).status,
    200,
  );

  // 3) A new code (against the new token) works and issues a cookie from an HMAC of the new token.
  const again = await fetch(`${fx.url}${LOGIN_CODE_PATH}`, {
    method: 'POST',
    headers: { 'x-hub-token': newToken, 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(again.status, 200);
  const fresh = await fetch(((await again.json()) as { url: string }).url, { redirect: 'manual' });
  assert.equal(fresh.status, 303);
  assert.equal(
    fresh.headers.get('set-cookie')?.split('=')[1]?.split(';')[0],
    uiCookieValue({ token: newToken, uiSecret: fx.uiSecret }),
    'cookie is an HMAC of the per-boot uiSecret over the NEW token',
  );
});
