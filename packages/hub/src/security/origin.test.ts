import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  isAllowedHost,
  isAllowedRead,
  isAllowedWrite,
  uiCookie,
  uiCookieValue,
  UI_COOKIE_NAME,
} from './origin.ts';
import type { ReadRequest, WriteRequest } from './origin.ts';

const PORT = 4747;
const TOKEN = 'FoVkq1nP8s1wQ0mQZ9cQ2RmV1cQ0nQpX8dL2kT9sB7c';
/** Per-boot cookie key, separate from the token. */
const UI_SECRET = 'Wc7mT2pL9qR4vX1yB6nK8dF3hJ5sZ0aQeU7iO4rY2wE';
const UI = { token: TOKEN, uiSecret: UI_SECRET };

function req(over: Partial<WriteRequest> = {}): WriteRequest {
  return {
    method: 'POST',
    host: `127.0.0.1:${PORT}`,
    origin: undefined,
    tokenHeader: undefined,
    cookieHeader: undefined,
    // The browser always sends it and JS cannot set it; the cookie path
    // requires it (UI login audit), the token path does not.
    secFetchSite: 'same-origin',
    ...over,
  };
}

const cfg = { token: TOKEN, uiSecret: UI_SECRET, port: PORT };
/** `uiCookieValue` is fail-closed (`null` without a usable configuration); here the
 *  configuration is valid, so the test may insist on a value. */
function cookieOf(over: Partial<typeof UI> = {}): string {
  const v = uiCookieValue({ ...UI, ...over });
  assert.ok(v !== null, 'a valid configuration must yield a value');
  return v;
}

test('isAllowedHost: only loopback with the exact port is allowed', () => {
  for (const ok of ['127.0.0.1:4747', 'localhost:4747', 'LOCALHOST:4747', 'LocalHost:4747']) {
    assert.equal(isAllowedHost(ok, PORT), true, ok);
  }
});

test('isAllowedHost: rejects everything else (DNS rebinding)', () => {
  const bad = [
    undefined,
    '',
    '127.0.0.1',
    'localhost',
    '127.0.0.1:4748',
    'localhost:80',
    'evil.com:4747',
    'localhost.evil.com:4747',
    'localhost.:4747',
    '127.0.0.1.evil.com:4747',
    '[::1]:4747',
    '0.0.0.0:4747',
    '127.0.0.2:4747',
    '127.1:4747',
    '2130706433:4747',
    'user@localhost:4747',
    ' localhost:4747',
    'localhost:4747 ',
    'localhost:4747\r\nX: y',
    'localhost:04747',
    'hub.local:4747',
  ];
  for (const h of bad) assert.equal(isAllowedHost(h, PORT), false, String(h));
});

test('isAllowedHost: a nonsensical port does not pass', () => {
  assert.equal(isAllowedHost('localhost:0', 0), false);
  assert.equal(isAllowedHost('localhost:99999', 99999), false);
});

test('uiCookie: HttpOnly + SameSite=Strict + Path, value != token, no Secure', () => {
  const c = uiCookie(UI, PORT);
  assert.ok(c !== null);
  assert.match(c, /^hub_ui=[A-Za-z0-9_-]{43}; /);
  assert.ok(c.includes('HttpOnly'));
  assert.ok(c.includes('SameSite=Strict'));
  assert.ok(c.includes('Path=/'));
  assert.ok(!c.includes('Secure'), 'http loopback: Secure would make the browser drop the cookie');
  assert.ok(!c.includes(TOKEN), 'the cookie never carries the raw token');
});

test('uiCookie: a different token → different value, the same one → stable', () => {
  assert.equal(cookieOf(), cookieOf());
  assert.notEqual(cookieOf(), cookieOf({ token: `${TOKEN}x` }));
});

test('safe methods pass without a token', () => {
  for (const m of ['GET', 'HEAD', 'OPTIONS', 'get', 'head']) {
    assert.equal(isAllowedWrite(req({ method: m, host: undefined }), cfg), true, m);
  }
});

test('POST with the exact token passes', () => {
  assert.equal(isAllowedWrite(req({ tokenHeader: TOKEN }), cfg), true);
  assert.equal(
    isAllowedWrite(req({ host: `localhost:${PORT}`, tokenHeader: TOKEN }), cfg),
    true,
  );
});

test('POST with a wrong token fails (including prefix, suffix, length)', () => {
  const bad = [
    undefined,
    '',
    TOKEN.slice(0, -1),
    `${TOKEN}x`,
    TOKEN.toUpperCase(),
    ` ${TOKEN}`,
    'A'.repeat(43),
  ];
  for (const t of bad) {
    assert.equal(isAllowedWrite(req({ tokenHeader: t }), cfg), false, String(t));
  }
});

test('POST with a good token but a bad Host fails', () => {
  assert.equal(
    isAllowedWrite(req({ host: 'evil.com:4747', tokenHeader: TOKEN }), cfg),
    false,
  );
  assert.equal(isAllowedWrite(req({ host: undefined, tokenHeader: TOKEN }), cfg), false);
});

test('UI path: correct Origin + cookie passes', () => {
  const cookieHeader = `${UI_COOKIE_NAME}=${cookieOf()}`;
  for (const origin of [`http://127.0.0.1:${PORT}`, `http://localhost:${PORT}`]) {
    assert.equal(isAllowedWrite(req({ origin, cookieHeader }), cfg), true, origin);
  }
  assert.equal(
    isAllowedWrite(
      req({ origin: `http://localhost:${PORT}`, cookieHeader: `other=1; ${cookieHeader}; z=2` }),
      cfg,
    ),
    true,
  );
});

test('UI path: cookie without Origin fails (CSRF)', () => {
  const cookieHeader = `${UI_COOKIE_NAME}=${cookieOf()}`;
  assert.equal(isAllowedWrite(req({ cookieHeader }), cfg), false);
});

test('UI path: foreign or approximate Origin fails', () => {
  const cookieHeader = `${UI_COOKIE_NAME}=${cookieOf()}`;
  const bad = [
    'http://evil.com',
    `http://evil.com:${PORT}`,
    `https://localhost:${PORT}`,
    `http://localhost:${PORT + 1}`,
    `http://localhost:${PORT}/`,
    `http://localhost:${PORT}.evil.com`,
    'null',
    `http://127.0.0.1:${PORT}\u0000`,
    'http://[::1]:4747',
  ];
  for (const origin of bad) {
    assert.equal(isAllowedWrite(req({ origin, cookieHeader }), cfg), false, origin);
  }
});

test('UI path: bad, missing or duplicated cookie fails', () => {
  const origin = `http://localhost:${PORT}`;
  const good = cookieOf();
  const bad = [
    undefined,
    '',
    `${UI_COOKIE_NAME}=`,
    `${UI_COOKIE_NAME}=${good.slice(0, -1)}`,
    `${UI_COOKIE_NAME}=${TOKEN}`,
    `${UI_COOKIE_NAME}=${good}; ${UI_COOKIE_NAME}=nope`,
    'hub_ui2=x',
  ];
  for (const cookieHeader of bad) {
    assert.equal(isAllowedWrite(req({ origin, cookieHeader }), cfg), false, String(cookieHeader));
  }
});

test('raw token as a cookie fails (domain separation)', () => {
  assert.equal(
    isAllowedWrite(
      req({ origin: `http://localhost:${PORT}`, cookieHeader: `${UI_COOKIE_NAME}=${TOKEN}` }),
      cfg,
    ),
    false,
  );
});

test('cookie value as X-Hub-Token fails', () => {
  assert.equal(isAllowedWrite(req({ tokenHeader: cookieOf() }), cfg), false);
});

test('empty / short server token locks writes', () => {
  assert.equal(
    isAllowedWrite(req({ tokenHeader: '' }), { token: '', uiSecret: UI_SECRET, port: PORT }),
    false,
  );
  assert.equal(
    isAllowedWrite(req({ tokenHeader: 'short' }), { token: 'short', uiSecret: UI_SECRET, port: PORT }),
    false,
  );
});

test('unknown method without a token fails', () => {
  for (const m of ['', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']) {
    assert.equal(isAllowedWrite(req({ method: m }), cfg), false, m);
  }
  assert.equal(isAllowedWrite(req({ method: 'DELETE', tokenHeader: TOKEN }), cfg), true);
});

/* ---------- reads require auth ---------- */

function readReq(over: Partial<ReadRequest> = {}): ReadRequest {
  return {
    tokenHeader: undefined,
    cookieHeader: undefined,
    secFetchSite: 'same-origin',
    ...over,
  };
}

test('isAllowedRead: a good token passes without Origin (unlike writes)', () => {
  assert.equal(isAllowedRead(readReq({ tokenHeader: TOKEN }), cfg), true);
});

test('isAllowedRead: without token and without cookie fails', () => {
  assert.equal(isAllowedRead(readReq(), cfg), false);
});

test('isAllowedRead: a bad token fails', () => {
  assert.equal(isAllowedRead(readReq({ tokenHeader: `${TOKEN}x` }), cfg), false);
});

test('isAllowedRead: a valid UI cookie passes even without Origin (same-origin GET does not send it)', () => {
  const cookieHeader = `${UI_COOKIE_NAME}=${cookieOf()}`;
  assert.equal(isAllowedRead(readReq({ cookieHeader }), cfg), true);
});

test('isAllowedRead: an invalid cookie fails', () => {
  assert.equal(isAllowedRead(readReq({ cookieHeader: `${UI_COOKIE_NAME}=nope` }), cfg), false);
});

test('isAllowedRead: an empty/short server token locks reads too', () => {
  assert.equal(isAllowedRead(readReq({ tokenHeader: '' }), { token: '', uiSecret: UI_SECRET }), false);
});

/* ---------- UI login audit: the cookie path requires Sec-Fetch-Site ---------- */

test('cookie path: without `Sec-Fetch-Site: same-origin` neither reads nor writes pass', () => {
  const cookieHeader = `${UI_COOKIE_NAME}=${cookieOf()}`;
  const origin = `http://localhost:${PORT}`;
  // `none` = top-level navigation (address bar) — for /v1/* it is never an
  // XHR, and letting it through would mean a GET from any page.
  for (const secFetchSite of [undefined, '', 'cross-site', 'same-site', 'none', 'x']) {
    assert.equal(
      isAllowedRead(readReq({ cookieHeader, secFetchSite }), cfg),
      false,
      `read ${String(secFetchSite)}`,
    );
    assert.equal(
      isAllowedWrite(req({ origin, cookieHeader, secFetchSite }), cfg),
      false,
      `write ${String(secFetchSite)}`,
    );
  }
  // The exact value (case-insensitive, wrapped in whitespace) passes.
  assert.equal(isAllowedRead(readReq({ cookieHeader, secFetchSite: 'Same-Origin' }), cfg), true);
  assert.equal(isAllowedRead(readReq({ cookieHeader, secFetchSite: ' same-origin ' }), cfg), true);
});

test('token path does not require Sec-Fetch-Site (CLI and hooks are not browsers)', () => {
  assert.equal(isAllowedRead(readReq({ tokenHeader: TOKEN, secFetchSite: undefined }), cfg), true);
  assert.equal(
    isAllowedWrite(req({ tokenHeader: TOKEN, secFetchSite: undefined }), cfg),
    true,
  );
  assert.equal(
    isAllowedWrite(req({ tokenHeader: TOKEN, secFetchSite: 'cross-site' }), cfg),
    true,
    'the token carries authorization by itself',
  );
});
