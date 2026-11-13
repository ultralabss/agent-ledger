/**
 * / audit B4-1 — the owner gate and the reply `author` label must come
 * from the credential the guard ACTUALLY accepted (`authPath`), and the UI
 * cookie must not be derivable from the hub token.
 *
 * Two separate failures were in scope:
 *  (a) routes decided "token caller vs human at the browser" from the mere
 *      PRESENCE of `x-hub-token`. A valid-cookie request that also carried a
 *      junk token header counted as an agent; a token-less request with no
 *      cookie-grade proof counted as a human,
 *  (b) the cookie was `HMAC(token, context)`, so every local holder of the
 *      token (CLI, hook, subagent) could compute it and take the cookie-only
 *      branch of the owner gate.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { newUiSecret, resolveReadPath, resolveWritePath, uiCookieValue, UI_COOKIE_NAME } from '../security/index.ts';
import { makeCommittedRepo, startTestHub } from '../test-helpers.ts';

const TOKEN = 'FoVkq1nP8s1wQ0mQZ9cQ2RmV1cQ0nQpX8dL2kT9sB7c';
const PORT = 4747;

/* ---------------- (b) the token no longer derives the cookie ------------- */

test('cookie is an HMAC of the per-boot uiSecret — the same token with another secret gives another value', () => {
  const a = uiCookieValue({ token: TOKEN, uiSecret: newUiSecret() });
  const b = uiCookieValue({ token: TOKEN, uiSecret: newUiSecret() });
  assert.ok(a !== null && b !== null);
  assert.notEqual(a, b, 'a token holder cannot compute the cookie without uiSecret');
});

test('token rotation still invalidates the cookie (the token fingerprint is in the message)', () => {
  const uiSecret = newUiSecret();
  const before = uiCookieValue({ token: TOKEN, uiSecret });
  const after = uiCookieValue({ token: `${TOKEN.slice(0, -1)}X`, uiSecret });
  assert.notEqual(before, after);
});

test('without a usable uiSecret no cookie is issued (fail closed)', () => {
  assert.equal(uiCookieValue({ token: TOKEN, uiSecret: '' }), null);
  assert.equal(uiCookieValue({ token: TOKEN, uiSecret: 'too-short' }), null);
  // A short/empty token is already refused by the token rules; the cookie side
  // must not become the way around that.
  assert.equal(uiCookieValue({ token: 'short', uiSecret: newUiSecret() }), null);
});

/* ---------------- (a) authPath is the resolved credential ---------------- */

test('resolveReadPath/resolveWritePath return the path that really authorized the request', () => {
  const uiSecret = newUiSecret();
  const cfg = { token: TOKEN, uiSecret, port: PORT };
  const cookie = uiCookieValue(cfg);
  assert.ok(cookie !== null);
  const cookieHeader = `${UI_COOKIE_NAME}=${cookie}`;

  // Token header present but WRONG, cookie valid → `cookie`, never `token`.
  assert.equal(
    resolveReadPath({ tokenHeader: 'nonsense', cookieHeader, secFetchSite: 'same-origin' }, cfg),
    'cookie',
  );
  assert.equal(
    resolveWritePath(
      {
        method: 'POST',
        host: `127.0.0.1:${PORT}`,
        origin: `http://127.0.0.1:${PORT}`,
        tokenHeader: 'nonsense',
        cookieHeader,
        secFetchSite: 'same-origin',
      },
      cfg,
    ),
    'cookie',
  );
  // Real token, no cookie → `token`.
  assert.equal(
    resolveReadPath({ tokenHeader: TOKEN, cookieHeader: undefined }, cfg),
    'token',
  );
  // Cookie without the browser-set Origin is not a write credential at all.
  assert.equal(
    resolveWritePath(
      {
        method: 'POST',
        host: `127.0.0.1:${PORT}`,
        origin: undefined,
        tokenHeader: undefined,
        cookieHeader,
        secFetchSite: 'same-origin',
      },
      cfg,
    ),
    null,
  );
});

/* ---------------- end-to-end: the owner gate and the reply label --------- */

test('a forged x-hub-token header does not turn a web reply into an agent reply', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const cookie = uiCookieValue(fx);
  assert.ok(cookie !== null);

  const repo = await makeCommittedRepo('hub50');
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });
  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: repo.path });
  const created = await fx.api('POST', '/v1/items', { repo: 'app', title: 'Question' });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'aaaa1111' });

  const res = await fetch(`${fx.url}/v1/items/${id}/reply`, {
    method: 'POST',
    headers: {
      // The B4-1 shape: a junk token header alongside a valid cookie. The old
      // code read only "is the header there" and labelled this `agent`.
      'x-hub-token': 'not-the-real-token',
      cookie: `${UI_COOKIE_NAME}=${cookie}`,
      origin: `http://127.0.0.1:${fx.hub.port}`,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ text: 'From the web, unverified identity.' }),
  });
  assert.equal(res.status, 201, await res.clone().text());
  const item = await fx.api('GET', `/v1/items/${id}`);
  const comments = item.json.detail.comments as { author: string }[];
  assert.equal(comments.at(-1)?.author, 'web');
});

test('the owner gate takes the cookie path from the guard, not from header presence', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const cookie = uiCookieValue(fx);
  assert.ok(cookie !== null);

  // Token caller WITHOUT a live session → 403 (unchanged, and the header is
  // now proven, not assumed).
  const viaToken = await fx.api('POST', '/v1/adopt', { session: 'deadbeef', path: '/tmp/nope' });
  assert.equal(viaToken.status, 403, viaToken.text);

  // A caller with NO credential at all must not reach the owner gate by
  // simply omitting the token header — the guard 401s it first.
  const anonymous = await fetch(`${fx.url}/v1/adopt`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ path: '/tmp/nope' }),
  });
  assert.equal(anonymous.status, 401);

  // And a token holder cannot manufacture the cookie: the value derived from
  // the token (the pre-fix formula) is rejected.
  const forged = await fetch(`${fx.url}/v1/adopt`, {
    method: 'POST',
    headers: {
      cookie: `${UI_COOKIE_NAME}=${uiCookieValue({ token: fx.token, uiSecret: fx.token })}`,
      origin: `http://127.0.0.1:${fx.hub.port}`,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ path: '/tmp/nope' }),
  });
  assert.equal(forged.status, 401);
});

test('uiSecret does not leak through any hub response', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  for (const path of ['/v1/healthz', '/v1/repos', '/v1/sessions']) {
    const res = await fx.api('GET', path);
    assert.ok(!res.text.includes(fx.uiSecret), `${path} must not contain uiSecret`);
  }
});
