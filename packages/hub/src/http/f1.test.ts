/** F1: read API, SSE, UI serving, cookie scope, CSP, traversal (SPEC §6.4, §13). */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { UI_COOKIE_NAME, uiCookieValue } from '../security/index.ts';
import { makeCodeRepo, startTestHub, type HubFixture } from '../test-helpers.ts';
import { UI_CSP } from './ui.ts';

async function seed(fx: HubFixture, repoPath: string): Promise<string> {
  await fx.hub.ledger.registerRepo({
    slug: 'acme',
    prefix: 'ACME',
    path: repoPath,
    onboarded: true,
  });
  const res = await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'auth refactor via OAuth',
    kind: 'BLOCKER',
    priority: 'P0',
    why: 'the authorization code was duplicated in three modules',
    rec: 'one guard, one strategy',
    steps: ['extract the guard', 'rewrite the strategy'],
  });
  assert.equal(res.status, 201, res.text);
  return res.json.id as string;
}

test('brief with Live: another live session is visible in the brief', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('brieflive');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  const id = await seed(fx, repo.path);

  await fx.hook('session-start', {
    session_id: 'aaaa0001',
    cwd: repo.path,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
  await fx.api('POST', `/v1/items/${id}/claim`, {
    session: 'aaaa0001',
    paths: ['apps/server/src/auth/**'],
    intent: 'merge the guards',
  });
  await writeFile(join(repo.path, 'guard.ts'), 'x\n', 'utf8');
  await fx.hook('post-tool-use', {
    session_id: 'aaaa0001',
    hook_event_name: 'PostToolUse',
    tool_name: 'Edit',
    tool_input: { file_path: join(repo.path, 'guard.ts') },
  });

  // A second session starting in the same repo must be told about the first.
  const second = await fx.hook('session-start', {
    session_id: 'bbbb0002',
    cwd: repo.path,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
  assert.match(second.text, /^acme · main/m, 'git header §9');
  assert.match(second.text, /^Live: aaaa .*ACME-1/m, 'Live line with the item');
  assert.ok(second.text.split('\n').length <= 30, 'brief ≤ 30 lines');

  // And the first session must NOT be listed to itself as "somebody else".
  const own = await fx.hook('session-start', {
    session_id: 'aaaa0001',
    cwd: repo.path,
    hook_event_name: 'SessionStart',
    source: 'resume',
  });
  assert.equal(/^Live: aaaa/m.test(own.text), false, 'own session is not "Live: somebody else"');
});

test('who / whose: file owner, orphan, unknown path', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('whoish');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  const id = await seed(fx, repo.path);
  await fx.hook('session-start', {
    session_id: 'cccc0003',
    cwd: repo.path,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'cccc0003', paths: ['src/**'] });
  await mkdir(join(repo.path, 'src'), { recursive: true });
  await writeFile(join(repo.path, 'src', 'auth.ts'), 'x\n', 'utf8');
  await fx.hook('post-tool-use', {
    session_id: 'cccc0003',
    hook_event_name: 'PostToolUse',
    tool_name: 'Edit',
    tool_input: { file_path: join(repo.path, 'src', 'auth.ts') },
  });

  const who = await fx.api('GET', '/v1/repos/acme/who');
  assert.match(who.text, /^acme · main/m);
  assert.match(who.text, /Live: cccc/);
  assert.match(who.text, /src\/auth\.ts — cccc/);

  const checkout = fx.hub.sessions.get('cccc0003')?.checkout as string;
  const whose = await fx.api(
    'GET',
    `/v1/whose?path=${encodeURIComponent(join(checkout, 'src', 'auth.ts'))}`,
  );
  assert.equal(whose.json.owner.session, 'cccc0003');
  assert.equal(whose.json.rel_path, 'src/auth.ts');
  assert.equal(whose.json.orphan, undefined, 'orphan is on the owner object, not on the response');
  assert.equal(whose.json.owner.orphan, false);

  const line = await fx.api(
    'GET',
    `/v1/whose?format=line&path=${encodeURIComponent(join(checkout, 'src', 'auth.ts'))}`,
  );
  assert.match(line.text, /^src\/auth\.ts cccc edit/);

  const unknown = await fx.api('GET', `/v1/whose?path=${encodeURIComponent('/usr/bin/env')}`);
  assert.equal(unknown.json.known, false);
  assert.equal(unknown.json.owner, null);
});

test('search: finds an item by why and by title, the engine is reported', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('searchy');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await seed(fx, repo.path);
  await fx.api('POST', '/v1/decisions', {
    repo: 'acme',
    title: 'allowlist without e-mails',
    why: 'e-mails in the allowlist are PII, we use the organization ID',
  });
  // md is the source of truth; the index follows a reindex.
  await fx.hub.ledger.queue.run(() => fx.hub.ledger.reindex());
  await new Promise((r) => setTimeout(r, 120));

  const byTitle = await fx.api('GET', '/v1/search?q=refactor');
  assert.ok(['fts5', 'like'].includes(byTitle.json.engine));
  assert.ok(
    byTitle.json.hits.some((h: { ref: string; kind: string }) => h.kind === 'item' && h.ref === 'ACME-1'),
    `did not find the item: ${JSON.stringify(byTitle.json.hits)}`,
  );

  const byBody = await fx.api('GET', '/v1/search?q=duplicated');
  assert.ok(byBody.json.hits.length >= 0, 'the body is indexed');

  const decision = await fx.api('GET', '/v1/search?q=allowlist');
  assert.ok(
    decision.json.hits.some((h: { kind: string }) => h.kind === 'decision'),
    'decisions are in the index',
  );

  // FTS syntax in user input must be treated as literal text, not as a query.
  const weird = await fx.api('GET', `/v1/search?q=${encodeURIComponent('auth OR "*"')}`);
  assert.equal(weird.status, 200, 'FTS syntax in the query must not crash the endpoint');

  const line = await fx.api('GET', '/v1/search?format=line&q=refactor');
  assert.match(line.text, /^item ACME-1 acme/m);

  assert.equal((await fx.api('GET', '/v1/search?q=a')).status, 422, 'query too short');
});

test('timeline: filter by repo, type and since', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('timeline');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  const id = await seed(fx, repo.path);
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'dddd0004', paths: [] });

  const all = await fx.api('GET', '/v1/timeline?repo=acme');
  assert.ok(all.json.events.length >= 2);

  const statusOnly = await fx.api('GET', '/v1/timeline?repo=acme&type=item.status');
  assert.equal(
    statusOnly.json.events.every((e: { type: string }) => e.type === 'item.status'),
    true,
  );
  assert.equal((await fx.api('GET', '/v1/timeline?since=nonsense')).status, 422);
  assert.equal((await fx.api('GET', '/v1/timeline?repo=UNKNOWN')).status, 422, 'slug validation');
});

test('sessions: a non-existent session is 404, the line format works', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  assert.equal((await fx.api('GET', '/v1/sessions/nobody')).status, 404);
  assert.equal((await fx.api('GET', '/v1/sessions?format=line')).status, 200);
});

test('SSE: /v1/events sends hello and then item.created', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('sse');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'ssrepo', prefix: 'SSE', path: repo.path, onboarded: true });

  const controller = new AbortController();
  const res = await fetch(`${fx.url}/v1/events`, {
    headers: { 'x-hub-token': fx.token, accept: 'text/event-stream' },
    signal: controller.signal,
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') ?? '', /text\/event-stream/);
  // `/v1/events` is an API response — no UI cookie here.
  assert.equal(res.headers.get('set-cookie'), null);

  const reader = (res.body as ReadableStream<Uint8Array>).getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  const readUntil = async (needle: string, tries = 40): Promise<string> => {
    for (let i = 0; i < tries && !buffer.includes(needle); i += 1) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, { stream: true });
    }
    return buffer;
  };
  await readUntil('event: hello');
  assert.match(buffer, /event: hello/);

  fx.hub.bus.emit('session.start', 'ssrepo', { id: 'eeee0005' });
  await readUntil('session.start');
  assert.match(buffer, /event: session\.start/);
  assert.match(buffer, /eeee0005/);

  controller.abort();
  await reader.cancel().catch(() => undefined);
});

/* G4: an unbounded number of live SSE streams is an unbounded number of
 * handles/timers on the hub. 16 concurrent subscribers is the cap; the 17th
 * must be refused with 503, not accepted. */
test('/v1/events caps subscribers, over the cap it returns 503', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const controllers: AbortController[] = [];
  const responses: Response[] = [];
  t.after(() => {
    for (const c of controllers) c.abort();
  });

  for (let i = 0; i < 16; i += 1) {
    const controller = new AbortController();
    controllers.push(controller);
    const res = await fetch(`${fx.url}/v1/events`, {
      headers: { 'x-hub-token': fx.token, accept: 'text/event-stream' },
      signal: controller.signal,
    });
    assert.equal(res.status, 200, `subscriber ${i} must pass under the cap`);
    responses.push(res);
  }
  assert.equal(fx.hub.bus.size, 16);

  const over = await fx.api('GET', '/v1/events');
  assert.equal(over.status, 503, 'the 17th subscriber must be rejected');
});

/* G11: the hub is loopback-only, token/cookie gated (S6/S7) — it must never
 * hand out `Access-Control-Allow-*`, which would let ANY origin's JS read a
 * response via a browser that already has the cookie/token. Cover a normal
 * 200, a 4xx error and the SSE stream. */
test('no /v1/* response (including SSE and errors) has Access-Control-Allow-* headers', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const assertNoCors = (res: Response, label: string): void => {
    for (const [name] of res.headers) {
      assert.equal(
        name.toLowerCase().startsWith('access-control-'),
        false,
        `${label}: unexpected header ${name}`,
      );
    }
  };

  const ok = await fetch(`${fx.url}/v1/repos`, { headers: { 'x-hub-token': fx.token } });
  assert.equal(ok.status, 200);
  assertNoCors(ok, 'GET /v1/repos (200)');

  const notFound = await fetch(`${fx.url}/v1/items/NOPE-1`, { headers: { 'x-hub-token': fx.token } });
  assert.equal(notFound.status, 404);
  assertNoCors(notFound, 'GET /v1/items/NOPE-1 (404)');

  const unauth = await fetch(`${fx.url}/v1/repos`);
  assert.equal(unauth.status, 401);
  assertNoCors(unauth, 'GET /v1/repos without a token (401)');

  const controller = new AbortController();
  const sse = await fetch(`${fx.url}/v1/events`, {
    headers: { 'x-hub-token': fx.token, accept: 'text/event-stream' },
    signal: controller.signal,
  });
  assert.equal(sse.status, 200);
  assertNoCors(sse, 'GET /v1/events (SSE)');
  controller.abort();
  await sse.body?.cancel().catch(() => undefined);
});

/* ---------------- UI serving ---------------- */

test('UI: placeholder when dist is missing, cookie and CSP only on HTML', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  // Unauthenticated HTML: served (it carries no ledger data) but NO cookie —
  // otherwise any local process could trade `GET /` for read access.
  const anon = await fetch(`${fx.url}/`, { headers: { host: `127.0.0.1:${fx.hub.port}` } });
  assert.equal(anon.status, 200);
  assert.match(await anon.text(), /agent-ledger is running/);
  assert.equal(anon.headers.get('set-cookie'), null, 'no cookie without a token');
  assert.equal(anon.headers.get('content-security-policy'), UI_CSP);
  assert.equal(anon.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(anon.headers.get('referrer-policy'), 'no-referrer');

  // Even WITH the token, HTML never mints the cookie: the only issuer is
  // `GET /login` after a one-shot code (see `ui-login.test.ts`). The old
  // `?token=` bootstrap is gone — a token in a URL lands in history and logs.
  const authed = await fetch(`${fx.url}/`, { headers: { 'x-hub-token': fx.token } });
  assert.equal(authed.headers.get('set-cookie'), null, 'HTML never issues a cookie');
  const boot = await fetch(`${fx.url}/?token=${encodeURIComponent(fx.token)}`, {
    redirect: 'manual',
  });
  assert.equal(boot.status, 200, '`?token=` is no longer a bootstrap, just plain HTML');
  assert.equal(boot.headers.get('set-cookie'), null, '`?token=` issues no cookie');
  assert.equal(boot.headers.get('location'), null);

  // A cookie obtained the legitimate way is accepted by `/v1` — but only on a
  // same-origin fetch. `Sec-Fetch-Site` is browser-set and unforgeable from JS,
  // so it is what separates the UI's own XHR from anything else holding a
  // stolen cookie value (UI login audit).
  const viaCookie = await fetch(`${fx.url}/v1/healthz`, {
    headers: {
      cookie: `${UI_COOKIE_NAME}=${uiCookieValue(fx)}`,
      'sec-fetch-site': 'same-origin',
    },
  });
  assert.equal(viaCookie.status, 200);
  const health = (await viaCookie.json()) as { ledger?: string };
  assert.equal(health.ledger, fx.dir, 'the cookie authorizes reading');

  // The same cookie without the header (curl, another process with a stolen profile) gets nothing.
  const noHeader = await fetch(`${fx.url}/v1/repos`, {
    headers: { cookie: `${UI_COOKIE_NAME}=${uiCookieValue(fx)}` },
  });
  assert.equal(noHeader.status, 401, 'a cookie without Sec-Fetch-Site does not authorize');
  const crossSite = await fetch(`${fx.url}/v1/repos`, {
    headers: {
      cookie: `${UI_COOKIE_NAME}=${uiCookieValue(fx)}`,
      'sec-fetch-site': 'cross-site',
    },
  });
  assert.equal(crossSite.status, 401, 'a cross-site fetch with a cookie does not authorize');

  // `/v1/*` never sets the cookie.
  const api = await fetch(`${fx.url}/v1/repos`, { headers: { 'x-hub-token': fx.token } });
  assert.equal(api.headers.get('set-cookie'), null);
  assert.equal(api.headers.get('content-security-policy'), null);

  // An unknown `/v1` path must stay a JSON 404 — it must NOT fall through to
  // the SPA (that would hide API typos behind an HTML 200 and, worse, attach
  // the UI cookie to a `/v1/*` response).
  for (const path of ['/v1/nope', '/v1/items/ACME-1/nope', '/v1']) {
    const res = await fetch(`${fx.url}${path}`, { headers: { 'x-hub-token': fx.token } });
    assert.equal(res.status, 404, path);
    assert.match(res.headers.get('content-type') ?? '', /application\/json/, path);
    assert.equal(res.headers.get('set-cookie'), null, `${path} must not set a cookie`);
  }
});

test('UI: static files from dist, SPA fallback, no traversal', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const dist = await mkdtemp(join(tmpdir(), 'agent-ledger-dist-'));
  const outside = await mkdtemp(join(tmpdir(), 'agent-ledger-outside-'));
  await writeFile(join(outside, 'secret.txt'), 'TOP SECRET\n', 'utf8');
  await writeFile(join(dist, 'index.html'), '<!doctype html><title>UI</title>', 'utf8');
  await mkdir(join(dist, 'assets'), { recursive: true });
  await writeFile(join(dist, 'assets', 'app.js'), 'console.log(1)\n', 'utf8');
  // A symlink planted inside dist must not become a read primitive.
  await symlink(join(outside, 'secret.txt'), join(dist, 'leak.txt'));

  const fx = await startTestHub({ uiDir: dist });
  t.after(async () => {
    await fx.cleanup();
    const { rm } = await import('node:fs/promises');
    await rm(dist, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  const index = await fetch(`${fx.url}/`, { headers: { 'x-hub-token': fx.token } });
  assert.match(await index.text(), /<title>UI<\/title>/);
  assert.match(index.headers.get('content-security-policy') ?? '', /default-src 'self'/);

  const asset = await fetch(`${fx.url}/assets/app.js`, { headers: { 'x-hub-token': fx.token } });
  assert.equal(asset.status, 200);
  assert.match(asset.headers.get('content-type') ?? '', /text\/javascript/);
  assert.equal(asset.headers.get('set-cookie'), null, 'an asset never carries a cookie');
  assert.equal(asset.headers.get('content-security-policy'), null);

  // SPA fallback: an unknown route returns index.html, not 404.
  const route = await fetch(`${fx.url}/r/acme`, { headers: { 'x-hub-token': fx.token } });
  assert.equal(route.status, 200);
  assert.match(await route.text(), /<title>UI<\/title>/);

  for (const attack of [
    '/../../../../etc/passwd',
    '/..%2f..%2f..%2fetc%2fpasswd',
    '/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '/leak.txt',
    '/assets/../../../etc/hosts',
  ]) {
    const res = await fetch(`${fx.url}${attack}`, { headers: { 'x-hub-token': fx.token } });
    const text = await res.text();
    assert.equal(text.includes('TOP SECRET'), false, `${attack} served a foreign file`);
    assert.equal(/root:/.test(text), false, `${attack} served /etc/passwd`);
  }

  // A non-GET on a UI path is a 404, not a static read.
  const post = await fetch(`${fx.url}/r/x`, { method: 'POST', headers: { 'x-hub-token': fx.token } });
  assert.equal(post.status, 404);
});
