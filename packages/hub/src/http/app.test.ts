import assert from 'node:assert/strict';
import { request } from 'node:http';
import test from 'node:test';
import { startTestHub } from '../test-helpers.ts';

const GITHUB_TOKEN = `ghp_${'A1bCdEfGhIjKlMnOpQrStUvWxYz01'}`;

function rawGet(
  port: number,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  return new Promise((resolvePromise, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', headers }, (res) => {
      let body = '';
      res.on('data', (d: Buffer) => {
        body += d.toString('utf8');
      });
      res.on('end', () => resolvePromise({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('guard: foreign Host is 403, write without a token is 401', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const evil = await rawGet(fx.hub.port, '/v1/healthz', { Host: 'evil.example.com' });
  assert.equal(evil.status, 403);
  assert.match(evil.body, /FORBIDDEN_HOST/);

  const ok = await rawGet(fx.hub.port, '/v1/healthz', { Host: `127.0.0.1:${fx.hub.port}` });
  assert.equal(ok.status, 200);

  const noToken = await fetch(`${fx.url}/v1/repos`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ slug: 'x', prefix: 'XX', path: null }),
  });
  assert.equal(noToken.status, 401);
  assert.equal(((await noToken.json()) as { error: string }).error, 'UNAUTHORIZED');

  const badToken = await fetch(`${fx.url}/v1/repos`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-hub-token': 'not-the-token' },
    body: JSON.stringify({ slug: 'x', prefix: 'XX', path: null }),
  });
  assert.equal(badToken.status, 401);
});

test('GET without a token is 401 (except healthz), unauthenticated healthz returns only {ok}', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const noTokenGet = await fetch(`${fx.url}/v1/repos`);
  assert.equal(noTokenGet.status, 401);
  assert.equal(((await noTokenGet.json()) as { error: string }).error, 'UNAUTHORIZED');

  const badTokenGet = await fetch(`${fx.url}/v1/items`, {
    headers: { 'x-hub-token': 'not-the-token' },
  });
  assert.equal(badTokenGet.status, 401);

  const anonHealth = await fetch(`${fx.url}/v1/healthz`);
  assert.equal(anonHealth.status, 200);
  const anonBody = (await anonHealth.json()) as Record<string, unknown>;
  assert.deepEqual(Object.keys(anonBody), ['ok']);

  const authedHealth = await fetch(`${fx.url}/v1/healthz`, {
    headers: { 'x-hub-token': fx.token },
  });
  assert.equal(authedHealth.status, 200);
  const authedBody = (await authedHealth.json()) as Record<string, unknown>;
  assert.ok('git' in authedBody && 'port' in authedBody, 'authed healthz carries detail');

  const okGet = await fetch(`${fx.url}/v1/repos`, { headers: { 'x-hub-token': fx.token } });
  assert.equal(okGet.status, 200);
});

test('body over 1 MB is 413 and nothing is stored', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const body = JSON.stringify({ repo: 'ops', title: 'x', why: 'a'.repeat(1024 * 1024 + 1) });
  // The server aborts (and closes the connection) as soon as it has seen
  // more than maxSize bytes, before the client — sending the whole body in
  // one go, not streamed — is done writing. Over loopback that races: either
  // fetch gets the clean 413, or the socket closing under it surfaces as a
  // network error. Both are the same outcome from the security angle: the
  // oversized body was rejected, not parsed, not stored.
  try {
    const res = await fetch(`${fx.url}/v1/items`, {
      method: 'POST',
      headers: { 'x-hub-token': fx.token, 'content-type': 'application/json' },
      body,
    });
    assert.equal(res.status, 413);
  } catch (err) {
    assert.match(String(err), /fetch failed/);
  }
  assert.equal(fx.hub.ledger.listItems().length, 0);
});

test('zod: invalid input is 422 {error,message}', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const res = await fx.api('POST', '/v1/repos', { slug: 'Capital Letters' });
  assert.equal(res.status, 422);
  assert.equal(res.json.error, 'INVALID');
  assert.match(res.json.message, /slug/);

  const bad = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'x', priority: 'P9' });
  assert.equal(bad.status, 422);
  assert.equal(bad.json.error, 'INVALID');
});

test('secret scanner: a secret in item text = 422 SECRET, the value is not echoed back', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  for (const payload of [
    { repo: 'ops', title: `token ${GITHUB_TOKEN}` },
    { repo: 'ops', title: 'ok', why: `use ${GITHUB_TOKEN}` },
    { repo: 'ops', title: 'ok', rec: `export GH=${GITHUB_TOKEN}` },
    { repo: 'ops', title: 'ok', steps: [`curl -H "Authorization: ${GITHUB_TOKEN}"`] },
  ]) {
    const res = await fx.api('POST', '/v1/items', payload);
    assert.equal(res.status, 422, JSON.stringify(payload));
    assert.equal(res.json.error, 'SECRET');
    assert.deepEqual(res.json.findings, [{ rule: 'github-token' }]);
    assert.equal(res.text.includes(GITHUB_TOKEN), false);
  }
  assert.equal(fx.hub.ledger.listItems().length, 0);

  const item = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'clean item' });
  assert.equal(item.status, 201);
  const comment = await fx.api('POST', `/v1/items/${item.json.id}/comments`, {
    text: `the password is ${GITHUB_TOKEN}`,
  });
  assert.equal(comment.status, 422);
  assert.equal(comment.json.error, 'SECRET');
  const decision = await fx.api('POST', '/v1/decisions', {
    repo: 'ops',
    title: 'heading',
    why: `key ${GITHUB_TOKEN}`,
  });
  assert.equal(decision.status, 422);
  const journal = await fx.api('POST', '/v1/journal', { repo: 'ops', text: GITHUB_TOKEN });
  assert.equal(journal.status, 422);
});

test('secrets are scanned in fields outside a hand-kept list too (owner, docs[])', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  // repos.yml docs[] and graphify used not to be scanned at all.
  const repo = await fx.api('POST', '/v1/repos', {
    slug: 'acme',
    prefix: 'ACME',
    path: null,
    docs: [`docs/${GITHUB_TOKEN}.md`],
  });
  assert.equal(repo.status, 422);
  assert.equal(repo.json.error, 'SECRET');
  assert.equal(fx.hub.ledger.repos().acme, undefined);

  // owner/session/agent on an item used to sit outside the hand-kept field list.
  const item = await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'ok',
    owner: `human-${GITHUB_TOKEN}`,
  });
  assert.equal(item.status, 422);
  assert.equal(item.json.error, 'SECRET');
  assert.equal(fx.hub.ledger.listItems().length, 0);
});

/* G5: the hook secret scan (R3) picked its paths from `tool_input.file_path`
 * / `notebook_path` only — a MultiEdit's per-edit `edits[].file_path` (the
 * same shape `editPaths` in hooks.ts already handles for file attribution)
 * was invisible to it, so a secret embedded there sailed through. */
test('hook secret scan sees MultiEdit edits[].file_path, not just file_path', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const res = await fx.api('POST', '/v1/hooks/post-tool-use', {
    session_id: 'gggg0005',
    hook_event_name: 'PostToolUse',
    tool_name: 'MultiEdit',
    tool_input: {
      edits: [{ file_path: `/tmp/${GITHUB_TOKEN}/file.ts`, old_string: 'a', new_string: 'b' }],
    },
  });
  assert.equal(res.status, 422, res.text);
  assert.equal(res.json.error, 'SECRET');
  assert.equal(res.text.includes(GITHUB_TOKEN), false);
});

test('intake: a secret is redacted, not rejected', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const res = await fx.api('POST', '/v1/intake', {
    text: `deploy it with ${GITHUB_TOKEN} and then call`,
    channel: 'chat',
  });
  assert.equal(res.status, 201);
  assert.equal(res.json.redacted, 1);
  assert.equal(res.text.includes(GITHUB_TOKEN), false);

  const stored = fx.hub.ledger.getIntake(res.json.id);
  assert.equal(stored.text.includes(GITHUB_TOKEN), false);
  assert.match(stored.text, /\[REDACTED:github-token\]/);
  assert.equal(stored.status, 'new');
});

test('items: filters, format=line, transitions via the API', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'acme', prefix: 'ACME', path: null });
  const a = await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'P0 for a human',
    kind: 'BLOCKER',
    priority: 'P0',
    owner: 'human',
  });
  await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'P2 for an agent',
    kind: 'BACKLOG',
    priority: 'P2',
  });
  assert.equal(a.json.id, 'ACME-1');

  const line = await fetch(`${fx.url}/v1/items?repo=acme&format=line`, {
    headers: { 'x-hub-token': fx.token },
  });
  const text = await line.text();
  assert.equal(text.trim().split('\n').length, 2);
  assert.match(text, /^ACME-1 open P0 \[BLOCKER\] acme @human · P0 for a human$/m);

  const human = await fx.api('GET', '/v1/items?owner=human&open=1');
  assert.equal(human.json.items.length, 1);

  const claimed = await fx.api('POST', '/v1/items/ACME-1/claim', {
    session: 'abcd1234',
    paths: ['apps/server/**'],
    intent: 'auth refactor',
  });
  assert.equal(claimed.json.item.status, 'doing');
  const badRelease = await fx.api('POST', '/v1/items/ACME-2/release', {});
  assert.equal(badRelease.status, 409);
  assert.equal(badRelease.json.error, 'CONFLICT');

  const step = await fx.api('POST', '/v1/items/ACME-1/steps', { n: 1, done: true });
  assert.equal(step.status, 404);

  const patched = await fx.api('PATCH', '/v1/items/ACME-1', {
    steps: ['first', 'second'],
    why_note: 'plan from triage',
  });
  assert.equal(patched.status, 200);
  const step2 = await fx.api('POST', '/v1/items/ACME-1/steps', { n: 2, done: true });
  assert.equal(step2.json.steps[1].done, true);

  const missing = await fx.api('GET', '/v1/items/ACME-999');
  assert.equal(missing.status, 404);
  assert.equal(missing.json.error, 'NOT_FOUND');
});

test('?repo=__proto__ is rejected (slug format), query goes through itemQuerySchema', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  // `__proto__` is not even a valid slug shape ([a-z0-9-]+) — itemQuerySchema
  // (previously dead code, S8) now rejects it as 422 before the repo lookup
  // is ever reached. The Object.hasOwn fix at `Ledger.repo()` itself — the
  // actual prototype-pollution guard — has its own direct test in
  // ledger.test.ts, independent of this HTTP-level schema check.
  const res = await fx.api('GET', '/v1/items?repo=__proto__');
  assert.equal(res.status, 422);
  assert.equal(res.json.error, 'INVALID');

  const badQuery = await fx.api('GET', '/v1/items?open=maybe');
  assert.equal(badQuery.status, 422);
  assert.equal(badQuery.json.error, 'INVALID');
});

test('brief: ≤ 30 lines, header, needs you, up next, intake, footer', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'acme', prefix: 'ACME', path: null, docs: ['docs/HANDOFF.md'] });
  await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'deploy authorization',
    kind: 'BLOCKER',
    priority: 'P0',
    owner: 'human',
  });
  for (let i = 0; i < 12; i += 1) {
    await fx.api('POST', '/v1/items', {
      repo: 'acme',
      title: `work ${i}`,
      kind: 'BACKLOG',
      priority: 'P1',
    });
  }
  await fx.api('POST', '/v1/intake', { text: 'one more thing', channel: 'web' });
  await fx.api('POST', '/v1/decisions', { repo: 'acme', title: 'Integer cents', why: 'No float rounding' });
  await fx.api('POST', '/v1/items/ACME-2/done', { ref: 'v0.26.0' });

  const res = await fetch(`${fx.url}/v1/brief?repo=acme`, {
    headers: { 'x-hub-token': fx.token },
  });
  const brief = (await res.text()).trimEnd().split('\n');
  assert.ok(brief.length <= 30, `brief has ${brief.length} lines`);
  assert.match(brief[0] ?? '', /^acme · ACME · \d+ open/);
  assert.ok(brief.some((l) => l.startsWith('Context: CONTEXT.md')));
  assert.ok(brief.some((l) => l.startsWith('Needs you (1)')));
  assert.ok(brief.some((l) => l.includes('ACME-1 [BLOCKER] P0 deploy authorization')));
  assert.ok(brief.some((l) => l.startsWith('Up next (')));
  // A record from this moment is triage in progress, not an unprocessed intake —
  // the brief mentions it only after 10 minutes (positive case: ledger.test.ts,
  // "listIntakeUnprocessed").
  assert.ok(
    !brief.some((l) => l.startsWith('Intake:')),
    'a fresh intake record does not nag in the brief',
  );
  assert.equal((await fx.api('GET', '/v1/healthz')).json.intakeNew, 0);
  assert.ok(brief.some((l) => l.startsWith('7 days:')));
  assert.ok(brief.some((l) => l.includes('D1 ')));
  assert.equal(brief.at(-1), 'More: ledger brief --full · ledger history --since 14d');

  const full = await (
    await fetch(`${fx.url}/v1/brief?repo=acme&full=1`, { headers: { 'x-hub-token': fx.token } })
  ).text();
  assert.ok(full.split('\n').length > brief.length);

  const global = await (
    await fetch(`${fx.url}/v1/brief`, { headers: { 'x-hub-token': fx.token } })
  ).text();
  assert.match(global, /^ledger · \d+ rep/);
  assert.match(global, /^ {2}acme: \d+ open/m);
});

test('journal a healthz', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.api('POST', '/v1/journal', {
    repo: 'ops',
    text: 'OAuth tab done\ndeploy waits for authorization',
  });
  const line = await (
    await fetch(`${fx.url}/v1/journal?repo=ops&format=line`, { headers: { 'x-hub-token': fx.token } })
  ).text();
  assert.match(line, /session\.summary · OAuth tab done · deploy waits for authorization/);

  const since = await fx.api('GET', '/v1/journal?repo=ops&since=nonsense');
  assert.equal(since.status, 422);

  const health = await fx.api('GET', '/v1/healthz');
  assert.equal(health.status, 200);
  assert.equal(health.json.ok, true);
  assert.deepEqual(health.json.warnings, []);
  assert.equal(health.json.port, fx.hub.port);
});

test('Idempotency-Key reuse with a different body is 422, not a replay of the first response', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const key = 'a'.repeat(32);
  const post = (body: unknown) =>
    fetch(`${fx.url}/v1/journal`, {
      method: 'POST',
      headers: {
        'x-hub-token': fx.token,
        'content-type': 'application/json',
        'idempotency-key': key,
      },
      body: JSON.stringify(body),
    });

  const first = await post({ repo: 'ops', text: 'first write' });
  assert.equal(first.status, 201, await first.clone().text());

  // Same key, DIFFERENT body: must 422, never replay the first response.
  const second = await post({ repo: 'ops', text: 'a completely different write' });
  assert.equal(second.status, 422);
  const secondJson = (await second.json()) as { error: string };
  assert.equal(secondJson.error, 'IDEMPOTENCY_MISMATCH');

  // Same key, SAME body: this is the legitimate replay case.
  const replay = await post({ repo: 'ops', text: 'first write' });
  assert.equal(replay.status, 201);
  assert.equal(replay.headers.get('idempotent-replay'), 'true');
});
