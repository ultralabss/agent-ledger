/**
 * Optional features (intrude, web replies, headless) are OFF by default and
 * gated at the HTTP layer: a gated route answers 403 `feature_disabled` after
 * the caller has been authenticated, and behaves as before when the flag is on.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { startTestHub } from '../test-helpers.ts';

type Feature = 'intrude' | 'web_replies' | 'headless';

interface GatedRoute {
  name: string;
  method: string;
  path: string;
  body?: unknown;
  feature: Feature;
}

const GATED: GatedRoute[] = [
  { name: 'list intrudes', method: 'GET', path: '/v1/intrude?session=aaaa1111', feature: 'intrude' },
  {
    name: 'begin intrude',
    method: 'POST',
    path: '/v1/intrude',
    body: { session: 'aaaa1111', repo: 'acme', paths: ['src/**'] },
    feature: 'intrude',
  },
  {
    name: 'commit intrude',
    method: 'POST',
    path: '/v1/intrude/some-lease/commit',
    body: { session: 'aaaa1111', commit: 'abc1234' },
    feature: 'intrude',
  },
  { name: 'end intrude', method: 'DELETE', path: '/v1/intrude/some-lease', body: {}, feature: 'intrude' },
  {
    name: 'post a web reply',
    method: 'POST',
    path: '/v1/items/ACME-1/reply',
    body: { text: 'hello' },
    feature: 'web_replies',
  },
  { name: 'list replies', method: 'GET', path: '/v1/items/ACME-1/replies', feature: 'web_replies' },
  { name: 'process one intake record', method: 'POST', path: '/v1/intake/abc123/process', body: {}, feature: 'headless' },
  { name: 'process pending intake', method: 'POST', path: '/v1/intake/process-pending', body: {}, feature: 'headless' },
  { name: 'groom', method: 'POST', path: '/v1/groom', body: {}, feature: 'headless' },
];

const OFF = { intrude: false, webReplies: false, headless: false } as const;

test('all optional features are 403 feature_disabled when switched off', async (t) => {
  const fx = await startTestHub(OFF);
  t.after(fx.cleanup);
  for (const route of GATED) {
    const res = await fx.api(route.method, route.path, route.body);
    assert.equal(res.status, 403, `${route.name}: ${res.text}`);
    assert.equal(res.json.error, 'feature_disabled', route.name);
    assert.equal(res.json.feature, route.feature, route.name);
    assert.equal(typeof res.json.message, 'string', route.name);
  }
});

test('gating happens after authentication: no token is still 401', async (t) => {
  const fx = await startTestHub(OFF);
  t.after(fx.cleanup);
  for (const route of GATED) {
    const res = await fetch(`${fx.url}${route.path}`, {
      method: route.method,
      headers: { 'content-type': 'application/json' },
      body: route.method === 'GET' ? undefined : JSON.stringify(route.body ?? {}),
    });
    assert.equal(res.status, 401, `${route.name} without a token`);
  }
});

test('each flag gates only its own routes', async (t) => {
  const fx = await startTestHub({ intrude: true, webReplies: false, headless: false });
  t.after(fx.cleanup);
  const enabled = await fx.api('GET', '/v1/intrude?session=aaaa1111');
  assert.equal(enabled.status, 200, enabled.text);
  assert.deepEqual(enabled.json.leases, []);
  const replies = await fx.api('GET', '/v1/items/ACME-1/replies');
  assert.equal(replies.status, 403);
  assert.equal(replies.json.feature, 'web_replies');
  const groom = await fx.api('POST', '/v1/groom', {});
  assert.equal(groom.status, 403);
  assert.equal(groom.json.feature, 'headless');
});

test('web replies on: the routes behave as before (404 for an unknown item, not 403)', async (t) => {
  const fx = await startTestHub({ intrude: false, webReplies: true, headless: false });
  t.after(fx.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'acme', prefix: 'ACME', path: null });
  const item = await fx.api('POST', '/v1/items', { repo: 'acme', title: 'needs an answer' });
  assert.equal(item.status, 201, item.text);
  const id = item.json.item.id as string;

  const list = await fx.api('GET', `/v1/items/${id}/replies`);
  assert.equal(list.status, 200, list.text);
  assert.deepEqual(list.json.replies, []);

  const missing = await fx.api('GET', '/v1/items/ACME-999/replies');
  assert.equal(missing.status, 404, missing.text);
});

test('a worker-mode reply needs the headless flag on top of web replies', async (t) => {
  const fx = await startTestHub({ intrude: false, webReplies: true, headless: false });
  t.after(fx.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'acme', prefix: 'ACME', path: null });
  const item = await fx.api('POST', '/v1/items', { repo: 'acme', title: 'needs an answer' });
  const id = item.json.item.id as string;
  const res = await fx.api('POST', `/v1/items/${id}/reply`, { text: 'go', mode: 'worker' });
  assert.equal(res.status, 403, res.text);
  assert.equal(res.json.error, 'feature_disabled');
  assert.equal(res.json.feature, 'headless');
});

test('intake triage_and_run needs headless and leaves no record behind when refused', async (t) => {
  const fx = await startTestHub({ intrude: false, webReplies: true, headless: false });
  t.after(fx.cleanup);
  const before = fx.hub.ledger.listIntake().length;
  const res = await fx.api('POST', '/v1/intake', {
    text: 'please handle this',
    channel: 'web',
    action: 'triage_and_run',
  });
  assert.equal(res.status, 403, res.text);
  assert.equal(res.json.feature, 'headless');
  assert.equal(fx.hub.ledger.listIntake().length, before, 'a refused request writes nothing');

  // The plain triage action is not headless and keeps working.
  const plain = await fx.api('POST', '/v1/intake', { text: 'just record this', channel: 'web' });
  assert.equal(plain.status, 201, plain.text);
});

test('headless on: the routes reach the runner (503 without a binary, empty intake is fine)', async (t) => {
  const fx = await startTestHub({ intrude: false, webReplies: false, headless: true, claudeBin: null });
  t.after(fx.cleanup);
  const pending = await fx.api('POST', '/v1/intake/process-pending', {});
  assert.equal(pending.status, 200, pending.text);
  assert.equal(pending.json.run.text, 'intake is empty');

  await fx.api('POST', '/v1/repos', { slug: 'acme', prefix: 'ACME', path: null });
  const groom = await fx.api('POST', '/v1/groom', { repo: 'acme' });
  assert.equal(groom.status, 503, groom.text);
  assert.equal(groom.json.error, 'UNAVAILABLE');
});

test('headless off: the runner exists but reports itself as not configured', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const off = await startTestHub({ headless: false, claudeBin: '/usr/bin/true' });
  t.after(off.cleanup);
  const offHealth = await off.api('GET', '/v1/healthz');
  assert.equal(offHealth.status, 200);
  assert.equal(offHealth.json.headless?.configured, false);
  assert.ok(
    off.logs.some((l) => l.includes('headless: disabled')),
    `expected a "headless: disabled" log line, got ${off.logs.join(' | ')}`,
  );

  const on = await startTestHub({ headless: true, claudeBin: '/usr/bin/true' });
  t.after(on.cleanup);
  const onHealth = await on.api('GET', '/v1/healthz');
  assert.equal(onHealth.json.headless?.configured, true);
  assert.equal(
    on.logs.some((l) => l.includes('headless: disabled')),
    false,
  );
});

test('the weekly groom timer is never armed while headless is off', async (t) => {
  // `periodic` is false in the shared fixture, so exercise the real server path.
  const { tempConfig } = await import('../test-helpers.ts');
  const { startHub } = await import('../server.ts');
  const tmp = await tempConfig({ headless: false, groomWeekly: true });
  const logs: string[] = [];
  const hub = await startHub({ config: tmp.config, log: (l) => logs.push(l), watch: false, periodic: true });
  t.after(() => hub.close());
  t.after(tmp.cleanup); // after close: hooks run in registration order; Windows cannot delete an open DB
  assert.ok(logs.some((l) => l.includes('headless: disabled')));
  assert.equal(
    logs.some((l) => l.includes('weekly grooming scheduled')),
    false,
    logs.join(' | '),
  );

  // Positive control: with headless on, the same configuration does arm it.
  const tmpOn = await tempConfig({ headless: true, groomWeekly: true });
  const logsOn: string[] = [];
  const hubOn = await startHub({ config: tmpOn.config, log: (l) => logsOn.push(l), watch: false, periodic: true });
  t.after(() => hubOn.close());
  t.after(tmpOn.cleanup);
  assert.ok(
    logsOn.some((l) => l.includes('weekly grooming scheduled')),
    logsOn.join(' | '),
  );
});
