import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { enqueue } from '@agent-ledger/shared';
import { sweepSpool } from './spool-sweep.ts';

// Regression: the startup sweep replays through in-process `app.fetch`, where
// no network layer sets Host — every replay came back 403 FORBIDDEN_HOST and
// landed in failed/.
test('sweep: replay sends a loopback Host header with the hub port', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-sweep-'));
  const env = { ...process.env, LEDGER_SPOOL_DIR: dir };
  try {
    await enqueue(
      { session: null },
      { method: 'POST', path: '/v1/items/ACME-1/comments', body: { text: 'offline note' }, cmd: 'note' },
      env,
      'test-token',
    );
    const hosts: (string | null)[] = [];
    const result = await sweepSpool({
      fetch: (req) => {
        hosts.push(req.headers.get('host'));
        return new Response('{}', { status: 201 });
      },
      token: 'test-token',
      port: 4747,
      log: () => {},
      env,
    });
    assert.deepEqual(hosts, ['127.0.0.1:4747']);
    assert.equal(result.failed, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
