import assert from 'node:assert/strict';
import test from 'node:test';
import { renameBackoff, renameRetry, RENAME_BUDGET_MS, RENAME_TRIES } from './fsretry.ts';

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

test('renameBackoff: 7 delays, exponential, total <= 2.5 s', () => {
  const d = renameBackoff();
  assert.equal(d.length, RENAME_TRIES - 1);
  assert.ok(d.reduce((a, b) => a + b, 0) <= RENAME_BUDGET_MS);
  assert.ok(d[1]! > d[0]!);
});

test('renameRetry win32: EPERM/EBUSY/EACCES retried, then succeeds', async () => {
  for (const code of ['EPERM', 'EBUSY', 'EACCES']) {
    let calls = 0;
    const slept: number[] = [];
    await renameRetry('a', 'b', {
      platform: 'win32',
      rename: async () => {
        calls += 1;
        if (calls < 4) throw errno(code);
      },
      sleep: async (ms) => void slept.push(ms),
    });
    assert.equal(calls, 4);
    assert.equal(slept.length, 3);
  }
});

test('renameRetry win32: gives up after 8 tries and throws the last error', async () => {
  let calls = 0;
  await assert.rejects(
    renameRetry('a', 'b', {
      platform: 'win32',
      rename: async () => {
        calls += 1;
        throw errno('EBUSY');
      },
      sleep: async () => undefined,
    }),
    { code: 'EBUSY' },
  );
  assert.equal(calls, RENAME_TRIES);
});

test('renameRetry win32: other errors are not retried', async () => {
  let calls = 0;
  await assert.rejects(
    renameRetry('a', 'b', {
      platform: 'win32',
      rename: async () => {
        calls += 1;
        throw errno('ENOENT');
      },
      sleep: async () => undefined,
    }),
    { code: 'ENOENT' },
  );
  assert.equal(calls, 1);
});

test('renameRetry posix: EPERM surfaces immediately', async () => {
  let calls = 0;
  await assert.rejects(
    renameRetry('a', 'b', {
      platform: 'linux',
      rename: async () => {
        calls += 1;
        throw errno('EPERM');
      },
      sleep: async () => undefined,
    }),
    { code: 'EPERM' },
  );
  assert.equal(calls, 1);
});
