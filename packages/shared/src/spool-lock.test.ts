import assert from 'node:assert/strict';
import test from 'node:test';
import { takeLock, type TakeLockDeps } from './spool.ts';

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

const OLD = 10 * 60_000;

function deps(over: Partial<TakeLockDeps> & { pid?: string; ageMs?: number }) {
  const calls = { open: 0, rm: 0, kill: 0 };
  const d: TakeLockDeps = {
    now: () => 1_000_000_000,
    open: async () => {
      calls.open += 1;
      throw errno('EEXIST');
    },
    stat: async () => ({ mtimeMs: 1_000_000_000 - (over.ageMs ?? OLD) }),
    readFile: async () => over.pid ?? '4242',
    rm: async () => {
      calls.rm += 1;
    },
    kill: () => {
      calls.kill += 1;
      throw errno('ESRCH');
    },
    ...over,
  };
  return { d, calls };
}

test('takeLock: rm always EPERM on a stale dead-pid lock => false, never more than 3 tries', async () => {
  const { d, calls } = deps({
    rm: async () => {
      throw errno('EPERM');
    },
  });
  let rmCalls = 0;
  const wrapped = { ...d, rm: async (l: string) => { rmCalls += 1; await d.rm!(l); } };
  assert.equal(await takeLock('/l', wrapped), false);
  assert.ok(rmCalls >= 1 && rmCalls <= 3, `rm calls ${rmCalls}`);
  assert.ok(calls.open <= 3);
});

test('takeLock: live pid is never stolen, however stale', async () => {
  const { d, calls } = deps({ kill: () => undefined, ageMs: 365 * 24 * 3600_000 });
  assert.equal(await takeLock('/l', d), false);
  assert.equal(calls.rm, 0);
});

test('takeLock: EPERM from kill(pid,0) means the pid exists => not stolen', async () => {
  const { d, calls } = deps({ kill: () => { throw errno('EPERM'); } });
  assert.equal(await takeLock('/l', d), false);
  assert.equal(calls.rm, 0);
});

test('takeLock: fresh lock is not stolen even if pid is dead', async () => {
  const { d, calls } = deps({ ageMs: 1_000 });
  assert.equal(await takeLock('/l', d), false);
  assert.equal(calls.rm, 0);
});

test('takeLock: stale + dead pid => removed and retaken', async () => {
  let removed = false;
  const written: string[] = [];
  const { d } = deps({
    open: async () => {
      if (!removed) throw errno('EEXIST');
      return { writeFile: async (t: string) => void written.push(t), close: async () => undefined };
    },
    rm: async () => {
      removed = true;
    },
  });
  assert.equal(await takeLock('/l', d), true);
  assert.deepEqual(written, [String(process.pid)]);
});

test('takeLock: stale lock with garbage pid is treated as ownerless', async () => {
  let removed = false;
  const { d } = deps({
    pid: 'garbage',
    open: async () => {
      if (!removed) throw errno('EEXIST');
      return { writeFile: async () => undefined, close: async () => undefined };
    },
    rm: async () => {
      removed = true;
    },
  });
  assert.equal(await takeLock('/l', d), true);
});

test('takeLock: stat null (lock vanished) loops but stays bounded', async () => {
  const { d, calls } = deps({ stat: async () => null });
  assert.equal(await takeLock('/l', d), false);
  assert.equal(calls.open, 3);
});
