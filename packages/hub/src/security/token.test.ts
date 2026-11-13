import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { loadOrCreateToken } from './token.ts';

async function tmpdir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), 'hub-token-'));
}

test('creates a 43-char base64url token, dir 0700, file 0600', async () => {
  const root = await tmpdir();
  const file = path.join(root, '.hub', 'token');
  const token = await loadOrCreateToken(file);

  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal((await fs.stat(path.dirname(file))).mode & 0o777, 0o700);
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  assert.equal((await fs.readFile(file, 'utf8')).trim(), token);
});

test('reuses an existing token, does not rotate', async () => {
  const root = await tmpdir();
  const file = path.join(root, 'token');
  const a = await loadOrCreateToken(file);
  const b = await loadOrCreateToken(file);
  assert.equal(a, b);
});

test('two tokens in different directories differ (CSPRNG)', async () => {
  const a = await loadOrCreateToken(path.join(await tmpdir(), 'token'));
  const b = await loadOrCreateToken(path.join(await tmpdir(), 'token'));
  assert.notEqual(a, b);
});

test('no .tmp file is left after tmp+link', async () => {
  const root = await tmpdir();
  await loadOrCreateToken(path.join(root, 'token'));
  const left = (await fs.readdir(root)).filter((f) => f.endsWith('.tmp'));
  assert.deepEqual(left, []);
});

test('loose permissions on an existing token → chmod 0600 AND value rotation', async () => {
  const root = await tmpdir();
  const file = path.join(root, 'token');
  const first = await loadOrCreateToken(file);
  await fs.chmod(file, 0o644);

  const second = await loadOrCreateToken(file);
  assert.notEqual(second, first, 'a leaked token must be invalidated');
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
});

test('group-readable (0640) also rotates', async () => {
  const root = await tmpdir();
  const file = path.join(root, 'token');
  const first = await loadOrCreateToken(file);
  await fs.chmod(file, 0o640);
  assert.notEqual(await loadOrCreateToken(file), first);
});

test('corrupted token content → overwritten with a valid one', async () => {
  const root = await tmpdir();
  const file = path.join(root, 'token');
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  await fs.writeFile(file, 'not-a-token', { mode: 0o600 });
  assert.match(await loadOrCreateToken(file), /^[A-Za-z0-9_-]{43}$/);
});

test('symlink instead of a token → refused', async () => {
  const root = await tmpdir();
  const file = path.join(root, 'token');
  await fs.writeFile(path.join(root, 'elsewhere'), 'x', { mode: 0o600 });
  await fs.symlink(path.join(root, 'elsewhere'), file);
  await assert.rejects(() => loadOrCreateToken(file), /is not a regular file/);
});

test('loose directory is tightened to 0700', async () => {
  const root = await tmpdir();
  const dir = path.join(root, '.hub');
  await fs.mkdir(dir, { mode: 0o755 });
  await fs.chmod(dir, 0o755);
  await loadOrCreateToken(path.join(dir, 'token'));
  assert.equal((await fs.stat(dir)).mode & 0o777, 0o700);
});

test('parallel starts get the same token', async () => {
  const root = await tmpdir();
  const file = path.join(root, '.hub', 'token');
  const tokens = await Promise.all(
    Array.from({ length: 8 }, () => loadOrCreateToken(file)),
  );
  assert.equal(new Set(tokens).size, 1, 'link() must not overwrite another process token');
});
