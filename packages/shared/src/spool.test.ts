/** Regression tests for the spool security properties. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { chmod, mkdir, mkdtemp, readdir, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  enqueue,
  ensureSpoolDir,
  isTrustedRootParent,
  isSpoolableRequest,
  lightSpoolStats,
  readFailedSpool,
  readSpool,
  replaySpool,
  retryFailedSpool,
  SpoolError,
  spoolDir,
  type KeyedRequester,
} from './spool.ts';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { ensurePrivateDir } from './platformTrust.ts';

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'spool-test-'));
}

function envFor(dir: string): NodeJS.ProcessEnv {
  return { LEDGER_SPOOL_DIR: dir };
}

/* ---------------- Default location ---------------- */

test('spoolDir: LEDGER_SPOOL_DIR wins, then XDG_STATE_HOME, then ~/.local/state', { skip: skipOnWin32("expects POSIX XDG/~/.local layout; win32 uses LOCALAPPDATA (covered by a platform-injected test)") }, () => {
  assert.equal(spoolDir({ LEDGER_SPOOL_DIR: '/tmp/x-spool', XDG_STATE_HOME: '/tmp/state' }), '/tmp/x-spool');
  assert.equal(spoolDir({ XDG_STATE_HOME: '/tmp/state' }), join('/tmp/state', 'agent-ledger', 'spool'));
  // A relative XDG_STATE_HOME is ignored (the XDG spec requires absolute paths).
  const fallback = spoolDir({ XDG_STATE_HOME: 'relative/state' });
  assert.equal(fallback, join(homedir(), '.local', 'state', 'agent-ledger', 'spool'));
  assert.equal(spoolDir({}), fallback);
  assert.ok(!fallback.includes('.claude'));
});

/* ---------------- Symlink rejected, not followed ---------------- */

test('ensureSpoolDir refuses a symlinked spool directory', async () => {
  const root = await tmp();
  const real = join(root, 'real');
  await mkdir(real, { mode: 0o700 });
  const link = join(root, 'spool-link');
  await symlink(real, link);
  await assert.rejects(() => ensureSpoolDir(link), /symlink/);
});

test('ensureSpoolDir refuses a spool dir whose PARENT is a symlink', async () => {
  // Pre-fix: only the leaf (`dir` itself, created fresh by `mkdir`) was
  // lstat'd. A symlinked parent sailed straight through — `mkdir(dir,
  // {recursive:true})` creates through the link and the new leaf directory
  // is, itself, a perfectly ordinary directory.
  const root = await tmp();
  const real = join(root, 'real-parent');
  await mkdir(real, { mode: 0o700 });
  const parentLink = join(root, 'parent-link');
  await symlink(real, parentLink);
  const dir = join(parentLink, 'ledger-spool');
  await assert.rejects(() => ensureSpoolDir(dir), /symlink/);
});

test('isTrustedRootParent: /tmp-style (root, 1777) passes; root-owned world-writable without sticky and foreign owners do not', () => {
  assert.equal(isTrustedRootParent({ uid: 0, mode: 0o41777 }), true, 'Linux /tmp');
  assert.equal(isTrustedRootParent({ uid: 0, mode: 0o40755 }), true, 'root-owned, not writable by others');
  assert.equal(isTrustedRootParent({ uid: 0, mode: 0o40777 }), false, 'world-writable without the sticky bit');
  assert.equal(isTrustedRootParent({ uid: 0, mode: 0o40775 }), false, 'group-writable without the sticky bit');
  assert.equal(isTrustedRootParent({ uid: 1234, mode: 0o41777 }), false, 'sticky but owned by someone else');
});

/* ---------------- Allowlist ---------------- */

test('isSpoolableRequest allows only the fixed CLI write set', () => {
  assert.equal(isSpoolableRequest('POST', '/v1/items?format=line', {}), true);
  assert.equal(isSpoolableRequest('POST', '/v1/items/ACME-1/comments', {}), true);
  assert.equal(isSpoolableRequest('POST', '/v1/items/ACME-1/done', {}), true);
  assert.equal(isSpoolableRequest('PATCH', '/v1/items/ACME-1', {}), true);
  assert.equal(isSpoolableRequest('POST', '/v1/decisions', {}), true);
  assert.equal(isSpoolableRequest('POST', '/v1/journal', {}), true);
  assert.equal(isSpoolableRequest('POST', '/v1/intake', {}), true);
  assert.equal(isSpoolableRequest('POST', '/v1/intake', { action: 'triage' }), true);

  // Explicitly excluded.
  assert.equal(isSpoolableRequest('POST', '/v1/items/ACME-1/reply', {}), false);
  assert.equal(isSpoolableRequest('POST', '/v1/intake', { action: 'send_to_session' }), false);
  assert.equal(isSpoolableRequest('POST', '/v1/intake', { action: 'triage_and_run' }), false);
  assert.equal(isSpoolableRequest('POST', '/v1/override', {}), false);
  assert.equal(isSpoolableRequest('POST', '/v1/adopt', {}), false);
  assert.equal(isSpoolableRequest('POST', '/v1/guard', {}), false);
  assert.equal(isSpoolableRequest('POST', '/v1/intrude', {}), false);
  assert.equal(isSpoolableRequest('POST', '/v1/groom', {}), false);
  assert.equal(isSpoolableRequest('POST', '/v1/intake/ACME-1/process', {}), false);
  assert.equal(isSpoolableRequest('GET', '/v1/inbox', {}), false);
  assert.equal(isSpoolableRequest('GET', '/v1/repos', {}), false);
});

test('enqueue refuses to queue a write outside the allowlist', async () => {
  const env = envFor(await tmp());
  await assert.rejects(
    () =>
      enqueue(
        { session: 's1' },
        { method: 'POST', path: '/v1/override', body: {}, cmd: 'ledger override' },
        env,
        'tok',
      ),
    (err: unknown) => err instanceof SpoolError && err.exitCode === 4,
  );
});

/* ---------------- HMAC verified at replay, per-record ---------------- */

class FakeClient implements KeyedRequester {
  calls: { method: string; path: string }[] = [];
  async requestKeyed(method: string, path: string): Promise<{ status: number }> {
    this.calls.push({ method, path });
    return { status: 201 };
  }
}

test('replaySpool quarantines a record when the token has rotated', async () => {
  const env = envFor(await tmp());
  await enqueue(
    { session: 's1' },
    { method: 'POST', path: '/v1/items', body: { title: 'x' }, cmd: 'ledger add' },
    env,
    'token-A',
  );
  const client = new FakeClient();
  const res = await replaySpool(client, env, () => Promise.resolve('token-B'));
  assert.equal(client.calls.length, 0, 'a token mismatch must never reach the hub');
  assert.equal(res.failed, 1);
  assert.equal(res.sent, 0);
  const failedFiles = await readdir(join((env.LEDGER_SPOOL_DIR as string), 'failed')).catch(() => []);
  assert.equal(failedFiles.length, 1);
});

test('replaySpool quarantines a tampered record (HMAC mismatch)', async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const record = await enqueue(
    { session: 's1' },
    { method: 'POST', path: '/v1/items', body: { title: 'x' }, cmd: 'ledger add' },
    env,
    'token-A',
  );
  // Tamper the body on disk without touching the hmac — same class of attack
  // as another local process editing the spool file directly.
  const file = join(dir, 's1.jsonl');
  const tampered = { ...record, body: { title: 'PODVRH' } };
  await writeFile(file, `${JSON.stringify(tampered)}\n`, 'utf8');

  const client = new FakeClient();
  const res = await replaySpool(client, env, () => Promise.resolve('token-A'));
  assert.equal(client.calls.length, 0);
  assert.equal(res.failed, 1);
});

test('replaySpool sends a valid, correctly-signed record', async () => {
  const env = envFor(await tmp());
  await enqueue(
    { session: 's1' },
    { method: 'POST', path: '/v1/items', body: { title: 'x' }, cmd: 'ledger add' },
    env,
    'token-A',
  );
  const client = new FakeClient();
  const res = await replaySpool(client, env, () => Promise.resolve('token-A'));
  assert.equal(client.calls.length, 1);
  assert.equal(res.sent, 1);
  assert.equal(res.failed, 0);
});

/* ---------------- Oversized file / line never fully read ---------------- */

test('readSpool quarantines a spool file over 8 MB without parsing it', async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const line = `${JSON.stringify({ key: 'k', ts: Date.now(), method: 'POST', path: '/v1/items', body: {}, hmac: 'x' })}\n`;
  const repeats = Math.ceil((8 * 1024 * 1024 + 1024) / line.length);
  await writeFile(join(dir, 'huge.jsonl'), line.repeat(repeats), 'utf8');

  const pending = await readSpool(env);
  assert.equal(pending.length, 0, 'an oversized file must not be parsed into pending records');
  const failed = await readdir(join(dir, 'failed')).catch(() => []);
  assert.equal(failed.length, 1);
  assert.match(failed[0] as string, /^oversized-/);
});

test('readSpool drops a single line over 128 KB but keeps the rest of the file', async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const hugeLine = JSON.stringify({
    key: 'huge',
    ts: Date.now(),
    method: 'POST',
    path: '/v1/items',
    body: { text: 'x'.repeat(200 * 1024) },
    hmac: 'x',
  });
  const okLine = JSON.stringify({
    key: 'ok',
    ts: Date.now(),
    method: 'POST',
    path: '/v1/items',
    body: {},
    hmac: 'x',
  });
  await writeFile(join(dir, 's1.jsonl'), `${hugeLine}\n${okLine}\n`, 'utf8');

  const pending = await readSpool(env);
  assert.equal(pending.length, 1);
  assert.equal(pending[0]?.record.key, 'ok');
});

test('lightSpoolStats never grows the process by reading an oversized file', async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const line = `${JSON.stringify({ key: 'k', ts: Date.now(), method: 'POST', path: '/v1/items', body: {}, hmac: 'x' })}\n`;
  const repeats = Math.ceil((8 * 1024 * 1024 + 1024) / line.length);
  await writeFile(join(dir, 'huge.jsonl'), line.repeat(repeats), 'utf8');

  const stats = await lightSpoolStats(env);
  assert.equal(stats.queued, 0);
});

/* ---------------- Append never follows a symlink ---------------- */

test('enqueue refuses to append through a symlinked session file', async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const outside = await tmp();
  const evilTarget = join(outside, 'not-the-spool.jsonl');
  await writeFile(evilTarget, '', 'utf8');
  await mkdir(dir, { recursive: true, mode: 0o700 }).catch(() => undefined);
  await symlink(evilTarget, join(dir, 'evil.jsonl'));

  await assert.rejects(() =>
    enqueue(
      { session: 'evil' },
      { method: 'POST', path: '/v1/items', body: {}, cmd: 'ledger add' },
      env,
      'tok',
    ),
  );
});

/* ---------------- Recovery after a token rotation ---------------- */

test('readFailedSpool reports a quarantined record (method, path, reason, time)', async () => {
  const env = envFor(await tmp());
  await enqueue(
    { session: 's1' },
    { method: 'POST', path: '/v1/items', body: { title: 'x' }, cmd: 'ledger add' },
    env,
    'token-A',
  );
  const client = new FakeClient();
  // Rotated token → quarantined into failed/, same as the existing HMAC test.
  await replaySpool(client, env, () => Promise.resolve('token-B'));

  const files = await readFailedSpool(env);
  assert.equal(files.length, 1);
  assert.equal(files[0]?.records.length, 1);
  const rec = files[0]?.records[0];
  assert.equal(rec?.method, 'POST');
  assert.equal(rec?.path, '/v1/items');
  assert.match(rec?.reason ?? '', /HMAC|token/);
  assert.equal(typeof rec?.failed_at, 'number');
});

test('retryFailedSpool without --confirm is a hard no-op', async () => {
  const env = envFor(await tmp());
  await enqueue(
    { session: 's1' },
    { method: 'POST', path: '/v1/items', body: { title: 'x' }, cmd: 'ledger add' },
    env,
    'token-A',
  );
  const client = new FakeClient();
  await replaySpool(client, env, () => Promise.resolve('token-B'));
  const files = await readFailedSpool(env);
  const name = files[0]?.file as string;

  const res = await retryFailedSpool(client, name, false, env, () => Promise.resolve('token-B'));
  assert.deepEqual(res, { requeued: 0, skipped: 0, sent: 0, failed: 0, offline: false });
  assert.equal(client.calls.length, 0, 'no request must be made without --confirm');
  const stillThere = await readFailedSpool(env);
  assert.equal(stillThere[0]?.records.length, 1, 'the failed file must be untouched');
});

test('retryFailedSpool re-signs with the current token and resends', async () => {
  const env = envFor(await tmp());
  await enqueue(
    { session: 's1' },
    { method: 'POST', path: '/v1/items', body: { title: 'x' }, cmd: 'ledger add' },
    env,
    'token-A',
  );
  const client = new FakeClient();
  await replaySpool(client, env, () => Promise.resolve('token-B')); // quarantines it
  assert.equal(client.calls.length, 0);
  const name = (await readFailedSpool(env))[0]?.file as string;

  const res = await retryFailedSpool(client, name, true, env, () => Promise.resolve('token-B'));
  assert.equal(res.requeued, 1);
  assert.equal(res.sent, 1);
  assert.equal(res.failed, 0);
  assert.equal(client.calls.length, 1);
  assert.equal(client.calls[0]?.path, '/v1/items');

  const after = await readFailedSpool(env);
  assert.equal(after.length, 0, 'the record must leave failed/ once resent');
});

test('retryFailedSpool rejects a filename outside failed/ (path traversal)', async () => {
  const env = envFor(await tmp());
  const client = new FakeClient();
  await assert.rejects(
    () => retryFailedSpool(client, '../../etc/passwd', true, env, () => Promise.resolve('token-A')),
    (err: unknown) => err instanceof SpoolError && err.exitCode === 4,
  );
  await assert.rejects(
    () => retryFailedSpool(client, 'not-jsonl.txt', true, env, () => Promise.resolve('token-A')),
    (err: unknown) => err instanceof SpoolError && err.exitCode === 4,
  );
  assert.equal(client.calls.length, 0);
});

test('retryFailedSpool skips a record no longer on the replay allowlist', async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const failedDir = join(dir, 'failed');
  await ensurePrivateDir(failedDir); // creates it private (win32: protected DACL; a plain mkdir inherits and is refused)
  const record = {
    key: 'k1',
    ts: Date.now(),
    session: null,
    method: 'POST',
    path: '/v1/not-on-allowlist',
    body: {},
    cmd: 'todo x',
    hmac: 'irrelevant-for-this-path',
    failed_at: Date.now(),
    reason: 'spool: POST /v1/not-on-allowlist is not on the replay allowlist',
  };
  await writeFile(join(failedDir, '2020-01-01.jsonl'), `${JSON.stringify(record)}\n`, 'utf8');

  const client = new FakeClient();
  const res = await retryFailedSpool(client, '2020-01-01.jsonl', true, env, () => Promise.resolve('token-A'));
  assert.equal(res.skipped, 1);
  assert.equal(res.requeued, 0);
  assert.equal(res.sent, 0);
  assert.equal(client.calls.length, 0, 'a record off the allowlist must never be sent');

  // Skipped records stay visible in failed/, not silently dropped.
  const stillThere = await readFailedSpool(env);
  assert.equal(stillThere[0]?.records.length, 1);
});

/* ---------------- S2: platformTrust-backed writes (T1/T2) ---------------- */

const posixOnly = process.platform === 'win32' && 'POSIX symlink / mode-bit test';

test('S2/T2: enqueue never appends through a pre-planted symlink at the session file', { skip: posixOnly }, async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const victim = join(await tmp(), 'victim.txt');
  await writeFile(victim, 'untouched\n', { mode: 0o600 });
  await ensureSpoolDir(dir);
  await symlink(victim, join(dir, 's1.jsonl'));
  await assert.rejects(
    () =>
      enqueue(
        { session: 's1' },
        { method: 'POST', path: '/v1/items', body: { title: 'x' }, cmd: 'ledger add' },
        env,
        'token-A',
      ),
    (err: unknown) => err instanceof SpoolError && err.exitCode === 4 && /symlink/.test(err.message),
  );
  assert.equal(await readFile(victim, 'utf8'), 'untouched\n', 'the symlink target must stay untouched');
});

test('S2/T1: a group-writable spool directory is refused with SpoolError(4), never chmod-fixed', { skip: posixOnly }, async () => {
  const root = await tmp();
  const dir = join(root, 'spool');
  await mkdir(dir, { mode: 0o700 });
  await chmod(dir, 0o770);
  await assert.rejects(
    () => ensureSpoolDir(dir),
    (err: unknown) => err instanceof SpoolError && err.exitCode === 4 && /group\/other/.test(err.message),
  );
  const { mode } = await stat(dir);
  assert.equal(mode & 0o777, 0o770, 'a directory we did not create is never re-permissioned');
});

test('S2/T2: pruneSpool rewrites through a random exclusive tmp — a planted `${file}.tmp` symlink is not followed', { skip: posixOnly }, async () => {
  const dir = await tmp();
  const env = envFor(dir);
  const victim = join(await tmp(), 'victim.txt');
  await writeFile(victim, 'untouched\n', { mode: 0o600 });
  for (const title of ['one', 'two']) {
    await enqueue(
      { session: 's1' },
      { method: 'POST', path: '/v1/items', body: { title }, cmd: 'ledger add' },
      env,
      'token-A',
    );
  }
  const file = join(dir, 's1.jsonl');
  await symlink(victim, `${file}.tmp`); // the predictable name the old code wrote to
  let n = 0;
  const client: KeyedRequester = {
    requestKeyed: () => {
      n += 1;
      if (n === 1) return Promise.resolve({ status: 201 });
      return Promise.reject(Object.assign(new Error('hub down'), { hubDown: true }));
    },
  };
  const res = await replaySpool(client, env, () => Promise.resolve('token-A'));
  assert.equal(res.sent, 1);
  assert.equal(await readFile(victim, 'utf8'), 'untouched\n', 'tmp symlink target must not be written');
  const left = (await readFile(file, 'utf8')).split('\n').filter((l) => l.trim() !== '');
  assert.equal(left.length, 1, 'one record remains queued (atomic rewrite happened)');
  const stray = (await readdir(dir)).filter((e) => e.endsWith('.tmp') && e !== 's1.jsonl.tmp');
  assert.deepEqual(stray, [], 'no random tmp file is left behind');
});
