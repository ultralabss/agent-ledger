/** Degraded-state reporting, `done.version` schema parity and
 *  log/WAL growth. Temp ledgers only; never touches the real `~/.claude`. */

import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { isDoneRef, parseItem, type ItemRepair } from '@agent-ledger/shared';
import { redactUrlCredentials } from './git.ts';
import { gitleaksAvailability, resetGitleaksCache, scanStaged } from './gitleaks.ts';
import { hubHealthLine, hubHealthParts } from './health.ts';
import { rotateLog } from './ops/logrotate.ts';
import { openTestLedger, startTestHub } from './test-helpers.ts';
import type { Ledger } from './ledger/ledger.ts';

const BASE = {
  kind: 'BACKLOG',
  priority: 'P2',
  owner: 'agent',
  steps: [] as string[],
  blocked_by: [] as string[],
  aliases: [] as string[],
  proposed: false,
};

function addItem(ledger: Ledger, title: string) {
  return ledger.createItem({ ...BASE, repo: 'ops', title });
}

/* ---------------- one schema, write and read ---------------- */

test('isDoneRef: accepts refs, rejects prose', () => {
  for (const ok of ['v0.3.0', '2f0e21d', 'release/2026-10', 'acme@1.2.3']) {
    assert.equal(isDoneRef(ok), true, ok);
  }
  for (const bad of ['', 'backup in /home/user/env.yml, original deleted', 'a'.repeat(65), 'a b']) {
    assert.equal(isDoneRef(bad), false, bad);
  }
});

test('done --ref with prose is refused at write time, with the note hint', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const item = await addItem(fx.ledger, 'test');
  await assert.rejects(
    () => fx.ledger.done(item.fm.id, { ref: 'backup in /home/user/env.yml, original deleted' }),
    /ledger note/,
  );
  // The item is still open — a refused ref must not half-close anything.
  assert.equal(fx.ledger.getItem(item.fm.id).item.fm.status, 'open');
});

test('an item with prose in done.version stays indexed and is migrated', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const item = await addItem(fx.ledger, 'ref test');
  await fx.ledger.done(item.fm.id, { ref: 'v9.9.9' });
  const file = fx.ledger.paths.itemFile('ops', item.fm.id);

  // Simulate the record an older hub wrote: a sentence in `done.version`.
  const prose = 'backup in /home/user/env.acme.yml, original deleted';
  const onDisk = await readFile(file, 'utf8');
  await writeFile(file, onDisk.replace('version: v9.9.9', `version: "${prose}"`), 'utf8');

  await fx.ledger.reindex();
  // (b) the item is NOT dropped from the index; only the bad field is blanked.
  const indexed = fx.ledger.getItem(item.fm.id).item;
  assert.equal(indexed.fm.done?.version, null);
  assert.equal(indexed.fm.status, 'done');
  assert.equal(fx.ledger.warnings.has(file), true, 'warned in healthz');
  assert.match(fx.logs.join('\n'), /blanked in the index/);

  // (c) the migration moves the text into the log and clears the warning.
  const fixed = await fx.ledger.migrateRepairedItems();
  assert.equal(fixed, 1);
  assert.equal(fx.ledger.warnings.has(file), false);
  const after = await readFile(file, 'utf8');
  assert.match(after, /version: null/);
  assert.match(after, /migration: /);
  assert.match(after, /env\.acme\.yml/, 'the sentence survives in the log');
  // Idempotent: a second pass has nothing left to do, and the file reparses clean.
  assert.equal(await fx.ledger.migrateRepairedItems(), 0);
  const repairs: never[] = [];
  assert.equal(parseItem(after, file, repairs).item.fm.done?.version, null);
  assert.equal(repairs.length, 0);
});

test('a broken REQUIRED field is still a hard parse error', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const item = await addItem(fx.ledger, 'req');
  const file = fx.ledger.paths.itemFile('ops', item.fm.id);
  const text = await readFile(file, 'utf8');
  await writeFile(file, text.replace('status: open', 'status: finished'), 'utf8');
  await fx.ledger.reindex();
  assert.match(fx.ledger.warnings.get(file) ?? '', /frontmatter/);
  assert.equal(await fx.ledger.migrateRepairedItems(), 0, 'nothing to repair automatically');
});

/* ---------------- log noise, rotation ---------------- */

test('an unreadable item logs once per (path, mtime), not once per reindex', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const item = await addItem(fx.ledger, 'noisy');
  const file = fx.ledger.paths.itemFile('ops', item.fm.id);
  const text = await readFile(file, 'utf8');
  await writeFile(file, text.replace('status: open', 'status: finished'), 'utf8');

  for (let i = 0; i < 4; i += 1) await fx.ledger.reindex();
  const count = (): number => fx.logs.filter((l) => l.includes('skipped')).length;
  assert.equal(count(), 1, `logged ${count()}× for one unchanged file`);

  // A changed file is a new fact and logs again.
  await writeFile(file, `${text.replace('status: open', 'status: finished')}\n`, 'utf8');
  await fx.ledger.reindex();
  assert.equal(count(), 2);
});

test('rotateLog copy-truncates at the cap and keeps N files', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-log-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const log = join(dir, 'hub.log');

  await writeFile(log, 'x'.repeat(100), 'utf8');
  assert.deepEqual(await rotateLog(log, { maxBytes: 1000, keep: 2 }), {
    rotated: false,
    size: 100,
    skippedSymlink: false,
  });

  await writeFile(log, 'a'.repeat(2000), 'utf8');
  assert.equal((await rotateLog(log, { maxBytes: 1000, keep: 2 })).rotated, true);
  assert.equal((await stat(log)).size, 0, 'same inode, emptied in place');
  assert.equal((await readFile(`${log}.1`, 'utf8')).length, 2000);

  await writeFile(log, 'b'.repeat(2000), 'utf8');
  await rotateLog(log, { maxBytes: 1000, keep: 2 });
  assert.equal((await readFile(`${log}.1`, 'utf8'))[0], 'b');
  assert.equal((await readFile(`${log}.2`, 'utf8'))[0], 'a');
  assert.equal(await stat(`${log}.3`).catch(() => null), null, 'nothing beyond keep');

  // Missing file is not an error.
  assert.equal((await rotateLog(join(dir, 'nope.log'))).rotated, false);
});

/** A8-10: `hub.log` itself must never be followed if it is a symlink — `stat`
 *  (which `rotateLog` used to call) follows symlinks, so a planted
 *  `hub.log → /some/other/file` would get ITS content truncated and copied
 *  into `hub.log.1` instead of being left alone. */
test('hub.log as a symlink is not followed — rotation is skipped', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-log-symlink-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const { symlink } = await import('node:fs/promises');
  const target = join(dir, 'secret-target.txt');
  await writeFile(target, 'a'.repeat(2000), 'utf8');
  const log = join(dir, 'hub.log');
  await symlink(target, log);

  const result = await rotateLog(log, { maxBytes: 1000, keep: 2 });
  assert.deepEqual(result, { rotated: false, size: 0, skippedSymlink: true });

  // The target must be untouched — neither truncated nor copied anywhere.
  assert.equal((await readFile(target, 'utf8')).length, 2000, 'symlink target must stay untouched');
  assert.equal(await stat(`${log}.1`).catch(() => null), null, 'hub.log.1 must not be created from the symlink target');
});

test('store.checkpoint truncates the WAL and is safe to repeat', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  fx.hub.store.checkpoint();
  fx.hub.store.checkpoint();
  const wal = await stat(join(fx.dir, '.hub', 'hub.sqlite-wal')).catch(() => null);
  assert.ok(wal === null || wal.size < 1024 * 1024);
});

/* ---------------- found vs trusted ---------------- */

async function fakeBin(dir: string, name: string): Promise<string> {
  const bin = join(dir, name);
  await writeFile(bin, '#!/bin/sh\nexit 0\n', { encoding: 'utf8', mode: 0o700 });
  await chmod(bin, 0o500);
  // A8-4: the hub only ever runs the install-managed copy, which always has a
  // recorded digest next to it.
  const { createHash } = await import('node:crypto');
  const digest = createHash('sha256').update(await readFile(bin)).digest('hex');
  await writeFile(`${bin}.sha256`, `${digest}\n`, { encoding: 'utf8', mode: 0o400 });
  return bin;
}

test('A8-4: a gitleaks copy in a group-writable dir is untrusted, not "not installed"', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-n1-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const binDir = join(dir, 'bin');
  await writeFile(join(dir, 'keep'), '', 'utf8');
  await rm(binDir, { recursive: true, force: true });
  await (await import('node:fs/promises')).mkdir(binDir, { mode: 0o775 });
  await chmod(binDir, 0o775); // group-writable
  const bin = await fakeBin(binDir, 'gitleaks');

  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  // A8-4: `g+w` is a rejection, full stop — no group enumeration decides it
  // any more (macOS enumeration misses nested groups and non-local accounts,
  // so it was not fail-closed).
  const res = await scanStaged(dir, { binPath: bin, trustStopAt: binDir });
  assert.equal(res.scanner, null);
  assert.equal(res.blocked, false, 'an untrusted scanner never blocks the commit');
  assert.match(res.note ?? '', /is not trusted/);
  assert.doesNotMatch(res.note ?? '', /is not in \.hub\/bin/);
  assert.equal(gitleaksAvailability().state, 'untrusted');
});

test('A8-4: a genuinely absent gitleaks copy still reports "is not in .hub/bin"', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-n1-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const res = await scanStaged(dir, { binPath: join(dir, 'nothing-here'), trustStopAt: dir });
  assert.match(res.note ?? '', /is not in \.hub\/bin/);
  assert.equal(gitleaksAvailability().state, 'missing');
});

/* ---------------- A8-8: hold reason vs. real push failure ---------------- */

test('a security hold must not overwrite or hide a real push error, and vice versa', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.git.flush();

  // Simulate a real, unrelated push failure that happened earlier — before
  // the fix this field was the SAME one `holdUnsafe()`/`lockdown()` wrote the
  // security-hold text into, so one clobbered the other.
  const state = (fx.ledger.git as unknown as { state: { lastPushError: string | null } }).state;
  state.lastPushError = 'push failed: network unreachable';

  // Trip an `unsafe` hold the normal way (token not ignored).
  const ignore = join(fx.dir, '.gitignore');
  const original = await import('node:fs/promises').then((m) => m.readFile(ignore, 'utf8'));
  await writeFile(ignore, '# .hub/ pattern removed by test\n', 'utf8');
  fx.ledger.git.touch('change with an unignored token');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.securityHold?.kind, 'unsafe');
  assert.equal(
    fx.ledger.git.status.lastPushError,
    'push failed: network unreachable',
    'a hold must not overwrite an existing push error',
  );
  const partsDuringHold = hubHealthParts({ ledger: fx.ledger }).join(' · ');
  assert.match(partsDuringHold, /DISABLED/);
  assert.match(partsDuringHold, /not in \.gitignore|unignored|unsafe/i);
  assert.match(partsDuringHold, /last push failed: push failed: network unreachable/);

  // Lift the hold the normal way.
  await writeFile(ignore, original, 'utf8');
  fx.ledger.git.touch('change after fixing .gitignore');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.securityHold, null);
  assert.equal(
    fx.ledger.git.status.lastPushError,
    'push failed: network unreachable',
    'releasing the hold must not erase an unrelated push error',
  );
  assert.match(
    hubHealthParts({ ledger: fx.ledger }).join(' · '),
    /last push failed: push failed: network unreachable/,
  );
});

/* ---------------- brief: degraded state on line 1 ---------------- */

test('brief: a git lockdown is the first line of the SessionStart brief', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());

  assert.equal(hubHealthLine({ ledger: fx.hub.ledger }), null, 'healthy hub says nothing');

  // Force the state left behind: commit/push disabled.
  (fx.hub.ledger.git as unknown as { enabled: boolean }).enabled = false;
  const parts = hubHealthParts({ ledger: fx.hub.ledger });
  // A sha mismatch is its own state now ("stale/forged copy"),
  // worded differently from "the directory is not exclusively ours" — the two
  // need different fixes, so they must not share a sentence.
  assert.match(
    hubHealthParts({
      ledger: fx.hub.ledger,
      scanner: { state: 'mismatch', detail: 'sha256 does not match the recorded one' },
    }).join(' '),
    /STALE.* install\.sh/,
  );
  assert.match(
    hubHealthParts({
      ledger: fx.hub.ledger,
      scanner: { state: 'untrusted', detail: 'the directory is writable outside {root, us}' },
    }).join(' '),
    /UNVERIFIED.* install\.sh/,
  );
  assert.match(parts.join(' '), /DISABLED/);

  const brief = await fx.api('GET', '/v1/brief');
  assert.match(brief.text.split('\n')[0] ?? '', /^⚠ hub:/);

  const health = await fx.api('GET', '/v1/healthz');
  assert.equal(health.json.ok, false);
  assert.match(String(health.json.degraded), /^⚠ hub:/);

  const hook = await fx.hook('session-start', { session_id: 's-degraded', cwd: fx.dir });
  assert.match(hook.text.split('\n')[0] ?? '', /^⚠ hub:/);
});

/* ---------------- audit regressions (H-1, S-2, S-3, S-5) ---------------- */

test('H-1: a broken lock/dependency field is NEVER blanked, only `done` is', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const item = await addItem(fx.ledger, 'locked');
  const file = fx.ledger.paths.itemFile('ops', item.fm.id);
  const good = await readFile(file, 'utf8');

  // A guard-bearing field must stay a hard parse error: the last good version
  // keeps being served instead of a silently unlocked one.
  for (const [from, to] of [
    ['claimed_by: null', 'claimed_by: 5'],
    ['paths: []', 'paths: 7'],
    ['blocked_by: []', 'blocked_by: 7'],
    ['blocks: []', 'blocks: 7'],
  ]) {
    assert.ok(good.includes(from as string), `fixture has ${from}`);
    const repairs: ItemRepair[] = [];
    assert.throws(
      () => parseItem(good.replace(from as string, to as string), file, repairs),
      /frontmatter/,
      `${from} must be fatal`,
    );
    assert.equal(repairs.length, 0, `${from} must not be repaired`);
  }

  // And such a file is never queued for a rewrite on disk.
  await writeFile(file, good.replace('claimed_by: null', 'claimed_by: 5'), 'utf8');
  await fx.ledger.reindex();
  assert.equal(await fx.ledger.migrateRepairedItems(), 0, 'no file rewrite for a lock field');
  assert.match(await readFile(file, 'utf8'), /claimed_by: 5/, 'file untouched');
});

test('S-2: a multi-line bad value cannot forge a hub.log line', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const item = await addItem(fx.ledger, 'forge');
  await fx.ledger.done(item.fm.id, { ref: 'v1.0.0' });
  const file = fx.ledger.paths.itemFile('ops', item.fm.id);
  const text = await readFile(file, 'utf8');
  await writeFile(file, text.replace('version: v1.0.0', 'version: "a\\nSECURITY: fake"'), 'utf8');
  await fx.ledger.reindex();
  for (const line of fx.logs) assert.doesNotMatch(line, /^SECURITY: fake/m);
  assert.equal(fx.ledger.warnings.get(file)?.includes('\n'), false);
});

test('S-3: credentials in a remote URL never reach lastPushError', () => {
  const raw = 'fatal: unable to access https://bob:ghp_SECRET0123@github.com/x/y.git/: 403';
  const red = redactUrlCredentials(raw);
  assert.doesNotMatch(red, /ghp_SECRET0123/);
  assert.match(red, /https:\/\/\*\*\*@github\.com/);
  assert.equal(redactUrlCredentials('push failed'), 'push failed');
  assert.doesNotMatch(redactUrlCredentials('git@github.com:x/y.git nope'), /\*\*\*/);
});

test('N-1: a blanked non-`done` field is never persisted — it stays a hard error', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const item = await addItem(fx.ledger, 'aliases');
  const file = fx.ledger.paths.itemFile('ops', item.fm.id);
  const good = await readFile(file, 'utf8');
  await writeFile(file, good.replace('aliases: []', 'aliases: 7'), 'utf8');

  await fx.ledger.reindex();
  // Not repaired into the index, not queued for a rewrite: the file is left to
  // a human, so no later mutation can silently drop the field.
  assert.match(fx.ledger.warnings.get(file) ?? '', /frontmatter/);
  assert.equal(await fx.ledger.migrateRepairedItems(), 0);
  assert.match(await readFile(file, 'utf8'), /aliases: 7/, 'file untouched');
  // And the warning / log line is a single line (S-2).
  assert.equal((fx.ledger.warnings.get(file) ?? '').includes('\n'), false);
  for (const line of fx.logs) assert.equal(line.includes('\n'), false);
});
