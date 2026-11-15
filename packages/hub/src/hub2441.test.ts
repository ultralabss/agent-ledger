/**
 * Four separate "the protection quietly turned itself off" bugs:
 *  - R7-1: a gitleaks timeout / failed spawn / throwing runner returned
 *    `blocked: false`, so the one input an attacker controls (the staged diff)
 *    was also the switch that skipped the scan,
 *  - R7-4: a missing or unverifiable scanner was only a line in `hub.log`,
 *  - A9-2: a token rotation that failed once was never retried, because
 *    `lockdown()` untracks the token on its first step and the retry lived in
 *    the branch that is only reached while the token is still tracked,
 *  - A9-1: `--trust-claude-group` tolerated any group-writable directory of
 *    any chain, not the one the user actually looked at.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';

import { resolveClaudeBin } from './claudebin.ts';
import { git, LedgerGit } from './git.ts';
import { gitleaksAvailability, resetGitleaksCache, scanStaged } from './gitleaks.ts';
import { hubHealthParts } from './health.ts';

async function temp(t: { after: (fn: () => unknown) => void }, prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `agent-ledger-${prefix}-`));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** Same thing `install.sh` records next to the managed copy. */
async function recordSha(bin: string): Promise<void> {
  await chmod(bin, 0o500);
  const digest = createHash('sha256').update(await readFile(bin)).digest('hex');
  await writeFile(`${bin}.sha256`, `${digest}\n`, { encoding: 'utf8', mode: 0o400 });
}

/* ---------------- the scanner fails closed ---------------- */

test('gitleaks timeout (code -2) BLOCKS the commit and is marked retryable', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const dir = await temp(t, 'r71-timeout');
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const bin = join(dir, 'gitleaks');
  // Outlives the budget → the runner SIGKILLs it and reports `-2`. The budget
  // is shortened here only so the suite does not sit for 10 s; production uses
  // the module constant.
  await writeFile(bin, '#!/bin/sh\nsleep 30\n', { encoding: 'utf8', mode: 0o700 });
  await recordSha(bin);

  const res = await scanStaged(dir, { binPath: bin, trustStopAt: dir, timeoutMs: 150 });
  assert.equal(res.scanner, 'gitleaks');
  assert.equal(res.blocked, true, 'a timeout must not let the commit through');
  assert.equal(res.retryable, true, 'a timeout is transient — the next cycle tries again');
  assert.match(res.note ?? '', /blocked/i);
  assert.doesNotMatch(res.note ?? '', /ran without a second check/);
});

test('a failed spawn (code -1) BLOCKS the commit', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const dir = await temp(t, 'r71-spawn');
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const bin = join(dir, 'gitleaks');
  // A file that passes the managed-binary checks but cannot be executed:
  // no shebang, not a valid Mach-O/ELF → `spawn` fails with ENOEXEC.
  await writeFile(bin, 'not a program\n', { encoding: 'utf8', mode: 0o700 });
  await recordSha(bin);

  // Regression on the runner itself: `spawn` throws ENOEXEC synchronously, so
  // this used to escape `scanStaged` as an exception rather than a result.
  const res = await scanStaged(dir, { binPath: bin, trustStopAt: dir });
  assert.equal(res.blocked, true, 'an unrunnable scanner must not let the commit through');
  assert.equal(res.retryable, true);
});

test('an exception in the runner BLOCKS the commit and the summary is not lost', async (t) => {
  const dir = await temp(t, 'r71-throw');
  await git(dir, ['init', '-q', '-b', 'main']);
  await git(dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(dir, ['config', 'user.name', 'agent-ledger test']);
  await writeFile(join(dir, '.gitignore'), '.hub/\n', 'utf8');
  await mkdir(join(dir, '.hub'), { recursive: true, mode: 0o700 });
  await writeFile(join(dir, '.hub', 'token'), 'x\n', { encoding: 'utf8', mode: 0o600 });
  await git(dir, ['add', '-A']);
  await git(dir, ['commit', '-q', '-m', 'init']);

  const logs: string[] = [];
  const ledgerGit = new LedgerGit({
    root: dir,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: (line) => logs.push(line),
    scanStaged: () => {
      throw new Error('runner crashed');
    },
  });

  await writeFile(join(dir, 'ITEMS.md'), '# new content\n', 'utf8');
  ledgerGit.touch('a change we do not want to lose');
  await ledgerGit.flush();

  const status = ledgerGit.status;
  assert.equal(status.secretScan.blocked, true, 'a runner exception = fail closed');
  assert.equal(status.lastCommit, null, 'no commit must have been made');
  assert.ok(status.pendingSummaries > 0, 'the summary stays for the next cycle');
  // The staged changes have to survive for a human / the retry.
  const staged = await git(dir, ['diff', '--cached', '--name-only']);
  assert.match(staged.stdout, /ITEMS\.md/);
});

/* ---------------- the state is visible ------------------- */

test('health line names a missing, unverified and stale scanner differently', () => {
  const base = {
    ledger: {
      git: { status: { enabled: true, lastPushError: null, secretScan: { blocked: false }, securityHold: null, tokenCheck: undefined } },
      warnings: new Map(),
    },
  } as unknown as Parameters<typeof hubHealthParts>[0];

  const missing = hubHealthParts({ ...base, scanner: { state: 'missing', detail: null } });
  assert.ok(
    missing.some((p) => /MISSING/.test(p) && /install\.sh/.test(p)),
    `missing scanner: ${missing.join(' | ')}`,
  );

  const untrusted = hubHealthParts({
    ...base,
    scanner: { state: 'untrusted', detail: 'the directory is writable outside {root, us}' },
  });
  assert.ok(
    untrusted.some((p) => /UNVERIFIED/.test(p)),
    `unverified scanner: ${untrusted.join(' | ')}`,
  );

  const stale = hubHealthParts({
    ...base,
    scanner: { state: 'mismatch', detail: 'sha256 does not match the recorded one' },
  });
  assert.ok(
    stale.some((p) => /STALE/.test(p) && /install\.sh/.test(p)),
    `stale copy: ${stale.join(' | ')}`,
  );
  // The three must not share wording — that was the whole complaint.
  assert.notDeepEqual(missing, untrusted);
  assert.notDeepEqual(untrusted, stale);

  const ok = hubHealthParts({ ...base, scanner: { state: 'ok', detail: '/x/gitleaks' } });
  assert.deepEqual(ok, [], 'a healthy scanner reports nothing');
});

test('sha256 mismatch → state `mismatch`, not the catch-all `untrusted`', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const dir = await temp(t, 'r74-mismatch');
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const bin = join(dir, 'gitleaks');
  await writeFile(bin, '#!/bin/sh\nexit 0\n', { encoding: 'utf8', mode: 0o700 });
  await recordSha(bin);
  // A `brew upgrade` the user never re-installed: new bytes, old digest.
  await chmod(bin, 0o700);
  await writeFile(bin, '#!/bin/sh\nexit 0\n# other version\n', { encoding: 'utf8', mode: 0o700 });
  await chmod(bin, 0o500);

  const res = await scanStaged(dir, { binPath: bin, trustStopAt: dir });
  assert.equal(res.scanner, null);
  assert.equal(res.blocked, false, 'a missing second check stays a warning, not a block');
  assert.match(res.note ?? '', /sha256/);
  assert.equal(gitleaksAvailability().state, 'mismatch');
});

/* ---------------- the rotation retries ------------------- */

/** A ledger repo whose `.hub/token` IS tracked → S1 lockdown on first cycle. */
async function leakyLedger(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await temp(t, 'a92');
  await git(dir, ['init', '-q', '-b', 'main']);
  await git(dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(dir, ['config', 'user.name', 'agent-ledger test']);
  await mkdir(join(dir, '.hub'), { recursive: true, mode: 0o700 });
  await writeFile(join(dir, '.hub', 'token'), 'leaked-token\n', { encoding: 'utf8', mode: 0o600 });
  // Tracked AND not ignored: exactly the S1 "leak" proof.
  await git(dir, ['add', '-A']);
  await git(dir, ['commit', '-q', '-m', 'oops, token']);
  return dir;
}

function newLedgerGit(dir: string, logs: string[], onLeak: () => Promise<boolean>): LedgerGit {
  const g = new LedgerGit({
    root: dir,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: (line) => logs.push(line),
    scanStaged: async () => ({ scanner: null, blocked: false, note: null }),
  });
  g.setTokenLeakHandler(onLeak);
  return g;
}

test('rotation repeats even after the token was untracked and the hold is released without a restart', async (t) => {
  const dir = await leakyLedger(t);
  const logs: string[] = [];
  let attempts = 0;
  let rotationWorks = false;
  const ledgerGit = newLedgerGit(dir, logs, async () => {
    attempts += 1;
    if (!rotationWorks) throw new Error('rotation failed (e.g. read-only .hub)');
    // A real rotation changes the bytes on disk — `checkLeakRelease` compares
    // the hash against the one taken before the lockdown.
    await writeFile(join(dir, '.hub', 'token'), `new-token-${attempts}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    return true;
  });

  // Cycle 1: lockdown, rotation throws.
  ledgerGit.touch('first cycle');
  await ledgerGit.flush();
  assert.equal(attempts, 1);
  assert.equal(ledgerGit.status.enabled, false, 'the hold holds');
  assert.equal(ledgerGit.status.securityHold?.kind, 'leak');

  // `lockdown()` ran `git rm --cached`, so from here on the S1 invariant is
  // `ok` — this is the exact state in which the OLD code never retried again.
  await writeFile(join(dir, '.gitignore'), '.hub/\n', 'utf8');

  // Cycle 2: the cause is still there, but the retry MUST be attempted.
  // (`retrySecurityHold` is what `server.ts`'s sweep calls.)
  await ledgerGit.retrySecurityHold();
  assert.ok(attempts >= 2, `the rotation must be retried, attempts: ${attempts}`);
  assert.equal(ledgerGit.status.enabled, false, 'until the rotation succeeds, the hold stays');

  // Cycle 3: the cause is fixed. The retry throttle is 30 s, so move past it
  // the way the sweep would.
  rotationWorks = true;
  const before = attempts;
  await new Promise((r) => setTimeout(r, 5));
  // Reach the throttle directly rather than sleeping 30 s in a test.
  (ledgerGit as unknown as { lastRotationRetry: number }).lastRotationRetry =
    Date.now() - LedgerGit.ROTATION_RETRY_MS - 1;
  await ledgerGit.retrySecurityHold();
  assert.ok(attempts > before, 'after the throttle expires it tries again');
  assert.equal(
    ledgerGit.status.securityHold?.kind === 'leak' &&
      ledgerGit.status.securityHold.rotationOk,
    true,
    'a confirmed rotation is written onto the hold',
  );
  assert.ok(
    logs.some((l) => /token rotation confirmed after a repeated attempt/.test(l)),
    `log: ${logs.join(' | ')}`,
  );
});

test('retrySecurityHold is a no-op without a hold and does not do a second lockdown', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const dir = await temp(t, 'a92-noop');
  await git(dir, ['init', '-q', '-b', 'main']);
  const logs: string[] = [];
  let attempts = 0;
  const ledgerGit = newLedgerGit(dir, logs, async () => {
    attempts += 1;
    return true;
  });
  await ledgerGit.retrySecurityHold();
  assert.equal(attempts, 0);
  assert.equal(ledgerGit.status.securityHold, null);
});

/* ---------------- the opt-in is pinned ------------------- */

/**
 * A group-writable directory holding a fake `claude`. `stopAt` bounds the
 * chain walk, because `tmpdir()`'s own ancestry is legitimately world-writable.
 */
async function groupWritableClaude(
  t: { after: (fn: () => unknown) => void },
): Promise<{ bin: string; stopAt: string; gid: number }> {
  const root = await temp(t, 'a91');
  const dir = join(root, 'bin');
  await mkdir(dir, { recursive: true });
  await chmod(root, 0o755);
  // g+w is the only condition the opt-in may excuse.
  await chmod(dir, 0o775);
  const bin = join(dir, 'claude');
  await writeFile(bin, '#!/bin/sh\nexit 0\n', { encoding: 'utf8', mode: 0o755 });
  const { stat } = await import('node:fs/promises');
  const gid = (await stat(dir)).gid;
  return { bin, stopAt: root, gid };
}

test('opt-in without a pin (gid/realpath) does NOT enable headless', async (t) => {
  const { bin, stopAt } = await groupWritableClaude(t);
  const status = await resolveClaudeBin(bin, { trustGroup: true, stopAt });
  assert.equal(status.state, 'group_writable');
  assert.equal(status.path, null, 'without a pin the binary is not run');
  assert.match(status.detail ?? '', /LEDGER_TRUST_CLAUDE_GID/);
});

test('opt-in pinned to the right gid and realpath enables headless', async (t) => {
  const { bin, stopAt, gid } = await groupWritableClaude(t);
  const status = await resolveClaudeBin(bin, {
    trustGroup: true,
    pin: { gid, realpath: bin },
    stopAt,
  });
  assert.equal(status.state, 'ok', status.detail ?? '');
  assert.equal(status.path, bin);
  assert.match(status.detail ?? '', new RegExp(`gid ${gid}`));
});

test('a group other than the pinned one → headless disabled with a message', async (t) => {
  const { bin, stopAt, gid } = await groupWritableClaude(t);
  const status = await resolveClaudeBin(bin, {
    trustGroup: true,
    // The directory was chgrp'd to a group the user never approved.
    pin: { gid: gid + 1_000, realpath: bin },
    stopAt,
  });
  assert.notEqual(status.state, 'ok');
  assert.equal(status.path, null);
  assert.match(status.detail ?? '', /the allowed group was/);
});

test('a path other than the pinned one → headless disabled with a message', async (t) => {
  const { bin, stopAt, gid } = await groupWritableClaude(t);
  const status = await resolveClaudeBin(bin, {
    trustGroup: true,
    // `claude` moved; the approval must not follow it.
    pin: { gid, realpath: join(stopAt, 'bin', 'claude-old') },
    stopAt,
  });
  assert.equal(status.state, 'untrusted');
  assert.equal(status.path, null);
  assert.match(status.detail ?? '', /the allowed path was/);
});

test('a binary that is trusted even without the opt-in stays enabled', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const root = await temp(t, 'a91-clean');
  const dir = join(root, 'bin');
  await mkdir(dir, { recursive: true, mode: 0o755 });
  await chmod(root, 0o755);
  const bin = join(dir, 'claude');
  await writeFile(bin, '#!/bin/sh\nexit 0\n', { encoding: 'utf8', mode: 0o755 });
  // Opt-in set but unpinned: a clean chain must not be punished for it.
  const status = await resolveClaudeBin(bin, { trustGroup: true, stopAt: root });
  assert.equal(status.state, 'ok', status.detail ?? '');
  assert.equal(status.path, bin);
});
