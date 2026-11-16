/**
 * S1 must distinguish PROOF that `.hub/token` reached git from git
 * merely failing to answer. The second one used to rotate the live token and
 * disable the ledger's commit/push forever.
 *
 * `g+w` on a path component is only disqualifying when the owning
 * group can actually contain someone other than root or us.
 */

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { writeBitsTrusted } from './bintrust.ts';
import { CHECK_ERROR_WARN_AFTER, dirChainTrusted, git, resolveTrustedBinaryInfo } from './git.ts';
import { hubHealthParts } from './health.ts';
import { openTestLedger } from './test-helpers.ts';
import { skipOnWin32 } from '@agent-ledger/shared/testing';

/* ===================== evidence vs. error ===================== */

/** Count rotations. A8-1: `LedgerGit` now hashes `.hub/token` on disk before
 *  and after the handler runs to confirm a rotation actually happened, so the
 *  fake handler has to write a new value too — a handler that merely resolves
 *  without touching the file must not look like a real rotation. */
function countingRotator(
  ledgerGit: { setTokenLeakHandler: (fn: () => Promise<boolean>) => void },
  dir: string,
): {
  calls: () => number;
} {
  let calls = 0;
  ledgerGit.setTokenLeakHandler(async () => {
    calls += 1;
    await writeFile(join(dir, '.hub', 'token'), `rotated-token-${calls}\n`, 'utf8');
    return true;
  });
  return { calls: () => calls };
}

test('git check error is NOT a lockdown — no rotation, the commit is retried', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const rotations = countingRotator(fx.ledger.git, fx.dir);
  await fx.ledger.git.flush();

  // The exact live failure mode: a concurrent git process holds `index.lock`,
  // so our own commands cannot take it and exit non-zero/128. We reproduce the
  // *inconclusive* answer by making `.git` temporarily unreadable as a repo —
  // every git call in the invariant then fails with 128, which is what
  // `index.lock`, a timeout and the output cap all look like to the caller.
  const realGit = join(fx.dir, '.git');
  const parked = join(fx.dir, '.git-parked');
  await rename(realGit, parked);

  // A real file change, so "did the deferred work get committed later" is a
  // question about the commit cycle and not about an empty index.
  await writeFile(join(fx.dir, 'deferred-change.md'), '# deferred change\n', 'utf8');
  fx.ledger.git.touch('change during a git error');
  await fx.ledger.git.flush();

  assert.equal(rotations.calls(), 0, 'a check error must not rotate');
  assert.equal(fx.ledger.git.status.securityHold, null, 'a check error must not switch on lockdown');
  assert.ok(
    fx.ledger.git.status.tokenCheck.consecutiveErrors >= 1,
    'the error must be counted for healthz',
  );
  assert.ok(
    fx.ledger.git.status.pendingSummaries >= 1,
    'the summary must not be dropped — the next cycle should commit it',
  );
  assert.match(fx.logs.join('\n'), /could not be evaluated/);
  assert.doesNotMatch(fx.logs.join('\n'), /git branch disabled/);

  // Same error twice: logged once, still no lockdown.
  const logsAfterFirst = fx.logs.length;
  await fx.ledger.git.flush();
  assert.equal(fx.ledger.git.status.securityHold, null);
  assert.ok(fx.logs.length - logsAfterFirst <= 1, 'the same error is logged once');

  // Recovery: git works again, the skipped summary is committed.
  await rename(parked, realGit);
  const before = await git(fx.dir, ['log', '--oneline']);
  await fx.ledger.git.flush();
  const after = await git(fx.dir, ['log', '--oneline']);
  assert.notEqual(after.stdout, before.stdout, 'the deferred change should be committed');
  assert.equal(fx.ledger.git.status.tokenCheck.consecutiveErrors, 0);
  assert.equal(fx.ledger.git.status.enabled, true);
  assert.equal(rotations.calls(), 0);
});

test('N errors in a row = a warning in healthz/brief, not a lockdown', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const rotations = countingRotator(fx.ledger.git, fx.dir);
  await fx.ledger.git.flush();

  const realGit = join(fx.dir, '.git');
  const parked = join(fx.dir, '.git-parked');
  await rename(realGit, parked);
  t.after(async () => {
    await rename(parked, realGit).catch(() => undefined);
  });

  for (let i = 0; i < CHECK_ERROR_WARN_AFTER; i += 1) {
    fx.ledger.git.touch(`change ${i}`);
    await fx.ledger.git.flush();
  }

  const status = fx.ledger.git.status;
  assert.equal(status.tokenCheck.consecutiveErrors, CHECK_ERROR_WARN_AFTER);
  assert.equal(status.securityHold, null);
  assert.equal(status.enabled, true, 'enabled stays true — this is not a lockdown');
  assert.equal(rotations.calls(), 0);

  const parts = hubHealthParts({ ledger: fx.ledger });
  assert.ok(
    parts.some((p) => /\.hub\/token check failed/.test(p)),
    `the warning must be in healthz/brief, got: ${JSON.stringify(parts)}`,
  );
});

test('evidence (tracked) = lockdown + one rotation, then self-recovery', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const rotations = countingRotator(fx.ledger.git, fx.dir);
  await fx.ledger.git.flush();

  await writeFile(join(fx.dir, '.hub', 'token'), 'fake-token-for-test\n', 'utf8');
  await git(fx.dir, ['add', '-f', '.hub/token']);
  const committed = await git(fx.dir, ['commit', '-m', 'oops: tracked token']);
  assert.equal(committed.code, 0, committed.stderr);

  fx.ledger.git.touch('ordinary change');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.enabled, false, 'evidence = commit/push disabled');
  assert.equal(fx.ledger.git.status.securityHold?.kind, 'leak');
  assert.equal(rotations.calls(), 1, 'evidence = token rotation');
  assert.match(fx.logs.join('\n'), /git branch disabled, rotating token/);

  const trackedAfter = await git(fx.dir, ['ls-files', '--error-unmatch', '.hub/token']);
  assert.notEqual(trackedAfter.code, 0, 'the token must be untracked');

  // Rotation happened once; a further cycle must not rotate again while the
  // repo still looks the same from the index' point of view.
  fx.ledger.git.touch('another change');
  await fx.ledger.git.flush();
  assert.ok(rotations.calls() <= 1, 'a repeated cycle must not rotate again');
});

test('rotation fails (handler throws) — the hold must not release by itself, the next cycle retries', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  let calls = 0;
  fx.ledger.git.setTokenLeakHandler(async () => {
    calls += 1;
    throw new Error('rotation failed (test)');
  });
  await fx.ledger.git.flush();

  await writeFile(join(fx.dir, '.hub', 'token'), 'fake-token-for-test\n', 'utf8');
  await git(fx.dir, ['add', '-f', '.hub/token']);
  await git(fx.dir, ['commit', '-m', 'oops: tracked token']);
  fx.ledger.git.touch('zmena');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.enabled, false, 'evidence = commit/push disabled even though the rotation failed');
  assert.equal(fx.ledger.git.status.securityHold?.kind, 'leak');
  assert.equal(calls, 1);

  // Before A8-1, a failed rotation still left a `leak` hold whose only gate
  // was "does the invariant look clean this cycle" — untracked + ignored was
  // enough, so the NEXT clean cycle released it and push went out with the
  // still-valid leaked token in history. Now it must keep retrying rotation
  // and must never release on its own.
  fx.ledger.git.touch('another change, the rotation would still fail');
  await fx.ledger.git.flush();
  assert.equal(calls, 2, 'a failed rotation must be retried, not given up on');
  assert.equal(fx.ledger.git.status.enabled, false, 'the hold must not vanish without a confirmed rotation');
  assert.equal(fx.ledger.git.status.securityHold?.kind, 'leak');
});

test('a repair commit without rewriting history must NOT release the leak hold — the token is still in `git log --all`', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const rotations = countingRotator(fx.ledger.git, fx.dir);
  await fx.ledger.git.flush();
  const base = await git(fx.dir, ['rev-parse', 'HEAD']);

  // Proof: token tracked.
  await writeFile(join(fx.dir, '.hub', 'token'), 'fake-token-for-test\n', 'utf8');
  await git(fx.dir, ['add', '-f', '.hub/token']);
  await git(fx.dir, ['commit', '-m', 'oops: tracked token']);
  fx.ledger.git.touch('zmena');
  await fx.ledger.git.flush();
  assert.equal(fx.ledger.git.status.enabled, false);
  assert.equal(rotations.calls(), 1, 'evidence = token rotation (now also with a write of the new file)');

  // `lockdown()` already removed it from the index. Make the tree match (the
  // tracked blob still lives in HEAD) exactly the way a naive human repair
  // would — untrack it going forward, but the blob stays reachable in HEAD's
  // ancestry. Before A8-1 this alone made the NEXT clean cycle release the
  // hold and re-enable push — exposing the leaked value to anyone who could
  // fetch the (already rotated, but still historically valid-looking) ledger.
  await git(fx.dir, ['commit', '-m', 'repair: untrack token']);
  const trackedNow = await git(fx.dir, ['ls-files', '--error-unmatch', '.hub/token']);
  assert.equal(trackedNow.code, 1, 'precondition: the token is no longer tracked in the tree');
  const historyAfterRepair = await git(fx.dir, ['log', '--all', '--format=%H', '--', '.hub/token']);
  assert.notEqual(historyAfterRepair.stdout.trim(), '', 'precondition: the token is still in history');

  fx.ledger.git.touch('change after the repair commit');
  await fx.ledger.git.flush();
  assert.equal(fx.ledger.git.status.enabled, false, 'a repair commit must not release the hold');
  assert.equal(fx.ledger.git.status.securityHold?.kind, 'leak');
  const hold = fx.ledger.git.status.securityHold;
  assert.match(
    (hold?.kind === 'leak' ? hold.blockedDetail : null) ?? '',
    /history|git log --all/i,
    'the reason must point at history, not just the working tree',
  );
  assert.equal(rotations.calls(), 1, 'the rotation was already confirmed, do not rotate again');

  // Real remedy: rewrite history so the leaked blob is unreachable from any
  // ref (`git reset --hard` to before the leak — same effect as the
  // `ledger doctor` / history-rewrite hint in the lockdown message).
  await git(fx.dir, ['reset', '--hard', base.stdout.trim()]);
  const historyAfterRewrite = await git(fx.dir, ['log', '--all', '--format=%H', '--', '.hub/token']);
  assert.equal(historyAfterRewrite.stdout.trim(), '', 'precondition: history is clean now');

  const logBefore = await git(fx.dir, ['log', '--oneline']);
  fx.ledger.git.touch('change after the history rewrite');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.enabled, true, 'rotation confirmed + history clean = the hold is released');
  assert.equal(fx.ledger.git.status.securityHold, null);
  assert.match(fx.logs.join('\n'), /re-enabled/);
  const logAfter = await git(fx.dir, ['log', '--oneline']);
  assert.notEqual(logAfter.stdout, logBefore.stdout, 'after recovery it commits again');
  assert.equal(rotations.calls(), 1, 'recovery does not rotate again');
});

test('token outside .gitignore = pause without rotation, releases itself', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const rotations = countingRotator(fx.ledger.git, fx.dir);
  await fx.ledger.git.flush();

  const ignore = join(fx.dir, '.gitignore');
  const original = await import('node:fs/promises').then((m) => m.readFile(ignore, 'utf8'));
  await writeFile(ignore, '# .hub/ pattern removed by test\n', 'utf8');

  fx.ledger.git.touch('change with an unignored token');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.securityHold?.kind, 'unsafe');
  assert.equal(fx.ledger.git.status.enabled, false, 'the commit must not run with add -A');
  assert.equal(rotations.calls(), 0, 'the token did not leak — do not rotate');
  const tracked = await git(fx.dir, ['ls-files', '--error-unmatch', '.hub/token']);
  assert.notEqual(tracked.code, 0, 'the token must not get into the index');

  await writeFile(ignore, original, 'utf8');
  fx.ledger.git.touch('change after fixing .gitignore');
  await fx.ledger.git.flush();
  assert.equal(fx.ledger.git.status.enabled, true);
  assert.equal(fx.ledger.git.status.securityHold, null);
  assert.equal(rotations.calls(), 0);
});

test('a concurrent index.lock must not disable the git branch', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  const rotations = countingRotator(fx.ledger.git, fx.dir);
  await fx.ledger.git.flush();

  // A real stale `index.lock`, exactly as a parallel session leaves behind.
  const lock = join(fx.dir, '.git', 'index.lock');
  await writeFile(lock, '', 'utf8');
  t.after(() => unlink(lock).catch(() => undefined));

  fx.ledger.git.touch('change during index.lock');
  await fx.ledger.git.flush();

  // Whether git answers (read-only commands can succeed despite the lock) or
  // fails, the one thing that must NEVER happen is a lockdown + rotation.
  assert.equal(rotations.calls(), 0, 'index.lock must not rotate the token');
  assert.notEqual(
    fx.ledger.git.status.securityHold?.kind,
    'leak',
    'index.lock is not evidence of a token leak',
  );

  await unlink(lock).catch(() => undefined);
  fx.ledger.git.touch('change after the lock is released');
  await fx.ledger.git.flush();
  assert.equal(fx.ledger.git.status.enabled, true);
  assert.equal(rotations.calls(), 0);
});

/* ===================== trust of a g+w chain ===================== */

const TRUSTED_GID = 4242;
const UNTRUSTED_GID = 4343;
const deps = {
  groupWritableOk: async (gid: number) => gid === TRUSTED_GID,
};

test('o+w never, g+w only with explicit permission (default = no)', async () => {
  const ok = deps.groupWritableOk;
  // A8-4: the DEFAULT (production for git and the managed gitleaks copy) is
  // fail-closed — a g+w component is rejected without any group lookup.
  assert.equal(await writeBitsTrusted(0o775, TRUSTED_GID), false);
  assert.equal(await writeBitsTrusted(0o755, TRUSTED_GID), true);
  // world-writable, with and without the sticky bit (`/tmp` is 1777)
  assert.equal(await writeBitsTrusted(0o777, TRUSTED_GID, ok), false);
  assert.equal(await writeBitsTrusted(0o1777, TRUSTED_GID, ok), false);
  // not group-writable: trusted regardless of the group
  assert.equal(await writeBitsTrusted(0o755, UNTRUSTED_GID, ok), true);
  // group-writable: only when the group cannot contain a third principal
  assert.equal(await writeBitsTrusted(0o775, TRUSTED_GID, ok), true);
  assert.equal(await writeBitsTrusted(0o775, UNTRUSTED_GID, ok), false);
  // resolution failure must be fail-closed
  assert.equal(await writeBitsTrusted(0o775, TRUSTED_GID, async () => false), false);
});

test('a g+w directory passes only with explicit permission (default fail-closed)', { skip: skipOnWin32("POSIX group-write bit") }, async (t) => {
  const base = await mkdtemp(join(tmpdir(), 'agent-ledger-h29-'));
  t.after(() => rm(base, { recursive: true, force: true }));
  const uid = process.getuid?.();
  const gid = process.getgid?.() ?? 0;

  const brew = join(base, 'brew');
  await mkdir(brew, { recursive: true });
  const bin = join(brew, 'gitleaks');
  await writeFile(bin, '#!/bin/sh\n', { mode: 0o755 });
  // Reproduce `/opt/homebrew/bin`: drwxrwxr-x, owned by us.
  await chmod(brew, 0o775);

  assert.equal(
    await dirChainTrusted(bin, uid, brew),
    false,
    '/opt/homebrew/bin (drwxrwxr-x) is no longer trusted without explicit permission',
  );
  assert.equal(
    await dirChainTrusted(bin, uid, brew, { groupWritableOk: async (g) => g === gid }),
    true,
    'only explicit permission (claude opt-in) lets g+w through',
  );
  assert.equal(
    await dirChainTrusted(bin, uid, brew, { groupWritableOk: async () => false }),
    false,
    'a g+w directory with an untrusted/undetermined group = rejected',
  );

  await chmod(brew, 0o777);
  assert.equal(
    await dirChainTrusted(bin, uid, brew, { groupWritableOk: async () => true }),
    false,
    'o+w cannot be excused by a group',
  );
});

/* A8-7 is gone with its subject: `dscl`/`dscacheutil` are no longer spawned at
 * all (A8-4 removed group enumeration), so there is no system binary left to
 * resolve. `a84.test.ts` asserts the enumeration cannot come back. */

test('a symlink in an untrusted directory is rejected even when the target is fine', { skip: skipOnWin32("POSIX symlink + mode semantics") }, async (t) => {
  const raw = await mkdtemp(join(tmpdir(), 'agent-ledger-h29-link-'));
  t.after(() => rm(raw, { recursive: true, force: true }));
  // macOS `tmpdir()` is itself a symlink (`/var` → `/private/var`); the chain
  // walk works on realpath'd dirs, so `stopAt` has to be realpath'd too.
  const base = await realpath(raw);
  const gid = process.getgid?.() ?? 0;

  // Target: perfect. Cellar-like, 0755.
  const cellar = join(base, 'cellar', 'bin');
  await mkdir(cellar, { recursive: true });
  const real = join(cellar, 'gitleaks');
  await writeFile(real, '#!/bin/sh\n', { mode: 0o755 });

  // Link lives in a world-writable dir — anyone can repoint it (A5).
  const loose = join(base, 'loose');
  await mkdir(loose, { recursive: true });
  const link = join(loose, 'gitleaks');
  await symlink(real, link);
  await chmod(loose, 0o777);

  const info = await resolveTrustedBinaryInfo([link], base, {
    groupWritableOk: async (g) => g === gid,
  });
  assert.equal(info.path, null, 'a symlink in an o+w directory must not be used');
  assert.equal(info.foundUntrusted, true, 'it should be reported as found but untrusted');
  assert.match(info.rejected.join(' '), /symlink|target/);

  // Same link, but its directory is 0755 → accepted, and we execute the target.
  await chmod(loose, 0o755);
  const okInfo = await resolveTrustedBinaryInfo([link], base, {
    groupWritableOk: async (g) => g === gid,
  });
  assert.equal(okInfo.path, real);
});
