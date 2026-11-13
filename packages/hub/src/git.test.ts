import assert from 'node:assert/strict';
import { chmod, copyFile, mkdir, mkdtemp, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { git, gitToplevel } from './git.ts';
import { openTestLedger } from './test-helpers.ts';

/** S1: `.hub/token` must never survive a commit. If it is ever tracked
 *  (e.g. a `.gitignore` predating agent-ledger let an earlier `git add -A`
 *  through before boot repaired it), the next commit must untrack it and
 *  permanently disable the git branch — never silently keep committing. */
test('S1: token tracked in git → untrack, commit/push disabled for good', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);

  // Make sure there is at least one real commit (long test debounce means
  // `init()`'s own touch has not fired yet).
  await fx.ledger.git.flush();
  const before = await git(fx.dir, ['log', '--oneline']);
  assert.notEqual(before.stdout.trim(), '');

  // Simulate the exact failure mode: token file tracked despite .gitignore.
  await writeFile(join(fx.dir, '.hub', 'token'), 'fake-token-for-test\n', 'utf8');
  await git(fx.dir, ['add', '-f', '.hub/token']);
  const committed = await git(fx.dir, ['commit', '-m', 'oops: tracked token']);
  assert.equal(committed.code, 0, committed.stderr);
  const trackedBefore = await git(fx.dir, ['ls-files', '--error-unmatch', '.hub/token']);
  assert.equal(trackedBefore.code, 0, 'test setup: token should be tracked now');

  fx.ledger.git.touch('normal change');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.enabled, false);
  // A8-8: the hold reason lives on `securityHold`, not `lastPushError`.
  assert.match(fx.ledger.git.status.securityHold?.reason ?? '', /tracked by git/);

  const trackedAfter = await git(fx.dir, ['ls-files', '--error-unmatch', '.hub/token']);
  assert.notEqual(trackedAfter.code, 0, 'token must be untracked');

  // The lockdown is sticky: a further touch must not re-enable or commit again.
  const logBefore = await git(fx.dir, ['log', '--oneline']);
  fx.ledger.git.touch('another change that must not be committed');
  await fx.ledger.git.flush();
  const logAfter = await git(fx.dir, ['log', '--oneline']);
  assert.equal(logAfter.stdout, logBefore.stdout);
  assert.equal(fx.ledger.git.status.enabled, false);
});

/** A8-9: APFS (default on macOS) is case-insensitive — `.hub/TOKEN` and
 *  `.hub/token` are the same file on disk, but git's index keeps the path
 *  exactly as it was added. An exact (case-sensitive) string compare against
 *  the lowercase `TOKEN_REL_PATH` constant missed this entirely: both the
 *  `ls-files --error-unmatch .hub/token` pathspec lookup AND the staged-name
 *  compare answered "not found/not staged" for a tracked `.hub/TOKEN`. */
test('A8-9: .hub/TOKEN (different case, same file on APFS) must be detected as a leak', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.git.flush();
  await writeFile(join(fx.dir, '.hub', 'token'), 'fake-token-for-test\n', 'utf8');

  // `git add -f .hub/TOKEN` is not reliable here: on a case-insensitive FS
  // with `.hub/` in `.gitignore`, git's own force-add silently no-ops for a
  // differently-cased pathspec (verified manually) instead of staging it —
  // a separate git quirk, not the bug under test. `update-index --cacheinfo`
  // stages the path directly, exactly as it would end up in the index
  // however it got there (checkout of an old branch, a tool that normalises
  // case, etc.).
  const blob = await git(fx.dir, ['hash-object', '-w', join(fx.dir, '.hub', 'token')]);
  assert.equal(blob.code, 0, blob.stderr);
  const added = await git(fx.dir, [
    'update-index',
    '--add',
    '--cacheinfo',
    `100644,${blob.stdout.trim()},.hub/TOKEN`,
  ]);
  assert.equal(added.code, 0, added.stderr);
  const committed = await git(fx.dir, ['commit', '-m', 'oops: tracked token (uppercase path)']);
  assert.equal(committed.code, 0, committed.stderr);

  fx.ledger.git.touch('normal change');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.enabled, false, 'A8-9: must be detected even with a different case');
  assert.equal(fx.ledger.git.status.securityHold?.kind, 'leak');
});

/** A8-3: `git diff --cached --name-only` right after `add -A` can fail
 *  (corrupt/unreadable object, concurrent lock) while `add -A` itself already
 *  succeeded. Before the fix, a non-zero/thrown result there produced an
 *  empty `stdout`, which `commit()` read as "nothing staged" — silently
 *  skipping both the commit AND the S1 check on what was just staged,
 *  without any error, warning or retry. */
test('A8-3: diff --cached fails after add -A → noteCheckError, no commit, retry follows', async (t) => {
  const fx = await openTestLedger();
  t.after(fx.cleanup);
  await fx.ledger.git.flush();
  const before = await git(fx.dir, ['log', '--oneline']);
  assert.notEqual(before.stdout.trim(), '');

  const head = (await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim();
  const obj = join(fx.dir, '.git', 'objects', head.slice(0, 2), head.slice(2));
  const backup = `${obj}.bak`;
  await chmod(obj, 0o644);
  await copyFile(obj, backup);
  await writeFile(obj, 'garbage, not a valid zlib stream\n', 'utf8');
  t.after(() => copyFile(backup, obj).then(() => rm(backup, { force: true })).catch(() => undefined));

  // Sanity: this really does make `add -A` succeed and `diff --cached` fail,
  // exactly the split the fix has to handle.
  await writeFile(join(fx.dir, 'a8-3.txt'), 'x\n', 'utf8');
  const add = await git(fx.dir, ['add', '-A']);
  assert.equal(add.code, 0, 'precondition: add -A does not touch the corrupted object');
  const diff = await git(fx.dir, ['diff', '--cached', '--name-only']);
  assert.notEqual(diff.code, 0, 'precondition: diff --cached with a corrupted HEAD object fails');
  await git(fx.dir, ['reset']); // undo the manual add above; let the hub do its own

  fx.ledger.git.touch('change while the HEAD object is corrupted');
  await fx.ledger.git.flush();

  assert.equal(fx.ledger.git.status.tokenCheck.consecutiveErrors, 1, 'must count as a check error');
  // `git log` itself needs to decode the (corrupted) HEAD commit object, so it
  // cannot be used as the "did a new commit happen" probe here — `rev-parse`
  // only resolves the ref to a sha without decoding it.
  const headAfterCorrupt = (await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim();
  assert.equal(headAfterCorrupt, head, 'must not commit without verifying the staged content');
  assert.equal(fx.ledger.git.status.enabled, true, 'a check error is not a lockdown');

  // Repair and retry: the pending summary must not have been lost.
  await copyFile(backup, obj);
  await rm(backup, { force: true });
  fx.ledger.git.touch('one more change after the repair');
  await fx.ledger.git.flush();
  const headAfterRepair = (await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim();
  assert.notEqual(headAfterRepair, head, 'after the repair the changes finally get committed');
});

/* S10: `gitToplevel` must resolve the toplevel by walking the filesystem
 *  itself — never by spawning `git` inside an attacker-supplied directory
 *  (which would read that repo's `.git/config`, e.g. `core.fsmonitor`). */
test('S10: gitToplevel finds the root without running git (fsmonitor does not run)', async () => {
  const repo = await mkdtemp(join(tmpdir(), 'agent-ledger-s10-'));
  try {
    await git(repo, ['init', '-q', '-b', 'main']);
    const marker = join(repo, 'pwned-marker');
    await git(repo, ['config', 'core.fsmonitor', `touch ${marker}`]);
    const nested = join(repo, 'a', 'b');
    await mkdir(nested, { recursive: true });

    const top = await gitToplevel(nested);
    assert.equal(top, await realpath(repo));

    await new Promise((r) => setTimeout(r, 200));
    await assert.rejects(
      () => stat(marker),
      'fsmonitor must not run — gitToplevel must not spawn git in a foreign repo',
    );

    const notARepo = await mkdtemp(join(tmpdir(), 'agent-ledger-s10-norepo-'));
    try {
      assert.equal(await gitToplevel(notARepo), null);
    } finally {
      await rm(notARepo, { recursive: true, force: true });
    }
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

/* G1: a git child can be made to print an unbounded amount of data (e.g.
 *  `cat-file -p` on an oversized blob). `git()` must cap accumulated
 *  stdout/stderr, kill the child once the cap is crossed, and resolve with
 *  `code: -1` instead of growing the buffer (and process memory) forever. */
test('G1: git() caps child output and neither crashes nor hangs on huge stdout', async () => {
  const repo = await mkdtemp(join(tmpdir(), 'agent-ledger-g1-'));
  try {
    await git(repo, ['init', '-q', '-b', 'main']);
    const big = join(repo, 'big.bin');
    // 9 MB, safely over the 8 MB cap, of compressible data so `hash-object`
    // and `cat-file` stay fast.
    await writeFile(big, Buffer.alloc(9 * 1024 * 1024, 'a'));
    const hashed = await git(repo, ['hash-object', '-w', 'big.bin']);
    assert.equal(hashed.code, 0, hashed.stderr);
    const hash = hashed.stdout.trim();

    const started = Date.now();
    const res = await git(repo, ['cat-file', '-p', hash]);
    const elapsedMs = Date.now() - started;

    assert.equal(res.code, -1, 'the cap must return code -1, not success');
    assert.match(res.stderr, /cap/, 'the error must explain that the output cap was hit');
    assert.ok(
      res.stdout.length <= 8 * 1024 * 1024 + 64 * 1024,
      `stdout must stay at the cap, has ${res.stdout.length} B`,
    );
    // Killed promptly on cap breach, not stuck until the 20s timeout.
    assert.ok(elapsedMs < 5_000, `the child should be killed right after the cap, took ${elapsedMs}ms`);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});
