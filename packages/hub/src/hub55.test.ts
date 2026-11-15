/**
 * The hub looked down while it was running.
 *
 * Covered here: the wake gate (fake clock), the stall monitor's attribution,
 * the ISO log prefix, a vanished git cwd, a missing repo checkout logging once
 * in each direction, the gitleaks backoff (still fail-closed), and the
 * authenticated-only `diag` block of `/v1/healthz`.
 */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { git, GitCwdMissingError, LedgerGit, scanRetryDelayMs } from './git.ts';
import { timestamped } from './log.ts';
import { makeCodeRepo, startTestHub } from './test-helpers.ts';
import { StallMonitor, WakeMonitor } from './wake.ts';

/* ---------------- (b) wake detection ---------------- */

test('a wall-clock jump closes the heavy-job gate and it reopens on its own', () => {
  let now = 1_000_000;
  const lines: string[] = [];
  const wake = new WakeMonitor({
    now: () => now,
    log: (l) => lines.push(l),
    intervalMs: 5_000,
    gapMs: 15_000,
    holdMs: 20_000,
    startupHoldMs: 0,
    jitterMs: 0,
    random: () => 0,
  });
  // A normal tick is not a wake.
  now += 5_000;
  wake.tick();
  assert.equal(wake.heavyAllowed(), true);
  assert.equal(wake.lastWakeAt, null);

  // Asleep for 10 minutes.
  now += 600_000;
  wake.tick();
  assert.equal(wake.heavyAllowed(), false, 'heavy jobs must not run into the post-wake storm');
  assert.equal(lines.length, 1);
  assert.match(lines[0] ?? '', /^wake detected \(gap 600 s\) — heavy jobs deferred until \d{4}-/);
  assert.ok(wake.lastWakeAt, 'healthz diag reports when it happened');
  assert.ok(wake.retryInMs() > 0 && wake.retryInMs() <= 20_000);

  // 20 s later the gate is open again, with no further log lines.
  now += 20_000;
  assert.equal(wake.heavyAllowed(), true);
  assert.equal(wake.retryInMs(), 0);
  assert.equal(lines.length, 1);
});

test('the first seconds after boot are gated too, a backwards clock is not', () => {
  let now = 5_000_000;
  const wake = new WakeMonitor({ now: () => now, startupHoldMs: 10_000, jitterMs: 0 });
  assert.equal(wake.heavyAllowed(), false, 'boot is the same storm as a wake');
  now += 10_000;
  assert.equal(wake.heavyAllowed(), true);
  // NTP stepping the clock back must not hold the ledger's commits hostage.
  now -= 3_600_000;
  wake.tick();
  assert.equal(wake.lastWakeAt, null);
});

test('whenAllowed runs now when open, defers when closed', async () => {
  let now = 0;
  const open = new WakeMonitor({ now: () => now, startupHoldMs: 0 });
  assert.equal(open.whenAllowed(() => undefined), true);

  const closed = new WakeMonitor({ now: () => now, startupHoldMs: 50 });
  let ran = 0;
  assert.equal(
    closed.whenAllowed(() => {
      ran += 1;
    }),
    false,
    'a closed gate defers the job instead of running it',
  );
  assert.equal(ran, 0);
  now = 50;
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(ran, 1, 'the deferred job runs once the gate opens');
});

/* ---------------- (a) stall monitor ---------------- */

test('a stall is logged once a minute, named after the running job', async () => {
  let now = 0;
  const lines: string[] = [];
  const stalls = new StallMonitor({
    now: () => now,
    log: (l) => lines.push(l),
    thresholdMs: 500,
    intervalMs: 100,
    logEveryMs: 60_000,
  });
  // A 700 ms block while `reindex` is the current job.
  await stalls.job('reindex', async () => {
    now += 800;
    stalls.tick();
  });
  assert.equal(lines.length, 1);
  assert.match(lines[0] ?? '', /^event loop stalled 700 ms \(job: reindex\)$/);

  // A second stall inside the same minute is counted, not logged.
  now += 900;
  stalls.tick();
  assert.equal(lines.length, 1);
  assert.equal(stalls.maxDelayMs(), 800);

  // After a minute it logs again and reports what it suppressed.
  now += 60_000;
  stalls.tick();
  now += 700;
  stalls.tick();
  assert.equal(lines.length, 2);
  assert.match(lines[1] ?? '', /\(job: none\) · 1 more suppressed$/);
});

test('loopDelayMaxMs only covers the last 5 minutes', () => {
  let now = 0;
  const stalls = new StallMonitor({ now: () => now, intervalMs: 100, windowMs: 300_000 });
  now += 900;
  stalls.tick();
  assert.equal(stalls.maxDelayMs(), 800);
  now += 300_001;
  assert.equal(stalls.maxDelayMs(), 0, 'an old stall must not be reported forever');
});

/* ---------------- (e) ISO prefix ---------------- */

test('every log line starts with an ISO timestamp', () => {
  const out: string[] = [];
  const sink = timestamped((l) => out.push(l), () => new Date('2026-10-11T18:30:00.000Z'));
  sink('hub running');
  sink('git add failed: exit 1\nfatal: something\n');
  assert.deepEqual(out, [
    '2026-10-11T18:30:00.000Z hub running',
    '2026-10-11T18:30:00.000Z git add failed: exit 1',
    '2026-10-11T18:30:00.000Z fatal: something',
  ]);
});

/* ---------------- (d) vanished cwd ---------------- */

test('git in a vanished cwd is a typed error, not `spawn git ENOENT`', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-gone-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await git(dir, ['init', '-b', 'main']);
  await rm(dir, { recursive: true, force: true });
  await assert.rejects(
    () => git(dir, ['status', '--porcelain']),
    (err: unknown) => {
      assert.ok(err instanceof GitCwdMissingError, `expected GitCwdMissingError, got ${String(err)}`);
      assert.equal(err.cwd, dir);
      // The old failure mode read like "git is missing", which is what sent
      // several debugging sessions after the binary.
      assert.doesNotMatch(err.message, /ENOENT/);
      return true;
    },
  );
});

/* ---------------- (d) missing checkout, logged once ---------------- */

test('a missing repo checkout logs once and its return logs once', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo('hub55');
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'gone', path: repo.path });
  await fx.hub.repoWatcher.start();
  const missingLines = (): string[] => fx.logs.filter((l) => /^repo gone: checkout/.test(l));

  await rm(repo.path, { recursive: true, force: true });
  await fx.hub.repoWatcher.sync();
  await fx.hub.repoWatcher.sync();
  assert.equal(missingLines().length, 1, 'one line per state change, not one per pass');
  assert.match(missingLines()[0] ?? '', /^repo gone: checkout missing \(.+\) — skipping$/);
  assert.deepEqual(fx.hub.repoWatcher.missingRepos(), ['gone'], 'healthz diag lists it');

  // Back (a remounted volume, a re-cloned checkout): one line, and the repo is
  // watched again.
  await mkdir(repo.path, { recursive: true });
  await git(repo.path, ['init', '-b', 'main']);
  await fx.hub.repoWatcher.sync();
  await fx.hub.repoWatcher.sync();
  assert.equal(missingLines().length, 2);
  assert.equal(missingLines()[1], 'repo gone: checkout is back');
  assert.deepEqual(fx.hub.repoWatcher.missingRepos(), []);
});

/* ---------------- (c) gitleaks backoff, still fail-closed ---------------- */

test('the backoff schedule is 15 s → 60 s → 5 min, capped', () => {
  assert.equal(scanRetryDelayMs(1), 15_000);
  assert.equal(scanRetryDelayMs(2), 60_000);
  assert.equal(scanRetryDelayMs(3), 300_000);
  assert.equal(scanRetryDelayMs(9), 300_000);
});

test('an inconclusive scan blocks the commit, logs once, retries', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'agent-ledger-hub55-git-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  await git(root, ['init', '-b', 'main']);
  await git(root, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(root, ['config', 'user.name', 'agent-ledger test']);
  await writeFile(join(root, '.gitignore'), '.hub/token\n', 'utf8');

  const lines: string[] = [];
  let verdict: 'timeout' | 'clean' = 'timeout';
  const led = new LedgerGit({
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: (l) => lines.push(l),
    scanStaged: async () =>
      verdict === 'timeout'
        ? { scanner: 'gitleaks' as const, blocked: true, retryable: true, note: 'exceeded 10000 ms' }
        : { scanner: 'gitleaks' as const, blocked: false, note: null },
  });
  await led.init();
  await writeFile(join(root, 'ITEMS.md'), '# work\n', 'utf8');

  await led.flush();
  assert.equal((await git(root, ['log', '--oneline'])).stdout.trim(), '', 'nothing may be committed');
  assert.equal(led.status.secretScan.blocked, true, 'fail-closed on a non-verdict');
  assert.ok(led.status.secretScan.retryAt, 'healthz diag shows when the retry is due');
  const security = (): string[] => lines.filter((l) => l.startsWith('SECURITY:'));
  assert.equal(security().length, 1);
  assert.match(security()[0] ?? '', /gave no verdict/);

  // A second attempt in the same streak must not repeat the line.
  await led.flush();
  assert.equal(security().length, 1, 'one SECURITY line per streak, not per attempt');
  assert.equal((await git(root, ['log', '--oneline'])).stdout.trim(), '');

  // The scanner recovers: the commit lands and the streak is reported closed.
  verdict = 'clean';
  await led.flush();
  assert.match((await git(root, ['log', '--oneline'])).stdout, /ledger:/);
  assert.equal(led.status.secretScan.retryAt, null);
  assert.ok(
    lines.some((l) => /gitleaks passed again after \d+ failed attempts/.test(l)),
    'a recovery line closes the streak',
  );
});

test('a closed wake gate defers the ledger commit, it is not lost', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'agent-ledger-hub55-gate-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
  await git(root, ['init', '-b', 'main']);
  await git(root, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(root, ['config', 'user.name', 'agent-ledger test']);
  await writeFile(join(root, '.gitignore'), '.hub/token\n', 'utf8');
  let allowed = false;
  const led = new LedgerGit({
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: () => undefined,
    scanStaged: async () => ({ scanner: null, blocked: false, note: null }),
    heavyAllowed: () => allowed,
    // Long enough that the re-armed retry cannot race the explicit `flush()`
    // below — this test is about the deferral, not about the timer.
    heavyRetryInMs: () => 3_600_000,
  });
  await led.init();
  await writeFile(join(root, 'ITEMS.md'), '# work\n', 'utf8');
  led.touch('after wake');
  await led.flush();
  assert.equal((await git(root, ['log', '--oneline'])).stdout.trim(), '', 'gated: no commit yet');

  allowed = true;
  await led.flush();
  assert.match(
    (await git(root, ['log', '--oneline'])).stdout,
    /after wake/,
    'the summary survived the deferral',
  );
});

/* ---------------- (g) healthz diag ---------------- */

test('healthz diag is authenticated-only; the public answer stays {ok}', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const anon = await fetch(`${fx.url}/v1/healthz`);
  assert.deepEqual(
    Object.keys((await anon.json()) as object),
    ['ok', 'platform', 'ledger_id'],
    'S7: no detail without a token (identity fingerprint only, T12)',
  );

  const authed = await fx.api('GET', '/v1/healthz');
  const diag = authed.json.diag as Record<string, unknown>;
  assert.ok(diag, 'the CLI codes against this block');
  assert.deepEqual(Object.keys(diag).sort(), [
    'gitleaksRetryAt',
    'lastWakeAt',
    'loopDelayMaxMs',
    'missingRepos',
    'startedAt',
  ]);
  assert.match(String(diag.startedAt), /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(diag.lastWakeAt, null);
  assert.equal(typeof diag.loopDelayMaxMs, 'number');
  assert.deepEqual(diag.missingRepos, []);
  assert.equal(diag.gitleaksRetryAt, null);
});
