/** Gitleaks in front of the ledger commit, exercised with a FAKE
 *  binary. Never runs the real gitleaks and never touches the real ledger. */

import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { git, LedgerGit } from './git.ts';
import { createHash } from 'node:crypto';
import { gitleaksInfoFor, resetGitleaksCache, scanStaged, summariseFindings } from './gitleaks.ts';

/** A8-4: the hub only runs the install-managed copy, so every fake binary in
 *  this file also gets the 0500 mode and the recorded sha256 the install
 *  writes. `recordSha` is the test-side equivalent of `install.sh`. */
async function recordSha(bin: string): Promise<string> {
  await chmod(bin, 0o500);
  const digest = createHash('sha256').update(await readFile(bin)).digest('hex');
  await writeFile(`${bin}.sha256`, `${digest}\n`, { encoding: 'utf8', mode: 0o400 });
  return digest;
}

/** A shell script that behaves like gitleaks: prints `out`, exits `code`. */
async function fakeGitleaks(dir: string, code: number, out = ''): Promise<string> {
  const bin = join(dir, 'gitleaks');
  await writeFile(
    bin,
    `#!/bin/sh\ncat <<'EOF'\n${out}\nEOF\nexit ${code}\n`,
    { encoding: 'utf8', mode: 0o700 },
  );
  await recordSha(bin);
  return bin;
}

async function temp(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-gitleaks-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('summariseFindings never echoes the matched secret', () => {
  const raw = [
    'Finding:     ghp_REALSECRETVALUE0123456789',
    'Secret:      ghp_REALSECRETVALUE0123456789',
    'RuleID:      github-pat',
    'File:        acme/ITEMS.md',
  ].join('\n');
  const note = summariseFindings(raw);
  assert.match(note, /github-pat/);
  assert.match(note, /ITEMS\.md/);
  assert.doesNotMatch(note, /ghp_REALSECRETVALUE/, 'the secret itself must never be surfaced');
});

test('scanStaged: exit 0 → clean, commit may proceed', async (t) => {
  const dir = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  await fakeGitleaks(dir, 0);
  const res = await scanStaged(dir, { binPath: join(dir, 'gitleaks'), trustStopAt: dir });
  assert.deepEqual(res, { scanner: 'gitleaks', blocked: false, note: null });
});

test('scanStaged: exit 1 → blocked, with a secret-free note', async (t) => {
  const dir = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  await fakeGitleaks(dir, 1, 'RuleID:      aws-access-token\nSecret:      AKIAXXXXXXXXXXXXXXXX');
  const res = await scanStaged(dir, { binPath: join(dir, 'gitleaks'), trustStopAt: dir });
  assert.equal(res.blocked, true);
  assert.equal(res.scanner, 'gitleaks');
  assert.match(res.note ?? '', /aws-access-token/);
  assert.doesNotMatch(res.note ?? '', /AKIA/);
});

test('scanStaged: missing binary → warning, NOT a block', async (t) => {
  const dir = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const res = await scanStaged(dir, { binPath: join(dir, 'does-not-exist'), trustStopAt: dir });
  assert.equal(res.scanner, null);
  assert.equal(res.blocked, false, 'a missing scanner must never stop the ledger committing');
  assert.match(res.note ?? '', /install\.sh/);
});

test('H6-1: gitleaks failing for its own reasons (exit > 1) is now fail-closed', async (t) => {
  const dir = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  await fakeGitleaks(dir, 3, 'boom');
  const res = await scanStaged(dir, { binPath: join(dir, 'gitleaks'), trustStopAt: dir });
  // An attacker able to make the scanner error out (crash, malformed input,
  // a tampered repo-local config it chokes on) must not thereby get an
  // unscanned commit through — a scanner that RAN and failed blocks, same as
  // a real finding. A scanner that never ran at all (missing binary, tested
  // separately) still just warns.
  assert.equal(res.blocked, true);
  assert.equal(res.scanner, 'gitleaks');
  assert.match(res.note ?? '', /failed/);
});

test('H55-A6: output-cap kill settles immediately, not only when the pipe happens to close', async (t) => {
  const dir = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());

  // A fake scanner that (1) escapes its own process group with a detached
  // grandchild that inherits stdout — exactly the "sleeping grandchild keeps
  // our pipe open" case the `detached` group-kill comment above describes —
  // and (2) immediately overflows the 4 MB output cap. Killing the direct
  // child can never close the pipe here, so only an immediate `settle()` in
  // the cap check (not the `close` handler) resolves this quickly.
  // `run()` gives the scanned process a locked-down PATH (`/usr/bin:/bin`),
  // so `#!/usr/bin/env node` cannot resolve a nvm/homebrew `node` — the
  // shebang needs the absolute interpreter path instead.
  const bin = join(dir, 'gitleaks');
  await writeFile(
    bin,
    [
      `#!${process.execPath}`,
      "require('child_process').spawn('sleep', ['2'], { stdio: 'inherit', detached: true }).unref();",
      "process.stdout.write('A'.repeat(5 * 1024 * 1024));",
    ].join('\n'),
    { encoding: 'utf8', mode: 0o700 },
  );
  await recordSha(bin);

  const startedAt = Date.now();
  // Generous budget: if the fix regresses, this test still terminates (the
  // independent timer eventually settles too) but takes the FULL budget —
  // the elapsed-time assertion below is what actually catches the regression.
  const res = await scanStaged(dir, { binPath: bin, trustStopAt: dir, timeoutMs: 4_000 });
  const elapsedMs = Date.now() - startedAt;

  assert.equal(res.blocked, true);
  assert.equal(res.retryable, true);
  assert.ok(
    elapsedMs < 2_000,
    `the output-cap kill must settle at once, not wait for the timeout (${elapsedMs} ms)`,
  );
});

test('H6-1: --config always points outside the scanned ledger, never trusts a repo-local .gitleaks.toml', async (t) => {
  const dir = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const bin = join(dir, 'gitleaks');
  await writeFile(
    bin,
    `#!/bin/sh\nprintf '%s\\n' "$@" > "$(dirname "$0")/argv.txt"\nexit 0\n`,
    { encoding: 'utf8', mode: 0o700 },
  );
  await recordSha(bin);
  await scanStaged(dir, { binPath: bin, trustStopAt: dir });
  const argv = (await readFile(join(dir, 'argv.txt'), 'utf8')).split('\n').filter(Boolean);
  const configIdx = argv.indexOf('--config');
  assert.notEqual(configIdx, -1, `--config missing from argv: ${argv.join(' ')}`);
  const configPath = argv[configIdx + 1] ?? '';
  assert.ok(configPath.length > 0 && !configPath.startsWith(dir), `--config must not point inside the scanned ledger (${dir}): ${configPath}`);
});

test('H6-2: the gitleaks child does not get the real user HOME', async (t) => {
  const dir = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const bin = join(dir, 'gitleaks');
  await writeFile(bin, `#!/bin/sh\nprintf '%s' "$HOME" > "$(dirname "$0")/home.txt"\nexit 0\n`, {
    encoding: 'utf8',
    mode: 0o700,
  });
  await recordSha(bin);
  await scanStaged(dir, { binPath: bin, trustStopAt: dir });
  const home = await readFile(join(dir, 'home.txt'), 'utf8');
  assert.notEqual(home, process.env.HOME, 'gitleaks child must not see the real user HOME');
});

test('H6-3: the binary-resolution cache is keyed by (binPath, stopAt), not shared globally', async (t) => {
  const dirA = await temp(t);
  const dirB = await temp(t);
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const binA = await fakeGitleaks(dirA, 0);
  // dirB has no gitleaks binary at all — its own resolution must independently
  // come back null, not reuse dirA's resolved path from an unkeyed cache.
  const resolvedA = (await gitleaksInfoFor(binA, dirA)).path;
  const resolvedB = (await gitleaksInfoFor(join(dirB, 'does-not-exist'), dirB)).path;
  assert.equal(resolvedA, binA);
  assert.equal(resolvedB, null, 'a distinct (binPath, stopAt) must not inherit the other call’s resolution');
});

/* ---------------- integration with the real LedgerGit ---------------- */

async function ledgerRepo(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await temp(t);
  await git(dir, ['init', '-b', 'main']);
  await git(dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(dir, ['config', 'user.name', 'agent-ledger test']);
  await writeFile(join(dir, '.gitignore'), '.hub/token\n', 'utf8');
  return dir;
}

test('a finding stops the commit and LEAVES the staged changes', async (t) => {
  const root = await ledgerRepo(t);
  const gitLog: string[] = [];
  const led = new LedgerGit({
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: (l) => gitLog.push(l),
    scanStaged: async () => ({ scanner: 'gitleaks', blocked: true, note: 'rules: github-pat' }),
  });
  await led.init();
  await writeFile(join(root, 'ITEMS.md'), '# leaked\n', 'utf8');
  led.touch('test');
  await led.flush();

  const head = await git(root, ['log', '--oneline']);
  assert.equal(head.stdout.trim(), '', 'no commit may exist');
  const staged = await git(root, ['diff', '--cached', '--name-only']);
  assert.match(staged.stdout, /ITEMS\.md/, 'staged changes must survive for a human to inspect');
  assert.equal(led.status.secretScan.blocked, true);
  assert.ok(led.status.secretScan.blockedAt, 'blockedAt is what /v1/healthz reports');
  assert.ok(gitLog.some((l) => l.startsWith('SECURITY:')));
});

test('a clean scan commits as before', async (t) => {
  const root = await ledgerRepo(t);
  const led = new LedgerGit({
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: () => undefined,
    scanStaged: async () => ({ scanner: 'gitleaks', blocked: false, note: null }),
  });
  await led.init();
  await writeFile(join(root, 'ITEMS.md'), '# ok\n', 'utf8');
  led.touch('test');
  await led.flush();
  assert.match((await git(root, ['log', '--oneline'])).stdout, /ledger: test/);
  assert.equal(led.status.secretScan.blocked, false);
  assert.ok(led.status.lastCommit, 'lastCommit is set by the commit itself');
});

test('a missing scanner still commits (hub scanner is the first line)', async (t) => {
  const root = await ledgerRepo(t);
  const led = new LedgerGit({
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: () => undefined,
    scanStaged: async () => ({ scanner: null, blocked: false, note: 'gitleaks is not installed' }),
  });
  await led.init();
  await writeFile(join(root, 'ITEMS.md'), '# ok\n', 'utf8');
  led.touch('test');
  await led.flush();
  assert.match((await git(root, ['log', '--oneline'])).stdout, /ledger: test/);
  assert.equal(led.status.secretScan.scanner, null);
});



test('a restarted hub recovers lastCommit/lastCommitAt from the repo', async (t) => {
  const root = await ledgerRepo(t);
  const opts = {
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: () => undefined,
    scanStaged: async () => ({ scanner: null, blocked: false, note: null }),
  };
  const first = new LedgerGit(opts);
  await first.init();
  await writeFile(join(root, 'ITEMS.md'), '# x\n', 'utf8');
  first.touch('first write');
  await first.flush();
  const sha = first.status.lastCommit;
  assert.ok(sha);

  // A brand new instance == a hub restart. Before the recovery fix this reported
  // `git — · push —` until it happened to commit something itself.
  const restarted = new LedgerGit(opts);
  await restarted.init();
  assert.equal(restarted.status.lastCommit, sha);
  assert.ok(restarted.status.lastCommitAt, 'commit time comes from the repo, not from memory');
  assert.doesNotThrow(() => new Date(restarted.status.lastCommitAt as string).toISOString());
});

test('no remote → upstream/ahead/behind are null, not a crash', async (t) => {
  const root = await ledgerRepo(t);
  const led = new LedgerGit({
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: () => undefined,
    scanStaged: async () => ({ scanner: null, blocked: false, note: null }),
  });
  await led.init();
  assert.equal(led.status.upstream, null);
  assert.equal(led.status.ahead, null);
  assert.equal(led.status.behind, null);
});

test('ahead/behind and the last push are read from the ledger repo', async (t) => {
  const root = await ledgerRepo(t);
  const remote = await temp(t);
  await git(remote, ['init', '--bare', '-b', 'main']);
  const opts = {
    root,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 3_600_000,
    push: false,
    log: () => undefined,
    scanStaged: async () => ({ scanner: null, blocked: false, note: null }),
  };
  const led = new LedgerGit(opts);
  await led.init();
  await writeFile(join(root, 'ITEMS.md'), '# x\n', 'utf8');
  led.touch('write');
  await led.flush();
  await git(root, ['remote', 'add', 'origin', remote]);
  await git(root, ['push', '-u', 'origin', 'main']);

  // Two more commits that never reached the remote → ahead 2, behind 0.
  await writeFile(join(root, 'ITEMS.md'), '# y\n', 'utf8');
  led.touch('second');
  await led.flush();
  await writeFile(join(root, 'ITEMS.md'), '# z\n', 'utf8');
  led.touch('third');
  await led.flush();

  const restarted = new LedgerGit(opts);
  await restarted.init();
  assert.equal(restarted.status.upstream, 'origin/main');
  assert.equal(restarted.status.ahead, 2);
  assert.equal(restarted.status.behind, 0);
  assert.ok(restarted.status.lastPushAt, 'last push time comes from the origin/main reflog');
});
