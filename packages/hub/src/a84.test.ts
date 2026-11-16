/**
 * A8-4 — the hub must not execute a binary that another admin account on the
 * machine can replace.
 *
 * Two independent mechanisms, tested here:
 *   1. gitleaks runs ONLY from the install-managed copy in `<ledger>/.hub/bin`,
 *      verified by owner/mode/directory chain AND the recorded sha256.
 *   2. the headless `claude` binary gates triage/grooming/reply worker off when
 *      its path chain is group-writable, unless the user opted in.
 * Plus: the macOS group enumeration (`dscacheutil`/`dscl`) that used to soften
 * rule (1) and (2) is gone and must not come back.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { GROUP_WRITABLE_MESSAGE, resolveClaudeBin } from './claudebin.ts';
import { HeadlessRunner } from './headless.ts';
import { gitleaksAvailability, resetGitleaksCache, scanStaged } from './gitleaks.ts';
import { verifyManagedBinary } from './managedbin.ts';
import { openTestLedger } from './test-helpers.ts';
import { skipOnWin32 } from '@agent-ledger/shared/testing';

async function temp(t: { after: (fn: () => unknown) => void }, tag: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), `agent-ledger-a84-${tag}-`));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** What `install.sh` does: copy, 0500, record sha256 (0400). */
async function installManaged(dir: string, name: string, body = '#!/bin/sh\nexit 0\n'): Promise<string> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
  const bin = join(dir, name);
  await rm(bin, { force: true });
  await writeFile(bin, body, { encoding: 'utf8', mode: 0o700 });
  const digest = createHash('sha256').update(await readFile(bin)).digest('hex');
  await writeFile(`${bin}.sha256`, `${digest}\n`, { encoding: 'utf8', mode: 0o400 });
  await chmod(bin, 0o500);
  return bin;
}

/* ============ 1. gitleaks: only the managed copy, only if it matches ============ */

test('A8-4: a correctly installed gitleaks copy is used', { skip: skipOnWin32("POSIX mode-bit/owner trust chain for managed binaries (win32 uses platformTrust, tested there)") }, async (t) => {
  const root = await temp(t, 'ok');
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const bin = await installManaged(join(root, '.hub', 'bin'), 'gitleaks');
  assert.equal((await verifyManagedBinary(bin, { stopAt: root })).state, 'ok');
  const res = await scanStaged(root, { binPath: bin, trustStopAt: root });
  assert.equal(res.scanner, 'gitleaks', 'the verified copy is the scanner that runs');
  assert.equal(res.blocked, false);
});

test('A8-4: a tampered binary (sha256 mismatch) is NOT run', { skip: skipOnWin32("POSIX mode-bit/owner trust chain for managed binaries (win32 uses platformTrust, tested there)") }, async (t) => {
  const root = await temp(t, 'swap');
  resetGitleaksCache();
  t.after(() => resetGitleaksCache());
  const bin = await installManaged(join(root, '.hub', 'bin'), 'gitleaks');
  // The attacker swaps the binary for one that always reports "clean" — the
  // recorded digest is what catches it, not the mode bits.
  await chmod(bin, 0o700);
  await writeFile(bin, '#!/bin/sh\nexit 0\n# tampered\n', { encoding: 'utf8', mode: 0o700 });
  await chmod(bin, 0o500);

  const verdict = await verifyManagedBinary(bin, { stopAt: root });
  assert.equal(verdict.state, 'mismatch');
  assert.equal(verdict.path, null, 'a mismatching binary is never handed out for spawn');

  const res = await scanStaged(root, { binPath: bin, trustStopAt: root });
  assert.equal(res.scanner, null, 'nothing was executed');
  // Existing policy for "no scanner": warn, do not block the ledger commit.
  assert.equal(res.blocked, false);
  assert.match(res.note ?? '', /sha256/);
  assert.match(res.note ?? '', /install\.sh/);
  // R7-4: `mismatch` is reported separately from `untrusted` — same
  // consequence (we do not run it), different remedy wording.
  assert.equal(gitleaksAvailability().state, 'mismatch', 'healthz/brief must warn');
});

test('A8-4: a missing or tampered .sha256 is not proof', { skip: skipOnWin32("POSIX mode-bit/owner trust chain for managed binaries (win32 uses platformTrust, tested there)") }, async (t) => {
  const root = await temp(t, 'sha');
  const bin = await installManaged(join(root, '.hub', 'bin'), 'gitleaks');

  await rm(`${bin}.sha256`);
  assert.equal((await verifyManagedBinary(bin, { stopAt: root })).state, 'mismatch');

  // A digest file anyone in the group can rewrite would let the attacker
  // "re-record" their own binary — it has to be as protected as the binary.
  await writeFile(`${bin}.sha256`, `${createHash('sha256').update(await readFile(bin)).digest('hex')}\n`, {
    encoding: 'utf8',
    mode: 0o664,
  });
  await chmod(`${bin}.sha256`, 0o664);
  const verdict = await verifyManagedBinary(bin, { stopAt: root });
  assert.equal(verdict.state, 'untrusted');
  assert.match(verdict.detail ?? '', /group\/other/);
});

test('A8-4: a symlink instead of a copy is rejected (the install copies, it does not link)', async (t) => {
  const root = await temp(t, 'link');
  const far = join(root, 'homebrew');
  await mkdir(far, { recursive: true });
  const real = join(far, 'gitleaks');
  await writeFile(real, '#!/bin/sh\nexit 0\n', { encoding: 'utf8', mode: 0o755 });

  const binDir = join(root, '.hub', 'bin');
  await mkdir(binDir, { recursive: true, mode: 0o700 });
  const link = join(binDir, 'gitleaks');
  await symlink(real, link);
  const digest = createHash('sha256').update(await readFile(real)).digest('hex');
  await writeFile(`${link}.sha256`, `${digest}\n`, { encoding: 'utf8', mode: 0o400 });

  const verdict = await verifyManagedBinary(link, { stopAt: root });
  assert.equal(verdict.state, 'untrusted');
  assert.match(verdict.detail ?? '', /symlink/);
});

test('A8-4: a group-writable directory chain → the copy is untrusted', { skip: skipOnWin32("POSIX mode-bit/owner trust chain for managed binaries (win32 uses platformTrust, tested there)") }, async (t) => {
  const root = await temp(t, 'chain');
  const binDir = join(root, '.hub', 'bin');
  const bin = await installManaged(binDir, 'gitleaks');
  assert.equal((await verifyManagedBinary(bin, { stopAt: root })).state, 'ok');

  // Reproduce `/opt/homebrew/bin`: drwxrwxr-x, owned by us. An older version used to
  // accept this after enumerating the owning group; A8-4 never does.
  await chmod(dirname(bin), 0o775);
  let verdict = await verifyManagedBinary(bin, { stopAt: root });
  assert.equal(verdict.state, 'untrusted');
  assert.match(verdict.detail ?? '', /writable outside/);

  // A parent further up counts too.
  await chmod(dirname(bin), 0o700);
  await chmod(join(root, '.hub'), 0o775);
  verdict = await verifyManagedBinary(bin, { stopAt: root });
  assert.equal(verdict.state, 'untrusted');
  await chmod(join(root, '.hub'), 0o700);

  // World-writable binary itself.
  await chmod(bin, 0o707);
  verdict = await verifyManagedBinary(bin, { stopAt: root });
  assert.equal(verdict.state, 'untrusted');
  assert.match(verdict.detail ?? '', /group\/other/);
  await chmod(bin, 0o500);
});

/* ============ 2. claude: group-writable chain turns headless off ============ */

async function fakeClaude(dir: string): Promise<string> {
  await mkdir(dir, { recursive: true });
  const bin = join(dir, 'claude');
  await writeFile(bin, '#!/bin/sh\nprintf \'{"result":"x","is_error":false}\'\n', {
    encoding: 'utf8',
    mode: 0o755,
  });
  await chmod(bin, 0o755);
  return bin;
}

test('A8-4: claude in a trusted chain → headless runs', { skip: skipOnWin32("POSIX mode-bit/owner trust chain for managed binaries (win32 uses platformTrust, tested there)") }, async (t) => {
  const root = await temp(t, 'claude-ok');
  const bin = await fakeClaude(join(root, 'bin'));
  const status = await resolveClaudeBin(bin, { stopAt: root });
  assert.equal(status.state, 'ok');
  assert.equal(status.path, bin);
});

test('A8-4: claude in a group-writable directory → headless disabled, with instructions', { skip: skipOnWin32("POSIX mode-bit/owner trust chain for managed binaries (win32 uses platformTrust, tested there)") }, async (t) => {
  const root = await temp(t, 'claude-gw');
  const bin = await fakeClaude(join(root, 'bin'));
  await chmod(join(root, 'bin'), 0o775);

  const status = await resolveClaudeBin(bin, { stopAt: root });
  assert.equal(status.state, 'group_writable');
  assert.equal(status.path, null, 'a group-writable claude is never spawned');
  assert.match(
    GROUP_WRITABLE_MESSAGE,
    /headless disabled.*~\/\.local.*--trust-claude-group/s,
    'the message has to name both fixes',
  );

  // A9-1: the conscious opt-in re-enables it, but ONLY pinned to the
  // gid and realpath the installer actually saw. An unpinned opt-in (an old
  // plist, a hand-edited one) is refused — that is the A9-1 change.
  const unpinned = await resolveClaudeBin(bin, { stopAt: root, trustGroup: true });
  assert.equal(unpinned.state, 'group_writable');
  assert.equal(unpinned.path, null);
  assert.match(unpinned.detail ?? '', /LEDGER_TRUST_CLAUDE_GID/);

  const { stat } = await import('node:fs/promises');
  const gid = (await stat(join(root, 'bin'))).gid;
  const optedIn = await resolveClaudeBin(bin, {
    stopAt: root,
    trustGroup: true,
    pin: { gid, realpath: bin },
  });
  assert.equal(optedIn.state, 'ok', optedIn.detail ?? '');
  assert.equal(optedIn.path, bin);
});

test('A8-4: --trust-claude-group does not rescue an o+w path either', async (t) => {
  const root = await temp(t, 'claude-ow');
  const bin = await fakeClaude(join(root, 'bin'));
  await chmod(join(root, 'bin'), 0o777);
  const { stat } = await import('node:fs/promises');
  const gid = (await stat(join(root, 'bin'))).gid;
  // Pinned or not, `o+w` is never excusable: the attacker only has to create a
  // file, not replace ours.
  for (const opts of [
    { stopAt: root, trustGroup: true },
    { stopAt: root, trustGroup: true, pin: { gid, realpath: bin } },
  ]) {
    const status = await resolveClaudeBin(bin, opts);
    assert.equal(status.state, 'untrusted', JSON.stringify(opts));
    assert.equal(status.path, null);
  }
});

test('A8-4: HeadlessRunner refuses the run (503) and reports it in the status', { skip: skipOnWin32("POSIX mode-bit/owner trust chain for managed binaries (win32 uses platformTrust, tested there)") }, async (t) => {
  const led = await openTestLedger();
  const root = await temp(t, 'headless');
  t.after(() => led.cleanup());
  const bin = await fakeClaude(join(root, 'bin'));
  await chmod(join(root, 'bin'), 0o775);

  const runner = new HeadlessRunner({
    ledger: led.ledger,
    config: { ...led.config, claudeBin: bin },
    trustStopAt: root,
  });
  await runner.probeBinaryTrust();
  assert.equal(runner.status.bin_trust, 'group_writable');

  const err = await runner
    .runIntake({ ids: ['ACME-1'] })
    .then(() => null)
    .catch((e: unknown) => e as { status?: number; message?: string });
  assert.ok(err, 'the run must not proceed');
  assert.equal(err?.status, 503);
  assert.match(err?.message ?? '', /group-writable/);

  // A9-1: the opt-in in the config only counts together with the pin
  // the installer recorded. Unpinned stays OFF.
  const unpinned = new HeadlessRunner({
    ledger: led.ledger,
    config: { ...led.config, claudeBin: bin, trustClaudeGroup: true },
    trustStopAt: root,
  });
  await unpinned.probeBinaryTrust();
  assert.equal(unpinned.status.bin_trust, 'group_writable', 'without a pin headless stays off');

  const { stat } = await import('node:fs/promises');
  const gid = (await stat(join(root, 'bin'))).gid;
  const trusting = new HeadlessRunner({
    ledger: led.ledger,
    config: {
      ...led.config,
      claudeBin: bin,
      trustClaudeGroup: true,
      trustClaudeGid: gid,
      trustClaudeRealpath: bin,
    },
    trustStopAt: root,
  });
  await trusting.probeBinaryTrust();
  assert.equal(trusting.status.bin_trust, 'ok', trusting.status.bin_trust_detail ?? '');
});

/* ============ 3. the group enumeration must not come back ============ */

test('A8-4: the hub production code contains no group enumeration', async () => {
  const srcDir = dirname(fileURLToPath(import.meta.url));
  const offenders: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
        continue;
      }
      if (!entry.name.endsWith('.ts') || entry.name.endsWith('.test.ts')) continue;
      const text = await readFile(full, 'utf8');
      // Only flag real usage, not the comments that explain why it is gone:
      // `dscacheutil`/`dscl` as a spawned path or in a candidate list.
      if (/['"`][^'"`]*\/(?:dscacheutil|dscl)['"`]/.test(text)) offenders.push(full);
      if (/\/etc\/group/.test(text)) offenders.push(full);
    }
  };
  await walk(srcDir);
  assert.deepEqual(offenders, [], `group enumeration is back: ${offenders.join(', ')}`);
});
