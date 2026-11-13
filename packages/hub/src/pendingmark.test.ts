/** Regression — `PendingMarks` writes a 0-byte marker file (and later
 *  removes it) under `<ledger>/.hub/inbox-pending/<session>`, a directory
 *  reachable by any local account that can write under the ledger root. A
 *  symlink swapped in for the directory, or pre-planted under the exact
 *  marker filename, used to turn that write into a write into (and the
 *  removal into an unlink through) whatever the link actually points at.
 *  These tests never touch the real `~/.ledger` directory — everything lives
 *  under a throwaway `mkdtemp` dir. */

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { PendingMarks } from './pendingmark.ts';

async function tmp(tag: string): Promise<string> {
  return mkdtemp(join(tmpdir(), `agent-ledger-pm-${tag}-`));
}

test('normal run — 0700 directory, 0600 marker, settle removes it', async () => {
  const hubDir = await tmp('ok');
  try {
    const pm = new PendingMarks(hubDir);
    await pm.owe('sess-a');
    const marker = join(pm.path, 'sess-a');
    assert.equal((await readFile(marker, 'utf8')), '');
    await pm.settle('sess-a');
    await assert.rejects(() => readFile(marker));
  } finally {
    await rm(hubDir, { recursive: true, force: true });
  }
});

test('inbox-pending as a symlink to another directory — write refused, target stays empty', async () => {
  const hubDir = await tmp('dirlink');
  const evilTarget = await tmp('evil-target');
  try {
    const pm = new PendingMarks(hubDir);
    // A legitimate first use creates the real directory...
    await pm.owe('sess-warm');
    await pm.settle('sess-warm');
    // ...then it gets replaced by a symlink to an attacker-writable directory
    // (the scenario: another local account, or a sibling compromised
    // session, can write anywhere under the ledger root).
    await rm(pm.path, { recursive: true, force: true });
    await symlink(evilTarget, pm.path);

    await pm.owe('sess-b');

    const leaked = await readFile(join(evilTarget, 'sess-b'), 'utf8').then(
      () => true,
      () => false,
    );
    assert.equal(leaked, false, 'a symlinked inbox-pending dir must never receive the marker write');
  } finally {
    await rm(hubDir, { recursive: true, force: true });
    await rm(evilTarget, { recursive: true, force: true });
  }
});

test('marker name pre-planted as a symlink to a foreign file — O_NOFOLLOW prevents writing to it', async () => {
  const hubDir = await tmp('filelink');
  const victimDir = await tmp('victim');
  try {
    const victim = join(victimDir, 'do-not-touch.txt');
    await writeFile(victim, 'original content\n', 'utf8');

    const pm = new PendingMarks(hubDir);
    // Pre-create the (safe) directory, then plant the marker FILENAME itself
    // as a symlink to the victim file before the hub ever writes to it.
    await mkdir(pm.path, { recursive: true, mode: 0o700 });
    await chmod(pm.path, 0o700);
    await symlink(victim, join(pm.path, 'sess-c'));

    await pm.owe('sess-c');

    const content = await readFile(victim, 'utf8');
    assert.equal(content, 'original content\n', 'O_NOFOLLOW must stop the write from following the planted symlink');
  } finally {
    await rm(hubDir, { recursive: true, force: true });
    await rm(victimDir, { recursive: true, force: true });
  }
});

test('wrong directory permissions (not 0700) — write refused', async () => {
  const hubDir = await tmp('perms');
  try {
    const pm = new PendingMarks(hubDir);
    await mkdir(pm.path, { recursive: true, mode: 0o700 });
    await chmod(pm.path, 0o755); // group/world-readable — not what the hub created
    await pm.owe('sess-d');
    const leaked = await readFile(join(pm.path, 'sess-d'), 'utf8').then(
      () => true,
      () => false,
    );
    assert.equal(leaked, false, 'a 0755 inbox-pending dir must not be trusted for the write');
  } finally {
    await rm(hubDir, { recursive: true, force: true });
  }
});
