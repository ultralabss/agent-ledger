/** Regression test for UL-669 T1: repo-local gpg.program must never run on `git log`. */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { git } from './git.ts';
import { readCommits, readCommitsSince } from './gitreader.ts';

const run = (cwd: string, args: string[], input?: string): string =>
  execFileSync('git', args, {
    cwd,
    input,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 't',
      GIT_AUTHOR_EMAIL: 't@example.com',
      GIT_COMMITTER_NAME: 't',
      GIT_COMMITTER_EMAIL: 't@example.com',
    },
  }).trim();

test('T1: log.showSignature + gpg.program in repo config does not execute', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-t1-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  run(dir, ['init', '-q']);
  const marker = join(dir, 'PWNED');
  const script = join(dir, 'evil-gpg.sh');
  await writeFile(script, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`, { mode: 0o755 });

  const tree = run(dir, ['hash-object', '-t', 'tree', '-w', '--stdin'], '');
  const raw = run(dir, ['commit-tree', tree, '-m', 'signed']);
  const body = run(dir, ['cat-file', 'commit', raw]);
  const forged = body.replace(
    /\n\n/,
    '\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n forged\n -----END PGP SIGNATURE-----\n\n',
  );
  const sha = run(dir, ['hash-object', '-t', 'commit', '-w', '--stdin'], `${forged}\n`);
  run(dir, ['update-ref', 'refs/heads/main', sha]);
  run(dir, ['symbolic-ref', 'HEAD', 'refs/heads/main']);
  run(dir, ['config', 'log.showSignature', 'true']);
  run(dir, ['config', 'gpg.program', script]);

  // Control: the forged commit really triggers gpg.program with a bare git log.
  try {
    run(dir, ['log', '-1']);
  } catch {
    /* gpg failure is irrelevant */
  }
  await stat(marker); // throws if the fixture does not exercise the vuln
  await rm(marker);

  await readCommitsSince(dir, 0);
  await readCommits(dir, 'HEAD');
  await git(dir, ['log', '-1', '--format=%H']);
  await assert.rejects(stat(marker), { code: 'ENOENT' }, 'gpg.program must not run');
});
