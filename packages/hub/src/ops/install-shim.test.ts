/** Regression — `install.sh`'s `ledger` shim generator embeds
 *  `$REPO`/`$NODE`/`$f` (a matched hook source path) straight into a heredoc
 *  that WRITES a script. Before the fix neither was shell-quoted for the
 *  script being written (only for `install.sh`'s own execution), so a repo
 *  checked out under a path containing `"` or `$` could break the generated
 *  shim's syntax or inject a command that runs on every `ledger` invocation.
 *  Separately, an empty glob match (no `hook*.ts`/`bin.ts` found) used to
 *  leave the freshness check empty, so the generated shim trusted a stale
 *  `dist/hook/bin.js` unconditionally instead of falling back to `.ts`.
 *
 *  This test extracts the actual shim-building block out of `install.sh` (by
 *  marker, not a fixed line range) and runs it standalone with a crafted
 *  `$REPO` — so it exercises the real, current source, never a
 *  reimplementation, without running the rest of the installer (no pnpm,
 *  gitleaks, service manager, and no real home directory ever touched). */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const INSTALL_SH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  '..',
  'install.sh',
);

/** Pulls out `HOOK_SRCS="" … mv "$SHIM.tmp" "$SHIM"` by marker text, not by
 *  line number, so a nearby unrelated edit does not silently de-sync the
 *  test from the file it is meant to exercise. */
async function extractShimBlock(): Promise<string> {
  const src = await readFile(INSTALL_SH, 'utf8');
  const start = src.indexOf('HOOK_SRCS=""');
  assert.notEqual(start, -1, 'HOOK_SRCS="" marker not found in install.sh — did it move/rename?');
  const endMarker = 'mv "$SHIM.tmp" "$SHIM"';
  const endAt = src.indexOf(endMarker, start);
  assert.notEqual(endAt, -1, 'mv "$SHIM.tmp" "$SHIM" marker not found after HOOK_SRCS');
  return src.slice(start, endAt + endMarker.length);
}

function run(script: string, env: NodeJS.ProcessEnv): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn('bash', ['-euo', 'pipefail', '-c', script], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d: Buffer) => (out += d.toString('utf8')));
    child.stderr.on('data', (d: Buffer) => (err += d.toString('utf8')));
    child.on('close', (code) => resolvePromise({ code, out, err }));
  });
}

async function bashSyntaxOk(path: string): Promise<boolean> {
  const res = await run(`bash -n ${shQuote(path)}`, process.env);
  return res.code === 0;
}

/** Single-quote shell escaping for embedding a value as BASH SOURCE (not
 *  JSON) — `JSON.stringify` produces a double-quoted string, and bash still
 *  expands `$(...)`/`$var` INSIDE double quotes, which is exactly the bug
 *  under test. Single quotes disable all expansion; the only character that
 *  needs escaping is `'` itself. */
function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

test('a REPO path with `"` and `$(…)` round-trips through the shim without breaking syntax or injecting', async (t) => {
  const block = await extractShimBlock();
  const base = await mkdtemp(join(tmpdir(), 'agent-ledger-shim-'));
  t.after(() => rm(base, { recursive: true, force: true }));

  // The crafted component is a literal filename — never executed as shell by
  // this test. If the fix regresses, `install.sh` is what would execute it.
  const repo = join(base, 'repo "quoted" $(touch PWNED)');
  await mkdir(join(repo, 'packages/cli/src'), { recursive: true });
  await writeFile(join(repo, 'packages/cli/src/hook-x.ts'), '// stub\n');
  await writeFile(join(repo, 'packages/cli/src/bin.ts'), '// stub\n');

  const stubNode = join(base, 'fake-node');
  const captured = join(base, 'captured-argv.txt');
  await writeFile(
    stubNode,
    ['#!/usr/bin/env bash', 'printf \'%s\\n\' "$@" > "$CAPTURE_OUT"', ''].join('\n'),
  );
  await chmod(stubNode, 0o755);

  const shim = join(base, 'ledger');
  const harness = ['set -euo pipefail', `REPO=${shQuote(repo)}`, `NODE=${shQuote(stubNode)}`, `SHIM=${shQuote(shim)}`, block].join('\n');

  const res = await run(harness, { ...process.env, PATH: process.env.PATH ?? '' });
  assert.equal(res.code, 0, `shim generation failed: ${res.err}`);
  assert.equal(await bashSyntaxOk(shim), true, 'generated shim must be syntactically valid bash');

  // Run the generated shim itself (not a stand-in) with the crafted repo in
  // play. `dist/hook/bin.js` does not exist, so this exercises the final
  // `.ts` fallback `exec` line — the one that embeds `$REPO` directly.
  await run(`CAPTURE_OUT=${shQuote(captured)} ${shQuote(shim)} some-arg`, {
    ...process.env,
  });

  const pwned = await readFile(join(base, 'PWNED')).then(
    () => true,
    () => false,
  );
  assert.equal(pwned, false, 'the crafted $(touch PWNED) in the path must never execute');

  const argv = (await readFile(captured, 'utf8')).trim().split('\n');
  assert.deepEqual(
    argv,
    [join(repo, 'packages/cli/src/bin.ts'), 'some-arg'],
    'the crafted path must reach the shim as ONE exact, unmangled argument',
  );
});

test('an empty source glob falls back to .ts, never trusts a stale dist/hook/bin.js', async (t) => {
  const block = await extractShimBlock();
  const base = await mkdtemp(join(tmpdir(), 'agent-ledger-shim-empty-'));
  t.after(() => rm(base, { recursive: true, force: true }));

  const repo = join(base, 'repo');
  // No packages/cli/src/hook*.ts, no bin.ts — the glob matches nothing.
  await mkdir(join(repo, 'packages/cli/dist/hook'), { recursive: true });
  // A "stale" dist build IS present — this is exactly the case the old code
  // would have trusted unconditionally (no sources → no freshness checks →
  // the `if` always won).
  await writeFile(join(repo, 'packages/cli/dist/hook/bin.js'), '// stale\n');

  const stubNode = join(base, 'fake-node');
  const captured = join(base, 'captured-argv.txt');
  await writeFile(
    stubNode,
    ['#!/usr/bin/env bash', 'printf \'%s\\n\' "$@" > "$CAPTURE_OUT"', ''].join('\n'),
  );
  await chmod(stubNode, 0o755);

  const shim = join(base, 'ledger');
  const harness = ['set -euo pipefail', `REPO=${shQuote(repo)}`, `NODE=${shQuote(stubNode)}`, `SHIM=${shQuote(shim)}`, block].join('\n');

  const res = await run(harness, { ...process.env });
  assert.equal(res.code, 0, `shim generation failed: ${res.err}`);
  assert.equal(await bashSyntaxOk(shim), true);

  const content = await readFile(shim, 'utf8');
  assert.equal(content.includes('dist/hook/bin.js'), false, 'empty glob must not offer the dist fast path at all');
  assert.match(content, /^# agent-ledger shim/m, 'uninstall.sh recognises the generated shim by this marker');

  await run(`CAPTURE_OUT=${shQuote(captured)} ${shQuote(shim)} hook`, {
    ...process.env,
  });
  const argv = (await readFile(captured, 'utf8')).trim().split('\n');
  assert.deepEqual(
    argv,
    [join(repo, 'packages/cli/src/bin.ts'), 'hook'],
    'with no sources found, the shim must run the .ts entry, never the stale dist build',
  );
});
