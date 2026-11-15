/**
 * I1 grep test: `process.getuid` and `O_NOFOLLOW` are trust primitives that only
 * `platformTrust` (and win-ps) may touch; everywhere else must go through its API so a
 * missing uid / missing flag is a refusal, not a silent pass.
 *
 * Comments are stripped before matching. Every remaining legitimate use is in ALLOWED
 * with the reason; entries marked TODO are migration work that is still open.
 */
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url)); // <repo>/packages
const PATTERN = /process\.getuid|O_NOFOLLOW/;

const ALLOWED: Record<string, string> = {
  'shared/src/platformTrust.ts': 'the one place (I1)',
  'hub/src/safeRead.ts':
    'non-private (user-owned ~/.claude) read-open: openPrivate would probe/create files there. ' +
    'win32 branch uses lstat/fstat/lstat identity and the POSIX branch fails closed when the flag is undefined. ' +
    'TODO: platformTrust.openNoFollowRead, then drop this entry',
  'cli/src/selfheal.ts': 'TODO(B6): migrate to platformTrust.openPrivate / isOwnedByMe',
  'cli/src/doctor.ts': 'TODO(B6): migrate to platformTrust.isOwnedByMe',
};

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
}

async function* walk(dir: string): AsyncGenerator<string> {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (/\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name)) yield p;
  }
}

test('I1: no process.getuid / O_NOFOLLOW outside platformTrust (allowlist is explicit)', async () => {
  const offenders: string[] = [];
  const seen = new Set<string>();
  for (const pkg of await readdir(ROOT)) {
    const src = join(ROOT, pkg, 'src');
    try {
      for await (const file of walk(src)) {
        const rel = relative(ROOT, file).split(sep).join('/');
        if (!PATTERN.test(stripComments(await readFile(file, 'utf8')))) continue;
        seen.add(rel);
        if (!(rel in ALLOWED)) offenders.push(rel);
      }
    } catch {
      /* package without src/ */
    }
  }
  assert.deepEqual(offenders, [], 'route trust decisions through @agent-ledger/shared platformTrust');
  // A stale allowlist entry hides nothing but rots: once migrated, the entry must go.
  const stale = Object.keys(ALLOWED).filter((k) => !seen.has(k));
  assert.deepEqual(stale, [], 'remove migrated files from ALLOWED');
});
