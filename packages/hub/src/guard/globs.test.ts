/** Glob matching + attribution exclusions (SPEC §10.3, §10.11). */

import assert from 'node:assert/strict';
import test from 'node:test';
import { isExcludedPath, isLedgerContextFile, matchAny, matchGlob } from './globs.ts';

test('matchGlob: `**` crosses `/`, `*` does not', () => {
  assert.equal(matchGlob('apps/server/src/auth/**', 'apps/server/src/auth/guard.ts'), true);
  assert.equal(matchGlob('apps/server/src/auth/**', 'apps/server/src/auth/deep/x/y.ts'), true);
  assert.equal(matchGlob('apps/server/src/auth/**', 'apps/server/src/user.ts'), false);
  assert.equal(matchGlob('src/*.ts', 'src/a.ts'), true);
  assert.equal(matchGlob('src/*.ts', 'src/deep/a.ts'), false);
  assert.equal(matchGlob('src/**/*.ts', 'src/a.ts'), true, '`**/` must also match zero levels');
  assert.equal(matchGlob('src/**/*.ts', 'src/deep/a.ts'), true);
});

test('matchGlob: a concrete path matches itself and as a directory prefix', () => {
  assert.equal(matchGlob('src/auth.ts', 'src/auth.ts'), true);
  assert.equal(matchGlob('src/auth.ts', 'src/auth.tsx'), false);
  assert.equal(matchGlob('src', 'src/a/b.ts'), true, 'a bare directory = the whole subtree');
  assert.equal(matchGlob('src/', 'src/a/b.ts'), true);
  assert.equal(matchGlob('src', 'srcx/a.ts'), false, 'the prefix must not be merely textual');
});

test('matchGlob: `?`, character class, leading `./` and `/`', () => {
  assert.equal(matchGlob('a?.ts', 'ab.ts'), true);
  assert.equal(matchGlob('a?.ts', 'a/b.ts'), false);
  assert.equal(matchGlob('[ab]/x.ts', 'a/x.ts'), true);
  assert.equal(matchGlob('[ab]/x.ts', 'c/x.ts'), false);
  assert.equal(matchGlob('./src/a.ts', 'src/a.ts'), true);
  assert.equal(matchGlob('/src/a.ts', 'src/a.ts'), true);
});

test('H4: `**` backtracks to the last wildcard when the literal segment after it fails', () => {
  assert.equal(matchGlob('a/**/b', 'a/b/c/b'), true);
  assert.equal(matchGlob('packages/**/src', 'packages/x/y/src'), true);
  assert.equal(matchGlob('a/**/b', 'a/x'), false, 'must not match without the final `b`');
  const start = performance.now();
  matchGlob('a*a*a*a*a*a*a*a*a*a*a*b', 'a'.repeat(40) + 'c');
  assert.ok(performance.now() - start < 5, 'a pathological pattern must finish under 5 ms');
});

test('matchGlob: regex metacharacters in a path are literals, not a pattern', () => {
  assert.equal(matchGlob('a.b.ts', 'axbxts'), false, '`.` must not mean "anything"');
  assert.equal(matchGlob('a+b.ts', 'a+b.ts'), true);
  assert.equal(matchGlob('(x)/y.ts', '(x)/y.ts'), true);
  assert.equal(matchGlob('a$b.ts', 'a$b.ts'), true);
});

test('matchGlob: a nonsensical or oversized pattern matches nothing', () => {
  assert.equal(matchGlob('', 'a.ts'), false);
  assert.equal(matchGlob('   ', 'a.ts'), false);
  assert.equal(matchGlob('/', 'a.ts'), false);
  assert.equal(matchGlob('x'.repeat(400), 'a.ts'), false);
});

test('matchAny: returns the first matching pattern (for the deny reason text)', () => {
  assert.equal(matchAny(['docs/**', 'src/**'], 'src/a.ts'), 'src/**');
  assert.equal(matchAny(['docs/**'], 'src/a.ts'), null);
});

test('isExcludedPath: ledger, temp and scratchpads are not attributed', () => {
  const opts = { ledgerRoot: '/home/user/.ledger', excludeTemp: true };
  assert.equal(isExcludedPath('/home/user/.ledger/acme/items/ACME-1.md', opts), true);
  assert.equal(isExcludedPath('/home/user/.ledger', opts), true);
  assert.equal(isExcludedPath('/home/user/.ledger-other/a.ts', opts), false, 'prefix != directory');
  assert.equal(isExcludedPath('/tmp/x.ts', opts), true);
  assert.equal(isExcludedPath('/private/tmp/claude-501/x/scratchpad/a.ts', opts), true);
  assert.equal(isExcludedPath('/private/var/folders/ab/cd/T/agent-ledger-x/a.ts', opts), true);
  assert.equal(isExcludedPath('/var/folders/ab/cd/T/x/a.ts', opts), true);
  assert.equal(isExcludedPath('/home/user/projects/acme/a.ts', opts), false);
  assert.equal(isExcludedPath('/home/user/projects/p/scratchpad/a.ts', opts), true, 'scratchpad anywhere');
});

test('isExcludedPath: without excludeTemp, temp repos pass (test fixtures)', () => {
  const opts = { ledgerRoot: '/home/user/.ledger', excludeTemp: false };
  assert.equal(isExcludedPath('/var/folders/ab/cd/T/agent-ledger-x/a.ts', opts), false);
  assert.equal(isExcludedPath('/home/user/.ledger/a.md', opts), true, 'the ledger always applies');
  assert.equal(isExcludedPath('', opts), true);
});

test('isLedgerContextFile: CONTEXT.md is the only exception to rule 1', () => {
  const root = '/l';
  assert.equal(isLedgerContextFile('/l/acme/CONTEXT.md', root), true);
  assert.equal(isLedgerContextFile('/l/acme/DECISIONS.md', root), false);
  assert.equal(isLedgerContextFile('/l/acme/CONTEXT.md.bak', root), false);
  // S4: exactly `<ledger>/<repo>/CONTEXT.md`, nothing shallower or deeper.
  assert.equal(isLedgerContextFile('/l/CONTEXT.md', root), false, 'missing repo segment');
  assert.equal(isLedgerContextFile('/l/.hub/CONTEXT.md', root), false, 'a hidden repo is not a repo');
  assert.equal(isLedgerContextFile('/l/acme/sub/CONTEXT.md', root), false, 'too deep');
});

test('S2: pathological patterns finish in ms — the matcher is not a regex', () => {
  // Exactly the shapes the re-audit measured on the regex version:
  //   `a*a*…b` → 7,8 s · `(*?)×11 b` → 14 s · `a**a**…b` → 79 s.
  const cases: [string, string][] = [
    [`${'**/'.repeat(30)}x`, `${'a/'.repeat(60)}y`],
    [`${'a*'.repeat(11)}b`, 'a'.repeat(40)],
    [`${'*?'.repeat(11)}b`, 'a'.repeat(40)],
    [`${'a**'.repeat(11)}b`, 'a'.repeat(60)],
    [`${'*'.repeat(50)}b`, 'a'.repeat(200)],
    [`${'[ab]*'.repeat(20)}c`, 'ab'.repeat(60)],
  ];
  for (const [pattern, path] of cases) {
    const start = performance.now();
    assert.equal(matchGlob(pattern, path), false, `${pattern.slice(0, 24)}… must not match`);
    const ms = performance.now() - start;
    assert.ok(ms < 200, `${pattern.slice(0, 24)}… took ${Math.round(ms)} ms`);
  }
});

test('S2: a complex pattern is NOT dropped — "matches nothing" would be fail-open', () => {
  // A claim with 20 wildcards must still protect its files; if the matcher
  // dropped it as "too complex", the guard would stop guarding that file.
  const pattern = `${'*/'.repeat(20)}auth.ts`;
  assert.equal(matchGlob(pattern, `${'x/'.repeat(20)}auth.ts`), true);
  assert.equal(matchGlob(`${'**/'.repeat(30)}x`, `${'a/'.repeat(5)}x`), true, 'semantics preserved');
  assert.equal(matchGlob('**/x', `${'a/'.repeat(5)}x`), true, 'equivalent without repetition');
});

test('S2: `**` across levels, `[!…]` and ranges in a class', () => {
  assert.equal(matchGlob('a/**/b', 'a/b'), true, '`**` also matches zero levels');
  assert.equal(matchGlob('a/**/b', 'a/x/y/b'), true);
  assert.equal(matchGlob('a/**/b', 'a/x/y/c'), false);
  assert.equal(matchGlob('a/**', 'a'), true, 'a trailing `**` also matches the directory itself');
  assert.equal(matchGlob('[!x]/a.ts', 'y/a.ts'), true);
  assert.equal(matchGlob('[!x]/a.ts', 'x/a.ts'), false);
  assert.equal(matchGlob('[a-c]/a.ts', 'b/a.ts'), true);
  assert.equal(matchGlob('[a-c]/a.ts', 'd/a.ts'), false);
  assert.equal(matchGlob('a[.ts', 'a[.ts'), true, 'an unclosed class is a literal');
});
