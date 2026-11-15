/** Glob matching + attribution exclusions (SPEC §10.3, §10.11). */

import assert from 'node:assert/strict';
import test from 'node:test';
import nodePath from 'node:path';
import {
  canonicalRel,
  checkoutCaseInsensitive,
  isExcludedPath,
  isLedgerContextFile,
  matchAny,
  matchGlob,
  resetCaseCache,
} from './globs.ts';

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

/* ---------------- S8 / T11: canonicalRel + case-insensitive claim matching ---------------- */

/** Fake `realpath.native` of a case-insensitive Windows volume: lookup folds case, answer keeps the on-disk spelling. */
function winFs(entries: Record<string, string>): (p: string) => Promise<string> {
  const norm = (p: string): string => nodePath.win32.normalize(p).replace(/[\\/]+$/, '').toLowerCase();
  const table = new Map(Object.entries(entries).map(([k, v]) => [norm(k), v]));
  return async (p) => {
    const hit = table.get(norm(p));
    if (hit === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    return hit;
  };
}

const WIN_FS = winFs({
  'C:\\repo': 'C:\\repo',
  'C:\\': 'C:\\',
  'C:\\repo\\src': 'C:\\repo\\Src',
  'C:\\repo\\src\\auth': 'C:\\repo\\Src\\Auth',
  'C:\\repo\\src\\auth\\x.ts': 'C:\\repo\\Src\\Auth\\x.ts',
  'C:\\repo\\caf\u00e9.ts': 'C:\\repo\\cafe\u0301.ts',
  'C:\\repo\\progra~1': 'C:\\repo\\Program Files',
  'C:\\repo\\link': 'D:\\elsewhere',
  'C:\\repo\\link\\x.ts': 'D:\\elsewhere\\x.ts',
});
const win = { platform: 'win32' as const, realpath: WIN_FS };

test('S8 canonicalRel(win32): on-disk casing, NFC, relative input joined to the checkout', async () => {
  assert.deepEqual(await canonicalRel('C:\\repo', 'c:\\REPO\\src\\auth\\X.TS', win), { ok: true, rel: 'Src/Auth/x.ts' });
  assert.deepEqual(await canonicalRel('C:\\repo', 'src\\auth\\x.ts', win), { ok: true, rel: 'Src/Auth/x.ts' });
  // decomposed é on disk -> composed in the canonical spelling
  assert.deepEqual(await canonicalRel('C:\\repo', 'C:\\repo\\caf\u00e9.ts', win), { ok: true, rel: 'caf\u00e9.ts' });
  // 8.3 alias of an EXISTING file is resolved by the OS to the long name
  assert.deepEqual(await canonicalRel('C:\\repo', 'C:\\repo\\PROGRA~1', win), { ok: true, rel: 'Program Files' });
  // a new file: nearest existing ancestor + tail
  assert.deepEqual(await canonicalRel('C:\\repo', 'C:\\repo\\src\\auth\\new.ts', win), { ok: true, rel: 'Src/Auth/new.ts' });
  assert.deepEqual(await canonicalRel('C:\\repo', 'C:\\repo', win), { ok: true, rel: '' });
});

test('S8 canonicalRel(win32): ADS, trailing dot/space, device names, namespaces, short names, escapes are refused', async () => {
  const refused = [
    'C:\\repo\\a.ts::$DATA',
    'C:\\repo\\a.ts:evil',
    'C:\\repo\\src\\auth\\x.ts::$DATA',
    'C:\\repo\\a.ts.',
    'C:\\repo\\a.ts ',
    'C:\\repo\\src\\auth.\\new.ts',
    'C:\\repo\\CON',
    'C:\\repo\\nul.txt',
    'C:\\repo\\COM1',
    'C:\\repo\\LPT\u00b9.log',
    '\\\\?\\C:\\repo\\a.ts',
    '\\\\.\\C:\\repo\\a.ts',
    'C:\\repo\\NEWFIL~1.TXT',
    'C:evil.ts',
    'C:\\repo\\..\\x',
    'C:\\repo\\src\\..\\..\\x',
    'C:\\repo\\link\\x.ts', // junction out of the checkout
    'C:\\repo\\a<b.ts',
    'C:\\repo\\a\0b.ts',
    '',
  ];
  for (const p of refused) {
    const r = await canonicalRel('C:\\repo', p, win);
    assert.equal(r.ok, false, JSON.stringify(p));
  }
});

test('S8 canonicalRel(posix): colons/device names are ordinary names; escape and `..` tails are still refused', async () => {
  const entries = new Set(['/r', '/r/src']);
  // Like the OS: every component must exist before a following `..` is applied.
  const realpath = async (p: string): Promise<string> => {
    let cur = '';
    for (const seg of p.split('/').filter((x) => x !== '')) {
      if (seg === '..') {
        cur = nodePath.posix.dirname(cur) === '.' ? '' : nodePath.posix.dirname(cur);
        continue;
      }
      const next = `${cur}/${seg}`;
      if (!entries.has(next)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      cur = next;
    }
    return cur === '' ? '/' : cur;
  };
  const deps = { platform: 'linux' as const, realpath };
  assert.deepEqual(await canonicalRel('/r', '/r/src/a:b.ts', deps), { ok: true, rel: 'src/a:b.ts' });
  assert.deepEqual(await canonicalRel('/r', '/r/CON', deps), { ok: true, rel: 'CON' });
  assert.equal((await canonicalRel('/r', '/elsewhere/x', deps)).ok, false);
  assert.equal((await canonicalRel('/r', '/r/nope/../../x', deps)).ok, false);
  assert.equal((await canonicalRel('/r', '/r/nope/../y', deps)).ok, false, '`..` after a missing dir is not resolved lexically');
});

test('T11: claim `src/auth/**` blocks `SRC/Auth/x.ts` only on a case-insensitive volume', () => {
  assert.equal(matchGlob('src/auth/**', 'SRC/Auth/x.ts'), false, 'case-sensitive volume: exact');
  assert.equal(matchGlob('src/auth/**', 'SRC/Auth/x.ts', { caseInsensitive: true }), true);
  assert.equal(matchGlob('SRC/AUTH/**', 'src/auth/x.ts', { caseInsensitive: true }), true);
  assert.equal(matchGlob('src/[A-C]*.ts', 'src/Bar.ts', { caseInsensitive: true }), true);
  assert.equal(matchAny(['docs/**', 'Src/Auth'], 'src/auth/deep/x.ts', { caseInsensitive: true }), 'Src/Auth');
  // NFD on one side, NFC on the other: the same name
  assert.equal(matchGlob('docs/caf\u00e9.md', 'docs/cafe\u0301.md'), true);
  assert.equal(matchGlob('docs/cafe\u0301.md', 'docs/caf\u00e9.md'), true);
  // folding never turns a different name into a match
  assert.equal(matchGlob('src/auth/**', 'src/author/x.ts', { caseInsensitive: true }), false);
});

test('S8 checkoutCaseInsensitive: cached 10 min, clock jumps re-probe, probe failure => true (widens claims only)', async () => {
  resetCaseCache();
  let calls = 0;
  let t = 1_000_000;
  const o = { now: () => t, probe: async () => (calls += 1, false) };
  assert.equal(await checkoutCaseInsensitive('/c1', o), false);
  assert.equal(await checkoutCaseInsensitive('/c1', o), false);
  assert.equal(calls, 1);
  t += 11 * 60 * 1000;
  await checkoutCaseInsensitive('/c1', o);
  assert.equal(calls, 2);
  t -= 60 * 60 * 1000; // clock jumped back an hour
  await checkoutCaseInsensitive('/c1', o);
  assert.equal(calls, 3);
  const boom = { now: () => t, probe: async (): Promise<boolean> => { throw new Error('x'); } };
  assert.equal(await checkoutCaseInsensitive('/c2', boom), true);
  resetCaseCache();
});
