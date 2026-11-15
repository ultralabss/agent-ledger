/** S9 / T9: shim path validator table + crtQuoteArg round-trip against a CommandLineToArgvW reference. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { assertShimSafePath, crtQuoteArg, crtQuoteArgv, WIN_MAX_PATH_CHARS } from './winquote.ts';

/**
 * Reference parser, written from the documented CommandLineToArgvW / MSVC rules (not from our
 * quoter): 2n backslashes + `"` -> n backslashes and toggle quote mode; 2n+1 -> n backslashes and a
 * literal quote; backslashes elsewhere are literal; inside quotes a `"` directly followed by `"` is a
 * literal quote (post-2008 rule); space/tab outside quotes separate arguments.
 */
function commandLineToArgv(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inArg = false;
  let inQuote = false;
  let i = 0;
  while (i < line.length) {
    const c = line[i] as string;
    if (c === '\\') {
      let n = 0;
      while (line[i] === '\\') {
        n += 1;
        i += 1;
      }
      inArg = true;
      if (line[i] === '"') {
        cur += '\\'.repeat(Math.floor(n / 2));
        if (n % 2 === 1) {
          cur += '"';
          i += 1;
        }
        // even: the quote is processed by the next loop turn as a toggle
      } else {
        cur += '\\'.repeat(n);
      }
      continue;
    }
    if (c === '"') {
      inArg = true;
      if (inQuote && line[i + 1] === '"') {
        cur += '"';
        i += 2;
        continue;
      }
      inQuote = !inQuote;
      i += 1;
      continue;
    }
    if ((c === ' ' || c === '\t') && !inQuote) {
      if (inArg) out.push(cur);
      cur = '';
      inArg = false;
      i += 1;
      continue;
    }
    inArg = true;
    cur += c;
    i += 1;
  }
  if (inArg) out.push(cur);
  return out;
}

test('reference parser sanity (documented examples)', () => {
  assert.deepEqual(commandLineToArgv('a "b c" d'), ['a', 'b c', 'd']);
  assert.deepEqual(commandLineToArgv('"a\\\\b c" d'), ['a\\\\b c', 'd']);
  assert.deepEqual(commandLineToArgv('"a\\\\\\"b" c'), ['a\\"b', 'c']);
  assert.deepEqual(commandLineToArgv('a\\\\\\"b c'), ['a\\"b', 'c']);
  assert.deepEqual(commandLineToArgv('"\\\\\\\\" x'), ['\\\\', 'x']);
  assert.deepEqual(commandLineToArgv('""'), ['']);
});

test('crtQuoteArg: golden outputs', () => {
  assert.equal(crtQuoteArg(''), '""');
  assert.equal(crtQuoteArg('abc'), 'abc');
  assert.equal(crtQuoteArg('C:\\dir\\file.exe'), 'C:\\dir\\file.exe');
  assert.equal(crtQuoteArg('C:\\dir\\'), 'C:\\dir\\', 'no quoting needed => backslashes untouched');
  assert.equal(crtQuoteArg('a b'), '"a b"');
  assert.equal(crtQuoteArg('C:\\Program Files\\x\\'), '"C:\\Program Files\\x\\\\"');
  assert.equal(crtQuoteArg('say "hi"'), '"say \\"hi\\""');
  assert.equal(crtQuoteArg('a\\"b'), '"a\\\\\\"b"');
  assert.equal(crtQuoteArg('a&b|c^d%e!'), 'a&b|c^d%e!', 'cmd metacharacters are not the CRT quoter\'s job');
  assert.equal(crtQuoteArgv(['x.exe', 'a b', '']), 'x.exe "a b" ""');
});

test('crtQuoteArg: refuses NUL / CR / LF', () => {
  for (const bad of ['a\0b', 'a\nb', 'a\rb']) assert.throws(() => crtQuoteArg(bad), RangeError);
  assert.throws(() => crtQuoteArg(5 as unknown as string), TypeError);
});

test('crtQuoteArg round-trips through the CommandLineToArgvW reference: exhaustive short strings', () => {
  const alphabet = ['a', ' ', '\t', '"', '\\', '&', '%', '^'];
  let checked = 0;
  const walk = (prefix: string, depth: number): void => {
    // every string up to length 6 over the alphabet
    const argv = ['prog.exe', prefix, 'tail'];
    const parsed = commandLineToArgv(crtQuoteArgv(argv));
    assert.deepEqual(parsed, argv, JSON.stringify(prefix));
    checked += 1;
    if (depth === 0) return;
    for (const ch of alphabet) walk(prefix + ch, depth - 1);
  };
  walk('', 6);
  assert.ok(checked > 40_000);
});

test('crtQuoteArg round-trips: realistic and hostile paths, many args at once', () => {
  const argv = [
    'C:\\Program Files\\nodejs\\node.exe',
    'C:\\Users\\Jane Doe\\AppData\\Local\\agent-ledger\\bin.ts',
    '--flag=C:\\a b\\c\\',
    'C:\\trailing\\\\',
    '"quoted"',
    '\\"',
    '\\\\"',
    'a"b c"d',
    '',
    ' ',
    '\\\\server\\share\\dir with space\\',
    'x\\\\\\"y z\\\\',
  ];
  assert.deepEqual(commandLineToArgv(crtQuoteArgv(argv)), argv);
  // random fuzz, deterministic LCG
  let seed = 12345;
  const rnd = (n: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  const chars = ['a', 'b', ' ', '\t', '"', '\\', '\\', '\\', '&', '%', '!', '^', '(', ')', ';', 'é'];
  for (let i = 0; i < 2000; i += 1) {
    const args = Array.from({ length: 1 + rnd(4) }, () =>
      Array.from({ length: rnd(12) }, () => chars[rnd(chars.length)] as string).join(''),
    );
    assert.deepEqual(commandLineToArgv(crtQuoteArgv(args)), args, JSON.stringify(args));
  }
});

test('assertShimSafePath: accepts ordinary absolute paths (spaces, parens, & ^ are fine inside quotes)', () => {
  for (const ok of [
    'C:\\Users\\Jane Doe\\AppData\\Local\\agent-ledger\\bin\\ledger.cmd',
    'C:\\Program Files (x86)\\nodejs\\node.exe',
    'D:\\Dev & Co\\a^b\\x.ts',
    'C:\\Users\\Zo\u00eb\\x',
    '\\\\server\\share\\x',
  ]) {
    assert.doesNotThrow(() => assertShimSafePath(ok), ok);
  }
});

test('assertShimSafePath: refuses %, !, ", CR/LF/controls, invisible/bidi, empty, non-string, unpaired surrogate', () => {
  const bad: unknown[] = [
    'C:\\Users\\%USERNAME%\\x',
    'C:\\a%b',
    'C:\\hello!\\x',
    'C:\\a"b',
    'C:\\a\nb',
    'C:\\a\rb',
    'C:\\a\0b',
    'C:\\a\tb',
    'C:\\a\u007fb',
    'C:\\a\u0085b',
    'C:\\a\u202eb',
    'C:\\a\u200bb',
    'C:\\a\ufeffb',
    'C:\\a\u2028b',
    'C:\\a\ud800b',
    '',
    undefined,
    null,
    42,
    ['C:\\x'],
  ];
  for (const b of bad) assert.throws(() => assertShimSafePath(b), RangeError, JSON.stringify(b));
});

test('assertShimSafePath: length limit, lifted only by longPaths', () => {
  const at = `C:\\${'a'.repeat(WIN_MAX_PATH_CHARS - 3)}`;
  assert.equal(at.length, WIN_MAX_PATH_CHARS);
  assert.doesNotThrow(() => assertShimSafePath(at));
  const over = `${at}a`;
  assert.throws(() => assertShimSafePath(over), RangeError);
  assert.doesNotThrow(() => assertShimSafePath(over, { longPaths: true }));
  assert.throws(() => assertShimSafePath(`C:\\${'a'.repeat(40_000)}`, { longPaths: true }), RangeError);
  // longPaths never lifts the character rules
  assert.throws(() => assertShimSafePath('C:\\%x%', { longPaths: true }), RangeError);
});
