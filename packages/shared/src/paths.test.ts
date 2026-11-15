import assert from 'node:assert/strict';
import test from 'node:test';
import { defaultLedgerDir, expandHome, samePath, spoolDir } from './paths.ts';

const win = { platform: 'win32' as const, homedir: () => 'C:\\Users\\Ann' };
const lin = { platform: 'linux' as const, homedir: () => '/home/ann' };

test('expandHome: posix ~ and ~/ only; ~\\ is not special', () => {
  assert.equal(expandHome('~', lin), '/home/ann');
  assert.equal(expandHome('~/x/y', lin), '/home/ann/x/y');
  assert.equal(expandHome('/abs', lin), '/abs');
  assert.throws(() => expandHome('~\\x', lin), /~user/);
});

test('expandHome: win32 accepts ~, ~/ and ~\\', () => {
  assert.equal(expandHome('~', win), 'C:\\Users\\Ann');
  assert.equal(expandHome('~\\.ledger', win), 'C:\\Users\\Ann\\.ledger');
  assert.equal(expandHome('~/.ledger', win), 'C:\\Users\\Ann\\.ledger');
  assert.equal(expandHome('D:\\data', win), 'D:\\data');
});

test('expandHome refuses ~user on every platform', () => {
  assert.throws(() => expandHome('~bob/x', lin));
  assert.throws(() => expandHome('~bob\\x', win));
});

test('defaultLedgerDir', () => {
  assert.equal(defaultLedgerDir(lin), '/home/ann/.ledger');
  assert.equal(defaultLedgerDir(win), 'C:\\Users\\Ann\\.ledger');
});

test('spoolDir win32: LOCALAPPDATA under home is used', () => {
  assert.equal(
    spoolDir({ LOCALAPPDATA: 'C:\\Users\\Ann\\AppData\\Local' }, win),
    'C:\\Users\\Ann\\AppData\\Local\\agent-ledger\\spool',
  );
  // case-insensitive "under home"
  assert.equal(
    spoolDir({ LOCALAPPDATA: 'c:\\users\\ann\\AppData\\Local' }, win),
    'c:\\users\\ann\\AppData\\Local\\agent-ledger\\spool',
  );
});

test('spoolDir win32: relative, foreign-drive-root, sibling-prefix or missing LOCALAPPDATA fall back to home', () => {
  const fallback = 'C:\\Users\\Ann\\AppData\\Local\\agent-ledger\\spool';
  for (const bad of ['AppData\\Local', '\\Temp', 'C:\\Users\\Anna\\AppData\\Local', 'D:\\Public\\x', '', undefined]) {
    assert.equal(spoolDir({ LOCALAPPDATA: bad }, win), fallback, String(bad));
  }
  assert.equal(spoolDir({}, win), fallback);
});

test('spoolDir win32: LEDGER_SPOOL_DIR wins and expands ~\\', () => {
  assert.equal(spoolDir({ LEDGER_SPOOL_DIR: '~\\sp' }, win), 'C:\\Users\\Ann\\sp');
});

test('spoolDir posix keeps XDG exactly', () => {
  assert.equal(spoolDir({ XDG_STATE_HOME: '/s' }, lin), '/s/agent-ledger/spool');
  assert.equal(spoolDir({ XDG_STATE_HOME: 'rel' }, lin), '/home/ann/.local/state/agent-ledger/spool');
  assert.equal(spoolDir({}, lin), '/home/ann/.local/state/agent-ledger/spool');
  assert.equal(spoolDir({ LEDGER_SPOOL_DIR: '/x' }, lin), '/x');
});

test('samePath win32: casefold, separators, trailing slash', () => {
  const w = { platform: 'win32' as const };
  assert.ok(samePath('C:\\Repo\\Src', 'c:/repo/src/', w));
  assert.ok(samePath('C:\\Repo\\a\\..\\Src', 'C:\\repo\\SRC', w));
  assert.ok(samePath('C:\\', 'c:/', w));
  assert.ok(!samePath('C:\\Repo', 'C:\\Repo2', w));
  assert.ok(!samePath('C:\\Repo', 'D:\\Repo', w));
});

test('samePath posix: case-sensitive, normalised', () => {
  const p = { platform: 'linux' as const };
  assert.ok(samePath('/a/b/', '/a/b', p));
  assert.ok(samePath('/a/./b', '/a/b', p));
  assert.ok(!samePath('/a/B', '/a/b', p));
});
