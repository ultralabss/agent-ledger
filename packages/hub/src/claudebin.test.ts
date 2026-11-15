/** S6 / T6: on win32 only a native claude.exe is accepted; shims are refused before any spawn. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { claudeBinBlockReason, nativeClaudeExeError, resolveClaudeBin } from './claudebin.ts';

const SHIMS = [
  'C:\\Users\\me\\AppData\\Roaming\\npm\\claude.cmd',
  'C:\\tools\\claude.CMD',
  'C:\\tools\\claude.bat',
  'C:\\tools\\claude.ps1',
  'C:\\tools\\claude.com',
];
const NOT_EXE = ['C:\\tools\\claude', 'C:\\tools\\claude.exe.', 'C:\\tools\\claude.exe ', 'C:\\tools\\claude.exe::$DATA', 'C:\\tools\\claude.exe.cmd'];

test('nativeClaudeExeError: win32 refuses .cmd/.bat/.ps1 with a fix hint, accepts *.exe only', () => {
  for (const p of SHIMS) {
    const msg = nativeClaudeExeError(p, 'win32');
    assert.ok(msg !== null, p);
    assert.match(msg, /claude\.exe/);
    assert.match(msg, /LEDGER_CLAUDE_BIN/);
  }
  for (const p of NOT_EXE) assert.ok(nativeClaudeExeError(p, 'win32') !== null, p);
  assert.equal(nativeClaudeExeError('C:\\tools\\claude.exe', 'win32'), null);
  assert.equal(nativeClaudeExeError('C:\\tools\\CLAUDE.EXE', 'win32'), null);
});

test('nativeClaudeExeError: POSIX behaviour is unchanged (never refuses on extension)', () => {
  for (const p of ['/usr/local/bin/claude', '/x/claude.cmd', '/x/claude.sh']) {
    assert.equal(nativeClaudeExeError(p, 'linux'), null);
    assert.equal(nativeClaudeExeError(p, 'darwin'), null);
  }
});

test('resolveClaudeBin(win32): a shim is untrusted before any filesystem trust walk, no opt-in overrides', async () => {
  for (const p of SHIMS) {
    for (const opts of [{}, { trustGroup: true, pin: { gid: 1, realpath: p } }]) {
      const st = await resolveClaudeBin(p, { platform: 'win32', ...opts });
      assert.equal(st.state, 'untrusted', p);
      assert.equal(st.path, null);
      assert.match(st.detail ?? '', /claude\.exe/);
      assert.match(claudeBinBlockReason(st) ?? '', /not trusted/);
    }
  }
});

test('resolveClaudeBin(win32): a *.exe passes the extension gate (trust walk decides the rest)', async () => {
  const st = await resolveClaudeBin('C:\\definitely\\not\\there\\claude.exe', { platform: 'win32' });
  assert.notEqual(st.detail ?? '', nativeClaudeExeError('C:\\definitely\\not\\there\\claude.exe', 'win32'));
  assert.equal(st.path, null, 'a missing binary is never ok');
});
