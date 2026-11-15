/** win-ps: input validation, strict output parsing, icacls argv, and the real process runner. */

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertWinPath,
  defaultSpawnFile,
  inspectWindowsPaths,
  parseInspectOutput,
  setPrivateAcl,
  validSystemRoot,
  WinPsError,
  type SpawnFile,
  type SpawnResult,
  type WinPsContext,
} from './win-ps.ts';

const ME = 'S-1-5-21-1111111111-2222222222-3333333333-1001';

test('validSystemRoot: single drive-rooted component only', () => {
  assert.equal(validSystemRoot('C:\\Windows'), 'C:\\Windows');
  assert.equal(validSystemRoot('d:\\WINNT'), 'd:\\WINNT');
  for (const bad of [undefined, '', 'C:\\', 'C:Windows', 'C:\\Windows\\System32', '\\\\h\\s', 'C:\\Win|dows', 'C:\\Windows\n', 'C:\\Win:dows', '/mnt/c/Windows']) {
    assert.throws(() => validSystemRoot(bad), WinPsError, String(bad));
  }
});

test('assertWinPath: absolute drive-rooted, no wildcard / control / stream / device syntax', () => {
  assert.equal(assertWinPath('C:\\Users\\me'), 'C:\\Users\\me');
  assert.equal(assertWinPath('C:\\'), 'C:\\');
  for (const bad of ['', 'C:', 'C:foo', 'foo\\bar', '\\\\srv\\share', '\\\\?\\C:\\x', '\\\\.\\COM1', 'C:\\a*b', 'C:\\a?b', 'C:\\a"b', 'C:\\a<b', 'C:\\a|b', 'C:\\a\u0000b', 'C:\\a\nb', 'C:\\file.txt:stream', '/tmp/x']) {
    assert.throws(() => assertWinPath(bad), WinPsError, JSON.stringify(bad));
  }
  assert.throws(() => assertWinPath(`C:\\${'a'.repeat(5000)}`), WinPsError);
});

const goodEntry = { exists: true, reparse: false, isDir: true, sddl: 'O:SYG:SYD:P', unc: false, driveFormat: 'NTFS', driveType: 'Fixed', error: null };

test('parseInspectOutput: strict shape; one-element list collapsed by PowerShell is accepted', () => {
  const r = parseInspectOutput(JSON.stringify({ sid: ME.toLowerCase(), elevated: false, paths: [goodEntry] }), 1);
  assert.equal(r.sid, ME);
  assert.equal(r.paths[0]?.driveFormat, 'NTFS');
  const one = parseInspectOutput(JSON.stringify({ sid: ME, elevated: true, paths: goodEntry }), 1);
  assert.equal(one.elevated, true);
  assert.equal(one.paths.length, 1);
  const missing = parseInspectOutput(JSON.stringify({ sid: ME, elevated: false, paths: [{ exists: false }] }), 1);
  assert.equal(missing.paths[0]?.sddl, null);
  const bad: unknown[] = [
    'x',
    null,
    {},
    { sid: ME, elevated: 'no', paths: [goodEntry] },
    { sid: 'S-1', elevated: false, paths: [goodEntry] },
    { sid: ME, elevated: false, paths: [] },
    { sid: ME, elevated: false, paths: [goodEntry, goodEntry] },
    { sid: ME, elevated: false, paths: ['x'] },
    { sid: ME, elevated: false, paths: [{ exists: 'yes' }] },
  ];
  for (const b of bad) assert.throws(() => parseInspectOutput(typeof b === 'string' ? b : JSON.stringify(b), 1), WinPsError, JSON.stringify(b));
});

function ctx(spawn: SpawnFile, env: Record<string, string | undefined> = { SystemRoot: 'C:\\Windows' }): WinPsContext {
  return { env, spawnFile: spawn, isFile: async () => true };
}
const okRes = (stdout = '', code = 0): SpawnResult => ({ code, stdout, stderr: '', timedOut: false, truncated: false });

test('inspectWindowsPaths: batch limits, env is minimal and never carries the caller PATH / PSModulePath', async () => {
  let seen: { file: string; env: Record<string, string>; cwd: string; timeoutMs: number; maxBuffer: number } | undefined;
  const spawn: SpawnFile = async (file, _args, opts) => {
    seen = { file, ...opts };
    return okRes(JSON.stringify({ sid: ME, elevated: false, paths: [goodEntry] }));
  };
  const env = { SystemRoot: 'C:\\Windows', PATH: 'C:\\evil', PSModulePath: 'C:\\evil\\modules', LOCALAPPDATA: 'C:\\Users\\me\\AppData\\Local', NODE_OPTIONS: '--require x' };
  await inspectWindowsPaths(['C:\\Users\\me'], ctx(spawn, env));
  assert.equal(seen?.file, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.equal(seen?.env.PATH, 'C:\\Windows\\System32');
  assert.equal(seen?.env.PSModulePath, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules');
  assert.equal(seen?.env.NODE_OPTIONS, undefined);
  assert.equal(seen?.env.LOCALAPPDATA, 'C:\\Users\\me\\AppData\\Local');
  assert.equal(seen?.cwd, 'C:\\Windows');
  assert.equal(seen?.timeoutMs, 45_000);
  assert.equal(seen?.maxBuffer, 1024 * 1024);
  await assert.rejects(inspectWindowsPaths([], ctx(spawn)), WinPsError);
  await assert.rejects(inspectWindowsPaths(Array.from({ length: 65 }, () => 'C:\\a'), ctx(spawn)), WinPsError);
  await assert.rejects(inspectWindowsPaths(['\\\\srv\\share'], ctx(spawn)), WinPsError);
});

test('setPrivateAcl: exact argv, validated SID, absolute icacls, exit code only', async () => {
  const calls: { file: string; args: readonly string[] }[] = [];
  const spawn: SpawnFile = async (file, args) => {
    calls.push({ file, args });
    return okRes();
  };
  await setPrivateAcl('C:\\Users\\me\\x', ME, ctx(spawn));
  assert.deepEqual(calls, [
    { file: 'C:\\Windows\\System32\\icacls.exe', args: ['C:\\Users\\me\\x', '/inheritance:r', '/grant:r', `*${ME}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F'] },
  ]);
  await assert.rejects(setPrivateAcl('C:\\x', 'me; calc', ctx(spawn)), WinPsError);
  await assert.rejects(setPrivateAcl('C:\\x', `${ME} /grant Everyone:F`, ctx(spawn)), WinPsError);
  await assert.rejects(setPrivateAcl('relative', ME, ctx(spawn)), WinPsError);
  await assert.rejects(setPrivateAcl('C:\\x', ME, ctx(async () => okRes('', 1))), WinPsError);
  await assert.rejects(setPrivateAcl('C:\\x', ME, ctx(async () => ({ ...okRes(), timedOut: true }))), WinPsError);
  assert.equal(calls.length, 1, 'invalid input must not start a process');
});

// ---- the real runner (portable: spawns the current node binary, never a shell) ----------

const opts = (over: Partial<{ timeoutMs: number; maxBuffer: number }> = {}) => ({
  env: { PATH: process.env.PATH ?? '' },
  cwd: process.cwd(),
  timeoutMs: 10_000,
  maxBuffer: 1024 * 1024,
  ...over,
});

test('defaultSpawnFile: success, exit code, shell metacharacters stay literal', async () => {
  const ok = await defaultSpawnFile(process.execPath, ['-e', 'process.stdout.write(process.argv[1])', 'a b; echo pwned & $(x)'], opts());
  assert.equal(ok.code, 0);
  assert.equal(ok.stdout, 'a b; echo pwned & $(x)');
  const bad = await defaultSpawnFile(process.execPath, ['-e', 'process.exit(3)'], opts());
  assert.equal(bad.code, 3);
  assert.equal(bad.timedOut, false);
});

test('defaultSpawnFile: output cap and timeout are enforced and reported', async () => {
  const big = await defaultSpawnFile(process.execPath, ['-e', 'process.stdout.write("x".repeat(5000))'], opts({ maxBuffer: 100 }));
  assert.equal(big.truncated, true);
  assert.equal(big.stdout, '');
  const slow = await defaultSpawnFile(process.execPath, ['-e', 'setTimeout(()=>{}, 30000)'], opts({ timeoutMs: 300 }));
  assert.equal(slow.timedOut, true);
  assert.notEqual(slow.code, 0);
});

test('defaultSpawnFile: stdin is closed (EOF), so a child that reads it to the end exits instead of hanging (powershell.exe)', async () => {
  const r = await defaultSpawnFile(
    process.execPath,
    ['-e', 'process.stdin.resume(); process.stdin.on("end", () => process.stdout.write("eof"))'],
    opts({ timeoutMs: 5_000 }),
  );
  assert.equal(r.timedOut, false);
  assert.equal(r.code, 0);
  assert.equal(r.stdout, 'eof');
});

test('inspectWindowsPaths: timeout / non-zero exit say why (bounded, printable stderr), still WinPsError', async () => {
  const noisy = 'x'.repeat(2000);
  const spawnT: SpawnFile = async () => ({ ...okRes(), code: null, timedOut: true, stderr: `\u001bboom\u0000\n${noisy}` });
  await assert.rejects(inspectWindowsPaths(['C:\\Users\\me'], ctx(spawnT)), (e: unknown) => {
    assert.ok(e instanceof WinPsError);
    assert.match(e.message, /^powershell timed out after 45000 ms \[stderr: boom x+\]$/);
    assert.ok(e.message.length < 400);
    assert.doesNotMatch(e.message, /[\u0000-\u001f]/);
    return true;
  });
  const spawnE: SpawnFile = async () => ({ ...okRes(), code: 1, stderr: 'Get-Acl : Attempted to perform an unauthorized operation.' });
  await assert.rejects(inspectWindowsPaths(['C:\\Users\\me'], ctx(spawnE)), /powershell exited with 1 \[stderr: Get-Acl : Attempted to perform an unauthorized operation\.\]/);
  const spawnQ: SpawnFile = async () => ({ ...okRes(), code: 2 });
  await assert.rejects(inspectWindowsPaths(['C:\\Users\\me'], ctx(spawnQ)), /^WinPsError: powershell exited with 2$/);
});

test('defaultSpawnFile: a missing binary is an error result, never a throw or a success', async () => {
  const r = await defaultSpawnFile('/definitely/not/here/binary', [], opts());
  assert.equal(r.code, null);
  assert.equal(r.error, 'ENOENT');
});
