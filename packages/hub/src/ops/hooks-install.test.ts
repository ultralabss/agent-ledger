/** `adapters/claude-code/install-hooks.mjs` — idempotency, backup, uninstall, dry-run, consent.
 *  Never touches the real `~/.claude/settings.json`: every test works on a copy. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  HOOK_SPECS,
  HOOK_TIMEOUT_S,
  commandFor,
  diffText,
  installedCount,
  planInstall,
  planUninstall,
  type Settings,
} from './hooks-install.ts';

const LEDGER = '/home/user/.local/bin/ledger';
const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  '..',
  '..',
  'adapters',
  'claude-code',
  'install-hooks.mjs',
);

/** Foreign hooks that must survive everything this installer does. */
function existing(): Settings {
  return {
    permissions: { allow: ['Bash(git status)'] },
    hooks: {
      PreToolUse: [
        {
          matcher: 'Read',
          hooks: [{ type: 'command', command: '~/scripts/read-guard.sh' }],
        },
        {
          matcher: 'Edit|Write|MultiEdit|NotebookEdit',
          hooks: [{ type: 'command', command: '~/scripts/path-guard.sh' }],
        },
      ],
      Stop: [{ hooks: [{ type: 'command', command: '~/scripts/other-stop-hook.sh' }] }],
    },
  };
}

test('planInstall: adds all 8 hooks with a 5 s timeout', () => {
  const { settings, changes } = planInstall({}, LEDGER);
  assert.equal(changes.length, HOOK_SPECS.length * 2, 'new block + entry for every hook');
  assert.equal(installedCount(settings, LEDGER), HOOK_SPECS.length);
  const pre = settings.hooks?.PreToolUse ?? [];
  assert.equal(pre.length, 2, 'PreToolUse has a matcher for editors and one for Bash');
  assert.deepEqual(
    pre.map((b) => b.matcher),
    ['Edit|Write|MultiEdit|NotebookEdit', 'Bash'],
  );
  for (const block of Object.values(settings.hooks ?? {})) {
    for (const b of block) {
      for (const e of b.hooks ?? []) {
        assert.equal(e.timeout, HOOK_TIMEOUT_S);
        assert.equal(e.type, 'command');
        assert.match(String(e.command), /^\/home\/user\/\.local\/bin\/ledger hook [a-z-]+$/);
      }
    }
  }
});

test('planInstall: a second run duplicates nothing and keeps foreign hooks', () => {
  const first = planInstall(existing(), LEDGER).settings;
  const second = planInstall(first, LEDGER);
  assert.deepEqual(second.changes, [], 'idempotent');
  assert.deepEqual(second.settings, first, 'byte-identical result');

  // Foreign entries are still there, including in the block we share.
  const shared = (first.hooks?.PreToolUse ?? []).find(
    (b) => b.matcher === 'Edit|Write|MultiEdit|NotebookEdit',
  );
  const commands = (shared?.hooks ?? []).map((h) => h.command);
  assert.ok(commands.includes('~/scripts/path-guard.sh'), 'foreign hook survived');
  assert.ok(commands.includes(commandFor(LEDGER, 'pre-tool-use')), 'our hook was added next to it');
  assert.equal(installedCount(first, LEDGER), HOOK_SPECS.length);
  assert.equal((first.hooks?.PreToolUse ?? []).some((b) => b.matcher === 'Read'), true);
  assert.deepEqual(first.permissions, { allow: ['Bash(git status)'] }, 'other keys untouched');
});

test('planUninstall: removes only our entries, empty blocks disappear', () => {
  const installed = planInstall(existing(), LEDGER).settings;
  const { settings, changes } = planUninstall(installed, LEDGER);
  assert.ok(changes.length > 0);
  assert.equal(installedCount(settings, LEDGER), 0);
  // Foreign hooks are exactly as before the install.
  assert.deepEqual(settings.hooks, existing().hooks);
  assert.deepEqual(planUninstall(settings, LEDGER).changes, [], 'a second uninstall has nothing to do');
});

test('planUninstall: a foreign hook that looks like ours in a different shape is not removed', () => {
  const s: Settings = {
    hooks: {
      Stop: [{ hooks: [{ type: 'command', command: `${LEDGER} hook stop --extra` }] }],
    },
  };
  assert.deepEqual(planUninstall(s, LEDGER).changes, [], 'exact command match, not a prefix');
});

test('diffText: nothing without changes, +/- lines with changes', () => {
  assert.equal(diffText({ a: 1 } as Settings, { a: 1 } as Settings), '(no changes)\n');
  const d = diffText({}, planInstall({}, LEDGER).settings);
  assert.match(d, /\+ .*"SessionStart"/);
});

/* ---------------- the real script, against a copy ---------------- */

function runScript(args: string[]): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [SCRIPT, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d: Buffer) => {
      out += d.toString('utf8');
    });
    child.stderr.on('data', (d: Buffer) => {
      err += d.toString('utf8');
    });
    child.on('close', (code) => resolvePromise({ code, out, err }));
  });
}

test('install-hooks.mjs: install → idempotency → backup → uninstall, on a copy', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'settings.json');
  const ledgerBin = join(dir, 'bin', 'ledger');
  await writeFile(file, `${JSON.stringify(existing(), null, 2)}\n`, 'utf8');

  // dry-run first: must neither write nor back up.
  const dry = await runScript(['--settings', file, '--ledger', ledgerBin, '--dry-run']);
  assert.equal(dry.code, 0, dry.err);
  assert.match(dry.out, /\+.*ledger hook session-start/);
  assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), existing(), 'dry-run wrote nothing');
  assert.deepEqual(
    (await readdir(dir)).filter((f) => f.includes('.bak.')),
    [],
    'dry-run does not back up',
  );

  const first = await runScript(['--settings', file, '--ledger', ledgerBin, '--yes']);
  assert.equal(first.code, 0, first.err);
  const afterInstall = JSON.parse(await readFile(file, 'utf8')) as Settings;
  assert.equal(installedCount(afterInstall, ledgerBin), HOOK_SPECS.length);
  const backups = (await readdir(dir)).filter((f) => f.startsWith('settings.json.bak.'));
  assert.equal(backups.length, 1, 'a write always backs up first');
  assert.deepEqual(JSON.parse(await readFile(join(dir, backups[0] as string), 'utf8')), existing());

  const again = await runScript(['--settings', file, '--ledger', ledgerBin, '--yes']);
  assert.equal(again.code, 0);
  assert.match(again.out, /already installed/);
  assert.deepEqual(
    JSON.parse(await readFile(file, 'utf8')),
    afterInstall,
    'the repeated run did not change the file',
  );
  assert.equal(
    (await readdir(dir)).filter((f) => f.startsWith('settings.json.bak.')).length,
    1,
    'no change means no new backup',
  );

  const off = await runScript(['--settings', file, '--ledger', ledgerBin, '--uninstall', '--yes']);
  assert.equal(off.code, 0, off.err);
  assert.deepEqual(
    (JSON.parse(await readFile(file, 'utf8')) as Settings).hooks,
    existing().hooks,
    'uninstall restored the exact original state',
  );
});

test('install-hooks.mjs: without a TTY and without --yes it refuses and writes nothing', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-consent-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'settings.json');
  await writeFile(file, `${JSON.stringify(existing(), null, 2)}\n`, 'utf8');

  const res = await runScript(['--settings', file, '--ledger', join(dir, 'ledger')]);
  assert.equal(res.code, 1);
  assert.match(res.err, /without confirmation/);
  assert.match(res.err, /--yes/);
  assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), existing(), 'file untouched');
  assert.deepEqual(
    (await readdir(dir)).filter((f) => f.includes('.bak.')),
    [],
    'no backup without consent',
  );

  // --uninstall follows the same rule (install first so there is something to remove).
  const ledgerBin = join(dir, 'ledger');
  const ok = await runScript(['--settings', file, '--ledger', ledgerBin, '--yes']);
  assert.equal(ok.code, 0, ok.err);
  const installed = await readFile(file, 'utf8');
  const off = await runScript(['--settings', file, '--ledger', ledgerBin, '--uninstall']);
  assert.equal(off.code, 1);
  assert.match(off.err, /without confirmation/);
  assert.equal(await readFile(file, 'utf8'), installed, 'uninstall also needs consent');
});

test('install-hooks.mjs: broken JSON is neither written nor overwritten', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-bad-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'settings.json');
  await writeFile(file, '{ this is not json', 'utf8');
  const res = await runScript(['--settings', file, '--ledger', join(dir, 'ledger'), '--yes']);
  assert.equal(res.code, 1);
  assert.match(res.err, /is not valid JSON/);
  assert.equal(await readFile(file, 'utf8'), '{ this is not json', 'file untouched');
});

test('H8: a settings.json symlink survives, the write goes through to its target', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-symlink-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const real = join(dir, 'dotfiles-settings.json');
  const link = join(dir, 'settings.json');
  await writeFile(real, `${JSON.stringify(existing(), null, 2)}\n`, 'utf8');
  await symlink(real, link);

  const res = await runScript(['--settings', link, '--ledger', join(dir, 'ledger'), '--yes']);
  assert.equal(res.code, 0, res.err);

  const st = await lstat(link);
  assert.equal(st.isSymbolicLink(), true, 'settings.json must stay a symlink, not be replaced by a file');
  const afterReal = JSON.parse(await readFile(real, 'utf8')) as Settings;
  assert.equal(installedCount(afterReal, join(dir, 'ledger')), HOOK_SPECS.length, 'the write went to the symlink target');
});

test('H8: a second run while the lock is held fails instead of racing for the write', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-lock-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'settings.json');
  await writeFile(file, `${JSON.stringify(existing(), null, 2)}\n`, 'utf8');
  // Hold the lock the script itself would create.
  await writeFile(`${file}.lock`, '', { flag: 'wx' });
  t.after(() => rm(`${file}.lock`, { force: true }));

  const res = await runScript(['--settings', file, '--ledger', join(dir, 'ledger'), '--yes']);
  assert.equal(res.code, 1, 'locked — must fail, not silently overwrite');
  assert.match(res.err, /lock/);
  assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), existing(), 'file untouched');
});

test('install-hooks.mjs: a missing settings.json is created', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-new-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'settings.json');
  const ledgerBin = join(dir, 'ledger');
  const res = await runScript(['--settings', file, '--ledger', ledgerBin, '--yes']);
  assert.equal(res.code, 0, res.err);
  assert.equal(installedCount(JSON.parse(await readFile(file, 'utf8')) as Settings, ledgerBin), 8);
});

test('J3: settings.json in a nonexistent directory (first install, `~/.claude` does not exist yet)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-noparent-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  // Neither `nested` nor `deeper` exists — `open(LOCK_FILE, 'wx')` used to
  // die on a raw ENOENT (stack trace, uncontrolled exit) before `mkdir` in
  // `main()` could even run.
  const file = join(dir, 'nested', 'deeper', 'settings.json');
  const ledgerBin = join(dir, 'ledger');
  const res = await runScript(['--settings', file, '--ledger', ledgerBin, '--yes']);
  assert.equal(res.code, 0, res.err);
  assert.doesNotMatch(res.err, /ENOENT|at Object\.|at async/, 'no raw stack trace');
  assert.equal(installedCount(JSON.parse(await readFile(file, 'utf8')) as Settings, ledgerBin), HOOK_SPECS.length);
});

test('J4: the lock is keyed by the real path — two symlinks to the same target do not race', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-two-symlinks-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const real = join(dir, 'dotfiles-settings.json');
  const linkA = join(dir, 'a-settings.json');
  const linkB = join(dir, 'b-settings.json');
  await writeFile(real, `${JSON.stringify(existing(), null, 2)}\n`, 'utf8');
  await symlink(real, linkA);
  await symlink(real, linkB);

  // Simulate a run in progress via `linkA`: hold the lock keyed by the real
  // target. A lock keyed by the symlink path (`${linkB}.lock`) would be a
  // different file, so a run via `linkB` would sail straight past it and
  // race the write.
  await writeFile(`${real}.lock`, '', { flag: 'wx' });
  t.after(() => rm(`${real}.lock`, { force: true }));

  const res = await runScript(['--settings', linkB, '--ledger', join(dir, 'ledger'), '--yes']);
  assert.equal(res.code, 1, 'must see the lock of another run through a different symlink to the same target');
  assert.match(res.err, /lock/);
  assert.deepEqual(JSON.parse(await readFile(real, 'utf8')), existing(), 'target untouched');
});

test('K4: --dry-run on a nonexistent directory does not even create the directory', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-dryrun-noparent-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  // `nested` does not exist — a top-level `mkdir` that ran before the
  // `--dry-run` decision would make "writes nothing" a lie: the directory
  // would always appear.
  const file = join(dir, 'nested', 'settings.json');
  const ledgerBin = join(dir, 'ledger');
  const res = await runScript(['--settings', file, '--ledger', ledgerBin, '--dry-run']);
  assert.equal(res.code, 0, res.err);
  await assert.rejects(
    () => readdir(join(dir, 'nested')),
    /ENOENT/,
    'dry-run must not create the directory for settings.json',
  );
});

test('K5: --uninstall on a nonexistent path is "nothing to remove", exit 0', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-uninstall-missing-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'nested', 'settings.json');
  const ledgerBin = join(dir, 'ledger');
  const res = await runScript(['--settings', file, '--ledger', ledgerBin, '--uninstall', '--yes']);
  assert.equal(res.code, 0, res.err);
  assert.match(res.out, /nothing to remove/);
  assert.doesNotMatch(res.err, /ENOENT|at Object\.|at async/, 'no raw stack trace');
});

test('a dangling symlink — the write goes to the target, the symlink stays a symlink', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-dangling-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  // `settings.json` → `dotfiles/claude/settings.json`, which does not exist yet
  // (typical state after `git clone` of dotfiles before the first `stow`/`link`).
  const target = join(dir, 'dotfiles', 'claude', 'settings.json');
  const link = join(dir, 'settings.json');
  await symlink(target, link);
  const ledgerBin = join(dir, 'ledger');

  const res = await runScript(['--settings', link, '--ledger', ledgerBin, '--yes']);
  assert.equal(res.code, 0, res.err);

  // A naive `realpath()` fallback would write to the symlink path and
  // `rename()` would replace the symlink with a plain file, leaving the target
  // nonexistent.
  const st = await lstat(link);
  assert.ok(st.isSymbolicLink(), 'the symlink must be preserved, not replaced by a file');
  const written = JSON.parse(await readFile(target, 'utf8')) as Settings;
  assert.equal(installedCount(written, ledgerBin), HOOK_SPECS.length, 'the hooks are in the symlink target');
  // And reading through the symlink sees the same thing.
  assert.deepEqual(JSON.parse(await readFile(link, 'utf8')), written);
});

test('a chain of dangling symlinks is followed to the end', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-chain-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const final = join(dir, 'real', 'settings.json');
  const mid = join(dir, 'mid.json');
  const link = join(dir, 'settings.json');
  await symlink(final, mid);
  await symlink(mid, link); // relative-free chain, both dangling
  const ledgerBin = join(dir, 'ledger');

  const res = await runScript(['--settings', link, '--ledger', ledgerBin, '--yes']);
  assert.equal(res.code, 0, res.err);
  assert.ok((await lstat(link)).isSymbolicLink());
  assert.ok((await lstat(mid)).isSymbolicLink());
  assert.equal(installedCount(JSON.parse(await readFile(final, 'utf8')) as Settings, ledgerBin), HOOK_SPECS.length);
});

test('a relative dangling symlink is resolved against its own directory', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-settings-rel-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const link = join(dir, 'settings.json');
  await symlink(join('dotfiles', 'settings.json'), link); // relative target
  const ledgerBin = join(dir, 'ledger');

  const res = await runScript(['--settings', link, '--ledger', ledgerBin, '--yes']);
  assert.equal(res.code, 0, res.err);
  assert.ok((await lstat(link)).isSymbolicLink());
  assert.equal(
    installedCount(
      JSON.parse(await readFile(join(dir, 'dotfiles', 'settings.json'), 'utf8')) as Settings,
      ledgerBin,
    ),
    HOOK_SPECS.length,
  );
});
