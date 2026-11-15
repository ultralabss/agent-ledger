#!/usr/bin/env node
/**
 * Claude Code adapter (optional): wire the ledger's hooks into
 * ~/.claude/settings.json.
 *
 *   adapters/claude-code/install-hooks.mjs --dry-run     # print the diff, write nothing
 *   adapters/claude-code/install-hooks.mjs               # install (asks for confirmation)
 *   adapters/claude-code/install-hooks.mjs --yes         # install without asking (required when stdin is not a TTY)
 *   adapters/claude-code/install-hooks.mjs --uninstall   # remove only our entries (same consent rules)
 *   adapters/claude-code/install-hooks.mjs --settings <file> --ledger <path>   # for tests
 *
 * Existing hooks (yours, or from any other tool) are left exactly as they are:
 * the script only adds entries whose command is `<ledger> hook <event>`, and
 * `--uninstall` removes only those.
 *
 * Consent: a run that WRITES prints the target file and a summary of the
 * entries it will add (or remove). On a TTY you must type `yes`; without a TTY
 * it refuses unless `--yes` is given. `--dry-run` never writes and never asks.
 *
 * Every run that writes takes a backup first (`settings.json.bak.<timestamp>`)
 * and writes atomically (tmp + rename) — a half-written settings.json would
 * leave Claude Code with no hooks at all, including the security ones.
 *
 * Two safety properties the tmp+rename dance alone does not give you:
 *  - `--settings` can point at a symlink (dotfiles-managed `settings.json` is
 *    common). `rename()` replaces whatever is AT a path, not what it points
 *    through — writing `tmp` next to the symlink and renaming over it would
 *    silently delete the symlink and leave a plain file in its place, and the
 *    real target (elsewhere in a dotfiles repo) would never be updated. So
 *    every path used for backup/tmp/rename is the `realpath()`-resolved
 *    target, resolved once up front, never the symlink itself.
 *  - two overlapping runs (e.g. a person re-running the installer while another
 *    shell is mid-install) both read the same `before`, compute independent
 *    `after` values and the second `rename()` clobbers the first — an
 *    exclusive, `O_EXCL`-created lock file serializes the whole
 *    read-modify-write, with a timeout so a crashed run cannot wedge every
 *    future one forever.
 */

import { readFile, writeFile, rename, copyFile, mkdir, chmod, open, unlink, realpath, readlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  HOOK_SPECS,
  backupName,
  diffText,
  installedCount,
  planInstall,
  planUninstall,
} from '../../packages/hub/src/ops/hooks-install.ts';

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  if (i >= 0 && process.argv[i + 1] !== undefined && !process.argv[i + 1].startsWith('--')) {
    return process.argv[i + 1];
  }
  return fallback;
}
const has = (name) => process.argv.includes(`--${name}`);

const settingsFile = resolve(arg('settings', join(homedir(), '.claude', 'settings.json')));
// What precedes ` hook <event>` in a hook command. POSIX: the shim `install.sh` creates (overridable
// so a test or a non-standard SHIM_DIR can point at its own). win32: node.exe + bin.ts DIRECTLY —
// never a `.cmd` shim (needs a shell; CVE-2024-27980 class) — resolved here from this very node and
// checkout, with forward slashes so Git Bash and cmd both parse it. `--ledger` still wins everywhere.
const CLI_BIN = fileURLToPath(new URL('../../packages/cli/src/bin.ts', import.meta.url));
let ledgerPath = arg('ledger', null);
let winSetup = null;
if (process.platform === 'win32' && ledgerPath === null) {
  winSetup = await import('../../packages/cli/src/setup.ts');
  try {
    ledgerPath = winSetup.winHookLauncher({ node: process.execPath, cliBin: CLI_BIN });
  } catch (err) {
    console.error(`install-hooks: ${err.message} — pass --ledger <launcher> or move the checkout/node to a plainer path`);
    process.exit(1);
  }
}
ledgerPath ??= join(homedir(), '.local', 'bin', 'ledger');
const dryRun = has('dry-run');
const uninstall = has('uninstall');
const assumeYes = has('yes');

/**
 * Resolve `settingsFile` through symlinks, INCLUDING dangling ones.
 *
 * `realpath()` throws ENOENT on a symlink whose target does not exist yet.
 * A naive fallback would use the symlink's own path as the write target, and
 * the atomic `rename(tmp, realTarget)` at the end would REPLACE the symlink
 * with a regular file — silently detaching a dotfiles-managed `settings.json`
 * from wherever it was supposed to live, and writing the user's hooks (and any
 * `env` secrets already in that file) to the wrong place.
 *
 * Correct behaviour: follow the link chain by hand, write into the final
 * target, create it (and its parent) if missing, and leave every symlink in
 * the chain exactly as it was. Resolved once, up front, so the lock and every
 * path derived from it name the same file regardless of which symlink alias
 * `--settings` used.
 */
async function resolveWriteTarget(start) {
  // Fast path: target exists — `realpath` is authoritative.
  const real = await realpath(start).catch(() => null);
  if (real !== null) return real;

  let current = start;
  // Bounded like the kernel's own symlink limit; a loop must not hang install.
  for (let i = 0; i < 16; i += 1) {
    const link = await readlink(current).catch(() => null);
    // Not a symlink → it simply does not exist yet. Write here.
    if (link === null) return current;
    const next = isAbsolute(link) ? link : resolve(dirname(current), link);
    if (next === current) return current;
    current = next;
    const real2 = await realpath(current).catch(() => null);
    if (real2 !== null) return real2;
  }
  throw new Error(`install-hooks: ${start} — symlink chain is too long or cyclic`);
}

const realTarget = await resolveWriteTarget(settingsFile);

const LOCK_FILE = `${realTarget}.lock`;
const LOCK_TIMEOUT_MS = 5000;
const LOCK_POLL_MS = 50;

/** Exclusive lock via `O_EXCL` create — fails if another run already holds
 *  it. Retries until `LOCK_TIMEOUT_MS` instead of hanging forever, so a lock
 *  left behind by a crashed/killed run cannot wedge every future one. */
async function acquireLock() {
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (;;) {
    try {
      const fh = await open(LOCK_FILE, 'wx');
      await fh.close();
      return;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      if (Date.now() >= deadline) {
        throw new Error(
          `install-hooks: lock ${LOCK_FILE} has been held for more than ${LOCK_TIMEOUT_MS} ms — ` +
            'another run is stuck, or one left it behind (delete it by hand if you know nothing is running).',
        );
      }
      await new Promise((r) => setTimeout(r, LOCK_POLL_MS));
    }
  }
}

async function releaseLock() {
  await unlink(LOCK_FILE).catch(() => {});
}

/** Explicit consent before touching the settings file. `--yes` skips the
 *  prompt; without a TTY there is nobody to ask, so refuse. */
async function confirm(changes) {
  const verb = uninstall ? 'remove' : 'add';
  if (assumeYes) return true;
  if (!process.stdin.isTTY) {
    console.error(
      `install-hooks: refusing to modify ${settingsFile} without confirmation — ` +
        're-run with --yes (or --dry-run to preview).',
    );
    return false;
  }
  console.log(`install-hooks: about to ${verb} ledger hook entries in ${settingsFile}:`);
  for (const line of changes) console.log(`  ${line}`);
  console.log('  (a backup is written first; other hooks are not touched)');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question('Type "yes" to continue: ');
    if (answer.trim() === 'yes') return true;
  } finally {
    rl.close();
  }
  console.error('install-hooks: not confirmed — nothing changed.');
  return false;
}

/** Runs the whole install/uninstall and returns the process exit code —
 *  never calls `process.exit()` itself, so the caller's `finally` (lock
 *  release) always runs. */
async function main() {
  const raw = await readFile(settingsFile, 'utf8').catch((err) => {
    if (err.code === 'ENOENT') return null;
    throw err;
  });
  let before = {};
  if (raw !== null && raw.trim() !== '') {
    try {
      before = JSON.parse(raw);
    } catch (err) {
      console.error(
        `install-hooks: ${settingsFile} is not valid JSON (${err.message}) — ` +
          'changing nothing, fix it by hand.',
      );
      return 1;
    }
  }

  let plan;
  if (uninstall && winSetup !== null) {
    // node.exe may have moved since the install: also remove entries that point at THIS checkout's
    // bin.ts through any other node path (other entries are never touched).
    const launchers = new Set([ledgerPath, ...winSetup.findWinHookLaunchers(before, CLI_BIN, HOOK_SPECS.map((h) => h.arg))]);
    plan = { settings: before, changes: [] };
    for (const l of launchers) {
      const step = planUninstall(plan.settings, l);
      plan = { settings: step.settings, changes: [...plan.changes, ...step.changes] };
    }
  } else {
    plan = uninstall ? planUninstall(before, ledgerPath) : planInstall(before, ledgerPath);
  }
  const { settings: after, changes } = plan;

  if (dryRun) {
    process.stdout.write(diffText(before, after));
    console.error(
      `install-hooks: ${changes.length === 0 ? 'no changes' : `${changes.length} changes`} (dry-run, nothing written)`,
    );
    for (const line of changes) console.error(`  ${line}`);
    return 0;
  }

  if (changes.length === 0) {
    console.log(
      `install-hooks: ${uninstall ? 'nothing to remove' : 'already installed'} ` +
        `(${installedCount(after, ledgerPath)} hooks, ${settingsFile})`,
    );
    return 0;
  }

  if (!(await confirm(changes))) return 1;

  if (raw !== null) {
    const backup = backupName(realTarget);
    await copyFile(realTarget, backup);
    console.log(`install-hooks: backup ${backup}`);
  }

  const tmp = `${realTarget}.tmp.${process.pid}`;
  await writeFile(tmp, `${JSON.stringify(after, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await chmod(tmp, 0o600);
  await rename(tmp, realTarget);

  console.log(
    `install-hooks: ${uninstall ? 'removed' : 'installed'} — ${installedCount(after, ledgerPath)} hooks in ${settingsFile}`,
  );
  for (const line of changes) console.log(`  ${line}`);
  return 0;
}

// `--dry-run` must write NOTHING — not even the `~/.claude` directory. So the
// directory (and the lock inside it) are only created on the write path, after
// the dry-run short-circuit, never for a plain diff preview.
let exitCode = 1;
if (dryRun) {
  exitCode = await main();
} else {
  // Create the lock's directory BEFORE trying to acquire it — a first-ever
  // install (`~/.claude` not created yet) would otherwise make
  // `open(LOCK_FILE, 'wx')` throw a raw ENOENT with a Node stack trace before
  // the script got a chance to print a clean error. Wrapped so that failure
  // (e.g. permission denied) is a script-style message too.
  let dirReady = true;
  try {
    await mkdir(dirname(realTarget), { recursive: true, mode: 0o700 });
  } catch (err) {
    console.error(
      `install-hooks: could not create the directory for ${realTarget} (${err.message})`,
    );
    dirReady = false;
  }
  if (dirReady) {
    await acquireLock();
    try {
      exitCode = await main();
    } finally {
      await releaseLock();
    }
  }
}
process.exitCode = exitCode;
