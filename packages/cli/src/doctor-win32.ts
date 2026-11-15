/**
 * Windows-family part of `ledger doctor`: the Task Scheduler supervisor on native Windows and
 * the dual-ledger / DrvFs warnings inside WSL (owner decision 5: ONE hub per machine).
 *
 * Read-only. Children: `<SystemRoot>\System32\schtasks.exe /Query /TN agent-ledger /XML`
 * through the injected `capture` (absolute path, `shell: false`, constant argv, timeout).
 * Only the task's action path is read from the XML — arguments and the rest are ignored.
 */

import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { assertWinPath, samePath } from '@agent-ledger/shared';
import type { Check } from './doctor-checks.ts';
import { WIN_TASK_NAME, schtasksPath, type runCapture } from './selfheal.ts';

const TIMEOUT_MS = 5_000;
/** Directories under `C:\Users` that are never a person's profile. */
const SYSTEM_PROFILES = new Set(['public', 'default', 'default user', 'all users', 'desktop.ini']);
const DRVFS_RE = /^\/mnt\/[a-z](?:\/|$)/;

export interface Win32Deps {
  capture: typeof runCapture;
  env: NodeJS.ProcessEnv;
  exists: (path: string) => Promise<boolean>;
}

export interface WinResult {
  checks: Check[];
  problems: string[];
  suggestion: string | null;
}

function unescapeXml(s: string): string {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/**
 * First `<Exec><Command>` of `schtasks /Query /XML` output, or null. Quotes around the path are
 * stripped; nothing else is interpreted (a path that is not drive-rooted is rejected by the caller).
 * The XML may be UTF-16-decoded-as-UTF-8 noise from a legacy console: NULs are dropped first.
 */
export function parseTaskAction(xml: string): string | null {
  const clean = xml.replace(/\u0000/g, '');
  const exec = /<Exec\b[^>]*>([\s\S]*?)<\/Exec>/i.exec(clean);
  if (exec === null) return null;
  const cmd = /<Command\b[^>]*>([\s\S]*?)<\/Command>/i.exec(exec[1] ?? '');
  if (cmd === null) return null;
  const raw = unescapeXml((cmd[1] ?? '').trim()).replace(/^"(.*)"$/s, '$1').trim();
  return raw === '' ? null : raw;
}

/** win32 supervisor: is the `agent-ledger` task registered and does its action exist? */
export async function win32Checks(deps: Win32Deps): Promise<WinResult> {
  const checks: Check[] = [];
  const problems: string[] = [];
  let suggestion: string | null = null;
  let exe: string;
  try {
    exe = schtasksPath(deps.env);
  } catch {
    checks.push({
      id: 'scheduler',
      status: 'fail',
      detail: 'scheduler: SystemRoot is missing or malformed, cannot locate System32\\schtasks.exe',
    });
    problems.push('SystemRoot is not set to a Windows directory');
    return { checks, problems, suggestion: 'fix the SystemRoot environment variable' };
  }
  const res = await deps.capture(exe, ['/Query', '/TN', WIN_TASK_NAME, '/XML'], TIMEOUT_MS);
  if (res.code !== 0) {
    checks.push({
      id: 'scheduler',
      status: 'fail',
      detail: `scheduler: task ${WIN_TASK_NAME} is not registered in Task Scheduler`,
    });
    problems.push('Task Scheduler task is not registered');
    return { checks, problems, suggestion: 'run install.ps1 (not elevated)' };
  }
  const action = parseTaskAction(res.stdout);
  let valid: string | null = null;
  if (action !== null) {
    try {
      valid = assertWinPath(action);
    } catch {
      valid = null;
    }
  }
  if (valid === null) {
    checks.push({
      id: 'scheduler',
      status: 'fail',
      detail: `scheduler: task ${WIN_TASK_NAME} has no usable absolute action path (${action === null ? 'none' : 'not drive-rooted'})`,
    });
    problems.push('Task Scheduler action path is missing or relative');
    suggestion = 'run install.ps1 to re-register the task';
  } else if (!(await deps.exists(valid))) {
    checks.push({
      id: 'scheduler',
      status: 'fail',
      detail: `scheduler: task ${WIN_TASK_NAME} runs ${valid}, which does not exist`,
    });
    problems.push(`Task Scheduler action ${valid} does not exist`);
    suggestion = 'run install.ps1 to re-register the task (node was moved or uninstalled)';
  } else {
    checks.push({ id: 'scheduler', status: 'ok', detail: `scheduler: task ${WIN_TASK_NAME} registered · action ${valid}` });
  }
  return { checks, problems, suggestion };
}

export interface WslDeps {
  env: NodeJS.ProcessEnv;
  ledgerDir: string;
  spoolDir: string;
  /** Existence probe (`stat`). */
  exists: (path: string) => Promise<boolean>;
  /** Entries of `/mnt/c/Users` (empty when absent). */
  listUsers?: () => Promise<string[]>;
}

/**
 * WSL: a ledger on the Windows side (`/mnt/c/Users/<user>/.ledger`) next to this one means two
 * hubs on one machine — an ERROR, not a warning. A ledger or spool living on a DrvFs mount
 * (`/mnt/<x>/...`) is a warning on its own (the FS section reports the weak-FS refusal).
 */
export async function wslChecks(deps: WslDeps): Promise<WinResult> {
  const checks: Check[] = [];
  const problems: string[] = [];
  let suggestion: string | null = null;

  const list =
    deps.listUsers ??
    (async (): Promise<string[]> => {
      try {
        return await readdir('/mnt/c/Users');
      } catch {
        return [];
      }
    });
  const dual: string[] = [];
  for (const name of await list()) {
    if (SYSTEM_PROFILES.has(name.toLowerCase()) || /[\\/\u0000]/.test(name)) continue;
    const candidate = path.posix.join('/mnt/c/Users', name, '.ledger');
    if (samePath(candidate, deps.ledgerDir)) continue;
    if (await deps.exists(candidate)) dual.push(candidate);
  }
  if (dual.length > 0) {
    checks.push({
      id: 'wsl_dual_ledger',
      status: 'fail',
      detail: `ERROR: a second ledger exists on the Windows side (${dual.join(', ')}); one hub per machine — keep ONE ledger, stop the other hub and move or delete the other directory`,
    });
    problems.push('two ledgers on this machine (WSL and Windows)');
    suggestion = 'keep one ledger (WSL or Windows), stop the other hub, remove the other directory';
  }
  for (const [label, p] of [
    ['ledger', deps.ledgerDir],
    ['spool', deps.spoolDir],
  ] as const) {
    if (DRVFS_RE.test(p)) {
      checks.push({
        id: `wsl_drvfs_${label}`,
        status: 'warn',
        detail: `WARNING: ${label} ${p} is on a Windows drive (DrvFs): private permissions cannot be enforced there — move it into the WSL filesystem (e.g. ~/.ledger)`,
      });
    }
  }
  return { checks, problems, suggestion };
}
