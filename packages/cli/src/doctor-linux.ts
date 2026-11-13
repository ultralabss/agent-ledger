/**
 * Linux part of `ledger doctor`: the systemd user unit `install.sh` writes
 * (`~/.config/systemd/user/<label>.service`) and user lingering.
 *
 * Read-only: only `systemctl --user show` and `loginctl show-user`, both with
 * an absolute binary path, `shell: false`, constant argv (the label is
 * validated, the uid is numeric) and a timeout. A missing systemctl/loginctl
 * or an unreachable user bus is `info`, never a failure of the doctor itself.
 */

import { stat } from 'node:fs/promises';
import type { Check } from './doctor-checks.ts';
import { HUB_LABEL, type runCapture } from './selfheal.ts';

const SYSTEMCTL = ['/usr/bin/systemctl', '/bin/systemctl'];
const LOGINCTL = ['/usr/bin/loginctl', '/bin/loginctl'];
const TIMEOUT_MS = 3_000;
const LABEL_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export interface LinuxDeps {
  capture: typeof runCapture;
  uid: number | undefined;
  env: NodeJS.ProcessEnv;
  /** Test seam; default `stat` succeeds. */
  exists?: (path: string) => Promise<boolean>;
}

export interface LinuxResult {
  checks: Check[];
  problems: string[];
  suggestion: string | null;
}

async function firstExisting(paths: string[], exists: (p: string) => Promise<boolean>): Promise<string | null> {
  for (const p of paths) if (await exists(p)) return p;
  return null;
}

function kv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return out;
}

export async function linuxChecks(deps: LinuxDeps): Promise<LinuxResult> {
  const exists =
    deps.exists ??
    (async (p: string): Promise<boolean> => {
      try {
        await stat(p);
        return true;
      } catch {
        return false;
      }
    });
  const checks: Check[] = [];
  const problems: string[] = [];
  let suggestion: string | null = null;
  const label = LABEL_RE.test(deps.env.AGENT_LEDGER_LABEL ?? '') ? (deps.env.AGENT_LEDGER_LABEL as string) : HUB_LABEL;
  const unit = `${label}.service`;

  const systemctl = await firstExisting(SYSTEMCTL, exists);
  if (systemctl === null) {
    checks.push({ id: 'systemd', status: 'info', detail: 'systemd: systemctl not found (service checks skipped)' });
    return { checks, problems, suggestion };
  }
  const shown = await deps.capture(
    systemctl,
    ['--user', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'NRestarts', '-p', 'ExecMainStatus', '--no-pager'],
    TIMEOUT_MS,
  );
  if (shown.code !== 0) {
    checks.push({ id: 'systemd', status: 'info', detail: 'systemd: no user session reachable (service checks skipped)' });
    return { checks, problems, suggestion };
  }
  const f = kv(shown.stdout);
  if (f.LoadState === 'not-found') {
    checks.push({ id: 'systemd', status: 'fail', detail: `systemd: ${unit} is not installed` });
    problems.push('systemd unit is not installed');
    suggestion = 'install.sh (or start the hub by hand)';
  } else if (f.ActiveState === 'active') {
    checks.push({
      id: 'systemd',
      status: 'ok',
      detail: `systemd: ${unit} active (${f.SubState ?? '?'}) · restarts ${f.NRestarts ?? '-'} · last exit ${f.ExecMainStatus ?? '-'}`,
    });
  } else {
    const state = `${f.ActiveState ?? '?'}/${f.SubState ?? '?'}`;
    checks.push({
      id: 'systemd',
      status: 'fail',
      detail: `systemd: ${unit} ${state} · restarts ${f.NRestarts ?? '-'} · last exit ${f.ExecMainStatus ?? '-'}`,
    });
    problems.push(`systemd unit ${state}`);
    suggestion = `systemctl --user restart ${unit}`;
  }

  /* ---- linger ---- */
  const loginctl = await firstExisting(LOGINCTL, exists);
  if (loginctl === null || typeof deps.uid !== 'number' || !Number.isInteger(deps.uid) || deps.uid < 0) {
    checks.push({ id: 'linger', status: 'info', detail: 'linger: loginctl not available (skipped)' });
  } else {
    const l = await deps.capture(loginctl, ['show-user', String(deps.uid), '-p', 'Linger'], TIMEOUT_MS);
    const value = l.code === 0 ? kv(l.stdout).Linger : undefined;
    if (value === 'yes') {
      checks.push({ id: 'linger', status: 'ok', detail: 'linger: on (hub survives logout)' });
    } else if (value === 'no') {
      checks.push({
        id: 'linger',
        status: 'warn',
        detail: 'linger: off — the hub stops at logout (loginctl enable-linger "$USER")',
      });
    } else {
      checks.push({ id: 'linger', status: 'info', detail: 'linger: unknown (loginctl gave no answer)' });
    }
  }
  return { checks, problems, suggestion };
}
