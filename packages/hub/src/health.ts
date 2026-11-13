/**
 * One line that says the hub is degraded — the FIRST line of the SessionStart
 * brief and of `ledger brief`.
 *
 * Motivation: the ledger's git branch sat in lockdown for a whole day
 * without anyone noticing, because the only trace was a line in `hub.log`. A
 * degraded hub has to announce itself where a session cannot miss it.
 *
 * Nothing here changes behaviour; it only reports state that already exists.
 */

import { CHECK_ERROR_WARN_AFTER } from './git.ts';
import type { GitleaksAvailability } from './gitleaks.ts';
import type { Ledger } from './ledger/ledger.ts';

export interface ScannerState {
  state: GitleaksAvailability;
  detail: string | null;
}

export interface HubHealthInput {
  ledger: Ledger;
  spool?: { queued: number; failed: number } | undefined;
  /** Resolved ONCE per hub (`server.ts`), never probed from here: a module-wide
   *  probe cache would let one process' fake binary answer for another. */
  scanner?: ScannerState | undefined;
  headless?: { bin_trust?: 'unknown' | 'ok' | 'group_writable' | 'untrusted' } | undefined;
}

export function hubHealthParts(input: HubHealthInput): string[] {
  const parts: string[] = [];
  const git = input.ledger.git.status;

  // The hold reason lives on `securityHold`, never on `lastPushError` —
  // show both independently so a real push failure is never shadowed by (or
  // shadows) an active security hold.
  if (git.enabled === false) {
    const hold = git.securityHold;
    const holdDetail = hold === null ? '' : hold.kind === 'leak' && hold.blockedDetail ? ` (${hold.reason} — ${hold.blockedDetail})` : ` (${hold.reason})`;
    parts.push(`ledger commit/push is DISABLED${holdDetail} — ledger changes stay local only`);
  }
  if (git.lastPushError) {
    parts.push(`last push failed: ${git.lastPushError}`);
  }

  // An inconclusive token check is not a lockdown, so `enabled` stays true
  // — but commits ARE being skipped, which is exactly how the ledger silently
  // stopped being backed up for a day. Say it out loud after a few in a row.
  const check = git.tokenCheck;
  if (check !== undefined && check.consecutiveErrors >= CHECK_ERROR_WARN_AFTER) {
    parts.push(
      `.hub/token check failed ${check.consecutiveErrors}x in a row (${
        check.lastError ?? '?'
      }) — ledger commits are being skipped, changes stay local only`,
    );
  }

  // The scanner's state is a first-class health fact, in the
  // same line every session already reads. Each state gets its own sentence,
  // because the fix differs: install it / re-run install after an upgrade /
  // somebody else can write the copy / nobody has probed it yet.
  const scan = input.scanner ?? { state: 'unknown' as GitleaksAvailability, detail: null };
  if (scan.state === 'untrusted') {
    parts.push(
      `gitleaks in .hub/bin is UNVERIFIED — directory or permissions are not exclusively ours ` +
        `(${scan.detail ?? '?'}); the binary is not run — run install.sh`,
    );
  } else if (scan.state === 'mismatch') {
    parts.push(
      'gitleaks in .hub/bin has a different sha256 than the installer recorded — the copy is STALE or ' +
        'tampered with, the binary is not run. After `brew upgrade gitleaks` run install.sh; ' +
        'if you did not update anything, treat it as tampering and investigate',
    );
  } else if (scan.state === 'missing') {
    parts.push(
      'gitleaks is MISSING from .hub/bin — ledger commits go without a second check (run install.sh)',
    );
  }
  // `unknown` (nothing has probed yet) stays silent HERE on purpose: it is only
  // reachable in the window before the boot probe resolves, and in a test hub
  // with the periodic jobs off. `ledger status` and `/v1/healthz` do name it
  // explicitly, so the state is never invisible — see `cmdStatus`.
  const secretScan = git.secretScan;
  if (secretScan?.blocked) {
    parts.push(
      `gitleaks blocked a ledger commit (${secretScan.note ?? 'no detail'}) — ` +
        'staged changes are waiting for a human',
    );
  }

  // Not a diagnostic any more — headless triage, grooming and the reply
  // worker are OFF while this is not `ok`.
  if (input.headless?.bin_trust === 'group_writable') {
    parts.push(
      'claude binary is in a group-writable directory — headless disabled; install claude into ~/.local ' +
        'or run install.sh --trust-claude-group',
    );
  } else if (input.headless?.bin_trust === 'untrusted') {
    parts.push('LEDGER_CLAUDE_BIN is in an untrusted directory — headless disabled');
  }

  const warnings = input.ledger.warnings.size;
  if (warnings > 0) {
    parts.push(`${warnings} items with a file error (detail: ledger healthz)`);
  }

  if (input.spool && input.spool.failed > 0) {
    parts.push(`${input.spool.failed} failed writes in the spool — ledger spool retry`);
  }

  return parts;
}

/** `⚠ hub: …`, or `null` when everything is healthy. */
export function hubHealthLine(input: HubHealthInput): string | null {
  const parts = hubHealthParts(input);
  return parts.length === 0 ? null : `⚠ hub: ${parts.join(' · ')}`;
}
