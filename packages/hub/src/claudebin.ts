/**
 * A8-4 — trust decision for the headless `claude` binary.
 *
 * `LEDGER_CLAUDE_BIN` is written into the launchd plist by `install.sh` and
 * is spawned by the triage runner, the weekly groom and the reply worker. It is
 * therefore code execution inside the hub's own uid, with the hub's ledger and
 * token reachable.
 *
 * The trust verdict used to be reported but never enforced, and the verdict
 * itself was softened by enumerating the owning group (which is not
 * fail-closed — see `bintrust.ts`). Now:
 *
 *   (a) the whole realpath chain must be writable by nobody except the hub's
 *       uid and root → headless features are ON,
 *   (b) a group-writable component anywhere in the chain → headless features
 *       are OFF with an actionable message, unless the user consciously opted
 *       in via `install.sh --trust-claude-group`
 *       (`LEDGER_TRUST_CLAUDE_GROUP=1` in the plist), which is recorded in the
 *       journal at boot,
 *   (c) anything else untrusted (world-writable, owned by a third party) → OFF
 *       with no opt-in available.
 */

import { resolveTrustedBinaryInfo } from './git.ts';

/**
 * What the opt-in is PINNED to.
 *
 * `--trust-claude-group` used to mean "tolerate a group-writable component,
 * whatever its group, wherever the binary is". That is broader than the
 * decision the user actually made: they looked at one binary, in one
 * directory, owned by one group (`/opt/homebrew/bin`, group `admin`), and
 * accepted THAT. Afterwards the flag kept applying to a `claude` that had
 * moved somewhere else, or whose directory had been chgrp'd to a group with a
 * different membership — neither of which the user ever saw.
 *
 * `install.sh --trust-claude-group` therefore records the realpath it
 * resolved and the gid of the group-writable directory it found, and the hub
 * honours the opt-in only while BOTH still match.
 */
export interface ClaudeGroupPin {
  /** gid of the group-writable directory the installer saw. */
  gid: number | null;
  /** realpath of the binary the installer saw. */
  realpath: string | null;
}

export type ClaudeBinTrust =
  /** `LEDGER_CLAUDE_BIN` is unset — nothing to trust, headless is unconfigured. */
  | 'unknown'
  | 'ok'
  /** Group-writable chain: fixable by reinstalling claude or by opting in. */
  | 'group_writable'
  /** Untrusted for a reason no flag may override. */
  | 'untrusted';

export interface ClaudeBinStatus {
  state: ClaudeBinTrust;
  /** Only set when `state === 'ok'` — the path that may be spawned. */
  path: string | null;
  detail: string | null;
}

export const GROUP_WRITABLE_MESSAGE =
  'claude binary is in a group-writable directory — headless disabled; ' +
  'install claude into ~/.local or run install.sh --trust-claude-group';

/** The opt-in is present but the hub environment carries no pin (an install from
 *  before this change, or a hand-edited environment). Fail closed and say why. */
export const PIN_MISSING_MESSAGE =
  'LEDGER_TRUST_CLAUDE_GROUP=1 is set, but the pin to gid and realpath is missing from the environment ' +
  '(LEDGER_TRUST_CLAUDE_GID / LEDGER_TRUST_CLAUDE_REALPATH) — headless disabled; run ' +
  'install.sh --trust-claude-group again';

/** The opt-in does not cover the binary we actually resolved. */
export function pinMismatchMessage(what: 'gid' | 'realpath', seen: string, pinned: string): string {
  return what === 'gid'
    ? `claude is in a group-writable directory with group ${seen}, but the allowed group was ${pinned} ` +
        '— headless disabled; if that is fine, run install.sh --trust-claude-group again'
    : `claude resolved to ${seen}, but the allowed path was ${pinned} — headless disabled; ` +
        'if that is fine, run install.sh --trust-claude-group again';
}

/** Human-readable reason the headless features are off, or `null` when on. */
export function claudeBinBlockReason(status: ClaudeBinStatus): string | null {
  if (status.state === 'ok') return null;
  if (status.state === 'group_writable') return GROUP_WRITABLE_MESSAGE;
  if (status.state === 'untrusted') {
    return (
      `claude binary is not trusted (${status.detail ?? '?'}) — headless disabled; ` +
      'install claude into ~/.local and run install.sh'
    );
  }
  return null;
}

export async function resolveClaudeBin(
  bin: string | null,
  opts: { trustGroup?: boolean; pin?: ClaudeGroupPin; stopAt?: string } = {},
): Promise<ClaudeBinStatus> {
  if (bin === null) return { state: 'unknown', path: null, detail: null };

  // A9-1: the opt-in only exists as a PIN. Without one, the tolerance
  // is not applied at all — it would be broader than the decision the user
  // made, and silently so.
  const pinnedGid = opts.trustGroup === true ? (opts.pin?.gid ?? null) : null;
  const pinnedRealpath = opts.trustGroup === true ? (opts.pin?.realpath ?? null) : null;
  if (opts.trustGroup === true && (pinnedGid === null || pinnedRealpath === null)) {
    // Resolve strictly anyway: a binary that is fine WITHOUT the opt-in must
    // not be turned off just because the pin is missing.
    const strict = await resolveTrustedBinaryInfo([bin], opts.stopAt, {});
    if (strict.path !== null) return { state: 'ok', path: strict.path, detail: strict.path };
    if (!strict.foundUntrusted) return { state: 'unknown', path: null, detail: null };
    // Only a `g+w` chain is something a pin could ever have excused. A
    // world-writable component or a foreign owner is `untrusted` no matter what
    // the plist says, so a missing pin must not relabel it as "fixable by
    // re-running the install with the flag".
    if (!strict.groupWritable) {
      return { state: 'untrusted', path: null, detail: strict.rejected.join(', ') };
    }
    return { state: 'group_writable', path: null, detail: PIN_MISSING_MESSAGE };
  }

  const info = await resolveTrustedBinaryInfo(
    [bin],
    opts.stopAt,
    pinnedGid === null
      ? {}
      : // Exactly one group is tolerated: the one the installer recorded. Any
        // other group-writable component is rejected as it was before the flag.
        { groupWritableOk: async (gid: number): Promise<boolean> => gid === pinnedGid },
  );
  if (info.path !== null) {
    if (pinnedRealpath !== null && info.path !== pinnedRealpath) {
      // The chain passed only because of the group tolerance, but this is not
      // the binary the user looked at. Refuse, and name both paths.
      return {
        state: 'untrusted',
        path: null,
        detail: pinMismatchMessage('realpath', info.path, pinnedRealpath),
      };
    }
    return {
      state: 'ok',
      path: info.path,
      detail:
        pinnedGid === null
          ? info.path
          : `${info.path} (group-writable gid ${pinnedGid} allowed by the user)`,
    };
  }
  if (!info.foundUntrusted) {
    // The path does not exist at all — same user-visible shape as "unset":
    // `headless.ts` already answers 503 with "fix the path in the hub environment".
    return { state: 'unknown', path: null, detail: null };
  }
  if (pinnedGid !== null) {
    // It was rejected WITH the pin. Would it have passed for any
    // group? Then the chain's group is simply not the one that was approved —
    // report that, instead of the generic "untrusted directory".
    const lenient = await resolveTrustedBinaryInfo([bin], opts.stopAt, {
      groupWritableOk: async (): Promise<boolean> => true,
    });
    if (lenient.path !== null) {
      return {
        state: 'group_writable',
        path: null,
        detail: pinMismatchMessage('gid', 'a different one than the allowed', String(pinnedGid)),
      };
    }
  }
  if (info.groupWritable) {
    return { state: 'group_writable', path: null, detail: info.rejected.join(', ') };
  }
  return { state: 'untrusted', path: null, detail: info.rejected.join(', ') };
}
