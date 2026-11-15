/**
 * A8-4 — the write set of a path, decided from mode bits ONLY.
 *
 * An earlier version used to tolerate a group-writable (`g+w`) directory such as
 * `/opt/homebrew/bin` whenever the owning group's membership, enumerated at
 * runtime, resolved to a subset of {root, us}. That enumeration is gone, and
 * with it the tolerance:
 *
 *   - `dscacheutil -q group` returns the group's *explicit* member list. It
 *     does NOT expand nested groups, so a group that contains another group
 *     (and through it a third admin account) enumerates as `{root, us}` while
 *     the real write set is larger.
 *   - `dscl . -list /Users PrimaryGroupID` reads the LOCAL node only. A user
 *     from a directory service (AD/LDAP/MDM-managed account) whose primary
 *     gid is that group never appears.
 *
 * Neither failure mode is detectable from the output, so the enumeration was
 * not fail-closed: it answered "harmless" with high confidence for a write set
 * it had never actually seen. On `/opt/homebrew/bin` (`drwxrwxr-x user:admin`)
 * that is enough for a second admin account to swap the binary we execute.
 *
 * The rule is therefore back to the N1 default and stays there: a `g+w` or
 * `o+w` component is NOT trusted. The two binaries that needed the exception
 * get it a different way —
 *   - gitleaks: the install copies the binary into `<ledger>/.hub/bin` (0700
 *     chain, 0500 file, owner us) and the hub verifies owner/mode/chain/sha256
 *     of THAT copy (`managedbin.ts`). Homebrew's directory is never trusted.
 *   - claude: the headless features turn themselves OFF with an explanation,
 *     unless the user consciously opted in with
 *     `install.sh --trust-claude-group` (`claudebin.ts`).
 *
 * The `groupWritableOk` predicate survives as an explicit, injected decision
 * (tests, and the claude opt-in). Nothing in production enumerates groups.
 */

import { posixWriteBitsTrusted } from '@agent-ledger/shared';

/** Production default: a group-writable component is never trusted. */
export const groupWriteNeverTrusted = async (_gid: number): Promise<boolean> => false;

/** The claude opt-in (`LEDGER_TRUST_CLAUDE_GROUP=1`) and nothing else. */
export const groupWriteTrustedByUser = async (_gid: number): Promise<boolean> => true;

/**
 * The permission-bit rule for a trusted binary or one of its parent directories. The rule
 * itself now lives in platformTrust (`posixWriteBitsTrusted`, moved without loosening);
 * this wrapper only supplies the production default for the group-write decision.
 */
export async function writeBitsTrusted(
  mode: number,
  gid: number,
  groupWritableOk: (gid: number) => Promise<boolean> = groupWriteNeverTrusted,
): Promise<boolean> {
  return posixWriteBitsTrusted(mode, gid, groupWritableOk);
}
