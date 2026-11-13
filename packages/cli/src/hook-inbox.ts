/**
 * The one bit of state that decides whether a PostToolUse hook may
 * stop waiting for the hub's answer.
 *
 * Contract with the hub (CLI side; the hub side lands separately):
 *
 *   <LEDGER_DIR>/.hub/inbox-pending/      mode 0700, created by the hub
 *   <LEDGER_DIR>/.hub/inbox-pending/<session_id>
 *       empty regular file, present for exactly as long as the session has
 *       output the hub still owes it (inbox message or a queued guard note).
 *       The hub removes it only after that output has been handed to a hook
 *       response.
 *
 * Three states, because the absence of the *directory* means something
 * different from the absence of the *file*:
 *
 *   'pending' — marker present   → the hook must wait and print the answer
 *   'empty'   — directory, no marker → nothing to deliver, fire-and-forget
 *   'unknown' — no directory, unreadable, or anything that is not a plain file
 *               /plain directory → behave exactly as before this change
 *
 * 'unknown' is what makes an older hub (no such directory) keep working: it
 * degrades to the synchronous path, so a message can be slow but never lost.
 *
 * A marker is only ever read, never created or removed here, and a symlink in
 * either position yields 'unknown' rather than being followed — `lstat`, not
 * `stat`, for that reason. Worst case of a lost race (hub queues a message
 * after this check) is delivery one tool call later: the marker stays until the
 * message actually goes out.
 */

import { lstat } from 'node:fs/promises';
import { join } from 'node:path';

export type InboxState = 'pending' | 'empty' | 'unknown';

/** Session ids from the agent host are uuids; this is the widest shape we accept as a
 *  file name. Anything else (empty, `..`, a path) is not looked up at all. */
const SESSION_RE = /^[A-Za-z0-9-]{1,64}$/;

export function inboxPendingDir(ledgerDir: string): string {
  return join(ledgerDir, '.hub', 'inbox-pending');
}

export async function inboxState(ledgerDir: string, session: unknown): Promise<InboxState> {
  if (typeof session !== 'string' || !SESSION_RE.test(session)) return 'unknown';
  const dir = inboxPendingDir(ledgerDir);
  const dirSt = await lstat(dir).catch(() => null);
  // No directory → old hub. A symlinked directory → someone is redirecting the
  // marker set; do not trust it, just keep the old behaviour.
  if (dirSt === null || !dirSt.isDirectory()) return 'unknown';
  const markerSt = await lstat(join(dir, session)).catch(() => null);
  if (markerSt === null) return 'empty';
  if (!markerSt.isFile()) return 'unknown';
  return 'pending';
}
