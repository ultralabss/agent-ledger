/** Keep `.hub/hub.log` bounded.
 *
 *  launchd owns the stdout/stderr file descriptor, so renaming the live file
 *  would leave the hub writing into the renamed inode forever (and `hub.log`
 *  would never reappear). Copy + truncate-in-place instead — the same trick
 *  logrotate calls `copytruncate`: the fd keeps pointing at the same inode,
 *  which is now empty. Worst case a line interleaves with the copy; a log line
 *  is not worth an fd handshake with launchd.
 */

import { copyFile, lstat, truncate } from 'node:fs/promises';
import { renameRetry, rmRetry } from '@agent-ledger/shared';

export const HUB_LOG_MAX_BYTES = 5 * 1024 * 1024;
export const HUB_LOG_KEEP = 3;

export interface RotateResult {
  rotated: boolean;
  size: number;
  /** A8-10: `hub.log` itself was a symlink — rotation was skipped rather than
   *  following it (an attacker-planted symlink would otherwise have its
   *  TARGET truncated and copied, not the real log). */
  skippedSymlink: boolean;
}

export async function rotateLog(
  path: string,
  opts: { maxBytes?: number; keep?: number } = {},
): Promise<RotateResult> {
  const maxBytes = opts.maxBytes ?? HUB_LOG_MAX_BYTES;
  const keep = Math.max(1, opts.keep ?? HUB_LOG_KEEP);
  // A8-10: `stat` follows symlinks; `hub.log` must be checked with `lstat` so
  // a symlink planted at the live log path is never followed into `truncate`
  // (which would zero out whatever it points to) or `copyFile` (which would
  // copy that target's content into `.1`, not the real log's).
  const st = await lstat(path).catch(() => null);
  if (st === null) return { rotated: false, size: 0, skippedSymlink: false };
  if (st.isSymbolicLink()) return { rotated: false, size: 0, skippedSymlink: true };
  if (!st.isFile()) return { rotated: false, size: 0, skippedSymlink: false };
  if (st.size <= maxBytes) return { rotated: false, size: st.size, skippedSymlink: false };

  // hub.log.2 → hub.log.3, hub.log.1 → hub.log.2, drop what falls off the end.
  await rmRetry(`${path}.${keep}`, { force: true });
  for (let i = keep - 1; i >= 1; i -= 1) {
    await renameRetry(`${path}.${i}`, `${path}.${i + 1}`).catch(() => undefined);
  }
  // S-4: never copy through a planted symlink sitting at `hub.log.1`.
  await rmRetry(`${path}.1`, { force: true });
  await copyFile(path, `${path}.1`);
  await truncate(path, 0);
  return { rotated: true, size: st.size, skippedSymlink: false };
}
