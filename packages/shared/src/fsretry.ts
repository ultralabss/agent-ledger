/**
 * Windows holds files open in ways POSIX does not (antivirus, indexer, a reader mid-open), so
 * `rename`/`rm` fail transiently with EPERM/EBUSY/EACCES. Retry there only; on POSIX those codes
 * are real permission errors and surface immediately.
 */

import type { RmOptions } from 'node:fs';
import { rename, rm } from 'node:fs/promises';

export const RENAME_TRIES = 8;
/** Total sleep budget across all retries. */
export const RENAME_BUDGET_MS = 2_500;
const RENAME_BASE_MS = 20;
const RETRYABLE = new Set(['EPERM', 'EBUSY', 'EACCES']);

export interface RenameRetryDeps {
  platform?: NodeJS.Platform;
  rename?: (from: string, to: string) => Promise<void>;
  sleep?: (ms: number) => Promise<void>;
}

/** Delays between tries: 20, 40, 80, ... truncated so the sum never exceeds the budget. */
export function renameBackoff(): number[] {
  const out: number[] = [];
  let left = RENAME_BUDGET_MS;
  for (let i = 0; i < RENAME_TRIES - 1; i += 1) {
    const d = Math.min(RENAME_BASE_MS * 2 ** i, left);
    out.push(d);
    left -= d;
  }
  return out;
}

export async function renameRetry(
  from: string,
  to: string,
  deps: RenameRetryDeps = {},
): Promise<void> {
  const platform = deps.platform ?? process.platform;
  const doRename = deps.rename ?? rename;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const delays = renameBackoff();
  for (let attempt = 0; ; attempt += 1) {
    try {
      await doRename(from, to);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (
        platform !== 'win32' ||
        code === undefined ||
        !RETRYABLE.has(code) ||
        attempt >= RENAME_TRIES - 1
      ) {
        throw err;
      }
      await sleep(delays[attempt] ?? 0);
    }
  }
}

/** `fs.rm` with Node's built-in retry on EBUSY/EPERM/ENOTEMPTY (5 tries, 50 ms linear backoff). */
export function rmRetry(path: string, opts: RmOptions = {}): Promise<void> {
  return rm(path, { maxRetries: 5, retryDelay: 50, ...opts });
}
