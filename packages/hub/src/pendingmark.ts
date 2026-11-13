/**
 * Hub side of the inbox marker. The CLI side and the full contract are
 * in `packages/cli/src/hook-inbox.ts`; in short:
 *
 *   <ledger>/.hub/inbox-pending/            0700, created by the hub
 *   <ledger>/.hub/inbox-pending/<session>   empty file, present while the hub
 *                                           owes that session output
 *
 * Why a file and not an HTTP call: the PostToolUse hook is fire-and-forget on
 * the fast path. It has to decide *without* talking to the hub whether there is
 * anything to wait for. An `lstat` is ~10 µs; a round trip is milliseconds, on
 * every single tool call.
 *
 * "Owes output" means BOTH channels: a queued inbox message and a guard note
 * parked by PreToolUse. Dropping either from the marker is how a note goes
 * missing — the hook would skip the wait and the note would be discarded with
 * the response nobody read.
 *
 * Every function is best effort. A marker that fails to appear costs latency
 * (the hook falls back to 'unknown' → the old synchronous path); a marker that
 * fails to disappear costs one needless wait. Neither is worth an exception on
 * the hook path.
 */

import { constants as fsConstants } from 'node:fs';
import { lstat, mkdir, open, rm } from 'node:fs/promises';
import { join } from 'node:path';

/** Same shape the CLI accepts as a marker name. Anything else is not written,
 *  so a crafted `session_id` can never address a path outside the directory. */
const SESSION_RE = /^[A-Za-z0-9-]{1,64}$/;

export class PendingMarks {
  private readonly dir: string;
  private readonly logFn: (line: string) => void;
  /** Mirrors what we believe is on disk, so a session that gets twenty inbox
   *  messages in a row does not do twenty `writeFile`s. */
  private readonly present = new Set<string>();
  private ready: Promise<void> | null = null;

  constructor(hubDir: string, log: (line: string) => void = () => undefined) {
    this.dir = join(hubDir, 'inbox-pending');
    this.logFn = log;
  }

  /** Absolute path of the directory — exposed for tests and the hub log. */
  get path(): string {
    return this.dir;
  }

  /** Created lazily and at most once per process. `.hub/` is already 0700, and
   *  this inherits the same mode explicitly rather than relying on the umask. */
  private ensure(): Promise<void> {
    this.ready ??= mkdir(this.dir, { recursive: true, mode: 0o700 }).then(
      () => undefined,
      (err: unknown) => {
        this.logFn(`inbox-pending: ${String(err)}`);
      },
    );
    return this.ready;
  }

  /** `this.dir` is attacker-reachable (any local account that can
   *  write under the ledger root) — a symlink swapped in for it, or for a
   *  session's marker file, would turn a 0-byte marker write/removal into
   *  a write into (or unlink of) whatever the link actually points to.
   *  `lstat` never follows the final symlink, so this catches the directory
   *  itself having been replaced; `O_NOFOLLOW` on the `open()` below catches
   *  the marker filename having been pre-planted as a symlink. */
  private async dirIsSafe(): Promise<boolean> {
    try {
      const st = await lstat(this.dir);
      if (!st.isDirectory()) return false;
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) return false;
      if ((st.mode & 0o777) !== 0o700) return false;
      return true;
    } catch {
      return false;
    }
  }

  /** The hub now owes this session output. */
  async owe(session: string): Promise<void> {
    if (!SESSION_RE.test(session)) return;
    if (this.present.has(session)) return;
    this.present.add(session);
    await this.ensure();
    if (!(await this.dirIsSafe())) {
      this.present.delete(session);
      this.logFn(`inbox-pending: ${this.dir} is not a safe directory (symlink/owner/permissions) — write refused`);
      return;
    }
    try {
      const fd = await open(
        join(this.dir, session),
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | fsConstants.O_NOFOLLOW,
        0o600,
      );
      await fd.close();
    } catch (err) {
      // Forget it, so the next message retries instead of trusting a write
      // that never happened.
      this.present.delete(session);
      this.logFn(`inbox-pending ${session}: ${String(err)}`);
    }
  }

  /** The debt has been handed to a hook response. */
  async settle(session: string): Promise<void> {
    if (!SESSION_RE.test(session)) return;
    this.present.delete(session);
    if (!(await this.dirIsSafe())) {
      this.logFn(`inbox-pending: ${this.dir} is not a safe directory (symlink/owner/permissions) — rm refused`);
      return;
    }
    try {
      await rm(join(this.dir, session), { force: true });
    } catch (err) {
      this.logFn(`inbox-pending ${session}: ${String(err)}`);
    }
  }

  /** Session is gone: no debt can be delivered to it any more. */
  async forget(session: string): Promise<void> {
    await this.settle(session);
  }
}
