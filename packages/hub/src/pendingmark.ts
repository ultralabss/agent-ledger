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

import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { assertPrivateDir, ensurePrivateDir, openPrivate } from '@agent-ledger/shared';

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
    this.ready ??= ensurePrivateDir(this.dir).then(
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
   *  platformTrust decides (I1, fail-closed — an unknown uid or ACL is a refusal, not a
   *  pass): the directory is a real dir (no symlink/reparse), owned by us, and nobody
   *  else may write or even read it (`secret`: POSIX no group/other bits at all, win32 a
   *  protected DACL). The marker FILE is opened through `openPrivate` below, which refuses
   *  a pre-planted symlink. */
  private async dirIsSafe(): Promise<boolean> {
    try {
      await assertPrivateDir(this.dir, { secret: true });
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
      const fd = await openPrivate(join(this.dir, session), 'trunc', 0o600);
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
