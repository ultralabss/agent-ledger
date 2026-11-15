/**
 * A8-4 — a binary the INSTALL put somewhere we fully control, verified against
 * a recorded sha256 before it is ever executed.
 *
 * Motivation: `/opt/homebrew/bin` and `/opt/homebrew/Cellar` are
 * `drwxrwxr-x <user>:admin`, so every admin account on the machine can replace
 * a Homebrew binary. The hub used to decide that was acceptable by enumerating
 * the `admin` group; that enumeration is not fail-closed (nested groups,
 * directory-service accounts — see `bintrust.ts`), so Homebrew paths are not
 * trusted at all any more.
 *
 * Instead, `install.sh` copies the binary into `<ledger>/.hub/bin/<name>`
 * (whole chain from `$HOME` validated and 0700, file 0500, owner = the user
 * running the hub) and writes `<name>.sha256`. The hub executes ONLY that copy
 * and only when all of these hold:
 *   - it is a regular file, not a symlink (the install copies, never links),
 *   - owner is the uid we run as,
 *   - neither group nor other can write it,
 *   - every directory from it up to `/` is owned by root or us and is not
 *     group/other-writable (`assertTrustedAncestors`, strict — no group enumeration),
 *   - the same rules hold for the `.sha256` side-car, and
 *   - sha256(file) equals the recorded digest, compared with
 *     `timingSafeEqual`.
 *
 * Residual TOCTOU: the verification and the later `spawn` are not atomic. The
 * only principals that can write the directory between the two are root and
 * the hub's own uid, which is the same trust boundary the hub's token already
 * lives inside, so the window buys an attacker nothing they do not already
 * have.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile } from 'node:fs/promises';
import { assertPrivateFile, assertTrustedAncestors, TrustError } from '@agent-ledger/shared';

export type ManagedBinState =
  /** Verified — safe to spawn. */
  | 'ok'
  /** Nothing installed at that path (install never ran, or it was removed). */
  | 'missing'
  /** Present but owner/mode/directory chain is not exclusively ours. */
  | 'untrusted'
  /** Present and well-permissioned, but the content is not what was recorded. */
  | 'mismatch';

export interface ManagedBinary {
  /** Absolute path, only when `state === 'ok'`. */
  path: string | null;
  state: ManagedBinState;
  /** Secret-free reason for healthz / the brief. */
  detail: string | null;
}

/** Secret-free, stable wording for a platformTrust refusal on a managed file. */
function describeRefusal(err: unknown): string {
  if (!(err instanceof TrustError)) return 'could not be verified';
  switch (err.code) {
    case 'SYMLINK':
      return 'is a symlink (the install copies, it does not link)';
    case 'REPARSE':
      return 'is a reparse point (junction/symlink)';
    case 'OWNER':
      return 'not owned by the hub user';
    case 'PERMS':
      return 'writable by group/other';
    case 'ACL':
      return 'writable by someone other than {you, SYSTEM, Administrators}';
    case 'IDENTITY':
      return 'is not a regular file';
    default:
      return `trust check refused (${err.code})`;
  }
}

/** Owner is us and nobody outside {root/SYSTEM, us} can write the file itself.
 *  The owner / mode / ACL decision is platformTrust's; unknown = refuse (I1). */
async function fileOwnedByUs(file: string): Promise<{ ok: true } | { ok: false; detail: string }> {
  let st;
  try {
    st = await lstat(file);
  } catch {
    return { ok: false, detail: 'missing' };
  }
  if (st.isSymbolicLink()) return { ok: false, detail: 'is a symlink (the install copies, it does not link)' };
  if (!st.isFile()) return { ok: false, detail: 'is not a regular file' };
  try {
    await assertPrivateFile(file);
  } catch (err) {
    return { ok: false, detail: describeRefusal(err) };
  }
  return { ok: true };
}

function sha256File(file: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(file);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

function digestsEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Verify the install-managed copy at `binPath`. `stopAt` bounds the directory
 * walk (production: `/`; tests: their own sandbox root, because `tmpdir()` is
 * legitimately world-writable).
 */
export async function verifyManagedBinary(
  binPath: string,
  opts: { stopAt?: string } = {},
): Promise<ManagedBinary> {
  const shaPath = `${binPath}.sha256`;

  const bin = await fileOwnedByUs(binPath);
  if (!bin.ok) {
    if (bin.detail === 'missing') return { path: null, state: 'missing', detail: null };
    return { path: null, state: 'untrusted', detail: bin.detail };
  }
  try {
    await assertTrustedAncestors(binPath, {
      executable: true,
      ...(opts.stopAt !== undefined ? { stopAt: opts.stopAt } : {}),
    });
  } catch {
    return { path: null, state: 'untrusted', detail: 'directory is writable outside {root, us}' };
  }

  // The digest is only evidence if the file holding it is as protected as the
  // binary — otherwise an attacker swaps both and the check self-approves.
  const sha = await fileOwnedByUs(shaPath);
  if (!sha.ok) {
    return {
      path: null,
      state: sha.detail === 'missing' ? 'mismatch' : 'untrusted',
      detail: sha.detail === 'missing' ? 'recorded sha256 is missing' : `${shaPath}: ${sha.detail}`,
    };
  }

  const recordedRaw = await readFile(shaPath, 'utf8').catch(() => null);
  const recorded = /^[0-9a-f]{64}$/.exec((recordedRaw ?? '').trim().split(/\s+/)[0] ?? '')?.[0];
  if (recorded === undefined) {
    return { path: null, state: 'mismatch', detail: 'recorded sha256 is corrupt' };
  }
  let actual;
  try {
    actual = await sha256File(binPath);
  } catch {
    return { path: null, state: 'untrusted', detail: 'the binary could not be read' };
  }
  if (!digestsEqual(actual, recorded)) {
    return { path: null, state: 'mismatch', detail: 'sha256 does not match the recorded one' };
  }
  return { path: binPath, state: 'ok', detail: binPath };
}
