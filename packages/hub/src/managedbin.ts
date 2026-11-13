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
 *     group/other-writable (`dirChainTrusted`, strict — no group enumeration),
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
import { dirChainTrusted } from './git.ts';

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

/** Owner is us and nobody outside {root, us} can write the file itself. */
async function fileOwnedByUs(
  file: string,
  uid: number | undefined,
): Promise<{ ok: true } | { ok: false; detail: string }> {
  let st;
  try {
    st = await lstat(file);
  } catch {
    return { ok: false, detail: 'missing' };
  }
  if (st.isSymbolicLink()) return { ok: false, detail: 'is a symlink (the install copies, it does not link)' };
  if (!st.isFile()) return { ok: false, detail: 'is not a regular file' };
  if (uid === undefined || st.uid !== uid) return { ok: false, detail: 'not owned by the hub user' };
  if ((st.mode & 0o022) !== 0) return { ok: false, detail: 'writable by group/other' };
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
  const uid = process.getuid?.();
  const shaPath = `${binPath}.sha256`;

  const bin = await fileOwnedByUs(binPath, uid);
  if (!bin.ok) {
    if (bin.detail === 'missing') return { path: null, state: 'missing', detail: null };
    return { path: null, state: 'untrusted', detail: bin.detail };
  }
  if (!(await dirChainTrusted(binPath, uid, opts.stopAt))) {
    return { path: null, state: 'untrusted', detail: 'directory is writable outside {root, us}' };
  }

  // The digest is only evidence if the file holding it is as protected as the
  // binary — otherwise an attacker swaps both and the check self-approves.
  const sha = await fileOwnedByUs(shaPath, uid);
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
