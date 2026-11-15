/**
 * Hub token on disk.
 *
 * Threat model:
 *  - Actor: another local user / another process on the same machine.
 *  - Protected: the bearer secret that allows writes to the ledger (CLI, hooks).
 *  - Failure modes: token readable by group/other, symlink attack on `.hub/token`,
 *    partially written file after a process crash, two parallel hub starts.
 */

import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import {
  assertPrivateDir,
  assertPrivateFile,
  ensurePrivateDir,
  openPrivate,
  TrustError,
  type FsCaps,
} from '@agent-ledger/shared';

const TOKEN_BYTES = 32;
const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
/** base64url of 32 B = 43 chars without padding. */
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

function newToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url');
}

function isErrno(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === code;
}

/** A platformTrust refusal becomes the token module's plain Error (fail-closed). */
function trustToError(err: unknown): unknown {
  if (err instanceof TrustError) return new Error(`hub token: ${err.message}`);
  return err;
}

/**
 * The token directory must be real, owned by us and private (platformTrust: POSIX owner +
 * no group/other write; win32 protected DACL). We never re-ACL or chmod a directory that
 * is group/other-WRITABLE (refused). POSIX only: a directory merely readable/searchable
 * by group/other is tightened to 0700 (owner already verified, so this only removes
 * access) — the behaviour this module always had.
 */
async function ensureDir(dir: string): Promise<FsCaps> {
  try {
    let caps = await ensurePrivateDir(dir);
    if (process.platform !== 'win32') {
      const st = await fs.lstat(dir);
      if ((st.mode & 0o077) !== 0 && caps.posixModes) {
        await fs.chmod(dir, DIR_MODE);
      }
    }
    // Re-verify (secret: nobody else may even look into it) after any tightening.
    caps = await assertPrivateDir(dir, { secret: true });
    return caps;
  } catch (err) {
    throw trustToError(err);
  }
}

/**
 * Atomic, non-overwriting write: tmp (exclusive, 0600) → fsync → `link` → unlink tmp.
 * `link` onto the target fails with EEXIST, so a parallel start never overwrites
 * someone else's token (which `rename` would do, invalidating tokens already
 * handed to hooks). Weak-FS bypass only (filesystem without hard links): the token is
 * created directly with an exclusive open — still never overwriting, but a parallel
 * reader may briefly see a partial file (it fails the format check and is rotated).
 */
async function writeNewToken(file: string, token: string, caps: FsCaps): Promise<boolean> {
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    const fh = await openPrivate(tmp, 'excl', FILE_MODE);
    try {
      await fh.writeFile(`${token}\n`);
      await fh.sync();
    } finally {
      await fh.close();
    }
    try {
      await fs.link(tmp, file);
      return true;
    } catch (err) {
      if (isErrno(err, 'EEXIST')) return false;
      if (!(caps.bypassed && !caps.hardlinks)) throw err;
    }
    // Weak-FS fallback (link unsupported here).
    let fh2;
    try {
      fh2 = await openPrivate(file, 'excl', FILE_MODE);
    } catch (err) {
      if (isErrno(err, 'EEXIST')) return false;
      throw err;
    }
    try {
      await fh2.writeFile(`${token}\n`);
      await fh2.sync();
    } finally {
      await fh2.close();
    }
    return true;
  } catch (err) {
    throw trustToError(err);
  } finally {
    await fs.rm(tmp, { force: true });
  }
}

/** Reads the existing token; `null` = none, or unusable/leaked and removed. */
async function readExisting(file: string): Promise<string | null> {
  let st;
  try {
    st = await fs.lstat(file);
  } catch (err) {
    if (isErrno(err, 'ENOENT')) return null;
    throw err;
  }
  if (!st.isFile()) {
    throw new Error(`hub token: ${file} is not a regular file (symlink/dir), refusing`);
  }

  // Readable by anyone else (mode bits, ACL) or more than one hard link = treat the
  // token as leaked. Rotate the VALUE; keeping the old value with only a permission
  // fix would leave an active secret that another local account may have read.
  try {
    await assertPrivateFile(file, { secret: true });
  } catch (err) {
    if (err instanceof TrustError) {
      if (err.code === 'PERMS' || err.code === 'ACL' || err.code === 'IDENTITY') {
        await fs.rm(file, { force: true });
        return null;
      }
      if (err.code === 'OWNER') throw new Error(`hub token: ${file} is not owned by this user, refusing`);
    }
    throw trustToError(err);
  }

  let raw: string;
  let linked: boolean;
  try {
    const fh = await openPrivate(file, 'read');
    try {
      raw = (await fh.readText()).trim();
      linked = (await fh.stat()).nlink !== 1; // re-checked on the open descriptor
    } finally {
      await fh.close();
    }
  } catch (err) {
    throw trustToError(err);
  }
  if (linked || !TOKEN_RE.test(raw)) {
    await fs.rm(file, { force: true });
    return null;
  }
  return raw;
}

/**
 * Returns the hub token. Reuses an existing one, otherwise generates 32 B CSPRNG
 * (base64url) and stores it atomically. Never logs the value.
 */
export async function loadOrCreateToken(tokenPath: string): Promise<string> {
  const file = path.resolve(tokenPath);
  const caps = await ensureDir(path.dirname(file));

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const existing = await readExisting(file);
    if (existing) return existing;

    const token = newToken();
    if (await writeNewToken(file, token, caps)) {
      await fs.access(file, fsConstants.R_OK);
      return token;
    }
    // Another process created the file in the meantime → read its token.
  }
  throw new Error(`hub token: could not settle on a token in ${file}`);
}

/**
 * Discards the current token and generates a new one. Used by `LedgerGit` when
 * it finds that `.hub/token` was tracked by git — the old token must be treated
 * as leaked regardless of whether the commit made it to `origin`.
 */
export async function rotateToken(tokenPath: string): Promise<string> {
  const file = path.resolve(tokenPath);
  await fs.rm(file, { force: true });
  return loadOrCreateToken(tokenPath);
}
