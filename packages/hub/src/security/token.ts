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
import { constants as FS } from 'node:fs';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

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

/** The token directory must be 0700 and owned by us. */
async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode: DIR_MODE });
  const st = await fs.lstat(dir);
  if (st.isSymbolicLink()) {
    throw new Error(`hub token: directory is a symlink, refusing: ${dir}`);
  }
  if (st.uid !== process.getuid?.()) {
    throw new Error(`hub token: directory is not owned by this user: ${dir}`);
  }
  if ((st.mode & 0o077) !== 0) {
    await fs.chmod(dir, DIR_MODE);
  }
}

/**
 * Atomic, non-overwriting write: tmp (`wx`, 0600) → fsync → `link` → unlink tmp.
 * `link` onto the target fails with EEXIST, so a parallel start never overwrites
 * someone else's token (which `rename` would do, invalidating tokens already
 * handed to hooks).
 */
async function writeNewToken(file: string, token: string): Promise<boolean> {
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const fh = await fs.open(tmp, 'wx', FILE_MODE);
  try {
    await fh.writeFile(`${token}\n`, 'utf8');
    await fh.sync();
  } finally {
    await fh.close();
  }
  try {
    await fs.link(tmp, file);
    return true;
  } catch (err) {
    if (isErrno(err, 'EEXIST')) return false;
    throw err;
  } finally {
    await fs.rm(tmp, { force: true });
  }
}

/** Reads the existing token; `null` = none, or unusable and removed. */
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
  if (st.uid !== process.getuid?.()) {
    throw new Error(`hub token: ${file} is not owned by this user, refusing`);
  }

  const raw = (await fs.readFile(file, 'utf8')).trim();

  // Loose permissions = treat the token as leaked. Fix the permissions AND rotate
  // the value; keeping the old value with only a chmod would leave an active
  // secret that another local account may have read.
  const leaked = (st.mode & 0o177) !== 0;
  if (leaked || !TOKEN_RE.test(raw)) {
    await fs.chmod(file, FILE_MODE);
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
  await ensureDir(path.dirname(file));

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const existing = await readExisting(file);
    if (existing) return existing;

    const token = newToken();
    if (await writeNewToken(file, token)) {
      await fs.access(file, FS.R_OK);
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
