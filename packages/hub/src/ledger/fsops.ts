import { randomBytes } from 'node:crypto';
import { appendFile, chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { sanitizeLine } from '@agent-ledger/shared';

export async function ensureDir(path: string, mode = 0o700): Promise<void> {
  await mkdir(path, { recursive: true, mode });
}

/** tmp + rename in the same directory — readers never see a half-written file. */
export async function writeAtomic(path: string, data: string, mode = 0o600): Promise<void> {
  const dir = dirname(path);
  await ensureDir(dir);
  const tmp = join(dir, `.${randomBytes(6).toString('hex')}.tmp`);
  await writeFile(tmp, data, { encoding: 'utf8', mode });
  await rename(tmp, path);
}

/**
 * F-1: the last sink before bytes hit an append-only, line-oriented file.
 * Whatever the caller believed, exactly one line is appended — a `\n` in
 * `line` would otherwise forge a second journal event / log entry, and this
 * function is reachable from the journal writer with commit subjects and hook
 * payloads that never passed a zod `singleLine` refinement.
 */
export async function appendLine(path: string, line: string, mode = 0o600): Promise<void> {
  await ensureDir(dirname(path));
  await appendFile(path, `${sanitizeLine(line)}\n`, { encoding: 'utf8', mode });
}

export async function readText(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function ensureFile(path: string, initial: string, mode = 0o600): Promise<boolean> {
  const existing = await readText(path);
  if (existing !== null) return false;
  await writeAtomic(path, initial, mode);
  return true;
}

export async function tighten(path: string, mode: number): Promise<void> {
  try {
    await chmod(path, mode);
  } catch {
    /* best effort */
  }
}
