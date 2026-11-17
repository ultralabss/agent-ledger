/** First-contact host key handling for `sync init|join` (docs/f3b-b4-plan.md §2.1, E-5, T-B4-8).
 *
 *  `Gitx` runs ssh with `StrictHostKeyChecking=yes` and its OWN empty `known_hosts`, so the first contact
 *  always fails. This module fetches the candidate keys (`ssh-keyscan`, UNAUTHENTICATED), computes the
 *  `SHA256:` fingerprint a human compares out of band, and pins ONE accepted key into the private file.
 *
 *  Threat model:
 *   - Actor: a network attacker (MITM on first contact), a hostile or compromised host answering with
 *     junk, a local process racing the pin file, a caller that pins before the human confirmed.
 *   - Protected: the pin file is the trust anchor for every later sync contact. Nothing reaches it that
 *     was not (a) shaped like exactly one `<host> <type> <base64>` line for exactly the asked host, and
 *     (b) handed to `pinHostKey` by a caller that already got the human confirmation (this module never
 *     decides trust, it only refuses to silently REPLACE a pinned key).
 *   - Failure modes: output flood, option injection through the host name, a key blob whose embedded type
 *     differs from its label, a symlinked / foreign-owned / torn pin file, a downgrade by "re-pinning".
 *   - Stance: fail closed, fixed error codes. Nothing from ssh-keyscan's stderr, the host list or a key
 *     blob is ever put into an error message; only the sanitised host token and `SHA256:` fingerprints
 *     are shown by callers. Residual: `ssh-keyscan` is unauthenticated, the human fingerprint check is
 *     the only anchor. UNVERIFIED on Windows (binary location, `[host]:port` form under MSYS ssh).
 */

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, open, rm } from 'node:fs/promises';
import nodePath from 'node:path';
import { ensurePrivateDir, openPrivate, renameRetry, resolveTrustedExecutable, TrustError } from '@agent-ledger/shared';
import { sshCandidates } from './gitx.ts';

export type HostKeyErrorCode =
  | 'HOST'
  | 'PORT'
  | 'LINE'
  | 'BINARY'
  | 'SPAWN'
  | 'TIMEOUT'
  | 'FAILED'
  | 'OUTPUT'
  | 'NO_KEYS'
  | 'CORRUPT'
  | 'UNSAFE'
  | 'REPIN_REFUSED'
  | 'IO';

export class HostKeyError extends Error {
  readonly code: HostKeyErrorCode;
  constructor(code: HostKeyErrorCode, message: string) {
    super(message);
    this.name = 'HostKeyError';
    this.code = code;
  }
}

export const KEYSCAN_MAX_OUTPUT = 16 * 1024;
export const KNOWN_HOSTS_MAX_BYTES = 8 * 1024;
export const KEYSCAN_TIMEOUT_MS = 10_000;
const MAX_BLOB_BYTES = 4096;
const MAX_KEYS = 3;

/** Same shape as the DNS / IPv4 host of `validateRemoteUrl`; no `-` start, no `:`, no brackets (IPv6 literals unsupported). */
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const KEY_TYPES = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'] as const;
export type HostKeyType = (typeof KEY_TYPES)[number];
const B64_RE = /^[A-Za-z0-9+/]{16,6000}={0,2}$/;

export interface HostKey {
  host: string;
  port: number;
  type: HostKeyType;
  /** `<host-token> <type> <base64>` exactly as it would sit in `known_hosts`. */
  line: string;
  /** `SHA256:<base64, no padding>` (what `ssh-keygen -l` prints). */
  fingerprint: string;
}

function checkHost(host: unknown): string {
  if (typeof host !== 'string' || !HOST_RE.test(host)) throw new HostKeyError('HOST', 'host name refused');
  return host.toLowerCase();
}

function checkPort(port: unknown): number {
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) throw new HostKeyError('PORT', 'port refused');
  return port;
}

/** The first field ssh itself writes and looks up: plain host for port 22, `[host]:port` otherwise. */
export function hostToken(host: string, port: number): string {
  const h = checkHost(host);
  const p = checkPort(port);
  return p === 22 ? h : `[${h}]:${String(p)}`;
}

/** `<type> <base64>` -> blob + fingerprint, or `null`. The blob's embedded type name must equal the label
 *  (a mislabelled blob is how an attacker would smuggle a different key past a comparison). */
function parseKeyPart(type: string, b64: string): { type: HostKeyType; b64: string; fingerprint: string } | null {
  if (!(KEY_TYPES as readonly string[]).includes(type) || !B64_RE.test(b64)) return null;
  const blob = Buffer.from(b64, 'base64');
  if (blob.length < 8 || blob.length > MAX_BLOB_BYTES || blob.toString('base64') !== b64) return null;
  const nameLen = blob.readUInt32BE(0);
  if (nameLen !== type.length || blob.length < 4 + nameLen || blob.subarray(4, 4 + nameLen).toString('latin1') !== type) return null;
  // fixed-size key types: name + 32-byte key / name + curve name + 65-byte point (a truncated blob is not a key)
  if (type === 'ssh-ed25519' && blob.length !== 4 + 11 + 4 + 32) return null;
  if (type === 'ecdsa-sha2-nistp256' && blob.length !== 4 + 19 + 4 + 8 + 4 + 65) return null;
  const fingerprint = `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
  return { type: type as HostKeyType, b64, fingerprint };
}

/** `SHA256:` fingerprint of a `[<host>] <type> <base64>` line (a `known_hosts` entry or a bare key). `null` when
 *  the line is not exactly that (extra fields, options, comment, unknown type, mislabelled blob). */
export function fingerprintOf(line: unknown): string | null {
  if (typeof line !== 'string' || line.length > 8192 || /[^\x20-\x7e]/.test(line)) return null;
  const parts = line.split(' ');
  if (parts.length !== 2 && parts.length !== 3) return null;
  // a leading field is a host token only: `command="..."`, `cert-authority`, `@revoked`, lists and wildcards are not
  if (parts.length === 3 && !/^[A-Za-z0-9[\].:-]{1,300}$/.test(parts[0] as string)) return null;
  const type = parts[parts.length - 2] as string;
  const b64 = parts[parts.length - 1] as string;
  return parseKeyPart(type, b64)?.fingerprint ?? null;
}

/* ---------------- scan ---------------- */

export interface ScanOptions {
  timeoutMs?: number;
  /** Test seam: absolute path of the scanner. Production resolves a trusted `ssh-keyscan` next to the trusted ssh. */
  bin?: string;
}

function keyscanCandidates(): string[] {
  const win = process.platform === 'win32';
  const api = win ? nodePath.win32 : nodePath.posix;
  return sshCandidates().map((c) => api.join(api.dirname(c), win ? 'ssh-keyscan.exe' : 'ssh-keyscan'));
}

interface Captured {
  code: number;
  stdout: string;
  timedOut: boolean;
  capped: boolean;
}

function capture(bin: string, argv: string[], timeoutMs: number): Promise<Captured> {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(bin, argv, {
        env: process.platform === 'win32' && process.env.SystemRoot !== undefined ? { SystemRoot: process.env.SystemRoot } : {}, // nothing inherited
        stdio: ['ignore', 'pipe', 'ignore'], // stderr is never read: it may carry hostile text
        shell: false,
        windowsHide: true,
        detached: process.platform !== 'win32',
      });
    } catch {
      reject(new HostKeyError('SPAWN', 'ssh-keyscan could not be started'));
      return;
    }
    const kill = (): void => {
      try {
        if (child.pid !== undefined && process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        try {
          child.kill('SIGKILL');
        } catch {
          /* already gone */
        }
      }
    };
    const out: Buffer[] = [];
    let bytes = 0;
    let timedOut = false;
    let capped = false;
    let settled = false;
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, timeoutMs);
    child.stdout.on('data', (d: Buffer) => {
      if (capped) return;
      bytes += d.length;
      if (bytes > KEYSCAN_MAX_OUTPUT) {
        capped = true;
        kill();
        return;
      }
      out.push(d);
    });
    child.on('error', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new HostKeyError('SPAWN', 'ssh-keyscan could not be started'));
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout: capped ? '' : Buffer.concat(out).toString('latin1'), timedOut, capped });
    });
  });
}

/** Candidate host keys for `host:port`, at most one per type, in a stable order (ed25519, ecdsa, rsa).
 *  Only lines that are exactly `<token> <type> <base64>` for exactly the asked host are accepted; comments
 *  and everything else are dropped. NO trust decision: the caller shows the fingerprint and asks a human. */
export async function scanHostKeys(host: string, port: number, opts: ScanOptions = {}): Promise<HostKey[]> {
  const h = checkHost(host);
  const p = checkPort(port);
  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? KEYSCAN_TIMEOUT_MS, 1_000), 60_000);
  let bin = opts.bin;
  if (bin !== undefined) {
    if (!(process.platform === 'win32' ? /^[A-Za-z]:[\\/]/.test(bin) : nodePath.posix.isAbsolute(bin)) || /[\0\r\n]/.test(bin)) {
      throw new HostKeyError('BINARY', 'scanner path must be absolute');
    }
  } else {
    const info = await resolveTrustedExecutable(keyscanCandidates());
    if (info.path === null) throw new HostKeyError('BINARY', 'ssh-keyscan: no trusted binary found');
    bin = info.path;
  }
  const res = await capture(bin, ['-T', String(Math.ceil(timeoutMs / 1000)), '-t', 'ed25519,ecdsa,rsa', '-p', String(p), '--', h], timeoutMs);
  if (res.timedOut) throw new HostKeyError('TIMEOUT', 'ssh-keyscan timed out');
  if (res.capped) throw new HostKeyError('OUTPUT', 'ssh-keyscan output exceeded the cap');
  const token = hostToken(h, p);
  const found = new Map<HostKeyType, HostKey>();
  for (const raw of res.stdout.split('\n')) {
    const lineText = raw.replace(/\r$/, '');
    if (lineText === '' || lineText.startsWith('#')) continue;
    if (/[^\x20-\x7e]/.test(lineText)) continue;
    const parts = lineText.split(' ');
    if (parts.length !== 3 || (parts[0] as string).toLowerCase() !== token) continue;
    const k = parseKeyPart(parts[1] as string, parts[2] as string);
    if (k === null || found.has(k.type)) continue;
    found.set(k.type, { host: h, port: p, type: k.type, line: `${token} ${k.type} ${k.b64}`, fingerprint: k.fingerprint });
    if (found.size >= MAX_KEYS) break;
  }
  if (found.size === 0) {
    throw new HostKeyError(res.code === 0 ? 'NO_KEYS' : 'FAILED', res.code === 0 ? 'the host offered no usable key' : 'ssh-keyscan failed');
  }
  return KEY_TYPES.flatMap((t) => found.get(t) ?? []);
}

/* ---------------- pin ---------------- */

/** Strict `known_hosts` reader: every non-empty line must be `<token> <type> <base64>` with a valid blob.
 *  Returns `[token, type, b64]` triples; anything else (hashed hosts, markers, comments, wildcards) is CORRUPT:
 *  this file is written only by `pinHostKey`, so a foreign line means somebody else touched it. */
function parsePinFile(text: string): [string, HostKeyType, string][] {
  const rows: [string, HostKeyType, string][] = [];
  const seen = new Set<string>();
  for (const l of text.split('\n')) {
    if (l === '') continue;
    const parts = l.split(' ');
    const k = parts.length === 3 && /^[A-Za-z0-9[\].:-]{1,300}$/.test(parts[0] as string) ? parseKeyPart(parts[1] as string, parts[2] as string) : null;
    if (k === null || seen.has(parts[0] as string)) throw new HostKeyError('CORRUPT', 'known_hosts has an unexpected line');
    seen.add(parts[0] as string);
    rows.push([parts[0] as string, k.type, k.b64]);
  }
  return rows;
}

async function readPinFile(path: string): Promise<string | null> {
  let st;
  try {
    st = await lstat(path, { bigint: true });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new HostKeyError('IO', 'cannot stat known_hosts');
  }
  if (st.isSymbolicLink() || !st.isFile()) throw new HostKeyError('UNSAFE', 'known_hosts is not a regular file');
  if (st.size > BigInt(KNOWN_HOSTS_MAX_BYTES)) throw new HostKeyError('CORRUPT', 'known_hosts is too large');
  try {
    const h = await openPrivate(path, 'read');
    try {
      const text = await h.readText();
      if (Buffer.byteLength(text, 'utf8') > KNOWN_HOSTS_MAX_BYTES) throw new HostKeyError('CORRUPT', 'known_hosts is too large');
      return text;
    } finally {
      await h.close().catch(() => undefined);
    }
  } catch (err) {
    if (err instanceof HostKeyError) throw err;
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    if (err instanceof TrustError) throw new HostKeyError('UNSAFE', 'known_hosts failed the ownership check');
    throw new HostKeyError('IO', 'cannot read known_hosts');
  }
}

async function fsyncDir(dir: string): Promise<void> {
  let fh;
  try {
    fh = await open(dir, 'r');
  } catch {
    if (process.platform === 'win32') return; // directories cannot be opened there; NOT verified
    throw new HostKeyError('IO', 'cannot sync the sync directory');
  }
  try {
    await fh.sync();
  } catch (err) {
    const c = (err as NodeJS.ErrnoException).code;
    if (c !== 'EINVAL' && c !== 'ENOTSUP' && process.platform !== 'win32') throw new HostKeyError('IO', 'cannot sync the sync directory');
  } finally {
    await fh.close().catch(() => undefined);
  }
}

export interface PinResult {
  /** `false` = the identical key was already pinned (nothing written). */
  written: boolean;
  fingerprint: string;
}

/** Pin ONE host key into `<syncDir>/known_hosts` (private dir 0700, file 0600, tmp + fsync + rename). `line` is
 *  `[<host>] <type> <base64>` of a key the HUMAN confirmed; the stored token is always recomputed here from
 *  `host`/`port` (plain host for 22, `[host]:port` otherwise), so a caller cannot pin under another name.
 *  One line per host: a DIFFERENT key already pinned for that host is refused (`REPIN_REFUSED`) unless
 *  `repin: true` (an explicit human act, e.g. `--repin`). The same key again is a no-op. */
export async function pinHostKey(
  syncDir: string,
  host: string,
  port: number,
  line: string,
  opts: { repin?: boolean } = {},
): Promise<PinResult> {
  const token = hostToken(host, port);
  if (typeof line !== 'string' || line.length > 8192 || /[^\x20-\x7e]/.test(line)) throw new HostKeyError('LINE', 'key line refused');
  const parts = line.split(' ');
  if (parts.length !== 2 && parts.length !== 3) throw new HostKeyError('LINE', 'key line refused');
  if (parts.length === 3 && (parts[0] as string).toLowerCase() !== token) throw new HostKeyError('LINE', 'key line names another host');
  const key = parseKeyPart(parts[parts.length - 2] as string, parts[parts.length - 1] as string);
  if (key === null) throw new HostKeyError('LINE', 'key line refused');
  if (!(process.platform === 'win32' ? /^[A-Za-z]:[\\/]/.test(syncDir) : nodePath.posix.isAbsolute(syncDir))) throw new HostKeyError('IO', 'sync directory must be absolute');
  try {
    await ensurePrivateDir(syncDir);
  } catch (err) {
    if (err instanceof TrustError) throw new HostKeyError('UNSAFE', 'sync directory is not private to this user');
    throw new HostKeyError('IO', 'cannot create the sync directory');
  }
  const path = nodePath.join(syncDir, 'known_hosts');
  const text = await readPinFile(path);
  const rows = text === null ? [] : parsePinFile(text);
  const at = rows.findIndex((r) => r[0] === token);
  if (at >= 0) {
    const [, t, b] = rows[at] as [string, HostKeyType, string];
    if (t === key.type && b === key.b64) return { written: false, fingerprint: key.fingerprint };
    if (opts.repin !== true) throw new HostKeyError('REPIN_REFUSED', 'a different key is already pinned for this host');
    rows[at] = [token, key.type, key.b64];
  } else {
    rows.push([token, key.type, key.b64]);
  }
  const out = `${rows.map((r) => r.join(' ')).join('\n')}\n`;
  if (Buffer.byteLength(out, 'utf8') > KNOWN_HOSTS_MAX_BYTES) throw new HostKeyError('CORRUPT', 'known_hosts would exceed its size cap');
  const tmp = `${path}.${String(process.pid)}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    const h = await openPrivate(tmp, 'excl', 0o600);
    try {
      await h.writeFile(out);
      await h.sync();
    } finally {
      await h.close();
    }
    await renameRetry(tmp, path);
  } catch (err) {
    await rm(tmp, { force: true }).catch(() => undefined);
    if (err instanceof TrustError) throw new HostKeyError('UNSAFE', 'sync directory failed the ownership check');
    throw new HostKeyError('IO', 'cannot write known_hosts');
  }
  await fsyncDir(syncDir);
  return { written: true, fingerprint: key.fingerprint };
}
