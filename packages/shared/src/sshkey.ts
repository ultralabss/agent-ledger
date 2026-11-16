/** Device key primitives (multi-device F2, docs/multi-device-spec.md §2.1, §6).
 *
 *  No crypto of our own: key generation, signing and verification are
 *  `ssh-keygen` (ed25519, `-Y sign|verify`). This module only (a) validates and
 *  derives public-key facts from the public line, (b) spawns the binary safely.
 *
 *  Spawn stance (same as git.ts / gitleaks.ts): absolute trusted path (never PATH),
 *  `shell: false`, argv built from constants and validated values only, minimal
 *  env, hard timeout that kills the process group, capped output. A missing or
 *  untrusted `ssh-keygen` is a hard error (`SshKeygenError` MISSING) — callers
 *  fail closed, there is no silent skip.
 *
 *  The private key is never read into this process: `-Y sign` gets the key
 *  PATH, the payload goes through stdin, the signature comes back on stdout.
 */

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import { sanitizeField } from './sanitize.ts';
import { assertPrivateFile, ensurePrivateDir, resolveTrustedExecutable, TrustError } from './platformTrust.ts';

/** Signature namespace: a signature made for another purpose never verifies here. */
export const SIGN_NAMESPACE = 'agent-ledger-v1';
/** Namespace git uses for SSH commit signatures (`gpg.format=ssh`). */
export const GIT_NAMESPACE = 'git';
export type SignNamespace = typeof SIGN_NAMESPACE | typeof GIT_NAMESPACE;
const KNOWN_NAMESPACES: readonly string[] = [SIGN_NAMESPACE, GIT_NAMESPACE];
/** `d_` + 10 base32 chars. The only shape allowed into a file name or a principal. */
export const DEVICE_ID_RE = /^d_[a-z2-7]{10}$/;

export const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
const MAX_SIG_BYTES = 4096;
const MAX_OUTPUT_BYTES = 64 * 1024;
const KEYGEN_TIMEOUT_MS = 30_000;
const SIGN_TIMEOUT_MS = 10_000;

export type SshKeygenErrorCode = 'MISSING' | 'FAILED' | 'TIMEOUT' | 'INVALID';

export class SshKeygenError extends Error {
  readonly code: SshKeygenErrorCode;
  constructor(code: SshKeygenErrorCode, message: string) {
    super(message);
    this.name = 'SshKeygenError';
    this.code = code;
  }
}

/* ---------------- public key facts ---------------- */

export interface Ed25519Pub {
  /** Canonical `ssh-ed25519 <base64>` — no comment, no options. */
  line: string;
  /** `SHA256:<base64, no padding>` — what `ssh-keygen -l` prints. */
  fingerprint: string;
  /** `d_` + first 10 base32 chars of sha256(SSH wire blob). */
  deviceId: string;
}

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
const B64_BLOB_RE = /^[A-Za-z0-9+/]{68}$/; // 51 bytes → exactly 68 chars, no padding
const WIRE_PREFIX = Buffer.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32]);

/** Strict parse of one public-key line. With `allowComment` a single trailing
 *  printable-ASCII comment is accepted (ssh-keygen's own `.pub` output) and
 *  dropped; devices.yml never allows one. Anything else → `null`. */
export function parseEd25519Pub(text: string, opts: { allowComment?: boolean } = {}): Ed25519Pub | null {
  if (typeof text !== 'string' || text.length > 512) return null;
  const t = text.replace(/\r?\n$/, '').replace(/ +$/, '');
  if (/[\0-\x1f\x7f]/.test(t)) return null;
  const parts = t.split(' ');
  if (parts[0] !== 'ssh-ed25519') return null;
  const b64 = parts[1];
  if (b64 === undefined || !B64_BLOB_RE.test(b64)) return null;
  if (parts.length > 2 && opts.allowComment !== true) return null;
  if (parts.length > 2 && !/^[\x20-\x7e]*$/.test(parts.slice(2).join(' '))) return null;
  const blob = Buffer.from(b64, 'base64');
  if (blob.length !== 51 || !blob.subarray(0, 19).equals(WIRE_PREFIX)) return null;
  if (blob.toString('base64') !== b64) return null;
  const digest = createHash('sha256').update(blob).digest();
  return {
    line: `ssh-ed25519 ${b64}`,
    fingerprint: `SHA256:${digest.toString('base64').replace(/=+$/, '')}`,
    deviceId: deviceIdFromDigest(digest),
  };
}

function deviceIdFromDigest(digest: Buffer): string {
  // First 50 bits of the digest, 5 bits per char.
  let bits = 0n;
  for (let i = 0; i < 7; i++) bits = (bits << 8n) | BigInt(digest[i] ?? 0);
  bits >>= 6n; // 56 → 50 bits
  let out = '';
  for (let i = 9; i >= 0; i--) out += B32[Number((bits >> BigInt(i * 5)) & 31n)];
  return `d_${out}`;
}

/* ---------------- binary + spawn ---------------- */

export function sshKeygenCandidates(
  platform: NodeJS.Platform = process.platform,
  env: Readonly<Record<string, string | undefined>> = process.env,
): string[] {
  if (platform !== 'win32') return ['/usr/bin/ssh-keygen', '/usr/local/bin/ssh-keygen', '/opt/homebrew/bin/ssh-keygen'];
  const roots: [string | undefined, string[]][] = [
    [env.SystemRoot, ['System32', 'OpenSSH', 'ssh-keygen.exe']],
    [env.ProgramW6432, ['Git', 'usr', 'bin', 'ssh-keygen.exe']],
    [env.ProgramFiles, ['Git', 'usr', 'bin', 'ssh-keygen.exe']],
  ];
  const out: string[] = [];
  for (const [base, rest] of roots) {
    if (typeof base !== 'string' || !/^[A-Za-z]:\\/.test(base) || base.includes('\0')) continue;
    const c = nodePath.win32.join(base, ...rest);
    if (!out.includes(c)) out.push(c);
  }
  return out;
}

let resolvedDefault: Promise<string> | null = null;

/** Absolute, owner/mode/chain-checked `ssh-keygen`. Never PATH. Throws MISSING. */
export function resolveSshKeygen(candidates?: readonly string[], stopAt?: string): Promise<string> {
  const run = async (): Promise<string> => {
    const list = candidates ?? sshKeygenCandidates();
    const info = await resolveTrustedExecutable(list, stopAt !== undefined ? { stopAt } : {});
    if (info.path !== null) return info.path;
    throw new SshKeygenError(
      'MISSING',
      `ssh-keygen: no trusted binary found (tried: ${list.join(', ') || 'none'}${
        info.rejected.length > 0 ? `; rejected: ${info.rejected.join(', ')}` : ''
      }) — install OpenSSH`,
    );
  };
  if (candidates !== undefined) return run();
  resolvedDefault ??= run().catch((err: unknown) => {
    resolvedDefault = null; // do not cache a failure
    throw err;
  });
  return resolvedDefault;
}

function minimalEnv(): Record<string, string> {
  const env: Record<string, string> = { LC_ALL: 'C' };
  if (process.platform === 'win32') {
    const root = process.env.SystemRoot;
    if (typeof root === 'string' && /^[A-Za-z]:\\/.test(root) && !root.includes('\0')) env.SystemRoot = root;
  }
  return env; // no SSH_AUTH_SOCK, no HOME: nothing but the named key file can sign
}

interface RunResult {
  code: number;
  stdout: Buffer;
  stderr: string;
}

function run(bin: string, args: string[], input: Uint8Array | null, timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(bin, args, {
        detached: true, // own process group → the timeout kills the whole tree
        env: minimalEnv(),
        stdio: [input === null ? 'ignore' : 'pipe', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
      });
    } catch {
      reject(new SshKeygenError('FAILED', 'ssh-keygen could not be started'));
      return;
    }
    const out: Buffer[] = [];
    let outBytes = 0;
    let errText = '';
    let settled = false;
    let over = false;
    const kill = (): void => {
      try {
        if (child.pid !== undefined && process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    };
    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => {
      kill();
      settle(() => reject(new SshKeygenError('TIMEOUT', `ssh-keygen timed out after ${timeoutMs} ms`)));
    }, timeoutMs);
    child.stdout?.on('data', (d: Buffer) => {
      outBytes += d.length;
      if (outBytes > MAX_OUTPUT_BYTES) {
        over = true;
        kill();
        return;
      }
      out.push(d);
    });
    child.stderr?.on('data', (d: Buffer) => {
      if (errText.length < 2000) errText += d.toString('utf8');
    });
    child.on('error', () => settle(() => reject(new SshKeygenError('FAILED', 'ssh-keygen could not be started'))));
    child.on('close', (code) => {
      settle(() => {
        if (over) reject(new SshKeygenError('FAILED', 'ssh-keygen output exceeded the cap'));
        else resolve({ code: code ?? -1, stdout: Buffer.concat(out), stderr: errText });
      });
    });
    if (input !== null && child.stdin !== null) {
      child.stdin.on('error', () => {
        /* EPIPE: the exit code tells the story */
      });
      child.stdin.end(Buffer.from(input));
    }
  });
}

function failed(what: string, r: RunResult): SshKeygenError {
  return new SshKeygenError('FAILED', `${what} failed (exit ${r.code}): ${sanitizeField(r.stderr.trim(), 160)}`);
}

function requireAbsolute(p: string, what: string): void {
  const abs = process.platform === 'win32' ? /^[A-Za-z]:\\/.test(p) : nodePath.posix.isAbsolute(p);
  if (!abs || /[\0\r\n]/.test(p)) throw new SshKeygenError('INVALID', `${what} must be an absolute path`);
}

/* ---------------- keygen / sign / verify ---------------- */

/** `ssh-keygen -t ed25519 -N ""` into `keyFile` (+ `.pub`). Refuses to overwrite:
 *  the caller (devicestore) generates into a fresh private directory. */
export async function generateKeyPair(keyFile: string, bin?: string): Promise<void> {
  requireAbsolute(keyFile, 'key file');
  const exe = bin ?? (await resolveSshKeygen());
  const r = await run(exe, ['-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', keyFile], null, KEYGEN_TIMEOUT_MS);
  if (r.code !== 0) throw failed('ssh-keygen key generation', r);
}

/** Public line of an existing private key (`ssh-keygen -y`). The key stays inside ssh-keygen. */
export async function publicKeyOf(keyFile: string, bin?: string): Promise<Ed25519Pub> {
  requireAbsolute(keyFile, 'key file');
  const exe = bin ?? (await resolveSshKeygen());
  const r = await run(exe, ['-y', '-f', keyFile], null, SIGN_TIMEOUT_MS);
  if (r.code !== 0) throw failed('ssh-keygen -y', r);
  const pub = parseEd25519Pub(r.stdout.toString('utf8'), { allowComment: true });
  if (pub === null) throw new SshKeygenError('INVALID', 'ssh-keygen returned something that is not an ed25519 public key');
  return pub;
}

export interface SignOpts {
  keyFile: string;
  /** Test seam; default = trusted resolved ssh-keygen. */
  bin?: string;
  timeoutMs?: number;
}

/** Armored SSH signature (`-----BEGIN SSH SIGNATURE-----`) over `bytes`, namespace
 *  `agent-ledger-v1`. The key file must pass the private-file check (owner-only,
 *  not a symlink) BEFORE ssh-keygen is started. */
export async function signPayload(bytes: Uint8Array, opts: SignOpts): Promise<string> {
  if (bytes.length > MAX_PAYLOAD_BYTES) throw new SshKeygenError('INVALID', 'payload too large to sign');
  requireAbsolute(opts.keyFile, 'key file');
  try {
    await assertPrivateFile(opts.keyFile, { secret: true });
  } catch (err) {
    if (err instanceof TrustError) throw new SshKeygenError('FAILED', `device key refused: ${err.message}`);
    throw err;
  }
  const exe = opts.bin ?? (await resolveSshKeygen());
  const r = await run(exe, ['-Y', 'sign', '-n', SIGN_NAMESPACE, '-f', opts.keyFile], bytes, opts.timeoutMs ?? SIGN_TIMEOUT_MS);
  if (r.code !== 0) throw failed('signing', r);
  const sig = r.stdout.toString('utf8');
  if (!isArmoredSignature(sig)) throw new SshKeygenError('INVALID', 'signing produced no valid signature');
  return sig;
}

export function isArmoredSignature(sig: string): boolean {
  return (
    sig.length <= MAX_SIG_BYTES &&
    /^-----BEGIN SSH SIGNATURE-----\n[A-Za-z0-9+/=\n]+-----END SSH SIGNATURE-----\n?$/.test(sig)
  );
}

export interface VerifyOpts {
  /** Private directory under which a per-call 0700 scratch dir is created and ALWAYS removed. */
  tmpRoot: string;
  bin?: string;
  timeoutMs?: number;
  /** Signature namespace the signature must have been made for (default `agent-ledger-v1`).
   *  A signature for another namespace never verifies: the allowed-signers entry and `-n`
   *  both carry exactly this value. Allowlisted — never taken from input as-is. */
  namespace?: SignNamespace;
}

/** Private scratch dir (0700 / owner-only ACL) that is removed even when `fn` throws.
 *  The root is created-or-VERIFIED private on every platform (`ensurePrivateDir`: a root
 *  that exists with loose permissions, a foreign owner or a symlink is refused, never reused). */
export async function withPrivateTmp<T>(root: string, fn: (dir: string) => Promise<T>): Promise<T> {
  requireAbsolute(root, 'tmp root');
  await ensurePrivateDir(root);
  const dir = nodePath.join(root, randomBytes(8).toString('hex'));
  if (process.platform === 'win32') await ensurePrivateDir(dir);
  else await mkdir(dir, { mode: 0o700 });
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** `true` only for a good signature by exactly `pubkey` over exactly `bytes`.
 *  A bad / malformed signature or foreign key → `false`. A broken environment
 *  (no ssh-keygen, timeout, spawn failure) THROWS: callers treat both as "not
 *  verified" (fail closed) but can tell the operator why. */
export async function verifyPayload(
  bytes: Uint8Array,
  sig: string,
  pubkey: string,
  opts: VerifyOpts,
): Promise<boolean> {
  const pub = parseEd25519Pub(pubkey);
  if (pub === null) throw new SshKeygenError('INVALID', 'pubkey is not a canonical ssh-ed25519 line');
  const ns = opts.namespace ?? SIGN_NAMESPACE;
  if (!KNOWN_NAMESPACES.includes(ns)) throw new SshKeygenError('INVALID', 'unknown signature namespace');
  if (bytes.length > MAX_PAYLOAD_BYTES) return false;
  if (!isArmoredSignature(sig)) return false;
  const exe = opts.bin ?? (await resolveSshKeygen());
  return withPrivateTmp(opts.tmpRoot, async (dir) => {
    const allowed = nodePath.join(dir, 'allowed');
    const sigFile = nodePath.join(dir, 'sig');
    await writeFile(allowed, `signer namespaces="${ns}" ${pub.line}\n`, { mode: 0o600, flag: 'wx' });
    await writeFile(sigFile, sig.endsWith('\n') ? sig : `${sig}\n`, { mode: 0o600, flag: 'wx' });
    const r = await run(
      exe,
      ['-Y', 'verify', '-f', allowed, '-I', 'signer', '-n', ns, '-s', sigFile],
      bytes,
      opts.timeoutMs ?? SIGN_TIMEOUT_MS,
    );
    return r.code === 0;
  });
}

/* ---------------- git signing recipe (not wired into the commit path before F3) ---------------- */

export interface GitSigningInput {
  sshKeygenBin: string;
  /** Private key file (`.hub/device/key`). */
  keyFile: string;
  /** `.hub/allowed_signers`. */
  allowedSignersFile: string;
}

/** `git -c …` argument list that makes `git commit` sign with the device key
 *  (`gpg.format=ssh`) via the ABSOLUTE ssh-keygen (`gpg.ssh.program`, so git does
 *  not search PATH). Pure: returns argv, runs nothing. */
export function gitSigningArgs(i: GitSigningInput): string[] {
  for (const [what, p] of [
    ['ssh-keygen', i.sshKeygenBin],
    ['signing key', i.keyFile],
    ['allowed signers', i.allowedSignersFile],
  ] as const) {
    requireAbsolute(p, what);
  }
  return [
    '-c',
    'gpg.format=ssh',
    '-c',
    `gpg.ssh.program=${i.sshKeygenBin}`,
    '-c',
    `user.signingkey=${i.keyFile}`,
    '-c',
    `gpg.ssh.allowedSignersFile=${i.allowedSignersFile}`,
    '-c',
    'commit.gpgsign=true',
  ];
}
