/**
 * Hub identity (T12, one hub per machine): which machine flavour is this process on, and a
 * stable fingerprint of "this platform + this ledger directory".
 *
 * Why a fingerprint and not the path: `/v1/healthz` answers an UNauthenticated caller with
 * almost nothing, and the CLI must decide whether the process on the port is "its" hub BEFORE
 * it attaches the bearer token. The path itself (it contains the user name) stays authenticated
 * only; the unauthenticated answer carries `platform` + `ledger_id`. This is a misconfiguration
 * guard (WSL2 localhost forwarding, a second install) — an impostor can compute the same hash,
 * which is why the token, not this value, remains the authority.
 *
 * Pure of trust decisions; deps are injectable so every flavour is testable on any host.
 */

import { createHash } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export type MachinePlatform = 'win32' | 'linux' | 'wsl' | 'darwin' | 'other';

export interface IdentityDeps {
  platform?: NodeJS.Platform;
  release?: () => string;
  /** Does `/proc/sys/fs/binfmt_misc/WSLInterop` exist? */
  hasWslInterop?: () => boolean;
  realpath?: (p: string) => string;
}

export function detectMachinePlatform(deps: IdentityDeps = {}): MachinePlatform {
  const platform = deps.platform ?? process.platform;
  if (platform === 'win32' || platform === 'darwin') return platform;
  if (platform !== 'linux') return 'other';
  const release = (deps.release ?? os.release)();
  if (/microsoft/i.test(release)) return 'wsl';
  const interop = deps.hasWslInterop ?? ((): boolean => existsSync('/proc/sys/fs/binfmt_misc/WSLInterop'));
  return interop() ? 'wsl' : 'linux';
}

function canonical(p: string, platform: MachinePlatform, deps: IdentityDeps): string {
  const real = (deps.realpath ?? ((x: string): string => realpathSync.native(x)))(p);
  if (platform !== 'win32') return path.posix.normalize(real).replace(/(.)\/+$/, '$1');
  let s = real.replace(/\//g, '\\');
  if (s.startsWith('\\\\?\\') && !s.startsWith('\\\\?\\UNC\\')) s = s.slice(4);
  s = path.win32.normalize(s);
  const root = path.win32.parse(s).root;
  while (s.length > root.length && s.endsWith('\\')) s = s.slice(0, -1);
  return s.toLowerCase();
}

/** Resolve `root` (falling back to the lexical path when it does not exist yet). */
function realOrSelf(root: string, platform: MachinePlatform, deps: IdentityDeps): string {
  try {
    return canonical(root, platform, deps);
  } catch {
    return canonical(root, platform, { ...deps, realpath: (x: string) => x });
  }
}

/** sha256 hex over a versioned `platform \0 canonical-realpath` string. */
export function ledgerId(root: string, deps: IdentityDeps = {}): string {
  const platform = detectMachinePlatform(deps);
  return createHash('sha256')
    .update(`agent-ledger:v1\0${platform}\0${realOrSelf(root, platform, deps)}`)
    .digest('hex');
}

export interface HubIdentity {
  platform: MachinePlatform;
  ledger_id: string;
}

/** What a hub for `root` reports (unauthenticated healthz) and what a client expects to see. */
export function hubIdentity(root: string, deps: IdentityDeps = {}): HubIdentity {
  return { platform: detectMachinePlatform(deps), ledger_id: ledgerId(root, deps) };
}
