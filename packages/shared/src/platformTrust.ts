/**
 * platformTrust: the single place that decides whether a path, a directory chain or a
 * binary is private to us / trustworthy. Scattered `process.getuid()` / `O_NOFOLLOW` /
 * mode-bit checks (spool, token, pendingmark, sessions, managedbin, git) migrate here
 * (work packages S2..S4); until then this module is additive.
 *
 * Threat model:
 *  - Actors: another local account, a malicious repo / checkout, a process racing us.
 *  - Protects: the ledger, spool and token (confidentiality + integrity), and the
 *    binaries we execute.
 *  - Fails: symlink / junction / reparse redirection, TOCTOU between check and use,
 *    hard-link plants, group/other (or ACL) access, a filesystem that cannot express
 *    permissions at all, a missing platform primitive (no uid, no O_NOFOLLOW, no
 *    PowerShell). Every one of those is a refusal, never a pass (I1).
 *
 * POSIX backend: the logic that used to live in spool.ts / token.ts / git.ts, moved
 * WITHOUT loosening. win32 backend: SDDL via one locked PowerShell call per batch
 * (`win-ps.ts`), parsed and judged by the pure `sddl.ts`.
 *
 * Weak-filesystem bypass (I5): `LEDGER_ALLOW_WEAK_FS` set to exactly `1` in the process
 * environment relaxes ONLY the capability the filesystem cannot express (mode bits,
 * uid, hard links, ACLs on non-ACL volumes). Symlink / reparse / regular-file / identity
 * checks and fixable misconfiguration (group-writable dir on a good filesystem) are
 * never relaxed.
 */
import { randomBytes } from 'node:crypto';
import { constants as FSC, type BigIntStats } from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as nodePath from 'node:path';
import { evaluateSddl, parseSddl, type SddlKind } from './sddl.ts';
import {
  assertWinPath,
  defaultSpawnFile,
  inspectWindowsPaths,
  setPrivateAcl,
  WinPsError,
  type SpawnFile,
  type WinInspect,
  type WinPathInfo,
  type WinPsContext,
} from './win-ps.ts';

// ---- public types ---------------------------------------------------------------------

export type TrustCode =
  | 'SYMLINK'
  | 'REPARSE'
  | 'OWNER'
  | 'PERMS'
  | 'ACL'
  | 'WEAK_FS'
  | 'CHAIN'
  | 'PROBE_FAILED'
  | 'IDENTITY';

export class TrustError extends Error {
  readonly code: TrustCode;
  readonly path: string | undefined;
  constructor(code: TrustCode, message: string, path?: string) {
    super(message);
    this.name = 'TrustError';
    this.code = code;
    this.path = path;
  }
}

export const ELEVATED_MESSAGE = 'refusing to run elevated: do not run agent-ledger as Administrator';

export interface FsCaps {
  /** chmod/mode bits round-trip (0600 then 0640 observed). */
  posixModes: boolean;
  /** A file we create is owned by our uid. */
  ownerMatches: boolean;
  /** link() works and nlink goes to 2. */
  hardlinks: boolean;
  /** win32: the volume enforces NTFS/ReFS ACLs. */
  acl: boolean;
  fsType: string;
  caseInsensitive: boolean;
  /** At least one capability above is missing (or WSL DrvFs/9p). */
  weak: boolean;
  /** `weak` AND `LEDGER_ALLOW_WEAK_FS` is exactly `1`. */
  bypassed: boolean;
  /** Human-readable list of what is missing. */
  reasons: string[];
}

/** Stat result with bigint file ids (compared for identity) and plain-number owner/mode. */
export interface StatLike {
  isSymbolicLink(): boolean;
  isDirectory(): boolean;
  isFile(): boolean;
  uid: number;
  gid: number;
  mode: number;
  nlink: number;
  dev: bigint;
  ino: bigint;
  ctimeNs: bigint;
}

export interface TrustHandle {
  stat(): Promise<StatLike>;
  writeFile(data: string | Uint8Array): Promise<void>;
  readText(): Promise<string>;
  truncate(len: number): Promise<void>;
  /** fchmod: acts on the open descriptor, never re-resolves a path (W1). */
  chmod(mode: number): Promise<void>;
  sync(): Promise<void>;
  close(): Promise<void>;
}

export interface TrustFs {
  lstat(p: string): Promise<StatLike>;
  stat(p: string): Promise<StatLike>;
  mkdir(p: string, mode: number, recursive?: boolean): Promise<void>;
  rmdir(p: string): Promise<void>;
  rm(p: string): Promise<void>;
  open(p: string, flags: number, mode: number): Promise<TrustHandle>;
  link(existing: string, created: string): Promise<void>;
  readdir(p: string): Promise<string[]>;
  realpath(p: string): Promise<string>;
  readText(p: string): Promise<string>;
}

interface CacheEntry {
  kind: 'caps' | 'verified';
  dev: bigint;
  ino: bigint;
  ctimeNs: bigint;
  at: number;
  caps: Omit<FsCaps, 'bypassed'>;
}

export interface TrustDeps {
  platform: NodeJS.Platform;
  getuid: () => number | undefined;
  fs: TrustFs;
  spawnFile: SpawnFile;
  env: Readonly<Record<string, string | undefined>>;
  now: () => number;
  /** `os.release()` (WSL detection). */
  release: () => string;
  homedir: () => string;
  /** `fs.constants` (injectable so tests need not depend on the host OS). */
  constants: Readonly<Record<string, number | undefined>>;
  cache: Map<string, CacheEntry>;
}

export type OpenMode = 'append' | 'excl' | 'trunc' | 'read';

export interface AncestorOpts {
  /** Highest directory the POSIX walk checks, inclusive (default `/`; tests bound it). */
  stopAt?: string;
  /** POSIX only: explicit opt-in for group-writable components (never enumerated). */
  groupWritableOk?: (gid: number) => Promise<boolean>;
  /** The chain leads to an executable (TrustedInstaller accepted on win32). */
  executable?: boolean;
  /** win32: `path` is a directory we are about to create (its parent must not hand out
   *  inheritable write access). */
  newChild?: boolean;
}

export interface TrustedExecutableInfo {
  /** The trusted absolute path, or null. */
  path: string | null;
  /** Candidates that exist but failed the rules, with the reason. */
  rejected: string[];
  /** Candidates that were not absolute (win32: drive-rooted) and were never looked at. */
  dropped: string[];
  candidates: readonly string[];
  foundUntrusted: boolean;
  /** POSIX diagnosis only: would pass if group-write were tolerated. Never widens trust. */
  groupWritable: boolean;
}

// ---- deps ----------------------------------------------------------------------------

const CACHE_TTL_MS = 10 * 60 * 1000;
const moduleCache = new Map<string, CacheEntry>();

function toStatLike(st: BigIntStats): StatLike {
  return {
    isSymbolicLink: () => st.isSymbolicLink(),
    isDirectory: () => st.isDirectory(),
    isFile: () => st.isFile(),
    uid: Number(st.uid),
    gid: Number(st.gid),
    mode: Number(st.mode),
    nlink: Number(st.nlink),
    dev: st.dev,
    ino: st.ino,
    ctimeNs: st.ctimeNs,
  };
}

function wrapHandle(fh: fsp.FileHandle): TrustHandle {
  return {
    stat: async () => toStatLike(await fh.stat({ bigint: true })),
    writeFile: (d) => fh.writeFile(d),
    readText: () => fh.readFile('utf8'),
    truncate: (n) => fh.truncate(n),
    chmod: (m) => fh.chmod(m),
    sync: () => fh.sync(),
    close: () => fh.close(),
  };
}

export const nodeTrustFs: TrustFs = {
  lstat: async (p) => toStatLike(await fsp.lstat(p, { bigint: true })),
  stat: async (p) => toStatLike(await fsp.stat(p, { bigint: true })),
  mkdir: async (p, mode, recursive = false) => {
    await fsp.mkdir(p, { mode, recursive });
  },
  rmdir: (p) => fsp.rmdir(p),
  rm: (p) => fsp.rm(p, { force: true }),
  open: async (p, flags, mode) => wrapHandle(await fsp.open(p, flags, mode)),
  link: (a, b) => fsp.link(a, b),
  readdir: (p) => fsp.readdir(p),
  realpath: (p) => fsp.realpath(p),
  readText: (p) => fsp.readFile(p, 'utf8'),
};

/** Production dependencies, with any field overridable (the DI seam for tests). */
export function createTrustDeps(overrides: Partial<TrustDeps> = {}): TrustDeps {
  return {
    platform: process.platform,
    getuid: () => process.getuid?.(),
    fs: nodeTrustFs,
    spawnFile: defaultSpawnFile,
    env: process.env,
    now: () => Date.now(),
    release: () => os.release(),
    homedir: () => os.homedir(),
    constants: FSC,
    cache: moduleCache,
    ...overrides,
  };
}

/** Forget cached probe / verification results (hub: at start and every 10 min). */
export function invalidateFsProbeCache(deps: Partial<TrustDeps> = {}): void {
  (deps.cache ?? moduleCache).clear();
}

// ---- small helpers --------------------------------------------------------------------

function pathApi(deps: TrustDeps): typeof nodePath.posix {
  return deps.platform === 'win32' ? nodePath.win32 : nodePath.posix;
}

function errCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null ? (err as { code?: string }).code : undefined;
}

async function lstatOrNull(deps: TrustDeps, p: string): Promise<StatLike | null> {
  try {
    return await deps.fs.lstat(p);
  } catch (err) {
    const c = errCode(err);
    if (c === 'ENOENT' || c === 'ENOTDIR') return null;
    throw err;
  }
}

function requireUid(deps: TrustDeps): number {
  const uid = deps.getuid();
  if (uid === undefined) {
    throw new TrustError('PROBE_FAILED', 'cannot determine the current user id (refusing: no trust decision without it)');
  }
  return uid;
}

function requireNoFollow(deps: TrustDeps): number {
  const v = deps.constants.O_NOFOLLOW;
  if (typeof v !== 'number' || v === 0) {
    throw new TrustError('PROBE_FAILED', 'O_NOFOLLOW is not available on this platform (refusing)');
  }
  return v;
}

function flag(deps: TrustDeps, name: string): number {
  const v = deps.constants[name];
  if (typeof v !== 'number') throw new TrustError('PROBE_FAILED', `${name} is not available`);
  return v;
}

function sameFile(a: StatLike, b: StatLike): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

function withBypass(base: Omit<FsCaps, 'bypassed'>, deps: TrustDeps): FsCaps {
  // Exactly "1". "true", "yes", " 1", "01" do nothing. Read from the process env only.
  return { ...base, bypassed: base.weak && deps.env.LEDGER_ALLOW_WEAK_FS === '1' };
}

function enforceFs(caps: FsCaps, p: string): void {
  if (caps.weak && !caps.bypassed) {
    throw new TrustError(
      'WEAK_FS',
      `${p}: this filesystem (${caps.fsType}) cannot enforce private permissions (${caps.reasons.join(', ')}); ` +
        'move the directory to a local filesystem, or set LEDGER_ALLOW_WEAK_FS=1 to accept the risk',
      p,
    );
  }
}

function fresh(entry: CacheEntry, deps: TrustDeps): boolean {
  // Clocks jump (sleep/wake, NTP): a negative age is as stale as a large one.
  return Math.abs(deps.now() - entry.at) < CACHE_TTL_MS;
}

function sameIdentity(entry: CacheEntry, st: StatLike): boolean {
  return entry.dev === st.dev && entry.ino === st.ino && entry.ctimeNs === st.ctimeNs;
}

function cacheKey(kind: CacheEntry['kind'], dir: string, deps: TrustDeps): string {
  return `${kind}:${deps.platform}:${dir}`;
}

async function cachePut(kind: CacheEntry['kind'], dir: string, caps: Omit<FsCaps, 'bypassed'>, deps: TrustDeps): Promise<void> {
  // Identity AFTER the probe: creating/removing the probe file changes the directory's ctime.
  const st = await lstatOrNull(deps, dir);
  if (st === null) return;
  deps.cache.set(cacheKey(kind, dir, deps), { kind, dev: st.dev, ino: st.ino, ctimeNs: st.ctimeNs, at: deps.now(), caps });
}

/** After OUR OWN create inside an already-verified directory the ctime moves; keep the entry. */
async function cacheRefresh(dir: string, deps: TrustDeps): Promise<void> {
  const st = await lstatOrNull(deps, dir);
  if (st === null) return;
  for (const kind of ['caps', 'verified'] as const) {
    const e = deps.cache.get(cacheKey(kind, dir, deps));
    if (e !== undefined && e.dev === st.dev && e.ino === st.ino && fresh(e, deps)) {
      deps.cache.set(cacheKey(kind, dir, deps), { ...e, ctimeNs: st.ctimeNs });
    }
  }
}

function toTrustError(err: unknown): never {
  if (err instanceof WinPsError) throw new TrustError('PROBE_FAILED', `windows trust probe failed: ${err.message}`);
  throw err;
}

// ---- POSIX: mount info / WSL / case ---------------------------------------------------

export interface MountEntry {
  mount: string;
  fstype: string;
}

/** Parse `/proc/self/mountinfo` (fields: ... mountpoint(5th) ... ` - ` fstype source opts). */
export function parseMountInfo(text: string): MountEntry[] {
  const out: MountEntry[] = [];
  for (const line of text.split('\n')) {
    const sep = line.indexOf(' - ');
    if (sep === -1) continue;
    const left = line.slice(0, sep).split(' ');
    const right = line.slice(sep + 3).split(' ');
    const mountRaw = left[4];
    const fstype = right[0];
    if (mountRaw === undefined || fstype === undefined) continue;
    const mount = mountRaw.replace(/\\([0-7]{3})/g, (_m, o: string) => String.fromCharCode(Number.parseInt(o, 8)));
    out.push({ mount, fstype });
  }
  return out;
}

/** Filesystem type of the longest mount point that contains `real`. */
export function fsTypeFor(real: string, mounts: readonly MountEntry[]): string {
  let best: MountEntry | undefined;
  for (const m of mounts) {
    const contains = real === m.mount || real.startsWith(m.mount === '/' ? '/' : `${m.mount}/`);
    if (contains && (best === undefined || m.mount.length >= best.mount.length)) best = m;
  }
  return best?.fstype ?? 'unknown';
}

const WSL_WEAK_TYPES = new Set(['9p', 'drvfs', 'v9fs']);
const WSL_DRIVE_RE = /^\/mnt\/[a-z](?:\/|$)/;

async function isWsl(deps: TrustDeps): Promise<boolean> {
  if (deps.platform !== 'linux') return false;
  if (/microsoft/i.test(deps.release())) return true;
  return (await lstatOrNull(deps, '/proc/sys/fs/binfmt_misc/WSLInterop').catch(() => null)) !== null;
}

function swapCase(s: string): string {
  return s.replace(/[A-Za-z]/g, (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()));
}

/**
 * Is `dir` on a case-insensitive filesystem? Stat-only (creates nothing, so it is safe in a
 * user's checkout): stat the path with the case of its last lettered component swapped and
 * compare file identity. win32 reports true (per-directory case sensitivity is not detected;
 * treating it as insensitive is the conservative direction for claim matching).
 */
export async function probeCaseInsensitive(dir: string, depsIn: Partial<TrustDeps> = {}): Promise<boolean> {
  const deps = createTrustDeps(depsIn);
  if (deps.platform === 'win32') return true;
  const parts = dir.split('/');
  for (let i = parts.length - 1; i >= 0; i -= 1) {
    const part = parts[i] ?? '';
    const swapped = swapCase(part);
    if (swapped === part) continue;
    const alt = [...parts.slice(0, i), swapped, ...parts.slice(i + 1)].join('/');
    try {
      const [a, b] = await Promise.all([deps.fs.stat(dir), deps.fs.stat(alt)]);
      return a.dev === b.dev && a.ino === b.ino;
    } catch {
      return false;
    }
  }
  return false;
}

// ---- POSIX: probe ---------------------------------------------------------------------

async function probePosix(dir: string, deps: TrustDeps): Promise<Omit<FsCaps, 'bypassed'>> {
  const uid = requireUid(deps);
  const noFollow = requireNoFollow(deps);
  const real = await deps.fs.realpath(dir).catch(() => {
    throw new TrustError('PROBE_FAILED', `cannot resolve ${dir}`, dir);
  });
  // W1: never create files in a directory that is not ours. Only a weak-FS bypass may probe a
  // foreign-owned dir, and then only a root-owned one another account cannot write into (or a
  // sticky one such as /tmp) — there nobody can plant anything under our probe name.
  const dst = await deps.fs.lstat(real);
  if (dst.uid !== uid && !(deps.env.LEDGER_ALLOW_WEAK_FS === '1' && isRootOwnedTrustedParent(dst))) {
    throw new TrustError('OWNER', `${dir} is not owned by you — refusing to use it`, dir);
  }
  const api = nodePath.posix;
  const file = api.join(real, `.ledger-fsprobe-${randomBytes(8).toString('hex')}`);
  const linked = `${file}.l`;
  const reasons: string[] = [];
  let posixModes = true;
  let ownerMatches = true;
  let hardlinks = true;
  try {
    let h: TrustHandle;
    try {
      h = await deps.fs.open(file, flag(deps, 'O_WRONLY') | flag(deps, 'O_CREAT') | flag(deps, 'O_EXCL') | noFollow, 0o600);
    } catch (err) {
      // Not a weak-FS symptom: a directory we cannot even write to is a fixable misconfiguration.
      throw new TrustError('PROBE_FAILED', `cannot create a probe file in ${dir} (${errCode(err) ?? 'error'})`, dir);
    }
    // Everything below goes through the descriptor of the file WE just created (O_EXCL|O_NOFOLLOW):
    // another account swapping the name for a symlink can never make us chmod/stat its target.
    try {
      try {
        const st = await h.stat();
        ownerMatches = st.isFile() && st.uid === uid;
      } catch {
        ownerMatches = false;
      }
      try {
        // Set explicitly (umask-independent), then flip to 0640: a silent chmod no-op shows up as a mismatch.
        await h.chmod(0o600);
        const a = await h.stat();
        await h.chmod(0o640);
        const b = await h.stat();
        posixModes = (a.mode & 0o777) === 0o600 && (b.mode & 0o777) === 0o640;
      } catch {
        posixModes = false;
      }
      try {
        await deps.fs.link(file, linked);
        // nlink from OUR descriptor: a swapped-in name cannot fake (or hide) the link count.
        hardlinks = (await h.stat()).nlink === 2;
      } catch {
        hardlinks = false;
      }
    } finally {
      await h.close().catch(() => undefined);
    }
  } finally {
    await deps.fs.rm(linked).catch(() => undefined);
    await deps.fs.rm(file).catch(() => undefined);
  }
  if (!posixModes) reasons.push('mode bits are not enforced');
  if (!ownerMatches) reasons.push('files are not owned by the creating user');
  if (!hardlinks) reasons.push('hard links are not supported');

  let fsType = 'unknown';
  let weak = !(posixModes && ownerMatches && hardlinks);
  if (deps.platform === 'linux') {
    const mounts = parseMountInfo(await deps.fs.readText('/proc/self/mountinfo').catch(() => ''));
    fsType = fsTypeFor(real, mounts);
    if (await isWsl(deps)) {
      if (WSL_WEAK_TYPES.has(fsType) || WSL_DRIVE_RE.test(real)) {
        weak = true;
        reasons.push('WSL DrvFs/9p mount (Windows-side access control)');
      }
    }
  }
  return {
    posixModes,
    ownerMatches,
    hardlinks,
    acl: false,
    fsType,
    caseInsensitive: await probeCaseInsensitive(real, deps),
    weak,
    reasons,
  };
}

// ---- win32: inspection helpers --------------------------------------------------------

function winCtx(deps: TrustDeps): WinPsContext {
  return {
    env: deps.env,
    spawnFile: deps.spawnFile,
    isFile: async (p) => (await deps.fs.stat(p)).isFile(),
  };
}

async function winInspect(paths: string[], deps: TrustDeps): Promise<WinInspect> {
  let r: WinInspect;
  try {
    r = await inspectWindowsPaths(paths, winCtx(deps));
  } catch (err) {
    return toTrustError(err);
  }
  if (r.elevated) throw new TrustError('PERMS', ELEVATED_MESSAGE);
  return r;
}

function isElevatedError(err: unknown): boolean {
  return err instanceof TrustError && err.message === ELEVATED_MESSAGE;
}

function winCaps(info: WinPathInfo): Omit<FsCaps, 'bypassed'> {
  const fsType = info.unc ? 'unc' : (info.driveFormat ?? 'unknown');
  const ntfsLike = /^(?:NTFS|ReFS)$/i.test(info.driveFormat ?? '');
  const localDrive = !info.unc && (info.driveType === 'Fixed' || info.driveType === 'Removable');
  const acl = ntfsLike && localDrive;
  const reasons: string[] = [];
  if (!ntfsLike) reasons.push(`${fsType} has no ACLs`);
  if (!localDrive) reasons.push('network or non-fixed volume');
  return {
    posixModes: acl,
    ownerMatches: acl,
    hardlinks: acl,
    acl,
    fsType,
    caseInsensitive: true,
    weak: !acl,
    reasons,
  };
}

function winAncestors(p: string): string[] {
  const out: string[] = [];
  let cur = p;
  for (;;) {
    const next = nodePath.win32.dirname(cur);
    if (next === cur) return out;
    out.push(next);
    cur = next;
  }
}

function winPathOrThrow(p: string): string {
  try {
    return assertWinPath(p);
  } catch {
    throw new TrustError('PROBE_FAILED', `${p}: not an absolute drive-rooted Windows path (UNC and device paths are refused)`, p);
  }
}

function verdictToError(v: { code?: 'OWNER' | 'ACL' | 'CHAIN'; reason?: string }, p: string): TrustError {
  return new TrustError(v.code ?? 'ACL', `${p}: ${v.reason ?? 'access control refused'}`, p);
}

/** ACL checks of an ancestor chain (entries 1..n of an inspection). Reparse points are refused. */
function checkWinChain(insp: WinInspect, chain: string[], startIndex: number, kind: SddlKind): void {
  for (let i = startIndex; i < chain.length; i += 1) {
    const info = insp.paths[i];
    const at = chain[i] ?? '?';
    if (info === undefined || !info.exists) throw new TrustError('CHAIN', `${at}: ancestor not readable`, at);
    if (info.reparse) throw new TrustError('REPARSE', `${at}: ancestor is a junction/symlink (reparse point)`, at);
    if (winCaps(info).weak) continue; // another (non-ACL) volume mounted in the chain: nothing to judge
    const v = evaluateSddl(info.sddl ?? '', kind, { mySid: insp.sid });
    if (!v.ok) throw verdictToError({ ...v, code: 'CHAIN' }, at);
  }
}

/**
 * Stat-only filesystem description of a directory we do NOT own (a user's checkout): creates,
 * chmods and links nothing (W1/W4). Linux fs type from mountinfo, case sensitivity by stat;
 * the capability flags are not measured (assumed present) — use for display only, never for a
 * trust decision.
 */
export async function probeFsStatOnly(dir: string, depsIn: Partial<TrustDeps> = {}): Promise<FsCaps> {
  const deps = createTrustDeps(depsIn);
  const real = await deps.fs.realpath(dir);
  let fsType = 'unknown';
  const reasons: string[] = [];
  let weak = false;
  if (deps.platform === 'linux') {
    const mounts = parseMountInfo(await deps.fs.readText('/proc/self/mountinfo').catch(() => ''));
    fsType = fsTypeFor(real, mounts);
    if ((await isWsl(deps)) && (WSL_WEAK_TYPES.has(fsType) || WSL_DRIVE_RE.test(real))) {
      weak = true;
      reasons.push('WSL DrvFs/9p mount (Windows-side access control)');
    }
  }
  return withBypass(
    {
      posixModes: !weak,
      ownerMatches: !weak,
      hardlinks: !weak,
      acl: false,
      fsType,
      caseInsensitive: await probeCaseInsensitive(real, deps),
      weak,
      reasons,
    },
    deps,
  );
}

// ---- probeFs --------------------------------------------------------------------------

/** Capabilities of the filesystem holding `dir` (cached by path + dev/ino/ctime, 10 min). */
export async function probeFs(dir: string, depsIn: Partial<TrustDeps> = {}): Promise<FsCaps> {
  return capsFor(dir, createTrustDeps(depsIn));
}

async function capsFor(dir: string, deps: TrustDeps): Promise<FsCaps> {
  if (deps.platform === 'win32') winPathOrThrow(dir);
  const st = await deps.fs.lstat(dir);
  const hit = deps.cache.get(cacheKey('caps', dir, deps));
  if (hit !== undefined && sameIdentity(hit, st) && fresh(hit, deps)) return withBypass(hit.caps, deps);
  let base: Omit<FsCaps, 'bypassed'>;
  if (deps.platform === 'win32') {
    winPathOrThrow(dir);
    const insp = await winInspect([dir], deps);
    const info = insp.paths[0];
    if (info === undefined || !info.exists) throw new TrustError('PROBE_FAILED', `${dir}: cannot inspect`, dir);
    base = winCaps(info);
  } else {
    base = await probePosix(dir, deps);
  }
  await cachePut('caps', dir, base, deps);
  return withBypass(base, deps);
}

// ---- POSIX backend --------------------------------------------------------------------

/** A root-owned parent we may sit under: not writable by group/other, or sticky (`/tmp`). */
export function isRootOwnedTrustedParent(st: { uid: number; mode: number }): boolean {
  if (st.uid !== 0) return false;
  const othersCanWrite = (st.mode & 0o022) !== 0;
  return !othersCanWrite || (st.mode & 0o1000) !== 0;
}

/**
 * Write bits of a binary / its parent directory. `o+w` is never acceptable (sticky does not
 * help: the attacker only has to create the file); `g+w` only through an explicit opt-in.
 */
export async function posixWriteBitsTrusted(
  mode: number,
  gid: number,
  groupWritableOk: (gid: number) => Promise<boolean> = async () => false,
): Promise<boolean> {
  if ((mode & 0o002) !== 0) return false;
  if ((mode & 0o020) === 0) return true;
  return groupWritableOk(gid);
}

async function assertSafeParentPosix(dir: string, deps: TrustDeps): Promise<void> {
  const parent = nodePath.posix.dirname(dir);
  if (parent === dir) return;
  const st = await lstatOrNull(deps, parent);
  if (st === null) return; // mkdir creates it directly, nothing to redirect through
  if (st.isSymbolicLink()) throw new TrustError('SYMLINK', `${parent} is a symlink — refusing to use it`, parent);
  if (st.uid !== requireUid(deps) && !isRootOwnedTrustedParent(st)) {
    throw new TrustError('OWNER', `${parent} is not owned by you — refusing to use it`, parent);
  }
}

/**
 * `lstat` semantics matter: `stat` would follow a symlink and approve the target's mode.
 * `forceProbe` false = only decide from the stat unless a violation needs the probe to
 * know whether the filesystem can express it (ancestors of a created chain).
 */
async function assertPrivateDirPosix(
  dir: string,
  deps: TrustDeps,
  opts: { secret?: boolean; forceProbe: boolean },
): Promise<FsCaps | null> {
  const uid = requireUid(deps);
  const st = await deps.fs.lstat(dir);
  if (st.isSymbolicLink()) throw new TrustError('SYMLINK', `${dir} is a symlink — refusing to use it`, dir);
  if (!st.isDirectory()) throw new TrustError('IDENTITY', `${dir} is not a directory`, dir);
  const violations: TrustError[] = [];
  if (st.uid !== uid) violations.push(new TrustError('OWNER', `${dir} is not owned by you — refusing to use it`, dir));
  // 0o022 = group-write | other-write (the spool rule); `secret` also forbids group/other read.
  if ((st.mode & 0o022) !== 0) violations.push(new TrustError('PERMS', `${dir} is writable by group/other — run \`chmod 700\``, dir));
  else if (opts.secret === true && (st.mode & 0o077) !== 0) {
    violations.push(new TrustError('PERMS', `${dir} is accessible by group/other — run \`chmod 700\``, dir));
  }
  if (violations.length === 0 && !opts.forceProbe) return null;
  let caps: FsCaps;
  try {
    caps = await capsFor(dir, deps);
  } catch (err) {
    const first = violations[0];
    if (first !== undefined) throw first;
    throw err;
  }
  enforceFs(caps, dir);
  for (const v of violations) {
    // Relax only what this filesystem cannot express (I5).
    const relaxable = v.code === 'OWNER' ? !caps.ownerMatches : !caps.posixModes;
    if (!relaxable) throw v;
  }
  return caps;
}

async function ensurePrivateDirPosix(dir: string, deps: TrustDeps): Promise<FsCaps> {
  const api = nodePath.posix;
  const home = deps.homedir();
  const parts: string[] = [];
  let cursor = dir;
  while (cursor !== home && cursor !== api.dirname(cursor)) {
    parts.unshift(cursor);
    cursor = api.dirname(cursor);
  }
  if (cursor !== home) {
    // Outside $HOME we cannot walk a chain we do not own: leaf and immediate parent only.
    await assertSafeParentPosix(dir, deps);
    await deps.fs.mkdir(dir, 0o700, true);
    const caps = await assertPrivateDirPosix(dir, deps, { forceProbe: true });
    if (caps === null) throw new TrustError('PROBE_FAILED', `${dir}: no capability probe`, dir);
    return caps;
  }
  let last: FsCaps | null = null;
  for (const part of parts) {
    try {
      await deps.fs.mkdir(part, 0o700);
    } catch (err) {
      if (errCode(err) !== 'EEXIST') throw err;
    }
    last = await assertPrivateDirPosix(part, deps, { forceProbe: part === dir });
  }
  if (last === null) return assertDirCapsPosix(dir, deps);
  return last;
}

async function assertDirCapsPosix(dir: string, deps: TrustDeps): Promise<FsCaps> {
  const caps = await assertPrivateDirPosix(dir, deps, { forceProbe: true });
  if (caps === null) throw new TrustError('PROBE_FAILED', `${dir}: no capability probe`, dir);
  return caps;
}

async function posixChainReason(
  file: string,
  deps: TrustDeps,
  stopAt: string,
  groupWritableOk: ((gid: number) => Promise<boolean>) | undefined,
): Promise<string | null> {
  const uid = deps.getuid();
  const api = nodePath.posix;
  let dir = api.dirname(file);
  for (;;) {
    let st: StatLike;
    try {
      st = await deps.fs.lstat(dir);
    } catch {
      return `${dir}: cannot be inspected`;
    }
    if (st.isSymbolicLink() || !st.isDirectory()) return `${dir}: not a real directory`;
    // uid unknown => only root counts as a trusted owner (fail-closed).
    const trustedOwner = st.uid === 0 || (uid !== undefined && st.uid === uid);
    if (!trustedOwner) return `${dir}: owned by someone other than {root, you}`;
    if (!(await posixWriteBitsTrusted(st.mode, st.gid, groupWritableOk))) {
      return `${dir}: writable by someone other than {root, you}`;
    }
    if (dir === stopAt) return null;
    const parent = api.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

// ---- win32 backend --------------------------------------------------------------------

/** Inspect the parent we will create under; returns its volume capabilities. */
async function inspectForCreateWin(parent: string, deps: TrustDeps): Promise<{ caps: FsCaps; sid: string }> {
  winPathOrThrow(parent);
  const chain = [parent, ...winAncestors(parent)];
  const insp = await winInspect(chain, deps);
  const p0 = insp.paths[0];
  if (p0 === undefined || !p0.exists) throw new TrustError('PROBE_FAILED', `${parent}: cannot inspect`, parent);
  if (p0.reparse) throw new TrustError('REPARSE', `${parent}: is a junction/symlink (reparse point)`, parent);
  const caps = withBypass(winCaps(p0), deps);
  enforceFs(caps, parent);
  if (caps.weak) return { caps, sid: insp.sid };
  // C:\ is fine as an ancestor but not as the direct parent: its children inherit
  // Authenticated Users:Modify until we strip it.
  const v = evaluateSddl(p0.sddl ?? '', 'parent-of-new', { mySid: insp.sid });
  if (!v.ok) throw verdictToError({ ...v, code: 'CHAIN' }, parent);
  checkWinChain(insp, chain, 1, 'ancestor');
  return { caps, sid: insp.sid };
}

async function assertPrivateDirWin(dir: string, deps: TrustDeps): Promise<FsCaps> {
  winPathOrThrow(dir);
  const st = await deps.fs.lstat(dir);
  if (st.isSymbolicLink()) throw new TrustError('SYMLINK', `${dir} is a symlink — refusing to use it`, dir);
  if (!st.isDirectory()) throw new TrustError('IDENTITY', `${dir} is not a directory`, dir);
  const chain = [dir, ...winAncestors(dir)];
  const insp = await winInspect(chain, deps);
  const d = insp.paths[0];
  if (d === undefined || !d.exists) throw new TrustError('PROBE_FAILED', `${dir}: cannot inspect`, dir);
  if (d.reparse) throw new TrustError('REPARSE', `${dir}: is a junction/symlink (reparse point)`, dir);
  const base = winCaps(d);
  const caps = withBypass(base, deps);
  enforceFs(caps, dir); // weak and not bypassed => WEAK_FS
  if (!caps.weak) {
    const v = evaluateSddl(d.sddl ?? '', 'private-dir', { mySid: insp.sid });
    if (!v.ok) throw verdictToError(v, dir);
    checkWinChain(insp, chain, 1, 'ancestor');
  }
  deps.cache.set(cacheKey('verified', dir, deps), {
    kind: 'verified',
    dev: st.dev,
    ino: st.ino,
    ctimeNs: st.ctimeNs,
    at: deps.now(),
    caps: base,
  });
  return caps;
}

async function assertPrivateDirCachedWin(dir: string, deps: TrustDeps): Promise<FsCaps> {
  winPathOrThrow(dir);
  const st = await deps.fs.lstat(dir);
  if (st.isSymbolicLink()) throw new TrustError('SYMLINK', `${dir} is a symlink — refusing to use it`, dir);
  const hit = deps.cache.get(cacheKey('verified', dir, deps));
  if (hit !== undefined && sameIdentity(hit, st) && fresh(hit, deps)) return withBypass(hit.caps, deps);
  return assertPrivateDirWin(dir, deps);
}

async function ensurePrivateDirWin(dirIn: string, deps: TrustDeps): Promise<FsCaps> {
  const api = nodePath.win32;
  const dir = api.normalize(winPathOrThrow(dirIn)).replace(/[\\/]+$/, '');
  winPathOrThrow(dir);
  const missing: string[] = [];
  let cur = dir;
  for (;;) {
    const st = await lstatOrNull(deps, cur);
    if (st !== null) {
      if (st.isSymbolicLink()) throw new TrustError('SYMLINK', `${cur} is a symlink — refusing to use it`, cur);
      if (!st.isDirectory()) throw new TrustError('IDENTITY', `${cur} is not a directory`, cur);
      break;
    }
    missing.unshift(cur);
    const parent = api.dirname(cur);
    if (parent === cur) throw new TrustError('PROBE_FAILED', `${dir}: no existing ancestor`, dir);
    cur = parent;
  }
  // Exists already: verify only. We never chmod/re-ACL a directory we did not create.
  if (missing.length === 0) return assertPrivateDirWin(dir, deps);

  let caps: FsCaps | null = null;
  for (const comp of missing) {
    const parent = api.dirname(comp);
    const { caps: parentCaps, sid } = await inspectForCreateWin(parent, deps);
    try {
      await deps.fs.mkdir(comp, 0o700);
    } catch (err) {
      if (errCode(err) === 'EEXIST') {
        throw new TrustError('IDENTITY', `${comp}: appeared while being created (raced) — refusing`, comp);
      }
      throw err;
    }
    try {
      if (!parentCaps.weak) {
        try {
          await setPrivateAcl(comp, sid, winCtx(deps));
        } catch (err) {
          return toTrustError(err);
        }
      }
      const made = await deps.fs.lstat(comp);
      if (made.isSymbolicLink() || !made.isDirectory()) throw new TrustError('IDENTITY', `${comp}: replaced while being created`, comp);
      caps = await assertPrivateDirWin(comp, deps);
      const entries = await deps.fs.readdir(comp);
      if (entries.length > 0) {
        throw new TrustError('IDENTITY', `${comp}: not empty right after creation (raced) — refusing`, comp);
      }
    } catch (err) {
      await deps.fs.rmdir(comp).catch(() => undefined);
      throw err;
    }
  }
  if (caps === null) throw new TrustError('PROBE_FAILED', `${dir}: nothing created`, dir);
  return caps;
}

// ---- public: dirs ---------------------------------------------------------------------

/**
 * Create `dir` (and missing parents) private to us, or verify it when it exists.
 * POSIX: every created/ancestor component is a real directory owned by us and not
 * group/other-writable (refused, never "fixed"). win32: ancestors checked, directory
 * created, DACL set to {me, SYSTEM} with inheritance removed, SDDL re-read and verified,
 * directory asserted empty; on any failure it is removed and the call refuses.
 */
export async function ensurePrivateDir(dir: string, depsIn: Partial<TrustDeps> = {}): Promise<FsCaps> {
  const deps = createTrustDeps(depsIn);
  const caps = deps.platform === 'win32' ? await ensurePrivateDirWin(dir, deps) : await ensurePrivateDirPosix(dir, deps);
  return caps;
}

/** Verify an existing private directory (never modifies it). */
export async function assertPrivateDir(
  dir: string,
  opts: { secret?: boolean } = {},
  depsIn: Partial<TrustDeps> = {},
): Promise<FsCaps> {
  const deps = createTrustDeps(depsIn);
  if (deps.platform === 'win32') return assertPrivateDirCachedWin(dir, deps);
  return assertDirCapsPosixOpts(dir, deps, opts);
}

async function assertDirCapsPosixOpts(dir: string, deps: TrustDeps, opts: { secret?: boolean }): Promise<FsCaps> {
  const caps = await assertPrivateDirPosix(dir, deps, { ...opts, forceProbe: true });
  if (caps === null) throw new TrustError('PROBE_FAILED', `${dir}: no capability probe`, dir);
  return caps;
}

// ---- public: files --------------------------------------------------------------------

/**
 * Verify an existing private file. `secret` = nobody else may read it (0o177 on POSIX,
 * no read ACE for others on win32) and it must have exactly one link.
 */
export async function assertPrivateFile(
  file: string,
  opts: { secret?: boolean } = {},
  depsIn: Partial<TrustDeps> = {},
): Promise<StatLike> {
  const deps = createTrustDeps(depsIn);
  const api = pathApi(deps);
  if (deps.platform === 'win32') winPathOrThrow(file);
  const st = await deps.fs.lstat(file);
  if (st.isSymbolicLink()) throw new TrustError('SYMLINK', `${file} is a symlink — refusing to use it`, file);
  if (!st.isFile()) throw new TrustError('IDENTITY', `${file} is not a regular file`, file);
  const dir = api.dirname(file);
  const secret = opts.secret === true;

  if (deps.platform === 'win32') {
    const caps = await assertPrivateDirCachedWin(dir, deps);
    if (caps.weak) return st; // bypassed: ACLs and links cannot be judged on this volume
    if (secret && st.nlink !== 1) throw new TrustError('IDENTITY', `${file}: has ${String(st.nlink)} hard links`, file);
    const insp = await winInspect([file], deps);
    const info = insp.paths[0];
    if (info === undefined || !info.exists) throw new TrustError('PROBE_FAILED', `${file}: cannot inspect`, file);
    if (info.reparse) throw new TrustError('REPARSE', `${file}: is a reparse point`, file);
    const v = evaluateSddl(info.sddl ?? '', secret ? 'secret-file' : 'private-file', { mySid: insp.sid });
    if (!v.ok) throw verdictToError(v, file);
    return st;
  }

  const uid = requireUid(deps);
  const violations: TrustError[] = [];
  if (st.uid !== uid) violations.push(new TrustError('OWNER', `${file} is not owned by you — refusing to use it`, file));
  const badBits = secret ? (st.mode & 0o177) !== 0 : (st.mode & 0o022) !== 0;
  if (badBits) violations.push(new TrustError('PERMS', `${file} has loose permissions (${(st.mode & 0o777).toString(8)})`, file));
  if (secret && st.nlink !== 1) violations.push(new TrustError('IDENTITY', `${file} has ${String(st.nlink)} hard links`, file));
  let caps: FsCaps;
  try {
    caps = await capsFor(dir, deps);
  } catch (err) {
    const first = violations[0];
    if (first !== undefined) throw first;
    throw err;
  }
  enforceFs(caps, file);
  for (const v of violations) {
    const relaxable = v.code === 'OWNER' ? !caps.ownerMatches : v.code === 'PERMS' ? !caps.posixModes : !caps.hardlinks;
    if (!relaxable) throw v;
  }
  return st;
}

/**
 * Open a file inside a private directory without following links and verify, on the
 * open descriptor, that it is the file we think it is.
 *  - `append` / `excl` / `trunc` create it (0600 by default); `read` does not.
 *  - POSIX: `O_NOFOLLOW`, then `fstat` owner/regular-file check.
 *  - win32: lstat -> open -> fstat -> lstat; dev+ino equal and no symlink, else IDENTITY.
 *    The containing directory's ACL is verified (cached) first; file ACLs are not
 *    re-read per open (use `assertPrivateFile` for that).
 * `trunc` truncates only after the checks pass.
 */
export async function openPrivate(
  file: string,
  mode: OpenMode,
  fileMode = 0o600,
  depsIn: Partial<TrustDeps> = {},
): Promise<TrustHandle> {
  const deps = createTrustDeps(depsIn);
  const api = pathApi(deps);
  const dir = api.dirname(file);
  const base =
    mode === 'read'
      ? flag(deps, 'O_RDONLY')
      : mode === 'append'
        ? flag(deps, 'O_WRONLY') | flag(deps, 'O_APPEND') | flag(deps, 'O_CREAT')
        : mode === 'excl'
          ? flag(deps, 'O_WRONLY') | flag(deps, 'O_CREAT') | flag(deps, 'O_EXCL')
          : flag(deps, 'O_WRONLY') | flag(deps, 'O_CREAT');

  if (deps.platform === 'win32') {
    winPathOrThrow(file);
    const caps = await assertPrivateDirCachedWin(dir, deps);
    const before = await lstatOrNull(deps, file);
    if (before !== null) {
      if (before.isSymbolicLink()) throw new TrustError('SYMLINK', `${file} is a symlink — refusing to use it`, file);
      if (!before.isFile()) throw new TrustError('IDENTITY', `${file} is not a regular file`, file);
    }
    const handle = await deps.fs.open(file, base, fileMode);
    try {
      const fst = await handle.stat();
      const after = await deps.fs.lstat(file);
      if (after.isSymbolicLink()) throw new TrustError('SYMLINK', `${file} was replaced by a symlink`, file);
      if (!fst.isFile() || !after.isFile()) throw new TrustError('IDENTITY', `${file} is not a regular file`, file);
      // An id of 0 means the volume gives no stable file identity: nothing to compare.
      if (!caps.weak && (fst.ino === 0n || after.ino === 0n)) throw new TrustError('IDENTITY', `${file}: no stable file id`, file);
      if (!sameFile(fst, after) || (before !== null && !sameFile(before, fst))) {
        throw new TrustError('IDENTITY', `${file} changed while being opened`, file);
      }
      if (mode === 'trunc') await handle.truncate(0);
    } catch (err) {
      await handle.close().catch(() => undefined);
      throw err;
    }
    if (mode !== 'read') await cacheRefresh(dir, deps);
    return handle;
  }

  const uid = requireUid(deps);
  const caps = await capsFor(dir, deps);
  enforceFs(caps, dir);
  let handle: TrustHandle;
  try {
    handle = await deps.fs.open(file, base | requireNoFollow(deps), fileMode);
  } catch (err) {
    const c = errCode(err);
    if (c === 'ELOOP' || c === 'EMLINK') throw new TrustError('SYMLINK', `${file} is a symlink — refusing to use it`, file);
    throw err;
  }
  try {
    const fst = await handle.stat();
    if (!fst.isFile()) throw new TrustError('IDENTITY', `${file} is not a regular file`, file);
    if (fst.uid !== uid && caps.ownerMatches) {
      throw new TrustError('OWNER', `${file} is not owned by you — refusing to use it`, file);
    }
    if (mode === 'trunc') await handle.truncate(0);
  } catch (err) {
    await handle.close().catch(() => undefined);
    throw err;
  }
  if (mode !== 'read') await cacheRefresh(dir, deps);
  return handle;
}

// ---- public: ancestors, executables, ownership ----------------------------------------

/**
 * Verify the directories ABOVE `path` (not `path` itself).
 * POSIX: every directory up to `stopAt` is a real directory owned by root or us and not
 * writable by anyone else (the old `dirChainTrusted`). win32: owner and DACL of every
 * ancestor judged from SDDL; `C:\` passes as an ancestor but not as the direct parent of
 * a new directory (`newChild`).
 */
export async function assertTrustedAncestors(
  path: string,
  opts: AncestorOpts = {},
  depsIn: Partial<TrustDeps> = {},
): Promise<void> {
  const deps = createTrustDeps(depsIn);
  if (deps.platform === 'win32') {
    winPathOrThrow(path);
    const chain = winAncestors(path);
    const insp = await winInspect(chain, deps);
    const kind: SddlKind = opts.executable === true ? 'exec-ancestor' : 'ancestor';
    if (opts.newChild === true) {
      const first = insp.paths[0];
      const at = chain[0] ?? path;
      if (first === undefined || !first.exists) throw new TrustError('CHAIN', `${at}: not readable`, at);
      if (first.reparse) throw new TrustError('REPARSE', `${at}: is a junction/symlink (reparse point)`, at);
      if (!winCaps(first).weak) {
        const v = evaluateSddl(first.sddl ?? '', 'parent-of-new', { mySid: insp.sid });
        if (!v.ok) throw verdictToError({ ...v, code: 'CHAIN' }, at);
      }
      checkWinChain(insp, chain, 1, kind);
      return;
    }
    checkWinChain(insp, chain, 0, kind);
    return;
  }
  const reason = await posixChainReason(path, deps, opts.stopAt ?? '/', opts.groupWritableOk);
  if (reason !== null) throw new TrustError('CHAIN', reason, path);
}

type CandidateVerdict = { kind: 'ok'; path: string } | { kind: 'absent' } | { kind: 'rejected'; reason: string };

async function checkCandidatePosix(
  candidate: string,
  deps: TrustDeps,
  stopAt: string,
  groupWritableOk: ((gid: number) => Promise<boolean>) | undefined,
): Promise<CandidateVerdict> {
  const uid = deps.getuid();
  try {
    const st = await deps.fs.lstat(candidate);
    const real = st.isSymbolicLink() ? await deps.fs.realpath(candidate) : candidate;
    const rst = await deps.fs.stat(real);
    if (!rst.isFile()) return { kind: 'absent' };
    const trustedOwner = rst.uid === 0 || (uid !== undefined && rst.uid === uid);
    if (!trustedOwner || !(await posixWriteBitsTrusted(rst.mode, rst.gid, groupWritableOk))) {
      return { kind: 'rejected', reason: 'owner/permissions' };
    }
    // Both the path we were handed AND the path we end up executing need a trusted chain:
    // a writable directory lets someone repoint the link while the target still looks fine.
    if ((await posixChainReason(real, deps, stopAt, groupWritableOk)) !== null) {
      return { kind: 'rejected', reason: 'target directory is writable by someone other than {root, us}' };
    }
    if (real !== candidate && (await posixChainReason(candidate, deps, stopAt, groupWritableOk)) !== null) {
      return { kind: 'rejected', reason: 'symlink directory is writable by someone other than {root, us}' };
    }
    return { kind: 'ok', path: real };
  } catch {
    return { kind: 'absent' };
  }
}

async function checkCandidateWin(candidate: string, deps: TrustDeps): Promise<CandidateVerdict> {
  const st = await lstatOrNull(deps, candidate);
  if (st === null) return { kind: 'absent' };
  if (st.isSymbolicLink()) return { kind: 'rejected', reason: 'is a symlink/junction' };
  if (!st.isFile()) return { kind: 'absent' };
  const chain = [candidate, ...winAncestors(candidate)];
  let insp: WinInspect;
  try {
    insp = await winInspect(chain, deps);
  } catch (err) {
    if (isElevatedError(err)) throw err;
    // Keep the probe's own reason (timeout / exit code / parse): a bare "probe failed" hid the
    // real cause in CI. Still a rejection (fail-closed); the text is path-free by construction.
    return { kind: 'rejected', reason: err instanceof TrustError ? err.message : 'trust probe failed' };
  }
  const f = insp.paths[0];
  if (f === undefined || !f.exists) return { kind: 'absent' };
  if (f.reparse) return { kind: 'rejected', reason: 'is a reparse point' };
  if (winCaps(f).weak) return { kind: 'rejected', reason: 'volume cannot enforce ACLs' };
  const v = evaluateSddl(f.sddl ?? '', 'executable', { mySid: insp.sid });
  if (!v.ok) return { kind: 'rejected', reason: v.reason ?? 'access control refused' };
  try {
    checkWinChain(insp, chain, 1, 'exec-ancestor');
  } catch (err) {
    return { kind: 'rejected', reason: err instanceof Error ? err.message : 'directory chain refused' };
  }
  return { kind: 'ok', path: candidate };
}

/**
 * First candidate that is an absolute, trustworthy executable (same rules git/gitleaks
 * binaries have always had on POSIX; SDDL-based on win32). Relative / empty / non-drive-rooted
 * candidates are dropped without being looked at (never resolved against PATH or the CWD).
 */
export async function resolveTrustedExecutable(
  candidates: readonly string[],
  opts: Pick<AncestorOpts, 'stopAt' | 'groupWritableOk'> = {},
  depsIn: Partial<TrustDeps> = {},
): Promise<TrustedExecutableInfo> {
  const deps = createTrustDeps(depsIn);
  const win = deps.platform === 'win32';
  const rejected: string[] = [];
  const dropped: string[] = [];
  let groupWritable = false;
  for (const candidate of candidates) {
    const absolute =
      typeof candidate === 'string' &&
      candidate !== '' &&
      !candidate.includes('\0') &&
      (win ? /^[A-Za-z]:\\/.test(candidate) : nodePath.posix.isAbsolute(candidate));
    if (!absolute) {
      dropped.push(String(candidate));
      continue;
    }
    if (win) {
      try {
        assertWinPath(candidate);
      } catch {
        dropped.push(candidate);
        continue;
      }
    }
    const verdict = win
      ? await checkCandidateWin(candidate, deps)
      : await checkCandidatePosix(candidate, deps, opts.stopAt ?? '/', opts.groupWritableOk);
    if (verdict.kind === 'absent') continue;
    if (verdict.kind === 'ok') {
      return { path: verdict.path, rejected, dropped, candidates, foundUntrusted: false, groupWritable };
    }
    rejected.push(`${candidate} (${verdict.reason})`);
    if (!win && opts.groupWritableOk === undefined) {
      const lenient = await checkCandidatePosix(candidate, deps, opts.stopAt ?? '/', async () => true);
      if (lenient.kind === 'ok') groupWritable = true;
    }
  }
  return { path: null, rejected, dropped, candidates, foundUntrusted: rejected.length > 0, groupWritable };
}

/** Sync POSIX ownership test of an existing stat. Unknown uid or win32 => false (fail-closed). */
export function isStatOwnedByMe(st: { uid: number }, depsIn: Partial<TrustDeps> = {}): boolean {
  const deps = createTrustDeps(depsIn);
  if (deps.platform === 'win32') return false; // owner is an SID there: use isOwnedByMe(path)
  const uid = deps.getuid();
  return uid !== undefined && st.uid === uid;
}

/** Is the existing `path` owned by the current principal? Missing path or any doubt => false. */
export async function isOwnedByMe(path: string, depsIn: Partial<TrustDeps> = {}): Promise<boolean> {
  const deps = createTrustDeps(depsIn);
  try {
    if (deps.platform === 'win32') {
      winPathOrThrow(path);
      const insp = await winInspect([path], deps);
      const info = insp.paths[0];
      if (info === undefined || !info.exists || info.sddl === null) return false;
      return parseSddl(info.sddl).owner === insp.sid;
    }
    const st = await lstatOrNull(deps, path);
    return st !== null && isStatOwnedByMe(st, deps);
  } catch (err) {
    if (isElevatedError(err)) throw err;
    return false;
  }
}
