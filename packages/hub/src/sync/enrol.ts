/** Enrolment of a ledger into sync: `sync init` (first device), `sync join` + `--continue` (every other one)
 *  (F3b B4b, docs/f3b-b4-plan.md §1.1-1.2, §2.2, §3, §4; AL-5).
 *
 *  Threat model:
 *   - Actor: a MITM on first contact, a remote that is public / foreign / hostile / rolled back, a crash at any
 *     step, a hub started or a second enrol racing mid-way, a local agent that holds the hub token (it cannot
 *     reach this module: it runs offline from the CLI), a hostile legacy `.gitattributes` / `.gitignore`.
 *   - Protected: (1) a device never mints an item id or a commit under a slot the accepted history does not
 *     assign to its key (the hub is blocked by the enrol marker while this runs); (2) the trust bootstrap needs
 *     TWO human confirmations out of band (host key fp, root key fp), neither persisted as "confirmed" before the
 *     step that depends on it; (3) nothing fetched is checked out before `validateGenesis` passed; (4) the first
 *     push never goes to a readable-by-anyone or non-empty remote; (5) no URL, stderr or key material in errors.
 *   - Failure modes: crash windows (docs §3: marker stage is a HINT, git state is the truth, every step is
 *     idempotent), pid reuse, a stale marker, TOCTOU between validate and checkout (F0 is resolved ONCE and the
 *     worktree is written from that sha), a prompt or a network call under the device lock.
 *   - Stance: all git goes through `Gitx` / `ObjectStore` / `TreeBuilder`; `.git/config` is NEVER written (a fresh
 *     join has no `remote.*`; the URL lives in `.hub/sync.yml` and the marker); no force, every ref move has an
 *     expected-old value; the device lock `D` is only ever taken inside the short `devicestore` operations, never
 *     across `EnrolIo.confirm` or a network call. `EnrolIo` is the ONLY human channel and `D`-free. Fixed error
 *     codes (`EnrolError`), never raw git output.
 *   - Residual: `ssh-keyscan` is unauthenticated (the typed fingerprint is the anchor); the join FF uses
 *     `read-tree --reset -u` on a worktree this module created and nobody else may touch (hub blocked, marker).
 */

import { timingSafeEqual } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import nodePath from 'node:path';
import {
  DevicesError,
  SshKeygenError,
  TrustError,
  adoptSlot,
  approveDevice,
  bootstrapSigners,
  deviceEmail,
  deviceLayout,
  initDevice,
  parseEd25519Pub,
  publicKeyOf,
  readDeviceFile,
  readDevices,
  pruneRevokedSigners,
  readSigners,
  resolveSshKeygen,
  safeOutput,
  withDeviceLock,
  type DeviceEntry,
  type DevicesFile,
  type Ed25519Pub,
  type GitSigningInput,
} from '@agent-ledger/shared';
import { LEDGER_FORMAT, readLocalFile } from '../ledger/device.ts';
import { fullTreeProblem, registryAt, validateGenesis, type GenesisCaps } from './genesis.ts';
import { GitxError, Gitx, REF_ACCEPTED, REF_INCOMING, REF_MAIN, checkGitConfig, isSha, type GitxResult, type RemoteKind } from './gitx.ts';
import { HostKeyError, pinHostKey, scanHostKeys, type HostKey } from './hostkey.ts';
import { ObjectStore, ObjectsError } from './objects.ts';
import { classifyProbe, pinnedFingerprint, probeRemote, remoteHostPort, remoteIdentity } from './remotecheck.ts';
import {
  StateError,
  StateStore,
  clearEnrolMarker,
  readEnrolMarker,
  readSyncConfig,
  writeEnrolMarker,
  writeSyncConfig,
  type EnrolMarker,
} from './state.ts';
import { TreeBuildError, TreeBuilder, type TreeChange } from './treebuild.ts';
import { verifyCommitSignature } from './sigverify.ts';
import { validateRange } from './validate.ts';

/* ---------------- public contract (B4c calls these; the shapes are fixed by the plan §2.2) ---------------- */

/** Fixed codes; the prefixed ones carry a rule TOKEN (`[a-z0-9:_.-]`), never text. */
export type EnrolErrorCode =
  | 'BAD_INPUT'
  | 'HUB_RUNNING'
  | 'NOT_EMPTY'
  | 'NOT_REPO'
  | 'FORMAT'
  | 'LOCAL_YML'
  | 'DIRTY'
  | 'INFLIGHT'
  | 'ALREADY_ENROLLED'
  | 'GIT_CONFIG'
  | 'REGISTRY_TRACKED'
  | 'PINNED'
  | 'URL'
  | 'REMOTE_SAME_AS_CODE'
  | 'REMOTE_PUBLIC'
  | 'REMOTE_INCONCLUSIVE'
  | 'REMOTE_UNREACHABLE'
  | 'REMOTE_AUTH'
  | 'REMOTE_NOT_EMPTY'
  | 'REMOTE_EMPTY'
  | 'HOSTKEY_REFUSED'
  | 'HOSTKEY_FAILED'
  | 'ROOT_FP_REFUSED'
  | 'ROOT_REVOKED'
  | 'REVOKED'
  | 'ADD_COMMIT'
  | 'ADD_COMMIT_REQUIRED'
  | 'PUSH_REJECTED'
  | 'PUSH_FAILED'
  | 'FETCH_FAILED'
  | 'REMOTE_REWOUND'
  | 'MARKER_BUSY'
  | 'MARKER_MISSING'
  | 'MARKER_STAGE'
  | 'STATE_MISMATCH'
  | 'STATE'
  | 'UNSAFE'
  | 'SSH_KEYGEN'
  | 'INTERNAL'
  | `GENESIS:${string}`
  | `RANGE:${string}`
  | `EGRESS:${string}`
  | `DEVICE:${string}`
  | `GIT:${string}`;

const MESSAGES: Readonly<Record<string, string>> = {
  BAD_INPUT: 'invalid input',
  HUB_RUNNING: 'the hub is running: stop it first (sync init|join works on a stopped hub)',
  NOT_EMPTY: 'the ledger directory is not empty (join needs an empty directory)',
  NOT_REPO: 'the ledger is not a git repository on branch main with at least one commit',
  FORMAT: 'ledger.format must be 2: start the hub once to migrate the ledger',
  LOCAL_YML: '.hub/local.yml is not valid',
  DIRTY: 'the ledger has uncommitted changes (or unexpected files): let the hub commit them first',
  INFLIGHT: 'an interrupted sync apply is pending: start the hub once so it can finish',
  ALREADY_ENROLLED: 'this ledger is already enrolled (.hub/sync.yml exists)',
  GIT_CONFIG: '.git/config is refused by the sync policy (see ledger doctor)',
  REGISTRY_TRACKED: 'devices.yml is already committed in this ledger without a signature: init needs a fresh registry',
  PINNED: '.gitignore / .gitattributes differ from the pinned text: re-run with --normalize to replace them',
  URL: 'the remote is not an acceptable ssh / scp URL',
  REMOTE_SAME_AS_CODE: 'the ledger remote is the same repository as the code repository',
  REMOTE_PUBLIC: 'the remote answers without credentials: refusing to put the ledger on a readable-by-anyone repository',
  REMOTE_INCONCLUSIVE: 'could not tell whether the remote is public (the anonymous check was inconclusive)',
  REMOTE_UNREACHABLE: 'the remote is not reachable',
  REMOTE_AUTH: 'access to the remote was denied or the repository does not exist',
  REMOTE_NOT_EMPTY: 'the remote already has a ledger: use `ledger sync join` instead',
  REMOTE_EMPTY: 'the remote has no ledger yet: run `ledger sync init` on the first device',
  HOSTKEY_REFUSED: 'the host key was not confirmed',
  HOSTKEY_FAILED: 'the host key could not be read or pinned',
  ROOT_FP_REFUSED: 'the root key fingerprint was not confirmed',
  ROOT_REVOKED: 'the root device of that ledger is revoked: joining is refused',
  REVOKED: 'this device is revoked in the registry',
  ADD_COMMIT: 'the --add-commit is not the commit by which a trusted device added this device (not in the fetched history, wrong signer or wrong change)',
  ADD_COMMIT_REQUIRED: '--add-commit <sha> is required: pass the commit printed by `ledger device add` on the trusted device',
  PUSH_REJECTED: 'the remote refused the push (it already has history): nothing was forced; the local migration commit is kept',
  PUSH_FAILED: 'the push did not reach the remote: re-run the same command to retry',
  FETCH_FAILED: 'fetching from the remote failed',
  REMOTE_REWOUND: 'the remote history no longer contains what was confirmed (rolled back or rewritten): refusing',
  MARKER_BUSY: 'another enrolment is in progress',
  MARKER_MISSING: 'there is no enrolment in progress to continue',
  MARKER_STAGE: 'the enrolment is not at the stage this command continues',
  STATE_MISMATCH: 'refs and enrolment state disagree: nothing was changed',
  STATE: 'the sync state could not be read or written',
  UNSAFE: 'a directory or file failed the ownership / safety check',
  SSH_KEYGEN: 'ssh-keygen is missing or failed',
  INTERNAL: 'internal error',
};

export class EnrolError extends Error {
  readonly code: EnrolErrorCode;
  constructor(code: EnrolErrorCode) {
    const base = MESSAGES[code];
    super(base ?? `refused (${code})`);
    this.name = 'EnrolError';
    this.code = code;
  }
}

/** Thrown by the `crashAt` TEST seam to simulate a dead process: passes through every error mapper untouched. */
export class EnrolCrash extends Error {
  readonly stage: string;
  constructor(stage: string) {
    super('simulated crash');
    this.name = 'EnrolCrash';
    this.stage = stage;
  }
}

/** The ONLY human channel. `confirm` shows `fp` to a person and returns whether they typed it back. Tests fake it. */
export interface EnrolIo {
  confirm(kind: 'host' | 'root', fp: string): Promise<boolean>;
  out(line: string): void;
}

/** TEST seams. Never filled from argv, env or a route. */
export interface EnrolSeams {
  testLocalRemotes?: readonly string[];
  sshKeygenBin?: string;
  gitBin?: string;
  sshBin?: string;
  /** Replaces the TCP probe of the hub port (`true` = a hub answers). */
  hubProbe?: () => Promise<boolean>;
  /** Replace `ssh-keyscan`. */
  scan?: (host: string, port: number) => Promise<HostKey[]>;
  /** Replace the two `ls-remote` calls. */
  anonymousProbe?: () => Promise<GitxResult>;
  authProbe?: () => Promise<GitxResult>;
  /** Called at named points; throwing `EnrolCrash` simulates the process dying right there. */
  crashAt?: (stage: string) => void | Promise<void>;
  now?: () => number;
}

interface BaseInput {
  /** Absolute ledger directory. */
  ledgerDir: string;
  /** The loopback port the hub would listen on (probed: an answer = HUB_RUNNING). */
  hubPort: number;
  label?: string;
  /** `SHA256:…` of the host key (mandatory without a terminal; the CLI enforces it). */
  hostFp?: string;
  /** `remote.origin.url` of the CODE repository when the caller knows it: the ledger must be another repo. */
  codeRepoRemote?: string | null;
  seams?: EnrolSeams;
}
export interface InitInput extends BaseInput {
  remote: string;
  normalize?: boolean;
}
export interface JoinInput extends BaseInput {
  remote: string;
  rootFp?: string;
}
export interface JoinContinueInput {
  ledgerDir: string;
  hubPort: number;
  /** MANDATORY (D5, T-B4-3; optional only in the type so a missing value is a refusal, not a compile error): the add commit
   *  printed by `ledger device add` on the trusted device. Must be in F0..F1, signed by a still-active registered device, and add exactly this key. */
  addCommit?: string;
  seams?: EnrolSeams;
}

export interface InitResult {
  deviceId: string;
  label: string;
  rootFp: string;
  commit: string;
  /** Legacy random id -> key-derived id, when it happened. */
  rekeyed: { from: string; to: string } | null;
}
export interface JoinResult {
  deviceId: string;
  label: string;
  pubkey: string;
  fingerprint: string;
  base: string;
  /** The exact command to run on a trusted device. */
  addCommand: string;
}
export type JoinContinueResult =
  | { status: 'waiting' }
  | { status: 'done'; deviceId: string; label: string; slot: string; commit: string };

/* ---------------- constants ---------------- */

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
const MIGRATION_MESSAGE = 'ledger: sync migration v2';
const M0_PATHS_RE = /^(?:devices\.yml|\.gitignore|\.gitattributes|counters\/d_[a-z2-7]{10}\.yml)$/;
const MAX_ENROL_FILE_BYTES = 256 * 1024;
const FETCH_TIMEOUT_MS = 120_000;
const PUSH_TIMEOUT_MS = 180_000;
/** Pinned byte-exact texts (`ingress.ts` rejects any other). */
const PINNED: readonly { path: '.gitignore' | '.gitattributes'; want: string }[] = [
  { path: '.gitignore', want: '.hub/\n*.tmp\n' },
  { path: '.gitattributes', want: '* text eol=lf\n' },
];

/* ---------------- small helpers ---------------- */

const token = (s: string): string => {
  const t = s.toLowerCase().replace(/[^a-z0-9:_.-]/g, '-').replace(/^[^a-z0-9]+/, '');
  return t.length === 0 ? 'unknown' : t.slice(0, 59);
};

function safeEq(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Map any failure to a fixed code. `EnrolCrash` and `EnrolError` pass through. */
function mapError(err: unknown): unknown {
  if (err instanceof EnrolError || err instanceof EnrolCrash) return err;
  if (err instanceof StateError) return new EnrolError(err.code === 'BUSY' ? 'MARKER_BUSY' : err.code === 'UNSAFE' ? 'UNSAFE' : 'STATE');
  if (err instanceof DevicesError) return new EnrolError(`DEVICE:${token(err.code)}`);
  if (err instanceof HostKeyError) return new EnrolError(err.code === 'UNSAFE' ? 'UNSAFE' : 'HOSTKEY_FAILED');
  if (err instanceof TrustError) return new EnrolError('UNSAFE');
  if (err instanceof SshKeygenError) return new EnrolError('SSH_KEYGEN');
  if (err instanceof GitxError) return new EnrolError(err.code === 'URL' ? 'URL' : `GIT:${token(err.code)}`);
  if (err instanceof TreeBuildError || err instanceof ObjectsError) return new EnrolError(`GIT:${token(err.code)}`);
  return new EnrolError('INTERNAL');
}

async function guarded<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    throw mapError(err);
  }
}

function checkInput(o: { ledgerDir: unknown; hubPort: unknown }): void {
  const abs = typeof o.ledgerDir === 'string' && (process.platform === 'win32' ? /^[A-Za-z]:[\\/]/.test(o.ledgerDir) : nodePath.posix.isAbsolute(o.ledgerDir)) && !/[\0\r\n]/.test(o.ledgerDir);
  if (!abs || typeof o.hubPort !== 'number' || !Number.isInteger(o.hubPort) || o.hubPort < 1 || o.hubPort > 65535) throw new EnrolError('BAD_INPUT');
}

async function hubRunning(o: { hubPort: number; seams?: EnrolSeams }): Promise<boolean> {
  if (o.seams?.hubProbe !== undefined) return o.seams.hubProbe();
  return new Promise<boolean>((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port: o.hubPort });
    const done = (v: boolean): void => {
      s.destroy();
      resolve(v);
    };
    s.setTimeout(1500, () => done(true)); // a listener that does not answer in time still occupies the port
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

interface Core {
  dir: string;
  syncDir: string;
  gitx: Gitx;
  store: ObjectStore;
  trees: TreeBuilder;
  state: StateStore;
  tmpRoot: string;
}

async function exists(p: string): Promise<boolean> {
  return (await lstat(p).catch(() => null)) !== null;
}

/** Private `.hub/sync`, a hardened `Gitx` (own empty config / hooks, `known_hosts`, optional `deploy_key`). Creates no `.git`. */
async function openCore(dir: string, seams: EnrolSeams | undefined): Promise<Core> {
  const state = await StateStore.open(dir);
  const syncDir = nodePath.join(dir, '.hub', 'sync');
  const deploy = nodePath.join(syncDir, 'deploy_key');
  const gitx = await Gitx.open({
    syncDir,
    ...((await exists(deploy)) ? { keyFile: deploy } : {}),
    ...(seams?.testLocalRemotes !== undefined ? { testLocalRemotes: seams.testLocalRemotes } : {}),
    ...(seams?.gitBin !== undefined ? { gitBin: seams.gitBin } : {}),
    ...(seams?.sshBin !== undefined ? { sshBin: seams.sshBin } : {}),
  });
  return { dir, syncDir, gitx, store: new ObjectStore(gitx, dir), trees: new TreeBuilder(gitx, dir, nodePath.join(syncDir, 'tmp')), state, tmpRoot: nodePath.join(syncDir, 'tmp') };
}

async function readCapped(p: string): Promise<string | null> {
  const st = await lstat(p).catch(() => null);
  if (st === null) return null;
  if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_ENROL_FILE_BYTES) throw new EnrolError('DIRTY');
  return readFile(p, 'utf8');
}

async function signingFor(dir: string, bin: string): Promise<{ signing: GitSigningInput; pub: Ed25519Pub; label: string; id: string }> {
  const l = deviceLayout(dir);
  const pub = await publicKeyOf(l.keyFile, bin);
  const self = await readDeviceFile(l);
  if (self === null) throw new EnrolError('STATE_MISMATCH');
  return { signing: { sshKeygenBin: bin, keyFile: l.keyFile, allowedSignersFile: l.allowedSigners }, pub, label: self.label, id: pub.deviceId };
}

/** `status --porcelain`, `.hub/` ignored. `unstaged` = a path whose worktree differs from the index (or is untracked). */
async function statusPaths(c: Core): Promise<{ path: string; x: string; y: string }[]> {
  await c.gitx.run(['update-index', '-q', '--refresh'], { cwd: c.dir });
  const r = await c.gitx.mustRun(['status', '--porcelain=v1', '-z', '--untracked-files=all', '--no-renames'], { cwd: c.dir });
  const out: { path: string; x: string; y: string }[] = [];
  for (const rec of r.stdout.toString('utf8').split('\0')) {
    if (rec.length < 4) continue;
    const p = rec.slice(3);
    if (p === '.hub' || p.startsWith('.hub/')) continue;
    out.push({ path: p, x: rec[0] as string, y: rec[1] as string });
  }
  return out;
}

async function gitConfigProblems(dir: string, seams: EnrolSeams | undefined): Promise<{ name: string }[]> {
  const text = await readCapped(nodePath.join(dir, '.git', 'config')).catch(() => null);
  if (text === null) throw new EnrolError('NOT_REPO');
  return checkGitConfig(text, { testLocalRemotes: seams?.testLocalRemotes ?? [] });
}

async function isUnborn(c: Core, ref: string): Promise<boolean> {
  return (await c.store.revParse(ref)) === null;
}

/* ---------------- host key (steps 1.1.5 / 1.2.3) ---------------- */

/** Pin the host key for `host:port` after a HUMAN confirmed its fingerprint (or `hostFp` matched one of the keys the
 *  host offers). An existing pin is the anchor already: it is only compared with `hostFp`, never re-asked. Nothing is
 *  pinned before the confirmation. `local` remotes (tests) have none. */
async function confirmAndPinHost(c: Core, url: string, kind: RemoteKind, o: { hostFp?: string; seams?: EnrolSeams }, io: EnrolIo): Promise<void> {
  const hp = remoteHostPort(url, kind);
  if (kind === 'local') return;
  if (hp === null) throw new EnrolError('HOSTKEY_FAILED');
  if (o.hostFp !== undefined && !FP_RE.test(o.hostFp)) throw new EnrolError('BAD_INPUT');
  const pinned = await pinnedFingerprint(c.syncDir, hp.host, hp.port);
  if (pinned !== null) {
    if (o.hostFp !== undefined && !safeEq(o.hostFp, pinned)) throw new EnrolError('HOSTKEY_REFUSED');
    return;
  }
  const keys = await (o.seams?.scan ?? ((h: string, p: number): Promise<HostKey[]> => scanHostKeys(h, p, o.seams?.sshKeygenBin === undefined ? {} : {})))(hp.host, hp.port);
  if (keys.length === 0) throw new EnrolError('HOSTKEY_FAILED');
  for (const k of keys) io.out(`host key offered: ${k.type} ${k.fingerprint}`);
  let chosen: HostKey | null = null;
  if (o.hostFp !== undefined) {
    chosen = keys.find((k) => safeEq(k.fingerprint, o.hostFp as string)) ?? null;
  } else {
    for (const k of keys) {
      if ((await io.confirm('host', k.fingerprint)) === true) {
        chosen = k;
        break;
      }
    }
  }
  if (chosen === null) throw new EnrolError('HOSTKEY_REFUSED');
  await pinHostKey(c.syncDir, hp.host, hp.port, chosen.line);
}

/** Probe the remote after the pin: refuse public, inconclusive and (init) non-empty remotes. */
async function probeOrRefuse(c: Core, url: string, kind: RemoteKind, seams: EnrolSeams | undefined): Promise<{ remote: 'empty' | 'has-main'; tip: string | null }> {
  const p = await probeRemote({
    gitx: c.gitx,
    cwd: c.dir,
    url,
    kind,
    ...(seams?.anonymousProbe !== undefined ? { anonymous: seams.anonymousProbe } : {}),
    ...(seams?.authProbe !== undefined ? { authenticated: seams.authProbe } : {}),
  });
  if (p.anonymous === 'public') throw new EnrolError('REMOTE_PUBLIC');
  if (p.anonymous === 'inconclusive') throw new EnrolError('REMOTE_INCONCLUSIVE');
  if (p.remote === 'hostkey') throw new EnrolError('HOSTKEY_FAILED');
  if (p.remote === 'denied') throw new EnrolError('REMOTE_AUTH');
  if (p.remote === 'unreachable') throw new EnrolError('REMOTE_UNREACHABLE');
  return { remote: p.remote, tip: p.tip };
}

/* ================================================================== */
/*  sync init                                                          */
/* ================================================================== */

/** Detect "main already IS our migration commit" from git (the marker stage is only a hint): a valid genesis whose
 *  root is THIS device and whose subject is the migration message. */
async function detectM0(c: Core, own: { pub: Ed25519Pub; id: string }, caps: GenesisCaps): Promise<string | null> {
  const tip = await c.store.revParse(REF_MAIN);
  if (tip === null) return null;
  const g = await validateGenesis(c.store, tip, caps);
  if (!g.ok || g.root.id !== own.id || g.root.pubkey !== own.pub.line) return null;
  const raw = (await c.store.readCommitRaw(tip)).toString('utf8');
  return raw.split('\n\n').slice(1).join('\n\n').trim() === MIGRATION_MESSAGE ? tip : null;
}

/** `ledger sync init`: first device. See the module header and docs §1.1. */
export async function syncInit(o: InitInput, io: EnrolIo): Promise<InitResult> {
  const flow: Flow = { fresh: false };
  return guarded(() => withFreshCleanup(o.ledgerDir, flow, () => initInner(o, io, flow)));
}

/** A refusal in a FRESH run, before anything but the `start` marker exists, must not leave that marker behind (it
 *  would keep the hub down). A crash (`EnrolCrash`) is a dead process and cleans nothing. */
interface Flow {
  /** The `start` marker is ours and nothing else has been written yet. */
  fresh: boolean;
}
async function withFreshCleanup<T>(dir: string, flow: Flow, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (flow.fresh && !(err instanceof EnrolCrash)) await clearEnrolMarker(dir).catch(() => undefined);
    throw err;
  }
}

async function initInner(o: InitInput, io: EnrolIo, flow: Flow): Promise<InitResult> {
  checkInput(o);
  const seams = o.seams;
  const at = async (stage: string): Promise<void> => {
    await seams?.crashAt?.(stage);
  };
  const dir = o.ledgerDir;
  const now = (): number => (seams?.now ?? Date.now)();

  /* ---- 1. preconditions ---- */
  if (await hubRunning(o)) throw new EnrolError('HUB_RUNNING');
  if (!(await exists(nodePath.join(dir, '.git')))) throw new EnrolError('NOT_REPO');
  const marker = await readEnrolMarker(dir).catch((err: unknown) => {
    throw mapError(err);
  });
  if (marker !== null && marker.kind !== 'init') throw new EnrolError('MARKER_BUSY');
  const resuming = marker !== null;
  const c = await openCore(dir, seams);
  const validated = c.gitx.remote(o.remote); // GitxError('URL') -> URL
  const url = validated.url;
  if (resuming && marker.remote !== url) throw new EnrolError('MARKER_BUSY');
  if (o.codeRepoRemote !== undefined && o.codeRepoRemote !== null) {
    const a = remoteIdentity(url);
    const b = remoteIdentity(o.codeRepoRemote);
    if (a !== null && a === b) throw new EnrolError('REMOTE_SAME_AS_CODE');
  }
  const sync = await readSyncConfig(dir);
  if (sync !== null && !resuming) throw new EnrolError('ALREADY_ENROLLED');

  const head = await c.gitx.run(['symbolic-ref', '-q', 'HEAD'], { cwd: dir });
  if (!head.ok || head.stdout.toString('utf8').trim() !== REF_MAIN || (await isUnborn(c, REF_MAIN))) throw new EnrolError('NOT_REPO');
  if ((await gitConfigProblems(dir, seams)).length > 0) {
    if (!resuming) io.out('hint: remove a legacy remote with `git remote remove origin` (the ledger never edits .git/config)');
    throw new EnrolError('GIT_CONFIG');
  }
  if ((await c.state.readInflight()) !== null) throw new EnrolError('INFLIGHT');
  const bin = seams?.sshKeygenBin ?? (await resolveSshKeygen());
  const caps: GenesisCaps = { gitx: c.gitx, cwd: dir, tmpRoot: c.tmpRoot, maxFormat: LEDGER_FORMAT, ...(seams?.sshKeygenBin !== undefined ? { sshKeygenBin: seams.sshKeygenBin } : {}) };
  const layout = deviceLayout(dir);

  // already our migration commit (resume after I3/I4, or a retry against another remote after an abort)? Then none of
  // the "fresh ledger" preconditions apply any more, but the worktree must be clean.
  let m0: string | null = null;
  if (await exists(layout.keyFile)) {
    const mine = await signingFor(dir, bin).catch(() => null);
    if (mine !== null) m0 = await detectM0(c, { pub: mine.pub, id: mine.id }, caps);
  }
  if (m0 !== null) {
    if ((await statusPaths(c)).length > 0) throw new EnrolError('DIRTY');
  } else {
    const fmt = await readCapped(nodePath.join(dir, 'ledger.format'));
    if (fmt === null || fmt !== `${String(LEDGER_FORMAT)}\n`) throw new EnrolError('FORMAT');
    if ((await readLocalFile(nodePath.join(dir, '.hub', 'local.yml'))) === null) throw new EnrolError('LOCAL_YML');
    if (!resuming) {
      const dirty = await statusPaths(c);
      if (dirty.length > 0) throw new EnrolError('DIRTY');
      const L0 = (await c.store.revParse(REF_MAIN)) as string;
      if ((await registryAt(c.store, c.gitx, dir, L0).catch(() => 'bad' as const)) !== null) throw new EnrolError('REGISTRY_TRACKED');
    }
  }

  /* ---- 2. marker ---- */
  const mark = async (stage: string, F0?: string): Promise<void> => {
    await writeEnrolMarker(dir, { v: 1, kind: 'init', stage, startedAt: marker?.startedAt ?? new Date(now()).toISOString(), remote: url, ...(F0 !== undefined ? { F0 } : {}) });
  };
  if (!resuming) {
    await mark('start');
    flow.fresh = true;
  } else {
    // take the marker over BEFORE any work: a live foreign owner (or a racing run) is BUSY here, not after an identity was written
    await mark(marker.stage, marker.F0);
  }

  /* ---- 4. pinned files (read-only decision now, write after the identity) ---- */
  const pinnedWrites: { path: '.gitignore' | '.gitattributes'; want: string }[] = [];
  if (m0 === null) {
    let anyDropped = false;
    for (const p of PINNED) {
      const have = await readCapped(nodePath.join(dir, p.path));
      if (have === p.want) continue;
      if (have !== null) {
        const wantLines = new Set(p.want.split('\n'));
        const dropped = have.split('\n').filter((l) => l.trim() !== '' && !wantLines.has(l.trim()) && !wantLines.has(l));
        if (dropped.length > 0) {
          anyDropped = true;
          for (const l of dropped.slice(0, 20)) io.out(`${o.normalize === true ? 'dropping' : 'would drop'} from ${p.path}: ${safeOutput(l, 120)}`);
        }
      }
      pinnedWrites.push(p);
    }
    if (anyDropped && o.normalize !== true) throw new EnrolError('PINNED');
  }

  /* ---- 5. host key, 6. remote checks (no identity or file has been written yet) ---- */
  await confirmAndPinHost(c, url, validated.kind, { ...(o.hostFp !== undefined ? { hostFp: o.hostFp } : {}), ...(seams !== undefined ? { seams } : {}) }, io);
  if (m0 === null) {
    const p = await probeOrRefuse(c, url, validated.kind, seams);
    if (p.remote !== 'empty') throw new EnrolError('REMOTE_NOT_EMPTY');
  }

  /* ---- 3. identity: key -> legacy re-key -> root registration (one idempotent operation under D, no I/O inside) ---- */
  let rekeyed: { from: string; to: string } | null = null;
  if (m0 === null) {
    const oldId = (await readDeviceFile(layout))?.device_id ?? null;
    const init = await initDevice(dir, { root: true, rekeyLegacy: true, bin, ...(o.label !== undefined ? { label: o.label } : {}), now: new Date(now()) });
    if (oldId !== null && oldId !== init.deviceId) rekeyed = { from: oldId, to: init.deviceId };
    await mark('identity');
    flow.fresh = false;
    await at('after-identity'); // I1
    for (const p of pinnedWrites) await writePinned(dir, p.path, p.want);
  }
  const own = await signingFor(dir, bin);
  const g0 = await readSigners(layout);
  if (!g0.some((s) => s.id === own.id && s.pubkey === own.pub.line)) throw new EnrolError('STATE_MISMATCH');

  /* ---- 7. migration commit M0 ---- */
  const L = (await c.store.revParse(REF_MAIN)) as string;
  if (m0 === null) {
    const changes = await collectChanges(c);
    const rootEntry = (await readDevices(layout))?.devices.find((d) => d.id === own.id);
    const addedMs = rootEntry === undefined ? NaN : Date.parse(rootEntry.added);
    // the root's `added` must be within 15 min of the commit time (acceptDevicesChange): a long pause (human
    // confirmation, a resumed run) makes the commit carry the registration time instead of "now"
    const date = new Date(Number.isFinite(addedMs) && Math.abs(now() - addedMs) > 10 * 60_000 ? addedMs : now());
    const tree = await c.trees.buildTree(L, changes);
    m0 = await c.trees.commitTree({
      tree,
      parents: [L],
      message: MIGRATION_MESSAGE,
      identity: { name: own.label, email: deviceEmail(own.id) },
      signing: own.signing,
      date,
    });
    await at('after-m0-built'); // I2
    // egress self-check: exactly what a joiner will run on the pushed tip, before any ref moves
    const eg = await validateGenesis(c.store, m0, caps);
    if (!eg.ok) throw new EnrolError(`EGRESS:${eg.rule}`);
    if (eg.root.id !== own.id || eg.root.pubkey !== own.pub.line) throw new EnrolError('EGRESS:root');
    // index -> M0 (the worktree already holds exactly these bytes); then main by compare-and-swap
    await c.gitx.mustRun(['read-tree', '--reset', m0], { cwd: dir });
    await at('after-read-tree'); // I3
    const left = (await statusPaths(c)).filter((s) => s.y !== ' ');
    if (left.length > 0) throw new EnrolError('DIRTY');
    await c.trees.updateRef(REF_MAIN, m0, L);
    await at('after-update-ref'); // I4
    if ((await statusPaths(c)).length > 0) throw new EnrolError('DIRTY');
  }
  await mark('committed', m0);

  /* ---- 8. sync.yml, push (ls-remote decides when the outcome is unknown) ---- */
  await writeSyncConfig(dir, url, { ...(seams?.testLocalRemotes !== undefined ? { testLocalRemotes: seams.testLocalRemotes } : {}) });
  await mark('pushing', m0);
  // freshest look right before the push, ALWAYS with the public / inconclusive refusal (also on every resumed run)
  const pre = await probeOrRefuse(c, url, validated.kind, seams);
  if (pre.remote === 'has-main' && pre.tip !== m0) throw new EnrolError('PUSH_REJECTED');
  if (pre.remote === 'empty') {
    const res = await c.gitx.push(dir, url, m0, { timeoutMs: PUSH_TIMEOUT_MS });
    if (!res.ok) {
      const after = await probeRemote({
        gitx: c.gitx,
        cwd: dir,
        url,
        kind: validated.kind,
        ...(seams?.anonymousProbe !== undefined ? { anonymous: seams.anonymousProbe } : {}),
        ...(seams?.authProbe !== undefined ? { authenticated: seams.authProbe } : {}),
      }).catch(() => null);
      if (after?.remote === 'has-main' && after.tip === m0) {
        // it arrived after all
      } else if (after?.remote === 'has-main') {
        throw new EnrolError('PUSH_REJECTED');
      } else {
        throw new EnrolError('PUSH_FAILED');
      }
    }
  }
  await at('after-push'); // I5/I6

  /* ---- 9. accepted ref + mirror, marker off ---- */
  const acc = await c.store.revParse(REF_ACCEPTED);
  if (acc === null) await c.trees.createRef(REF_ACCEPTED, m0);
  else if (acc !== m0) throw new EnrolError('STATE_MISMATCH');
  await at('after-accepted-ref');
  const mirror = m0;
  await c.state.update((s) => {
    s.accepted = mirror;
  });
  await clearEnrolMarker(dir);

  const rootFp = own.pub.fingerprint;
  io.out(`device ${own.id} (${own.label}) is now the root of this ledger`);
  io.out(`root key fingerprint ${rootFp} (give it to every joining device: --root-fp)`);
  if (rekeyed !== null) io.out(`legacy device id ${rekeyed.from} became ${rekeyed.to} (counters carried over)`);
  io.out('next: start the hub with LEDGER_SYNC=1');
  return { deviceId: own.id, label: own.label, rootFp, commit: m0, rekeyed };
}

async function writePinned(dir: string, path: string, text: string): Promise<void> {
  const full = nodePath.join(dir, path);
  const st = await lstat(full).catch(() => null);
  if (st !== null && (st.isSymbolicLink() || !st.isFile())) throw new EnrolError('DIRTY');
  const tmp = `${full}.enrol.${String(process.pid)}.tmp`;
  await writeFile(tmp, text, { mode: 0o600, flag: 'w' });
  await rename(tmp, full);
}

/** The M0 change set: exactly the dirty paths of the worktree, each of which must be one this flow writes. */
async function collectChanges(c: Core): Promise<TreeChange[]> {
  const dirty = await statusPaths(c);
  const out: TreeChange[] = [];
  for (const d of dirty) {
    if (!M0_PATHS_RE.test(d.path)) throw new EnrolError('DIRTY');
    const full = nodePath.join(c.dir, d.path);
    const st = await lstat(full).catch(() => null);
    if (st === null) {
      out.push({ path: d.path, remove: true });
      continue;
    }
    if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_ENROL_FILE_BYTES) throw new EnrolError('DIRTY');
    out.push({ path: d.path, content: await readFile(full, 'utf8') });
  }
  if (!out.some((x) => x.path === 'devices.yml' && 'content' in x)) throw new EnrolError('DIRTY');
  return out;
}

/* ================================================================== */
/*  sync join                                                          */
/* ================================================================== */

/** Entries of a join directory that are NOT ours. */
async function foreignEntries(dir: string): Promise<string[]> {
  const names = await readdir(dir).catch((err: unknown) => {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [] as string[];
    throw err;
  });
  return names.filter((n) => n !== '.hub' && n !== '.git');
}

function joinInstructions(io: EnrolIo, r: JoinResult): void {
  io.out(`this device is ${r.deviceId} (${r.label})`);
  io.out(`public key: ${r.pubkey}`);
  io.out(`fingerprint: ${r.fingerprint}`);
  io.out('on a trusted device run:');
  io.out(r.addCommand);
  io.out('then run `ledger sync join --continue --add-commit <sha>` here (the commit sha `ledger device add` prints there; required)');
}

async function joinResult(dir: string, bin: string, base: string): Promise<JoinResult> {
  const own = await signingFor(dir, bin);
  return {
    deviceId: own.id,
    label: own.label,
    pubkey: own.pub.line,
    fingerprint: own.pub.fingerprint,
    base,
    addCommand: `ledger device add '${own.pub.line}' --label ${own.label} --fp ${own.pub.fingerprint}`,
  };
}

/** `ledger sync join <url>`: phase 1 (fetch, validate genesis, two confirmations, checkout of F0). */
export async function syncJoin(o: JoinInput, io: EnrolIo): Promise<JoinResult> {
  const flow: Flow = { fresh: false };
  return guarded(() => withFreshCleanup(o.ledgerDir, flow, () => joinInner(o, io, flow)));
}

async function joinInner(o: JoinInput, io: EnrolIo, flow: Flow): Promise<JoinResult> {
  checkInput(o);
  const seams = o.seams;
  const at = async (stage: string): Promise<void> => {
    await seams?.crashAt?.(stage);
  };
  const dir = o.ledgerDir;
  const now = (): number => (seams?.now ?? Date.now)();
  if (o.rootFp !== undefined && !FP_RE.test(o.rootFp)) throw new EnrolError('BAD_INPUT');

  /* ---- 1. preconditions ---- */
  if (await hubRunning(o)) throw new EnrolError('HUB_RUNNING');
  const marker = await readEnrolMarker(dir).catch((err: unknown) => {
    // a missing directory is "no marker"; everything else is real
    if ((err as { code?: string }).code === 'ENOENT') return null;
    throw mapError(err);
  });
  if (marker !== null && marker.kind !== 'join') throw new EnrolError('MARKER_BUSY');
  const bin = seams?.sshKeygenBin ?? (await resolveSshKeygen());
  const resuming = marker !== null;

  if (!resuming) {
    if ((await foreignEntries(dir)).length > 0) throw new EnrolError('NOT_EMPTY');
    await mkdir(dir, { recursive: true, mode: 0o700 });
  } else if (marker.stage === 'awaiting-add') {
    // idempotent: show the instructions again
    const base = marker.F0;
    if (base === undefined) throw new EnrolError('MARKER_STAGE');
    const r = await joinResult(dir, bin, base);
    joinInstructions(io, r);
    return r;
  } else if (marker.stage === 'checkout') {
    // a crash in the middle of OUR checkout: nobody else wrote here (the dir was empty), start the checkout again
    if (await exists(nodePath.join(dir, '.git'))) {
      for (const n of await readdir(dir)) if (n !== '.hub') await rm(nodePath.join(dir, n), { recursive: true, force: true });
    } else if ((await foreignEntries(dir)).length > 0) throw new EnrolError('NOT_EMPTY');
  }
  const core = await openCore(dir, seams);
  const c = core;
  const validated = c.gitx.remote(o.remote);
  const url = validated.url;
  if (resuming && marker.remote !== url) throw new EnrolError('MARKER_BUSY');
  if (o.codeRepoRemote !== undefined && o.codeRepoRemote !== null) {
    const a = remoteIdentity(url);
    const b = remoteIdentity(o.codeRepoRemote);
    if (a !== null && a === b) throw new EnrolError('REMOTE_SAME_AS_CODE');
  }
  if ((await readSyncConfig(dir)) !== null) throw new EnrolError('ALREADY_ENROLLED');

  /* ---- 2. marker ---- */
  const startedAt = marker?.startedAt ?? new Date(now()).toISOString();
  const mark = async (stage: string, F0?: string): Promise<void> => {
    await writeEnrolMarker(dir, { v: 1, kind: 'join', stage, startedAt, remote: url, ...(F0 !== undefined ? { F0 } : {}) });
  };
  await mark('start');
  flow.fresh = !resuming;

  /* ---- 3. host key pin + remote checks (no repository exists yet) ---- */
  await confirmAndPinHost(c, url, validated.kind, { ...(o.hostFp !== undefined ? { hostFp: o.hostFp } : {}), ...(seams !== undefined ? { seams } : {}) }, io);
  const probe = await probeOrRefuse(c, url, validated.kind, seams);
  if (probe.remote === 'empty') throw new EnrolError('REMOTE_EMPTY');

  /* ---- repository + identity ---- */
  const hasGit = await exists(nodePath.join(dir, '.git'));
  if (hasGit) {
    if (!(await isUnborn(c, REF_MAIN)) || !(await isUnborn(c, REF_ACCEPTED))) throw new EnrolError('NOT_EMPTY');
    if ((await gitConfigProblems(dir, seams)).length > 0) throw new EnrolError('GIT_CONFIG');
  } else {
    await c.gitx.initRepo(dir);
  }
  await initDevice(dir, { bin, ...(o.label !== undefined ? { label: o.label } : {}) });

  /* ---- 4. fetch F0 once; nothing is checked out yet ---- */
  const f = await c.gitx.fetch(dir, url, { src: REF_MAIN, dst: REF_INCOMING, timeoutMs: FETCH_TIMEOUT_MS });
  if (!f.ok) throw new EnrolError(classifyProbe(f) === 'hostkey' ? 'HOSTKEY_FAILED' : 'FETCH_FAILED');
  const F0 = await c.store.revParse(REF_INCOMING);
  if (F0 === null) throw new EnrolError('FETCH_FAILED');
  await at('after-fetch'); // J1

  /* ---- 5. genesis + root confirmation ---- */
  const caps: GenesisCaps = { gitx: c.gitx, cwd: dir, tmpRoot: c.tmpRoot, maxFormat: LEDGER_FORMAT, ...(seams?.sshKeygenBin !== undefined ? { sshKeygenBin: seams.sshKeygenBin } : {}) };
  const g = await validateGenesis(c.store, F0, caps);
  if (!g.ok) throw new EnrolError(`GENESIS:${g.rule}`);
  const rootPub = parseEd25519Pub(g.root.pubkey);
  if (rootPub === null) throw new EnrolError('GENESIS:root-key');
  io.out(`root device ${g.root.id} (${g.root.label}) key fingerprint ${rootPub.fingerprint}`);
  if (o.rootFp !== undefined) {
    if (!safeEq(o.rootFp, rootPub.fingerprint)) throw new EnrolError('ROOT_FP_REFUSED');
  } else if ((await io.confirm('root', rootPub.fingerprint)) !== true) {
    throw new EnrolError('ROOT_FP_REFUSED');
  }
  if (g.root.revoked !== null) throw new EnrolError('ROOT_REVOKED');

  /* ---- 6. trust bootstrap (idempotent), checkout of F0, refs ---- */
  await mark('checkout', F0);
  flow.fresh = false;
  let boot: { rootRevoked: boolean };
  try {
    boot = await bootstrapSigners(dir, g.devices, rootPub.fingerprint);
  } catch (err) {
    // a half-finished earlier join of THIS directory may hold a different (older) set: it never completed, so it
    // is reset (the human just confirmed the root again) and rebuilt from the registry validated now
    if (err instanceof DevicesError && err.code === 'SIGNERS_NOT_EMPTY' && resuming) {
      await rm(deviceLayout(dir).allowedSigners, { force: true });
      boot = await bootstrapSigners(dir, g.devices, rootPub.fingerprint);
    } else throw err;
  }
  if (boot.rootRevoked) throw new EnrolError('ROOT_REVOKED');
  // the checkout writes only objects the validator saw (F0 is resolved once), onto an empty worktree
  await c.gitx.mustRun(['read-tree', '--reset', '-u', F0], { cwd: dir });
  await at('after-checkout'); // J2a
  const zero = '0'.repeat(F0.length);
  const mainNow = await c.store.revParse(REF_MAIN);
  if (mainNow === null) {
    const r = await c.gitx.run(['update-ref', '--no-deref', REF_MAIN, F0, zero], { cwd: dir });
    if (!r.ok) throw new EnrolError('STATE_MISMATCH');
  } else if (mainNow !== F0) throw new EnrolError('STATE_MISMATCH');
  const acc = await c.store.revParse(REF_ACCEPTED);
  if (acc === null) await c.trees.createRef(REF_ACCEPTED, F0);
  else if (acc !== F0) throw new EnrolError('STATE_MISMATCH');
  await c.state.update((s) => {
    s.accepted = F0;
  });
  await mark('awaiting-add', F0);
  await at('after-awaiting');

  /* ---- 7. instructions ---- */
  const r = await joinResult(dir, bin, F0);
  joinInstructions(io, r);
  return r;
}

/* ---------------- phase 2 ---------------- */

/** The `--add-commit` pin: a single-parent commit strictly between F0 and F1 (on top of F0), signed (valid ssh signature) by a
 *  device that is registered and NOT revoked in its parent registry nor in F1, whose only change to `devices.yml` is adding
 *  exactly THIS joiner's entry (as it is in F1). The range F0..F1 itself was validated by `validateRange` (bootstrap trust set). */
async function verifyAddCommit(
  c: Core,
  dir: string,
  v: { addCommit: string; F0: string; F1: string; own: string; ownEntry: DeviceEntry; registryF1: DevicesFile; sshKeygenBin?: string },
): Promise<void> {
  const bad = (): never => {
    throw new EnrolError('ADD_COMMIT');
  };
  if (!(await c.store.hasCommit(v.addCommit))) bad();
  if (v.addCommit === v.F0 || !(await c.store.isAncestor(v.F0, v.addCommit)) || !(await c.store.isAncestor(v.addCommit, v.F1))) bad();
  const raw = await c.store.readCommitRaw(v.addCommit);
  const sig = await verifyCommitSignature(raw, { tmpRoot: c.tmpRoot, ...(v.sshKeygenBin !== undefined ? { bin: v.sshKeygenBin } : {}) });
  if (sig.reason === 'verifier-error') throw new EnrolError('SSH_KEYGEN');
  if (!sig.valid || sig.pubkeyLine === null || sig.headers === null || sig.headers.parents.length !== 1) bad();
  const parent = (sig.headers as { parents: string[] }).parents[0] as string;
  const signer = parseEd25519Pub(sig.pubkeyLine as string)?.line;
  if (signer === undefined || signer === v.own) bad(); // a device never vouches for itself
  const before = await registryAt(c.store, c.gitx, dir, parent);
  const after = await registryAt(c.store, c.gitx, dir, v.addCommit);
  if (before === null || after === null) bad();
  const b = (before as DevicesFile).devices;
  const a = (after as DevicesFile).devices;
  const sBefore = b.find((d) => d.pubkey === signer);
  const sF1 = v.registryF1.devices.find((d) => d.pubkey === signer);
  // revoked in the parent registry, or since (in F1): refused (the rollback this pin exists for)
  if (sBefore === undefined || sBefore.revoked !== null || sF1 === undefined || sF1.revoked !== null) bad();
  if (a.length !== b.length + 1) bad();
  const added = a.filter((d) => !b.some((o) => o.id === d.id));
  if (added.length !== 1 || (added[0] as DeviceEntry).pubkey !== v.own) bad();
  if ((added[0] as DeviceEntry).id !== v.ownEntry.id) bad();
  for (const o of b) {
    const n = a.find((d) => d.id === o.id);
    if (n === undefined || JSON.stringify({ ...n, last_seen: undefined }) !== JSON.stringify({ ...o, last_seen: undefined })) bad();
  }
}

/** `ledger sync join --continue --add-commit <sha>` (the pin is mandatory: D5 / T-B4-3). */
export async function syncJoinContinue(o: JoinContinueInput, io: EnrolIo): Promise<JoinContinueResult> {
  return guarded(() => continueInner(o, io));
}

async function continueInner(o: JoinContinueInput, io: EnrolIo): Promise<JoinContinueResult> {
  checkInput(o);
  const seams = o.seams;
  const at = async (stage: string): Promise<void> => {
    await seams?.crashAt?.(stage);
  };
  const dir = o.ledgerDir;
  if (o.addCommit === undefined) throw new EnrolError('ADD_COMMIT_REQUIRED');
  if (!isSha(o.addCommit)) throw new EnrolError('BAD_INPUT');
  const addCommit = o.addCommit;
  if (await hubRunning(o)) throw new EnrolError('HUB_RUNNING');
  const marker = await readEnrolMarker(dir).catch((err: unknown) => {
    throw mapError(err);
  });
  if (marker === null) throw new EnrolError('MARKER_MISSING');
  if (marker.kind !== 'join' || marker.stage !== 'awaiting-add' || marker.F0 === undefined) throw new EnrolError('MARKER_STAGE');
  const F0 = marker.F0;
  const bin = seams?.sshKeygenBin ?? (await resolveSshKeygen());
  const c = await openCore(dir, seams);
  const url = c.gitx.remote(marker.remote).url;
  const own = await signingFor(dir, bin);
  const layout = deviceLayout(dir);

  /* ---- 8. fetch F1; range validated with the bootstrap trust set; own entry present ---- */
  const f = await c.gitx.fetch(dir, url, { src: REF_MAIN, dst: REF_INCOMING, timeoutMs: FETCH_TIMEOUT_MS });
  if (!f.ok) throw new EnrolError(classifyProbe(f) === 'hostkey' ? 'HOSTKEY_FAILED' : 'FETCH_FAILED');
  const F1 = await c.store.revParse(REF_INCOMING);
  if (F1 === null) throw new EnrolError('FETCH_FAILED');
  // `tip` = where the worktree is: F0, or (after a crash inside the FF) a later commit an earlier run of ours validated
  const tip = await c.store.revParse(REF_MAIN);
  if (tip === null || !(await c.store.isAncestor(F0, tip))) throw new EnrolError('STATE_MISMATCH');
  if (!(await c.store.isAncestor(tip, F1))) throw new EnrolError('REMOTE_REWOUND');

  if (F1 !== tip) {
    const trusted = new Set((await readSigners(layout)).map((s) => s.pubkey));
    const outcome = await validateRange({
      store: c.store,
      tmpRoot: c.tmpRoot,
      A: tip,
      L: tip,
      F: F1,
      mode: 'enforce', // join never runs in warn
      localDevice: own.id,
      trusted,
      seenSigning: new Set<string>(),
      confirmedRevocations: new Set<string>(),
      maxFormat: LEDGER_FORMAT,
      ...(seams?.sshKeygenBin !== undefined ? { sshKeygenBin: seams.sshKeygenBin } : {}),
    });
    if (outcome.kind === 'quarantine') throw new EnrolError(`RANGE:${token(outcome.rule)}`);
    if (outcome.kind === 'halt-d2') throw new EnrolError(outcome.d2Kind === 'self' ? 'REVOKED' : 'RANGE:revocation-root');
    if (outcome.kind === 'format') throw new EnrolError('FORMAT');
    if (outcome.kind === 'transient') throw new EnrolError(`RANGE:retry-${token(outcome.why)}`);
    const treeProblem = await fullTreeProblem(c.store, F1, LEDGER_FORMAT);
    if (treeProblem !== null) throw new EnrolError(`RANGE:${token(treeProblem)}`);
  }
  const reg = await registryAt(c.store, c.gitx, dir, F1);
  const mine = reg?.devices.find((d) => d.pubkey === own.pub.line);
  if (reg === null || mine === undefined) return { status: 'waiting' };
  if (mine.id !== own.id) throw new EnrolError('DEVICE:id_mismatch');
  if (mine.revoked !== null) throw new EnrolError('REVOKED');
  // T-B4-3 (D5): the pinned commit is what a rolled-back remote cannot forge
  await verifyAddCommit(c, dir, { addCommit, F0, F1, own: own.pub.line, ownEntry: mine, registryF1: reg, ...(seams?.sshKeygenBin !== undefined ? { sshKeygenBin: seams.sshKeygenBin } : {}) });

  /* ---- 9. fast-forward tip -> F1 (refs by compare-and-swap) ---- */
  if (tip !== F1) {
    await c.gitx.mustRun(['read-tree', '--reset', '-u', F1], { cwd: dir });
    await at('after-ff-readtree'); // J3a
    await c.trees.updateRef(REF_MAIN, F1, tip);
    await at('after-ff-main'); // J3
  }
  const target = F1;
  const accepted = await c.store.revParse(REF_ACCEPTED);
  if (accepted === null || !(await c.store.isAncestor(accepted, target)) || !(await c.store.isAncestor(F0, accepted))) throw new EnrolError('STATE_MISMATCH');
  if (accepted !== target) await c.trees.updateRef(REF_ACCEPTED, target, accepted);
  if ((await c.store.revParse(REF_MAIN)) !== target) throw new EnrolError('STATE_MISMATCH');
  await withDeviceLock(dir, async () => {
    await pruneRevokedSigners(dir);
  });

  /* ---- 10. slot, own key, sync.yml, mirror, marker ---- */
  const adopted = await adoptSlot(dir, { bin });
  await at('after-adopt'); // J4a
  await approveDevice(dir, own.id, own.pub.fingerprint);
  await writeSyncConfig(dir, url, { ...(seams?.testLocalRemotes !== undefined ? { testLocalRemotes: seams.testLocalRemotes } : {}) });
  await at('after-sync-yml'); // J4
  await c.state.update((s) => {
    s.accepted = target;
  });
  await clearEnrolMarker(dir);
  io.out(`joined as ${own.id} (${adopted.label}, slot ${adopted.slot === '' ? '-' : adopted.slot})`);
  io.out('next: start the hub with LEDGER_SYNC=1');
  return { status: 'done', deviceId: own.id, label: adopted.label, slot: adopted.slot, commit: target };
}

/* ---------------- abort ---------------- */

/** `--abort`: removes the enrol marker and `.hub/sync.yml`, nothing else (never commits, keys, refs, pins). Without a
 *  marker there is nothing to abort and an enrolled ledger stays enrolled. */
export async function enrolAbort(ledgerDir: string): Promise<{ aborted: boolean }> {
  return guarded(async () => {
    checkInput({ ledgerDir, hubPort: 1 });
    const hasMarker = await lstat(nodePath.join(ledgerDir, '.hub', 'sync', 'enrol.json')).then(() => true, (err: unknown) => {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw err;
    });
    if (!hasMarker) return { aborted: false };
    await rm(nodePath.join(ledgerDir, '.hub', 'sync.yml'), { force: true });
    await clearEnrolMarker(ledgerDir, { force: true });
    return { aborted: true };
  });
}

export type { EnrolMarker };
