/** Test fixtures for the sync plumbing (docs/f3b-plan.md §3). TEST-ONLY: never imported by production code.
 *
 *  A `Kit` is a private temp root holding one bare repository that plays the remote, plus N "hubs": each a real
 *  working repo with its own real ssh-keygen ed25519 device key and its own hardened `Gitx`. The remote is
 *  reached through the runner's `testLocalRemotes` option (a local path, the only non-ssh remote there is).
 *
 *  Hostile-commit helpers write straight into the bare remote with git plumbing, so they can express things the
 *  production builders refuse on purpose: unsigned commits, commits signed by a key nobody registered,
 *  symlinks and exec bits, `.hub/x`, and history rewrites (`update-ref` without an old value).
 */

import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import {
  addDevice,
  approveDevice,
  deviceLayout,
  generateKeyPair,
  parseEd25519Pub,
  readDeviceFile,
  readSigners,
  renderAllowedSigners,
  renderDevicesYaml,
  type DeviceEntry,
  gitSigningArgs,
  publicKeyOf,
  resolveSshKeygen,
  withPrivateTmp,
  type Ed25519Pub,
  type GitSigningInput,
} from '@agent-ledger/shared';
import type { CommitOutcome } from '../git.ts';
import { Ledger } from '../ledger/ledger.ts';
import { tempConfig } from '../test-helpers.ts';
import type { ApplyDeps, ApplyHost, DeliverNotes } from './apply.ts';
import type { CycleDeps } from './cycle.ts';
import { Gitx, REF_ACCEPTED, REF_MAIN, isSha, type GitxResult } from './gitx.ts';
import type { ProposedItem } from './merge/tree.ts';
import { ObjectStore } from './objects.ts';
import { StateStore } from './state.ts';
import { TreeBuilder, type CommitIdentity, type TreeChange } from './treebuild.ts';

export interface RawFile {
  path: string;
  content: string | Uint8Array;
  /** `100644` (default), `100755` (exec bit), `120000` (symlink: content = link target). */
  mode?: '100644' | '100755' | '120000';
}

export interface RawRemove {
  path: string;
  remove: true;
}

export interface RawCommitSpec {
  files?: readonly (RawFile | RawRemove)[];
  /** Default: current tip of `main` (none for the first commit). `[]` = root commit. */
  parents?: readonly string[];
  message?: string;
  /** `null` = unsigned. A hub = signed with THAT hub's key (a "foreign" signer is simply a hub nobody registered). */
  signer?: TestHub | null;
  /** Committer identity claim (a hint only; the hostile case is a lie here). */
  identity?: CommitIdentity;
  date?: Date;
  /** Move `main` to the new commit (default true). Always without an old value: this is the hostile remote. */
  setMain?: boolean;
}

export interface TestRemote {
  /** Bare repository path (also the value to pass as the remote URL). */
  path: string;
  gitx: Gitx;
  store: ObjectStore;
  main(): Promise<string | null>;
  rawCommit(spec: RawCommitSpec): Promise<string>;
  /** Unsigned commit on top of main. */
  pushUnsigned(files: readonly RawFile[], message?: string): Promise<string>;
  /** Commit on top of main signed by `signer` (use a hub that was never registered for "foreign-signed"). */
  pushSigned(signer: TestHub, files: readonly RawFile[], message?: string): Promise<string>;
  /** A symlink at `path` pointing at `target`. */
  pushSymlink(signer: TestHub | null, path: string, target: string): Promise<string>;
  /** A file under `.hub/`. */
  pushHubPath(signer: TestHub | null, path?: string): Promise<string>;
  /** Replace history: a fresh ROOT commit and `main` force-moved onto it. Returns the new tip. */
  rewriteHistory(signer: TestHub | null, files?: readonly RawFile[]): Promise<string>;
  /** Force `main` to `sha` (rollback / rewrite). */
  forceMain(sha: string): Promise<void>;
}

export interface TestHub {
  n: number;
  label: string;
  deviceId: string;
  /** Working repository. */
  dir: string;
  keyFile: string;
  pub: Ed25519Pub;
  signing: GitSigningInput;
  identity: CommitIdentity;
  gitx: Gitx;
  store: ObjectStore;
  trees: TreeBuilder;
  syncDir: string;
  /** Honest commit built the production way (temp index, `--no-filters`, signed unless `signed: false`); advances local `main`. */
  commit(changes: readonly TreeChange[], o?: { message?: string; signed?: boolean; date?: Date }): Promise<string>;
  main(): Promise<string | null>;
  pushMain(remote: TestRemote): Promise<{ ok: boolean; stderr: string }>;
  fetchIncoming(remote: TestRemote): Promise<string | null>;
}

export interface Kit {
  root: string;
  remote: TestRemote;
  makeHub(n: number): Promise<TestHub>;
  cleanup(): Promise<void>;
}

const BLOB_MODE_RE = /^(?:100644|100755|120000)$/;

async function privateMkdir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
}

/** Commit assembled with plain plumbing in a temp index; any mode, any path git itself accepts. */
async function rawCommit(
  ctx: { gitx: Gitx; cwd: string; tmpRoot: string; currentMain: () => Promise<string | null> },
  spec: RawCommitSpec,
): Promise<string> {
  const { gitx, cwd } = ctx;
  const parents = spec.parents ?? ((await ctx.currentMain()) !== null ? [(await ctx.currentMain()) as string] : []);
  const files = spec.files ?? [];
  const sha = await withPrivateTmp(ctx.tmpRoot, async (dir) => {
    const extraEnv = { GIT_INDEX_FILE: nodePath.join(dir, 'index') } as const;
    const first = parents[0];
    if (first !== undefined) await gitx.mustRun(['read-tree', first], { cwd, extraEnv });
    const lines: Buffer[] = [];
    let hex = first !== undefined ? first.length : 40;
    for (const f of files) {
      if ('remove' in f) {
        lines.push(Buffer.from(`0 ${'0'.repeat(hex)}\t${f.path}\0`, 'utf8'));
        continue;
      }
      const mode = f.mode ?? '100644';
      if (!BLOB_MODE_RE.test(mode)) throw new Error('testkit: bad mode');
      const bytes = typeof f.content === 'string' ? Buffer.from(f.content, 'utf8') : Buffer.from(f.content);
      const h = await gitx.mustRun(['hash-object', '-w', '--no-filters', '-t', 'blob', '--stdin'], { cwd, input: bytes });
      const blob = h.stdout.toString('utf8').trim();
      hex = blob.length;
      lines.push(Buffer.from(`${mode} ${blob}\t${f.path}\0`, 'utf8'));
    }
    if (lines.length > 0) await gitx.mustRun(['update-index', '-z', '--index-info'], { cwd, extraEnv, input: Buffer.concat(lines) });
    const tree = (await gitx.mustRun(['write-tree'], { cwd, extraEnv })).stdout.toString('utf8').trim();
    const args = ['commit-tree', tree];
    for (const p of parents) args.push('-p', p);
    const identity = spec.identity ?? { name: 'testkit', email: 'testkit@devices.agent-ledger.invalid' };
    const extraConfig = [`user.name=${identity.name}`, `user.email=${identity.email}`];
    if (spec.signer !== undefined && spec.signer !== null) {
      const s = gitSigningArgs(spec.signer.signing);
      for (let k = 1; k < s.length; k += 2) extraConfig.push(s[k] as string);
      args.push('-S');
    }
    args.push('-F', '-');
    const env: { GIT_AUTHOR_DATE?: string; GIT_COMMITTER_DATE?: string } = {};
    if (spec.date !== undefined) {
      const unix = Math.floor(spec.date.getTime() / 1000);
      env.GIT_AUTHOR_DATE = `${unix} +0000`;
      env.GIT_COMMITTER_DATE = `${unix} +0000`;
    }
    const out = await gitx.mustRun(args, { cwd, input: `${spec.message ?? 'testkit commit'}\n`, extraConfig, extraEnv: env });
    return out.stdout.toString('utf8').trim();
  });
  if (!isSha(sha)) throw new Error('testkit: commit-tree returned a non-object-id');
  return sha;
}

export async function makeKit(): Promise<Kit> {
  const root = await realpath(await mkdtemp(nodePath.join(await realpath(tmpdir()), 'agl-f3b-')));
  await chmod(root, 0o700);
  const sshKeygenBin = await resolveSshKeygen();

  const remotePath = nodePath.join(root, 'remote.git');
  await privateMkdir(remotePath);
  const remoteSync = nodePath.join(root, 'remote-sync');
  const remoteGitx = await Gitx.open({ syncDir: remoteSync });
  await remoteGitx.mustRun(['init', '-q', '--bare', '-b', 'main'], { cwd: remotePath });
  const remoteStore = new ObjectStore(remoteGitx, remotePath);
  const remoteMain = (): Promise<string | null> => remoteStore.revParse(REF_MAIN);
  const remoteCtx = { gitx: remoteGitx, cwd: remotePath, tmpRoot: nodePath.join(remoteSync, 'tmp'), currentMain: remoteMain };

  const forceMain = async (sha: string): Promise<void> => {
    await remoteGitx.mustRun(['update-ref', '--no-deref', REF_MAIN, sha], { cwd: remotePath });
  };
  const advance = async (spec: RawCommitSpec): Promise<string> => {
    const sha = await rawCommit(remoteCtx, spec);
    if (spec.setMain !== false) await forceMain(sha);
    return sha;
  };

  const remote: TestRemote = {
    path: remotePath,
    gitx: remoteGitx,
    store: remoteStore,
    main: remoteMain,
    rawCommit: advance,
    forceMain,
    pushUnsigned: (files, message) => advance({ files, signer: null, ...(message !== undefined ? { message } : {}) }),
    pushSigned: (signer, files, message) => advance({ files, signer, ...(message !== undefined ? { message } : {}) }),
    pushSymlink: (signer, path, target) => advance({ files: [{ path, content: target, mode: '120000' }], signer }),
    pushHubPath: (signer, path = '.hub/x') => advance({ files: [{ path, content: 'hostile\n' }], signer }),
    rewriteHistory: (signer, files = [{ path: 'rewritten.md', content: 'rewritten\n' }]) =>
      advance({ files, parents: [], signer, message: 'rewritten root' }),
  };

  const makeHub = async (n: number): Promise<TestHub> => {
    const hubRoot = nodePath.join(root, `hub${n}`);
    await privateMkdir(hubRoot);
    const keyDir = nodePath.join(hubRoot, 'key');
    await privateMkdir(keyDir);
    const keyFile = nodePath.join(keyDir, 'key');
    await generateKeyPair(keyFile, sshKeygenBin);
    const pub = await publicKeyOf(keyFile, sshKeygenBin);
    const dir = nodePath.join(hubRoot, 'repo');
    await privateMkdir(dir);
    const syncDir = nodePath.join(hubRoot, 'sync');
    const gitx = await Gitx.open({ syncDir, keyFile, testLocalRemotes: [remotePath] });
    await gitx.mustRun(['init', '-q', '-b', 'main'], { cwd: dir });
    const store = new ObjectStore(gitx, dir);
    const trees = new TreeBuilder(gitx, dir, nodePath.join(syncDir, 'tmp'));
    const signing: GitSigningInput = { sshKeygenBin, keyFile, allowedSignersFile: nodePath.join(keyDir, 'allowed_signers') };
    const label = `hub${n}`;
    const identity: CommitIdentity = { name: label, email: `${pub.deviceId}@devices.agent-ledger.invalid` };
    const main = (): Promise<string | null> => store.revParse(REF_MAIN);
    const hub: TestHub = {
      n,
      label,
      deviceId: pub.deviceId,
      dir,
      keyFile,
      pub,
      signing,
      identity,
      gitx,
      store,
      trees,
      syncDir,
      main,
      async commit(changes, o = {}) {
        const tip = await main();
        const tree = await trees.buildTree(tip, changes);
        const sha = await trees.commitTree({
          tree,
          parents: tip === null ? [] : [tip],
          message: o.message ?? 'testkit honest commit',
          identity,
          ...(o.signed === false ? {} : { signing }),
          ...(o.date !== undefined ? { date: o.date } : {}),
        });
        if (tip === null) await gitx.mustRun(['update-ref', '--no-deref', REF_MAIN, sha, '0'.repeat(sha.length)], { cwd: dir });
        else await trees.updateRef(REF_MAIN, sha, tip);
        return sha;
      },
      async pushMain(r) {
        const tip = await main();
        if (tip === null) return { ok: false, stderr: 'nothing to push' };
        const res = await gitx.push(dir, r.path, tip);
        return { ok: res.ok, stderr: res.stderr };
      },
      async fetchIncoming(r) {
        const res = await gitx.fetch(dir, r.path);
        gitx.ensureOk(res, 'fetch');
        return store.revParse('refs/ledger-sync/incoming');
      },
    };
    return hub;
  };

  return {
    root,
    remote,
    makeHub,
    async cleanup() {
      await rm(root, { recursive: true, force: true }).catch(() => undefined);
    },
  };
}

/** Raw plumbing commit inside a hub's own repository (hostile local objects: a symlink, `.hub/x`, an unsigned commit). */
export function hubRawCommit(hub: TestHub, spec: RawCommitSpec): Promise<string> {
  return rawCommit({ gitx: hub.gitx, cwd: hub.dir, tmpRoot: nodePath.join(hub.syncDir, 'tmp'), currentMain: hub.main }, spec);
}

/* ---------------- B3c additions: ledger-like hubs, fake host, scripted remote ---------------- */

/** A kit hub plus what the apply/cycle layers need: a `.hub/sync` state store, a worktree that follows `main`,
 *  and the deps bundle. Test-only. */
export interface LedgerHub {
  hub: TestHub;
  /** Ledger root = the hub's working repository. */
  dir: string;
  state: StateStore;
  /** An honest signed local commit (plumbing) AND the worktree/index brought to it (what a real commit leaves). */
  commitLocal(changes: readonly TreeChange[], o?: { message?: string; date?: Date }): Promise<string>;
  /** Point `main`, index and worktree at `sha` (a commit already in the object store); `main` may be unborn. */
  adopt(sha: string): Promise<void>;
  /** Dirty/untracked paths (porcelain), empty = clean. */
  dirty(): Promise<string[]>;
  /** `refs/ledger-sync/accepted` + its state mirror (what `sync init` / `join` do in B4). */
  seedAccepted(sha: string): Promise<void>;
  applyDeps(over?: Partial<ApplyDeps>): ApplyDeps;
}

export const PINNED_GITIGNORE = '.hub/\n*.tmp\n';
export const PINNED_GITATTRIBUTES = '* text eol=lf\n';

export async function makeLedgerHub(kit: Kit, n: number): Promise<LedgerHub> {
  const hub = await kit.makeHub(n);
  const state = await StateStore.open(hub.dir);
  const sshKeygenBin = hub.signing.sshKeygenBin;
  void sshKeygenBin;
  const lh: LedgerHub = {
    hub,
    dir: hub.dir,
    state,
    async commitLocal(changes, o = {}) {
      const sha = await hub.commit(changes, o);
      await hub.gitx.mustRun(['read-tree', '--reset', '-u', sha], { cwd: hub.dir });
      return sha;
    },
    async adopt(sha) {
      const old = await hub.main();
      if (old === null) await hub.gitx.mustRun(['update-ref', '--no-deref', REF_MAIN, sha, '0'.repeat(sha.length)], { cwd: hub.dir });
      else await hub.gitx.mustRun(['update-ref', '--no-deref', REF_MAIN, sha, old], { cwd: hub.dir });
      await hub.gitx.mustRun(['read-tree', '--reset', '-u', sha], { cwd: hub.dir });
    },
    async dirty() {
      await hub.gitx.run(['update-index', '-q', '--refresh'], { cwd: hub.dir });
      const r = await hub.gitx.mustRun(['status', '--porcelain=v1', '-z', '--untracked-files=all', '--no-renames'], { cwd: hub.dir });
      return r.stdout.toString('utf8').split('\0').filter((x) => x.length > 3).map((x) => x.slice(3));
    },
    async seedAccepted(sha) {
      await hub.trees.createRef(REF_ACCEPTED, sha);
      await state.update((s) => {
        s.accepted = sha;
      });
    },
    applyDeps(over = {}) {
      return {
        ledgerDir: hub.dir,
        gitx: hub.gitx,
        store: hub.store,
        trees: hub.trees,
        state,
        identity: hub.identity,
        signing: hub.signing,
        localDevice: hub.deviceId,
        maxFormat: 2,
        ...over,
      };
    },
  };
  return lh;
}

export interface FakeHost extends ApplyHost {
  reindexed: string[][];
  delivered: DeliverNotes[];
  proposed: ProposedItem[][];
  logs: string[];
  flushes: number;
  localNotes: { type: string; rule: string; device: string | null }[][];
  /** `auto` = `clean` when the worktree is clean, else `held`. */
  commitOutcome: 'auto' | CommitOutcome;
  /** Runs inside `runExclusive` before `fn` (a "local write racing the apply"). */
  beforeFn: (() => Promise<void>) | null;
  /** Runs BEFORE the host takes R (a local write between validate and apply). */
  beforeExclusive: (() => Promise<void>) | null;
  exclusive: boolean;
  inQueue: boolean;
  /** Lock-order violations seen (queueRun outside runExclusive, nested runExclusive). */
  violations: string[];
  flushLocal(): Promise<void>;
  noteLocal(notes: readonly { type: string; rule: string; device: string | null }[]): Promise<void>;
  createProposed(items: readonly ProposedItem[]): Promise<void>;
}

export function fakeHost(lh: LedgerHub): FakeHost {
  let rChain: Promise<unknown> = Promise.resolve();
  let qChain: Promise<unknown> = Promise.resolve();
  const host: FakeHost = {
    reindexed: [],
    delivered: [],
    proposed: [],
    logs: [],
    flushes: 0,
    localNotes: [],
    commitOutcome: 'auto',
    beforeFn: null,
    beforeExclusive: null,
    exclusive: false,
    inQueue: false,
    violations: [],
    async runExclusive(fn) {
      if (host.exclusive) {
        host.violations.push('nested runExclusive');
        throw new Error('nested runExclusive');
      }
      if (host.beforeExclusive !== null) await host.beforeExclusive();
      const job = rChain.then(async () => {
        host.exclusive = true;
        try {
          if (host.beforeFn !== null) await host.beforeFn();
          return await fn({
            commitNow: async (): Promise<CommitOutcome> => {
              if (host.commitOutcome !== 'auto') return host.commitOutcome;
              return (await lh.dirty()).length === 0 ? 'clean' : 'held';
            },
          });
        } finally {
          host.exclusive = false;
        }
      });
      rChain = job.catch(() => undefined);
      return job;
    },
    async queueRun(fn) {
      if (!host.exclusive) host.violations.push('queueRun outside runExclusive');
      const job = qChain.then(async () => {
        host.inQueue = true;
        try {
          return await fn();
        } finally {
          host.inQueue = false;
        }
      });
      qChain = job.catch(() => undefined);
      return job;
    },
    async reindexPaths(paths) {
      if (!host.inQueue) host.violations.push('reindexPaths without the queue');
      host.reindexed.push([...paths]);
    },
    async deliver(n) {
      host.delivered.push(n);
    },
    async createProposed(items) {
      if (host.inQueue) host.violations.push('createProposed inside the queue');
      host.proposed.push([...items]);
    },
    async flushLocal() {
      host.flushes += 1;
    },
    async noteLocal(notes) {
      host.localNotes.push([...notes]);
    },
    log(line) {
      host.logs.push(line);
    },
  };
  return host;
}

export interface ScriptedFailure {
  stderr?: string;
  code?: number;
  timedOut?: boolean;
}

export interface FlakyRemote {
  /** Use this as the hub's `gitx` in cycle deps. */
  gitx: Gitx;
  /** argv of every `exec` (network and local), for the "no force flag" assertions. */
  argv: string[][];
  fetchCalls: number;
  pushCalls: number;
  /** Make the next `times` fetches/pushes fail with this result (never reaches the real remote). */
  failNext(kind: 'fetch' | 'push', f: ScriptedFailure, times?: number): void;
  /** Hooks around the real network calls (a remote that moves between fetch and apply, etc.). */
  afterFetch: (() => Promise<void>) | null;
  beforePush: (() => Promise<void>) | null;
  /** After the real push succeeded, report this failure instead (unknown outcome). */
  lieAboutPush: ScriptedFailure | null;
}

/** Wraps a hub's `Gitx` so network calls can fail on demand. Everything else is the real hardened runner. */
export function flakyRemote(real: Gitx): FlakyRemote {
  const script: { fetch: ScriptedFailure[]; push: ScriptedFailure[] } = { fetch: [], push: [] };
  const f: FlakyRemote = {
    gitx: real,
    argv: [],
    fetchCalls: 0,
    pushCalls: 0,
    failNext(kind, fail, times = 1) {
      for (let i = 0; i < times; i += 1) script[kind].push(fail);
    },
    afterFetch: null,
    beforePush: null,
    lieAboutPush: null,
  };
  const result = (x: ScriptedFailure): GitxResult => ({
    ok: false,
    code: x.code ?? 1,
    stdout: Buffer.alloc(0),
    stderr: x.stderr ?? '',
    timedOut: x.timedOut === true,
    capped: false,
  });
  const proxy: Gitx = new Proxy(real, {
    get(target, prop) {
      const v = Reflect.get(target, prop, target) as unknown;
      if (typeof v !== 'function') return v;
      if (prop === 'exec') {
        return (args: readonly string[], ...rest: unknown[]) => {
          f.argv.push([...args]);
          return (v as (...a: unknown[]) => unknown).call(proxy, args, ...rest);
        };
      }
      if (prop === 'fetch') {
        return async (...a: unknown[]) => {
          f.fetchCalls += 1;
          const s = script.fetch.shift();
          if (s !== undefined) return result(s);
          const r = (await (v as (...x: unknown[]) => Promise<GitxResult>).apply(proxy, a));
          if (f.afterFetch !== null) await f.afterFetch();
          return r;
        };
      }
      if (prop === 'push') {
        return async (...a: unknown[]) => {
          f.pushCalls += 1;
          const s = script.push.shift();
          if (s !== undefined) return result(s);
          if (f.beforePush !== null) await f.beforePush();
          const r = (await (v as (...x: unknown[]) => Promise<GitxResult>).apply(proxy, a));
          if (f.lieAboutPush !== null && r.ok) return result(f.lieAboutPush);
          return r;
        };
      }
      return (v as (...x: unknown[]) => unknown).bind(proxy);
    },
  });
  f.gitx = proxy;
  return f;
}

export const FLEET_T0 = '2026-11-01T00:00:00.000Z';

export interface Fleet {
  kit: Kit;
  hubs: LedgerHub[];
  /** The first commit every hub shares (signed by hub 1, on the remote). */
  base: string;
  devicesText: string;
}

/** `n` ledger hubs sharing one history: hub 1 is the root (slot ""), the others get slots B, C, ...; every key
 *  is registered in `devices.yml` and approved in every hub's `.hub/allowed_signers`; `accepted` = base. */
export async function makeFleet(kit: Kit, n: number, extra: readonly RawFile[] = []): Promise<Fleet> {
  const hubs: LedgerHub[] = [];
  for (let i = 1; i <= n; i += 1) hubs.push(await makeLedgerHub(kit, i));
  const root = hubs[0] as LedgerHub;
  const entries: DeviceEntry[] = hubs.map((h, i) => ({
    id: h.hub.deviceId,
    label: h.hub.label,
    slot: i === 0 ? '' : String.fromCharCode(65 + i),
    pubkey: h.hub.pub.line,
    added: FLEET_T0,
    added_by: i === 0 ? h.hub.deviceId : root.hub.deviceId,
    revoked: null,
    role: 'owner',
  }));
  const devicesText = renderDevicesYaml({ devices: entries });
  const files: TreeChange[] = [
    { path: '.gitignore', content: PINNED_GITIGNORE },
    { path: '.gitattributes', content: PINNED_GITATTRIBUTES },
    { path: 'ledger.format', content: '2\n' },
    { path: 'devices.yml', content: devicesText },
    { path: 'acme/CONTEXT.md', content: '# acme\n' },
    ...extra.map((f) => ({ path: f.path, content: f.content })),
  ];
  const base = await root.commitLocal(files, { message: 'base' });
  const pushed = await root.hub.pushMain(kit.remote);
  if (!pushed.ok) throw new Error('testkit: could not push the base commit');
  const signers = renderAllowedSigners(hubs.map((h) => ({ id: h.hub.deviceId, pubkey: h.hub.pub.line })));
  for (const h of hubs) {
    if (h !== root) {
      await h.hub.fetchIncoming(kit.remote);
      await h.adopt(base);
    }
    const hubDir = nodePath.join(h.dir, '.hub');
    await mkdir(hubDir, { recursive: true, mode: 0o700 });
    await chmod(hubDir, 0o700);
    await writeFile(nodePath.join(hubDir, 'allowed_signers'), signers, { mode: 0o600 });
    await chmod(nodePath.join(hubDir, 'allowed_signers'), 0o600);
    await h.seedAccepted(base);
  }
  return { kit, hubs, base, devicesText };
}

/** Cycle deps for a ledger hub against the kit's remote. `trusted` reads the hub's real `.hub/allowed_signers`. */
export function cycleDeps(lh: LedgerHub, kit: Kit, over: Partial<CycleDeps> = {}): CycleDeps {
  const host = (over.host as FakeHost | undefined) ?? fakeHost(lh);
  return {
    ...lh.applyDeps(),
    remote: kit.remote.path,
    host,
    verify: 'enforce',
    trusted: async () => new Set((await readSigners(deviceLayout(lh.dir))).map((s) => s.pubkey)),
    log: (line) => host.log(line),
    rnd: () => 0.5,
    testLocalRemotes: [kit.remote.path],
    ...over,
  };
}


/* ---------------- B4b additions: legacy ledgers and a trusted device for enrol tests ---------------- */

export interface LegacyLedger {
  dir: string;
  /** The random F1 device id the ledger minted before any key existed. */
  legacyId: string;
  /** Ids of the items created (`OPS-1`, ...). */
  itemIds: string[];
  cleanup(): Promise<void>;
}

const ITEM_BASE = { kind: 'BACKLOG', priority: 'P2', owner: 'agent', steps: [] as string[], blocked_by: [] as string[], aliases: [] as string[], proposed: false } as const;

/** A REAL legacy ledger: `Ledger.init()` on a fresh directory (git repo, pinned `.gitignore` / `.gitattributes`,
 *  `ledger.format` 2, a RANDOM legacy device id, no key, unsigned commits) with `n` items, all committed. The hub is
 *  closed again: this is what `sync init` meets on a stopped hub. `pre` = files written BEFORE the first boot
 *  (the ledger repairs `.gitignore` / `.gitattributes` around them). */
export async function makeLegacyLedger(n = 3, pre: Readonly<Record<string, string>> = {}): Promise<LegacyLedger> {
  const tmp = await tempConfig({ commitDebounceMs: 3_600_000 });
  const dir = await realpath(tmp.dir);
  for (const [name, text] of Object.entries(pre)) await writeFile(nodePath.join(dir, name), text, { mode: 0o600 });
  const ledger = new Ledger({ config: { ...tmp.config, ledgerDir: dir }, log: () => undefined });
  await ledger.init();
  const itemIds: string[] = [];
  for (let i = 1; i <= n; i += 1) {
    const it = await ledger.createItem({ ...ITEM_BASE, repo: 'ops', title: `legacy item ${String(i)}` });
    itemIds.push(it.fm.id);
  }
  await ledger.git.flush();
  const legacyId = ledger.device.device_id;
  await ledger.close();
  return { dir, legacyId, itemIds, cleanup: () => tmp.cleanup() };
}

/** The TRUSTED side of an add, done the way a hub does it, but offline: `device add` into the worktree, a signed commit
 *  holding ONLY `devices.yml` on top of the device's `main`, the worktree moved to it, pushed to the kit remote.
 *  `approve` also trusts the new key locally. Returns the new commit. */
export async function trustedAdd(
  trustedDir: string,
  remote: string,
  joiner: { pubkey: string; label: string; fingerprint: string },
  o: { approve?: boolean; push?: boolean } = {},
): Promise<string> {
  const gitx = await Gitx.open({ syncDir: nodePath.join(trustedDir, '.hub', 'sync'), testLocalRemotes: [remote] });
  const trees = new TreeBuilder(gitx, trustedDir, nodePath.join(trustedDir, '.hub', 'sync', 'tmp'));
  const store = new ObjectStore(gitx, trustedDir);
  const L = (await store.revParse(REF_MAIN)) as string;
  const l = deviceLayout(trustedDir);
  await addDevice(trustedDir, joiner.pubkey, joiner.label, joiner.fingerprint);
  const devices = await readFile(l.devicesYml, 'utf8');
  const pub = await publicKeyOf(l.keyFile, await resolveSshKeygen());
  const tree = await trees.buildTree(L, [{ path: 'devices.yml', content: devices }]);
  const label = (await readDeviceFile(l))?.label ?? 'trusted';
  const sha = await trees.commitTree({
    tree,
    parents: [L],
    message: 'testkit: device add',
    identity: { name: label, email: `${pub.deviceId}@devices.agent-ledger.invalid` },
    signing: { sshKeygenBin: await resolveSshKeygen(), keyFile: l.keyFile, allowedSignersFile: l.allowedSigners },
  });
  await trees.updateRef(REF_MAIN, sha, L);
  await gitx.mustRun(['read-tree', '--reset', '-u', sha], { cwd: trustedDir });
  if (o.approve !== false) await approveDevice(trustedDir, parseEd25519Pub(joiner.pubkey)?.deviceId as string, joiner.fingerprint);
  if (o.push !== false) {
    const res = await gitx.push(trustedDir, remote, sha);
    if (!res.ok) throw new Error('testkit: trusted add could not be pushed');
  }
  return sha;
}
