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

import { chmod, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import {
  generateKeyPair,
  gitSigningArgs,
  publicKeyOf,
  resolveSshKeygen,
  withPrivateTmp,
  type Ed25519Pub,
  type GitSigningInput,
} from '@agent-ledger/shared';
import { Gitx, REF_MAIN, isSha } from './gitx.ts';
import { ObjectStore } from './objects.ts';
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
