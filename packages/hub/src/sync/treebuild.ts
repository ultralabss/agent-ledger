/** Building merge output without touching the worktree (docs/f3b-plan.md §1.3 step 5, §1.4; S4, S9, S10;
 *  invariants 1, 3, 4, 13).
 *
 *  Threat model:
 *   - Actor: hostile merge inputs (paths, bytes) and a concurrent local writer racing a ref update.
 *   - Protected: the worktree and the real index (merge output is assembled in a TEMP index under a private
 *     directory), `refs/heads/main` (only ever moved by compare-and-swap), and "no code runs" (blobs are written
 *     with `--no-filters`, so no clean/smudge filter or `.gitattributes` driver can execute).
 *   - Failure modes: path tricks (`.git`, `..`, `.hub`, backslash), exec/symlink modes smuggled into a tree,
 *     a lost update (blind `update-ref`), a non-fast-forward move of `main`.
 *   - Stance: only regular files (mode 100644) can be written; paths are validated here too (defence in depth
 *     behind ingress); `updateRef` REQUIRES the expected old id, refuses the zero id, and refuses a new id that
 *     does not descend from it. `createRef` is the explicit "must not exist yet" variant.
 */

import type { GitSigningInput } from '@agent-ledger/shared';
import { gitSigningArgs, withPrivateTmp } from '@agent-ledger/shared';
import nodePath from 'node:path';
import { assertSha, isSha, isZeroSha, REF_ACCEPTED, REF_MAIN, type Gitx } from './gitx.ts';
import { ObjectStore } from './objects.ts';

export type TreeBuildErrorCode = 'PATH' | 'LIMIT' | 'CAS' | 'NOT_FF' | 'REF' | 'IDENTITY' | 'ARGS' | 'GIT';

export class TreeBuildError extends Error {
  readonly code: TreeBuildErrorCode;
  constructor(code: TreeBuildErrorCode, message: string) {
    super(message);
    this.name = 'TreeBuildError';
    this.code = code;
  }
}

export const MAX_BLOB_BYTES = 8 * 1024 * 1024;
export const MAX_CHANGES = 20_000;
const MAX_PATH_CHARS = 512;
const MAX_MESSAGE_BYTES = 4096;

export type TreeChange = { path: string; content: Uint8Array | string } | { path: string; remove: true };

/** Throws `PATH` for anything that is not a plain relative ledger path. */
export function assertTreePath(p: unknown): asserts p is string {
  const bad = (why: string): never => {
    throw new TreeBuildError('PATH', `tree path refused: ${why}`);
  };
  if (typeof p !== 'string' || p === '') return bad('empty');
  if (p.length > MAX_PATH_CHARS) return bad('too long');
  if (/[\0-\x1f\x7f\\]/.test(p)) return bad('control character or backslash');
  if (p.startsWith('/') || p.endsWith('/')) return bad('leading or trailing slash');
  const segs = p.split('/');
  for (const s of segs) {
    if (s === '' || s === '.' || s === '..') return bad('empty, dot or dot-dot segment');
    const l = s.toLowerCase();
    if (l === '.git' || /^git~\d+$/.test(l) || l.replace(/[. ]+$/, '') === '.git') return bad('.git segment');
  }
  if ((segs[0] as string).toLowerCase() === '.hub') return bad('.hub is never part of a ledger tree');
}

function assertIdentity(name: string, email: string): void {
  if (typeof name !== 'string' || !/^[^<>\0-\x1f\x7f]{1,100}$/.test(name) || name.trim() !== name) {
    throw new TreeBuildError('IDENTITY', 'committer name refused');
  }
  if (typeof email !== 'string' || !/^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{1,255}$/.test(email)) {
    throw new TreeBuildError('IDENTITY', 'committer email refused');
  }
}

export interface CommitIdentity {
  /** Device label: a hint only, authority is the verified key. */
  name: string;
  /** `<device_id>@devices.agent-ledger.invalid` */
  email: string;
}

export interface CommitTreeInput {
  tree: string;
  parents: readonly string[];
  message: string;
  identity: CommitIdentity;
  /** Sign with the device key (`gpg.format=ssh`, namespace `git`). Absent = unsigned (tests only). */
  signing?: GitSigningInput;
  /** Author/committer time; default now. */
  date?: Date;
}

export class TreeBuilder {
  private readonly gitx: Gitx;
  private readonly cwd: string;
  private readonly tmpRoot: string;
  private readonly store: ObjectStore;

  /** `tmpRoot` = private dir for temp indexes (`<ledger>/.hub/sync/tmp`); created/verified on use. */
  constructor(gitx: Gitx, cwd: string, tmpRoot: string) {
    this.gitx = gitx;
    this.cwd = cwd;
    this.tmpRoot = tmpRoot;
    this.store = new ObjectStore(gitx, cwd);
  }

  /**
   * Tree id = `base` (a commit or tree id, or null for empty) with `changes` applied, assembled in a temporary
   * index. Blobs are stored with `hash-object -w --no-filters`. The real index and the worktree are never read
   * or written.
   */
  async buildTree(base: string | null, changes: readonly TreeChange[]): Promise<string> {
    if (base !== null) assertSha(base, 'base');
    if (changes.length > MAX_CHANGES) throw new TreeBuildError('LIMIT', `more than ${MAX_CHANGES} changes`);
    const seen = new Set<string>();
    for (const c of changes) {
      assertTreePath(c.path);
      if (seen.has(c.path)) throw new TreeBuildError('PATH', 'duplicate path in one change set');
      seen.add(c.path);
    }
    return withPrivateTmp(this.tmpRoot, async (dir) => {
      const extraEnv = { GIT_INDEX_FILE: nodePath.join(dir, 'index') } as const;
      const opts = { cwd: this.cwd, extraEnv };
      if (base !== null) await this.gitx.mustRun(['read-tree', base], opts);
      let hex = base !== null ? base.length : 0;
      const lines: Buffer[] = [];
      const removes: string[] = [];
      for (const c of changes) {
        if ('remove' in c) {
          removes.push(c.path);
          continue;
        }
        const bytes = typeof c.content === 'string' ? Buffer.from(c.content, 'utf8') : Buffer.from(c.content);
        if (bytes.length > MAX_BLOB_BYTES) throw new TreeBuildError('LIMIT', 'blob too large');
        const h = await this.gitx.mustRun(['hash-object', '-w', '--no-filters', '-t', 'blob', '--stdin'], { cwd: this.cwd, input: bytes });
        const sha = h.stdout.toString('utf8').trim();
        if (!isSha(sha)) throw new TreeBuildError('GIT', 'hash-object returned a non-object-id');
        hex = sha.length;
        lines.push(Buffer.from(`100644 ${sha}\t${c.path}\0`, 'utf8'));
      }
      if (hex === 0) hex = 40;
      for (const p of removes) lines.push(Buffer.from(`0 ${'0'.repeat(hex)}\t${p}\0`, 'utf8'));
      if (lines.length > 0) {
        await this.gitx.mustRun(['update-index', '-z', '--index-info'], { ...opts, input: Buffer.concat(lines) });
      }
      const w = await this.gitx.mustRun(['write-tree'], opts);
      const tree = w.stdout.toString('utf8').trim();
      if (!isSha(tree)) throw new TreeBuildError('GIT', 'write-tree returned a non-object-id');
      return tree;
    });
  }

  /** `commit-tree` with an explicit identity (`-c user.name/email`) and optional ssh signing. Returns the commit id. */
  async commitTree(i: CommitTreeInput): Promise<string> {
    assertSha(i.tree, 'tree');
    const parents = [...i.parents];
    for (const p of parents) assertSha(p, 'parent');
    if (new Set(parents).size !== parents.length) throw new TreeBuildError('ARGS', 'duplicate parent');
    assertIdentity(i.identity.name, i.identity.email);
    if (typeof i.message !== 'string' || i.message.includes('\0') || Buffer.byteLength(i.message, 'utf8') > MAX_MESSAGE_BYTES) {
      throw new TreeBuildError('ARGS', 'commit message refused');
    }
    const message = i.message.endsWith('\n') ? i.message : `${i.message}\n`;
    const extraConfig = [`user.name=${i.identity.name}`, `user.email=${i.identity.email}`];
    const args = ['commit-tree', i.tree];
    for (const p of parents) args.push('-p', p);
    if (i.signing !== undefined) {
      const sargs = gitSigningArgs(i.signing); // pairs: '-c', 'k=v'
      for (let k = 1; k < sargs.length; k += 2) extraConfig.push(sargs[k] as string);
      args.push('-S');
    }
    args.push('-F', '-');
    const extraEnv: { GIT_AUTHOR_DATE?: string; GIT_COMMITTER_DATE?: string } = {};
    if (i.date !== undefined) {
      const unix = Math.floor(i.date.getTime() / 1000);
      if (!Number.isSafeInteger(unix) || unix < 0) throw new TreeBuildError('ARGS', 'commit date refused');
      extraEnv.GIT_AUTHOR_DATE = `${unix} +0000`;
      extraEnv.GIT_COMMITTER_DATE = `${unix} +0000`;
    }
    const r = await this.gitx.mustRun(args, { cwd: this.cwd, input: message, extraConfig, extraEnv });
    const sha = r.stdout.toString('utf8').trim();
    if (!isSha(sha)) throw new TreeBuildError('GIT', 'commit-tree returned a non-object-id');
    return sha;
  }

  /**
   * Move `main` or `accepted` forward: `update-ref <ref> <new> <old>` (compare-and-swap). `old` is REQUIRED
   * and may not be the zero id; `new` must descend from `old` (invariant 1). A lost race is `CAS`.
   */
  async updateRef(ref: string, newSha: string, oldSha: string): Promise<void> {
    if (ref !== REF_MAIN && ref !== REF_ACCEPTED) throw new TreeBuildError('REF', 'ref not allowed');
    assertSha(newSha, 'new');
    if (typeof oldSha !== 'string' || oldSha === '') throw new TreeBuildError('CAS', 'expected old id is required');
    assertSha(oldSha, 'old');
    if (isZeroSha(oldSha) || isZeroSha(newSha)) throw new TreeBuildError('CAS', 'zero object id refused');
    if (!(await this.store.isAncestor(oldSha, newSha))) throw new TreeBuildError('NOT_FF', 'new tip does not descend from the expected old tip');
    const r = await this.gitx.run(['update-ref', '--no-deref', ref, newSha, oldSha], { cwd: this.cwd });
    if (!r.ok) throw new TreeBuildError('CAS', 'ref changed concurrently or update failed');
  }

  /** Create `refs/ledger-sync/accepted` if (and only if) it does not exist yet (`update-ref <ref> <new> <zero>`). */
  async createRef(ref: string, newSha: string): Promise<void> {
    if (ref !== REF_ACCEPTED) throw new TreeBuildError('REF', 'ref not allowed');
    assertSha(newSha, 'new');
    const r = await this.gitx.run(['update-ref', '--no-deref', ref, newSha, '0'.repeat(newSha.length)], { cwd: this.cwd });
    if (!r.ok) throw new TreeBuildError('CAS', 'ref already exists or update failed');
  }
}
