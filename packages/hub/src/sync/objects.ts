/** Read-only object access by id for the sync cycle (docs/f3b-plan.md §1.4, S4, S6; invariant 4).
 *
 *  Threat model:
 *   - Actor: a hostile remote whose commits/trees/blobs we read before trusting them.
 *   - Protected: memory and time (a 10 GB blob, a million-entry tree), and TOCTOU: the validator and the
 *     merger must read the SAME objects, so every read here is addressed by a full object id, never by a
 *     moving ref or the worktree.
 *   - Failure modes: ref/option injection through a "sha", output flood, filters or textconv drivers
 *     running on read, non-UTF-8 paths slipping past a validator.
 *   - Stance: strict 40/64-hex ids only (callers resolve a ref ONCE with `revParse`); blobs are read with
 *     plain `cat-file --batch` (no `--filters`, no `--textconv`); sizes are checked with `--batch-check`
 *     BEFORE any content is read; every list has a cap and exceeding it is an error, not a truncation.
 */

import { assertSha, GitxError, isSha, type Gitx } from './gitx.ts';

export { assertSha, isSha };

export const MAX_COMMITS_DEFAULT = 2000;
export const MAX_TREE_ENTRIES_DEFAULT = 20_000;
export const MAX_DIFF_ENTRIES_DEFAULT = 5000;
export const MAX_OBJECT_BYTES_DEFAULT = 256 * 1024;
export const MAX_TOTAL_BYTES_DEFAULT = 5 * 1024 * 1024;
export const MAX_BATCH_COUNT_DEFAULT = 5000;
/** A raw commit larger than this is hostile (a signed ledger commit is ~1 KB). */
export const MAX_COMMIT_BYTES = 64 * 1024;

export type ObjectsErrorCode = 'LIMIT' | 'MISSING' | 'TYPE' | 'PARSE' | 'REF';

export class ObjectsError extends Error {
  readonly code: ObjectsErrorCode;
  constructor(code: ObjectsErrorCode, message: string) {
    super(message);
    this.name = 'ObjectsError';
    this.code = code;
  }
}

const REF_RE = /^refs\/[A-Za-z0-9._/-]{1,200}$/;

/** `refs/...` only: no `..`, no `//`, no leading dash possible (starts with `refs/`). */
function assertRefName(ref: string): void {
  if (typeof ref !== 'string' || !REF_RE.test(ref) || ref.includes('..') || ref.includes('//') || ref.endsWith('/') || ref.endsWith('.lock')) {
    throw new ObjectsError('REF', 'ref name refused');
  }
}

export interface TreeEntry {
  mode: string;
  type: string;
  sha: string;
  /** `null` for submodules (`-`). */
  size: number | null;
  path: string;
  /** Raw path bytes were not valid UTF-8 (the decoded `path` is lossy). The validator must reject. */
  badUtf8: boolean;
}

export interface RawDiffEntry {
  srcMode: string;
  dstMode: string;
  srcSha: string;
  dstSha: string;
  /** git status letter: A, M, D, T, ... */
  status: string;
  path: string;
  badUtf8: boolean;
}

export interface BatchObject {
  sha: string;
  type: string;
  size: number;
  content: Buffer;
}

export interface BatchLimits {
  maxCount?: number;
  maxObjectBytes?: number;
  maxTotalBytes?: number;
  /** Refuse any object of another type (`blob`, `commit`, `tree`). */
  expectType?: string;
}

function decodePath(raw: Buffer): { path: string; badUtf8: boolean } {
  const path = raw.toString('utf8');
  return { path, badUtf8: !Buffer.from(path, 'utf8').equals(raw) };
}

/** Well-known empty trees (sha1 / sha256 repositories). Git treats them as always present. */
const EMPTY_TREE: Readonly<Record<number, string>> = {
  40: '4b825dc642cb6eb9a060e54bf8d69288fbee4904',
  64: '6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321',
};

export class ObjectStore {
  private readonly gitx: Gitx;
  private readonly cwd: string;

  constructor(gitx: Gitx, cwd: string) {
    this.gitx = gitx;
    this.cwd = cwd;
  }

  /** Resolve a `refs/...` name to a commit id, ONCE. `null` when it does not exist. */
  async revParse(ref: string): Promise<string | null> {
    assertRefName(ref);
    const r = await this.gitx.run(['rev-parse', '--verify', '--quiet', '--end-of-options', `${ref}^{commit}`], { cwd: this.cwd });
    if (r.code === 1) return null;
    this.gitx.ensureOk(r, 'rev-parse');
    const out = r.stdout.toString('utf8').trim();
    if (!isSha(out)) throw new ObjectsError('PARSE', 'rev-parse returned a non-object-id');
    return out;
  }

  /** Does this commit id exist (as a commit) in the object store? */
  async hasCommit(sha: string): Promise<boolean> {
    assertSha(sha);
    const r = await this.gitx.run(['cat-file', '-e', `${sha}^{commit}`], { cwd: this.cwd });
    if (r.code === 0) return true;
    if (r.code === 1 || r.code === 128) return false;
    this.gitx.ensureOk(r, 'cat-file -e');
    return false;
  }

  /** `merge-base --is-ancestor <a> <b>`: exit 0 yes, 1 no, anything else is an error. A commit is its own ancestor. */
  async isAncestor(ancestor: string, descendant: string): Promise<boolean> {
    assertSha(ancestor, 'ancestor');
    assertSha(descendant, 'descendant');
    const r = await this.gitx.run(['merge-base', '--is-ancestor', ancestor, descendant], { cwd: this.cwd });
    if (r.code === 0) return true;
    if (r.code === 1) return false;
    this.gitx.ensureOk(r, 'merge-base --is-ancestor');
    return false;
  }

  /** Best common ancestor, or `null` for unrelated histories. Deterministic for a given graph. */
  async mergeBase(a: string, b: string): Promise<string | null> {
    assertSha(a);
    assertSha(b);
    const r = await this.gitx.run(['merge-base', a, b], { cwd: this.cwd });
    if (r.code === 1) return null;
    this.gitx.ensureOk(r, 'merge-base');
    const out = r.stdout.toString('utf8').trim();
    if (!isSha(out)) throw new ObjectsError('PARSE', 'merge-base returned a non-object-id');
    return out;
  }

  /**
   * Commits in `from..to` (or everything reachable from `to` when `from` is null), parents first (topological,
   * oldest first). More than `max` commits throws `LIMIT` (S6) instead of truncating.
   */
  async revList(from: string | null, to: string, max = MAX_COMMITS_DEFAULT): Promise<{ sha: string; parents: string[] }[]> {
    if (from !== null) assertSha(from, 'from');
    assertSha(to, 'to');
    const range = from === null ? [to] : [`${from}..${to}`];
    const r = await this.gitx.run(
      ['rev-list', '--topo-order', '--reverse', '--parents', `--max-count=${max + 1}`, ...range],
      { cwd: this.cwd, maxStdoutBytes: (max + 1) * (65 * 65 + 2) },
    );
    this.gitx.ensureOk(r, 'rev-list');
    const lines = r.stdout.toString('utf8').split('\n').filter((l) => l !== '');
    if (lines.length > max) throw new ObjectsError('LIMIT', `more than ${max} commits in range`);
    return lines.map((line) => {
      const ids = line.split(' ');
      if (ids.length === 0 || !ids.every(isSha)) throw new ObjectsError('PARSE', 'rev-list line malformed');
      return { sha: ids[0] as string, parents: ids.slice(1) };
    });
  }

  /** `ls-tree -r -l -z --full-tree <commit-or-tree>`: every blob/gitlink/symlink entry with its size. */
  async lsTree(treeish: string, max = MAX_TREE_ENTRIES_DEFAULT): Promise<TreeEntry[]> {
    assertSha(treeish);
    const r = await this.gitx.run(['ls-tree', '-r', '-l', '-z', '--full-tree', treeish], {
      cwd: this.cwd,
      maxStdoutBytes: (max + 1) * 1200,
    });
    this.gitx.ensureOk(r, 'ls-tree');
    const out: TreeEntry[] = [];
    let pos = 0;
    const buf = r.stdout;
    while (pos < buf.length) {
      const end = buf.indexOf(0, pos);
      if (end < 0) throw new ObjectsError('PARSE', 'ls-tree output not NUL-terminated');
      const rec = buf.subarray(pos, end);
      pos = end + 1;
      const tab = rec.indexOf(9);
      if (tab < 0) throw new ObjectsError('PARSE', 'ls-tree record has no tab');
      const meta = /^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40}|[0-9a-f]{64}) +(\d+|-)$/.exec(rec.subarray(0, tab).toString('latin1'));
      if (meta === null) throw new ObjectsError('PARSE', 'ls-tree record malformed');
      const { path, badUtf8 } = decodePath(rec.subarray(tab + 1));
      out.push({
        mode: meta[1] as string,
        type: meta[2] as string,
        sha: meta[3] as string,
        size: meta[4] === '-' ? null : Number(meta[4]),
        path,
        badUtf8,
      });
      if (out.length > max) throw new ObjectsError('LIMIT', `more than ${max} tree entries`);
    }
    return out;
  }

  /**
   * Raw tree diff `old..new` (`null` old = against the empty tree). `-r --raw -z --no-renames --no-abbrev`,
   * never rename detection, textconv or external diff. More than `max` entries throws `LIMIT`.
   */
  async diffTreeRaw(oldSha: string | null, newSha: string, max = MAX_DIFF_ENTRIES_DEFAULT): Promise<RawDiffEntry[]> {
    assertSha(newSha, 'new');
    if (oldSha !== null) assertSha(oldSha, 'old');
    const base = oldSha ?? EMPTY_TREE[newSha.length];
    if (base === undefined) throw new ObjectsError('PARSE', 'no empty tree for this object format');
    const r = await this.gitx.run(
      ['diff-tree', '-r', '--raw', '-z', '--no-renames', '--no-abbrev', '--no-textconv', '--no-ext-diff', base, newSha],
      { cwd: this.cwd, maxStdoutBytes: (max + 1) * 1200 },
    );
    this.gitx.ensureOk(r, 'diff-tree');
    const parts: Buffer[] = [];
    let pos = 0;
    const buf = r.stdout;
    while (pos < buf.length) {
      const end = buf.indexOf(0, pos);
      if (end < 0) throw new ObjectsError('PARSE', 'diff-tree output not NUL-terminated');
      parts.push(buf.subarray(pos, end));
      pos = end + 1;
    }
    const out: RawDiffEntry[] = [];
    for (let i = 0; i < parts.length; i += 2) {
      const meta = /^:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-9a-f]{40}|[0-9a-f]{64}) ([A-Z])$/.exec(
        (parts[i] as Buffer).toString('latin1'),
      );
      const rawPath = parts[i + 1];
      if (meta === null || rawPath === undefined) throw new ObjectsError('PARSE', 'diff-tree record malformed');
      const { path, badUtf8 } = decodePath(rawPath);
      out.push({
        srcMode: meta[1] as string,
        dstMode: meta[2] as string,
        srcSha: meta[3] as string,
        dstSha: meta[4] as string,
        status: meta[5] as string,
        path,
        badUtf8,
      });
      if (out.length > max) throw new ObjectsError('LIMIT', `more than ${max} changed paths`);
    }
    return out;
  }

  /**
   * `cat-file --batch` by object id with caps. Two phases: `--batch-check` learns every size, and ONLY if the
   * count, each object and the total are within the limits are the contents read. A missing object throws
   * `MISSING`; a type other than `expectType` throws `TYPE`. No filters, no textconv, no symlink following.
   */
  async catFileBatch(shas: readonly string[], limits: BatchLimits = {}): Promise<Map<string, BatchObject>> {
    const maxCount = limits.maxCount ?? MAX_BATCH_COUNT_DEFAULT;
    const maxObject = limits.maxObjectBytes ?? MAX_OBJECT_BYTES_DEFAULT;
    const maxTotal = limits.maxTotalBytes ?? MAX_TOTAL_BYTES_DEFAULT;
    const unique = [...new Set(shas)];
    for (const s of unique) assertSha(s);
    const result = new Map<string, BatchObject>();
    if (unique.length === 0) return result;
    if (unique.length > maxCount) throw new ObjectsError('LIMIT', `more than ${maxCount} objects requested`);
    const input = `${unique.join('\n')}\n`;
    const check = await this.gitx.run(['cat-file', '--batch-check'], {
      cwd: this.cwd,
      input,
      maxStdoutBytes: unique.length * 200,
    });
    this.gitx.ensureOk(check, 'cat-file --batch-check');
    const sizes: { sha: string; type: string; size: number }[] = [];
    let total = 0;
    for (const line of check.stdout.toString('utf8').split('\n')) {
      if (line === '') continue;
      if (/ missing$/.test(line)) throw new ObjectsError('MISSING', 'object not found');
      const m = /^([0-9a-f]{40}|[0-9a-f]{64}) (blob|tree|commit|tag) (\d+)$/.exec(line);
      if (m === null) throw new ObjectsError('PARSE', 'cat-file --batch-check line malformed');
      const size = Number(m[3]);
      if (limits.expectType !== undefined && m[2] !== limits.expectType) throw new ObjectsError('TYPE', 'object has an unexpected type');
      if (size > maxObject) throw new ObjectsError('LIMIT', `object larger than ${maxObject} bytes`);
      total += size;
      if (total > maxTotal) throw new ObjectsError('LIMIT', `objects larger than ${maxTotal} bytes in total`);
      sizes.push({ sha: m[1] as string, type: m[2] as string, size });
    }
    if (sizes.length !== unique.length) throw new ObjectsError('PARSE', 'cat-file --batch-check answered a different count');
    const read = await this.gitx.run(['cat-file', '--batch'], {
      cwd: this.cwd,
      input,
      maxStdoutBytes: total + sizes.length * 200,
    });
    this.gitx.ensureOk(read, 'cat-file --batch');
    const buf = read.stdout;
    let pos = 0;
    for (const expect of sizes) {
      const nl = buf.indexOf(10, pos);
      if (nl < 0) throw new ObjectsError('PARSE', 'cat-file --batch truncated');
      const head = buf.subarray(pos, nl).toString('latin1');
      const m = /^([0-9a-f]{40}|[0-9a-f]{64}) (blob|tree|commit|tag) (\d+)$/.exec(head);
      if (m === null || m[1] !== expect.sha || Number(m[3]) !== expect.size) throw new GitxError('EXIT', 'cat-file --batch disagreed with --batch-check');
      const start = nl + 1;
      const end = start + expect.size;
      if (end >= buf.length + 1 || buf[end] !== 10) throw new ObjectsError('PARSE', 'cat-file --batch content truncated');
      result.set(expect.sha, { sha: expect.sha, type: expect.type, size: expect.size, content: Buffer.from(buf.subarray(start, end)) });
      pos = end + 1;
    }
    if (pos !== buf.length) throw new ObjectsError('PARSE', 'cat-file --batch left trailing output');
    return result;
  }

  /** One object (type-checked, size-capped). */
  async readObject(sha: string, expectType: string, maxBytes = MAX_OBJECT_BYTES_DEFAULT): Promise<Buffer> {
    assertSha(sha);
    const m = await this.catFileBatch([sha], { expectType, maxObjectBytes: maxBytes, maxTotalBytes: maxBytes, maxCount: 1 });
    const o = m.get(sha);
    if (o === undefined) throw new ObjectsError('MISSING', 'object not found');
    return o.content;
  }

  /** Raw bytes of a commit object (capped at 64 KiB). Input for `sigverify.ts`. */
  readCommitRaw(sha: string): Promise<Buffer> {
    return this.readObject(sha, 'commit', MAX_COMMIT_BYTES);
  }
}
