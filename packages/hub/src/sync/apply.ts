/** The sync APPLY critical section and its crash replay (F3b B3c, docs/f3b-b3-plan.md §1.3, §2, §3; T-B3-2/3/4).
 *
 *  Threat model:
 *   - Actor: a crash / `kill -9` / power loss in the middle of moving the worktree, a local editor racing the
 *     apply, and a hostile merge input that survived validation (a merger bug).
 *   - Protected: `main`, the index and the worktree move L -> M together or not at all; a half-applied state is
 *     never committed as a "revert" by the next `git add -A`; no local edit is overwritten silently; the
 *     remote parent never gets dropped from a merge (a `commit()` between read-tree and update-ref would do it).
 *   - Failure modes: crash at any step (marker names L, M, F; git state is the truth), stale `index.lock`, a
 *     foreign edit during replay, a revoked key left in `allowed_signers` after a crash between update-ref and
 *     prune, a notes delivery that runs twice.
 *   - Stance: step order is normative (§1.3): validated M is built OUTSIDE the section's mutation window; the
 *     marker is durable BEFORE `read-tree`; `read-tree` happens BEFORE `update-ref`; `update-ref` is a CAS on L;
 *     `pruneRevokedSigners` runs under the device lock after EVERY move of main (and again at replay).
 *     Locks: the caller's `runExclusive` (R) is taken BEFORE `queueRun` (Q); the device lock (D) is innermost
 *     and bounded. Nothing here calls `flush()/close()` (deadlock). Local-side errors are transient, remote-side
 *     ones quarantine (T-B3-6). No stderr, URL or blob content is logged: tokens only.
 */

import { randomBytes } from 'node:crypto';
import { lstat, readFile, readdir, rm } from 'node:fs/promises';
import nodePath from 'node:path';
import { DevicesError, pruneRevokedSigners, safeOutput, withDeviceLock, type GitSigningInput } from '@agent-ledger/shared';
import type { CommitOutcome, ExclusiveHandle } from '../git.ts';
import { GitxError, REF_MAIN, isSha, type Gitx } from './gitx.ts';
import { validateIncoming, type IncomingChange } from './ingress.ts';
import { mergeTrees, type ProposedItem } from './merge/tree.ts';
import { ObjectsError, type ObjectStore, type TreeEntry } from './objects.ts';
import { mapNotes, type InboxOut, type NotePlan } from './notes.ts';
import { splitCommit } from './sigverify.ts';
import { StateError, type Inflight, type StateStore } from './state.ts';
import { assertTreePath, TreeBuildError, type CommitIdentity, type TreeBuilder, type TreeChange } from './treebuild.ts';

/* ---------------- types ---------------- */

export type CrashPoint = 'marker' | 'read-tree' | 'update-ref' | 'reindex' | 'notes' | 'marker-delete';

/** Thrown by the test seam `crashAt`; never produced in production. */
export class CrashError extends Error {
  readonly point: CrashPoint;
  constructor(point: CrashPoint) {
    super(`test crash at ${point}`);
    this.name = 'CrashError';
    this.point = point;
  }
}

export interface DeliverNotes {
  inbox: InboxOut[];
  releaseLeases: { item: string; session: string }[];
}

/** The ONLY coupling to the Ledger (tests fake it). */
export interface ApplyHost {
  /** R: `LedgerGit.runExclusive`. Taken BEFORE `queueRun`. */
  runExclusive<T>(fn: (x: ExclusiveHandle) => Promise<T>): Promise<T>;
  /** Q: `Ledger.queue.run`. */
  queueRun<T>(fn: () => Promise<T>): Promise<T>;
  /** Caller holds Q (`Ledger.reindexPaths`). */
  reindexPaths(paths: readonly string[]): Promise<void>;
  /** Inbox rows + lease releases for local sessions. At-least-once (idempotent per row). */
  deliver(n: DeliverNotes): Promise<void>;
  /** Hub-proposed items (CONTEXT.md conflicts); only used by the notes replay, never inside Q. */
  createProposed?(items: readonly ProposedItem[]): Promise<void>;
  log(line: string): void;
}

export interface ApplyTiming {
  /** Budget for everything before the marker (ms, default 15000). */
  totalMs?: number;
  /** Device-lock wait (ms, default 2000). */
  lockWaitMs?: number;
  /** How long replay waits for a young `index.lock` (ms, default 5000). */
  indexLockWaitMs?: number;
  /** Age after which replay removes `index.lock` (ms, default 30000). */
  indexLockStaleMs?: number;
}

export interface ApplyDeps {
  /** Ledger ROOT (the git worktree). */
  ledgerDir: string;
  gitx: Gitx;
  store: ObjectStore;
  trees: TreeBuilder;
  state: StateStore;
  /** Committer identity of the merge commit (`<device_id>@devices.agent-ledger.invalid`). */
  identity: CommitIdentity;
  /** Signing is MANDATORY: no unsigned fallback (T-B3-10). */
  signing: GitSigningInput;
  localDevice: string;
  maxFormat: number;
  now?: () => Date;
  timing?: ApplyTiming;
  /** Test seam: called AFTER the named step; throw to simulate a crash. */
  crashAt?: (point: CrashPoint) => void | Promise<void>;
}

export interface ApplyPlan {
  /** Accepted tip before this cycle (informational: stored in the marker). */
  A: string;
  /** Fetched, fully validated remote tip. */
  F: string;
  /** An item delete was seen: take the merge path even when L is an ancestor of F. */
  forcedMerge: boolean;
  /** Device the tip is attributed to (merge tie-break), or `null`. */
  tipDevice: string | null;
}

export type ApplyOutcome =
  | { kind: 'applied'; mode: 'ff' | 'merge'; L: string; M: string; changed: string[]; proposed: ProposedItem[] }
  | { kind: 'noop'; L: string }
  | { kind: 'quarantine'; rule: string }
  | { kind: 'transient'; why: 'local-hold' | 'dirty' | 'device-lock' | 'local-git' | 'budget' }
  | { kind: 'halt'; reason: 'inflight' | 'config'; detail: string };

const MAX_PATHS = 20_000;
const LOCAL_CAPS = { maxCount: 60_000, maxObjectBytes: 8 * 1024 * 1024, maxTotalBytes: 64 * 1024 * 1024, expectType: 'blob' } as const;
const FALLBACK_REMOTE_DEVICE = 'd_7777777777';
const UTF8 = new TextDecoder('utf-8', { fatal: true });

const isoOf = (d: Date): string => d.toISOString();
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/* ---------------- helpers ---------------- */

async function crash(deps: { crashAt?: ApplyDeps['crashAt'] }, p: CrashPoint): Promise<void> {
  if (deps.crashAt !== undefined) await deps.crashAt(p);
}

async function treeOf(deps: Pick<ApplyDeps, 'gitx' | 'ledgerDir'>, commit: string): Promise<string> {
  const r = await deps.gitx.mustRun(['rev-parse', '--verify', '--quiet', '--end-of-options', `${commit}^{tree}`], { cwd: deps.ledgerDir });
  const out = r.stdout.toString('utf8').trim();
  if (!isSha(out)) throw new ObjectsError('PARSE', 'rev-parse returned a non-object-id');
  return out;
}

/** Paths git reports as modified, staged, deleted or untracked (the worktree and index versus HEAD). */
async function dirtyPaths(deps: Pick<ApplyDeps, 'gitx' | 'ledgerDir'>): Promise<string[]> {
  // a stat-dirty-only index would make `read-tree -m` refuse; refresh first (best effort, exit 1 = real changes)
  await deps.gitx.run(['update-index', '-q', '--refresh'], { cwd: deps.ledgerDir });
  const r = await deps.gitx.mustRun(['status', '--porcelain=v1', '-z', '--untracked-files=all', '--no-renames'], { cwd: deps.ledgerDir });
  const out: string[] = [];
  for (const rec of r.stdout.toString('utf8').split('\0')) {
    if (rec.length < 4) continue;
    out.push(rec.slice(3));
  }
  return out;
}

async function indexIsCommit(deps: Pick<ApplyDeps, 'gitx' | 'ledgerDir'>, commit: string): Promise<boolean> {
  const r = await deps.gitx.run(['diff-index', '--cached', '--quiet', commit, '--'], { cwd: deps.ledgerDir });
  return r.code === 0;
}

function treeMap(entries: readonly TreeEntry[], only: ReadonlySet<string> | null): Map<string, string> {
  const m = new Map<string, string>();
  for (const e of entries) if (only === null || only.has(e.path)) m.set(e.path, e.sha);
  return m;
}

/** Hash of the worktree file as git would store it with NO filters; `null` = absent; `'?'` = not a regular file. */
async function worktreeBlob(deps: Pick<ApplyDeps, 'gitx' | 'ledgerDir'>, rel: string): Promise<string | null> {
  assertTreePath(rel);
  const abs = nodePath.join(deps.ledgerDir, ...rel.split('/'));
  const st = await lstat(abs).catch((err: NodeJS.ErrnoException) => (err.code === 'ENOENT' || err.code === 'ENOTDIR' ? null : undefined));
  if (st === null) return null;
  if (st === undefined || !st.isFile() || st.isSymbolicLink() || st.size > LOCAL_CAPS.maxObjectBytes) return '?';
  const bytes = await readFile(abs);
  const r = await deps.gitx.mustRun(['hash-object', '--no-filters', '-t', 'blob', '--stdin'], { cwd: deps.ledgerDir, input: bytes });
  const sha = r.stdout.toString('utf8').trim();
  return isSha(sha) ? sha : '?';
}

const sanitizeBody = (s: unknown, max: number): string => (typeof s === 'string' ? s.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, ' ').slice(0, max) : '');
const sanitizeLine = (s: unknown, max: number): string => (typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max) : '');

function transientOf(err: unknown): ApplyOutcome {
  if (err instanceof DevicesError && err.code === 'LOCKED') return { kind: 'transient', why: 'device-lock' };
  return { kind: 'transient', why: 'local-git' };
}

/* ---------------- merge construction (outside the mutation window) ---------------- */

interface Built {
  M: string;
  mode: 'ff' | 'merge';
  treeM: string;
  notes: NotePlan;
  proposed: ProposedItem[];
}

type BuildResult = { ok: true; built: Built } | { ok: false; out: ApplyOutcome };

async function decodeBlobs(
  store: ObjectStore,
  entries: ReadonlyMap<string, string>,
  side: 'local' | 'remote',
): Promise<Map<string, string> | ApplyOutcome> {
  const shas = [...new Set(entries.values())];
  let got;
  try {
    got = await store.catFileBatch(shas, LOCAL_CAPS);
  } catch (err) {
    if (side === 'remote' && err instanceof ObjectsError) return { kind: 'quarantine', rule: err.code === 'LIMIT' ? 'oversize' : `objects:${err.code.toLowerCase()}` };
    return { kind: 'transient', why: 'local-git' };
  }
  const out = new Map<string, string>();
  for (const [path, sha] of entries) {
    const obj = got.get(sha);
    if (obj === undefined) return { kind: 'transient', why: 'local-git' };
    try {
      out.set(path, UTF8.decode(obj.content));
    } catch {
      return side === 'remote' ? { kind: 'quarantine', rule: 'encoding' } : { kind: 'transient', why: 'local-git' };
    }
  }
  return out;
}

const isOutcome = (v: unknown): v is ApplyOutcome => typeof v === 'object' && v !== null && 'kind' in v;

async function buildMerge(deps: ApplyDeps, plan: ApplyPlan, L: string, lIsAncestor: boolean, over: () => boolean): Promise<BuildResult> {
  const { store, trees } = deps;
  const fail = (out: ApplyOutcome): BuildResult => ({ ok: false, out });
  const base = await store.mergeBase(L, plan.F);
  if (base === null) return fail({ kind: 'quarantine', rule: 'unrelated' });
  let dL;
  let dF;
  try {
    dL = await store.diffTreeRaw(base, L, MAX_PATHS);
  } catch (err) {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return fail({ kind: 'transient', why: 'budget' });
    throw err;
  }
  try {
    dF = await store.diffTreeRaw(base, plan.F, MAX_PATHS);
  } catch (err) {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return fail({ kind: 'quarantine', rule: 'oversize' });
    throw err;
  }
  const subset = new Set<string>([...dL.map((d) => d.path), ...dF.map((d) => d.path), 'devices.yml', 'repos.yml']);
  const eL = await store.lsTree(L, MAX_PATHS).catch((err: unknown) => {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return null;
    throw err;
  });
  const eB = await store.lsTree(base, MAX_PATHS).catch((err: unknown) => {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return null;
    throw err;
  });
  if (eL === null || eB === null) return fail({ kind: 'transient', why: 'budget' });
  const eF = await store.lsTree(plan.F, MAX_PATHS).catch((err: unknown) => {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return null;
    throw err;
  });
  if (eF === null) return fail({ kind: 'quarantine', rule: 'oversize' });
  if (over()) return fail({ kind: 'transient', why: 'budget' });

  const oursSha = treeMap(eL, subset);
  const baseSha = treeMap(eB, subset);
  const theirsSha = treeMap(eF, subset);
  const ours = await decodeBlobs(store, oursSha, 'local');
  if (isOutcome(ours)) return fail(ours);
  const baseBlobs = await decodeBlobs(store, baseSha, 'local');
  if (isOutcome(baseBlobs)) return fail(baseBlobs);
  const theirs = await decodeBlobs(store, theirsSha, 'remote');
  if (isOutcome(theirs)) return fail(theirs);

  const nowIso = isoOf((deps.now ?? (() => new Date()))());
  const res = mergeTrees({
    base: baseBlobs,
    ours,
    theirs,
    ctx: { ourDevice: deps.localDevice, theirDevice: plan.tipDevice ?? FALLBACK_REMOTE_DEVICE, remoteIsTheirs: true },
  });
  if (!res.ok) {
    const first = res.quarantine[0];
    return fail({ kind: 'quarantine', rule: `merge:${(first?.rule ?? 'internal').toLowerCase().replace(/[^a-z0-9:_.-]/g, '-').slice(0, 40)}` });
  }
  const notes = mapNotes({ notes: res.notes, at: nowIso, localDevice: deps.localDevice });

  const change = new Map<string, TreeChange>();
  for (const p of res.changed) {
    const text = res.blobs.get(p);
    change.set(p, text === undefined ? { path: p, remove: true } : { path: p, content: text });
  }
  // journal notes land inside M (one atomic commit): append to the merged / local journal of the repo
  const month = nowIso.slice(0, 7);
  const byPath = new Map<string, string[]>();
  for (const j of notes.journal) {
    const p = `${j.repo ?? 'ops'}/journal/${month}.md`;
    const lines = byPath.get(p) ?? [];
    lines.push(j.line);
    byPath.set(p, lines);
  }
  const lEntry = new Map(eL.map((e) => [e.path, e.sha] as const));
  for (const [p, lines] of byPath) {
    const staged = change.get(p);
    let text: string | null = staged !== undefined && 'content' in staged ? (typeof staged.content === 'string' ? staged.content : null) : (res.blobs.get(p) ?? ours.get(p) ?? null);
    if (text === null && lEntry.has(p) && !(staged !== undefined && 'remove' in staged)) {
      const loaded = await decodeBlobs(store, new Map([[p, lEntry.get(p) as string]]), 'local');
      if (isOutcome(loaded)) return fail(loaded);
      text = loaded.get(p) ?? null;
    }
    const repo = p.slice(0, p.indexOf('/'));
    let out = text ?? `# ${repo} — journal ${month}\n`;
    if (!out.endsWith('\n')) out += '\n';
    const have = new Set(out.split('\n'));
    for (const line of lines) if (!have.has(line)) out += `${line}\n`;
    change.set(p, { path: p, content: out });
  }

  // self-check: the output of OUR merge must pass the same ingress we apply to peers (T-B3-4)
  const incoming: IncomingChange[] = [];
  for (const c of change.values()) {
    if ('remove' in c) incoming.push({ path: c.path, mode: '000000', type: 'blob', size: 0, deleted: true });
    else {
      const bytes = typeof c.content === 'string' ? Buffer.from(c.content, 'utf8') : c.content;
      incoming.push({ path: c.path, mode: '100644', type: 'blob', size: bytes.length, content: bytes });
    }
  }
  const fmtEntry = eL.find((e) => e.path === 'ledger.format');
  let baseFormat = 1;
  if (fmtEntry !== undefined) {
    const f = await decodeBlobs(store, new Map([['ledger.format', fmtEntry.sha]]), 'local');
    if (isOutcome(f)) return fail(f);
    const n = /^[1-9][0-9]{0,3}\n?$/.test(f.get('ledger.format') ?? '') ? Number((f.get('ledger.format') as string).trim()) : 1;
    baseFormat = n;
  }
  const check = validateIncoming(incoming, {
    maxFormat: deps.maxFormat,
    baseFormat,
    existingPaths: eL.map((e) => e.path),
    maxPushBytes: LOCAL_CAPS.maxTotalBytes,
    maxChanges: MAX_PATHS,
  });
  if (check.rejected.some((r) => r.rule !== 'delete')) return fail({ kind: 'quarantine', rule: 'merge-output' });

  if (over()) return fail({ kind: 'transient', why: 'budget' });
  const treeM = await trees.buildTree(L, [...change.values()]);
  const treeF = await treeOf(deps, plan.F);
  if (treeM === treeF && lIsAncestor) {
    return { ok: true, built: { M: plan.F, mode: 'ff', treeM: treeF, notes, proposed: res.proposed } };
  }
  const M = await trees.commitTree({
    tree: treeM,
    parents: [L, plan.F],
    message: 'sync: merge remote changes',
    identity: deps.identity,
    signing: deps.signing,
    date: (deps.now ?? (() => new Date()))(),
  });
  return { ok: true, built: { M, mode: 'merge', treeM, notes, proposed: res.proposed } };
}

/* ---------------- applyRemote ---------------- */

export async function applyRemote(host: ApplyHost, deps: ApplyDeps, plan: ApplyPlan): Promise<ApplyOutcome> {
  try {
    if (!isSha(plan.F) || !isSha(plan.A)) return { kind: 'transient', why: 'local-git' };
    // R before Q (lock order SF -> R -> Q -> D): nothing inside awaits flush/close/runExclusive.
    return await host.runExclusive((x) => host.queueRun(() => critical(x, host, deps, plan)));
  } catch (err) {
    if (err instanceof CrashError) throw err;
    host.log(`sync: apply aborted (${safeOutput(err instanceof Error ? err.name : 'error', 40)})`);
    if (err instanceof ObjectsError || err instanceof GitxError || err instanceof TreeBuildError || err instanceof StateError || err instanceof DevicesError) return transientOf(err);
    return { kind: 'transient', why: 'local-git' };
  }
}

async function critical(x: ExclusiveHandle, host: ApplyHost, deps: ApplyDeps, plan: ApplyPlan): Promise<ApplyOutcome> {
  const { store, gitx, trees, state } = deps;
  const t0 = performance.now();
  const budget = deps.timing?.totalMs ?? 15_000;
  const over = (): boolean => performance.now() - t0 > budget;
  const now = deps.now ?? (() => new Date());

  // 1. everything pending is committed by the SAME exclusive section (no flush(): it would deadlock)
  const oc: CommitOutcome = await x.commitNow();
  if (oc !== 'clean' && oc !== 'committed') return { kind: 'transient', why: 'local-hold' };

  // 2. L is read inside R+Q: one L for merge input, marker and CAS
  const L = await store.revParse(REF_MAIN);
  if (L === null) return { kind: 'transient', why: 'local-git' };
  if (await store.isAncestor(plan.F, L)) return { kind: 'noop', L };

  // 3. FF or merge (no worktree input, no mutation)
  const lIsAncestor = await store.isAncestor(L, plan.F);
  let built: Built;
  if (lIsAncestor && !plan.forcedMerge) {
    built = { M: plan.F, mode: 'ff', treeM: await treeOf(deps, plan.F), notes: { journal: [], inbox: [], releaseLeases: [] }, proposed: [] };
  } else {
    const b = await buildMerge(deps, plan, L, lIsAncestor, over);
    if (!b.ok) return b.out;
    built = b.built;
  }
  const treeL = await treeOf(deps, L);
  let changed: string[];
  try {
    changed = (await store.diffTreeRaw(L, built.M, MAX_PATHS)).map((d) => d.path);
  } catch (err) {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return { kind: 'transient', why: 'budget' };
    throw err;
  }
  if (over()) return { kind: 'transient', why: 'budget' };

  // 4. mutation window, under the device lock (D is innermost and bounded)
  try {
    return await withDeviceLock(
      deps.ledgerDir,
      () => mutate(host, deps, plan, { L, treeL, built, changed, now }),
      { waitMs: deps.timing?.lockWaitMs ?? 2000 },
    );
  } catch (err) {
    if (err instanceof DevicesError && err.code === 'LOCKED') return { kind: 'transient', why: 'device-lock' };
    throw err;
  }
}

async function mutate(
  host: ApplyHost,
  deps: ApplyDeps,
  plan: ApplyPlan,
  c: { L: string; treeL: string; built: Built; changed: string[]; now: () => Date },
): Promise<ApplyOutcome> {
  const { gitx, trees, state, ledgerDir } = deps;
  const { L, built, changed } = c;
  const M = built.M;

  // (a) clean worktree and index, else nothing is touched
  if ((await dirtyPaths(deps)).length > 0) return { kind: 'transient', why: 'dirty' };

  // (b) durable marker BEFORE any mutation
  const marker: Inflight = {
    v: 1,
    id: randomBytes(12).toString('base64url'),
    createdAt: isoOf(c.now()),
    mode: built.mode,
    A: plan.A,
    L,
    M,
    F: plan.F,
    treeL: c.treeL,
    treeM: built.treeM,
    changed,
    notes: {
      inbox: built.notes.inbox.slice(0, 20).map((n) => ({
        to_session: sanitizeLine(n.to_session, 80),
        repo: n.repo,
        item_id: n.item_id === null ? null : sanitizeLine(n.item_id, 40),
        body: sanitizeBody(n.body, 2000),
        origin: 'hub' as const,
      })),
      releaseLeases: built.notes.releaseLeases.slice(0, 200).map((r) => ({ item: sanitizeLine(r.item, 40), session: sanitizeLine(r.session, 80) })),
      proposed: built.proposed.slice(0, 20).map((p) => ({ repo: p.repo, title: p.title, why: p.why })),
    },
    stage: 'prepared',
  };
  try {
    await state.writeInflight(marker);
  } catch {
    return { kind: 'transient', why: 'local-git' }; // nothing mutated yet
  }
  await crash(deps, 'marker');

  // (c) index + worktree: L -> M. git verifies every path before touching any (pinned in the crash test).
  const rt = await gitx.run(['read-tree', '-m', '-u', L, M], { cwd: ledgerDir, timeoutMs: 60_000 });
  await crash(deps, 'read-tree');
  if (!rt.ok) {
    if (!rt.timedOut && !rt.capped) {
      const main = await deps.store.revParse(REF_MAIN).catch(() => null);
      if (main === L && (await indexIsCommit(deps, L).catch(() => false)) && (await dirtyPaths(deps).catch(() => ['?'])).length === 0) {
        await state.clearInflight().catch(() => undefined); // read-tree refused before touching anything
        return { kind: 'transient', why: 'local-git' };
      }
    }
    host.log('sync: read-tree failed — marker kept for replay');
    return { kind: 'halt', reason: 'inflight', detail: 'read-tree failed' };
  }

  // (d) main L -> M (CAS)
  await trees.updateRef(REF_MAIN, M, L);
  await crash(deps, 'update-ref');
  await state.writeInflight({ ...marker, stage: 'ref-moved' }).catch(() => undefined); // informative only: git is the truth

  // (e) a key revoked by this merge must leave allowed_signers NOW (T-B3-8); replay repeats it
  try {
    await pruneRevokedSigners(ledgerDir);
  } catch {
    host.log('sync: prune of revoked signers failed — marker kept, replay retries');
    return { kind: 'halt', reason: 'inflight', detail: 'prune failed' };
  }

  // 5. index follows the files (the caller holds Q)
  await host.reindexPaths(changed);
  await crash(deps, 'reindex');
  // 6. notes (at-least-once)
  await host.deliver({ inbox: built.notes.inbox, releaseLeases: built.notes.releaseLeases });
  await crash(deps, 'notes');
  await state.writeInflight({ ...marker, stage: 'notes-done' }).catch(() => undefined);
  // 7.
  await state.clearInflight();
  await crash(deps, 'marker-delete');
  return { kind: 'applied', mode: built.mode, L, M, changed, proposed: built.proposed };
}

/* ---------------- replay ---------------- */

export type ReplayDeps = Pick<ApplyDeps, 'ledgerDir' | 'gitx' | 'store' | 'trees' | 'state' | 'timing' | 'crashAt'>;

export type ReplayGit =
  | { kind: 'none' }
  | { kind: 'rolled-back' }
  | { kind: 'forward'; marker: Inflight }
  | { kind: 'halt'; reason: 'inflight' | 'config'; detail: string };

async function settleIndexLock(deps: ReplayDeps): Promise<boolean> {
  const lock = nodePath.join(deps.ledgerDir, '.git', 'index.lock');
  const waitMs = deps.timing?.indexLockWaitMs ?? 5000;
  const staleMs = deps.timing?.indexLockStaleMs ?? 30_000;
  let waited = 0;
  for (;;) {
    const st = await lstat(lock).catch(() => null);
    if (st === null) return true;
    const age = Math.abs(Date.now() - st.mtimeMs); // clocks jump: distance, not difference
    if (age >= staleMs && st.isFile()) {
      await rm(lock, { force: true }); // only ever called with a marker present, i.e. an apply of ours died
      return true;
    }
    if (waited >= waitMs) return false;
    await sleep(100);
    waited += 100;
  }
}

/** Every dirty/untracked path must be inside the marker's set AND hold exactly the L or the M version. */
async function verifyWorktree(deps: ReplayDeps, m: Inflight): Promise<boolean> {
  const dirty = await dirtyPaths(deps);
  const changed = new Set(m.changed);
  if (dirty.some((p) => !changed.has(p))) return false;
  if (dirty.length === 0) return true;
  const only = new Set(dirty);
  const lMap = treeMap(await deps.store.lsTree(m.L, MAX_PATHS), only);
  const mMap = treeMap(await deps.store.lsTree(m.M, MAX_PATHS), only);
  for (const p of dirty) {
    const have = await worktreeBlob(deps, p);
    if (have === '?') return false;
    const wantL = lMap.get(p) ?? null;
    const wantM = mMap.get(p) ?? null;
    if (have !== wantL && have !== wantM) return false;
  }
  return true;
}

export async function replayGitPhase(deps: ReplayDeps): Promise<ReplayGit> {
  const halt = (reason: 'inflight' | 'config', detail: string): ReplayGit => ({ kind: 'halt', reason, detail });
  try {
    let marker: Inflight | null;
    try {
      marker = await deps.state.readInflight();
    } catch {
      return halt('config', 'inflight marker unreadable');
    }
    if (marker === null) return { kind: 'none' };
    const { store } = deps;
    const main = await store.revParse(REF_MAIN);
    if (main !== marker.L && main !== marker.M) return halt('inflight', 'main is neither L nor M');
    if (!(await store.hasCommit(marker.M))) {
      // W1: crashed before M was durable in the object store (or M was pruned): roll back if nothing moved
      if (main === marker.L && (await indexIsCommit(deps, marker.L)) && (await dirtyPaths(deps)).length === 0) {
        await deps.state.clearInflight();
        return { kind: 'rolled-back' };
      }
      return halt('inflight', 'M is missing and the worktree is not clean');
    }
    // marker trust: shape of M against L and F, trees against the marker
    const raw = await store.readCommitRaw(marker.M);
    const hdr = splitCommit(raw).headers;
    if (hdr === null) return halt('inflight', 'M is not a commit');
    if (marker.mode === 'merge') {
      if (hdr.parents.length !== 2 || hdr.parents[0] !== marker.L || hdr.parents[1] !== marker.F) return halt('inflight', 'M parents do not match the marker');
    } else if (marker.M !== marker.F || !(await store.isAncestor(marker.L, marker.M))) {
      return halt('inflight', 'fast-forward marker does not fit');
    }
    if ((await treeOf(deps, marker.M)) !== marker.treeM || (await treeOf(deps, marker.L)) !== marker.treeL) return halt('inflight', 'marker trees do not match');
    if (!(await settleIndexLock(deps))) return halt('inflight', 'index.lock is held');

    const needMove = main === marker.L;
    const dirty = needMove ? true : (await dirtyPaths(deps)).length > 0;
    if (dirty) {
      if (!(await verifyWorktree(deps, marker))) return halt('inflight', 'worktree holds edits outside the marker');
      const rt = await deps.gitx.run(['read-tree', '--reset', '-u', marker.M], { cwd: deps.ledgerDir, timeoutMs: 60_000 });
      if (!rt.ok) return halt('inflight', 'read-tree --reset failed');
    }
    if (needMove) await deps.trees.updateRef(REF_MAIN, marker.M, marker.L);
    // a key revoked by M must leave allowed_signers even when the crash hit between update-ref and prune
    try {
      await withDeviceLock(deps.ledgerDir, () => pruneRevokedSigners(deps.ledgerDir), { waitMs: Math.max(deps.timing?.lockWaitMs ?? 2000, 2000) });
    } catch {
      return halt('inflight', 'prune of revoked signers failed');
    }
    return { kind: 'forward', marker };
  } catch (err) {
    if (err instanceof CrashError) throw err;
    return halt('inflight', safeOutput(`replay failed (${err instanceof Error ? err.name : 'error'})`, 80));
  }
}

/** Deliver the marker's notes (at-least-once) and delete the marker. Idempotent per step. */
export async function replayNotesPhase(
  host: Pick<ApplyHost, 'deliver' | 'log'> & { createProposed?: ApplyHost['createProposed'] },
  deps: Pick<ReplayDeps, 'state' | 'crashAt'>,
  marker: Inflight,
): Promise<void> {
  if (marker.stage !== 'notes-done') {
    await host.deliver({
      inbox: marker.notes.inbox.map((n) => ({ ...n })),
      releaseLeases: marker.notes.releaseLeases,
    });
  }
  await crash(deps, 'notes');
  if (host.createProposed !== undefined && marker.notes.proposed.length > 0) {
    const items: ProposedItem[] = marker.notes.proposed.map((p) => ({ repo: p.repo ?? 'ops', title: p.title ?? 'sync proposal', why: p.why ?? '' }));
    await host.createProposed(items).catch(() => host.log('sync: proposed items could not be created'));
  }
  await deps.state.clearInflight();
  await crash(deps, 'marker-delete');
}

export type ReplayResult = ReplayGit | { kind: 'completed' };

/** Running hub (cycle PRECHECK): replay under R then Q, reindex the marker's paths, deliver, clear. */
export async function replayInflight(host: ApplyHost, deps: ReplayDeps): Promise<ReplayResult> {
  try {
    return await host.runExclusive(() =>
      host.queueRun(async (): Promise<ReplayResult> => {
        const g = await replayGitPhase(deps);
        if (g.kind !== 'forward') return g;
        await host.reindexPaths(g.marker.changed);
        await crash(deps, 'reindex');
        await replayNotesPhase(host, deps, g.marker);
        return { kind: 'completed' };
      }),
    );
  } catch (err) {
    if (err instanceof CrashError) throw err;
    return { kind: 'halt', reason: 'inflight', detail: 'replay failed' };
  }
}

/* ---------------- boot hygiene ---------------- */

/** W0: temp-index scratch dirs left by a crash (`<ledger>/.hub/sync/tmp`, older than 10 min). Best effort. */
export async function sweepSyncTmp(ledgerDir: string, maxAgeMs = 10 * 60_000): Promise<number> {
  const root = nodePath.join(ledgerDir, '.hub', 'sync', 'tmp');
  let names: string[];
  try {
    names = await readdir(root);
  } catch {
    return 0;
  }
  let removed = 0;
  for (const name of names) {
    const p = nodePath.join(root, name);
    const st = await lstat(p).catch(() => null);
    if (st === null || st.isSymbolicLink()) continue;
    if (Math.abs(Date.now() - st.mtimeMs) <= maxAgeMs) continue;
    await rm(p, { recursive: true, force: true }).catch(() => undefined);
    removed += 1;
  }
  return removed;
}
