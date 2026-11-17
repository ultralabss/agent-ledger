/** Range validation for the sync cycle (F3b B3c, docs/f3b-b3-plan.md §1.2, threats T-B3-6/7/8, S1-S26).
 *
 *  Threat model:
 *   - Actor: a hostile or compromised remote (or a stolen device key) whose commits `A..F` we are about to
 *     merge into the ledger; plus a local environment that can fail (ssh-keygen missing, disk errors).
 *   - Protected: nothing of `A..F` reaches the worktree/index before EVERY commit of the range (side branches
 *     included, not only the first-parent chain) and the final tree of F passed; the local trust state
 *     (revocations, approved signers) is never changed by hostile bytes; no verifier outage downgrades to accept.
 *   - Failure modes: a throwing parser on hostile data (AL-36), a million-commit range, a 10 GB blob, a signer
 *     revoked on a side branch (AL-46), a baseFormat downgrade inside the range (AL-23), a verifier error read as
 *     "unsigned" (AL-43), local I/O errors read as "the remote is hostile".
 *   - Stance: pure decision over object ids of ONE F (callers resolve refs once). `validateRange` NEVER throws:
 *     remote-side errors quarantine (nothing applied), local-side errors are transient. `verifier-error` never
 *     reaches the gate. The operator override (`sync accept`, OQ-B/OQ-C) only re-runs the gate with a weaker
 *     MODE for signature rows; layer T (final-tree safety), revoked signers, devices.yml gate failures, merge
 *     equality and D2 are never overridable. No stderr, URL or blob content ends up in an outcome: rule tokens
 *     and sanitised notes only.
 */

import { parseDevicesYaml, parseEd25519Pub, safeOutput, type DevicesFile } from '@agent-ledger/shared';
import {
  claimedDeviceFromEmail,
  gateCommit,
  gateRange,
  signerStatus,
  type GateInput,
  type GateMergeInput,
  type GateVerdict,
  type VerifyMode,
} from './gate.ts';
import { GitxError, isSha } from './gitx.ts';
import { validateIncoming, validateTreeShape, type IncomingChange, type IngressRejection } from './ingress.ts';
import type { SyncNote } from './merge/types.ts';
import { ObjectsError, type ObjectStore, type RawDiffEntry, type TreeEntry } from './objects.ts';
import { verifyCommitSignature } from './sigverify.ts';

/* ---------------- public types ---------------- */

export interface RangeInput {
  store: ObjectStore;
  /** Private scratch dir for signature verification (`<ledger>/.hub/sync/tmp`). */
  tmpRoot: string;
  /** Last accepted remote tip, local tip (at validation time), fetched remote tip. All full object ids. */
  A: string;
  L: string;
  F: string;
  mode: VerifyMode;
  /** This device (a revocation of it is held for a human, D2). */
  localDevice: string;
  /** Canonical pubkey lines approved on this device. */
  trusted: ReadonlySet<string>;
  /** Device ids ever seen signing (OQ-4 ratchet). */
  seenSigning: ReadonlySet<string>;
  /** `confirmationKey(sha,id)` of every human-confirmed D2 revocation. */
  confirmedRevocations: ReadonlySet<string>;
  /** Highest `ledger.format` this hub supports. */
  maxFormat: number;
  /** Active operator override for THIS tip only (the caller matched `state.overrides` against F). */
  override?: { secretAck: boolean } | null;
  /** Test seam: absolute ssh-keygen. */
  sshKeygenBin?: string;
  maxCommits?: number;
}

export type RangeOutcome =
  | {
      kind: 'ok';
      /** An item delete was seen: the merge path must be used even when L is an ancestor of F (spec §3.2). */
      forcedMerge: boolean;
      notes: SyncNote[];
      /** Device ids whose registered key signed a commit of the range (ratchet input). */
      signers: string[];
      /** Device the tip F is attributed to (verified signer, else committer e-mail hint); merge tie-break only. */
      tipDevice: string | null;
      /** True when the operator override changed at least one verdict. */
      overrideUsed: boolean;
    }
  | { kind: 'quarantine'; rule: string; layer: 'tree' | 'provenance'; commit: string | null; notes: SyncNote[] }
  | { kind: 'halt-d2'; reason: 'quarantine:revocation-root' | 'quarantine:revocation-self'; commit: string; deviceIds: string[]; d2Kind: 'root' | 'self'; notes: SyncNote[] }
  | { kind: 'format'; notes: SyncNote[] }
  | { kind: 'transient'; why: string };

/** Rules `sync accept` may override (OQ-B): signature rows, e-mail mismatch, per-commit ingress hits (and
 *  `secret` only with the extra acknowledgement, OQ-C). Everything else is final. */
export const OVERRIDABLE_RULES: ReadonlySet<string> = new Set(['unsigned', 'unknown-key', 'unapproved', 'unsigned-ratchet', 'email-mismatch', 'secret']);

export function isOverridableRule(rule: string): boolean {
  return OVERRIDABLE_RULES.has(rule) || (rule.startsWith('ingress:') && rule !== 'ingress:secret');
}

/* ---------------- error classification (T-B3-6) ---------------- */

export type ErrorSide = 'local' | 'remote';
export type ErrorClass = { kind: 'quarantine'; rule: string } | { kind: 'transient'; why: string };

/** Remote-side failures (hostile objects, caps) quarantine; local-side ones never do. `TIMEOUT` is transient
 *  (the cycle turns three strikes against the same F into a `timeout` quarantine). */
export function classifySyncError(err: unknown, side: ErrorSide): ErrorClass {
  if (side === 'local') return { kind: 'transient', why: 'local-git' };
  if (err instanceof ObjectsError) {
    if (err.code === 'LIMIT') return { kind: 'quarantine', rule: 'oversize' };
    return { kind: 'quarantine', rule: `objects:${err.code.toLowerCase()}` };
  }
  if (err instanceof GitxError) {
    switch (err.code) {
      case 'CAPPED':
        return { kind: 'quarantine', rule: 'oversize' };
      case 'TIMEOUT':
        return { kind: 'transient', why: 'timeout' };
      case 'BINARY':
      case 'SPAWN':
      case 'PRIVATE':
      case 'ARGS':
      case 'URL':
        return { kind: 'transient', why: 'local-git' };
      default:
        return { kind: 'quarantine', rule: 'objects:git' };
    }
  }
  return { kind: 'quarantine', rule: 'internal' };
}

/* ---------------- tree snapshots (carry-forward maps) ---------------- */

interface Snap {
  devices: string | null;
  format: string | null;
  counters: Map<string, string>;
}

const COUNTER_PATH_RE = /^counters\/d_[a-z2-7]{10}\.yml$/;

function snapOf(entries: readonly TreeEntry[]): Snap {
  const s: Snap = { devices: null, format: null, counters: new Map() };
  for (const e of entries) {
    if (e.path === 'devices.yml') s.devices = e.sha;
    else if (e.path === 'ledger.format') s.format = e.sha;
    else if (COUNTER_PATH_RE.test(e.path)) s.counters.set(e.path, e.sha);
  }
  return s;
}

function applyDiff(prev: Snap, diff: readonly RawDiffEntry[]): Snap {
  const s: Snap = { devices: prev.devices, format: prev.format, counters: new Map(prev.counters) };
  for (const d of diff) {
    const gone = d.status === 'D';
    if (d.path === 'devices.yml') s.devices = gone ? null : d.dstSha;
    else if (d.path === 'ledger.format') s.format = gone ? null : d.dstSha;
    else if (COUNTER_PATH_RE.test(d.path)) {
      if (gone) s.counters.delete(d.path);
      else s.counters.set(d.path, d.dstSha);
    }
  }
  return s;
}

const FORMAT_RE = /^[1-9][0-9]{0,3}\n?$/;
const parseFormat = (text: string | null | undefined): number | null => (typeof text === 'string' && FORMAT_RE.test(text) ? Number(text.trim()) : null);

/** Blob texts by object id, filled lazily through ONE two-phase batch per commit. */
class BlobTexts {
  private readonly cache = new Map<string, string>();
  private readonly store: ObjectStore;
  constructor(store: ObjectStore) {
    this.store = store;
  }
  /** Fetch (and keep) the given blob ids plus return their raw content for the caller's `extra` use. */
  async load(shas: Iterable<string>, contentOf?: Map<string, Buffer>): Promise<void> {
    const want = [...new Set(shas)];
    const missing = want.filter((s) => !this.cache.has(s) || contentOf !== undefined);
    if (missing.length === 0) return;
    const got = await this.store.catFileBatch(missing, { expectType: 'blob' });
    for (const [sha, obj] of got) {
      if (contentOf !== undefined) contentOf.set(sha, obj.content);
      this.cache.set(sha, obj.content.toString('utf8'));
    }
  }
  text(sha: string | null): string | null {
    return sha === null ? null : (this.cache.get(sha) ?? null);
  }
}

/* ---------------- shared diff -> ingress input ---------------- */

export interface Gathered {
  changes: IncomingChange[];
  gate: { path: string; status: string }[];
  badUtf8: boolean;
}

/** `diff` entries -> `validateIncoming` input; contents come from the SAME batch the caller already holds. */
function toChanges(diff: readonly RawDiffEntry[], contents: ReadonlyMap<string, Buffer>): Gathered {
  const changes: IncomingChange[] = [];
  let badUtf8 = false;
  for (const d of diff) {
    if (d.badUtf8) badUtf8 = true;
    if (d.status === 'D') {
      changes.push({ path: d.path, mode: '000000', type: 'blob', size: 0, deleted: true });
      continue;
    }
    const content = d.dstMode === '100644' ? contents.get(d.dstSha) : undefined;
    changes.push({
      path: d.path,
      mode: d.dstMode,
      type: d.dstMode === '160000' ? 'commit' : 'blob',
      size: content?.length ?? 0,
      ...(content !== undefined ? { content } : {}),
    });
  }
  return { changes, gate: diff.map((d) => ({ path: d.path, status: d.status })), badUtf8 };
}

const contentShas = (diff: readonly RawDiffEntry[]): string[] => diff.filter((d) => d.status !== 'D' && d.dstMode === '100644').map((d) => d.dstSha);

const rejectionsOf = (r: { rejected: readonly IngressRejection[] }, extraEncoding: boolean): { path: string; rule: string }[] => {
  const out: { path: string; rule: string }[] = r.rejected.map((x) => ({ path: x.path, rule: x.rule }));
  if (extraEncoding) out.push({ path: '(path)', rule: 'encoding' });
  return out;
};

const ruleToken = (s: string): string => {
  const t = s.toLowerCase().replace(/[^a-z0-9:_.-]/g, '-').replace(/^[^a-z0-9]+/, '');
  return t.length === 0 ? 'unknown' : t.slice(0, 59);
};

/* ---------------- override (OQ-B / OQ-C) ---------------- */

/** Re-run the gate as the operator override allows: signature rows in `warn` strength (ratchet and claimed
 *  device dropped), the structural ingress hits of this commit removed (the final tree is checked separately
 *  by layer T), `secret` only with `secretAck`. Everything else still quarantines. */
function regate(input: GateInput, first: GateVerdict, secretAck: boolean): GateVerdict | null {
  const rule = first.rule;
  if (!isOverridableRule(rule)) return null;
  if (rule === 'secret' && !secretAck) return null;
  const rejected = input.ingress.rejected.filter((r) => {
    if (r.rule === 'delete') return true; // soft rule: the gate itself handles it
    if (r.rule === 'secret') return !secretAck;
    return !rule.startsWith('ingress:');
  });
  const second = gateCommit({
    ...input,
    mode: 'warn',
    seenSigning: new Set<string>(),
    // the claimed device is dropped for the rows that talk about it; without an owner the ownership rows
    // (`unowned`) still quarantine a commit that touches counters or creates items
    claimedDevice: rule === 'email-mismatch' || rule === 'unsigned-ratchet' || rule === 'unsigned' ? null : input.claimedDevice,
    ingress: { accepted: input.ingress.accepted ?? [], rejected },
  });
  if (second.action === 'quarantine' || second.action === 'halt') return null;
  return second;
}

/* ---------------- validateRange ---------------- */

const MAX_NOTES = 40;

function attachDevice(notes: readonly SyncNote[], device: string | null): SyncNote[] {
  return notes.map((n) => (n.device === undefined && device !== null ? { ...n, device } : n));
}

/** A failure while reading LOCAL objects (L's tree): never a reason to quarantine the remote. */
class LocalSide extends Error {
  readonly inner: unknown;
  constructor(inner: unknown) {
    super('local side failed');
    this.inner = inner;
  }
}
const asLocal = <T>(p: Promise<T>): Promise<T> =>
  p.catch((err: unknown) => {
    throw new LocalSide(err);
  });

export async function validateRange(i: RangeInput): Promise<RangeOutcome> {
  try {
    return await validateRangeInner(i);
  } catch (err) {
    const c = classifySyncError(err instanceof LocalSide ? err.inner : err, err instanceof LocalSide ? 'local' : 'remote');
    if (c.kind === 'transient') return { kind: 'transient', why: c.why };
    return { kind: 'quarantine', rule: ruleToken(c.rule), layer: 'tree', commit: null, notes: [{ type: 'sync.reject', rule: ruleToken(c.rule), detail: 'range could not be read safely' }] };
  }
}

async function validateRangeInner(i: RangeInput): Promise<RangeOutcome> {
  const { store } = i;
  for (const id of [i.A, i.L, i.F]) if (!isSha(id)) return { kind: 'transient', why: 'bad-input' };
  if (!(i.mode === 'warn' || i.mode === 'enforce')) return { kind: 'transient', why: 'bad-input' };
  const q = (rule: string, layer: 'tree' | 'provenance', commit: string | null, notes: SyncNote[] = []): RangeOutcome => ({
    kind: 'quarantine',
    rule: ruleToken(rule),
    layer,
    commit,
    notes: notes.length > 0 ? notes : [{ type: 'sync.reject', rule: ruleToken(rule), detail: safeOutput(`range refused (${rule})`, 120) }],
  });

  /* (1) every commit of A..F, side branches included (AL-46) */
  let commits: { sha: string; parents: string[] }[];
  try {
    commits = await store.revList(i.A, i.F, i.maxCommits ?? 2000);
  } catch (err) {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return q('oversize', 'tree', null);
    throw err;
  }

  /* (2) carry-forward maps */
  const texts = new BlobTexts(store);
  const snaps = new Map<string, Snap>();
  const snapOfCommit = async (sha: string, local = false): Promise<Snap> => {
    const hit = snaps.get(sha);
    if (hit !== undefined) return hit;
    const s = snapOf(await (local ? asLocal(store.lsTree(sha)) : store.lsTree(sha)));
    snaps.set(sha, s);
    return s;
  };
  const snapRemote = (sha: string): Promise<Snap> => snapOfCommit(sha);
  const snapA = await snapRemote(i.A);
  const currentDevicesSha = (await snapOfCommit(i.L, true)).devices;
  await asLocal(texts.load([...(currentDevicesSha === null ? [] : [currentDevicesSha])]));
  const currentDevices = texts.text(currentDevicesSha);
  if (currentDevicesSha !== null && currentDevices === null) return { kind: 'transient', why: 'local-git' };

  const verdicts: { v: GateVerdict; sha: string; signerDevice: string | null }[] = [];
  let overrideUsed = false;
  const signers = new Set<string>();
  const inRange = new Set(commits.map((c) => c.sha));
  const secretAck = i.override?.secretAck === true;
  let tipDevice: string | null = null;

  for (const c of commits) {
    if (c.parents.length === 0) return q('root-commit', 'provenance', c.sha);
    if (c.parents.length > 2) return q('merge-octopus', 'provenance', c.sha);
    const parent0 = c.parents[0] as string;
    const raw = await store.readCommitRaw(c.sha);
    const sig = await verifyCommitSignature(raw, { tmpRoot: i.tmpRoot, ...(i.sshKeygenBin !== undefined ? { bin: i.sshKeygenBin } : {}) });
    // AL-43: a verifier outage is NOT "unsigned"; nothing is accepted, nothing quarantined, retry later.
    if (sig.reason === 'verifier-error') return { kind: 'transient', why: 'verifier' };
    const h = sig.headers;
    if (h === null) return q('malformed-commit', 'provenance', c.sha);
    if (h.parents.length !== c.parents.length || h.parents.some((p, k) => p !== c.parents[k])) return q('malformed-commit', 'provenance', c.sha);

    const parentSnaps: Snap[] = [];
    for (const p of c.parents) parentSnaps.push(inRange.has(p) ? (snaps.get(p) as Snap) : await snapRemote(p));
    const diff = await store.diffTreeRaw(parent0, c.sha);
    const mySnap = applyDiff(parentSnaps[0] as Snap, diff);
    snaps.set(c.sha, mySnap);

    const isMerge = c.parents.length === 2;
    let mergeInput: GateMergeInput | undefined;
    const need = new Set<string>(contentShas(diff));
    const addNeed = (s: string | null): void => {
      if (s !== null) need.add(s);
    };
    for (const ps of parentSnaps) addNeed(ps.devices);
    addNeed(mySnap.devices);
    addNeed((parentSnaps[0] as Snap).format);
    let baseSnap: Snap | null = null;
    let addedVsBoth: string[] = [];
    if (isMerge) {
      const mb = await store.mergeBase(c.parents[0] as string, c.parents[1] as string);
      baseSnap = mb === null ? null : inRange.has(mb) ? (snaps.get(mb) as Snap) : await snapRemote(mb);
      addNeed(baseSnap?.devices ?? null);
      for (const s of [...parentSnaps, mySnap, ...(baseSnap === null ? [] : [baseSnap])]) for (const b of s.counters.values()) need.add(b);
      const d1 = await store.diffTreeRaw(c.parents[0] as string, c.sha);
      const d2 = await store.diffTreeRaw(c.parents[1] as string, c.sha);
      const added2 = new Set(d2.filter((d) => d.status === 'A').map((d) => d.path));
      addedVsBoth = d1.filter((d) => d.status === 'A' && added2.has(d.path)).map((d) => d.path);
    }
    const contents = new Map<string, Buffer>();
    await texts.load(need, contents);
    const g = toChanges(diff, contents);

    const baseFormat = parseFormat(texts.text((parentSnaps[0] as Snap).format)) ?? 1;
    const ing = validateIncoming(g.changes, { baseFormat, maxFormat: i.maxFormat });
    const rejected = rejectionsOf(ing, g.badUtf8);

    const textsOf = (s: Snap | null): Map<string, string> => {
      const m = new Map<string, string>();
      if (s !== null) for (const [p, b] of s.counters) m.set(p, texts.text(b) ?? '');
      return m;
    };
    if (isMerge) {
      mergeInput = {
        baseDevices: texts.text(baseSnap?.devices ?? null),
        baseCounters: textsOf(baseSnap),
        parentCounters: [textsOf(parentSnaps[0] as Snap), textsOf(parentSnaps[1] as Snap)],
        mergedCounters: textsOf(mySnap),
        addedVsBoth,
      };
    }
    const claimed = claimedDeviceFromEmail(h.committerEmail);
    const input: GateInput = {
      mode: i.mode,
      sha: c.sha,
      commitTimeMs: h.committerTime * 1000,
      signature: { valid: sig.valid, pubkey: sig.pubkeyLine, reason: sig.reason },
      claimedDevice: claimed,
      localDevice: i.localDevice,
      trusted: i.trusted,
      seenSigning: i.seenSigning,
      parentDevices: parentSnaps.map((s) => texts.text(s.devices)),
      devicesText: texts.text(mySnap.devices),
      currentDevices,
      confirmedRevocations: i.confirmedRevocations,
      changes: g.gate,
      ingress: { accepted: ing.accepted, rejected },
      ...(mergeInput !== undefined ? { merge: mergeInput } : {}),
    };
    let v = gateCommit(input);
    if ((v.action === 'quarantine') && i.override !== undefined && i.override !== null) {
      const second = regate(input, v, secretAck);
      if (second !== null) {
        overrideUsed = true;
        v = { ...second, notes: [...second.notes, { type: 'sync.warning', rule: 'override', detail: `accepted by operator override (commit ${c.sha.slice(0, 12)})` }] };
      }
    }
    const pub = sig.valid && sig.pubkeyLine !== null ? parseEd25519Pub(sig.pubkeyLine) : null;
    const signerDevice = pub?.deviceId ?? null;
    v = { ...v, notes: attachDevice(v.notes, signerDevice ?? claimed) };
    verdicts.push({ v, sha: c.sha, signerDevice });
    if (c.sha === i.F) tipDevice = signerDevice ?? claimed;
    if (v.action === 'accept' || v.action === 'accept-warn' || v.action === 'forced-merge-keep-items') {
      if (pub !== null) {
        const parsed: (DevicesFile | null)[] = [];
        for (const t of input.parentDevices) {
          try {
            parsed.push(t === null ? null : parseDevicesYaml(t));
          } catch {
            parsed.push(null);
          }
        }
        const st = signerStatus(input.signature, parsed, i.trusted).status;
        if (st === 'trusted' || st === 'unapproved') signers.add(pub.deviceId);
      }
    }
  }

  /* (4) layer T: the final tree, never overridable */
  const snapF = snaps.get(i.F) ?? (await snapRemote(i.F));
  await texts.load([...(snapF.format === null ? [] : [snapF.format])]);
  const formatF = parseFormat(texts.text(snapF.format));
  if (snapF.format !== null && formatF !== null && formatF > i.maxFormat) return { kind: 'format', notes: [{ type: 'sync.reject', rule: 'format', detail: 'ledger.format is newer than this hub supports' }] };
  const rangeDiff = await store.diffTreeRaw(i.A, i.F);
  const rangeContents = new Map<string, Buffer>();
  await texts.load(contentShas(rangeDiff), rangeContents);
  const rg = toChanges(rangeDiff, rangeContents);
  const localEntries = await asLocal(store.lsTree(i.L));
  const baseFormatA = parseFormat(texts.text(snapA.format)) ?? 1;
  const existing = localEntries.map((e) => e.path);
  const tIngress = validateIncoming(rg.changes, { baseFormat: baseFormatA, maxFormat: i.maxFormat, existingPaths: existing });
  const tRejected = rejectionsOf(tIngress, rg.badUtf8);
  const hard = tRejected.filter((r) => r.rule !== 'delete');
  if (hard.length > 0) {
    const first = [...hard].sort((a, b) => (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0))[0] as { rule: string };
    return q(`tree:${first.rule}`, 'tree', i.F, hard.slice(0, 20).map((r) => ({ type: r.rule === 'secret' ? 'sync.secret' : 'sync.reject', rule: ruleToken(r.rule), path: r.path, detail: `final tree refused (${ruleToken(r.rule)})` }) as SyncNote));
  }
  const shape = validateTreeShape(await store.lsTree(i.F), { existingPaths: existing });
  if (shape.rejected.length > 0) {
    const first = shape.rejected[0] as IngressRejection;
    return q(`tree:${first.rule}`, 'tree', i.F, shape.rejected.slice(0, 20).map((r) => ({ type: 'sync.reject', rule: ruleToken(r.rule), path: r.path, detail: `final tree refused (${ruleToken(r.rule)})` }) as SyncNote));
  }

  /* (5) range verdict */
  const worst = gateRange(verdicts.map((x) => x.v));
  const notes = worst.notes.slice(0, MAX_NOTES);
  if (worst.action === 'halt') {
    const d2 = worst.d2;
    if (d2 === undefined || worst.haltReason === undefined) return q('internal', 'tree', null);
    return { kind: 'halt-d2', reason: worst.haltReason, commit: d2.commit, deviceIds: d2.deviceIds, d2Kind: d2.kind, notes };
  }
  if (worst.action === 'quarantine') {
    const at = verdicts.find((x) => x.v.action === 'quarantine' && x.v.rule === worst.rule);
    return { kind: 'quarantine', rule: ruleToken(worst.rule), layer: 'provenance', commit: at?.sha ?? null, notes };
  }
  const forcedMerge = worst.action === 'forced-merge-keep-items' || verdicts.some((x) => x.v.action === 'forced-merge-keep-items') || tRejected.some((r) => r.rule === 'delete');
  return { kind: 'ok', forcedMerge, notes, signers: [...signers].sort(), tipDevice, overrideUsed };
}

/* ---------------- egress self-check (invariant 12) ---------------- */

export type EgressOutcome = { ok: true } | { ok: false; rule: string };

/** The hub never pushes a range its own ingress would reject. Every local commit of `A..L` (diff against its
 *  first parent), the whole diff and the final tree shape are checked. A `delete` rule alone is fine (peers
 *  soft-revert item deletes). Errors THROW (local side: the caller treats them as transient). */
export async function egressSelfCheck(store: ObjectStore, i: { A: string; L: string; maxFormat: number; maxCommits?: number }): Promise<EgressOutcome> {
  const texts = new BlobTexts(store);
  const commits = await store.revList(i.A, i.L, i.maxCommits ?? 2000).catch((err: unknown) => {
    if (err instanceof ObjectsError && err.code === 'LIMIT') return null;
    throw err;
  });
  if (commits === null) return { ok: false, rule: 'push-count' };
  const check = async (oldSha: string | null, newSha: string): Promise<string | null> => {
    const diff = await store.diffTreeRaw(oldSha, newSha).catch((err: unknown) => {
      if (err instanceof ObjectsError && err.code === 'LIMIT') return null;
      throw err;
    });
    if (diff === null) return 'push-count';
    const contents = new Map<string, Buffer>();
    try {
      await texts.load(contentShas(diff), contents);
    } catch (err) {
      if (err instanceof ObjectsError && err.code === 'LIMIT') return 'size';
      throw err;
    }
    const g = toChanges(diff, contents);
    const r = validateIncoming(g.changes, { maxFormat: i.maxFormat });
    const bad = rejectionsOf(r, g.badUtf8).filter((x) => x.rule !== 'delete');
    return bad.length === 0 ? null : ruleToken(bad[0]?.rule ?? 'unknown');
  };
  for (const c of commits) {
    const p0 = c.parents[0];
    if (p0 === undefined) continue; // a local root commit cannot be in A..L
    const bad = await check(p0, c.sha);
    if (bad !== null) return { ok: false, rule: bad };
  }
  const total = await check(i.A, i.L);
  if (total !== null) return { ok: false, rule: total };
  const shape = validateTreeShape(await store.lsTree(i.L));
  if (shape.rejected.length > 0) return { ok: false, rule: ruleToken((shape.rejected[0] as IngressRejection).rule) };
  return { ok: true };
}
