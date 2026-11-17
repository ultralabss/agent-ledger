/** Genesis validation for `sync join` (F3b B4b, docs/f3b-b4-plan.md §2.3, E-14, T-B4-8, T-B4-3).
 *
 *  A joiner has NO accepted base: `validateRange` quarantines a root commit and needs a trust set. Before the
 *  first checkout this module decides, from object ids alone, whether a fetched tip `F` is a ledger whose
 *  device registry chains back to ONE self-registered root that signed its own registration.
 *
 *  Threat model:
 *   - Actor: a hostile or compromised remote / MITM that survived the host key check, serving an attacker's
 *     repo, a second root, a registry planted before the "root", a registry nobody signed, a rolled-back
 *     history, hostile trees (symlinks, gitlinks, `.hub/x`, hooks via `.gitattributes`).
 *   - Protected: the trust bootstrap. Everything the joiner will trust (`allowed_signers`) is derived from the
 *     registry this function returns, anchored on the root fingerprint a HUMAN confirms afterwards.
 *   - Failure modes: two roots, an unsigned or wrongly signed introduction, a later registry change that the
 *     signer was not entitled to (`acceptDevicesChange`), a merge that is not the typed merge, an oversized
 *     history, a verifier outage read as "fine".
 *   - Stance: fail closed, never throws. Any anomaly is `{ ok: false, rule }` with a rule TOKEN only (no URL,
 *     no stderr, no blob text). `rule: 'verifier'` / `'unreadable'` are local-side (retry), everything else is
 *     about the remote. Legacy commits BEFORE the introducing commit are unsigned and are history only: their
 *     content is covered by the full-tree check of `F` itself.
 *   - Residual: freshness. A first-time joiner cannot tell a stale-but-valid tip from the current one; phase 2
 *     of the join (own entry added by a trusted signer on top of F0, optional `--add-commit`) closes that gap.
 */

import {
  DEVICES_MAX_BYTES,
  acceptDevicesChange,
  parseDevicesYaml,
  parseEd25519Pub,
  type DeviceEntry,
  type DevicesFile,
} from '@agent-ledger/shared';
import { GitxError, isSha, type Gitx } from './gitx.ts';
import { validateIncoming, validateTreeShape, type IncomingChange } from './ingress.ts';
import { mergeDevicesNullable } from './merge/devices.ts';
import { ObjectsError, type ObjectStore } from './objects.ts';
import { verifyCommitSignature } from './sigverify.ts';

export const GENESIS_MAX_COMMITS = 20_000;
/** Whole-tree check caps (one-time, at join / init): bigger than a per-push cap on purpose, still bounded. */
export const GENESIS_MAX_TREE_ENTRIES = 20_000;
export const GENESIS_MAX_TREE_BYTES = 64 * 1024 * 1024;

export interface GenesisCaps {
  /** Same repository the store reads (batch lookups of `devices.yml` per commit go through it). */
  gitx: Gitx;
  cwd: string;
  /** Private scratch dir for signature verification (`<ledger>/.hub/sync/tmp`). */
  tmpRoot: string;
  /** Highest `ledger.format` this hub supports. */
  maxFormat: number;
  maxCommits?: number;
  /** Test seam: absolute ssh-keygen. */
  sshKeygenBin?: string;
}

export type GenesisResult =
  | {
      ok: true;
      /** The self-registered primary (slot "") of the registry at `F`. */
      root: DeviceEntry;
      /** The registry at `F`. */
      devices: DevicesFile;
      /** Canonical pubkey lines of every NON-revoked device at `F`, sorted. */
      signers: string[];
    }
  | { ok: false; rule: string };

const canon = (k: string): string | null => parseEd25519Pub(k)?.line ?? null;

/** Rule token: `[a-z0-9:_.-]`, <= 59 chars. */
const token = (s: string): string => {
  const t = s.toLowerCase().replace(/[^a-z0-9:_.-]/g, '-').replace(/^[^a-z0-9]+/, '');
  return t.length === 0 ? 'unknown' : t.slice(0, 59);
};

class Refuse extends Error {
  readonly rule: string;
  constructor(rule: string) {
    super('genesis refused');
    this.rule = rule;
  }
}
const refuse = (rule: string): never => {
  throw new Refuse(token(rule));
};

/** `devices.yml` blob id per commit, one `cat-file --batch-check` for ALL commits (input `<commit>:devices.yml`). */
async function registryBlobs(caps: GenesisCaps, commits: readonly string[]): Promise<Map<string, string | null>> {
  const r = await caps.gitx.run(['cat-file', '--batch-check'], {
    cwd: caps.cwd,
    input: `${commits.map((c) => `${c}:devices.yml`).join('\n')}\n`,
    maxStdoutBytes: commits.length * 220 + 1024,
    timeoutMs: 120_000,
  });
  caps.gitx.ensureOk(r, 'cat-file --batch-check');
  const lines = r.stdout.toString('utf8').split('\n').filter((l) => l !== '');
  if (lines.length !== commits.length) throw new ObjectsError('PARSE', 'batch-check answered a different count');
  const out = new Map<string, string | null>();
  for (const [i, line] of lines.entries()) {
    const c = commits[i] as string;
    if (/ missing$/.test(line)) {
      out.set(c, null);
      continue;
    }
    const m = /^([0-9a-f]{40}|[0-9a-f]{64}) (blob|tree|commit|tag) \d+$/.exec(line);
    if (m === null) throw new ObjectsError('PARSE', 'batch-check line malformed');
    if (m[2] !== 'blob') refuse('devices-type');
    out.set(c, m[1] as string);
  }
  return out;
}

/** Full-tree safety of one commit: names, modes, layout (`validateTreeShape`) and every file's content
 *  (`validateIncoming` with every path as an add). Returns a rule token or `null`. Throws on object errors. */
export async function fullTreeProblem(store: ObjectStore, commit: string, maxFormat: number): Promise<string | null> {
  const entries = await store.lsTree(commit, GENESIS_MAX_TREE_ENTRIES);
  const shape = validateTreeShape(entries);
  if (shape.rejected.length > 0) return `tree:${token((shape.rejected[0] as { rule: string }).rule)}`;
  const blobs = entries.filter((e) => e.mode === '100644' && e.type === 'blob').map((e) => e.sha);
  const got = await store.catFileBatch(blobs, {
    expectType: 'blob',
    maxCount: GENESIS_MAX_TREE_ENTRIES,
    maxTotalBytes: GENESIS_MAX_TREE_BYTES,
  });
  const changes: IncomingChange[] = entries.map((e) => {
    const content = e.mode === '100644' && e.type === 'blob' ? got.get(e.sha)?.content : undefined;
    return { path: e.path, mode: e.mode, type: e.type, size: content?.length ?? e.size ?? 0, ...(content !== undefined ? { content } : {}) };
  });
  const res = validateIncoming(changes, { maxFormat, maxChanges: GENESIS_MAX_TREE_ENTRIES, maxPushBytes: GENESIS_MAX_TREE_BYTES });
  const hard = res.rejected.filter((r) => r.rule !== 'delete');
  if (hard.length > 0) {
    const first = [...hard].sort((a, b) => (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0))[0] as { rule: string };
    return `content:${token(first.rule)}`;
  }
  return null;
}

/** The parsed registry at `commit`, or `null` when there is none. Throws on a malformed one (`DevicesError`). */
export async function registryAt(store: ObjectStore, gitx: Gitx, cwd: string, commit: string): Promise<DevicesFile | null> {
  if (!isSha(commit)) throw new ObjectsError('REF', 'commit id refused');
  const r = await gitx.run(['rev-parse', '--verify', '--quiet', '--end-of-options', `${commit}:devices.yml`], { cwd });
  if (r.code === 1) return null;
  gitx.ensureOk(r, 'rev-parse');
  const blob = r.stdout.toString('utf8').trim();
  if (!isSha(blob)) throw new ObjectsError('PARSE', 'rev-parse returned a non-object-id');
  const text = (await store.readObject(blob, 'blob', DEVICES_MAX_BYTES + 1)).toString('utf8');
  return parseDevicesYaml(text);
}

/** Validate `F` as the tip of a joinable ledger. Never throws. */
export async function validateGenesis(store: ObjectStore, F: string, caps: GenesisCaps): Promise<GenesisResult> {
  try {
    return await validateInner(store, F, caps);
  } catch (err) {
    if (err instanceof Refuse) return { ok: false, rule: err.rule };
    if (err instanceof ObjectsError) return { ok: false, rule: err.code === 'LIMIT' ? 'oversize' : 'malformed' };
    // a git / OS failure is OURS (retry), anything else thrown while reading hostile bytes is the remote's
    if (err instanceof GitxError) return { ok: false, rule: err.code === 'EXIT' || err.code === 'CAPPED' ? 'malformed' : 'unreadable' };
    return { ok: false, rule: 'malformed' };
  }
}

async function validateInner(store: ObjectStore, F: string, caps: GenesisCaps): Promise<GenesisResult> {
  if (!isSha(F)) return refuse('bad-input');
  const cap = Math.min(caps.maxCommits ?? GENESIS_MAX_COMMITS, GENESIS_MAX_COMMITS);
  const verify = async (sha: string): Promise<{ pub: string; time: number; parents: string[] }> => {
    const raw = await store.readCommitRaw(sha);
    const sig = await verifyCommitSignature(raw, { tmpRoot: caps.tmpRoot, ...(caps.sshKeygenBin !== undefined ? { bin: caps.sshKeygenBin } : {}) });
    if (sig.reason === 'verifier-error') return refuse('verifier');
    if (sig.headers === null) return refuse('malformed-commit');
    const pub = sig.valid && sig.pubkeyLine !== null ? canon(sig.pubkeyLine) : null;
    return { pub: pub ?? '', time: sig.headers.committerTime * 1000, parents: sig.headers.parents };
  };

  /* (1) every commit, oldest first (LIMIT = oversize) */
  const commits = await store.revList(null, F, cap);
  const tip = commits[commits.length - 1];
  if (tip === undefined || tip.sha !== F) return refuse('bad-input');

  /* (2) the tip tree: shape + every file's content */
  const tree = await fullTreeProblem(store, F, caps.maxFormat);
  if (tree !== null) return refuse(tree);

  /* (3) registry blob per commit */
  const blobOf = await registryBlobs(
    caps,
    commits.map((c) => c.sha),
  );
  const parsed = new Map<string, DevicesFile>();
  const registryOfBlob = async (blob: string): Promise<DevicesFile> => {
    const hit = parsed.get(blob);
    if (hit !== undefined) return hit;
    const text = (await store.readObject(blob, 'blob', DEVICES_MAX_BYTES + 1)).toString('utf8');
    let file: DevicesFile;
    try {
      file = parseDevicesYaml(text);
    } catch {
      return refuse('devices-invalid');
    }
    parsed.set(blob, file);
    return file;
  };
  const textOfBlob = async (blob: string | null): Promise<string | null> =>
    blob === null ? null : (await store.readObject(blob, 'blob', DEVICES_MAX_BYTES + 1)).toString('utf8');

  /* (4) walk, oldest first. `file[c]` = the registry at commit c (only for commits that carry one) */
  const fileAt = new Map<string, DevicesFile>();
  let introductions = 0;
  for (const c of commits) {
    const blob = blobOf.get(c.sha) ?? null;
    const parentBlobs = c.parents.map((p) => blobOf.get(p) ?? null);
    if (c.parents.length > 2) return refuse('merge-octopus');
    if (blob === null) {
      if (parentBlobs.some((b) => b !== null)) return refuse('registry-removed');
      continue;
    }
    const file = await registryOfBlob(blob);
    fileAt.set(c.sha, file);

    /* the introducing commit: every parent lacks a registry */
    if (parentBlobs.every((b) => b === null)) {
      introductions += 1;
      if (introductions > 1) return refuse('multiple-roots');
      const only = file.devices[0];
      if (file.devices.length !== 1 || only === undefined || only.slot !== '' || only.added_by !== only.id || only.revoked !== null) return refuse('root-shape');
      const s = await verify(c.sha);
      if (s.pub === '') return refuse('root-unsigned');
      if (s.pub !== canon(only.pubkey)) return refuse('root-signer');
      // exactly the rule `device init --root` applies locally, with the time binding of THIS commit
      const v = acceptDevicesChange(null, file, s.pub, new Set(), { allowRoot: true, commitTimeMs: s.time });
      if (!v.ok) return refuse(`root-${v.reason}`);
      continue;
    }

    /* every later change */
    const same = parentBlobs.every((b) => b === blob);
    if (same) continue;
    const parentFiles: (DevicesFile | null)[] = [];
    for (const b of parentBlobs) parentFiles.push(b === null ? null : await registryOfBlob(b));
    const s = await verify(c.sha);
    if (s.pub === '') return refuse('devices-unsigned');
    // the signer must be registered and live in EVERY parent that carries a registry
    for (const pf of parentFiles) {
      if (pf === null) continue;
      const e = pf.devices.find((d) => canon(d.pubkey) === s.pub);
      if (e === undefined) return refuse('devices-signer-unregistered');
      if (e.revoked !== null) return refuse('devices-signer-revoked');
    }
    if (c.parents.length === 2) {
      // merge: must be exactly the typed merge of the two sides (the same rule the gate applies)
      const mb = await store.mergeBase(c.parents[0] as string, c.parents[1] as string);
      const baseText = mb === null ? null : await textOfBlob(blobOf.get(mb) ?? null);
      const t0 = await textOfBlob(parentBlobs[0] ?? null);
      const t1 = await textOfBlob(parentBlobs[1] ?? null);
      const exp = mergeDevicesNullable(baseText, t0, t1);
      if (!exp.ok) return refuse('merge-devices');
      if (exp.merged !== (await textOfBlob(blob))) return refuse('merge-devices');
      continue;
    }
    const base = parentFiles[0];
    if (base === null || base === undefined) return refuse('devices-base');
    const trusted = new Set(base.devices.flatMap((d) => canon(d.pubkey) ?? []));
    const v = acceptDevicesChange(base, file, s.pub, trusted, { commitTimeMs: s.time });
    if (!v.ok) return refuse(`devices-${v.reason}`);
  }
  if (introductions !== 1) return refuse('no-registry');

  /* (5) the tip: signed by a registered, non-revoked key of the registry AT the tip */
  const devices = fileAt.get(F);
  if (devices === undefined) return refuse('no-registry');
  const t = await verify(F);
  if (t.pub === '') return refuse('tip-unsigned');
  const signer = devices.devices.find((d) => canon(d.pubkey) === t.pub);
  if (signer === undefined) return refuse('tip-signer-unregistered');
  if (signer.revoked !== null) return refuse('tip-signer-revoked');

  const root = devices.devices.find((d) => d.slot === '' && d.added_by === d.id);
  if (root === undefined) return refuse('no-root');
  const signers = devices.devices.filter((d) => d.revoked === null).flatMap((d) => canon(d.pubkey) ?? []);
  return { ok: true, root, devices, signers: [...new Set(signers)].sort() };
}
