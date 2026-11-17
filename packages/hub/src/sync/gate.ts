/** Per-commit verdict (F3b B2, docs/f3b-plan.md §2.3 "Inputs x outcome"). Pure: every
 *  fact arrives as input (signature result, parents' `devices.yml`, ingress result,
 *  changed paths), nothing is read from git, disk or the clock. NEVER throws: any
 *  failure, malformed or hostile input is a quarantine.
 *
 *  Evaluation order (first match wins; Q = quarantine the whole range):
 *   1. ingress rejection other than `delete` / `secret`                  -> Q  sync.reject
 *   2. ingress rule `secret`                                             -> Q  sync.secret
 *   3. only `delete` (item) rejections                                   -> remembered: if the
 *      commit is otherwise acceptable the outcome is `forced-merge-keep-items`
 *      (item kept, `sync.reject`); with a devices.yml change -> Q
 *   4. merge commit: devices.yml(M) == render(mergeDevices(base,P1,P2)) and
 *      counters(M) == per-key max, else Q; a merge whose devices.yml differs from ANY
 *      parent changes the registry: the signer must be `trusted` (both modes), else Q
 *   5. valid signature, key revoked in any parent                        -> Q  (both modes)
 *      valid signature, key revoked in `currentDevices` (local tip)      -> Q  `revoked-current`
 *   6. valid signature, committer-email device id != signer              -> Q  (S19)
 *   7. counters/<x>.yml of another device / item id with another slot    -> Q  (S18)
 *   8. signer rows: trusted+active / registered-unapproved / unknown key / unsigned
 *      (with the OQ-4 ratchet) x devices.yml change, warn vs enforce.
 *
 *  Deviation from a literal reading of the matrix (see the B2 report): the soft
 *  item-delete row and the counters/slot row are evaluated as conditions on top of the
 *  signature rows, not as short-circuit rows that would let an unsigned or revoked
 *  commit through (invariants 5, 6, 11 outrank row order).
 */

import {
  acceptDevicesChange,
  parseDevicesYaml,
  parseEd25519Pub,
  parseItemId,
  safeOutput,
  type DeviceEntry,
  type DevicesFile,
} from '@agent-ledger/shared';
import { mergeDevicesNullable } from './merge/devices.ts';
import { mergeCounters } from './merge/files.ts';
import type { SyncNote } from './merge/types.ts';

export type VerifyMode = 'warn' | 'enforce';
export type GateAction = 'accept' | 'accept-warn' | 'forced-merge-keep-items' | 'quarantine' | 'halt';
export type HaltReason = 'quarantine:revocation-root' | 'quarantine:revocation-self';

export interface GateSignature {
  valid: boolean;
  /** Canonical `ssh-ed25519 …` of the key the signature verified against. */
  pubkey: string | null;
  reason: string;
}

export interface GateChange {
  path: string;
  /** diff-tree status letter (`A`, `M`, `D`, …). */
  status: string;
}

export interface GateMergeInput {
  baseDevices: string | null;
  baseCounters: ReadonlyMap<string, string>;
  /** `counters/<id>.yml` texts of the two parents. */
  parentCounters: readonly [ReadonlyMap<string, string>, ReadonlyMap<string, string>];
  /** `counters/<id>.yml` texts of the merge commit itself. */
  mergedCounters: ReadonlyMap<string, string>;
}

export interface GateInput {
  mode: VerifyMode;
  sha: string;
  /** Committer time (epoch ms): binds `added` / `revoked.at` (D2). */
  commitTimeMs: number;
  signature: GateSignature;
  /** Device id named by the committer e-mail (hint, never authority); `null` = none. */
  claimedDevice: string | null;
  /** This device (self-revocation is held for a human, D2). */
  localDevice: string;
  /** Canonical pubkey lines approved on this device (`.hub/allowed_signers`). */
  trusted: ReadonlySet<string>;
  /** Device ids ever seen signing a commit (OQ-4 ratchet). */
  seenSigning: ReadonlySet<string>;
  /** `devices.yml` text of every parent (`null` = absent). */
  parentDevices: readonly (string | null)[];
  /** `devices.yml` text of this commit (`null` = absent). For a merge commit, a text that
   *  differs from ANY parent's counts as a registry change: it needs a `trusted` signer in
   *  both warn and enforce (typed-merge equality is checked separately, row 4). */
  devicesText: string | null;
  /** `devices.yml` text at the local tip / last accepted commit (`null` = no registry
   *  there). A valid signature by a key revoked HERE is quarantined (`revoked-current`) in
   *  both modes even when the commit's parents predate the revocation (stolen-key fork).
   *  `undefined` = not provided: the check is skipped (callers MUST provide it; kept
   *  optional only so existing call sites stay valid). Present but unparseable -> Q. */
  currentDevices?: string | null;
  /** Paths changed by this commit against its first parent. */
  changes: readonly GateChange[];
  /** `validateIncoming` result for this commit's changes. */
  ingress: { accepted?: readonly string[]; rejected: readonly { path: string; rule: string }[] };
  /** Required for merge commits (two parents). */
  merge?: GateMergeInput;
}

export interface GateVerdict {
  action: GateAction;
  haltReason?: HaltReason;
  /** Machine token of the deciding rule (`ok`, `ingress:symlink`, `revoked-signer`, …). */
  rule: string;
  notes: SyncNote[];
}

const COUNTER_RE = /^counters\/(d_[a-z2-7]{10})\.yml$/;
const ITEM_FILE_RE = /^[a-z0-9-]+\/items\/([A-Z]{2,4}-[A-HJ-NP-Z]?[1-9][0-9]*)\.md$/;
const DEVICE_ID_RE = /^d_[a-z2-7]{10}$/;
const EMAIL_RE = /^(d_[a-z2-7]{10})@devices\.agent-ledger\.invalid$/;
const MAX_NOTES = 20;

/** Committer e-mail -> claimed device id (`<device_id>@devices.agent-ledger.invalid`). */
export function claimedDeviceFromEmail(email: unknown): string | null {
  const m = typeof email === 'string' ? EMAIL_RE.exec(email) : null;
  return m === null ? null : (m[1] as string);
}

const shortSha = (sha: unknown): string => (typeof sha === 'string' && /^[0-9a-f]{40,64}$/.test(sha) ? sha.slice(0, 12) : '?');

function parseOrNull(text: string | null): DevicesFile | null {
  if (text === null) return null;
  try {
    return parseDevicesYaml(text);
  } catch {
    return null;
  }
}

const canonKey = (k: string): string | null => parseEd25519Pub(k)?.line ?? null;

type SignerStatus = 'none' | 'revoked' | 'trusted' | 'unapproved' | 'unknown';

/** Signer status derived from the devices.yml of EVERY parent. Revoked in any parent
 *  wins; otherwise the key must be registered in all of them. */
export function signerStatus(
  sig: GateSignature,
  parents: readonly (DevicesFile | null)[],
  trusted: ReadonlySet<string>,
): { status: SignerStatus; entry: DeviceEntry | null; pub: string | null } {
  const pub = sig.valid === true && typeof sig.pubkey === 'string' ? canonKey(sig.pubkey) : null;
  if (pub === null) return { status: 'none', entry: null, pub: null };
  const entries = parents.map((p) => p?.devices.find((d) => canonKey(d.pubkey) === pub) ?? null);
  if (entries.some((e) => e !== null && e.revoked !== null)) return { status: 'revoked', entry: null, pub };
  if (parents.length === 0 || entries.some((e) => e === null)) return { status: 'unknown', entry: null, pub };
  const approved = [...trusted].some((t) => typeof t === 'string' && canonKey(t) === pub);
  return { status: approved ? 'trusted' : 'unapproved', entry: entries[0] as DeviceEntry, pub };
}

function normCounters(text: string | undefined): string | null {
  try {
    return mergeCounters(null, text ?? '', text ?? '').merged;
  } catch {
    return null;
  }
}

/** Merge commit: devices.yml and counters must be exactly what the typed mergers give. */
function mergeProblem(input: GateInput): string | null {
  const m = input.merge;
  if (m === undefined) return 'merge-input-missing';
  const [p1, p2] = input.parentDevices as readonly [string | null, string | null];
  const exp = mergeDevicesNullable(m.baseDevices, p1, p2);
  if (!exp.ok) return 'merge-devices';
  if (exp.merged !== input.devicesText) return 'merge-devices';
  const paths = new Set<string>([...m.baseCounters.keys(), ...m.parentCounters[0].keys(), ...m.parentCounters[1].keys(), ...m.mergedCounters.keys()]);
  for (const path of paths) {
    if (!COUNTER_RE.test(path)) return 'merge-counters';
    let want: string;
    try {
      want = mergeCounters(m.baseCounters.get(path) ?? null, m.parentCounters[0].get(path) ?? '', m.parentCounters[1].get(path) ?? '').merged;
    } catch {
      return 'merge-counters';
    }
    const got = m.mergedCounters.has(path) ? normCounters(m.mergedCounters.get(path)) : null;
    if (got === null || got !== normCounters(want)) return 'merge-counters';
  }
  return null;
}

export function gateCommit(input: GateInput): GateVerdict {
  const notes: SyncNote[] = [];
  const short = shortSha(input?.sha);
  const note = (type: SyncNote['type'], rule: string, detail: string, path?: string): void => {
    if (notes.length >= MAX_NOTES) return;
    notes.push({ type, rule, detail: safeOutput(`${detail} (commit ${short})`, 200), ...(path === undefined ? {} : { path: safeOutput(path, 120) }) });
  };
  const quarantine = (rule: string, detail: string, type: SyncNote['type'] = 'sync.reject'): GateVerdict => {
    note(type, rule, detail);
    return { action: 'quarantine', rule, notes };
  };

  try {
    const warn = input.mode === 'warn'; // anything else is enforce (fail closed)
    const parents = Array.isArray(input.parentDevices) ? input.parentDevices : null;
    if (parents === null || !Array.isArray(input.changes) || input.ingress === null || typeof input.ingress !== 'object' || !Array.isArray(input.ingress.rejected)) {
      return quarantine('malformed-input', 'gate input malformed');
    }
    if (parents.length > 2) return quarantine('merge-octopus', 'merge commit with more than two parents');

    /* rows 1-3: content */
    const rejected = input.ingress.rejected.filter((r) => r !== null && typeof r === 'object');
    const structural = rejected.filter((r) => r.rule !== 'delete' && r.rule !== 'secret');
    if (structural.length > 0) {
      const sorted = [...structural].sort((a, b) => (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
      for (const r of sorted) note('sync.reject', `ingress:${safeOutput(String(r.rule), 30)}`, `ingress rule ${safeOutput(String(r.rule), 30)}`, String(r.path));
      return { action: 'quarantine', rule: `ingress:${safeOutput(String(sorted[0]?.rule), 30)}`, notes };
    }
    const secrets = rejected.filter((r) => r.rule === 'secret');
    if (secrets.length > 0) {
      // path + rule only, never the matched text
      for (const r of secrets) note('sync.secret', 'secret', 'secret scanner hit', String(r.path));
      return { action: 'quarantine', rule: 'secret', notes };
    }
    const softDeletes = rejected.filter((r) => r.rule === 'delete');

    /* parents / devices change */
    const parsedParents = parents.map(parseOrNull);
    const isMerge = parents.length === 2;
    const parent0 = parents[0] ?? null;
    // merge: registry changed relative to ANY parent (not only P1) -> same strictness as a plain change
    const devicesChanged = isMerge ? parents.some((p) => input.devicesText !== p) : input.devicesText !== parent0;
    if (softDeletes.length > 0 && devicesChanged) {
      return quarantine('delete-with-devices', 'item delete together with a devices.yml change');
    }

    /* row 4: merge commits */
    if (isMerge) {
      const problem = mergeProblem(input);
      if (problem !== null) return quarantine(problem, `merge commit does not match the typed merge (${problem})`);
    }

    /* rows 5-6 */
    const signer = signerStatus(input.signature, parsedParents, input.trusted);
    if (signer.status === 'revoked') return quarantine('revoked-signer', 'commit signed by a key revoked in a parent');
    if (signer.pub !== null && input.currentDevices !== undefined && input.currentDevices !== null) {
      const cur = parseOrNull(input.currentDevices);
      if (cur === null) return quarantine('revoked-current', 'current devices.yml is invalid, signer cannot be checked');
      if (cur.devices.some((d) => d.revoked !== null && canonKey(d.pubkey) === signer.pub)) {
        return quarantine('revoked-current', 'commit signed by a key revoked in the current registry');
      }
    }
    const claimed = typeof input.claimedDevice === 'string' && DEVICE_ID_RE.test(input.claimedDevice) ? input.claimedDevice : null;
    if (signer.pub !== null && claimed !== null && parseEd25519Pub(signer.pub)?.deviceId !== claimed) {
      return quarantine('email-mismatch', 'committer e-mail names a different device than the signing key');
    }

    /* row 7: ownership (merge commits are covered by the per-key max rule) */
    if (!isMerge) {
      const owner = signer.entry ?? (claimed === null ? null : (parsedParents[0]?.devices.find((d) => d.id === claimed) ?? null));
      if (owner !== null) {
        for (const c of input.changes) {
          const m = typeof c?.path === 'string' ? COUNTER_RE.exec(c.path) : null;
          if (m !== null && m[1] !== owner.id) return quarantine('counters-foreign', `counter file of ${m[1]} changed by ${owner.id}`);
          const im = typeof c?.path === 'string' ? ITEM_FILE_RE.exec(c.path) : null;
          if (im !== null && c.status !== 'M' && c.status !== 'D') {
            const slot = parseItemId(im[1] as string)?.slot;
            if (slot !== owner.slot) return quarantine('item-slot', `item ${im[1]} created by ${owner.id} carries another device's slot`);
          }
        }
      }
    }

    /* row 8: signer x devices change x mode */
    let outcome: 'accept' | 'warn';
    let warnNote: [SyncNote['type'], string, string] | null = null;
    switch (signer.status) {
      case 'trusted': {
        // merge: content already proven equal to the typed merge of two gated sides (row 4)
        if (devicesChanged && !isMerge) {
          if (input.devicesText === null) return quarantine('devices:deleted', 'devices.yml deleted');
          const base = parsedParents[0] ?? null;
          if (parent0 !== null && base === null) return quarantine('devices:invalid-base', 'parent devices.yml is invalid');
          let incoming: DevicesFile;
          try {
            incoming = parseDevicesYaml(input.devicesText);
          } catch {
            return quarantine('devices:invalid-incoming', 'devices.yml of the commit is invalid');
          }
          const res = acceptDevicesChange(base, incoming, signer.pub as string, input.trusted, { commitTimeMs: input.commitTimeMs });
          if (!res.ok) return quarantine(`devices:${res.reason}`, `devices.yml change refused (${res.reason})`);
          const self = res.revokes.ids.includes(input.localDevice);
          if (res.revokes.root || self) {
            const haltReason: HaltReason = self ? 'quarantine:revocation-self' : 'quarantine:revocation-root';
            note('sync.reject', haltReason === 'quarantine:revocation-self' ? 'revocation-self' : 'revocation-root', 'revocation of the root or this device is held for human confirmation');
            return { action: 'halt', haltReason, rule: haltReason === 'quarantine:revocation-self' ? 'revocation-self' : 'revocation-root', notes };
          }
        }
        outcome = 'accept';
        break;
      }
      case 'unapproved':
        if (devicesChanged) return quarantine('unapproved-devices', 'devices.yml change from a key not approved on this device');
        if (!warn) return quarantine('unapproved', 'signer is registered but not approved on this device');
        outcome = 'warn';
        warnNote = ['sync.unverified', 'unapproved', 'signed by a registered key not approved on this device'];
        break;
      case 'unknown':
        if (devicesChanged) return quarantine('unknown-devices', 'devices.yml change from an unregistered key');
        if (!warn) return quarantine('unknown-key', 'signer key is not registered');
        outcome = 'warn';
        warnNote = ['sync.warning', 'unknown-key', 'signed by a key that is not registered'];
        break;
      default: {
        // unsigned / bad signature
        if (devicesChanged) return quarantine('unsigned-devices', 'devices.yml change without a valid signature');
        if (!warn) return quarantine('unsigned', 'commit has no valid signature');
        if (claimed !== null && input.seenSigning.has(claimed)) {
          return quarantine('unsigned-ratchet', 'unsigned commit claims a device that has signed before');
        }
        outcome = 'warn';
        warnNote = ['sync.warning', 'unsigned', 'commit has no valid signature (warn mode)'];
      }
    }
    if (warnNote !== null) note(warnNote[0], warnNote[1], warnNote[2]);
    if (softDeletes.length > 0) {
      for (const r of softDeletes) note('sync.reject', 'delete', 'item delete reverted, item kept', String(r.path));
      return { action: 'forced-merge-keep-items', rule: 'item-delete', notes };
    }
    return outcome === 'accept' ? { action: 'accept', rule: 'ok', notes } : { action: 'accept-warn', rule: warnNote?.[1] ?? 'warn', notes };
  } catch {
    return { action: 'quarantine', rule: 'internal', notes: [{ type: 'sync.reject', rule: 'internal', detail: `gate failed (commit ${short})` }] };
  }
}

const PRECEDENCE: Record<GateAction, number> = { halt: 4, quarantine: 3, 'forced-merge-keep-items': 2, 'accept-warn': 1, accept: 0 };

/** Worst verdict of a range (a halt beats a quarantine beats a forced merge …). */
export function gateRange(verdicts: readonly GateVerdict[]): GateVerdict {
  let worst: GateVerdict = { action: 'accept', rule: 'empty-range', notes: [] };
  const notes: SyncNote[] = [];
  for (const v of verdicts) {
    notes.push(...v.notes);
    if (PRECEDENCE[v.action] > PRECEDENCE[worst.action] || worst.rule === 'empty-range') worst = v;
  }
  const out: GateVerdict = { action: worst.action, rule: worst.rule, notes };
  if (worst.haltReason !== undefined) out.haltReason = worst.haltReason;
  return out;
}
