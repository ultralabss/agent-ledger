/** Device add on an ENROLLED ledger: the push-first slot compare-and-swap (F3b B4c, docs/f3b-b4-plan.md §1.3;
 *  T-B4-4, T-B4-9, T-B4-7; invariants 2, 3, 8, 9, 11).
 *
 *  Threat model:
 *   - Actor: two trusted devices adding two different joiners at the same moment (same lowest free slot), a
 *     remote that times out after receiving the push, an attacker who hands the operator a key (wrong fingerprint),
 *     a caller that retries a route forever (the single-flight slot is bounded by `exclusiveOp`'s budget).
 *   - Protected: a `devices.yml` addition reaches `main` of this ledger only AFTER the remote accepted exactly that
 *     commit; the remote's fast-forward rule is the only arbiter (no force, no lease). A lost race leaves an
 *     unreferenced commit object and nothing else: `main`, `accepted` and the worktree are never touched before
 *     the push succeeded. The key is registered only when the human-typed fingerprint equals the key's own.
 *   - Failure modes: unknown push outcome (timeout) -> a fetch decides (tip == C: it landed, else drop and retry
 *     with a fresh slot); crash after the push and before the local apply (A1: the next cycle fast-forwards,
 *     approval is repeated by re-running the add, which is idempotent); the device lock is never held across the
 *     network or a prompt (only the final approval takes it, innermost).
 *   - Stance: APPLY is not reimplemented. After a successful push the standard cycle fetches C, validates the
 *     range, runs `applyRemote` (fast-forward, inflight marker, reindex) and moves `accepted` by CAS. Results
 *     carry fixed codes only: no URL, stderr or key material leaves this module.
 */

import { timingSafeEqual } from 'node:crypto';
import nodePath from 'node:path';
import {
  DEVICES_MAX_BYTES,
  DevicesError,
  acceptDevicesChange,
  approveLocked,
  deviceLayout,
  labelSchema,
  parseDevicesYaml,
  parseEd25519Pub,
  planAddDevice,
  publicKeyOf,
  readDevices,
  renderDevicesYaml,
  withDeviceLock,
  type DevicesFile,
} from '@agent-ledger/shared';
import { classifyNetError, type CycleDeps } from './cycle.ts';
import { REF_ACCEPTED, REF_INCOMING, REF_MAIN, isSha } from './gitx.ts';
import { ExclusiveOpError, type ExclusiveCtx, type SyncLoop } from './loop.ts';
import { verifyCommitSignature } from './sigverify.ts';
import { egressSelfCheck } from './validate.ts';

export interface AddSyncedInput {
  /** Canonical `ssh-ed25519 <base64>` of the joiner. */
  pubkey: string;
  label: string;
  /** `SHA256:…` the human read off the joiner's screen. */
  fp: string;
}

export type AddSyncedCode =
  | 'INVALID'
  | 'FP_MISMATCH'
  | 'HALTED'
  | 'NOT_SYNCED'
  | 'NOT_MEMBER'
  | 'SLOT_BUSY'
  | 'SLOTS_EXHAUSTED'
  | 'REFUSED'
  | 'REMOTE'
  | 'LOCAL'
  | 'BUSY'
  | 'TIMEOUT'
  | 'STOPPED';

export type AddSyncedResult =
  | {
      ok: true;
      id: string;
      slot: string;
      fp: string;
      /** The commit that registered the device (`null` when it was registered already). */
      commit: string | null;
      /** The registration is in this ledger's worktree (`main`). */
      applied: boolean;
      /** The key is trusted on this device (`allowed_signers`). */
      approved: boolean;
      /** Registered before this call (idempotent re-run). */
      existing: boolean;
    }
  | { ok: false; code: AddSyncedCode };

export interface AddSyncedOptions {
  /** Default 3. */
  maxAttempts?: number;
  /** Epoch ms used for `added` and the commit time (they must agree: time binding). */
  now?: () => number;
  /** Test seam; production = `approveLocked` under the device lock. */
  approve?: (deps: CycleDeps, id: string, fp: string) => Promise<{ added: boolean }>;
  /** Test seam: called after the named step; throw to simulate a crash. */
  crashAt?: (point: 'built' | 'pushed') => void | Promise<void>;
}

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
const MAX_ATTEMPTS = 3;
const SYNCED = new Set(['applied', 'up-to-date', 'pushed']);

const fail = (code: AddSyncedCode): AddSyncedResult => ({ ok: false, code });

function fpEqual(given: string, actual: string): boolean {
  const a = Buffer.from(given);
  const b = Buffer.from(actual);
  return a.length === b.length && timingSafeEqual(a, b);
}

type Built =
  | { kind: 'built'; L: string; C: string; id: string; slot: string }
  | { kind: 'existing'; id: string; slot: string }
  | { kind: 'retry' }
  | { kind: 'fail'; code: AddSyncedCode };

/** Add a device through the sync loop's exclusive slot. NEVER throws. */
export async function addDeviceSynced(loop: SyncLoop, input: AddSyncedInput, opts: AddSyncedOptions = {}): Promise<AddSyncedResult> {
  const pub = typeof input.pubkey === 'string' ? parseEd25519Pub(input.pubkey) : null;
  if (pub === null || pub.line !== input.pubkey) return fail('INVALID');
  if (typeof input.label !== 'string' || !labelSchema.safeParse(input.label).success) return fail('INVALID');
  if (typeof input.fp !== 'string' || !FP_RE.test(input.fp)) return fail('INVALID');
  if (!fpEqual(input.fp, pub.fingerprint)) return fail('FP_MISMATCH');
  try {
    return await loop.exclusiveOp((deps, ctx) => run(deps, ctx, { pub, label: input.label, fp: pub.fingerprint }, opts));
  } catch (err) {
    if (err instanceof ExclusiveOpError) return fail(err.code);
    return fail('LOCAL');
  }
}

interface Target {
  pub: NonNullable<ReturnType<typeof parseEd25519Pub>>;
  label: string;
  fp: string;
}

async function run(deps: CycleDeps, ctx: ExclusiveCtx, t: Target, opts: AddSyncedOptions): Promise<AddSyncedResult> {
  const attempts = opts.maxAttempts ?? MAX_ATTEMPTS;
  const now = opts.now ?? ((): number => Date.now());
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (ctx.expired()) return fail('TIMEOUT');
    // 1. everything local is pushed, nothing is halted (the gate is the loop's, not ours)
    const pre = await synced(deps, ctx);
    if (pre !== null) return fail(pre);
    // 2. plan + build under R -> Q, WITHOUT moving main
    const b = await build(deps, t, now());
    if (b.kind === 'fail') return fail(b.code);
    if (b.kind === 'retry') continue;
    if (b.kind === 'existing') return finish(deps, t, opts, { id: b.id, slot: b.slot, commit: null, existing: true });
    if (opts.crashAt !== undefined) await opts.crashAt('built');
    if (ctx.expired()) return fail('TIMEOUT');
    // 3. push-first: the remote's fast-forward rule is the arbiter
    let landed: boolean;
    try {
      const pr = await deps.gitx.push(deps.ledgerDir, deps.remote, b.C, { timeoutMs: deps.net?.pushMs ?? 30_000 });
      if (pr.ok) {
        landed = true;
      } else {
        const cls = classifyNetError(pr);
        if (!pr.timedOut && (cls === 'auth' || cls === 'hostkey')) return fail('REMOTE'); // never retried (invariant 14)
        if (!pr.timedOut && cls === 'non-ff') continue; // CAS lost: C is unreferenced, the next attempt re-syncs and takes a fresh slot
        // a timeout, or a failure that is not clearly a refusal (a remote ref lock lost in a race reads like one):
        // the outcome is unknown, so the remote decides. If it cannot even be asked nothing local has changed (A1).
        if (!(await fetched(deps))) return fail('REMOTE');
        landed = (await deps.store.revParse(REF_INCOMING)) === b.C;
      }
    } catch {
      return fail('LOCAL');
    }
    if (!landed) continue;
    if (opts.crashAt !== undefined) await opts.crashAt('pushed');
    // 4. the standard cycle fast-forwards main to C (APPLY) and moves accepted by CAS; then approve
    if (!ctx.expired()) {
      try {
        await ctx.cycle();
      } catch (err) {
        if (err instanceof ExclusiveOpError && err.code !== 'TIMEOUT') return fail(err.code);
        // the push landed: whatever the apply did, the next cycle finishes it (A1)
      }
    }
    return finish(deps, t, opts, { id: b.id, slot: b.slot, commit: b.C, existing: false });
  }
  return fail('SLOT_BUSY');
}

/** One cycle; require no halt and an up-to-date result. Returns a failure code or `null`. */
async function synced(deps: CycleDeps, ctx: ExclusiveCtx): Promise<AddSyncedCode | null> {
  try {
    if ((await deps.state.read()).halt !== null) return 'HALTED';
  } catch {
    return 'NOT_SYNCED';
  }
  let res;
  try {
    res = await ctx.cycle();
  } catch (err) {
    return err instanceof ExclusiveOpError ? err.code : 'NOT_SYNCED';
  }
  if (res.halted !== undefined) return 'HALTED';
  return SYNCED.has(res.outcome) ? null : 'NOT_SYNCED';
}

async function build(deps: CycleDeps, t: Target, nowMs: number): Promise<Built> {
  try {
    return await deps.host.runExclusive((x) =>
      deps.host.queueRun(async (): Promise<Built> => {
        const oc = await x.commitNow(); // pending local writes become a commit by THIS section: no flush() (deadlock)
        if (oc !== 'clean' && oc !== 'committed') return { kind: 'fail', code: 'NOT_SYNCED' };
        const L = await deps.store.revParse(REF_MAIN);
        const A = await deps.store.revParse(REF_ACCEPTED);
        if (L === null || A === null) return { kind: 'fail', code: 'NOT_SYNCED' };
        if (L !== A) return { kind: 'retry' }; // a local commit appeared: the next cycle pushes it first

        const entries = await deps.store.lsTree(L);
        const file = entries.find((e) => e.path === 'devices.yml');
        if (file === undefined) return { kind: 'fail', code: 'REFUSED' };
        let devices: DevicesFile;
        try {
          devices = parseDevicesYaml((await deps.store.readObject(file.sha, 'blob')).toString('utf8'));
        } catch {
          return { kind: 'fail', code: 'REFUSED' };
        }
        const self = await publicKeyOf(deps.signing.keyFile, deps.signing.sshKeygenBin);
        const mine = devices.devices.find((d) => d.id === deps.localDevice);
        if (mine === undefined || mine.revoked !== null || mine.pubkey !== self.line) return { kind: 'fail', code: 'NOT_MEMBER' };

        let plan;
        try {
          plan = planAddDevice(devices, deps.localDevice, t.pub, t.label, nowMs);
        } catch (err) {
          if (err instanceof DevicesError) {
            if (err.code === 'DEVICE_EXISTS') {
              const known = devices.devices.find((d) => d.id === t.pub.deviceId && d.pubkey === t.pub.line);
              return known === undefined ? { kind: 'fail', code: 'REFUSED' } : { kind: 'existing', id: known.id, slot: known.slot };
            }
            if (err.code === 'SLOTS_EXHAUSTED') return { kind: 'fail', code: 'SLOTS_EXHAUSTED' };
            if (err.code === 'LABEL_INVALID') return { kind: 'fail', code: 'INVALID' };
          }
          return { kind: 'fail', code: 'REFUSED' };
        }
        const verdict = acceptDevicesChange(devices, plan.next, self.line, await deps.trusted(), { commitTimeMs: nowMs });
        if (!verdict.ok) return { kind: 'fail', code: 'REFUSED' };
        const text = renderDevicesYaml(plan.next);
        if (Buffer.byteLength(text, 'utf8') > DEVICES_MAX_BYTES) return { kind: 'fail', code: 'REFUSED' };

        const tree = await deps.trees.buildTree(L, [{ path: 'devices.yml', content: text }]);
        const C = await deps.trees.commitTree({
          tree,
          parents: [L],
          message: `ledger: add device ${plan.entry.slot} ${t.label}`,
          identity: deps.identity,
          signing: deps.signing,
          date: new Date(nowMs),
        });
        if (!isSha(C)) return { kind: 'fail', code: 'LOCAL' };
        // invariant 8: a commit that does not verify against our own key is never pushed
        const sig = await verifyCommitSignature(await deps.store.readCommitRaw(C), {
          tmpRoot: nodePath.join(deps.ledgerDir, '.hub', 'sync', 'tmp'),
          bin: deps.signing.sshKeygenBin,
        });
        if (!sig.valid || sig.pubkeyLine !== self.line) return { kind: 'fail', code: 'LOCAL' };
        // invariant 12: nothing our own ingress would reject goes out
        const eg = await egressSelfCheck(deps.store, { A: L, L: C, maxFormat: deps.maxFormat });
        if (!eg.ok) return { kind: 'fail', code: 'REFUSED' };
        return { kind: 'built', L, C, id: plan.entry.id, slot: plan.entry.slot };
      }),
    );
  } catch (err) {
    void err; // local-side failure: nothing was pushed, nothing is echoed
    return { kind: 'fail', code: 'LOCAL' };
  }
}

/** Fetch `main` into the scratch ref; `false` = the remote could not be asked. */
async function fetched(deps: CycleDeps): Promise<boolean> {
  try {
    return (await deps.gitx.fetch(deps.ledgerDir, deps.remote, { timeoutMs: deps.net?.fetchMs ?? 20_000 })).ok;
  } catch {
    return false;
  }
}

/** Approve under the device lock (innermost, no network) when the registration is in the worktree. */
async function finish(
  deps: CycleDeps,
  t: Target,
  opts: AddSyncedOptions,
  r: { id: string; slot: string; commit: string | null; existing: boolean },
): Promise<AddSyncedResult> {
  let applied = false;
  try {
    const devices = await readDevices(deviceLayout(deps.ledgerDir));
    applied = devices?.devices.some((d) => d.id === r.id && d.pubkey === t.pub.line && d.revoked === null) === true;
  } catch {
    applied = false;
  }
  let approved = false;
  if (applied) {
    const approve =
      opts.approve ?? ((d: CycleDeps, id: string, fp: string) => withDeviceLock(d.ledgerDir, () => approveLocked(d.ledgerDir, id, fp), { waitMs: 2000 }));
    try {
      await approve(deps, r.id, t.fp);
      approved = true;
    } catch {
      // the registration is applied and stays: say so (approved=false), re-running the add repeats the approval
      approved = false;
    }
  }
  return { ok: true, id: r.id, slot: r.slot, fp: t.fp, commit: r.commit, applied, approved, existing: r.existing };
}
