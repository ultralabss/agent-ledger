/** `SyncLoop`: triggers, single-flight, backoff and halt gating around `runCycle` (F3b B3c, docs/f3b-b3-plan.md
 *  §1.5, §3 (SF), §4; invariant 14).
 *
 *  Threat model:
 *   - Actor: a flapping network, a storm of local commits, a CLI/UI caller (B4 routes: loopback only) and a
 *     hostile remote that wants the hub to hammer it or to retry a failed authentication forever.
 *   - Protected: at most one cycle at a time; no remote contact in a `no-contact` / `d2` / `terminal` halt;
 *     `probe` / `sticky` halts contact the remote at most every 15 minutes; `stop()` never kills a cycle in the
 *     middle of APPLY (it waits); clock jumps never freeze or flood the loop (`Math.abs` distances).
 *   - Failure modes: trigger storms (coalesced: one rerun), a human override for a tip that is not overridable,
 *     a confirmation whose fingerprint does not match the key that is being revoked, resume used to skip a halt
 *     that needs a human (it only clears `no-contact` and `sticky`).
 *   - Stance: the loop owns no git. Every state change goes through `StateStore`; nothing from a caller is
 *     written except validated tokens (sha, device id, `SHA256:` fingerprint).
 */

import { parseDevicesYaml, parseEd25519Pub } from '@agent-ledger/shared';
import { runCycle, type CycleDeps, type CycleResult } from './cycle.ts';
import { isSha } from './gitx.ts';
import type { HaltState, SyncState } from './state.ts';
import { isOverridableRule } from './validate.ts';

export interface LoopClock {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const realClock: LoopClock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => {
    const t = setTimeout(fn, ms);
    t.unref?.();
    return t;
  },
  clearTimeout: (h) => clearTimeout(h as NodeJS.Timeout),
};

export interface SyncLoopOptions {
  deps: CycleDeps;
  /** Periodic tick (ms). */
  intervalMs: number;
  /** Debounce for commit triggers (ms, default 5000). */
  debounceMs?: number;
  /** Minimum distance between remote contacts in a `probe` / `sticky` halt (ms, default 15 min). */
  probeMs?: number;
  clock?: LoopClock;
  /** Test seam. */
  cycle?: (deps: CycleDeps) => Promise<CycleResult>;
}

export interface LoopStatus {
  started: boolean;
  running: boolean;
  /** A rerun is queued behind the running cycle. */
  pending: boolean;
  halt: HaltState | null;
  backoff: SyncState['backoff'] | null;
  accepted: string | null;
  lastCycle: SyncState['lastCycle'];
  pushBlocked: SyncState['pushBlocked'];
  /** `state.json` could not be read (corrupt / unsafe): the loop reports it and does nothing else. */
  stateError: boolean;
}

export type LoopAnswer = { ok: true } | { ok: false; reason: string };

const MAX_BACKOFF_FUTURE_MS = 20 * 60_000;
const MAX_COALESCED_RERUNS = 3;
const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
const DEVICE_ID_RE = /^d_[a-z2-7]{10}$/;

export class SyncLoop {
  private readonly deps: CycleDeps;
  private readonly clock: LoopClock;
  private readonly intervalMs: number;
  private readonly debounceMs: number;
  private readonly probeMs: number;
  private readonly cycleFn: (deps: CycleDeps) => Promise<CycleResult>;
  private started = false;
  private stopped = false;
  private running: Promise<void> | null = null;
  private rerun = false;
  private rerunForce = false;
  private tick: unknown = null;
  private debounce: unknown = null;
  private lastContact: number | null = null;

  constructor(o: SyncLoopOptions) {
    this.deps = o.deps;
    this.clock = o.clock ?? realClock;
    this.intervalMs = Math.max(1000, o.intervalMs);
    this.debounceMs = o.debounceMs ?? 5000;
    this.probeMs = o.probeMs ?? 15 * 60_000;
    this.cycleFn = o.cycle ?? runCycle;
  }

  /** Start ticking and run one cycle now. */
  start(): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.schedule();
    this.kick(false);
  }

  /** Stop scheduling and WAIT for a running cycle (never kills one mid-APPLY). */
  async stop(): Promise<void> {
    this.stopped = true;
    if (this.tick !== null) this.clock.clearTimeout(this.tick);
    if (this.debounce !== null) this.clock.clearTimeout(this.debounce);
    this.tick = null;
    this.debounce = null;
    this.rerun = false;
    while (this.running !== null) await this.running;
  }

  /** Ask for a cycle. `commit` triggers are debounced; everything else coalesces into at most one rerun. */
  trigger(why: string): void {
    if (this.stopped) return;
    if (why === 'commit') {
      if (this.debounce !== null) return;
      this.debounce = this.clock.setTimeout(() => {
        this.debounce = null;
        this.kick(false);
      }, this.debounceMs);
      return;
    }
    this.kick(why === 'manual');
  }

  private schedule(): void {
    if (this.stopped) return;
    this.tick = this.clock.setTimeout(() => {
      this.tick = null;
      this.kick(false);
      this.schedule();
    }, this.intervalMs);
  }

  private kick(force: boolean): void {
    if (this.stopped) return;
    if (this.running !== null) {
      this.rerun = true;
      this.rerunForce ||= force;
      return;
    }
    this.running = this.loopOnce(force).finally(() => {
      this.running = null;
    });
  }

  private async loopOnce(force: boolean): Promise<void> {
    let f = force;
    for (let i = 0; i <= MAX_COALESCED_RERUNS; i += 1) {
      this.rerun = false;
      this.rerunForce = false;
      try {
        if ((await this.gate(f)) === 'run') {
          this.lastContact = this.clock.now();
          await this.cycleFn(this.deps);
        }
      } catch {
        this.deps.log('sync: cycle crashed outside runCycle');
      }
      if (!this.rerun || this.stopped) return;
      f = this.rerunForce;
    }
  }

  /** May this tick run a cycle? (`force` = a human asked: backoff and the probe distance do not apply.) */
  private async gate(force: boolean): Promise<'run' | 'skip'> {
    let st: SyncState;
    try {
      st = await this.deps.state.read();
    } catch {
      return force ? 'run' : 'skip'; // a corrupt state file is reported by status(); the cycle halts `config`
    }
    const now = this.clock.now();
    const h = st.halt;
    if (h !== null) {
      switch (h.cls) {
        case 'no-contact':
        case 'terminal':
          return 'skip'; // invariant 14: no contact, no retry
        case 'd2': {
          const d2 = h.d2;
          const confirmed =
            d2 !== null &&
            d2.kind === 'root' &&
            d2.deviceIds.every((id) => st.confirmations.some((c) => c.kind === 'root' && c.commit === d2.commit && c.device_id === id));
          if (!confirmed && !(d2?.kind === 'self' && st.confirmations.some((c) => c.kind === 'self' && c.commit === d2.commit))) return 'skip';
          break;
        }
        case 'probe':
        case 'sticky': {
          const overridden = h.tip !== null && st.overrides.some((o) => o.tip === h.tip);
          if (!force && !overridden) {
            const last = this.lastContact ?? (st.lastCycle === null ? null : Date.parse(st.lastCycle.at));
            if (last !== null && Number.isFinite(last) && Math.abs(now - last) < this.probeMs) return 'skip';
          }
          break;
        }
        default: // 'local': re-checked every tick
      }
    }
    if (!force && st.backoff.nextAt !== null) {
      const d = Date.parse(st.backoff.nextAt) - now;
      if (Number.isFinite(d) && d > 0 && d <= MAX_BACKOFF_FUTURE_MS) return 'skip'; // far-future = the clock jumped: run
    }
    return 'run';
  }

  async status(): Promise<LoopStatus> {
    let st: SyncState | null = null;
    try {
      st = await this.deps.state.read();
    } catch {
      st = null;
    }
    return {
      started: this.started && !this.stopped,
      running: this.running !== null,
      pending: this.rerun,
      halt: st?.halt ?? null,
      backoff: st?.backoff ?? null,
      accepted: st?.accepted ?? null,
      lastCycle: st?.lastCycle ?? null,
      pushBlocked: st?.pushBlocked ?? null,
      stateError: st === null,
    };
  }

  /** `sync resume`: clears `no-contact` and `sticky` halts (and the backoff) only, then runs a cycle. */
  async resume(): Promise<{ ok: true; cleared: boolean }> {
    let cleared = false;
    await this.deps.state.update((s) => {
      if (s.halt !== null && (s.halt.cls === 'no-contact' || s.halt.cls === 'sticky')) {
        s.halt = null;
        s.backoff = { failures: 0, nextAt: null, lastError: null };
        cleared = true;
      }
    });
    this.trigger('manual');
    return { ok: true, cleared };
  }

  /** D2: a human confirms the revocation named by the halt. `fp` must equal the fingerprint of the key `id`
   *  has in `devices.yml` AT the revoking commit. A confirmed SELF revocation detaches this device. */
  async confirmRevocation(id: string, fp: string): Promise<LoopAnswer> {
    if (typeof id !== 'string' || !DEVICE_ID_RE.test(id) || typeof fp !== 'string' || !FP_RE.test(fp)) return { ok: false, reason: 'invalid-input' };
    let st: SyncState;
    try {
      st = await this.deps.state.read();
    } catch {
      return { ok: false, reason: 'state-unreadable' };
    }
    const h = st.halt;
    if (h === null || h.cls !== 'd2' || h.d2 === null) return { ok: false, reason: 'no-revocation-halt' };
    const d2 = h.d2;
    if (!d2.deviceIds.includes(id)) return { ok: false, reason: 'unknown-device' };
    let keyFp: string | undefined;
    try {
      const entries = await this.deps.store.lsTree(d2.commit);
      const devices = entries.find((e) => e.path === 'devices.yml');
      if (devices === undefined) return { ok: false, reason: 'registry-missing' };
      const text = (await this.deps.store.readObject(devices.sha, 'blob')).toString('utf8');
      const entry = parseDevicesYaml(text).devices.find((x) => x.id === id);
      keyFp = entry === undefined ? undefined : parseEd25519Pub(entry.pubkey)?.fingerprint;
    } catch {
      return { ok: false, reason: 'registry-unreadable' };
    }
    if (keyFp === undefined || keyFp !== fp) return { ok: false, reason: 'fingerprint-mismatch' };
    const at = new Date(this.clock.now()).toISOString();
    await this.deps.state.update((s) => {
      s.confirmations = s.confirmations.filter((c) => !(c.commit === d2.commit && c.device_id === id));
      s.confirmations.push({ kind: d2.kind, device_id: id, commit: d2.commit, fp, at });
      if (d2.kind === 'self' && s.halt !== null) {
        s.halt = { reason: 'detached', cls: 'terminal', since: at, tip: s.halt.tip, rule: 'detached', detail: 'this device was revoked by a peer (confirmed): sync stopped, local work continues', d2: null };
      }
    });
    this.trigger('manual');
    return { ok: true };
  }

  /** `sync accept <sha>`: record an operator override for exactly the quarantined tip. Signature rows, e-mail
   *  mismatch and per-commit ingress hits only (OQ-B); `secret` additionally needs `secretAck` (OQ-C). The
   *  next cycle re-validates with the override, so layer T and every non-overridable rule still apply. */
  async acceptQuarantine(sha: string, o: { secretAck?: boolean } = {}): Promise<LoopAnswer> {
    if (!isSha(sha)) return { ok: false, reason: 'invalid-input' };
    let st: SyncState;
    try {
      st = await this.deps.state.read();
    } catch {
      return { ok: false, reason: 'state-unreadable' };
    }
    const h = st.halt;
    if (h === null || !h.reason.startsWith('quarantine:') || h.cls !== 'probe') return { ok: false, reason: 'no-quarantine' };
    if (h.tip !== sha) return { ok: false, reason: 'tip-mismatch' };
    if (h.rule === null || !isOverridableRule(h.rule)) return { ok: false, reason: 'not-overridable' };
    if (h.rule === 'secret' && o.secretAck !== true) return { ok: false, reason: 'secret-acknowledgement-required' };
    const at = new Date(this.clock.now()).toISOString();
    await this.deps.state.update((s) => {
      s.overrides = s.overrides.filter((x) => x.tip !== sha);
      s.overrides.push({ tip: sha, at, ...(o.secretAck === true ? { secretAck: true } : {}) });
    });
    this.trigger('manual');
    return { ok: true };
  }
}
