/** One sync cycle: PRECHECK -> COMMIT_PENDING -> FETCH -> ANCESTRY -> VALIDATE -> APPLY -> PUSH
 *  (F3b B3c, docs/f3b-b3-plan.md §1.4, §4, §5; T-B3-1/2/7/9/10/11, invariants 1, 2, 12, 14).
 *
 *  Threat model:
 *   - Actor: a hostile or broken remote (rewrites history, rolls back, floods, lies about a push), a flaky
 *     network, a crash anywhere in the cycle, a local ledger that keeps being written while we work.
 *   - Protected: `main` and `refs/ledger-sync/accepted` only move forward by compare-and-swap to a validated,
 *     remote-seen descendant; nothing unvalidated is applied; nothing the hub's own ingress would reject is
 *     pushed; auth / host-key failures are never retried (inv 14); a D2 revocation needs a human.
 *   - Failure modes: history rewrite / rollback (HALT `history-rewrite`), mirror tamper (HALT `config`),
 *     validation storms (same-tip skip, strikes), push ping-pong (3 refetches then backoff), unknown push
 *     outcome (transient; the next fetch decides), warn-note commits that two hubs would trade forever.
 *   - Stance: `runCycle` NEVER throws (the only exception is the test seam `CrashError`). Remote-side failures
 *     quarantine, local-side ones back off. Nothing from stderr, a URL or blob content reaches state, logs or
 *     the journal: tokens only. Warn-notes never create commits here (the host writes at most one line per
 *     (rule, device) per 24 h through its ordinary write path). No `--force`, `-f` or `+refs/heads`.
 */

import { readFile } from 'node:fs/promises';
import nodePath from 'node:path';
import { safeOutput } from '@agent-ledger/shared';
import { CrashError, applyRemote, replayInflight, type ApplyDeps, type ApplyHost } from './apply.ts';
import type { VerifyMode } from './gate.ts';
import { GitxError, REF_ACCEPTED, REF_INCOMING, REF_MAIN, checkGitConfig, type GitxResult } from './gitx.ts';
import type { ProposedItem } from './merge/tree.ts';
import type { SyncNote } from './merge/types.ts';
import { StateError, confirmationKey, nextBackoff, type HaltReason, type HaltState, type SyncState } from './state.ts';
import { TreeBuildError } from './treebuild.ts';
import { egressSelfCheck, validateRange } from './validate.ts';

/* ---------------- deps ---------------- */

export interface LocalNote {
  type: string;
  rule: string;
  device: string | null;
  detail: string;
}

export interface CycleHost extends ApplyHost {
  /** Commit what is pending (the host's own debounce path); no lock held. */
  flushLocal(): Promise<void>;
  /** At most one line per (rule, device) per 24 h reaches this (the cycle rate-limits). Never a commit by the cycle. */
  noteLocal(notes: readonly LocalNote[]): Promise<void>;
  /** Hub-proposed items (CONTEXT.md conflicts); called OUTSIDE every lock, after the apply. */
  createProposed(items: readonly ProposedItem[]): Promise<void>;
}

export interface CycleDeps extends ApplyDeps {
  /** Validated URL from `.hub/sync.yml` (re-validated by `Gitx` at every use). */
  remote: string;
  host: CycleHost;
  /** `LEDGER_SYNC_VERIFY`. */
  verify: VerifyMode;
  /** Canonical pubkey lines approved on this device (`.hub/allowed_signers`). */
  trusted(): Promise<ReadonlySet<string>>;
  log(line: string): void;
  rnd?: () => number;
  net?: { fetchMs?: number; pushMs?: number };
  /** Tests only: exact local paths accepted as remote in `.git/config`. */
  testLocalRemotes?: readonly string[];
  sshKeygenBin?: string;
}

export interface CycleResult {
  /** Token (`[a-z0-9:_.-]`): what the cycle ended with. */
  outcome: string;
  halted?: HaltReason;
  applied?: boolean;
  pushed?: boolean;
  refetches: number;
  ms: number;
}

/* ---------------- network classification ---------------- */

export type NetClass = 'auth' | 'hostkey' | 'non-ff' | 'fsck' | 'transient';

/** stderr/stdout patterns of a failed network call. The text itself is NEVER echoed anywhere. */
export function classifyNetError(r: GitxResult): NetClass {
  if (r.timedOut || r.capped) return 'transient';
  const t = `${r.stderr}\n${r.stdout.toString('utf8')}`.toLowerCase();
  if (/host key verification failed|remote host identification has changed|no [a-z0-9-]+ host key is known|host key for .* has changed/.test(t)) return 'hostkey';
  if (/permission denied|authentication failed|access denied|repository not found|denied to deploy key|could not read from remote repository/.test(t)) return 'auth';
  if (/non-fast-forward|\[rejected\]|fetch first|updates were rejected|stale info|\(rejected\)/.test(t)) return 'non-ff';
  if (/fsck|corrupt|bad object|invalid sha1 pointer|unpack-objects failed|index-pack failed/.test(t)) return 'fsck';
  return 'transient';
}

/* ---------------- small helpers ---------------- */

const DAY_MS = 24 * 3600 * 1000;
const HALT_TOKEN = /[^a-z0-9:_.-]/g;
const tok = (s: string): string => {
  const t = s.toLowerCase().replace(HALT_TOKEN, '-').replace(/^[^a-z0-9]+/, '');
  return t.length === 0 ? 'unknown' : t.slice(0, 59);
};

function haltClass(reason: HaltReason): HaltState['cls'] {
  switch (reason) {
    case 'auth':
    case 'hostkey':
      return 'no-contact';
    case 'history-rewrite':
    case 'format':
      return 'sticky';
    case 'config':
    case 'inflight':
      return 'local';
    case 'detached':
      return 'terminal';
    case 'quarantine:revocation-root':
    case 'quarantine:revocation-self':
      return 'd2';
    default:
      return 'probe';
  }
}

class Cycle {
  private readonly d: CycleDeps;
  private readonly t0 = performance.now();
  private refetches = 0;
  constructor(d: CycleDeps) {
    this.d = d;
  }

  private now(): Date {
    return (this.d.now ?? (() => new Date()))();
  }

  /** State update that never throws: a failed write is logged and reported, the cycle ends. */
  private async upd(fn: (s: SyncState) => SyncState | void): Promise<boolean> {
    try {
      await this.d.state.update(fn);
      return true;
    } catch (err) {
      this.d.log(`sync: state write failed (${err instanceof StateError ? err.code : 'error'})`);
      return false;
    }
  }

  async finish(outcome: string, extra: Partial<CycleResult> = {}): Promise<CycleResult> {
    const ms = Math.min(Math.round(performance.now() - this.t0), 24 * 3600 * 1000 - 1);
    const at = this.now().toISOString();
    await this.upd((s) => {
      s.lastCycle = { at, outcome: tok(outcome), ms };
    });
    return { outcome: tok(outcome), refetches: this.refetches, ms, ...extra };
  }

  private async setHalt(
    reason: HaltReason,
    o: { tip?: string | null; rule?: string | null; detail: string; d2?: HaltState['d2'] },
  ): Promise<void> {
    const at = this.now().toISOString();
    await this.upd((s) => {
      const keep = s.halt !== null && s.halt.reason === reason && s.halt.tip === (o.tip ?? null) ? s.halt.since : at;
      s.halt = {
        reason,
        cls: haltClass(reason),
        since: keep,
        tip: o.tip ?? null,
        rule: o.rule === undefined || o.rule === null ? null : tok(o.rule),
        detail: safeOutput(o.detail, 120),
        d2: o.d2 ?? null,
      };
    });
  }

  private async clearHalt(): Promise<void> {
    await this.upd((s) => {
      s.halt = null;
    });
  }

  private async transient(why: string): Promise<CycleResult> {
    const now = this.now().getTime();
    const rnd = this.d.rnd;
    await this.upd((s) => {
      s.backoff.failures += 1;
      s.backoff.nextAt = new Date(now + nextBackoff(s.backoff.failures, rnd)).toISOString();
      s.backoff.lastError = tok(why);
    });
    return this.finish(`transient:${why}`);
  }

  private async success(): Promise<void> {
    await this.upd((s) => {
      if (s.backoff.failures !== 0 || s.backoff.nextAt !== null || s.backoff.lastError !== null) s.backoff = { failures: 0, nextAt: null, lastError: null };
      s.strikes = null;
    });
  }

  /** Move `accepted` F-ward: ref CAS first, then the mirror (a crash between is repaired in PRECHECK). */
  private async casAccepted(from: string, to: string): Promise<void> {
    await this.d.trees.updateRef(REF_ACCEPTED, to, from);
    await this.d.state.update((s) => {
      s.accepted = to;
    });
  }

  /** Warn-notes: at most one line per (rule, device) per 24 h, local only (T-B3-7). */
  private async localNotes(notes: readonly SyncNote[], extra: LocalNote[] = []): Promise<void> {
    const now = this.now().getTime();
    const cand: LocalNote[] = [
      ...notes.filter((n) => n.type === 'sync.warning' || n.type === 'sync.unverified').map((n) => ({ type: n.type, rule: tok(n.rule ?? 'warning'), device: n.device ?? null, detail: safeOutput(n.detail, 160) })),
      ...extra,
    ];
    if (cand.length === 0) return;
    const send: LocalNote[] = [];
    await this.upd((s) => {
      for (const n of cand) {
        const key = `${n.rule}:${n.device ?? '-'}`;
        if (s.noted.some((x) => x.key === key && Math.abs(now - Date.parse(x.at)) < DAY_MS)) continue;
        s.noted = s.noted.filter((x) => x.key !== key);
        s.noted.push({ key, at: new Date(now).toISOString() });
        send.push(n);
      }
    });
    if (send.length > 0) await this.d.host.noteLocal(send.slice(0, 20)).catch(() => this.d.log('sync: could not write a local note'));
  }

  /* ---------------- the cycle ---------------- */

  async run(): Promise<CycleResult> {
    const d = this.d;
    let st: SyncState;
    try {
      st = await d.state.read();
    } catch {
      d.log('sync: state file unreadable — staying halted (config)');
      return { outcome: 'state-corrupt', halted: 'config', refetches: 0, ms: Math.round(performance.now() - this.t0) };
    }
    const halt = st.halt;
    let offline = false;
    if (halt !== null) {
      if (halt.cls === 'no-contact' || halt.cls === 'terminal') return this.finish('halted', { halted: halt.reason });
      if (halt.cls === 'd2') {
        const d2 = halt.d2;
        // a confirmed revocation of THIS device never applies: the device detaches (terminal), local work goes on
        if (d2 !== null && d2.kind === 'self' && st.confirmations.some((c) => c.kind === 'self' && c.commit === d2.commit)) {
          await this.setHalt('detached', { tip: halt.tip, rule: 'detached', detail: 'this device was revoked by a peer (confirmed): sync stopped' });
          return this.finish('halted', { halted: 'detached' });
        }
        const confirmed =
          d2 !== null &&
          d2.kind === 'root' &&
          d2.deviceIds.every((id) => st.confirmations.some((c) => c.kind === 'root' && c.commit === d2.commit && c.device_id === id));
        if (!confirmed || halt.tip === null) return this.finish('halted', { halted: halt.reason });
        offline = true; // re-gate the stored tip with the human confirmation: no remote contact
      }
    }

    /* PRECHECK */
    let marker;
    try {
      marker = await d.state.readInflight();
    } catch {
      await this.setHalt('config', { detail: 'inflight marker unreadable' });
      return this.finish('halt:config', { halted: 'config' });
    }
    if (marker !== null) {
      const r = await replayInflight(d.host, d);
      if (r.kind === 'halt') {
        await this.setHalt(r.reason, { detail: r.detail });
        return this.finish(`halt:${r.reason}`, { halted: r.reason });
      }
    }
    const cfg = await readFile(nodePath.join(d.ledgerDir, '.git', 'config'), { encoding: 'utf8' }).catch(() => null);
    if (cfg === null || cfg.length > 256 * 1024) {
      await this.setHalt('config', { detail: 'git config unreadable' });
      return this.finish('halt:config', { halted: 'config' });
    }
    const problems = checkGitConfig(cfg, d.testLocalRemotes === undefined ? {} : { testLocalRemotes: d.testLocalRemotes });
    if (problems.length > 0) {
      await this.setHalt('config', { detail: `git config refused (${tok(String((problems[0] as { code?: unknown }).code ?? 'problem'))})` });
      return this.finish('halt:config', { halted: 'config' });
    }
    const A = await d.store.revParse(REF_ACCEPTED);
    if (A === null) {
      await this.setHalt('config', { detail: 'accepted ref missing (sync init/join not done)' });
      return this.finish('halt:config', { halted: 'config' });
    }
    if (A !== st.accepted) {
      // a crash between the ref CAS and the mirror write leaves the mirror BEHIND the ref: repair that, nothing else
      const lag = st.accepted !== null && (await d.store.isAncestor(st.accepted, A).catch(() => false));
      if (!lag || !(await this.upd((s) => { s.accepted = A; }))) {
        await this.setHalt('config', { detail: 'accepted mirror does not match the ref' });
        return this.finish('halt:config', { halted: 'config' });
      }
    }
    if (halt !== null && (halt.reason === 'config' || halt.reason === 'inflight')) await this.clearHalt();

    /* COMMIT_PENDING (no lock held) */
    if (!offline) {
      try {
        await d.host.flushLocal();
      } catch {
        return this.transient('local-git');
      }
    }

    for (let round = 0; round < 3; round += 1) {
      const res = await this.round(offline);
      if (res !== 'refetch') return res;
      this.refetches += 1;
    }
    return this.transient('push-rejected');
  }

  /** FETCH .. PUSH once. `'refetch'` = the push lost a race, go again. */
  private async round(offline: boolean): Promise<CycleResult | 'refetch'> {
    const d = this.d;
    const st0 = await d.state.read();
    const A = (await d.store.revParse(REF_ACCEPTED)) as string;
    let F: string | null;
    if (offline) {
      F = st0.halt?.tip ?? null;
      if (F === null || !(await d.store.hasCommit(F))) return this.finish('halted', { halted: st0.halt?.reason ?? 'config' });
    } else {
      /* FETCH (no locks) */
      let fr: GitxResult;
      try {
        fr = await d.gitx.fetch(d.ledgerDir, d.remote, { timeoutMs: d.net?.fetchMs ?? 20_000 });
      } catch (err) {
        if (err instanceof GitxError && (err.code === 'URL' || err.code === 'ARGS')) {
          await this.setHalt('config', { detail: 'remote url refused' });
          return this.finish('halt:config', { halted: 'config' });
        }
        return this.transient('local-git');
      }
      if (!fr.ok) {
        const c = classifyNetError(fr);
        if (c === 'auth' || c === 'hostkey') {
          await this.setHalt(c, { detail: c === 'auth' ? 'authentication failed' : 'host key problem' });
          return this.finish(`halt:${c}`, { halted: c });
        }
        if (c === 'fsck') {
          await this.setHalt('quarantine:fsck', { rule: 'fsck', detail: 'remote objects failed the integrity check' });
          return this.finish('halt:quarantine:fsck', { halted: 'quarantine:fsck' });
        }
        return this.transient(fr.timedOut ? 'fetch-timeout' : 'fetch');
      }
      F = await d.store.revParse(REF_INCOMING);
      if (F === null) return this.transient('fetch-empty');
    }

    /* ANCESTRY (the hub's own rule: git does not enforce fast-forward outside refs/heads) */
    let upToDate = F === A;
    if (!upToDate && !offline) {
      let anc: boolean;
      try {
        anc = await d.store.isAncestor(A, F);
      } catch {
        return this.transient('local-git');
      }
      if (!anc) {
        await this.setHalt('history-rewrite', { tip: F, detail: 'remote history is not a descendant of the accepted tip' });
        return this.finish('halt:history-rewrite', { halted: 'history-rewrite' });
      }
    }
    const st = await d.state.read();
    if (st.halt !== null && !offline && st.halt.reason === 'history-rewrite') await this.clearHalt(); // the ancestry check passed again

    let applied = false;
    if (!upToDate) {
      /* SHORT-CIRCUIT: we already have everything F says (a crash after APPLY, or a push that arrived) */
      const L0 = await d.store.revParse(REF_MAIN);
      if (L0 === null) return this.transient('local-git');
      if (await d.store.isAncestor(F, L0)) {
        try {
          await this.casAccepted(A, F);
        } catch {
          return this.transient('local-git');
        }
        await this.clearQuarantine();
        upToDate = true;
      } else {
        /* same quarantined tip is not re-validated (T-B3-7) */
        const h = st.halt;
        const ov = [...st.overrides].reverse().find((o) => o.tip === F);
        if (h !== null && !offline && h.cls === 'probe' && h.tip === F && ov === undefined) return this.finish('halted-same-tip', { halted: h.reason });

        /* VALIDATE (no locks) */
        const out = await validateRange({
          store: d.store,
          tmpRoot: nodePath.join(d.ledgerDir, '.hub', 'sync', 'tmp'),
          A,
          L: L0,
          F,
          mode: d.verify,
          localDevice: d.localDevice,
          trusted: await d.trusted(),
          seenSigning: new Set(st.seenSigning),
          confirmedRevocations: new Set(st.confirmations.map((c) => confirmationKey(c.commit, c.device_id))),
          maxFormat: d.maxFormat,
          ...(ov === undefined ? {} : { override: { secretAck: ov.secretAck === true } }),
          ...(d.sshKeygenBin === undefined ? {} : { sshKeygenBin: d.sshKeygenBin }),
        });
        if (out.kind === 'transient') {
          if (out.why === 'timeout') {
            let n = 1;
            await this.upd((s) => {
              n = s.strikes !== null && s.strikes.tip === F ? s.strikes.n + 1 : 1;
              s.strikes = { tip: F as string, n };
            });
            if (n >= 3) {
              await this.setHalt('quarantine:timeout', { tip: F, rule: 'timeout', detail: 'reading the range timed out three times' });
              return this.finish('halt:quarantine:timeout', { halted: 'quarantine:timeout' });
            }
          }
          return this.transient(out.why);
        }
        if (out.kind === 'quarantine') {
          const reason = `quarantine:${tok(out.rule)}` as HaltReason;
          await this.setHalt(reason, { tip: F, rule: out.rule, detail: `range refused (${tok(out.rule)}, ${out.layer})` });
          await this.localNotes([], [{ type: 'sync.reject', rule: `q-${tok(out.rule)}`, device: null, detail: `a remote range was quarantined (${tok(out.rule)})` }]);
          return this.finish(`halt:${reason}`, { halted: reason });
        }
        if (out.kind === 'halt-d2') {
          await this.setHalt(out.reason, {
            tip: F,
            rule: out.reason === 'quarantine:revocation-root' ? 'revocation-root' : 'revocation-self',
            detail: 'a revocation needs human confirmation',
            d2: { commit: out.commit, deviceIds: out.deviceIds, kind: out.d2Kind },
          });
          return this.finish(`halt:${out.reason}`, { halted: out.reason });
        }
        if (out.kind === 'format') {
          await this.setHalt('format', { tip: F, detail: 'the remote ledger format is newer than this hub supports' });
          return this.finish('halt:format', { halted: 'format' });
        }

        /* APPLY (critical section, R -> Q -> D) */
        let ap;
        try {
          ap = await applyRemote(d.host, d, { A, F, forcedMerge: out.forcedMerge, tipDevice: out.tipDevice });
        } catch (err) {
          if (err instanceof CrashError) throw err;
          return this.transient('apply');
        }
        if (ap.kind === 'quarantine') {
          const reason = `quarantine:${tok(ap.rule)}` as HaltReason;
          await this.setHalt(reason, { tip: F, rule: ap.rule, detail: `apply refused (${tok(ap.rule)})` });
          return this.finish(`halt:${reason}`, { halted: reason });
        }
        if (ap.kind === 'halt') {
          await this.setHalt(ap.reason, { detail: ap.detail });
          return this.finish(`halt:${ap.reason}`, { halted: ap.reason });
        }
        if (ap.kind === 'transient') return this.transient(ap.why);
        // applied | noop: the validated tip is now (an ancestor of) main
        try {
          await this.casAccepted(A, F);
        } catch (err) {
          d.log(`sync: accepted CAS failed (${err instanceof TreeBuildError ? err.code : 'error'})`);
          return this.transient('local-git');
        }
        applied = ap.kind === 'applied';
        const signers = out.signers;
        await this.upd((s) => {
          const have = new Set(s.seenSigning);
          const add = signers.filter((id) => !have.has(id));
          if (add.length > 0) {
            if (s.seenSigning.length + add.length > 64) d.log('sync: seenSigning is at its cap, the oldest ratchet entries are evicted');
            s.seenSigning = [...s.seenSigning, ...add];
          }
        });
        await this.clearQuarantine();
        // post-critical, outside every lock: local notes (rate limited), proposed items as ordinary writes
        const extra: LocalNote[] = out.overrideUsed && ov?.secretAck === true ? [{ type: 'sync.secret', rule: 'secret-override', device: null, detail: 'a quarantined range with a removed secret was accepted by the operator' }] : [];
        await this.localNotes(out.notes, extra);
        if (ap.kind === 'applied' && ap.proposed.length > 0) await d.host.createProposed(ap.proposed).catch(() => d.log('sync: proposed items could not be created'));
      }
    }
    if (offline) return this.finish('d2-confirmed', { applied });
    await this.clearQuarantine();

    /* PUSH (outside every lock) */
    return this.push(applied);
  }

  /** A halt of a class that a passing validation resolves (probe / format) ends here. */
  private async clearQuarantine(): Promise<void> {
    await this.upd((s) => {
      if (s.halt !== null && (s.halt.cls === 'probe' || s.halt.reason === 'format' || s.halt.cls === 'd2' || s.halt.reason === 'history-rewrite')) s.halt = null;
    });
  }

  private async push(applied: boolean): Promise<CycleResult | 'refetch'> {
    const d = this.d;
    const Ap = await d.store.revParse(REF_ACCEPTED);
    const Lp = await d.store.revParse(REF_MAIN);
    if (Ap === null || Lp === null) return this.transient('local-git');
    if (Ap === Lp) {
      await this.success();
      await this.upd((s) => {
        s.pushBlocked = null;
      });
      return this.finish(applied ? 'applied' : 'up-to-date', { applied });
    }
    let anc: boolean;
    try {
      anc = await d.store.isAncestor(Ap, Lp);
    } catch {
      return this.transient('local-git');
    }
    if (!anc) return this.transient('local-diverged');

    /* egress self-check (invariant 12) */
    let eg;
    try {
      eg = await egressSelfCheck(d.store, { A: Ap, L: Lp, maxFormat: d.maxFormat });
    } catch {
      return this.transient('local-git');
    }
    if (!eg.ok) {
      const since = this.now().toISOString();
      await this.upd((s) => {
        s.pushBlocked = { rule: tok(eg.rule), tip: Lp, since: s.pushBlocked !== null && s.pushBlocked.rule === tok(eg.rule) && s.pushBlocked.tip === Lp ? s.pushBlocked.since : since };
      });
      await this.success();
      return this.finish('push-blocked', { applied });
    }
    await this.upd((s) => {
      s.pushBlocked = null;
    });

    let pr: GitxResult;
    try {
      pr = await d.gitx.push(d.ledgerDir, d.remote, Lp, { timeoutMs: d.net?.pushMs ?? 30_000 });
    } catch (err) {
      if (err instanceof GitxError && (err.code === 'URL' || err.code === 'ARGS')) {
        await this.setHalt('config', { detail: 'remote url refused' });
        return this.finish('halt:config', { halted: 'config' });
      }
      return this.transient('local-git');
    }
    if (pr.ok) {
      try {
        await this.casAccepted(Ap, Lp);
      } catch {
        return this.transient('local-git'); // pushed, mirror CAS failed: the next fetch reconciles (W8)
      }
      await this.success();
      return this.finish('pushed', { applied, pushed: true });
    }
    // Unknown outcome (timeout): the remote may or may not have it. Never retry blindly; the next fetch decides.
    if (pr.timedOut) return this.transient('push-unknown');
    const c = classifyNetError(pr);
    if (c === 'auth' || c === 'hostkey') {
      await this.setHalt(c, { detail: c === 'auth' ? 'authentication failed' : 'host key problem' });
      return this.finish(`halt:${c}`, { halted: c });
    }
    if (c === 'non-ff') return 'refetch';
    return this.transient('push-failed');
  }
}

/** Run one cycle. NEVER throws (the single exception is the test seam `CrashError`). */
export async function runCycle(deps: CycleDeps): Promise<CycleResult> {
  const c = new Cycle(deps);
  try {
    return await c.run();
  } catch (err) {
    if (err instanceof CrashError) throw err;
    const name = err instanceof Error ? err.name : 'error';
    deps.log(`sync: cycle failed (${safeOutput(name, 40)})`);
    return c.finish('error').catch(() => ({ outcome: 'error', refetches: 0, ms: 0 }));
  }
}
