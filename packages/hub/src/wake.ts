/**
 * Sleep/wake awareness and an event-loop stall monitor.
 *
 * Why both live here: the hub is a launchd agent on a laptop that sleeps. Two
 * failure shapes were measured on the live hub and neither was visible in
 * `hub.log`:
 *
 *  1. Right after a wake every periodic job fires at once (its timer fired
 *     while the machine was asleep, or immediately after), the ledger's git
 *     and gitleaks children start under a cold page cache, and the 1 s hook
 *     timeout turns the resulting pile-up into a false "AGENT-LEDGER DOWN".
 *     `WakeMonitor` notices the wall-clock jump and closes a gate; the heavy
 *     jobs reschedule themselves instead of running into the storm. HTTP
 *     handlers and `/v1/healthz` are NEVER gated — a hub that answers is the
 *     whole point of the gate.
 *  2. A long synchronous block (full FTS rebuild, SQLite checkpoint) delays
 *     every pending timer and request. `StallMonitor` measures timer drift,
 *     attributes it to whichever periodic job is running, and logs it once a
 *     minute at most.
 *
 * Both take an injectable clock so the tests do not sleep.
 */

import type { LogSink } from './log.ts';

export interface WakeOptions {
  log?: LogSink;
  /** Wall clock in ms. Injected by the tests. */
  now?: () => number;
  /** Ticker period (SPEC ops/resilience: 5 s). */
  intervalMs?: number;
  /** A tick that arrives this much later than expected is a wake, not a tick. */
  gapMs?: number;
  /** How long heavy jobs stay deferred after a wake. */
  holdMs?: number;
  /** Same, for the first seconds of the process — boot is its own storm. */
  startupHoldMs?: number;
  /** Upper bound of the random extra hold, so two hubs (or a hub and a
   *  session's own git) do not restart their heavy work in lockstep. */
  jitterMs?: number;
  /** Injected by the tests to make the jitter deterministic. */
  random?: () => number;
}

/**
 * Detects a sleep/wake (or any clock jump forward) and gates heavy jobs.
 *
 * The gate is deliberately a *question* (`heavyAllowed()`), not a queue: a job
 * that skips a cycle must stay responsible for its own retry, so nothing is
 * accumulated here that a shutdown would have to drain.
 */
export class WakeMonitor {
  private readonly log: LogSink;
  private readonly now: () => number;
  private readonly intervalMs: number;
  private readonly gapMs: number;
  private readonly holdMs: number;
  private readonly jitterMs: number;
  private readonly random: () => number;
  private readonly startedAtMs: number;
  private lastTickMs: number;
  private holdUntilMs: number;
  private lastWakeAtMs: number | null = null;
  private ticker: NodeJS.Timeout | null = null;

  constructor(opts: WakeOptions = {}) {
    this.log = opts.log ?? ((): void => undefined);
    this.now = opts.now ?? ((): number => Date.now());
    this.intervalMs = opts.intervalMs ?? 5_000;
    this.gapMs = opts.gapMs ?? 15_000;
    this.holdMs = opts.holdMs ?? 20_000;
    this.jitterMs = opts.jitterMs ?? 3_000;
    this.random = opts.random ?? ((): number => Math.random());
    this.startedAtMs = this.now();
    this.lastTickMs = this.startedAtMs;
    // Boot is the same storm as a wake: the first reindex, the repo walk and
    // the spool replay all land inside the first seconds.
    this.holdUntilMs = this.startedAtMs + (opts.startupHoldMs ?? 10_000);
  }

  start(): void {
    if (this.ticker) return;
    this.ticker = setInterval(() => this.tick(), this.intervalMs);
    this.ticker.unref?.();
  }

  stop(): void {
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
  }

  /** The ticker body. Public so the tests can drive it with a fake clock. */
  tick(): void {
    const now = this.now();
    const gap = now - this.lastTickMs;
    this.lastTickMs = now;
    // Only forward jumps matter. A backwards clock (NTP step) is left alone on
    // purpose: `Date.now()` going back would otherwise hold the heavy jobs for
    // as long as the step, and the ledger would stop committing.
    if (gap <= this.gapMs) return;
    this.lastWakeAtMs = now;
    this.holdUntilMs = now + this.holdMs + Math.floor(this.random() * this.jitterMs);
    this.log(
      `wake detected (gap ${Math.round(gap / 1000)} s) — heavy jobs deferred until ` +
        `${new Date(this.holdUntilMs).toISOString()}`,
    );
  }

  /** False while the post-wake (or post-boot) hold is active. */
  heavyAllowed(): boolean {
    return this.now() >= this.holdUntilMs;
  }

  /** How long until the gate opens. 0 when it is already open. */
  retryInMs(): number {
    return Math.max(0, this.holdUntilMs - this.now());
  }

  get startedAt(): string {
    return new Date(this.startedAtMs).toISOString();
  }

  get lastWakeAt(): string | null {
    return this.lastWakeAtMs === null ? null : new Date(this.lastWakeAtMs).toISOString();
  }

  /**
   * Run `fn` now when the gate is open, otherwise once it opens.
   *
   * Returns true when it ran synchronously (the caller may continue), false
   * when it was deferred. One timer per deferred call and the gate opens for
   * everyone at the same instant, so this cannot pile up unbounded: at most one
   * pending retry per skipped job cycle.
   */
  whenAllowed(fn: () => void): boolean {
    if (this.heavyAllowed()) return true;
    const t = setTimeout(fn, this.retryInMs() + 100);
    t.unref?.();
    return false;
  }
}

export interface StallOptions {
  log?: LogSink;
  /** Monotonic clock in ms (`performance.now()` in production). */
  now?: () => number;
  /** Drift above this is logged. */
  thresholdMs?: number;
  /** `loopDelayMaxMs` in `/v1/healthz` covers this window. */
  windowMs?: number;
  /** At most one stall line per this period, however many stalls happen. */
  logEveryMs?: number;
  /** Drift ticker period. */
  intervalMs?: number;
}

/**
 * Timer-drift monitor. `perf_hooks.monitorEventLoopDelay` reports a histogram
 * but cannot say WHAT blocked; the whole value of this line is naming the job,
 * so a plain drift ticker it is — 10 wakeups a second, no native handle, and
 * the same number `healthz` reports.
 */
export class StallMonitor {
  private readonly log: LogSink;
  private readonly now: () => number;
  private readonly thresholdMs: number;
  private readonly windowMs: number;
  private readonly logEveryMs: number;
  private readonly intervalMs: number;
  private ticker: NodeJS.Timeout | null = null;
  private lastTick: number;
  private lastLogAt = -Infinity;
  private suppressed = 0;
  /** Nested job names; the innermost one is the honest attribution. */
  private jobs: string[] = [];
  /** `[at, ms]` of recent stalls, trimmed to `windowMs`. */
  private recent: [number, number][] = [];

  constructor(opts: StallOptions = {}) {
    this.log = opts.log ?? ((): void => undefined);
    this.now = opts.now ?? ((): number => performance.now());
    this.thresholdMs = opts.thresholdMs ?? 500;
    this.windowMs = opts.windowMs ?? 5 * 60_000;
    this.logEveryMs = opts.logEveryMs ?? 60_000;
    this.intervalMs = opts.intervalMs ?? 100;
    this.lastTick = this.now();
  }

  start(): void {
    if (this.ticker) return;
    this.lastTick = this.now();
    this.ticker = setInterval(() => this.tick(), this.intervalMs);
    this.ticker.unref?.();
  }

  stop(): void {
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
  }

  /** The ticker body. Public for the tests. */
  tick(): void {
    const now = this.now();
    const drift = now - this.lastTick - this.intervalMs;
    this.lastTick = now;
    if (drift <= 0) return;
    this.recent.push([now, drift]);
    this.trim(now);
    if (drift < this.thresholdMs) return;
    if (now - this.lastLogAt < this.logEveryMs) {
      this.suppressed += 1;
      return;
    }
    const job = this.jobs.at(-1) ?? 'none';
    const extra = this.suppressed > 0 ? ` · ${this.suppressed} more suppressed` : '';
    this.suppressed = 0;
    this.lastLogAt = now;
    this.log(`event loop stalled ${Math.round(drift)} ms (job: ${job})${extra}`);
  }

  /** Wrap a periodic job so a stall inside it can be attributed to it. */
  async job<T>(name: string, fn: () => Promise<T>): Promise<T> {
    this.jobs.push(name);
    try {
      return await fn();
    } finally {
      const i = this.jobs.lastIndexOf(name);
      if (i >= 0) this.jobs.splice(i, 1);
    }
  }

  /** Worst drift seen in the last `windowMs` (0 when quiet). */
  maxDelayMs(): number {
    const now = this.now();
    this.trim(now);
    let max = 0;
    for (const [, ms] of this.recent) if (ms > max) max = ms;
    return Math.round(max);
  }

  private trim(now: number): void {
    const cutoff = now - this.windowMs;
    if (this.recent.length > 0 && this.recent[0]![0] >= cutoff) return;
    this.recent = this.recent.filter(([at]) => at >= cutoff);
  }
}
