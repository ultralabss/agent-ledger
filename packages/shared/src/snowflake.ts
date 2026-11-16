/**
 * Snowflake ids — 63-bit, time-ordered, unique per worker.
 *
 *   63 bits: [41 ms since SNOWFLAKE_EPOCH_MS][10 worker][12 sequence]
 *
 * Written for Node type stripping (`erasableSyntaxOnly`): no parameter
 * properties. Validation happens with zod elsewhere, not with decorators.
 *
 * Ids are time-ordered (cursor pagination = last id), unique per worker and
 * NEVER a JS `number` — they travel as decimal strings on the wire.
 *
 * Worker id comes from `SNOWFLAKE_WORKER_ID` (0–1023, default 1). Two
 * processes with the same worker id can collide — every replica MUST get
 * its own id.
 */

/** 2026-09-11T12:40:26Z — fixed for every worker, never change. */
export const SNOWFLAKE_EPOCH_MS = 1789130426000;

const TIMESTAMP_BITS = 41n;
const WORKER_BITS = 10n;
const SEQUENCE_BITS = 12n;
const WORKER_SHIFT = SEQUENCE_BITS;
const TIMESTAMP_SHIFT = WORKER_BITS + SEQUENCE_BITS;
const MAX_WORKER = (1n << WORKER_BITS) - 1n; // 1023
const MAX_SEQUENCE = (1n << SEQUENCE_BITS) - 1n; // 4095
const MAX_TIMESTAMP = (1n << TIMESTAMP_BITS) - 1n;
const MAX_ID = (1n << 63n) - 1n;

export const SNOWFLAKE_RE = /^\d{1,20}$/;

export interface ParsedSnowflake {
  timestamp: Date;
  worker: number;
  seq: number;
}

export interface SnowflakeOptions {
  /** 0–1023. */
  workerId?: number;
  /** Injectable clock (tests). Must return unix ms. */
  now?: () => number;
}

export class SnowflakeClockError extends Error {
  readonly driftMs: number;

  constructor(driftMs: number) {
    super(`snowflake: clock moved backwards by ${driftMs} ms — refusing to mint`);
    this.name = 'SnowflakeClockError';
    this.driftMs = driftMs;
  }
}

export function parseWorkerId(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === '') return 1;
  if (!/^\d{1,4}$/.test(raw.trim())) {
    throw new Error(`SNOWFLAKE_WORKER_ID must be an integer 0–1023, got "${raw}"`);
  }
  const n = Number(raw.trim());
  if (n < 0 || n > Number(MAX_WORKER)) {
    throw new Error(`SNOWFLAKE_WORKER_ID must be 0–1023, got ${n}`);
  }
  return n;
}

/**
 * Device slot letters (multi-device ids `ACME-W7`): 24 letters, no I and O (look
 * like 1 and 0). Slot `""` is the primary (existing) ledger and keeps worker 1,
 * the value every single-machine ledger has always used. A letter maps to
 * worker 2 + index (2..25), so two devices can never mint the same id.
 * (`SNOWFLAKE_WORKER_ID` only applies to slot `""`; do not set it to 2..25 on a
 * primary that syncs with lettered devices.)
 */
export const SLOT_LETTERS = 'ABCDEFGHJKLMNPQRSTUVWXYZ';

export function slotWorkerId(slot: string): number {
  if (slot === '') return 1;
  const idx = slot.length === 1 ? SLOT_LETTERS.indexOf(slot) : -1;
  if (idx < 0) throw new Error(`invalid device slot "${slot}" (one letter A-H J-N P-Z, or empty)`);
  return 2 + idx;
}

export class Snowflake {
  private id: number;
  private workerBits: bigint;
  private readonly now: () => number;
  private lastMs = -1;
  private seq = 0n;

  constructor(opts: SnowflakeOptions = {}) {
    const workerId = opts.workerId ?? 1;
    if (!Number.isInteger(workerId) || workerId < 0 || workerId > Number(MAX_WORKER)) {
      throw new Error(`snowflake worker id must be 0–1023, got ${workerId}`);
    }
    this.id = workerId;
    this.workerBits = BigInt(workerId) << WORKER_SHIFT;
    this.now = opts.now ?? Date.now;
  }

  get workerId(): number {
    return this.id;
  }

  /** Re-point the worker field (device slot is only known after the ledger
   *  opened). Clock state is kept, so ids stay monotonic across the switch. */
  setWorkerId(workerId: number): void {
    if (!Number.isInteger(workerId) || workerId < 0 || workerId > Number(MAX_WORKER)) {
      throw new Error(`snowflake worker id must be 0–1023, got ${workerId}`);
    }
    this.id = workerId;
    this.workerBits = BigInt(workerId) << WORKER_SHIFT;
  }

  /** Decimal string. Monotonic per worker; throws on clock rollback. */
  generate(): string {
    let ms = this.now();
    if (ms < this.lastMs) throw new SnowflakeClockError(this.lastMs - ms);
    if (ms === this.lastMs) {
      this.seq = (this.seq + 1n) & MAX_SEQUENCE;
      if (this.seq === 0n) {
        // 4096 ids in one ms — spin until the clock ticks. Rollback while
        // spinning is still an error, never a duplicate.
        do {
          ms = this.now();
          if (ms < this.lastMs) throw new SnowflakeClockError(this.lastMs - ms);
        } while (ms === this.lastMs);
      }
    } else {
      this.seq = 0n;
    }
    this.lastMs = ms;
    const ts = BigInt(ms - SNOWFLAKE_EPOCH_MS);
    if (ts < 0n || ts > MAX_TIMESTAMP) {
      throw new Error(`snowflake: timestamp ${ms} outside the 41-bit window`);
    }
    return ((ts << TIMESTAMP_SHIFT) | this.workerBits | this.seq).toString(10);
  }
}

/** `true` for a canonical decimal string that fits the 63-bit id space. */
export function isSnowflake(s: unknown): s is string {
  if (typeof s !== 'string' || !SNOWFLAKE_RE.test(s)) return false;
  if (s.length > 1 && s.startsWith('0')) return false; // no leading zeros
  const n = BigInt(s);
  return n > 0n && n <= MAX_ID; // '0' is not a valid id either
}

export function parseSnowflake(id: string): ParsedSnowflake {
  if (!isSnowflake(id)) throw new Error(`not a snowflake id: "${String(id)}"`);
  const n = BigInt(id);
  return {
    timestamp: new Date(Number(n >> TIMESTAMP_SHIFT) + SNOWFLAKE_EPOCH_MS),
    worker: Number((n >> WORKER_SHIFT) & MAX_WORKER),
    seq: Number(n & MAX_SEQUENCE),
  };
}

/** Process-wide generator, worker id from `SNOWFLAKE_WORKER_ID`. */
export const snowflake = new Snowflake({
  workerId: parseWorkerId(process.env.SNOWFLAKE_WORKER_ID),
});

/** Derive the process-wide worker id from the device slot. Slot `""` = the
 *  value from `SNOWFLAKE_WORKER_ID` (default 1), i.e. no change for a
 *  single-machine ledger. Called by `Ledger.init()`. */
export function configureSnowflakeWorker(slot: string): void {
  snowflake.setWorkerId(slot === '' ? parseWorkerId(process.env.SNOWFLAKE_WORKER_ID) : slotWorkerId(slot));
}

/** Convenience: `id = generate()`. */
export function generate(): string {
  return snowflake.generate();
}

/** Alias kept for parity with the reference implementation's `parse`. */
export function parse(id: string): ParsedSnowflake {
  return parseSnowflake(id);
}
