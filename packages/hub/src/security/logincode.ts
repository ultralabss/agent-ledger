/**
 * One-time login codes for the web UI (SPEC §6.5, §13).
 *
 * Threat model:
 *  - Actor: another local account/process on the machine, any page in the
 *    browser, and anything that sees the URL (history, Referer, screen share,
 *    `ps`, proxy logs).
 *  - Protected: the hub token (ledger writes) and reading the ledger via the UI cookie.
 *  - Failure modes: a token in the URL ends up in history and logs · a code can
 *    be used twice (a link in history = an eternal session) · a code can be
 *    brute-forced · a code stays in memory forever (DoS / heap dump read) ·
 *    `next` redirects the user to a foreign origin (open redirect).
 *  - Hence: 32 B CSPRNG code, only the SHA-256 hash in memory, 60 s TTL,
 *    consumed on first use, the number of live codes is capped, failures are
 *    rate limited, `next` may only be a relative path on this origin.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** 32 B CSPRNG → 43 base64url chars without padding. */
const CODE_BYTES = 32;
const CODE_RE = /^[A-Za-z0-9_-]{43}$/;
const DEFAULT_TTL_MS = 60_000;
/** Cap on live codes: `ledger open` asks for one; this cap only prevents an
 *  authorized but broken client from inflating hub memory. */
const DEFAULT_MAX_LIVE = 16;

const NEXT_MAX_LEN = 256;
/** Allowed characters of a relative path. No `\`, no whitespace, no CR/LF
 *  (also protects against injecting a second header into `Location`). */
const NEXT_RE = /^\/[A-Za-z0-9\-._~!$&'()*+,;=:@/?%#]*$/;

/**
 * Validates `next` for the redirect after login.
 * Only a path on this origin passes: it must start with `/`, must not start
 * with `//` (protocol-relative URL = foreign origin), must not contain `\`
 * (browsers treat it as `/` in URLs, so `/\evil.com` is also a foreign
 * origin), whitespace, NUL or percent-encoding that decodes to any of these.
 * Returns a safe value or `null` — never a "repaired" version of the input.
 */
export function safeNextPath(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  if (raw.length === 0 || raw.length > NEXT_MAX_LEN) return null;
  if (!raw.startsWith('/')) return null; // `https://evil`, `javascript:…`, `evil.com`
  if (raw.startsWith('//')) return null; // protocol-relative
  if (/[\s\\\0]/.test(raw)) return null; // `/\evil.com`, CRLF injection
  if (!NEXT_RE.test(raw)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null; // malformed percent-encoding
  }
  if (/[\s\\\0]/.test(decoded)) return null; // `%5Cevil`, `%0d%0a`
  if (decoded.startsWith('//')) return null; // `/%2F%2Fevil.com`
  return raw;
}

function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

interface Entry {
  /** Only the hash is kept in memory — neither a heap dump nor logs contain a usable code. */
  hash: Buffer;
  expiresAt: number;
}

export interface LoginCodeOptions {
  ttlMs?: number;
  maxLive?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

/**
 * Store of one-time codes. A code exists in readable form only as the return
 * value of `issue()` — i.e. in the response to an already authorized
 * `POST /v1/ui/login-code` and in the URL that `ledger open` hands to the
 * browser. It is never logged.
 */
export class LoginCodeStore {
  readonly ttlMs: number;
  private readonly maxLive: number;
  private readonly now: () => number;
  private readonly entries: Entry[] = [];

  constructor(opts: LoginCodeOptions = {}) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
    this.maxLive = opts.maxLive ?? DEFAULT_MAX_LIVE;
    this.now = opts.now ?? Date.now;
  }

  private prune(): void {
    const t = this.now();
    for (let i = this.entries.length - 1; i >= 0; i -= 1) {
      const e = this.entries[i];
      if (e === undefined || e.expiresAt <= t) this.entries.splice(i, 1);
    }
  }

  /** Number of live (unconsumed, unexpired) codes — for tests/metrics. */
  get live(): number {
    this.prune();
    return this.entries.length;
  }

  /** A new code. Returns the raw value; the caller may only put it in a response. */
  issue(): string {
    this.prune();
    // The oldest code drops first: `ledger open` run twice must not leave the
    // old code alive and must not fail on the cap.
    while (this.entries.length >= this.maxLive) this.entries.shift();
    const code = randomBytes(CODE_BYTES).toString('base64url');
    this.entries.push({ hash: sha256(code), expiresAt: this.now() + this.ttlMs });
    return code;
  }

  /**
   * Consumes a code. `true` only on the first use of a valid, unexpired code —
   * a second use of the same code (link in history, page reload) is `false`.
   * The comparison is timing-safe over hashes so response time does not leak a prefix.
   */
  consume(code: unknown): boolean {
    this.prune();
    if (typeof code !== 'string' || !CODE_RE.test(code)) return false;
    const want = sha256(code);
    let index = -1;
    for (let i = 0; i < this.entries.length; i += 1) {
      const e = this.entries[i];
      if (e === undefined) continue;
      if (timingSafeEqual(e.hash, want) && index < 0) index = i;
    }
    if (index < 0) return false;
    this.entries.splice(index, 1);
    return true;
  }

  /** Drops everything (e.g. after a token rotation). */
  clear(): void {
    this.entries.length = 0;
  }
}

export interface FailureLimiterOptions {
  limit?: number;
  windowMs?: number;
  now?: () => number;
}

/**
 * Sliding window for failed login attempts. Without it the 32 B code is
 * unguessable, but `/login` would serve as an amplifier for other errors and
 * would flood the log. We do not key by IP — the hub listens on loopback only,
 * so every attempt comes from the same machine and one global window is more accurate.
 */
export class FailureLimiter {
  readonly limit: number;
  readonly windowMs: number;
  private readonly now: () => number;
  private hits: number[] = [];

  constructor(opts: FailureLimiterOptions = {}) {
    this.limit = opts.limit ?? 10;
    this.windowMs = opts.windowMs ?? 60_000;
    this.now = opts.now ?? Date.now;
  }

  private prune(): void {
    const cutoff = this.now() - this.windowMs;
    this.hits = this.hits.filter((t) => t > cutoff);
  }

  /** `true` = the next attempt must be rejected with 429. */
  get blocked(): boolean {
    this.prune();
    return this.hits.length >= this.limit;
  }

  fail(): void {
    this.prune();
    this.hits.push(this.now());
  }

  /** A successful login empties the window — a valid code cannot be guessed,
   *  so success proves an authorized user. */
  reset(): void {
    this.hits = [];
  }
}
