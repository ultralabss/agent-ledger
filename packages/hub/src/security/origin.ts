/**
 * Host / Origin / token gate for the local hub.
 *
 * Threat model:
 *  - Actor: any web page in the user's browser (CSRF, DNS rebinding),
 *    plus a local process without the token.
 *  - Protected: every mutating hub endpoint (writes to the md ledger, hooks, leases).
 *  - Failure modes: a page POSTs to http://127.0.0.1:4747 (no preflight for a
 *    simple request) · an attacker's domain resolves to 127.0.0.1 and the Host passes ·
 *    the UI cookie is the raw token, extractable from `document.cookie` (XSS).
 *
 * The cookie used to be HMAC(token, context), so anyone holding the token
 * (CLI, hook, subagent) could compute it and impersonate "the human at the
 * browser". The HMAC key is now `uiSecret` — 32 B CSPRNG created at hub
 * start, living only in process memory and going over the wire only as the
 * `Set-Cookie` of `GET /login`. The token is still in the message (as `sha256`)
 * so that rotating the token invalidates the cookie immediately. Consequence:
 * a token holder cannot forge the cookie path, and a hub restart means a new
 * login via `ledger open`.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * What the hub needs to verify both authorization paths.
 * `uiSecret` is a per-boot secret for the cookie path — separate from `token`,
 * never on disk, never in an API response.
 */
export interface UiAuthConfig {
  token: string;
  uiSecret: string;
}

/** Which path authorized the request. `null` = not authorized at all. */
export type AuthPath = 'token' | 'cookie';

export type WriteRequest = {
  method: string;
  host: string | undefined;
  origin: string | undefined;
  tokenHeader: string | undefined;
  cookieHeader: string | undefined;
  /** `Sec-Fetch-Site` — required for the cookie path, see `isSameOriginFetch`. */
  secFetchSite?: string | undefined;
};

export const UI_COOKIE_NAME = 'hub_ui';
/** Domain separation — the cookie is not usable as an X-Hub-Token and vice versa. */
const UI_COOKIE_CONTEXT = 'agent-ledger:ui-cookie:v1';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function eqSafe(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  // timingSafeEqual throws on different lengths, so take one fixed path for all inputs.
  // (The token length is not secret, but this keeps a single code path.)
  if (ab.length !== bb.length) {
    const pad = Buffer.alloc(Math.max(ab.length, bb.length, 1));
    timingSafeEqual(pad, Buffer.alloc(pad.length));
    return false;
  }
  if (ab.length === 0) return false;
  return timingSafeEqual(ab, bb);
}

/** The one friendly name the web UI is served under. `*.localhost` is resolved
 *  to loopback by browsers and `curl` themselves (RFC 6761), so it needs no
 *  hosts entry. Exactly this label — never a wildcard over `*.localhost`: any
 *  other name under it is attacker-chosen and must not pass the Host gate. */
export const LEDGER_LOCALHOST = 'ledger.localhost';

/** The ONLY list behind both the Host gate and the Origin check, so a browser
 *  origin passes exactly where the same-named Host passes, and nowhere else. */
function allowedAuthorities(port: number): string[] {
  return [`127.0.0.1:${port}`, `localhost:${port}`, `${LEDGER_LOCALHOST}:${port}`];
}

/**
 * Exact match of `127.0.0.1:<port>` / `localhost:<port>` / `ledger.localhost:<port>`
 * (host case-insensitive). Everything else (other name, other `*.localhost`,
 * missing port, other port, `[::1]`, trailing dot, userinfo, whitespace) is
 * rejected, so DNS rebinding has no valid Host.
 */
export function isAllowedHost(host: string | undefined, port: number): boolean {
  if (typeof host !== 'string' || host.length === 0 || host.length > 64) return false;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  if (/[\s/@\\[\]]/.test(host)) return false;
  const lower = host.toLowerCase();
  return allowedAuthorities(port).includes(lower);
}

function isAllowedOrigin(origin: string | undefined, port: number): boolean {
  if (typeof origin !== 'string' || origin.length === 0 || origin.length > 96) return false;
  if (/[\s\\]/.test(origin)) return false;
  return allowedAuthorities(port).some((a) => origin === `http://${a}`);
}

/** Minimum length of the per-boot `uiSecret` — below it the cookie path is disabled. */
const MIN_UI_SECRET_LEN = 32;

/** New per-boot secret for the cookie path (32 B CSPRNG → 43 base64url chars). */
export function newUiSecret(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * UI cookie value: HMAC-SHA256(uiSecret, context ‖ sha256(token)).
 *
 * The key is `uiSecret` (per-boot, only in hub memory), not the token — a token
 * holder cannot compute the cookie. The token is in the message as a hash, so
 * rotating the token invalidates the cookie as before, and the cookie never
 * carries the token itself.
 * Returns `null` when the configuration is unusable (fail closed).
 */
export function uiCookieValue(cfg: UiAuthConfig): string | null {
  if (typeof cfg.token !== 'string' || cfg.token.length < 16) return null;
  if (typeof cfg.uiSecret !== 'string' || cfg.uiSecret.length < MIN_UI_SECRET_LEN) return null;
  const tokenFingerprint = createHash('sha256').update(cfg.token, 'utf8').digest('hex');
  return createHmac('sha256', cfg.uiSecret)
    .update(`${UI_COOKIE_CONTEXT}:${tokenFingerprint}`)
    .digest('base64url');
}

/**
 * Set-Cookie for the UI on the same origin. Issued only by `GET /login` after
 * consuming a one-time code (`http/ui.ts`).
 *
 * No `Domain` attribute, deliberately: the cookie is host-only, so it is sent to
 * the exact host that was logged into (`ledger.localhost` OR `127.0.0.1`, which
 * are separate cookie jars) and never to a sibling name under `*.localhost`.
 *
 * No `Secure`: the hub runs only on http://127.0.0.1 (loopback, the packet never
 * leaves the machine), and some browsers drop a `Secure` cookie from an http
 * response, so the UI would never store it. If the hub ever gets TLS, add
 * `Secure` + the `__Host-` prefix.
 * `port` is in the signature for symmetry with the other functions; the cookie
 * is not bound to a port because browsers do not include the port in cookie scope.
 *
 * `Max-Age=43200` (12 h) — the lower bound of the allowed range, chosen
 * deliberately: the cookie is `HttpOnly` but sits on disk in the browser
 * profile, so its value should live at most one working day; renewal is one
 * command (`ledger open`), so a longer lifetime buys nothing except a bigger
 * window for a stolen profile. Token rotation (`ledger`/hub) invalidates it
 * immediately because the value is an HMAC of the current token.
 */
export function uiCookie(cfg: UiAuthConfig, port: number): string | null {
  void port;
  const value = uiCookieValue(cfg);
  // Without a usable `uiSecret` the cookie is NOT issued. Issuing it with a
  // fallback key (e.g. the token) would silently restore exactly the boundary
  // this design removes — better no session than a forgeable one.
  if (value === null) return null;
  return [
    `${UI_COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=43200',
  ].join('; ');
}

/**
 * The cookie path additionally requires `Sec-Fetch-Site: same-origin`.
 *
 * The browser sends this header and it **cannot** be set from JS (forbidden
 * header name), so it is the only signal an attacker's page cannot forge.
 * Origin is not sent at all on a same-origin GET, `SameSite=Strict` only blocks
 * cross-site *navigation*, and a `fetch` from an extension or a `file://`
 * origin sends neither. The cookie is HttpOnly but sits on disk in the
 * profile — without this check it could be read from the profile and replayed
 * with cURL.
 *
 * The token path does NOT require this header: the CLI, hooks and `curl` are
 * not browsers and do not send it; their authorization is the bearer token
 * from a 0600 file.
 */
function isSameOriginFetch(secFetchSite: string | undefined): boolean {
  if (typeof secFetchSite !== 'string') return false;
  const value = secFetchSite.trim().toLowerCase();
  // `none` = direct user navigation (address bar, bookmark) — never happens for
  // `/v1/*` XHR, and allowing it would open a top-level GET from any page.
  // Hence `same-origin` only.
  return value === 'same-origin';
}

/** Returns the cookie value; `null` if missing or duplicated (cookie shadowing). */
function readCookie(cookieHeader: string | undefined, name: string): string | null {
  if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) return null;
  let found: string | null = null;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    if (found !== null) return null;
    found = part.slice(eq + 1).trim();
  }
  return found;
}

/**
 * Authorization of a mutating request.
 * GET/HEAD/OPTIONS → true (reads are guarded by `isAllowedRead`, called
 * separately — see guard.ts).
 * Otherwise: valid Host AND (X-Hub-Token timing-safe match OR exact local Origin
 * + valid UI cookie). A missing Origin never passes the cookie path.
 */
export function resolveWritePath(
  req: WriteRequest,
  cfg: UiAuthConfig & { port: number },
): AuthPath | null {
  const method = typeof req.method === 'string' ? req.method.toUpperCase() : '';
  if (SAFE_METHODS.has(method)) {
    // A safe method is not a write — `resolveReadPath` decides the path.
    return resolveReadPath(req, cfg);
  }
  if (method.length === 0) return null;
  if (typeof cfg.token !== 'string' || cfg.token.length < 16) return null;
  // Defense in depth: a mutation without a valid Host fails even with the token.
  if (!isAllowedHost(req.host, cfg.port)) return null;

  if (typeof req.tokenHeader === 'string' && req.tokenHeader.length > 0) {
    if (eqSafe(req.tokenHeader, cfg.token)) return 'token';
  }

  // The cookie path for a WRITE requires an exact local `Origin` AND
  // `Sec-Fetch-Site: same-origin` — the browser sends both and neither can be
  // set from JS. Together with the per-boot `uiSecret` this means `cookie`
  // really denotes the human at the browser, not a process with the token.
  if (!isAllowedOrigin(req.origin, cfg.port)) return null;
  if (!isSameOriginFetch(req.secFetchSite)) return null;
  const cookie = readCookie(req.cookieHeader, UI_COOKIE_NAME);
  if (cookie === null) return null;
  const expected = uiCookieValue(cfg);
  if (expected === null) return null;
  return eqSafe(cookie, expected) ? 'cookie' : null;
}

/** Legacy behaviour kept: a safe method passes, reads are guarded by
 *  `isAllowedRead`. New callers should prefer `resolveWritePath`. */
export function isAllowedWrite(req: WriteRequest, cfg: UiAuthConfig & { port: number }): boolean {
  const method = typeof req.method === 'string' ? req.method.toUpperCase() : '';
  if (SAFE_METHODS.has(method)) return true;
  return resolveWritePath(req, cfg) !== null;
}

export type ReadRequest = {
  tokenHeader: string | undefined;
  cookieHeader: string | undefined;
  /** `Sec-Fetch-Site` — required for the cookie path (not for the token). */
  secFetchSite?: string | undefined;
};

/**
 * Authorization of reads (decision: GET requires auth too, except
 * `GET /v1/healthz`, which is authorized separately in app.ts because of its
 * different response for an unauthenticated request).
 *
 * X-Hub-Token timing-safe match OR a valid UI cookie. Origin is not required:
 * the browser does not send it on a same-origin GET at all, so it would block
 * the cookie path needlessly — the cookie path is guarded instead by
 * `Sec-Fetch-Site: same-origin`, which JS cannot set.
 */
export function resolveReadPath(req: ReadRequest, cfg: UiAuthConfig): AuthPath | null {
  if (typeof cfg.token !== 'string' || cfg.token.length < 16) return null;
  if (typeof req.tokenHeader === 'string' && req.tokenHeader.length > 0) {
    if (eqSafe(req.tokenHeader, cfg.token)) return 'token';
  }
  if (!isSameOriginFetch(req.secFetchSite)) return null;
  const cookie = readCookie(req.cookieHeader, UI_COOKIE_NAME);
  if (cookie === null) return null;
  const expected = uiCookieValue(cfg);
  if (expected === null) return null;
  return eqSafe(cookie, expected) ? 'cookie' : null;
}

export function isAllowedRead(req: ReadRequest, cfg: UiAuthConfig): boolean {
  return resolveReadPath(req, cfg) !== null;
}
