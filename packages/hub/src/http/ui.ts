/**
 * Static UI serving + UI login — SPEC §13, §6.5 (serve only; the app itself is
 * `web-dev`'s job and this repo never creates `packages/web/`).
 *
 * Security rules, all enforced here:
 *  - files come only from `realpath(packages/web/dist)`; a request whose
 *    resolved target is outside that directory is a 404, so neither `..` nor a
 *    symlink planted inside `dist` can read the ledger or `~/.ssh`,
 *  - `Set-Cookie: hub_ui=…` is minted by `GET /login` and NOWHERE else: not on
 *    `/` (an unauthenticated local process must not trade a plain `GET /` for
 *    ledger read access), not on `/v1/*` (an API reply is not a navigation),
 *    not on an asset (a cached `.js` would carry the cookie into disk cache),
 *  - the hub token NEVER appears in a URL. The old `?token=` bootstrap is gone
 *    (it put the write secret into history, `Referer` and every proxy log);
 *    `POST /v1/ui/login-code` mints a one-shot 32 B code instead, and only the
 *    code — useless after one use and after 60 s — travels in the URL,
 *  - HTML carries the CSP/nosniff/no-referrer headers; assets do not need them
 *    and `nosniff` on a hashed asset is added anyway because it is free.
 *
 * Both endpoints live in this file on purpose: `app.all('*')` already routes
 * every non-`/v1` path here, and `POST /v1/ui/login-code` reaches this handler
 * after `guard()` has run, so the token check in front of it is the same one
 * every other write gets.
 */

import { readFile, realpath, stat } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Context } from 'hono';
import {
  FailureLimiter,
  isAllowedHost,
  isAllowedRead,
  LoginCodeStore,
  safeNextPath,
  uiCookie,
} from '../security/index.ts';

/** `packages/web/dist`, sibling of this package. */
export function defaultUiDir(): string {
  const here = dirname(fileURLToPath(import.meta.url)); // packages/hub/src/http
  return resolve(here, '..', '..', '..', 'web', 'dist');
}

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

function contentType(path: string): string {
  const dot = path.lastIndexOf('.');
  const ext = dot < 0 ? '' : path.slice(dot).toLowerCase();
  return TYPES[ext] ?? 'application/octet-stream';
}

export interface UiDeps {
  /** Overridable for tests. */
  dir?: string;
  /**
   * The LIVE guard config, not a copy of `token`/`port`.
   *
   * Audit finding (UI login): copying the token at construction time meant that
   * after a rotation (`setTokenLeakHandler`) this handler kept minting cookies
   * for the OLD, leaked token — and kept validating them. Copying `port` had the
   * same class of bug with `port: 0`. Holding the object means every read sees
   * the current value.
   */
  guard: { token: string; uiSecret: string; port: number };
  /** Overridable for tests (short TTL / fake clock). */
  codes?: LoginCodeStore;
  /** Overridable for tests (small limit). */
  loginLimiter?: FailureLimiter;
}

/** `POST` here (with `X-Hub-Token`) returns the one-shot login URL. */
export const LOGIN_CODE_PATH = '/v1/ui/login-code';
export const LOGIN_PATH = '/login';

/**
 * Headers every HTML response gets (SPEC §13 + §6.5).
 * Deliberately no `Set-Cookie`: HTML is served to anyone on loopback (it carries
 * no ledger data — the SPA shows the "run `ledger open`" prompt after its first
 * 401 from the API), and the session cookie is minted only by `/login`.
 */
function htmlHeaders(c: Context): void {
  c.header('content-type', 'text/html; charset=utf-8');
  c.header('content-security-policy', CSP);
  c.header('x-content-type-options', 'nosniff');
  c.header('referrer-policy', 'no-referrer');
  c.header('cache-control', 'no-store');
}

const PLACEHOLDER = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-ledger</title>
<style>
  body { font: 15px/1.6 -apple-system, system-ui, sans-serif; margin: 3rem auto; max-width: 42rem; padding: 0 1rem; color: #222; }
  code { background: #f4f4f5; padding: .1rem .3rem; border-radius: 3px; }
  ul { padding-left: 1.2rem; }
</style>
</head>
<body>
<h1>agent-ledger is running</h1>
<p>The web UI is not built yet — <code>packages/web/dist</code> does not exist.</p>
<p>The API is at <code>/v1</code>. Quick overview from the terminal:</p>
<ul>
  <li><code>ledger brief</code> — briefing</li>
  <li><code>ledger who &lt;repo&gt;</code> — who is working on what</li>
  <li><code>ledger sessions --live</code> — live sessions</li>
  <li><code>ledger search "&lt;q&gt;"</code> — full-text search</li>
</ul>
<p>UI login: <code>ledger open</code> (one-time code, valid for 60 s).</p>
<p>Once the UI exists, build it into <code>packages/web/dist</code> and reload the page.</p>
</body>
</html>
`;

/** Minimal HTML page (login errors). No ledger data, no user input echoed. */
function loginPage(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-ledger — ${title}</title>
<style>
  body { font: 15px/1.6 -apple-system, system-ui, sans-serif; margin: 3rem auto; max-width: 34rem; padding: 0 1rem; color: #222; }
  code { background: #f4f4f5; padding: .1rem .3rem; border-radius: 3px; }
</style>
</head>
<body>
<h1>${title}</h1>
${body}
</body>
</html>
`;
}

const LOGIN_DENIED = loginPage(
  'Login failed',
  `<p>The code is invalid or has expired — it is valid for 60 seconds and for a single use.</p>
<p>Run <code>ledger open</code> in a terminal.</p>`,
);

const LOGIN_THROTTLED = loginPage(
  'Too many attempts',
  `<p>Login is blocked for a moment.</p>
<p>Wait a minute and run <code>ledger open</code>.</p>`,
);

/**
 * The port the client actually uses to talk to the hub. Taken from `Host` (for
 * `/v1/*` `guard()` has already verified it equals `cfg.port`), because
 * `deps.guard.port` can still be zero with `port: 0` (random OS port) until
 * `listen` completes. Falls back to `deps.guard.port`.
 */
function portFromHost(host: string | undefined, fallback: number): number {
  if (typeof host !== 'string') return fallback;
  const colon = host.lastIndexOf(':');
  if (colon < 0) return fallback;
  const port = Number(host.slice(colon + 1));
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : fallback;
}

/**
 * `Host` gate for `/login` (outside `guard()`, which covers only `/v1/*`).
 * When the real port is known, requires an exact match like `guard()`. When the
 * hub got its port from the OS and `deps.guard.port` is still 0, any loopback
 * authority is allowed — this still blocks DNS rebinding to a foreign name.
 */
function loginHostAllowed(host: string | undefined, deps: UiDeps): boolean {
  if (deps.guard.port > 0 && isAllowedHost(host, deps.guard.port)) return true;
  if (typeof host !== 'string' || host.length === 0 || host.length > 64) return false;
  if (/[\s/@\\[\]]/.test(host)) return false;
  return /^(?:127\.0\.0\.1|localhost|ledger\.localhost):[0-9]{1,5}$/.test(host.toLowerCase());
}

/**
 * `POST /v1/ui/login-code` — issues a one-time code and a URL for the browser.
 * Requires `X-Hub-Token`: a cookie is deliberately not enough here, so that an
 * XSS in the UI cannot mint a new (longer-lived) login artifact.
 */
async function handleLoginCode(c: Context, deps: UiDeps, codes: LoginCodeStore): Promise<Response> {
  const tokenHeader = c.req.header('x-hub-token');
  if (!isAllowedRead({ tokenHeader, cookieHeader: undefined }, deps.guard)) {
    return c.json({ error: 'UNAUTHORIZED', message: 'requires a valid X-Hub-Token' }, 401);
  }
  let body: unknown = null;
  try {
    body = await c.req.json();
  } catch {
    body = null; // an empty body is fine
  }
  const rawNext = (body as { next?: unknown } | null)?.next;
  let next: string | null = null;
  if (rawNext !== undefined && rawNext !== null && rawNext !== '') {
    next = safeNextPath(rawNext);
    if (next === null) {
      return c.json(
        { error: 'VALIDATION', message: 'next must be a relative path starting with "/"' },
        400,
      );
    }
  }
  const port = portFromHost(c.req.header('host'), deps.guard.port);
  const code = codes.issue();
  const query = new URLSearchParams({ code });
  if (next !== null) query.set('next', next);
  c.header('cache-control', 'no-store');
  c.header('referrer-policy', 'no-referrer');
  return c.json({
    url: `http://127.0.0.1:${port}${LOGIN_PATH}?${query.toString()}`,
    expiresInSeconds: Math.round(codes.ttlMs / 1000),
  });
}

/**
 * `GET /login?code=…[&next=/path]` — consumes the code and issues the session cookie.
 * The code is never logged. The response is `303` (GET to the target) with
 * `no-store`, so the URL with the code does not stay in the cache and
 * `no-referrer` does not forward it.
 */
function handleLogin(
  c: Context,
  deps: UiDeps,
  codes: LoginCodeStore,
  limiter: FailureLimiter,
): Response {
  const host = c.req.header('host');
  if (!loginHostAllowed(host, deps)) {
    c.header('cache-control', 'no-store');
    c.header('referrer-policy', 'no-referrer');
    return c.json(
      { error: 'FORBIDDEN_HOST', message: 'hub accepts only a loopback Host with its own port' },
      403,
    );
  }
  htmlHeaders(c);
  // The code is verified BEFORE the rate limit. `/login` has no auth, so any
  // page in the browser can burn 10 failures a minute
  // (`<img src="…/login?code=x">`) — if the limit ran before verification it
  // would lock the user out of the UI (DoS) and a valid code would burn on a 429.
  // The code has 256 bits of entropy, so the limit only guards against guessing;
  // a successful login therefore passes even during a block.
  if (!codes.consume(c.req.query('code'))) {
    if (limiter.blocked) {
      c.header('retry-after', String(Math.ceil(limiter.windowMs / 1000)));
      return c.body(LOGIN_THROTTLED, 429);
    }
    limiter.fail();
    return c.body(LOGIN_DENIED, 401);
  }
  limiter.reset();
  const target = safeNextPath(c.req.query('next')) ?? '/';
  // B4-1: `/login` is the ONLY issuer of a cookie keyed by the per-boot
  // `uiSecret`. `null` means the hub has no usable secret — refuse rather than
  // redirect to a UI that will 401 on every request with no explanation.
  const cookie = uiCookie(deps.guard, portFromHost(host, deps.guard.port));
  if (cookie === null) {
    c.header('cache-control', 'no-store');
    c.header('referrer-policy', 'no-referrer');
    return c.body(LOGIN_DENIED, 503);
  }
  c.header('set-cookie', cookie);
  c.header('cache-control', 'no-store');
  c.header('referrer-policy', 'no-referrer');
  c.header('content-type', 'text/html; charset=utf-8');
  c.header('location', target);
  return c.body(null, 303);
}

async function safeStat(p: string): Promise<{ isFile: boolean } | null> {
  try {
    const st = await stat(p);
    return { isFile: st.isFile() };
  } catch {
    return null;
  }
}

/**
 * Resolve a URL path to a file inside `dist`, or null.
 * The containment check runs on the *realpath* of the candidate, so a symlink
 * inside `dist` pointing at `/etc/passwd` is rejected just like `../../etc`.
 */
export async function resolveAsset(distReal: string, urlPath: string): Promise<string | null> {
  let decoded: string;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null; // malformed percent-encoding
  }
  if (decoded.includes('\0')) return null;
  // `join` already normalises `..`, but do the containment check on the
  // resolved real path — that is the part that also covers symlinks.
  const candidate = join(distReal, decoded.replace(/^\/+/, ''));
  let real: string;
  try {
    real = await realpath(candidate);
  } catch {
    return null;
  }
  if (real !== distReal && !real.startsWith(distReal + sep)) return null;
  const st = await safeStat(real);
  return st?.isFile ? real : null;
}

/** Hono handler for every non-`/v1` path: static file, SPA fallback, placeholder. */
export function uiHandler(deps: UiDeps) {
  const dir = deps.dir ?? defaultUiDir();
  const codes = deps.codes ?? new LoginCodeStore();
  const limiter = deps.loginLimiter ?? new FailureLimiter();
  return async (c: Context): Promise<Response> => {
    // Reached only after `guard()` — which already required a valid Host and a
    // write-grade credential for POST. The handler re-checks the token header on
    // its own, see `handleLoginCode`.
    if (c.req.method === 'POST' && c.req.path === LOGIN_CODE_PATH) {
      return handleLoginCode(c, deps, codes);
    }
    // This handler is registered as `app.all('*')`, so it also catches paths
    // under `/v1` that no route matched. Those must stay JSON 404s: serving the
    // SPA there would (a) hide an API typo behind an HTML 200 and (b) attach
    // `Set-Cookie` to a `/v1/*` response, which SPEC §13 forbids outright.
    if (c.req.path === '/v1' || c.req.path.startsWith('/v1/')) {
      return c.json({ error: 'NOT_FOUND', message: `unknown path ${c.req.path}` }, 404);
    }
    if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
      return c.json({ error: 'NOT_FOUND', message: `unknown path ${c.req.path}` }, 404);
    }
    // GET only: a `HEAD /login` (link prefetch, scanner) must not burn the
    // one-shot code, and it is never a real navigation.
    if (c.req.path === LOGIN_PATH) {
      if (c.req.method !== 'GET') {
        return c.json({ error: 'NOT_FOUND', message: `unknown path ${c.req.path}` }, 404);
      }
      return handleLogin(c, deps, codes, limiter);
    }

    let distReal: string;
    try {
      distReal = await realpath(dir);
    } catch {
      htmlHeaders(c);
      return c.body(PLACEHOLDER, 200);
    }

    const file = await resolveAsset(distReal, c.req.path);
    if (file !== null) {
      const type = contentType(file);
      const data = await readFile(file);
      if (type.startsWith('text/html')) {
        htmlHeaders(c);
        return c.body(new Uint8Array(data), 200);
      }
      // Asset: no cookie, no CSP (it is not a document), but nosniff is free.
      c.header('content-type', type);
      c.header('x-content-type-options', 'nosniff');
      return c.body(new Uint8Array(data), 200);
    }

    // SPA fallback — every unknown path is a client route.
    const index = await resolveAsset(distReal, '/index.html');
    if (index === null) {
      htmlHeaders(c);
      return c.body(PLACEHOLDER, 200);
    }
    htmlHeaders(c);
    return c.body(new Uint8Array(await readFile(index)), 200);
  };
}

export const UI_CSP = CSP;
