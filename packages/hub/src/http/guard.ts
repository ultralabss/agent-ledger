/** Host / token gate in front of every route (SPEC §6.5, S7).
 *
 *  Every route needs a valid `X-Hub-Token` (or the UI cookie on a
 *  same-origin request) — reads included — except `GET /v1/healthz`, which
 *  always passes the Host gate; the handler itself reads `authPath` below to
 *  decide how much detail to return (SPEC: healthz never leaks detail to an
 *  unauthenticated caller, but always answers `{ok}`).
 *  Mutations additionally need the write rules (Origin + `Sec-Fetch-Site` for
 *  the cookie path). The rules themselves live in `../security/` — this
 *  middleware only maps them to HTTP.
 *
 *  The guard is the ONLY place that decides which credential
 *  authorized a request, and it records that decision on the context as
 *  `authPath`. Routes used to re-derive it from `c.req.header('x-hub-token')`
 *  being merely PRESENT — a request with a garbage token header and a valid
 *  cookie counted as "token caller", and a cookie-less caller could flip the
 *  owner gate by just dropping the header. `authPath` is set from the same
 *  check that actually granted access, so the two can never disagree.
 */

import type { Context, MiddlewareHandler } from 'hono';
import type { AuthPath } from '../security/index.ts';
import { isAllowedHost, resolveReadPath, resolveWritePath } from '../security/index.ts';

declare module 'hono' {
  interface ContextVariableMap {
    /** See `GuardVariables.authPath`. */
    authPath: AuthPath | null;
  }
}

export interface GuardConfig {
  token: string;
  /** B4-1: per-boot secret for the UI cookie path. In memory only, never on
   *  disk, never in a response body — see `security/origin.ts`. */
  uiSecret: string;
  /** Mutable: the port is only known after `listen` when binding to 0. */
  port: number;
}

/** Hono context variables this middleware sets. */
export interface GuardVariables {
  /** Which credential authorized THIS request; `null` on the unauthenticated
   *  healthz pass-through (the only route that reaches a handler without it). */
  authPath: AuthPath | null;
}

/** The single reader of `authPath`. Anything else is a bug (B4-1). */
export function authPathOf(c: Context): AuthPath | null {
  return c.get('authPath') ?? null;
}

/** `true` only when the caller proved it holds the hub token. */
export function isTokenCaller(c: Context): boolean {
  return authPathOf(c) === 'token';
}

/** `true` only when a human at the browser authorized this request (B4-1):
 *  a per-boot-secret cookie plus the browser-set `Origin`/`Sec-Fetch-Site`. */
export function isCookieCaller(c: Context): boolean {
  return authPathOf(c) === 'cookie';
}

export function guard(cfg: GuardConfig): MiddlewareHandler {
  return async (c, next) => {
    const host = c.req.header('host');
    if (!isAllowedHost(host, cfg.port)) {
      return c.json(
        { error: 'FORBIDDEN_HOST', message: 'hub accepts only a loopback Host with its own port' },
        403,
      );
    }
    const tokenHeader = c.req.header('x-hub-token');
    const cookieHeader = c.req.header('cookie');
    // Browser-set, unforgeable from JS — the cookie path requires it, the
    // token path ignores it (the CLI is not a browser).
    const secFetchSite = c.req.header('sec-fetch-site');
    const readPath = resolveReadPath({ tokenHeader, cookieHeader, secFetchSite }, cfg);

    const isHealthz = c.req.method === 'GET' && c.req.path === '/v1/healthz';
    if (isHealthz) {
      // S7: healthz always answers, but the handler must know whether the
      // caller is authenticated — it reads `authPath`, it does not re-check.
      c.set('authPath', readPath);
      await next();
      return;
    }
    if (readPath === null) {
      return c.json(
        { error: 'UNAUTHORIZED', message: 'requires a valid X-Hub-Token or UI session' },
        401,
      );
    }
    const writePath = resolveWritePath(
      {
        method: c.req.method,
        host,
        origin: c.req.header('origin'),
        tokenHeader,
        cookieHeader,
        secFetchSite,
      },
      cfg,
    );
    if (writePath === null) {
      return c.json({ error: 'UNAUTHORIZED', message: 'write requires a valid X-Hub-Token' }, 401);
    }
    // The path that actually authorized this request — for a write that is the
    // write check, not the (weaker) read check.
    c.set('authPath', writePath);
    await next();
  };
}
