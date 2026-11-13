/** Thin fetch wrapper over `/v1/*`. All requests are same-origin, cookie-auth
 *  — the hub mints `hub_ui` itself. We never read or send
 *  `X-Hub-Token` here; that header is for CLI/agent callers only. */

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Optional hub features (web replies, headless runs) are off by default; the
 *  hub answers 403 `{error:'feature_disabled', feature}` when one is used. */
export class FeatureDisabledError extends ApiError {
  feature: string;

  constructor(feature: string, message: string) {
    super(403, 'feature_disabled', message);
    this.feature = feature;
  }
}

const FEATURE_HINTS: Record<string, string> = {
  web_replies: 'Replies from the web are disabled on this hub. Set LEDGER_WEB_REPLIES=1 and restart.',
  headless: 'Headless runs are disabled on this hub. Set LEDGER_HEADLESS=1 and restart.',
};

/** Thrown by the query layer so routes can show the "not logged in" screen
 *  instead of a generic error card. */
export class UnauthorizedError extends ApiError {}

/** Thrown when the API rejects a write because the text contains a secret
 *  Never carries the offending value. */
export class SecretRejectedError extends ApiError {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      credentials: 'same-origin',
      headers: init?.body ? { 'content-type': 'application/json' } : undefined,
      ...init,
    });
  } catch (err) {
    throw new ApiError(0, 'NETWORK', err instanceof Error ? err.message : 'network error');
  }

  if (res.status === 204) return undefined as T;

  let payload: unknown = null;
  const text = await res.text();
  if (text.length > 0) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!res.ok) {
    const errObj = (payload ?? {}) as { error?: string; message?: string; feature?: string };
    const code = errObj.error ?? `HTTP_${res.status}`;
    const message = errObj.message ?? `server error (${res.status})`;
    if (res.status === 403 && code === 'feature_disabled') {
      const feature = errObj.feature ?? 'unknown';
      throw new FeatureDisabledError(
        feature,
        FEATURE_HINTS[feature] ?? `The "${feature}" feature is disabled on this hub (see the LEDGER_* settings).`,
      );
    }
    if (res.status === 401) throw new UnauthorizedError(res.status, code, message);
    if (res.status === 422 && code === 'SECRET') {
      throw new SecretRejectedError(res.status, code, 'text contains a secret — strip it before sending');
    }
    throw new ApiError(res.status, code, message);
  }

  return payload as T;
}

export function apiGet<T>(path: string): Promise<T> {
  return request<T>(path, { method: 'GET' });
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
}

export function apiPatch<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: 'PATCH', body: JSON.stringify(body) });
}

/** Builds a `?a=b&c=d` query string, dropping empty/undefined values. */
export function qs(params: Record<string, string | number | boolean | undefined>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === '') continue;
    usp.set(k, String(v));
  }
  const s = usp.toString();
  return s.length > 0 ? `?${s}` : '';
}
