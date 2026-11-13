/** Thin hub client. Exit-code mapping lives here (SPEC §7):
 *  0 ok · 2 conflict · 3 hub not running · 4 validation · 5 secret scanner. */

import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { triggerSelfHeal } from './selfheal.ts';

/** Default request budget. Without a timeout a wedged hub would hang `ledger`
 *  (and `ledger wait`) forever instead of falling through to the spool. */
const REQUEST_TIMEOUT_MS = 5_000;
/** `/v1/healthz` either answers immediately or the hub is not healthy. */
const HEALTHZ_TIMEOUT_MS = 1_500;
/** After a self-heal: how long to give the service manager before the single retry. */
const HEAL_POLL_TOTAL_MS = 3_000;
const HEAL_POLL_STEP_MS = 250;

/**
 * Copies of the two classifiers in `hook.ts`, on purpose.
 *
 * `hook.ts` imports nothing from the rest of the CLI (its header explains why:
 * every module on that path costs real milliseconds per tool call), and this
 * module is on the slow path, so importing `hook.ts` here would drag the whole
 * hook graph into every `ledger` command just to share ten lines.
 */
function isRefusedErr(err: unknown, depth = 0): boolean {
  if (err === null || typeof err !== 'object' || depth > 4) return false;
  const o = err as { code?: unknown; errors?: unknown; cause?: unknown };
  if (o.code === 'ECONNREFUSED') return true;
  if (Array.isArray(o.errors) && o.errors.some((e) => isRefusedErr(e, depth + 1))) return true;
  return isRefusedErr(o.cause, depth + 1);
}

function isTimeoutErr(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false;
  const name = (err as { name?: unknown }).name;
  return name === 'TimeoutError' || name === 'AbortError';
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => {
    setTimeout(r, ms);
  });
}

export class CliError extends Error {
  readonly exitCode: number;
  /**
   * True only when the hub is *not answering* — a refused connection, a
   * timeout, or a 502/503 from something that is not the hub.
   *
   * This is the single gate for spooling. A missing token or a 4xx is NOT hub
   * down: the first means the hub never ran here (queueing would hide a setup
   * problem), the second means the hub answered and the request is wrong.
   */
  readonly hubDown: boolean;
  /**
   * The hub's JSON error body, when there was one. Structured detail the CLI
   * acts on: `conflicts` from `POST /v1/intrude`, `candidates` from a
   * `DUPLICATE` / `ALREADY_DONE` answer.
   */
  readonly detail: unknown;
  /** HTTP status when the hub answered. `null` for transport failures. */
  readonly status: number | null;

  constructor(
    exitCode: number,
    message: string,
    hubDown = false,
    detail?: unknown,
    status: number | null = null,
  ) {
    super(message);
    this.name = 'CliError';
    this.exitCode = exitCode;
    this.hubDown = hubDown;
    this.detail = detail;
    this.status = status;
  }
}

export function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return resolve(homedir(), p.slice(2));
  return isAbsolute(p) ? p : resolve(p);
}

export interface CliEnvConfig {
  baseUrl: string;
  ledgerDir: string;
  session: string | null;
  agent: string;
}

/** S2: `LEDGER_HUB_URL` must stay loopback — http:, host 127.0.0.1 or localhost.
 *  Anything else (https, a real host, a redirect target) could ship the
 *  bearer token to a network peer, so it is rejected before the token is
 *  ever read (exit 4). */
function assertLocalUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new CliError(4, `LEDGER_HUB_URL is not a valid URL: "${raw}"`);
  }
  if (u.protocol !== 'http:') {
    throw new CliError(4, `LEDGER_HUB_URL must be http:, not "${u.protocol}" ("${raw}")`);
  }
  if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') {
    throw new CliError(
      4,
      `LEDGER_HUB_URL must point at 127.0.0.1 or localhost, not "${u.hostname}"`,
    );
  }
  return raw;
}

export function readEnvConfig(env: NodeJS.ProcessEnv = process.env): CliEnvConfig {
  const port = env.LEDGER_HUB_PORT?.trim() || '4747';
  return {
    // 127.0.0.1, not localhost: the hub's Host check accepts both, but the
    // literal IP skips DNS and cannot be rebound.
    baseUrl: assertLocalUrl(
      (env.LEDGER_HUB_URL?.trim() || `http://127.0.0.1:${port}`).replace(/\/$/, ''),
    ),
    ledgerDir: expandHome(env.LEDGER_DIR?.trim() || '~/.ledger'),
    session: env.LEDGER_SESSION?.trim() || null,
    agent: env.LEDGER_AGENT?.trim() || 'orchestrator',
  };
}

export interface HubResponse {
  status: number;
  json: unknown;
  text: string;
}

/** Test seam — production always uses the defaults above. */
export interface HubTimeouts {
  requestMs?: number;
  healthzMs?: number;
  healPollTotalMs?: number;
  healPollStepMs?: number;
}

export class HubClient {
  private readonly baseUrl: string;
  private readonly tokenPath: string;
  private readonly ledgerDir: string;
  private readonly timeouts: Required<HubTimeouts>;
  /** One self-heal per process, no matter how many requests fail. */
  private healed = false;
  private token: string | null = null;

  constructor(cfg: CliEnvConfig, timeouts: HubTimeouts = {}) {
    this.baseUrl = cfg.baseUrl;
    this.ledgerDir = cfg.ledgerDir;
    this.tokenPath = join(cfg.ledgerDir, '.hub', 'token');
    this.timeouts = {
      requestMs: timeouts.requestMs ?? REQUEST_TIMEOUT_MS,
      healthzMs: timeouts.healthzMs ?? HEALTHZ_TIMEOUT_MS,
      healPollTotalMs: timeouts.healPollTotalMs ?? HEAL_POLL_TOTAL_MS,
      healPollStepMs: timeouts.healPollStepMs ?? HEAL_POLL_STEP_MS,
    };
  }

  /**
   * Restart the hub via the service manager + wait for `/v1/healthz`, at most
   * once per process.
   *
   * Only ever called after a *refused* connection, which is the one transport
   * failure that proves the request was never delivered.
   */
  async selfHeal(env: NodeJS.ProcessEnv = process.env): Promise<void> {
    if (this.healed) return;
    this.healed = true;
    await triggerSelfHeal({
      ledgerDir: this.ledgerDir,
      port: new URL(this.baseUrl).port || '80',
      env,
      mode: 'checked',
    });
    const deadline = Date.now() + this.timeouts.healPollTotalMs;
    for (;;) {
      try {
        const res = await fetch(`${this.baseUrl}/v1/healthz`, {
          redirect: 'manual',
          signal: AbortSignal.timeout(this.timeouts.healthzMs),
        });
        if (res.ok) return;
      } catch {
        // still down
      }
      if (Date.now() >= deadline) return;
      await sleep(this.timeouts.healPollStepMs);
    }
  }

  /** `SpoolingClient` needs the same token to sign/verify spool records
   *  — protected rather than a second read of the token file. */
  protected async readToken(): Promise<string | null> {
    if (this.token !== null) return this.token;
    try {
      this.token = (await readFile(this.tokenPath, 'utf8')).trim();
    } catch {
      this.token = null;
    }
    return this.token;
  }

  async request(method: string, path: string, payload?: unknown): Promise<HubResponse> {
    return this.requestKeyed(method, path, payload);
  }

  /**
   * Same as `request`, plus an `Idempotency-Key` header.
   *
   * `SpoolingClient` mints this key before the FIRST send of a
   * write, not only on spool replay, and reuses it if that send times out and
   * gets spooled. The key makes replay safe to repeat: the hub remembers what
   * the key produced and returns that instead of doing the work a second time.
   */
  async requestKeyed(
    method: string,
    path: string,
    payload?: unknown,
    idempotencyKey?: string,
  ): Promise<HubResponse> {
    const headers: Record<string, string> = { accept: 'application/json, text/plain' };
    if (idempotencyKey !== undefined) headers['idempotency-key'] = idempotencyKey;
    // S7: the hub now gates reads too (except /v1/healthz) — the CLI is
    // never a browser, so it always authenticates via the token header.
    const token = await this.readToken();
    if (!token) {
      throw new CliError(3, `hub token not found (${this.tokenPath}) — is the hub running? (\`ledger doctor\`)`);
    }
    headers['x-hub-token'] = token;
    if (method !== 'GET') {
      headers['content-type'] = 'application/json';
    }
    const body = method === 'GET' ? undefined : JSON.stringify(payload ?? {});
    const timeoutMs = path.endsWith('/healthz')
      ? this.timeouts.healthzMs
      : this.timeouts.requestMs;
    let res: Response;
    try {
      res = await this.send(method, path, headers, body, timeoutMs);
    } catch (err) {
      if (!isRefusedErr(err)) {
        // Timeout or any other transport error: the request may already have
        // been delivered, so it is NOT retried here — a retried write could
        // land twice. It falls through to the spool.
        throw this.downError(err, timeoutMs);
      }
      // Refused: nothing was listening, so nothing happened. Heal, wait for the
      // port, and retry exactly once.
      await this.selfHeal();
      try {
        res = await this.send(method, path, headers, body, timeoutMs);
      } catch (err2) {
        throw this.downError(err2, timeoutMs);
      }
    }
    if (res.status === 502 || res.status === 503) {
      // Nothing that IS the hub answers with these: a proxy or a half-started
      // process is on the port, so treat it as down and spool.
      throw new CliError(3, `hub is not answering (${res.status}) at ${this.baseUrl}`, true);
    }
    const text = await res.text();
    let json: unknown = null;
    if (text.trim().startsWith('{') || text.trim().startsWith('[')) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }
    if (res.ok) return { status: res.status, json, text };
    throw toError(res.status, json, text);
  }

  private send(
    method: string,
    path: string,
    headers: Record<string, string>,
    body: string | undefined,
    timeoutMs: number,
  ): Promise<Response> {
    return fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body,
      // S2: never follow a redirect blindly — it could carry the token off
      // loopback. A redirect is treated as a hard error, not a hop.
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    });
  }

  private downError(err: unknown, timeoutMs: number): CliError {
    if (isTimeoutErr(err)) {
      return new CliError(
        3,
        `hub did not answer within ${timeoutMs} ms (${this.baseUrl}) — status: \`ledger doctor\``,
        true,
      );
    }
    return new CliError(
      3,
      `hub is not running at ${this.baseUrl} (${(err as Error).message}) — \`ledger doctor --fix\``,
      true,
    );
  }

  get(path: string): Promise<HubResponse> {
    return this.request('GET', path);
  }

  post(path: string, payload?: unknown): Promise<HubResponse> {
    return this.request('POST', path, payload);
  }

  patch(path: string, payload?: unknown): Promise<HubResponse> {
    return this.request('PATCH', path, payload);
  }
}

/** Hub feature name (as in the 403 body) → the env flag that enables it. */
const FEATURE_FLAGS: Record<string, string> = {
  intrude: 'LEDGER_INTRUDE',
  web_replies: 'LEDGER_WEB_REPLIES',
  headless: 'LEDGER_HEADLESS',
  recap_guard: 'LEDGER_RECAP_GUARD',
};

/** Message for an optional hub feature that is switched off. */
export function featureDisabledMessage(json: unknown): string {
  const feature = String((json as { feature?: unknown } | null)?.feature ?? 'feature');
  const flag = FEATURE_FLAGS[feature] ?? `LEDGER_${feature.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
  return `${feature} is disabled on this hub (set ${flag}=1 and restart the hub)`;
}

function toError(status: number, json: unknown, text: string): CliError {
  const obj = (json ?? {}) as { error?: string; message?: string; findings?: { rule: string }[] };
  if (obj.error === 'SECRET') {
    const rules = (obj.findings ?? []).map((f) => f.rule).join(', ');
    return new CliError(
      5,
      `secret scanner: text not saved (rules: ${rules || 'unknown'})`,
      false,
      json,
      status,
    );
  }
  if (status === 403 && obj.error === 'feature_disabled') {
    return new CliError(4, featureDisabledMessage(json), false, json, status);
  }
  if (status >= 300 && status < 400) {
    return new CliError(
      4,
      `hub redirected the request (${status}) — refused (redirect: manual)`,
      false,
      json,
      status,
    );
  }
  if (status === 409) return new CliError(2, obj.message ?? 'conflict', false, json, status);
  if (status === 401 || status === 403) {
    return new CliError(
      4,
      obj.message ?? 'hub rejected the request (Host/token)',
      false,
      json,
      status,
    );
  }
  if (status >= 400 && status < 500) {
    return new CliError(
      4,
      obj.message ?? `error ${status}: ${text.slice(0, 200)}`,
      false,
      json,
      status,
    );
  }
  return new CliError(4, obj.message ?? `hub returned ${status}`, false, json, status);
}
