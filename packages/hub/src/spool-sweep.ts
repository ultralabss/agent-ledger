/**
 * The hub flushes the spool itself on startup.
 *
 * Without this, a queued write waits for the next `ledger` command. The common
 * case is exactly the opposite: the hub was restarted, the session that queued
 * the write has moved on, and nobody runs another command for an hour.
 *
 * The adapter is handed a `fetch`; the hub passes the global one, so replays go
 * over loopback to its own (already bound) port — the same path as the CLI.
 * In-process `app.fetch` looked cheaper but its single-use Request bodies broke
 * on the idempotency middleware (500 "ReadableStream is locked"). Either way the
 * request passes the full middleware stack — guard, idempotency, validation — so
 * a replayed write is indistinguishable from a live one.
 */

import { lightSpoolStats, replaySpool, type KeyedRequester, type ReplayResult } from '@agent-ledger/shared';

export interface SweepDeps {
  fetch: (req: Request) => Response | Promise<Response>;
  /** The hub's own token — the guard gates `/v1/*` for reads too. */
  token: string;
  port: number;
  log: (line: string) => void;
  env?: NodeJS.ProcessEnv;
}

/** `KeyedRequester` over `app.fetch`. Throws the shape `replaySpool` expects. */
class InProcessClient implements KeyedRequester {
  private readonly deps: SweepDeps;

  constructor(deps: SweepDeps) {
    this.deps = deps;
  }

  async requestKeyed(
    method: string,
    path: string,
    payload: unknown,
    key: string,
  ): Promise<{ status: number }> {
    // Host must look loopback: the guard rejects anything else.
    const url = `http://127.0.0.1:${this.deps.port}${path}`;
    const res = await this.deps.fetch(
      new Request(url, {
        method,
        headers: {
          // In-process `app.fetch` gets no Host from a network layer — set it
          // explicitly, or the guard answers 403 FORBIDDEN_HOST to every replay.
          host: `127.0.0.1:${this.deps.port}`,
          'content-type': 'application/json',
          accept: 'application/json',
          'x-hub-token': this.deps.token,
          'idempotency-key': key,
        },
        body: method === 'GET' ? undefined : JSON.stringify(payload ?? {}),
      }),
    );
    if (res.status >= 200 && res.status < 300) return { status: res.status };
    const text = await res.text().catch(() => '');
    const err = new Error(`hub returned ${res.status}: ${text.slice(0, 300)}`) as Error & {
      exitCode: number;
      status: number;
    };
    // 409 → exit 2, which `replaySpool` treats as "already had its effect".
    err.exitCode = res.status === 409 ? 2 : 4;
    // `replaySpool` classifies on `status`, never on the message text.
    err.status = res.status;
    throw err;
  }
}

export async function sweepSpool(deps: SweepDeps): Promise<ReplayResult> {
  const client = new InProcessClient(deps);
  try {
    const res = await replaySpool(client, deps.env ?? process.env, () => Promise.resolve(deps.token));
    if (res.sent > 0 || res.failed > 0) {
      deps.log(`spool sweep: sent ${res.sent}, failed ${res.failed}`);
    }
    return res;
  } catch (err) {
    // A broken spool must never stop the hub from starting.
    deps.log(`spool sweep failed: ${String(err)}`);
    return { sent: 0, failed: 0, offline: false };
  }
}

/**
 * `spoolStats` with a 1 s cache, for `/v1/healthz`.
 *
 * healthz is polled by the web UI; counting spool records means a `readdir` plus
 * a read per file, which is cheap but not free at 1 Hz. The counter is advisory,
 * so a second of staleness costs nothing.
 */
export function cachedSpoolStats(
  env: NodeJS.ProcessEnv = process.env,
  ttlMs = 1000,
): () => { queued: number; failed: number } {
  let cached = { queued: 0, failed: 0 };
  let at = 0;
  let inFlight = false;
  return () => {
    const now = Date.now();
    if (now - at > ttlMs && !inFlight) {
      inFlight = true;
      // Async refresh behind a sync getter: healthz must not await the disk.
      void lightSpoolStats(env)
        .then((s) => {
          cached = s;
          at = Date.now();
        })
        .catch(() => undefined)
        .finally(() => {
          inFlight = false;
        });
    }
    return cached;
  };
}
