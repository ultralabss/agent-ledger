/**
 * "Post it and go": send a hook request and resolve as soon as the
 * body has left this process, without waiting for the hub to answer.
 *
 * Why not `fetch`: undici gives no signal for "the request body is flushed".
 * The only observable we need is the write callback of `node:http`'s
 * ClientRequest, which fires once libuv has handed every byte to the kernel's
 * send buffer. At that point the hub is going to receive the complete request
 * whatever this process does next, because closing a socket with `SO_LINGER`
 * off still delivers what the kernel already holds, then FINs.
 *
 * So after the flush we `unref()` the socket instead of destroying it:
 * destroying could reset the connection before the hub finished reading, while
 * unref only stops the pending (and unwanted) response from holding the event
 * loop open. The process then exits on its own and the response is discarded.
 *
 * This module is imported dynamically — `node:http` must not be on the startup
 * path of hooks that never use it.
 */

import { request } from 'node:http';

export interface SendNoWaitOptions {
  port: string;
  event: string;
  token: string;
  body: string;
  timeoutMs: number;
}

/** Resolves `true` when the whole body reached the kernel, `false` on any
 *  failure (hub down, timeout). Never rejects — callers exit 0 either way. */
export function sendNoWait(o: SendNoWaitOptions): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      resolve(ok);
    };
    let req: ReturnType<typeof request>;
    try {
      req = request({
        host: '127.0.0.1',
        port: Number(o.port),
        path: `/v1/hooks/${o.event}`,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-hub-token': o.token,
          'content-length': String(Buffer.byteLength(o.body)),
          // We are never going to reuse this socket, and the hub should not
          // keep one half-open for a client that has already exited.
          connection: 'close',
        },
      });
    } catch {
      done(false);
      return;
    }
    // Only a connect/write failure can trip this — we are not waiting for the
    // response, so a slow hub cannot time out here.
    req.setTimeout(o.timeoutMs, () => {
      req.destroy();
      done(false);
    });
    req.on('error', () => done(false));
    req.end(o.body, () => {
      // Flushed. Let the un-awaited response stop keeping the loop alive.
      req.socket?.unref();
      done(true);
    });
  });
}
