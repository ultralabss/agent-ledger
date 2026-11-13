/** In-process fan-out for `GET /v1/events` (SPEC §6.4).
 *
 *  Deliberately not `EventEmitter`: a slow or dead SSE client must never make
 *  the writer (a hook on a 1 s budget) wait or throw. Each subscriber gets a
 *  bounded queue; when it overflows the oldest events are dropped and the
 *  client is told to refetch, which is the right trade-off for a live view.
 */

import type { SseEnvelope, SseEventName } from '@agent-ledger/shared';
import { isoLocal } from '@agent-ledger/shared';

const MAX_QUEUE = 256;

export interface Subscriber {
  id: string;
  push: (env: SseEnvelope) => void;
}

export class EventBus {
  private subs = new Map<string, Subscriber>();
  private seq = 0;

  get size(): number {
    return this.subs.size;
  }

  subscribe(push: (env: SseEnvelope) => void): () => void {
    this.seq += 1;
    const id = `s${this.seq}`;
    this.subs.set(id, { id, push });
    return () => {
      this.subs.delete(id);
    };
  }

  emit(event: SseEventName, repo: string | null, data: unknown): void {
    const env: SseEnvelope = { event, at: isoLocal(), repo, data };
    for (const sub of this.subs.values()) {
      try {
        sub.push(env);
      } catch {
        // A broken pipe is the client's problem — drop it silently, the stream
        // handler removes the subscription on its own error path.
        this.subs.delete(sub.id);
      }
    }
  }
}

export const MAX_SSE_QUEUE = MAX_QUEUE;
