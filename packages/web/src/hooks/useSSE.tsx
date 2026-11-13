/** `GET /v1/events` (server-sent events). On each event we invalidate the
 *  query keys it affects instead of trying to patch cache by hand — the
 *  payloads are small and re-fetch is cheap on a localhost hub. Auto-reconnect
 *  is native to `EventSource`; we only track connection state for the UI. */

import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { SseEventName } from '@agent-ledger/shared/api';

const INVALIDATES: Record<SseEventName, string[][]> = {
  'item.created': [['items'], ['timeline']],
  'item.updated': [['items'], ['item'], ['timeline']],
  'item.status': [['items'], ['item'], ['timeline'], ['repo']],
  'session.start': [['sessions'], ['repo']],
  'session.end': [['sessions'], ['repo'], ['session']],
  'session.heartbeat': [['sessions']],
  'repo.dirty': [['repo']],
  'journal.appended': [['timeline'], ['repo']],
  'intake.created': [['intake']],
  'intake.triaged': [['intake'], ['intake-one'], ['items']],
  /* inbox, guard, leases */
  'inbox.new': [['inbox']],
  'guard.changed': [['healthz']],
  'intrude.begin': [['session'], ['repo']],
  'intrude.commit': [['session'], ['repo'], ['items'], ['timeline']],
  'intrude.end': [['session'], ['repo']],
  'lock.override': [['repo'], ['session']],
  'orphan.adopt': [['repo'], ['session']],
  /* replies */
  'reply.created': [['items'], ['item']],
  'reply.updated': [['items'], ['item']],
};

export type ConnState = 'connecting' | 'open' | 'down';

/** Rows carry `view-transition-name: item-<id>` (ItemRow) so a card
 *  moving between board columns / Needs-you / Resolved animates smoothly
 *  instead of popping. Falls back to an instant, unanimated DOM swap when the
 *  API is missing or the user asked for reduced motion — never a hard
 *  requirement for the UI to work. */
function withViewTransition(apply: () => Promise<unknown>) {
  const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  const supported = typeof document !== 'undefined' && 'startViewTransition' in document;
  if (!supported || reduced) {
    void apply();
    return;
  }
  (document as unknown as { startViewTransition: (cb: () => Promise<unknown>) => void }).startViewTransition(apply);
}

/** Events whose effect is a row moving between lists/columns — these get the
 *  animated swap. Everything else just invalidates immediately. */
const TRANSITIONED: SseEventName[] = ['item.status', 'item.updated', 'reply.created', 'reply.updated'];

export function useLiveEvents(): ConnState {
  const qc = useQueryClient();
  const [state, setState] = useState<ConnState>('connecting');

  useEffect(() => {
    let cancelled = false;
    const es = new EventSource('/v1/events', { withCredentials: true });

    es.onopen = () => {
      if (!cancelled) setState('open');
    };
    es.onerror = () => {
      if (!cancelled) setState('down');
    };

    const names = Object.keys(INVALIDATES) as SseEventName[];
    for (const name of names) {
      es.addEventListener(name, () => {
        const invalidateAll = () => Promise.all(INVALIDATES[name].map((key) => qc.invalidateQueries({ queryKey: key })));
        if (TRANSITIONED.includes(name)) withViewTransition(invalidateAll);
        else void invalidateAll();
      });
    }

    return () => {
      cancelled = true;
      es.close();
    };
  }, [qc]);

  return state;
}
