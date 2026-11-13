/** Board/list filters (kind, status, owner, priority, session, text) kept in
 *  the URL query string — shareable, back-button works. */
import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router';

export interface ItemFiltersState {
  kind: string;
  status: string;
  owner: string;
  priority: string;
  session: string;
  q: string;
}

const EMPTY: ItemFiltersState = { kind: '', status: '', owner: '', priority: '', session: '', q: '' };

export function useItemFilters(): {
  filters: ItemFiltersState;
  set: (patch: Partial<ItemFiltersState>) => void;
  reset: () => void;
  preset: (name: 'needs-me' | 'in-progress' | 'done-week') => void;
} {
  const [params, setParams] = useSearchParams();

  const filters = useMemo<ItemFiltersState>(
    () => ({
      kind: params.get('kind') ?? '',
      status: params.get('status') ?? '',
      owner: params.get('owner') ?? '',
      priority: params.get('priority') ?? '',
      session: params.get('session') ?? '',
      q: params.get('q') ?? '',
    }),
    [params],
  );

  const set = useCallback(
    (patch: Partial<ItemFiltersState>) => {
      const next = new URLSearchParams(params);
      for (const [k, v] of Object.entries(patch)) {
        if (v) next.set(k, v);
        else next.delete(k);
      }
      setParams(next, { replace: true });
    },
    [params, setParams],
  );

  const reset = useCallback(() => setParams(new URLSearchParams(), { replace: true }), [setParams]);

  const preset = useCallback(
    (name: 'needs-me' | 'in-progress' | 'done-week') => {
      if (name === 'needs-me') set({ ...EMPTY, owner: 'human', status: '' });
      if (name === 'in-progress') set({ ...EMPTY, status: 'doing' });
      if (name === 'done-week') set({ ...EMPTY, status: 'done' });
    },
    [set],
  );

  return { filters, set, reset, preset };
}
