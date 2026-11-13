import { useMemo, useState } from 'react';
import { useItems, useSessions } from '../api/queries.tsx';
import { useRepoSelection } from '../hooks/useRepoSelection.tsx';
import { useItemFilters } from '../hooks/useItemFilters.tsx';
import { useIsMobile } from '../hooks/use-mobile.ts';
import { FilterBar } from '../components/FilterBar.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { ItemCard } from '../components/ItemCard.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select.tsx';
import type { ItemKind } from '@agent-ledger/shared';
import type { ItemView } from '@agent-ledger/shared/api';

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

type ColumnKey = 'open' | 'doing' | 'blocked' | 'done';
const COLUMNS: { key: ColumnKey; label: string }[] = [
  { key: 'open', label: 'OPEN' },
  { key: 'doing', label: 'IN PROGRESS' },
  { key: 'blocked', label: 'BLOCKED' },
  { key: 'done', label: 'DONE (this week)' },
];

function columnOf(item: ItemView): ColumnKey | null {
  if (item.status === 'proposed' || item.status === 'open') return 'open';
  if (item.status === 'doing') return 'doing';
  if (item.status === 'blocked') return 'blocked';
  if (item.status === 'done') {
    const at = item.done?.at ? new Date(item.done.at).getTime() : 0;
    return Date.now() - at <= WEEK_MS ? 'done' : null;
  }
  return null;
}

/** Board (`/`) — Kanban across the repos selected in the sidebar. Filters
 *  live in the URL; dropped items never appear here. */
export function Overview() {
  const repos = useRepoSelection();
  const { filters, set } = useItemFilters();
  const sessions = useSessions(repos.csv, true);
  const isMobile = useIsMobile();
  const [mobileCol, setMobileCol] = useState<ColumnKey>('open');

  const filtered = useItems({
    repo: repos.csv,
    owner: filters.owner || undefined,
    kind: (filters.kind as ItemKind) || undefined,
    priority: filters.priority || undefined,
    session: filters.session || undefined,
    q: filters.q || undefined,
  });
  const unfiltered = useItems({
    repo: repos.csv,
    owner: filters.owner || undefined,
    priority: filters.priority || undefined,
    session: filters.session || undefined,
    q: filters.q || undefined,
  });

  const counts = useMemo(() => {
    const items = unfiltered.data?.items ?? [];
    const c: Partial<Record<ItemKind | 'all', number>> = { all: 0 };
    for (const i of items) {
      if (i.status === 'dropped') continue;
      c.all = (c.all ?? 0) + 1;
      c[i.kind] = (c[i.kind] ?? 0) + 1;
    }
    return c;
  }, [unfiltered.data]);

  const columns = useMemo(() => {
    const items = filtered.data?.items ?? [];
    const byCol: Record<ColumnKey, ItemView[]> = { open: [], doing: [], blocked: [], done: [] };
    for (const i of items) {
      const col = columnOf(i);
      if (col) byCol[col].push(i);
    }
    return byCol;
  }, [filtered.data]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-2.5" style={{ borderColor: 'var(--border)' }}>
        <FilterBar filters={filters} set={set} counts={counts} sessions={sessions.data?.sessions} />
      </div>

      {filtered.isLoading && (
        <div className="p-4">
          <Loading />
        </div>
      )}
      {filtered.isError && (
        <div className="p-4">
          <RequestError error={filtered.error} />
        </div>
      )}

      {filtered.data && isMobile && (
        <div className="flex-1 min-h-0 flex flex-col gap-2 p-3 overflow-auto">
          <Select value={mobileCol} onValueChange={(v) => setMobileCol(v as ColumnKey)}>
            <SelectTrigger className="h-[34px] text-[12.5px] w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {COLUMNS.map((c) => (
                <SelectItem key={c.key} value={c.key}>
                  {c.label} ({columns[c.key].length})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {columns[mobileCol].map((i) => (
            <ItemCard key={i.id} item={i} />
          ))}
          {columns[mobileCol].length === 0 && (
            <div
              className="border border-dashed rounded-[2px] px-2.5 py-8 text-center text-[12px]"
              style={{ borderColor: 'var(--border)', color: 'var(--muted-foreground)' }}
            >
              nothing here
            </div>
          )}
        </div>
      )}

      {filtered.data && !isMobile && (
        <div className="flex-1 min-h-0 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 p-4 overflow-auto">
          {COLUMNS.map((col) => {
            const list = columns[col.key];
            return (
              <div
                key={col.key}
                className="min-w-0 min-h-0 flex flex-col border rounded-[2px]"
                style={{ borderColor: 'var(--border)', background: 'color-mix(in oklch, var(--card) 45%, transparent)' }}
              >
                <div
                  className="h-[38px] flex-none flex items-center gap-2 px-3 border-b"
                  style={{ borderColor: 'var(--border)', background: 'var(--background)' }}
                >
                  <span className="text-[12px] font-semibold">{col.label}</span>
                  <span className="font-mono text-[10.5px]" style={{ color: 'var(--muted-foreground)' }}>
                    {list.length}
                  </span>
                </div>
                <div className="flex-1 min-h-0 overflow-auto p-2 flex flex-col gap-2">
                  {list.map((i) => (
                    <ItemCard key={i.id} item={i} />
                  ))}
                  {list.length === 0 && (
                    <div
                      className="border border-dashed rounded-[2px] px-2.5 py-4 text-center text-[12px]"
                      style={{ borderColor: 'var(--border)', color: 'var(--muted-foreground)' }}
                    >
                      nothing here
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
