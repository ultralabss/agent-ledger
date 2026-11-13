import type { ItemKind } from '@agent-ledger/shared';
import type { SessionView } from '@agent-ledger/shared/api';
import type { ItemFiltersState } from '../hooks/useItemFilters.tsx';
import { Input } from './ui/input.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select.tsx';

const KINDS: ItemKind[] = ['BLOCKER', 'DEPLOY', 'RISK', 'UNVERIFIED', 'BACKLOG'];
const KIND_LABEL: Record<ItemKind, string> = {
  BLOCKER: 'BLOCKER',
  DEPLOY: 'DEPLOY',
  RISK: 'RISK',
  UNVERIFIED: 'UNVERIFIED',
  BACKLOG: 'BACKLOG',
};
const KIND_VAR: Record<ItemKind, string> = {
  BLOCKER: 'var(--k-blocking)',
  DEPLOY: 'var(--k-deploy)',
  RISK: 'var(--k-risk)',
  UNVERIFIED: 'var(--k-unverified)',
  BACKLOG: 'var(--k-backlog)',
};

/** Filter chips + selects — state lives in the URL via
 *  useItemFilters, so it is shareable and survives back/forward navigation.
 *  Layout: kind chip row, then Owner/Priority/Session selects and a text input. */
export function FilterBar({
  filters,
  set,
  counts,
  sessions,
}: {
  filters: ItemFiltersState;
  set: (patch: Partial<ItemFiltersState>) => void;
  /** item count per kind, for the chip badges — `all` is the unfiltered total */
  counts?: Partial<Record<ItemKind | 'all', number>>;
  sessions?: Pick<SessionView, 'id' | 'title' | 'short'>[];
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="flex border border-input bg-card rounded-[2px] overflow-hidden">
        <button
          type="button"
          className="flex items-center gap-1.5 h-7 px-2.5 text-[11.5px] font-medium tracking-tight hover:text-foreground"
          style={{ color: filters.kind ? 'var(--muted-foreground)' : 'var(--foreground)' }}
          onClick={() => set({ kind: '' })}
        >
          All
          <span className="font-mono text-[10.5px]" style={{ color: 'var(--muted-foreground)' }}>
            {counts?.all ?? ''}
          </span>
        </button>
        {KINDS.map((k) => (
          <button
            key={k}
            type="button"
            className="flex items-center gap-1.5 h-7 px-2.5 border-l text-[11.5px] font-medium tracking-tight hover:text-foreground"
            style={{ borderColor: 'var(--input)', color: filters.kind === k ? 'var(--foreground)' : 'var(--muted-foreground)' }}
            onClick={() => set({ kind: filters.kind === k ? '' : k })}
          >
            <span className="w-[7px] h-[7px]" style={{ background: KIND_VAR[k] }} />
            {KIND_LABEL[k]}
            <span className="font-mono text-[10.5px]" style={{ color: 'var(--muted-foreground)' }}>
              {counts?.[k] ?? 0}
            </span>
          </button>
        ))}
      </div>

      <Select value={filters.owner || 'all'} onValueChange={(v) => set({ owner: v === 'all' ? '' : v })}>
        <SelectTrigger size="sm" className="h-[30px] text-[12.5px] rounded-[2px]">
          <SelectValue placeholder="Owner: any" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">Owner: any</SelectItem>
          <SelectItem value="human">Owner: you</SelectItem>
          <SelectItem value="agent">Owner: agent</SelectItem>
        </SelectContent>
      </Select>

      <Select value={filters.priority || 'all'} onValueChange={(v) => set({ priority: v === 'all' ? '' : v })}>
        <SelectTrigger size="sm" className="h-[30px] text-[12.5px] rounded-[2px]">
          <SelectValue placeholder="Priority: any" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">Priority: any</SelectItem>
          <SelectItem value="P0">P0 · now</SelectItem>
          <SelectItem value="P1">P1 · next</SelectItem>
          <SelectItem value="P2">P2 · later</SelectItem>
          <SelectItem value="P3">P3 · someday</SelectItem>
        </SelectContent>
      </Select>

      {sessions && (
        <Select value={filters.session || 'all'} onValueChange={(v) => set({ session: v === 'all' ? '' : v })}>
          <SelectTrigger size="sm" className="h-[30px] max-w-[220px] text-[12.5px] rounded-[2px]">
            <SelectValue placeholder="Session: any" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Session: any</SelectItem>
            {sessions.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.title ?? s.short ?? s.id.slice(0, 8)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      <Input
        placeholder="Filter by text or ID"
        value={filters.q}
        onChange={(e) => set({ q: e.target.value })}
        className="h-[30px] w-[190px] text-[12.5px] rounded-[2px]"
      />
    </div>
  );
}
