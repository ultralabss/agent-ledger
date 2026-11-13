import { Link } from 'react-router';
import { useItems, useSessions } from '../api/queries.tsx';
import { useRepoSelection } from '../hooks/useRepoSelection.tsx';
import { useItemFilters } from '../hooks/useItemFilters.tsx';
import { FilterBar } from '../components/FilterBar.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { RelativeTime } from '../components/RelativeTime.tsx';
import { ReplyPopover } from '../components/ReplyPopover.tsx';
import { KindBadge, PriorityBadge } from '../components/Badges.tsx';
import { repoColorVar } from '../lib/repoColor.ts';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.tsx';
import type { ItemKind } from '@agent-ledger/shared';
import type { ItemView } from '@agent-ledger/shared/api';

const KIND_ORDER: ItemKind[] = ['BLOCKER', 'DEPLOY', 'RISK', 'UNVERIFIED', 'BACKLOG'];

function sortForHuman(items: ItemView[]): ItemView[] {
  return [...items].sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind));
}

/** Everything with `owner: human` and open — the queue a human actually has
 *  to act on, sorted BLOCKER → DEPLOY → RISK → UNVERIFIED → BACKLOG,
 *  across every repo currently selected in the sidebar. */
export function NeedsYou() {
  const repos = useRepoSelection();
  const { filters, set } = useItemFilters();
  const sessions = useSessions(repos.csv, true);
  const items = useItems({
    repo: repos.csv,
    owner: 'human',
    open: true,
    kind: filters.kind || undefined,
    priority: filters.priority || undefined,
    session: filters.session || undefined,
    q: filters.q || undefined,
  });

  const sorted = items.data ? sortForHuman(items.data.items) : [];

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-2.5" style={{ borderColor: 'var(--border)' }}>
        <FilterBar filters={filters} set={set} sessions={sessions.data?.sessions} />
      </div>

      <div className="flex-1 overflow-auto p-4">
        {items.isLoading && <Loading />}
        {items.isError && <RequestError error={items.error} />}

        {items.data && sorted.length === 0 && (
          <div
            className="border border-dashed rounded-[2px] px-4 py-12 text-center flex flex-col gap-1.5 items-center"
            style={{ borderColor: 'var(--input)' }}
          >
            <div className="text-[15px] font-semibold">Nothing needs you</div>
            <div style={{ color: 'var(--muted-foreground)' }}>Agents are working without blockers in the selected repos.</div>
          </div>
        )}

        {items.data && sorted.length > 0 && (
          <div className="border rounded-[2px]" style={{ borderColor: 'var(--border)' }}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>id</TableHead>
                  <TableHead>kind</TableHead>
                  <TableHead>priority</TableHead>
                  <TableHead>ask</TableHead>
                  <TableHead>repo</TableHead>
                  <TableHead>age</TableHead>
                  <TableHead className="text-right">reply</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className="font-mono text-[11.5px]" style={{ color: 'var(--muted-foreground)' }}>
                      <Link to={`/i/${encodeURIComponent(i.id)}`}>{i.id}</Link>
                    </TableCell>
                    <TableCell>
                      <KindBadge kind={i.kind} />
                    </TableCell>
                    <TableCell>
                      <PriorityBadge priority={i.priority} />
                    </TableCell>
                    <TableCell className="max-w-[420px] truncate">
                      <Link to={`/i/${encodeURIComponent(i.id)}`}>{i.title}</Link>
                    </TableCell>
                    <TableCell className="font-mono text-[11.5px]" style={{ color: 'var(--muted-foreground)' }}>
                      <span className="inline-flex items-center gap-1.5">
                        <span className="w-[7px] h-[7px] rounded-full" style={{ background: repoColorVar(i.repo) }} />
                        {i.repo}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-[11px]" style={{ color: 'var(--muted-foreground)' }}>
                      <RelativeTime at={i.updated} />
                    </TableCell>
                    <TableCell className="text-right">
                      <ReplyPopover item={i} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}
