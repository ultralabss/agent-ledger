import type { SearchKind, SearchResponse } from '@agent-ledger/shared/api';
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from './ui/command.tsx';

const KIND_LABEL: Record<SearchKind, string> = {
  item: 'item',
  journal: 'journal',
  decision: 'decision',
  intake: 'intake',
  context: 'context',
};

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  q: string;
  setQ: (q: string) => void;
  data: SearchResponse | undefined;
  isFetching: boolean;
  onSelect: (kind: SearchKind, ref: string, repo: string) => void;
};

/** cmdk-backed palette body, split out so `SearchBox` can lazy-load it —
 *  cmdk is only needed once the user actually opens search. */
export default function CommandPalette({ open, onOpenChange, q, setQ, data, isFetching, onSelect }: Props) {
  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Search" description="Search items, journal, decisions…">
      <CommandInput placeholder="Search items, journal, decisions…" value={q} onValueChange={setQ} />
      <CommandList>
        {isFetching && <div className="py-6 text-center text-[12px]" style={{ color: 'var(--muted-foreground)' }}>searching…</div>}
        <CommandEmpty>nothing found</CommandEmpty>
        <CommandGroup>
          {(data?.hits ?? []).map((hit) => (
            <CommandItem
              key={`${hit.kind}-${hit.ref}`}
              value={`${hit.kind}-${hit.ref}-${hit.title}`}
              onSelect={() => onSelect(hit.kind, hit.ref, hit.repo)}
            >
              <span className="font-mono text-[10.5px]" style={{ color: 'var(--muted-foreground)' }}>
                {KIND_LABEL[hit.kind]}
              </span>
              <span className="flex-1 truncate">{hit.title}</span>
              <span className="text-[11px]" style={{ color: 'var(--muted-foreground)' }}>
                {hit.repo}
              </span>
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
