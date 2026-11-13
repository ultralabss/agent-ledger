import { lazy, Suspense, useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { useSearch } from '../api/queries.tsx';
import type { SearchKind } from '@agent-ledger/shared/api';

// cmdk pulls in its own tree — only load it once the palette is actually
// opened, not on every page's first paint.
const CommandPalette = lazy(() => import('./CommandPalette.tsx'));

// `ref`/`repo` come straight from search hits — encode before they join
// a URL, same as every other id/slug-built path in this app.
function hitHref(kind: SearchKind, ref: string, repo: string): string {
  switch (kind) {
    case 'item':
      return `/i/${encodeURIComponent(ref)}`;
    case 'decision':
      return `/r/${encodeURIComponent(repo)}`;
    case 'intake':
      return '/intake';
    default:
      return `/r/${encodeURIComponent(repo)}`;
  }
}

/** ⌘K / `/` opens a Command palette over `GET /v1/search` . */
export function SearchBox() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const navigate = useNavigate();
  const { data, isFetching } = useSearch(q);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const typing = target && ['INPUT', 'TEXTAREA'].includes(target.tagName);
      if ((e.key === '/' && !typing) || ((e.metaKey || e.ctrlKey) && e.key === 'k')) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  function go(kind: SearchKind, ref: string, repo: string) {
    setOpen(false);
    setQ('');
    navigate(hitHref(kind, ref, repo));
  }

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 h-8 w-[340px] px-2.5 border rounded-[2px] text-left"
        style={{ borderColor: 'var(--input)', background: 'var(--card)', color: 'var(--muted-foreground)' }}
      >
        <span className="flex-1 text-[12.5px]">Search…</span>
        <span className="font-mono text-[10.5px] px-[5px] py-px border" style={{ borderColor: 'var(--border)' }}>
          ⌘K
        </span>
        <span className="font-mono text-[10.5px] px-[5px] py-px border" style={{ borderColor: 'var(--border)' }}>
          /
        </span>
      </button>
      {open && (
        <Suspense fallback={null}>
          <CommandPalette open={open} onOpenChange={setOpen} q={q} setQ={setQ} data={data} isFetching={isFetching} onSelect={go} />
        </Suspense>
      )}
    </>
  );
}
