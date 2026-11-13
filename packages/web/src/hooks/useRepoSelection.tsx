/** Sidebar repo multi-select — persisted to localStorage, read by every view
 *  (Overview, board, timeline, sessions) so the choice sticks across routes. */
import { useCallback, useEffect, useState } from 'react';

const KEY = 'agent-ledger.repos';

function read(): string[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function write(slugs: string[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(slugs));
  } catch {
    // storage unavailable — selection just won't persist
  }
}

/** Empty array means "all repos". */
export function useRepoSelection(): {
  selected: string[];
  isAll: boolean;
  toggle: (slug: string, only?: boolean) => void;
  selectAll: () => void;
  csv: string | undefined;
} {
  const [selected, setSelected] = useState<string[]>(() => read());

  useEffect(() => {
    write(selected);
  }, [selected]);

  const toggle = useCallback((slug: string, only?: boolean) => {
    setSelected((prev) => {
      if (only) return [slug];
      if (prev.includes(slug)) return prev.filter((s) => s !== slug);
      return [...prev, slug];
    });
  }, []);

  const selectAll = useCallback(() => setSelected([]), []);

  return {
    selected,
    isAll: selected.length === 0,
    toggle,
    selectAll,
    csv: selected.length > 0 ? selected.join(',') : undefined,
  };
}
