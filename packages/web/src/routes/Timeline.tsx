import { useState } from 'react';
import { useTimeline } from '../api/queries.tsx';
import { useRepoSelection } from '../hooks/useRepoSelection.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { Input } from '../components/ui/input.tsx';
import { repoColorVar } from '../lib/repoColor.ts';

/** Activity (`/timeline`) — a flat feed of `/v1/timeline` events across the
 *  repos selected in the sidebar, filterable by event type. */
export function TimelinePage() {
  const repos = useRepoSelection();
  const [type, setType] = useState('');
  const timeline = useTimeline({ repo: repos.csv, type: type || undefined });

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b px-4 py-2.5 flex-wrap" style={{ borderColor: 'var(--border)' }}>
        <span className="text-[12px]" style={{ color: 'var(--muted-foreground)' }}>
          repos: {repos.isAll ? 'all' : repos.selected.join(', ')} (set in sidebar)
        </span>
        <Input
          placeholder="type (e.g. item.status)"
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="h-[30px] w-[220px] text-[12.5px] ml-auto"
        />
      </div>

      <div className="flex-1 overflow-auto p-4">
        {timeline.isLoading && <Loading />}
        {timeline.isError && <RequestError error={timeline.error} />}
        {timeline.data && (
          <div className="flex flex-col">
            {timeline.data.events.map((e, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 py-1.5 border-b font-mono text-[11.5px]"
                style={{ borderColor: 'var(--border)' }}
              >
                <span style={{ color: 'var(--muted-foreground)' }}>{e.at}</span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="w-[6px] h-[6px] rounded-full" style={{ background: repoColorVar(e.repo) }} />
                  {e.repo}
                </span>
                <span style={{ color: 'var(--muted-foreground)' }}>{e.session}</span>
                <span className="font-semibold">{e.type}</span>
                <span style={{ color: 'var(--muted-foreground)' }}>{e.fields.join(' · ')}</span>
              </div>
            ))}
            {timeline.data.events.length === 0 && <p className="muted">no events.</p>}
          </div>
        )}
      </div>
    </div>
  );
}
