import type { CSSProperties } from 'react';
import { Link } from 'react-router';
import type { ItemView } from '@agent-ledger/shared/api';
import { KIND_COLOR, KIND_LABEL } from '../lib/format.tsx';
import { AgeBadge } from './AgeBadge.tsx';
import { repoColorVar } from '../lib/repoColor.ts';

const PRIORITY_COLOR: Record<string, string> = {
  P0: 'var(--k-blocking)',
  P1: 'var(--k-deploy)',
  P2: 'var(--muted-foreground)',
  P3: 'var(--muted-foreground)',
};

/** One Kanban card — repo dot + mono id, priority box, title, kind badge,
 *  owner, and (for `doing`) the session line, per the design's board cards. */
export function ItemCard({ item }: { item: ItemView }) {
  return (
    <Link
      to={`/i/${encodeURIComponent(item.id)}`}
      className={`block border rounded-[2px] px-2.5 pt-2.5 pb-2 flex flex-col gap-1.5 no-underline hover:no-underline transition-colors${
        item.status === 'done' ? ' just-resolved' : ''
      }`}
      style={
        {
          viewTransitionName: `item-${item.id}`,
          borderColor: 'var(--border)',
          background: 'var(--card)',
          color: 'var(--foreground)',
        } as CSSProperties
      }
    >
      <div className="flex items-center gap-1.5">
        <span className="w-[7px] h-[7px] rounded-full flex-none" style={{ background: repoColorVar(item.repo) }} />
        <span className="font-mono text-[11px]" style={{ color: 'var(--muted-foreground)' }}>
          {item.id}
        </span>
        <span
          className="ml-auto font-mono text-[10px] font-semibold px-1"
          style={{ color: PRIORITY_COLOR[item.priority], border: `1px solid ${PRIORITY_COLOR[item.priority]}` }}
        >
          {item.priority}
        </span>
      </div>
      <div className="text-[12.5px] leading-snug" style={{ color: 'var(--foreground)' }}>
        {item.title}
      </div>
      <div className="flex items-center gap-1.5 flex-wrap">
        <span
          className="text-[10px] font-semibold tracking-wide px-1 py-px rounded-[2px] text-white"
          style={{ background: KIND_COLOR[item.kind] }}
        >
          {KIND_LABEL[item.kind]}
        </span>
        <span className="text-[11px]" style={{ color: 'var(--muted-foreground)' }}>
          {item.owner === 'human' ? 'you' : item.owner}
        </span>
        <span className="ml-auto">
          <AgeBadge item={item} />
        </span>
      </div>
      {item.status === 'doing' && item.claimed_by && (
        <div
          className="flex items-center gap-1.5 pt-1.5 border-t font-mono text-[10.5px] truncate"
          style={{ borderColor: 'var(--border)', color: 'var(--muted-foreground)' }}
        >
          {item.claimed_by.session.slice(0, 8)}
        </div>
      )}
    </Link>
  );
}
