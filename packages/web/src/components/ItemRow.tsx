import type { CSSProperties } from 'react';
import { Link } from 'react-router';
import type { ItemView } from '@agent-ledger/shared/api';
import { KindBadge, PriorityBadge, StatusBadge } from './Badges.tsx';
import { ReplyStatusChip } from './ReplyStatusChip.tsx';
import { ReplyPopover } from './ReplyPopover.tsx';

export function ItemRow({ item }: { item: ItemView }) {
  return (
    <li
      className={`item-row${item.status === 'done' ? ' just-resolved' : ''}`}
      style={{ viewTransitionName: `item-${item.id}` } as CSSProperties}
    >
      <span className="id">{item.id}</span>
      <KindBadge kind={item.kind} />
      <StatusBadge status={item.status} />
      <PriorityBadge priority={item.priority} />
      <Link className="title" to={`/i/${encodeURIComponent(item.id)}`}>
        {item.title}
      </Link>
      <span className="muted">{item.owner}</span>
      {item.last_reply && <ReplyStatusChip reply={item.last_reply} />}
      {item.owner === 'human' && <ReplyPopover item={item} />}
    </li>
  );
}
