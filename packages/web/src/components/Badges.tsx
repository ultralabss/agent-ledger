import type { ItemKind, ItemPriority, ItemStatus } from '@agent-ledger/shared';
import { KIND_COLOR, KIND_LABEL, STATUS_COLOR, STATUS_LABEL } from '../lib/format.tsx';

export function KindBadge({ kind }: { kind: ItemKind }) {
  return (
    <span className="badge" style={{ background: KIND_COLOR[kind] }} title={kind}>
      {KIND_LABEL[kind]}
    </span>
  );
}

export function StatusBadge({ status }: { status: ItemStatus }) {
  return (
    <span className="badge" style={{ background: STATUS_COLOR[status] }}>
      {STATUS_LABEL[status]}
    </span>
  );
}

export function PriorityBadge({ priority }: { priority: ItemPriority }) {
  const colors: Record<ItemPriority, string> = {
    P0: 'var(--k-blocking)',
    P1: 'var(--k-deploy)',
    P2: 'var(--muted-foreground)',
    P3: 'var(--muted-foreground)',
  };
  return (
    <span className="badge" style={{ background: colors[priority] }}>
      {priority}
    </span>
  );
}
