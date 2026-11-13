import type { ItemView } from '@agent-ledger/shared/api';
import { ageBadge, itemAge } from '../lib/age.ts';

export function AgeBadge({ item }: { item: ItemView }) {
  const age = itemAge(item);
  const label = ageBadge(age);
  if (!age || !label) return null;
  return (
    <span
      className="font-mono text-[10px] px-1"
      title={age.stale ? `Stale · idle ${age.days} days` : `Idle ${age.days} days`}
      style={
        age.stale
          ? { color: 'var(--k-blocking)', border: '1px solid var(--k-blocking)', fontWeight: 600 }
          : { color: 'var(--muted-foreground)' }
      }
    >
      {label}
    </span>
  );
}
