import type { ItemView } from '@agent-ledger/shared/api';

/** Badge shows from this age. */
export const AGE_BADGE_DAYS = 3;
/** Client-side fallback for list views, which do not carry `age_days`/`stale`. */
export const STALE_FALLBACK_DAYS = 14;

export interface ItemAge {
  days: number;
  stale: boolean;
}

/** Prefer the hub's computed values; otherwise derive from `updated` (display only). */
export function itemAge(item: Pick<ItemView, 'age_days' | 'stale' | 'updated' | 'status'>, now = Date.now()): ItemAge | null {
  if (item.status === 'done' || item.status === 'dropped') return null;
  if (typeof item.age_days === 'number') return { days: item.age_days, stale: item.stale ?? false };
  const t = Date.parse(item.updated);
  if (Number.isNaN(t)) return null;
  const days = Math.max(0, Math.floor((now - t) / 86_400_000));
  return { days, stale: days >= STALE_FALLBACK_DAYS };
}

/** Badge label (`23d`) or null when too young to show. */
export function ageBadge(age: ItemAge | null): string | null {
  return age && age.days >= AGE_BADGE_DAYS ? `${age.days}d` : null;
}
