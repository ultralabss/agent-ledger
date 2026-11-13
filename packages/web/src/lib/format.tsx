import type { ItemKind, ItemStatus } from '@agent-ledger/shared';

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffMs = Date.now() - then;
  const abs = Math.abs(diffMs);
  const future = diffMs < 0;
  const sec = Math.round(abs / 1000);
  if (sec < 5) return 'just now';
  const units: [number, string][] = [
    [60, 'sec'],
    [60, 'min'],
    [24, 'hr'],
    [7, 'day'],
    [4.345, 'wk'],
    [12, 'mo'],
    [Number.POSITIVE_INFINITY, 'yr'],
  ];
  let value = sec;
  let label = 'sec';
  for (const [size, unit] of units) {
    if (value < size) {
      label = unit;
      break;
    }
    value = Math.floor(value / size);
    label = unit;
  }
  const plural = value === 1 ? '' : 's';
  return future ? `in ${value} ${label}${plural}` : `${value} ${label}${plural} ago`;
}

export function fullTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('en-GB');
}

export const KIND_COLOR: Record<ItemKind, string> = {
  BLOCKER: 'var(--k-blocking)',
  DEPLOY: 'var(--k-deploy)',
  RISK: 'var(--k-risk)',
  UNVERIFIED: 'var(--k-unverified)',
  BACKLOG: 'var(--k-backlog)',
};

export const STATUS_COLOR: Record<ItemStatus, string> = {
  proposed: 'var(--muted-foreground)',
  open: 'var(--ring)',
  doing: 'var(--k-deploy)',
  blocked: 'var(--k-blocking)',
  done: 'var(--ok)',
  dropped: 'var(--muted-foreground)',
};

export const STATUS_LABEL: Record<ItemStatus, string> = {
  proposed: 'proposed',
  open: 'open',
  doing: 'doing',
  blocked: 'blocked',
  done: 'done',
  dropped: 'dropped',
};

/** Display label per kind; the wire value is the enum itself. */
export const KIND_LABEL: Record<ItemKind, string> = {
  BLOCKER: 'BLOCKER',
  DEPLOY: 'DEPLOY',
  RISK: 'RISK',
  UNVERIFIED: 'UNVERIFIED',
  BACKLOG: 'BACKLOG',
};

/** `AUTHORIZED:` line inside "Recommendation" — a "Copy" button copies just
 *  this line to the clipboard; it never authorizes anything by itself. */
export function findAuthorizedLine(rec: string): string | null {
  const line = rec.split('\n').find((l) => l.trim().startsWith('AUTHORIZED:'));
  return line ? line.trim() : null;
}
