import { fullTime, relativeTime } from '../lib/format.tsx';

export function RelativeTime({ at }: { at: string | null | undefined }) {
  if (!at) return <span className="muted">—</span>;
  return <time title={fullTime(at)}>{relativeTime(at)}</time>;
}
