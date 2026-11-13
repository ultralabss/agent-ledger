/** Local-time helpers. The ledger is a human-readable file tree, so every
 *  timestamp written to md is local time with an explicit offset. */

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

function offset(d: Date): string {
  const mins = -d.getTimezoneOffset();
  const sign = mins < 0 ? '-' : '+';
  const abs = Math.abs(mins);
  return `${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

/** `2026-09-28T14:02:00+02:00` */
export function isoLocal(d: Date = new Date()): string {
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${offset(d)}`
  );
}

/** `2026-09-28 14:02` — journal, log and comment headers. */
export function stamp(d: Date = new Date()): string {
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/** `2026-09-28` */
export function day(d: Date = new Date()): string {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** `2026-09` — journal file name. */
export function month(d: Date = new Date()): string {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
}

/** Short session handle used in journal/log lines. */
export function shortSession(session: string | null | undefined): string {
  if (!session || session.trim() === '') return '—';
  return session.trim().slice(0, 4);
}

/** `7d`, `36h`, `90m` → ms. Bare number = days. */
export function parseSince(since: string): number {
  const m = /^(\d+)\s*([dhm]?)$/.exec(since.trim());
  if (!m) throw new Error(`cannot parse --since "${since}" (e.g. 7d, 36h, 90m)`);
  const n = Number(m[1]);
  switch (m[2]) {
    case 'h':
      return n * 3600_000;
    case 'm':
      return n * 60_000;
    default:
      return n * 86_400_000;
  }
}

/** Journal stamps are local wall clock without offset — parse them as local. */
export function parseStamp(s: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/.exec(s.trim());
  if (!m) return null;
  return new Date(
    Number(m[1]),
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    0,
    0,
  );
}
