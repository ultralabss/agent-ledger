/**
 * `ledger why` output. The hub already sanitizes every string it returns; this
 * module does it AGAIN before anything reaches a terminal or an agent's
 * context, because titles, intents and summaries are data written by other
 * sessions (and git authors) and may be a prompt injection or an escape-sequence
 * forgery. The first line of every answer says so.
 */

import { WHY_DATA_NOTICE, type WhyView } from '@agent-ledger/shared';

/** Hard cap on the printed answer. */
export const WHY_MAX_LINES = 40;
const LINE_MAX = 200;

const ANSI_CSI = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g;
const ANSI_OTHER = /\u001b[@-Z\\-_]/g;
const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/** One printable line of data: no ANSI, no control characters, no newline. */
export function safeText(value: unknown, max = LINE_MAX): string {
  if (typeof value !== 'string') return '';
  const flat = value
    .slice(0, 4 * max)
    .replace(ANSI_OSC, '')
    .replace(ANSI_CSI, '')
    .replace(ANSI_OTHER, '')
    .replace(INVISIBLE, '')
    .replace(CONTROL, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** `5 min`, `3 h`, `2 d` — never negative (a skewed clock shows `just now`). */
export function ageText(fromMs: number, nowMs: number): string {
  const ms = Math.max(0, nowMs - fromMs);
  const min = Math.floor(ms / 60_000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min} min ago`;
  const h = Math.floor(min / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} d ago`;
}

const q = (s: string): string => `"${s.replace(/"/g, "'")}"`;

function list<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

/**
 * The answer as lines (≤ `WHY_MAX_LINES`). Defensive about the shape: a hub of
 * another version or a hand-built response never throws here.
 */
export function formatWhy(view: WhyView, nowMs: number = Date.now()): string[] {
  const out: string[] = [WHY_DATA_NOTICE];
  const where = `${safeText(view.repo, 60)}:${safeText(view.path, 160)}`;
  if (view.ignored === true) {
    out.push(`${where} — ${safeText(view.note, 120) || 'ignored by git — nothing shown'}`);
    return out;
  }

  const items = list<WhyView['items'][number]>(view.items);
  const claims = list<WhyView['claims'][number]>(view.claims);
  const mentions = list<WhyView['mentions'][number]>(view.mentions);
  const sessions = list<WhyView['sessions'][number]>(view.sessions);
  const uncommitted = list<WhyView['uncommitted'][number]>(view.uncommitted);

  const known = items.length + claims.length + mentions.length + sessions.length;
  out.push(
    known === 0
      ? `${where}: nothing recorded in the ledger`
      : `${where}${view.kind === 'glob' ? ' (glob)' : ''}:`,
  );

  for (const it of items) {
    const bits: string[] = [];
    if (it.claim) {
      const intent = it.claim.intent ? `, intent ${q(safeText(it.claim.intent, 100))}` : '';
      bits.push(`claim session ${safeText(it.claim.session, 8)}${intent}`);
    }
    if (typeof it.commits === 'number' && it.commits > 0) {
      bits.push(`${it.commits} commit${it.commits === 1 ? '' : 's'}`);
    }
    out.push(
      `  ${safeText(it.id, 24)} ${safeText(it.status, 16)} ${q(safeText(it.title, 100))}` +
        `${bits.length > 0 ? ` (${bits.join('; ')})` : ''}`,
    );
  }
  for (const c of claims) {
    const intent = c.intent ? `, intent ${q(safeText(c.intent, 100))}` : '';
    out.push(
      `  claim session ${safeText(c.session, 8)} on ${safeText(c.pattern, 80)}` +
        `${c.item_id ? ` (${safeText(c.item_id, 24)})` : ''}${intent}`,
    );
  }
  for (const m of mentions) {
    out.push(`  ${m.kind === 'decision' ? safeText(m.ref, 12) : `journal ${safeText(m.ref, 40)}`} ${q(safeText(m.text, 100))}`);
  }
  for (const s of sessions) {
    const at = Date.parse(s.last_at);
    const when = Number.isFinite(at) ? ageText(at, nowMs) : 'earlier';
    out.push(`  session ${safeText(s.session, 8)} ${when}${s.why ? ` ${q(safeText(s.why, 100))}` : ''}`);
  }

  const last = view.last_changed;
  const lastAt = last ? Date.parse(last.at) : Number.NaN;
  const changed = Number.isFinite(lastAt)
    ? `last changed ${ageText(lastAt, nowMs)}${last?.source === 'ledger' ? ' (ledger)' : ''}`
    : 'last change unknown';
  const dirty =
    uncommitted.length === 0
      ? 'uncommitted: nobody'
      : `uncommitted: ${uncommitted
          .map((u) => `${safeText(u.session, 8)} ${safeText(u.via, 12)}${u.orphan ? ' ORPHAN' : ''} ${safeText(u.path, 60)}`)
          .join(', ')}`;
  out.push(`${changed}; ${dirty}`);
  if (view.truncated === true) out.push('(more exists — narrow the path)');

  // Cap the whole answer; the footer must survive, so cut from the middle.
  const clipped = out.map((l) => (l.length > LINE_MAX ? `${l.slice(0, LINE_MAX - 1)}…` : l));
  if (clipped.length <= WHY_MAX_LINES) return clipped;
  const head = clipped.slice(0, WHY_MAX_LINES - 2);
  return [...head, '  …', clipped[clipped.length - 1] as string];
}
