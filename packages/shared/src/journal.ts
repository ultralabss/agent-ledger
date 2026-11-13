/** Journal lines — SPEC §4.5. Append-only, one event per line:
 *
 *  `- YYYY-MM-DD HH:MM · <session|—> · <type> · <fields…>`
 *
 *  The parser is deliberately tolerant: a hand-written line with extra `·`
 *  inside the session field (`a9f2 (acme · ACME-13)`) still parses, and
 *  anything unparseable is skipped instead of throwing.
 */

import { sanitizeField, sanitizeLine } from './sanitize.ts';
import { stamp } from './time.ts';
import type { JournalEvent } from './types.ts';

export const SEP = ' · ';

export const KNOWN_TYPES: readonly string[] = [
  'item.created',
  'item.status',
  'item.comment',
  'session.start',
  'session.end',
  'session.summary',
  'intrude.begin',
  'intrude.commit',
  'intrude.end',
  'commit',
  'release',
  'decision',
  'orphan',
  'override',
  'branch.stale',
  'intake.triaged',
  // An intake record marked by `ledger add --intake`, without an explicit triage.
  'intake.linked',
];

/** F-1: the sink sanitises. A `\n` in any field would otherwise append a
 *  second, forged journal event — fields carry commit subjects, `why` notes and
 *  hook payloads that never passed a zod `singleLine` refinement. */
function journalField(value: string): string {
  return sanitizeField(value);
}

/**
 * F-1: `at`, `session` and `type` additionally lose `·`.
 *
 * `parseJournalLine` splits on `·` and locates `type` as the FIRST field that
 * is a known type name. Fields come after it, so a `·` inside a field is
 * harmless (it only splits that field, which is why `ledger log` may legitimately
 * contain one). A `·` in the *session* column, however, would shift the type
 * position and could name a known type — that is the forgeable one.
 */
function journalHeader(value: string): string {
  return sanitizeField(value, 120).replace(/·/g, '•');
}

export function journalLine(ev: { at?: string; session: string; type: string; fields: string[] }): string {
  const parts = [
    journalHeader(ev.at ?? stamp()),
    journalHeader(ev.session) || '—',
    journalHeader(ev.type) || 'unknown',
    ...ev.fields.map(journalField).filter((f) => f !== ''),
  ];
  return sanitizeLine(`- ${parts.join(SEP)}`);
}

export function parseJournalLine(line: string, repo: string): JournalEvent | null {
  const m = /^\s*-\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\s*·\s*(.*)$/.exec(line);
  if (!m) return null;
  const rest = (m[2] ?? '').split('·').map((p) => p.trim());
  if (rest.length === 0) return null;
  let typeIdx = rest.findIndex((p) => KNOWN_TYPES.includes(p));
  if (typeIdx < 1) typeIdx = rest.length > 1 ? 1 : 0;
  const session = rest.slice(0, typeIdx).join(SEP).trim() || '—';
  return {
    at: m[1] ?? '',
    session: typeIdx === 0 ? '—' : session,
    type: rest[typeIdx] ?? 'unknown',
    fields: rest.slice(typeIdx + 1),
    repo,
  };
}

export function parseJournal(text: string, repo: string): JournalEvent[] {
  const out: JournalEvent[] = [];
  for (const line of text.split('\n')) {
    const ev = parseJournalLine(line, repo);
    if (ev) out.push(ev);
  }
  return out;
}

export function eventLine(ev: JournalEvent): string {
  return `${ev.at} ${ev.repo} ${ev.session} ${ev.type}${
    ev.fields.length > 0 ? ` · ${ev.fields.join(SEP)}` : ''
  }`;
}
