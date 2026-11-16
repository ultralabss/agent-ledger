/** Intake md ⇄ object — SPEC §4.7. */

import { escapeStructuralLines, parseMd, serializeMd, type MdDoc } from './md.ts';
import { intakeFrontmatterSchema, ITEM_ID_PATTERN } from './schema.ts';
import type { IntakeDropped, IntakeRecord } from './types.ts';

export const SECTION_TRIAGE = 'Triage';

/** `- ACME-12 ← excerpt` (slot ids `ACME-W3` included). */
const TRIAGE_LINE = new RegExp(`^\\s*-\\s*(${ITEM_ID_PATTERN})\\s*←\\s*(.*)$`);

const OPEN_Q = '\u201c'; // “
const CLOSE_Q = '\u201d'; // ”

/** One line, no `—` (the dropped-line separator), capped. */
function flat(s: string, max = 120): string {
  const one = s.replace(/\s+/g, ' ').trim().replace(/—/g, '-');
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}

function quote(s: string): string {
  return `${OPEN_Q}${flat(s)}${CLOSE_Q}`;
}

function unquote(s: string): string {
  return s.trim().replace(/^[\u201c\u201e"']/, '').replace(/[\u201d\u201c"']$/, '').trim();
}

export function parseIntake(text: string, file?: string): { rec: IntakeRecord; doc: MdDoc } {
  const doc = parseMd(text, file);
  const parsed = intakeFrontmatterSchema.safeParse(doc.frontmatter);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new Error(
      `${file ? `${file}: ` : ''}invalid intake frontmatter (${
        first?.path.join('.') ?? '?'
      }: ${first?.message ?? 'error'})`,
    );
  }
  const fm = parsed.data;
  const triageBody =
    doc.sections.find((s) => s.heading.toLowerCase() === SECTION_TRIAGE.toLowerCase())?.body ?? '';
  const triage: { item: string; excerpt: string }[] = [];
  const dropped: IntakeDropped[] = [];
  for (const line of triageBody.split('\n')) {
    const drop = /^\s*-\s*dropped:\s*(.*?)\s+—\s+(.*)$/i.exec(line);
    if (drop) {
      dropped.push({ text: unquote(drop[1] ?? ''), reason: (drop[2] ?? '').trim() });
      continue;
    }
    const m = TRIAGE_LINE.exec(line);
    if (m) triage.push({ item: m[1] ?? '', excerpt: unquote(m[2] ?? '') });
  }
  return {
    rec: {
      id: fm.id,
      at: fm.at,
      channel: fm.channel,
      session: fm.session,
      repo_hint: fm.repo_hint,
      status: fm.status,
      items: fm.items,
      text: doc.preamble,
      triage,
      dropped,
    },
    doc,
  };
}

export function serializeIntake(rec: IntakeRecord, doc?: MdDoc): string {
  const base: MdDoc = doc ?? { frontmatter: {}, preamble: '', sections: [] };
  base.frontmatter = {
    ...base.frontmatter,
    id: rec.id,
    at: rec.at,
    channel: rec.channel,
    session: rec.session,
    repo_hint: rec.repo_hint,
    status: rec.status,
    items: rec.items,
  };
  // R2: the intake text is verbatim user/agent input and lands in the preamble —
  // the part `parseMd` reads until the first `## `. Without escaping, a line
  // `## Triage` in the text forges the triage section on the next parse (and a
  // `- ACME-1 ← "…"` line inside it forges a triage decision). Same treatment as
  // every other free-form body (SPEC §6.5): structural lines get a backtick.
  base.preamble = escapeStructuralLines(rec.text);
  const lines: string[] = [];
  for (const t of rec.triage) lines.push(`- ${t.item} ← ${quote(t.excerpt)}`);
  for (const d of rec.dropped) lines.push(`- dropped: ${quote(d.text)} — ${flat(d.reason, 200)}`);
  const existing = base.sections.find(
    (s) => s.heading.toLowerCase() === SECTION_TRIAGE.toLowerCase(),
  );
  if (lines.length > 0) {
    if (existing) existing.body = lines.join('\n');
    else base.sections.push({ heading: SECTION_TRIAGE, body: lines.join('\n') });
  }
  return serializeMd(base);
}

/**
 * How long a record may sit untouched before the brief nags about it.
 * A triage in progress in the current session (`ledger intake "…"` → read it →
 * `ledger add`) would otherwise show up as "unprocessed" in that same session's
 * next brief.
 */
export const INTAKE_UNPROCESSED_AFTER_MS = 10 * 60_000;

/**
 * A record nobody has acted on — `status: new`, no items, no triage
 * decisions at all (a `--drop` IS a decision), and old enough to not be work
 * in flight.
 *
 * `status === 'new'` on its own over-counted: before that nothing marked the
 * record when `ledger add --intake` cut an item from it, so ~10 records stayed
 * `new` forever despite being fully processed. The item/triage check is the
 * part that survives those old records.
 */
export function isIntakeUnprocessed(rec: IntakeRecord, now: number = Date.now()): boolean {
  if (rec.status !== 'new') return false;
  if (rec.items.length > 0 || rec.triage.length > 0 || rec.dropped.length > 0) return false;
  const at = Date.parse(rec.at);
  // Unparseable `at` (hand-edited md) → count it. Hiding a record because its
  // timestamp is broken is the worse failure.
  if (Number.isNaN(at)) return true;
  return now - at >= INTAKE_UNPROCESSED_AFTER_MS;
}

export function intakeLine(rec: IntakeRecord): string {
  const first = rec.text.replace(/\s+/g, ' ').trim();
  const excerpt = first.length > 80 ? `${first.slice(0, 79)}…` : first;
  const items = rec.items.length > 0 ? ` → ${rec.items.join(',')}` : '';
  return `${rec.id} ${rec.status} ${rec.channel} ${rec.at.slice(0, 16)}${items} · ${excerpt}`;
}
