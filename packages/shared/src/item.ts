/** Item md ⇄ object. Round-trip safe: unknown sections survive a rewrite. */

import {
  appendToSection,
  escapeStructuralLines,
  getSection,
  parseMd,
  serializeMd,
  setSection,
  type MdDoc,
} from './md.ts';
import { sanitizeField } from './sanitize.ts';
import { itemFrontmatterSchema } from './schema.ts';
import { stamp } from './time.ts';
import type {
  Item,
  ItemComment,
  ItemFrontmatter,
  ItemStatus,
  LogLine,
  PlanStep,
} from './types.ts';

export const SECTION_WHY = 'Why';
export const SECTION_PLAN = 'Plan';
export const SECTION_REC = 'Recommendation';
export const SECTION_COMMENTS = 'Comments';
export const SECTION_LOG = 'Log';

export const KNOWN_SECTIONS: readonly string[] = [
  SECTION_WHY,
  SECTION_PLAN,
  SECTION_REC,
  SECTION_COMMENTS,
  SECTION_LOG,
];

export interface ParsedItem {
  item: Item;
  /** The source document — keep it, mutate it, serialize it. */
  doc: MdDoc;
}

export function parseSteps(body: string): PlanStep[] {
  const steps: PlanStep[] = [];
  for (const line of body.split('\n')) {
    const m = /^\s*-\s*\[( |x|X)\]\s*(\d+)\.\s*(.*)$/.exec(line);
    if (!m) continue;
    steps.push({
      n: Number(m[2]),
      done: (m[1] ?? ' ').toLowerCase() === 'x',
      text: (m[3] ?? '').trim(),
    });
  }
  return steps;
}

export function serializeSteps(steps: PlanStep[]): string {
  return steps.map((s) => `- [${s.done ? 'x' : ' '}] ${s.n}. ${s.text}`).join('\n');
}

export function parseComments(body: string): ItemComment[] {
  const out: ItemComment[] = [];
  let current: ItemComment | null = null;
  const push = (): void => {
    if (current) {
      current.text = current.text.trim();
      out.push(current);
    }
  };
  for (const line of body.split('\n')) {
    const m = /^###\s+(.*)$/.exec(line);
    if (m) {
      push();
      const parts = (m[1] ?? '').split('·').map((p) => p.trim());
      current = {
        at: parts[0] ?? '',
        author: parts[1] ?? 'unknown',
        id: (parts[2] ?? '').replace(/^c/, ''),
        text: '',
      };
      continue;
    }
    if (current) current.text += `${line}\n`;
  }
  push();
  return out;
}

export function serializeComments(comments: ItemComment[]): string {
  // F-1: the `### at · author · cid` header is a single line the parser splits
  // on `·` — sanitise every part at the sink, not just at the API edge.
  return comments
    .map((c) =>
      `### ${headerPart(c.at)} · ${headerPart(c.author)} · c${headerPart(c.id)}\n${escapeStructuralLines(
        c.text,
      )}`.trimEnd(),
    )
    .join('\n\n');
}

function headerPart(value: string): string {
  return sanitizeField(value, 120).replace(/·/g, '•');
}

export function parseLog(body: string): LogLine[] {
  const out: LogLine[] = [];
  for (const line of body.split('\n')) {
    const m = /^\s*-\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\s*·\s*([^·]*)·\s*(.*)$/.exec(line);
    if (!m) continue;
    out.push({ at: m[1] ?? '', session: (m[2] ?? '').trim(), text: (m[3] ?? '').trim() });
  }
  return out;
}

export function serializeLog(log: LogLine[]): string {
  // S4: `escapeStructuralLines` neutralises a forged log/step/heading line
  // inside the text, so an embedded newline can only ever produce a stray,
  // unparseable line (dropped on re-parse), never a second log entry.
  // F-1 adds the header fields: `at` and `session` are columns the parser
  // splits on, so they lose newlines and `·` outright.
  return log
    .map((l) => `- ${headerPart(l.at)} · ${headerPart(l.session)} · ${escapeStructuralLines(l.text)}`)
    .join('\n');
}

/** Fields a reader may blank out instead of dropping the whole item.
 *  Everything else (id, title, status, kind, priority, owner, repo, timestamps)
 *  is load-bearing — a broken value there is still a hard parse error. */
/*  H-1: `claimed_by`, `paths`, `blocks` and `blocked_by` are NOT here on
 *  purpose. They carry the coordination locks (who owns which files) and the
 *  dependency graph — blanking those to keep an item visible would silently
 *  unlock files for another session. A broken value there stays a hard parse
 *  error: the last good version keeps being served and a human gets a warning.
 *  Only cosmetic / informational fields may be blanked. */
const REPAIRABLE: ReadonlySet<string> = new Set([
  'done',
  'source',
  'aliases',
  'requested_by',
  'intake',
  'area',
]);

export interface ItemRepair {
  /** Dotted frontmatter path, e.g. `done.version`. */
  path: string;
  /** The rejected value, stringified (trimmed to 200 chars). */
  value: string;
  message: string;
}

function repairFrontmatter(
  raw: unknown,
  issues: readonly { path: readonly (string | number)[]; message: string }[],
): { fm: Record<string, unknown>; repairs: ItemRepair[] } | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const fm: Record<string, unknown> = { ...(raw as Record<string, unknown>) };
  const repairs: ItemRepair[] = [];
  for (const issue of issues) {
    const root = issue.path[0];
    if (typeof root !== 'string' || !REPAIRABLE.has(root)) return null;
    const parent = issue.path.length > 1 ? fm[root] : fm;
    const before =
      issue.path.length > 1 && typeof parent === 'object' && parent !== null
        ? (parent as Record<string, unknown>)[String(issue.path[1])]
        : fm[root];
    repairs.push({
      path: issue.path.join('.'),
      value: String(before ?? '').slice(0, 200),
      message: issue.message,
    });
    if (issue.path.length === 1) {
      // Drop it entirely — the schema default (null / []) takes over.
      delete fm[root];
    } else if (typeof parent === 'object' && parent !== null) {
      const nested = { ...(parent as Record<string, unknown>) };
      nested[String(issue.path[1])] = null;
      fm[root] = nested;
    } else {
      return null;
    }
  }
  return { fm, repairs };
}

export function itemFromDoc(doc: MdDoc, file?: string, repairs?: ItemRepair[]): Item {
  let parsed = itemFrontmatterSchema.safeParse(doc.frontmatter);
  if (!parsed.success && repairs) {
    // An optional field the writer should never have accepted must not
    // make the item invisible. Blank it, report it, keep the item.
    const repaired = repairFrontmatter(doc.frontmatter, parsed.error.issues);
    if (repaired) {
      const retry = itemFrontmatterSchema.safeParse(repaired.fm);
      if (retry.success) {
        doc.frontmatter = repaired.fm;
        repairs.push(...repaired.repairs);
        parsed = retry;
      }
    }
  }
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    throw new Error(
      `${file ? `${file}: ` : ''}invalid frontmatter (${first?.path.join('.') ?? '?'}: ${
        first?.message ?? 'error'
      })`,
    );
  }
  const fm = parsed.data as ItemFrontmatter;
  return {
    fm,
    why: getSection(doc, SECTION_WHY)?.body ?? '',
    steps: parseSteps(getSection(doc, SECTION_PLAN)?.body ?? ''),
    rec: getSection(doc, SECTION_REC)?.body ?? '',
    comments: parseComments(getSection(doc, SECTION_COMMENTS)?.body ?? ''),
    log: parseLog(getSection(doc, SECTION_LOG)?.body ?? ''),
  };
}

export function parseItem(text: string, file?: string, repairs?: ItemRepair[]): ParsedItem {
  const doc = parseMd(text, file);
  return { item: itemFromDoc(doc, file, repairs), doc };
}

/** Write the known sections back into `doc`, leaving everything else alone. */
export function applyItem(doc: MdDoc, item: Item): MdDoc {
  doc.frontmatter = { ...doc.frontmatter, ...item.fm };
  setSection(doc, SECTION_WHY, escapeStructuralLines(item.why));
  setSection(doc, SECTION_PLAN, serializeSteps(item.steps));
  setSection(doc, SECTION_REC, escapeStructuralLines(item.rec));
  setSection(doc, SECTION_COMMENTS, serializeComments(item.comments));
  setSection(doc, SECTION_LOG, serializeLog(item.log));
  return doc;
}

export function serializeItem(item: Item, doc?: MdDoc): string {
  const base: MdDoc = doc ?? { frontmatter: {}, preamble: '', sections: [] };
  if (!doc) {
    for (const heading of KNOWN_SECTIONS) base.sections.push({ heading, body: '' });
  }
  return serializeMd(applyItem(base, item));
}

export function newItemDoc(fm: ItemFrontmatter): MdDoc {
  return {
    frontmatter: { ...fm },
    preamble: '',
    sections: KNOWN_SECTIONS.map((heading) => ({ heading, body: '' })),
  };
}

export function appendLog(doc: MdDoc, item: Item, session: string, text: string): void {
  const line: LogLine = { at: stamp(), session, text };
  item.log.push(line);
  appendToSection(doc, SECTION_LOG, serializeLog([line]));
}

/* ---------- transitions (SPEC §4.4) ---------- */

export type Transition =
  | 'open'
  | 'claim'
  | 'release'
  | 'block'
  | 'unblock'
  | 'done'
  | 'drop'
  | 'reopen';

const ALLOWED: Record<Transition, { from: readonly ItemStatus[]; to: ItemStatus }> = {
  open: { from: ['proposed'], to: 'open' },
  claim: { from: ['open'], to: 'doing' },
  release: { from: ['doing'], to: 'open' },
  block: { from: ['open', 'doing'], to: 'blocked' },
  unblock: { from: ['blocked'], to: 'open' },
  done: { from: ['proposed', 'open', 'doing', 'blocked'], to: 'done' },
  drop: { from: ['proposed', 'open', 'doing', 'blocked'], to: 'dropped' },
  reopen: { from: ['done', 'dropped'], to: 'open' },
};

export function targetStatus(t: Transition): ItemStatus {
  return ALLOWED[t].to;
}

export function canTransition(from: ItemStatus, t: Transition): boolean {
  return ALLOWED[t].from.includes(from);
}

export function transitionError(from: ItemStatus, t: Transition): string {
  return `transition ${t} is not allowed from status ${from} (allowed from: ${ALLOWED[t].from.join(', ')})`;
}

export const OPEN_STATUSES: readonly ItemStatus[] = ['proposed', 'open', 'doing', 'blocked'];

export function isOpen(status: ItemStatus): boolean {
  return OPEN_STATUSES.includes(status);
}

/** One line per record, for `?format=line` and the CLI. */
export function itemLine(item: Item): string {
  const fm = item.fm;
  const owner = fm.owner === 'agent' ? '' : ` @${fm.owner}`;
  const blocked = fm.blocked_by.length > 0 ? ` ←${fm.blocked_by.join(',')}` : '';
  return `${fm.id} ${fm.status} ${fm.priority} [${fm.kind}] ${fm.repo}${owner}${blocked} · ${fm.title}`;
}
