/** Mergers for the non-item synced files: journal, DECISIONS.md, counters,
 *  intake records, CONTEXT.md (spec §3.2). All inputs are file texts; output
 *  is LF text ending in one newline (or '' for an empty file). */

import { parseIntake, serializeIntake, type IntakeRecord, type IntakeStatus } from '@agent-ledger/shared';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { canon, cmpStr, mergeSet, merge3, minTime, unionList } from './common.ts';
import { joinLines, mergeText, splitLines } from './diff3.ts';
import type { ContextMergeResult, MergeResult, SyncNote } from './types.ts';

const fileText = (lines: readonly string[]): string => (lines.length === 0 ? '' : `${joinLines(lines)}\n`);

/* ---------------- journal/YYYY-MM.md ---------------- */

const JOURNAL_TS = /^\s*-\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2})/;

function journalLines(text: string | null): string[] {
  return text === null ? [] : splitLines(text).map((l) => l.trimEnd()).filter((l) => l.trim() !== '');
}

/** Line-set union, deduped by exact line. Order: timestamp, then lines already
 *  in `base` (in base order — same-minute events keep their order), then new
 *  lines by text (the session column leads the text, so effectively by device). */
export function mergeJournal(base: string | null, ours: string, theirs: string): MergeResult {
  const baseLines = journalLines(base);
  const idx = new Map<string, number>();
  baseLines.forEach((l, i) => {
    if (!idx.has(l)) idx.set(l, i);
  });
  const all = [...new Set([...journalLines(ours), ...journalLines(theirs)])];
  const ts = (l: string): string => JOURNAL_TS.exec(l)?.[1] ?? '';
  all.sort((x, y) => {
    const c = cmpStr(ts(x), ts(y));
    if (c !== 0) return c;
    const ix = idx.get(x);
    const iy = idx.get(y);
    if (ix !== undefined && iy !== undefined) return ix - iy;
    if (ix !== undefined) return -1;
    if (iy !== undefined) return 1;
    return cmpStr(x, y);
  });
  return { merged: fileText(all), notes: [] };
}

/* ---------------- DECISIONS.md ---------------- */

const DECISION_HEAD = /^###\s+(D[A-HJ-NP-Z]?\d+)(?![A-Za-z0-9])/;

interface DecisionFile {
  preamble: string;
  blocks: Map<string, string[]>; // id → distinct normalized block texts
}

function trimBlank(lines: string[]): string[] {
  let s = 0;
  let e = lines.length;
  while (s < e && (lines[s] as string).trim() === '') s += 1;
  while (e > s && (lines[e - 1] as string).trim() === '') e -= 1;
  return lines.slice(s, e);
}

function parseDecisionFile(text: string | null): DecisionFile {
  const pre: string[] = [];
  const blocks = new Map<string, string[]>();
  let curId: string | null = null;
  let cur: string[] = [];
  const flush = (): void => {
    if (curId === null) return;
    const t = joinLines(trimBlank(cur.map((l) => l.trimEnd())));
    const list = blocks.get(curId) ?? [];
    if (!list.includes(t)) list.push(t);
    blocks.set(curId, list);
  };
  for (const line of text === null ? [] : splitLines(text)) {
    const m = DECISION_HEAD.exec(line);
    if (m) {
      flush();
      curId = m[1] as string;
      cur = [line];
    } else if (curId === null) pre.push(line);
    else cur.push(line);
  }
  flush();
  return { preamble: joinLines(trimBlank(pre.map((l) => l.trimEnd()))), blocks };
}

function cmpDecisionId(a: string, b: string): number {
  const pa = /^D([A-HJ-NP-Z]?)(\d+)$/.exec(a);
  const pb = /^D([A-HJ-NP-Z]?)(\d+)$/.exec(b);
  if (!pa || !pb) return cmpStr(a, b);
  const x = BigInt(pa[2] as string);
  const y = BigInt(pb[2] as string);
  if (x !== y) return x < y ? -1 : 1;
  return cmpStr(pa[1] as string, pb[1] as string);
}

const sameSet = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && a.every((x) => b.includes(x));

/** Union of `### D…` blocks by id. Same id: 3-way over the set of bodies (an
 *  edit on one side applies; a deletion never does). Diverging bodies → both
 *  kept + `sync.decision-conflict`. */
export function mergeDecisions(base: string | null, ours: string, theirs: string): MergeResult {
  const B = parseDecisionFile(base);
  const O = parseDecisionFile(ours);
  const T = parseDecisionFile(theirs);
  const notes: SyncNote[] = [];
  const pre = mergeText(base === null ? null : B.preamble, O.preamble, T.preamble, cmpStr(O.preamble, T.preamble) <= 0);
  if (pre.conflict) {
    notes.push({ type: 'sync.decision-conflict', field: 'preamble', detail: 'DECISIONS.md preamble diverged, smaller text kept' });
  }
  const ids = [...new Set([...O.blocks.keys(), ...T.blocks.keys()])].sort(cmpDecisionId);
  const out: string[] = [];
  if (pre.text !== '') out.push(pre.text);
  for (const id of ids) {
    const o = O.blocks.get(id) ?? [];
    const t = T.blocks.get(id) ?? [];
    let res = mergeSet(B.blocks.get(id) ?? [], o, t);
    if (res.length === 0) res = [...new Set([...o, ...t])].sort(cmpStr);
    res = [...res].sort(cmpStr);
    if (res.length > 1 && !sameSet(res, o) && !sameSet(res, t)) {
      notes.push({ type: 'sync.decision-conflict', item: id, detail: `${id}: same id, different bodies, both kept` });
    }
    out.push(...res);
  }
  notes.sort((x, y) => cmpStr(x.item ?? '', y.item ?? '') || cmpStr(x.detail, y.detail));
  return { merged: out.length === 0 ? '' : `${out.join('\n\n')}\n`, notes };
}

/* ---------------- counters/<device_id>.yml ---------------- */

function parseCounters(text: string | null): Map<string, number> {
  const raw: unknown = text === null || text.trim() === '' ? {} : parseYaml(text);
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('counters: not a map');
  const out = new Map<string, number>();
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!/^[a-z0-9-]+$/.test(k)) throw new Error('counters: bad slug key');
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > Number.MAX_SAFE_INTEGER - 1) {
      throw new Error('counters: bad value');
    }
    out.set(k, v);
  }
  return out;
}

/** Per-key max (counters only grow). Invalid input throws — fail closed. */
export function mergeCounters(base: string | null, ours: string, theirs: string): MergeResult {
  const out = new Map<string, number>();
  for (const m of [parseCounters(base), parseCounters(ours), parseCounters(theirs)]) {
    for (const [k, v] of m) if (v > (out.get(k) ?? -1)) out.set(k, v);
  }
  const sorted = Object.fromEntries([...out.entries()].sort(([a], [b]) => cmpStr(a, b)));
  return { merged: stringifyYaml(sorted, { lineWidth: 0 }), notes: [] };
}

/* ---------------- intake/<snowflake>.md ---------------- */

const INTAKE_RANK: Record<IntakeStatus, number> = { triaged: 2, partial: 1, new: 0 };

/** Status triaged > partial > new; items, triage and dropped lines are unions.
 *  Remaining fields: 3-way, a real conflict keeps the canonically smaller value
 *  (side-independent). */
export function mergeIntake(base: string | null, ours: string, theirs: string): MergeResult {
  if (ours === theirs) return { merged: ours, notes: [] };
  if (base !== null && ours === base) return { merged: theirs, notes: [] };
  if (base !== null && theirs === base) return { merged: ours, notes: [] };
  const o = parseIntake(ours).rec;
  const t = parseIntake(theirs).rec;
  let b: IntakeRecord | null = null;
  if (base !== null) {
    try {
      b = parseIntake(base).rec;
    } catch {
      b = null;
    }
  }
  if (o.id !== t.id) throw new Error('mergeIntake: sides are different records');
  const pick = <T>(bv: T | undefined, ov: T, tv: T): T => merge3<T>(bv, ov, tv, canon(ov) <= canon(tv)).value;
  const status: IntakeStatus = INTAKE_RANK[o.status] >= INTAKE_RANK[t.status] ? o.status : t.status;
  const tri = (r: IntakeRecord | null): string[] => (r?.triage ?? []).map((x) => `${x.item}\u0000${x.excerpt}`);
  const drp = (r: IntakeRecord | null): string[] => (r?.dropped ?? []).map((x) => `${x.text}\u0000${x.reason}`);
  const rec: IntakeRecord = {
    id: o.id,
    at: minTime(o.at, t.at),
    channel: pick(b?.channel, o.channel, t.channel),
    session: pick(b?.session, o.session, t.session),
    repo_hint: pick(b?.repo_hint, o.repo_hint, t.repo_hint),
    status,
    items: unionList(b?.items ?? [], o.items, t.items),
    text: pick(b?.text, o.text, t.text),
    triage: unionList(tri(b), tri(o), tri(t)).map((k) => {
      const [item, excerpt] = k.split('\u0000');
      return { item: item as string, excerpt: excerpt ?? '' };
    }),
    dropped: unionList(drp(b), drp(o), drp(t)).map((k) => {
      const [text, reason] = k.split('\u0000');
      return { text: text as string, reason: reason ?? '' };
    }),
  };
  return { merged: serializeIntake(rec), notes: [] };
}

/* ---------------- CONTEXT.md ---------------- */

/** Line 3-way. Conflicting regions keep the LOCAL (`ours`) text — by design not
 *  side-independent; the other version comes back as `proposedItem`. */
export function mergeContext(base: string | null, ours: string, theirs: string): ContextMergeResult {
  const r = mergeText(base, ours, theirs, true);
  const merged = fileText(splitLines(r.text));
  if (!r.conflict) return { merged, notes: [], proposedItem: null };
  return {
    merged,
    notes: [{ type: 'sync.context-conflict', field: 'CONTEXT.md', detail: 'CONTEXT.md diverged, local kept, other version proposed' }],
    proposedItem: {
      title: 'CONTEXT.md changed on another device (conflict)',
      why: r.loserBlocks.filter((x) => x.trim() !== '').join('\n…\n'),
      otherVersion: fileText(splitLines(theirs)),
    },
  };
}
