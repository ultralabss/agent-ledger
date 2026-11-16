/** `items/<ID>.md` merger — spec §3.2 rows for frontmatter, status, claim,
 *  sets, done, Plan, Why/Recommendation, Comments, Log. */

import {
  escapeStructuralLines,
  KNOWN_SECTIONS,
  parseItem,
  serializeItem,
  type ClaimedBy,
  type Item,
  type ItemComment,
  type ItemDone,
  type ItemFrontmatter,
  type ItemStatus,
  type LogLine,
  type MdDoc,
  type MdSection,
  type ParsedItem,
  type PlanStep,
} from '@agent-ledger/shared';
import {
  cmpIds,
  cmpStr,
  excerpt,
  maxTime,
  merge3,
  mergeSet,
  minTime,
  oursWins,
  same,
  stampOf,
  syncCommentId,
} from './common.ts';
import { mergeText } from './diff3.ts';
import type { MergeCtx, MergeResult, SyncNote } from './types.ts';

/** done > dropped > blocked > doing > open > proposed. */
const RANK: Record<ItemStatus, number> = {
  done: 5,
  dropped: 4,
  blocked: 3,
  doing: 2,
  open: 1,
  proposed: 0,
};
const isTerminal = (s: ItemStatus): boolean => s === 'done' || s === 'dropped';

export function mergeStatus(base: ItemStatus | undefined, ours: ItemStatus, theirs: ItemStatus): ItemStatus {
  if (ours === theirs) return ours;
  if (base !== undefined && ours === base) return theirs;
  if (base !== undefined && theirs === base) return ours;
  // Both sides moved. A reopen of a terminal base beats the stale terminal side.
  if (base !== undefined && isTerminal(base)) {
    if (!isTerminal(ours) && isTerminal(theirs)) return ours;
    if (!isTerminal(theirs) && isTerminal(ours)) return theirs;
  }
  return RANK[ours] >= RANK[theirs] ? ours : theirs;
}

const FM_ORDER: readonly (keyof ItemFrontmatter)[] = [
  'id', 'title', 'status', 'kind', 'priority', 'owner', 'repo', 'area', 'paths', 'blocks',
  'blocked_by', 'requested_by', 'intake', 'aliases', 'claimed_by', 'source', 'done', 'created', 'updated',
];
const KNOWN_FM: ReadonlySet<string> = new Set(FM_ORDER);
const KNOWN_LOWER: ReadonlySet<string> = new Set(KNOWN_SECTIONS.map((s) => s.toLowerCase()));

function firstByNumber(steps: readonly PlanStep[]): Map<number, PlanStep> {
  const m = new Map<number, PlanStep>();
  for (const s of steps) if (!m.has(s.n)) m.set(s.n, s);
  return m;
}

function sectionMap(doc: MdDoc): Map<string, MdSection> {
  const m = new Map<string, MdSection>();
  for (const s of doc.sections) {
    const k = s.heading.toLowerCase();
    if (!m.has(k)) m.set(k, s);
  }
  return m;
}

const cKey = (c: ItemComment): string => `${c.id}\u0000${c.at}\u0000${c.author}\u0000${c.text}`;
const lKey = (l: LogLine): string => `${l.at}\u0000${l.session}\u0000${l.text}`;

export function mergeItem(base: string | null, ours: string, theirs: string, ctx: MergeCtx): MergeResult {
  // Untouched side: take the other one byte for byte (no reformatting, no notes).
  if (ours === theirs) return { merged: ours, notes: [] };
  if (base !== null && ours === base) return { merged: theirs, notes: [] };
  if (base !== null && theirs === base) return { merged: ours, notes: [] };

  // Invalid sides throw — the caller quarantines instead of merging garbage.
  const O: ParsedItem = parseItem(ours);
  const T: ParsedItem = parseItem(theirs);
  let B: ParsedItem | null = null;
  if (base !== null) {
    try {
      B = parseItem(base);
    } catch {
      B = null; // corrupt base: behave as if there were none (conservative: more conflicts, no loss)
    }
  }
  const o = O.item;
  const t = T.item;
  const b = B?.item;
  if (o.fm.id !== t.fm.id || o.fm.repo !== t.fm.repo) throw new Error('mergeItem: sides are different items');
  const id = o.fm.id;
  const ow = oursWins(ctx, o.fm.updated, t.fm.updated);
  const winnerDev = ow ? ctx.ourDevice : ctx.theirDevice;
  const loserDev = ow ? ctx.theirDevice : ctx.ourDevice;
  const updated = maxTime(o.fm.updated, t.fm.updated);
  const at = stampOf(updated);

  const notes: SyncNote[] = [];
  const syncLogs: LogLine[] = [];
  const syncComments: ItemComment[] = [];

  const conflict = (field: string, kept: unknown, dropped: unknown): void => {
    notes.push({
      type: 'sync.conflict',
      item: id,
      field,
      device: loserDev,
      detail: `${field}: kept ${excerpt(kept)}, dropped ${excerpt(dropped)}`,
    });
    syncLogs.push({
      at,
      session: 'sync',
      text: `sync: ${field} kept ${excerpt(kept)} dropped ${excerpt(dropped)} (${loserDev})`,
    });
  };
  const textConflict = (field: string, blocks: string[]): void => {
    notes.push({ type: 'sync.conflict', item: id, field, device: loserDev, detail: `${field}: text conflict, other version kept as sync comment` });
    const kept = blocks.filter((x) => x.trim() !== '');
    if (kept.length === 0) return; // the loser only deleted lines — nothing to preserve
    const text = escapeStructuralLines(
      `sync: ${field} conflict, kept version of ${winnerDev}; dropped version of ${loserDev}:\n${kept.join('\n…\n')}`,
    ).trim();
    syncComments.push({ at, author: 'sync', id: syncCommentId(updated, `${id}\n${field}\n${text}`), text });
  };

  /* ---- frontmatter ---- */
  const sc = <K extends keyof ItemFrontmatter>(k: K): ItemFrontmatter[K] => {
    const r = merge3<ItemFrontmatter[K]>(b?.fm[k], o.fm[k], t.fm[k], ow);
    if (r.conflict) conflict(String(k), r.value, r.loser);
    return r.value;
  };
  const title = sc('title');
  const kind = sc('kind');
  const priority = sc('priority');
  const owner = sc('owner');
  const area = sc('area');
  const requested_by = sc('requested_by');
  const intake = sc('intake');
  const source = sc('source');

  let status = mergeStatus(b?.fm.status, o.fm.status, t.fm.status);

  const remoteFm = ctx.remoteIsTheirs ? t.fm : o.fm;
  const cl = merge3<ClaimedBy | null>(b?.fm.claimed_by, o.fm.claimed_by, t.fm.claimed_by, !ctx.remoteIsTheirs);
  let claimed: ClaimedBy | null = cl.conflict ? remoteFm.claimed_by : cl.value;
  if (status !== 'doing') claimed = null;
  else if (claimed === null) status = 'open'; // `doing` without a holder is not a state
  for (const [fm, dev] of [[o.fm, ctx.ourDevice], [t.fm, ctx.theirDevice]] as const) {
    const c = fm.claimed_by;
    if (c && !same(c, b?.fm.claimed_by) && !same(c, claimed)) {
      notes.push({
        type: 'sync.claim-lost',
        item: id,
        device: dev,
        session: c.session,
        detail: `claim by ${c.session} not kept (merged status ${status})`,
      });
    }
  }

  let done: ItemDone | null = null;
  if (status === 'done') {
    const od = o.fm.status === 'done' ? o.fm.done : null;
    const td = t.fm.status === 'done' ? t.fm.done : null;
    if (od && td) {
      const r = merge3<ItemDone | null>(b?.fm.done, od, td, ow);
      if (r.conflict) conflict('done', r.value, r.loser);
      done = r.value;
    } else done = od ?? td ?? o.fm.done ?? t.fm.done;
  }

  const fm: ItemFrontmatter = {
    id,
    title,
    status,
    kind,
    priority,
    owner,
    repo: o.fm.repo,
    area,
    paths: mergeSet(b?.fm.paths ?? [], o.fm.paths, t.fm.paths),
    blocks: mergeSet(b?.fm.blocks ?? [], o.fm.blocks, t.fm.blocks),
    blocked_by: mergeSet(b?.fm.blocked_by ?? [], o.fm.blocked_by, t.fm.blocked_by),
    requested_by,
    intake,
    aliases: mergeSet(b?.fm.aliases ?? [], o.fm.aliases, t.fm.aliases),
    claimed_by: claimed,
    source,
    done,
    created: minTime(o.fm.created, t.fm.created),
    updated,
  };

  // Keys the schema does not know survive (round-trip safe), field-level 3-way too.
  const full: Record<string, unknown> = {};
  for (const k of FM_ORDER) full[k] = fm[k];
  const extra = new Set<string>();
  for (const d of [O.doc, T.doc, B?.doc]) {
    for (const k of Object.keys(d?.frontmatter ?? {})) if (!KNOWN_FM.has(k)) extra.add(k);
  }
  for (const k of [...extra].sort(cmpStr)) {
    const r = merge3<unknown>(B?.doc.frontmatter[k], O.doc.frontmatter[k], T.doc.frontmatter[k], ow);
    if (r.conflict) conflict(k, r.value, r.loser);
    if (r.value !== undefined) full[k] = r.value;
  }

  /* ---- Plan ---- */
  const bs = b ? firstByNumber(b.steps) : new Map<number, PlanStep>();
  const os = firstByNumber(o.steps);
  const ts = firstByNumber(t.steps);
  const steps: PlanStep[] = [];
  for (const n of [...new Set([...os.keys(), ...ts.keys()])].sort((x, y) => x - y)) {
    const so = os.get(n);
    const st = ts.get(n);
    const sb = bs.get(n);
    if (so && st) {
      const r = merge3<string>(sb?.text, so.text, st.text, ow);
      if (r.conflict) {
        notes.push({ type: 'sync.conflict', item: id, field: `plan.${n}`, device: loserDev, detail: `plan step ${n}: text conflict, other version kept as sync comment` });
        const text = escapeStructuralLines(
          `sync: plan step ${n} conflict, kept version of ${winnerDev}; dropped version of ${loserDev}:\n${r.loser ?? ''}`,
        ).trim();
        syncComments.push({ at, author: 'sync', id: syncCommentId(updated, `${id}\nplan.${n}\n${text}`), text });
      }
      steps.push({ n, done: so.done || st.done, text: r.value });
      continue;
    }
    // Present on one side only: new there, or deleted by the other. A deletion
    // is honoured only when the surviving side never touched the step.
    const alive = (so ?? st) as PlanStep;
    if (sb && same(alive, sb)) continue;
    steps.push({ ...alive });
  }

  /* ---- Why / Recommendation / preamble / unknown sections ---- */
  const merge = (field: string, bt: string | null, ot: string, tt: string): string => {
    const r = mergeText(bt, ot, tt, ow);
    if (r.conflict) textConflict(field, r.loserBlocks);
    return r.text;
  };
  const sb = B ? sectionMap(B.doc) : new Map<string, MdSection>();
  const so = sectionMap(O.doc);
  const st = sectionMap(T.doc);
  const body = (m: Map<string, MdSection>, k: string): string | null => m.get(k)?.body ?? null;
  const why = merge('why', b ? b.why : null, o.why, t.why);
  const rec = merge('rec', b ? b.rec : null, o.rec, t.rec);
  const preamble = merge('preamble', B ? B.doc.preamble : null, O.doc.preamble, T.doc.preamble);
  const unknown: MdSection[] = [];
  const keys = new Set<string>();
  for (const m of [so, st]) for (const k of m.keys()) if (!KNOWN_LOWER.has(k)) keys.add(k);
  for (const k of [...keys].sort(cmpStr)) {
    const names = [so.get(k)?.heading, st.get(k)?.heading].filter((x): x is string => x !== undefined);
    const heading = names.sort(cmpStr)[0] as string;
    unknown.push({ heading, body: merge(`section:${k}`, body(sb, k), body(so, k) ?? '', body(st, k) ?? '') });
  }

  /* ---- Comments: union by Snowflake id, never delete ---- */
  const cmap = new Map<string, ItemComment>();
  for (const c of [...o.comments, ...t.comments, ...syncComments]) if (!cmap.has(cKey(c))) cmap.set(cKey(c), c);
  const comments = [...cmap.values()].sort(
    (x, y) => cmpIds(x.id, y.id) || cmpStr(x.at, y.at) || cmpStr(x.author, y.author) || cmpStr(x.text, y.text),
  );
  const byId = new Map<string, number>();
  for (const c of comments) byId.set(c.id, (byId.get(c.id) ?? 0) + 1);
  const seenId = new Set<string>();
  for (const [cid, count] of byId) {
    const inO = o.comments.filter((c) => c.id === cid).length;
    const inT = t.comments.filter((c) => c.id === cid).length;
    if (count > 1 && count > inO && count > inT && !seenId.has(cid)) {
      seenId.add(cid);
      notes.push({ type: 'sync.conflict', item: id, field: 'comments', detail: `comment ${cid}: same id, different content, both kept` });
    }
  }

  /* ---- Log: union by exact line; order = time, then base order, then text ---- */
  const baseIdx = new Map<string, number>();
  (b?.log ?? []).forEach((l, i) => {
    if (!baseIdx.has(lKey(l))) baseIdx.set(lKey(l), i);
  });
  const lmap = new Map<string, LogLine>();
  for (const l of [...o.log, ...t.log, ...syncLogs]) if (!lmap.has(lKey(l))) lmap.set(lKey(l), l);
  const log = [...lmap.values()].sort((x, y) => {
    const c = cmpStr(x.at, y.at);
    if (c !== 0) return c;
    const ix = baseIdx.get(lKey(x));
    const iy = baseIdx.get(lKey(y));
    if (ix !== undefined && iy !== undefined) return ix - iy;
    if (ix !== undefined) return -1;
    if (iy !== undefined) return 1;
    return cmpStr(x.session, y.session) || cmpStr(x.text, y.text);
  });

  /* ---- assemble: canonical frontmatter and section order ---- */
  const doc: MdDoc = {
    frontmatter: full,
    preamble,
    sections: [
      ...KNOWN_SECTIONS.map((heading) => ({ heading, body: '' })),
      ...unknown,
    ],
  };
  const merged: Item = { fm, why, steps, rec, comments, log };
  notes.sort((x, y) => cmpStr(x.type, y.type) || cmpStr(x.field ?? '', y.field ?? '') || cmpStr(x.detail, y.detail));
  return { merged: serializeItem(merged, doc), notes };
}
