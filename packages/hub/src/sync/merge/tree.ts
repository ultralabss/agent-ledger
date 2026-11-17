/** Tree dispatcher (F3b B2): base/ours/theirs blob maps -> merged blob map + notes.
 *
 *  Pure. Routes every path to its typed merger. Guarantees:
 *   - a merger that throws is caught and becomes a quarantine result — nothing
 *     propagates (ledger AL-36);
 *   - item deletes never apply (spec §3.2): the item is kept, `sync.reject` note;
 *   - any other delete, an unclassified path changed on both sides, or a pinned
 *     file that diverged is a quarantine (fail closed);
 *   - `devices.yml` / `repos.yml` always go through their mergers (never the
 *     "other side verbatim" shortcut) so uniqueness / validation always run;
 *   - output order is by path, notes are totally ordered: same inputs, same bytes.
 */

import { safeOutput } from '@agent-ledger/shared';
import { cmpStr } from './common.ts';
import { mergeDevicesNullable } from './devices.ts';
import { mergeContext, mergeCounters, mergeDecisions, mergeIntake, mergeJournal } from './files.ts';
import { mergeItem } from './item.ts';
import { mergeRepos } from './repos.ts';
import type { MergeCtx, MergeResult, SyncNote } from './types.ts';

export type BlobMap = ReadonlyMap<string, string>;

export interface TreeMergeInput {
  /** Merge-base tree; `null` = unrelated histories. */
  base: BlobMap | null;
  ours: BlobMap;
  theirs: BlobMap;
  ctx: MergeCtx;
}

export interface TreeQuarantine {
  rule: string;
  path: string;
  detail: string;
}

export interface ProposedItem {
  repo: string;
  title: string;
  why: string;
}

export type TreeMergeResult =
  | {
      ok: true;
      /** Complete merged tree (path -> text), sorted by path. Deleted paths absent. */
      blobs: Map<string, string>;
      /** Paths whose merged text differs from `ours` (reindex set), sorted. */
      changed: string[];
      notes: SyncNote[];
      proposed: ProposedItem[];
    }
  | { ok: false; quarantine: TreeQuarantine[]; notes: SyncNote[] };

type Kind =
  | 'repos' | 'devices' | 'counters' | 'format' | 'gitignore' | 'gitattributes'
  | 'context' | 'decisions' | 'item' | 'journal' | 'intake';
interface Route {
  kind: Kind;
  slug?: string;
  id?: string;
}

const DEVICE_COUNTER_RE = /^counters\/d_[a-z2-7]{10}\.yml$/;
const JOURNAL_RE = /^([a-z0-9-]+)\/journal\/\d{4}-(?:0[1-9]|1[0-2])\.md$/;
const ITEM_FILE_RE = /^([a-z0-9-]+)\/items\/([A-Z]{2,4}-[A-HJ-NP-Z]?[1-9][0-9]*)\.md$/;
const INTAKE_RE = /^intake\/\d{4}-(?:0[1-9]|1[0-2])\/[1-9][0-9]{0,19}\.md$/;
const SLUG_FILE_RE = /^([a-z0-9-]+)\/(CONTEXT|DECISIONS)\.md$/;

function route(path: string): Route | null {
  switch (path) {
    case 'repos.yml': return { kind: 'repos' };
    case 'devices.yml': return { kind: 'devices' };
    case 'ledger.format': return { kind: 'format' };
    case '.gitignore': return { kind: 'gitignore' };
    case '.gitattributes': return { kind: 'gitattributes' };
    default:
  }
  if (DEVICE_COUNTER_RE.test(path)) return { kind: 'counters' };
  let m = ITEM_FILE_RE.exec(path);
  if (m) return { kind: 'item', slug: m[1] as string, id: m[2] as string };
  m = SLUG_FILE_RE.exec(path);
  if (m) return { kind: m[2] === 'CONTEXT' ? 'context' : 'decisions', slug: m[1] as string };
  m = JOURNAL_RE.exec(path);
  if (m) return { kind: 'journal', slug: m[1] as string };
  if (INTAKE_RE.test(path)) return { kind: 'intake' };
  return null;
}

const FORMAT_RE = /^[1-9][0-9]{0,3}\n?$/;

function noteKey(n: SyncNote): string {
  return [n.type, n.repo ?? '', n.item ?? '', n.field ?? '', n.device ?? '', n.session ?? '', n.path ?? '', n.rule ?? '', n.detail]
    .map((x) => x.length.toString(36) + ':' + x)
    .join('|');
}

/** Merge three trees. Never throws. */
export function mergeTrees(input: TreeMergeInput): TreeMergeResult {
  const notes: SyncNote[] = [];
  const quarantine: TreeQuarantine[] = [];
  const proposed: ProposedItem[] = [];
  try {
    const { base, ours, theirs, ctx } = input;
    const paths = new Set<string>([...ours.keys(), ...theirs.keys(), ...(base?.keys() ?? [])]);
    const blobs = new Map<string, string>();
    const q = (rule: string, path: string, detail: string): void => {
      quarantine.push({ rule, path: safeOutput(path, 120), detail: safeOutput(detail, 160) });
    };

    for (const path of [...paths].sort(cmpStr)) {
      const o = ours.get(path);
      const t = theirs.get(path);
      const b = base?.get(path);
      const r = route(path);
      const put = (text: string | undefined | null): void => {
        if (text !== undefined && text !== null) blobs.set(path, text);
      };
      const tag = (list: readonly SyncNote[]): void => {
        for (const n of list) {
          notes.push({
            ...n,
            ...(r?.slug !== undefined ? { repo: r.slug } : {}),
            path,
          });
        }
      };
      try {
        // devices.yml / repos.yml: always the merger (validation + uniqueness), even for no-op sides.
        if (r?.kind === 'devices') {
          if (b !== undefined && (o === undefined || t === undefined)) {
            q('delete-protected', path, 'devices.yml deleted on one side'); // never a trust-root reset
            continue;
          }
          const res = mergeDevicesNullable(b ?? null, o ?? null, t ?? null);
          if (!res.ok) q(res.rule, path, res.detail);
          else put(res.merged);
          continue;
        }
        if (r?.kind === 'repos' && o !== undefined && t !== undefined) {
          const res = mergeRepos(b ?? null, o, t);
          tag(res.notes);
          put(res.merged);
          continue;
        }
        if (o === t) {
          put(o);
          continue;
        }
        if (o === undefined || t === undefined) {
          const present = (o ?? t) as string;
          if (b === undefined) {
            put(present); // plain addition on one side
          } else if (r?.kind === 'item') {
            // Delete on one side (invariant 4 / spec §3.2): the item stays.
            put(present);
            const deleter = o === undefined ? ctx.ourDevice : ctx.theirDevice;
            notes.push({
              type: 'sync.reject',
              rule: 'delete',
              item: r.id as string,
              repo: r.slug as string,
              path,
              device: deleter,
              detail: 'item delete reverted, item kept',
            });
          } else {
            q('delete-protected', path, 'file deleted on one side; only items may be soft-reverted');
          }
          continue;
        }
        // Both present and different.
        if (b !== undefined && r?.kind !== 'repos') {
          if (o === b) { put(t); continue; }
          if (t === b) { put(o); continue; }
        }
        if (r === null) {
          q('layout', path, 'unclassified path changed on both sides');
          continue;
        }
        let res: MergeResult;
        switch (r.kind) {
          case 'item':
            res = mergeItem(b ?? null, o, t, ctx);
            break;
          case 'journal':
            res = mergeJournal(b ?? null, o, t);
            break;
          case 'decisions':
            res = mergeDecisions(b ?? null, o, t);
            break;
          case 'counters':
            res = mergeCounters(b ?? null, o, t);
            break;
          case 'intake':
            res = mergeIntake(b ?? null, o, t);
            break;
          case 'repos':
            res = mergeRepos(b ?? null, o, t);
            break;
          case 'context': {
            const c = mergeContext(b ?? null, o, t);
            res = c;
            if (c.proposedItem !== null) {
              proposed.push({
                repo: r.slug as string,
                title: safeOutput(c.proposedItem.title, 120),
                why: safeOutput(c.proposedItem.why, 600),
              });
            }
            break;
          }
          case 'format': {
            if (!FORMAT_RE.test(o) || !FORMAT_RE.test(t)) throw new Error('ledger.format: not an integer');
            res = { merged: Number(o) >= Number(t) ? o : t, notes: [] }; // monotonic: never down
            break;
          }
          default:
            q('pinned', path, 'pinned file differs on both sides');
            continue;
        }
        tag(res.notes);
        put(res.merged);
      } catch {
        // AL-36: no merger failure escapes; the caller quarantines the range.
        q('merge-error', path, 'merger failed on this path');
      }
    }

    notes.sort((x, y) => cmpStr(noteKey(x), noteKey(y)));
    proposed.sort((x, y) => cmpStr(x.repo, y.repo) || cmpStr(x.title, y.title) || cmpStr(x.why, y.why));
    if (quarantine.length > 0) {
      quarantine.sort((x, y) => cmpStr(x.path, y.path) || cmpStr(x.rule, y.rule));
      return { ok: false, quarantine, notes };
    }
    const changed = [...new Set([...blobs.keys(), ...ours.keys()])].filter((p) => blobs.get(p) !== ours.get(p)).sort(cmpStr);
    return { ok: true, blobs: new Map([...blobs.entries()].sort(([x], [y]) => cmpStr(x, y))), changed, notes, proposed };
  } catch {
    return { ok: false, quarantine: [{ rule: 'internal', path: '(tree)', detail: 'tree merge failed' }], notes: [] };
  }
}
