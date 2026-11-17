/** `repos.yml` (format 2, synced) merger (F3b B2, findings F-7 / F3A-8).
 *
 *  Per-slug field 3-way (lists as sets, `prefix_aliases` union, `onboarded` OR),
 *  never deletes a repo. After the merge the registry is made unique, with a
 *  deterministic winner = lowest slug (total `cmpStr` order) and a `sync.conflict`
 *  note per repair:
 *   - primary `prefix` shared by two slugs: the loser gets a fresh prefix derived
 *     from its slug (its old prefix is NOT kept as alias — it would clash again);
 *   - `prefix_aliases` entries that clash with another slug's prefix/alias, or
 *     repeat the slug's own primary, are dropped;
 *   - `identity.root_sha` shared by two slugs: the loser loses `identity`.
 *  Throws on invalid input (the tree dispatcher turns that into a quarantine).
 *  Output: LF, slugs sorted, key order as `Ledger.saveRepos` writes it.
 */

import { repoSyncedSchema, reposSyncedFileSchema } from '@agent-ledger/shared';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { z } from 'zod';
import { canon, cmpStr, merge3, mergeSet, unionList } from './common.ts';
import type { MergeResult, SyncNote } from './types.ts';

type Entry = z.infer<typeof repoSyncedSchema>;
type Rec = Record<string, unknown>;

const KEY_ORDER = [
  'kind', 'host', 'prefix', 'docs', 'graphify_rel', 'identity', 'prefix_aliases',
  'onboarded', 'contracts', 'consumers', 'path', 'next', 'graphify',
] as const;
const SET_KEYS = new Set<string>(['docs', 'contracts', 'consumers']);

function parseRepos(text: string | null): Map<string, Entry> {
  if (text === null) return new Map();
  const raw: unknown = parseYaml(text, { maxAliasCount: 0 });
  const res = reposSyncedFileSchema.safeParse(raw ?? {});
  if (!res.success) throw new Error('repos.yml: invalid');
  return new Map(Object.entries(res.data));
}

function asList(v: unknown): string[] {
  return Array.isArray(v) ? (v as string[]) : [];
}

function mergeEntry(slug: string, b: Entry | undefined, o: Entry, t: Entry, notes: SyncNote[]): Rec {
  const out: Rec = {};
  const bb = (b ?? {}) as Rec;
  const oo = o as Rec;
  const tt = t as Rec;
  for (const k of KEY_ORDER) {
    const ov = oo[k];
    const tv = tt[k];
    if (ov === undefined && tv === undefined) continue;
    let value: unknown;
    if (SET_KEYS.has(k)) {
      value = mergeSet(asList(bb[k]), asList(ov), asList(tv));
    } else if (k === 'prefix_aliases') {
      value = unionList(asList(bb[k]), asList(ov), asList(tv));
    } else if (k === 'onboarded') {
      value = ov === true || tv === true;
    } else {
      const r = merge3<unknown>(bb[k], ov, tv, canon(ov) <= canon(tv));
      value = r.value;
      if (r.conflict) {
        notes.push({
          type: 'sync.conflict',
          field: `repos.yml:${k}`,
          repo: slug,
          rule: 'repos-field',
          detail: `repos.yml ${slug}: ${k} diverged, canonically smaller value kept`,
        });
      }
    }
    if (value !== undefined) out[k] = value;
  }
  return out;
}

/** Deterministic fresh prefix for `slug`: slug letters first, then padded / counted
 *  variants, never one of `taken`. */
function freshPrefix(slug: string, taken: ReadonlySet<string>): string | null {
  const letters = slug.toUpperCase().replace(/[^A-Z]/g, '');
  const seed = (letters + 'XXXX').slice(0, 4);
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const cands: string[] = [seed, seed.slice(0, 3), seed.slice(0, 2)];
  for (const c of A) cands.push(seed.slice(0, 3) + c);
  for (const c of A) for (const d of A) cands.push(seed.slice(0, 2) + c + d);
  for (const c of A) for (const d of A) cands.push(c + d);
  return cands.find((c) => /^[A-Z]{2,4}$/.test(c) && !taken.has(c)) ?? null;
}

export function mergeRepos(base: string | null, ours: string, theirs: string): MergeResult {
  let B = new Map<string, Entry>();
  if (base !== null) {
    try {
      B = parseRepos(base);
    } catch {
      B = new Map(); // a broken base only loses the 3-way hint; sides are validated below
    }
  }
  const O = parseRepos(ours);
  const T = parseRepos(theirs);
  if (ours === theirs) return { merged: ours, notes: [] };
  const notes: SyncNote[] = [];
  const merged = new Map<string, Rec>();
  for (const slug of [...new Set([...O.keys(), ...T.keys()])].sort(cmpStr)) {
    const o = O.get(slug);
    const t = T.get(slug);
    // Never delete a repo (`repo rm` is refused in sync mode): the side that has it wins.
    merged.set(slug, o !== undefined && t !== undefined ? mergeEntry(slug, B.get(slug), o, t, notes) : { ...((o ?? t) as Rec) });
  }
  const slugs = [...merged.keys()].sort(cmpStr);

  // Everything already spoken for, so a fresh prefix cannot create a new clash.
  const taken = new Set<string>();
  for (const s of slugs) {
    const e = merged.get(s) as Rec;
    taken.add(e.prefix as string);
    for (const a of asList(e.prefix_aliases)) taken.add(a);
  }

  // 1) primary prefixes, lowest slug wins
  const primary = new Map<string, string>();
  for (const s of slugs) {
    const e = merged.get(s) as Rec;
    const p = e.prefix as string;
    const holder = primary.get(p);
    if (holder === undefined) {
      primary.set(p, s);
      continue;
    }
    const fresh = freshPrefix(s, taken);
    if (fresh === null) throw new Error('repos.yml: no free prefix');
    e.prefix = fresh;
    taken.add(fresh);
    primary.set(fresh, s);
    notes.push({
      type: 'sync.conflict',
      field: 'repos.yml:prefix',
      repo: s,
      rule: 'repos-prefix',
      detail: `repos.yml prefix ${p} already used by ${holder}: ${s} now uses ${fresh} (old ids keep working only under ${holder})`,
    });
  }
  // 2) aliases: not a foreign primary, not a foreign earlier alias, not the own primary
  const aliasOwner = new Map<string, string>();
  for (const s of slugs) {
    const e = merged.get(s) as Rec;
    if (e.prefix_aliases === undefined) continue;
    const keep: string[] = [];
    for (const a of [...new Set(asList(e.prefix_aliases))].sort(cmpStr)) {
      const owner = primary.get(a) ?? aliasOwner.get(a);
      if (owner !== undefined && owner !== s) {
        notes.push({
          type: 'sync.conflict',
          field: 'repos.yml:prefix_aliases',
          repo: s,
          rule: 'repos-alias',
          detail: `repos.yml alias ${a} of ${s} clashes with ${owner}, alias dropped`,
        });
        continue;
      }
      if (primary.get(a) === s) continue; // own primary repeated as alias: silently redundant
      aliasOwner.set(a, s);
      keep.push(a);
    }
    if (keep.length === 0) delete e.prefix_aliases;
    else e.prefix_aliases = keep;
  }
  // 3) one registry entry per git root
  const roots = new Map<string, string>();
  for (const s of slugs) {
    const e = merged.get(s) as Rec;
    const sha = (e.identity as { root_sha?: string } | undefined)?.root_sha;
    if (sha === undefined) continue;
    const holder = roots.get(sha);
    if (holder === undefined) {
      roots.set(sha, s);
      continue;
    }
    delete e.identity;
    notes.push({
      type: 'sync.conflict',
      field: 'repos.yml:identity',
      repo: s,
      rule: 'repos-root',
      detail: `repos.yml root_sha of ${s} is the same as ${holder}: identity of ${s} removed`,
    });
  }

  const obj: Rec = {};
  for (const s of slugs) {
    const e = merged.get(s) as Rec;
    const ordered: Rec = {};
    for (const k of KEY_ORDER) if (e[k] !== undefined) ordered[k] = e[k];
    obj[s] = ordered;
  }
  notes.sort((x, y) => cmpStr(x.repo ?? '', y.repo ?? '') || cmpStr(x.field ?? '', y.field ?? '') || cmpStr(x.detail, y.detail));
  return { merged: stringifyYaml(obj, { lineWidth: 0 }), notes };
}
