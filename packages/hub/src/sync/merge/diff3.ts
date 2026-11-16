/** Line diff + 3-way merge in plain JS (the `git merge-file` equivalent the
 *  spec asks for; no process is ever spawned). Never emits conflict markers:
 *  callers get structured regions and decide what to keep. */

export interface Hunk {
  /** Base range [start, end) replaced by `lines`. start === end = pure insertion. */
  start: number;
  end: number;
  lines: string[];
}

export type Region =
  | { kind: 'ok'; lines: string[] }
  | { kind: 'conflict'; base: string[]; ours: string[]; theirs: string[] };

/** CRLF → LF, no trailing empty element, '' → []. */
export function splitLines(text: string): string[] {
  if (text === '') return [];
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

export function joinLines(lines: readonly string[]): string {
  return lines.join('\n');
}

/** DP cell budget; above it the middle is replaced as one hunk (conservative:
 *  two such edits conflict instead of being merged on a guess). */
const MAX_CELLS = 4_000_000;

function eqArr(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

export function diffHunks(base: readonly string[], side: readonly string[]): Hunk[] {
  const n = base.length;
  const m = side.length;
  let p = 0;
  while (p < n && p < m && base[p] === side[p]) p += 1;
  let s = 0;
  while (s < n - p && s < m - p && base[n - 1 - s] === side[m - 1 - s]) s += 1;
  const bn = n - p - s;
  const sn = m - p - s;
  if (bn === 0 && sn === 0) return [];
  if (bn === 0 || sn === 0 || bn * sn > MAX_CELLS) {
    return [{ start: p, end: p + bn, lines: side.slice(p, p + sn) }];
  }
  const w = sn + 1;
  const dp = new Uint32Array((bn + 1) * w);
  for (let i = bn - 1; i >= 0; i -= 1) {
    for (let j = sn - 1; j >= 0; j -= 1) {
      dp[i * w + j] =
        base[p + i] === side[p + j]
          ? (dp[(i + 1) * w + j + 1] ?? 0) + 1
          : Math.max(dp[(i + 1) * w + j] ?? 0, dp[i * w + j + 1] ?? 0);
    }
  }
  const hunks: Hunk[] = [];
  let open: Hunk | null = null;
  const close = (): void => {
    if (open) hunks.push(open);
    open = null;
  };
  let i = 0;
  let j = 0;
  while (i < bn || j < sn) {
    if (i < bn && j < sn && base[p + i] === side[p + j]) {
      close();
      i += 1;
      j += 1;
      continue;
    }
    if (!open) open = { start: p + i, end: p + i, lines: [] };
    const del = j >= sn || (i < bn && (dp[(i + 1) * w + j] ?? 0) >= (dp[i * w + j + 1] ?? 0));
    if (del) {
      i += 1;
      open.end = p + i;
    } else {
      open.lines.push(side[p + j] as string);
      j += 1;
    }
  }
  close();
  return hunks;
}

function apply(base: readonly string[], s: number, e: number, hunks: readonly Hunk[]): string[] {
  const out: string[] = [];
  let pos = s;
  for (const h of hunks) {
    out.push(...base.slice(pos, h.start), ...h.lines);
    pos = h.end;
  }
  out.push(...base.slice(pos, e));
  return out;
}

/** Git semantics: hunks that overlap or touch form one region; a region
 *  changed by both sides in different ways is a conflict. */
export function merge3Lines(
  base: readonly string[],
  ours: readonly string[],
  theirs: readonly string[],
): Region[] {
  const tagged = [
    ...diffHunks(base, ours).map((h) => ({ h, a: true })),
    ...diffHunks(base, theirs).map((h) => ({ h, a: false })),
  ].sort((x, y) => x.h.start - y.h.start || x.h.end - y.h.end);
  const regions: Region[] = [];
  let pos = 0;
  let k = 0;
  while (k < tagged.length) {
    const first = tagged[k] as { h: Hunk; a: boolean };
    const s = first.h.start;
    let e = first.h.end;
    const as: Hunk[] = [];
    const bs: Hunk[] = [];
    while (k < tagged.length && (tagged[k] as { h: Hunk }).h.start <= e) {
      const cur = tagged[k] as { h: Hunk; a: boolean };
      e = Math.max(e, cur.h.end);
      (cur.a ? as : bs).push(cur.h);
      k += 1;
    }
    if (s > pos) regions.push({ kind: 'ok', lines: base.slice(pos, s) as string[] });
    const av = apply(base, s, e, as);
    const bv = apply(base, s, e, bs);
    if (as.length === 0) regions.push({ kind: 'ok', lines: bv });
    else if (bs.length === 0 || eqArr(av, bv)) regions.push({ kind: 'ok', lines: av });
    else regions.push({ kind: 'conflict', base: base.slice(s, e) as string[], ours: av, theirs: bv });
    pos = e;
  }
  if (pos < base.length) regions.push({ kind: 'ok', lines: base.slice(pos) as string[] });
  return regions;
}

export interface TextMerge {
  text: string;
  conflict: boolean;
  /** Rejected side's text of each conflicting region (empty when no conflict). */
  loserBlocks: string[];
}

/** Line 3-way on whole texts. Conflicting regions resolve to `preferOurs`'s
 *  side; the other side's blocks are returned, never dropped silently. */
export function mergeText(
  base: string | null,
  ours: string,
  theirs: string,
  preferOurs: boolean,
): TextMerge {
  if (ours === theirs) return { text: ours, conflict: false, loserBlocks: [] };
  if (base !== null && ours === base) return { text: theirs, conflict: false, loserBlocks: [] };
  if (base !== null && theirs === base) return { text: ours, conflict: false, loserBlocks: [] };
  const regions = merge3Lines(splitLines(base ?? ''), splitLines(ours), splitLines(theirs));
  const out: string[] = [];
  const loserBlocks: string[] = [];
  for (const r of regions) {
    if (r.kind === 'ok') out.push(...r.lines);
    else {
      out.push(...(preferOurs ? r.ours : r.theirs));
      loserBlocks.push(joinLines(preferOurs ? r.theirs : r.ours));
    }
  }
  return { text: joinLines(out), conflict: loserBlocks.length > 0, loserBlocks };
}
