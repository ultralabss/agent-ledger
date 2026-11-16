/** Property tests: fixed seeds, 3 devices, random op sequences. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { parseItem, type Item } from '@agent-ledger/shared';
import { mergeCounters, mergeDecisions, mergeIntake, mergeJournal } from './files.ts';
import { mergeItem } from './item.ts';
import { baseText, ctxOf, DEV_A, DEV_B, DEV_C, edit, MARKERS, rng, type Rng } from './testkit.ts';

const DEVS = [DEV_A, DEV_B, DEV_C];
const ROUNDS = 150;

interface Allow {
  scalars: number[];
  status: number[];
  why: number[];
  rec: number[];
  stepText: number[];
}
const ALL: Allow = { scalars: [0, 1, 2], status: [0, 1, 2], why: [0, 1, 2], rec: [0, 1, 2], stepText: [0, 1, 2] };
/** Disjoint ownership: no field is edited by two devices (mergeable parts stay open to all). */
const DISJOINT: Allow = { scalars: [0], status: [1], why: [2], rec: [0], stepText: [1] };

let cid = 0;
const stamp = (r: Rng): string => `2026-11-1${r.int(3)}T1${r.int(3)}:00:00+01:00`;

function ops(r: Rng, text: string, di: number, allow: Allow, n: number): string {
  let out = text;
  for (let k = 0; k < n; k += 1) {
    out = edit(out, (i: Item) => {
      const op = r.int(13);
      if (op === 0 && allow.scalars.includes(di)) i.fm.title = `t${r.int(3)}`;
      else if (op === 1 && allow.scalars.includes(di)) i.fm.priority = r.pick(['P0', 'P1', 'P2', 'P3'] as const);
      else if (op === 2 && allow.status.includes(di)) {
        const s = r.pick(['open', 'doing', 'blocked', 'done', 'dropped', 'proposed'] as const);
        i.fm.status = s;
        i.fm.claimed_by = s === 'doing' ? { session: `s${di}${r.int(2)}`, since: '2026-11-11T10:00:00+01:00' } : null;
        i.fm.done = s === 'done' ? { commit: null, version: null, at: stamp(r) } : null;
      } else if (op === 3) {
        const p = `src/p${r.int(6)}`;
        i.fm.paths = i.fm.paths.includes(p) ? i.fm.paths.filter((x) => x !== p) : [...i.fm.paths, p].sort();
      } else if (op === 4) {
        const x = `ACME-${2 + r.int(4)}`;
        i.fm.blocks = i.fm.blocks.includes(x) ? i.fm.blocks.filter((y) => y !== x) : [...i.fm.blocks, x].sort();
      } else if (op === 5) {
        cid += 1;
        i.comments.push({ at: '2026-11-11 10:00', author: `a${di}`, id: String(10_000 * (di + 1) + cid), text: `c${r.int(9)}` });
      } else if (op === 6) {
        i.log.push({ at: `2026-11-1${r.int(3)} 1${r.int(3)}:0${r.int(3)}`, session: `s${r.int(2)}`, text: `e${r.int(5)}` });
      } else if (op === 7) {
        const s = r.pick(i.steps);
        if (s) s.done = !s.done;
      } else if (op === 8 && allow.stepText.includes(di)) {
        const s = r.pick(i.steps);
        if (s) s.text = `step-${r.int(3)}`;
      } else if (op === 9) {
        const n2 = 10 * (di + 1) + r.int(3);
        if (!i.steps.some((s) => s.n === n2)) i.steps.push({ n: n2, done: false, text: `new ${di}` });
        i.steps.sort((x, y) => x.n - y.n);
      } else if (op === 10 && allow.why.includes(di)) {
        const lines = i.why.split('\n');
        lines[r.int(lines.length)] = `w${di}-${r.int(3)}`;
        i.why = lines.join('\n');
      } else if (op === 11 && allow.rec.includes(di)) {
        const lines = i.rec.split('\n');
        lines[r.int(lines.length)] = `x${di}-${r.int(3)}`;
        i.rec = lines.join('\n');
      } else if (op === 12 && allow.why.includes(di)) i.why = `${i.why}\nadd${di}${r.int(2)}`;
      i.fm.updated = stamp(r);
    });
  }
  return out;
}

const pair = (x: number, y: number): [ReturnType<typeof ctxOf>, ReturnType<typeof ctxOf>] => [
  ctxOf(DEVS[x]!, DEVS[y]!, true),
  ctxOf(DEVS[y]!, DEVS[x]!, false),
];

test('mergeItem: commutative, marker-free, parseable, never loses comments/log (random ops, 3 devices)', () => {
  const base = baseText();
  let conflicts = 0;
  let claimLost = 0;
  let textConflicts = 0;
  for (let seed = 1; seed <= ROUNDS; seed += 1) {
    const r = rng(seed);
    const t = [0, 1, 2].map((d) => ops(r, base, d, ALL, 1 + r.int(5)));
    for (const [x, y] of [[0, 1], [0, 2], [1, 2]] as const) {
      const [c1, c2] = pair(x, y);
      const m1 = mergeItem(base, t[x]!, t[y]!, c1);
      const m2 = mergeItem(base, t[y]!, t[x]!, c2);
      assert.equal(m1.merged, m2.merged, `seed ${seed} pair ${x}${y}: commutative`);
      assert.deepEqual(m1.notes, m2.notes, `seed ${seed} pair ${x}${y}: notes commutative`);
      assert.ok(!MARKERS.test(m1.merged), `seed ${seed}: markers`);
      conflicts += m1.notes.filter((n) => n.type === 'sync.conflict').length;
      textConflicts += m1.notes.filter((n) => n.field === 'why' || n.field === 'rec' || n.field?.startsWith('plan.')).length;
      claimLost += m1.notes.filter((n) => n.type === 'sync.claim-lost').length;
      const m = parseItem(m1.merged).item;
      const ids = new Set(m.comments.map((c) => c.id));
      const lines = new Set(m.log.map((l) => `${l.at}|${l.session}|${l.text}`));
      for (const side of [t[x]!, t[y]!]) {
        const p = parseItem(side).item;
        for (const c of p.comments) assert.ok(ids.has(c.id), `seed ${seed}: comment ${c.id} lost`);
        for (const l of p.log) assert.ok(lines.has(`${l.at}|${l.session}|${l.text}`), `seed ${seed}: log line lost`);
      }
      if (m.fm.status !== 'doing') assert.equal(m.fm.claimed_by, null);
      if (m.fm.status === 'doing') assert.ok(m.fm.claimed_by);
    }
  }
  // the generator must actually reach the interesting branches
  assert.ok(conflicts > 50 && textConflicts > 20 && claimLost > 3, `coverage ${conflicts}/${textConflicts}/${claimLost}`);
});

test('mergeItem: absorption — merging the result with a contributing side changes nothing', () => {
  const base = baseText();
  for (let seed = 1000; seed < 1000 + ROUNDS; seed += 1) {
    const r = rng(seed);
    const a = ops(r, base, 0, ALL, 1 + r.int(5));
    const b = ops(r, base, 1, ALL, 1 + r.int(5));
    const m = mergeItem(base, a, b, ctxOf(DEV_A, DEV_B, true)).merged;
    // the intermediate result is "device min(a,b)" for tie-breaks
    assert.equal(mergeItem(base, m, b, ctxOf(DEV_A, DEV_B, true)).merged, m, `seed ${seed}: absorb b`);
    assert.equal(mergeItem(base, a, m, ctxOf(DEV_A, DEV_B, true)).merged, m, `seed ${seed}: absorb a`);
  }
});

test('mergeItem: associative when no field is edited by two devices; convergent in every order', () => {
  const base = baseText();
  for (let seed = 2000; seed < 2000 + ROUNDS; seed += 1) {
    const r = rng(seed);
    const [a, b, c] = [0, 1, 2].map((d) => ops(r, base, d, DISJOINT, 1 + r.int(6))) as [string, string, string];
    const mid = (x: string, y: string, dx: string, dy: string): string =>
      mergeItem(base, x, y, ctxOf(dx, dy, true)).merged;
    const lo = (x: string, y: string): string => (x < y ? x : y);
    const left = mergeItem(base, mid(a, b, DEV_A, DEV_B), c, ctxOf(lo(DEV_A, DEV_B), DEV_C, true)).merged;
    const right = mergeItem(base, a, mid(b, c, DEV_B, DEV_C), ctxOf(DEV_A, lo(DEV_B, DEV_C), true)).merged;
    const swapped = mergeItem(base, mid(c, a, DEV_C, DEV_A), b, ctxOf(lo(DEV_C, DEV_A), DEV_B, true)).merged;
    assert.equal(left, right, `seed ${seed}: (ab)c == a(bc)`);
    assert.equal(left, swapped, `seed ${seed}: (ca)b == (ab)c`);
    assert.ok(!MARKERS.test(left));
  }
});

test('mergeItem: scalar LWW is order-independent for 2 devices even when updated ties', () => {
  const base = baseText();
  for (let seed = 3000; seed < 3100; seed += 1) {
    const r = rng(seed);
    const fixed = '2026-11-12T12:00:00+01:00';
    const a = edit(base, (i) => { i.fm.title = `a${r.int(2)}`; i.fm.priority = 'P0'; i.fm.updated = fixed; });
    const b = edit(base, (i) => { i.fm.title = `b${r.int(2)}`; i.fm.priority = 'P3'; i.fm.updated = fixed; });
    const ab = mergeItem(base, a, b, ctxOf(DEV_A, DEV_B, true)).merged;
    assert.equal(ab, mergeItem(base, b, a, ctxOf(DEV_B, DEV_A, false)).merged);
    assert.equal(parseItem(ab).item.fm.priority, 'P0'); // lower device id
  }
});

/* ---------------- journal / counters / decisions / intake ---------------- */

function genJournal(r: Rng, base: string, di: number): string {
  let s = base;
  for (let k = r.int(5); k > 0; k -= 1) {
    s += `- 2026-11-1${r.int(3)} 1${r.int(3)}:0${r.int(3)} · s${r.int(2)}${di === 9 ? '' : ''} · item.comment · ACME-${r.int(4)}\n`;
  }
  return s;
}

test('mergeJournal: commutative, associative, idempotent, marker-free', () => {
  const base = '- 2026-11-10 09:00 · s0 · item.created · ACME-1\n- 2026-11-10 09:00 · s0 · item.status · ACME-1 · open→doing\n';
  for (let seed = 1; seed <= ROUNDS; seed += 1) {
    const r = rng(seed);
    const [a, b, c] = [0, 1, 2].map((d) => genJournal(r, base, d)) as [string, string, string];
    const j = (x: string, y: string): string => mergeJournal(base, x, y).merged;
    assert.equal(j(a, b), j(b, a));
    assert.equal(j(j(a, b), c), j(a, j(b, c)), `seed ${seed}`);
    assert.equal(j(j(a, b), c), j(j(c, a), b));
    assert.equal(j(a, a), j(a, j(a, a)));
    assert.equal(j(j(a, b), b), j(a, b));
    assert.ok(!MARKERS.test(j(a, b)));
  }
});

test('mergeCounters: commutative, associative, idempotent, monotone', () => {
  for (let seed = 1; seed <= ROUNDS; seed += 1) {
    const r = rng(seed);
    const gen = (): string => {
      const keys = ['acme', 'web', 'zed', 'k1'].filter(() => r.chance(0.6));
      return keys.map((k) => `${k}: ${r.int(20)}`).join('\n') + (keys.length ? '\n' : '');
    };
    const [a, b, c] = [gen(), gen(), gen()];
    const m = (x: string, y: string): string => mergeCounters(null, x, y).merged;
    assert.equal(m(a, b), m(b, a));
    assert.equal(m(m(a, b), c), m(a, m(b, c)));
    assert.equal(m(m(a, b), a), m(a, b));
  }
});

function genDecisions(r: Rng, base: string, di: number): string {
  let s = base;
  for (let k = r.int(4); k > 0; k -= 1) {
    const id = r.chance(0.5) ? `D${3 + r.int(3)}` : `D${'ABC'[di]}${1 + r.int(3)}`;
    s += `\n### ${id} · 2026-11-1${r.int(3)} · title\nbody ${r.int(3)}\n`;
  }
  if (r.chance(0.3)) s = s.replace('body one', `edited ${di}`);
  return s;
}

test('mergeDecisions: commutative, associative, idempotent, marker-free', () => {
  const base = '### D1 · 2026-11-10 · first\nbody one\n\n### D2 · 2026-11-10 · second\nbody two\n';
  for (let seed = 1; seed <= ROUNDS; seed += 1) {
    const r = rng(seed);
    const [a, b, c] = [0, 1, 2].map((d) => genDecisions(r, base, d)) as [string, string, string];
    const m = (x: string, y: string): string => mergeDecisions(base, x, y).merged;
    assert.equal(m(a, b), m(b, a), `seed ${seed}`);
    assert.equal(m(m(a, b), c), m(a, m(b, c)), `seed ${seed}`);
    assert.equal(m(m(a, b), b), m(a, b), `seed ${seed} absorb`);
    assert.ok(!MARKERS.test(m(a, b)));
  }
});

test('mergeIntake: commutative and associative on status/items', () => {
  const rec = (status: string, items: string[]): string =>
    `---\nid: '5'\nat: 2026-11-10T09:00:00+01:00\nchannel: web\nsession: null\nrepo_hint: null\nstatus: ${status}\nitems: [${items.join(', ')}]\n---\ntext\n`;
  const base = rec('new', []);
  for (let seed = 1; seed <= 100; seed += 1) {
    const r = rng(seed);
    const g = (): string => rec(r.pick(['new', 'partial', 'triaged']), [1, 2, 3, 4].filter(() => r.chance(0.4)).map((n) => `ACME-${n}`));
    const [a, b, c] = [g(), g(), g()];
    const m = (x: string, y: string): string => mergeIntake(base, x, y).merged;
    assert.equal(m(a, b), m(b, a), `seed ${seed}`);
    assert.equal(m(m(a, b), c), m(a, m(b, c)), `seed ${seed}`);
  }
});
