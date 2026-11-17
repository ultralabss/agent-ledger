import assert from 'node:assert/strict';
import test from 'node:test';
import { parseItem } from '@agent-ledger/shared';
import { stringify as stringifyYaml } from 'yaml';
import { mergeTrees, type BlobMap } from './tree.ts';
import { baseText, ctxOf, DEV_A, DEV_B, edit, MARKERS, rng } from './testkit.ts';

const ITEM = 'acme/items/ACME-1.md';
const T1 = '2026-11-10T10:00:00+01:00';
const CA = ctxOf(DEV_A, DEV_B);
const CB = ctxOf(DEV_B, DEV_A, false);

const tree = (o: Record<string, string>): BlobMap => new Map(Object.entries(o));
const FIXED = { 'ledger.format': '2\n', '.gitignore': '.hub/\n*.tmp\n' };

function merge(base: Record<string, string> | null, a: Record<string, string>, b: Record<string, string>) {
  return mergeTrees({ base: base === null ? null : tree(base), ours: tree(a), theirs: tree(b), ctx: CA });
}
function must(r: ReturnType<typeof merge>) {
  assert.ok(r.ok, r.ok ? '' : JSON.stringify(r.quarantine));
  return r;
}

test('items: both sides edit -> merged item, no markers; notes tagged with repo + path', () => {
  const a = edit(baseText(), (i) => { i.fm.title = 'A'; i.fm.updated = T1; });
  const b = edit(baseText(), (i) => { i.fm.title = 'B'; i.fm.updated = '2026-11-10T11:00:00+01:00'; });
  const r = must(merge({ [ITEM]: baseText() }, { [ITEM]: a }, { [ITEM]: b }));
  const text = r.blobs.get(ITEM) as string;
  assert.ok(!MARKERS.test(text));
  assert.equal(parseItem(text).item.fm.title, 'B');
  assert.ok(r.notes.length > 0);
  for (const n of r.notes) {
    assert.equal(n.repo, 'acme');
    assert.equal(n.path, ITEM);
  }
  assert.deepEqual(r.changed, [ITEM]);
});

test('item delete on either side is soft-reverted: item kept, sync.reject note names the deleter', () => {
  const base = { [ITEM]: baseText() };
  const edited = edit(baseText(), (i) => { i.fm.title = 'kept edit'; i.fm.updated = T1; });
  // theirs deleted, ours edited
  let r = must(merge(base, { [ITEM]: edited }, {}));
  assert.equal(parseItem(r.blobs.get(ITEM) as string).item.fm.title, 'kept edit');
  assert.deepEqual(r.notes.map((n) => [n.type, n.rule, n.device, n.item]), [['sync.reject', 'delete', DEV_B, 'ACME-1']]);
  // ours deleted, theirs untouched
  r = must(merge(base, {}, base));
  assert.equal(r.blobs.get(ITEM), baseText());
  assert.equal(r.notes[0]?.device, DEV_A);
  // swapped sides + swapped ctx: identical outcome
  const sw = must(mergeTrees({ base: tree(base), ours: tree(base), theirs: tree({}), ctx: CB }));
  assert.equal(sw.blobs.get(ITEM), baseText());
  assert.equal(sw.notes[0]?.device, DEV_A, 'deleter is theirs here = ctx.theirDevice = DEV_A');
});

test('delete of any non-item file is a quarantine, not a merge', () => {
  const base = { ...FIXED, 'devices.yml': 'devices: []\n' };
  const r = merge(base, base, { ...FIXED });
  assert.equal(r.ok, false);
  const r2 = merge({ ...FIXED, 'repos.yml': '{}\n' }, { ...FIXED, 'repos.yml': '{}\n' }, { ...FIXED });
  assert.equal(r2.ok, false);
  if (!r2.ok) assert.equal(r2.quarantine[0]?.rule, 'delete-protected');
});

test('addition on one side is taken; identical additions collapse', () => {
  const r = must(merge({}, { [ITEM]: baseText() }, { 'acme/CONTEXT.md': 'ctx\n' }));
  assert.deepEqual([...r.blobs.keys()], ['acme/CONTEXT.md', ITEM]);
  assert.deepEqual(r.changed, ['acme/CONTEXT.md']);
  const same = must(merge({}, { [ITEM]: baseText() }, { [ITEM]: baseText() }));
  assert.equal(same.blobs.get(ITEM), baseText());
});

test('merger throw becomes a quarantine (AL-36): bad counters, garbage item, bad format', () => {
  const ctr = 'counters/d_aaaaaaaaaa.yml';
  const bad = merge({ [ctr]: 'acme: 1\n' }, { [ctr]: 'acme: 2\n' }, { [ctr]: 'acme: -5\n' });
  assert.equal(bad.ok, false);
  if (!bad.ok) assert.equal(bad.quarantine[0]?.rule, 'merge-error');
  const item = merge({ [ITEM]: baseText() }, { [ITEM]: '\u0000garbage' }, { [ITEM]: edit(baseText(), (i) => { i.fm.title = 'x'; }) });
  assert.equal(item.ok, false);
  const fmt = merge({ 'ledger.format': '2\n' }, { 'ledger.format': '3\n' }, { 'ledger.format': 'x\n' });
  assert.equal(fmt.ok, false);
});

test('a Map that throws on access cannot escape: internal quarantine', () => {
  class Evil extends Map<string, string> {
    override get(): string | undefined {
      throw new Error('boom');
    }
  }
  const r = mergeTrees({ base: null, ours: new Evil([['a', 'b']]), theirs: tree({ a: 'c' }), ctx: CA });
  assert.equal(r.ok, false);
});

test('counters: per-key max; journal union; format monotonic; decisions union', () => {
  const ctr = 'counters/d_aaaaaaaaaa.yml';
  const j = 'acme/journal/2026-11.md';
  const r = must(
    merge(
      { [ctr]: 'acme: 1\n', [j]: '- 2026-11-10 09:00 · s · item.created · ACME-1\n', 'ledger.format': '2\n' },
      { [ctr]: 'acme: 5\n', [j]: '- 2026-11-10 09:00 · s · item.created · ACME-1\n- 2026-11-10 09:10 · a · item.comment · ACME-1\n', 'ledger.format': '3\n' },
      { [ctr]: 'acme: 3\nbeta: 2\n', [j]: '- 2026-11-10 09:00 · s · item.created · ACME-1\n- 2026-11-10 09:05 · b · item.comment · ACME-1\n', 'ledger.format': '2\n' },
    ),
  );
  assert.equal(r.blobs.get(ctr), stringifyYaml({ acme: 5, beta: 2 }, { lineWidth: 0 }));
  assert.equal((r.blobs.get(j) as string).trim().split('\n').length, 3);
  assert.equal(r.blobs.get('ledger.format'), '3\n');
});

test('CONTEXT.md conflict: local kept, other version surfaces as a proposed item with the repo', () => {
  const p = 'acme/CONTEXT.md';
  const r = must(merge({ [p]: 'a\nb\nc\n' }, { [p]: 'a\nOURS\nc\n' }, { [p]: 'a\nTHEIRS\nc\n' }));
  assert.ok((r.blobs.get(p) as string).includes('OURS'));
  assert.equal(r.proposed.length, 1);
  assert.equal(r.proposed[0]?.repo, 'acme');
  assert.ok(r.notes.some((n) => n.type === 'sync.context-conflict' && n.repo === 'acme'));
});

test('devices.yml clash -> quarantine; repos.yml prefix clash -> merged + note (no quarantine)', () => {
  const dev = merge({ 'devices.yml': 'devices: []\n' }, { 'devices.yml': '{{{' }, { 'devices.yml': 'devices: []\n' });
  assert.equal(dev.ok, false);
  const base = { 'repos.yml': stringifyYaml({}, { lineWidth: 0 }) };
  const r = must(
    merge(
      base,
      { 'repos.yml': stringifyYaml({ foo: { prefix: 'FOO' } }, { lineWidth: 0 }) },
      { 'repos.yml': stringifyYaml({ foobar: { prefix: 'FOO' } }, { lineWidth: 0 }) },
    ),
  );
  assert.ok(r.notes.some((n) => n.rule === 'repos-prefix'));
});

test('devices.yml / repos.yml are never taken verbatim from one side without validation', () => {
  const good = 'devices: []\n';
  const r = merge({ 'devices.yml': good }, { 'devices.yml': good }, { 'devices.yml': 'devices: 5\n' });
  assert.equal(r.ok, false);
  const rr = merge({ 'repos.yml': '{}\n' }, { 'repos.yml': '{}\n' }, { 'repos.yml': 'x: {prefix: lower}\n' });
  assert.equal(rr.ok, false);
});

test('unclassified path: changed on both sides = quarantine; same on both sides or one side = kept', () => {
  assert.equal(merge({ 'x.bin': '1' }, { 'x.bin': '2' }, { 'x.bin': '3' }).ok, false);
  assert.equal(must(merge({ 'x.bin': '1' }, { 'x.bin': '2' }, { 'x.bin': '2' })).blobs.get('x.bin'), '2');
  assert.equal(must(merge({ 'x.bin': '1' }, { 'x.bin': '1' }, { 'x.bin': '3' })).blobs.get('x.bin'), '3');
});

test('pinned file diverging on both sides -> quarantine', () => {
  const r = merge({ '.gitignore': '.hub/\n' }, { '.gitignore': 'a\n' }, { '.gitignore': 'b\n' });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.quarantine[0]?.rule, 'pinned');
});

test('quarantine output is sanitised (hostile path names)', () => {
  const evil = 'a\u001b[31m‮\nb';
  const r = merge({ [evil]: '1' }, { [evil]: '2' }, { [evil]: '3' });
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.ok(!/[\u0000-\u001f‮]/.test(r.quarantine[0]?.path ?? ''));
  }
});

test('determinism: shuffled insertion order and swapped sides give identical bytes + notes', () => {
  const r = rng(3);
  for (let n = 0; n < 30; n += 1) {
    const ia = edit(baseText(), (i) => { if (r.chance(0.7)) i.fm.title = `T${r.int(3)}`; if (r.chance(0.5)) i.fm.priority = r.pick(['P0', 'P1', 'P2'] as const); i.fm.updated = `2026-11-10T1${r.int(3)}:00:00+01:00`; });
    const ib = edit(baseText(), (i) => { if (r.chance(0.7)) i.fm.title = `T${r.int(3)}`; if (r.chance(0.5)) i.fm.priority = r.pick(['P0', 'P1', 'P2'] as const); i.fm.updated = `2026-11-10T1${r.int(3)}:00:00+01:00`; });
    const base: Record<string, string> = { [ITEM]: baseText(), 'counters/d_aaaaaaaaaa.yml': 'acme: 1\n', 'acme/DECISIONS.md': '' };
    const sideA: Record<string, string> = { [ITEM]: ia, 'counters/d_aaaaaaaaaa.yml': `acme: ${1 + r.int(4)}\n`, 'acme/DECISIONS.md': '' };
    const sideB: Record<string, string> = { [ITEM]: ib, 'counters/d_aaaaaaaaaa.yml': `acme: ${1 + r.int(4)}\n`, 'acme/DECISIONS.md': '' };
    const shuffled = (o: Record<string, string>): BlobMap => new Map(Object.entries(o).sort(() => r.next() - 0.5));
    const x = mergeTrees({ base: shuffled(base), ours: shuffled(sideA), theirs: shuffled(sideB), ctx: CA });
    const y = mergeTrees({ base: shuffled(base), ours: shuffled(sideB), theirs: shuffled(sideA), ctx: CB });
    assert.ok(x.ok && y.ok);
    if (x.ok && y.ok) {
      assert.deepEqual([...x.blobs.entries()], [...y.blobs.entries()]);
      assert.deepEqual(x.notes, y.notes);
    }
  }
});
