import assert from 'node:assert/strict';
import test from 'node:test';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { mergeRepos } from './repos.ts';
import { rng } from './testkit.ts';

const SHA1 = 'a'.repeat(40);
const SHA2 = 'b'.repeat(40);
const y = (o: Record<string, unknown>): string => stringifyYaml(o, { lineWidth: 0 });
const load = (t: string): Record<string, Record<string, unknown>> => parseYaml(t) as never;

function both(base: string | null, a: string, b: string) {
  const ab = mergeRepos(base, a, b);
  const ba = mergeRepos(base, b, a);
  assert.equal(ab.merged, ba.merged, 'side independent bytes');
  assert.deepEqual(ab.notes, ba.notes, 'side independent notes');
  return ab;
}

test('disjoint additions: union, slugs sorted, no notes', () => {
  const base = y({ acme: { prefix: 'ACME' } });
  const a = y({ acme: { prefix: 'ACME' }, zed: { prefix: 'ZED' } });
  const b = y({ acme: { prefix: 'ACME' }, beta: { prefix: 'BETA' } });
  const r = both(base, a, b);
  assert.deepEqual(Object.keys(load(r.merged)), ['acme', 'beta', 'zed']);
  assert.equal(r.notes.length, 0);
});

test('never deletes a repo; fields 3-way; lists as sets; aliases union; onboarded OR', () => {
  const base = y({ acme: { prefix: 'ACME', docs: ['a.md'], onboarded: false }, gone: { prefix: 'GONE' } });
  const a = y({ acme: { prefix: 'ACME', docs: ['a.md', 'b.md'], onboarded: true, kind: 'system' } });
  const b = y({ acme: { prefix: 'ACME', docs: ['a.md', 'c.md'], prefix_aliases: ['OLD'] }, gone: { prefix: 'GONE' } });
  const r = both(base, a, b);
  const m = load(r.merged);
  assert.ok(m.gone, 'repo deleted on one side survives');
  assert.deepEqual(m.acme?.docs, ['a.md', 'b.md', 'c.md']);
  assert.equal(m.acme?.onboarded, true);
  assert.equal(m.acme?.kind, 'system');
  assert.deepEqual(m.acme?.prefix_aliases, ['OLD']);
});

test('prefix collision (two slugs add the same prefix): lowest slug keeps it, loser gets a fresh deterministic one + note', () => {
  const base = y({});
  const a = y({ foo: { prefix: 'FOO' } });
  const b = y({ foobar: { prefix: 'FOO' } });
  const r = both(base, a, b);
  const m = load(r.merged);
  assert.equal(m.foo?.prefix, 'FOO');
  assert.notEqual(m.foobar?.prefix, 'FOO');
  assert.match(String(m.foobar?.prefix), /^[A-Z]{2,4}$/);
  assert.equal(r.notes.length, 1);
  assert.equal(r.notes[0]?.type, 'sync.conflict');
  assert.equal(r.notes[0]?.repo, 'foobar');
});

test('fresh prefix never collides with an existing prefix or alias', () => {
  const a = y({ aaa: { prefix: 'AB' }, abcd: { prefix: 'AB' }, other: { prefix: 'ABCD', prefix_aliases: ['ABC'] } });
  const r = mergeRepos(null, a, y({}));
  const m = load(r.merged);
  const all = Object.values(m).flatMap((e) => [e.prefix as string, ...((e.prefix_aliases as string[] | undefined) ?? [])]);
  assert.equal(new Set(all).size, all.length, `unique: ${all.join(',')}`);
});

test('alias clash with a foreign primary or alias is dropped; own primary repeated as alias is dropped silently', () => {
  const a = y({
    aa: { prefix: 'AAA', prefix_aliases: ['AAA', 'SHR', 'BBB'] },
    bb: { prefix: 'BBB', prefix_aliases: ['SHR'] },
  });
  const r = mergeRepos(null, a, y({ aa: { prefix: 'AAA' } }));
  const m = load(r.merged);
  assert.deepEqual(m.aa?.prefix_aliases, ['SHR']); // BBB is bb's primary, AAA is aa's own
  assert.equal(m.bb?.prefix_aliases, undefined, 'lowest slug (aa) owns SHR');
  assert.equal(r.notes.filter((n) => n.rule === 'repos-alias').length, 2);
});

test('root_sha uniqueness: lowest slug keeps identity, loser loses it + note', () => {
  const id = (sha: string) => ({ root_sha: sha, origin_hint: null });
  const a = y({ one: { prefix: 'ONE', identity: id(SHA1) }, two: { prefix: 'TWO', identity: id(SHA1) }, three: { prefix: 'TRE', identity: id(SHA2) } });
  const r = mergeRepos(null, a, y({ one: { prefix: 'ONE', identity: id(SHA1) } }));
  const m = load(r.merged);
  assert.ok(m.one?.identity);
  assert.equal(m.two?.identity, undefined);
  assert.ok(m.three?.identity);
  assert.equal(r.notes.filter((n) => n.rule === 'repos-root').length, 1);
});

test('same field changed differently on both sides: canonical smaller kept, conflict note, side independent', () => {
  const base = y({ acme: { prefix: 'ACME', kind: 'repo' } });
  const a = y({ acme: { prefix: 'ACME', kind: 'system' } });
  const b = y({ acme: { prefix: 'ACME', kind: 'vps' } });
  const r = both(base, a, b);
  assert.equal(load(r.merged).acme?.kind, 'system');
  assert.equal(r.notes.length, 1);
});

test('hostile / invalid input throws (caller quarantines); never returns markers', () => {
  const good = y({ a: { prefix: 'AA' } });
  for (const bad of ['{{{', 'a: 5', y({ a: { prefix: 'lower' } }), y({ 'BAD SLUG': { prefix: 'AA' } }), 'a: &x {prefix: AA}\nb: *x\n']) {
    assert.throws(() => mergeRepos(good, bad, good));
    assert.throws(() => mergeRepos(good, good, bad));
  }
});

test('determinism: random registries merged in both orders, idempotent, always unique', () => {
  const r = rng(11);
  const slugs = ['alpha', 'beta', 'gamma', 'delta', 'omega'];
  const prefixes = ['AL', 'BE', 'GA', 'DE', 'OM', 'AB'];
  for (let n = 0; n < 60; n += 1) {
    const mk = (): string => {
      const o: Record<string, unknown> = {};
      for (const s of slugs) {
        if (!r.chance(0.6)) continue;
        o[s] = {
          prefix: r.pick(prefixes),
          ...(r.chance(0.4) ? { prefix_aliases: [r.pick(prefixes)] } : {}),
          ...(r.chance(0.4) ? { identity: { root_sha: r.pick([SHA1, SHA2]), origin_hint: null } } : {}),
        };
      }
      return y(o);
    };
    const a = mk();
    const b = mk();
    if (a === b) continue;
    const ab = mergeRepos(null, a, b);
    const ba = mergeRepos(null, b, a);
    assert.equal(ab.merged, ba.merged);
    const m = load(ab.merged);
    const all = Object.values(m).flatMap((e) => [e.prefix as string, ...((e.prefix_aliases as string[] | undefined) ?? [])]);
    assert.equal(new Set(all).size, all.length, 'prefixes/aliases unique');
    const roots = Object.values(m).flatMap((e) => ((e.identity as { root_sha: string } | undefined) ? [(e.identity as { root_sha: string }).root_sha] : []));
    assert.equal(new Set(roots).size, roots.length, 'root_sha unique');
    assert.equal(mergeRepos(null, ab.merged, ab.merged).merged, ab.merged, 'idempotent');
  }
});
