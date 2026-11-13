import assert from 'node:assert/strict';
import test from 'node:test';
import {
  blockSchema,
  claimSchema,
  doneActionSchema,
  doneSchema,
  hookInputSchema,
  itemCreateSchema,
  itemFrontmatterSchema,
  itemIdSchema,
  itemPatchSchema,
  itemQuerySchema,
  repoConfigSchema,
  repoListSchema,
  reposFileSchema,
  searchQuerySchema,
  slugSchema,
  snowflakeIdSchema,
  titleSchema,
  replyCreateSchema,
} from './schema.ts';
import { TITLE_MAX } from './types.ts';

/* Characterization of the validation boundary. These assertions passed on
 * zod 3.25 and must keep passing on zod 4 — they pin what is accepted,
 * rejected, stripped and defaulted. */

const fm = {
  id: 'UL-1',
  title: 'a title',
  status: 'open',
  kind: 'BACKLOG',
  priority: 'P2',
  owner: 'agent',
  repo: 'ops',
  created: '2026-01-01T00:00:00Z',
  updated: '2026-01-01T00:00:00Z',
};

test('frontmatter: defaults are filled, unknown fields are stripped', () => {
  const r = itemFrontmatterSchema.safeParse({ ...fm, extra: 'x', claimed_by: { session: 's', since: 't', zzz: 1 } });
  assert.equal(r.success, true);
  assert.deepEqual(r.data, {
    ...fm,
    area: null,
    paths: [],
    blocks: [],
    blocked_by: [],
    requested_by: null,
    intake: null,
    aliases: [],
    claimed_by: { session: 's', since: 't' },
    source: { session: null, agent: null, commit: null },
    done: null,
  });
  assert.equal('extra' in (r.data as object), false);
});

test('frontmatter: partial source / done get inner defaults', () => {
  const r = itemFrontmatterSchema.safeParse({
    ...fm,
    source: { session: 's1' },
    done: { at: 't' },
  });
  assert.equal(r.success, true);
  assert.deepEqual((r.data as any).source, { session: 's1', agent: null, commit: null });
  assert.deepEqual((r.data as any).done, { commit: null, version: null, at: 't' });
});

test('frontmatter: null vs undefined', () => {
  for (const k of ['area', 'requested_by', 'intake', 'claimed_by', 'done'] as const) {
    assert.equal(itemFrontmatterSchema.safeParse({ ...fm, [k]: null }).success, true, `${k}=null`);
    assert.equal(itemFrontmatterSchema.safeParse({ ...fm, [k]: undefined }).success, true, `${k}=undefined`);
  }
  for (const k of ['paths', 'blocks', 'blocked_by', 'aliases'] as const) {
    assert.equal(itemFrontmatterSchema.safeParse({ ...fm, [k]: null }).success, false, `${k}=null`);
    assert.equal(itemFrontmatterSchema.safeParse({ ...fm, [k]: undefined }).success, true, `${k}=undefined`);
  }
  assert.equal(itemFrontmatterSchema.safeParse({ ...fm, source: null }).success, false);
  for (const k of Object.keys(fm)) {
    const { [k]: _, ...rest } = fm as Record<string, string>;
    assert.equal(itemFrontmatterSchema.safeParse(rest).success, false, `missing ${k}`);
    assert.equal(itemFrontmatterSchema.safeParse({ ...fm, [k]: null }).success, false, `${k}=null`);
  }
});

test('frontmatter: empty strings, bad ids, over-limit, enums', () => {
  const bad: Record<string, unknown>[] = [
    { id: '' }, { id: 'ul-1' }, { id: 'U-1' }, { id: 'ULTRA-1' }, { id: 'UL-' }, { id: 'UL-1\n' }, { id: ' UL-1' },
    { title: '' }, { title: 'x'.repeat(401) }, { title: 'a\nb' }, { title: 'a\u0000b' },
    { owner: '' }, { owner: 'x'.repeat(65) }, { repo: '' }, { repo: 'Ops' }, { repo: 'a_b' }, { repo: 'a b' },
    { status: 'nope' }, { kind: 'x' }, { priority: 'P9' }, { area: 'nope' },
    { created: '' }, { updated: '' },
    { blocks: ['x'] }, { blocked_by: ['UL-1', 'bad'] }, { requested_by: 'bad' },
    { intake: '0' }, { intake: '01' }, { intake: '1'.repeat(21) }, { intake: 'abc' }, { intake: 5 },
    { paths: [''] }, { paths: ['x'.repeat(301)] }, { aliases: [''] }, { aliases: ['x'.repeat(201)] },
    { claimed_by: { session: '', since: 't' } }, { claimed_by: { session: 's' } },
    { done: { at: '' } }, { done: { at: 't', version: 'has space' } }, { done: { at: 't', version: 'x'.repeat(65) } },
    { done: { at: 't', version: '' } }, { done: { at: 't', commit: 'x'.repeat(65) } },
    { source: { session: 'x'.repeat(65) } },
  ];
  for (const b of bad) {
    assert.equal(itemFrontmatterSchema.safeParse({ ...fm, ...b }).success, false, JSON.stringify(b));
  }
  const ok: Record<string, unknown>[] = [
    { title: 'x'.repeat(400) }, { intake: '1' }, { intake: '1'.repeat(20) }, { id: 'ABCD-123' },
    { done: { at: 't', version: 'v1.2.3' } }, { done: { at: 't', version: null } },
    { owner: 'x'.repeat(64) }, { paths: ['x'.repeat(300)] },
  ];
  for (const o of ok) {
    assert.equal(itemFrontmatterSchema.safeParse({ ...fm, ...o }).success, true, JSON.stringify(o));
  }
});

test('frontmatter: non-object input', () => {
  for (const v of [null, undefined, 'str', 5, [], true]) {
    assert.equal(itemFrontmatterSchema.safeParse(v).success, false);
  }
});

test('id regexes', () => {
  assert.equal(itemIdSchema.safeParse('UL-12').success, true);
  assert.equal(itemIdSchema.safeParse('UL-12\n').success, false);
  assert.equal(slugSchema.safeParse('a-b-1').success, true);
  assert.equal(slugSchema.safeParse('a\n').success, false);
  assert.equal(slugSchema.safeParse('').success, false);
  assert.equal(snowflakeIdSchema.safeParse('1234567890123456789').success, true);
  assert.equal(snowflakeIdSchema.safeParse('12345678901234567890').success, true);
  assert.equal(snowflakeIdSchema.safeParse('123456789012345678901').success, false);
  assert.equal(snowflakeIdSchema.safeParse(123).success, false);
});

test('title: TITLE_MAX and message text', () => {
  assert.equal(titleSchema.safeParse('x'.repeat(TITLE_MAX)).success, true);
  const r = titleSchema.safeParse('x'.repeat(TITLE_MAX + 1));
  assert.equal(r.success, false);
  assert.match(r.error!.issues[0]!.message, /title has at most/);
});

test('repoList: transform, dedupe, bounds', () => {
  assert.deepEqual(repoListSchema.parse('a, b,a,,'), ['a', 'b']);
  assert.equal(repoListSchema.safeParse(',,').success, false);
  assert.equal(repoListSchema.safeParse('A').success, false);
  assert.equal(repoListSchema.safeParse('x'.repeat(1001)).success, false);
  assert.equal(
    repoListSchema.safeParse(Array.from({ length: 51 }, (_, i) => `r${i}`).join(',')).success,
    false,
  );
  assert.equal(
    repoListSchema.safeParse(Array.from({ length: 50 }, (_, i) => `r${i}`).join(',')).success,
    true,
  );
});

test('doneSchema.version refine runs after default', () => {
  assert.equal(doneSchema.parse({ at: 't' }).version, null);
  assert.equal(doneSchema.safeParse({ at: 't', version: 'a b' }).success, false);
});

test('itemCreate: defaults, strip, boundaries', () => {
  const r = itemCreateSchema.parse({ repo: 'ops', title: 't', junk: 1 });
  assert.deepEqual(r, {
    repo: 'ops',
    title: 't',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
    force: false,
  });
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: 't', priority: null }).success, false);
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: 't', area: null }).success, true);
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: 't', why: 'x'.repeat(20_001) }).success, false);
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: 't', why: 'x'.repeat(20_000) }).success, true);
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: 't', steps: Array(51).fill('s') }).success, false);
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: 't', force: 'true' }).success, false);
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops', title: '' }).success, false);
  assert.equal(itemCreateSchema.safeParse({ repo: 'ops' }).success, false);
  assert.equal(itemCreateSchema.safeParse({}).success, false);
});

test('itemPatch: refine on empty / force-only, strip unknown', () => {
  assert.equal(itemPatchSchema.safeParse({}).success, false);
  assert.equal(itemPatchSchema.safeParse({ force: true }).success, false);
  assert.equal(itemPatchSchema.safeParse({ junk: 1 }).success, false);
  const r = itemPatchSchema.safeParse({ title: 'n', junk: 1 });
  assert.equal(r.success, true);
  assert.deepEqual(r.data, { title: 'n', force: false });
  // JSON bodies cannot carry `undefined`, so only the parsed-JSON shape is pinned.
  assert.equal(itemPatchSchema.safeParse(JSON.parse('{"junk":null}')).success, false);
  assert.equal(itemPatchSchema.safeParse(JSON.parse('{"title":null}')).success, false);
  assert.equal(itemPatchSchema.safeParse({ title: undefined, status: 'open' }).success, true);
});

test('claim / done / block / reply defaults and refines', () => {
  assert.deepEqual(claimSchema.parse({}), { session: 'manual', paths: [] });
  assert.equal(claimSchema.safeParse({ paths: Array(101).fill('p') }).success, false);
  assert.equal(doneActionSchema.safeParse({ ref: '' }).success, true);
  assert.equal(doneActionSchema.safeParse({ ref: 'a b' }).success, false);
  assert.equal(doneActionSchema.safeParse({ ref: 'v1.0' }).success, true);
  assert.equal(doneActionSchema.safeParse({}).success, true);
  assert.equal(blockSchema.safeParse({ by: 'UL-1' }).success, true);
  assert.equal(blockSchema.safeParse({ on: 'human' }).success, true);
  assert.equal(blockSchema.safeParse({}).success, false);
  assert.equal(blockSchema.safeParse({ by: 'UL-1', on: 'human' }).success, false);
  assert.equal(blockSchema.safeParse({ on: 'robot' }).success, false);
  assert.deepEqual(replyCreateSchema.parse({}), { text: '', mode: 'auto' });
  assert.equal(replyCreateSchema.safeParse({ text: 'x'.repeat(4001) }).success, false);
});

test('query schemas: coerce + defaults + enums', () => {
  assert.equal(searchQuerySchema.parse({ q: 'ab' }).limit, 40);
  assert.equal(searchQuerySchema.parse({ q: 'ab', limit: '5' }).limit, 5);
  assert.equal(searchQuerySchema.safeParse({ q: 'ab', limit: '0' }).success, false);
  assert.equal(searchQuerySchema.safeParse({ q: 'ab', limit: '201' }).success, false);
  assert.equal(searchQuerySchema.safeParse({ q: 'ab', limit: '1.5' }).success, false);
  assert.equal(searchQuerySchema.safeParse({ q: 'ab', limit: 'abc' }).success, false);
  assert.equal(searchQuerySchema.safeParse({ q: 'a' }).success, false);
  assert.equal(itemQuerySchema.safeParse({ open: 'yes' }).success, false);
  assert.equal(itemQuerySchema.safeParse({ open: 'true', repo: 'a,b' }).success, true);
  assert.deepEqual(itemQuerySchema.parse({ repo: 'a,b' }).repo, ['a', 'b']);
  assert.equal(itemQuerySchema.safeParse({ repo: undefined }).success, true);
});

test('hookInput: passthrough keeps unknown keys, record, optional', () => {
  const r = hookInputSchema.safeParse({
    session_id: 's',
    future_field: { a: 1 },
    tool_input: { a: 1 },
    tool_response: null,
  });
  assert.equal(r.success, true);
  assert.deepEqual(r.data, {
    session_id: 's',
    future_field: { a: 1 },
    tool_input: { a: 1 },
    tool_response: null,
  });
  assert.equal(hookInputSchema.safeParse({}).success, false);
  assert.equal(hookInputSchema.safeParse({ session_id: '' }).success, false);
  assert.equal(hookInputSchema.safeParse({ session_id: 's', tool_input: 'x' }).success, false);
  assert.equal(hookInputSchema.safeParse({ session_id: 's', tool_input: null }).success, false);
  assert.equal(hookInputSchema.safeParse({ session_id: 's', tool_input: [] }).success, false);
  assert.equal(hookInputSchema.safeParse({ session_id: 's', cwd: 'a\nb' }).success, false);
  assert.equal(hookInputSchema.safeParse({ session_id: 's', worker: 'true' }).success, false);
});

test('repos file: record keys validated by slug, config strip / optional', () => {
  const cfg = { prefix: 'UL', path: null, next: 1 };
  assert.equal(reposFileSchema.safeParse({ ops: cfg }).success, true);
  assert.equal(reposFileSchema.safeParse({ Ops: cfg }).success, false);
  assert.equal(reposFileSchema.safeParse({ ops: { ...cfg, prefix: 'u' } }).success, false);
  assert.equal(reposFileSchema.safeParse({}).success, true);
  assert.deepEqual(reposFileSchema.parse({ ops: { ...cfg, junk: 1 } }), { ops: cfg });
  assert.equal(repoConfigSchema.safeParse({ ...cfg, next: 0 }).success, false);
  assert.equal(repoConfigSchema.safeParse({ ...cfg, next: 1.5 }).success, false);
  assert.equal(repoConfigSchema.safeParse({ ...cfg, path: undefined }).success, false);
  assert.equal(repoConfigSchema.safeParse({ ...cfg, kind: 'vps', host: 'h.example' }).success, true);
  assert.equal(repoConfigSchema.safeParse({ ...cfg, host: 'bad host' }).success, false);
  assert.equal(repoConfigSchema.safeParse({ ...cfg, kind: 'other' }).success, false);
  assert.equal(repoConfigSchema.safeParse({ ...cfg, prefix_aliases: Array(11).fill('AB') }).success, false);
  assert.equal(repoConfigSchema.safeParse({ ...cfg, contracts: Array(41).fill('a') }).success, false);
});

/* Error shape the HTTP layer relies on: issues[0].path + message. */
test('issues: path + message are present for the 422 body', () => {
  const r = itemCreateSchema.safeParse({ repo: 'Bad', title: 't' });
  assert.equal(r.success, false);
  assert.deepEqual(r.error!.issues[0]!.path, ['repo']);
  assert.equal(r.error!.issues[0]!.message, 'slug must be [a-z0-9-]+');
  const e = itemPatchSchema.safeParse({});
  assert.deepEqual(e.error!.issues[0]!.path, []);
  assert.equal(e.error!.issues[0]!.message, 'empty PATCH');
  const n = itemCreateSchema.safeParse({ repo: 'ops', title: 'a\nb' });
  assert.equal(n.error!.issues[0]!.message, 'must not contain a newline or control character');
});
