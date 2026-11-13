/**
 * "Related:" on every message, with paths.
 *
 * Every test is also a budget test: it pins that the feed stays silent for the
 * common case, that a ref is shown once, that a session cannot spend more than
 * its share, and that the path segment tells the truth about moved files. With
 * `LEDGER_MEASURE=1` the lines are printed — the before/after sample in the
 * ledger log comes from there.
 */

import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import {
  cleanRelPath,
  isNoisePath,
  MAX_COMMIT_FILES,
  mergePaths,
  recordCommitFiles,
} from './related-paths.ts';
import { relatedLines, SESSION_MAX_CHARS, SESSION_MAX_HITS } from './related.ts';
import {
  BM25_MAX,
  LATER_BM25_MAX,
  LATER_MIN_OVERLAP,
  MIN_OVERLAP,
  contentTokens,
  relevance,
} from './relevance.ts';
import { makeCommittedRepo, startTestHub, type HubFixture } from './test-helpers.ts';

const MEASURE = process.env.LEDGER_MEASURE === '1';
function note(label: string, text: string): void {
  if (MEASURE) process.stdout.write(`MEASURE ${label} (${text.length} chars):\n${text}\n`);
}

type Api = HubFixture['api'];

/** Distinct, realistic topics — each with vocabulary no other topic shares. */
const TOPICS: { title: string; why: string; prompt: string }[] = [
  {
    title: 'OAuth refresh token rotation on every refresh',
    why: 'rotate the token and detect reuse, on reuse revoke the whole token family',
    prompt: 'oauth refresh token rotation, reuse detection and revoking the token family',
  },
  {
    title: 'Billing wallet migration to credits',
    why: 'expand contract migration of wallet columns, reversible down step',
    prompt: 'billing wallet migration to credits, expand contract and reversible down',
  },
  {
    title: 'Offline profile cache in the Expo app',
    why: 'persist the profile to SQLite, invalidate the cache after sign-in',
    prompt: 'offline profile cache in expo, sqlite persistence and invalidation after sign-in',
  },
  {
    title: 'Payment webhook idempotency',
    why: 'body hash and idempotency key for thirty days, ignore a duplicate webhook',
    prompt: 'payment webhook idempotency, body hash and idempotency key for thirty days',
  },
  {
    title: 'Compose for the development Postgres',
    why: 'healthcheck, named volume for data and a seed script',
    prompt: 'compose for the development postgres, healthcheck and named volume for data',
  },
  {
    title: 'Invoicing form in Next.js',
    why: 'server action, zod validation and error messages for the VAT number',
    prompt: 'invoicing form in next.js, server action and zod validation for the vat number',
  },
  {
    title: 'Remove N+1 in the orders list',
    why: 'add a join and a composite index on order_id and tenant_id',
    prompt: 'remove n+1 in the orders list, join and composite index on order_id',
  },
];

/** ~40 unrelated items so BM25 idf is not degenerate (a one-document corpus
 *  scores everything near zero). */
async function seedLedger(api: Api, repo: string, topics = TOPICS): Promise<string[]> {
  const ids: string[] = [];
  for (const t of topics) {
    const res = await api('POST', '/v1/items', {
      repo,
      title: t.title,
      kind: 'BACKLOG',
      priority: 'P2',
      owner: 'agent',
      why: t.why,
      force: true,
    });
    assert.equal(res.status, 201, res.text);
    ids.push(res.json.id as string);
  }
  const words = ['warehouse', 'invoice', 'calendar', 'export', 'table', 'color', 'icon', 'font', 'logo', 'banner'];
  for (let i = 0; i < 40; i += 1) {
    const w = (n: number): string => words[(i * 3 + n) % words.length] as string;
    const res = await api('POST', '/v1/items', {
      repo,
      title: `Add ${w(0)} ${w(1)} entry ${i + 100}`,
      kind: 'BACKLOG',
      priority: 'P3',
      owner: 'agent',
      why: `${w(2)} ${w(0)} note ${i + 100}`,
      force: true,
    });
    assert.equal(res.status, 201, res.text);
  }
  return ids;
}

async function setup(prefix: string): Promise<{
  fx: HubFixture;
  code: Awaited<ReturnType<typeof makeCommittedRepo>>;
  ids: string[];
  deps: { ledger: HubFixture['hub']['ledger']; store: HubFixture['hub']['store'] };
}> {
  const fx = await startTestHub();
  const code = await makeCommittedRepo(prefix);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: code.path });
  const ids = await seedLedger(fx.api, 'app');
  fx.hub.store.rebuildSearch(await fx.hub.ledger.searchDocs());
  return { fx, code, ids, deps: { ledger: fx.hub.ledger, store: fx.hub.store } };
}

/** `AP-3` / `D1` at the start of each hit line. */
function hitIds(text: string): string[] {
  return [...text.matchAll(/(?:^|«)(AP-\d+|D\d+) ·/gm)].map((m) => m[1] as string);
}

/** Make the next message face the LATER bar. */
function burnFirst(deps: { ledger: unknown; store: HubFixture['hub']['store'] }, session: string): void {
  deps.store.markOnce('related', session);
}

/* ---------------- threshold ---------------- */

test('threshold — a later message needs more shared words and a stronger BM25', () => {
  assert.ok(LATER_MIN_OVERLAP > MIN_OVERLAP);
  assert.ok(LATER_BM25_MAX < BM25_MAX, 'more negative = stricter');
  const tokens = contentTokens('oauth refresh token rotation reuse detection');
  const twoWords = { text: 'oauth rotation in the fleet', score: -3 };
  const threeWords = { text: 'oauth rotation refresh in the fleet', score: -3 };
  // Two shared words: enough for the first message, not for a later one.
  assert.equal(relevance(tokens, twoWords, 'first').passes, true);
  assert.equal(relevance(tokens, twoWords, 'later').passes, false);
  assert.equal(relevance(tokens, threeWords, 'later').passes, true);
  // Same words, BM25 between the two bars: first yes, later no.
  const mid = { text: 'oauth rotation refresh in the fleet', score: (BM25_MAX + LATER_BM25_MAX) / 2 };
  assert.equal(relevance(tokens, mid, 'first').passes, true);
  assert.equal(relevance(tokens, mid, 'later').passes, false);
  // No ranking engine (LIKE fallback): one more word on top of the tier's bar.
  assert.equal(relevance(tokens, { text: 'oauth rotation refresh in the fleet', score: null }, 'later').passes, false);
  assert.equal(
    relevance(tokens, { text: 'oauth rotation refresh token in the fleet', score: null }, 'later').passes,
    true,
  );
});

/* ---------------- every message, nothing for generic ones ---------------- */

test('related works on a later message too; a generic message inserts 0 characters', async () => {
  const { fx, code, ids, deps } = await setup('h62a');
  try {
    const session = 's-later';
    // First eligible message: generic → nothing, but it spends the first-message mark.
    assert.equal(
      relatedLines(deps, { session, repo: 'app', prompt: 'fix that typo in the heading please' }),
      '',
    );
    // Later and generic → still nothing (0 characters, no frame header either).
    for (const generic of ['ok continue', 'look at that once more', 'thanks, looks good', '   ']) {
      assert.equal(relatedLines(deps, { session, repo: 'app', prompt: generic }), '', generic);
    }
    // Later and on topic → a hit, though this is not the session's first message.
    const topic = TOPICS[0] as (typeof TOPICS)[number];
    const hit = relatedLines(deps, { session, repo: 'app', prompt: topic.prompt });
    assert.match(hit, /^Related: /, hit);
    assert.ok(hitIds(hit).includes(ids[0] as string), hit);
    note('later message', hit);
  } finally {
    await code.cleanup();
    await fx.cleanup();
  }
});

/* ---------------- dedupe ---------------- */

test('an ID is shown at most once per session', async () => {
  const { fx, code, ids, deps } = await setup('h62b');
  try {
    const session = 's-dedupe';
    const topic = TOPICS[1] as (typeof TOPICS)[number];
    const first = relatedLines(deps, { session, repo: 'app', prompt: topic.prompt });
    assert.ok(hitIds(first).includes(ids[1] as string), first);
    // Same topic again, then a reworded one: the ref must not come back.
    const again = relatedLines(deps, { session, repo: 'app', prompt: topic.prompt });
    assert.ok(!hitIds(again).includes(ids[1] as string), again);
    const reworded = relatedLines(deps, {
      session,
      repo: 'app',
      prompt: `${topic.prompt} and once more billing wallet credits`,
    });
    assert.ok(!hitIds(reworded).includes(ids[1] as string), reworded);
    // A DIFFERENT session is told again — dedupe is per session.
    const other = relatedLines(deps, { session: 's-dedupe-2', repo: 'app', prompt: topic.prompt });
    assert.ok(hitIds(other).includes(ids[1] as string), other);
  } finally {
    await code.cleanup();
    await fx.cleanup();
  }
});

/* ---------------- session cap ---------------- */

test('session cap — at most 5 hits and 1,500 characters, then silence without searching', async () => {
  const { fx, code, ids, deps } = await setup('h62c');
  try {
    // Realistic run: seven different topics in one session.
    const session = 's-cap';
    burnFirst(deps, session);
    let total = 0;
    const seen = new Set<string>();
    for (const t of TOPICS) {
      const out = relatedLines(deps, { session, repo: 'app', prompt: t.prompt });
      total += out.length;
      for (const id of hitIds(out)) {
        assert.ok(!seen.has(id), `${id} repeated`);
        seen.add(id);
      }
    }
    assert.ok(seen.size >= 1, 'something must have passed, otherwise the test measures nothing');
    assert.ok(seen.size <= SESSION_MAX_HITS, `${seen.size} hits`);
    assert.ok(total <= SESSION_MAX_CHARS, `${total} chars`);

    // Deterministic: five refs already shown → silent, whatever the prompt is.
    const full = 's-cap-hits';
    for (let i = 0; i < SESSION_MAX_HITS; i += 1) {
      deps.store.markOnce('related-shown', `${full}:AP-${900 + i}:100`);
    }
    assert.equal(relatedLines(deps, { session: full, repo: 'app', prompt: (TOPICS[2] as { prompt: string }).prompt }), '');

    // Deterministic: the character budget is spent → silent as well.
    const chars = 's-cap-chars';
    deps.store.markOnce('related-shown', `${chars}:AP-900:${SESSION_MAX_CHARS}`);
    assert.equal(relatedLines(deps, { session: chars, repo: 'app', prompt: (TOPICS[2] as { prompt: string }).prompt }), '');

    // A hit that would overshoot the remaining characters is skipped, not cut.
    const nearly = 's-cap-near';
    deps.store.markOnce('related-shown', `${nearly}:AP-900:${SESSION_MAX_CHARS - 60}`);
    const tight = relatedLines(deps, { session: nearly, repo: 'app', prompt: (TOPICS[3] as { prompt: string }).prompt });
    assert.equal(tight, '', tight);
    void ids;
  } finally {
    await code.cleanup();
    await fx.cleanup();
  }
});

/* ---------------- paths ---------------- */

test('paths — existing unflagged, deleted "maybe moved", glob by directory', async () => {
  const { fx, code, ids, deps } = await setup('h62d');
  try {
    // Two files that exist in the checkout, one that was deleted/moved.
    for (const rel of ['src/auth/rotate.ts', 'src/auth/reuse.ts']) {
      await mkdir(dirname(join(code.path, rel)), { recursive: true });
      await writeFile(join(code.path, rel), 'x\n', 'utf8');
    }
    const id = ids[0] as string;
    recordCommitFiles(fx.hub.store, 'app', [id], [
      'src/auth/rotate.ts',
      'src/auth/reuse.ts',
      'lib/gone.ts',
      'pnpm-lock.yaml',
    ]);
    const out = relatedLines(deps, {
      session: 's-paths',
      repo: 'app',
      prompt: (TOPICS[0] as { prompt: string }).prompt,
    });
    const line = out.split('\n').find((l) => l.includes(id)) ?? '';
    note('hit with paths', out);
    // `ID · state · title · path1, path2` — on ONE line.
    assert.match(line, new RegExp(`${id} · open · OAuth refresh token rotation on every refresh · `), line);
    assert.ok(line.includes('src/auth/*'), `two files in one directory are merged: ${line}`);
    assert.ok(!line.includes('src/auth/*' + ' (maybe'), `an existing path has no flag: ${line}`);
    assert.ok(line.includes('lib/gone.ts (maybe moved)'), `a deleted path is flagged: ${line}`);
    assert.ok(!line.includes('pnpm-lock'), 'a lockfile is not information');
    assert.equal(out.match(/data from the ledger\/git/g)?.length, 1);
  } finally {
    await code.cleanup();
    await fx.cleanup();
  }
});

test('paths from session_facts of the session that claimed the item; its own work is not reminded to it', async () => {
  const { fx, code, ids, deps } = await setup('h62e');
  try {
    const id = ids[3] as string;
    const worker = 's-worker-1111';
    fx.hub.store.recordChange({ repo: 'app', item_id: id, kind: 'claimed', actor: worker, title: 'x' });
    fx.hub.store.addSessionFact({
      session: worker,
      repo: 'app',
      files: ['svc/payments/webhook.ts', 'svc/payments/hash.ts', 'svc/payments/webhook.test.ts'],
    });
    const prompt = (TOPICS[3] as { prompt: string }).prompt;

    const other = relatedLines(deps, { session: 's-other', repo: 'app', prompt });
    const line = other.split('\n').find((l) => l.includes(id)) ?? '';
    assert.ok(line.includes('svc/payments/*'), line);
    // Nothing is on disk → the glob's directory is unknown to the checkout.
    assert.ok(line.includes('svc/payments/* (maybe moved)'), line);

    // The worker itself already knows — no reminder of its own item.
    const own = relatedLines(deps, { session: worker, repo: 'app', prompt });
    assert.ok(!hitIds(own).includes(id), own);

    // A session that touched dozens of files says nothing about one item.
    const sprawl = ids[4] as string;
    const big = 's-sprawl';
    fx.hub.store.recordChange({ repo: 'app', item_id: sprawl, kind: 'done', actor: big, title: 'x' });
    fx.hub.store.addSessionFact({
      session: big,
      repo: 'app',
      files: Array.from({ length: 41 }, (_, i) => `misc/f${i}.ts`),
    });
    const sprawlOut = relatedLines(deps, {
      session: 's-other-2',
      repo: 'app',
      prompt: (TOPICS[4] as { prompt: string }).prompt,
    });
    const sprawlLine = sprawlOut.split('\n').find((l) => l.includes(sprawl)) ?? '';
    assert.ok(sprawlLine.includes(sprawl), sprawlOut);
    assert.ok(!sprawlLine.includes('misc/'), sprawlLine);
  } finally {
    await code.cleanup();
    await fx.cleanup();
  }
});

test('without a checkout paths cannot be verified — they stay unflagged', async () => {
  const fx = await startTestHub();
  try {
    await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: null });
    const ids = await seedLedger(fx.api, 'app');
    fx.hub.store.rebuildSearch(await fx.hub.ledger.searchDocs());
    recordCommitFiles(fx.hub.store, 'app', [ids[0] as string], ['a/b/one.ts']);
    const out = relatedLines(
      { ledger: fx.hub.ledger, store: fx.hub.store },
      { session: 's-nocheckout', repo: 'app', prompt: (TOPICS[0] as { prompt: string }).prompt },
    );
    assert.ok(out.includes('a/b/one.ts'), out);
    assert.ok(!out.includes('maybe moved'), out);
  } finally {
    await fx.cleanup();
  }
});

/* ---------------- path folding (pure) ---------------- */

test('mergePaths — files in one directory → dir/*, lone ones stay, cap 4', () => {
  const w = (files: string[], weight = 3): Map<string, number> => new Map(files.map((f) => [f, weight]));
  assert.deepEqual(mergePaths(w(['a/b/x.ts', 'a/b/y.ts', 'c/z.ts'])), ['a/b/*', 'c/z.ts']);
  assert.deepEqual(mergePaths(w(['README.md', 'package.json'])), ['README.md', 'package.json']);

  // Too many directories: siblings are lifted into their parent.
  const many = mergePaths(
    w([
      'p/s/a/1.ts',
      'p/s/a/2.ts',
      'p/s/b/1.ts',
      'p/s/b/2.ts',
      'p/s/c/1.ts',
      'p/s/c/2.ts',
      'q/other.ts',
      'r/another.ts',
    ]),
  );
  assert.ok(many.length <= 4, many.join(', '));
  assert.ok(many.includes('p/s/**'), many.join(', '));

  // Heavier (commit) paths beat lighter (session) ones when something must go.
  const mixed = new Map<string, number>([
    ['one/a.ts', 1],
    ['two/b.ts', 1],
    ['three/c.ts', 1],
    ['four/d.ts', 1],
    ['hot/e.ts', 9],
  ]);
  const top = mergePaths(mixed);
  assert.equal(top.length, 4);
  assert.equal(top[0], 'hot/e.ts');
});

test('cleanRelPath and isNoisePath — nothing outside the checkout, no noise', () => {
  for (const bad of ['', '/etc/passwd', '../x', 'a/../../x', 'a//b', 'a/./b', 'C:\\x', 'a\\b', 'a/b/', 'a\nb', 'a\u0000b']) {
    assert.equal(cleanRelPath(bad), null, JSON.stringify(bad));
  }
  assert.equal(cleanRelPath('./src/a.ts'), 'src/a.ts');
  assert.equal(cleanRelPath('src/a b.ts'), 'src/a b.ts');
  assert.equal(isNoisePath('pnpm-lock.yaml'), true);
  assert.equal(isNoisePath('apps/web/CHANGELOG.md'), true);
  assert.equal(isNoisePath('node_modules/x/index.js'), true);
  assert.equal(isNoisePath('src/dist/a.ts'), true);
  assert.equal(isNoisePath('src/lock.ts'), false);
});

/* ---------------- recording from commits ---------------- */

test('a commit with Refs/Closes records the item files; a big commit, a lockfile and a foreign repo do not', async () => {
  const fx = await startTestHub();
  const code = await makeCommittedRepo('h62f');
  const other = await makeCommittedRepo('h62g');
  try {
    await fx.hub.ledger.registerRepo({ slug: 'mine', prefix: 'MN', path: code.path, onboarded: true });
    await fx.hub.ledger.registerRepo({ slug: 'theirs', prefix: 'TH', path: other.path, onboarded: true });
    await fx.hub.repoWatcher.start();
    const mine = (await fx.api('POST', '/v1/items', { repo: 'mine', title: 'My item', kind: 'BACKLOG', priority: 'P2' })).json.id as string;
    const theirs = (await fx.api('POST', '/v1/items', { repo: 'theirs', title: 'Their item', kind: 'BACKLOG', priority: 'P2' })).json.id as string;

    await code.commit(`feat: thing\n\nRefs: ${mine}\nRefs: ${theirs}\n`, {
      'src/a.ts': '1\n',
      'src/b.ts': '1\n',
      'pnpm-lock.yaml': 'lock\n',
    });
    await fx.hub.repoWatcher.sync();
    assert.deepEqual(
      fx.hub.store.itemFiles('mine', mine).map((r) => r.path).sort(),
      ['src/a.ts', 'src/b.ts'],
    );
    assert.deepEqual(fx.hub.store.itemFiles('theirs', theirs), [], 'an ID of a foreign repo is not recorded');
    assert.deepEqual(fx.hub.store.itemFiles('mine', theirs), []);

    // A sweep (rename, format-all) tells nothing about the item.
    const sweep: Record<string, string> = {};
    for (let i = 0; i <= MAX_COMMIT_FILES; i += 1) sweep[`sweep/f${i}.ts`] = `${i}\n`;
    await code.commit(`chore: format\n\nRefs: ${mine}\n`, sweep);
    await fx.hub.repoWatcher.sync();
    assert.equal(fx.hub.store.itemFiles('mine', mine).length, 2);

    // Same file in a second commit raises its count rather than adding a row.
    await code.commit(`fix: more\n\nCloses: ${mine}\n`, { 'src/a.ts': '2\n' });
    await fx.hub.repoWatcher.sync();
    const rows = fx.hub.store.itemFiles('mine', mine);
    assert.equal(rows.length, 2);
    assert.equal(rows.find((r) => r.path === 'src/a.ts')?.n, 2);
  } finally {
    await code.cleanup();
    await other.cleanup();
    await fx.cleanup();
  }
});

test('item_files is capped per item — the oldest paths drop out', async () => {
  const fx = await startTestHub();
  try {
    const store = fx.hub.store;
    store.addItemFiles('app', 'AP-1', Array.from({ length: 30 }, (_, i) => `old/f${i}.ts`), 1_000);
    store.addItemFiles('app', 'AP-1', ['new/a.ts', 'new/b.ts'], 2_000);
    const rows = store.itemFiles('app', 'AP-1');
    assert.equal(rows.length, 30);
    assert.ok(rows.some((r) => r.path === 'new/a.ts') && rows.some((r) => r.path === 'new/b.ts'));
  } finally {
    await fx.cleanup();
  }
});

/* ---------------- through the real hook ---------------- */

test('UserPromptSubmit — a generic first message yields nothing, later a topic with paths, the prompt is not stored', async () => {
  const { fx, code, ids } = await setup('h62h');
  try {
    await mkdir(join(code.path, 'src/webhooks'), { recursive: true });
    await writeFile(join(code.path, 'src/webhooks/hash.ts'), 'x\n', 'utf8');
    await rm(join(code.path, 'nothing'), { recursive: true, force: true });
    recordCommitFiles(fx.hub.store, 'app', [ids[3] as string], ['src/webhooks/hash.ts', 'src/webhooks/dedupe.ts']);
    await fx.hook('session-start', { session_id: 's-hook', cwd: code.path, source: 'startup' });

    const generic = await fx.hook('user-prompt-submit', {
      session_id: 's-hook',
      cwd: code.path,
      prompt: 'fix that typo in the heading please',
    });
    assert.ok(!generic.text.includes('Related'), generic.text);

    const canary = 'canaryXq9f3c';
    const topic = await fx.hook('user-prompt-submit', {
      session_id: 's-hook',
      cwd: code.path,
      prompt: `${(TOPICS[3] as { prompt: string }).prompt} ${canary}`,
    });
    assert.match(topic.text, /Related: /, topic.text);
    assert.ok(topic.text.includes('src/webhooks/*'), topic.text);

    // The prompt was used to build a query and dropped: neither the marks nor
    // the log carry any of its words.
    const marks = fx.hub.store.markKeys('related-shown', 's-hook:').join('\n');
    assert.ok(!marks.includes(canary));
    assert.ok(!fx.logs.join('\n').includes(canary));
  } finally {
    await code.cleanup();
    await fx.cleanup();
  }
});
