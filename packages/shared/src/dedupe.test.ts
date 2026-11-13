import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DEFAULT_THRESHOLD,
  findDuplicatePairs,
  findDuplicatePairsAsync,
  findDuplicates,
  normalizeTitle,
  titleSimilarity,
  titleTokens,
} from './dedupe.ts';

/**
 * The calibration table. Every row is a real-shaped pair; `dup` is the verdict
 * the threshold has to produce. Changing `DEFAULT_THRESHOLD` without changing
 * this table is how the feature regresses, so the table is the spec.
 */
const PAIRS: { a: string; b: string; dup: boolean; why: string }[] = [
  // --- must be duplicates ---
  {
    a: 'demo.example.com does not exist — host without certificate, Caddy has no zone for it',
    b: 'demo.example.com does not exist — host without certificate',
    dup: true,
    why: 'containment: the shorter title is a subset of the longer one',
  },
  {
    a: 'Production without content',
    b: 'Production without content test3',
    dup: true,
    why: 'containment through the stop word "without"',
  },
  {
    a: 'Production without content',
    b: 'production content',
    dup: true,
    why: 'same tokens after stop-word removal',
  },
  {
    a: 'Add index on items.repo',
    b: 'add   index on items repo',
    dup: true,
    why: 'punctuation and case are normalised',
  },
  {
    a: 'Hub crashes at startup when token is missing',
    b: 'Hub crashes at startup, token missing',
    dup: true,
    why: 'same set of content words',
  },

  // --- must NOT be duplicates ---
  {
    a: 'Add index on items.repo',
    b: 'Add index on items.session',
    dup: false,
    why: 'Jaccard 0.60 < threshold — a different column is different work',
  },
  {
    a: 'Production without content',
    b: 'Dev without content',
    dup: false,
    why: 'they share only "content"',
  },
  {
    a: 'demo.example.com does not exist — host without certificate',
    b: 'demo.example.com returns 502 after deploy',
    dup: false,
    why: 'same host, different problem',
  },
  {
    a: 'Write queue during hub outage',
    b: 'Session name from the agent sidebar',
    dup: false,
    why: 'unrelated items',
  },
  {
    a: 'Deploy',
    b: 'Deploy web app to Hetzner',
    dup: false,
    why: 'a one-word title must not match everything through containment',
  },
];

test('calibration table of pairs', () => {
  for (const row of PAIRS) {
    const score = titleSimilarity(row.a, row.b);
    assert.equal(
      score >= DEFAULT_THRESHOLD,
      row.dup,
      `"${row.a}" ~ "${row.b}" → ${score.toFixed(3)} (expected dup=${row.dup}: ${row.why})`,
    );
  }
});

test('similarity is symmetric and within 0..1', () => {
  for (const row of PAIRS) {
    const ab = titleSimilarity(row.a, row.b);
    const ba = titleSimilarity(row.b, row.a);
    assert.equal(ab, ba);
    assert.ok(ab >= 0 && ab <= 1, `${ab} outside 0..1`);
  }
});

test('normalisation drops diacritics, case and punctuation', () => {
  assert.equal(normalizeTitle('Crème brûlée — ÜBER Café!'), 'creme brulee uber cafe');
  assert.equal(normalizeTitle('   '), '');
});

test('tokens drop stop words and single-character noise', () => {
  assert.deepEqual([...titleTokens('Add it to the server and to DB')], [
    'add',
    'server',
    'db',
  ]);
});

test('a title made only of stop words matches nothing but itself', () => {
  assert.equal(titleSimilarity('the of to', 'the of to'), 1);
  assert.equal(titleSimilarity('the of to', 'Production without content'), 0);
});

test('findDuplicates returns at most 3 candidates, best first', () => {
  const open = [
    { id: 'ACME-1', title: 'Production without content' },
    { id: 'ACME-2', title: 'Production without content test3' },
    { id: 'ACME-3', title: 'production content extra' },
    { id: 'ACME-4', title: 'Production content' },
    { id: 'ACME-5', title: 'Totally different thing about sessions' },
  ];
  const hits = findDuplicates('Production without content', open);
  assert.equal(hits.length, 3);
  assert.ok(hits[0] !== undefined);
  assert.ok((hits[0] as { score: number }).score >= (hits[1] as { score: number }).score);
  assert.ok(!hits.some((h) => h.id === 'ACME-5'));
});

test('findDuplicates honours a custom threshold', () => {
  const open = [{ id: 'ACME-1', title: 'Add index on items.session' }];
  assert.equal(findDuplicates('Add index on items.repo', open).length, 0);
  assert.equal(findDuplicates('Add index on items.repo', open, 0.5).length, 1);
});

test('findDuplicatePairs finds pairs within one repo, without self-pairs', () => {
  const pairs = findDuplicatePairs([
    { id: 'ACME-1', title: 'Production without content' },
    { id: 'ACME-2', title: 'Production without content test3' },
    { id: 'ACME-3', title: 'Something entirely different' },
  ]);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0]?.a.id, 'ACME-1');
  assert.equal(pairs[0]?.b.id, 'ACME-2');
});

test('findDuplicatePairsAsync finds the same pairs as the sync version and does not block the event loop', async () => {
  const items = Array.from({ length: 450 }, (_, i) => ({
    id: `ACME-${i}`,
    title: i % 2 === 0 ? 'Production without content' : `Completely different thing number ${i} about sessions and tokens`,
  }));
  const sync = findDuplicatePairs(items, 0.95, 10_000);
  const async_ = await findDuplicatePairsAsync(items, 0.95, 10_000);
  assert.ok(sync.length > 0, 'fixture must really produce matches');
  assert.deepEqual(
    async_.map((p) => `${p.a.id}~${p.b.id}`).sort(),
    sync.map((p) => `${p.a.id}~${p.b.id}`).sort(),
    'the async version must find exactly the same pairs as the sync one',
  );

  // The event loop must get a turn DURING the scan, not just before/after it.
  // A high threshold + fully distinct titles means no early truncation, so
  // this runs the full O(n²) sweep — long enough to cross several 20 ms
  // yield boundaries.
  const distinct = Array.from({ length: 1000 }, (_, i) => ({
    id: `ACME-${i}`,
    title: `Totally distinct item with unique words ${i} and something extra ${i * 7}`,
  }));
  let ticks = 0;
  const timer = setInterval(() => {
    ticks += 1;
  }, 3);
  try {
    await findDuplicatePairsAsync(distinct, 0.99, 10_000);
  } finally {
    clearInterval(timer);
  }
  assert.ok(ticks > 0, 'the event loop must get a turn at least once during a large scan (setImmediate yield)');
});
