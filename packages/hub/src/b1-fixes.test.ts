/** Regression tests for B1-5 (`GET /v1/dups` repo-scoping + input cap),
 *  B1-6 (`PATCH /v1/items/:id` respects `force`) and B1-7 (server-side cap
 *  on headless `dup` merges). Each test exercises the real HTTP route
 *  through `startTestHub`'s fixture, not a reimplementation. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { MAX_DUPLICATE_ITEMS } from '@agent-ledger/shared';
import { GROOM_SEMANTIC_DUP_CAP } from './headless.ts';
import { startTestHub } from './test-helpers.ts';

/* ---------------- B1-6 ---------------- */

test('B1-6: PATCH title to a near-duplicate is 409, but force:true overrides it', async () => {
  const fx = await startTestHub();
  try {
    await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: null });
    await fx.api('POST', '/v1/items', {
      repo: 'app',
      title: 'Production without content',
      kind: 'BACKLOG',
      priority: 'P2',
      owner: 'agent',
    });
    const created = await fx.api('POST', '/v1/items', {
      repo: 'app',
      title: 'A completely different item to rename',
      kind: 'BACKLOG',
      priority: 'P2',
      owner: 'agent',
    });
    const id = created.json.id as string;

    const blocked = await fx.api('PATCH', `/v1/items/${id}`, { title: 'Production without content' });
    assert.equal(blocked.status, 409, JSON.stringify(blocked.json));

    const forced = await fx.api('PATCH', `/v1/items/${id}`, { title: 'Production without content', force: true });
    assert.equal(forced.status, 200, JSON.stringify(forced.json));
    assert.equal(forced.json.item.title, 'Production without content');
  } finally {
    await fx.cleanup();
  }
});

/* ---------------- B1-5 ---------------- */

test('B1-5: GET /v1/dups without ?repo= is 422 (the fleet-wide default is gone)', async () => {
  const fx = await startTestHub();
  try {
    const res = await fx.api('GET', '/v1/dups');
    assert.equal(res.status, 422, JSON.stringify(res.json));
  } finally {
    await fx.cleanup();
  }
});

test(`B1-5: more than ${MAX_DUPLICATE_ITEMS} open items in a repo is 413, not a silent O(n²) scan`, async () => {
  const fx = await startTestHub();
  try {
    await fx.api('POST', '/v1/repos', { slug: 'big', prefix: 'BG', path: null });
    const over = MAX_DUPLICATE_ITEMS + 1;
    for (let i = 0; i < over; i += 1) {
      await fx.hub.ledger.createItem({
        repo: 'big',
        title: `Item number ${i} with unique text ${i * 31}`,
        kind: 'BACKLOG',
        priority: 'P2',
        owner: 'agent',
        steps: [],
        blocked_by: [],
        aliases: [],
        proposed: false,
      });
    }
    const res = await fx.api('GET', '/v1/dups?repo=big');
    assert.equal(res.status, 413, JSON.stringify(res.json));
  } finally {
    await fx.cleanup();
  }
});

/* ---------------- B1-7 ---------------- */

test(`B1-7: a headless run gets at most ${GROOM_SEMANTIC_DUP_CAP} dup merges, the rest 429`, async () => {
  const fx = await startTestHub();
  try {
    await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: null });
    const target = await fx.api('POST', '/v1/items', {
      repo: 'app',
      title: 'Target item for merging',
      kind: 'BACKLOG',
      priority: 'P2',
      owner: 'agent',
    });
    const into = target.json.id as string;

    // Titles are deliberately UNRELATED to each other (only "force" skips the
    // near-duplicate check, and these calls do not set it) — distinct nouns,
    // not a shared template plus an index, which the dedupe scorer treats as
    // the same item worded slightly differently.
    const words = ['banana', 'tractor', 'lightbulb', 'umbrella', 'keyboard', 'pond', 'chimney', 'sweater'];
    const sources: string[] = [];
    for (let i = 0; i < GROOM_SEMANTIC_DUP_CAP + 1; i += 1) {
      const src = await fx.api('POST', '/v1/items', {
        repo: 'app',
        title: `Repair ${words[i]} in the warehouse`,
        kind: 'BACKLOG',
        priority: 'P2',
        owner: 'agent',
      });
      assert.equal(src.status, 201, JSON.stringify(src.json));
      sources.push(src.json.id as string);
    }

    const session = 'headless-groom-xyz';
    for (let i = 0; i < GROOM_SEMANTIC_DUP_CAP; i += 1) {
      const res = await fx.api('POST', `/v1/items/${sources[i]}/dup`, { session, into });
      assert.equal(res.status, 200, `merge #${i} should pass: ${JSON.stringify(res.json)}`);
    }
    const overCap = await fx.api('POST', `/v1/items/${sources[GROOM_SEMANTIC_DUP_CAP]}/dup`, {
      session,
      into,
    });
    assert.equal(overCap.status, 429, JSON.stringify(overCap.json));

    // The item the capped call targeted must stay untouched (open, not
    // merged) — the cap must block the merge, not just the HTTP response.
    const untouched = await fx.api('GET', `/v1/items/${sources[GROOM_SEMANTIC_DUP_CAP]}`);
    assert.equal(untouched.json.item.status, 'open');

    // A session NOT named `headless-*` is unaffected by this cap.
    const human = await fx.api('POST', `/v1/items/${sources[GROOM_SEMANTIC_DUP_CAP]}/dup`, {
      session: 'human-sess-9',
      into,
    });
    assert.equal(human.status, 200, JSON.stringify(human.json));
  } finally {
    await fx.cleanup();
  }
});
