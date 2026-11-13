/**
 * The API contract `packages/shared/src/api.ts` promises to the web UI.
 *
 * `web-dev` builds against those types and nothing else, so a drift between the
 * declared shape and the real response has to break here rather than in the UI.
 * The types are erased at runtime, so the check is: every declared key exists on
 * a live response with the declared kind of value (and nothing declared as
 * non-optional is missing).
 */

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import type {
  DirtyFileView,
  GitBranchView,
  GitHeadView,
  ItemCounts,
  RepoStatusView,
  SearchResponse,
  SessionDetailResponse,
  SessionView,
  TouchedView,
  WhoResponse,
  WhoseResponse,
} from '@agent-ledger/shared';
import { emptyCounts, SSE_EVENTS } from '@agent-ledger/shared';
import { makeCommittedRepo, startTestHub } from '../test-helpers.ts';

type Shape = Record<string, 'string' | 'number' | 'boolean' | 'array' | 'object' | 'nullable-string' | 'nullable-number' | 'nullable-object'>;

function assertShape(value: unknown, shape: Shape, where: string): void {
  assert.ok(value !== null && typeof value === 'object', `${where}: not an object`);
  const obj = value as Record<string, unknown>;
  for (const [key, kind] of Object.entries(shape)) {
    assert.ok(Object.hasOwn(obj, key), `${where}: missing key "${key}"`);
    const v = obj[key];
    switch (kind) {
      case 'array':
        assert.ok(Array.isArray(v), `${where}.${key}: expected an array, got ${typeof v}`);
        break;
      case 'nullable-string':
        assert.ok(v === null || typeof v === 'string', `${where}.${key}: string|null, got ${typeof v}`);
        break;
      case 'nullable-number':
        assert.ok(v === null || typeof v === 'number', `${where}.${key}: number|null, got ${typeof v}`);
        break;
      case 'nullable-object':
        assert.ok(v === null || typeof v === 'object', `${where}.${key}: object|null, got ${typeof v}`);
        break;
      case 'object':
        assert.ok(v !== null && typeof v === 'object', `${where}.${key}: object`);
        break;
      default:
        assert.equal(typeof v, kind, `${where}.${key}: ${kind}, got ${typeof v}`);
    }
  }
}

const SESSION_VIEW: Shape = {
  id: 'string',
  home_repo: 'nullable-string',
  cwd: 'nullable-string',
  checkout: 'nullable-string',
  branch: 'nullable-string',
  transcript_path: 'nullable-string',
  started_at: 'string',
  last_seen: 'string',
  ended_at: 'nullable-string',
  source: 'string',
  liveness: 'string',
  idle_ms: 'number',
  short: 'string',
  items: 'array',
  agents: 'array',
  touched_count: 'number',
};

const TOUCHED_VIEW: Shape = {
  id: 'string',
  session: 'string',
  repo: 'string',
  checkout: 'string',
  rel_path: 'string',
  via: 'string',
  agent_type: 'nullable-string',
  first_at: 'string',
  last_at: 'string',
  committed_sha: 'nullable-string',
  orphan: 'boolean',
};

const DIRTY_VIEW: Shape = {
  rel_path: 'string',
  code: 'string',
  staged: 'boolean',
  untracked: 'boolean',
  owner: 'nullable-string',
  owner_short: 'nullable-string',
  via: 'nullable-string',
  orphan: 'boolean',
};

const GIT_HEAD_VIEW: Shape = {
  head: 'nullable-string',
  branch: 'nullable-string',
  ahead: 'nullable-number',
  behind: 'nullable-number',
  detached: 'boolean',
  refreshed_at: 'nullable-string',
};

const BRANCH_VIEW: Shape = {
  name: 'string',
  head: 'string',
  ahead: 'number',
  behind: 'number',
  base: 'nullable-string',
  upstream: 'nullable-string',
  stale: 'boolean',
};

const REPO_STATUS_VIEW: Shape = {
  slug: 'string',
  prefix: 'string',
  path: 'nullable-string',
  next: 'number',
  graphify: 'nullable-string',
  docs: 'array',
  git: 'nullable-object',
  last_release: 'nullable-object',
  counts: 'object',
  sessions: 'array',
  dirty: 'array',
  orphans: 'array',
  branches: 'array',
  worktrees: 'array',
  intake_new: 'number',
};

const COUNTS: Shape = {
  proposed: 'number',
  open: 'number',
  doing: 'number',
  blocked: 'number',
  done: 'number',
  dropped: 'number',
  open_total: 'number',
  total: 'number',
};

test('api.ts contract: every shape the UI needs matches the live response', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('contract');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({
    slug: 'acme',
    prefix: 'ACME',
    path: repo.path,
    graphify: '~/projects/graphify-out',
    docs: ['docs/HANDOFF.md'],
    onboarded: true,
  });
  await fx.hub.repoWatcher.start();
  await repo.tag('v0.1.0');

  const created = await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'contract item',
    kind: 'BLOCKER',
    priority: 'P0',
    why: 'so the UI has something to build on',
    steps: ['step one'],
  });
  const id = created.json.id as string;

  await fx.hook('session-start', {
    session_id: 'ffff0001',
    cwd: repo.path,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
  await fx.api('POST', `/v1/items/${id}/claim`, {
    session: 'ffff0001',
    paths: ['src/**'],
    intent: 'contract',
  });
  await writeFile(join(repo.path, 'contract.ts'), 'x\n', 'utf8');
  await fx.hook('post-tool-use', {
    session_id: 'ffff0001',
    hook_event_name: 'PostToolUse',
    tool_name: 'Edit',
    tool_input: { file_path: join(repo.path, 'contract.ts') },
    agent_type: 'backend-architect',
  });

  /* ---- GET /v1/sessions ---- */
  const sessions = await fx.api('GET', '/v1/sessions');
  assert.ok(Array.isArray(sessions.json.sessions));
  const session = sessions.json.sessions[0] as SessionView;
  assertShape(session, SESSION_VIEW, 'SessionView');
  assert.deepEqual(session.items, [id], 'claimed items');
  assert.deepEqual(session.agents, ['backend-architect']);
  assert.ok(['active', 'idle', 'ended'].includes(session.liveness));

  /* ---- GET /v1/sessions/:id ---- */
  const detail = (await fx.api('GET', `/v1/sessions/${session.id}`)).json as SessionDetailResponse;
  assertShape(detail, { session: 'object', touched: 'array', leases: 'array', events: 'array' }, 'SessionDetailResponse');
  assertShape(detail.touched[0] as TouchedView, TOUCHED_VIEW, 'TouchedView');
  assertShape(
    detail.leases[0] as unknown,
    {
      id: 'string',
      session: 'string',
      repo: 'string',
      checkout: 'nullable-string',
      kind: 'string',
      item_id: 'nullable-string',
      paths: 'array',
      intent: 'nullable-string',
      created_at: 'string',
      released_at: 'nullable-string',
    },
    'LeaseView',
  );

  /* ---- GET /v1/repos/:slug ---- */
  const view = (await fx.api('GET', '/v1/repos/acme')).json.repo as RepoStatusView;
  assertShape(view, REPO_STATUS_VIEW, 'RepoStatusView');
  assertShape(view.counts as ItemCounts, COUNTS, 'ItemCounts');
  assertShape(view.git as GitHeadView, GIT_HEAD_VIEW, 'GitHeadView');
  assertShape(view.last_release as object, { tag: 'string', at: 'nullable-string', sha: 'nullable-string' }, 'ReleaseView');
  assertShape(view.dirty[0] as DirtyFileView, DIRTY_VIEW, 'DirtyFileView');
  assertShape(view.branches[0] as GitBranchView, BRANCH_VIEW, 'GitBranchView');
  assertShape(
    view.worktrees[0] as unknown,
    {
      path: 'string',
      head: 'nullable-string',
      branch: 'nullable-string',
      detached: 'boolean',
      bare: 'boolean',
      main: 'boolean',
      live: 'boolean',
    },
    'GitWorktreeView',
  );
  assertShape(view.sessions[0] as SessionView, SESSION_VIEW, 'RepoStatusView.sessions[]');
  assert.equal(view.counts.doing, 1);
  assert.equal(view.counts.open_total, 1);
  assert.equal(view.counts.total, 1);
  assert.deepEqual(Object.keys(view.counts).sort(), Object.keys(emptyCounts()).sort());

  /* ---- GET /v1/repos/:slug/who ---- */
  const who = (await fx.api('GET', '/v1/repos/acme/who?format=json')).json as WhoResponse;
  assertShape(
    who,
    { repo: 'string', sessions: 'array', dirty: 'array', orphans: 'array', git: 'nullable-object', text: 'string' },
    'WhoResponse',
  );

  /* ---- GET /v1/whose ---- */
  const whose = (
    await fx.api(
      'GET',
      `/v1/whose?path=${encodeURIComponent(join(session.checkout as string, 'contract.ts'))}`,
    )
  ).json as WhoseResponse;
  assertShape(
    whose,
    {
      path: 'string',
      repo: 'nullable-string',
      checkout: 'nullable-string',
      rel_path: 'nullable-string',
      owner: 'nullable-object',
      known: 'boolean',
    },
    'WhoseResponse',
  );
  assertShape(whose.owner as TouchedView, TOUCHED_VIEW, 'WhoseResponse.owner');

  /* ---- GET /v1/search ---- */
  await fx.hub.ledger.queue.run(() => fx.hub.ledger.reindex());
  await new Promise((r) => setTimeout(r, 120));
  const search = (await fx.api('GET', '/v1/search?q=contract')).json as SearchResponse;
  assertShape(search, { q: 'string', engine: 'string', hits: 'array' }, 'SearchResponse');
  assert.ok(['fts5', 'like'].includes(search.engine));
  if (search.hits.length > 0) {
    assertShape(
      search.hits[0] as unknown,
      { kind: 'string', ref: 'string', repo: 'string', title: 'string', excerpt: 'string' },
      'SearchHit',
    );
  }

  /* ---- GET /v1/timeline ---- */
  const timeline = await fx.api('GET', '/v1/timeline?repo=acme');
  assertShape(timeline.json, { events: 'array' }, 'TimelineResponse');
  assertShape(
    timeline.json.events[0],
    { at: 'string', session: 'string', type: 'string', fields: 'array', repo: 'string' },
    'JournalEvent',
  );

  /* ---- GET /v1/inbox ---- */
  const inbox = await fx.api('GET', `/v1/inbox?session=${session.id}`);
  assertShape(inbox.json, { messages: 'array' }, 'InboxResponse');

  /* ---- F0 shapes the UI also reads ---- */
  const item = await fx.api('GET', `/v1/items/${id}`);
  assertShape(item.json, { item: 'object', detail: 'object' }, 'ItemDetailResponse');
  assertShape(
    item.json.detail,
    { why: 'string', steps: 'array', rec: 'string', comments: 'array', log: 'array' },
    'ItemDetail',
  );
  assertShape(
    item.json.item,
    {
      id: 'string',
      title: 'string',
      status: 'string',
      kind: 'string',
      priority: 'string',
      owner: 'string',
      repo: 'string',
      area: 'nullable-string',
      paths: 'array',
      blocks: 'array',
      blocked_by: 'array',
      requested_by: 'nullable-string',
      intake: 'nullable-string',
      aliases: 'array',
      claimed_by: 'nullable-object',
      source: 'object',
      done: 'nullable-object',
      created: 'string',
      updated: 'string',
    },
    'ItemFrontmatter',
  );

  const health = await fx.api('GET', '/v1/healthz');
  assertShape(
    health.json,
    { ok: 'boolean', sessions: 'object', search: 'string', git: 'object', warnings: 'array' },
    'HealthzResponse',
  );
  assertShape(health.json.sessions, { live: 'number', active: 'number' }, 'HealthzResponse.sessions');
});

test('SSE_EVENTS contains every event the hub really sends', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const seen: string[] = [];
  fx.hub.bus.subscribe((env) => seen.push(env.event));
  for (const name of SSE_EVENTS) fx.hub.bus.emit(name, null, {});
  assert.deepEqual(seen, [...SSE_EVENTS], 'event names are a stable contract for the UI');
  // Names the UI switches on must stay kebab-free and dot-separated.
  for (const name of SSE_EVENTS) assert.match(name, /^[a-z]+\.[a-z]+$/);
});
