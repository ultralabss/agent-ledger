/**
 * Ownership attribution and lock expiry with two sessions in
 * ONE checkout: files written by session A were attributed to session B
 * (whose Bash ran next), locks survived the change they described, and a
 * `app/src/**` claim denied edits across a whole tree.
 *
 * Every test drives the real hook endpoints, because the bug lived in the
 * interaction between PostToolUse(Edit), PostToolUse(Bash) and the git cache —
 * not in any single function.
 */

import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { LEASE_IDLE_MS, STALE_OWNER_MS } from './db/store.ts';
import { makeCommittedRepo, startTestHub, type HubFixture } from './test-helpers.ts';

/* ---------------- helpers ---------------- */

async function startSession(fx: HubFixture, id: string, cwd: string): Promise<void> {
  const res = await fx.hook('session-start', {
    session_id: id,
    cwd,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
  assert.equal(res.status, 200);
}

/** PostToolUse(Write) — the editor write actually happens on disk first. */
async function didWrite(fx: HubFixture, session: string, file: string, body = 'x\n'): Promise<void> {
  await mkdir(join(file, '..'), { recursive: true });
  await writeFile(file, body, 'utf8');
  await fx.hook('post-tool-use', {
    session_id: session,
    hook_event_name: 'PostToolUse',
    tool_name: 'Write',
    tool_input: { file_path: file, content: body },
    tool_response: { ok: true },
  });
}

/** PostToolUse(Bash) — the hub only sees "a Bash ran", never what it did. */
async function didBash(fx: HubFixture, session: string, cwd: string): Promise<void> {
  await fx.hook('post-tool-use', {
    session_id: session,
    hook_event_name: 'PostToolUse',
    tool_name: 'Bash',
    cwd,
    tool_input: { command: "sed -i '' s/a/b/ file" },
    tool_response: { ok: true },
  });
}

async function tryEdit(fx: HubFixture, session: string, file: string): Promise<Record<string, any>> {
  return fx.hookJson('pre-tool-use', {
    session_id: session,
    hook_event_name: 'PreToolUse',
    tool_name: 'Edit',
    tool_input: { file_path: file },
  });
}

function denied(out: Record<string, any>): boolean {
  return out.hookSpecificOutput?.permissionDecision === 'deny';
}

function reason(out: Record<string, any>): string {
  return String(out.hookSpecificOutput?.permissionDecisionReason ?? '');
}

async function whose(fx: HubFixture, path: string): Promise<{ line: string; json: any }> {
  const line = await fx.api('GET', `/v1/whose?format=line&path=${encodeURIComponent(path)}`);
  const json = await fx.api('GET', `/v1/whose?path=${encodeURIComponent(path)}`);
  return { line: line.text.trim(), json: json.json };
}

/** Pretend the session has been silent for `ms` (no hook may touch it after). */
function idleFor(fx: HubFixture, session: string, ms: number): void {
  fx.hub.store.heartbeat(session, Date.now() - ms);
}

/* ---------------- attribution ---------------- */

test('a Write by session A stays A, even when session B runs Bash right after', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('one');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);
  await startSession(fx, 'bbbb2222', repo.path);

  const x = join(repo.path, 'x.ts');
  await didWrite(fx, 'aaaa1111', x, 'export const x = 1;\n');
  await didBash(fx, 'bbbb2222', repo.path);

  const { line, json } = await whose(fx, x);
  assert.equal(json.owner.session, 'aaaa1111', `a new file from Write belongs to A, got: ${line}`);
  assert.equal(json.owner.via, 'edit');
  assert.equal(json.guard_blocks, true);
  assert.match(line, /^x\.ts aaaa edit /);
  assert.match(line, /guard:blocks/);

  // The guard still protects A's work against B.
  const out = await tryEdit(fx, 'bbbb2222', x);
  assert.equal(denied(out), true, 'B must not overwrite the uncommitted Write from A');
  assert.match(reason(out), /Edit\/Write/);
});

test('a file from session B\'s Bash without a foreign edit belongs to B but does not block A', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('two');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);
  await startSession(fx, 'bbbb2222', repo.path);

  const y = join(repo.path, 'y.ts');
  await writeFile(y, 'export const y = 2;\n', 'utf8');
  await didBash(fx, 'bbbb2222', repo.path);

  const { json } = await whose(fx, y);
  assert.equal(json.owner.session, 'bbbb2222');
  assert.equal(json.owner.via, 'bash');
  assert.equal(json.guard_blocks, false, 'a bash guess never blocks');

  const out = await tryEdit(fx, 'aaaa1111', y);
  assert.equal(denied(out), false, `a bash owner must not block, got: ${JSON.stringify(out)}`);
  // The note rides on the next PostToolUse, once per file.
  const note = await fx.hook('post-tool-use', {
    session_id: 'aaaa1111',
    hook_event_name: 'PostToolUse',
    tool_name: 'Read',
    tool_input: {},
  });
  assert.match(note.text, /a change from Bash|ambiguous/, `info in PostToolUse: ${note.text}`);
  const again = await tryEdit(fx, 'aaaa1111', y);
  assert.equal(denied(again), false);
  const second = await fx.hook('post-tool-use', {
    session_id: 'aaaa1111',
    hook_event_name: 'PostToolUse',
    tool_name: 'Read',
    tool_input: {},
  });
  assert.doesNotMatch(second.text, /a change from Bash/, 'the info about the same file comes once');
});

test('concurrent Bash by A and B in one checkout → ambiguous, no owner', async (t) => {
  // 40 ms delay: both attribution passes are in flight at the same time, which
  // is exactly the production race (two agents, one checkout, one git status).
  const fx = await startTestHub({}, { bashDelayMs: 40 });
  const repo = await makeCommittedRepo('three');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);
  await startSession(fx, 'bbbb2222', repo.path);

  const z = join(repo.path, 'z.ts');
  await writeFile(z, 'export const z = 3;\n', 'utf8');
  await Promise.all([didBash(fx, 'aaaa1111', repo.path), didBash(fx, 'bbbb2222', repo.path)]);

  const { json } = await whose(fx, z);
  assert.equal(json.owner.via, 'ambiguous', `either could have done it, so nobody: ${JSON.stringify(json.owner)}`);
  assert.equal(json.guard_blocks, false);
  assert.equal(denied(await tryEdit(fx, 'aaaa1111', z)), false);
  assert.equal(denied(await tryEdit(fx, 'bbbb2222', z)), false);
});

test('the lock disappears once the file is clean in git again', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('four');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);
  await startSession(fx, 'bbbb2222', repo.path);

  const w = join(repo.path, 'w.ts');
  await didWrite(fx, 'aaaa1111', w);
  assert.equal(denied(await tryEdit(fx, 'bbbb2222', w)), true, 'while the change is in git, the lock holds');

  // A reverts the change (the new file is simply gone) — nothing in git status.
  await rm(w);
  // The checkout key is the realpath the hook recorded, not the fixture path
  // (`/var/folders/…` vs `/private/var/folders/…` on macOS).
  const checkout = fx.hub.store.getSession('aaaa1111')?.checkout as string;
  await fx.hub.gitCache.refresh(checkout, 'acme');

  const { json } = await whose(fx, w);
  assert.equal(json.owner, null, 'a clean file has no owner');
  assert.equal(denied(await tryEdit(fx, 'bbbb2222', w)), false, 'the lock over a clean file does not hold');
  assert.ok(
    fx.logs.some((l) => l.includes('touched released')),
    'the release is in the log',
  );
});

test('A8-6: a refresh does NOT clear a lock on a gitignored file — git status never shows it', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('five');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await repo.commit('chore: ignore secrets', { '.gitignore': 'secret.env\n' });
  await fx.hub.ledger.registerRepo({ slug: 'acme5', prefix: 'ACME5', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);
  await startSession(fx, 'bbbb2222', repo.path);

  const secret = join(repo.path, 'secret.env');
  await didWrite(fx, 'aaaa1111', secret, 'TOKEN=x\n');
  assert.equal(denied(await tryEdit(fx, 'bbbb2222', secret)), true, 'a lock on a gitignored file holds');

  const checkout = fx.hub.store.getSession('aaaa1111')?.checkout as string;
  await fx.hub.gitCache.refresh(checkout, 'acme5');

  // `secret.env` is gitignored: `git status` never lists it, not even as
  // untracked — the file STILL EXISTS unchanged, so this must not look like
  // the "reverted/deleted" case.
  const { json } = await whose(fx, secret);
  assert.notEqual(json.owner, null, 'a refresh must not unlock a gitignored file');
  assert.equal(denied(await tryEdit(fx, 'bbbb2222', secret)), true, 'the lock must survive the reconcile');
});

test('an owner idle > 2 h lets others through with a warning and an adopt hint', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('five');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);
  await startSession(fx, 'bbbb2222', repo.path);

  const f = join(repo.path, 'stale.ts');
  await didWrite(fx, 'aaaa1111', f);
  assert.equal(denied(await tryEdit(fx, 'bbbb2222', f)), true, 'an active owner blocks');

  idleFor(fx, 'aaaa1111', STALE_OWNER_MS + 60_000);
  const out = await tryEdit(fx, 'bbbb2222', f);
  assert.equal(denied(out), false, `an idle owner does not block, got: ${JSON.stringify(out)}`);
  const note = await fx.hook('post-tool-use', {
    session_id: 'bbbb2222',
    hook_event_name: 'PostToolUse',
    tool_name: 'Read',
    tool_input: {},
  });
  assert.match(note.text, /ledger adopt/, `the warning suggests adopt: ${note.text}`);
  const { json } = await whose(fx, f);
  assert.equal(json.guard_blocks, false, 'whose reports that the guard no longer blocks');
});

/* ---------------- claims ---------------- */

test('claim app/src/** does not block app/src/auth/x.ts, it only warns', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('six');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);
  await startSession(fx, 'bbbb2222', repo.path);

  const item = await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'billing wallet',
    kind: 'BACKLOG',
    priority: 'P1',
  });
  const claim = await fx.api('POST', `/v1/items/${item.json.id}/claim`, {
    session: 'aaaa1111',
    paths: ['app/src/**'],
    intent: 'billing',
  });
  assert.equal(claim.status, 200, claim.text);
  assert.ok(
    (claim.json.warnings as string[]).some((w) => w.includes('whole tree')),
    `a broad claim gets a warning: ${JSON.stringify(claim.json.warnings)}`,
  );

  const target = join(repo.path, 'app', 'src', 'auth', 'x.ts');
  const out = await tryEdit(fx, 'bbbb2222', target);
  assert.equal(denied(out), false, `a claim glob must not block: ${JSON.stringify(out)}`);
  const note = await fx.hook('post-tool-use', {
    session_id: 'bbbb2222',
    hook_event_name: 'PostToolUse',
    tool_name: 'Read',
    tool_input: {},
  });
  assert.match(note.text, /in the claim of/, `warning about the claim: ${note.text}`);

  const { json } = await whose(fx, target);
  assert.equal(json.claims.length, 1);
  assert.equal(json.claims[0].pattern, 'app/src/**');
  assert.equal(json.guard_blocks, false);
});

test('the claim of an idle session (> 4 h) expires on sweep', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('seven');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: repo.path, onboarded: true });
  await startSession(fx, 'aaaa1111', repo.path);

  const item = await fx.api('POST', '/v1/items', {
    repo: 'acme',
    title: 'long claim',
    kind: 'BACKLOG',
    priority: 'P2',
  });
  await fx.api('POST', `/v1/items/${item.json.id}/claim`, {
    session: 'aaaa1111',
    paths: ['app/src/billing/**'],
  });
  assert.equal(fx.hub.store.listLeases({ session: 'aaaa1111', active: true }).length, 1);

  idleFor(fx, 'aaaa1111', LEASE_IDLE_MS + 60_000);
  await fx.hub.sweep();

  assert.equal(
    fx.hub.store.listLeases({ session: 'aaaa1111', active: true }).length,
    0,
    'the lease of an idle session is released',
  );
  const journal = fx.hub.ledger.listJournal().map((e) => e.type);
  assert.ok(journal.includes('lease.expire'), `the expiry is in the journal: ${journal.join(',')}`);
});

/* ---------------- startup migration ---------------- */

test('migration of old bash rows (an edit owner wins, the rest become ambiguous)', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const store = fx.hub.store;
  const checkout = '/tmp/checkout-x';
  for (const id of ['aaaa1111', 'bbbb2222']) {
    store.upsertSession({
      id,
      home_repo: 'acme',
      cwd: checkout,
      checkout,
      branch: 'main',
      transcript_path: null,
      source: 'startup',
    });
  }
  store.touch({ session_id: 'aaaa1111', repo: 'acme', checkout, rel_path: 'a.ts', via: 'edit' });
  store.touch({ session_id: 'bbbb2222', repo: 'acme', checkout, rel_path: 'a.ts', via: 'bash' });
  store.touch({ session_id: 'bbbb2222', repo: 'acme', checkout, rel_path: 'b.ts', via: 'bash' });

  const res = store.migrateWeakTouched();
  assert.equal(res.droppedOwnedByEdit, 1, 'a bash row for a file with an edit owner is dropped');
  assert.equal(res.requalified, 1, 'an unconfirmable bash row becomes ambiguous');

  const owners = store.ownersOfPath(checkout, 'a.ts');
  assert.deepEqual(
    owners.map((o) => [o.session_id, o.via]),
    [['aaaa1111', 'edit']],
  );
  assert.equal(store.ownersOfPath(checkout, 'b.ts')[0]?.via, 'ambiguous');
});
