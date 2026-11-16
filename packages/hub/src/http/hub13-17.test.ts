/**
 * (dedupe + title limits), (session titles), (already-done
 * + delta feed) at the HTTP boundary.
 *
 * These are one file because they share a fixture shape: a hub, two sessions,
 * and a transcript on disk. Splitting them would mean three copies of the same
 * setup.
 */

import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { makeCodeRepo, startTestHub } from '../test-helpers.ts';
import { skipOnWin32 } from '@agent-ledger/shared/testing';

/** A minimal Claude Code transcript. `custom-title` repeats — the last wins. */
function transcript(lines: Record<string, unknown>[]): string {
  return `${lines.map((l) => JSON.stringify(l)).join('\n')}\n`;
}

async function writeTranscript(
  dir: string,
  name: string,
  lines: Record<string, unknown>[],
): Promise<string> {
  const file = join(dir, name);
  await mkdir(dir, { recursive: true });
  await writeFile(file, transcript(lines), 'utf8');
  return file;
}

/* ---------------- --------------- */

test('shortening an item\'s own title (PATCH) does not collide with itself', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const item = await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'Production without content — portfolio, demos, catalog and blog return nothing',
  });
  assert.equal(item.status, 201, item.text);
  const id = item.json.item.id as string;

  const renamed = await fx.api('PATCH', `/v1/items/${id}`, { title: 'Production without content' });
  assert.equal(renamed.status, 200, renamed.text);
  assert.equal(renamed.json.item.title, 'Production without content');
});

test('renaming does not run into ALREADY_DONE of a closed item', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const old = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Production without content test3' });
  assert.equal(old.status, 201, old.text);
  const dropped = await fx.api('POST', `/v1/items/${old.json.item.id}/drop`, { why: 'test item' });
  assert.ok(dropped.status < 300, dropped.text);

  const item = await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'Portfolio, demos, catalog and blog in production return empty fields',
    force: true,
  });
  assert.equal(item.status, 201, item.text);
  const renamed = await fx.api('PATCH', `/v1/items/${item.json.item.id}`, { title: 'Production without content' });
  assert.equal(renamed.status, 200, renamed.text);
});

test('an almost identical title is 409 DUPLICATE with candidates', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const first = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Production without content' });
  assert.equal(first.status, 201, first.text);

  const dup = await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'Production without content test3',
  });
  assert.equal(dup.status, 409, dup.text);
  assert.equal(dup.json.error, 'DUPLICATE');
  assert.equal(dup.json.candidates.length, 1);
  assert.equal(dup.json.candidates[0].id, first.json.item.id);
  assert.ok(dup.json.candidates[0].score >= 0.65, `score ${dup.json.candidates[0].score}`);

  // `force` is the escape hatch — a human looked at the candidates.
  const forced = await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'Production without content test3',
    force: true,
  });
  assert.equal(forced.status, 201, forced.text);
});

test('an unrelated item in the same repo passes', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  assert.equal(
    (await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Add index on items.repo' })).status,
    201,
  );
  const other = await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'Add index on items.session',
  });
  assert.equal(other.status, 201, `a different column is different work: ${other.text}`);
});

test('a closed item does not block as DUPLICATE (that is ALREADY_DONE)', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const created = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'One-off thing' });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'aaaa1111' });
  assert.equal((await fx.api('POST', `/v1/items/${id}/done`, {})).status, 200);

  const again = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'One-off thing' });
  assert.equal(again.status, 409, again.text);
  assert.equal(again.json.error, 'ALREADY_DONE', 'closed → ALREADY_DONE, not DUPLICATE');
  assert.equal(again.json.candidates[0].id, id);
  assert.equal(again.json.candidates[0].status, 'done');
  assert.ok(again.json.candidates[0].closed_at, 'the candidate carries the closing time');
});

test('a title over 80 characters is 422 with a hint about --why', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const long = 'a'.repeat(81);
  const res = await fx.api('POST', '/v1/items', { repo: 'ops', title: long });
  assert.equal(res.status, 422, res.text);
  assert.match(res.json.message, /at most 80 characters/);
  assert.match(res.json.message, /--why/);

  // Exactly 80 is fine.
  assert.equal(
    (await fx.api('POST', '/v1/items', { repo: 'ops', title: 'b'.repeat(80) })).status,
    201,
  );
});

test('GET /v1/dups finds pairs among open items', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Production without content' });
  await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'Production without content test3',
    force: true,
  });
  await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Something entirely different about sessions' });

  const res = await fx.api('GET', '/v1/dups?repo=ops');
  assert.equal(res.status, 200, res.text);
  assert.equal(res.json.pairs.length, 1, res.text);
  assert.ok(res.json.pairs[0].score >= 0.65);
});

test('PATCH with a new title also checks for duplicates', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Production without content' });
  const other = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Completely different thing' });
  const id = other.json.item.id as string;

  const renamed = await fx.api('PATCH', `/v1/items/${id}`, { title: 'Production without content test3' });
  assert.equal(renamed.status, 409, renamed.text);
  assert.equal(renamed.json.error, 'DUPLICATE');

  // Renaming to something unrelated still works.
  assert.equal((await fx.api('PATCH', `/v1/items/${id}`, { title: 'A new different title' })).status, 200);
});

/* ---------------- --------------- */

test('session-start reads the title from the transcript (custom-title, the last one wins)', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const file = await writeTranscript(join(fx.dir, 'tr'), 'a.jsonl', [
    { type: 'summary', summary: 'some summary' },
    { type: 'custom-title', customTitle: 'First title', sessionId: 'aaaa1111' },
    { type: 'custom-title', customTitle: 'Write queue during an outage', sessionId: 'aaaa1111' },
  ]);

  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: fx.dir, transcript_path: file });
  const res = await fx.api('GET', '/v1/sessions');
  const s = (res.json.sessions as { id: string; title: string; title_source: string }[]).find(
    (x) => x.id === 'aaaa1111',
  );
  assert.ok(s, res.text);
  assert.equal(s?.title, 'Write queue during an outage');
  assert.equal(s?.title_source, 'claude');
});

test('without custom-title the summary is used, then the first message', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);

  const summaryFile = await writeTranscript(join(fx.dir, 'tr'), 'sum.jsonl', [
    { type: 'summary', summary: 'Oprava dedupe v hube' },
  ]);
  await fx.hook('session-start', {
    session_id: 'bbbb2222',
    cwd: fx.dir,
    transcript_path: summaryFile,
  });

  const promptFile = await writeTranscript(join(fx.dir, 'tr'), 'prompt.jsonl', [
    { type: 'user', message: { content: 'Build me a write queue for a hub outage' } },
  ]);
  await fx.hook('session-start', {
    session_id: 'cccc3333',
    cwd: fx.dir,
    transcript_path: promptFile,
  });

  const sessions = (await fx.api('GET', '/v1/sessions')).json.sessions as {
    id: string;
    title: string | null;
    title_source: string | null;
  }[];
  const b = sessions.find((s) => s.id === 'bbbb2222');
  const c = sessions.find((s) => s.id === 'cccc3333');
  assert.equal(b?.title, 'Oprava dedupe v hube');
  assert.equal(b?.title_source, 'summary');
  assert.equal(c?.title, 'Build me a write queue for a hub outage');
  assert.equal(c?.title_source, 'prompt');
});

test('a transcript outside the allowed roots is not read', { skip: skipOnWin32("uses /tmp (POSIX path)") }, async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  // `transcriptRoots` is the fixture dir; `/tmp` is outside it.
  const outside = join('/tmp', `agent-ledger-outside-${process.pid}.jsonl`);
  await writeFile(outside, transcript([{ type: 'custom-title', customTitle: 'Must not be read' }]));

  await fx.hook('session-start', { session_id: 'dddd4444', cwd: fx.dir, transcript_path: outside });
  const sessions = (await fx.api('GET', '/v1/sessions')).json.sessions as {
    id: string;
    title: string | null;
  }[];
  assert.equal(sessions.find((s) => s.id === 'dddd4444')?.title, null);
});

test('a title with a secret is not stored', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const file = await writeTranscript(join(fx.dir, 'tr'), 'secret.jsonl', [
    {
      type: 'custom-title',
      customTitle: `deploy s ghp_${'A1bCdEfGhIjKlMnOpQrStUvWxYz01'}`,
    },
  ]);
  await fx.hook('session-start', { session_id: 'eeee5555', cwd: fx.dir, transcript_path: file });
  const sessions = (await fx.api('GET', '/v1/sessions')).json.sessions as {
    id: string;
    title: string | null;
    title_source: string | null;
  }[];
  const s = sessions.find((x) => x.id === 'eeee5555');
  assert.equal(s?.title, null, 'secret scan → no title');
  assert.equal(s?.title_source, null);
});

test('the title shows up in `who` and in `ledger sessions`', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  // A registered checkout: without one the session has no home repo and `who`
  // legitimately reports nobody.
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });

  const file = await writeTranscript(join(fx.dir, 'tr'), 'guard.jsonl', [
    { type: 'custom-title', customTitle: 'I hold this file' },
  ]);
  await fx.hook('session-start', {
    session_id: 'ffff6666',
    cwd: repo.path,
    transcript_path: file,
  });

  // `Live:` columns print the bare tag — the word "session" belongs to prose
  // (deny reasons, delta lines), not to a column that already says `Live:`.
  const who = await fx.api('GET', '/v1/repos/app/who?format=line');
  // R3-04: every non-null title is unconditionally marked untrusted now, not
  // just ones matching the old instruction-keyword denylist.
  assert.match(who.text, /Live: "I hold this file" \(session title, unverified\) \(ffff\)/, who.text);

  const sessionsLine = await fx.api('GET', '/v1/sessions?format=line');
  assert.match(sessionsLine.text, /I hold this file/, sessionsLine.text);
});

/* ---------------- contract for the new UI (item 4) ---------------- */

test('contract: repo as a list, session=, q= on /v1/items', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const a = await fx.api('POST', '/v1/items', {
    repo: 'ops',
    title: 'Accents in a title façade',
    session: 'aaaa1111',
  });
  await fx.api('POST', '/v1/items', { repo: 'ops', title: 'No accents', session: 'bbbb2222' });

  // `q` ignores case and diacritics.
  const q = await fx.api('GET', '/v1/items?repo=ops&q=facade');
  assert.equal((q.json.items as unknown[]).length, 1, q.text);
  assert.equal((q.json.items as { id: string }[])[0]?.id, a.json.item.id);

  // `session` matches source.session as well as claimed_by.session.
  const bySession = await fx.api('GET', '/v1/items?repo=ops&session=bbbb2222');
  assert.equal((bySession.json.items as { title: string }[])[0]?.title, 'No accents');

  // A comma list of repos is accepted; an unknown slug 404s rather than silently
  // returning nothing.
  assert.equal((await fx.api('GET', '/v1/items?repo=ops,ops')).status, 200);
  assert.equal((await fx.api('GET', '/v1/items?repo=ops,missing')).status, 404);

  // Every item carries `last_reply`, even with no replies at all.
  const all = await fx.api('GET', '/v1/items?repo=ops');
  for (const item of all.json.items as { last_reply: unknown }[]) {
    assert.equal(item.last_reply, null);
  }
});

test('contract: /v1/sessions and /v1/timeline take repo=a,b', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: fx.dir });
  assert.equal((await fx.api('GET', '/v1/sessions?repo=ops')).status, 200);
  assert.equal((await fx.api('GET', '/v1/sessions?repo=ops,ops&live=1')).status, 200);
  assert.equal((await fx.api('GET', '/v1/timeline?repo=ops,ops')).status, 200);
  assert.equal((await fx.api('GET', '/v1/timeline?repo=missing')).status, 404);
});

test('contract: healthz carries spool counts', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const res = await fx.api('GET', '/v1/healthz');
  assert.equal(res.status, 200);
  assert.equal(typeof res.json.spool.queued, 'number', res.text);
  assert.equal(typeof res.json.spool.failed, 'number');
});

/* ---------------- delta feed ---------------- */

test('A gets a delta about what B closed, and its add is ALREADY_DONE', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });

  const titleB = await writeTranscript(join(fx.dir, 'tr'), 'b.jsonl', [
    { type: 'custom-title', customTitle: 'Session B' },
  ]);

  // Both sessions live in the same repo — that is what makes B's change
  // relevant to A.
  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: repo.path });
  await fx.hook('session-start', {
    session_id: 'bbbb2222',
    cwd: repo.path,
    transcript_path: titleB,
  });

  // First prompt of A only starts A's clock — it must show nothing.
  const firstPrompt = await fx.hook('user-prompt-submit', { session_id: 'aaaa1111' });
  assert.ok(
    !firstPrompt.text.includes('Ledger changes'),
    `the first prompt must not dump the whole journal: ${firstPrompt.text}`,
  );

  // B creates and closes an item.
  const created = await fx.api('POST', '/v1/items', {
    repo: 'app',
    title: 'Missing certificate for the demo host',
    session: 'bbbb2222',
  });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'bbbb2222' });
  await fx.api('POST', `/v1/items/${id}/done`, { session: 'bbbb2222', ref: 'abc1234' });

  // A's next prompt carries the delta.
  const second = await fx.hook('user-prompt-submit', { session_id: 'aaaa1111' });
  assert.match(second.text, /Ledger changes \(app\) since your last message:/, second.text);
  assert.match(second.text, new RegExp(`${id} done`), second.text);
  assert.match(second.text, /session "Session B" \(session title, unverified\) \(bbbb\)/, second.text);
  assert.match(second.text, /abc1234/, second.text);

  // Delivered once: the cursor moved.
  const third = await fx.hook('user-prompt-submit', { session_id: 'aaaa1111' });
  assert.ok(!third.text.includes('Ledger changes'), `the delta must not repeat: ${third.text}`);

  // And A cannot re-log the same thing.
  const again = await fx.api('POST', '/v1/items', {
    repo: 'app',
    title: 'Missing certificate for the demo host',
    session: 'aaaa1111',
  });
  assert.equal(again.status, 409, again.text);
  assert.equal(again.json.error, 'ALREADY_DONE');
  assert.equal(again.json.candidates[0].id, id);
  assert.equal(again.json.candidates[0].commit, 'abc1234');
});

test('a session\'s own changes do not show in the delta', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });
  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: repo.path });
  await fx.hook('user-prompt-submit', { session_id: 'aaaa1111' });

  await fx.api('POST', '/v1/items', {
    repo: 'app',
    title: 'My own change',
    session: 'aaaa1111',
  });
  const next = await fx.hook('user-prompt-submit', { session_id: 'aaaa1111' });
  assert.ok(!next.text.includes('My own change'), next.text);
});

/* ---------------- reply → session inbox E2E ---------------- */

test('E2E — a web reply is delivered to the session, last_reply in the list tracks the states', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const repo = await makeCodeRepo();
  t.after(repo.cleanup);
  await fx.api('POST', '/v1/repos', { slug: 'app', prefix: 'AP', path: repo.path });
  await fx.hook('session-start', { session_id: 'aaaa1111', cwd: repo.path });

  const created = await fx.api('POST', '/v1/items', { repo: 'app', title: 'E2E reply delivery' });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'aaaa1111' });

  // POST reply — session is live, so it is delivered immediately.
  const reply = await fx.api('POST', `/v1/items/${id}/reply`, { text: 'Do it now.' });
  assert.equal(reply.status, 201, reply.text);
  assert.equal(reply.json.reply.status, 'delivered');
  assert.equal(reply.json.reply.target_session, 'aaaa1111');

  // The LIST endpoint carries last_reply with the correct status — this is what
  // ReplyStatusChip in the web UI reads to show the badge.
  type Row = { id: string; last_reply: { status: string; id: string } | null };
  const listAfter = await fx.api('GET', '/v1/items?repo=app');
  const row = (listAfter.json.items as Row[]).find((i) => i.id === id);
  assert.ok(row?.last_reply, 'the list must carry last_reply after a reply is sent');
  assert.equal(row.last_reply!.id, reply.json.reply.id, 'last_reply.id must match');
  assert.equal(row.last_reply!.status, 'delivered');

  // The session inbox carries the reply text on the next prompt.
  const prompt = await fx.hook('user-prompt-submit', { session_id: 'aaaa1111' });
  assert.match(prompt.text, /Do it now\./, 'the inbox carries the reply text');
  assert.match(prompt.text, new RegExp(id), 'the inbox carries the item ID');

  // Session picks up the reply (posts comment) → working.
  await fx.api('POST', `/v1/items/${id}/comments`, {
    session: 'aaaa1111',
    author: 'orchestrator',
    text: 'working on it',
  });
  type RowS = { id: string; last_reply: { status: string } | null };
  const listWorking = await fx.api('GET', '/v1/items?repo=app');
  const rowWorking = (listWorking.json.items as RowS[]).find((i) => i.id === id);
  assert.equal(rowWorking?.last_reply?.status, 'working');

  // Done → last_reply.status = done via item detail (item is now closed).
  await fx.api('POST', `/v1/items/${id}/done`, { session: 'aaaa1111' });
  const detail = await fx.api('GET', `/v1/items/${id}`);
  assert.equal((detail.json.item.last_reply as { status: string }).status, 'done');
});

test('GET /v1/check writes nothing and also returns closed items', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const created = await fx.api('POST', '/v1/items', { repo: 'ops', title: 'Thing being checked' });
  const id = created.json.item.id as string;
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'aaaa1111' });
  await fx.api('POST', `/v1/items/${id}/done`, {});

  const before = (await fx.api('GET', '/v1/items?repo=ops')).json.items.length as number;
  const check = await fx.api('GET', `/v1/check?repo=ops&title=${encodeURIComponent('Thing being checked')}`);
  assert.equal(check.status, 200, check.text);
  assert.equal(check.json.matches[0].id, id);
  assert.equal(check.json.matches[0].status, 'done');
  const after = (await fx.api('GET', '/v1/items?repo=ops')).json.items.length as number;
  assert.equal(after, before, 'check must not write anything');
});
