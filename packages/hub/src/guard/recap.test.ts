/** Stop recap check (SPEC §10.2). */

import assert from 'node:assert/strict';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { startTestHub } from '../test-helpers.ts';
import {
  buildTagRe,
  chainStable,
  checkRecap,
  lastAssistantText,
  offendingLines,
  parentChain,
  resolveRoots,
  snapshotChain,
} from './recap.ts';

function entry(text: string): string {
  return `${JSON.stringify({ type: 'assistant', message: { role: 'assistant', content: [{ type: 'text', text }] } })}\n`;
}

test('offendingLines: a tag without an ID blocks, a tag with an ID does not', () => {
  assert.deepEqual(offendingLines('- [BLOCKER] deploy needs authorization'), [
    '- [BLOCKER] deploy needs authorization',
  ]);
  assert.deepEqual(offendingLines('- [BLOCKER] ACME-142 deploy authorization'), []);
  assert.deepEqual(offendingLines('- [DEPLOY] ACME-13 migration'), []);
  assert.deepEqual(offendingLines('- [RISK] nothing was tested'), ['- [RISK] nothing was tested']);
  assert.deepEqual(offendingLines('- [UNVERIFIED] test missing'), ['- [UNVERIFIED] test missing']);
  assert.deepEqual(offendingLines('All done, nothing left.'), [], 'no tag, nothing');
  assert.deepEqual(offendingLines('the word BLOCKER in prose'), [], 'the tag must be in square brackets');
});

test('offendingLines: the ID must be on the SAME line', () => {
  const text = ['## Still left', '- [BLOCKER] authorization missing', 'ACME-142 is elsewhere'].join('\n');
  assert.equal(offendingLines(text).length, 1);
});

test('offendingLines: code in ``` is ignored (a recap example is not a recap)', () => {
  const text = ['```', '- [BLOCKER] example without ID', '```', '- [DEPLOY] ACME-9 ok'].join('\n');
  assert.deepEqual(offendingLines(text), []);
});

test('offendingLines: cap of 10 lines (a long recap does not bloat the reply)', () => {
  const text = Array.from({ length: 30 }, (_, i) => `- [RISK] vec ${i}`).join('\n');
  assert.equal(offendingLines(text).length, 10);
});

test('lastAssistantText: takes the last assistant block, both transcript shapes', () => {
  const jsonl = [
    entry('first reply'),
    `${JSON.stringify({ type: 'user', message: { role: 'user', content: 'question' } })}\n`,
    entry('last reply [RISK] without ID'),
  ].join('');
  assert.match(lastAssistantText(`skip\n${jsonl}`) ?? '', /last reply/);

  const legacy = `skip\n${JSON.stringify({ role: 'assistant', content: 'legacy shape' })}\n`;
  assert.equal(lastAssistantText(legacy), 'legacy shape');
  assert.equal(lastAssistantText('skip\nnot json\n'), null);
});

test('checkRecap: blocks only under allowed roots, otherwise silent', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'agent-ledger-transcripts-'));
  const outside = await mkdtemp(join(tmpdir(), 'agent-ledger-outside-'));
  t.after(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });
  // Like server.ts: roots are realpathed once (on macOS `/var` is a symlink to
  // `/private/var`, so a textual prefix would never match).
  const roots = await resolveRoots([root]);

  const good = join(root, 'session.jsonl');
  await writeFile(good, `skip\n${entry('## Still left\n- [BLOCKER] authorization missing')}`, 'utf8');
  const blocked = await checkRecap(good, [...roots]);
  assert.equal(blocked.block, true);
  assert.equal(blocked.lines.length, 1);

  // The same content outside the roots: `transcript_path` is hook input, so this
  // would otherwise be "read me any file".
  const bad = join(outside, 'session.jsonl');
  await writeFile(bad, `skip\n${entry('- [BLOCKER] authorization missing')}`, 'utf8');
  const skipped = await checkRecap(bad, [...roots]);
  assert.equal(skipped.block, false);
  assert.equal(skipped.skipped, 'outside-roots');

  // A symlink out of an allowed root is resolved by realpath, not by a textual prefix.
  const link = join(root, 'link.jsonl');
  await symlink(bad, link);
  const viaLink = await checkRecap(link, [...roots]);
  assert.equal(viaLink.block, false);
  assert.equal(viaLink.skipped, 'outside-roots');

  assert.equal((await checkRecap(null, [...roots])).skipped, 'no-path');
  assert.equal((await checkRecap(join(root, 'missing.jsonl'), [...roots])).skipped, 'unreadable');
});

test('checkRecap: a clean recap with IDs does not block and only the tail of the file is read', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'agent-ledger-transcripts-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const roots = await resolveRoots([root]);
  const file = join(root, 's.jsonl');
  // 400 KB of filler before the valid end: only the last 256 KB are read, so an
  // older (even bad) recap at the start must not affect anything.
  const filler = `${entry(`- [BLOCKER] old recap without ID ${'x'.repeat(400)}`)}`.repeat(900);
  await writeFile(file, `${filler}${entry('- [DEPLOY] ACME-9 migration · done')}`, 'utf8');
  const res = await checkRecap(file, [...roots]);
  assert.equal(res.block, false, 'the last assistant text is clean');
});

/* ---------------- realpath→open TOCTOU ---------------- */

test('a transcript swapped for a symlink after the check is not read', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const { mkdtemp, rm, writeFile, unlink, symlink, realpath } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');

  const dir = await realpath(await mkdtemp(join(tmpdir(), 'agent-ledger-recap-toctou-')));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const roots = [dir];

  const secret = join(dir, 'outside-secret.jsonl');
  await writeFile(
    secret,
    `${JSON.stringify({ type: 'assistant', message: { content: [{ type: 'text', text: '[BLOCKER] secret without id' }] } })}\n`,
    'utf8',
  );

  // The attacker replaces the validated path with a symlink to another file
  // between the realpath check and the read. `O_NOFOLLOW` must refuse it.
  const transcript = join(dir, 'session.jsonl');
  await writeFile(transcript, '{}\n', 'utf8');
  await unlink(transcript);
  await symlink(secret, transcript);

  const res = await checkRecap(transcript, roots);
  // Following the symlink would have produced `block: true` from the planted
  // line. Refusing to follow it is the fix.
  assert.equal(res.block, false, 'a symlinked transcript must not be followed and read');
});

test('an ordinary transcript still reads normally', async (t) => {
  const { mkdtemp, rm, writeFile, realpath } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');

  const dir = await realpath(await mkdtemp(join(tmpdir(), 'agent-ledger-recap-ok-')));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'session.jsonl');
  await writeFile(
    file,
    [
      '{"type":"user","message":{"content":"hello"}}',
      JSON.stringify({
        type: 'assistant',
        message: { content: [{ type: 'text', text: '## Needs you\n- [BLOCKER] something without id' }] },
      }),
      '',
    ].join('\n'),
    'utf8',
  );
  const res = await checkRecap(file, [dir]);
  assert.equal(res.block, true, 'the normal path must keep working');
  assert.equal(res.skipped, null);
});

test('a hard-linked transcript is refused (aliasing)', async (t) => {
  const { mkdtemp, rm, writeFile, link, realpath } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');

  const dir = await realpath(await mkdtemp(join(tmpdir(), 'agent-ledger-recap-link-')));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'session.jsonl');
  await writeFile(
    file,
    `${JSON.stringify({ type: 'assistant', message: { content: [{ type: 'text', text: '[BLOCKER] without id' }] } })}\n`,
    'utf8',
  );
  await link(file, join(dir, 'alias.jsonl'));
  const res = await checkRecap(file, [dir]);
  assert.equal(res.block, false);
  // H3-2: aliasing (nlink != 1) is its own reason, not folded into generic
  // "unreadable" — it is a signal something else names this file too.
  assert.equal(res.skipped, 'aliased');
});

/* ---------------- H3-1: directory-component swap between check and read ---------------- */

test('H3-1: parentChain walks root → file, excluding the file\'s own basename', async (t) => {
  const { mkdtemp, rm, mkdir, writeFile: write, realpath } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'agent-ledger-recap-chain-')));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, 'a', 'b'), { recursive: true });
  const file = join(dir, 'a', 'b', 'session.jsonl');
  await write(file, '{}\n', 'utf8');

  const chain = parentChain(dir, file);
  assert.deepEqual(chain, [dir, join(dir, 'a'), join(dir, 'a', 'b')]);
});

test('H3-1: chainStable(false) when a directory in the chain is swapped for a symlink', { skip: skipOnWin32('POSIX-only: symlink/chmod/mode bits/uid/shell stubs') }, async (t) => {
  const { mkdtemp, rm, mkdir, writeFile: write, realpath, symlink } = await import(
    'node:fs/promises'
  );
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'agent-ledger-recap-chain-swap-')));
  t.after(() => rm(dir, { recursive: true, force: true }));

  await mkdir(join(dir, 'sub'), { recursive: true });
  const file = join(dir, 'sub', 'session.jsonl');
  await write(file, '{}\n', 'utf8');
  const elsewhere = join(dir, 'elsewhere');
  await mkdir(elsewhere, { recursive: true });

  const chain = parentChain(dir, file);
  const before = await snapshotChain(chain);
  assert.ok(before !== null);
  assert.ok(before.every((s) => !s.isSymlink), 'precondition: nothing is a symlink yet');

  // The swap this closes: `sub` (a plain directory a moment ago) is now a
  // symlink to a different directory — same name, different identity.
  await rm(join(dir, 'sub'), { recursive: true, force: true });
  await symlink(elsewhere, join(dir, 'sub'));

  const after = await snapshotChain(chain);
  assert.ok(after !== null);
  assert.equal(chainStable(before as NonNullable<typeof before>, after as NonNullable<typeof after>), false);
});

/* ---------------- H3-2: aliased/unreadable are logged, not a silent PASS ---------------- */

test('H3-2: the Stop hook logs when the recap check is skipped as aliased', async (t) => {
  const { Hooks } = await import('../hooks.ts');
  const { mkdtemp, rm, writeFile: write, link, realpath } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'agent-ledger-recap-log-')));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'session.jsonl');
  await write(file, `${JSON.stringify({ type: 'assistant', message: { content: [{ type: 'text', text: 'ok' }] } })}\n`, 'utf8');
  await link(file, join(dir, 'alias.jsonl'));

  const logs: string[] = [];
  const sessions = { heartbeat: () => undefined, refreshTitle: async () => undefined };
  const ledger = { log: (l: string) => logs.push(l) };
  const hooks = new Hooks({
    // Minimal deps — Stop only needs `sessions.heartbeat`, `ledger.log` and
    // `transcriptRoots` before it reaches the recap check.
    ledger: ledger as unknown as ConstructorParameters<typeof Hooks>[0]['ledger'],
    store: {} as unknown as ConstructorParameters<typeof Hooks>[0]['store'],
    sessions: sessions as unknown as ConstructorParameters<typeof Hooks>[0]['sessions'],
    gitCache: {} as unknown as ConstructorParameters<typeof Hooks>[0]['gitCache'],
    transcriptRoots: [dir],
    recapGuard: true,
  });
  await hooks.handle('stop', {
    session_id: 'sess-aliased',
    transcript_path: file,
  } as Parameters<typeof hooks.handle>[1]);

  assert.ok(
    logs.some((l) => l.includes('sess-aliased') && l.includes('aliased')),
    `expected an aliased log line, got: ${JSON.stringify(logs)}`,
  );
});

/* ---------------- configurable tags + feature flag ---------------- */

test('buildTagRe: defaults, custom tags, regex metacharacters stay literal', () => {
  assert.ok(buildTagRe().test('- [RISK] x'));
  assert.ok(buildTagRe([]).test('- [BLOCKER] x'), 'an empty list falls back to the defaults');
  const custom = buildTagRe(['TODO', 'NEEDS-YOU']);
  assert.ok(custom.test('- [TODO] ship it'));
  assert.ok(custom.test('- [NEEDS-YOU] decide'));
  assert.equal(custom.test('- [BLOCKER] x'), false, 'default tags no longer apply');
  assert.equal(buildTagRe(['A.B']).test('[AxB]'), false, 'a dot in a tag is a literal dot');
  assert.ok(buildTagRe(['A.B']).test('[A.B]'));
});

test('offendingLines / checkRecap: custom tags replace the default ones', async (t) => {
  const custom = buildTagRe(['TODO']);
  assert.deepEqual(offendingLines('- [TODO] write docs', custom), ['- [TODO] write docs']);
  assert.deepEqual(offendingLines('- [TODO] ACME-5 write docs', custom), []);
  assert.deepEqual(offendingLines('- [BLOCKER] no id', custom), [], '[BLOCKER] is not a tag here');

  const root = await mkdtemp(join(tmpdir(), 'agent-ledger-recap-tags-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const roots = await resolveRoots([root]);
  const file = join(root, 's.jsonl');
  await writeFile(file, `skip\n${entry('- [TODO] write docs')}`, 'utf8');
  assert.equal((await checkRecap(file, [...roots], ['TODO'])).block, true);
  assert.equal((await checkRecap(file, [...roots], ['RISK'])).block, false);
  assert.equal((await checkRecap(file, [...roots])).block, false, 'default tags do not include TODO');
});

test('Stop hook: recapGuard off → nothing is checked; custom recapTags apply', async (t) => {
  const roots = await mkdtemp(join(tmpdir(), 'agent-ledger-stop-flag-'));
  const off = await startTestHub({ transcriptRoots: [roots], recapGuard: false });
  const custom = await startTestHub({ transcriptRoots: [roots], recapTags: ['TODO'] });
  t.after(async () => {
    await off.cleanup();
    await custom.cleanup();
    await rm(roots, { recursive: true, force: true });
  });
  const transcript = join(roots, 'session.jsonl');
  const stop = { session_id: 'aaaa1111', hook_event_name: 'Stop', transcript_path: transcript };

  await writeFile(transcript, `x\n${entry('- [BLOCKER] missing authorization')}`, 'utf8');
  assert.deepEqual(await off.hookJson('stop', stop), {}, 'flag off: a tag without an ID does not block');
  assert.equal((await custom.hookJson('stop', stop)).decision, undefined, '[BLOCKER] is not a custom tag');

  await writeFile(transcript, `x\n${entry('- [TODO] write docs')}`, 'utf8');
  assert.equal((await custom.hookJson('stop', stop)).decision, 'block', 'a custom tag without an ID blocks');
  assert.deepEqual(await off.hookJson('stop', stop), {}, 'flag off: still silent');
});
