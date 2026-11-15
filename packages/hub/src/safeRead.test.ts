/**
 * The hardened reader, and the proof that
 * `transcript.ts` now goes through it instead of opening by name.
 *
 * The old `transcript.ts` read the hook-supplied `transcript_path` with a
 * plain `stat`-then-`open` pair, so anything that could place entries next to
 * the transcript (the transcript directory is not the hub's alone) could swap
 * the final component — or a parent directory — between the root check and the
 * read, and get arbitrary file content into a session title that is stored in
 * the DB and rendered in the web UI. The checks below are what makes that a
 * refusal rather than a read.
 */

import assert from 'node:assert/strict';
import { link, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { matchedRoot, parentChain, readHeadVerified, readTailVerified, resolveRoots, snapshotChain } from './safeRead.ts';
import { readTranscriptTitle } from './transcript.ts';

interface Fixture {
  root: string;
  dir: string;
  file: string;
  roots: string[];
  cleanup: () => Promise<void>;
}

/** `<root>/proj/session.jsonl`, so there is a real parent component between
 *  the root and the file for the chain check to have something to say. */
async function fixture(body: string): Promise<Fixture> {
  // realpath right away: `readWindowVerified` gets an already resolved path from
  // its callers (`safeRealpath`) and the parent chain is computed by a string
  // operation against the root — on macOS `/var` is a symlink to `/private/var`,
  // so an unresolved `mkdtemp` would not match the root and the chain would come out empty.
  const base = await realpath(await mkdtemp(join(tmpdir(), 'agent-ledger-saferead-')));
  const root = join(base, 'projects');
  const dir = join(root, 'proj');
  await mkdir(dir, { recursive: true });
  const file = join(dir, 'session.jsonl');
  await writeFile(file, body, 'utf8');
  const roots = await resolveRoots([root]);
  return {
    root: roots[0] as string,
    dir,
    file,
    roots,
    cleanup: () => rm(base, { recursive: true, force: true }),
  };
}

function titleLine(title: string): string {
  return `${JSON.stringify({ type: 'custom-title', customTitle: title })}\n`;
}

function userLine(text: string): string {
  return `${JSON.stringify({ type: 'user', message: { role: 'user', content: text } })}\n`;
}

test('readTailVerified / readHeadVerified read the right end of the file', async (t) => {
  const fx = await fixture('AAAAABBBBBCCCCC');
  t.after(fx.cleanup);

  const tail = await readTailVerified(fx.root, fx.file, 5);
  assert.deepEqual(tail, { text: 'CCCCC', skipped: null });

  const head = await readHeadVerified(fx.root, fx.file, 5);
  assert.deepEqual(head, { text: 'AAAAA', skipped: null });

  // A window larger than the file → the whole file, not a tail of zero bytes.
  const whole = await readHeadVerified(fx.root, fx.file, 4096);
  assert.deepEqual(whole, { text: 'AAAAABBBBBCCCCC', skipped: null });
});

test('an empty file is empty text, not an error', async (t) => {
  const fx = await fixture('');
  t.after(fx.cleanup);
  assert.deepEqual(await readTailVerified(fx.root, fx.file, 64), { text: '', skipped: null });
  assert.deepEqual(await readHeadVerified(fx.root, fx.file, 64), { text: '', skipped: null });
});

test('a symlink in place of the file → aliased (O_NOFOLLOW), the target is not read', async (t) => {
  const fx = await fixture('secret-ignored');
  t.after(fx.cleanup);
  const outside = join(fx.dir, '..', '..', 'outside.txt');
  await writeFile(outside, 'SECRET', 'utf8');
  // This is exactly the swap planted after the root check: a name we
  // validated is now a symlink outside the sandbox.
  await rm(fx.file);
  await symlink(outside, fx.file);

  const out = await readTailVerified(fx.root, fx.file, 64);
  assert.equal(out.text, null);
  // `O_NOFOLLOW` makes open fail with ELOOP, which falls into the catch-all `unreadable` —
  // what matters is that the symlink target is NOT read.
  assert.equal(out.skipped, 'unreadable');
});

test('a symlink in the parent path → aliased (H3-1 parent chain)', async (t) => {
  const fx = await fixture(titleLine('must not be read'));
  t.after(fx.cleanup);
  const elsewhere = join(fx.root, '..', 'elsewhere');
  await mkdir(elsewhere, { recursive: true });
  await writeFile(join(elsewhere, 'session.jsonl'), 'SECRET', 'utf8');
  await rm(fx.dir, { recursive: true, force: true });
  await symlink(elsewhere, fx.dir);

  const out = await readTailVerified(fx.root, fx.file, 64);
  assert.equal(out.text, null);
  assert.equal(out.skipped, 'aliased');
});

test('hard link (nlink > 1) → aliased', async (t) => {
  const fx = await fixture('AAAA');
  t.after(fx.cleanup);
  await link(fx.file, join(fx.dir, 'alias.jsonl'));
  const out = await readTailVerified(fx.root, fx.file, 64);
  assert.equal(out.skipped, 'aliased');
});

test('a directory or a nonexistent path is not a read', async (t) => {
  const fx = await fixture('AAAA');
  t.after(fx.cleanup);
  assert.equal((await readTailVerified(fx.root, fx.dir, 64)).skipped, 'unreadable');
  assert.equal((await readTailVerified(fx.root, join(fx.dir, 'nic.jsonl'), 64)).skipped, 'unreadable');
});

/* ---------------- transcript.ts goes through the same reader ---------------- */

test('readTranscriptTitle still reads the title from the tail and from the prompt', async (t) => {
  const fx = await fixture(`${userLine('first question')}${titleLine('Session name')}`);
  t.after(fx.cleanup);
  assert.deepEqual(await readTranscriptTitle(fx.file, fx.roots), {
    title: 'Session name',
    source: 'claude',
  });

  // The prompt fallback uses the head window — also a verified read.
  const only = await fixture(userLine('only the first question'));
  t.after(only.cleanup);
  assert.deepEqual(await readTranscriptTitle(only.file, only.roots), {
    title: 'only the first question',
    source: 'prompt',
  });
});

test('an aliased transcript yields no title (a foreign file used to be read)', async (t) => {
  const fx = await fixture(titleLine('Original name'));
  t.after(fx.cleanup);
  // A foreign file with a "title" planted via a symlink in the parent path —
  // realpath and the root check both pass (the chain is still under the root), the read does not.
  const elsewhere = join(fx.root, '..', 'elsewhere');
  await mkdir(elsewhere, { recursive: true });
  await writeFile(join(elsewhere, 'session.jsonl'), titleLine('Planted name'), 'utf8');
  await rm(fx.dir, { recursive: true, force: true });
  await symlink(elsewhere, fx.dir);

  assert.equal(await readTranscriptTitle(fx.file, fx.roots), null);
});

test('a path outside the roots is not read at all', async (t) => {
  const fx = await fixture(titleLine('Name'));
  t.after(fx.cleanup);
  const outside = join(fx.root, '..', 'outside.jsonl');
  await writeFile(outside, titleLine('Outside the sandbox'), 'utf8');
  assert.equal(await readTranscriptTitle(outside, fx.roots), null);
  assert.equal(await readTranscriptTitle(fx.file, []), null);
  assert.equal(await readTranscriptTitle('', fx.roots), null);
  assert.equal(await readTranscriptTitle(null, fx.roots), null);
});

test('S4: matchedRoot casefolds and unifies separators on win32 only', () => {
  const roots = ['C:\\Users\\Me\\.claude'];
  assert.equal(matchedRoot('c:/users/me/.CLAUDE/projects/x.jsonl', roots, 'win32'), roots[0]);
  assert.equal(matchedRoot('C:\\Users\\Me\\.claude', roots, 'win32'), roots[0], 'the root itself');
  assert.equal(matchedRoot('C:\\Users\\Me\\.claude-evil\\x', roots, 'win32'), null, 'prefix is not containment');
  assert.equal(matchedRoot('D:\\Users\\Me\\.claude\\x', roots, 'win32'), null);
  // POSIX stays case-sensitive: a different case is a different directory.
  assert.equal(matchedRoot('/home/me/.CLAUDE/x', ['/home/me/.claude'], 'linux'), null);
  assert.equal(matchedRoot('/home/me/.claude/x', ['/home/me/.claude'], 'linux'), '/home/me/.claude');
});

test('S4: chain snapshots carry bigint dev/ino (no Number precision loss)', async (t) => {
  const fx = await fixture('x');
  t.after(fx.cleanup);
  const snaps = await snapshotChain(parentChain(fx.root, fx.file));
  assert.ok(snaps !== null && snaps.length > 0);
  for (const s of snaps) {
    assert.equal(typeof s.dev, 'bigint');
    assert.equal(typeof s.ino, 'bigint');
  }
});
