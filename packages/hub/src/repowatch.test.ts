/** F1: commit and release watcher (SPEC §12) + git reader parsing (§6.3). */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import {
  listTrackedAmong,
  listTrackedFiles,
  readBranches,
  readStatus,
  readWorktrees,
  trailerIds,
} from './gitreader.ts';
import { makeCommittedRepo, startTestHub, type HubFixture } from './test-helpers.ts';

async function addItem(fx: HubFixture, repo: string, title: string): Promise<string> {
  const res = await fx.api('POST', '/v1/items', { repo, title, kind: 'BACKLOG', priority: 'P1' });
  assert.equal(res.status, 201, res.text);
  return res.json.id as string;
}

test('trailerIds: Closes / Refs, several ids per line, case-insensitive key', () => {
  const body = 'feat: x\n\nRefs: acme-1, ACME-2\nCloses: WEB-13\ncloses: ACME-3\nNot-A-Trailer: ACME-9\n';
  assert.deepEqual(trailerIds(body, 'Closes').sort(), ['ACME-3', 'WEB-13']);
  assert.deepEqual(trailerIds(body, 'Refs').sort(), ['ACME-1', 'ACME-2']);
  assert.deepEqual(trailerIds('no trailers here ACME-5', 'Closes'), []);
});

test('a commit with Closes: closes the item, clears touched and writes the journal', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('closes');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'closer', prefix: 'CLS', path: repo.path, onboarded: true });
  await fx.hub.repoWatcher.start();

  const id = await addItem(fx, 'closer', 'close by commit');
  await fx.hook('session-start', {
    session_id: 'cccc1111',
    cwd: repo.path,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'cccc1111', paths: ['src/**'] });

  // The session edits the file, so `touched` owns it…
  await writeFile(join(repo.path, 'feature.ts'), 'export const f = 1;\n', 'utf8');
  await fx.hook('post-tool-use', {
    session_id: 'cccc1111',
    hook_event_name: 'PostToolUse',
    tool_name: 'Write',
    tool_input: { file_path: join(repo.path, 'feature.ts') },
  });
  const beforeCommit = await fx.api('GET', '/v1/sessions/cccc1111');
  assert.equal(beforeCommit.json.touched.length, 1);

  // …and the commit takes it away again.
  const sha = await repo.commit(`feat: finished thing\n\nCloses: ${id}\n`, {
    'feature.ts': 'export const f = 2;\n',
  });
  await fx.hub.repoWatcher.sync();

  const item = await fx.api('GET', `/v1/items/${id}`);
  assert.equal(item.json.item.status, 'done');
  assert.equal(item.json.item.done.commit, sha, 'G3: done.commit holds the full 40-hex sha, not a shortened one');
  assert.equal(item.json.item.done.version, null, 'the version is filled in only by the tag');
  assert.equal(item.json.item.claimed_by, null);

  const afterCommit = await fx.api('GET', '/v1/sessions/cccc1111');
  assert.equal(afterCommit.json.touched.length, 0, 'committed files disappear from touched');

  const timeline = await fx.api('GET', '/v1/timeline?repo=closer&format=line');
  assert.match(timeline.text, new RegExp(`commit · ${sha.slice(0, 7)}`));
  assert.match(timeline.text, /finished thing/);
  assert.match(timeline.text, new RegExp(`closes ${id}`));
  // The commit is attributed to the session that owned its files.
  assert.match(timeline.text, /cccc ·? ?commit|cccc/);
});

test('a commit with Refs: only logs, status unchanged', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('refs');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'refser', prefix: 'RFS', path: repo.path, onboarded: true });
  await fx.hub.repoWatcher.start();
  const id = await addItem(fx, 'refser', 'related item');

  const sha = await repo.commit(`fix: small thing\n\nRefs: ${id}\n`, { 'a.ts': 'x\n' });
  await fx.hub.repoWatcher.sync();

  const item = await fx.api('GET', `/v1/items/${id}`);
  assert.equal(item.json.item.status, 'open', 'Refs does not close');
  const log = item.json.detail.log.map((l: { text: string }) => l.text).join('\n');
  assert.match(log, new RegExp(`commit ${sha.slice(0, 7)}`));
});

/* G2: `Closes: <ID>` / `Refs: <ID>` in a commit must only ever resolve an ID
 * that belongs to the repo the commit came from — not any item in the ledger
 * that happens to share the numeric suffix or was pasted in by mistake. */
test('G2: a commit in a foreign repo with Closes on another repo\'s id does not close the item', async (t) => {
  const fx = await startTestHub();
  const repoA = await makeCommittedRepo('g2a');
  const repoB = await makeCommittedRepo('g2b');
  t.after(async () => {
    await fx.cleanup();
    await repoA.cleanup();
    await repoB.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'g2repoa', prefix: 'GXA', path: repoA.path, onboarded: true });
  await fx.hub.ledger.registerRepo({ slug: 'g2repob', prefix: 'GXB', path: repoB.path, onboarded: true });
  await fx.hub.repoWatcher.start();

  const idA = await addItem(fx, 'g2repoa', 'belongs to repo A');

  // A commit landing in repo B claims to close an item that lives in repo A.
  const sha = await repoB.commit(`feat: by mistake\n\nCloses: ${idA}\n`, { 'x.ts': '1\n' });
  await fx.hub.repoWatcher.sync();

  const item = await fx.api('GET', `/v1/items/${idA}`);
  assert.equal(item.json.item.status, 'open', 'a foreign Closes must not close the item');
  assert.equal(item.json.item.done, null);

  const journal = await fx.api('GET', '/v1/timeline?repo=g2repob&format=line');
  assert.match(journal.text, new RegExp(`${idA}.*ignored`), 'the foreign id is recorded, not silently dropped');
  assert.match(journal.text, new RegExp(sha.slice(0, 7)));
});

test('new tag v* → journal release + done.version on the items in range', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('tagged');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'tagger', prefix: 'TGR', path: repo.path, onboarded: true });
  await fx.hub.repoWatcher.start();

  // v0.1.0 exists first, so the range of v0.2.0 is well defined.
  await repo.commit('chore: baseline', { 'base.ts': '0\n' });
  await repo.tag('v0.1.0');
  await fx.hub.repoWatcher.sync();

  const id = await addItem(fx, 'tagger', 'goes into the release');
  const sha = await repo.commit(`feat: thing for the release\n\nCloses: ${id}\n`, { 'rel.ts': '1\n' });
  await fx.hub.repoWatcher.sync();
  assert.equal((await fx.api('GET', `/v1/items/${id}`)).json.item.done.commit, sha);

  await repo.tag('v0.2.0');
  await fx.hub.repoWatcher.sync();

  const item = await fx.api('GET', `/v1/items/${id}`);
  assert.equal(item.json.item.done.version, 'v0.2.0', 'the tag fills in the version');

  const timeline = await fx.api('GET', '/v1/timeline?repo=tagger&format=line');
  assert.match(timeline.text, /release · v0\.2\.0/);
  assert.match(timeline.text, new RegExp(`closed ${id}`));

  const view = await fx.api('GET', '/v1/repos/tagger');
  assert.equal(view.json.repo.last_release.tag, 'v0.2.0');
});

test('the first watcher run does not replay history (old commits close nothing)', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('history');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'histo', prefix: 'HST', path: repo.path, onboarded: true });
  const id = await addItem(fx, 'histo', 'must not be closed');
  // A commit that mentions the item exists BEFORE the watcher ever looked.
  await repo.commit(`feat: old\n\nCloses: ${id}\n`, { 'old.ts': '1\n' });

  await fx.hub.repoWatcher.start();
  await fx.hub.repoWatcher.sync();

  assert.equal(
    (await fx.api('GET', `/v1/items/${id}`)).json.item.status,
    'open',
    'a commit from before the first look is not replayed',
  );
});

test('git reader: status --porcelain=v2 parses staged, untracked and spaces in paths', async (t) => {
  const repo = await makeCommittedRepo('status');
  t.after(repo.cleanup);
  await writeFile(join(repo.path, 'README.md'), '# changed\n', 'utf8');
  await writeFile(join(repo.path, 'a file with spaces.ts'), 'x\n', 'utf8');

  const status = await readStatus(repo.path);
  assert.ok(status, 'status was read');
  assert.equal(status?.branch, 'main');
  const paths = status?.dirty.map((d) => d.rel_path) ?? [];
  assert.ok(paths.includes('README.md'), `README.md missing: ${paths.join(',')}`);
  assert.ok(paths.includes('a file with spaces.ts'), 'a path with spaces does not fall apart');
  assert.equal(status?.dirty.find((d) => d.rel_path === 'a file with spaces.ts')?.untracked, true);

  const worktrees = await readWorktrees(repo.path);
  assert.equal(worktrees.length, 1);
  assert.equal(worktrees[0]?.main, true);
  assert.equal(worktrees[0]?.branch, 'main');

  const branches = await readBranches(repo.path);
  assert.equal(branches.length, 1);
  assert.equal(branches[0]?.name, 'main');
  assert.equal(branches[0]?.ahead, 0);
});

test('git reader: ahead/behind relative to main', async (t) => {
  const repo = await makeCommittedRepo('ab');
  t.after(repo.cleanup);
  const { git } = await import('./git.ts');
  await git(repo.path, ['checkout', '-q', '-b', 'task/ahead']);
  await repo.commit('feat: one', { 'x.ts': '1\n' });
  await repo.commit('feat: two', { 'y.ts': '2\n' });

  const branches = await readBranches(repo.path);
  const task = branches.find((b) => b.name === 'task/ahead');
  assert.equal(task?.ahead, 2, 'two commits ahead of main');
  assert.equal(task?.behind, 0);
  assert.equal(task?.base, 'main');
  assert.equal(task?.stale, true);
});

/* ---------------- releasing locks in a large repo ---------------- */

/** 50,000 tracked paths without 50,000 files on disk: one blob and
 *  `update-index --index-info`. The index is exactly what `ls-files` asks,
 *  so for this test it is the same repo as one with real files, it just
 *  gets built in tens of milliseconds. */
function fillIndex(dir: string, paths: readonly string[]): void {
  const sha = execFileSync('git', ['hash-object', '-w', '--stdin'], {
    cwd: dir,
    input: 'x\n',
    encoding: 'utf8',
  }).trim();
  execFileSync('git', ['update-index', '--add', '--index-info'], {
    cwd: dir,
    input: `${paths.map((p) => `100644 ${sha}\t${p}`).join('\n')}\n`,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
}

test('listTrackedAmong answers even in a repo with 50,000 tracked files', async (t) => {
  const repo = await makeCommittedRepo('big43');
  t.after(repo.cleanup);

  const generated = Array.from({ length: 50_000 }, (_, i) => `gen/${String(i).padStart(6, '0')}.ts`);
  fillIndex(repo.path, generated);

  const late = generated[49_999] as string;
  const started = Date.now();
  const tracked = await listTrackedAmong(repo.path, [late, 'README.md', 'never-existed.ts']);
  const elapsed = Date.now() - started;

  assert.deepEqual([...tracked].sort(), ['README.md', late].sort());
  // This is the A9-4 finding itself: the full listing is capped at 5,000
  // paths, so a file that sorts past the cap looks untracked — and its
  // `touched` lock would never drop.
  const full = await listTrackedFiles(repo.path);
  assert.equal(full.length, 5_000, 'cap of the full listing');
  assert.ok(!full.includes(late), 'the path past the cap is missing from the full listing — that is the bug');
  // Performance: the answer is bounded by the number of candidates, not the repo size.
  assert.ok(elapsed < 5_000, `listTrackedAmong took ${elapsed} ms`);
});

test('paths are sent as :(literal) — a glob in a file name does not decide', async (t) => {
  const repo = await makeCommittedRepo('lit43');
  t.after(repo.cleanup);
  fillIndex(repo.path, ['gen/a[1].ts', 'gen/ab.ts']);

  const tracked = await listTrackedAmong(repo.path, ['gen/a[1].ts', 'gen/a*.ts', 'gen/a?.ts']);
  assert.deepEqual([...tracked], ['gen/a[1].ts'], 'only the real name, no pattern expansion');
});

test('a touched lock on a clean tracked file drops even past the 5,000 cap', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCommittedRepo('rel43');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'big', prefix: 'BIG', path: repo.path, onboarded: true });
  await fx.hub.repoWatcher.start();

  // `zzz.ts` is real, committed and clean, but sorts after 5,500
  // generated paths — exactly the case the old full listing cut off.
  await repo.commit('feat: late file', { 'zzz.ts': 'export const z = 1;\n' });
  fillIndex(
    repo.path,
    Array.from({ length: 5_500 }, (_, i) => `gen/${String(i).padStart(6, '0')}.ts`),
  );

  // macOS: `touched` is keyed by the resolved checkout (`/private/var/…`),
  // while `mkdtemp` returns `/var/…`.
  const checkout = await realpath(repo.path);
  const id = await addItem(fx, 'big', 'release the lock');
  await fx.hook('session-start', { session_id: 'bbbb4343', cwd: repo.path, hook_event_name: 'SessionStart', source: 'startup' });
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'bbbb4343', paths: ['**'] });
  await fx.hook('post-tool-use', {
    session_id: 'bbbb4343',
    hook_event_name: 'PostToolUse',
    tool_name: 'Write',
    tool_input: { file_path: join(repo.path, 'zzz.ts') },
  });
  assert.ok(
    fx.hub.store.listTouched({ checkout }).some((r) => r.rel_path === 'zzz.ts'),
    'the lock must exist first',
  );

  await fx.hub.gitCache.refresh(checkout, 'big');
  assert.ok(
    !fx.hub.store.listTouched({ checkout }).some((r) => r.rel_path === 'zzz.ts'),
    'a clean tracked file must be released even when it is past the cap of the full listing',
  );
});

// R5: an invalid rel_path (absolute path, `..` segment) is filtered out BEFORE
// it goes to git, so it cannot spoil the whole batch for the other legitimate
// paths in it (exactly the "one bad line takes down 199 others" shape). The
// second half of R5 (retry one path at a time when the batch as a whole fails)
// cannot be forced deterministically through the real `git` binary without
// mocking `git()` from `./git.ts` — the `:(literal)` pathspec is designed not
// to fail on content, so a "bad" path in argv never really causes a non-zero
// exit code.
test('R5: an invalid rel_path (absolute path, `..`) is filtered out and does not spoil the batch', async (t) => {
  const repo = await makeCommittedRepo('r5-filter');
  t.after(repo.cleanup);
  await repo.commit('feat: ok', { 'ok.ts': 'export const o = 1;\n' });

  const tracked = await listTrackedAmong(repo.path, [
    'ok.ts',
    '/etc/passwd',
    '../outside.ts',
    'a/../../escape.ts',
  ]);
  assert.deepEqual([...tracked], ['ok.ts']);
});
