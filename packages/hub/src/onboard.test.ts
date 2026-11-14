/** F1 addendum: repo onboarding — the block, the flag, cwd outside any repo,
 *  and the fact collector behind `ledger onboard`. */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { git } from './git.ts';
import { parseRemoteUrl, stripCredentials } from './onboard.ts';
import { makeCodeRepo, startTestHub } from './test-helpers.ts';

function start(session: string, cwd: string): Record<string, unknown> {
  return { session_id: session, cwd, hook_event_name: 'SessionStart', source: 'startup' };
}

test('ONBOARDING block for a new repo, gone after `ledger repo onboarded`', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('fresh');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });

  const first = await fx.hook('session-start', start('aaaa1000', repo.path));
  const slug = first.repo as string;
  assert.ok(slug, 'the repo was auto-registered');

  const block = first.text.split('\n');
  assert.match(block[0] ?? '', /^ONBOARDING: for repo /);
  assert.match(first.text, new RegExp(`ONBOARDING: for repo ${slug} \\(`));
  assert.match(first.text, /just created \(prefix [A-Z]{2,4}\)/);
  assert.match(first.text, /1\) ledger onboard/);
  assert.match(first.text, new RegExp(`~/\\.ledger/${slug}/CONTEXT\\.md`));
  assert.match(first.text, /ledger-keeper/);
  assert.match(first.text, new RegExp(`5\\) ledger repo onboarded ${slug}`));
  assert.match(first.text, /continue with the user's request\./i);
  const onboardingLines = block.filter(
    (l, i) => i < block.findIndex((x) => x.startsWith(`${slug} ·`) || x.includes(' · ')) || i < 9,
  );
  assert.ok(onboardingLines.length <= 12, 'onboarding block is at most 12 lines');
  assert.match(first.text, /onboarded=false/, 'the brief also reports it in the counts header');

  // Flag flips, block disappears.
  const res = await fx.api('POST', `/v1/repos/${slug}/onboarded`, {});
  assert.equal(res.status, 200);
  assert.equal((await fx.api('GET', '/v1/repos')).json.repos[slug].onboarded, true);

  const second = await fx.hook('session-start', start('bbbb1000', repo.path));
  assert.equal(second.text.includes('ONBOARDING'), false, 'no block after onboarded');
  assert.equal(second.text.includes('onboarded=false'), false);
});

test('a filled-in CONTEXT.md sets onboarded even without `ledger repo onboarded`', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('ctx');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  const first = await fx.hook('session-start', start('cccc1000', repo.path));
  const slug = first.repo as string;
  assert.equal((await fx.api('GET', '/v1/repos')).json.repos[slug].onboarded, false);

  await writeFile(
    fx.hub.ledger.paths.contextFile(slug),
    [
      `# ${slug} — repo map`,
      '',
      '## Stack',
      '',
      '- Node 22 + TypeScript, hub via Hono, SQLite for runtime state',
      '',
      '## Structure',
      '',
      '- packages/hub — server, ledger, hooks',
      '- packages/cli — thin client',
      '',
      '## Commands',
      '',
      '- test: pnpm test',
      '',
    ].join('\n'),
    'utf8',
  );
  await fx.hub.ledger.queue.run(() => fx.hub.ledger.reindex());

  assert.equal(
    (await fx.api('GET', '/v1/repos')).json.repos[slug].onboarded,
    true,
    'the hub noticed on reindex',
  );
  const after = await fx.hook('session-start', start('dddd1000', repo.path));
  assert.equal(after.text.includes('ONBOARDING'), false);
});

test('cwd outside a git repo: NO REPO + repo list + AskUserQuestion instruction', async (t) => {
  const fx = await startTestHub();
  const parent = await mkdtemp(join(tmpdir(), 'agent-ledger-nogit-'));
  t.after(async () => {
    await fx.cleanup();
    await rm(parent, { recursive: true, force: true });
  });

  // Two repos below cwd: one registered, one not. Plus noise that must be skipped.
  const known = join(parent, 'known-repo');
  const unknown = join(parent, 'nested', 'unknown-repo');
  await mkdir(known, { recursive: true });
  await mkdir(unknown, { recursive: true });
  await git(known, ['init', '-q', '-b', 'main']);
  await git(unknown, ['init', '-q', '-b', 'main']);
  await mkdir(join(parent, 'node_modules', 'pkg'), { recursive: true });
  await git(join(parent, 'node_modules', 'pkg'), ['init', '-q', '-b', 'main']);
  await fx.hub.ledger.registerRepo({ slug: 'known', prefix: 'KNW', path: known, onboarded: true });

  const res = await fx.hook('session-start', start('eeee1000', parent));
  assert.equal(res.repo, null, 'no home repo');
  assert.match(res.text, new RegExp(`^NO REPO: cwd ${parent} is not a git repo\\.`, 'm'));
  assert.match(res.text, /Git repos under cwd:/);
  assert.match(res.text, new RegExp(`${known} — known`));
  assert.match(res.text, new RegExp(`${unknown} — unregistered`));
  assert.equal(res.text.includes('node_modules'), false, 'node_modules is skipped');
  assert.match(res.text, /Registered repos: known, ops/);
  assert.match(res.text, /AskUserQuestion/);
  assert.match(res.text, /monorepo \/ separate repos and stack/);
  assert.match(res.text, /git init \/ ledger repo add/);

  // The session exists but holds nothing.
  const view = await fx.api('GET', '/v1/sessions/eeee1000');
  assert.equal(view.json.session.home_repo, null);
  assert.equal(view.json.touched.length, 0);
});

test('stripCredentials / parseRemoteUrl: a secret in the remote URL does not leak', () => {
  assert.equal(
    stripCredentials('https://user:ghp_secret@github.com/org/repo.git'),
    'https://github.com/org/repo.git',
  );
  assert.equal(stripCredentials('git@github.com:org/repo.git'), 'git@github.com:org/repo.git');
  const config = [
    '[core]',
    '\tbare = false',
    '[remote "upstream"]',
    '\turl = https://example.com/up.git',
    '[remote "origin"]',
    '\turl = https://tok:pw@github.com/org/repo.git',
  ].join('\n');
  assert.equal(parseRemoteUrl(config), 'https://github.com/org/repo.git');
  assert.equal(parseRemoteUrl('[core]\n\tbare = false\n'), null);
});

test('ledger onboard: repo facts without an LLM and without running git in a foreign repo', async (t) => {
  const fx = await startTestHub();
  const repo = await mkdtemp(join(tmpdir(), 'agent-ledger-onb-'));
  t.after(async () => {
    await fx.cleanup();
    await rm(repo, { recursive: true, force: true });
  });
  await git(repo, ['init', '-q', '-b', 'main']);
  await git(repo, ['remote', 'add', 'origin', 'https://user:tok@github.com/org/thing.git']);
  await writeFile(
    join(repo, 'package.json'),
    JSON.stringify(
      {
        name: 'thing',
        dependencies: { '@nestjs/core': '^10', typescript: '^5' },
        devDependencies: { vite: '^5' },
        scripts: { dev: 'x', build: 'y', test: 'z' },
        workspaces: ['apps/*'],
      },
      null,
      2,
    ),
    'utf8',
  );
  await writeFile(join(repo, 'pnpm-workspace.yaml'), 'packages:\n  - apps/*\n', 'utf8');
  await writeFile(join(repo, 'Dockerfile'), 'FROM node:22\n', 'utf8');
  await writeFile(join(repo, 'README.md'), '# thing\n', 'utf8');
  await writeFile(join(repo, 'BACKLOG.md'), '- old todo\n', 'utf8');
  await mkdir(join(repo, 'docs'), { recursive: true });
  await writeFile(join(repo, 'docs', 'HANDOFF.md'), '# handoff\n', 'utf8');
  await mkdir(join(repo, 'node_modules', 'junk'), { recursive: true });
  await writeFile(join(repo, 'node_modules', 'junk', 'TODO.md'), 'x\n', 'utf8');

  const res = await fx.api('GET', `/v1/onboard?path=${encodeURIComponent(repo)}`);
  assert.equal(res.status, 200);
  const text = res.text;
  assert.ok(text.split('\n').length <= 31, `at most 30 lines, got ${text.split('\n').length}`);
  assert.ok(text.split('\n').includes(`repo ${await realpath(repo)}`), 'the first line names the real repo path');
  assert.match(text, /ledger: unregistered · suggested slug agent-ledger-onb-/);
  assert.match(text, /remote: https:\/\/github\.com\/org\/thing\.git/, 'without credentials');
  assert.equal(text.includes('tok@'), false, 'the token from the remote URL is never printed');
  assert.match(text, /branch: main · default main/);
  assert.match(text, /package\.json: node \+ typescript \+ nestjs \+ vite \+ npm-workspaces/);
  assert.match(text, /scripts: dev, build, test/);
  assert.match(text, /pnpm-workspace\.yaml: pnpm workspace/);
  assert.match(text, /Dockerfile: docker/);
  assert.match(text, /docs: .*README\.md/);
  assert.match(text, /docs: .*docs\/HANDOFF\.md/);
  assert.match(text, /TODO files: BACKLOG\.md/);
  assert.equal(text.includes('node_modules'), false, 'node_modules is not searched');

  const json = await fx.api('GET', `/v1/onboard?format=json&path=${encodeURIComponent(repo)}`);
  assert.equal(json.json.facts.registered_as, null);
  assert.equal(json.json.facts.onboarded, false);
  assert.deepEqual(json.json.facts.todo_files, ['BACKLOG.md']);

  // Registering it changes the ledger line.
  await fx.hub.ledger.registerRepo({ slug: 'thing', prefix: 'THG', path: repo });
  const after = await fx.api('GET', `/v1/onboard?path=${encodeURIComponent(repo)}`);
  assert.match(after.text, /ledger: thing · onboarded=false/);
});

/* findFiles used stat() (follows symlinks), so a symlinked `docs/` dir
 * or a symlinked doc file could walk/read outside the checkout. */
test('onboard neither walks a symlinked directory nor reads a symlinked file', async (t) => {
  const fx = await startTestHub();
  const repo = await mkdtemp(join(tmpdir(), 'agent-ledger-sym-'));
  const outside = await mkdtemp(join(tmpdir(), 'agent-ledger-sym-outside-'));
  t.after(async () => {
    await fx.cleanup();
    await rm(repo, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });
  await git(repo, ['init', '-q', '-b', 'main']);
  await writeFile(join(outside, 'SECRET.md'), '# secret outside the repo\n', 'utf8');
  // A symlinked directory named `docs` pointing outside the checkout...
  await symlink(outside, join(repo, 'docs'), 'dir');
  // ...and a symlinked file at top level that would otherwise match DOC_CANDIDATES.
  await symlink(join(outside, 'SECRET.md'), join(repo, 'README.md'), 'file');

  const json = await fx.api('GET', `/v1/onboard?format=json&path=${encodeURIComponent(repo)}`);
  assert.equal(json.status, 200, json.text);
  const docs = json.json.facts.docs as string[];
  assert.equal(docs.includes('README.md'), false, 'a symlinked README must not be returned');
  assert.equal(
    docs.some((d) => d.startsWith('docs/')),
    false,
    'a symlinked docs/ directory must not be searched',
  );
});

test('ledger onboard outside a repo lists what is nearby', async (t) => {
  const fx = await startTestHub();
  const parent = await mkdtemp(join(tmpdir(), 'agent-ledger-onbnone-'));
  t.after(async () => {
    await fx.cleanup();
    await rm(parent, { recursive: true, force: true });
  });
  await mkdir(join(parent, 'inner'), { recursive: true });
  await git(join(parent, 'inner'), ['init', '-q', '-b', 'main']);

  const res = await fx.api('GET', `/v1/onboard?path=${encodeURIComponent(parent)}`);
  assert.equal(res.status, 200);
  assert.match(res.text, /is not a git repo\./);
  assert.match(res.text, /inner — unregistered/);
  assert.equal((await fx.api('GET', '/v1/onboard')).status, 422, 'without ?path it is 422');
  assert.equal(
    (await fx.api('GET', '/v1/onboard?path=/nope/nope/nope')).status,
    404,
    'nonexistent path',
  );
});
