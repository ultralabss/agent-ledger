/** `ledger hook <event>` — transport only. Its contract is: never fail loudly.
 *  A hook that errors would either flood the transcript or (on PreToolUse)
 *  block the user's own work, so every failure mode must be exit 0 + no output. */

import assert from 'node:assert/strict';
import { mkdir, readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { git } from '@agent-ledger/hub/git';
import { makeCodeRepo, makeCommittedRepo, startTestHub } from '@agent-ledger/hub/test-helpers';
import { run, shellQuote } from './index.ts';

interface Captured {
  code: number;
  out: string[];
  err: string[];
}

async function runCli(
  argv: string[],
  env: NodeJS.ProcessEnv,
  stdin: string,
  cwd = '/',
): Promise<Captured> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(argv, {
    out: (l) => out.push(l),
    err: (l) => err.push(l),
    env,
    cwd,
    stdin: async () => stdin,
  });
  return { code, out, err };
}

test('shellQuote: safe for `export X=<value>`', () => {
  assert.equal(shellQuote('abcd'), `'abcd'`);
  assert.equal(shellQuote(`a'b`), `'a'\\''b'`);
  assert.equal(shellQuote('$(rm -rf /)'), `'$(rm -rf /)'`);
  assert.equal(shellQuote('a b;c`d`'), `'a b;c\`d\`'`);
  // Round-trip through a real shell: the value must come out byte-identical.
  for (const value of [`a'b`, '$(id)', 'x`y`', 'a b', '~/x', '\\n']) {
    assert.equal(shellQuote(value).startsWith(`'`), true, value);
    assert.equal(shellQuote(value).endsWith(`'`), true, value);
  }
});

test('fail-open: hub not running → exit 0; session-start mentions the queue', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-hookdown-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  // A token file exists, so we get all the way to the request and fail there.
  await writeFile(join(dir, 'token'), 'x'.repeat(43), { mode: 0o600 });
  const env = {
    LEDGER_DIR: join(dir, '..', 'nope'),
    LEDGER_HUB_PORT: '1', // nothing listens on port 1
  } as NodeJS.ProcessEnv;

  // session-start is the ONE hook that speaks when the hub is down —
  // otherwise the session treats the later `QUEUED …` lines as errors. Still
  // exit 0, still nothing on stderr.
  const start = await runCli(['hook', 'session-start'], env, JSON.stringify({ session_id: 'x' }));
  assert.equal(start.code, 0, 'exit 0 even when the hub is not running');
  assert.equal(start.out.length, 1, start.out.join('|'));
  assert.match(start.out[0] ?? '', /AGENT-LEDGER DOWN: ledger writes are queued/);
  assert.deepEqual(start.err, [], 'no stderr — the agent host sees nothing');

  // Every other hook stays completely silent: a warning on each tool call would
  // be unreadable.
  for (const ev of ['stop', 'post-tool-use', 'user-prompt-submit', 'session-end']) {
    const res = await runCli(['hook', ev], env, JSON.stringify({ session_id: 'x' }));
    assert.equal(res.code, 0, ev);
    assert.deepEqual(res.out, [], `${ev}: no stdout`);
    assert.deepEqual(res.err, [], `${ev}: no stderr`);
  }
});

test('fail-open: missing token, empty stdin, nonsense event → exit 0, silent', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-hookbad-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { LEDGER_DIR: dir, LEDGER_HUB_PORT: '1' } as NodeJS.ProcessEnv;

  // Cases that must stay completely silent: no event name, a nonsense event, or
  // no payload at all — none of them is "the hub is down", so none of them may
  // print the down notice.
  for (const [argv, stdin, why] of [
    [['hook'], '{}', 'missing event name'],
    [['hook', 'Nonsense; rm -rf /'], '{}', 'invalid event name'],
    [['hook', 'session-start'], '', 'empty stdin'],
  ] as [string[], string, string][]) {
    const res = await runCli(argv, env, stdin);
    assert.equal(res.code, 0, why);
    assert.deepEqual(res.out, [], why);
    assert.deepEqual(res.err, [], why);
  }

  // A missing token or unparseable payload on session-start is indistinguishable
  // from a hub that is not there, so it gets the same notice — and still exit 0.
  for (const [stdin, why] of [
    ['{"session_id":"x"}', 'missing token'],
    ['this is not json', 'invalid JSON'],
  ] as [string, string][]) {
    const res = await runCli(['hook', 'session-start'], env, stdin);
    assert.equal(res.code, 0, why);
    assert.deepEqual(res.err, [], why);
    assert.match(res.out.join('\n'), /AGENT-LEDGER DOWN/, why);
  }
});

test('hook against a live hub: stdout is the brief and CLAUDE_ENV_FILE gets the export', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('clihook');
  const envDir = await mkdtemp(join(tmpdir(), 'agent-ledger-envfile-'));
  const envFile = join(envDir, 'claude-env.sh');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
    await rm(envDir, { recursive: true, force: true });
  });
  await fx.hub.ledger.registerRepo({ slug: 'clihook', prefix: 'CLH', path: repo.path, onboarded: true });

  const env = {
    LEDGER_DIR: fx.dir,
    LEDGER_HUB_PORT: String(fx.hub.port),
    CLAUDE_ENV_FILE: envFile,
  } as NodeJS.ProcessEnv;

  const res = await runCli(
    ['hook', 'session-start'],
    env,
    JSON.stringify({
      session_id: 'cli00001',
      cwd: repo.path,
      hook_event_name: 'SessionStart',
      source: 'startup',
    }),
  );
  assert.equal(res.code, 0);
  assert.match(res.out.join('\n'), /^clihook · main/m, 'stdout = brief §9');

  const written = await readFile(envFile, 'utf8');
  assert.match(written, /^export LEDGER_SESSION='cli00001'$/m);
  assert.match(written, /^export LEDGER_REPO='clihook'$/m);

  // PostToolUse prints nothing but records the file.
  await writeFile(join(repo.path, 'cli.ts'), 'x\n', 'utf8');
  const post = await runCli(
    ['hook', 'post-tool-use'],
    env,
    JSON.stringify({
      session_id: 'cli00001',
      hook_event_name: 'PostToolUse',
      tool_name: 'Write',
      tool_input: { file_path: join(repo.path, 'cli.ts') },
    }),
  );
  assert.equal(post.code, 0);
  assert.deepEqual(post.out, [], 'PostToolUse has no output');

  const detail = await fx.api('GET', '/v1/sessions/cli00001');
  assert.equal(detail.json.touched.length, 1);
  assert.equal(detail.json.touched[0].rel_path, 'cli.ts');
});

test('CLI commands: who, whose, search, sessions, onboard', async (t) => {
  const fx = await startTestHub();
  const repo = await makeCodeRepo('clicmds');
  t.after(async () => {
    await fx.cleanup();
    await repo.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'clicmds', prefix: 'CMD', path: repo.path, onboarded: true });
  const env = {
    LEDGER_DIR: fx.dir,
    LEDGER_HUB_PORT: String(fx.hub.port),
    LEDGER_SESSION: 'cli00002',
    LEDGER_REPO: 'clicmds',
  } as NodeJS.ProcessEnv;

  const added = await fx.api('POST', '/v1/items', {
    repo: 'clicmds',
    title: 'searchable item about authorization',
    kind: 'BACKLOG',
    priority: 'P1',
  });
  const id = added.json.id as string;

  await runCli(
    ['hook', 'session-start'],
    env,
    JSON.stringify({ session_id: 'cli00002', cwd: repo.path, source: 'startup' }),
  );
  await fx.api('POST', `/v1/items/${id}/claim`, { session: 'cli00002', paths: ['x/**'] });
  await writeFile(join(repo.path, 'owned.ts'), 'x\n', 'utf8');
  await runCli(
    ['hook', 'post-tool-use'],
    env,
    JSON.stringify({
      session_id: 'cli00002',
      tool_name: 'Edit',
      tool_input: { file_path: join(repo.path, 'owned.ts') },
    }),
  );

  const who = await runCli(['who', 'clicmds'], env, '');
  assert.equal(who.code, 0, who.err.join('\n'));
  assert.match(who.out.join('\n'), /Live: cli0/);
  assert.match(who.out.join('\n'), /owned\.ts — cli0/);

  const checkout = fx.hub.sessions.get('cli00002')?.checkout as string;
  const whose = await runCli(['whose', join(checkout, 'owned.ts')], env, '');
  assert.equal(whose.code, 0, whose.err.join('\n'));
  assert.match(whose.out.join('\n'), /^owned\.ts cli0 edit/);

  const sessions = await runCli(['sessions', '--live'], env, '');
  assert.equal(sessions.code, 0);
  assert.match(sessions.out.join('\n'), /cli0 cli00002 active clicmds/);

  await fx.hub.ledger.queue.run(() => fx.hub.ledger.reindex());
  await new Promise((r) => setTimeout(r, 120));
  const search = await runCli(['search', 'authorization'], env, '');
  assert.equal(search.code, 0, search.err.join('\n'));
  assert.match(search.out.join('\n'), new RegExp(`item ${id} clicmds`));

  const onboard = await runCli(['onboard', '--path', repo.path], env, '');
  assert.equal(onboard.code, 0, onboard.err.join('\n'));
  assert.match(onboard.out.join('\n'), /ledger: clicmds/);

  const history = await runCli(['history', '--since', '7d'], env, '');
  assert.equal(history.code, 0);
  assert.match(history.out.join('\n'), /item\.status/);

  // `ledger repo onboarded` flips the flag through the API.
  await fx.hub.ledger.setOnboarded('clicmds', false);
  const flip = await runCli(['repo', 'onboarded', 'clicmds'], env, '');
  assert.equal(flip.code, 0, flip.err.join('\n'));
  assert.deepEqual(flip.out, ['clicmds onboarded']);
  assert.equal(fx.hub.ledger.isOnboarded('clicmds'), true);
});

/* ---------------- hub not running → rule 5c (SPEC §10.3) ---------------- */

test('hub not running: edit in a DIFFERENT git repo than the session cwd → deny (rule 5c)', async (t) => {
  const home = await mkdtemp(join(tmpdir(), 'agent-ledger-5c-home-'));
  const foreign = await mkdtemp(join(tmpdir(), 'agent-ledger-5c-foreign-'));
  const ledger = await mkdtemp(join(tmpdir(), 'agent-ledger-5c-ledger-'));
  t.after(async () => {
    for (const d of [home, foreign, ledger]) await rm(d, { recursive: true, force: true });
  });
  // The git toplevel is found by walking up without git, so a `.git` directory is enough.
  const { mkdir } = await import('node:fs/promises');
  await mkdir(join(home, '.git'), { recursive: true });
  await mkdir(join(foreign, '.git'), { recursive: true });
  await mkdir(join(foreign, 'src'), { recursive: true });
  const env = { LEDGER_DIR: ledger, LEDGER_HUB_PORT: '1' } as NodeJS.ProcessEnv;

  const payload = (file: string): string =>
    JSON.stringify({
      session_id: 'aaaa1111',
      hook_event_name: 'PreToolUse',
      tool_name: 'Edit',
      cwd: home,
      tool_input: { file_path: file },
    });

  const denied = await runCli(['hook', 'pre-tool-use'], env, payload(join(foreign, 'src', 'a.ts')));
  assert.equal(denied.code, 0, 'the hook never fails hard');
  assert.equal(denied.out.length, 1, `expected one JSON line: ${JSON.stringify(denied.out)}`);
  const out = JSON.parse(denied.out[0] as string) as {
    hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
  };
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /Hub is not running/);
  // The hint is `ledger doctor --fix`, not a raw `launchctl kickstart -k`
  // — `-k` would kill a hub that is merely slow.
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /ledger doctor --fix/);
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /LEDGER_HUB_GUARD=off/);

  // Own repo, a new file in a new subdirectory, Bash, other events → silent.
  for (const [argv, body, why] of [
    [['hook', 'pre-tool-use'], payload(join(home, 'src', 'new', 'a.ts')), 'own repo'],
    [['hook', 'pre-tool-use'], payload('/etc/hosts'), 'outside a git repo'],
    [
      ['hook', 'pre-tool-use'],
      JSON.stringify({
        session_id: 'a',
        tool_name: 'Bash',
        cwd: home,
        tool_input: { command: `git -C ${foreign} reset --hard` },
      }),
      'Bash guard does not guess without a hub',
    ],
    [['hook', 'post-tool-use'], payload(join(foreign, 'src', 'a.ts')), 'other event'],
    [['hook', 'stop'], payload(join(foreign, 'src', 'a.ts')), 'stop'],
  ] as [string[], string, string][]) {
    const res = await runCli(argv, env, body);
    assert.equal(res.code, 0, why);
    assert.deepEqual(res.out, [], why);
  }

  // The kill switch applies without a hub too.
  const off = await runCli(
    ['hook', 'pre-tool-use'],
    { ...env, LEDGER_HUB_GUARD: 'off' },
    payload(join(foreign, 'src', 'a.ts')),
  );
  assert.deepEqual(off.out, [], 'LEDGER_HUB_GUARD=off → fail-open');
});

test('LEDGER_HUB_HEADLESS=1: the hook exits 0 immediately (no recursion into the hub)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-headless-hook-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const res = await runCli(
    ['hook', 'session-start'],
    { LEDGER_DIR: fx.dir, LEDGER_HUB_PORT: String(fx.hub.port), LEDGER_HUB_HEADLESS: '1' },
    JSON.stringify({ session_id: 'headless-1', cwd: dir }),
  );
  assert.equal(res.code, 0);
  assert.deepEqual(res.out, [], 'no briefing');
  assert.equal(fx.hub.sessions.get('headless-1'), null, 'the session was not even registered');
});

/* ---------------- guard, intrude, inbox, adopt, override (SPEC §7, §10–§11) ---------------- */

test('CLI: guard, intrude, inbox, adopt, override, release-notes', async (t) => {
  const fx = await startTestHub();
  const x = await makeCommittedRepo('clix');
  const z = await makeCommittedRepo('cliz');
  t.after(async () => {
    await fx.cleanup();
    await x.cleanup();
    await z.cleanup();
  });
  await fx.hub.ledger.registerRepo({ slug: 'clix', prefix: 'CX', path: x.path, onboarded: true });
  await fx.hub.ledger.registerRepo({ slug: 'cliz', prefix: 'CZ', path: z.path, onboarded: true });

  const env = (session: string, repo: string): NodeJS.ProcessEnv =>
    ({
      LEDGER_DIR: fx.dir,
      LEDGER_HUB_PORT: String(fx.hub.port),
      LEDGER_SESSION: session,
      LEDGER_REPO: repo,
    }) as NodeJS.ProcessEnv;
  const envA = env('aaaa1111', 'clix');
  const envB = env('bbbb2222', 'cliz');

  /* guard on/off/status */
  const status = await runCli(['guard', 'status'], envA, '', x.path);
  assert.equal(status.code, 0, status.err.join('\n'));
  assert.match(status.out.join('\n'), /Guard: on/);
  assert.match((await runCli(['guard', 'off'], envA, '', x.path)).out.join('\n'), /Guard: OFF/);
  assert.match((await runCli(['guard', 'on'], envA, '', x.path)).out.join('\n'), /Guard: on/);
  assert.equal((await runCli(['guard', 'nonsense'], envA, '', x.path)).code, 4);

  /* two sessions: A in clix, B in cliz */
  for (const [session, repo] of [
    ['aaaa1111', x.path],
    ['bbbb2222', z.path],
  ] as [string, string][]) {
    await runCli(
      ['hook', 'session-start'],
      env(session, session === 'aaaa1111' ? 'clix' : 'cliz'),
      JSON.stringify({ session_id: session, cwd: repo, source: 'startup' }),
    );
  }
  const bItem = await fx.api('POST', '/v1/items', {
    repo: 'cliz',
    title: 'need a change in clix',
    kind: 'BACKLOG',
    priority: 'P1',
  });

  /* intrude begin → commit → end, all without `--lease` (the CLI finds it) */
  const begin = await runCli(
    ['intrude', 'begin', '--repo', 'clix', '--item', String(bItem.json.id), '--paths', 'docs/api.md', '--intent', 'error mapping'],
    envB,
    '',
    z.path,
  );
  assert.equal(begin.code, 0, begin.err.join('\n'));
  assert.match(begin.out.join('\n'), /intrude \d+ · clix/);
  assert.match(begin.out.join('\n'), /commit --only -- docs\/api\.md/, 'prints the next step');

  await mkdir(join(x.path, 'docs'), { recursive: true });
  await writeFile(join(x.path, 'docs', 'api.md'), '# API\n', 'utf8');
  await git(x.path, ['add', 'docs/api.md']);
  await git(x.path, ['commit', '--only', '-m', `docs: api\n\nRefs: ${bItem.json.id}`, '--', 'docs/api.md']);
  const sha = (await git(x.path, ['rev-parse', 'HEAD'])).stdout.trim();

  const commit = await runCli(['intrude', 'commit', sha], envB, '', z.path);
  assert.equal(commit.code, 0, commit.err.join('\n'));
  assert.match(commit.out.join('\n'), /1 \S+ · inbox 1 sessions/);

  /* A reads the message with `ledger inbox` — and reading does NOT mark it delivered */
  const inbox = await runCli(['inbox'], envA, '', x.path);
  assert.equal(inbox.code, 0, inbox.err.join('\n'));
  assert.match(inbox.out.join('\n'), /📥 .*bbbb .*docs\/api\.md/);
  assert.match((await runCli(['inbox'], envA, '', x.path)).out.join('\n'), /docs\/api\.md/, '`ledger inbox` does not consume');

  assert.equal((await runCli(['intrude', 'end'], envB, '', z.path)).code, 0);
  assert.equal(
    (await runCli(['intrude', 'commit', sha], envB, '', z.path)).code,
    4,
    'it does not work without an open lease',
  );

  /* conflict → exit 2 + advice for `ledger add --requested-by` and `ledger block` */
  await writeFile(join(x.path, 'src.ts'), 'x\n', 'utf8');
  await runCli(
    ['hook', 'post-tool-use'],
    envA,
    JSON.stringify({ session_id: 'aaaa1111', tool_name: 'Edit', tool_input: { file_path: join(x.path, 'src.ts') } }),
  );
  const clash = await runCli(
    ['intrude', 'begin', '--repo', 'clix', '--item', String(bItem.json.id), '--paths', 'src.ts'],
    envB,
    '',
    z.path,
  );
  assert.equal(clash.code, 2, 'conflict = exit 2');
  const advice = clash.err.join('\n');
  assert.match(advice, /ledger add --repo clix/);
  assert.match(advice, new RegExp(`--requested-by ${bItem.json.id}`));
  assert.match(advice, new RegExp(`ledger block ${bItem.json.id} --by`));
  assert.match(advice, /--force/);

  /* override (requires a reason) and adopt */
  assert.equal((await runCli(['override', join(x.path, 'src.ts')], envB, '', z.path)).code, 4);
  const over = await runCli(
    ['override', join(x.path, 'src.ts'), '--reason', 'the user authorized it in chat'],
    envB,
    '',
    z.path,
  );
  assert.equal(over.code, 0, over.err.join('\n'));
  assert.match(over.out.join('\n'), /override src\.ts · \S+ aaaa/);

  await runCli(['hook', 'session-end'], envA, JSON.stringify({ session_id: 'aaaa1111', reason: 'other' }));
  // A token caller (the CLI) must name a registered, live session
  // for an owner-level action — register `cccc3333` first, same as `aaaa1111`
  // and `bbbb2222` above.
  const envC = env('cccc3333', 'clix');
  await runCli(
    ['hook', 'session-start'],
    envC,
    JSON.stringify({ session_id: 'cccc3333', cwd: x.path, source: 'startup' }),
  );
  const adopt = await runCli(['adopt', join(x.path, 'src.ts')], envC, '', x.path);
  assert.equal(adopt.code, 0, adopt.err.join('\n'));
  assert.match(adopt.out.join('\n'), /src\.ts → cccc/);

  /* release-notes */
  const notes = await runCli(['release-notes', '--repo', 'clix'], envA, '', x.path);
  assert.equal(notes.code, 0, notes.err.join('\n'));
  assert.match(notes.out.join('\n'), /^## /m);
});

/* ---------------- session-start budget, self-heal, retry ---------------- */

/**
 * A stand-in for the hub: only `POST /v1/hooks/*` and `GET /v1/healthz`, so
 * these tests measure the CLI's retry logic and nothing else.
 *
 * `LEDGER_SELFHEAL=0` in every env below — a unit test must never spawn
 * `launchctl` against the machine's own hub.
 */
async function mockHub(opts: { body?: string; hang?: boolean; listen?: boolean; port?: number }) {
  const { createServer } = await import('node:http');
  let hits = 0;
  const server = createServer((req, res) => {
    if (req.url === '/v1/healthz') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
      return;
    }
    hits += 1;
    req.resume();
    if (opts.hang === true) return; // never answers: the timeout path
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(opts.body ?? '');
  });
  const start = (port: number): Promise<void> =>
    new Promise((r) => {
      server.listen(port, '127.0.0.1', r);
    });
  if (opts.listen !== false) await start(opts.port ?? 0);
  const addr = server.address();
  return {
    port: typeof addr === 'object' && addr !== null ? String(addr.port) : String(opts.port ?? 0),
    hits: () => hits,
    start,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

async function ledgerWithToken(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-selfheal-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, '.hub'), { recursive: true });
  await writeFile(join(dir, '.hub', 'token'), 'x'.repeat(43), { mode: 0o600 });
  return dir;
}

/** A port nothing listens on: bound by the OS, then released. */
async function deadPort(): Promise<string> {
  const mock = await mockHub({});
  const port = mock.port;
  await mock.close();
  return port;
}

test('session-start — refused, hub comes up → briefing, no DOWN', async (t) => {
  const dir = await ledgerWithToken(t);
  const port = await deadPort();
  const env = {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: port,
    LEDGER_SELFHEAL: '0',
  } as NodeJS.ProcessEnv;

  // The hub appears 400 ms into the healthz poll — the launchd restart this
  // whole path exists for.
  const late = await mockHub({ body: 'BRIEFING OK', listen: false });
  t.after(() => late.close());
  const timer = setTimeout(() => void late.start(Number(port)), 400);
  t.after(() => clearTimeout(timer));

  const res = await runCli(['hook', 'session-start'], env, JSON.stringify({ session_id: 's1' }));
  assert.equal(res.code, 0);
  assert.deepEqual(res.err, []);
  assert.equal(res.out.join('|'), 'BRIEFING OK', 'the retry succeeds once the hub is up');
});

test('session-start — timeout → one retry and DOWN with an unchanged prefix', async (t) => {
  const dir = await ledgerWithToken(t);
  const mock = await mockHub({ hang: true });
  t.after(() => mock.close());
  const env = {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: mock.port,
    LEDGER_SELFHEAL: '0',
  } as NodeJS.ProcessEnv;

  const res = await runCli(['hook', 'session-start'], env, JSON.stringify({ session_id: 's2' }));
  assert.equal(res.code, 0);
  assert.deepEqual(res.err, []);
  assert.equal(res.out.length, 1);
  // Byte-identical prefix + sentence; only the reason is appended.
  assert.equal(
    (res.out[0] ?? '').startsWith('AGENT-LEDGER DOWN: ledger writes are queued and sent automatically.'),
    true,
    res.out[0],
  );
  assert.match(res.out[0] ?? '', /\(hub not answering\)$/);
  // Exactly two deliveries: attempt + the single retry. Sound only because the
  // hub's session-start upserts by session_id (see `sessionStartSend`).
  assert.equal(mock.hits(), 2, 'one attempt + one retry');
});

test('tool hook keeps its 1 s and a single attempt (no retry)', async (t) => {
  const dir = await ledgerWithToken(t);
  const mock = await mockHub({ hang: true });
  t.after(() => mock.close());
  const env = {
    LEDGER_DIR: dir,
    LEDGER_HUB_PORT: mock.port,
    LEDGER_SELFHEAL: '0',
  } as NodeJS.ProcessEnv;

  const started = Date.now();
  const res = await runCli(
    ['hook', 'post-tool-use'],
    env,
    JSON.stringify({ session_id: 's3', tool_name: 'Read' }),
  );
  const elapsed = Date.now() - started;
  assert.equal(res.code, 0);
  assert.deepEqual(res.out, [], 'the tool hook stays silent even when the hub is not answering');
  assert.equal(mock.hits(), 1, 'a tool hook never retries');
  assert.ok(elapsed < 2_200, `a tool hook must not stretch (${elapsed} ms)`);
});
