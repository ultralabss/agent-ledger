/** End-to-end: real hub on a random port, real `ledger` process via spawn. */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { makeCodeRepo, startTestHub } from '@agent-ledger/hub/test-helpers';

const BIN = join(import.meta.dirname, 'bin.ts');

interface Run {
  code: number;
  stdout: string;
  stderr: string;
  lines: string[];
}

function ledger(args: string[], env: NodeJS.ProcessEnv, cwd = tmpdir()): Promise<Run> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => {
      stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (code) =>
      resolvePromise({
        code: code ?? -1,
        stdout,
        stderr,
        lines: stdout.replace(/\n$/, '').split('\n').filter((l) => l !== ''),
      }),
    );
  });
}

test('repo add --kind system|vps, path+kind is an error, repo ls shows the kind', async (t) => {
  const fx = await startTestHub();
  const code = await makeCodeRepo('acme');
  t.after(fx.cleanup);
  t.after(code.cleanup);
  const env = { LEDGER_HUB_URL: fx.url, LEDGER_DIR: fx.dir, LEDGER_SESSION: '61e0b33d' };

  const sys = await ledger(['repo', 'add', 'infra', '--kind', 'system', '--prefix', 'INF'], env);
  assert.equal(sys.code, 0, sys.stderr);
  assert.equal(sys.lines[0], 'infra INF system');

  const vps = await ledger(
    ['repo', 'add', 'vps-prod', '--kind', 'vps', '--host', 'web-host', '--prefix', 'VPS'],
    env,
  );
  assert.equal(vps.code, 0, vps.stderr);
  assert.equal(vps.lines[0], 'vps-prod VPS vps web-host');

  const bad = await ledger(
    ['repo', 'add', 'bad', '--kind', 'system', '--path', code.path, '--prefix', 'BAD'],
    env,
  );
  assert.notEqual(bad.code, 0);
  assert.match(bad.stderr, /has no path/);
  const badHost = await ledger(['repo', 'add', 'bad2', '--host', 'h', '--prefix', 'BAF'], env);
  assert.notEqual(badHost.code, 0);
  assert.match(badHost.stderr, /--host/);

  const ls = await ledger(['repo', 'ls'], env);
  assert.equal(ls.code, 0, ls.stderr);
  assert.ok(ls.lines.some((l) => /^infra INF next=1 open=0 system —$/.test(l)), ls.stdout);
  assert.ok(ls.lines.some((l) => /^vps-prod VPS next=1 open=0 vps web-host$/.test(l)), ls.stdout);
  assert.ok(ls.lines.some((l) => /^ops OPS next=1 open=0 system —$/.test(l)), ls.stdout);

  // claim without --paths works on a system/vps item (no checkout to resolve).
  const added = await ledger(['add', 'rotate logs', '--repo', 'vps-prod', '--priority', 'P1'], env);
  assert.equal(added.code, 0, added.stderr);
  const id = (added.lines[0] ?? '').split(' ')[0] ?? '';
  assert.match(id, /^VPS-1$/);
  const claim = await ledger(['claim', id, '--intent', 'logrotate'], env);
  assert.equal(claim.code, 0, claim.stderr);
});

test('CLI end-to-end: intake → add → claim → step → done → brief', async (t) => {
  const fx = await startTestHub();
  const code = await makeCodeRepo('acme');
  t.after(fx.cleanup);
  t.after(code.cleanup);
  const env = {
    LEDGER_HUB_URL: fx.url,
    LEDGER_DIR: fx.dir,
    LEDGER_SESSION: '61e0b33d',
    LEDGER_AGENT: 'backend-architect',
  };

  const add = await ledger(['repo', 'add', 'acme', '--path', code.path, '--prefix', 'ACME'], env);
  assert.equal(add.code, 0, add.stderr);
  assert.match(add.lines[0] ?? '', /^acme ACME /);

  const repos = await ledger(['repo', 'ls'], env);
  assert.equal(repos.code, 0);
  assert.equal(repos.lines.length, 2); // ops + acme

  const intake = await ledger(['intake', 'Settings tab with buttons, plus a billing page bug'], env, code.path);
  assert.equal(intake.code, 0, intake.stderr);
  const intakeId = (intake.lines[0] ?? '').split(' ')[0] ?? '';
  assert.match(intakeId, /^[1-9]\d+$/);
  const intakeLs = await ledger(['intake', 'ls', '--new'], env);
  assert.equal(intakeLs.lines.length, 1);

  // Repo resolved from cwd (git toplevel ↔ repos.yml), no --repo flag.
  const created = await ledger(
    [
      'add',
      'Settings tab with buttons',
      '--kind',
      'DEPLOY',
      '--priority',
      'P0',
      '--owner',
      'agent',
      '--area',
      'web',
      '--why',
      'cannot ship without it',
      '--step',
      'add handler',
      '--step',
      'test',
      '--intake',
      intakeId,
    ],
    env,
    code.path,
  );
  assert.equal(created.code, 0, created.stderr);
  assert.match(created.lines[0] ?? '', /^ACME-1 open P0 \[DEPLOY\] acme · Settings tab/);

  // `add --intake` marked the record by itself, without explicit triage.
  const auto = await ledger(['intake', 'show', intakeId], env);
  assert.equal(auto.code, 0, auto.stderr);
  assert.match(auto.lines[0] ?? '', new RegExp(`^${intakeId} triaged chat `));
  assert.match(auto.stdout, /items: ACME-1/);
  assert.match(auto.stdout, /Settings tab with buttons, plus a billing page bug/);
  // …so the brief does not count it as unprocessed.
  const lsAfter = await ledger(['intake', 'ls', '--new'], env);
  assert.equal(lsAfter.lines.length, 0, lsAfter.stdout);

  // `ledger intake show` without an id does not store a record with the text "show".
  const typo = await ledger(['intake', 'show'], env, code.path);
  assert.equal(typo.code, 4, typo.stdout);
  const afterTypo = await ledger(['intake', 'ls'], env);
  assert.equal(afterTypo.lines.length, 1, 'no new intake record');
  const reserved = await ledger(['intake', 'list'], env, code.path);
  assert.equal(reserved.code, 4, reserved.stdout);
  assert.match(reserved.stderr, /is a subcommand/);
  assert.equal((await ledger(['intake', 'ls'], env)).lines.length, 1);

  const triage = await ledger(['intake', 'triage', intakeId, '--items', 'ACME-1', '--drop', 'not this::done in ACME-0'], env);
  assert.equal(triage.code, 0, triage.stderr);
  assert.match(triage.lines[0] ?? '', /triaged → ACME-1$/);

  const claim = await ledger(['claim', 'acme-1', '--paths', 'apps/web/**', '--intent', 'Settings tab'], env);
  assert.equal(claim.code, 0, claim.stderr);
  assert.match(claim.lines[0] ?? '', /^ACME-1 doing /);

  const step = await ledger(['step', 'ACME-1', '1', 'done'], env);
  assert.equal(step.code, 0, step.stderr);
  assert.match(step.lines[0] ?? '', /^ACME-1 step 1 done · add handler$/);

  const note = await ledger(['note', 'ACME-1', 'watch out for mobile too'], env);
  assert.equal(note.code, 0, note.stderr);
  assert.match(note.lines[0] ?? '', /^ACME-1 comment c\d+ · backend-architect$/);

  const show = await ledger(['show', 'ACME-1'], env);
  assert.equal(show.code, 0);
  assert.ok(show.lines.some((l) => l.includes('backend-architect: watch out for mobile too')));
  assert.ok(show.lines.some((l) => l.includes('[x] 1. add handler')));

  const done = await ledger(['done', 'ACME-1', '--ref', 'v0.26.0'], env);
  assert.equal(done.code, 0, done.stderr);
  assert.match(done.lines[0] ?? '', /^ACME-1 done /);

  const decide = await ledger(['decide', 'Integer cents', '--why', 'No float rounding', '--related', 'ACME-1'], env, code.path);
  assert.equal(decide.code, 0, decide.stderr);
  assert.match(decide.lines[0] ?? '', /^D1 \d{4}-\d{2}-\d{2} acme · Integer cents$/);

  const log = await ledger(['log', 'Settings tab done, deploy pending', '--repo', 'acme'], env);
  assert.equal(log.code, 0, log.stderr);

  const history = await ledger(['history', '--repo', 'acme', '--since', '7d'], env);
  assert.equal(history.code, 0);
  assert.ok(history.lines.some((l) => l.includes('session.summary')));
  assert.ok(history.lines.some((l) => l.includes('item.created')));

  const brief = await ledger(['brief'], env, code.path);
  assert.equal(brief.code, 0, brief.stderr);
  assert.ok(brief.lines.length <= 30);
  assert.match(brief.lines[0] ?? '', /^acme · ACME · /);
  assert.match(brief.lines.at(-1) ?? '', /ledger brief --full · ledger history --since 14d$/);

  const status = await ledger(['status'], env);
  assert.equal(status.code, 0);
  assert.match(status.lines[0] ?? '', /^hub ok · port \d+ · ledger /);
});

test('CLI exit codes: 2 conflict · 3 hub not running · 4 validation · 5 secret', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const env = { LEDGER_HUB_URL: fx.url, LEDGER_DIR: fx.dir, LEDGER_SESSION: 'aaaa1111' };

  const created = await ledger(['add', 'task', '--repo', 'ops'], env);
  assert.equal(created.code, 0, created.stderr);

  const conflict = await ledger(['release', 'OPS-1'], env);
  assert.equal(conflict.code, 2, conflict.stderr);
  assert.match(conflict.stderr, /transition release is not allowed/);

  const validation = await ledger(['add', 'no repo'], env, tmpdir());
  assert.equal(validation.code, 4);
  assert.match(validation.stderr, /unknown repo — `ledger repo add/);

  const badFlag = await ledger(['drop', 'OPS-1'], env);
  assert.equal(badFlag.code, 4);
  assert.match(badFlag.stderr, /--why/);

  const secret = await ledger(
    ['add', `deploy with ghp_${'A1bCdEfGhIjKlMnOpQrStUvWxYz01'}`, '--repo', 'ops'],
    env,
  );
  assert.equal(secret.code, 5, secret.stderr);
  assert.match(secret.stderr, /secret scanner/);
  assert.match(secret.stderr, /github-token/);

  // `ls`/`show`/`brief` no longer fail when the hub is down — they read
  // the md ledger and say so. Exit 3 is now for the live-only commands, which
  // have nothing in md to fall back to.
  const downEnv = { ...env, LEDGER_HUB_URL: 'http://127.0.0.1:1' };
  const down = await ledger(['sessions'], downEnv);
  assert.equal(down.code, 3, down.stderr);
  assert.match(down.stderr, /hub is not running/);

  const offline = await ledger(['ls', '--repo', 'ops'], downEnv);
  assert.equal(offline.code, 0, offline.stderr);
  assert.match(offline.stdout, /offline — from the ledger, no live data/);
  assert.match(offline.stdout, /OPS-1/);

  const unknown = await ledger(['no-such-command'], env);
  assert.equal(unknown.code, 4);

  const help = await ledger(['help'], env);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /Exit: 0 ok · 2 conflict/);
});

test('S2: a foreign/https LEDGER_HUB_URL is exit 4, not an unhandled exception', async () => {
  const foreign = await ledger(['status'], {
    LEDGER_HUB_URL: 'http://evil.example.com:4747',
    LEDGER_DIR: tmpdir(),
  });
  assert.equal(foreign.code, 4, foreign.stderr);
  assert.match(foreign.stderr, /127\.0\.0\.1|localhost/);

  const https = await ledger(['status'], {
    LEDGER_HUB_URL: 'https://127.0.0.1:4747',
    LEDGER_DIR: tmpdir(),
  });
  assert.equal(https.code, 4, https.stderr);
});

test('status: a foreign process or a hub of another ledger on the port is NOT reported as ok', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const mine = await ledger(['status'], { LEDGER_HUB_URL: fx.url, LEDGER_DIR: fx.dir });
  assert.equal(mine.code, 0, mine.stderr);

  // Same hub, but the CLI believes in another ledger directory (same token file).
  const other = await mkdtemp(join(tmpdir(), 'ledger-status-other-'));
  t.after(() => rm(other, { recursive: true, force: true }));
  await mkdir(join(other, '.hub'), { recursive: true });
  await writeFile(join(other, '.hub', 'token'), await readFile(join(fx.dir, '.hub', 'token'), 'utf8'), {
    mode: 0o600,
  });
  const wrongLedger = await ledger(['status'], { LEDGER_HUB_URL: fx.url, LEDGER_DIR: other });
  assert.equal(wrongLedger.code, 3, wrongLedger.stdout);
  // T12: caught before the token is sent — the hub's ledger_id is not ours.
  assert.match(wrongLedger.stderr, /port held by another agent-ledger/);
  assert.doesNotMatch(wrongLedger.stdout, /^hub ok/m);

  // A stranger that answers `{ok:true}` to everything and never reveals a ledger.
  const stranger = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });
  await new Promise<void>((r) => stranger.listen(0, '127.0.0.1', r));
  t.after(
    () =>
      new Promise<void>((r) => {
        stranger.closeAllConnections();
        stranger.close(() => r());
      }),
  );
  const addr = stranger.address();
  const url = `http://127.0.0.1:${typeof addr === 'object' && addr !== null ? addr.port : 0}`;
  const foreign = await ledger(['status'], { LEDGER_HUB_URL: url, LEDGER_DIR: other });
  assert.equal(foreign.code, 3, foreign.stdout);
  assert.match(foreign.stderr, /refusing to send the hub token/);
  assert.equal(foreign.stdout, '');
});

test('repo bind: points a slug at a checkout, verifies the root commit', async (t) => {
  const fx = await startTestHub();
  const { git } = await import('@agent-ledger/hub/git');
  const mk = async (label: string) => {
    const repo = await makeCodeRepo(label);
    const res = await git(repo.path, ['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '--allow-empty', '-q', '-m', `root of ${label}`]);
    assert.equal(res.code, 0, res.stderr);
    const root = (await git(repo.path, ['rev-list', '--max-parents=0', 'HEAD'])).stdout.trim();
    return { ...repo, root };
  };
  const mine = await mk('bindcli-a');
  const other = await mk('bindcli-b');
  t.after(async () => {
    await fx.cleanup();
    await mine.cleanup();
    await other.cleanup();
  });
  await writeFile(
    fx.hub.ledger.paths.reposYml,
    `ops:\n  kind: system\n  prefix: OPS\napp:\n  prefix: APP\n  identity:\n    root_sha: ${mine.root}\n`,
    'utf8',
  );
  await fx.hub.ledger.queue.run(() => fx.hub.ledger.reindex());
  const env = { LEDGER_HUB_URL: fx.url, LEDGER_DIR: fx.dir, LEDGER_SESSION: '61e0b33d' };

  const bad = await ledger(['repo', 'bind', 'app', other.path], env);
  assert.notEqual(bad.code, 0);
  assert.match(bad.stderr, /different root commit/);
  assert.equal((await ledger(['repo', 'bind', 'app'], env)).code, 4, 'path is required');

  // relative path resolves against cwd
  const good = await ledger(['repo', 'bind', 'app', '.'], env, mine.path);
  assert.equal(good.code, 0, good.stderr);
  assert.match(good.lines[0] ?? '', /^app bound → .+/);
  const ls = await ledger(['repo', 'ls'], env);
  assert.ok(ls.lines.some((l) => l.startsWith('app APP ') && !l.endsWith(' —')), ls.stdout);
});
