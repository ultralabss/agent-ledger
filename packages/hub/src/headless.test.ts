/** F3: headless intake triage and grooming with a fake `claude` binary. */

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  CLAUDE_HOME_READ_DENYLIST,
  HeadlessRunner,
  SHELL_ESCAPE_DENYLIST,
  buildHeadlessArgs,
  KEEPER_ALLOWED_BASH,
  nextMondayNine,
  resultText,
  stripFrontmatter,
} from './headless.ts';
import { matchGlob } from './guard/globs.ts';
import { openTestLedger } from './test-helpers.ts';

/** K7: `Read(...)` tool-permission pattern → checkout-relative path `matchGlob`
 *  understands, anchored at a fixed fake home so `~/` and `//<abs>` compare
 *  against the same root as the ledger paths under test. */
function denyPatternToRelPath(pattern: string, home: string): string {
  const inner = pattern.replace(/^Read\(/, '').replace(/\)$/, '');
  if (inner.startsWith('//')) return inner.slice(2);
  if (inner === '~') return home;
  if (inner.startsWith('~/')) return `${home}/${inner.slice(2)}`;
  return inner;
}

/** A fake `claude` that records its argv/env/cwd and answers like `-p --json`. */
async function fakeClaude(dir: string, body?: string): Promise<string> {
  const bin = join(dir, 'claude');
  await writeFile(
    bin,
    body ??
      `#!/bin/bash
{
  echo "ARGC=$#"
  for a in "$@"; do echo "ARG=$a"; done
  echo "CWD=$PWD"
  echo "HEADLESS=$LEDGER_HUB_HEADLESS"
  echo "AGENT=$LEDGER_AGENT"
  echo "SESSION=$LEDGER_SESSION"
} > "$(dirname "$0")/argv.txt"
printf '{"result":"Created: ACME-150, ACME-151 (2)","is_error":false}\\n'
`,
    'utf8',
  );
  await chmod(bin, 0o755);
  return bin;
}

async function fixture(t: { after: (fn: () => Promise<void> | void) => void }, body?: string) {
  const led = await openTestLedger();
  const binDir = await mkdtemp(join(tmpdir(), 'agent-ledger-bin-'));
  const agents = await mkdtemp(join(tmpdir(), 'agent-ledger-agents-'));
  await mkdir(agents, { recursive: true });
  await writeFile(
    join(agents, 'ledger-keeper.md'),
    `---\nname: ledger-keeper\ntools: Bash, Read\n---\nYou work only with the ledger through the CLI \`ledger\`.\nTriage: every piece of text → an item.\n`,
    'utf8',
  );
  const bin = await fakeClaude(binDir, body);
  t.after(async () => {
    await led.cleanup();
    await rm(binDir, { recursive: true, force: true });
    await rm(agents, { recursive: true, force: true });
  });
  const runner = new HeadlessRunner({
    trustStopAt: tmpdir(),
    ledger: led.ledger,
    config: { ...led.config, claudeBin: bin, agentsDir: agents },
  });
  return { led, runner, binDir, agents, bin };
}

test('stripFrontmatter: takes the agent body, a `---` in the text survives', () => {
  assert.equal(stripFrontmatter('---\nname: x\n---\nbody\n'), 'body\n');
  assert.equal(stripFrontmatter('no frontmatter\n'), 'no frontmatter\n');
  assert.match(stripFrontmatter('---\na: 1\n---\nA\n\n---\n\nB\n'), /A\n\n---\n\nB/);
});

test('resultText: `--output-format json` → the result field, otherwise raw stdout', () => {
  assert.equal(resultText('{"result":"done"}'), 'done');
  assert.equal(resultText('{"error":"nope"}'), 'nope');
  assert.equal(resultText('plain text'), 'plain text');
  assert.equal(resultText('{not json'), '{not json');
  assert.equal(resultText('   '), '');
});

test('nextMondayNine: always the nearest Monday 9:00, never in the past', () => {
  // 2026-09-28 is a Monday.
  const monday8 = new Date(2026, 8, 28, 8, 0, 0);
  const a = nextMondayNine(monday8);
  assert.equal(a.getDay(), 1);
  assert.equal(a.getHours(), 9);
  assert.equal(a.getDate(), 28, 'the same Monday if 9:00 has not happened yet');

  const monday10 = new Date(2026, 8, 28, 10, 0, 0);
  const b = nextMondayNine(monday10);
  assert.equal(b.getDate(), 5, 'after 9:00 only next week');
  assert.equal(b.getMonth(), 9);

  const wednesday = new Date(2026, 8, 30, 15, 0, 0);
  const c = nextMondayNine(wednesday);
  assert.equal(c.getDay(), 1);
  assert.ok(c.getTime() > wednesday.getTime());
});

test('runIntake: runs the binary with exact flags, cwd = ledger, headless env', async (t) => {
  const { led, runner, binDir } = await fixture(t);
  const rec = await led.ledger.createIntake({ text: 'do X and Y', channel: 'web' });

  const run = await runner.runIntake({ ids: [rec.id] });
  assert.equal(run.ok, true, run.text);
  assert.equal(run.kind, 'intake');
  assert.equal(run.ref, rec.id);
  assert.equal(run.text, 'Created: ACME-150, ACME-151 (2)');

  const argv = await readFile(join(binDir, 'argv.txt'), 'utf8');
  const args = argv
    .split('\n')
    .filter((l) => l.startsWith('ARG='))
    .map((l) => l.slice(4));
  assert.equal(args[0], '-p');
  assert.match(args[1] ?? '', /Triage the intake/);
  assert.equal(args[2], '--append-system-prompt');
  assert.match(args[3] ?? '', /You work only with the ledger/);
  assert.equal(args[3]?.includes('name: ledger-keeper'), false, 'the frontmatter is not sent');
  const ledgerRoot = led.ledger.paths.root.replace(/^\/+/, '');
  // The deny list is no longer spelled out again here. It used
  // to be a frozen literal, which meant every addition to
  // `CLAUDE_HOME_READ_DENYLIST` broke this test for the wrong reason — and,
  // worse, invited someone to "fix" it by deleting a deny rule. The structure
  // is asserted; the CONTENT of the rules is asserted against real match
  // behaviour in `headless.rules.test.ts`.
  const tail = args.slice(4);
  assert.deepEqual(
    tail.slice(0, KEEPER_ALLOWED_BASH.length + 3),
    ['--allowedTools', ...KEEPER_ALLOWED_BASH, `Read(//${ledgerRoot}/**)`, '--disallowedTools'],
    'allow list is exactly: the keeper ledger subcommands + the ledger dir',
  );
  assert.ok(!tail.includes('Bash(ledger *)'), 'UL-651: no blanket ledger allow');
  const deny = tail.slice(4, tail.indexOf('--permission-mode'));
  for (const rule of CLAUDE_HOME_READ_DENYLIST) {
    assert.ok(deny.includes(rule), `missing shared deny rule ${rule}`);
  }
  for (const rule of SHELL_ESCAPE_DENYLIST) {
    assert.ok(deny.includes(rule), `missing shell deny rule ${rule}`);
  }
  // The ledger's own `.hub/` is denied last, after the shared lists.
  assert.equal(deny.at(-1), `Read(//${ledgerRoot}/.hub/**)`);
  assert.deepEqual(
    args.slice(args.indexOf('--permission-mode')),
    ['--permission-mode', 'default', '--output-format', 'json'],
  );
  assert.equal(args.includes('--bare'), false, '--bare would disable subscription login');
  assert.equal(args.includes('--dangerously-skip-permissions'), false);

  assert.match(argv, /HEADLESS=1/);
  assert.match(argv, /AGENT=ledger-keeper/);
  assert.match(argv, /SESSION=headless-intake-/);
  assert.match(argv, new RegExp(`CWD=${led.dir.replace('/var/', '/private/var/')}|CWD=${led.dir}`));

  // Journal: `intake.triaged` with the result (SPEC F3).
  const events = led.ledger.listJournal('ops');
  const triaged = events.find((e) => e.type === 'intake.triaged');
  assert.ok(triaged, `missing journal intake.triaged: ${JSON.stringify(events)}`);
  assert.ok(triaged?.fields.join(' ').includes('Created: ACME-150'));
  assert.equal(runner.status.last?.ok, true);
  assert.equal(runner.status.configured, true);
});

test('J2: deny must not cover the ledger — real glob matching, not just a string comparison', () => {
  // A real run (verified manually): with the old
  // `Read(~/.claude/**)` triage could not read even its own `notes.md` in the
  // default ledger `~/.ledger`. K7: string equality on patterns would let any
  // deny shape that really behaves like `**` (e.g. `Read(~/.ledger/**)`) slip
  // through without the test noticing — so the very same `matchGlob` the guard
  // uses runs here on real paths.
  const home = 'home/user'; // fixed fake home, without the leading `/`
  const ledgerRoot = `/${home}/.ledger`;
  const args = buildHeadlessArgs(ledgerRoot, 'prompt', 'system');
  const denyStart = args.indexOf('--disallowedTools') + 1;
  const denyEnd = args.indexOf('--permission-mode');
  const deny = args.slice(denyStart, denyEnd).map((p) => denyPatternToRelPath(p, home));

  const mdPaths = [
    `${home}/.ledger/notes.md`,
    `${home}/.ledger/sub/deep/notes.md`,
  ];
  for (const path of mdPaths) {
    for (const pattern of deny) {
      assert.equal(matchGlob(pattern, path), false, `deny "${pattern}" would cover ${path}`);
    }
  }

  // `.hub/` (token/DB) MUST be covered by at least one deny pattern.
  const hubToken = `${home}/.ledger/.hub/token`;
  assert.ok(
    deny.some((pattern) => matchGlob(pattern, hubToken)),
    '.hub/token must be hit by at least one deny pattern',
  );

  // And the allow rule for the whole ledger (where the `.md` notes live) is still there.
  assert.ok(args.includes(`Read(//${ledgerRoot.replace(/^\/+/, '')}/**)`));
});

test('H2: the child gets an env allowlist, not process.env with secrets', async (t) => {
  const binDir = await mkdtemp(join(tmpdir(), 'agent-ledger-bin-'));
  const bin = join(binDir, 'claude');
  await writeFile(
    bin,
    `#!/bin/bash
env | sort > "$(dirname "$0")/env.txt"
printf '{"result":"ok","is_error":false}\\n'
`,
    'utf8',
  );
  await chmod(bin, 0o755);
  const led = await openTestLedger();
  const agents = await mkdtemp(join(tmpdir(), 'agent-ledger-agents-'));
  await writeFile(join(agents, 'ledger-keeper.md'), '---\nname: ledger-keeper\n---\nbody\n', 'utf8');
  t.after(async () => {
    await led.cleanup();
    await rm(binDir, { recursive: true, force: true });
    await rm(agents, { recursive: true, force: true });
  });
  const prevKey = process.env.ANTHROPIC_API_KEY;
  const prevToken = process.env.SOME_SERVICE_TOKEN;
  process.env.ANTHROPIC_API_KEY = 'sk-leak-me';
  process.env.SOME_SERVICE_TOKEN = 'also-leak-me';
  t.after(() => {
    if (prevKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = prevKey;
    if (prevToken === undefined) delete process.env.SOME_SERVICE_TOKEN;
    else process.env.SOME_SERVICE_TOKEN = prevToken;
  });
  const runner = new HeadlessRunner({
    trustStopAt: tmpdir(),
    ledger: led.ledger,
    config: { ...led.config, claudeBin: bin, agentsDir: agents },
  });
  await runner.runGroom({ repo: null });
  const dump = await readFile(join(binDir, 'env.txt'), 'utf8');
  assert.equal(dump.includes('ANTHROPIC_API_KEY'), false, 'the API key must not pass to the child');
  assert.equal(dump.includes('SOME_SERVICE_TOKEN'), false, '*_TOKEN must not pass to the child');
  assert.match(dump, /^PATH=/m);
  assert.match(dump, /^LEDGER_HUB_HEADLESS=1$/m);
});

test('J5: proxy/CA env passes to the child (not a secret, a network necessity)', async (t) => {
  const binDir = await mkdtemp(join(tmpdir(), 'agent-ledger-bin-'));
  const bin = join(binDir, 'claude');
  await writeFile(
    bin,
    `#!/bin/bash
env | sort > "$(dirname "$0")/env.txt"
printf '{"result":"ok","is_error":false}\\n'
`,
    'utf8',
  );
  await chmod(bin, 0o755);
  const led = await openTestLedger();
  const agents = await mkdtemp(join(tmpdir(), 'agent-ledger-agents-'));
  await writeFile(join(agents, 'ledger-keeper.md'), '---\nname: ledger-keeper\n---\nbody\n', 'utf8');
  t.after(async () => {
    await led.cleanup();
    await rm(binDir, { recursive: true, force: true });
    await rm(agents, { recursive: true, force: true });
  });
  const vars = {
    HTTPS_PROXY: 'http://proxy.example:8080',
    HTTP_PROXY: 'http://proxy.example:8080',
    NO_PROXY: 'localhost,127.0.0.1',
    https_proxy: 'http://proxy.example:8080',
    SSL_CERT_FILE: '/etc/ssl/corp-ca.pem',
    NODE_EXTRA_CA_CERTS: '/etc/ssl/corp-ca.pem',
  };
  const prev: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k];
    process.env[k] = v;
  }
  t.after(() => {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
  const runner = new HeadlessRunner({
    trustStopAt: tmpdir(),
    ledger: led.ledger,
    config: { ...led.config, claudeBin: bin, agentsDir: agents },
  });
  await runner.runGroom({ repo: null });
  const dump = await readFile(join(binDir, 'env.txt'), 'utf8');
  for (const [k, v] of Object.entries(vars)) {
    assert.match(dump, new RegExp(`^${k}=${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'), k);
  }
});

test('runGroom: is recorded as `groom` and kept in status.last_groom', async (t) => {
  const { led, runner } = await fixture(t);
  const run = await runner.runGroom({ repo: null });
  assert.equal(run.kind, 'groom');
  assert.equal(run.ok, true);
  assert.equal(runner.status.last_groom?.kind, 'groom');
  assert.ok(led.ledger.listJournal('ops').some((e) => e.type === 'groom'));
});

test('without LEDGER_CLAUDE_BIN it is a 503 with instructions, not a silent no-op', async (t) => {
  const led = await openTestLedger();
  t.after(led.cleanup);
  const runner = new HeadlessRunner({ ledger: led.ledger, config: { ...led.config, claudeBin: null }, trustStopAt: tmpdir() });
  assert.equal(runner.status.configured, false);
  await assert.rejects(runner.runIntake({ ids: ['1'] }), (err: Error & { status?: number }) => {
    assert.equal(err.status, 503);
    assert.match(err.message, /LEDGER_CLAUDE_BIN/);
    assert.match(err.message, /install\.sh|launchctl/);
    return true;
  });
});

test('a missing ledger-keeper.md is a 503, not a hub crash', async (t) => {
  const led = await openTestLedger();
  const binDir = await mkdtemp(join(tmpdir(), 'agent-ledger-bin-'));
  t.after(async () => {
    await led.cleanup();
    await rm(binDir, { recursive: true, force: true });
  });
  const runner = new HeadlessRunner({
    trustStopAt: tmpdir(),
    ledger: led.ledger,
    config: { ...led.config, claudeBin: await fakeClaude(binDir), agentsDir: join(binDir, 'missing') },
  });
  await assert.rejects(runner.runGroom(), /ledger-keeper/);
});

test('binary failure: ok=false, exit code in the run, the hub stays alive', async (t) => {
  const { runner } = await fixture(t, '#!/bin/bash\necho "crashed" >&2\nexit 7\n');
  const run = await runner.runIntake({ ids: ['1'] });
  assert.equal(run.ok, false);
  assert.equal(run.exit_code, 7);
  assert.match(run.text, /crashed/);
});

test('queue: two runs never start in parallel', async (t) => {
  const { runner } = await fixture(
    t,
    `#!/bin/bash
LOCK="$(dirname "$0")/lock"
if [ -e "$LOCK" ]; then echo '{"result":"PARALLEL"}'; exit 0; fi
: > "$LOCK"
sleep 0.3
rm -f "$LOCK"
printf '{"result":"ok"}\\n'
`,
  );
  const [a, b] = await Promise.all([
    runner.runIntake({ ids: ['1'] }),
    runner.runGroom({ repo: null }),
  ]);
  assert.equal(a.text, 'ok');
  assert.equal(b.text, 'ok', 'the second run waited in the queue, it did not start at once');
  assert.equal(runner.status.busy, false);
  assert.equal(runner.status.queued, 0);
});

test('a timeout kills the child and the run fails', async (t) => {
  const led = await openTestLedger();
  const binDir = await mkdtemp(join(tmpdir(), 'agent-ledger-bin-'));
  const agents = await mkdtemp(join(tmpdir(), 'agent-ledger-agents-'));
  await writeFile(join(agents, 'ledger-keeper.md'), 'agent body\n', 'utf8');
  t.after(async () => {
    await led.cleanup();
    await rm(binDir, { recursive: true, force: true });
    await rm(agents, { recursive: true, force: true });
  });
  const bin = await fakeClaude(binDir, '#!/bin/bash\nsleep 30\n');
  const runner = new HeadlessRunner({
    trustStopAt: tmpdir(),
    ledger: led.ledger,
    config: { ...led.config, claudeBin: bin, agentsDir: agents, headlessTimeoutMs: 1_000 },
  });
  const run = await runner.runIntake({ ids: ['1'] });
  assert.equal(run.ok, false);
  assert.match(run.text, /timeout/);
});

test('agentsDir unset: 503 with a clear message and the same text in the status', async (t) => {
  const led = await openTestLedger();
  const binDir = await mkdtemp(join(tmpdir(), 'agent-ledger-bin-'));
  t.after(async () => {
    await led.cleanup();
    await rm(binDir, { recursive: true, force: true });
  });
  const runner = new HeadlessRunner({
    trustStopAt: tmpdir(),
    ledger: led.ledger,
    config: { ...led.config, claudeBin: await fakeClaude(binDir), agentsDir: null },
  });
  assert.match(runner.status.bin_trust_detail ?? '', /agents dir not configured \(copy examples\/agents\/ledger-keeper\.md and set LEDGER_AGENTS_DIR\)/);
  await assert.rejects(runner.runGroom(), (err: Error & { status?: number }) => {
    assert.equal(err.status, 503);
    assert.match(err.message, /agents dir not configured/);
    return true;
  });
});
