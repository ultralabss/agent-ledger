/** The Bash allowlist is a security-shaped predicate: a wrong `true`
 *  silently drops file attribution for a command that wrote something, a wrong
 *  `false` costs one HTTP round trip. So the table below is mostly about the
 *  commands that must NOT be skipped. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { isReadOnlyBash } from './hook-bash.ts';

/** Skippable: provably cannot write and cannot run anything unvetted. */
const SKIP = [
  'ls',
  'ls -la /tmp',
  'cat package.json',
  'head -40 src/hook.ts',
  'tail -n 5 log.txt',
  'wc -l src/*.ts',
  'rg isReadOnlyBash',
  'rg -n --glob "*.ts" TODO',
  'grep -i -rn needle src',
  'find . -name "*.ts"',
  'find packages -type f -newer package.json',
  'stat -f %m package.json',
  'file dist/hook/bin.js',
  'pwd',
  'which node',
  'echo hello world',
  'printf "%s" x',
  'date',
  'env',
  'printenv HOME',
  'node -v',
  'pnpm --version',
  'true',
  'false',
  'test -f package.json',
  '[ -d src ]',
  'ledger ls --open',
  'ledger note ACME-37 "measure p95"',
  // Pipelines: every segment has to pass on its own.
  'rg -n TODO src | head -20',
  'cat package.json | wc -l',
  'git status --short | wc -l',
  // git readers
  'git status',
  'git log --oneline -5',
  'git diff --stat',
  'git show HEAD',
  'git rev-parse --abbrev-ref HEAD',
  'git branch',
  'git branch --list "task/*"',
  'git branch -a',
  'git remote -v',
  'git ls-files',
  'git blame -L 1,20 src/hook.ts',
  'git grep -n runHook',
  'git --no-pager log -1',
  'git -C /tmp/repo status --short',
  // Regression: --pre-glob is a different, harmless rg flag and must
  // not be caught by a naive prefix match on `--pre`.
  'rg --pre-glob "*.ts" TODO',
];

/** Must reach the hub. Each entry pairs with the reason it is not skippable. */
const SEND: [string, string][] = [
  ['', 'empty command'],
  ['   ', 'whitespace only'],
  ['rm -rf /tmp/x', 'head is not in the allowlist'],
  ['sed -i "" s/a/b/ f.ts', 'sed is not in the allowlist at all'],
  ['python script.py', 'unknown interpreter'],
  ['ls; rm -rf x', '; chains another command'],
  ['ls && rm -rf x', '&& chains'],
  ['ls || true', '|| — empty segment'],
  ['ls &', 'background'],
  ['cat f > out.txt', 'redirection writes a file'],
  ['cat f >> out.txt', 'append'],
  ['cat < in.txt', 'input redirection'],
  ['cat f | tee out.txt', 'tee is not in the allowlist'],
  ['echo $(whoami)', 'substitution'],
  ['echo `whoami`', 'backticks'],
  ['echo $HOME', 'variable expansion'],
  ['echo ${HOME}', 'variable expansion'],
  ['find . -name "*.ts" -exec rm {} ;', '-exec runs a program'],
  ['find . -name "*.tmp" -delete', '-delete deletes'],
  ['find . -fprintf out.txt "%p"', '-fprintf writes'],
  ['env FOO=bar rm -rf x', 'env with arguments runs a command'],
  ['env PATH=/x ls', 'env with arguments'],
  ['node script.js', 'node other than -v'],
  ['node -e "require(\\"fs\\")"', 'node -e'],
  ['pnpm test', 'pnpm other than -v'],
  ['pnpm build', 'pnpm other than -v'],
  ['git commit -m x', 'mutating git'],
  ['git checkout main', 'mutating git'],
  ['git add -A', 'mutating git'],
  ['git stash', 'mutating git'],
  ['git branch -d task/x', 'branch deletion'],
  ['git branch -m a b', 'branch rename'],
  ['git remote add o git@x:y.git', 'remote add'],
  ['git remote', 'remote without -v is not in the contract'],
  ['git -c core.pager=sh log', '-c runs the pager from config'],
  ['git log --ext-diff', 'external diff program'],
  ['git grep -O needle', '-O opens a pager'],
  ['git diff --output=f.txt', 'writes a file'],
  ['git diff --output f.txt', 'writes a file'],
  ['git', 'git without a subcommand'],
  ['git -C', '-C without a path'],
  ['ls "unterminated', 'unterminated quote'],
  ['rg "a;b"', 'metacharacter even inside quotes → not risked'],
  ['ls \\\n -la', 'backslash/newline'],
  ['ls\tsrc', 'tab as a separator is not parsed'],
  ['cat a | head | wc -l | tail -1 | wc -c', 'pipeline too long'],
  ['ls | rm -rf x', 'second segment is not a reader'],
  [`echo ${'x'.repeat(4100)}`, 'over the length limit'],
  ['FOO=bar ls', 'env prefix — head is not in the allowlist'],
  ['!ls', 'history expansion'],
  ['(ls)', 'subshell'],
  ['{ ls; }', 'group'],
  // Attached/`=`-form flags bypassed the exact-match check.
  ['rg --pre /tmp/evil foo', '--pre runs a program'],
  ['rg --pre=/tmp/evil foo', '--pre= runs a program'],
  ['rg --hostname-bin /tmp/evil foo', '--hostname-bin runs a program'],
  ['rg --hostname-bin=/tmp/evil foo', '--hostname-bin= runs a program'],
  ['rg --search-zip foo', '--search-zip runs a decompressor'],
  ['git grep -O/tmp/evil foo', '-O with an attached value opens a pager'],
  ['git grep --open-files-in-pager=/tmp/evil foo', '--open-files-in-pager= opens a pager'],
  ['git log --textconv', 'external textconv driver'],
  ['git diff --output=f.txt', 'writes a file (= form)'],
  ['git diff -oF.txt', 'writes a file (-o attached)'],
];

test('isReadOnlyBash: skip table — read-only commands do not go to the hub', () => {
  for (const cmd of SKIP) {
    assert.equal(isReadOnlyBash(cmd), true, `should be skipped: ${cmd}`);
  }
});

test('isReadOnlyBash: send table — everything else goes to the hub', () => {
  for (const [cmd, why] of SEND) {
    assert.equal(isReadOnlyBash(cmd), false, `should be sent (${why}): ${cmd}`);
  }
});

test('isReadOnlyBash: non-string input is never skipped', () => {
  for (const value of [undefined, null, 42, {}, ['ls'], true]) {
    assert.equal(isReadOnlyBash(value), false, String(value));
  }
});
