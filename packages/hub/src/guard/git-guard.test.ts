/** Git guard parsing (SPEC §10.4). The table rows themselves are exercised
 *  end-to-end against a live hub in `http/f2.test.ts`; this file pins the parser,
 *  where a mistake means a FALSE DENY on a read-only command. */

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isAddAll,
  isCommitAll,
  isMutating,
  isPlainCommit,
  parseGitInvocations,
  tokenize,
  type GitInvocation,
} from './git-guard.ts';

function one(command: string, cwd: string | null = '/repo'): GitInvocation | undefined {
  return parseGitInvocations(command, cwd)[0];
}

test('parse: `git -C <p>` sets the checkout, and so does `cd <p> &&`', () => {
  assert.equal(one('git -C /other/repo status')?.cwd, '/other/repo');
  assert.equal(one('git -C /other/repo status')?.dashC, '/other/repo');
  assert.equal(one('cd /other && git status')?.cwd, '/other');
  assert.equal(one('cd sub && git status')?.cwd, '/repo/sub', 'relative `cd`');
  assert.equal(one('git status')?.cwd, '/repo', 'otherwise the session cwd');
  assert.equal(one('git -C sub status')?.cwd, '/repo/sub');
});

test('parse: chaining with `&&`, `;`, `||` and a newline yields several invocations', () => {
  const chain = parseGitInvocations('git add . && git commit -m x ; git push', '/repo');
  assert.deepEqual(
    chain.map((i) => i.subcommand),
    ['add', 'commit', 'push'],
  );
  assert.equal(parseGitInvocations('git status\ngit log', '/repo').length, 2);
  assert.equal(parseGitInvocations('git status || git log', '/repo').length, 2);
  // `cd` applies only to the rest of the chain that follows it.
  const after = parseGitInvocations('git status && cd /x && git log', '/repo');
  assert.equal(after[0]?.cwd, '/repo');
  assert.equal(after[1]?.cwd, '/x');
});

test('parse: global options before the subcommand are skipped', () => {
  assert.equal(one('git --no-pager log')?.subcommand, 'log');
  assert.equal(one('git -c core.pager=cat status')?.subcommand, 'status');
  assert.equal(one('/usr/bin/git status')?.subcommand, 'status');
  assert.equal(one('env GIT_PAGER=cat git status')?.subcommand, 'status');
  assert.equal(one('GIT_PAGER=cat git status')?.subcommand, 'status');
  // `--git-dir` cannot be mapped to a checkout → cwd is unknown (the guard stays silent).
  assert.equal(one('git --git-dir=/x/.git status')?.cwd, null);
});

test('parse: what cannot be parsed honestly is not policed (no false deny)', () => {
  assert.deepEqual(parseGitInvocations('git status $(echo x)', '/repo'), []);
  assert.deepEqual(parseGitInvocations('(cd /x && git reset --hard)', '/repo'), []);
  assert.deepEqual(parseGitInvocations('echo `git reset`', '/repo'), []);
  // `echo git reset` only mentions `git`/`reset`, it does not run them — `echo` is not
  // on the list of wrappers that actually execute their arguments (J8).
  assert.deepEqual(parseGitInvocations('echo git reset', '/repo'), []);
  assert.deepEqual(parseGitInvocations('rm -rf /', '/repo'), []);
  assert.deepEqual(parseGitInvocations('', '/repo'), []);
});

test('tokenize: quotes, escaping, paths with spaces', () => {
  assert.deepEqual(tokenize('git commit -m "a b"'), ['git', 'commit', '-m', 'a b']);
  assert.deepEqual(tokenize("git commit -m 'a b'"), ['git', 'commit', '-m', 'a b']);
  assert.deepEqual(tokenize('git -C "/a b/c" status'), ['git', '-C', '/a b/c', 'status']);
  assert.deepEqual(tokenize('git commit -m ""'), ['git', 'commit', '-m', ''], 'empty argument');
  assert.equal(tokenize('git $(id)'), null);
});

test('isMutating: exactly row 1 of the §10.4 table', () => {
  for (const sub of ['checkout', 'switch', 'reset', 'rebase', 'merge', 'pull']) {
    assert.equal(isMutating(one(`git ${sub} main`) as GitInvocation), true, sub);
  }
  // S5: `restore`, `cherry-pick`, `revert`, `am` were missing from the table and would delete
  // another session's uncommitted files just like `checkout`.
  assert.equal(isMutating(one('git restore .') as GitInvocation), true);
  assert.equal(isMutating(one('git restore --staged a.ts') as GitInvocation), true);
  assert.equal(isMutating(one('git cherry-pick abc123') as GitInvocation), true);
  assert.equal(isMutating(one('git revert HEAD') as GitInvocation), true);
  assert.equal(isMutating(one('git am patch.eml') as GitInvocation), true);
  // `clean` is denied only with a force flag — without it git deletes nothing anyway.
  assert.equal(isMutating(one('git clean -fd') as GitInvocation), true, '-fd is a bundle with f');
  assert.equal(isMutating(one('git clean --force') as GitInvocation), true);
  assert.equal(isMutating(one('git clean -n') as GitInvocation), false, 'a dry run is a read');
  assert.equal(isMutating(one('git clean') as GitInvocation), false, 'nothing is deleted without -f');
  assert.equal(isMutating(one('git stash') as GitInvocation), true, 'bare stash = push');
  assert.equal(isMutating(one('git stash push') as GitInvocation), true);
  assert.equal(isMutating(one('git stash list') as GitInvocation), false, 'stash list is a read');
  assert.equal(isMutating(one('git stash show') as GitInvocation), false);
  assert.equal(isMutating(one('git branch -d task/x') as GitInvocation), true);
  assert.equal(isMutating(one('git branch -D task/x') as GitInvocation), true);
  assert.equal(isMutating(one('git branch -m a b') as GitInvocation), true);
  assert.equal(isMutating(one('git branch') as GitInvocation), false, 'listing branches is a read');
  assert.equal(isMutating(one('git branch --list') as GitInvocation), false);
  assert.equal(isMutating(one('git worktree remove ../x') as GitInvocation), true);
  assert.equal(isMutating(one('git worktree list') as GitInvocation), false);
  assert.equal(isMutating(one('git worktree add ../x -b y') as GitInvocation), false);
});

test('S5: `--help`, `--dry-run` and `--show-current-patch` are never denied', () => {
  // The re-audit found a false deny: `restore|cherry-pick|revert|am` were in
  // MUTATING regardless of arguments. A false deny is worse than a false allow.
  for (const cmd of [
    'git restore --help',
    'git restore -h',
    'git am --help',
    'git am --show-current-patch',
    'git am --show-current-patch=diff',
    'git revert --help',
    'git cherry-pick --help',
    'git checkout --help',
    'git merge --help',
    'git clean -n',
    'git clean --dry-run',
    'git clean -fdn',
    'git clean',
    'git rebase --dry-run',
  ]) {
    assert.equal(isMutating(one(cmd) as GitInvocation), false, cmd);
  }
  // And real mutations were not weakened by this.
  for (const cmd of [
    'git restore .',
    'git restore src/a.ts',
    'git clean -fd',
    'git clean --force',
    'git cherry-pick abc1234',
    'git revert HEAD',
    'git revert -n HEAD',
    'git am patch.mbox',
  ]) {
    assert.equal(isMutating(one(cmd) as GitInvocation), true, cmd);
  }
});

test('J1: `git stash` reads significantArgs, not raw args — the value of `-m`/`--message` does not bypass STASH_READS', () => {
  for (const cmd of ['git stash -m list', 'git stash --message show', 'git stash -m list -- .']) {
    assert.equal(isMutating(one(cmd) as GitInvocation), true, cmd);
  }
  assert.equal(isMutating(one('git stash list') as GitInvocation), false);
  assert.equal(isMutating(one('git stash show') as GitInvocation), false);
});

test('J7: `git branch` deny knows delete/move/copy/force/upstream, list/show is a read', () => {
  for (const cmd of [
    'git branch --delete task/x',
    'git branch --move a b',
    'git branch -c a b',
    'git branch -C a b',
    'git branch --copy a b',
    'git branch -f task/x main',
    'git branch --force task/x main',
    'git branch --set-upstream-to origin/main',
    'git branch -u origin/main',
    'git branch --unset-upstream',
    'git branch --edit-description',
  ]) {
    assert.equal(isMutating(one(cmd) as GitInvocation), true, cmd);
  }
  for (const cmd of [
    'git branch',
    'git branch -a',
    'git branch --list',
    'git branch -v',
    'git branch --show-current',
    'git branch --contains main',
  ]) {
    assert.equal(isMutating(one(cmd) as GitInvocation), false, cmd);
  }
});

test('J8: common wrappers are unwrapped (`sh -c`, `command`, `exec`, `nice`/`nohup`/`time`)', () => {
  assert.equal(isMutating(one('sh -c "git stash -m list"') as GitInvocation), true);
  assert.equal(isMutating(one('bash -lc "git branch -D task/x"') as GitInvocation), true);
  assert.equal(isMutating(one('zsh -ec "git reset --hard"') as GitInvocation), true);
  assert.equal(one('sh -c "git status"')?.subcommand, 'status');
  assert.equal(one('command git status')?.subcommand, 'status');
  assert.equal(one('exec git status')?.subcommand, 'status');
  assert.equal(one('nice git status')?.subcommand, 'status');
  assert.equal(one('nice -n 10 git status')?.subcommand, 'status');
  assert.equal(one('nohup git status')?.subcommand, 'status');
  assert.equal(one('time git status')?.subcommand, 'status');
  assert.equal(isMutating(one('nice -n 10 git reset --hard') as GitInvocation), true);
});

test('J8: a wrapper that cannot be unwrapped positionally (`xargs`, `parallel`) is a fail-closed deny when it carries a mutating subcommand together with `git`', () => {
  assert.equal(isMutating(one('xargs git checkout') as GitInvocation), true, 'we cannot know what the checkout applies to');
  assert.equal(
    isMutating(one('parallel git reset --hard ::: a b') as GitInvocation),
    true,
  );
  // A read-only subcommand through the same wrapper path is not denied blindly.
  assert.deepEqual(parseGitInvocations('xargs git status', '/repo'), []);
});

test('H1: an option value (`-m`, `-e`, …) does not bypass the guard via isReadOnlyForm', () => {
  for (const cmd of [
    'git stash push -m --dry-run',
    'git merge -m -h somebranch',
    'git clean -fd -e -n',
    'git clean -e -n -fd',
    'git reset --hard --dry-run',
    'git checkout -h foo',
    'git stash push -m -h',
    'git merge --message=--dry-run x',
  ]) {
    assert.equal(isMutating(one(cmd) as GitInvocation), true, cmd);
  }
  for (const cmd of [
    'git stash --help',
    'git clean -n',
    'git clean -fdn',
    'git push --dry-run',
    'git add --dry-run .',
  ]) {
    assert.equal(isMutating(one(cmd) as GitInvocation), false, cmd);
  }
});

test('isMutating: read commands never (negative cases from the spec)', () => {
  for (const cmd of [
    'git status',
    'git status --porcelain=v2 -b',
    'git log --oneline -5',
    'git diff --name-only',
    'git diff HEAD~1',
    'git show HEAD',
    'git rev-parse HEAD',
    'git for-each-ref refs/tags',
    'git describe --tags',
    'git blame a.ts',
    'git ls-files',
    'git fetch --dry-run',
  ]) {
    const inv = one(cmd) as GitInvocation;
    assert.equal(isMutating(inv), false, cmd);
    assert.equal(isAddAll(inv), false, cmd);
    assert.equal(isCommitAll(inv), false, cmd);
    assert.equal(isPlainCommit(inv), false, cmd);
  }
});

test('isAddAll / isCommitAll: row 2 of the table', () => {
  for (const cmd of ['git add -A', 'git add --all', 'git add .', 'git add -A .']) {
    assert.equal(isAddAll(one(cmd) as GitInvocation), true, cmd);
  }
  assert.equal(isAddAll(one('git add src/a.ts') as GitInvocation), false);
  assert.equal(isAddAll(one('git add -p src/a.ts') as GitInvocation), false);
  for (const cmd of ['git commit -a -m x', 'git commit --all -m x', 'git commit -am x']) {
    assert.equal(isCommitAll(one(cmd) as GitInvocation), true, cmd);
  }
  assert.equal(isCommitAll(one('git commit -m x') as GitInvocation), false);
  assert.equal(
    isCommitAll(one('git commit --amend -m x') as GitInvocation),
    false,
    '`--amend` is not a bundle of short flags',
  );
});

test('isPlainCommit: `--only` / `-- <paths>` is the safe form, not a deny candidate', () => {
  assert.equal(isPlainCommit(one('git commit -m x') as GitInvocation), true);
  assert.equal(isPlainCommit(one('git commit --only -- a.ts') as GitInvocation), false);
  assert.equal(isPlainCommit(one('git commit --only -- a.ts b.ts') as GitInvocation), false);
  assert.equal(isPlainCommit(one('git commit -o a.ts') as GitInvocation), false);
  assert.equal(isPlainCommit(one('git commit -m x -- a.ts') as GitInvocation), false);
  assert.equal(isPlainCommit(one('git commit -a -m x') as GitInvocation), false, 'that is row 2');
});

test('K1: basename normalization of the command head before lookup in the wrapper sets', () => {
  assert.equal(one('/bin/sh -c "git status"')?.subcommand, 'status', '/bin/sh as sh');
  assert.equal(one('/bin/bash -lc "git status"')?.subcommand, 'status', '/bin/bash as bash');
  assert.equal(one('/usr/bin/env git status')?.subcommand, 'status', '/usr/bin/env as env');
  assert.equal(
    isMutating(one('/bin/sh -c "git reset --hard x"') as GitInvocation),
    true,
    'a mutating command through the full path to the shell must not be lost',
  );
  assert.deepEqual(
    parseGitInvocations('/usr/bin/xargs git status', '/repo'),
    [],
    '/usr/bin/xargs (read subcommand) must not be denied fail-closed',
  );
  assert.equal(
    isMutating(one('/usr/bin/xargs git reset --hard') as GitInvocation),
    true,
    '/usr/bin/xargs with a mutating subcommand stays fail-closed',
  );
});

test('K2: `--set-upstream-to=x` mutates the branch just like `--set-upstream-to x`', () => {
  assert.equal(isMutating(one('git branch --set-upstream-to=origin/main') as GitInvocation), true);
  assert.equal(isMutating(one('git branch --set-upstream-to origin/main') as GitInvocation), true);
  // Without `=` and without a mutating flag the original behaviour still applies.
  assert.equal(isMutating(one('git branch -a') as GitInvocation), false);
});

test('K3: `xargs`/`find`/`parallel` with `git stash|branch|worktree list` is not a false deny', () => {
  assert.deepEqual(parseGitInvocations('xargs git branch --list', '/repo'), []);
  assert.deepEqual(parseGitInvocations('xargs git worktree list', '/repo'), []);
  assert.deepEqual(parseGitInvocations('xargs git stash list', '/repo'), []);
  // A really mutating word behind the same unwrappable wrapper stays denied.
  assert.equal(isMutating(one('xargs git reset --hard') as GitInvocation), true);
});

test('K8: `bash -c -- "…"` — `--` after `-c` is skipped, it is not the command', () => {
  assert.equal(one('bash -c -- "git status"')?.subcommand, 'status');
  assert.equal(
    isMutating(one('bash -c -- "git reset --hard x"') as GitInvocation),
    true,
  );
});

test('pipe `|` and `|&` are segment separators, not outside the guard reach', () => {
  const piped = parseGitInvocations('true | git reset --hard x', '/repo');
  assert.equal(piped.length, 1);
  assert.equal(isMutating(piped[0] as GitInvocation), true);
  const pipedAmp = parseGitInvocations('true |& git reset --hard x', '/repo');
  assert.equal(pipedAmp.length, 1);
  assert.equal(isMutating(pipedAmp[0] as GitInvocation), true);
  // Read commands on both sides of the pipe are still two, both reads.
  const chain = parseGitInvocations('git log | git status', '/repo');
  assert.deepEqual(
    chain.map((i) => i.subcommand),
    ['log', 'status'],
  );
});

test('ANSI-C quoting `$\'…\'` is tokenized as one token without `$`, with escape sequences', () => {
  assert.deepEqual(tokenize("git commit -m $'line1\\nline2'"), [
    'git',
    'commit',
    '-m',
    'line1\nline2',
  ]);
  assert.deepEqual(tokenize("git $'\\tstatus'"), ['git', '\tstatus']);
  assert.deepEqual(tokenize("echo $'a\\\\b'"), ['echo', 'a\\b']);
  assert.deepEqual(tokenize("echo $'it\\'s'"), ['echo', "it's"]);
});

test('a subcommand delivered via stdin behind `xargs` is a fail-closed deny', () => {
  // `echo 'reset --hard' | xargs git -C /r` really runs `git -C /r reset
  // --hard`. The subcommand is NOT in the command text, so the old positional parser
  // judged it as "no subcommand → does not mutate" and allowed it — making stdin
  // a bypass of the guard for all mutating subcommands at once.
  const stdin = parseGitInvocations("echo 'reset --hard' | xargs git -C /r", '/repo');
  assert.equal(stdin.length, 1, 'the xargs segment must generate an invocation to judge');
  assert.equal(isMutating(stdin[0] as GitInvocation), true);

  for (const cmd of [
    'xargs git',
    'xargs git -C /r',
    'xargs -n1 git',
    'xargs -I r git -C r',
    'xargs /usr/bin/git',
    'time xargs git -C /r',
    'xargs -d \'\\n\' git',
  ]) {
    const invs = parseGitInvocations(cmd, '/repo');
    assert.equal(invs.length, 1, `${cmd}: missing invocation`);
    assert.equal(isMutating(invs[0] as GitInvocation), true, `${cmd} must be deny`);
  }

  // Pipe: a read on the left, `xargs git` without a subcommand on the right.
  const piped = parseGitInvocations('git ls-files | xargs git', '/repo');
  assert.deepEqual(
    piped.map((i) => isMutating(i)),
    [false, true],
  );
});

test('`parallel git :::` — the subcommand is in the arguments, not in position', () => {
  for (const cmd of [
    "parallel git ::: 'reset --hard'",
    'parallel git ::: reset',
    'parallel -j2 git ::: reset',
    'parallel git ::::+ reset',
    'parallel git ::: status',
  ]) {
    const invs = parseGitInvocations(cmd, '/repo');
    assert.equal(invs.length, 1, `${cmd}: missing invocation`);
    assert.equal(isMutating(invs[0] as GitInvocation), true, `${cmd} must be deny`);
  }
});

test('fail-closed must NOT trigger when the subcommand is present or the wrapper does not run git', () => {
  // A positional subcommand is present → the verdict is exactly as before (allow).
  for (const cmd of [
    'xargs git log',
    'xargs git blame a.txt',
    'xargs git -C /r status',
    'xargs git ls-files',
    'xargs git branch --list',
    'xargs git stash list',
  ]) {
    assert.deepEqual(parseGitInvocations(cmd, '/repo'), [], `${cmd} must stay allow`);
  }
  // `git` is merely an argument of another command — this is the false deny the
  // guard must not have (`grep git` over tracked files is an ordinary command).
  for (const cmd of [
    'git ls-files | xargs grep git',
    'git ls-files | xargs -n1 grep git',
    'xargs echo git',
    'xargs grep -n git',
  ]) {
    const invs = parseGitInvocations(cmd, '/repo');
    assert.ok(
      invs.every((i) => !isMutating(i)),
      `${cmd} must stay allow`,
    );
  }
  // `find -exec` spells out the whole command on the line, so nothing changes for it.
  assert.deepEqual(parseGitInvocations('find . -name x -exec git status \;', '/repo'), []);
});

test('R1: a placeholder token/custom placeholder in the subcommand position is a fail-closed deny', () => {
  for (const cmd of [
    "echo 'reset --hard' | xargs -I {} git -C /r {}",
    'xargs -I{} git -C /r {}',
    'xargs -I% git -C /r %',
    'xargs -J% git -C /r %',
    "parallel git {} ::: 'reset --hard'",
  ]) {
    const invs = parseGitInvocations(cmd, '/repo');
    assert.equal(invs.length, 1, `${cmd}: missing invocation`);
    assert.equal(isMutating(invs[0] as GitInvocation), true, `${cmd} must be deny`);
  }
  // A placeholder name equal to a real subcommand in the text ("stash") must not
  // trigger fail-closed — the subcommand IS on the line, it is just the same word.
  assert.deepEqual(parseGitInvocations('xargs -I stash git stash list', '/repo'), []);
});

test('R2: a call wrapper (`env`/`command`/`nice`/`nohup`) before `git` behind `xargs`/`parallel` is unwrapped', () => {
  for (const cmd of [
    'xargs env git -C /r',
    'xargs command git -C /r',
    'xargs nice git -C /r',
    'xargs nohup git -C /r',
    "parallel env git -C /r ::: 'reset --hard'",
  ]) {
    const invs = parseGitInvocations(cmd, '/repo');
    assert.equal(invs.length, 1, `${cmd}: missing invocation`);
    assert.equal(isMutating(invs[0] as GitInvocation), true, `${cmd} must be deny`);
  }
  // Not git at all → no change.
  assert.deepEqual(parseGitInvocations('xargs -n1 grep git', '/repo'), []);
});

test('R3: an `sh -c` payload behind `xargs`/`parallel` with "$@"/a missing subcommand is deny', () => {
  const invs = parseGitInvocations("echo 'reset --hard' | xargs sh -c 'git -C /r \"$@\"' _", '/repo');
  assert.equal(invs.length, 1);
  assert.equal(isMutating(invs[0] as GitInvocation), true);
  // A full subcommand in the payload stays allow/deny exactly by its content.
  assert.deepEqual(parseGitInvocations('xargs sh -c "git log --grep merge"', '/repo'), []);
});

test('R4: an attached flag value (`-I{}`, `-I%`) is recognized as a placeholder, not as the command word', () => {
  const invs = parseGitInvocations('xargs -I{} git -C /r {}', '/repo');
  assert.equal(isMutating(invs[0] as GitInvocation), true);
});
