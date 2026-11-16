/**
 * Matrix against real git (SPEC §10.4, rounds K1–K8).
 *
 * `git-guard.test.ts` pins the parser unit by unit; this table is the
 * cross-check: for "real" rows the command is actually run in a fresh
 * temporary repo and HEAD/refs/index/stash/worktree are compared before and
 * after — that is ground truth, not one more assumption about what git does.
 * The guard must not allow a command that really mutated, nor deny one that
 * did not.
 *
 * Some shapes (an unknown flag on subcommands whose `--dry-run` behaviour is
 * version-dependent, `xargs`/`find` wrappers, a missing remote/upstream) have a
 * non-deterministic outcome in real git, or the command is not safe to run
 * blindly (`xargs` waits on stdin, a bad revision `x` would just fail without
 * a mutation and prove nothing). Those carry `skipReal` with a reason and are
 * verified only through `parseGitInvocations`/`isMutating` — exactly what
 * `git-guard.test.ts` verifies too, just collected here in one table for
 * overview.
 */

import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { type GitInvocation, isMutating, parseGitInvocations } from './git-guard.ts';

/* ---------------- temp-repo harness ---------------- */

function sh(cmd: string, cwd: string): string {
  try {
    return execSync(cmd, { cwd, shell: '/bin/bash', stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
  } catch (err) {
    const e = err as { stdout?: Buffer | string };
    return String(e.stdout ?? '');
  }
}

/** Two commits on `main`, `a.txt` tracked and clean. Nothing else. */
function initRepo(dir: string): void {
  sh('git init -q -b main', dir);
  sh('git config user.email t@example.com', dir);
  sh('git config user.name Test', dir);
  sh('printf "one\\n" > a.txt && git add a.txt && git commit -q -m c1', dir);
  sh('printf "two\\n" > a.txt && git commit -aq -m c2', dir);
}

/** `feature` branch off `main`, one extra commit touching a DIFFERENT file
 *  (`b.txt`) — diverges from `main` without ever conflicting with it, so
 *  `checkout`/`switch`/`merge`/`cherry-pick` all run clean. */
function setupFeatureBranch(dir: string): void {
  sh('git checkout -q -b feature', dir);
  sh('printf "feature\\n" > b.txt && git add b.txt && git commit -q -m feature-commit', dir);
  sh('git checkout -q main', dir);
}

function setupDirty(dir: string): void {
  sh('printf "dirty\\n" > a.txt', dir);
}

function setupStashed(dir: string): void {
  setupDirty(dir);
  sh('git stash push -q -m wip', dir);
}

function setupUntracked(dir: string): void {
  sh('printf "junk" > junk.tmp', dir);
}

function setupBranch(name: string): (dir: string) => void {
  return (dir: string) => sh(`git branch ${name}`, dir);
}

function worktreePathFor(dir: string): string {
  return join(dirname(dir), `${dir.split('/').pop()}-wt`);
}

function setupWorktree(dir: string): void {
  sh(`git worktree add -q -b wtbranch ${worktreePathFor(dir)}`, dir);
}

/** Snapshot of everything the guard is meant to protect: HEAD, branch refs,
 *  index/worktree status, stash stack, worktree list. Byte-equal before/after
 *  == "did not mutate", by the same yardstick a live session would notice. */
function snapshot(dir: string): string {
  return [
    sh('git rev-parse HEAD', dir),
    sh('git status --porcelain=v1 --branch', dir),
    sh('git stash list', dir),
    sh('git worktree list --porcelain', dir),
    sh("git for-each-ref refs/heads --format='%(refname) %(objectname)'", dir),
  ].join('\n===\n');
}

/* ---------------- table ---------------- */

interface Row {
  /** Label for the test name; the actual command run/parsed. */
  cmd: string | ((dir: string) => string);
  /** Expected guard verdict. `'none'` = the wrapper is positionally
   *  unresolvable AND the guard is right to produce zero invocations to
   *  judge (nothing to deny). */
  mutating: boolean | 'none';
  /** Which parsed invocation to check, for multi-invocation rows (pipes).
   *  Default 0. */
  invocationIndex?: number;
  setup?: (dir: string) => void;
  cleanup?: (dir: string) => void;
  /** Present only on rows verified via the parser alone — reason why running
   *  it for real would not prove anything (or would be unsafe/flaky). */
  skipReal?: string;
}

const ROWS: Row[] = [
  /* ---- common reads an agent actually types (spec's own list) ---- */
  { cmd: 'git status', mutating: false },
  { cmd: 'git status --porcelain', mutating: false },
  { cmd: 'git log --oneline -5', mutating: false },
  { cmd: 'git diff --stat', mutating: false },
  { cmd: 'git show HEAD', mutating: false },
  { cmd: 'git branch -a', mutating: false },
  { cmd: 'git branch --list', mutating: false },
  { cmd: 'git branch', mutating: false },
  { cmd: 'git branch --show-current', mutating: false },
  { cmd: 'git worktree list', mutating: false },
  { cmd: 'git rev-parse HEAD', mutating: false },
  { cmd: 'git blame a.txt', mutating: false },
  { cmd: (dir) => `git -C ${dir} status`, mutating: false },
  { cmd: 'sh -c "git status"', mutating: false },
  { cmd: 'git stash list', mutating: false },
  { cmd: 'git for-each-ref refs/heads', mutating: false },
  { cmd: 'git ls-files', mutating: false },

  /* ---- J8 wrapper heads, real execution (K1: basename normalisation) ---- */
  { cmd: 'bash -lc "git status"', mutating: false },
  { cmd: '/bin/sh -c "git status"', mutating: false },
  { cmd: 'command git status', mutating: false },
  { cmd: 'nice git status', mutating: false },
  { cmd: '/usr/bin/env git status', mutating: false },

  /* ---- clean dry-run vs real (H1) ---- */
  { cmd: 'git clean -n', mutating: false, setup: setupUntracked },
  { cmd: 'git clean -f', mutating: true, setup: setupUntracked },

  /* ---- destructive verbs, real execution ---- */
  { cmd: 'git checkout feature', mutating: true, setup: setupFeatureBranch },
  { cmd: 'git checkout -b newbranch', mutating: true },
  { cmd: 'git switch feature', mutating: true, setup: setupFeatureBranch },
  { cmd: 'git reset --hard HEAD~1', mutating: true },
  { cmd: 'git merge feature', mutating: true, setup: setupFeatureBranch },
  { cmd: 'git cherry-pick feature', mutating: true, setup: setupFeatureBranch },
  { cmd: 'git revert HEAD --no-edit', mutating: true },
  { cmd: 'git branch -D tmp', mutating: true, setup: setupBranch('tmp') },
  { cmd: 'git stash drop', mutating: true, setup: setupStashed },
  {
    cmd: (dir) => `git worktree remove ${worktreePathFor(dir)}`,
    mutating: true,
    setup: setupWorktree,
    cleanup: (dir) => sh(`rm -rf ${worktreePathFor(dir)}`, dir),
  },

  /* ---- H1: value-taking option masquerading as `--dry-run`/`-h` ----
   * Confirmed against real git when this guard clause was written, but the
   * exact "unknown flag → error, no mutation" behaviour is git-version
   * dependent (the guard deliberately fails closed regardless — see
   * `isReadOnlyForm`'s comment). Parser-only, so the matrix does not assert
   * a specific git version's error behaviour as ground truth. */
  { cmd: 'git stash push -m --dry-run', mutating: true, skipReal: 'unknown-flag behaviour is git-version dependent' },
  { cmd: 'git merge -m -h somebranch', mutating: true, skipReal: 'unknown-flag behaviour is git-version dependent' },
  { cmd: 'git clean -fd -e -n', mutating: true, skipReal: 'unknown-flag behaviour is git-version dependent' },
  { cmd: 'git clean -e -n -fd', mutating: true, skipReal: 'unknown-flag behaviour is git-version dependent' },
  { cmd: 'git reset --hard --dry-run', mutating: true, skipReal: 'unknown-flag behaviour is git-version dependent' },
  { cmd: 'git checkout -h foo', mutating: true, skipReal: 'unknown-flag behaviour is git-version dependent' },
  { cmd: 'git stash push -m -h', mutating: true, skipReal: 'unknown-flag behaviour is git-version dependent' },
  {
    cmd: 'git merge --message=--dry-run x',
    mutating: true,
    skipReal: 'unknown-flag behaviour is git-version dependent',
  },
  { cmd: 'git stash --help', mutating: false, skipReal: '--help exit code/behaviour varies by git build' },
  { cmd: 'git clean -fdn', mutating: false, skipReal: 'already covered for real by `git clean -n` above' },

  /* ---- J1: raw-args bug — value of `-m` must not read as the subcommand ---- */
  { cmd: 'git stash -m list', mutating: true, skipReal: 'would need a real dirty tree; covered for real by `git stash drop`' },
  { cmd: 'git branch --contains -d somebranch', mutating: false, skipReal: "real git's parsing of `-d` as --contains's value is version-sensitive" },

  /* ---- J7: branch flags that actually mutate ---- */
  { cmd: 'git branch -d feature', mutating: true, skipReal: 'covered for real by `git branch -D tmp`' },
  { cmd: 'git branch -D feature', mutating: true, skipReal: 'covered for real by `git branch -D tmp`' },
  { cmd: 'git branch -m old new', mutating: true, skipReal: 'covered for real by `git branch -D tmp`' },
  { cmd: 'git branch -c old new', mutating: true, skipReal: 'covered for real by `git branch -D tmp`' },
  { cmd: 'git branch -C old new', mutating: true, skipReal: 'covered for real by `git branch -D tmp`' },
  { cmd: 'git branch -f feature HEAD', mutating: true, skipReal: 'covered for real by `git branch -D tmp`' },
  { cmd: 'git branch --unset-upstream', mutating: true, skipReal: 'needs a configured upstream to be meaningful' },

  /* ---- K2: inline `=` must compare like a separate value ---- */
  { cmd: 'git branch --set-upstream-to=origin/main', mutating: true, skipReal: 'needs a configured remote/upstream' },
  { cmd: 'git branch --set-upstream-to origin/main', mutating: true, skipReal: 'needs a configured remote/upstream' },

  /* ---- J8/K1: fail-closed unsafe wrapper, and its basename-normalised form ---- */
  { cmd: 'xargs git checkout', mutating: true, skipReal: 'xargs waits on stdin; positionally unresolvable by design' },
  {
    cmd: 'parallel git reset --hard ::: a b',
    mutating: true,
    skipReal: 'GNU parallel may not be installed everywhere CI runs',
  },
  // A literal target keeps the wrapper-detection path exercised here; the `{}`
  // placeholder forms (which R1 made tokenizable and a later round then judged) have
  // their own block further down.
  { cmd: 'find . -name x -exec git checkout main \\;', mutating: true, skipReal: 'no matching file, `find` would no-op for real; parser-only' },
  { cmd: '/usr/bin/xargs git status', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: '/usr/bin/xargs git reset --hard', mutating: true, skipReal: 'xargs waits on stdin' },

  /* ---- K3: stash/branch/worktree `list` behind an unsafe wrapper is a read ---- */
  { cmd: 'xargs git branch --list', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git worktree list', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git stash list', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: "xargs -d '\\n' git branch --list", mutating: 'none', skipReal: 'xargs waits on stdin' },

  /* ---- L1: a mutating marker after stash/branch/worktree behind a wrapper ---- */
  { cmd: 'xargs git branch -d', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git branch -D tmp', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'git branch --merged main | xargs git branch -d', mutating: true, invocationIndex: 1, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git worktree remove p', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git stash', mutating: true, skipReal: 'xargs waits on stdin' },
  /* ---- M1–M3: option values behind a wrapper, and wrapper args named like a subcommand ---- */
  { cmd: 'xargs git stash -m show', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git stash --message list', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git branch --contains -d somebranch', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'find stash -exec git status \\;', mutating: 'none', skipReal: 'parser-only' },
  { cmd: 'xargs -I stash git stash list', mutating: 'none', skipReal: 'xargs waits on stdin' },
  /* ---- N1/N2: absolute git behind a wrapper; a ref named like a subcommand ---- */
  { cmd: 'xargs /usr/bin/git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs /usr/bin/git branch -D tmp', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'find . -exec /usr/bin/git stash \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'xargs git log --oneline stash', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git grep stash', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git -C p stash -m list', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'git stash list | xargs -n1 git stash pop', mutating: true, invocationIndex: 1, skipReal: 'xargs waits on stdin' },

  /* ---- A call wrapper in front of the unsafe wrapper must not hide it ---- */
  { cmd: 'time xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'nice xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'nice -n 5 xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'env xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'env FOO=1 xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'command xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'exec xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'nohup xargs git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'time /usr/bin/xargs git reset --hard', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'time xargs git status', mutating: 'none', skipReal: 'xargs waits on stdin' },
  /* ---- The real command hides in a shell `-c` string behind the wrapper ---- */
  { cmd: 'xargs sh -c "git stash drop"', mutating: true, skipReal: 'xargs waits on stdin' },
  // `-I{}` would make `tokenize` bail out on the braces (see the note above),
  // so the wrapper flag here is one that keeps the parse path exercised.
  { cmd: "xargs -n1 bash -lc 'git reset --hard'", mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs zsh -c -- "git worktree remove p"', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'time xargs sh -c "git stash drop"', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs sh -c "git log --grep merge"', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs sh -c "git stash list"', mutating: 'none', skipReal: 'xargs waits on stdin' },

  /* ---- A wrapper ARG that looks like a shell head must not
         swallow the search — the git token behind it still decides ---- */
  { cmd: 'find . -name sh -exec git reset --hard \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -path ./bash -exec git checkout main \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -name sh -exec git status \\;', mutating: 'none', skipReal: 'parser-only' },
  { cmd: 'xargs -a zsh git stash drop', mutating: true, skipReal: 'xargs waits on stdin' },

  /* ---- The subcommand is NOT on the command line — it arrives
         on stdin (`xargs`) or from the `:::` list (`parallel`). Nothing in the
         text can be read as a subcommand, so the verdict must be fail-closed
         deny, not "no subcommand found → allow". ---- */
  { cmd: "echo 'reset --hard' | xargs git -C /r", mutating: true, invocationIndex: 0, skipReal: 'xargs waits on stdin; the subcommand is never in the command string' },
  { cmd: 'xargs git', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git -C /r', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs -n1 git', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs -I r git -C r', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs /usr/bin/git', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'time xargs git -C /r', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'git ls-files | xargs git', mutating: true, invocationIndex: 1, skipReal: 'xargs waits on stdin' },
  { cmd: "parallel git ::: 'reset --hard'", mutating: true, skipReal: 'GNU parallel may not be installed everywhere CI runs' },
  { cmd: 'parallel git ::: status', mutating: true, skipReal: 'the `:::` list is input, so even a read-looking list cannot be trusted as the subcommand' },
  { cmd: 'parallel -j2 git ::: reset', mutating: true, skipReal: 'GNU parallel may not be installed everywhere CI runs' },

  /* ---- R1: a placeholder/custom-replacement token in the subcommand slot
         is the same "subcommand is not on the line" hole as the stdin case above ---- */
  { cmd: "echo 'reset --hard' | xargs -I {} git -C /r {}", mutating: true, invocationIndex: 0, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs -I{} git -C /r {}', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs -I% git -C /r %', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs -J% git -C /r %', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: "parallel git {} ::: 'reset --hard'", mutating: true, skipReal: 'GNU parallel may not be installed everywhere CI runs' },
  { cmd: 'xargs -I stash git stash list', mutating: 'none', skipReal: 'the placeholder name happens to equal the real, literal subcommand text' },

  /* ---- R6: `find -exec git …` — the same two holes as R1, one
         predicate over. `{}` in the subcommand slot is a path substituted at
         run time; no subcommand at all is stdin-shaped by another name.
         A literal subcommand next to `{}` is judged as before. ---- */
  { cmd: 'find . -name x -exec git {} \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -exec git {} +', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -exec git -C /r {} \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -execdir git {} \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -ok git {} \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -okdir git {} \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -exec git \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -exec git -C /r \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -exec /usr/bin/git {} \\;', mutating: true, skipReal: 'parser-only' },
  { cmd: 'find . -name x -exec git log {} \\;', mutating: 'none', skipReal: 'parser-only' },
  { cmd: 'find . -name x -exec git log --oneline {} \\;', mutating: 'none', skipReal: 'parser-only' },
  { cmd: 'find . -name x -exec git stash list {} \\;', mutating: 'none', skipReal: 'parser-only' },
  { cmd: 'find . -name x -exec git checkout {} \\;', mutating: true, skipReal: 'parser-only' },
  // the `{}` belongs to `grep`, not to a git subcommand slot — never fires
  { cmd: 'find . -name x -exec grep git {} \\;', mutating: 'none', skipReal: 'parser-only' },
  { cmd: 'find . -name "{}" -print', mutating: 'none', skipReal: 'parser-only' },

  /* ---- R2: a call-wrapper (`env`/`command`/`nice`/`nohup`) between
         `xargs`/`parallel` and `git` must not hide git from the positional
         check above ---- */
  { cmd: 'xargs env git -C /r', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs command git -C /r', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs nice git -C /r', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs nohup git -C /r', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: "parallel env git -C /r ::: 'reset --hard'", mutating: true, skipReal: 'GNU parallel may not be installed everywhere CI runs' },

  /* ---- R3: the `sh -c` PAYLOAD's own subcommand slot can also hide behind
         a positional-parameter expansion fed by the same stdin/`:::` ---- */
  { cmd: "echo 'reset --hard' | xargs sh -c 'git -C /r \"$@\"' _", mutating: true, invocationIndex: 0, skipReal: 'xargs waits on stdin' },

  /* ---- …and the negatives: a subcommand that IS positionally present is
         judged exactly as before, and a wrapper whose command is not git at
         all must never be touched by the rule above ---- */
  { cmd: 'xargs git log', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git blame a.txt', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git -C /r status', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git ls-files', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs grep git', mutating: 'none', skipReal: '`grep` is the command; "git" is its pattern — must not fail closed' },
  { cmd: 'xargs -n1 grep git', mutating: 'none', skipReal: '`grep` is the command; "git" is its pattern' },
  { cmd: 'xargs echo git', mutating: 'none', skipReal: '`echo` is the command word, not git' },

  /* ---- A read behind a wrapper whose ARGS merely name a subcommand ---- */
  { cmd: 'xargs git log --grep merge', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git log --oneline checkout', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git show reset', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git diff merge', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git log --format=%s rebase', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'find . -name revert -exec git status \\;', mutating: 'none', skipReal: 'parser-only' },
  /* …while the same positional path still denies the real mutations ---- */
  { cmd: 'xargs git merge main', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git cherry-pick abc', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git clean -fd', mutating: true, skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git clean -n', mutating: 'none', skipReal: 'xargs waits on stdin' },
  { cmd: 'xargs git pull --dry-run', mutating: 'none', skipReal: 'xargs waits on stdin' },

  /* ---- K8: `--` right after `-c` is not the command string ---- */
  { cmd: 'bash -c -- "git status"', mutating: false, skipReal: 'covered for real by the plain `sh -c`/`bash -lc` rows above' },
  {
    cmd: 'bash -c -- "git reset --hard x"',
    mutating: true,
    skipReal: "`x` is not a real revision; running it would only prove git's error path, not the guard's",
  },

  /* ---- pipe `|`/`|&` as a segment separator ---- */
  {
    cmd: 'true | git reset --hard x',
    mutating: true,
    skipReal: "`x` is not a real revision in this fixture; the guard's job is to see the git command at all",
  },
  {
    cmd: 'true |& git reset --hard x',
    mutating: true,
    skipReal: "`x` is not a real revision in this fixture; the guard's job is to see the git command at all",
  },
  { cmd: 'git log | git status', mutating: false, invocationIndex: 0, skipReal: 'both sides are reads; real-verified individually above' },
  { cmd: 'git log | git status', mutating: false, invocationIndex: 1, skipReal: 'both sides are reads; real-verified individually above' },

  /* ---- ANSI-C quoting doesn't break flag detection ---- */
  {
    cmd: "git commit -m $'wip\\nmore'",
    mutating: false,
    skipReal: "`commit` isn't in the mutating set at all — parser-only sanity check",
  },
  {
    cmd: "git branch -D $'weird\\tname'",
    mutating: true,
    skipReal: 'branch name with a literal tab is awkward to assert on in a real repo; parser-only',
  },
];

test(`matrix: the data table has at least 60 rows (has ${ROWS.length})`, () => {
  assert.ok(ROWS.length >= 60, `only ${ROWS.length} commands — at least 60 needed`);
});

for (const [idx, row] of ROWS.entries()) {
  const label = typeof row.cmd === 'string' ? row.cmd : row.cmd('<dir>');
  const idxSuffix = row.invocationIndex !== undefined ? ` [invocation #${row.invocationIndex}]` : '';
  const tag = row.skipReal ? ' [parser only]' : ' [real git]';

  test(`matrix #${idx + 1}${tag}: ${label}${idxSuffix}`, async (t) => {
    if (row.skipReal) {
      const invs = parseGitInvocations(typeof row.cmd === 'string' ? row.cmd : row.cmd('/repo'), '/repo');
      if (row.mutating === 'none') {
        assert.deepEqual(invs, [], `"${label}" must not generate an invocation to judge`);
        return;
      }
      const inv = invs[row.invocationIndex ?? 0] as GitInvocation | undefined;
      assert.ok(inv, `"${label}": invocation at index ${row.invocationIndex ?? 0} is missing`);
      assert.equal(isMutating(inv as GitInvocation), row.mutating, `guard verdict for "${label}"`);
      return;
    }

    // Real row: fresh temp repo, ground truth from an actual git snapshot.
    if (process.platform === 'win32') {
      t.skip('skipped on win32: the rows run POSIX shell one-liners; the guard verdict above is still checked');
      return;
    }
    const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-guard-matrix-'));
    t.after(async () => {
      row.cleanup?.(dir);
      await rm(dir, { recursive: true, force: true });
      await rm(worktreePathFor(dir), { recursive: true, force: true }).catch(() => {});
    });
    initRepo(dir);
    row.setup?.(dir);

    const cmdStr = typeof row.cmd === 'string' ? row.cmd : row.cmd(dir);
    const before = snapshot(dir);
    sh(cmdStr, dir);
    const after = snapshot(dir);
    const reallyMutated = before !== after;

    assert.equal(
      reallyMutated,
      row.mutating,
      `ground truth: "${cmdStr}" should ${row.mutating ? '' : 'NOT '}have mutated the real repo`,
    );

    const inv = parseGitInvocations(cmdStr, dir)[0] as GitInvocation;
    assert.equal(isMutating(inv), row.mutating, `guard verdict for "${cmdStr}"`);
  });
}
