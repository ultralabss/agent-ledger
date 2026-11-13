/**
 * PreToolUse guard for Bash — SPEC §10.4.
 *
 * Heuristic by design (the spec says so): the rules in CLAUDE.md hold anyway, so
 * the only unforgivable failure mode here is a FALSE DENY. A denied `git status`
 * teaches the agent to stop using the guard's advice, and there is no way to
 * appeal it mid-turn. So the parser is built inside-out: it recognises a small,
 * closed set of *mutating* invocations and denies only those; literally
 * everything else — unknown subcommand, unparseable quoting, a subshell — falls
 * through to allow. Pipe segments (`|`, `|&`) ARE split and judged like
 * `&&`/`;`, same as any other segment.
 *
 * The one exception to "fall through to allow" is a wrapper that runs `git`
 * with its subcommand supplied from OUTSIDE the command line (`xargs git -C /r`
 * fed `reset --hard` on stdin, `parallel git ::: …`): there the text simply
 * does not contain the operation, so allowing it would be allowing every
 * mutating subcommand at once. That shape — and only that shape — is
 * fail-closed; see `wrapperRunsGitWithoutSubcommand`.
 *
 * Checkout resolution follows the spec: `git -C <p>`, else a `cd <p> &&` earlier
 * in the same chain, else the session's cwd.
 */

import type { GuardRule } from '@agent-ledger/shared';
import { shortSession } from '@agent-ledger/shared';
import type { RuntimeStore } from '../db/store.ts';
import type { GitCache } from '../repowatch.ts';
import type { Sessions } from '../sessions.ts';
import type { GuardSwitch } from './switch.ts';
import { toPosix } from './globs.ts';

/** Subcommands that move HEAD, the index or the worktree under other people. */
const MUTATING = new Set([
  'checkout',
  'switch',
  'stash',
  'reset',
  'rebase',
  'merge',
  'pull',
  'restore',
  'cherry-pick',
  'revert',
  'am',
]);
/** `git stash list|show` is a read — only the mutating forms are denied. */
const STASH_READS = new Set(['list', 'show']);
/** `git worktree remove` only; `list`, `add`, `prune` are not the spec's case. */
const WORKTREE_MUTATING = new Set(['remove']);

/**
 * J8: shells that a raw `-c` command string is commonly piped through
 * (`sh -c "…"`, `bash -lc "…"`, …). The inner string is re-parsed with the
 * same rules, recursively — that is how `git` invocations hiding one layer
 * deep still get judged instead of silently allowed.
 */
// R3-03: exported so `worker-guard.ts` recognises the same shell-wrapper
// heads without a second, possibly-drifting list.
export const SHELL_WRAPPER_HEADS = new Set(['sh', 'bash', 'zsh', 'dash']);
/** Wrapper words that run the NEXT word as the real command, without
 *  changing which checkout/args it sees (`command git …`, `exec git …`,
 *  `nice/nohup/time git …`) — skipped like `env`/`VAR=val` already were. */
const CALL_WRAPPER_WORDS = new Set(['command', 'exec', 'nice', 'nohup', 'time']);
/**
 * Wrappers that run an arbitrary later token as a *subcommand* we cannot
 * reliably locate (`xargs git reset`, `find … -exec git checkout … \;`) —
 * unlike `CALL_WRAPPER_WORDS` there is no fixed "next token is the command"
 * shape to unwrap. Deliberately a short, explicit list (not "any unknown
 * head"): the guard's one unforgivable failure is a false deny, so this only
 * fires for wrappers that are actually in the business of executing their
 * arguments, not for e.g. `echo git reset` mentioning the words in passing.
 */
const UNSAFE_WRAPPER_HEADS = new Set(['xargs', 'find', 'parallel']);
/** The subset that supplies its command's ARGUMENTS from outside the
 *  command line — stdin for `xargs`, the `:::` list for `parallel`. */
const STDIN_FED_WRAPPER_HEADS = new Set(['xargs', 'parallel']);
/** Sentinel subcommand for the fail-closed marker `isMutating` always denies. */
const UNSAFE_WRAPPER_SUBCOMMAND = '(unwrappable wrapper)';

/**
 * What the wrapper would really run, judged POSITIONALLY — never by
 * scanning for mutating words anywhere in the line. The word scan denied
 * `xargs git log --grep merge` and `xargs git show reset`, i.e. plain reads
 * whose *arguments* merely mention a subcommand name; that is the one failure
 * mode this guard must not have. So: find the `git` token, skip git's global
 * options exactly like `parseGitInvocations` does (`xargs git log stash` is
 * `log`, not `stash`), then hand the real subcommand and its args to
 * `isMutating` — the same verdict the unwrapped path gets, including
 * `STASH_READS`, `BRANCH_MUTATING_FLAGS`, `WORKTREE_MUTATING`, `clean -n`,
 * `significantArgs` (M1–M3) and `isReadOnlyForm`.
 */
function wrappedSubcommandMutates(tokens: readonly string[]): boolean {
  const gitAt = tokens.findIndex((t) => isGitBinary(t));
  if (gitAt === -1) return false;
  const i = subcommandIdxAfterGit(tokens, gitAt);
  const sub = tokens[i];
  if (sub === undefined) return false;
  return isMutating({ cwd: null, dashC: null, subcommand: sub, args: tokens.slice(i + 1) });
}

/** Index of git's positional subcommand, skipping git's global options exactly
 *  like `parseGitInvocations` does (`xargs git log stash` is `log`, not
 *  `stash`). May point past the end when there is no positional at all. */
function subcommandIdxAfterGit(tokens: readonly string[], gitAt: number): number {
  let i = gitAt + 1;
  while (i < tokens.length) {
    const tok = tokens[i] as string;
    if (tok === '-C' || tok === '-c') i += 2;
    else if (tok.startsWith('--git-dir') || tok.startsWith('--work-tree')) i += tok.includes('=') ? 1 : 2;
    else if (tok.startsWith('-')) i += 1;
    else break;
  }
  return i;
}

/**
 * Wrapper flags that take their value as a SEPARATE token, so the value is not
 * mistaken for the wrapper's command word. Short list on purpose — only what
 * `xargs`/`parallel` actually use in the shapes an agent types.
 */
const WRAPPER_VALUE_FLAGS = new Set([
  '-I',
  '-i',
  '-n',
  '-L',
  '-l',
  '-P',
  '-j',
  '-s',
  '-E',
  '-e',
  '-d',
  '-a',
  '-N',
  '-S',
  '--replace',
  '--max-args',
  '--max-lines',
  '--max-procs',
  '--max-chars',
  '--delimiter',
  '--eof',
  '--arg-file',
  '--jobs',
  '--colsep',
  '--sshlogin',
  '--process-slot-var',
]);

/**
 * GNU parallel separators: everything after them is INPUT fed to the command,
 * not the command's own argv as written. `parallel git ::: 'reset --hard'`
 * therefore runs `git reset --hard` even though no mutating subcommand sits in
 * a subcommand position on the line.
 */
const PARALLEL_ARG_SEPARATORS = new Set([':::', '::::', ':::+', '::::+']);

/**
 * R1: `xargs`/`parallel` replacement tokens with their BUILT-IN spelling —
 * present in the subcommand position, these mean "whatever came in on
 * stdin/`:::`", same hole as a missing subcommand. `{}` is the default for
 * both tools; `{.}`/`{/}`/`{#}`/`{%}` are GNU parallel's variants.
 */
const PLACEHOLDER_TOKENS = new Set(['{}', '{.}', '{/}', '{#}', '{%}']);

/** R4: flags whose value is xargs'/parallel's CUSTOM replacement string —
 *  `-I`, `-J` (short, so the value may be concatenated: `-I{}`, `-J%`) or
 *  `--replace[=str]`. Only these feed R1's placeholder check; everything
 *  else that looks like a flag is just a flag, not a reason to doubt the
 *  subcommand next to it. */
const PLACEHOLDER_FLAGS = ['-I', '-J'];

/** R4: the value of a `PLACEHOLDER_FLAGS` flag, whether given as a separate
 *  token (`-I {}`) or concatenated onto the short flag (`-I{}`, `-J%`) —
 *  compares a PREFIX of the short flag, not the whole token, so the
 *  concatenated forms are not missed. `null` when no such flag is present. */
function placeholderFlagValue(rest: readonly string[]): string | null {
  for (let i = 0; i < rest.length; i += 1) {
    const tok = rest[i] as string;
    if (tok === '--replace') return (rest[i + 1] as string) ?? '{}';
    if (tok.startsWith('--replace=')) return tok.slice('--replace='.length);
    for (const flag of PLACEHOLDER_FLAGS) {
      if (tok === flag) return (rest[i + 1] as string) ?? null;
      if (tok.startsWith(flag) && tok.length > flag.length) return tok.slice(flag.length);
    }
  }
  return null;
}

/**
 * The wrapper's command word, i.e. the first token that is neither one
 * of the wrapper's own flags nor a flag's value. Returns `-1` when there is
 * none. This is what tells `xargs git -C /r` (git IS the command) apart from
 * `git ls-files | xargs grep git` (the command is `grep`; the word "git" is
 * just its pattern) — without it, the fail-closed rule below would deny a
 * perfectly ordinary grep.
 */
function wrapperCommandIdx(rest: readonly string[]): number {
  for (let i = 0; i < rest.length; ) {
    const tok = rest[i] as string;
    if (tok.startsWith('-')) {
      i += 1;
      if (WRAPPER_VALUE_FLAGS.has(tok)) i += 1;
      continue;
    }
    // R2: the wrapper's command word may itself be hidden behind `env`/
    // `command`/`exec`/`nice`/`nohup`/`time` (`xargs env git -C /r`,
    // `parallel env git -C /r ::: …`) — unwrap exactly like
    // `parseGitInvocations` does before deciding this word IS the command.
    const after = skipCallWrapperPrefix(rest, i);
    if (after !== i) {
      i = after;
      continue;
    }
    return i;
  }
  return -1;
}

/** R2: advance past `env`/`VAR=val` prefixes and `command`/`exec`/`nice`/
 *  `nohup`/`time` call-wrappers (plus `nice -n <adjustment>`'s value),
 *  shared by `parseGitInvocations`'s own prefix-skip and `wrapperCommandIdx`
 *  so the two never drift apart on what counts as "not the real command". */
function skipCallWrapperPrefix(tokens: readonly string[], start: number): number {
  let i = start;
  while (i < tokens.length) {
    const tok = tokens[i] as string;
    if (isEnvPrefix(tok)) {
      i += 1;
      continue;
    }
    if (CALL_WRAPPER_WORDS.has(baseName(tok))) {
      const wrapper = baseName(tok);
      i += 1;
      while (i < tokens.length && (tokens[i] as string).startsWith('-')) {
        const flag = tokens[i] as string;
        i += 1;
        if (
          wrapper === 'nice' &&
          (flag === '-n' || flag === '--adjustment') &&
          i < tokens.length &&
          !(tokens[i] as string).startsWith('-')
        ) {
          i += 1;
        }
      }
      continue;
    }
    break;
  }
  return i;
}

/**
 * Audit R7-3 — `git` run by `xargs`/`parallel` with NO positional
 * subcommand on the line.
 *
 * `echo 'reset --hard' | xargs git -C /r` runs `git -C /r reset --hard`: the
 * subcommand arrives on STDIN, which no amount of parsing of the command
 * string can see. The old positional path resolved the subcommand to
 * `undefined` and returned "not mutating" — allow — which made stdin a
 * complete bypass of the guard for every mutating subcommand at once. The same
 * hole with the argument list instead of stdin is `parallel git ::: 'reset
 * --hard'`, where the subcommand sits after a parallel separator.
 *
 * So: when `git` is what the wrapper actually executes and the line carries no
 * subcommand for it, the verdict is deny. A bare `xargs git` is never a read —
 * it is a command whose operation is supplied from outside the text we are
 * judging, which is precisely the case the guard must fail closed on.
 *
 * Deliberately narrow, because a false deny is this guard's worst outcome:
 *  - `xargs git log` / `git ls-files | xargs git blame` → a subcommand IS
 *    present and positional, judged as before, allowed;
 *  - `git ls-files | xargs grep git` → `grep` is the command word, so this
 *    never fires;
 *  - `find … -exec git …` is judged by `findExecHidesGitSubcommand` instead
 * — find's command word is not positionally first, so this
 *    predicate cannot locate it.
 */
function wrapperRunsGitWithoutSubcommand(rest: readonly string[]): boolean {
  const cmdIdx = wrapperCommandIdx(rest);
  if (cmdIdx === -1) return false;
  if (!isGitBinary(rest[cmdIdx] as string)) return false;
  // R1: a `:::`/`::::` separator ANYWHERE means everything from there on is
  // input fed to the command, not its literal argv — regardless of whether
  // a token happens to sit in the subcommand slot on the line.
  if (rest.some((t) => PARALLEL_ARG_SEPARATORS.has(t))) return true;
  const sub = rest[subcommandIdxAfterGit(rest, cmdIdx)];
  if (sub === undefined) return true;
  // R1/R4: a replacement token (built-in `{}`/`{.}`/… or a custom `-I`/`-J`/
  // `--replace` placeholder) in the subcommand slot means the real
  // subcommand is substituted in from stdin at run time. Guarded to SYMBOLIC
  // custom placeholders only (no letters/digits) — `xargs -I stash git stash
  // list` names its placeholder "stash", which also happens to be the real,
  // literal subcommand next to it; that must stay allow, not deny.
  if (PLACEHOLDER_TOKENS.has(sub)) return true;
  const custom = placeholderFlagValue(rest);
  return custom !== null && custom !== '' && !/[a-zA-Z0-9]/.test(custom) && sub === custom;
}

/** `find` predicates that run the rest of the clause as a command. */
const FIND_EXEC_FLAGS = new Set(['-exec', '-execdir', '-ok', '-okdir']);
/**
 * End of a `-exec` clause. `;` and `+` are the real terminators, but
 * `splitSegments` cuts the command on a bare `;` *before* tokenizing — even an
 * escaped `\;` — so what actually reaches us at the end of the clause is the
 * leftover `\` (or nothing at all, at end of segment).
 */
const FIND_EXEC_TERMINATORS = new Set([';', '\\;', '\\', '+']);

/**
 * Audit R6 — the `find -exec` twin of
 * `wrapperRunsGitWithoutSubcommand`.
 *
 * `find . -name '*.ts' -exec git {} \;` substitutes each found PATH into `{}`,
 * so the subcommand git actually runs is a filename picked at run time, not
 * text we can judge; `find . -exec git \;` has no subcommand on the line at
 * all. Both resolved to "no subcommand → not mutating → allow" before, which
 * is the same stdin-shaped bypass R1 closed for `xargs`. So both fail closed.
 *
 * Narrow, for the same reason R1 is narrow — a false deny is this guard's worst
 * outcome:
 *  - `find . -name x -exec git log {} \;` — the subcommand IS positional and
 *    literal (`log`), `{}` is only an argument → judged as before, allowed;
 *  - `find . -exec git checkout {} \;` → `checkout`, denied as before;
 *  - `find . -name git -print` — no `-exec`, so this never fires.
 */
function findExecHidesGitSubcommand(rest: readonly string[]): boolean {
  for (let i = 0; i < rest.length; i += 1) {
    if (!FIND_EXEC_FLAGS.has(rest[i] as string)) continue;
    let end = i + 1;
    while (end < rest.length && !FIND_EXEC_TERMINATORS.has(rest[end] as string)) end += 1;
    const argv = rest.slice(i + 1, end);
    i = end;
    // find runs argv[0] directly — no shell, so no prefix words to skip.
    if (argv.length === 0 || !isGitBinary(argv[0] as string)) continue;
    const sub = argv[subcommandIdxAfterGit(argv, 0)];
    if (sub === undefined) return true;
    if (PLACEHOLDER_TOKENS.has(sub)) return true;
  }
  return false;
}

/** R3: a shell positional-parameter expansion (`$@`, `$*`, `$1`, `$2`, …) —
 *  stands for args supplied by the CALLER, never literal subcommand text. */
const POSITIONAL_PARAM_RE = /^\$(@|\*|\d+)$/;

/**
 * R3: does this `sh -c`/`bash -c` PAYLOAD run `git` with no subcommand of its
 * own — either nothing after `git`'s global options, or a positional-
 * parameter placeholder sitting there instead of real text? Either shape
 * means the subcommand is filled in from stdin/`:::` at run time, same hole
 * `wrapperRunsGitWithoutSubcommand` closes one layer up.
 */
function shPayloadHidesGitSubcommand(inner: string): boolean {
  const tokens = tokenize(inner);
  if (tokens === null) return false;
  const gitAt = tokens.findIndex((t) => isGitBinary(t));
  if (gitAt === -1) return false;
  const sub = tokens[subcommandIdxAfterGit(tokens, gitAt)];
  return sub === undefined || POSITIONAL_PARAM_RE.test(sub);
}

/**
 * The payload of an unsafe wrapper, one shell layer deeper.
 * `xargs sh -c "git stash drop"` has no `git` token at all — the command hides
 * inside the `-c` string — so it has to be re-parsed with the full rule set
 * (recursively: the inner string may wrap again).
 */
function wrapperPayloadMutates(rest: readonly string[], head: string): boolean {
  // Checked first — the stdin/`:::` case has no subcommand to find, so
  // every later rule would resolve it to "nothing to judge" and allow it.
  if (STDIN_FED_WRAPPER_HEADS.has(head) && wrapperRunsGitWithoutSubcommand(rest)) return true;
  // `find` spells its command out, but `{}` in the subcommand slot (or
  // no subcommand at all) is the same hole one predicate over.
  if (head === 'find' && findExecHidesGitSubcommand(rest)) return true;
  for (let i = 0; i < rest.length; i += 1) {
    if (!SHELL_WRAPPER_HEADS.has(baseName(rest[i] as string))) continue;
    // A miss must NOT end the search. `find . -name sh -exec git
    // reset --hard \;` has a token whose basename is `sh` (find's own
    // argument), and `-exec` even looks like a `-c` cluster — keep looking,
    // then fall through to the git-token path below, which still denies it.
    const inner = ownedDashCArg(rest, i);
    if (inner === undefined) continue;
    // R3: `xargs sh -c 'git -C /r "$@"' _` — the PAYLOAD's own subcommand
    // slot is a shell positional-parameter expansion (or missing outright),
    // so the real subcommand again arrives from stdin/`:::`, one shell layer
    // deeper than `wrapperRunsGitWithoutSubcommand` looks. Scoped to
    // STDIN_FED_WRAPPER_HEADS only — a plain top-level `sh -c 'git "$@"'`
    // (not fed by xargs/parallel) is unaffected.
    if (STDIN_FED_WRAPPER_HEADS.has(head) && shPayloadHidesGitSubcommand(inner)) return true;
    if (parseGitInvocations(inner, null).some(isMutating)) return true;
  }
  // N1: `/usr/bin/git` behind a wrapper is still git.
  if (!rest.some((t) => isGitBinary(t))) return false;
  return wrappedSubcommandMutates(rest);
}

/**
 * The wrapper head is only the head *after* the prefixes
 * `parseGitInvocations` already skips — `time xargs git stash drop`,
 * `env nice -n 5 xargs …`, `/usr/bin/xargs …`. Callers therefore pass the
 * token slice starting at the resolved command word, not the raw segment.
 */
function looksLikeUnsafeGitWrapper(tokens: readonly string[]): boolean {
  const head = tokens[0];
  if (head === undefined || !UNSAFE_WRAPPER_HEADS.has(baseName(head))) return false;
  return wrapperPayloadMutates(tokens.slice(1), baseName(head));
}

/**
 * Like `shellDashCArg`, but the `-c` must belong to the head at
 * `headIdx` — only the unbroken run of flags right after it is scanned. Inside
 * a wrapper payload the "first `-c`-shaped token anywhere later" rule is wrong:
 * `find . -name sh -exec …` would hand `-exec`'s neighbour over as a shell
 * command string. The broad form stays in use for a real `sh -c` segment head,
 * where the loose scan is what makes `bash -O extglob -c "…"` still resolve.
 */
function ownedDashCArg(tokens: readonly string[], headIdx: number): string | undefined {
  for (let i = headIdx + 1; i < tokens.length; i += 1) {
    const tok = tokens[i] as string;
    if (!tok.startsWith('-')) return undefined;
    if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(tok)) {
      const innerIdx = tokens[i + 1] === '--' ? i + 2 : i + 1;
      return tokens[innerIdx];
    }
  }
  return undefined;
}

/** The command string of a `sh -c "…"` / `bash -lc -- "…"` invocation whose
 *  head sits at `headIdx`, or `undefined` when there is no `-c`. K8: a literal
 *  `--` right after `-c` is the end-of-options separator, not the command. */
function shellDashCArg(tokens: readonly string[], headIdx: number): string | undefined {
  const cFlagIdx = tokens.findIndex((t, idx) => idx > headIdx && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(t));
  if (cFlagIdx === -1) return undefined;
  let innerIdx = cFlagIdx + 1;
  if (tokens[innerIdx] === '--') innerIdx += 1;
  return tokens[innerIdx];
}

/** K1: basename of a command head/token, so `/bin/sh`, `/usr/bin/env` and
 *  `/usr/bin/xargs` are recognised the same as their bare names — the same
 *  normalisation `isGitBinary` already did for `git` itself. */
function baseName(token: string): string {
  return toPosix(token).split('/').pop() ?? token;
}

export interface GitGuardDeps {
  store: RuntimeStore;
  sessions: Sessions;
  gitCache: GitCache;
  guard: GuardSwitch;
  now?: () => number;
}

export interface GitGuardResult {
  decision: 'allow' | 'deny';
  rule: GuardRule;
  reason: string | null;
}

const ALLOW: GitGuardResult = { decision: 'allow', rule: 'allow', reason: null };

export class GitGuard {
  private readonly deps: GitGuardDeps;

  constructor(deps: GitGuardDeps) {
    this.deps = deps;
  }

  /** `command` is the raw `tool_input.command` string. */
  async evaluate(input: {
    session: string;
    command: string | undefined;
    cwd: string | null | undefined;
  }): Promise<GitGuardResult> {
    if (!this.deps.guard.enabled) return { decision: 'allow', rule: 'guard-off', reason: null };
    const command = input.command;
    if (typeof command !== 'string' || command.trim() === '') return ALLOW;
    if (command.length > 8_000) return ALLOW; // not a git one-liner; do not guess

    const sessionRow = this.deps.store.getSession(input.session);
    const fallbackCwd = input.cwd ?? sessionRow?.cwd ?? null;

    for (const invocation of parseGitInvocations(command, fallbackCwd)) {
      const verdict = await this.judge(input.session, invocation);
      if (verdict.decision === 'deny') return verdict;
    }
    return ALLOW;
  }

  private async judge(session: string, inv: GitInvocation): Promise<GitGuardResult> {
    const checkout = await this.resolveCheckout(inv.cwd);
    if (checkout === null) return ALLOW; // not a checkout we know → nothing to protect
    const repo = checkout.repo;

    /* ---- row 1: history/worktree mutation while someone else lives there ---- */
    if (isMutating(inv)) {
      const others = this.othersIn(checkout.checkout, session);
      if (others.length > 0) {
        return {
          decision: 'deny',
          rule: 'git-mutation',
          reason:
            `\`git ${inv.subcommand}\` switches the state of the whole checkout ${checkout.checkout}, ` +
            `where ${others.map(describe).join(' · ')} is active. ` +
            `Their uncommitted files would vanish or move. ` +
            `First \`ledger who ${repo ?? '<repo>'}\`; branches and merges are handled by the main session, not a subagent.`,
        };
      }
      return ALLOW;
    }

    /* ---- row 2: `git add -A|--all|.` / `git commit -a` ---- */
    if (isAddAll(inv) || isCommitAll(inv)) {
      const foreign = this.foreignDirty(checkout.checkout, session);
      if (foreign.length > 0) {
        const mine = this.myDirty(checkout.checkout, session);
        return {
          decision: 'deny',
          rule: 'git-add-all',
          reason:
            `\`git ${[inv.subcommand, ...inv.args].join(' ').trim()}\` would also take other sessions' files: ` +
            `${foreign.slice(0, 6).map((f) => `${f.rel_path} (${shortSession(f.session)})`).join(', ')}` +
            `${foreign.length > 6 ? ` … +${foreign.length - 6}` : ''}. ` +
            `Your files: ${mine.length > 0 ? mine.slice(0, 20).join(' ') : 'none'}. ` +
            `Commit only your own: \`git ${inv.dashC ? `-C ${inv.dashC} ` : ''}commit --only -- ${
              mine.length > 0 ? mine.slice(0, 20).join(' ') : '<your files>'
            }\`.`,
        };
      }
      return ALLOW;
    }

    /* ---- row 3: plain `git commit` with someone else's files staged ---- */
    if (isPlainCommit(inv)) {
      const staged = this.foreignDirty(checkout.checkout, session).filter((f) => f.staged);
      if (staged.length > 0) {
        const mine = this.myDirty(checkout.checkout, session);
        return {
          decision: 'deny',
          rule: 'git-commit-foreign',
          reason:
            `Other sessions' files are staged: ${staged
              .slice(0, 6)
              .map((f) => `${f.rel_path} (${shortSession(f.session)})`)
              .join(', ')}. ` +
            `A commit would bundle them into yours. ` +
            `Use \`git ${inv.dashC ? `-C ${inv.dashC} ` : ''}commit --only -- ${
              mine.length > 0 ? mine.slice(0, 20).join(' ') : '<your files>'
            }\`, leave the others alone (\`ledger whose <path>\`).`,
        };
      }
      return ALLOW;
    }

    return ALLOW;
  }

  /* ---------------- state lookups ---------------- */

  private async resolveCheckout(
    cwd: string | null,
  ): Promise<{ checkout: string; repo: string | null } | null> {
    if (cwd === null) return null;
    // `resolvePath` gives repo + checkout for a path inside a registered repo;
    // a directory is a perfectly good path for it.
    const resolved = await this.deps.sessions.resolvePath(cwd);
    if (resolved === null) return null;
    return { checkout: resolved.layout.checkout, repo: resolved.repo };
  }

  private othersIn(checkout: string, self: string): { short: string; items: string[] }[] {
    const out: { short: string; items: string[] }[] = [];
    for (const view of this.deps.sessions.list({ liveOnly: true })) {
      if (view.id === self) continue;
      if (view.checkout !== checkout) continue;
      out.push({ short: view.short, items: view.items });
    }
    return out;
  }

  /** Dirty files in this checkout attributed to a live session that is not us. */
  private foreignDirty(
    checkout: string,
    self: string,
  ): { rel_path: string; session: string; staged: boolean }[] {
    const dirty = new Map(this.deps.gitCache.cachedDirty(checkout).map((d) => [d.rel_path, d]));
    const out: { rel_path: string; session: string; staged: boolean }[] = [];
    for (const row of this.deps.store.listTouched({ checkout })) {
      if (row.session_id === self) continue;
      const view = this.deps.sessions.get(row.session_id);
      if (view === null || view.liveness === 'ended') continue; // orphans are rule 4's job
      const entry = dirty.get(row.rel_path);
      if (entry === undefined) continue; // already committed or reverted
      out.push({ rel_path: row.rel_path, session: row.session_id, staged: entry.staged });
    }
    return out;
  }

  private myDirty(checkout: string, self: string): string[] {
    const dirty = new Set(this.deps.gitCache.cachedDirty(checkout).map((d) => d.rel_path));
    return this.deps.store
      .listTouched({ session: self, checkout })
      .map((r) => r.rel_path)
      .filter((p) => dirty.has(p))
      .sort();
  }
}

function describe(s: { short: string; items: string[] }): string {
  return `${s.short} (${s.items.join(',') || 'no item'})`;
}

/* ---------------- command parsing ---------------- */

export interface GitInvocation {
  /** `cd`-adjusted or `-C` directory this invocation runs in. */
  cwd: string | null;
  /** Value of `-C`, when present (verbatim, for the advice text). */
  dashC: string | null;
  subcommand: string;
  /** Arguments after the subcommand. */
  args: string[];
}

/**
 * Split a Bash one-liner into git invocations, tracking `cd`.
 *
 * Separators: `&&`, `||`, `;`, `|`, `|&`, newline. `|` is a separator, not
 * just `&&`/`;` — `true | git reset --hard x` runs the git command for real
 * regardless of what sits on the left, so treating a pipe as "out of scope"
 * would be a false allow, not a harmless skip. A segment that contains a
 * subshell, a backtick, `$(`, or a redirect into git is skipped entirely: it
 * cannot be parsed honestly and a guess would risk a false deny.
 */
export function parseGitInvocations(command: string, cwd: string | null): GitInvocation[] {
  const out: GitInvocation[] = [];
  let current = cwd;
  for (const segment of splitSegments(command)) {
    const tokens = tokenize(segment);
    if (tokens === null || tokens.length === 0) continue;
    const head = tokens[0] as string;

    if (head === 'cd' && tokens[1] !== undefined) {
      const target = tokens[1] as string;
      if (target !== '-' && !target.startsWith('~')) {
        current = target.startsWith('/') ? target : joinPosix(current, target);
      } else {
        current = null; // `cd -` / `cd ~foo`: unknown from here on
      }
      continue;
    }

    // J8: `sh -c "…"` / `bash -lc "…"` / … — re-parse the inner string.
    if (SHELL_WRAPPER_HEADS.has(baseName(head))) {
      const inner = shellDashCArg(tokens, 0);
      if (inner !== undefined) {
        out.push(...parseGitInvocations(inner, current));
        continue;
      }
    }

    // Accept `git …`, `/usr/bin/git …`, `env … git …`, `command git …`,
    // `exec git …` and `nice/nohup/time [flags] git …` (all common wrappers).
    let i = skipCallWrapperPrefix(tokens, 0);
    const bin = tokens[i];
    if (bin === undefined || !isGitBinary(bin)) {
      // J8: cannot follow this wrapper positionally — fail-closed rather
      // than silently allowing when it textually pairs `git` with a
      // mutating subcommand.
      // Judge from the resolved command word, so `time|nice|env|command|
      // exec|nohup xargs git stash drop` is seen as the `xargs` it really is.
      if (looksLikeUnsafeGitWrapper(tokens.slice(i))) {
        out.push({ cwd: current, dashC: null, subcommand: UNSAFE_WRAPPER_SUBCOMMAND, args: [] });
      }
      continue;
    }
    i += 1;

    let dashC: string | null = null;
    let localCwd = current;
    // Global options before the subcommand.
    while (i < tokens.length) {
      const tok = tokens[i] as string;
      if (tok === '-C' && tokens[i + 1] !== undefined) {
        dashC = tokens[i + 1] as string;
        localCwd = dashC.startsWith('/') ? dashC : joinPosix(current, dashC);
        i += 2;
        continue;
      }
      if (tok === '-c' && tokens[i + 1] !== undefined) {
        i += 2;
        continue;
      }
      if (tok.startsWith('--git-dir') || tok.startsWith('--work-tree')) {
        // A custom gitdir means we cannot map it to a checkout — skip this one.
        localCwd = null;
        i += tok.includes('=') ? 1 : 2;
        continue;
      }
      if (tok.startsWith('-')) {
        i += 1;
        continue;
      }
      break;
    }
    const subcommand = tokens[i];
    if (subcommand === undefined) continue;
    out.push({ cwd: localCwd, dashC, subcommand, args: tokens.slice(i + 1) });
  }
  return out;
}

/** `cd sub` / `-C sub` relative to the segment's current directory. Purely
 *  textual — the result is handed to `resolvePath`, which realpaths it. */
function joinPosix(base: string | null, rel: string): string | null {
  if (base === null) return null;
  const clean = rel.replace(/^\.\//, '');
  if (clean === '' || clean === '.') return base;
  return `${toPosix(base).replace(/\/$/, '')}/${toPosix(clean)}`;
}

function isEnvPrefix(token: string): boolean {
  return baseName(token) === 'env' || /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function isGitBinary(token: string): boolean {
  return baseName(token) === 'git';
}

/** Split on `&&`, `||`, `;` and newlines, outside quotes. */
export function splitSegments(command: string): string[] {
  const out: string[] = [];
  let buf = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i] as string;
    if (quote !== null) {
      if (ch === '\\' && quote === '"') {
        buf += ch + (command[i + 1] ?? '');
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      buf += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      buf += ch;
      continue;
    }
    if (ch === '\\' && command[i + 1] === '\n') {
      i += 1;
      continue;
    }
    if (ch === '\n' || ch === ';') {
      out.push(buf);
      buf = '';
      continue;
    }
    if ((ch === '&' || ch === '|') && command[i + 1] === ch) {
      out.push(buf);
      buf = '';
      i += 1;
      continue;
    }
    // `|` and `|&` also start a new segment: `true | git reset --hard x` runs
    // the git command for real, so it must not fall through to allow just
    // because it sits on the right of a pipe.
    if (ch === '|') {
      out.push(buf);
      buf = '';
      if (command[i + 1] === '&') i += 1;
      continue;
    }
    buf += ch;
  }
  out.push(buf);
  return out.map((s) => s.trim()).filter((s) => s !== '');
}

/**
 * Quote-aware word split. Returns null when the segment contains something we
 * refuse to reason about (command substitution, a subshell) — the caller then
 * skips it rather than guessing.
 */
export function tokenize(segment: string): string[] | null {
  if (/\$\(|`|<\(/.test(segment)) return null;
  const tokens: string[] = [];
  let buf = '';
  let started = false;
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i] as string;
    if (quote !== null) {
      if (quote === '"' && ch === '\\' && segment[i + 1] !== undefined) {
        buf += segment[i + 1] as string;
        i += 1;
        continue;
      }
      if (ch === quote) {
        quote = null;
        continue;
      }
      buf += ch;
      continue;
    }
    // ANSI-C quoting `$'…'` — one token, without the leading `$`, with
    // `\n`/`\t`/`\\`/`\'` unescaped like Bash does (everything else keeps its
    // backslash literally rather than guessing at a wider escape table).
    if (ch === '$' && segment[i + 1] === "'") {
      i += 2;
      started = true;
      const ANSI_C_ESCAPES: Readonly<Record<string, string>> = {
        n: '\n',
        t: '\t',
        '\\': '\\',
        "'": "'",
      };
      while (i < segment.length && segment[i] !== "'") {
        const c = segment[i] as string;
        if (c === '\\' && segment[i + 1] !== undefined) {
          const esc = segment[i + 1] as string;
          buf += ANSI_C_ESCAPES[esc] ?? `\\${esc}`;
          i += 2;
          continue;
        }
        buf += c;
        i += 1;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
      continue;
    }
    if (ch === '\\' && segment[i + 1] !== undefined) {
      buf += segment[i + 1] as string;
      i += 1;
      started = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (started || buf !== '') tokens.push(buf);
      buf = '';
      started = false;
      continue;
    }
    // R1: `{`/`}` used to abort the WHOLE segment unconditionally — which
    // meant `xargs -I{} git -C /r {}` / `parallel git {} ::: …` never even
    // reached the wrapper checks below and fell through to the default
    // allow. Subshells (`(`/`)`) stay rejected; GNU xargs'/parallel's bare
    // replacement tokens (`{}`, `{.}`, `{/}`, `{#}`, `{%}`) need to flow
    // through as ordinary characters so `PLACEHOLDER_TOKENS` can see them.
    if (ch === '(' || ch === ')') return null;
    buf += ch;
    started = true;
  }
  if (started || buf !== '') tokens.push(buf);
  return tokens;
}

/* ---------------- rule predicates ---------------- */

/**
 * Options that consume the following token as a value, per subcommand (from
 * `git <sub> -h`). Without this, that value can spell `-h` or `--dry-run` and
 * get read as a flag of its own — audit H1, confirmed against real git:
 * `git stash push -m --dry-run`, `git merge -m -h <branch>` and
 * `git clean -fd -e -n` all mutate despite looking "read-only" to a scan that
 * does not know `-m`/`-e` take an argument. Not a single global list: e.g.
 * `-C` takes a value for `am`/`rebase` but means something else in `merge`.
 */
const VALUE_TAKING_OPTS: Readonly<Record<string, readonly string[]>> = {
  stash: ['-m', '--message', '--pathspec-from-file'],
  merge: [
    '-m', '--message', '-F', '--file', '-s', '--strategy', '-X', '--strategy-option',
    '--cleanup', '--into-name', '--log',
  ],
  checkout: ['-b', '-B', '--orphan', '--conflict', '--pathspec-from-file'],
  switch: ['-c', '--create', '-C', '--force-create', '--orphan', '--conflict'],
  restore: ['-s', '--source', '--conflict', '--pathspec-from-file'],
  branch: [
    '-u', '--set-upstream-to', '--contains', '--no-contains', '--merged', '--no-merged',
    '--sort', '--points-at', '--format',
  ],
  clean: ['-e', '--exclude'],
  'cherry-pick': ['-m', '--mainline', '-s', '--strategy', '-X', '--strategy-option', '--cleanup'],
  revert: ['-m', '--mainline', '-s', '--strategy', '-X', '--strategy-option', '--cleanup'],
  rebase: ['--onto', '-C', '--whitespace', '-x', '--exec', '-s', '--strategy', '-X', '--strategy-option'],
  am: [
    '--quoted-cr', '--directory', '--exclude', '--include', '-C', '-p', '--resolvemsg',
    '--patch-format',
  ],
  worktree: ['-b', '-B', '--reason', '--expire'],
};

/**
 * Subcommands where a bare `--dry-run` is really a no-op, verified against
 * `git help <sub>`: `pull` and `rebase` (an *unknown* `--dry-run` on most
 * other mutating subcommands — `reset`, `checkout`, `merge` — also happens to
 * abort with "unknown option" on current git, but the guard must not depend
 * on that being true of every git version; fail-closed instead). `clean`'s
 * own short forms (`-n`, bundled `-fdn`) are handled separately in
 * `isMutating`; this only covers its long form.
 */
const DRY_RUN_OK_SUBCOMMANDS = new Set(['pull', 'clean', 'rebase']);

/**
 * `inv.args` restricted to the part before a literal `--` (pathspec
 * separator — nothing after it is a flag), with the value of any
 * `VALUE_TAKING_OPTS` option removed so it can never be misread as a flag.
 */
function significantArgs(sub: string, args: readonly string[]): string[] {
  const ddIdx = args.indexOf('--');
  const scanned = ddIdx === -1 ? args : args.slice(0, ddIdx);
  const valueOpts = VALUE_TAKING_OPTS[sub];
  if (valueOpts === undefined) return [...scanned];
  const out: string[] = [];
  for (let i = 0; i < scanned.length; i += 1) {
    const a = scanned[i] as string;
    out.push(a);
    if (valueOpts.includes(a) && i + 1 < scanned.length) i += 1; // skip its value
  }
  return out;
}

/**
 * Forms that never change anything, whatever the subcommand (audit S5 regression):
 * documentation and dry runs. Without this, `git restore --help` or
 * `git am --show-current-patch` were denied whenever another session lived in
 * the checkout — and a false deny is the one failure this guard must not have.
 *
 * `--help`/`-h` only counts when it is the ONLY remaining argument: `git
 * checkout -h foo` still prints usage in real git, but the guard cannot
 * verify that for every subcommand/version, so a trailing positional makes it
 * fail-closed (audit H1). `--dry-run` only counts on `DRY_RUN_OK_SUBCOMMANDS`.
 *
 * Deliberately NOT `-n`: that is `--dry-run` only for `clean` (handled in
 * `isMutating`), while `git revert -n` is `--no-commit` and very much changes
 * the worktree. Deliberately NOT `--abort`/`--quit` either: they roll back an
 * operation whose half-finished state may belong to the other session.
 */
function isReadOnlyForm(inv: GitInvocation): boolean {
  const args = significantArgs(inv.subcommand, inv.args);
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) return true;
  if (args.some((a) => a === '--show-current-patch' || a.startsWith('--show-current-patch='))) {
    return true;
  }
  if (DRY_RUN_OK_SUBCOMMANDS.has(inv.subcommand) && args.includes('--dry-run')) return true;
  return false;
}

/** `git branch` flags that actually change something (delete/rename/copy/
 *  move/force-create/upstream config) — audit J7. Bare `git branch`, `-a`,
 *  `--list`, `-v`, `--show-current`, `--contains <x>` are reads. */
/** K2: `--set-upstream-to=x` and `--set-upstream-to x` mean the same thing —
 *  compare only the part before an inline `=` when checking flag membership. */
function flagBase(arg: string): string {
  const eq = arg.indexOf('=');
  return eq === -1 ? arg : arg.slice(0, eq);
}

const BRANCH_MUTATING_FLAGS = new Set([
  '-d', '-D', '--delete',
  '-m', '-M', '--move',
  '-c', '-C', '--copy',
  '-f', '--force',
  '-u', '--set-upstream-to',
  '--unset-upstream',
  '--edit-description',
]);

export function isMutating(inv: GitInvocation): boolean {
  // J8: a wrapper the parser could not honestly unwrap (`xargs … git …`) but
  // that textually pairs `git` with a mutating subcommand — fail-closed
  // rather than silently falling through to allow.
  if (inv.subcommand === UNSAFE_WRAPPER_SUBCOMMAND) return true;
  if (isReadOnlyForm(inv)) return false;
  const sub = inv.subcommand;
  if (sub === 'stash') {
    // J1: was `inv.args.find(...)` — read the RAW args, so `git stash -m
    // list` (a push whose message happens to be "list") walked right past
    // `STASH_READS` and was allowed to mutate. `significantArgs` strips the
    // value of `-m`/`--message` first, the same way `clean`/`branch` already do.
    const args = significantArgs('stash', inv.args);
    const first = args.find((a) => !a.startsWith('-'));
    // Bare `git stash` == `git stash push`.
    return first === undefined || !STASH_READS.has(first);
  }
  if (sub === 'worktree') {
    // Same class of bug: `--reason`/`--expire`/`-b`/`-B` take a value that
    // could spell `remove` and get misread as the positional subcommand.
    const args = significantArgs('worktree', inv.args);
    const first = args.find((a) => !a.startsWith('-'));
    return first !== undefined && WORKTREE_MUTATING.has(first);
  }
  if (sub === 'branch') {
    // J1/J7: was `inv.args.some(...)` over raw args, so e.g. `git branch
    // --contains -d somebranch` (the `-d` is the VALUE of `--contains`) read
    // as a delete. `significantArgs` drops that value before scanning flags.
    // K2: compare the part before `=` — `--set-upstream-to=x` mutates exactly
    // like `--set-upstream-to x`, but as one token it never equalled the flag
    // in `BRANCH_MUTATING_FLAGS` and read as an unknown (non-mutating) arg.
    const args = significantArgs('branch', inv.args);
    return args.some((a) => BRANCH_MUTATING_FLAGS.has(flagBase(a)));
  }
  if (sub === 'clean') {
    // `-n` (also inside a bundle like `-fdn`) is a dry run — git deletes nothing, so a
    // deny would be a false one. Without `-f`/`--force` it deletes nothing either. `significantArgs` drops the
    // value of `-e`/`--exclude` so it can't be mistaken for a bundled flag
    // (audit H1: `clean -fd -e -n` — that `-n` is the exclude pattern, not a
    // dry-run flag, and the command really deletes).
    const args = significantArgs('clean', inv.args);
    const dryRun = args.some((a) => /^-[a-zA-Z]+$/.test(a) && a.slice(1).includes('n'));
    if (dryRun) return false;
    return args.some(
      (a) => a === '--force' || (/^-[a-zA-Z]+$/.test(a) && a.slice(1).includes('f')),
    );
  }
  return MUTATING.has(sub);
}

export function isAddAll(inv: GitInvocation): boolean {
  if (inv.subcommand !== 'add') return false;
  return inv.args.some((a) => a === '-A' || a === '--all' || a === '.' || a === '-Av' || a === ':/');
}

export function isCommitAll(inv: GitInvocation): boolean {
  if (inv.subcommand !== 'commit') return false;
  // `-a`, `--all`, and bundled short flags (`-am "msg"`, `-va`). `--amend` is a
  // long option and must not be read as a bundle.
  return inv.args.some(
    (a) => a === '--all' || (/^-[a-zA-Z]+$/.test(a) && a.slice(1).includes('a')),
  );
}

/** `git commit` that is neither `-a` nor path-scoped (`--only`, `--include`,
 *  `-- <paths>`): those are the safe forms the spec's advice recommends. */
export function isPlainCommit(inv: GitInvocation): boolean {
  if (inv.subcommand !== 'commit') return false;
  if (isCommitAll(inv)) return false;
  if (inv.args.some((a) => a === '--only' || a === '-o' || a === '--include' || a === '-i')) {
    return false;
  }
  if (inv.args.includes('--')) return false;
  if (inv.args.some((a) => a === '--amend')) return true;
  return true;
}
