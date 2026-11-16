/**
 * R2-06 — structural plot for the reply worker.
 *
 * The worker's system prompt (`WORKER_SYSTEM_PROMPT` in `replies.ts`) already
 * tells it not to deploy, push, touch secrets or run anything irreversible —
 * but a prompt is advice, not a fence, and the worker's whole attack surface is
 * a web reply it treats as data. This is the fence: the CLI hook marks a
 * worker's tool calls with `worker: true` (env `LEDGER_WORKER=1`, set in
 * `replies.ts`'s `childEnv`), and this module denies the specific
 * high-blast-radius Bash commands and file paths for that marker only —
 * every other session is untouched.
 *
 * Philosophy is the OPPOSITE of `git-guard.ts`: there a false deny is the
 * unforgivable failure (it teaches a trusted agent to stop trusting the
 * guard). Here the worker is reply-triggered and the whole point is
 * containment, so a segment this parser cannot safely reason about (a
 * subshell, command substitution — `tokenize` returns `null`) is denied
 * rather than passed through.
 */

import { SHELL_WRAPPER_HEADS, splitSegments, tokenize } from './git-guard.ts';

// `sudo` is NOT here: it must reach `denyReasonFor` as the head so the
// explicit `sudo` deny below fires, rather than being unwrapped to whatever
// it runs (`sudo whoami` must deny on `sudo`, not fall through to `whoami`).
const CALL_WRAPPERS = new Set(['command', 'exec', 'nice', 'nohup', 'time']);

/**
 * R3-03: wrapper heads this parser refuses to unwrap at all — `sh -c "…"`,
 * `eval …`, bare `env cmd`, `xargs …`, `timeout …`, `stdbuf …`, `watch …` can
 * all hide an arbitrary command behind flags this tokenizer would otherwise
 * have to guess the arity of (`timeout 10 git push` — is `10` a flag value or
 * the command? `watch -n 5 git push` — same problem). Per this module's own
 * fail-closed rule, a head we cannot cleanly resolve is denied outright
 * rather than partially unwrapped and risk missing what actually runs.
 */
const OPAQUE_WRAPPER_HEADS = new Set(['eval', 'env', 'xargs', 'timeout', 'stdbuf', 'watch', ...SHELL_WRAPPER_HEADS]);

function isEnvPrefix(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token);
}

function baseName(token: string): string {
  return token.split('/').pop() ?? token;
}

/** Piping a fetch straight into a shell is judged on the raw command text: the
 *  segment splitter treats `|` as a boundary, which would otherwise hide the
 *  `curl ... | sh` idiom as two separately-innocuous segments. */
const PIPE_TO_SHELL_RE = /\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash)\b/i;

/**
 * R3-03: one path list for Bash args AND Edit/Write destinations — the Bash
 * list (`.env`, `.ssh`, `.aws`, `.claude`) and the Edit list (`.env`, `auth/`,
 * `security/`, `migrations/`, `.github/workflows/`) used to be two separate,
 * silently-drifting sets; a path sensitive enough to fence from `cat` is
 * exactly as sensitive to fence from `Write`, and vice versa.
 */
const SENSITIVE_PATH_RES = [
  /(^|\/)\.env[^/]*$/,
  /(^|\/)\.ssh(\/|$)/,
  /(^|\/)\.aws(\/|$)/,
  /(^|\/)\.claude\//,
  /(^|\/)\.ledger(\/|$)/,
  /(^|\/)\.git\/hooks(\/|$)/,
  /(^|\/)guard\//,
  /(^|\/)auth\//,
  /(^|\/)security\//,
  /(^|\/)migrations\//,
  /(^|\/)\.github\/workflows\//,
  // Home dotfiles a shell/tool reads on startup — shell init, git identity,
  // package registry auth, DB password files.
  /(^|\/)\.(bashrc|zshrc|bash_profile|zprofile|profile|gitconfig|npmrc|netrc|pgpass)$/,
];

const REMOTE_HEADS = new Set(['ssh', 'scp', 'rsync']);
const RELEASE_TOKEN_RE = /(^|\/)(release|deploy)(\.sh)?$/i;

export const WORKER_BASH_DENY_REASON =
  'worker: requires authorization in chat → ledger note <ID> "needs chat authorization: <what and why>"';

/**
 * `cwdRepo` is the checkout root the worker was spawned in (`replies.ts`
 * passes `cwd` to `spawn`). `rm -rf` outside it is denied; inside it (build
 * output, a scratch dir) is left to the worker's own judgement.
 */
export function evaluateWorkerBash(command: string, cwdRepo: string | null): string | null {
  // H23-2: a multi-line command (`git status\nrm -rf /`) could let a second
  // line run past an allow-listed first line if Claude Code's `Bash(prefix*)`
  // rule treats `*` as matching `\n` too — unverified against a real build,
  // so this 2nd-layer guard denies outright rather than assume either way.
  if (/[\r\n]/.test(command)) return WORKER_BASH_DENY_REASON;
  if (PIPE_TO_SHELL_RE.test(command)) return WORKER_BASH_DENY_REASON;

  for (const segment of splitSegments(command)) {
    const tokens = tokenize(segment);
    if (tokens === null || tokens.length === 0) return WORKER_BASH_DENY_REASON;

    let i = 0;
    while (i < tokens.length && (isEnvPrefix(tokens[i] as string) || CALL_WRAPPERS.has(baseName(tokens[i] as string)))) {
      i += 1;
    }
    const head = baseName(tokens[i] ?? '');
    const rest = tokens.slice(i + 1);

    if (denyReasonFor(head, rest, tokens, cwdRepo) !== null) return WORKER_BASH_DENY_REASON;
  }
  return null;
}

/** Skip git's global options (`-C <dir>`, `-c <k=v>`, `--git-dir[=…]`,
 *  `--work-tree[=…]`) to find the actual subcommand — `git -C /r push` has
 *  `rest[0] === '-C'`, not `'push'`, and reading `rest[0]` directly missed it
 *  entirely (R3-03). */
function gitSubcommand(rest: readonly string[]): string | undefined {
  let i = 0;
  while (i < rest.length) {
    const tok = rest[i] as string;
    if (tok === '-C' || tok === '-c') {
      i += 2;
      continue;
    }
    if (tok.startsWith('--git-dir') || tok.startsWith('--work-tree')) {
      i += tok.includes('=') ? 1 : 2;
      continue;
    }
    if (tok.startsWith('-')) {
      i += 1;
      continue;
    }
    break;
  }
  return rest[i];
}

function denyReasonFor(
  head: string,
  rest: readonly string[],
  allTokens: readonly string[],
  cwdRepo: string | null,
): string | null {
  if (OPAQUE_WRAPPER_HEADS.has(head)) return head;
  if (head === 'sudo' || head === 'launchctl' || head === 'kubectl') return head;
  if (REMOTE_HEADS.has(head)) return head;
  if (head === 'git') {
    const sub = gitSubcommand(rest);
    if (sub === 'push' || sub === 'tag') return 'git';
  }
  if ((head === 'npm' || head === 'pnpm' || head === 'yarn') && rest[0] === 'publish') return 'publish';
  if (head === 'docker' && rest[0] === 'push') return 'docker push';
  if (head === 'terraform' && rest[0] === 'apply') return 'terraform apply';
  if (head === 'gh' && (rest[0] === 'release' || (rest[0] === 'pr' && rest[1] === 'merge'))) return 'gh';
  if (allTokens.some((t) => RELEASE_TOKEN_RE.test(t))) return 'release';
  if (head === 'rm' && isRecursiveForce(rest) && rmTargetsOutside(rest, cwdRepo)) return 'rm -rf';
  if (touchesSensitivePath(allTokens, head)) return 'sensitive path';
  return null;
}

function isRecursiveForce(args: readonly string[]): boolean {
  let hasR = false;
  let hasF = false;
  for (const a of args) {
    if (!a.startsWith('-') || a.startsWith('--')) {
      if (a === '--recursive') hasR = true;
      if (a === '--force') hasF = true;
      continue;
    }
    if (/r/i.test(a)) hasR = true;
    if (/f/i.test(a)) hasF = true;
  }
  return hasR && hasF;
}

function rmTargetsOutside(args: readonly string[], cwdRepo: string | null): boolean {
  const targets = args.filter((a) => !a.startsWith('-'));
  if (targets.length === 0) return false;
  return targets.some((t) => {
    if (t.startsWith('~') || t.startsWith('/')) {
      // An absolute path is "outside cwd" unless it is literally under it.
      return cwdRepo === null || !t.startsWith(cwdRepo);
    }
    return t.split('/').includes('..');
  });
}

function touchesSensitivePath(tokens: readonly string[], head: string): boolean {
  if (head === 'ledger') return false;
  return tokens.some((t) => isSensitivePath(t));
}

export const WORKER_EDIT_DENY_REASON =
  'worker: requires authorization in chat → ledger note <ID> "needs chat authorization: <what and why>"';

/** Edit|Write destinations a worker may never touch — same list as the Bash
 *  path fence above (R3-03). */
export function isWorkerDeniedEditPath(absPath: string): boolean {
  return isSensitivePath(absPath);
}

/** The fence is written with `/`; a Windows path (`C:\\x\\.env`) is the same
 *  path, so backslashes count as separators. (On POSIX a backslash is a legal
 *  filename character, but treating it as a separator here only ever widens the
 *  deny set — the safe direction for a fence.) */
function isSensitivePath(p: string): boolean {
  const norm = p.replaceAll('\\', '/');
  return SENSITIVE_PATH_RES.some((re) => re.test(norm));
}
