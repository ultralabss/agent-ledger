/**
 * "Is this Bash command so obviously read-only that PostToolUse has
 * nothing to attribute?"
 *
 * The hub's PostToolUse handler for Bash does exactly one thing: diff the
 * repo's dirty set before/after to attribute files the Edit guard never saw
 * (`hooks.ts#attributeBash`). A command that cannot write anything produces no
 * new dirty entry, so the whole round trip is pure latency — and hooks run on
 * every tool call of every session.
 *
 * PreToolUse is deliberately NOT covered: the guard must see every command.
 *
 * The predicate is one-sided. `true` must mean "cannot write, cannot spawn
 * anything we did not read"; `false` only means "not sure" and costs nothing
 * but the normal request. Every ambiguity therefore resolves to `false`:
 * unknown head, unknown git subcommand, any quoting we cannot parse with
 * certainty, any metacharacter — even inside quotes, where it would be inert.
 * Being wrong in the `true` direction loses file attribution silently, so the
 * asymmetry is the point.
 *
 * This module imports nothing (see `hook.ts`'s header — startup is a budget).
 */

/** Chaining, redirection, substitution, escapes. `|` is handled separately: it
 *  is the one separator whose semantics we model (every segment must pass).
 *  Rejected anywhere in the string, quoted or not — deciding whether a `;` is
 *  inert would mean implementing the shell. */
const FORBIDDEN = /[;&<>`$(){}\\\n\r\t\v\f!]/;

/** Heads that cannot write a file or run a program we have not vetted. */
const HEADS = new Set([
  'ls',
  'cat',
  'head',
  'tail',
  'wc',
  'rg',
  'grep',
  'find',
  'stat',
  'file',
  'pwd',
  'which',
  'echo',
  'printf',
  'date',
  'printenv',
  'true',
  'false',
  'test',
  '[',
  // The hub's own CLI. It talks to the hub itself (so nothing is lost by the
  // hook staying quiet) and writes only inside the ledger, which PostToolUse
  // excludes from attribution anyway.
  'ledger',
]);

/** Heads that are read-only only with a fixed argument list. */
const HEADS_FIXED = new Map<string, string[][]>([
  // `env FOO=bar cmd` runs `cmd`; bare `env` just prints. No arguments, ever.
  ['env', [[]]],
  ['node', [['-v'], ['--version']]],
  ['pnpm', [['-v'], ['--version']]],
]);

/** `git <sub>` that cannot mutate a repo and takes arbitrary further args. */
const GIT_READ = new Set(['status', 'log', 'diff', 'show', 'rev-parse', 'ls-files', 'blame', 'grep']);

/** Flags that turn a reader into a writer or a process spawner (`find -exec`,
 *  `find -delete`). Checked for every head, not only the one that defines them,
 *  so a later addition to `HEADS` cannot reintroduce the hole. */
const DANGEROUS_FLAGS = new Set([
  '-exec',
  '-execdir',
  '-ok',
  '-okdir',
  '-delete',
  '-fls',
  '-fprint',
  '-fprint0',
  '-fprintf',
]);

/** In-place editing is head-scoped on purpose: `-i` means "edit the file" for
 *  `sed`/`perl` but "ignore case" for `grep`/`rg`, which must stay skippable.
 *  None of these heads is allowlisted today — the guard is here so that adding
 *  one later does not silently allow `sed -i`. */
const IN_PLACE_HEADS = new Set(['sed', 'gsed', 'perl', 'ruby', 'awk']);
const IN_PLACE_FLAGS = new Set(['-i', '--in-place', '-pi', '-ni']);

/** git options that read a config value, a pager or an external program, i.e.
 *  that can execute something this allowlist never saw. */
const GIT_UNSAFE = new Set([
  '-c',
  '--config',
  '--config-env',
  '--exec-path',
  '--upload-pack',
  '--receive-pack',
  '-O',
  '--open-files-in-pager',
  '--ext-diff',
  '--textconv',
  '-o',
  '--output',
]);

/** the flags above were matched only as exact tokens, so an attached
 *  value (`-O/tmp/evil`, no space — short-flag getopt style) or a `--long=`
 *  form (`--open-files-in-pager=/tmp/evil`) slipped through untouched. Prefix
 *  match the ones that take an attached value; `-o`/`--output` already had
 *  their `=` form covered below but are included for symmetry. */
const GIT_UNSAFE_PREFIXES = ['-O', '--open-files-in-pager=', '--output=', '-o'];

function gitArgUnsafe(a: string): boolean {
  return GIT_UNSAFE.has(a) || GIT_UNSAFE_PREFIXES.some((p) => a.startsWith(p));
}

/** `rg --pre <cmd>` and `rg --hostname-bin <cmd>` run an arbitrary
 *  program chosen by the caller; `rg --search-zip` shells out to a
 *  decompressor. None of these are "DANGEROUS_FLAGS" (that set is find's
 *  process-spawning flags, checked for every head) so `rg` passed through
 *  unfiltered. `--pre=`/`--hostname-bin=` cover the `--long=value` form;
 *  exact match only, so `--pre-glob` (a different, harmless flag) is not
 *  caught by a naive prefix test. */
const RG_UNSAFE_EXACT = new Set(['--pre', '--hostname-bin', '--search-zip']);
const RG_UNSAFE_PREFIXES = ['--pre=', '--hostname-bin='];

function rgArgUnsafe(a: string): boolean {
  return RG_UNSAFE_EXACT.has(a) || RG_UNSAFE_PREFIXES.some((p) => a.startsWith(p));
}

const MAX_LEN = 4_000;
const MAX_SEGMENTS = 4;

/**
 * Split on whitespace, honouring `'…'` and `"…"` as grouping only. Safe because
 * `FORBIDDEN` already removed every character whose meaning depends on the
 * quoting context (`$`, backtick, backslash). Unterminated quote → `null`.
 */
function tokenize(segment: string): string[] | null {
  const tokens: string[] = [];
  let current = '';
  let started = false;
  let quote: "'" | '"' | null = null;
  for (const ch of segment) {
    if (quote !== null) {
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
      continue;
    }
    if (ch === ' ') {
      if (started) tokens.push(current);
      current = '';
      started = false;
      continue;
    }
    current += ch;
    started = true;
  }
  if (quote !== null) return null;
  if (started) tokens.push(current);
  return tokens;
}

function gitOk(rest: string[]): boolean {
  let i = 0;
  // Pre-subcommand options we accept: both are inert for a reader.
  while (i < rest.length) {
    const t = rest[i];
    if (t === '--no-pager' || t === '--literal-pathspecs') {
      i += 1;
      continue;
    }
    if (t === '-C') {
      if (rest[i + 1] === undefined) return false;
      i += 2;
      continue;
    }
    break;
  }
  const sub = rest[i];
  if (sub === undefined) return false;
  const args = rest.slice(i + 1);
  if (args.some(gitArgUnsafe)) return false;
  if (GIT_READ.has(sub)) return true;
  if (sub === 'branch') {
    // No arguments, or listing only — never `-d`, `-m`, `--set-upstream-to`.
    const listing = args.includes('--list');
    return args.every(
      (a) => a === '--list' || a === '-a' || a === '-v' || (listing && !a.startsWith('-')),
    );
  }
  if (sub === 'remote') return args.length === 1 && args[0] === '-v';
  return false;
}

function segmentOk(tokens: string[]): boolean {
  const head = tokens[0];
  if (head === undefined) return false;
  const rest = tokens.slice(1);
  if (rest.some((t) => DANGEROUS_FLAGS.has(t))) return false;
  if (IN_PLACE_HEADS.has(head) && rest.some((t) => IN_PLACE_FLAGS.has(t) || t.startsWith('-i'))) {
    return false;
  }
  if (head === 'git') return gitOk(rest);
  if (head === 'rg' && rest.some(rgArgUnsafe)) return false;
  const fixed = HEADS_FIXED.get(head);
  if (fixed !== undefined) {
    return fixed.some((variant) => variant.length === rest.length && variant.every((a, i) => a === rest[i]));
  }
  return HEADS.has(head);
}

/**
 * `true` ⇒ the command provably cannot write, so PostToolUse can skip the hub
 * entirely. `false` ⇒ send it (the default for everything unclear).
 */
export function isReadOnlyBash(command: unknown): boolean {
  if (typeof command !== 'string') return false;
  const cmd = command.trim();
  if (cmd === '' || cmd.length > MAX_LEN) return false;
  if (FORBIDDEN.test(cmd)) return false;
  const segments = cmd.split('|');
  if (segments.length > MAX_SEGMENTS) return false;
  for (const segment of segments) {
    // `a || b` splits into an empty middle segment → rejected here.
    const tokens = tokenize(segment.trim());
    if (tokens === null || tokens.length === 0) return false;
    if (!segmentOk(tokens)) return false;
  }
  return true;
}
