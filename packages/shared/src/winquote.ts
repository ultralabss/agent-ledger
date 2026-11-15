/**
 * S9 (T9) — escaping validators for the few places a Windows path or argument ends up inside
 * text that another parser re-reads: `ledger.cmd` shims, Task Scheduler arguments, hook command
 * lines. No process is ever started through these (children are `spawn(abs, argv[])`, never a
 * shell); they exist so generated files and command-line strings cannot be turned into code.
 *
 *  - `assertShimSafePath`: REFUSES (does not escape) any path that cmd.exe could treat specially
 *    even inside double quotes: `%` (expansion), `!` (delayed expansion), `"` (ends the quoting),
 *    CR/LF/control characters (end the batch line), invisible/bidi characters (spoofed display),
 *    and over-long paths. Refusal beats escaping because cmd.exe has no single reliable escape.
 *  - `crtQuoteArg`: quotes ONE argument so that `CommandLineToArgvW` / the MSVC runtime parse it
 *    back to exactly the same string (backslash-before-quote rules).
 */

/** MAX_PATH counts the terminating NUL, so a legacy path has at most 259 characters. */
export const WIN_MAX_PATH_CHARS = 259;

export interface ShimPathOptions {
  /** The machine/app opted into long paths (>259); the length limit is then lifted to 32 767. */
  longPaths?: boolean;
}

const MAX_LONG_PATH_CHARS = 32_767;
// C0 controls, DEL, C1 controls, line/paragraph separators, zero-width / bidi / BOM / soft hyphen.
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/u;

/** An unpaired UTF-16 surrogate (not valid Unicode; would be written as U+FFFD). */
const LONE_SURROGATE_RE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/** Throws (RangeError, no path echo beyond the offending character class) unless `p` can sit in a quoted cmd.exe word. */
export function assertShimSafePath(p: unknown, opts: ShimPathOptions = {}): asserts p is string {
  if (typeof p !== 'string' || p === '') throw new RangeError('shim path: empty or not a string');
  const max = opts.longPaths === true ? MAX_LONG_PATH_CHARS : WIN_MAX_PATH_CHARS;
  if (p.length > max) throw new RangeError(`shim path: longer than ${max} characters`);
  if (p.includes('%')) throw new RangeError('shim path: contains "%" (cmd.exe variable expansion)');
  if (p.includes('!')) throw new RangeError('shim path: contains "!" (cmd.exe delayed expansion)');
  if (p.includes('"')) throw new RangeError('shim path: contains a double quote');
  if (CONTROL_RE.test(p)) throw new RangeError('shim path: contains a control, line-break or invisible character');
  if (LONE_SURROGATE_RE.test(p)) throw new RangeError('shim path: not well-formed Unicode');
}

/**
 * Quote one argument for a Windows command line (the "everyone quotes command line arguments the
 * wrong way" algorithm): backslashes are literal EXCEPT in front of a `"` (and at the end of a
 * quoted word, where they would otherwise escape the closing quote), so those are doubled; a `"` is
 * written `\"`. An argument with no space/tab/VT/quote and not empty is returned unchanged.
 * NUL, CR and LF are refused: they cannot be represented safely in a one-line command string.
 */
export function crtQuoteArg(arg: string): string {
  if (typeof arg !== 'string') throw new TypeError('argument must be a string');
  if (/[\u0000\r\n]/.test(arg)) throw new RangeError('argument contains NUL, CR or LF');
  if (arg !== '' && !/[ \t\v"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === '\\') {
      backslashes += 1;
      continue;
    }
    if (ch === '"') {
      out += '\\'.repeat(backslashes * 2 + 1) + '"';
    } else {
      out += '\\'.repeat(backslashes) + ch;
    }
    backslashes = 0;
  }
  // Trailing backslashes precede the closing quote: double them so the quote is not escaped.
  out += '\\'.repeat(backslashes * 2) + '"';
  return out;
}

/** `crtQuoteArg` over an argv, joined by single spaces. */
export function crtQuoteArgv(argv: readonly string[]): string {
  return argv.map(crtQuoteArg).join(' ');
}
