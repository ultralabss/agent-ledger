/**
 * Claude Code adapter: `~/.claude/settings.json` hook wiring (optional).
 *
 * The logic lives here (and not in `adapters/claude-code/install-hooks.mjs`) for
 * one reason: it rewrites the user's live Claude Code configuration, and that
 * has to be covered by tests running against a copy. The mjs script is a thin
 * wrapper (arguments, locking, backup, consent prompt).
 *
 * Idempotency rule, and the only one that matters: an entry is *ours* iff its
 * `command` is exactly `<ledgerPath> hook <event>`. Re-running the installer
 * therefore replaces nothing and duplicates nothing, `--uninstall` removes
 * exactly our entries, and every hook the user (or another tool) configured is
 * left untouched — including a matcher block we happen to share, whose other
 * entries survive.
 */

export interface HookSpec {
  /** Claude Code event name, e.g. `PreToolUse`. */
  event: string;
  /** Tool matcher, or null for events that take none (SessionStart, Stop, …). */
  matcher: string | null;
  /** `ledger hook <arg>` — the hub's own event slug. */
  arg: string;
}

/** The full set of hooks the hub needs, in the order it documents them. */
export const HOOK_SPECS: readonly HookSpec[] = [
  { event: 'SessionStart', matcher: null, arg: 'session-start' },
  { event: 'UserPromptSubmit', matcher: null, arg: 'user-prompt-submit' },
  { event: 'PreToolUse', matcher: 'Edit|Write|MultiEdit|NotebookEdit', arg: 'pre-tool-use' },
  { event: 'PreToolUse', matcher: 'Bash', arg: 'pre-tool-use' },
  { event: 'PostToolUse', matcher: 'Edit|Write|MultiEdit|NotebookEdit', arg: 'post-tool-use' },
  { event: 'PostToolUse', matcher: 'Bash', arg: 'post-tool-use' },
  { event: 'Stop', matcher: null, arg: 'stop' },
  { event: 'SessionEnd', matcher: null, arg: 'session-end' },
];

/** The hook budget is 1 s per hook; 5 s is the outer bound before Claude
 *  Code gives up on us, which is what we want on a loaded machine. */
export const HOOK_TIMEOUT_S = 5;

interface HookEntry {
  type?: string;
  command?: string;
  timeout?: number;
  [k: string]: unknown;
}

interface MatcherBlock {
  matcher?: string;
  hooks?: HookEntry[];
  [k: string]: unknown;
}

export interface Settings {
  hooks?: Record<string, MatcherBlock[]>;
  [k: string]: unknown;
}

export function commandFor(ledgerPath: string, arg: string): string {
  return `${ledgerPath} hook ${arg}`;
}

/** True when this entry was written by us (and by nobody else). */
function isOurs(entry: HookEntry, ledgerPath: string): boolean {
  if (typeof entry.command !== 'string') return false;
  return HOOK_SPECS.some((spec) => entry.command === commandFor(ledgerPath, spec.arg));
}

function sameMatcher(block: MatcherBlock, matcher: string | null): boolean {
  const have = typeof block.matcher === 'string' ? block.matcher : null;
  if (matcher === null) return have === null || have === '' || have === '*';
  return have === matcher;
}

export interface PlanResult {
  settings: Settings;
  /** Human-readable changes, one per line. Empty = already installed. */
  changes: string[];
}

/**
 * Add every missing hook entry. Pure: the input object is never mutated (the
 * caller may still need it to produce a diff), and the output is a deep-enough
 * copy that writing it cannot alias the original.
 */
export function planInstall(input: Settings, ledgerPath: string): PlanResult {
  const settings = clone(input);
  const hooks = (settings.hooks ??= {});
  const changes: string[] = [];

  for (const spec of HOOK_SPECS) {
    const command = commandFor(ledgerPath, spec.arg);
    const blocks = (hooks[spec.event] ??= []);
    let block = blocks.find((b) => sameMatcher(b, spec.matcher));
    if (block === undefined) {
      block = spec.matcher === null ? { hooks: [] } : { matcher: spec.matcher, hooks: [] };
      blocks.push(block);
      changes.push(`+ ${spec.event}${spec.matcher ? ` [${spec.matcher}]` : ''} (new block)`);
    }
    const entries = (block.hooks ??= []);
    if (entries.some((e) => e.command === command)) continue;
    entries.push({ type: 'command', command, timeout: HOOK_TIMEOUT_S });
    changes.push(`+ ${spec.event}${spec.matcher ? ` [${spec.matcher}]` : ''} → ${command}`);
  }
  return { settings, changes };
}

/** Remove our entries, and any block we emptied. Foreign entries stay. */
export function planUninstall(input: Settings, ledgerPath: string): PlanResult {
  const settings = clone(input);
  const hooks = settings.hooks;
  const changes: string[] = [];
  if (hooks === undefined) return { settings, changes };

  for (const [event, blocks] of Object.entries(hooks)) {
    if (!Array.isArray(blocks)) continue;
    for (const block of blocks) {
      const entries = Array.isArray(block.hooks) ? block.hooks : [];
      const keep = entries.filter((e) => !isOurs(e, ledgerPath));
      if (keep.length !== entries.length) {
        changes.push(
          `- ${event}${block.matcher ? ` [${block.matcher}]` : ''} (${entries.length - keep.length} entries)`,
        );
      }
      block.hooks = keep;
    }
    const remaining = blocks.filter((b) => (Array.isArray(b.hooks) ? b.hooks.length > 0 : true));
    if (remaining.length === 0) delete hooks[event];
    else hooks[event] = remaining;
  }
  if (Object.keys(hooks).length === 0) delete settings.hooks;
  return { settings, changes };
}

/** Line diff of two settings objects, for `--dry-run`. */
export function diffText(before: Settings, after: Settings): string {
  const a = `${JSON.stringify(before, null, 2)}\n`.split('\n');
  const b = `${JSON.stringify(after, null, 2)}\n`.split('\n');
  const out: string[] = [];
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i += 1) {
    const left = a[i];
    const right = b[i];
    if (left === right) continue;
    if (left !== undefined) out.push(`- ${left}`);
    if (right !== undefined) out.push(`+ ${right}`);
  }
  return out.length === 0 ? '(no changes)\n' : `${out.join('\n')}\n`;
}

/** `settings.json.bak.<ISO-ish timestamp>` — sortable, no colons (Finder). */
export function backupName(file: string, at = new Date()): string {
  const stamp = at
    .toISOString()
    .replace(/[:.]/g, '-')
    .replace(/Z$/, '');
  return `${file}.bak.${stamp}`;
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value ?? {})) as T;
}

/** Count of our entries currently present, used by the script's summary. */
export function installedCount(settings: Settings, ledgerPath: string): number {
  let n = 0;
  for (const blocks of Object.values(settings.hooks ?? {})) {
    if (!Array.isArray(blocks)) continue;
    for (const block of blocks) {
      for (const entry of Array.isArray(block.hooks) ? block.hooks : []) {
        if (isOurs(entry, ledgerPath)) n += 1;
      }
    }
  }
  return n;
}
