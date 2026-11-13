/** Tiny argv parser: `--flag value`, `--flag=value`, repeatable flags, `--`. */

export interface Args {
  positional: string[];
  flags: Map<string, string[]>;
  bools: Set<string>;
}

const KNOWN_BOOLS = new Set([
  'full',
  'proposed',
  'open',
  'new',
  'json',
  'help',
  'version',
  'print',
  // F2/F3
  'force',
  'all',
  'late',
  'markdown',
  // doctor
  'fix',
  'online',
  // show --origin, tidy --apply (rejected, but must not eat the next argument)
  'origin',
  'apply',
]);

export function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string[]>();
  const bools = new Set<string>();
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i] ?? '';
    if (arg === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      if (eq > 2) {
        const name = arg.slice(2, eq);
        push(flags, name, arg.slice(eq + 1));
        i += 1;
        continue;
      }
      const name = arg.slice(2);
      const next = argv[i + 1];
      if (KNOWN_BOOLS.has(name) || next === undefined || next.startsWith('--')) {
        bools.add(name);
        i += 1;
        continue;
      }
      push(flags, name, next);
      i += 2;
      continue;
    }
    positional.push(arg);
    i += 1;
  }
  return { positional, flags, bools };
}

function push(flags: Map<string, string[]>, name: string, value: string): void {
  const list = flags.get(name);
  if (list) list.push(value);
  else flags.set(name, [value]);
}

export function flag(args: Args, name: string): string | undefined {
  return args.flags.get(name)?.at(-1);
}

export function flagList(args: Args, name: string): string[] {
  return args.flags.get(name) ?? [];
}

export function bool(args: Args, name: string): boolean {
  return args.bools.has(name) || flag(args, name) === 'true' || flag(args, name) === '1';
}

/** Comma-or-repeat list: `--items A,B --items C` → [A, B, C]. */
export function csv(args: Args, name: string): string[] {
  return flagList(args, name)
    .flatMap((v) => v.split(','))
    .map((v) => v.trim())
    .filter((v) => v !== '');
}
