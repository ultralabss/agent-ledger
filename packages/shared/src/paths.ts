/**
 * Path helpers shared by the hub, the CLI, the hook fast path and the spool.
 *
 * Dependency-free on purpose (`node:os` + `node:path` only): `cli/src/hook.ts` is a latency
 * budget and imports this single file, which `scripts/build-hook.mjs` precompiles next to it.
 * Platform and home directory are injectable so win32 behaviour is testable on any host.
 */

import { homedir as osHomedir } from 'node:os';
import path from 'node:path';

export interface PathsDeps {
  platform?: NodeJS.Platform;
  homedir?: () => string;
}

function flavour(platform: NodeJS.Platform): typeof path.posix {
  return platform === 'win32' ? path.win32 : path.posix;
}

/**
 * `~` expansion. `~` and `~/x` everywhere, `~\x` on win32 only. `~user` is refused (throws):
 * resolving it as a relative directory literally named `~user` would be a silent surprise.
 * Anything else resolves to an absolute path.
 */
export function expandHome(p: string, deps: PathsDeps = {}): string {
  const platform = deps.platform ?? process.platform;
  const home = (deps.homedir ?? osHomedir)();
  const f = flavour(platform);
  if (p === '~') return home;
  if (p.startsWith('~/') || (platform === 'win32' && p.startsWith('~\\'))) {
    return f.resolve(home, p.slice(2));
  }
  if (p.startsWith('~')) {
    throw new Error(`unsupported path "${p.slice(0, 40)}": only "~" and "~/" are expanded, not "~user"`);
  }
  return f.isAbsolute(p) ? p : f.resolve(p);
}

/** Default ledger repo: `<home>/.ledger`. */
export function defaultLedgerDir(deps: PathsDeps = {}): string {
  const platform = deps.platform ?? process.platform;
  return flavour(platform).join((deps.homedir ?? osHomedir)(), '.ledger');
}

/** Case-fold + separator-normalise for comparing win32 paths. */
function winKey(p: string): string {
  let s = p.replace(/\//g, '\\');
  if (s.startsWith('\\\\?\\') && !s.startsWith('\\\\?\\UNC\\')) s = s.slice(4);
  s = path.win32.normalize(s);
  const root = path.win32.parse(s).root;
  while (s.length > root.length && s.endsWith('\\')) s = s.slice(0, -1);
  return s.toLowerCase();
}

/**
 * True when `a` and `b` name the same path. win32: case-insensitive, `/` and `\` equal,
 * trailing separators ignored. Elsewhere a plain (normalised) `===`. Neither form touches the
 * filesystem, so symlinks are NOT resolved — callers that need that realpath both sides first.
 */
export function samePath(a: string, b: string, deps: Pick<PathsDeps, 'platform'> = {}): boolean {
  const platform = deps.platform ?? process.platform;
  if (platform === 'win32') return winKey(a) === winKey(b);
  const strip = (s: string): string => {
    const n = path.posix.normalize(s);
    return n.length > 1 && n.endsWith('/') ? n.slice(0, -1) : n;
  };
  return strip(a) === strip(b);
}

function isUnder(child: string, parent: string): boolean {
  const c = winKey(child);
  const p = winKey(parent);
  return c === p || c.startsWith(p.endsWith('\\') ? p : `${p}\\`);
}

/**
 * Spool directory: `LEDGER_SPOOL_DIR` if set, else
 * - win32: `%LOCALAPPDATA%\agent-ledger\spool` (only when `%LOCALAPPDATA%` is absolute, drive-rooted
 *   and under the home directory; otherwise `<home>\AppData\Local`),
 * - posix: `$XDG_STATE_HOME/agent-ledger/spool` (absolute only, per the XDG spec), else
 *   `~/.local/state/agent-ledger/spool`.
 */
export function spoolDir(env: NodeJS.ProcessEnv = process.env, deps: PathsDeps = {}): string {
  const platform = deps.platform ?? process.platform;
  const home = (deps.homedir ?? osHomedir)();
  const f = flavour(platform);
  const raw = env.LEDGER_SPOOL_DIR?.trim();
  if (raw && raw !== '') return expandHome(raw, deps);
  if (platform === 'win32') {
    const local = env.LOCALAPPDATA?.trim();
    const ok =
      local !== undefined &&
      local !== '' &&
      /^[A-Za-z]:[\\/]/.test(local) &&
      path.win32.isAbsolute(local) &&
      isUnder(local, home);
    const base = ok ? path.win32.normalize(local) : path.win32.join(home, 'AppData', 'Local');
    return path.win32.join(base, 'agent-ledger', 'spool');
  }
  const xdg = env.XDG_STATE_HOME?.trim();
  const stateHome = xdg && f.isAbsolute(xdg) ? xdg : f.resolve(home, '.local', 'state');
  return f.join(stateHome, 'agent-ledger', 'spool');
}
