/**
 * `ledger open [path]` — sign in to the web UI (SPEC §13).
 *
 * Threat model:
 *  - Actor: another local account/process, the contents of `~/.zsh_history`,
 *    screen sharing, and anything that can see process arguments (`ps`).
 *  - Protected: the hub token — it must never leave `.hub/token` and the
 *    `X-Hub-Token` header. Only a one-time code with a 60 s TTL goes to the browser.
 *  - Failure modes: token in a URL (history, Referer, logs) · `open` run through
 *    a shell (URL like `; rm -rf ~`) · browser opened on a foreign URL planted by
 *    a broken/spoofed hub · a path from an argument used as an open redirect.
 *
 * Hence: the code is issued by `POST /v1/ui/login-code` (token only in the
 * header), `spawn` gets an argument array and never runs through a shell, and the URL
 * returned by the hub is validated before the browser is launched (http,
 * loopback, path `/login`).
 */

import { spawn } from 'node:child_process';
import os from 'node:os';
import { resolveTrustedExecutable } from '@agent-ledger/shared';
import { bool, type Args } from './args.ts';
import { CliError, type CliEnvConfig, type HubClient } from './client.ts';
import type { Io } from './index.ts';

/** macOS launcher, absolute path — no `PATH` lookup. */
const OPEN_BIN = '/usr/bin/open';
const XDG_OPEN_BIN = '/usr/bin/xdg-open';
const WSLVIEW_BIN = '/usr/bin/wslview';
/** `%SystemRoot%` must be a plain drive-rooted directory; anything else is not trusted. */
const SYSTEM_ROOT_RE = /^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+$/;
/** The friendly name the UI is opened under. `*.localhost` resolves to loopback
 *  in browsers (RFC 6761); the hub accepts exactly this label and nothing else
 *  under `.localhost`. */
const UI_HOST = 'ledger.localhost';
const NEXT_MAX_LEN = 256;
const NEXT_RE = /^\/[A-Za-z0-9\-._~!$&'()*+,;=:@/?%#]*$/;

/**
 * Validation of a UI path. A deliberate copy of the hub's `safeNextPath`: the CLI
 * must not depend on the hub package at runtime, and the client-side check is
 * only the first line of defence — the hub validates `next` again when it issues
 * the code and on the redirect.
 */
export function safeUiPath(raw: string): string | null {
  if (raw.length === 0 || raw.length > NEXT_MAX_LEN) return null;
  if (!raw.startsWith('/')) return null;
  if (raw.startsWith('//')) return null;
  if (/[\s\\\0]/.test(raw)) return null;
  if (!NEXT_RE.test(raw)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  if (/[\s\\\0]/.test(decoded)) return null;
  if (decoded.startsWith('//')) return null;
  return raw;
}

function portOf(u: URL): string {
  return u.port !== '' ? u.port : '80';
}

/**
 * The hub may only return a loopback `http://<same port>/login` (`127.0.0.1`,
 * `localhost` or `ledger.localhost`). Otherwise the browser is not launched.
 * The URL that is returned (and opened) always uses `ledger.localhost`: the UI
 * cookie is host-only, so the host the browser logs in on is the host it keeps
 * using — a uniform, recognisable one.
 * The port is also checked against `LEDGER_HUB_URL` — otherwise a broken or
 * spoofed hub could make the browser open another local service and hand it
 * the navigation (and `next` with it).
 */
function assertLoginUrl(raw: unknown, baseUrl: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 512) {
    throw new CliError(4, 'hub did not return a login URL');
  }
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new CliError(4, 'hub returned an invalid login URL');
  }
  const loopback =
    u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === UI_HOST;
  if (u.protocol !== 'http:' || !loopback || u.pathname !== '/login') {
    // No URL value in the message — it contains the one-time code.
    throw new CliError(4, 'hub returned a login URL outside loopback — refused');
  }
  if (portOf(u) !== portOf(new URL(baseUrl))) {
    throw new CliError(4, 'hub returned a login URL on a foreign port — refused');
  }
  if ((u.searchParams.get('code') ?? '').length === 0) {
    throw new CliError(4, 'hub returned a login URL without a code');
  }
  // Only the host part changes; path, query (the one-time code) and port are
  // taken from the URL that was just validated.
  return `http://${UI_HOST}:${portOf(u)}${u.pathname}${u.search}`;
}

export interface LauncherPlan {
  bin: string;
  /** win32 `explorer.exe <url>` reports exit code 1 even when it opened the page. */
  ignoreExit1: boolean;
}

export interface LauncherEnv {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  release: string;
  /** Test seam: trust verdict for an absolute executable (production: platformTrust). */
  trust?: (candidates: readonly string[]) => Promise<string | null>;
}

const PRINT_HINT = 'use `ledger open --print`';

function isWslEnv(e: LauncherEnv): boolean {
  return e.platform === 'linux' && (/microsoft/i.test(e.release) || (e.env.WSL_DISTRO_NAME ?? '') !== '');
}

/**
 * Which absolute launcher may open the browser on this OS. Never a `PATH` lookup, never a
 * shell. win32: `%SystemRoot%\explorer.exe` (SystemRoot validated), Linux `/usr/bin/xdg-open`,
 * WSL `/usr/bin/wslview` when it passes the trust rules (otherwise print the URL instead).
 */
export async function planLauncher(e: LauncherEnv): Promise<LauncherPlan> {
  const trust =
    e.trust ??
    (async (c: readonly string[]): Promise<string | null> => (await resolveTrustedExecutable(c)).path);
  if (e.platform === 'darwin') return { bin: OPEN_BIN, ignoreExit1: false };
  if (e.platform === 'win32') {
    const root = e.env.SystemRoot ?? e.env.SYSTEMROOT ?? '';
    if (!SYSTEM_ROOT_RE.test(root)) {
      throw new CliError(3, `SystemRoot is not a plain drive-rooted path — ${PRINT_HINT}`);
    }
    const bin = await trust([`${root}\\explorer.exe`]);
    if (bin === null) throw new CliError(3, `explorer.exe could not be verified — ${PRINT_HINT}`);
    return { bin, ignoreExit1: true };
  }
  if (e.platform === 'linux') {
    const wanted = isWslEnv(e) ? WSLVIEW_BIN : XDG_OPEN_BIN;
    const bin = await trust([wanted]);
    if (bin === null) throw new CliError(3, `${wanted} is missing or not trusted — ${PRINT_HINT}`);
    return { bin, ignoreExit1: false };
  }
  throw new CliError(3, `no browser launcher for ${e.platform} — ${PRINT_HINT}`);
}

/** `spawn` with an argument array, no shell — the URL never passes an interpreter. */
function launchBrowser(url: string): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    // Defence in depth: assertLoginUrl already produced this from a parsed URL.
    if (/[\s"\x00-\x1f\x7f]/.test(url)) {
      reject(new CliError(4, 'refusing to launch a URL with unsafe characters'));
      return;
    }
    planLauncher({ platform: process.platform, env: process.env, release: os.release() }).then(
      (plan) => {
        const child = spawn(plan.bin, [url], { stdio: 'ignore', shell: false, windowsHide: true });
        child.on('error', () =>
          reject(new CliError(3, `could not run ${plan.bin} — ${PRINT_HINT}`)),
        );
        child.on('close', (code) => {
          if (code === 0 || (plan.ignoreExit1 && code === 1)) resolvePromise();
          else reject(new CliError(3, `${plan.bin} exited with code ${code} — ${PRINT_HINT}`));
        });
      },
      reject,
    );
  });
}

export interface OpenDeps {
  /** Injectable for tests — production picks the OS launcher (planLauncher). */
  launch?: (url: string) => Promise<void>;
}

/**
 * `ledger open [/path] [--print]`
 *  - requests a one-time code (the token goes only in the `X-Hub-Token` header),
 *  - `--print` prints the URL (only whoever asked for it sees the code),
 *  - otherwise opens the browser and prints nothing that contains the code.
 */
export async function cmdOpen(
  args: Args,
  client: HubClient,
  cfg: CliEnvConfig,
  io: Io,
  deps: OpenDeps = {},
): Promise<number> {
  const target = args.positional[1];
  let next: string | null = null;
  if (target !== undefined && target !== '') {
    next = safeUiPath(target);
    if (next === null) {
      throw new CliError(
        4,
        `path must be relative and start with "/" (e.g. /r/acme), not "${target.slice(0, 40)}"`,
      );
    }
  }

  const res = await client.post('/v1/ui/login-code', next === null ? {} : { next });
  const url = assertLoginUrl((res.json as { url?: unknown } | null)?.url, cfg.baseUrl);

  if (bool(args, 'print')) {
    io.out(url);
    return 0;
  }
  await (deps.launch ?? launchBrowser)(url);
  io.out(`opened in the browser${next === null ? '' : ` at ${next}`} — code valid for 60 s, single use`);
  return 0;
}
