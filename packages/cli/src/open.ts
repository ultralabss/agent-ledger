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
 * header), `spawn` gets an argument array and never `shell: true`, and the URL
 * returned by the hub is validated before the browser is launched (http,
 * loopback, path `/login`).
 */

import { spawn } from 'node:child_process';
import { bool, type Args } from './args.ts';
import { CliError, type CliEnvConfig, type HubClient } from './client.ts';
import type { Io } from './index.ts';

/** macOS launcher, absolute path — no `PATH` lookup. */
const OPEN_BIN = '/usr/bin/open';
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
 * The hub may only return a loopback `http://<same port>/login`. Otherwise the
 * browser is not launched.
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
  const loopback = u.hostname === '127.0.0.1' || u.hostname === 'localhost';
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
  return raw;
}

/** `spawn` with an argument array, no shell — the URL never passes an interpreter. */
function launchBrowser(url: string): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(OPEN_BIN, [url], { stdio: 'ignore', shell: false });
    child.on('error', () =>
      reject(
        new CliError(3, `could not run ${OPEN_BIN} — use \`ledger open --print\``),
      ),
    );
    child.on('close', (code) => {
      if (code === 0) resolvePromise();
      else
        reject(
          new CliError(3, `${OPEN_BIN} exited with code ${code} — use \`ledger open --print\``),
        );
    });
  });
}

export interface OpenDeps {
  /** Injectable for tests — production runs `/usr/bin/open`. */
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
