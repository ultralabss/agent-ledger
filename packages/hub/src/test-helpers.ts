/** Test fixtures: a throwaway ledger in a temp dir and a hub on a random port.
 *  Never touches the real `~/.ledger` — every test sets LEDGER_DIR. */

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { loadConfig, type HubConfig } from './config.ts';
import { git } from './git.ts';
import { Ledger } from './ledger/ledger.ts';
import { startHub, type HubHandle } from './server.ts';
import { mkdtempSync, rmSync } from 'node:fs';

// Tests must never read the real spool dir: a write queued on the
// developer's machine changed the brief output and broke assertions. Always a
// fresh temp dir — even if the shell exports LEDGER_SPOOL_DIR — removed
// when the test process exits.
const testSpoolDir = mkdtempSync(join(tmpdir(), 'ledger-spool-test-'));
process.env.LEDGER_SPOOL_DIR = testSpoolDir;
process.on('exit', () => rmSync(testSpoolDir, { recursive: true, force: true }));

export interface TempLedger {
  dir: string;
  config: HubConfig;
  cleanup: () => Promise<void>;
}

export async function tempConfig(overrides: Partial<HubConfig> = {}): Promise<TempLedger> {
  const dir = await mkdtemp(join(tmpdir(), 'agent-ledger-test-'));
  const config: HubConfig = {
    ...loadConfig({ LEDGER_DIR: dir, LEDGER_HUB_PORT: '0', LEDGER_PUSH: '0' }),
    // Long debounce: tests assert on md files, not on git.
    commitDebounceMs: 3_600_000,
    // No `packages/web/dist` in a test — point at a path that cannot exist so
    // the placeholder path is exercised deterministically.
    uiDir: join(dir, '.hub', 'no-ui'),
    // Every fixture repo lives under `tmpdir()` (`/var/folders/**` on macOS),
    // which production excludes from attribution (SPEC §10.11). The
    // exclusion itself is covered by unit tests on `isExcludedPath`.
    excludeTemp: false,
    // Tests point `transcript_path` into their own temp dir.
    transcriptRoots: [dir],
    // Optional features are off in production defaults; tests exercise them.
    intrude: true,
    recapGuard: true,
    webReplies: true,
    headless: true,
    ...overrides,
  };
  return {
    dir,
    config,
    cleanup: async () => {
      await rm(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    },
  };
}

/** Identity so the shutdown commit in `close()` does not warn. */
async function configureGit(dir: string): Promise<void> {
  await git(dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(dir, ['config', 'user.name', 'agent-ledger test']);
}

export interface LedgerFixture extends TempLedger {
  ledger: Ledger;
  logs: string[];
}

export async function openTestLedger(): Promise<LedgerFixture> {
  const tmp = await tempConfig();
  const logs: string[] = [];
  const ledger = new Ledger({ config: tmp.config, log: (line) => logs.push(line) });
  await ledger.init();
  await configureGit(tmp.dir);
  return {
    ...tmp,
    ledger,
    logs,
    cleanup: async () => {
      await ledger.close();
      await tmp.cleanup();
    },
  };
}

export interface HubFixture {
  hub: HubHandle;
  dir: string;
  url: string;
  token: string;
  /** B4-1: per-boot key of the UI cookie — `uiCookieValue(fx)` forges the
   *  cookie a browser would get, which the hub token alone can no longer do. */
  uiSecret: string;
  logs: string[];
  cleanup: () => Promise<void>;
  /** fetch with the hub token attached. */
  api: (method: string, path: string, body?: unknown) => Promise<{ status: number; json: any; text: string }>;
  /** POST a fake Claude Code hook payload; returns stdout + env headers. */
  hook: (
    event: string,
    payload: Record<string, unknown>,
  ) => Promise<{ status: number; text: string; session: string | null; repo: string | null }>;
  /** Parsed JSON body of a hook response (`{}` when the hook printed nothing). */
  hookJson: (event: string, payload: Record<string, unknown>) => Promise<Record<string, any>>;
}

export async function startTestHub(
  overrides: Partial<HubConfig> = {},
  /** A non-zero Bash delay is the only way to make two Bash windows in
   *  one checkout overlap deterministically (ambiguous attribution). */
  opts: { bashDelayMs?: number } = {},
): Promise<HubFixture> {
  const tmp = await tempConfig(overrides);
  const logs: string[] = [];
  const hub = await startHub({
    config: tmp.config,
    log: (line) => logs.push(line),
    watch: false,
    // No background timers in tests — `hub.sweep()` runs the same work on demand.
    periodic: false,
    bashDelayMs: opts.bashDelayMs ?? 0,
    awaitBackground: true,
    // Fake `claude` binaries in these fixtures live under `tmpdir()`,
    // whose ancestry (`/var` → `/private/var`) is a symlink and therefore
    // never "trusted" in production terms. Bound the chain walk to the temp
    // root so the gate can be exercised at all; production leaves it at `/`.
    trustStopAt: overrides.claudeBin ? dirname(overrides.claudeBin) : tmpdir(),
  });
  await configureGit(tmp.dir);
  const api = async (
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; json: any; text: string }> => {
    const res = await fetch(`${hub.url}${path}`, {
      method,
      // S7: reads are gated too now (except /v1/healthz) — always send the
      // token so `fx.api('GET', …)` keeps working for every other route.
      headers:
        method === 'GET'
          ? { 'x-hub-token': hub.token }
          : { 'x-hub-token': hub.token, 'content-type': 'application/json' },
      body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
    });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    return { status: res.status, json, text };
  };
  const hook = async (
    event: string,
    payload: Record<string, unknown>,
  ): Promise<{ status: number; text: string; session: string | null; repo: string | null }> => {
    const res = await fetch(`${hub.url}/v1/hooks/${event}`, {
      method: 'POST',
      headers: { 'x-hub-token': hub.token, 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return {
      status: res.status,
      text: await res.text(),
      session: res.headers.get('x-ledger-session'),
      repo: res.headers.get('x-ledger-repo'),
    };
  };
  const hookJson = async (
    event: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, any>> => {
    const res = await hook(event, payload);
    const text = res.text.trim();
    if (text === '') return {};
    try {
      return JSON.parse(text) as Record<string, any>;
    } catch {
      return { _text: res.text };
    }
  };
  return {
    hub,
    dir: tmp.dir,
    url: hub.url,
    token: hub.token,
    uiSecret: hub.uiSecret,
    logs,
    api,
    hook,
    hookJson,
    cleanup: async () => {
      await hub.close();
      await tmp.cleanup();
    },
  };
}

/** A temp git repo with one commit, an identity, and `main` as the branch. */
export async function makeCommittedRepo(prefix = 'code'): Promise<{
  path: string;
  commit: (message: string, files: Record<string, string>) => Promise<string>;
  tag: (name: string) => Promise<void>;
  cleanup: () => Promise<void>;
}> {
  const path = await mkdtemp(join(tmpdir(), `agent-ledger-${prefix}-`));
  await git(path, ['init', '-q', '-b', 'main']);
  await configureGit(path);
  const { writeFile, mkdir } = await import('node:fs/promises');
  const { dirname } = await import('node:path');
  const commit = async (message: string, files: Record<string, string>): Promise<string> => {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(path, rel);
      await mkdir(dirname(abs), { recursive: true });
      await writeFile(abs, content, 'utf8');
    }
    await git(path, ['add', '-A']);
    const res = await git(path, ['commit', '-m', message]);
    if (res.code !== 0) throw new Error(`commit failed: ${res.stderr}`);
    const sha = await git(path, ['rev-parse', 'HEAD']);
    return sha.stdout.trim();
  };
  await commit('chore: init', { 'README.md': '# test\n' });
  return {
    path,
    commit,
    tag: async (name: string) => {
      const res = await git(path, ['tag', '-a', name, '-m', name]);
      if (res.code !== 0) throw new Error(`tag failed: ${res.stderr}`);
    },
    cleanup: async () => {
      await rm(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
}

/** A registered repo backed by a real (empty) git checkout — `repo add` needs
 *  `git rev-parse --show-toplevel` to succeed. */
export async function makeCodeRepo(prefix = 'code'): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const path = await mkdtemp(join(tmpdir(), `agent-ledger-${prefix}-`));
  await git(path, ['init', '-b', 'main']);
  return {
    path,
    cleanup: async () => {
      await rm(path, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
}
