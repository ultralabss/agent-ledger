/**
 * Platform-independent building blocks of `ledger doctor`: the check record,
 * the `ledger_format` note and the "is the ledger's git remote private?"
 * heuristics.
 *
 * The ledger holds task text, decisions and history of every project on the
 * machine. It is private data: its remote must not be public and must not be
 * the remote of the code repository. Everything here is offline unless the
 * caller passes `online` (the `--online` flag) — then, and only then, one
 * unauthenticated request to the code host's public API says whether the repo
 * is publicly visible. Nothing else ever leaves the machine, and credentials
 * embedded in a remote URL are never printed.
 */

import { readFile, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'info';

export interface Check {
  /** Stable machine id (`--json` consumers key on it). */
  id: string;
  status: CheckStatus;
  /** The human line, exactly as printed. */
  detail: string;
}

/** No on-disk format marker exists yet, so nothing is read or invented. */
export function formatCheck(): Check {
  return { id: 'ledger_format', status: 'info', detail: 'ledger_format: not defined yet' };
}

export interface RemoteUrl {
  /** Safe to print: scheme/host/path only, no user info. */
  display: string;
  /** Comparison key (lowercase host/path, no `.git`, no credentials). */
  norm: string;
  host: string;
  path: string;
  scheme: 'https' | 'http' | 'ssh' | 'file';
  /** `https://user:token@host/…` — secret in the URL (never printed). */
  credentialed: boolean;
}

const KNOWN_PUBLIC_HOSTS = new Set(['github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org']);

export function parseRemoteUrl(raw: string): RemoteUrl {
  const url = raw.trim();
  const trimPath = (p: string): string => p.replace(/^\/+/, '').replace(/\/+$/, '').replace(/\.git$/i, '');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
    try {
      const u = new URL(url);
      const scheme = u.protocol === 'https:' ? 'https' : u.protocol === 'http:' ? 'http' : u.protocol === 'file:' ? 'file' : 'ssh';
      const host = u.hostname.toLowerCase();
      const path = trimPath(decodeURIComponent(u.pathname));
      const credentialed = u.password !== '' || ((scheme === 'https' || scheme === 'http') && u.username !== '');
      const display = scheme === 'file' ? `file://${path}` : `${u.protocol}//${host}/${path}`;
      return { display, norm: `${host}/${path}`.toLowerCase(), host, path, scheme, credentialed };
    } catch {
      return { display: '(unparseable url)', norm: url.toLowerCase(), host: '', path: '', scheme: 'ssh', credentialed: false };
    }
  }
  const scp = /^(?:[^@/\s]+@)?([^:/\s]+):(?!\/\/)(.+)$/.exec(url);
  if (scp !== null) {
    const host = (scp[1] ?? '').toLowerCase();
    const path = trimPath(scp[2] ?? '');
    return { display: `ssh://${host}/${path}`, norm: `${host}/${path}`.toLowerCase(), host, path, scheme: 'ssh', credentialed: false };
  }
  const path = url.replace(/\/+$/, '').replace(/\.git$/i, '');
  return { display: `file://${path}`, norm: path.toLowerCase(), host: '', path, scheme: 'file', credentialed: false };
}

/** `[remote "name"] url = …` pairs from `<dir>/.git/config`; `null` when `dir`
 *  is not a plain git work tree. Reads a bounded prefix, spawns nothing. */
export async function readGitRemotes(dir: string): Promise<{ name: string; url: string }[] | null> {
  const gitDir = join(dir, '.git');
  let text: string;
  try {
    if (!(await stat(gitDir)).isDirectory()) return null;
    text = (await readFile(join(gitDir, 'config'), 'utf8')).slice(0, 256 * 1024);
  } catch {
    return null;
  }
  const out: { name: string; url: string }[] = [];
  let current: string | null = null;
  for (const line of text.split('\n')) {
    const section = /^\s*\[(.+)\]\s*$/.exec(line);
    if (section !== null) {
      current = /^remote\s+"(.+)"$/.exec(section[1] ?? '')?.[1] ?? null;
      continue;
    }
    const url = current === null ? null : /^\s*url\s*=\s*(.+?)\s*$/.exec(line)?.[1];
    if (current !== null && url) out.push({ name: current, url });
  }
  return out;
}

/** Default: the checkout this CLI runs from (`packages/cli/src` → repo root). */
export function defaultCodeRepoDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
}

export interface RemoteDeps {
  ledgerDir: string;
  /** Directory of the code repository whose `origin` the ledger must not share. */
  codeRepoDir?: string;
  /** `--online`: allow ONE unauthenticated request to the host's public API. */
  online?: boolean;
  fetchFn?: typeof fetch;
}

const RANK: Record<CheckStatus, number> = { info: 0, ok: 1, warn: 2, fail: 3 };

export async function remoteCheck(deps: RemoteDeps): Promise<Check> {
  const id = 'ledger_remote';
  const remotes = await readGitRemotes(deps.ledgerDir);
  if (remotes === null) return { id, status: 'info', detail: 'ledger remote: ledger dir is not a git work tree' };
  if (remotes.length === 0) return { id, status: 'info', detail: 'ledger remote: none (local only)' };

  const code = (await readGitRemotes(deps.codeRepoDir ?? defaultCodeRepoDir())) ?? [];
  const codeNorms = new Set(code.map((r) => parseRemoteUrl(r.url).norm));

  let worst: CheckStatus = 'ok';
  const notes: string[] = [];
  const bump = (s: CheckStatus): void => {
    if (RANK[s] > RANK[worst]) worst = s;
  };
  for (const r of remotes) {
    const p = parseRemoteUrl(r.url);
    const note: string[] = [`${r.name} ${p.display}`];
    if (codeNorms.has(p.norm)) {
      bump('warn');
      note.push('SAME as the code repo remote — the ledger must have its own private remote');
    }
    if (p.credentialed) {
      bump('warn');
      note.push('credentials embedded in the URL (use ssh or a credential helper)');
    }
    if ((p.scheme === 'https' || p.scheme === 'http') && !p.credentialed && KNOWN_PUBLIC_HOSTS.has(p.host)) {
      bump('warn');
      note.push('unauthenticated https URL — verify it is private');
    }
    if (deps.online === true) {
      const verdict = await onlineVisibility(p, deps.fetchFn ?? fetch);
      bump(verdict.status);
      note.push(verdict.note);
    }
    notes.push(note.join(' · '));
  }
  const suffix = worst === 'ok' && deps.online !== true ? ' · privacy not verified (offline, see --online)' : '';
  return { id, status: worst, detail: `ledger remote: ${notes.join('; ')}${suffix}`.slice(0, 400) };
}

async function onlineVisibility(p: RemoteUrl, fetchFn: typeof fetch): Promise<{ status: CheckStatus; note: string }> {
  const m = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(p.path);
  if (p.host !== 'github.com' || m === null) {
    return { status: 'warn', note: 'online check supports github.com owner/repo only' };
  }
  try {
    const res = await fetchFn(`https://api.github.com/repos/${m[1]}/${m[2]}`, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'agent-ledger-doctor' },
      redirect: 'manual',
      signal: AbortSignal.timeout(5_000),
    });
    if (res.status === 200) return { status: 'fail', note: 'PUBLICLY VISIBLE on github.com — make it private' };
    if (res.status === 404) return { status: 'ok', note: 'not publicly visible' };
    return { status: 'warn', note: `online check inconclusive (HTTP ${res.status})` };
  } catch {
    return { status: 'warn', note: 'online check failed (network)' };
  }
}
