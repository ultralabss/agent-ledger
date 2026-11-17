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

import { constants as fsc } from 'node:fs';
import { lstat, open, readFile, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SLOT_LETTERS } from '@agent-ledger/shared';

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'info';

export interface Check {
  /** Stable machine id (`--json` consumers key on it). */
  id: string;
  status: CheckStatus;
  /** The human line, exactly as printed. */
  detail: string;
}

/** Highest `ledger.format` this CLI knows (`hub/ledger/device.ts` `LEDGER_FORMAT`; the CLI has no runtime
 *  dependency on the hub, so the number is mirrored and only ever used for a "newer than I know" note). */
const KNOWN_LEDGER_FORMAT = 2;

/** `ledger.format` marker of the ledger: absent = format 1 (legacy, pre-sync layout). Reads one tiny file, never
 *  follows a symlink, never fails the run (a broken marker is a warn: the hub itself refuses to start on it). */
export async function formatCheck(ledgerDir: string): Promise<Check> {
  const id = 'ledger_format';
  const file = join(ledgerDir, 'ledger.format');
  let text: string;
  try {
    const st = await lstat(file);
    if (!st.isFile() || st.size > 64) return { id, status: 'warn', detail: 'ledger_format: the marker is not a small regular file' };
    text = await readFile(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { id, status: 'info', detail: 'ledger_format: 1 (legacy layout, no marker)' };
    return { id, status: 'warn', detail: 'ledger_format: the marker could not be read' };
  }
  const t = text.trim();
  if (!/^[0-9]{1,6}$/.test(t) || Number(t) < 1) return { id, status: 'warn', detail: 'ledger_format: the marker is unreadable (the hub will refuse to start)' };
  const n = Number(t);
  return n > KNOWN_LEDGER_FORMAT
    ? { id, status: 'warn', detail: `ledger_format: ${String(n)} is newer than this install understands (${String(KNOWN_LEDGER_FORMAT)}): upgrade` }
    : { id, status: 'info', detail: `ledger_format: ${String(n)}${n < KNOWN_LEDGER_FORMAT ? ' (older layout; the hub migrates it on start)' : ''}` };
}

/* ---------------- sync (enrolled ledgers): offline, read-only ---------------- */
// Texts never carry a URL, a key or git output: only fixed words, whitelisted tokens and counts.

/** `LEDGER_SYNC_VERIFY` as seen by THIS process (the hub's own service environment may differ). */
export function syncVerifyCheck(raw: string | undefined, loop: string | undefined): Check {
  const id = 'sync_verify_mode';
  const v = raw === undefined || raw.trim() === '' ? 'warn' : raw.trim();
  const loopOn = loop?.trim() === '1';
  if (v !== 'warn' && v !== 'enforce') return { id, status: 'fail', detail: 'sync: LEDGER_SYNC_VERIFY must be "warn" or "enforce" (the hub refuses to start)' };
  const loopNote = loopOn ? '' : '; the sync loop is off in this shell (LEDGER_SYNC is not 1)';
  return v === 'enforce'
    ? { id, status: 'ok', detail: `sync: verify mode enforce (unsigned or unapproved commits are quarantined)${loopNote}` }
    : { id, status: 'warn', detail: `sync: verify mode warn: unsigned or unapproved commits are only reported, not blocked; set LEDGER_SYNC_VERIFY=enforce once every device is approved${loopNote}` };
}

const STATE_MAX_BYTES = 512 * 1024;
const HALT_REASON_RE = /^[a-z][a-z0-9:-]{0,39}$/;
const HALT_CLASSES = new Set(['no-contact', 'sticky', 'probe', 'd2', 'local', 'terminal']);

/** Read a small regular file without following a symlink (`O_NOFOLLOW`; `lstat` first for platforms without it).
 *  `null` = absent; throws on anything else (symlink, too large, unreadable). */
async function readSmallNoFollow(path: string, maxBytes: number): Promise<string | null> {
  let st;
  try {
    st = await lstat(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
  if (!st.isFile() || st.size > maxBytes) throw new Error('not a small regular file');
  const fh = await open(path, fsc.O_RDONLY | (fsc.O_NOFOLLOW ?? 0));
  try {
    const st2 = await fh.stat();
    if (!st2.isFile() || st2.size > maxBytes || st2.ino !== st.ino || st2.dev !== st.dev) throw new Error('changed under us');
    return await fh.readFile('utf8');
  } finally {
    await fh.close().catch(() => undefined);
  }
}

/** Halt state of the sync loop (`.hub/sync/state.json`). Transient classes (`no-contact`, `probe`) are a warn;
 *  anything that needs a human is a fail. Only whitelisted tokens are printed, never the free-text `detail`. */
export async function syncHaltCheck(ledgerDir: string): Promise<Check> {
  const id = 'sync_halt';
  let text: string | null;
  try {
    text = await readSmallNoFollow(join(ledgerDir, '.hub', 'sync', 'state.json'), STATE_MAX_BYTES);
  } catch {
    return { id, status: 'warn', detail: 'sync: the sync state file is unreadable (ledger sync status)' };
  }
  if (text === null) return { id, status: 'info', detail: 'sync: no sync state yet (the loop has not run)' };
  let halt: unknown;
  try {
    halt = (JSON.parse(text) as { halt?: unknown }).halt;
  } catch {
    return { id, status: 'warn', detail: 'sync: the sync state file is not valid (ledger sync status)' };
  }
  if (halt === null || halt === undefined) return { id, status: 'ok', detail: 'sync: not halted' };
  const h = halt as { reason?: unknown; cls?: unknown; since?: unknown };
  const reason = typeof h.reason === 'string' && HALT_REASON_RE.test(h.reason) ? h.reason : 'unknown';
  const cls = typeof h.cls === 'string' && HALT_CLASSES.has(h.cls) ? h.cls : 'unknown';
  const since = typeof h.since === 'string' && /^\d{4}-\d{2}-\d{2}/.test(h.since) ? h.since.slice(0, 10) : '?';
  return {
    id,
    status: cls === 'no-contact' || cls === 'probe' ? 'warn' : 'fail',
    detail: `sync: HALTED (${reason}, ${cls}) since ${since}: remote changes are not being applied; see: ledger sync status`,
  };
}

/** Slot letters are never reused (a revoked device keeps its slot), so the count is every registry entry with a
 *  letter. `>= 20` of 24 warns; all taken means no further `device add` can succeed. */
export function syncSlotsCheck(rows: readonly { slot: string }[]): Check {
  const id = 'sync_slots';
  const total = SLOT_LETTERS.length;
  const used = rows.filter((r) => r.slot !== '').length;
  if (used >= total) return { id, status: 'fail', detail: `sync: all ${String(total)} device slots are used (revoked devices keep theirs): no further device can be added` };
  if (used >= 20) return { id, status: 'warn', detail: `sync: ${String(used)} of ${String(total)} device slots used (revoked devices keep theirs, slots are never reused)` };
  return { id, status: 'ok', detail: `sync: ${String(used)} of ${String(total)} device slots used` };
}

const PINNED_FILES: readonly { name: string; text: string }[] = [
  { name: '.gitignore', text: '.hub/\n*.tmp\n' },
  { name: '.gitattributes', text: '* text eol=lf\n' },
];

/** Byte-exact pinned files: peers' ingress rejects any other text, so a hand-edit makes every commit of this ledger
 *  unacceptable to them (and a `.gitignore` without `.hub/` would stage the device key). */
export async function syncPinnedFilesCheck(ledgerDir: string): Promise<Check> {
  const id = 'sync_pinned_files';
  const bad: string[] = [];
  for (const f of PINNED_FILES) {
    try {
      if ((await readSmallNoFollow(join(ledgerDir, f.name), 4096)) !== f.text) bad.push(f.name);
    } catch {
      bad.push(f.name);
    }
  }
  return bad.length > 0
    ? { id, status: 'fail', detail: `sync: ${bad.join(' and ')} differ${bad.length === 1 ? 's' : ''} from the pinned text (peers reject the commits; restore it, see docs/multi-device-spec.md 7.3)` }
    : { id, status: 'ok', detail: 'sync: .gitignore and .gitattributes match the pinned text' };
}

/** `git version 2.39.5 (Apple Git-154)` -> [2, 39]; `null` when it does not look like that. */
export function parseGitVersion(out: string): [number, number] | null {
  const m = /^git version (\d{1,4})\.(\d{1,4})(?:[.\s]|$)/.exec(out.trim());
  return m === null ? null : [Number(m[1]), Number(m[2])];
}

const GIT_CANDIDATES_POSIX = ['/usr/bin/git', '/opt/homebrew/bin/git', '/usr/local/bin/git'];
const GIT_CANDIDATES_WIN32 = ['C:\\Program Files\\Git\\cmd\\git.exe'];

/** SSH commit signing and `gpg.ssh.allowedSignersFile` need git >= 2.34. Absolute path, constant argv, no shell. */
export async function syncGitVersionCheck(d: {
  platform: string;
  exists: (p: string) => Promise<boolean>;
  capture: (command: string, args: readonly string[], timeoutMs: number) => Promise<{ code: number | null; stdout: string }>;
}): Promise<Check> {
  const id = 'sync_git_version';
  let bin: string | null = null;
  for (const c of d.platform === 'win32' ? GIT_CANDIDATES_WIN32 : GIT_CANDIDATES_POSIX) {
    if (await d.exists(c).catch(() => false)) {
      bin = c;
      break;
    }
  }
  if (bin === null) return { id, status: 'info', detail: 'sync: git was not found at a standard path (version not checked)' };
  const r = await d.capture(bin, ['--version'], 3000);
  const v = r.code === 0 ? parseGitVersion(r.stdout) : null;
  if (v === null) return { id, status: 'info', detail: 'sync: the git version could not be read' };
  return v[0] > 2 || (v[0] === 2 && v[1] >= 34)
    ? { id, status: 'ok', detail: `sync: git ${String(v[0])}.${String(v[1])} (>= 2.34 for ssh signing)` }
    : { id, status: 'fail', detail: `sync: git ${String(v[0])}.${String(v[1])} is too old: ssh commit signing needs >= 2.34` };
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
