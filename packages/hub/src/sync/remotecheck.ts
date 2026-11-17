/** Remote probes and doctor checks for `sync init|join` and `ledger doctor` (F3b B4b, docs/f3b-b4-plan.md §2.4,
 *  T-B4-1, T-B4-13).
 *
 *  Threat model:
 *   - Actor: a remote that is PUBLIC (anonymous read), a network that fails in ways that look like a refusal, a
 *     hostile server answering `ls-remote` with junk, text that would leak a URL into a log.
 *   - Protected: the first push must never put a ledger on a repository anybody can read, and "I could not
 *     tell" must never be read as "it is private".
 *   - Failure modes: classifying "connection refused / DNS failure / timeout / host key mismatch" as an
 *     authentication refusal (`git` prints `Could not read from remote repository` for ALL of them).
 *   - Stance: the anonymous probe passes ONLY on an explicit permission-denied answer of a reachable server;
 *     everything else is `inconclusive` and a caller refuses. stderr / URL never leave this module: results are
 *     tokens, details carry the sanitised host token only. A `local` remote (tests only, `testLocalRemotes`)
 *     has no credentials to test and reports `not-applicable`.
 */

import { lstat, open } from 'node:fs/promises';
import nodePath from 'node:path';
import { listDevices, safeOutput, type DeviceCheck } from '@agent-ledger/shared';
import { classifyNetError } from './cycle.ts';
import { checkGitConfig, parseGitConfig, validateRemoteUrl, type Gitx, type GitxResult, type RemoteKind } from './gitx.ts';
import { ENROL_STALE_MS, readEnrolMarker, readSyncConfig, SYNC_DIR } from './state.ts';
import { fingerprintOf, hostToken, KNOWN_HOSTS_MAX_BYTES } from './hostkey.ts';

const SSH_HOST_RE = /^ssh:\/\/(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,63}@)?(\[[0-9A-Fa-f:]{2,45}\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::([0-9]{1,5}))?\//;
const SCP_HOST_RE = /^(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,63}@)?([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):/;

/** Host and port of a remote URL the caller already passed `validateRemoteUrl` for; `null` for a `local` remote or
 *  a host form `hostkey.ts` does not support (IPv6 literal). */
export function remoteHostPort(url: string, kind: RemoteKind): { host: string; port: number } | null {
  if (kind === 'local') return null;
  if (kind === 'ssh') {
    const m = SSH_HOST_RE.exec(url);
    if (m === null || (m[1] as string).startsWith('[')) return null;
    return { host: (m[1] as string).toLowerCase(), port: m[2] === undefined ? 22 : Number(m[2]) };
  }
  const m = SCP_HOST_RE.exec(url);
  return m === null ? null : { host: (m[1] as string).toLowerCase(), port: 22 };
}

/** `host/path` identity of a remote, for "is this the same repository" comparisons (case of the host, `.git` suffix,
 *  scp vs ssh spelling and the user name do not matter). `null` when it is not a recognisable ssh / scp URL. */
export function remoteIdentity(url: string): string | null {
  const ssh = /^ssh:\/\/(?:[^@/]+@)?([^:/]+)(?::(\d+))?\/(.+)$/.exec(url);
  const scp = ssh === null ? /^(?:[^@/:]+@)?([^:/]+):(.+)$/.exec(url) : null;
  const host = ssh !== null ? ssh[1] : scp?.[1];
  const port = ssh?.[2] ?? '22';
  const path = ssh !== null ? ssh[3] : scp?.[2];
  if (host === undefined || path === undefined) return null;
  return `${host.toLowerCase()}:${port}/${path.replace(/^\/+/, '').replace(/\.git$/, '').replace(/\/+$/, '')}`;
}

/** The pinned host key fingerprint for `host:port` in `<syncDir>/known_hosts`, or `null` (no pin / unreadable). */
export async function pinnedFingerprint(syncDir: string, host: string, port: number): Promise<string | null> {
  let token: string;
  try {
    token = hostToken(host, port);
  } catch {
    return null;
  }
  const file = nodePath.join(syncDir, 'known_hosts');
  const st = await lstat(file).catch(() => null);
  if (st === null || !st.isFile() || st.size > KNOWN_HOSTS_MAX_BYTES) return null;
  const fh = await open(file, 'r').catch(() => null);
  if (fh === null) return null;
  try {
    const text = await fh.readFile('utf8');
    for (const l of text.split('\n')) {
      const first = l.split(' ')[0]?.toLowerCase();
      if (first === token) return fingerprintOf(l);
    }
    return null;
  } finally {
    await fh.close().catch(() => undefined);
  }
}

/* ---------------- probes ---------------- */

type NetKind = 'ok' | 'hostkey' | 'network' | 'denied' | 'timeout' | 'other';

const NETWORK_RE = /connection (?:refused|timed out|reset|closed)|could not resolve|no route to host|network is unreachable|name or service not known|temporary failure in name resolution|operation timed out|kex_exchange_identification|connect to host/;
const DENIED_RE = /permission denied|authentication failed|access denied|repository not found|denied to deploy key/;

/** Stricter than `classifyNetError`: `denied` only on an explicit refusal of a server that answered. */
export function classifyProbe(r: GitxResult): NetKind {
  if (r.ok) return 'ok';
  if (r.timedOut) return 'timeout';
  if (r.capped) return 'other';
  if (classifyNetError(r) === 'hostkey') return 'hostkey';
  const t = `${r.stderr}\n${r.stdout.toString('utf8')}`.toLowerCase();
  if (NETWORK_RE.test(t)) return 'network';
  if (DENIED_RE.test(t)) return 'denied';
  return 'other';
}

export type AnonymousProbe = 'denied' | 'public' | 'inconclusive' | 'not-applicable';
export type RemoteState = 'empty' | 'has-main' | 'denied' | 'hostkey' | 'unreachable';

export interface ProbeDeps {
  gitx: Gitx;
  cwd: string;
  url: string;
  kind: RemoteKind;
  timeoutMs?: number;
  /** TEST seams (never from argv / env): replace the two network calls. */
  anonymous?: () => Promise<GitxResult>;
  authenticated?: () => Promise<GitxResult>;
}

export interface ProbeResult {
  anonymous: AnonymousProbe;
  remote: RemoteState;
  /** `refs/heads/main` of the remote when `remote === 'has-main'`. */
  tip: string | null;
}

const MAIN_LINE_RE = /^([0-9a-f]{40}|[0-9a-f]{64})\trefs\/heads\/main$/;

/** Credential-less probe first, then the authenticated one. Never throws for a network outcome (a spawn / binary
 *  failure of `Gitx` itself does propagate: that is local). */
export async function probeRemote(d: ProbeDeps): Promise<ProbeResult> {
  const timeoutMs = d.timeoutMs ?? 30_000;
  let anonymous: AnonymousProbe = 'not-applicable';
  if (d.kind !== 'local' || d.anonymous !== undefined) {
    const r = await (d.anonymous ?? ((): Promise<GitxResult> => d.gitx.lsRemoteAnonymous(d.cwd, d.url, { timeoutMs })))();
    const c = classifyProbe(r);
    anonymous = c === 'ok' ? 'public' : c === 'denied' ? 'denied' : 'inconclusive';
  }
  const a = await (d.authenticated ?? ((): Promise<GitxResult> => d.gitx.lsRemote(d.cwd, d.url, { timeoutMs })))();
  const c = classifyProbe(a);
  if (c === 'hostkey') return { anonymous, remote: 'hostkey', tip: null };
  if (c === 'denied') return { anonymous, remote: 'denied', tip: null };
  if (c !== 'ok') return { anonymous, remote: 'unreachable', tip: null };
  if (a.stdout.length > 4096) return { anonymous, remote: 'unreachable', tip: null };
  const lines = a.stdout.toString('utf8').split('\n').filter((l) => l !== '');
  if (lines.length === 0) return { anonymous, remote: 'empty', tip: null };
  const m = lines.length === 1 ? MAIN_LINE_RE.exec(lines[0] as string) : null;
  if (m === null) return { anonymous, remote: 'unreachable', tip: null };
  return { anonymous, remote: 'has-main', tip: m[1] as string };
}

/* ---------------- doctor checks ---------------- */

export interface RemoteCheckDeps {
  ledgerDir: string;
  /** Required for the network checks (`online`). */
  gitx?: Gitx;
  /** Remote URL (`.hub/sync.yml`); `null` = read it from the ledger. */
  url?: string | null;
  /** Network checks only with `--online`. */
  online: boolean;
  /** `remote.origin.url` of the CODE repository, when the caller knows it (`null` = unknown). */
  codeRepoRemote?: string | null;
  testLocalRemotes?: readonly string[];
  now?: () => number;
  /** TEST seam: replace the network probes. */
  probe?: Pick<ProbeDeps, 'anonymous' | 'authenticated'>;
  pidAlive?: (pid: number) => boolean;
}

function defaultPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

const check = (id: string, status: DeviceCheck['status'], detail: string): DeviceCheck => ({ id, status, detail: safeOutput(detail, 300) });

/** Doctor rows for an enrolled (or half-enrolled) ledger. Details carry the sanitised host token, never the URL,
 *  a key or git output. Each check is independent: one failing read never hides the others. */
export async function remoteChecks(d: RemoteCheckDeps): Promise<DeviceCheck[]> {
  const out: DeviceCheck[] = [];
  const syncDir = nodePath.join(d.ledgerDir, SYNC_DIR);
  let url = d.url ?? null;
  if (url === null) {
    try {
      url = (await readSyncConfig(d.ledgerDir))?.remote ?? null;
    } catch {
      out.push(check('sync_remote_scheme', 'fail', 'sync.yml is unreadable'));
    }
  }
  let kind: RemoteKind | null = null;
  let hp: { host: string; port: number } | null = null;
  if (url === null) {
    if (!out.some((c) => c.id === 'sync_remote_scheme')) out.push(check('sync_remote_scheme', 'info', 'not enrolled (no remote configured)'));
  } else {
    try {
      const v = validateRemoteUrl(url, d.testLocalRemotes ?? []);
      kind = v.kind;
      hp = remoteHostPort(v.url, v.kind);
      out.push(check('sync_remote_scheme', 'ok', `${v.kind} remote${hp === null ? '' : ` (${hostToken(hp.host, hp.port)})`}`));
    } catch {
      out.push(check('sync_remote_scheme', 'fail', 'the configured remote is not an acceptable ssh / scp URL'));
    }
  }

  // host key pin
  if (kind === null || kind === 'local') {
    out.push(check('sync_hostkey_pinned', 'info', kind === 'local' ? 'local remote: no host key' : 'no remote to pin a host key for'));
  } else if (hp === null) {
    out.push(check('sync_hostkey_pinned', 'warn', 'this host form is not supported for pinning'));
  } else {
    const fp = await pinnedFingerprint(syncDir, hp.host, hp.port);
    out.push(fp === null ? check('sync_hostkey_pinned', 'fail', `no pinned host key for ${hostToken(hp.host, hp.port)}: run ledger sync init|join again`) : check('sync_hostkey_pinned', 'ok', `pinned ${fp}`));
  }

  // distinct from the code repository
  const mine = url === null ? null : remoteIdentity(url);
  const code = d.codeRepoRemote === undefined || d.codeRepoRemote === null ? null : remoteIdentity(d.codeRepoRemote);
  if (mine === null || code === null) out.push(check('sync_remote_distinct', 'info', 'not compared (the code repository remote is not known)'));
  else out.push(mine === code ? check('sync_remote_distinct', 'fail', 'the ledger remote is the SAME repository as the code repository') : check('sync_remote_distinct', 'ok', 'differs from the code repository remote'));

  // network checks
  if (!d.online || url === null || kind === null || d.gitx === undefined) {
    const why = !d.online ? 'skipped (run with --online)' : 'skipped (no remote)';
    out.push(check('sync_remote_anonymous', 'info', why), check('sync_remote_reachable', 'info', why));
  } else {
    try {
      const p = await probeRemote({ gitx: d.gitx, cwd: d.ledgerDir, url, kind, ...(d.probe ?? {}) });
      out.push(
        p.anonymous === 'public'
          ? check('sync_remote_anonymous', 'fail', 'the remote answers WITHOUT credentials: the ledger would be readable by anyone')
          : p.anonymous === 'denied'
            ? check('sync_remote_anonymous', 'ok', 'anonymous access is refused')
            : p.anonymous === 'not-applicable'
              ? check('sync_remote_anonymous', 'info', 'local remote: nothing to test')
              : check('sync_remote_anonymous', 'warn', 'inconclusive (could not tell whether the remote is public)'),
      );
      out.push(
        p.remote === 'has-main' || p.remote === 'empty'
          ? check('sync_remote_reachable', 'ok', p.remote === 'empty' ? 'reachable, no ledger pushed yet' : 'reachable')
          : check('sync_remote_reachable', 'fail', p.remote === 'hostkey' ? 'host key verification failed' : p.remote === 'denied' ? 'access denied or repository not found' : 'not reachable'),
      );
    } catch {
      out.push(check('sync_remote_anonymous', 'warn', 'probe could not run'), check('sync_remote_reachable', 'warn', 'probe could not run'));
    }
  }

  // .git/config policy
  try {
    const fh = await open(nodePath.join(d.ledgerDir, '.git', 'config'), 'r');
    let text: string;
    try {
      const st = await fh.stat();
      if (st.size > 256 * 1024) throw new Error('large');
      text = await fh.readFile('utf8');
    } finally {
      await fh.close().catch(() => undefined);
    }
    const problems = checkGitConfig(text, { testLocalRemotes: d.testLocalRemotes ?? [] });
    if (problems.length > 0) {
      const names = problems.slice(0, 4).map((p) => `${p.code}${p.name === '' ? '' : ` ${p.name}`}`).join(', ');
      const hint = problems.some((p) => p.name === 'remote.origin.url') ? '; remove the legacy remote: git remote remove origin' : '';
      out.push(check('sync_git_config', 'fail', `.git/config refused by the sync policy (${names})${hint}`));
    } else {
      const origin = parseGitConfig(text).entries.find((e) => e.section === 'remote' && e.subsection === 'origin' && e.key === 'url');
      let tolerated = false;
      if (origin?.value !== null && origin?.value !== undefined) {
        try {
          validateRemoteUrl(origin.value, d.testLocalRemotes ?? []);
        } catch {
          tolerated = true; // a clean absolute path (D3): inert, but not a remote
        }
      }
      out.push(tolerated ? check('sync_git_config', 'warn', 'a legacy local-path `origin` remote is present (tolerated; remove it with: git remote remove origin)') : check('sync_git_config', 'ok', '.git/config passes the sync policy'));
    }
  } catch {
    out.push(check('sync_git_config', 'fail', '.git/config is unreadable'));
  }

  // enrol marker
  try {
    const m = await readEnrolMarker(d.ledgerDir);
    if (m === null) out.push(check('sync_enrol_marker', 'ok', 'no enrolment in progress'));
    else {
      const now = (d.now ?? Date.now)();
      const alive = (d.pidAlive ?? defaultPidAlive)(m.pid);
      const stale = Math.abs(now - Date.parse(m.startedAt)) > ENROL_STALE_MS || !alive;
      out.push(
        stale
          ? check('sync_enrol_marker', 'fail', `a ${m.kind} enrolment (stage ${m.stage}) was interrupted: re-run ledger sync ${m.kind} to resume, or --abort; the hub will not start until then`)
          : check('sync_enrol_marker', 'warn', `a ${m.kind} enrolment is in progress (stage ${m.stage}); the hub will not start until it finishes`),
      );
    }
  } catch {
    out.push(check('sync_enrol_marker', 'fail', 'the enrolment marker is unreadable or invalid (ledger sync init|join --abort removes it)'));
  }

  // registry vs local trust
  try {
    const rows = await listDevices(d.ledgerDir);
    const active = rows.filter((r) => r.status === 'active');
    const unapproved = active.filter((r) => !r.trusted);
    out.push(
      unapproved.length > 0
        ? check('sync_devices_unapproved', 'warn', `${String(unapproved.length)} registered device(s) are NOT approved on this machine: ledger device approve <id> --fp <SHA256:…>`)
        : check('sync_devices_unapproved', 'ok', 'every active device is approved here'),
    );
    out.push(
      url !== null && active.filter((r) => r.trusted).length === 1
        ? check('sync_single_trusted_device', 'warn', 'only one trusted device: losing it loses the ledger signing authority')
        : check('sync_single_trusted_device', 'ok', 'more than one trusted device, or not enrolled'),
    );
  } catch {
    out.push(check('sync_devices_unapproved', 'warn', 'device registry unreadable'), check('sync_single_trusted_device', 'info', 'not checked'));
  }
  return out;
}
