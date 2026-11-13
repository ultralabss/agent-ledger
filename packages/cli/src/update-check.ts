// `ledger update check`: read-only update notice. No self-update in 0.1.
// Network access only when LEDGER_UPDATE_CHECK=1 (default off). The release text comes
// from the network and is untrusted data: it is shown, never executed or interpreted.

export const RELEASES_URL = 'https://api.github.com/repos/ultralabss/agent-ledger/releases/latest';
const TAG_RE = /^v(\d+)\.(\d+)\.(\d+)$/;
const MAX_BODY = 4000;
const MAX_BYTES = 256 * 1024;

export interface UpdateResult {
  status: 'disabled' | 'up-to-date' | 'update-available' | 'error';
  current: string;
  latest?: string;
  changelog?: string;
  message?: string;
}

export function parseVersion(v: string): [number, number, number] | null {
  const m = TAG_RE.exec(v.startsWith('v') ? v : `v${v}`);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function isNewer(latest: string, current: string): boolean {
  const a = parseVersion(latest);
  const b = parseVersion(current);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i]! > b[i]!;
  }
  return false;
}

/** Strip control characters (ANSI escapes included) and cap length. */
export function sanitizeText(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s
    .slice(0, MAX_BODY * 2)
    .replace(/\r/g, '')
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFE00-\uFE0F\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu, '')
    .slice(0, MAX_BODY);
}

export function manualSteps(tag: string): string[] {
  return [`git fetch --tags && git verify-tag ${tag} && git checkout ${tag} && ./install.sh`];
}

export interface CheckOptions {
  currentVersion: string;
  env?: Record<string, string | undefined>;
  fetchImpl?: (url: string, init: { signal: AbortSignal; headers: Record<string, string> }) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;
}

export async function checkForUpdate(opts: CheckOptions): Promise<UpdateResult> {
  const env = opts.env ?? process.env;
  const current = opts.currentVersion;
  if (env.LEDGER_UPDATE_CHECK !== '1') {
    return { status: 'disabled', current, message: 'Update check is off. Set LEDGER_UPDATE_CHECK=1 to query GitHub Releases.' };
  }
  const doFetch = opts.fetchImpl ?? ((url, init) => fetch(url, init));
  try {
    const res = await doFetch(RELEASES_URL, {
      signal: AbortSignal.timeout(5000),
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'agent-ledger-update-check' },
    });
    if (!res.ok) return { status: 'error', current, message: `GitHub returned HTTP ${res.status}` };
    const raw = await res.text();
    if (raw.length > MAX_BYTES) return { status: 'error', current, message: 'response too large' };
    const data = JSON.parse(raw) as { tag_name?: unknown; body?: unknown };
    const tag = typeof data.tag_name === 'string' ? data.tag_name : '';
    if (!TAG_RE.test(tag)) return { status: 'error', current, message: 'unexpected release tag' };
    if (!isNewer(tag, current)) return { status: 'up-to-date', current, latest: tag };
    const changelog = typeof data.body === 'string' ? sanitizeText(data.body) : '';
    return { status: 'update-available', current, latest: tag, changelog };
  } catch (e) {
    return { status: 'error', current, message: e instanceof Error ? e.message : 'request failed' };
  }
}

export function formatReport(r: UpdateResult): string {
  switch (r.status) {
    case 'disabled':
      return `${r.message}\n`;
    case 'up-to-date':
      return `agent-ledger ${r.current} is up to date (latest ${r.latest}).\n`;
    case 'error':
      return `update check failed: ${r.message}\n`;
    case 'update-available': {
      const tag = r.latest!;
      return [
        `agent-ledger ${tag} is available (you have ${r.current}).`,
        '',
        'Changelog (untrusted text from GitHub, shown as data):',
        r.changelog ? r.changelog.split('\n').map((l) => `  | ${l}`).join('\n') : '  (empty)',
        '',
        'Update manually, after reading the diff:',
        ...manualSteps(tag).map((s) => `  ${s}`),
        '',
        'The ledger never updates itself and never runs code from the release notes.',
        '',
      ].join('\n');
    }
  }
}
