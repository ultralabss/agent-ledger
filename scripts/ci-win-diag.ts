// CI diagnostics (windows, UL-700): wall-clock of each primitive the hub tests depend on.
// Run as the non-elevated test user: node scripts/ci-win-diag.ts
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensurePrivateDir, assertPrivateDir } from '../packages/shared/src/index.ts';

const t0 = Date.now();
const lap = (what: string) => console.log(`[diag +${Date.now() - t0}ms] ${what}`);
const withTimeout = async <T>(what: string, ms: number, p: Promise<T>): Promise<T | undefined> => {
  const s = Date.now();
  let timer: NodeJS.Timeout | undefined;
  const r = await Promise.race([p, new Promise<'T'>((res) => (timer = setTimeout(() => res('T'), ms)))]);
  clearTimeout(timer);
  lap(`${what}: ${r === 'T' ? `STALLED > ${ms}ms` : `${Date.now() - s}ms`}`);
  return r === 'T' ? undefined : (r as T);
};
const run = (cmd: string, args: string[], cwd?: string) =>
  new Promise<string>((resolve) => {
    const c = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let o = '';
    c.stdout.on('data', (d) => (o += d));
    c.stderr.on('data', (d) => (o += d));
    c.on('close', (code) => resolve(`code=${code} ${o.trim().slice(0, 120)}`));
    c.on('error', (e) => resolve(`error ${e.message}`));
  });

lap(`start; tmpdir=${tmpdir()}`);
const git = 'C:\\Program Files\\Git\\cmd\\git.exe';
lap(`git --version -> ${await withTimeout('git --version', 30000, run(git, ['--version']))}`);
const base = await mkdtemp(join(tmpdir(), 'diag-'));
await withTimeout('git init', 30000, run(git, ['init', '-q'], base));
await withTimeout('git config --list', 30000, run(git, ['config', '--list', '--show-origin'], base));
await withTimeout('git commit --allow-empty', 30000, run(git, ['-c', 'user.name=d', '-c', 'user.email=d@d', 'commit', '--allow-empty', '-qm', 'x'], base));
const d1 = join(tmpdir(), `diag-priv-${Date.now()}`);
await withTimeout('ensurePrivateDir #1 (cold probe)', 60000, ensurePrivateDir(d1));
await withTimeout('assertPrivateDir #1 (cached)', 60000, assertPrivateDir(d1));
const d2 = join(tmpdir(), `diag-priv2-${Date.now()}`);
await withTimeout('ensurePrivateDir #2 (new dir)', 60000, ensurePrivateDir(d2));
const { openTestLedger } = await import('../packages/hub/src/test-helpers.ts');
const fx = await withTimeout('openTestLedger', 90000, openTestLedger());
if (fx) await withTimeout('ledger.git.flush', 90000, fx.ledger.git.flush());
lap('done');
process.exit(0);
