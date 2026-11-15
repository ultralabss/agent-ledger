// CI diagnostics (windows, UL-700): wall-clock of each primitive the hub tests depend on.
// Run as the non-elevated test user: node scripts/ci-win-diag.ts
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ensurePrivateDir, assertPrivateDir, createTrustDeps, invalidateFsProbeCache } from '../packages/shared/src/index.ts';

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
const sysRoot = process.env.SystemRoot ?? 'C:\\Windows';
const psExe = `${sysRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const baseArgs = ['-NoProfile', '-NonInteractive', '-NoLogo', '-InputFormat', 'None', '-ExecutionPolicy', 'Bypass'];
await withTimeout('powershell -Command 1 (full env)', 90000, run(psExe, [...baseArgs, '-Command', '1']));
await withTimeout('powershell Get-Acl (full env)', 90000, run(psExe, [...baseArgs, '-Command', '(Get-Acl -LiteralPath $env:SystemRoot).Sddl.Length']));
const mini = { SystemRoot: sysRoot, windir: sysRoot, PATH: `${sysRoot}\\System32`, PSModulePath: `${sysRoot}\\System32\\WindowsPowerShell\\v1.0\\Modules` };
const runEnv = (args: string[], env: Record<string, string>) =>
  new Promise<string>((resolve) => {
    const c = spawn(psExe, args, { env, cwd: sysRoot, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let o = '';
    c.stdout.on('data', (d) => (o += d));
    c.stderr.on('data', (d) => (o += d));
    c.on('close', (code) => resolve(`code=${code} ${o.trim().slice(0, 120)}`));
    c.on('error', (e) => resolve(`error ${e.message}`));
  });
await withTimeout('powershell -Command 1 (minimal env, no USERPROFILE/TEMP)', 90000, runEnv([...baseArgs, '-Command', '1'], mini));
await withTimeout('powershell Get-Acl (minimal env)', 90000, runEnv([...baseArgs, '-Command', '(Get-Acl -LiteralPath $env:SystemRoot).Sddl.Length'], mini));
const timedDeps = createTrustDeps({
  spawnFile: async (file, args, opts) => {
    const s = Date.now();
    const { defaultSpawnFile } = await import('../packages/shared/src/win-ps.ts');
    const r = await defaultSpawnFile(file, args, opts);
    lap(`  spawnFile ${file.split('\\').pop()} ${args.length} args: ${Date.now() - s}ms code=${r.code} timedOut=${r.timedOut} err=${r.error ?? ''} stderr=${r.stderr.trim().slice(0, 80)}`);
    return r;
  },
});
invalidateFsProbeCache();
const d0 = join(tmpdir(), `diag-priv0-${Date.now()}`);
await withTimeout('ensurePrivateDir (instrumented)', 120000, ensurePrivateDir(d0, timedDeps));
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
