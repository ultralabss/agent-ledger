/** B5: hub identity in `/v1/healthz` and the weak-filesystem bypass made visible. */
import assert from 'node:assert/strict';
import { join } from 'node:path';
import test from 'node:test';
import { hubIdentity, type FsCaps } from '@agent-ledger/shared';
import { WeakFsMonitor } from './fsweak.ts';
import { startHub } from './server.ts';
import { startTestHub, tempConfig } from './test-helpers.ts';

const weakCaps = (bypassed: boolean): FsCaps => ({
  posixModes: false,
  ownerMatches: false,
  hardlinks: false,
  acl: false,
  fsType: 'vfat',
  caseInsensitive: true,
  weak: true,
  bypassed,
  reasons: ['mode bits do not stick'],
});

test('WeakFsMonitor: one WARNING line per path, none when not bypassed, list follows the probe', async () => {
  const lines: string[] = [];
  let bypassed = true;
  const mon = new WeakFsMonitor(
    () => [
      { probeDir: '/x/.hub', label: '/x' },
      { probeDir: '/spool', label: '/spool' },
    ],
    (l) => lines.push(l),
    async (dir) => {
      if (dir === '/spool') throw new Error('ENOENT'); // not a weak-FS symptom: skipped
      return weakCaps(bypassed);
    },
  );
  await mon.refresh();
  await mon.refresh();
  assert.deepEqual(mon.paths(), ['/x']);
  assert.equal(lines.length, 1, 'logged once per path, not per refresh');
  assert.match(lines[0] ?? '', /^WARNING: weak filesystem \/x \(vfat: mode bits do not stick\) — LEDGER_ALLOW_WEAK_FS=1/);
  bypassed = false;
  await mon.refresh();
  assert.deepEqual(mon.paths(), [], 'bypass off => nothing reported');
});

test('healthz: identity is public, fs_weak and the path only for an authenticated caller', async (t) => {
  const fx = await startTestHub();
  t.after(fx.cleanup);
  const anon = (await (await fetch(`${fx.url}/v1/healthz`)).json()) as Record<string, unknown>;
  assert.deepEqual(anon, { ok: anon.ok, ...hubIdentity(fx.dir) });
  const authed = (await fx.api('GET', '/v1/healthz')).json as Record<string, unknown>;
  assert.deepEqual(authed.fs_weak, [], 'empty unless the bypass is active');
  assert.equal(authed.platform, anon.platform);
  assert.equal(authed.ledger_id, anon.ledger_id);
  assert.equal(typeof authed.ledger_real, 'string');
});

test('LEDGER_ALLOW_WEAK_FS bypass: WARNING in hub.log, fs_weak in authed healthz only', async (t) => {
  const tmp = await tempConfig();
  const logs: string[] = [];
  const hub = await startHub({
    config: tmp.config,
    log: (l) => logs.push(l),
    watch: false,
    periodic: false,
    fsProbe: async (dir) => {
      if (dir === join(tmp.dir, '.hub')) return weakCaps(true);
      throw new Error('ENOENT'); // spool dir absent
    },
  });
  t.after(async () => {
    await hub.close();
    await tmp.cleanup();
  });
  const warnings = logs.filter((l) => l.startsWith('WARNING: weak filesystem'));
  assert.equal(warnings.length, 1, logs.join('\n'));
  assert.ok(warnings[0]?.includes(tmp.dir));
  const authed = (await (await fetch(`${hub.url}/v1/healthz`, { headers: { 'x-hub-token': hub.token } })).json()) as {
    fs_weak: string[];
  };
  assert.deepEqual(authed.fs_weak, [tmp.dir]);
  const anon = (await (await fetch(`${hub.url}/v1/healthz`)).json()) as Record<string, unknown>;
  assert.ok(!('fs_weak' in anon));
});
