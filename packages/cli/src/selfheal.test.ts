/** `triggerSelfHeal` is allowed to spawn `launchctl`, so every guard
 *  around it (platform, kill switch, rate limit, plist ownership) is a test.
 *  The spawn itself is injected: a test must never touch the real launchd. */

import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  SELFHEAL_MIN_INTERVAL_MS,
  lastSelfHealAt,
  selfHealMarker,
  triggerSelfHeal,
  validatePlist,
  type SelfHealDeps,
} from './selfheal.ts';

const UID = 501;

interface Harness {
  calls: string[][];
  deps: Partial<SelfHealDeps>;
  setNow: (ms: number) => void;
  /** `launchctl print` exit code for `mode: 'checked'`. */
  setLoaded: (loaded: boolean) => void;
}

function harness(home: string, overrides: Partial<SelfHealDeps> = {}): Harness {
  const calls: string[][] = [];
  let now = 1_000_000;
  let loaded = true;
  return {
    calls,
    setNow: (ms) => {
      now = ms;
    },
    setLoaded: (v) => {
      loaded = v;
    },
    deps: {
      now: () => now,
      platform: 'darwin',
      getuid: () => UID,
      homedir: () => home,
      spawnDetached: (cmd, args) => {
        calls.push([cmd, ...args]);
        return { unref: () => undefined };
      },
      capture: async () => ({ code: loaded ? 0 : 1, stdout: '' }),
      statOf: async () => ({ isFile: true, isSymlink: false, uid: UID, mode: 0o644 }),
      ...overrides,
    },
  };
}

async function tmp(t: { after: (fn: () => unknown) => void }): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-selfheal-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('rate limit: two attempts within 30 s → one spawn, a second after 30 s', async (t) => {
  const dir = await tmp(t);
  const h = harness(dir);
  const first = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: h.deps });
  assert.equal(first.attempted, true);
  const spawnsAfterFirst = h.calls.length;
  assert.ok(spawnsAfterFirst > 0);

  // Marker is written before the spawn and is private to the user.
  const marker = selfHealMarker(dir);
  const st = await lstat(marker);
  assert.equal(st.mode & 0o777, 0o600);
  assert.equal(await lastSelfHealAt(dir), 1_000_000);

  h.setNow(1_000_000 + SELFHEAL_MIN_INTERVAL_MS - 1);
  const second = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: h.deps });
  assert.equal(second.attempted, false);
  assert.equal(second.reason, 'rate-limited');
  assert.equal(h.calls.length, spawnsAfterFirst, 'rate limit must not spawn');

  h.setNow(1_000_000 + SELFHEAL_MIN_INTERVAL_MS + 1);
  const third = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: h.deps });
  assert.equal(third.attempted, true);
  assert.ok(h.calls.length > spawnsAfterFirst);
});

test('never `kickstart -k` — a running hub must not be shot', async (t) => {
  const dir = await tmp(t);
  const h = harness(dir);
  await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: h.deps });
  for (const call of h.calls) {
    assert.equal(
      call.includes('-k'),
      false,
      `-k in argv: ${call.join(' ')}`,
    );
    assert.equal(call[0], '/bin/launchctl');
  }
  assert.ok(h.calls.some((c) => c[1] === 'kickstart'));
});

test('disabled: LEDGER_SELFHEAL=0 and non-darwin → no spawn', async (t) => {
  const dir = await tmp(t);
  const off = harness(dir);
  const a = await triggerSelfHeal({ ledgerDir: dir, env: { LEDGER_SELFHEAL: '0' }, deps: off.deps });
  assert.deepEqual([a.attempted, a.reason], [false, 'disabled']);
  assert.equal(off.calls.length, 0);
  assert.equal(await lastSelfHealAt(dir), null, 'a disabled self-heal must not write the marker');

  const linux = harness(dir, { platform: 'linux' });
  const b = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: linux.deps });
  assert.deepEqual([b.attempted, b.reason], [false, 'not-darwin']);
  assert.equal(linux.calls.length, 0);
});

test('a marker dated in the future must not bypass the rate limit', async (t) => {
  const dir = await tmp(t);
  const h = harness(dir);
  h.setNow(1_000_000);
  await mkdir(join(dir, '.hub'), { recursive: true });
  // Small clock skew: marker claims "last heal" 5 s in the future — well
  // inside the 30 s window, so this must still count as recently healed.
  await writeFile(selfHealMarker(dir), `${1_000_000 + 5_000}\n`, { mode: 0o600 });

  const res = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: h.deps });
  assert.deepEqual([res.attempted, res.reason], [false, 'rate-limited']);
  assert.equal(h.calls.length, 0, 'a future marker must not trigger launchctl');
});

test('a writable ancestor between $HOME and the plist (not just the direct parent) is detected', async (t) => {
  const dir = await tmp(t);
  const home = join(dir, 'home');
  const library = join(home, 'Library');
  const launchAgents = join(library, 'LaunchAgents');
  await mkdir(launchAgents, { recursive: true });
  const uid = process.getuid?.() ?? 0;
  const plist = join(launchAgents, 'x.plist');
  await writeFile(plist, '<plist/>', { mode: 0o644 });
  // group/other-writable two levels up from the plist — an older check only
  // looked at `dirname(path)` (LaunchAgents, which stays 0755) and the file
  // itself, so this ancestor slipped past it.
  await chmod(library, 0o775);

  assert.match(
    (await validatePlist(plist, uid, { homedir: () => home })) ?? '',
    /group\/other/,
    'a writable Library between $HOME and the plist must be detected',
  );
});

test('plist: a symlink or group-writable file is not bootstrapped', async (t) => {
  const dir = await tmp(t);
  for (const bad of [
    { isFile: true, isSymlink: true, uid: UID, mode: 0o644 },
    { isFile: true, isSymlink: false, uid: UID, mode: 0o664 },
    { isFile: true, isSymlink: false, uid: UID + 1, mode: 0o644 },
    { isFile: false, isSymlink: false, uid: UID, mode: 0o644 },
  ]) {
    await rm(selfHealMarker(dir), { force: true });
    const h = harness(dir, { statOf: async () => bad });
    const res = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: h.deps });
    assert.equal(res.reason, 'plist-rejected', JSON.stringify(bad));
    assert.equal(
      h.calls.some((c) => c[1] === 'bootstrap'),
      false,
      `bootstrap from an untrusted plist: ${JSON.stringify(bad)}`,
    );
  }
});

test('validatePlist: a real file on disk', async (t) => {
  const dir = await tmp(t);
  const uid = process.getuid?.() ?? 0;
  const file = join(dir, 'ok.plist');
  await writeFile(file, '<plist/>', { mode: 0o644 });
  // The chain walks down from `$HOME` — `dir` stands in for it here, so the
  // chain is just two entries (`dir`, `file`).
  const homeDeps = { homedir: () => dir };
  assert.equal(await validatePlist(file, uid, homeDeps), null);
  // `writeFile` does not change the mode of an existing file — chmod does.
  await chmod(file, 0o666);
  assert.match((await validatePlist(file, uid, homeDeps)) ?? '', /group\/other/);
  assert.match(
    (await validatePlist(join(dir, 'nope.plist'), uid, homeDeps)) ?? '',
    /cannot be read/,
  );
});

test('checked mode: loaded job → kickstart only; not loaded → bootstrap', async (t) => {
  const dir = await tmp(t);
  const h = harness(dir);
  h.setLoaded(true);
  const loaded = await triggerSelfHeal({ ledgerDir: dir, env: {}, mode: 'checked', deps: h.deps });
  assert.equal(loaded.reason, 'kickstart');
  assert.deepEqual(h.calls.map((c) => c[1]), ['kickstart']);

  await rm(selfHealMarker(dir), { force: true });
  h.calls.length = 0;
  h.setLoaded(false);
  const cold = await triggerSelfHeal({ ledgerDir: dir, env: {}, mode: 'checked', deps: h.deps });
  assert.equal(cold.reason, 'bootstrap');
  assert.deepEqual(h.calls.map((c) => c[1]), ['bootstrap']);
  assert.equal(h.calls[0]?.[2], `gui/${UID}`);
  assert.match(h.calls[0]?.[3] ?? '', /Library\/LaunchAgents\/io\.agent-ledger\.hub\.plist$/);
});

test('checked mode: a job on another port/ledger is not kicked', async (t) => {
  const dir = await tmp(t);
  const h = harness(dir, {
    capture: async () => ({
      code: 0,
      stdout: 'state = running\n\tenvironment = {\n\t\tLEDGER_HUB_PORT => 4747\n\t}\n',
    }),
  });
  const res = await triggerSelfHeal({
    ledgerDir: dir,
    port: '19999',
    env: {},
    mode: 'checked',
    deps: h.deps,
  });
  assert.deepEqual([res.attempted, res.reason], [false, 'other-instance']);
  assert.equal(h.calls.length, 0);
});

test('the marker is written before the spawn (a failed spawn does not open a loop)', async (t) => {
  const dir = await tmp(t);
  const h = harness(dir, {
    spawnDetached: () => {
      throw new Error('spawn failed');
    },
  });
  const res = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: h.deps });
  assert.equal(res.attempted, true);
  assert.equal((await readFile(selfHealMarker(dir), 'utf8')).trim(), '1000000');
});

test('a marker that is a symlink is not followed — fail-open, nothing is written through it', async (t) => {
  const dir = await tmp(t);
  const hubDir = join(dir, '.hub');
  await mkdir(hubDir, { recursive: true, mode: 0o700 });
  const evilTarget = join(dir, 'evil-target');
  const marker = selfHealMarker(dir);
  await symlink(evilTarget, marker);

  // Real (unmocked) deps on purpose — this exercises the actual
  // `open(..., O_NOFOLLOW)` production code path, not a test double. Only the
  // platform is pinned: self-heal is darwin-only and returns 'not-darwin'
  // before it ever reaches the marker on a Linux runner.
  const res = await triggerSelfHeal({ ledgerDir: dir, env: {}, deps: { platform: 'darwin' } });
  assert.deepEqual([res.attempted, res.reason], [false, 'error']);
  await assert.rejects(stat(evilTarget), 'the symlink target must not be created/written');
  const st = await lstat(marker);
  assert.equal(st.isSymbolicLink(), true, 'the symlink in place of the marker must stay untouched');
});
