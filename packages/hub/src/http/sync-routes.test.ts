/** `/v1/sync/*` (docs/f3b-b4-plan.md §1.4; T-B4-1, T-B4-2, T-B4-7, T-B4-12, T-B4-13): human gate, uniform `refused`
 *  answers + limiter, replay, no URL in any body or journal line, 1 KB body cap, SYNC_OFF. The app is the real
 *  `createApp` driven through `app.request` (no sockets); the loop is real, its cycle is stubbed except where the
 *  real add is exercised. POSIX only (real git + ssh-keygen in the fleet). */

import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { generateKeyPair, publicKeyOf, resolveSshKeygen } from '@agent-ledger/shared';
import { openTestLedger } from '../test-helpers.ts';
import { UI_COOKIE_NAME, newUiSecret, uiCookieValue } from '../security/index.ts';
import type { Sessions } from '../sessions.ts';
import { runCycle, type CycleDeps, type CycleResult } from '../sync/cycle.ts';
import { SyncLoop } from '../sync/loop.ts';
import { cycleDeps, fakeHost, makeFleet, makeKit, type LedgerHub } from '../sync/testkit-remote.ts';
import { createApp } from './app.ts';

const posix = process.platform !== 'win32';
const PORT = 4747;
const TOKEN = 'a'.repeat(48);
const guard = { token: TOKEN, uiSecret: newUiSecret(), port: PORT };
const stubCycle = async (): Promise<CycleResult> => ({ outcome: 'up-to-date', refetches: 0, ms: 1 });

const sessions = {
  get: (id: string) => (id === 'human1111' ? { liveness: 'live' } : null),
} as unknown as Sessions;

interface Rig {
  call(method: 'GET' | 'POST', path: string, body?: unknown, o?: { cookie?: boolean; session?: string | null; raw?: string; noAuth?: boolean }): Promise<{ status: number; json: any; text: string }>;
  loop: SyncLoop;
  lh: LedgerHub;
  peer: LedgerHub;
  base: string;
  remotePath: string;
  bodies: string[];
  journal(): Promise<string>;
}

async function withRig<T>(fn: (r: Rig) => Promise<T>, o: { cycle?: (d: CycleDeps) => Promise<CycleResult>; syncOff?: boolean; remote?: string; realDevice?: boolean } = {}): Promise<T> {
  const kit = await makeKit();
  const fx = await openTestLedger();
  let loop: SyncLoop | null = null;
  try {
    const fleet = await makeFleet(kit, 2);
    const lh = fleet.hubs[0] as LedgerHub;
    if (o.realDevice === true) {
      // the fleet hubs carry their key elsewhere: give hub 1 a real `.hub/device.yml` + `key.pub` (the real approval)
      await mkdir(nodePath.join(lh.dir, '.hub', 'device'), { recursive: true, mode: 0o700 });
      await writeFile(nodePath.join(lh.dir, '.hub', 'device.yml'), `device_id: ${lh.hub.deviceId}\nlabel: ${lh.hub.label}\nslot: ""\n`, { mode: 0o600 });
      await writeFile(nodePath.join(lh.dir, '.hub', 'device', 'key.pub'), `${lh.hub.pub.line}\n`, { mode: 0o600 });
    }
    const deps = cycleDeps(lh, kit, { host: fakeHost(lh), ...(o.remote === undefined ? {} : { remote: o.remote }) });
    loop = new SyncLoop({ deps, intervalMs: 3_600_000, cycle: o.cycle ?? stubCycle });
    const active = loop;
    const app = createApp({ ledger: fx.ledger, guard, sessions, sync: () => (o.syncOff === true ? null : active) });
    const bodies: string[] = [];
    const call: Rig['call'] = async (method, path, body, opt = {}) => {
      const headers: Record<string, string> = { host: `127.0.0.1:${String(PORT)}` };
      if (opt.noAuth !== true) {
        if (opt.cookie === true) {
          headers.cookie = `${UI_COOKIE_NAME}=${uiCookieValue(guard) as string}`;
          headers.origin = `http://127.0.0.1:${String(PORT)}`;
          headers['sec-fetch-site'] = 'same-origin';
        } else headers['x-hub-token'] = TOKEN;
      }
      let text: string | undefined;
      if (method === 'POST') {
        headers['content-type'] = 'application/json';
        const payload = opt.raw ?? JSON.stringify({ ...(body as object), ...(opt.session === null || opt.cookie === true ? {} : { session: opt.session ?? 'human1111' }) });
        text = payload;
      }
      const res = await app.request(path, { method, headers, ...(text === undefined ? {} : { body: text }) });
      const t = await res.text();
      bodies.push(t);
      let json: unknown = null;
      try {
        json = JSON.parse(t);
      } catch {
        json = null;
      }
      return { status: res.status, json, text: t };
    };
    return await fn({
      call,
      loop,
      lh,
      peer: fleet.hubs[1] as LedgerHub,
      base: fleet.base,
      remotePath: kit.remote.path,
      bodies,
      // the sync events go to the hub-level journal `agent-ledger` (not a registered repo): read the file
      journal: async () => {
        const month = new Date().toISOString().slice(0, 7);
        const text = await readFile(fx.ledger.paths.journalFile('agent-ledger', month), 'utf8').catch(() => '');
        return text.replace(/ · /g, ' ');
      },
    });
  } finally {
    await loop?.stop();
    await fx.cleanup();
    await kit.cleanup();
  }
}

const REFUSED = { answer: 'refused' };

test('SYNC_OFF: every route answers 409 when the hub has no sync loop (and auth still comes first)', async () => {
  await withRig(async (r) => {
    assert.equal((await r.call('GET', '/v1/sync/status')).status, 409);
    assert.equal((await r.call('POST', '/v1/sync/trigger', {})).status, 409);
    const res = await r.call('POST', '/v1/sync/resume', {});
    assert.equal(res.status, 409);
    assert.equal(res.json.error, 'SYNC_OFF');
    assert.equal((await r.call('GET', '/v1/sync/status', undefined, { noAuth: true })).status, 401, 'no token, no answer');
  }, { syncOff: true });
});

test('status: auth required, host token only, no URL, no remote path anywhere (T-B4-1, T-B4-13)', { skip: !posix }, async () => {
  await withRig(async (r) => {
    assert.equal((await r.call('GET', '/v1/sync/status', undefined, { noAuth: true })).status, 401);
    const res = await r.call('GET', '/v1/sync/status');
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.enabled, true);
    assert.equal(res.json.remote_host, 'local');
    assert.equal(res.json.locked, false);
    assert.equal(res.json.loop.halt, null);
    assert.equal(res.json.loop.accepted, r.base);
    assert.ok(!res.text.includes(r.remotePath), 'the remote URL / path is not part of status');
    assert.ok(!/ssh:\/\/|@.*:/.test(res.text.replace(/SHA256:[A-Za-z0-9+/]+/g, '')), 'no URL-like text');
  });
  for (const [url, host] of [
    ['git@example.com:me/ledger.git', 'example.com'],
    ['ssh://deploy@host.example:2222/srv/ledger.git', 'host.example'],
  ] as const) {
    await withRig(async (r) => {
      const res = await r.call('GET', '/v1/sync/status');
      assert.equal(res.json.remote_host, host);
      assert.ok(!res.text.includes('deploy') && !res.text.includes('/srv') && !res.text.includes('me/ledger') && !res.text.includes('git@'));
    }, { remote: url });
  }
});

test('trigger: one per 5 s', { skip: !posix }, async () => {
  await withRig(async (r) => {
    assert.equal((await r.call('POST', '/v1/sync/trigger', {}, { session: null })).status, 200);
    const second = await r.call('POST', '/v1/sync/trigger', {}, { session: null });
    assert.equal(second.status, 429);
    assert.equal(second.json.error, 'RATE_LIMITED');
  });
});

test('human gate (T-B4-12): worker / headless / unknown / missing session over a token is 403 on every human route; the UI cookie passes', { skip: !posix }, async () => {
  await withRig(async (r) => {
    const fp = 'SHA256:' + 'A'.repeat(43);
    const sha = 'c'.repeat(40);
    const routes: [string, unknown][] = [
      ['/v1/sync/resume', {}],
      ['/v1/sync/confirm-revocation', { id: 'd_aaaaaaaaaa', fp }],
      ['/v1/sync/accept', { sha }],
      ['/v1/sync/device-add', { pubkey: 'ssh-ed25519 AAAA', label: 'x', fp }],
    ];
    for (const [path, body] of routes) {
      for (const session of ['worker-abc', 'headless-sweep-1', 'ghost9999', null]) {
        const res = await r.call('POST', path, body, { session });
        assert.equal(res.status, 403, `${path} as ${String(session)}: ${res.text}`);
      }
    }
    // a human at the browser (cookie) needs no session
    assert.equal((await r.call('POST', '/v1/sync/resume', {}, { cookie: true })).status, 200);
    // a live non-worker session over the token passes
    assert.equal((await r.call('POST', '/v1/sync/resume', {}, { session: 'human1111' })).status, 200);
  });
});

test('uniform refusal + lockout: unknown id, wrong fingerprint, no halt and a locked limiter all answer the same bytes; resume unlocks (T-B4-1)', { skip: !posix }, async () => {
  await withRig(async (r) => {
    const root = r.lh;
    const base = r.base;
    // a revocation halt naming hub 2 at the base commit (its registered key is the one to match)
    const targetId = r.peer.hub.deviceId;
    const fp = r.peer.hub.pub.fingerprint;
    const setHalt = async (on: boolean): Promise<void> => {
      await root.state.update((s) => {
        s.halt = on ? { reason: 'quarantine:revocation-root', cls: 'd2', since: '2026-11-17T09:00:00.000Z', tip: base, rule: 'revocation-root', detail: 'x', d2: { commit: base, deviceIds: [targetId], kind: 'root' } } : null;
      });
    };
    await setHalt(true);
    const wrongFp = 'SHA256:' + 'B'.repeat(43);
    const bodies = new Set<string>();
    const statuses = new Set<number>();
    for (const b of [
      { id: 'd_zzzzzzzzzz', fp }, // unknown device
      { id: targetId, fp: wrongFp }, // fingerprint mismatch
      { id: 'd_aaaaaaaaaa', fp: wrongFp },
      { id: 'd_bbbbbbbbbb', fp },
    ]) {
      const res = await r.call('POST', '/v1/sync/confirm-revocation', b);
      statuses.add(res.status);
      bodies.add(res.text);
    }
    assert.deepEqual([...statuses], [200]);
    assert.deepEqual([...bodies], [JSON.stringify(REFUSED)], 'identical bytes for every failure');
    // no halt at all: the same answer again (5th failure -> locked)
    await setHalt(false);
    const none = await r.call('POST', '/v1/sync/confirm-revocation', { id: targetId, fp });
    assert.equal(none.text, JSON.stringify(REFUSED));
    // locked: even the CORRECT request is refused with the same bytes, and status says so
    await setHalt(true);
    const locked = await r.call('POST', '/v1/sync/confirm-revocation', { id: targetId, fp });
    assert.equal(locked.text, JSON.stringify(REFUSED));
    assert.equal((await r.call('GET', '/v1/sync/status')).json.locked, true);
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: base })).text, JSON.stringify(REFUSED), 'the limiter is shared');
    // resume unlocks; the correct request now passes and is journalled (tokens only)
    assert.equal((await r.call('POST', '/v1/sync/resume', {})).status, 200);
    assert.equal((await r.call('GET', '/v1/sync/status')).json.locked, false);
    const ok = await r.call('POST', '/v1/sync/confirm-revocation', { id: targetId, fp });
    assert.equal(ok.text, JSON.stringify({ answer: 'ok' }));
    assert.equal((await r.lh.state.read()).confirmations.length, 1);
    const journal = await r.journal();
    assert.match(journal, new RegExp(`sync.confirm device=${targetId} fp=${fp.replace(/[+/]/g, '\\$&')}`));
    // replay of the same request: idempotent, still ONE confirmation
    assert.equal((await r.call('POST', '/v1/sync/confirm-revocation', { id: targetId, fp })).text, JSON.stringify({ answer: 'ok' }));
    assert.equal((await r.lh.state.read()).confirmations.length, 1);
    // stale: the halt is gone, the same request is refused
    await setHalt(false);
    assert.equal((await r.call('POST', '/v1/sync/confirm-revocation', { id: targetId, fp })).text, JSON.stringify(REFUSED));
  });
});

test('accept: bound to the current halt tip; replay is idempotent; a stale or foreign tip is refused; journalled', { skip: !posix }, async () => {
  await withRig(async (r) => {
    const tip = 'd'.repeat(40);
    const other = 'e'.repeat(40);
    await r.lh.state.update((s) => {
      s.halt = { reason: 'quarantine:unsigned', cls: 'probe', since: '2026-11-17T09:00:00.000Z', tip, rule: 'unsigned', detail: 'x', d2: null };
    });
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: other })).text, JSON.stringify(REFUSED));
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: tip })).text, JSON.stringify({ answer: 'ok' }));
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: tip })).text, JSON.stringify({ answer: 'ok' }), 'replay');
    assert.equal((await r.lh.state.read()).overrides.filter((o) => o.tip === tip).length, 1, 'one override, not two');
    // the tip moved on: the old request is refused
    await r.lh.state.update((s) => {
      s.halt = { reason: 'quarantine:unsigned', cls: 'probe', since: '2026-11-17T09:00:00.000Z', tip: other, rule: 'unsigned', detail: 'x', d2: null };
    });
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: tip })).text, JSON.stringify(REFUSED));
    // a secret needs the explicit acknowledgement
    await r.lh.state.update((s) => {
      s.halt = { reason: 'quarantine:secret', cls: 'probe', since: '2026-11-17T09:00:00.000Z', tip: other, rule: 'secret', detail: 'x', d2: null };
    });
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: other })).text, JSON.stringify(REFUSED));
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: other, secret_ack: true })).text, JSON.stringify({ answer: 'ok' }));
    const journal = await r.journal();
    assert.match(journal, /sync\.accept tip=d{40} secret_ack=false/);
    assert.match(journal, /sync\.accept tip=e{40} secret_ack=true/);
  });
});

test('input: strict schema, 1 KB cap before the body is read, nothing echoed', { skip: !posix }, async () => {
  await withRig(async (r) => {
    const fp = 'SHA256:' + 'A'.repeat(43);
    const extra = await r.call('POST', '/v1/sync/confirm-revocation', { id: 'd_aaaaaaaaaa', fp, url: 'ssh://evil/x' });
    assert.equal(extra.status, 422);
    assert.ok(!extra.text.includes('evil'));
    assert.equal((await r.call('POST', '/v1/sync/confirm-revocation', { id: 'not-an-id', fp })).status, 422);
    assert.equal((await r.call('POST', '/v1/sync/accept', { sha: 'zz' })).status, 422);
    const big = await r.call('POST', '/v1/sync/accept', {}, { raw: JSON.stringify({ sha: 'a'.repeat(40), session: 'human1111', pad: 'x'.repeat(2000) }) });
    assert.equal(big.status, 413);
    // invalid shapes are NOT counted as failures: the routes stay unlocked
    assert.equal((await r.call('GET', '/v1/sync/status')).json.locked, false);
  });
});

let seq = 0;
async function joinerKey(root: string): Promise<{ line: string; fp: string }> {
  const bin = await resolveSshKeygen();
  seq += 1;
  const dir = nodePath.join(root, `route-joiner${String(seq)}`);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await generateKeyPair(nodePath.join(dir, 'key'), bin);
  const pub = await publicKeyOf(nodePath.join(dir, 'key'), bin);
  return { line: pub.line, fp: pub.fingerprint };
}

test('device-add through the route: real push-first add, journalled with tokens only; wrong fingerprints lock the routes', { skip: !posix }, async () => {
  await withRig(async (r) => {
    const root = nodePath.dirname(r.remotePath);
    const j = await joinerKey(root);
    const wrong = await joinerKey(root);
    const res = await r.call('POST', '/v1/sync/device-add', { pubkey: j.line, label: 'laptop', fp: j.fp });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.ok, true);
    assert.equal(res.json.slot, 'A');
    assert.equal(res.json.applied, true);
    assert.match(res.json.commit, /^[0-9a-f]{40}$/);
    const journal = await r.journal();
    assert.match(journal, /device\.add device=d_[a-z2-7]{10} slot=A fp=SHA256:\S+ commit=[0-9a-f]{40} applied=true/);
    assert.ok(!journal.includes(r.remotePath) && !journal.includes(j.line), 'no URL, no key material in the journal');
    // replay: idempotent
    const again = await r.call('POST', '/v1/sync/device-add', { pubkey: j.line, label: 'laptop', fp: j.fp });
    assert.equal(again.json.existing, true);
    // wrong fingerprint: fixed code, no detail; five of them lock the human routes
    for (let i = 0; i < 5; i += 1) {
      const bad = await r.call('POST', '/v1/sync/device-add', { pubkey: wrong.line, label: 'x', fp: j.fp });
      assert.equal(bad.status, 409);
      assert.equal(bad.json.error, 'FP_MISMATCH');
    }
    const locked = await r.call('POST', '/v1/sync/device-add', { pubkey: wrong.line, label: 'x', fp: wrong.fp });
    assert.equal(locked.status, 409);
    assert.equal(locked.json.error, 'LOCKED');
    // T-B4-13: no body ever contained the remote path
    assert.ok(r.bodies.every((b) => !b.includes(r.remotePath)));
  }, { cycle: runCycle, realDevice: true });
});

test('device-add: a second request while one is in flight is BUSY, never queued', { skip: !posix }, async () => {
  await withRig(async (r) => {
    const root = nodePath.dirname(r.remotePath);
    const a = await joinerKey(root);
    const b = await joinerKey(root);
    const [x, y] = await Promise.all([
      r.call('POST', '/v1/sync/device-add', { pubkey: a.line, label: 'one', fp: a.fp }),
      r.call('POST', '/v1/sync/device-add', { pubkey: b.line, label: 'two', fp: b.fp }),
    ]);
    const statuses = [x.status, y.status].sort();
    assert.deepEqual(statuses, [200, 409]);
    const busy = x.status === 409 ? x : y;
    assert.equal(busy.json.error, 'BUSY');
  }, { cycle: runCycle, realDevice: true });
});
