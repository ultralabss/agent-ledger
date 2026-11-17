/** `SyncLoop` (docs/f3b-b3-plan.md §1.5, §4; inv 14): single-flight + coalescing, halt gating, backoff, debounce,
 *  `stop()` waits, `resume` scope, D2 confirmation, operator override. Fake clock; `runCycle` is stubbed except in
 *  the one test that needs the real thing. */

import assert from 'node:assert/strict';
import test from 'node:test';
import type { CycleDeps, CycleResult } from './cycle.ts';
import { runCycle } from './cycle.ts';
import { SyncLoop, type LoopClock } from './loop.ts';
import type { HaltState } from './state.ts';
import { cycleDeps, makeFleet, makeKit, type LedgerHub } from './testkit-remote.ts';

const posix = process.platform !== 'win32';
const T0 = Date.parse('2026-11-17T10:00:00.000Z');
const SHA = 'a'.repeat(40);

interface Fake extends LoopClock {
  advance(ms: number): Promise<void>;
  jump(ms: number): void;
}

function fakeClock(): Fake {
  let t = T0;
  let id = 0;
  const timers: { id: number; at: number; fn: () => void }[] = [];
  const settle = async (): Promise<void> => {
    for (let i = 0; i < 8; i += 1) await new Promise((r) => setImmediate(r));
  };
  return {
    now: () => t,
    setTimeout(fn, ms) {
      const h = { id: (id += 1), at: t + ms, fn };
      timers.push(h);
      return h;
    },
    clearTimeout(h) {
      const i = timers.indexOf(h as (typeof timers)[number]);
      if (i >= 0) timers.splice(i, 1);
    },
    async advance(ms) {
      const end = t + ms;
      for (;;) {
        timers.sort((a, b) => a.at - b.at);
        const next = timers[0];
        if (next === undefined || next.at > end) break;
        timers.shift();
        t = Math.max(t, next.at);
        next.fn();
        await settle();
      }
      t = end;
      await settle();
    },
    jump(ms) {
      t += ms;
    },
  };
}

async function idle(loop: SyncLoop): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    if (!(await loop.status()).running) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('loop did not go idle');
}

async function until(cond: () => boolean): Promise<void> {
  for (let i = 0; i < 400; i += 1) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('condition not reached');
}

const result = (outcome = 'up-to-date'): CycleResult => ({ outcome, refetches: 0, ms: 1 });
const halt = (over: Partial<HaltState>): HaltState => ({ reason: 'auth', cls: 'no-contact', since: '2026-11-17T09:00:00.000Z', tip: null, rule: null, detail: 'x', d2: null, ...over });

interface Ctx {
  deps: CycleDeps;
  lh: LedgerHub;
  clock: Fake;
  calls: number[];
  loop(o?: { cycle?: (d: CycleDeps) => Promise<CycleResult>; intervalMs?: number }): SyncLoop;
  setHalt(h: HaltState | null): Promise<void>;
  fleet: Awaited<ReturnType<typeof makeFleet>>;
}

async function withCtx<T>(fn: (c: Ctx) => Promise<T>, n = 2): Promise<T> {
  const kit = await makeKit();
  try {
    const fleet = await makeFleet(kit, n);
    const lh = fleet.hubs[0] as LedgerHub;
    const clock = fakeClock();
    const calls: number[] = [];
    const deps = cycleDeps(lh, kit);
    const c: Ctx = {
      deps,
      lh,
      clock,
      calls,
      fleet,
      loop: (o = {}) =>
        new SyncLoop({
          deps,
          intervalMs: o.intervalMs ?? 60_000,
          clock,
          cycle: o.cycle ?? (async () => {
            calls.push(clock.now());
            return result();
          }),
        }),
      async setHalt(h) {
        await lh.state.update((s) => {
          s.halt = h;
        });
      },
    };
    return await fn(c);
  } finally {
    await kit.cleanup();
  }
}

test('single flight: triggers during a running cycle coalesce into ONE rerun', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    let release: () => void = () => undefined;
    let running = 0;
    let maxRunning = 0;
    const loop = c.loop({
      cycle: async () => {
        running += 1;
        maxRunning = Math.max(maxRunning, running);
        c.calls.push(c.clock.now());
        await new Promise<void>((r) => { release = r; });
        running -= 1;
        return result();
      },
    });
    loop.start();
    await until(() => c.calls.length === 1);
    for (let i = 0; i < 6; i += 1) loop.trigger('manual');
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(c.calls.length, 1);
    release();
    await until(() => c.calls.length === 2);
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(c.calls.length, 2, 'exactly one rerun');
    release();
    await idle(loop);
    assert.equal(maxRunning, 1, 'never two cycles at once');
    await loop.stop();
  });
});

test('commit triggers are debounced (5 s) into one cycle', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    const loop = c.loop({ intervalMs: 3_600_000 });
    loop.start();
    await idle(loop);
    const base = c.calls.length;
    loop.trigger('commit');
    await c.clock.advance(2000);
    loop.trigger('commit');
    loop.trigger('commit');
    await c.clock.advance(2000);
    assert.equal(c.calls.length, base, 'still waiting');
    await c.clock.advance(1500);
    await idle(loop);
    assert.equal(c.calls.length, base + 1);
    await loop.stop();
  });
});

test('no-contact and terminal halts: the cycle is never started (inv 14); d2 only once confirmed', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    for (const h of [halt({ reason: 'auth', cls: 'no-contact' }), halt({ reason: 'hostkey', cls: 'no-contact' }), halt({ reason: 'detached', cls: 'terminal', rule: 'detached' })]) {
      await c.setHalt(h);
      c.calls.length = 0;
      const loop = c.loop();
      loop.start();
      await c.clock.advance(10 * 60_000);
      await idle(loop);
      assert.equal(c.calls.length, 0, `${h.reason}: no cycle`);
      loop.trigger('manual');
      await idle(loop);
      assert.equal(c.calls.length, 0, `${h.reason}: not even a manual trigger`);
      await loop.stop();
    }
    const d2 = halt({ reason: 'quarantine:revocation-root', cls: 'd2', tip: SHA, rule: 'revocation-root', d2: { commit: SHA, deviceIds: ['d_aaaaaaaaaa'], kind: 'root' } });
    await c.setHalt(d2);
    c.calls.length = 0;
    const loop = c.loop();
    loop.start();
    await c.clock.advance(5 * 60_000);
    await idle(loop);
    assert.equal(c.calls.length, 0, 'unconfirmed d2: no contact');
    await c.lh.state.update((s) => {
      s.confirmations.push({ kind: 'root', device_id: 'd_aaaaaaaaaa', commit: SHA, fp: `SHA256:${'A'.repeat(43)}`, at: '2026-11-17T10:00:00.000Z' });
    });
    await c.clock.advance(60_000);
    await idle(loop);
    assert.ok(c.calls.length >= 1, 'confirmed d2: the cycle re-gates offline');
    await loop.stop();
  });
});

test('probe / sticky halts contact the remote at most every 15 minutes; a manual trigger bypasses', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    await c.setHalt(halt({ reason: 'quarantine:unsigned', cls: 'probe', tip: SHA, rule: 'unsigned' }));
    const loop = c.loop({ intervalMs: 60_000 });
    loop.start();
    await idle(loop);
    assert.equal(c.calls.length, 1, 'first contact right away');
    await c.clock.advance(10 * 60_000);
    await idle(loop);
    assert.equal(c.calls.length, 1, '10 min later: still quiet');
    await c.clock.advance(6 * 60_000);
    await idle(loop);
    assert.equal(c.calls.length, 2, 'after 15 min: one probe');
    loop.trigger('manual');
    await idle(loop);
    assert.equal(c.calls.length, 3, 'a human asked');
    // the clock jumps BACKWARDS by a day: the distance (not the difference) is what counts
    c.clock.jump(-24 * 3600_000);
    await c.clock.advance(60_000);
    await idle(loop);
    assert.equal(c.calls.length, 3, 'a backward jump does not flood the remote');
    await loop.stop();
  });
});

test('backoff gate: not before nextAt; a far-future nextAt (clock jump) does not freeze the loop; manual bypasses', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    const soon = new Date(c.clock.now() + 5 * 60_000).toISOString();
    await c.lh.state.update((s) => {
      s.backoff = { failures: 2, nextAt: soon, lastError: 'fetch' };
    });
    const loop = c.loop({ intervalMs: 60_000 });
    loop.start();
    await idle(loop);
    assert.equal(c.calls.length, 0, 'inside the backoff window');
    await c.clock.advance(5 * 60_000 + 61_000);
    await idle(loop);
    assert.equal(c.calls.length >= 1, true, 'after nextAt');
    await loop.stop();
    c.calls.length = 0;
    await c.lh.state.update((s) => {
      s.backoff = { failures: 2, nextAt: new Date(c.clock.now() + 30 * 24 * 3600_000).toISOString(), lastError: 'fetch' };
    });
    const l2 = c.loop();
    l2.start();
    await idle(l2);
    assert.equal(c.calls.length, 1, 'a nextAt a month away can only be a clock jump: run');
    await l2.stop();
  });
});

test('stop() waits for the running cycle and never kills it mid-way', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    let release: () => void = () => undefined;
    let finished = false;
    const loop = c.loop({
      cycle: async () => {
        await new Promise<void>((r) => { release = r; });
        finished = true;
        return result();
      },
    });
    loop.start();
    await new Promise((r) => setTimeout(r, 40)); // the cycle is running (gate read state)
    let stopped = false;
    const p = loop.stop().then(() => { stopped = true; });
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(stopped, false, 'still waiting for the cycle');
    release();
    await p;
    assert.equal(finished, true);
    loop.trigger('manual');
    await c.clock.advance(120_000);
    assert.equal((await loop.status()).started, false, 'a stopped loop stays stopped');
  });
});

test('resume clears no-contact and sticky only; d2, probe, local and terminal are untouched', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    const loop = c.loop();
    const cases: [HaltState, boolean][] = [
      [halt({ reason: 'auth', cls: 'no-contact' }), true],
      [halt({ reason: 'hostkey', cls: 'no-contact' }), true],
      [halt({ reason: 'history-rewrite', cls: 'sticky', tip: SHA }), true],
      [halt({ reason: 'format', cls: 'sticky', tip: SHA }), true],
      [halt({ reason: 'quarantine:unsigned', cls: 'probe', tip: SHA, rule: 'unsigned' }), false],
      [halt({ reason: 'config', cls: 'local' }), false],
      [halt({ reason: 'inflight', cls: 'local' }), false],
      [halt({ reason: 'detached', cls: 'terminal', rule: 'detached' }), false],
      [halt({ reason: 'quarantine:revocation-root', cls: 'd2', tip: SHA, rule: 'revocation-root', d2: { commit: SHA, deviceIds: ['d_aaaaaaaaaa'], kind: 'root' } }), false],
    ];
    for (const [h, clears] of cases) {
      await c.setHalt(h);
      const r = await loop.resume();
      assert.equal(r.cleared, clears, h.reason);
      assert.equal((await c.lh.state.read()).halt === null, clears, h.reason);
    }
    await loop.stop();
  });
});

test('confirmRevocation: the fingerprint must match the key in devices.yml AT the revoking commit; self -> detached', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    const root = (c.fleet.hubs[0] as LedgerHub).hub;
    const base = c.fleet.base; // devices.yml with the root's key lives here
    const loop = c.loop();
    await c.setHalt(halt({ reason: 'quarantine:revocation-root', cls: 'd2', tip: base, rule: 'revocation-root', d2: { commit: base, deviceIds: [root.deviceId], kind: 'root' } }));
    assert.deepEqual(await loop.confirmRevocation(root.deviceId, `SHA256:${'A'.repeat(43)}`), { ok: false, reason: 'fingerprint-mismatch' });
    assert.deepEqual(await loop.confirmRevocation('d_bbbbbbbbbb', root.pub.fingerprint), { ok: false, reason: 'unknown-device' });
    assert.deepEqual(await loop.confirmRevocation('nope', root.pub.fingerprint), { ok: false, reason: 'invalid-input' });
    assert.equal((await c.lh.state.read()).confirmations.length, 0);
    assert.deepEqual(await loop.confirmRevocation(root.deviceId, root.pub.fingerprint), { ok: true });
    const st = await c.lh.state.read();
    assert.equal(st.confirmations.length, 1);
    assert.deepEqual([st.confirmations[0]?.commit, st.confirmations[0]?.device_id, st.confirmations[0]?.kind], [base, root.deviceId, 'root']);
    assert.notEqual(st.halt, null, 'confirming does not clear the halt: the next cycle re-gates');

    await c.setHalt(halt({ reason: 'quarantine:revocation-self', cls: 'd2', tip: base, rule: 'revocation-self', d2: { commit: base, deviceIds: [root.deviceId], kind: 'self' } }));
    assert.deepEqual(await loop.confirmRevocation(root.deviceId, root.pub.fingerprint), { ok: true });
    const after = (await c.lh.state.read()).halt;
    assert.equal(after?.reason, 'detached');
    assert.equal(after?.cls, 'terminal');
    assert.deepEqual(await loop.confirmRevocation(root.deviceId, root.pub.fingerprint), { ok: false, reason: 'no-revocation-halt' });
    await loop.stop();
  });
});

test('acceptQuarantine: only the halted tip, only overridable rules, secrets need the acknowledgement', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    const loop = c.loop();
    assert.deepEqual(await loop.acceptQuarantine(SHA), { ok: false, reason: 'no-quarantine' });
    await c.setHalt(halt({ reason: 'quarantine:unsigned', cls: 'probe', tip: SHA, rule: 'unsigned' }));
    assert.deepEqual(await loop.acceptQuarantine('b'.repeat(40)), { ok: false, reason: 'tip-mismatch' });
    assert.deepEqual(await loop.acceptQuarantine('abc'), { ok: false, reason: 'invalid-input' });
    assert.deepEqual(await loop.acceptQuarantine(SHA), { ok: true });
    assert.deepEqual((await c.lh.state.read()).overrides.map((o) => [o.tip, o.secretAck]), [[SHA, undefined]]);
    for (const rule of ['tree:symlink', 'revoked-signer', 'revoked-current', 'merge-devices', 'oversize', 'timeout']) {
      await c.setHalt(halt({ reason: `quarantine:${rule}` as never, cls: 'probe', tip: SHA, rule }));
      assert.deepEqual(await loop.acceptQuarantine(SHA), { ok: false, reason: 'not-overridable' }, rule);
    }
    await c.setHalt(halt({ reason: 'quarantine:secret', cls: 'probe', tip: SHA, rule: 'secret' }));
    assert.deepEqual(await loop.acceptQuarantine(SHA), { ok: false, reason: 'secret-acknowledgement-required' });
    assert.deepEqual(await loop.acceptQuarantine(SHA, { secretAck: true }), { ok: true });
    assert.equal((await c.lh.state.read()).overrides.at(-1)?.secretAck, true);
    await loop.stop();
  });
});

test('with the REAL cycle: an unsigned tip is accepted after `sync accept`, applied by the very next cycle', { skip: !posix }, async () => {
  await withCtx(async (c) => {
    const tip = await (c.fleet.kit.remote).pushUnsigned([{ path: 'acme/CONTEXT.md', content: '# acme\nunsigned\n' }]);
    const loop = new SyncLoop({ deps: c.deps, intervalMs: 3_600_000, clock: c.clock, cycle: runCycle });
    loop.start();
    await idle(loop);
    assert.equal((await loop.status()).halt?.reason, 'quarantine:unsigned');
    assert.deepEqual(await loop.acceptQuarantine(tip), { ok: true });
    await new Promise((r) => setTimeout(r, 50));
    await idle(loop);
    const st = await loop.status();
    assert.equal(st.halt, null);
    assert.equal(st.accepted, tip);
    assert.equal(await c.lh.hub.main(), tip);
    await loop.stop();
  });
});
