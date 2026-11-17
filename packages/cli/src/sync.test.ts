/** `ledger sync` (docs/f3b-b4-plan.md §1.4, §2.5; T-B4-1, T-B4-12, T-B4-13): the decision commands need a terminal and a
 *  retyped value, never spool, print only sanitised hub text, and map the hub's single `refused` to exit 2. The hub is
 *  a fake (`SyncHub`); the routes themselves are covered in hub/src/http/sync-routes.test.ts. */

import assert from 'node:assert/strict';
import test from 'node:test';
import { parseArgs } from './args.ts';
import { CliError, type HubResponse } from './client.ts';
import { cmdSync, type SyncHub, type SyncIo } from './sync.ts';

const SHA = 'a1'.repeat(20);
const FP = `SHA256:${'A'.repeat(43)}`;
const ID = 'd_abcdefg32j';

interface Rig {
  out: string[];
  err: string[];
  calls: { method: string; path: string; payload: unknown }[];
  run(argv: string[], o?: { tty?: boolean; ask?: (p: string) => Promise<string | null>; answer?: (path: string) => unknown; session?: string | null; throwOn?: CliError }): Promise<number>;
}

function rig(): Rig {
  const r: Rig = {
    out: [],
    err: [],
    calls: [],
    async run(argv, o = {}) {
      const hub: SyncHub = {
        async get(path) {
          r.calls.push({ method: 'GET', path, payload: undefined });
          if (o.throwOn !== undefined) throw o.throwOn;
          return { status: 200, text: '', json: o.answer?.(path) ?? null } satisfies HubResponse;
        },
        async post(path, payload) {
          r.calls.push({ method: 'POST', path, payload });
          if (o.throwOn !== undefined) throw o.throwOn;
          return { status: 200, text: '', json: o.answer?.(path) ?? { ok: true } } satisfies HubResponse;
        },
      };
      const env: NodeJS.ProcessEnv = { LEDGER_HUB_URL: 'http://127.0.0.1:9', ...(o.session === null ? {} : { LEDGER_SESSION: o.session ?? 'human1111' }) };
      const io: SyncIo = {
        out: (l) => r.out.push(l),
        err: (l) => r.err.push(l),
        env,
        ...(o.tty === true ? { tty: { stdin: true, stdout: true } } : {}),
        ...(o.ask === undefined ? {} : { ask: o.ask }),
      };
      return cmdSync(parseArgs(argv), io, hub);
    },
  };
  return r;
}

const status = (over: Record<string, unknown> = {}): unknown => ({
  enabled: true,
  remote_host: 'example.com',
  loop: { started: true, running: false, pending: false, halt: null, backoff: null, accepted: SHA, lastCycle: { at: '2026-11-17T10:00:00.000Z', outcome: 'up-to-date', ms: 3 }, pushBlocked: null, stateError: false },
  locked: false,
  devices: [],
  unapproved: [],
  single_trusted_device: false,
  ...over,
});

test('`ledger sync` triggers; resume says what it cleared', async () => {
  const r = rig();
  assert.equal(await r.run(['sync']), 0);
  assert.deepEqual(r.calls, [{ method: 'POST', path: '/v1/sync/trigger', payload: {} }]);
  assert.equal(await r.run(['sync', 'resume'], { answer: () => ({ ok: true, cleared: true }) }), 0);
  assert.deepEqual(r.calls[1], { method: 'POST', path: '/v1/sync/resume', payload: { session: 'human1111' } });
  assert.match(r.out.join('\n'), /resumed/);
});

test('status: one line per fact, halt and approval warnings, hostile text is sanitised, --json is verbatim, no URL', async () => {
  const r = rig();
  const body = status({
    loop: { started: true, running: false, pending: false, halt: { reason: 'quarantine:unsigned', cls: 'probe', since: '2026-11-17T09:00:00.000Z', tip: SHA, rule: 'unsigned', detail: 'range refused \u001b[31m(unsigned)‮', d2: null }, backoff: { failures: 2, nextAt: null, lastError: 'fetch' }, accepted: SHA, lastCycle: null, pushBlocked: null, stateError: false },
    devices: [{ id: ID, slot: 'B', label: 'evil\u001b[2Jlabel', fingerprint: FP, status: 'active', trusted: false, self: false }],
    unapproved: [{ id: ID, slot: 'B', label: 'evil\u001b[2Jlabel', fingerprint: FP }],
    single_trusted_device: true,
    locked: true,
  });
  assert.equal(await r.run(['sync', 'status'], { answer: () => body }), 0);
  const text = r.out.join('\n');
  assert.match(text, /^sync: idle · remote example\.com · accepted a1a1a1a1a1/);
  assert.match(text, /halt: quarantine:unsigned \(probe\)/);
  assert.match(text, /NOT-APPROVED/);
  assert.ok(text.includes(`WARNING: device ${ID} (evillabel)`) && text.includes(`\`ledger device approve ${ID} --fp ${FP}\``));
  assert.match(text, /only one trusted device/);
  assert.match(text, /LOCKED/);
  assert.ok(!/[\u001b‮]/.test(text), 'no escape or bidi control reaches the terminal');
  const j = rig();
  assert.equal(await j.run(['sync', 'status', '--json'], { answer: () => body }), 0);
  assert.deepEqual(JSON.parse(j.out[0] ?? ''), JSON.parse(JSON.stringify(body)));
});

test('accept: needs a terminal AND a retyped commit id; nothing is sent otherwise (T-B4-12)', async () => {
  const noTty = rig();
  assert.equal(await noTty.run(['sync', 'accept', SHA]), 4);
  assert.match(noTty.err.join('\n'), /interactive terminal/);
  assert.deepEqual(noTty.calls, []);

  const wrong = rig();
  assert.equal(await wrong.run(['sync', 'accept', SHA], { tty: true, ask: async () => 'b'.repeat(40) }), 4);
  assert.deepEqual(wrong.calls, []);
  const eof = rig();
  assert.equal(await eof.run(['sync', 'accept', SHA], { tty: true, ask: async () => null }), 4);
  assert.deepEqual(eof.calls, []);

  const ok = rig();
  assert.equal(await ok.run(['sync', 'accept', SHA], { tty: true, ask: async (p) => (assert.match(p, /retype to confirm/), SHA), answer: () => ({ answer: 'ok' }) }), 0);
  assert.deepEqual(ok.calls, [{ method: 'POST', path: '/v1/sync/accept', payload: { sha: SHA, session: 'human1111' } }]);

  // the flag works before and after the commit id, and is only sent when given
  for (const argv of [['sync', 'accept', SHA, '--secret-acknowledged'], ['sync', 'accept', '--secret-acknowledged', SHA]]) {
    const s = rig();
    assert.equal(await s.run(argv, { tty: true, ask: async () => SHA, answer: () => ({ answer: 'ok' }) }), 0, argv.join(' '));
    assert.deepEqual(s.calls[0]?.payload, { sha: SHA, secret_ack: true, session: 'human1111' });
  }

  // the hub's single refusal = exit 2 and a pointer to status (no reason is invented)
  const refused = rig();
  assert.equal(await refused.run(['sync', 'accept', SHA], { tty: true, ask: async () => SHA, answer: () => ({ answer: 'refused' }) }), 2);
  assert.match(refused.err.join('\n'), /refused/);

  assert.equal(await rig().run(['sync', 'accept', 'not-a-sha']), 4);
  assert.equal(await rig().run(['sync', 'accept']), 4);
});

test('confirm-revocation: id + fingerprint validated, terminal + retyped fingerprint required, refusal = exit 2', async () => {
  assert.equal(await rig().run(['sync', 'confirm-revocation', ID]), 4, 'no --fp');
  assert.equal(await rig().run(['sync', 'confirm-revocation', 'x', '--fp', FP]), 4);
  const noTty = rig();
  assert.equal(await noTty.run(['sync', 'confirm-revocation', ID, '--fp', FP]), 4);
  assert.deepEqual(noTty.calls, []);
  const wrong = rig();
  assert.equal(await wrong.run(['sync', 'confirm-revocation', ID, '--fp', FP], { tty: true, ask: async () => `SHA256:${'B'.repeat(43)}` }), 4);
  assert.deepEqual(wrong.calls, []);
  const ok = rig();
  assert.equal(await ok.run(['sync', 'confirm-revocation', ID, '--fp', FP], { tty: true, ask: async () => FP, answer: () => ({ answer: 'ok' }) }), 0);
  assert.deepEqual(ok.calls, [{ method: 'POST', path: '/v1/sync/confirm-revocation', payload: { id: ID, fp: FP, session: 'human1111' } }]);
  const refused = rig();
  assert.equal(await refused.run(['sync', 'confirm-revocation', ID, '--fp', FP], { tty: true, ask: async () => FP, answer: () => ({ answer: 'refused' }) }), 2);
});

test('hub errors: exit code from the client (hub down = 3), message sanitised; no session = no session field (the hub decides)', async () => {
  const down = rig();
  assert.equal(await down.run(['sync', 'status'], { throwOn: new CliError(3, 'hub is not running \u001b[31m(refused)', true) }), 3);
  assert.ok(!/\u001b/.test(down.err.join('\n')));
  const forbidden = rig();
  assert.equal(await forbidden.run(['sync', 'resume'], { session: null, throwOn: new CliError(4, 'owner actions over a token need a registered, live session', false, null, 403) }), 4);
  assert.deepEqual(forbidden.calls[0]?.payload, {}, 'no LEDGER_SESSION: nothing invented');
  assert.equal(await rig().run(['sync', 'bogus']), 4);
});

test('the sync CLI never spools: no spooling client and no fetch in the module', async () => {
  const { readFile } = await import('node:fs/promises');
  const src = await readFile(new URL('./sync.ts', import.meta.url), 'utf8');
  assert.ok(!/SpoolingClient|enqueue\(|fetch\(/.test(src));
  assert.ok(/new HubClient\(cfg\)/.test(src));
});
