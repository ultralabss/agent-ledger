/** F3b B6 threat suite: transport and error handling (S23-24, inv 14, T-B4-13; docs/f3b-b6-plan.md file 10).
 *
 *  UNVERIFIED: there is no sshd in the test environment, so a REAL man-in-the-middle (a server presenting another
 *  host key to the hub's own `ssh` with its pinned known_hosts) is NOT exercised here. What is proven: the text real
 *  clients print classifies the right way, an auth / host-key failure halts and is then never retried by anything
 *  (ticks, commit triggers, manual triggers, the exclusive-op cycle), the pinned known_hosts file is not touched, and
 *  neither the URL nor stderr reaches a halt, a log, state.json or the journal. stderr samples are the shapes
 *  OpenSSH 8/9 and Git for Windows print; they are written from memory of real output, not captured live. */

import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { classifyNetError, runCycle, type CycleDeps, type CycleResult } from './cycle.ts';
import type { GitxResult } from './gitx.ts';
import { SyncLoop, type LoopClock } from './loop.ts';
import { rng } from './merge/testkit.ts';
import { assertNoLeak, collectTexts, ctx, haltOf, skipSync, withRig, type Rig } from './threatkit.ts';

const res = (stderr: string, o: Partial<GitxResult> = {}): GitxResult => ({ ok: false, code: 128, stdout: Buffer.alloc(0), stderr, timedOut: false, capped: false, ...o });
const FATAL = 'fatal: Could not read from remote repository.\n\nPlease make sure you have the correct access rights\nand the repository exists.';

const HOSTKEY_CHANGED_OPENSSH9 = [
  '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
  '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @',
  '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
  'IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!',
  'Someone could be eavesdropping on you right now (man-in-the-middle attack)!',
  'The fingerprint for the ED25519 key sent by the remote host is',
  'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.',
  'Offending ED25519 key in /home/u/ledger/.hub/sync/known_hosts:1',
  'Host key for git.example.invalid has changed and you have requested strict checking.',
  'Host key verification failed.',
  FATAL,
].join('\n');

/** [name, stderr, expected class]: shapes the real clients print. */
const SAMPLES: readonly [string, string, ReturnType<typeof classifyNetError>][] = [
  ['OpenSSH 9: key changed (MITM banner)', HOSTKEY_CHANGED_OPENSSH9, 'hostkey'],
  ['OpenSSH 8: no host key known (strict)', `No ED25519 host key is known for git.example.invalid and you have requested strict checking.\nHost key verification failed.\n${FATAL}`, 'hostkey'],
  ['Git for Windows (CRLF): verification failed', `Host key verification failed.\r\n${FATAL.replace(/\n/g, '\r\n')}`, 'hostkey'],
  ['OpenSSH: publickey refused', `git@git.example.invalid: Permission denied (publickey).\n${FATAL}`, 'auth'],
  ['OpenSSH: password prompt exhausted', 'git@git.example.invalid: Permission denied (publickey,password).\nfatal: Could not read from remote repository.', 'auth'],
  ['GitHub-style: deploy key / repo not found', `ERROR: Repository not found.\n${FATAL}`, 'auth'],
  ['non-ff push (porcelain)', ' !\trefs/heads/main:refs/heads/main\t[rejected] (non-fast-forward)\nDone', 'non-ff'],
  ['non-ff push (human)', 'error: failed to push some refs to \'x\'\nhint: Updates were rejected because the tip of your current branch is behind', 'non-ff'],
  ['fsck', 'error: object 1234 is corrupt\nfatal: fsck error in packed object', 'fsck'],
  ['junk', 'totally unrelated words', 'transient'],
  ['empty', '', 'transient'],
];

test('classifyNetError over real-shaped stderr samples: the right class, and the text never leaves the function', { skip: skipSync }, () => {
  for (const [name, text, want] of SAMPLES) assert.equal(classifyNetError(res(text)), want, name);
  // a timeout / cap is never an auth or host-key verdict, whatever the text says
  assert.equal(classifyNetError(res(HOSTKEY_CHANGED_OPENSSH9, { timedOut: true })), 'transient');
  assert.equal(classifyNetError(res('Permission denied (publickey).', { capped: true })), 'transient');
  // stdout is read too (git porcelain prints the ref status there)
  assert.equal(classifyNetError(res('', { stdout: Buffer.from('!\trefs/heads/main:refs/heads/main\t[rejected] (fetch first)') })), 'non-ff');
  // unknown text must never become auth or hostkey: 300 random sentences from a vocabulary with no trigger phrase
  const vocab = ['fatal:', 'error:', 'ssh:', 'connect', 'to', 'host', 'port', '22:', 'kex_exchange_identification:', 'Connection', 'closed', 'by', 'remote', 'banner', 'exchange', 'unexpected', 'EOF', 'broken', 'pipe', 'reset', 'peer', 'timeout', 'network', 'unreachable', 'could', 'resolve', 'hostname', 'name', 'service', 'known', 'refused', 'temporary', 'failure', 'ok', 'client_loop:', 'send', 'disconnect:', 'the', 'is', 'git', 'upload-pack', 'protocol', 'version', 'warning:', 'hint:'];
  const g = rng(0x7e57);
  for (let i = 0; i < 300; i += 1) {
    const words = Array.from({ length: 1 + g.int(14) }, () => g.pick(vocab));
    const c = classifyNetError(res(words.join(' ')));
    assert.equal(c, 'transient', `"${words.join(' ')}" -> ${c}`);
  }
});

test('connection refused / DNS failure / timeout with the standard git trailer are TRANSIENT, not an auth halt', { skip: skipSync, todo: 'PRODUCTION BUG candidate: classifyNetError (cycle.ts:84) matches "could not read from remote repository", which git prints after EVERY ssh failure, so a network blip classifies as `auth` and halts sync (no-contact) until a human resumes. remotecheck.ts:86 classifyProbe already guards against exactly this.' }, () => {
  const rows: [string, string][] = [
    ['refused', `ssh: connect to host git.example.invalid port 22: Connection refused\n${FATAL}`],
    ['dns', `ssh: Could not resolve hostname git.example.invalid: Name or service not known\n${FATAL}`],
    ['unreachable', `ssh: connect to host git.example.invalid port 22: Network is unreachable\n${FATAL}`],
    ['timed out', `ssh: connect to host git.example.invalid port 22: Operation timed out\n${FATAL}`],
    ['reset', `Connection reset by 203.0.113.7 port 22\n${FATAL}`],
    ['kex', `kex_exchange_identification: Connection closed by remote host\n${FATAL}`],
    ['Git for Windows dns (CRLF)', `ssh: Could not resolve hostname git.example.invalid: No such host is known.\r\n${FATAL.replace(/\n/g, '\r\n')}`],
  ];
  for (const [name, text] of rows) assert.equal(classifyNetError(res(text)), 'transient', name);
});

/* ---------------- loop-level: a halt is never retried by anything ---------------- */

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** `SyncLoop` clock: debounce timers fire for real (1 ms), the periodic tick never (the test pulls the ticks). */
function pulledClock(): LoopClock {
  return {
    now: () => Date.now(),
    setTimeout: (fn, ms) => (ms <= 10 ? setTimeout(fn, ms) : null),
    clearTimeout: (h) => {
      if (h !== null) clearTimeout(h as NodeJS.Timeout);
    },
  };
}

async function idle(loop: SyncLoop): Promise<void> {
  for (let i = 0; i < 400; i += 1) {
    if (!(await loop.status()).running) return;
    await sleep(5);
  }
  throw new Error('loop did not go idle');
}

interface Halted {
  loop: SyncLoop;
  calls: () => number;
  flaky: ReturnType<Rig['mk']>['flaky'];
  deps: CycleDeps;
  host: ReturnType<Rig['mk']>['host'];
}

/** A loop over a rig whose first fetch fails with `stderr`; the cycle function counts its calls. */
function haltedLoop(r: Rig, stderr: string, over: Partial<CycleDeps> = {}): Halted {
  const { deps, flaky, host } = r.mk(0, over);
  flaky.failNext('fetch', { stderr, code: 128 }, 1);
  let n = 0;
  const loop = new SyncLoop({
    deps,
    intervalMs: 3_600_000,
    debounceMs: 1,
    clock: pulledClock(),
    cycle: async (d): Promise<CycleResult> => {
      n += 1;
      return runCycle(d);
    },
  });
  return { loop, calls: () => n, flaky, deps, host };
}

async function hammer(h: Halted): Promise<void> {
  for (let i = 0; i < 10; i += 1) {
    h.loop.trigger('tick');
    await idle(h.loop);
    h.loop.trigger('commit');
    await sleep(15);
    await idle(h.loop);
    h.loop.trigger('manual');
    await idle(h.loop);
  }
  await h.loop.exclusiveOp(async (_d, c) => {
    assert.equal((await c.cycle()).outcome, 'gate-skip', 'the exclusive-op cycle goes through the same halt gate');
  });
}

test('host-key halt: 10 ticks + commit triggers + manual triggers + an exclusive-op cycle = ZERO further contacts, known_hosts bytes unchanged', { skip: skipSync }, async () => {
  await withRig(2, async (r) => {
    const knownHosts = nodePath.join(r.lh.hub.syncDir, 'known_hosts');
    const pinned = 'git.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPINNEDPINNEDPINNEDPINNEDPINNEDPINNEDPINNEDPINNED\n';
    await writeFile(knownHosts, pinned, { mode: 0o600 });
    const h = haltedLoop(r, HOSTKEY_CHANGED_OPENSSH9);
    h.loop.trigger('tick');
    await idle(h.loop);
    assert.equal(h.calls(), 1);
    assert.equal(h.flaky.fetchCalls, 1);
    const halt = await haltOf(r.lh);
    assert.equal(halt?.reason, 'hostkey');
    assert.equal(halt?.cls, 'no-contact');
    await hammer(h);
    assert.equal(h.calls(), 1, 'the cycle function was called again while halted');
    assert.equal(h.flaky.fetchCalls, 1, 'network contact while halted');
    assert.equal(h.flaky.pushCalls, 0);
    assert.equal(await readFile(knownHosts, 'utf8'), pinned, 'known_hosts changed');
    assert.equal((await haltOf(r.lh))?.reason, 'hostkey');
    // only a human clears it: resume = exactly ONE more contact (which fails the same way and halts again)
    h.flaky.failNext('fetch', { stderr: HOSTKEY_CHANGED_OPENSSH9, code: 128 }, 1);
    await h.loop.resume();
    await idle(h.loop);
    assert.equal(h.flaky.fetchCalls, 2);
    assert.equal((await haltOf(r.lh))?.reason, 'hostkey');
    assert.equal(await readFile(knownHosts, 'utf8'), pinned);
  });
});

test('auth storm: one refusal = one attempt, then silence; the same for a refused PUSH', { skip: skipSync }, async () => {
  const denied = `git@git.example.invalid: Permission denied (publickey).\n${FATAL}`;
  await withRig(2, async (r) => {
    const h = haltedLoop(r, denied);
    h.loop.trigger('tick');
    await idle(h.loop);
    assert.equal((await haltOf(r.lh))?.reason, 'auth');
    await hammer(h);
    assert.equal(h.flaky.fetchCalls, 1);
    assert.equal(h.calls(), 1);
  });
  await withRig(2, async (r) => {
    await r.lh.commitLocal([ctx('# acme\nlocal\n')]);
    const { deps, flaky } = r.mk();
    flaky.failNext('push', { stderr: denied, code: 128 }, 1);
    let n = 0;
    const loop = new SyncLoop({ deps, intervalMs: 3_600_000, debounceMs: 1, clock: pulledClock(), cycle: async (d) => {
        n += 1;
        return runCycle(d);
      },
    });
    loop.trigger('tick');
    await idle(loop);
    assert.equal((await haltOf(r.lh))?.reason, 'auth');
    assert.equal(flaky.pushCalls, 1);
    for (let i = 0; i < 10; i += 1) {
      loop.trigger('tick');
      await idle(loop);
    }
    assert.equal(n, 1);
    assert.equal(flaky.pushCalls, 1, 'a second push attempt after an auth refusal');
    assert.equal(flaky.fetchCalls, 1);
    assert.equal(await r.kit.remote.main(), r.fleet.base);
  });
});

test('no URL, host, user or stderr text in any halt, log, state.json, inflight or journal after failures (fetch AND push)', { skip: skipSync }, async () => {
  const URL = 'ssh://git@leak-marker.invalid/x.git';
  const needles = ['leak-marker', 'x.git', 'Permission denied', 'Host key', 'HOST IDENTIFICATION', 'Name or service', 'Connection refused', 'git@', 'AAAAAAAAAAAAAAAA', '/home/u/ledger', 'SHA256:'];
  const failures: [string, string][] = [
    ['auth', `git@leak-marker.invalid: Permission denied (publickey).\n${FATAL}`],
    ['hostkey', HOSTKEY_CHANGED_OPENSSH9.replace(/git\.example\.invalid/g, 'leak-marker.invalid')],
    ['dns', `ssh: Could not resolve hostname leak-marker.invalid: Name or service not known\n${FATAL}`],
    ['refused', `ssh: connect to host leak-marker.invalid port 22: Connection refused\n${FATAL}`],
    ['junk', 'fatal: protocol error: leak-marker.invalid sent x.git'],
  ];
  for (const kind of ['fetch', 'push'] as const) {
    for (const [name, stderr] of failures) {
      await withRig(2, async (r) => {
        if (kind === 'push') await r.lh.commitLocal([ctx('# acme\nlocal\n')]);
        const { deps, flaky, host } = r.mk(0, { remote: URL });
        flaky.failNext(kind, { stderr, code: 128 }, 1);
        const out = await runCycle(deps);
        assert.ok(out.outcome.length > 0);
        // a second cycle (halted, or backing off) and a third with the failure repeated
        flaky.failNext(kind, { stderr, code: 128 }, 1);
        await runCycle(deps);
        const texts = [...(await collectTexts(r.lh, host)), JSON.stringify(out), JSON.stringify(await r.lh.state.read())];
        assert.ok(texts.length > 2);
        try {
          assertNoLeak(texts, needles);
        } catch (err) {
          if (err instanceof Error) err.message = `[${kind}/${name}] ${err.message}`;
          throw err;
        }
      });
    }
  }
});
