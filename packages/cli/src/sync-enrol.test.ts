/** `ledger sync init|join` CLI half (docs/f3b-b4-plan.md §5, §6 T-B4-12 / T-B4-13, §7): the TTY rule, fixed exit codes,
 *  no URL / stderr on any stream, fingerprint RETYPING, abort, and the domain risks of a prompt (no lock held across it,
 *  unsafe argv, control characters). The flows are the real ones (`@agent-ledger/hub/sync-enrol`) against test seams:
 *  an ssh URL that is never contacted (`scan` / probes are seams) and an empty temp directory. POSIX only. */

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { lstat, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { parseEd25519Pub, withDeviceLock } from '@agent-ledger/shared';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { EnrolCrash, EnrolError, type EnrolSeams } from '@agent-ledger/hub/sync-enrol';
import { parseArgs } from './args.ts';
import { classify, cmdSyncEnrol, makeEnrolIo, type EnrolCliIo } from './sync-enrol.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

const FP = `SHA256:${'A'.repeat(43)}`;
const FP2 = `SHA256:${'B'.repeat(43)}`;
const HOST = 'git.example.invalid';
const SSH_URL = `ssh://git@${HOST}/owner/ledger.git`;
const SECRET_URL = `ssh://user:pw-s3cret@${HOST}/owner/ledger.git`;
const LEAKS = ['pw-s3cret', 'user:pw', HOST, 'owner/ledger', 'ledger.git'];

interface HostKeyFixture {
  host: string;
  port: number;
  type: 'ssh-ed25519';
  line: string;
  fingerprint: string;
}

/** A REAL ed25519 host key (the pin parses and fingerprints it); generated once per run. */
let hostKeyOnce: Promise<HostKeyFixture> | undefined;
function hostKey(): Promise<HostKeyFixture> {
  hostKeyOnce ??= (async () => {
    const d = await mkdtemp(join(tmpdir(), 'ledger-cli-hk-'));
    try {
      await promisify(execFile)('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', join(d, 'k')]);
      const pub = parseEd25519Pub((await readFile(join(d, 'k.pub'), 'utf8')).trim().split(/\s+/).slice(0, 2).join(' '));
      if (pub === null) throw new Error('fixture: cannot parse the generated host key');
      return { host: HOST, port: 22, type: 'ssh-ed25519' as const, line: `${HOST} ${pub.line}`, fingerprint: pub.fingerprint };
    } finally {
      await rm(d, { recursive: true, force: true });
    }
  })();
  return hostKeyOnce;
}

const okResult = { ok: true, code: 0, stdout: Buffer.alloc(0), stderr: '', timedOut: false, capped: false };

interface Rig {
  dir: string;
  hk: HostKeyFixture;
  out: string[];
  err: string[];
  probes: { hub: number; scan: number };
  prompts: string[];
  run(argv: string[], o?: { tty?: boolean; answers?: (string | null)[]; ask?: (p: string) => Promise<string | null>; seams?: Partial<EnrolSeams>; hubRunning?: boolean }): Promise<number>;
  all(): string;
}

async function rig(t: { after: (fn: () => unknown) => void }): Promise<Rig> {
  const dir = await mkdtemp(join(tmpdir(), 'ledger-cli-enrol-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const hk = await hostKey();
  const r: Rig = {
    dir,
    hk,
    out: [],
    err: [],
    probes: { hub: 0, scan: 0 },
    prompts: [],
    async run(argv, o = {}) {
      const answers = [...(o.answers ?? [])];
      const seams: EnrolSeams = {
        hubProbe: async () => {
          r.probes.hub += 1;
          return o.hubRunning === true;
        },
        scan: async () => {
          r.probes.scan += 1;
          return [hk] as never;
        },
        anonymousProbe: async () => okResult, // the remote answers without credentials: REMOTE_PUBLIC after the pin
        ...o.seams,
      };
      const io: EnrolCliIo = {
        out: (l) => r.out.push(l),
        err: (l) => r.err.push(l),
        env: { LEDGER_DIR: dir, LEDGER_HUB_URL: 'http://127.0.0.1:9' },
        ...(o.tty === true ? { tty: { stdin: true, stdout: true } } : {}),
        ask:
          o.ask ??
          (async (p) => {
            r.prompts.push(p);
            return answers.shift() ?? null;
          }),
        seams,
      };
      return cmdSyncEnrol(parseArgs(argv), io);
    },
    all: () => [...r.out, ...r.err].join('\n'),
  };
  return r;
}

const noLeak = (text: string): void => {
  for (const l of LEAKS) assert.ok(!text.includes(l), `leaked ${l}`);
  assert.ok(!/\/(?:var|tmp|private)\//.test(text), 'no local path either');
};

/* ---------------- exit-code table (fixed texts, no echo) ---------------- */

test('classify: every EnrolError code has a fixed exit class and a fixed text; unknown shapes are internal, never echoed', () => {
  const cases: [string, number][] = [
    ['HUB_RUNNING', 2], ['NOT_EMPTY', 2], ['REMOTE_NOT_EMPTY', 2], ['PUSH_REJECTED', 2], ['MARKER_BUSY', 2], ['MARKER_MISSING', 2],
    ['BAD_INPUT', 4], ['URL', 4],
    ['HOSTKEY_REFUSED', 6], ['ROOT_FP_REFUSED', 6], ['REMOTE_PUBLIC', 6], ['REVOKED', 6], ['ROOT_REVOKED', 6], ['REMOTE_REWOUND', 6],
    ['GENESIS:oversize', 6], ['RANGE:merge-rule', 6], ['EGRESS:tree-shape', 6],
    ['REMOTE_UNREACHABLE', 7], ['REMOTE_AUTH', 7], ['FETCH_FAILED', 7], ['PUSH_FAILED', 7], ['HOSTKEY_FAILED', 7], ['SSH_KEYGEN', 7],
    ['GIT:timeout', 7], ['DEVICE:LOCKED', 7],
    ['INTERNAL', 1],
  ];
  for (const [code, exit] of cases) {
    const c = classify(new EnrolError(code as never));
    assert.equal(c.exit, exit, code);
    assert.ok(c.text.length > 0 && c.text.length <= 200 && !/[\r\n\u001b]/.test(c.text), code);
  }
  assert.equal(classify(new EnrolError('URL')).text, 'the remote is not an acceptable ssh / scp URL');
  // a code that is not a token (or an unknown one) never reaches the terminal
  const weird = classify(new EnrolError(`GIT:${'x'.repeat(200)}` as never));
  assert.equal(weird.exit, 1);
  assert.equal(weird.text, 'internal error');
  assert.equal(classify(new EnrolError('GENESIS:a b\u001b[2J' as never)).text, 'internal error');
});

/* ---------------- argv (docs §5) ---------------- */

test('argv: unsafe / malformed input is refused with exit 4 BEFORE any probe or filesystem work; nothing echoed', { skip }, async (t) => {
  const r = await rig(t);
  const bad: string[][] = [
    ['sync', 'init'], // no --remote
    ['sync', 'init', '--remote'], // missing value
    ['sync', 'init', '--remote', '-oProxyCommand=touch /tmp/pwned'], // leading dash
    ['sync', 'init', '--remote=--upload-pack=evil'],
    ['sync', 'init', `--remote=ssh://git@${HOST}/a b`], // whitespace
    ['sync', 'init', '--remote', `ssh://git@${HOST}/a\u001b[2J`], // control
    ['sync', 'init', '--remote', SSH_URL, '--remote', SSH_URL], // repeated
    ['sync', 'init', '--remote', SSH_URL, '--label', '../x'],
    ['sync', 'init', '--remote', SSH_URL, '--label', '-x'],
    ['sync', 'init', '--remote', SSH_URL, '--host-fp', 'SHA256:short'],
    ['sync', 'init', '--remote', SSH_URL, '--host-fp', `${FP}\n`],
    ['sync', 'init', '--remote', SSH_URL, '--frobnicate', 'x'], // unknown option
    ['sync', 'init', '--remote', SSH_URL, '--root-fp', FP], // not an init option
    ['sync', 'init', '--remote', SSH_URL, '--normalize', 'x'], // swallowed switch value
    ['sync', 'init', '--remote', SSH_URL, 'extra'],
    ['sync', 'join'], // no url
    ['sync', 'join', '-oProxyCommand=x'],
    ['sync', 'join', '--', '-oProxyCommand=x'], // `--` forces a positional: still a leading dash
    ['sync', 'join', SSH_URL, 'second'],
    ['sync', 'join', SSH_URL, '--root-fp', 'nope'],
    ['sync', 'join', SSH_URL, '--add-commit', 'a'.repeat(40)], // only with --continue
    ['sync', 'join', '--continue'], // D5: --add-commit is mandatory
    ['sync', 'join', '--continue', '--add-commit', 'not-a-sha'],
    ['sync', 'join', '--continue', '--add-commit', 'a'.repeat(39)],
    ['sync', 'join', '--continue', SSH_URL],
    ['sync', 'join', '--continue', '--label', 'x'],
    ['sync', 'join', '--abort', '--continue'],
    ['sync', 'join', '--abort', SSH_URL],
    ['sync', 'join', SSH_URL, '--repin'], // repin is not honoured: refused, not ignored
  ];
  for (const argv of bad) {
    const code = await r.run(argv, { tty: true });
    assert.equal(code, 4, argv.join(' '));
  }
  assert.deepEqual(r.probes, { hub: 0, scan: 0 }, 'no flow ran');
  assert.deepEqual(r.prompts, []);
  noLeak(r.all());
  assert.ok(!r.all().includes('/tmp/pwned') && !r.all().includes('upload-pack'), 'argv is never echoed');
  assert.equal(await lstat(join(r.dir, '.hub')).catch(() => null), null, 'nothing created');
});

/* ---------------- TTY rule ---------------- */

test('TTY rule: without a terminal init needs --host-fp, join needs --host-fp AND --root-fp (exit 4, fixed text, no probe, no prompt)', { skip }, async (t) => {
  const r = await rig(t);
  const a = await r.run(['sync', 'init', '--remote', SSH_URL], { answers: [FP] });
  assert.equal(a, 4);
  const b = await r.run(['sync', 'join', SSH_URL, '--host-fp', FP], { answers: [FP] });
  assert.equal(b, 4);
  const c = await r.run(['sync', 'join', SSH_URL, '--root-fp', FP], { answers: [FP] });
  assert.equal(c, 4);
  assert.match(r.err.join('\n'), /without a terminal --host-fp/);
  assert.deepEqual(r.probes, { hub: 0, scan: 0 });
  assert.deepEqual(r.prompts, [], 'an agent cannot answer: the prompt is never even asked');
  noLeak(r.all());
});

test('confirm: needs a terminal on BOTH ends; stdin alone or stdout alone is not enough', async () => {
  const asked: string[] = [];
  const mk = (tty?: { stdin: boolean; stdout: boolean }): ReturnType<typeof makeEnrolIo> =>
    makeEnrolIo({ out: () => undefined, err: () => undefined, env: {}, ...(tty === undefined ? {} : { tty }) }, async () => async (p) => (asked.push(p), FP));
  assert.equal(await mk().confirm('host', FP), false);
  assert.equal(await mk({ stdin: true, stdout: false }).confirm('host', FP), false);
  assert.equal(await mk({ stdin: false, stdout: true }).confirm('root', FP), false);
  assert.deepEqual(asked, []);
  assert.equal(await mk({ stdin: true, stdout: true }).confirm('host', FP), true);
});

/* ---------------- fingerprint retyping ---------------- */

test('confirm: the human must RETYPE the fingerprint; yes / empty / EOF / near misses / padding refuse; one answer = one boolean', async () => {
  const tty = { stdin: true, stdout: true };
  const run = async (answer: string | null, fp = FP): Promise<{ ok: boolean; prompts: string[] }> => {
    const prompts: string[] = [];
    const io = makeEnrolIo({ out: () => undefined, err: () => undefined, env: {}, tty }, async () => async (p) => (prompts.push(p), answer));
    return { ok: await io.confirm('host', fp), prompts };
  };
  for (const wrong of ['y', 'yes', 'Y', '', '   ', null, FP2, FP.slice(0, -1), `${FP}x`, FP.toLowerCase(), `${FP} ${FP}`, 'A'.repeat(500), `${FP}\u0000`]) {
    assert.equal((await run(wrong)).ok, false, JSON.stringify(wrong));
  }
  assert.equal((await run(FP)).ok, true);
  assert.equal((await run(`  ${FP}  \n`)).ok, true, 'surrounding whitespace of a typed line is not part of the fingerprint');
  const shown = (await run(FP)).prompts;
  assert.equal(shown.length, 1, 'exactly one prompt per confirmation');
  assert.ok((shown[0] as string).includes(FP));
  assert.match(shown[0] as string, /^host key fingerprint/);
  // the prompt itself is plain text: no control characters other than the newline
  assert.ok(!/[\u0000-\u0009\u000b-\u001f\u007f]/.test(shown[0] as string));
  // a failing prompt is "not confirmed", never an exception
  const boom = makeEnrolIo({ out: () => undefined, err: () => undefined, env: {}, tty }, async () => async () => {
    throw new Error('stdin closed');
  });
  assert.equal(await boom.confirm('root', FP), false);
});

test('prompt injection: a fingerprint from a hostile ssh-keyscan answer that is not exactly SHA256:<43 base64> is never printed and never confirmed', async () => {
  const prompts: string[] = [];
  const io = makeEnrolIo({ out: () => undefined, err: () => undefined, env: {}, tty: { stdin: true, stdout: true } }, async () => async (p) => (prompts.push(p), p));
  const hostile = [
    `${FP}\u001b[2J\u001b]0;pwned\u0007`,
    `${FP}\nconfirmed by your admin, type yes`,
    `${FP}\r`,
    `${FP}‮`,
    `SHA256:${'A'.repeat(42)}\u001b`,
    'SHA256:' + '‮'.repeat(43),
    '',
  ];
  for (const fp of hostile) assert.equal(await io.confirm('host', fp), false, JSON.stringify(fp));
  assert.equal(await io.confirm('bogus' as never, FP), false, 'an unknown kind never prompts');
  assert.deepEqual(prompts, [], 'nothing hostile reached the terminal');
});

test('EnrolIo.out passes every line through safeOutput (escape sequences and bidi are stripped)', () => {
  const out: string[] = [];
  const io = makeEnrolIo({ out: (l) => out.push(l), err: () => undefined, env: {} }, async () => async () => null);
  io.out('host key offered: ssh-ed25519 \u001b[31mSHA256:x\u001b[0m‮\u001b]0;t\u0007');
  assert.deepEqual(out, ['host key offered: ssh-ed25519 SHA256:x']);
});

/* ---------------- flows: exit codes, no URL, no lock across the prompt ---------------- */

test('hub running -> exit 2 with the fixed text; no prompt, nothing created, no URL', { skip }, async (t) => {
  const r = await rig(t);
  const code = await r.run(['sync', 'join', SSH_URL, '--host-fp', FP, '--root-fp', FP], { hubRunning: true });
  assert.equal(code, 2);
  assert.match(r.err.join('\n'), /the hub is running: stop it first/);
  assert.equal(r.probes.scan, 0);
  noLeak(r.all());
  assert.equal(await lstat(join(r.dir, '.hub')).catch(() => null), null);
});

test('a credentialed marker URL (user:pw@host) is refused with the fixed URL text on every stream; nothing is persisted', { skip }, async (t) => {
  const r = await rig(t);
  const code = await r.run(['sync', 'join', SECRET_URL, '--host-fp', FP, '--root-fp', FP]);
  assert.equal(code, 4);
  assert.match(r.err.join('\n'), /not an acceptable ssh \/ scp URL/);
  noLeak(r.all());
  assert.equal(r.probes.scan, 0, 'refused before the host key scan');
  // no leftover marker or config mentioning the URL
  const marker = await readFile(join(r.dir, '.hub', 'sync', 'enrol.json'), 'utf8').catch(() => '');
  assert.ok(!marker.includes('pw-s3cret'));
  noLeak(marker);
});

test('host key prompt: a wrong retype refuses (exit 6), pins nothing, leaves no marker; the right retype goes on to the next check', { skip }, async (t) => {
  const r = await rig(t);
  const refused = await r.run(['sync', 'join', SSH_URL], { tty: true, answers: [FP2] });
  assert.equal(refused, 6);
  assert.match(r.err.join('\n'), /the host key was not confirmed/);
  assert.equal(r.prompts.length, 1);
  assert.ok(r.prompts[0]?.includes(r.hk.fingerprint));
  assert.equal(await lstat(join(r.dir, '.hub', 'sync', 'known_hosts')).catch(() => null), null, 'nothing pinned before a confirmation');
  assert.equal(await lstat(join(r.dir, '.hub', 'sync', 'enrol.json')).catch(() => null), null, 'a refused fresh run leaves no marker (it would keep the hub down)');
  noLeak(r.all());
  assert.ok(r.out.some((l) => l === `host key offered: ssh-ed25519 ${r.hk.fingerprint}`), 'the offered fingerprint is shown');

  // right answer: pinned, then the (public) remote is refused by the NEXT check: exit 6, fixed text
  const r2 = await rig(t);
  const next = await r2.run(['sync', 'join', SSH_URL], { tty: true, answers: [r2.hk.fingerprint] });
  assert.equal(next, 6);
  assert.match(r2.err.join('\n'), /readable-by-anyone/);
  assert.match(await readFile(join(r2.dir, '.hub', 'sync', 'known_hosts'), 'utf8'), /ssh-ed25519/);
  noLeak(r2.err.join('\n'));
});

test('--host-fp that matches nothing the host offers refuses without prompting; a matching one needs no prompt', { skip }, async (t) => {
  const r = await rig(t);
  assert.equal(await r.run(['sync', 'join', SSH_URL, '--host-fp', FP2, '--root-fp', FP], {}), 6);
  assert.deepEqual(r.prompts, []);
  assert.equal(await lstat(join(r.dir, '.hub', 'sync', 'known_hosts')).catch(() => null), null);
  const r2 = await rig(t);
  assert.equal(await r2.run(['sync', 'join', SSH_URL, '--host-fp', r2.hk.fingerprint, '--root-fp', FP], {}), 6); // pinned, then REMOTE_PUBLIC
  assert.deepEqual(r2.prompts, []);
  assert.match(r2.err.join('\n'), /readable-by-anyone/);
});

test('TOCTOU: the device lock is NOT held while the human is at the prompt (another process can take it)', { skip }, async (t) => {
  const r = await rig(t);
  let lockFree: boolean | null = null;
  let waited = false;
  const code = await r.run(['sync', 'join', SSH_URL], {
    tty: true,
    ask: async () => {
      // `waitMs: 0` = one attempt: if the CLI held D across the prompt this would throw LOCKED
      lockFree = await withDeviceLock(r.dir, async () => true, { waitMs: 0 }).catch(() => false);
      waited = true;
      return FP2; // refuse
    },
  });
  assert.equal(code, 6);
  assert.ok(waited);
  assert.equal(lockFree, true, 'D was free during the prompt');
  // and structurally: this module takes no lock of its own at all
  const src = await readFile(new URL('./sync-enrol.ts', import.meta.url), 'utf8');
  assert.ok(!/withDeviceLock|device\.lock|lockLayout/.test(src.replace(/\/\*[\s\S]*?\*\//g, '')));
  assert.ok(!/\.git\/config|'config'/.test(src.replace(/\/\*[\s\S]*?\*\//g, '')), 'never reads .git/config');
});

test('an unexpected (non-Enrol) error is "internal error", exit 1: its text, path and URL never reach a stream', { skip }, async (t) => {
  const r = await rig(t);
  const code = await r.run(['sync', 'join', SSH_URL, '--host-fp', FP, '--root-fp', FP], {
    seams: {
      scan: async () => {
        throw new Error(`boom ${SECRET_URL} /Users/someone/.ssh/id_ed25519`);
      },
    },
  });
  assert.equal(code, 1);
  assert.equal(r.err.join('\n'), 'ledger: internal error');
  noLeak(r.all());
  assert.ok(!r.all().includes('/Users/'));
});

/* ---------------- abort ---------------- */

test('--abort: removes the marker without a terminal; nothing to abort is a plain 0; a bare --continue without a marker is exit 2', { skip }, async (t) => {
  // plant a marker the same way the flow does, via a crash AFTER the marker is written
  const r2 = await rig(t);
  const code = await r2.run(['sync', 'join', SSH_URL, '--host-fp', FP, '--root-fp', FP], {
    seams: {
      scan: async () => {
        throw new EnrolCrash('after-marker'); // the process "dies" after the `start` marker was written
      },
    },
  });
  assert.equal(code, 1, 'a crash is an internal error to the CLI');
  const markerPath = join(r2.dir, '.hub', 'sync', 'enrol.json');
  assert.ok(await lstat(markerPath).catch(() => null), 'the marker survived the crash');
  assert.equal(await r2.run(['sync', 'join', SSH_URL, '--host-fp', FP, '--root-fp', FP], { hubRunning: true }), 2);
  assert.equal(await r2.run(['sync', 'join', '--abort']), 0, 'abort needs no terminal and no fingerprint');
  assert.match(r2.out.at(-1) ?? '', /enrolment aborted/);
  assert.equal(await lstat(markerPath).catch(() => null), null, 'marker removed');
  assert.ok(await lstat(join(r2.dir, '.hub')).catch(() => null), 'only the marker / sync.yml are removed, the private dir stays');
  assert.equal(await r2.run(['sync', 'init', '--abort']), 0);
  assert.equal(r2.out.at(-1), 'nothing to abort');
  noLeak(r2.all());

  // continuing without anything in progress
  const r3 = await rig(t);
  assert.equal(await r3.run(['sync', 'join', '--continue']), 4, 'D5: --add-commit is mandatory');
  assert.match(r3.err.join('\n'), /--continue requires --add-commit/);
  assert.equal(await r3.run(['sync', 'join', '--continue', '--add-commit', 'a'.repeat(40)]), 2);
  assert.match(r3.err.join('\n'), /no enrolment in progress/);
});
