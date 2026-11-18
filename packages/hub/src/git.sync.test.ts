/** F3b B3b: `LedgerGit.commit()` is the S1 secret-leak gate and, with sync on, the signer. Pins `CommitOutcome`,
 *  the APPLY marker guard, `runExclusive`/`commitNow`, the widened `.hub` S1 check, the pathspec exclude (an
 *  UNVERIFIED git behaviour, measured here), signed sync commits and `maybePush` off (docs/f3b-b3-plan.md §1.6). */

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { generateKeyPair, publicKeyOf, resolveSshKeygen } from '@agent-ledger/shared';
import {
  LedgerGit,
  git,
  isHubPath,
  onlyHubIgnoredNotice,
  type CommitOutcome,
  type LedgerGitOptions,
  type SyncCommitIdentity,
} from './git.ts';
import { verifyCommitSignature } from './sync/sigverify.ts';

const posix = process.platform !== 'win32';
const skip = posix ? false : 'POSIX only (ssh-keygen, modes)';

type After = { after: (fn: () => unknown) => void };

interface Fx {
  dir: string;
  lg: LedgerGit;
  logs: string[];
  journal: string[][];
  marker: string;
  /** Test seam: the live options object (sync / syncCommit are flipped per case). */
  opts: LedgerGitOptions;
  head(): Promise<string>;
  commit(): Promise<CommitOutcome>;
}

async function fixture(t: After, over: Partial<LedgerGitOptions> = {}, o: { gitignore?: string } = {}): Promise<Fx> {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'agl-b3b-'));
  await chmod(dir, 0o700);
  await mkdir(join(dir, '.hub', 'sync'), { recursive: true, mode: 0o700 });
  const must = async (args: string[]): Promise<void> => {
    const r = await git(dir, args);
    assert.equal(r.code, 0, `${args.join(' ')}: ${r.stderr}`);
  };
  await must(['init', '-q', '-b', 'main']);
  await must(['config', 'user.email', 'test@agent-ledger.local']);
  await must(['config', 'user.name', 'agent-ledger test']);
  await must(['config', 'commit.gpgsign', 'false']);
  await writeFile(join(dir, '.gitignore'), o.gitignore ?? '.hub/\n');
  const logs: string[] = [];
  const journal: string[][] = [];
  const marker = join(dir, '.hub', 'sync', 'inflight.json');
  const opts: LedgerGitOptions = {
    root: dir,
    commitDebounceMs: 3_600_000,
    pushIntervalMs: 0,
    push: false,
    log: (l) => logs.push(l),
    journal: async (type, fields) => {
      journal.push([type, ...fields]);
    },
    scanStaged: async () => ({ scanner: null, blocked: false, note: null }),
    inflightMarker: marker,
    ...over,
  };
  const lg = new LedgerGit(opts);
  await lg.init();
  t.after(async () => {
    await lg.close().catch(() => undefined);
    await rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  return {
    dir,
    lg,
    logs,
    journal,
    marker,
    opts,
    head: async () => (await git(dir, ['rev-parse', 'HEAD'])).stdout.trim(),
    commit: () => lg.runExclusive((x) => x.commitNow()),
  };
}

async function writeTracked(fx: Fx, name = 'a.md', text = 'x\n'): Promise<void> {
  await writeFile(join(fx.dir, name), text);
}

async function seed(fx: Fx): Promise<string> {
  await writeTracked(fx, 'seed.md', 'seed\n');
  assert.equal(await fx.commit(), 'committed');
  return fx.head();
}

async function hashBlob(dir: string, text: string): Promise<string> {
  const p = join(dir, '.blob-tmp');
  await writeFile(p, text);
  const r = await git(dir, ['hash-object', '-w', '--no-filters', p]);
  await rm(p, { force: true });
  assert.equal(r.code, 0, r.stderr);
  return r.stdout.trim();
}

/** ssh key + matching `SyncCommitIdentity`. */
async function identity(dir: string): Promise<{ who: SyncCommitIdentity; keyFile: string; line: string }> {
  const keyDir = join(dir, '.hub', 'device');
  await mkdir(keyDir, { recursive: true, mode: 0o700 });
  await chmod(keyDir, 0o700);
  const keyFile = join(keyDir, 'key');
  const bin = await resolveSshKeygen();
  await generateKeyPair(keyFile, bin);
  const pub = await publicKeyOf(keyFile, bin);
  return {
    keyFile,
    line: pub.line,
    who: {
      label: 'hub1',
      deviceId: pub.deviceId,
      signing: { sshKeygenBin: bin, keyFile, allowedSignersFile: join(dir, '.hub', 'allowed_signers') },
    },
  };
}

async function headRaw(dir: string): Promise<Buffer> {
  const r = await git(dir, ['cat-file', 'commit', 'HEAD']);
  assert.equal(r.code, 0, r.stderr);
  return Buffer.from(r.stdout, 'utf8');
}

async function until(cond: () => Promise<boolean>, ms = 4_000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail('condition not reached in time');
}

/* ---------------- CommitOutcome ---------------- */

test('CommitOutcome: clean / committed / deferred / held (scanner)', async (t) => {
  let gate = true;
  let finding = false;
  const fx = await fixture(t, {
    heavyAllowed: () => gate,
    heavyRetryInMs: () => 3_600_000,
    scanStaged: async () =>
      finding ? { scanner: 'gitleaks', blocked: true, note: 'finding' } : { scanner: null, blocked: false, note: null },
  });
  await seed(fx);
  assert.equal(await fx.commit(), 'clean');

  await writeTracked(fx);
  gate = false;
  assert.equal(await fx.commit(), 'deferred', 'wake gate');
  gate = true;
  finding = true;
  assert.equal(await fx.commit(), 'held', 'scanner finding');
  finding = false;
  assert.equal(await fx.commit(), 'committed');
  assert.equal(await fx.commit(), 'clean');
});

test('CommitOutcome: inconclusive scan → deferred', async (t) => {
  const fx = await fixture(t, {
    scanStaged: async () => ({ scanner: null, blocked: true, retryable: true, note: 'timeout' }),
  });
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'deferred');
});

test('CommitOutcome: error when git cannot answer after add (A8-3 shape)', async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  await writeTracked(fx);
  const head = await fx.head();
  const obj = join(fx.dir, '.git', 'objects', head.slice(0, 2), head.slice(2));
  const saved = await readFile(obj);
  await chmod(obj, 0o644);
  await writeFile(obj, 'garbage\n');
  try {
    assert.equal(await fx.commit(), 'error');
  } finally {
    await writeFile(obj, saved);
  }
  assert.equal(await fx.commit(), 'committed', 'recovers after the repair');
});

test('CommitOutcome: disabled git branch → held', async (t) => {
  const fx = await fixture(t);
  (fx.lg as unknown as { enabled: boolean }).enabled = false;
  assert.equal(await fx.commit(), 'held');
});

/* ---------------- marker guard ---------------- */

for (const sync of [false, true]) {
  test(`marker blocks commit, sync=${String(sync)}; summaries and worktree kept; lifts when removed`, { skip }, async (t) => {
    const fx = await fixture(t, { sync, syncCommit: () => null });
    const before = await seed(fx);
    await writeTracked(fx, 'half-applied.md');
    fx.lg.touch('pending summary');
    await writeFile(fx.marker, '{}');

    assert.equal(await fx.commit(), 'inflight');
    assert.equal(await fx.head(), before, 'no commit while the marker exists');
    assert.equal(fx.lg.status.pendingSummaries, 1, 'summary kept');
    assert.equal((await git(fx.dir, ['diff', '--cached', '--name-only'])).stdout, '', 'nothing staged either');
    assert.ok(fx.logs.some((l) => /sync apply is in flight/.test(l)));

    await rm(fx.marker);
    assert.equal(await fx.commit(), 'committed');
    assert.match((await git(fx.dir, ['log', '-1', '--format=%s'])).stdout, /pending summary/);
  });
}

test('marker guard runs BEFORE the S1 check: no lockdown, no rotation while it exists', { skip }, async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  let rotations = 0;
  fx.lg.setTokenLeakHandler(async () => {
    rotations += 1;
    return true;
  });
  await writeFile(join(fx.dir, '.hub', 'token'), 'fake-token\n');
  await git(fx.dir, ['add', '-f', '.hub/token']);
  await writeFile(fx.marker, '{}');
  assert.equal(await fx.commit(), 'inflight');
  assert.equal(rotations, 0);
  assert.equal(fx.lg.status.securityHold, null);
});

test('marker that is a dangling symlink still blocks (lstat, fail-closed)', { skip }, async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  await writeTracked(fx);
  await symlink('/nonexistent/target', fx.marker);
  assert.equal(await fx.commit(), 'inflight');
});

test('no marker option: commit works as before (default LedgerGit users)', async (t) => {
  const fx = await fixture(t);
  delete fx.opts.inflightMarker;
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
});

/* ---------------- runExclusive / commitNow ---------------- */

test('runExclusive serialises against a timer/flush; commitNow is inline (no deadlock)', async (t) => {
  const fx = await fixture(t);
  const before = await seed(fx);
  await writeTracked(fx);
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let inside = false;
  const job = fx.lg.runExclusive(async (x) => {
    inside = true;
    await gate;
    return x.commitNow();
  });
  while (!inside) await new Promise((r) => setTimeout(r, 5));
  const flushed = fx.lg.flush();
  await new Promise((r) => setTimeout(r, 150));
  assert.equal(await fx.head(), before, 'flush queues behind the exclusive section');
  release();
  assert.equal(await job, 'committed');
  await flushed;
  assert.notEqual(await fx.head(), before);
});

test('runExclusive: a rejecting fn rejects but never breaks the chain; nested flush/close/runExclusive throw instead of deadlocking', async (t) => {
  const fx = await fixture(t);
  await assert.rejects(
    fx.lg.runExclusive(async () => {
      throw new Error('boom');
    }),
    /boom/,
  );
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed', 'chain alive');

  await fx.lg.runExclusive(async () => {
    assert.throws(() => fx.lg.flush(), /would deadlock/);
    assert.throws(() => void fx.lg.runExclusive(async () => 1), /would deadlock/);
    await assert.rejects(fx.lg.close(), /would deadlock/);
  });
  // and the chain is still alive after those refusals
  await writeTracked(fx, 'b.md');
  assert.equal(await fx.commit(), 'committed');
});

test('commitNow after the section ended is refused', async (t) => {
  const fx = await fixture(t);
  let leaked: { commitNow(): Promise<CommitOutcome> } | null = null;
  await fx.lg.runExclusive(async (x) => {
    leaked = x;
  });
  assert.ok(leaked);
  await assert.rejects((leaked as { commitNow(): Promise<CommitOutcome> }).commitNow(), /after the exclusive section/);
});

test('a timer armed INSIDE runExclusive still fires its flush afterwards', async (t) => {
  const fx = await fixture(t, { commitDebounceMs: 30 });
  await seed(fx);
  const before = await fx.head();
  await fx.lg.runExclusive(async () => {
    await writeTracked(fx, 'from-timer.md');
    fx.lg.touch('armed inside');
  });
  await until(async () => (await fx.head()) !== before);
});

test('a continuation born inside runExclusive may call runExclusive/flush after the section ended (B3-M2)', async (t) => {
  const fx = await fixture(t);
  fx.lg.setOnCommitted(() => undefined);
  await seed(fx);
  let later!: Promise<unknown>;
  await fx.lg.runExclusive(async () => {
    later = new Promise<void>((resolve) => setTimeout(resolve, 20)).then(async () => {
      await fx.lg.runExclusive(async () => 'ok');
      await fx.lg.flush();
      return 'survived';
    });
  });
  assert.equal(await later, 'survived');
});

test('onCommitted runs outside the exclusive context: work it schedules may use flush()/runExclusive() later', async (t) => {
  let later: Promise<unknown> = Promise.resolve();
  let hooked = 0;
  const fx = await fixture(t);
  fx.lg.setOnCommitted(() => {
    hooked += 1;
    assert.doesNotThrow(() => void fx.lg.flush().catch(() => undefined));
    later = new Promise<void>((resolve) => setTimeout(resolve, 20)).then(() => fx.lg.runExclusive(async () => 1));
  });
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  assert.equal(hooked, 1);
  assert.equal(await later, 1);
});

/* ---------------- add exit 1: judged by status, not by English stderr ---------------- */

type Stage = { code: number; stdout: string; stderr: string };
function stubStageAll(fx: Fx, wrap: (real: Stage) => Stage, skipReal = false): void {
  const lg = fx.lg as unknown as { stageAll(ex: string): Promise<Stage> };
  const real = lg.stageAll.bind(lg);
  lg.stageAll = async (ex: string) => (skipReal ? wrap({ code: 0, stdout: '', stderr: '' }) : wrap(await real(ex)));
}

test('add exit 1 + the .hub notice + an EXTRA warning line, worktree settled → committed (not a permanent error)', async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  await writeFile(join(fx.dir, '.hub', 'sync', 'x'), 'k\n');
  await writeTracked(fx);
  stubStageAll(fx, (r) => ({
    code: 1,
    stdout: r.stdout,
    stderr: `warning: adding embedded git repository: sub\nThe following paths are ignored by one of your .gitignore files:\n.hub\nhint: Use -f.\n`,
  }));
  assert.equal(await fx.commit(), 'committed');
  const files = (await git(fx.dir, ['ls-files'])).stdout.split('\n').filter((l) => l !== '');
  assert.deepEqual(files.filter(isHubPath), []);
  assert.ok(files.includes('a.md'));
});

test('add exit 1 with a settled clean worktree → clean; with `error:`/`fatal:` or an unstaged file → error, never clean', async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  stubStageAll(fx, (r) => ({ ...r, code: 1, stderr: 'warning: something new\n' }));
  assert.equal(await fx.commit(), 'clean', 'nothing to commit and status settled');

  await writeTracked(fx);
  stubStageAll(fx, () => ({ code: 1, stdout: '', stderr: 'warning: partial\n' }), true); // add staged NOTHING
  assert.equal(await fx.commit(), 'error', 'untracked file still outside the index');

  stubStageAll(fx, (r) => ({ ...r, code: 1, stderr: 'error: unable to index file x\n' }));
  assert.equal(await fx.commit(), 'error');
});

test('git() runs with LC_ALL=C / LANGUAGE=C (stderr notices are English)', async (t) => {
  const fx = await fixture(t);
  const r = await git(fx.dir, ['-c', 'alias.envdump=!env', 'envdump']);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /^LC_ALL=C$/m);
  assert.match(r.stdout, /^LANGUAGE=C$/m);
});

/* ---------------- widened S1: other .hub paths ---------------- */

test('isHubPath: case, dots/spaces, quoting; not token-only; not look-alikes', () => {
  for (const p of ['.hub/x', '.hub', '.HUB/Device/key', '.Hub/token', '.hub./x', '.hub /x', '".hub/\\303\\251"']) {
    assert.equal(isHubPath(p), true, p);
  }
  for (const p of ['hub/x', '.hubx/x', 'a/.hub/x', '', '.gitignore']) assert.equal(isHubPath(p), false, p);
});

for (const [label, path] of [
  ['lower-case', '.hub/x'],
  ['upper-case variant', '.HUB/Device/key'],
  ['quoted non-ASCII', '.hub/é'],
] as const) {
  test(`force-added ${label} .hub path → unsafe hold, NO token rotation, no commit; lifts when untracked`, { skip }, async (t) => {
    const fx = await fixture(t);
    const before = await seed(fx);
    let rotations = 0;
    fx.lg.setTokenLeakHandler(async () => {
      rotations += 1;
      return true;
    });
    const h = await hashBlob(fx.dir, 'not a secret\n');
    const added = await git(fx.dir, ['update-index', '--add', '--cacheinfo', `100644,${h},${path}`]);
    assert.equal(added.code, 0, added.stderr);
    await writeTracked(fx);

    assert.equal(await fx.commit(), 'held');
    assert.equal(await fx.head(), before);
    assert.equal(fx.lg.status.securityHold?.kind, 'unsafe');
    assert.equal(rotations, 0, 'not the token: no rotation');
    assert.ok(fx.journal.some((j) => j[0] === 'security' && j[1] === 's1.hold' && j[2] === '.hub/**'));
    assert.equal(await fx.commit(), 'held', 'hold persists while it is in the index');

    await git(fx.dir, ['rm', '-q', '--cached', '--', path]);
    assert.equal(await fx.commit(), 'committed');
    assert.equal(fx.lg.status.securityHold, null);
  });
}

test('tracked (committed) .hub path is an unsafe hold too', { skip }, async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  await writeFile(join(fx.dir, '.hub', 'sync', 'state.json'), '{}\n');
  await git(fx.dir, ['add', '-f', '.hub/sync/state.json']);
  assert.equal((await git(fx.dir, ['commit', '-q', '-m', 'oops'])).code, 0);
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'held');
  assert.equal(fx.lg.status.securityHold?.kind, 'unsafe');
});

test('a tracked token keeps the leak flow (rotation) even with other .hub paths present', { skip }, async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  let rotations = 0;
  fx.lg.setTokenLeakHandler(async () => {
    rotations += 1;
    return true;
  });
  await writeFile(join(fx.dir, '.hub', 'token'), 'fake\n');
  await writeFile(join(fx.dir, '.hub', 'other'), 'x\n');
  await git(fx.dir, ['add', '-f', '.hub/token', '.hub/other']);
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'held');
  assert.equal(fx.lg.status.securityHold?.kind, 'leak');
  assert.equal(rotations, 1);
});

test('a non-token .hub finding does not overwrite an active leak hold', { skip }, async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  fx.lg.setTokenLeakHandler(async () => true);
  await writeFile(join(fx.dir, '.hub', 'token'), 'fake\n');
  await git(fx.dir, ['add', '-f', '.hub/token']);
  assert.equal(await fx.commit(), 'held');
  assert.equal(fx.lg.status.securityHold?.kind, 'leak');
  await git(fx.dir, ['rm', '-q', '--cached', '.hub/token']);
  const h = await hashBlob(fx.dir, 'y\n');
  await git(fx.dir, ['update-index', '--add', '--cacheinfo', `100644,${h},.hub/other`]);
  assert.equal(await fx.commit(), 'held');
  assert.equal(fx.lg.status.securityHold?.kind, 'leak', 'leak proof (rotation, history) is not downgraded');
});

/* ---------------- pathspec exclude (UNVERIFIED git behaviour, pinned) ---------------- */

async function scratchRepo(t: After, gitignore: boolean): Promise<string> {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'agl-b3b-ps-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  assert.equal((await git(dir, ['init', '-q', '-b', 'main'])).code, 0);
  if (gitignore) await writeFile(join(dir, '.gitignore'), '.hub/\n');
  await writeFile(join(dir, 'a.md'), 'a\n');
  for (const d of ['.hub', '.HUB', '.Hub']) {
    await mkdir(join(dir, d), { recursive: true });
    await writeFile(join(dir, d, 'secret'), 'k\n');
  }
  return dir;
}

async function stagedNames(dir: string): Promise<string[]> {
  return (await git(dir, ['diff', '--cached', '--name-only'])).stdout.split('\n').filter((l) => l !== '');
}

for (const spec of [':(exclude,icase).hub', ':(exclude).hub']) {
  test(`pathspec ${spec}: add -A never stages .hub (no .gitignore to help)`, async (t) => {
    const dir = await scratchRepo(t, false);
    const r = await git(dir, ['add', '-A', '--', '.', spec]);
    assert.equal(r.code, 0, `this git rejects ${spec}: ${r.stderr}`);
    const names = await stagedNames(dir);
    assert.ok(names.includes('a.md'));
    if (spec.includes('icase')) assert.deepEqual(names.filter(isHubPath), [], 'icase exclude covers every case variant');
    else assert.ok(!names.includes('.hub/secret'), 'case-sensitive exclude still covers the real .hub');
  });
}

test('pathspec exclude + a .gitignore that lists .hub: git stages the rest but exits 1 with ONLY the ignored-notice', async (t) => {
  const dir = await scratchRepo(t, true);
  const r = await git(dir, ['add', '-A', '--', '.', ':(exclude,icase).hub']);
  // Measured on git 2.54: exit 1 + notice. A git that exits 0 is fine too; anything else is not.
  assert.ok(r.code === 0 || (r.code === 1 && onlyHubIgnoredNotice(r.stderr)), `unexpected: ${r.code} ${r.stderr}`);
  const names = await stagedNames(dir);
  assert.ok(names.includes('a.md') && names.includes('.gitignore'));
  assert.deepEqual(names.filter(isHubPath), []);
});

test('onlyHubIgnoredNotice accepts only the exact notice for .hub paths', () => {
  const head = 'The following paths are ignored by one of your .gitignore files:';
  assert.equal(onlyHubIgnoredNotice(`${head}\n.hub\nhint: Use -f if you really want to add them.\n`), true);
  assert.equal(onlyHubIgnoredNotice(`${head}\n.hub\n.HUB\n`), true);
  assert.equal(onlyHubIgnoredNotice(`${head}\nbuild\n`), false, 'another ignored path is not ours');
  assert.equal(onlyHubIgnoredNotice(`${head}\n.hub\nerror: unable to index file 'x'\n`), false);
  assert.equal(onlyHubIgnoredNotice('fatal: pathspec magic not supported\n'), false);
  assert.equal(onlyHubIgnoredNotice(''), false);
});

test('commit(): .hub never reaches the index; the case-sensitive fallback pathspec also commits', async (t) => {
  for (const icase of [true, false]) {
    const fx = await fixture(t);
    (fx.lg as unknown as { icaseExclude: boolean }).icaseExclude = icase;
    await writeFile(join(fx.dir, '.hub', 'device-note'), 'k\n');
    await writeTracked(fx);
    assert.equal(await fx.commit(), 'committed', `icase=${String(icase)}`);
    const files = (await git(fx.dir, ['ls-files'])).stdout.split('\n').filter((l) => l !== '');
    assert.deepEqual(files.filter(isHubPath), []);
    assert.ok(files.includes('a.md'));
  }
});

test('a worktree dirty only inside .hub is clean (never reported dirty, never staged)', async (t) => {
  const fx = await fixture(t);
  await seed(fx);
  await writeFile(join(fx.dir, '.hub', 'sync', 'state.json'), '{"x":1}\n');
  assert.equal(await fx.commit(), 'clean');
});

/* ---------------- signed sync commits ---------------- */

test('sync commit is signed by the device key and made as that device', { skip }, async (t) => {
  const fx = await fixture(t);
  const id = await identity(fx.dir);
  fx.opts.sync = true;
  fx.opts.syncCommit = () => id.who;
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');

  const raw = await headRaw(fx.dir);
  const v = await verifyCommitSignature(raw, { tmpRoot: join(fx.dir, '.hub', 'sync') });
  assert.equal(v.valid, true, v.reason);
  assert.ok(v.pubkeyLine?.includes(id.line.split(' ')[1] as string), 'signed by THIS device key');
  const who = (await git(fx.dir, ['log', '-1', '--format=%cn <%ce>|%an <%ae>'])).stdout.trim();
  const expect = `hub1 <${id.who.deviceId}@devices.agent-ledger.invalid>`;
  assert.equal(who, `${expect}|${expect}`);
});

test('sync: missing key → error, NO commit, NO unsigned fallback, summary kept; works again once the key is back', { skip }, async (t) => {
  const fx = await fixture(t);
  const before = await seed(fx);
  const id = await identity(fx.dir);
  fx.opts.sync = true;
  fx.opts.syncCommit = () => id.who;
  const keyBytes = await readFile(id.keyFile);
  await rm(id.keyFile);
  await writeTracked(fx);
  fx.lg.touch('needs the key');
  assert.equal(await fx.commit(), 'error');
  assert.equal(await fx.head(), before);
  assert.equal(fx.lg.status.pendingSummaries, 1);
  assert.ok(fx.logs.some((l) => /git commit failed/.test(l)));

  await writeFile(id.keyFile, keyBytes, { mode: 0o600 });
  assert.equal(await fx.commit(), 'committed');
  assert.equal((await verifyCommitSignature(await headRaw(fx.dir), { tmpRoot: join(fx.dir, '.hub', 'sync') })).valid, true);
});

test('sync: identity provider throws or returns garbage → error, nothing committed', { skip }, async (t) => {
  const fx = await fixture(t);
  const before = await seed(fx);
  fx.opts.sync = true;
  await writeTracked(fx);
  fx.opts.syncCommit = () => {
    throw new Error('device identity unreadable');
  };
  assert.equal(await fx.commit(), 'error');
  const id = await identity(fx.dir);
  for (const bad of [
    { ...id.who, deviceId: 'd_not valid\nuser.name=x' },
    { ...id.who, label: 'Bad Label' },
    { ...id.who, signing: { ...id.who.signing, keyFile: 'relative/key' } },
  ]) {
    fx.opts.syncCommit = () => bad;
    assert.equal(await fx.commit(), 'error');
  }
  assert.equal(await fx.head(), before);
});

test('sync but not enrolled (syncCommit returns null) → commits as before, unsigned', async (t) => {
  const fx = await fixture(t, { sync: true, syncCommit: () => null });
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  assert.doesNotMatch((await headRaw(fx.dir)).toString('utf8'), /gpgsig/);
});

test('sync true WITHOUT a syncCommit provider → error, nothing committed (never unsigned); sync false still commits', async (t) => {
  const fx = await fixture(t, { sync: true });
  const before = await seed0(fx);
  await writeTracked(fx);
  fx.lg.touch('needs identity');
  assert.equal(await fx.commit(), 'error');
  assert.equal(await fx.head(), before);
  assert.equal(fx.lg.status.pendingSummaries, 1);
  assert.ok(fx.logs.some((l) => /no signing identity provider/.test(l)));
  fx.opts.sync = false;
  assert.equal(await fx.commit(), 'committed', 'control: sync off commits');
});

/** HEAD of a fixture that has no commit yet (the sync fixture cannot commit before the provider exists). */
async function seed0(fx: Fx): Promise<string> {
  fx.opts.sync = false;
  await writeTracked(fx, 'seed.md', 'seed\n');
  assert.equal(await fx.commit(), 'committed');
  fx.opts.sync = true;
  return fx.head();
}

test('sync off, NOT enrolled: commits stay unsigned and use the repo identity', async (t) => {
  const fx = await fixture(t);
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  assert.doesNotMatch((await headRaw(fx.dir)).toString('utf8'), /gpgsig/);
  assert.equal((await git(fx.dir, ['log', '-1', '--format=%cn'])).stdout.trim(), 'agent-ledger test');
});

/* ---------------- AL-86: enforcement follows the ledger state, not LEDGER_SYNC ---------------- */

test('AL-86 T1 sync:false + enrolled identity → signed, verifies, made as the device', { skip }, async (t) => {
  const fx = await fixture(t);
  const id = await identity(fx.dir);
  fx.opts.sync = false;
  fx.opts.syncCommit = () => id.who;
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  const v = await verifyCommitSignature(await headRaw(fx.dir), { tmpRoot: join(fx.dir, '.hub', 'sync') });
  assert.equal(v.valid, true, v.reason);
  const em = (await git(fx.dir, ['log', '-1', '--format=%ae|%ce'])).stdout.trim();
  assert.equal(em, `${id.who.deviceId}@devices.agent-ledger.invalid|${id.who.deviceId}@devices.agent-ledger.invalid`);
});

test('AL-86 T2 sync:false + enrolled + deleted key → error, HEAD unchanged, summary kept; key back → signed', { skip }, async (t) => {
  const fx = await fixture(t);
  const before = await seed(fx);
  const id = await identity(fx.dir);
  fx.opts.sync = false;
  fx.opts.syncCommit = () => id.who;
  const keyBytes = await readFile(id.keyFile);
  await rm(id.keyFile);
  await writeTracked(fx);
  fx.lg.touch('needs the key');
  assert.equal(await fx.commit(), 'error');
  assert.equal(await fx.head(), before);
  assert.equal(fx.lg.status.pendingSummaries, 1);
  await writeFile(id.keyFile, keyBytes, { mode: 0o600 });
  assert.equal(await fx.commit(), 'committed');
  assert.equal((await verifyCommitSignature(await headRaw(fx.dir), { tmpRoot: join(fx.dir, '.hub', 'sync') })).valid, true);
});

test('AL-86 T3 provider null then identity (same process, no cache) → 1st unsigned, 2nd signed', { skip }, async (t) => {
  const fx = await fixture(t);
  const id = await identity(fx.dir);
  let who: SyncCommitIdentity | null = null;
  fx.opts.sync = false;
  fx.opts.syncCommit = () => who;
  await writeTracked(fx, 'one.md');
  assert.equal(await fx.commit(), 'committed');
  assert.doesNotMatch((await headRaw(fx.dir)).toString('utf8'), /gpgsig/);
  who = id.who;
  await writeTracked(fx, 'two.md');
  assert.equal(await fx.commit(), 'committed');
  assert.equal((await verifyCommitSignature(await headRaw(fx.dir), { tmpRoot: join(fx.dir, '.hub', 'sync') })).valid, true);
});

test('AL-86 T4 sync:false + enrolled + push:true → legacy push never runs (origin untouched), one log line', { skip }, async (t) => {
  const remote = await mkdtemp(join(await realpath(tmpdir()), 'agl-al86-remote-'));
  t.after(() => rm(remote, { recursive: true, force: true }));
  assert.equal((await git(remote, ['init', '-q', '--bare', '-b', 'main'])).code, 0);
  const fx = await fixture(t, { push: true, sync: false });
  const id = await identity(fx.dir);
  fx.opts.syncCommit = () => id.who;
  assert.equal((await git(fx.dir, ['remote', 'add', 'origin', remote])).code, 0);
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  await writeTracked(fx, 'b.md');
  assert.equal(await fx.commit(), 'committed');
  assert.equal((await git(remote, ['for-each-ref'])).stdout.trim(), '');
  assert.equal(fx.lg.status.lastPushAt, null);
  assert.equal(fx.logs.filter((l) => /legacy push disabled/.test(l)).length, 1);
});

test('AL-86 T5 provider throws (sync:false) → error, no commit, no push', { skip }, async (t) => {
  const remote = await mkdtemp(join(await realpath(tmpdir()), 'agl-al86-remote-'));
  t.after(() => rm(remote, { recursive: true, force: true }));
  assert.equal((await git(remote, ['init', '-q', '--bare', '-b', 'main'])).code, 0);
  const fx = await fixture(t, { push: true, sync: false });
  const before = await seed(fx);
  fx.opts.syncCommit = () => {
    throw new Error('enrolment state unreadable');
  };
  assert.equal((await git(fx.dir, ['remote', 'add', 'origin', remote])).code, 0);
  await writeTracked(fx, 'b.md');
  fx.lg.touch('x');
  assert.equal(await fx.commit(), 'error');
  assert.equal(await fx.head(), before);
  assert.equal(fx.lg.status.pendingSummaries, 1);
  assert.ok(fx.logs.some((l) => /signed commit refused/.test(l)));
  assert.equal((await git(remote, ['for-each-ref'])).stdout.trim(), '');
});

test('AL-86 T6 non-enrolled sync:false (provider null) → unsigned, repo identity, legacy push as before', { skip }, async (t) => {
  const remote = await mkdtemp(join(await realpath(tmpdir()), 'agl-al86-remote-'));
  t.after(() => rm(remote, { recursive: true, force: true }));
  assert.equal((await git(remote, ['init', '-q', '--bare', '-b', 'main'])).code, 0);
  const fx = await fixture(t, { push: true, sync: false, syncCommit: () => null });
  assert.equal((await git(fx.dir, ['remote', 'add', 'origin', remote])).code, 0);
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  assert.doesNotMatch((await headRaw(fx.dir)).toString('utf8'), /gpgsig/);
  assert.equal((await git(fx.dir, ['log', '-1', '--format=%cn'])).stdout.trim(), 'agent-ledger test');
  assert.match((await git(remote, ['for-each-ref'])).stdout, /refs\/heads\/main/);
});

test('onCommitted fires once per commit, never on clean; a throwing hook cannot fail the commit', async (t) => {
  let n = 0;
  const fx = await fixture(t);
  fx.lg.setOnCommitted(() => {
    n += 1;
    throw new Error('hook bug');
  });
  assert.equal(await fx.commit(), 'committed', 'the fixture .gitignore is the first commit');
  assert.equal(n, 1);
  assert.equal(await fx.commit(), 'clean');
  assert.equal(n, 1);
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  assert.equal(n, 2);
  assert.ok(fx.logs.some((l) => /onCommitted hook failed/.test(l)));
});

test('AL-51 setOnCommitted: replaces the previous hook, null removes it, a non-function is treated as null', async (t) => {
  let a = 0;
  let b = 0;
  const fx = await fixture(t);
  fx.lg.setOnCommitted(() => {
    a += 1;
  });
  assert.equal(await fx.commit(), 'committed', 'the fixture .gitignore is the first commit');
  assert.equal(a, 1);
  fx.lg.setOnCommitted(() => {
    b += 1;
  });
  await writeTracked(fx);
  assert.equal(await fx.commit(), 'committed');
  assert.deepEqual([a, b], [1, 1]);
  fx.lg.setOnCommitted(null);
  await writeFile(join(fx.dir, 'tracked2.txt'), 'two\n');
  assert.equal(await fx.commit(), 'committed');
  assert.deepEqual([a, b], [1, 1]);
  fx.lg.setOnCommitted('nope' as unknown as () => void);
  await writeFile(join(fx.dir, 'tracked3.txt'), 'three\n');
  assert.equal(await fx.commit(), 'committed');
  assert.deepEqual([a, b], [1, 1]);
});

/* ---------------- maybePush ---------------- */

test('maybePush: with sync on NEVER spawns a push (legacy path is off); with sync off it does', { skip }, async (t) => {
  for (const sync of [true, false]) {
    const remote = await mkdtemp(join(await realpath(tmpdir()), 'agl-b3b-remote-'));
    t.after(() => rm(remote, { recursive: true, force: true }));
    assert.equal((await git(remote, ['init', '-q', '--bare', '-b', 'main'])).code, 0);
    const fx = await fixture(t, { push: true, sync, syncCommit: () => null });
    assert.equal((await git(fx.dir, ['remote', 'add', 'origin', remote])).code, 0);
    await writeTracked(fx);
    assert.equal(await fx.commit(), 'committed');
    const refs = (await git(remote, ['for-each-ref'])).stdout.trim();
    if (sync) {
      assert.equal(refs, '', 'nothing pushed');
      assert.equal(fx.lg.status.lastPushAt, null);
      assert.equal(fx.logs.filter((l) => /legacy push disabled/.test(l)).length, 1);
      await writeTracked(fx, 'b.md');
      await fx.commit();
      assert.equal(fx.logs.filter((l) => /legacy push disabled/.test(l)).length, 1, 'one line only');
    } else {
      assert.match(refs, /refs\/heads\/main/, 'control: the legacy push works when sync is off');
    }
  }
});
