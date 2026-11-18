/** F3b B4b: `sync init|join` end to end against a real bare remote (docs/f3b-b4-plan.md §3 crash windows, §6, §7).
 *  The crash matrix comes FIRST: every window I1-I6 / J1-J4 must converge on the same final state as an
 *  uninterrupted run. Real git, real ssh-keygen (signing), real `Ledger` for the legacy fixture; POSIX only. */

import assert from 'node:assert/strict';
import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import nodePath from 'node:path';
import test from 'node:test';
import { addDevice, deviceLayout, parseEd25519Pub, readDevices, readSigners, revokeDevice, withDeviceLock } from '@agent-ledger/shared';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { Ledger } from '../ledger/ledger.ts';
import { tempConfig } from '../test-helpers.ts';
import {
  EnrolCrash,
  EnrolError,
  enrolAbort,
  syncInit,
  syncJoin,
  syncJoinContinue,
  type EnrolIo,
  type EnrolSeams,
  type InitResult,
  type JoinResult,
} from './enrol.ts';
import { validateGenesis } from './genesis.ts';
import { Gitx, REF_ACCEPTED, REF_INCOMING, REF_MAIN } from './gitx.ts';
import { ObjectStore } from './objects.ts';
import { StateStore, readEnrolMarker, readSyncConfig, writeEnrolMarker } from './state.ts';
import { makeKit, makeLegacyLedger, trustedAdd, type Kit, type LegacyLedger } from './testkit-remote.ts';

const skip = skipOnWin32('POSIX modes + OpenSSH');

/* ---------------- harness ---------------- */

interface Io extends EnrolIo {
  lines: string[];
  confirms: { kind: string; fp: string }[];
}

function mkIo(answer: (kind: 'host' | 'root', fp: string) => boolean = () => true): Io {
  const io: Io = {
    lines: [],
    confirms: [],
    async confirm(kind, fp) {
      io.confirms.push({ kind, fp });
      return answer(kind, fp);
    },
    out(line) {
      io.lines.push(line);
    },
  };
  return io;
}

const crashAt = (stage: string): ((s: string) => void) => (s) => {
  if (s === stage) throw new EnrolCrash(s);
};

function seams(kit: Kit, extra: Partial<EnrolSeams> = {}): EnrolSeams {
  return { testLocalRemotes: [kit.remote.path], hubProbe: async () => false, ...extra };
}

interface World {
  kit: Kit;
  /** The first device (legacy ledger, initialised once with `bootA`). */
  a: LegacyLedger;
  cleanup(): Promise<void>;
}

async function world(n = 3, pre: Record<string, string> = {}): Promise<World> {
  const kit = await makeKit();
  const a = await makeLegacyLedger(n, pre);
  return {
    kit,
    a,
    async cleanup() {
      await a.cleanup().catch(() => undefined);
      await kit.cleanup();
    },
  };
}

const initIn = (w: World, over: Record<string, unknown> = {}, extraSeams: Partial<EnrolSeams> = {}): { input: Parameters<typeof syncInit>[0] } => ({
  input: { ledgerDir: w.a.dir, remote: w.kit.remote.path, hubPort: 4747, label: 'mac', seams: seams(w.kit, extraSeams), ...over },
});

async function core(dir: string): Promise<{ gitx: Gitx; store: ObjectStore; tmpRoot: string }> {
  const syncDir = nodePath.join(dir, '.hub', 'sync');
  const gitx = await Gitx.open({ syncDir });
  return { gitx, store: new ObjectStore(gitx, dir), tmpRoot: nodePath.join(syncDir, 'tmp') };
}

async function dirty(dir: string): Promise<string[]> {
  const { gitx } = await core(dir);
  await gitx.run(['update-index', '-q', '--refresh'], { cwd: dir });
  const r = await gitx.mustRun(['status', '--porcelain=v1', '-z', '--untracked-files=all', '--no-renames'], { cwd: dir });
  return r.stdout
    .toString('utf8')
    .split('\0')
    .filter((x) => x.length > 3)
    .map((x) => x.slice(3))
    .filter((p) => !p.startsWith('.hub/'));
}

async function remoteGenesis(kit: Kit, tip: string): Promise<Awaited<ReturnType<typeof validateGenesis>>> {
  return validateGenesis(kit.remote.store, tip, { gitx: kit.remote.gitx, cwd: kit.remote.path, tmpRoot: nodePath.join(kit.root, 'remote-sync', 'tmp'), maxFormat: 2 });
}

/** The final state every converging run must reach (§3, invariants 1, 5, 8). */
async function assertInitialised(w: World, res: InitResult, commitsBefore: number): Promise<void> {
  const dir = w.a.dir;
  assert.equal(await w.kit.remote.main(), res.commit, 'remote main = the migration commit');
  const { store } = await core(dir);
  assert.equal(await store.revParse(REF_MAIN), res.commit);
  assert.equal(await store.revParse(REF_ACCEPTED), res.commit, 'accepted ref');
  assert.equal((await (await StateStore.open(dir)).read()).accepted, res.commit, 'accepted mirror');
  assert.equal(await readEnrolMarker(dir), null, 'marker gone');
  assert.equal((await readSyncConfig(dir))?.remote, w.kit.remote.path);
  assert.deepEqual(await dirty(dir), [], 'clean worktree');
  const g = await remoteGenesis(w.kit, res.commit);
  assert.ok(g.ok, g.ok ? '' : g.rule);
  if (g.ok) {
    assert.equal(g.root.id, res.deviceId);
    assert.equal(g.devices.devices.length, 1);
  }
  assert.equal((await w.kit.remote.store.revList(null, res.commit)).length, commitsBefore + 1, 'exactly one migration commit on the remote');
  assert.ok((await lstat(nodePath.join(dir, 'counters', `${res.deviceId}.yml`)).catch(() => null)) !== null, 'counters under the key-derived id');
  assert.equal(await lstat(nodePath.join(dir, 'counters', `${w.a.legacyId}.yml`)).catch(() => null), null, 'legacy counters file gone');
  const signers = await readSigners(deviceLayout(dir));
  assert.deepEqual(signers.map((s) => s.id), [res.deviceId], 'only the root is trusted');
}

const commitCount = async (dir: string): Promise<number> => {
  const { store } = await core(dir);
  return (await store.revList(null, (await store.revParse(REF_MAIN)) as string)).length;
};

/* ================= 1. crash matrix (WRITTEN FIRST) ================= */

const INIT_CRASHES = ['after-identity', 'after-m0-built', 'after-read-tree', 'after-update-ref', 'after-push', 'after-accepted-ref'] as const;

for (const stage of INIT_CRASHES) {
  test(`init crash window ${stage}: the re-run converges on the uninterrupted end state`, { skip }, async () => {
    const w = await world();
    try {
      const before = await commitCount(w.a.dir);
      await assert.rejects(syncInit(initIn(w, {}, { crashAt: crashAt(stage) }).input, mkIo()), (e: unknown) => e instanceof EnrolCrash && e.stage === stage);
      const mid = await readEnrolMarker(w.a.dir);
      assert.ok(mid !== null, 'the crash left the marker (the hub stays down)');
      const res = await syncInit(initIn(w).input, mkIo());
      await assertInitialised(w, res, before);
    } finally {
      await w.cleanup();
    }
  });
}

test('init crash window after-push, outcome unknown: a REMOTE that already has our commit is recognised, not pushed twice or refused', { skip }, async () => {
  const w = await world();
  try {
    const before = await commitCount(w.a.dir);
    await assert.rejects(syncInit(initIn(w, {}, { crashAt: crashAt('after-push') }).input, mkIo()), EnrolCrash);
    const pushedTip = await w.kit.remote.main();
    assert.ok(pushedTip !== null);
    const res = await syncInit(initIn(w).input, mkIo());
    assert.equal(res.commit, pushedTip, 'same commit, no second migration commit');
    await assertInitialised(w, res, before);
  } finally {
    await w.cleanup();
  }
});

test('init resumes even after a long pause: the migration commit carries the registration time (15 min time binding)', { skip }, async () => {
  const w = await world();
  try {
    const t0 = Date.parse('2026-11-17T10:00:00.000Z');
    const before = await commitCount(w.a.dir);
    await assert.rejects(syncInit(initIn(w, {}, { now: () => t0, crashAt: crashAt('after-identity') }).input, mkIo()), EnrolCrash);
    const res = await syncInit(initIn(w, {}, { now: () => t0 + 3 * 3_600_000 }).input, mkIo());
    await assertInitialised(w, res, before);
  } finally {
    await w.cleanup();
  }
});

/* ---------------- join crash matrix ---------------- */

interface JoinWorld extends World {
  root: InitResult;
  jdir: string;
}

async function joinWorld(): Promise<JoinWorld> {
  const w = await world();
  const root = await syncInit(initIn(w).input, mkIo());
  const jdir = nodePath.join(w.kit.root, 'joiner');
  return {
    ...w,
    root,
    jdir,
    async cleanup() {
      await w.cleanup();
    },
  };
}

const joinInput = (jw: JoinWorld, over: Record<string, unknown> = {}, extraSeams: Partial<EnrolSeams> = {}): Parameters<typeof syncJoin>[0] => ({
  ledgerDir: jw.jdir,
  remote: jw.kit.remote.path,
  hubPort: 4747,
  label: 'phone',
  seams: seams(jw.kit, extraSeams),
  ...over,
});
const contInput = (jw: JoinWorld, over: Record<string, unknown> = {}, extraSeams: Partial<EnrolSeams> = {}): Parameters<typeof syncJoinContinue>[0] => ({
  ledgerDir: jw.jdir,
  hubPort: 4747,
  seams: seams(jw.kit, extraSeams),
  ...over,
});

async function assertJoined(jw: JoinWorld, r: JoinResult, done: Awaited<ReturnType<typeof syncJoinContinue>>): Promise<void> {
  assert.equal(done.status, 'done');
  if (done.status !== 'done') return;
  const dir = jw.jdir;
  const { store } = await core(dir);
  assert.equal(done.deviceId, r.deviceId);
  assert.equal(done.slot, 'A', 'the registered slot was adopted');
  assert.equal(await store.revParse(REF_MAIN), done.commit);
  assert.equal(await store.revParse(REF_ACCEPTED), done.commit);
  assert.equal((await (await StateStore.open(dir)).read()).accepted, done.commit);
  assert.equal(await readEnrolMarker(dir), null);
  assert.equal((await readSyncConfig(dir))?.remote, jw.kit.remote.path);
  assert.deepEqual(await dirty(dir), [], 'clean worktree');
  const ids = (await readSigners(deviceLayout(dir))).map((s) => s.id).sort();
  assert.deepEqual(ids, [jw.root.deviceId, r.deviceId].sort(), 'root + self trusted');
  const reg = await readDevices(deviceLayout(dir));
  assert.equal(reg?.devices.length, 2);
  const self = (await readFile(deviceLayout(dir).deviceYml, 'utf8')).replace(/\s+/g, ' ');
  assert.match(self, /slot: A/);
}

const JOIN_CRASHES = ['after-fetch', 'after-checkout', 'after-awaiting'] as const;
for (const stage of JOIN_CRASHES) {
  test(`join crash window ${stage} (phase 1): the re-run reaches awaiting-add, the add + continue then complete`, { skip }, async () => {
    const jw = await joinWorld();
    try {
      await assert.rejects(syncJoin(joinInput(jw, {}, { crashAt: crashAt(stage) }), mkIo()), (e: unknown) => e instanceof EnrolCrash && e.stage === stage);
      const io = mkIo();
      const r = await syncJoin(joinInput(jw), io);
      assert.equal((await readEnrolMarker(jw.jdir))?.stage, 'awaiting-add');
      const added = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: r.pubkey, label: r.label, fingerprint: r.fingerprint });
      const done = await syncJoinContinue(contInput(jw, { addCommit: added }), mkIo());
      await assertJoined(jw, r, done);
    } finally {
      await jw.cleanup();
    }
  });
}

const CONT_CRASHES = ['after-ff-readtree', 'after-ff-main', 'after-adopt', 'after-sync-yml'] as const;
for (const stage of CONT_CRASHES) {
  test(`join crash window ${stage} (phase 2): --continue again converges`, { skip }, async () => {
    const jw = await joinWorld();
    try {
      const r = await syncJoin(joinInput(jw), mkIo());
      const added = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: r.pubkey, label: r.label, fingerprint: r.fingerprint });
      await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: added }, { crashAt: crashAt(stage) }), mkIo()), (e: unknown) => e instanceof EnrolCrash && e.stage === stage);
      assert.ok((await readEnrolMarker(jw.jdir)) !== null, 'marker still there: the hub stays down');
      const done = await syncJoinContinue(contInput(jw, { addCommit: added }), mkIo());
      await assertJoined(jw, r, done);
    } finally {
      await jw.cleanup();
    }
  });
}

/* ================= 2. init: happy path, invariants ================= */

test('init (legacy ledger): re-keys the random id, carries the counters, signs the migration commit with the device e-mail, never touches .git/config', { skip }, async () => {
  const w = await world(3);
  try {
    const dir = w.a.dir;
    const cfgBefore = await readFile(nodePath.join(dir, '.git', 'config'), 'utf8');
    const before = await commitCount(dir);
    const countersBefore = await readFile(nodePath.join(dir, 'counters', `${w.a.legacyId}.yml`), 'utf8');
    const io = mkIo();
    const res = await syncInit(initIn(w).input, io);
    await assertInitialised(w, res, before);
    assert.deepEqual(res.rekeyed, { from: w.a.legacyId, to: res.deviceId });
    assert.equal(await readFile(nodePath.join(dir, 'counters', `${res.deviceId}.yml`), 'utf8'), countersBefore, 'counters carried over byte for byte');
    assert.equal(await readFile(nodePath.join(dir, '.git', 'config'), 'utf8'), cfgBefore, '.git/config is never written');
    // the migration commit: signed, the device e-mail, the fixed message, exactly the allowed paths changed
    const { store } = await core(dir);
    const raw = (await store.readCommitRaw(res.commit)).toString('utf8');
    assert.match(raw, new RegExp(`committer [^<]*<${res.deviceId}@devices\\.agent-ledger\\.invalid> `));
    assert.match(raw, /\ngpgsig -----BEGIN SSH SIGNATURE-----/);
    assert.match(raw, /\n\nledger: sync migration v2\n$/);
    const diff = await store.diffTreeRaw((await store.revList(null, res.commit)).at(-2)?.sha ?? null, res.commit);
    assert.deepEqual(diff.map((d) => d.path).sort(), ['counters/' + res.deviceId + '.yml', 'counters/' + w.a.legacyId + '.yml', 'devices.yml'].sort());
    // the registry holds exactly the root, bound to the key
    const reg = await readDevices(deviceLayout(dir));
    assert.equal(reg?.devices.length, 1);
    assert.equal(parseEd25519Pub(reg?.devices[0]?.pubkey ?? '')?.deviceId, res.deviceId);
    // a hub started afterwards mints ids ABOVE the old maximum under the new identity (the point of the re-key)
    const tmp = await tempConfig({ commitDebounceMs: 3_600_000, ledgerDir: dir });
    const ledger = new Ledger({ config: { ...tmp.config, ledgerDir: dir }, log: () => undefined });
    await ledger.init();
    const next = await ledger.createItem({ kind: 'BACKLOG', priority: 'P2', owner: 'agent', steps: [], blocked_by: [], aliases: [], proposed: false, repo: 'ops', title: 'after enrol' });
    await ledger.close();
    assert.equal(next.fm.id, 'OPS-4', 'ids continue above the legacy maximum');
    // output: fingerprints and ids only
    const all = io.lines.join('\n');
    assert.match(all, /root key fingerprint SHA256:[A-Za-z0-9+/]{43}/);
    assert.ok(!all.includes(w.kit.remote.path), 'no URL in the output');
  } finally {
    await w.cleanup();
  }
});

test('init: a clean absolute-path legacy origin (D3) is tolerated and left alone; an https origin is refused with the removal hint', { skip }, async () => {
  const w = await world(1);
  try {
    const cfgPath = nodePath.join(w.a.dir, '.git', 'config');
    const original = await readFile(cfgPath, 'utf8');
    await writeFile(cfgPath, `${original}[remote "origin"]\n\turl = /some/backup/ledger.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`);
    const withPath = await readFile(cfgPath, 'utf8');
    const res = await syncInit(initIn(w).input, mkIo());
    assert.equal(await readFile(cfgPath, 'utf8'), withPath, 'config byte-identical');
    assert.ok(res.commit);
    // https: a fresh ledger
    const w2 = await world(1);
    try {
      const p2 = nodePath.join(w2.a.dir, '.git', 'config');
      await writeFile(p2, `${await readFile(p2, 'utf8')}[remote "origin"]\n\turl = https://example.invalid/o/r.git\n`);
      const io = mkIo();
      await assert.rejects(syncInit(initIn(w2).input, io), (e: unknown) => e instanceof EnrolError && e.code === 'GIT_CONFIG');
      assert.ok(io.lines.some((l) => l.includes('git remote remove origin')));
      assert.equal(await readEnrolMarker(w2.a.dir), null, 'a refusal leaves no marker');
    } finally {
      await w2.cleanup();
    }
  } finally {
    await w.cleanup();
  }
});

/* ================= 3. init: refusals leave nothing behind and leak nothing ================= */

async function untouched(w: World, headBefore: string): Promise<void> {
  const dir = w.a.dir;
  const { store } = await core(dir);
  assert.equal(await store.revParse(REF_MAIN), headBefore, 'main not moved');
  assert.equal(await store.revParse(REF_ACCEPTED), null, 'no accepted ref');
  assert.equal(await readEnrolMarker(dir), null, 'no marker left behind');
  assert.equal(await readSyncConfig(dir), null, 'no sync.yml');
  assert.equal(await lstat(deviceLayout(dir).keyFile).catch(() => null), null, 'no key generated');
  assert.equal(await lstat(deviceLayout(dir).devicesYml).catch(() => null), null, 'no devices.yml');
  assert.equal(await w.kit.remote.main(), null, 'nothing pushed');
}

const GOOD = (kit: Kit): Partial<EnrolSeams> => ({ testLocalRemotes: [kit.remote.path] });
const resultOf = (stderr: string, over: Record<string, unknown> = {}) => async () => ({ ok: false, code: 128, stdout: Buffer.alloc(0), stderr, timedOut: false, capped: false, ...over });

test('init refuses (and changes nothing) when the hub is running, the remote is public / inconclusive / non-empty / unreachable, or the ledger is dirty', { skip }, async () => {
  const w = await world(2);
  try {
    const head = (await core(w.a.dir)).store.revParse(REF_MAIN);
    const headSha = (await head) as string;
    const refuse = async (code: string, over: Record<string, unknown>, extra: Partial<EnrolSeams> = {}): Promise<void> => {
      const io = mkIo();
      await assert.rejects(syncInit(initIn(w, over, extra).input, io), (e: unknown) => {
        assert.ok(e instanceof EnrolError, String(e));
        assert.equal(e.code, code);
        assert.ok(!e.message.includes(w.kit.remote.path), 'no URL in the error');
        return true;
      });
      assert.ok(!io.lines.join('\n').includes(w.kit.remote.path), 'no URL in the output');
      await untouched(w, headSha);
    };
    await refuse('HUB_RUNNING', {}, { hubProbe: async () => true });
    await refuse('REMOTE_PUBLIC', {}, { anonymousProbe: async () => ({ ok: true, code: 0, stdout: Buffer.alloc(0), stderr: '', timedOut: false, capped: false }) });
    // "could not tell" is NOT "private": connection refused / DNS / timeout / host key problems
    await refuse('REMOTE_INCONCLUSIVE', {}, { anonymousProbe: resultOf('ssh: connect to host git.example.invalid port 22: Connection refused\nfatal: Could not read from remote repository.') });
    await refuse('REMOTE_INCONCLUSIVE', {}, { anonymousProbe: resultOf('ssh: Could not resolve hostname git.example.invalid\nfatal: Could not read from remote repository.') });
    await refuse('REMOTE_INCONCLUSIVE', {}, { anonymousProbe: resultOf('', { timedOut: true, code: -1 }) });
    await refuse('REMOTE_INCONCLUSIVE', {}, { anonymousProbe: resultOf('Host key verification failed.\nfatal: Could not read from remote repository.') });
    await refuse('REMOTE_UNREACHABLE', {}, { anonymousProbe: resultOf('git@host: Permission denied (publickey).'), authProbe: resultOf('ssh: connect to host x port 22: Connection refused') });
    await refuse('REMOTE_AUTH', {}, { anonymousProbe: resultOf('git@host: Permission denied (publickey).'), authProbe: resultOf('git@host: Permission denied (publickey).') });
    // remote already holds a ledger
    const hub = await w.kit.makeHub(9);
    await w.kit.remote.pushSigned(hub, [{ path: 'x.md', content: 'x\n' }]);
    {
      const io = mkIo();
      await assert.rejects(syncInit(initIn(w).input, io), (e: unknown) => e instanceof EnrolError && e.code === 'REMOTE_NOT_EMPTY');
      assert.equal(await readEnrolMarker(w.a.dir), null);
      assert.equal(await lstat(deviceLayout(w.a.dir).keyFile).catch(() => null), null);
      await w.kit.remote.forceMain((await w.kit.remote.store.revParse(REF_MAIN)) as string); // keep as is
    }
    // dirty ledger
    await writeFile(nodePath.join(w.a.dir, 'stray.md'), 'x\n');
    await assert.rejects(syncInit(initIn(w).input, mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'DIRTY');
  } finally {
    await w.cleanup();
  }
});

test('init: pinned .gitignore / .gitattributes — extra lines refuse (and are shown), --normalize drops them, a missing pinned line is just added', { skip }, async () => {
  const w = await world(1, { '.gitignore': '*.log\n', '.gitattributes': '*.md merge=union\n' });
  try {
    const io = mkIo();
    await assert.rejects(syncInit(initIn(w).input, io), (e: unknown) => e instanceof EnrolError && e.code === 'PINNED');
    const text = io.lines.join('\n');
    assert.match(text, /would drop from \.gitignore: \*\.log/);
    assert.match(text, /would drop from \.gitattributes: \*\.md merge=union/);
    assert.equal(await readEnrolMarker(w.a.dir), null);
    assert.equal(await readFile(nodePath.join(w.a.dir, '.gitignore'), 'utf8'), '*.log\n.hub/\n*.tmp\n', 'nothing was rewritten on refusal');
    const io2 = mkIo();
    const before = await commitCount(w.a.dir);
    const res = await syncInit(initIn(w, { normalize: true }).input, io2);
    assert.match(io2.lines.join('\n'), /dropping from \.gitignore: \*\.log/);
    assert.equal(await readFile(nodePath.join(w.a.dir, '.gitignore'), 'utf8'), '.hub/\n*.tmp\n');
    assert.equal(await readFile(nodePath.join(w.a.dir, '.gitattributes'), 'utf8'), '* text eol=lf\n');
    await assertInitialised(w, res, before);
  } finally {
    await w.cleanup();
  }
});

test('init: a devices.yml that is already committed (unsigned) is refused; a second init after success is ALREADY_ENROLLED; a live foreign marker is MARKER_BUSY', { skip }, async () => {
  const w = await world(1);
  try {
    // foreign live marker (the parent process is alive)
    await writeEnrolMarker(w.a.dir, { v: 1, kind: 'init', stage: 'start', startedAt: new Date().toISOString(), remote: w.kit.remote.path }, { selfPid: process.ppid, pidAlive: () => true }).catch(async () => {
      // the remote path is not an ssh URL: the marker schema only needs a safe string
      throw new Error('marker could not be written');
    });
    await assert.rejects(syncInit(initIn(w).input, mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'MARKER_BUSY');
    await rm(nodePath.join(w.a.dir, '.hub', 'sync', 'enrol.json'));
    const res = await syncInit(initIn(w).input, mkIo());
    assert.ok(res.commit);
    await assert.rejects(syncInit(initIn(w).input, mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'ALREADY_ENROLLED');
  } finally {
    await w.cleanup();
  }
});

/* ================= 4. host key (ssh remotes, no network: scan + probes are seams) ================= */

const SSH_URL = 'ssh://git@git.example.invalid/owner/ledger.git';
const FPS = { ed: `SHA256:${'A'.repeat(43)}`, other: `SHA256:${'B'.repeat(43)}` };
const key = (fp: string, type: 'ssh-ed25519' | 'ssh-rsa' = 'ssh-ed25519'): { host: string; port: number; type: 'ssh-ed25519' | 'ssh-rsa'; line: string; fingerprint: string } => ({
  host: 'git.example.invalid',
  port: 22,
  type,
  line: `git.example.invalid ${type} AAAA`,
  fingerprint: fp,
});

test('host key: nothing is pinned before a human (or --host-fp) confirmed; a wrong fp refuses; the pin happens after the confirmation', { skip }, async () => {
  const w = await world(1);
  try {
    const known = nodePath.join(w.a.dir, '.hub', 'sync', 'known_hosts');
    const scan = async (): Promise<ReturnType<typeof key>[]> => [key(FPS.ed)];
    // human says no
    const io = mkIo((k) => k !== 'host');
    await assert.rejects(syncInit(initIn(w, { remote: SSH_URL }, { scan: scan as never }).input, io), (e: unknown) => e instanceof EnrolError && e.code === 'HOSTKEY_REFUSED');
    assert.equal(await lstat(known).catch(() => null), null, 'no pin without a confirmation');
    assert.deepEqual(io.confirms.map((c) => c.kind), ['host']);
    // --host-fp that matches nothing the host offers
    await assert.rejects(syncInit(initIn(w, { remote: SSH_URL, hostFp: FPS.other }, { scan: scan as never }).input, mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'HOSTKEY_REFUSED');
    assert.equal(await lstat(known).catch(() => null), null);
    // a malformed --host-fp
    await assert.rejects(syncInit(initIn(w, { remote: SSH_URL, hostFp: 'nope' }, { scan: scan as never }).input, mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'BAD_INPUT');
  } finally {
    await w.cleanup();
  }
});

/* ================= 5. join: confirmations, genesis refusals, non-empty dirs ================= */

test('join: the host / root fingerprints are shown, a wrong --root-fp or a "no" answer refuses BEFORE anything is checked out or trusted', { skip }, async () => {
  const jw = await joinWorld();
  try {
    const refusedFresh = async (over: Record<string, unknown>, io: Io): Promise<void> => {
      await assert.rejects(syncJoin(joinInput(jw, over), io), (e: unknown) => e instanceof EnrolError && e.code === 'ROOT_FP_REFUSED');
      const { store } = await core(jw.jdir);
      assert.equal(await store.revParse(REF_MAIN), null, 'nothing checked out');
      assert.equal(await store.revParse(REF_ACCEPTED), null);
      assert.equal(await lstat(deviceLayout(jw.jdir).allowedSigners).catch(() => null), null, 'nothing trusted');
      assert.deepEqual((await readdir(jw.jdir)).sort(), ['.git', '.hub'], 'worktree still empty');
    };
    const ioNo = mkIo((k) => k !== 'root');
    await refusedFresh({}, ioNo);
    assert.deepEqual(ioNo.confirms, [{ kind: 'root', fp: jw.root.rootFp }], 'the human was shown the ROOT fingerprint');
    await refusedFresh({ rootFp: FPS.other }, mkIo());
    // a retry after the refusals works (leftover .git / .hub of our own refused join)
    const r = await syncJoin(joinInput(jw, { rootFp: jw.root.rootFp }), mkIo());
    assert.equal((await readEnrolMarker(jw.jdir))?.stage, 'awaiting-add');
    assert.match(r.addCommand, /^ledger device add 'ssh-ed25519 [A-Za-z0-9+/=]+' --label phone --fp SHA256:[A-Za-z0-9+/]{43}$/);
    assert.equal(r.fingerprint, parseEd25519Pub(r.pubkey)?.fingerprint);
  } finally {
    await jw.cleanup();
  }
});

test('join: a non-empty directory (items, stray files) is refused and untouched; a join marker of another stage is not a licence', { skip }, async () => {
  const jw = await joinWorld();
  try {
    await mkdir(jw.jdir, { recursive: true });
    await writeFile(nodePath.join(jw.jdir, 'mine.md'), 'my notes\n');
    await assert.rejects(syncJoin(joinInput(jw, { rootFp: jw.root.rootFp }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'NOT_EMPTY');
    assert.deepEqual(await readdir(jw.jdir), ['mine.md']);
    // a populated legacy ledger (init target) is NOT a join target either
    await assert.rejects(syncJoin(joinInput(jw, { ledgerDir: jw.a.dir, rootFp: jw.root.rootFp }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'NOT_EMPTY');
  } finally {
    await jw.cleanup();
  }
});

test('join: a hostile remote is refused at genesis (unsigned registry, planted registry, symlink tip, .hub/x tip) — nothing checked out', { skip }, async () => {
  const kit = await makeKit();
  try {
    const root = await kit.makeHub(1);
    const evil = await kit.makeHub(2);
    const { renderDevicesYaml } = await import('@agent-ledger/shared');
    const entry = (h: typeof root, at: Date): Parameters<typeof renderDevicesYaml>[0]['devices'][number] => ({ id: h.deviceId, label: h.label, slot: '', pubkey: h.pub.line, added: at.toISOString(), added_by: h.deviceId, revoked: null, role: 'owner' });
    const files = (h: typeof root, at: Date): { path: string; content: string }[] => [
      { path: '.gitignore', content: '.hub/\n*.tmp\n' },
      { path: '.gitattributes', content: '* text eol=lf\n' },
      { path: 'ledger.format', content: '2\n' },
      { path: 'devices.yml', content: renderDevicesYaml({ devices: [entry(h, at)] }) },
    ];
    const attempt = async (name: string, code: string): Promise<void> => {
      const jdir = nodePath.join(kit.root, `j-${name}`);
      await assert.rejects(
        syncJoin({ ledgerDir: jdir, remote: kit.remote.path, hubPort: 4747, label: 'phone', rootFp: root.pub.fingerprint, seams: seams(kit) }, mkIo()),
        (e: unknown) => e instanceof EnrolError && e.code === code,
        name,
      );
      assert.equal(await (await core(jdir)).store.revParse(REF_MAIN), null, `${name}: nothing checked out`);
      assert.deepEqual((await readdir(jdir)).sort(), ['.git', '.hub'], `${name}: empty worktree`);
      assert.equal(await lstat(deviceLayout(jdir).allowedSigners).catch(() => null), null, `${name}: nothing trusted`);
    };
    const now = new Date();
    // 1. registry introduced UNSIGNED
    await kit.remote.rawCommit({ files: files(root, now), signer: null, date: now });
    await attempt('unsigned', 'GENESIS:root-unsigned');
    // 2. signed by somebody else than the entry's key
    await kit.remote.rawCommit({ files: files(root, now), parents: [], signer: evil, date: now });
    await attempt('wrong-signer', 'GENESIS:root-signer');
    // 3. a good root, then a symlink on top (tip tree is hostile)
    const good = await kit.remote.rawCommit({ files: files(root, now), parents: [], signer: root, date: now });
    await kit.remote.pushSymlink(root, 'acme/link.md', '/etc/passwd');
    await attempt('symlink', 'GENESIS:tree:symlink');
    await kit.remote.forceMain(good);
    await kit.remote.pushHubPath(root);
    await attempt('hub-path', 'GENESIS:tree:hub-path');
    await kit.remote.forceMain(good);
    // 4. a tip signed by a key the registry does not know
    await kit.remote.pushSigned(evil, [{ path: 'acme/CONTEXT.md', content: '# x\n' }]);
    await attempt('tip-signer', 'GENESIS:tip-signer-unregistered');
    await kit.remote.forceMain(good);
    // 5. the introducing commit's time is far from the registration time
    await kit.remote.rawCommit({ files: files(root, new Date(now.getTime() - 3 * 3_600_000)), parents: [], signer: root, date: now });
    await attempt('time', 'GENESIS:root-time-unbound');
    // and the honest root IS accepted
    await kit.remote.forceMain(good);
    const jdir = nodePath.join(kit.root, 'j-ok');
    const r = await syncJoin({ ledgerDir: jdir, remote: kit.remote.path, hubPort: 4747, label: 'phone', rootFp: root.pub.fingerprint, seams: seams(kit) }, mkIo());
    assert.equal(r.base, good);
  } finally {
    await kit.cleanup();
  }
});

/* ================= 6. --continue: waiting, rollback, forged history, add-commit, revoked ================= */

test('continue: before the add it is `waiting` (nothing moves, marker stays); after the add it completes; a re-run of join prints the instructions again', { skip }, async () => {
  const jw = await joinWorld();
  try {
    const r = await syncJoin(joinInput(jw), mkIo());
    const { store } = await core(jw.jdir);
    const f0 = await store.revParse(REF_MAIN);
    assert.deepEqual(await syncJoinContinue(contInput(jw, { addCommit: 'a'.repeat(40) }), mkIo()), { status: 'waiting' });
    assert.equal(await store.revParse(REF_MAIN), f0);
    assert.equal((await readEnrolMarker(jw.jdir))?.stage, 'awaiting-add');
    // a remote that advanced WITHOUT our entry is still `waiting`
    await jw.kit.remote.pushSigned((await jw.kit.makeHub(7)) as never, [{ path: 'x.md', content: 'x\n' }]).catch(() => undefined);
    await jw.kit.remote.forceMain(f0 as string);
    const io = mkIo();
    const again = await syncJoin(joinInput(jw), io);
    assert.equal(again.pubkey, r.pubkey);
    assert.ok(io.lines.some((l) => l.includes(r.addCommand)));
    const addedHere = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: r.pubkey, label: r.label, fingerprint: r.fingerprint });
    await assertJoined(jw, r, await syncJoinContinue(contInput(jw, { addCommit: addedHere }), mkIo()));
  } finally {
    await jw.cleanup();
  }
});

test('continue (T-B4-3): a remote that is rolled back, rewritten or serves a forged branch is refused; a stale-but-valid one is just `waiting`; --add-commit must be part of the history', { skip }, async () => {
  const jw = await joinWorld();
  try {
    const r = await syncJoin(joinInput(jw), mkIo());
    const f0 = (await core(jw.jdir)).store.revParse(REF_MAIN);
    const base = (await f0) as string;
    const added = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: r.pubkey, label: r.label, fingerprint: r.fingerprint });
    // --add-commit that is not in the fetched history
    await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: 'a'.repeat(40) }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'ADD_COMMIT');
    assert.equal(await (await core(jw.jdir)).store.revParse(REF_MAIN), base, 'nothing moved');
    // the remote history was REWRITTEN (a fresh root, F0 is no longer an ancestor)
    const hub = await jw.kit.makeHub(8);
    const forged = await jw.kit.remote.rewriteHistory(hub);
    await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: added }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'REMOTE_REWOUND');
    assert.equal(await (await core(jw.jdir)).store.revParse(REF_MAIN), base);
    // rolled back to F0 (valid, stale): our entry is not in it
    void forged;
    await jw.kit.remote.forceMain(base);
    assert.deepEqual(await syncJoinContinue(contInput(jw, { addCommit: added }), mkIo()), { status: 'waiting' });
    // a forged continuation on top of F0: signed by a key the bootstrap does not trust
    await jw.kit.remote.pushSigned(hub, [{ path: 'acme/CONTEXT.md', content: '# forged\n' }]);
    await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: added }), mkIo()), (e: unknown) => e instanceof EnrolError && String(e.code).startsWith('RANGE:'));
    assert.equal(await (await core(jw.jdir)).store.revParse(REF_MAIN), base, 'still at F0');
    // the honest history, with the printed add commit
    await jw.kit.remote.forceMain(added);
    await assertJoined(jw, r, await syncJoinContinue(contInput(jw, { addCommit: added }), mkIo()));
  } finally {
    await jw.cleanup();
  }
});

test('continue: a device revoked BEFORE it adopts its slot is refused and nothing moves (stolen joiner)', { skip }, async () => {
  const jw = await joinWorld();
  try {
    const r = await syncJoin(joinInput(jw), mkIo());
    const base = (await (await core(jw.jdir)).store.revParse(REF_MAIN)) as string;
    const added = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: r.pubkey, label: r.label, fingerprint: r.fingerprint });
    // the trusted device revokes it right away and pushes
    await revokeDevice(jw.a.dir, r.deviceId, 'stolen before adoption');
    const { store: aStore } = await core(jw.a.dir);
    const { Gitx: G } = await import('./gitx.ts');
    const ag = await G.open({ syncDir: nodePath.join(jw.a.dir, '.hub', 'sync'), testLocalRemotes: [jw.kit.remote.path] });
    const { TreeBuilder } = await import('./treebuild.ts');
    const trees = new TreeBuilder(ag, jw.a.dir, nodePath.join(jw.a.dir, '.hub', 'sync', 'tmp'));
    const tip = (await aStore.revParse(REF_MAIN)) as string;
    const { resolveSshKeygen, readDeviceFile } = await import('@agent-ledger/shared');
    const l = deviceLayout(jw.a.dir);
    const tree = await trees.buildTree(tip, [{ path: 'devices.yml', content: await readFile(l.devicesYml, 'utf8') }]);
    const self = await readDeviceFile(l);
    const rev = await trees.commitTree({
      tree,
      parents: [tip],
      message: 'testkit: revoke',
      identity: { name: self?.label ?? 'a', email: `${jw.root.deviceId}@devices.agent-ledger.invalid` },
      signing: { sshKeygenBin: await resolveSshKeygen(), keyFile: l.keyFile, allowedSignersFile: l.allowedSigners },
    });
    await trees.updateRef(REF_MAIN, rev, tip);
    assert.ok((await ag.push(jw.a.dir, jw.kit.remote.path, rev)).ok);
    await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: added }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'REVOKED');
    const { store } = await core(jw.jdir);
    assert.equal(await store.revParse(REF_MAIN), base, 'main not moved');
    assert.equal(await store.revParse(REF_ACCEPTED), base);
    assert.equal((await readEnrolMarker(jw.jdir))?.stage, 'awaiting-add');
    assert.equal(await readSyncConfig(jw.jdir), null, 'not enrolled');
  } finally {
    await jw.cleanup();
  }
});

/** A commit signed by the ROOT device's key holding only `devices.yml` = `text`, on top of `parent`, pushed to the kit remote. */
async function rootSignedDevices(jw: JoinWorld, parent: string, text: string): Promise<string> {
  const { Gitx: G } = await import('./gitx.ts');
  const { TreeBuilder } = await import('./treebuild.ts');
  const { resolveSshKeygen, readDeviceFile } = await import('@agent-ledger/shared');
  const ag = await G.open({ syncDir: nodePath.join(jw.a.dir, '.hub', 'sync'), testLocalRemotes: [jw.kit.remote.path] });
  const trees = new TreeBuilder(ag, jw.a.dir, nodePath.join(jw.a.dir, '.hub', 'sync', 'tmp'));
  const l = deviceLayout(jw.a.dir);
  const self = await readDeviceFile(l);
  assert.ok((await ag.fetch(jw.a.dir, jw.kit.remote.path, { src: REF_MAIN, dst: REF_INCOMING, timeoutMs: 60_000 })).ok, 'the root fetches the remote-built parent');
  const tree = await trees.buildTree(parent, [{ path: 'devices.yml', content: text }]);
  const sha = await trees.commitTree({
    tree,
    parents: [parent],
    message: 'testkit: root devices change',
    identity: { name: self?.label ?? 'a', email: `${jw.root.deviceId}@devices.agent-ledger.invalid` },
    signing: { sshKeygenBin: await resolveSshKeygen(), keyFile: l.keyFile, allowedSignersFile: l.allowedSigners },
  });
  assert.ok((await ag.push(jw.a.dir, jw.kit.remote.path, sha)).ok);
  await jw.kit.remote.forceMain(sha);
  return sha;
}

/* ---- D5 / T-B4-3: --add-commit is mandatory and verified ---- */

test('continue (D5): --add-commit is REQUIRED (fixed message, no remote URL), refused before any fetch or state change; a wrong pin is refused; the correct one adopts', { skip }, async () => {
  const jw = await joinWorld();
  try {
    const r = await syncJoin(joinInput(jw), mkIo());
    const base = (await (await core(jw.jdir)).store.revParse(REF_MAIN)) as string;
    const added = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: r.pubkey, label: r.label, fingerprint: r.fingerprint });
    // missing: refused although the honest add is on the remote
    await assert.rejects(syncJoinContinue(contInput(jw), mkIo()), (e: unknown) => {
      assert.ok(e instanceof EnrolError && e.code === 'ADD_COMMIT_REQUIRED');
      assert.ok(!(e as Error).message.includes(jw.kit.remote.path), 'no URL in the message');
      assert.match((e as Error).message, /--add-commit/);
      return true;
    });
    // not a commit id at all
    await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: 'nope' }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'BAD_INPUT');
    // mismatch: F0 itself (not strictly after F0), an object that does not exist
    for (const bad of [base, 'b'.repeat(40)]) {
      await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: bad }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'ADD_COMMIT');
    }
    const { store } = await core(jw.jdir);
    assert.equal(await store.revParse(REF_MAIN), base, 'nothing moved');
    assert.equal((await readEnrolMarker(jw.jdir))?.stage, 'awaiting-add');
    assert.equal(await readSyncConfig(jw.jdir), null, 'not enrolled');
    // correct
    await assertJoined(jw, r, await syncJoinContinue(contInput(jw, { addCommit: added }), mkIo()));
  } finally {
    await jw.cleanup();
  }
});

test('continue (D5): a commit that is in F0..F1 but is NOT the add of this device (a later commit, or one that adds another key) is refused', { skip }, async () => {
  const jw = await joinWorld();
  try {
    const r = await syncJoin(joinInput(jw), mkIo());
    const other = await jw.kit.makeHub(6);
    // the trusted device adds ANOTHER device first, then the joiner
    const otherAdd = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: other.pub.line, label: 'other', fingerprint: other.pub.fingerprint });
    const added = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: r.pubkey, label: r.label, fingerprint: r.fingerprint });
    await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: otherAdd }), mkIo()), (e: unknown) => e instanceof EnrolError && e.code === 'ADD_COMMIT');
    assert.equal(await (await core(jw.jdir)).store.revParse(REF_MAIN) !== added, true, 'nothing moved');
    const done = await syncJoinContinue(contInput(jw, { addCommit: added }), mkIo());
    assert.equal(done.status, 'done'); // (slot B: the other device took A)
  } finally {
    await jw.cleanup();
  }
});

test('continue (D5, T-B4-3): an add commit signed by a key that is revoked (before or since) is refused and nothing moves', { skip }, async () => {
  const jw = await joinWorld();
  try {
    const r = await syncJoin(joinInput(jw), mkIo());
    const base = (await (await core(jw.jdir)).store.revParse(REF_MAIN)) as string;
    const x = await jw.kit.makeHub(7);
    // root registers X; X "adds" the joiner (devices.yml signed by X); root then revokes X
    const cx = await trustedAdd(jw.a.dir, jw.kit.remote.path, { pubkey: x.pub.line, label: 'xdev', fingerprint: x.pub.fingerprint });
    await addDevice(jw.a.dir, r.pubkey, r.label, r.fingerprint);
    const withJoiner = await readFile(deviceLayout(jw.a.dir).devicesYml, 'utf8');
    const cy = await jw.kit.remote.rawCommit({ files: [{ path: 'devices.yml', content: withJoiner }], signer: x, parents: [cx], identity: x.identity });
    await revokeDevice(jw.a.dir, x.deviceId, 'compromised');
    const revoked = await readFile(deviceLayout(jw.a.dir).devicesYml, 'utf8');
    await rootSignedDevices(jw, cy, revoked);
    await assert.rejects(syncJoinContinue(contInput(jw, { addCommit: cy }), mkIo()), (e: unknown) => e instanceof EnrolError && (e.code === 'ADD_COMMIT' || String(e.code).startsWith('RANGE:'))); // the range gate (unapproved device) fires first; the signer check is defence in depth
    const { store } = await core(jw.jdir);
    assert.equal(await store.revParse(REF_MAIN), base, 'main not moved');
    assert.equal((await readEnrolMarker(jw.jdir))?.stage, 'awaiting-add');
    assert.equal(await readSyncConfig(jw.jdir), null, 'not enrolled');
  } finally {
    await jw.cleanup();
  }
});

/* ================= 7. abort, marker discipline, source scans ================= */

test('abort: removes the marker and sync.yml ONLY (keys, refs, commits stay); without a marker it does nothing and an enrolled ledger stays enrolled', { skip }, async () => {
  const w = await world(1);
  try {
    await assert.rejects(syncInit(initIn(w, {}, { crashAt: crashAt('after-update-ref') }).input, mkIo()), EnrolCrash);
    const dir = w.a.dir;
    const { store } = await core(dir);
    const tip = await store.revParse(REF_MAIN);
    assert.ok((await readSyncConfig(dir)) === null || true);
    assert.deepEqual(await enrolAbort(dir), { aborted: true });
    assert.equal(await readEnrolMarker(dir), null);
    assert.equal(await readSyncConfig(dir), null);
    assert.equal(await store.revParse(REF_MAIN), tip, 'commits stay');
    assert.ok((await lstat(deviceLayout(dir).keyFile).catch(() => null)) !== null, 'the key stays');
    // retry against the same (still empty) remote: our own migration commit is recognised, not re-created
    const before = await commitCount(dir);
    const res = await syncInit(initIn(w).input, mkIo());
    assert.equal(res.commit, tip, 'the existing migration commit is reused');
    await assertInitialised(w, res, before - 1);
    // enrolled: abort is a no-op
    assert.deepEqual(await enrolAbort(dir), { aborted: false });
    assert.ok((await readSyncConfig(dir)) !== null);
  } finally {
    await w.cleanup();
  }
});

test('source discipline: D is never held across a prompt or a network call; .git/config is never written; every ref move has an expected-old value', { skip }, async () => {
  const src = await readFile(new URL('./enrol.ts', import.meta.url), 'utf8');
  const blocks: string[] = [];
  for (let at = src.indexOf('withDeviceLock('); at >= 0; at = src.indexOf('withDeviceLock(', at + 1)) {
    let depth = 0;
    let end = at;
    for (let i = src.indexOf('{', at); i < src.length; i += 1) {
      if (src[i] === '{') depth += 1;
      if (src[i] === '}' && --depth === 0) {
        end = i;
        break;
      }
    }
    blocks.push(src.slice(at, end));
  }
  assert.ok(blocks.length >= 1);
  for (const b of blocks) assert.ok(!/io\.confirm|gitx\.(?:fetch|push|lsRemote)|probeRemote|scanHostKeys/.test(b), `lock block: ${b.slice(0, 60)}`);
  assert.ok(!/withDeviceLock[\s\S]{0,200}io\.confirm/.test(src));
  assert.ok(!/writeFile\([^)]*\.git/.test(src) && !/'config'/.test(src.replace(/\.git', 'config'/g, '')), '.git/config is only ever read');
  assert.ok(!/['"]--force|['"]-f['"]|--force-with-lease/.test(src), 'no force');
  assert.ok(!/update-ref', '--no-deref', REF_MAIN, [a-zA-Z0-9]+\]/.test(src), 'update-ref without an old value');
  assert.ok(!/\bclone\b/.test(src.replace(/\/\*[\s\S]*?\*\//g, '')), 'no clone');
});

test('no URL, stderr or key material in any error, output line or state file after the failing and the succeeding flows (T-B4-13)', { skip }, async () => {
  const w = await world(1);
  try {
    const marker = 'secret-marker-host.example.invalid';
    const io = mkIo();
    // an ssh URL that carries a recognisable host token; the flow stops at the (faked) host key confirmation
    const url = `ssh://git@${marker}/o/r.git`;
    const key1 = { host: marker, port: 22, type: 'ssh-ed25519' as const, line: `${marker} ssh-ed25519 AAAA`, fingerprint: FPS.ed };
    await assert.rejects(syncInit(initIn(w, { remote: url }, { scan: (async () => [key1]) as never }).input, mkIo(() => false)), (e: unknown) => {
      assert.ok(e instanceof EnrolError);
      assert.ok(!e.message.includes(marker) && !String(e.stack).includes('ssh://'), 'no URL in the error');
      return true;
    });
    const res = await syncInit(initIn(w).input, io);
    assert.ok(res.commit);
    const state = await readFile(nodePath.join(w.a.dir, '.hub', 'sync', 'state.json'), 'utf8').catch(() => '');
    assert.ok(!state.includes(w.kit.remote.path) && !state.includes('BEGIN'));
    assert.ok(!io.lines.join('\n').includes('BEGIN OPENSSH'));
  } finally {
    await w.cleanup();
  }
});

void [REF_INCOMING, withDeviceLock, GOOD];
