/** Shared helpers for the F3b B6 threat suites (docs/f3b-b6-plan.md, Step 0). TEST-ONLY: never imported by
 *  production code. Built on `testkit-remote.ts` (which is NOT modified) and the cycle.test.ts rig. */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile, readlink } from 'node:fs/promises';
import nodePath from 'node:path';
import { itemFrontmatterSchema, newItemDoc, parseDevicesYaml, renderDevicesYaml, serializeMd } from '@agent-ledger/shared';
import type { CycleDeps, CycleResult } from './cycle.ts';
import { REF_ACCEPTED, REF_INCOMING, REF_MAIN } from './gitx.ts';
import { ObjectStore } from './objects.ts';
import type { HaltState } from './state.ts';
import { cycleDeps, fakeHost, flakyRemote, makeFleet, makeKit, type FakeHost, type FlakyRemote, type Fleet, type Kit, type LedgerHub } from './testkit-remote.ts';
import { TreeBuilder } from './treebuild.ts';

/** Every real-git sync test is POSIX-gated; `LEDGER_TEST_SYNC_WIN32=1` lifts it (Windows CI, report-only). */
export const skipSync: string | false =
  process.platform === 'win32' && process.env.LEDGER_TEST_SYNC_WIN32 !== '1' ? 'POSIX-gated (LEDGER_TEST_SYNC_WIN32=1 lifts)' : false;

/* ---------------- rig (copy of cycle.test.ts:19-58) ---------------- */

export interface Rig {
  kit: Kit;
  fleet: Fleet;
  lh: LedgerHub;
  other: LedgerHub;
  hubOf(i: number): LedgerHub;
  /** Deps for hub `i` (default 0) with a scripted remote and a fake host. */
  mk(i?: number, over?: Partial<CycleDeps>): { deps: CycleDeps; flaky: FlakyRemote; host: FakeHost };
}

export async function withRig<T>(n: number, fn: (r: Rig) => Promise<T>, extra: { path: string; content: string }[] = []): Promise<T> {
  const kit = await makeKit();
  try {
    const fleet = await makeFleet(kit, n, extra);
    const hubOf = (i: number): LedgerHub => fleet.hubs[i] as LedgerHub;
    const rig: Rig = {
      kit,
      fleet,
      lh: hubOf(0),
      other: hubOf(1),
      hubOf,
      mk(i = 0, over = {}) {
        const lh = hubOf(i);
        const flaky = flakyRemote(lh.hub.gitx);
        const host = (over.host as FakeHost | undefined) ?? fakeHost(lh);
        const deps = cycleDeps(lh, kit, {
          gitx: flaky.gitx,
          store: new ObjectStore(flaky.gitx, lh.dir),
          trees: new TreeBuilder(flaky.gitx, lh.dir, nodePath.join(lh.hub.syncDir, 'tmp')),
          host,
          ...over,
        });
        return { deps, flaky, host };
      },
    };
    return await fn(rig);
  } finally {
    await kit.cleanup();
  }
}

/* ---------------- fixtures (cycle.test.ts:60-75) ---------------- */

export const ctx = (text: string): { path: string; content: string } => ({ path: 'acme/CONTEXT.md', content: text });

export const item = (id: string, title = 'a title'): string => {
  const fm = itemFrontmatterSchema.parse({ id, title, status: 'open', kind: 'BACKLOG', priority: 'P2', owner: 'agent', repo: 'acme', created: '2026-11-16T10:00:00.000Z', updated: '2026-11-16T10:00:00.000Z' });
  return serializeMd(newItemDoc(fm as never));
};

export const nowIso = (): string => new Date().toISOString().replace(/\.\d+Z$/, '.000Z');

/** `devices.yml` text of the fleet after `mutate` edited the parsed entries (the array is a fresh copy). */
export function devicesWith(fleet: Fleet, mutate: (devices: ReturnType<typeof parseDevicesYaml>['devices']) => ReturnType<typeof parseDevicesYaml>['devices']): string {
  const file = parseDevicesYaml(fleet.devicesText);
  return renderDevicesYaml({ devices: mutate(file.devices.map((d) => ({ ...d }))) });
}

/** `devices.yml` text with hub `victim` revoked by hub `by` (cycle.test.ts `revoke`). */
export function revokeText(fleet: Fleet, victim: number, by: number): string {
  const id = (fleet.hubs[victim] as LedgerHub).hub.deviceId;
  const byId = (fleet.hubs[by] as LedgerHub).hub.deviceId;
  return devicesWith(fleet, (ds) => ds.map((d) => (d.id === id ? { ...d, revoked: { at: nowIso(), by: byId, reason: 'lost' } } : d)));
}

/* ---------------- snapshot / assertUntouched ---------------- */

export interface Snapshot {
  main: string | null;
  accepted: string | null;
  incoming: string | null;
  /** `for-each-ref` output (name + object id), all refs. */
  refs: string;
  /** sha256 of `git ls-files -s -z` (index content; immune to stat-only refreshes). */
  indexHex: string;
  /** Worktree files (symlinks hashed by target), minus `.git`, `.hub/sync/tmp` and `.hub/sync/state.json`. */
  files: Map<string, string>;
  /** `state.json` text with the volatile `lastCycle` removed ('' when absent). */
  stateJson: string;
}

const sha256 = (b: Uint8Array | string): string => createHash('sha256').update(b).digest('hex');
const SKIP_DIRS = new Set(['.git', '.hub/sync/tmp']);
const SKIP_FILES = new Set(['.hub/sync/state.json']);

async function walk(root: string, rel: string, out: Map<string, string>): Promise<void> {
  const entries = await readdir(nodePath.join(root, rel), { withFileTypes: true });
  for (const e of entries) {
    const r = rel === '' ? e.name : `${rel}/${e.name}`;
    const abs = nodePath.join(root, r);
    if (SKIP_DIRS.has(r) || SKIP_FILES.has(r)) continue;
    const st = await lstat(abs);
    if (st.isSymbolicLink()) out.set(r, `symlink:${sha256(await readlink(abs))}`);
    else if (st.isDirectory()) await walk(root, r, out);
    else if (st.isFile()) out.set(r, sha256(await readFile(abs)));
  }
}

export async function snapshot(lh: LedgerHub): Promise<Snapshot> {
  const { gitx, store } = lh.hub;
  const refs = (await gitx.mustRun(['for-each-ref', '--format=%(refname) %(objectname)'], { cwd: lh.dir })).stdout.toString('utf8');
  const index = (await gitx.mustRun(['ls-files', '-s', '-z'], { cwd: lh.dir })).stdout;
  const files = new Map<string, string>();
  await walk(lh.dir, '', files);
  let stateJson = '';
  try {
    const raw = JSON.parse(await readFile(lh.state.statePath, 'utf8')) as Record<string, unknown>;
    delete raw.lastCycle;
    stateJson = JSON.stringify(raw);
  } catch {
    stateJson = '';
  }
  return {
    main: await store.revParse(REF_MAIN),
    accepted: await store.revParse(REF_ACCEPTED),
    incoming: await store.revParse(REF_INCOMING),
    refs,
    indexHex: sha256(index),
    files,
    stateJson,
  };
}

/** Nothing moved: main, accepted, refs, index, every worktree byte. `allow` exempts `incoming` (a fetch moves it)
 *  and/or `state` (a quarantine writes `halt` into state.json). */
export function assertUntouched(before: Snapshot, after: Snapshot, o: { allow?: readonly ('incoming' | 'state')[] } = {}): void {
  const allow = new Set(o.allow ?? []);
  assert.equal(after.main, before.main, 'main moved');
  assert.equal(after.accepted, before.accepted, 'accepted moved');
  if (!allow.has('incoming')) {
    assert.equal(after.incoming, before.incoming, 'incoming moved');
    assert.equal(after.refs, before.refs, 'refs changed');
  } else {
    const strip = (s: string): string => s.split('\n').filter((l) => !l.startsWith(`${REF_INCOMING} `)).join('\n');
    assert.equal(strip(after.refs), strip(before.refs), 'refs (other than incoming) changed');
  }
  assert.equal(after.indexHex, before.indexHex, 'index changed');
  const paths = new Set([...before.files.keys(), ...after.files.keys()]);
  for (const p of [...paths].sort()) assert.equal(after.files.get(p), before.files.get(p), `worktree file changed: ${p}`);
  if (!allow.has('state')) assert.equal(after.stateJson, before.stateJson, 'state.json changed');
}

/* ---------------- halts ---------------- */

export async function haltOf(lh: LedgerHub): Promise<HaltState | null> {
  return (await lh.state.read()).halt;
}

/** A quarantine happened: outcome token, `halt.tip`, `halted` reason (optionally matched by `ruleRe`), nothing applied.
 *  Optional: `o.tip` expected halt tip, `o.before` snapshot (main must not have moved), `o.flaky` (pushCalls must be 0). */
export async function assertQuarantined(
  lh: LedgerHub,
  res: CycleResult,
  ruleRe?: RegExp,
  o: { tip?: string; before?: Snapshot; flaky?: FlakyRemote } = {},
): Promise<HaltState> {
  assert.match(res.halted ?? '', /^quarantine:/, `expected a quarantine, got outcome=${res.outcome} halted=${res.halted ?? '-'}`);
  assert.ok(res.outcome === `halt:${res.halted}` || res.outcome === 'halted-same-tip' || res.outcome === 'halted', `outcome token: ${res.outcome}`);
  if (ruleRe !== undefined) assert.match(res.halted ?? '', ruleRe);
  assert.notEqual(res.applied, true, 'a quarantined tip must not be applied');
  const halt = await haltOf(lh);
  assert.ok(halt !== null, 'halt state missing');
  assert.equal(halt.reason, res.halted);
  assert.ok(halt.tip !== null, 'halt.tip missing');
  if (o.tip !== undefined) assert.equal(halt.tip, o.tip, 'halt.tip is not the hostile tip');
  assert.notEqual(await lh.hub.main(), halt.tip, 'the quarantined tip became main');
  if (o.before !== undefined) assert.equal(await lh.hub.main(), o.before.main, 'main moved');
  if (o.flaky !== undefined) assert.equal(o.flaky.pushCalls, 0, 'a quarantine must never push');
  return halt;
}

/* ---------------- leak checks ---------------- */

/** None of `needles` (non-empty strings) may appear in any of `texts`. Failure messages carry the needle INDEX only. */
export function assertNoLeak(texts: readonly string[], needles: readonly string[]): void {
  needles.forEach((n, i) => {
    assert.ok(n.length > 0, `needle #${String(i)} is empty`);
    texts.forEach((t, j) => assert.ok(!t.includes(n), `needle #${String(i)} leaked into text #${String(j)}`));
  });
}

async function readIf(p: string): Promise<string | null> {
  try {
    return await readFile(p, 'utf8');
  } catch {
    return null;
  }
}

/** Everything a hub could have written an observable line into: host logs, state.json, inflight.json, and every
 *  journal file (`<slug>/journal/*.md`) of the worktree. */
export async function collectTexts(lh: LedgerHub, host: FakeHost): Promise<string[]> {
  const texts = [...host.logs];
  for (const p of [lh.state.statePath, lh.state.inflightPath]) {
    const t = await readIf(p);
    if (t !== null) texts.push(t);
  }
  const top = await readdir(lh.dir, { withFileTypes: true });
  for (const e of top) {
    if (!e.isDirectory() || e.name === '.git' || e.name === '.hub') continue;
    const jdir = nodePath.join(lh.dir, e.name, 'journal');
    let names: string[] = [];
    try {
      names = await readdir(jdir);
    } catch {
      continue;
    }
    for (const n of names) {
      const t = await readIf(nodePath.join(jdir, n));
      if (t !== null) texts.push(t);
    }
  }
  return texts;
}

/* ---------------- modes ---------------- */

export type VerifyMode = CycleDeps['verify'];

/** Runs `fn` under verify 'warn' and then 'enforce' (sequential); a failure names the mode. */
export async function bothModes(fn: (mode: VerifyMode) => Promise<void>): Promise<void> {
  for (const mode of ['warn', 'enforce'] as const) {
    try {
      await fn(mode);
    } catch (err) {
      if (err instanceof Error) err.message = `[verify=${mode}] ${err.message}`;
      throw err;
    }
  }
}
