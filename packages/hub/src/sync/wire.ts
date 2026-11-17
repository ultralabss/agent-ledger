/** Wiring of the sync loop into `startHub` (F3b B3c, docs/f3b-b3-plan.md §1.8; T-B3-3, T-B3-11).
 *
 *  Threat model:
 *   - Actor: a crash that left an APPLY half done (before this boot), a misconfigured hub (LEDGER_SYNC=1 without
 *     enrolment), a hub started with sync OFF after a crashed apply.
 *   - Protected: the crash replay runs BEFORE `ledger.init()` and before any writer, in every mode (also
 *     `LEDGER_SYNC=0`): `LedgerGit.commit()` would otherwise `add -A` a half-moved worktree as a revert.
 *     Without enrolment (`.hub/sync.yml`) nothing runs and nothing is contacted.
 *   - Stance: replay problems never stop the hub (the marker keeps commits paused and the cycle halts
 *     `inflight` with a token); nothing from git output reaches the log beyond tokens.
 */

import { lstat } from 'node:fs/promises';
import nodePath from 'node:path';
import { deviceEmail, deviceLayout, readSigners, resolveSshKeygen } from '@agent-ledger/shared';
import type { HubConfig } from '../config.ts';
import type { RuntimeStore } from '../db/store.ts';
import type { Ledger } from '../ledger/ledger.ts';
import { LEDGER_FORMAT } from '../ledger/device.ts';
import { replayGitPhase, replayNotesPhase, sweepSyncTmp, type DeliverNotes, type ReplayDeps, type ReplayGit } from './apply.ts';
import type { CycleDeps, CycleHost, LocalNote } from './cycle.ts';
import { Gitx } from './gitx.ts';
import { SyncLoop } from './loop.ts';
import type { ProposedItem } from './merge/tree.ts';
import { cleanText } from './notes.ts';
import { ObjectStore } from './objects.ts';
import { StateStore, readSyncConfig, type Inflight } from './state.ts';
import { TreeBuilder } from './treebuild.ts';

export interface BootReplay {
  result: ReplayGit | null;
  deps: ReplayDeps | null;
}

async function exists(p: string): Promise<boolean> {
  return (await lstat(p).catch(() => null)) !== null;
}

async function openCore(ledger: Ledger, keyFile?: string, testLocalRemotes?: readonly string[]): Promise<{ gitx: Gitx; store: ObjectStore; trees: TreeBuilder; state: StateStore }> {
  const root = ledger.paths.root;
  const syncDir = ledger.paths.syncDir;
  const state = await StateStore.open(root);
  const gitx = await Gitx.open({ syncDir, ...(keyFile === undefined ? {} : { keyFile }), ...(testLocalRemotes === undefined ? {} : { testLocalRemotes }) });
  return { gitx, store: new ObjectStore(gitx, root), trees: new TreeBuilder(gitx, root, nodePath.join(syncDir, 'tmp')), state };
}

/** Phase 1: BEFORE `ledger.init()`, regardless of `LEDGER_SYNC`. No marker = no side effect at all. */
export async function bootReplayGit(ledger: Ledger, log: (line: string) => void): Promise<BootReplay> {
  try {
    if (!(await exists(ledger.paths.inflightMarker))) return { result: null, deps: null };
    const core = await openCore(ledger);
    await sweepSyncTmp(ledger.paths.root).catch(() => 0);
    const deps: ReplayDeps = { ledgerDir: ledger.paths.root, ...core };
    const result = await replayGitPhase(deps);
    log(`sync: boot replay of an interrupted apply -> ${result.kind}${result.kind === 'halt' ? ` (${result.reason})` : ''}`);
    return { result, deps };
  } catch {
    log('sync: boot replay failed — commits stay paused, the sync cycle halts `inflight`');
    return { result: null, deps: null };
  }
}

/** The inbox + lease side effects of a delivery (idempotent per row: at-least-once is fine). */
export function makeDeliver(store: RuntimeStore, log: (line: string) => void): (n: DeliverNotes) => Promise<void> {
  return async (n) => {
    for (const m of n.inbox) {
      try {
        store.addInbox({ to_session: m.to_session, from_session: null, repo: m.repo, item_id: m.item_id, body: m.body, origin: 'hub' });
      } catch {
        log('sync: an inbox note could not be stored');
      }
    }
    for (const r of n.releaseLeases) {
      try {
        store.releaseLeases({ item: r.item, session: r.session, kind: 'claim' });
      } catch {
        log('sync: a lease release failed');
      }
    }
  };
}

/** Phase 2: after the RuntimeStore is up, before `listen`. Delivers the marker's notes and deletes the marker. */
export async function bootReplayNotes(boot: BootReplay, store: RuntimeStore, log: (line: string) => void): Promise<void> {
  if (boot.result === null || boot.deps === null || boot.result.kind !== 'forward') return;
  const marker: Inflight = boot.result.marker;
  try {
    await replayNotesPhase({ deliver: makeDeliver(store, log), log }, boot.deps, marker);
    log('sync: interrupted apply completed');
  } catch {
    log('sync: notes of an interrupted apply could not be delivered — the marker is kept');
  }
}

/** `LEDGER_SYNC=1` and enrolled (`.hub/sync.yml`): build the loop. Otherwise `null` (staying local). */
export async function startSync(o: {
  ledger: Ledger;
  store: RuntimeStore;
  config: HubConfig;
  log: (line: string) => void;
  start: boolean;
  /** Tests only: exact local paths accepted as remote (never read from env). */
  testLocalRemotes?: readonly string[];
}): Promise<SyncLoop | null> {
  const { ledger, store, config, log } = o;
  if (!config.sync) return null;
  let cfg;
  try {
    cfg = await readSyncConfig(ledger.paths.root);
  } catch {
    log('sync: LEDGER_SYNC=1 but .hub/sync.yml is unreadable — staying local');
    return null;
  }
  if (cfg === null) {
    log('sync: LEDGER_SYNC=1 but this ledger is not enrolled (no .hub/sync.yml) — staying local');
    return null;
  }
  try {
    const layout = deviceLayout(ledger.paths.root);
    const deployKey = nodePath.join(ledger.paths.syncDir, 'deploy_key');
    await sweepSyncTmp(ledger.paths.root).catch(() => 0);
    const core = await openCore(ledger, (await exists(deployKey)) ? deployKey : undefined, o.testLocalRemotes);
    const device = ledger.device;
    const signing = { sshKeygenBin: await resolveSshKeygen(), keyFile: layout.keyFile, allowedSignersFile: layout.allowedSigners };
    const host: CycleHost = {
      runExclusive: (fn) => ledger.git.runExclusive(fn),
      queueRun: (fn) => ledger.queue.run(fn),
      reindexPaths: (paths) => ledger.reindexPaths(paths),
      deliver: makeDeliver(store, log),
      flushLocal: () => ledger.git.flush(),
      log,
      async noteLocal(notes: readonly LocalNote[]) {
        for (const n of notes) {
          const fields = [`rule=${cleanText(n.rule, 40)}`, ...(n.device === null ? [] : [`device=${cleanText(n.device, 20)}`]), cleanText(n.detail, 160)];
          await ledger.appendJournalEvent('agent-ledger', 'sync', cleanText(n.type, 30), fields);
        }
      },
      async createProposed(items: readonly ProposedItem[]) {
        for (const p of items) {
          try {
            await ledger.createItem({
              repo: p.repo,
              title: cleanText(p.title, 120),
              kind: 'BACKLOG',
              priority: 'P3',
              owner: 'human',
              why: cleanText(p.why, 600),
              steps: [],
              blocked_by: [],
              aliases: [],
              proposed: true,
            });
          } catch {
            log('sync: a proposed item could not be created');
          }
        }
      },
    };
    const deps: CycleDeps = {
      ledgerDir: ledger.paths.root,
      ...core,
      identity: { name: device.label, email: deviceEmail(device.device_id) },
      signing,
      localDevice: device.device_id,
      maxFormat: LEDGER_FORMAT,
      remote: cfg.remote,
      host,
      verify: config.syncVerify,
      trusted: async () => new Set((await readSigners(layout)).map((s) => s.pubkey)),
      log,
      ...(o.testLocalRemotes === undefined ? {} : { testLocalRemotes: o.testLocalRemotes }),
    };
    const loop = new SyncLoop({ deps, intervalMs: config.syncIntervalMs });
    // A commit by the local ledger asks for a cycle (debounced by the loop).
    ledger.git.setOnCommitted(() => loop.trigger('commit'));
    if (o.start) loop.start();
    log(`sync: enabled (verify ${config.syncVerify}, every ${String(Math.round(config.syncIntervalMs / 1000))} s)`);
    return loop;
  } catch (err) {
    log(`sync: could not start (${err instanceof Error ? err.name : 'error'}) — staying local`);
    return null;
  }
}
