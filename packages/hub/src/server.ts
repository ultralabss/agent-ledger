import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { serve, type ServerType } from '@hono/node-server';
import { spoolDir } from '@agent-ledger/shared';
import { loadConfig, type HubConfig } from './config.ts';
import { Coordination } from './coord.ts';
import { RuntimeStore } from './db/store.ts';
import { EventBus } from './events.ts';
import { EditGuard } from './guard/edit-guard.ts';
import { GitGuard } from './guard/git-guard.ts';
import { resolveRoots } from './guard/recap.ts';
import { GuardSwitch } from './guard/switch.ts';
import { HeadlessRunner, nextMondayNine } from './headless.ts';
import { WeakFsMonitor, type FsProbe } from './fsweak.ts';
import { Hooks } from './hooks.ts';
import { gitleaksAvailability, gitleaksInfo } from './gitleaks.ts';
import { hubHealthLine, type ScannerState } from './health.ts';
import { createApp } from './http/app.ts';
import { hubLog } from './log.ts';
import { rotateLog } from './ops/logrotate.ts';
import { Ledger } from './ledger/ledger.ts';
import { GitCache, RepoWatcher } from './repowatch.ts';
import { Replies } from './replies.ts';
import { LoginCodeStore, loadOrCreateToken, newUiSecret, rotateToken } from './security/index.ts';
import { cachedSpoolStats, sweepSpool } from './spool-sweep.ts';
import { Sessions } from './sessions.ts';
import { PendingMarks } from './pendingmark.ts';
import { Summarizer } from './summary.ts';
import { bootReplayGit, bootReplayNotes, startSync } from './sync/wire.ts';
import type { SyncLoop } from './sync/loop.ts';
import { StallMonitor, WakeMonitor } from './wake.ts';
import { startWatcher, type Watcher } from './watcher.ts';

export interface HubHandle {
  port: number;
  url: string;
  token: string;
  /** B4-1: per-boot key of the UI cookie. Exposed so tests (and nothing else —
   *  no endpoint returns it) can forge the cookie the browser would get. */
  uiSecret: string;
  ledger: Ledger;
  watcher: Watcher;
  store: RuntimeStore;
  sessions: Sessions;
  hooks: Hooks;
  gitCache: GitCache;
  repoWatcher: RepoWatcher;
  bus: EventBus;
  /* F2/F3 */
  guardSwitch: GuardSwitch;
  coord: Coordination;
  editGuard: EditGuard;
  gitGuard: GitGuard;
  headless: HeadlessRunner;
  /** Reply router. `background` is awaited by tests for worker runs. */
  replies: Replies;
  /* v0.4.0 */
  /** Rolling session summary. */
  summarizer: Summarizer;
  /** `<ledger>/.hub/inbox-pending/` marker set. */
  pending: PendingMarks;
  /* */
  /** Sleep/wake detector + the gate heavy jobs ask before running. */
  wake: WakeMonitor;
  /** Event-loop drift monitor behind `healthz.diag.loopDelayMaxMs`. */
  stalls: StallMonitor;
  /** F3b sync loop (`LEDGER_SYNC=1` and enrolled), else `null`. B4 routes drive it. */
  sync: SyncLoop | null;
  /** Run the periodic jobs once, synchronously (tests). */
  sweep(): Promise<void>;
  close(): Promise<void>;
}

export interface StartOptions {
  config?: HubConfig;
  log?: (line: string) => void;
  /** Skip the fs watcher (tests that drive the ledger directly). */
  watch?: boolean;
  /** Skip the periodic timers (tests call `sweep()` instead). */
  periodic?: boolean;
  /** Bash attribution delay; tests set 0. */
  bashDelayMs?: number;
  /** Tests await the background Bash pass. */
  awaitBackground?: boolean;
  /** A8-4 test seam: bound the binary trust directory walk to a sandbox root.
   *  Production never sets it — the walk goes to `/`. */
  trustStopAt?: string;
  /** Test seam: capability probe behind the weak-filesystem warning (default `probeFs`). */
  fsProbe?: FsProbe;
}

export async function startHub(opts: StartOptions = {}): Promise<HubHandle> {
  const config = opts.config ?? loadConfig();
  // The default sink stamps every line with an ISO timestamp (`log.ts`).
  // A caller-supplied sink is used verbatim — tests own their own formatting.
  const log = opts.log ?? hubLog;
  // Both monitors exist before anything heavy starts, so the startup
  // hold already covers the boot reindex storm and the spool replay.
  const wake = new WakeMonitor({ log });
  const stalls = new StallMonitor({ log });
  const heavyAllowed = (): boolean => wake.heavyAllowed();
  const heavyRetryInMs = (): number => wake.retryInMs();
  const ledger = new Ledger({ config, log, heavyAllowed, heavyRetryInMs });
  // F3b: an APPLY that died half-way is rolled forward/back BEFORE anything can write or commit (in every mode,
  // also LEDGER_SYNC=0). No marker = no effect. The notes of the replay are delivered once the store is up.
  const bootReplay = await bootReplayGit(ledger, log);
  await ledger.init();
  // Items whose `done.version` held prose were parsed leniently by the
  // reindex above (and flagged); fix the files once, atomically, through the
  // write queue, so the next reindex has nothing to repair.
  const migrated = await ledger.migrateRepairedItems();
  if (migrated > 0) log(`migration: repaired ${migrated} items`);
  const token = await loadOrCreateToken(ledger.paths.tokenPath);
  // Weak-FS bypass (LEDGER_ALLOW_WEAK_FS=1) is never silent: hub.log line per path here, the
  // list in authenticated healthz (`fs_weak`) and the web banner. `.hub` is probed (private,
  // git-ignored) instead of the ledger root so the probe file never shows up in the ledger repo.
  // The spool is probed only when it is the real one (periodic hub) or a probe is injected.
  const weakFs = new WeakFsMonitor(
    () => [
      { probeDir: ledger.paths.hubDir, label: ledger.paths.root },
      ...(opts.periodic !== false || opts.fsProbe !== undefined
        ? [{ probeDir: spoolDir(process.env), label: spoolDir(process.env) }]
        : []),
    ],
    log,
    opts.fsProbe,
  );
  await weakFs.refresh();
  // The UI cookie is keyed by this, NOT by the hub token, so a
  // local process holding the token cannot compute a cookie and pose as "a
  // human at the browser right now" for the owner-level routes. 32 B CSPRNG,
  // created per boot, kept only in this closure: never written to disk, never
  // returned by an endpoint, never logged. Cost: a hub restart invalidates
  // open UI sessions — `ledger open` mints a new one in one command.
  const guardCfg = { token, uiSecret: newUiSecret(), port: config.port };
  // One-shot UI login codes live here, not inside the UI handler, because the
  // rotation handler below has to be able to throw them away.
  const codes = new LoginCodeStore();
  // S1: if the git-ignored-and-untracked invariant on `.hub/token` ever
  // breaks, rotate the token and make the live guard use the new value
  // immediately — the old one must be treated as leaked, on-disk file or not.
  ledger.git.setTokenLeakHandler(async () => {
    guardCfg.token = await rotateToken(ledger.paths.tokenPath);
    // Audit UI-login: a code minted against the leaked token must not still be
    // redeemable for a cookie afterwards — the cookie is an HMAC of the token,
    // so an outstanding code is a live path back to read access.
    codes.clear();
    // A8-1: `rotateToken` throws on failure (caught by `LedgerGit.lockdown`),
    // so reaching here means a new token is on disk and live.
    return true;
  });

  // Runtime state. `.hub/` is already 0700 and git-ignored (S1), so the DB and
  // its WAL siblings inherit that protection.
  const store = new RuntimeStore(join(ledger.paths.hubDir, 'hub.sqlite'));
  await bootReplayNotes(bootReplay, store, log);
  const bus = new EventBus();
  const sessions = new Sessions({ ledger, store, bus });
  const gitCache = new GitCache({ ledger, store, bus, heavyAllowed });
  // Facts in, one journal line out. Constructed before the watcher,
  // which is one of its three triggers.
  const summarizer = new Summarizer({ ledger, store, sessions });
  // The marker the PostToolUse fast path reads instead of asking.
  const pending = new PendingMarks(ledger.paths.hubDir, log);
  store.onInbox = (to) => void pending.owe(to);
  const repoWatcher = new RepoWatcher({
    ledger,
    store,
    bus,
    gitCache,
    repoForCheckout: (layout) => sessions.repoForCheckout(layout),
    sessions,
    summarizer,
    heavyAllowed,
    heavyRetryInMs,
  });
  const guardSwitch = new GuardSwitch({ ledger, envState: config.guardEnv });
  const coord = new Coordination({ ledger, store, sessions, gitCache, bus });
  const editGuard = new EditGuard({
    ledger,
    store,
    sessions,
    guard: guardSwitch,
    excludeTemp: config.excludeTemp,
    intrude: config.intrude,
  });
  const gitGuard = new GitGuard({ store, sessions, gitCache, guard: guardSwitch });
  // Headless runs are an optional feature (LEDGER_HEADLESS=1). When it is off
  // the runner still exists (routes, status, healthz stay uniform) but has no
  // binary to spawn, so it reports `configured: false` and every run answers 503.
  const headless = new HeadlessRunner({
    ledger,
    config: config.headless ? config : { ...config, claudeBin: null },
    ...(opts.trustStopAt === undefined ? {} : { trustStopAt: opts.trustStopAt }),
  });
  // Reply router. `coord` writes the inbox for session mode; `claudeBin`
  // is the same absolute-path-only binary the triage runner uses.
  const replies = new Replies({
    store,
    ledger,
    sessions,
    bus,
    coord,
    claudeBin: config.headless ? config.claudeBin : null,
    trustClaudeGroup: config.trustClaudeGroup,
    ...(opts.trustStopAt === undefined ? {} : { trustStopAt: opts.trustStopAt }),
  });
  // Roots are realpath'd once: a symlinked `$HOME` would otherwise never match
  // the `transcript_path` the hook reports (Stop recap check).
  const transcriptRoots = await resolveRoots(config.transcriptRoots);

  // One cached counter source, shared by healthz, the brief and the
  // SessionStart hook — the spool is on disk and polling it is a readdir.
  const spoolStats = cachedSpoolStats();

  // ONE source for the degraded-hub line — healthz, `ledger brief` and
  // the SessionStart hook all read this, so they can never disagree.
  // The gitleaks probe hits the real filesystem, so it is skipped when the
  // periodic jobs are off (tests): a fixture must not report the developer's
  // own /opt/homebrew state.
  let scannerState: ScannerState = { state: 'unknown', detail: null };
  const scanner = (): ScannerState => scannerState;
  if (opts.periodic !== false) {
    void gitleaksInfo(config.ledgerDir)
      .then(() => {
        scannerState = gitleaksAvailability();
        if (scannerState.state !== 'ok') {
          log(`gitleaks: ${scannerState.state}${scannerState.detail ? ` — ${scannerState.detail}` : ''}`);
        }
      })
      .catch(() => undefined);
  }
  const health = (): string | null =>
    hubHealthLine({
      ledger,
      spool: spoolStats(),
      scanner: scannerState,
      headless: headless.status,
    });

  const hooks = new Hooks({
    ledger,
    store,
    sessions,
    gitCache,
    bashDelayMs: opts.bashDelayMs,
    awaitBackground: opts.awaitBackground,
    guard: guardSwitch,
    editGuard,
    gitGuard,
    coord,
    postToolMode: config.postToolMode,
    transcriptRoots,
    recapGuard: config.recapGuard,
    recapTags: config.recapTags,
    excludeTemp: config.excludeTemp,
    health,
    summarizer,
    pending,
  });

  // md is the source of truth; the search index follows every reindex.
  //
  // `rebuildSearch` is `DELETE FROM fts` + one INSERT per doc in a
  // single synchronous transaction — 75–120 ms of blocked event loop for ~7 000
  // docs, every reindex (so twice a minute at idle, plus once per watcher
  // event), and multiplied several times over by launchd's Background CPU/IO
  // throttling. That was the dominant stall. The corpus is derived from the
  // in-memory index, so a cheap fingerprint answers "did anything change?" in
  // a few ms, and at idle the rebuild simply does not run.
  let searchFingerprint: string | null = null;
  const reindexSearch = (): void => {
    void ledger
      .searchDocs()
      .then((docs) => {
        const h = createHash('sha1');
        for (const d of docs) h.update(`${d.kind}\u0000${d.ref}\u0000${d.title}\u0000${d.body}\u0000`);
        const fingerprint = h.digest('hex');
        if (fingerprint === searchFingerprint) return;
        searchFingerprint = fingerprint;
        store.rebuildSearch(docs);
      })
      .catch((err: unknown) => log(`search reindex: ${String(err)}`));
  };
  ledger.onReindex = reindexSearch;
  reindexSearch();

  // This is a gate (headless triage, grooming and the reply worker refuse to
  // spawn an untrusted `claude`), so the verdict is resolved at boot and
  // logged — a silently disabled feature is easy to overlook.
  if (!config.headless) {
    log('headless: disabled');
  }
  void headless
    .probeBinaryTrust()
    .then(() => {
      const trust = headless.status.bin_trust;
      if (trust !== undefined && trust !== 'ok' && trust !== 'unknown') {
        log(`claude: ${trust} — ${headless.status.bin_trust_detail ?? 'headless disabled'}`);
      }
    })
    .catch(() => undefined);

  // The conscious `--trust-claude-group` opt-in is a security decision of
  // the machine's owner, so it leaves an auditable trail rather than living
  // only in a plist nobody reads. Best effort — the journal must never be the
  // reason the hub does not boot.
  if (config.trustClaudeGroup && config.claudeBin !== null) {
    // The journal says WHAT was approved, not just "something
    // was". An opt-in with no pin is reported as the no-op it now is.
    const pin =
      config.trustClaudeGid === null || config.trustClaudeRealpath === null
        ? 'WITHOUT a pin (gid/realpath missing) — the opt-in does not apply, re-run the installer'
        : `pinned to gid ${config.trustClaudeGid} and ${config.trustClaudeRealpath}`;
    log(`claude: group-writable allowed by the user (LEDGER_TRUST_CLAUDE_GROUP=1) · ${pin}`);
    void ledger
      .appendJournalEntry({
        repo: 'agent-ledger',
        type: 'security',
        text:
          'claude-trust-group · user allowed a group-writable path for claude ' +
          `(install.sh --trust-claude-group) · ${config.claudeBin} · ${pin}`,
      })
      .catch(() => undefined);
  }

  await repoWatcher.start();
  if (opts.periodic !== false) gitCache.start();

  const app = createApp({
    ledger,
    guard: guardCfg,
    store,
    sessions,
    hooks,
    gitCache,
    repoWatcher,
    bus,
    uiDir: config.uiDir,
    coord,
    guardSwitch,
    headless,
    features: {
      intrude: config.intrude,
      webReplies: config.webReplies,
      headless: config.headless,
    },
    codes,
    replies,
    summarizer,
    // Counters for `/v1/healthz`. Cached for a second so a UI polling
    // healthz does not readdir the spool on every request.
    spoolStats,
    health,
    scanner,
    fsWeak: () => weakFs.paths(),
    // Authenticated-only runtime diagnostics. Fixed shape — the CLI
    // codes against it.
    diag: () => ({
      startedAt: wake.startedAt,
      lastWakeAt: wake.lastWakeAt,
      loopDelayMaxMs: stalls.maxDelayMs(),
      missingRepos: repoWatcher.missingRepos(),
      gitleaksRetryAt: ledger.git.status.secretScan.retryAt,
    }),
  });

  // LH-1: the UI login URL uses `ledger.localhost:<port>`, which a client may
  // resolve to `::1` first. A hub bound only to 127.0.0.1 would leave `[::1]:<port>`
  // free for another local account, which would then receive the one-time
  // login code. So the same port is bound on `::1` too, fail-closed.
  const listenOne = (port: number, hostname: '127.0.0.1' | '::1'): Promise<ServerType> =>
    new Promise((resolvePromise, reject) => {
      let listening = false;
      const s = serve({ fetch: app.fetch, port, hostname }, () => {
        listening = true;
        resolvePromise(s);
      });
      s.on('error', (err: NodeJS.ErrnoException) => {
        // The PostToolUse hook is fire-and-forget — when the marker says
        // the hub owes it nothing, it closes the socket without reading the
        // response. The write then fails with EPIPE/ECONNRESET, which is the
        // *expected* shape of a fast hook, not a fault. Logging it would fill
        // hub.log with one line per tool call of every session and bury the
        // errors that matter.
        if (err.code === 'EPIPE' || err.code === 'ECONNRESET') return;
        if (listening) {
          log(`server: ${String(err)}`);
          return;
        }
        // Before `listen` succeeded an error is fatal (port in use, EACCES).
        reject(err);
      });
      // Per-connection errors never reach the server emitter on some Node
      // versions, so the same tolerance is applied where the socket lives.
      s.on('connection', (socket) => {
        socket.on('error', (err: NodeJS.ErrnoException) => {
          if (err.code === 'EPIPE' || err.code === 'ECONNRESET') return;
          log(`socket: ${String(err)}`);
        });
      });
    });
  const closeOne = (s: ServerType): Promise<void> =>
    new Promise<void>((resolvePromise) => s.close(() => resolvePromise()));

  const servers: ServerType[] = [];
  for (let attempt = 0; ; attempt++) {
    const v4 = await listenOne(config.port, '127.0.0.1');
    const boundPort = (v4.address() as AddressInfo | null)?.port ?? config.port;
    try {
      const v6 = await listenOne(boundPort, '::1');
      servers.push(v4, v6);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'EADDRNOTAVAIL' || code === 'EAFNOSUPPORT') {
        // No IPv6 loopback on this machine: nothing to squat on.
        log(`server: ::1 unavailable (${code}), listening on 127.0.0.1 only`);
        servers.push(v4);
      } else {
        await closeOne(v4);
        // Port 0 = ephemeral: the v4 port was random, try another pair.
        if (config.port === 0 && code === 'EADDRINUSE' && attempt < 8) continue;
        if (code === 'EADDRINUSE') {
          throw new Error(
            `port ${boundPort} is already in use on ::1 — refusing to start: another process could receive the UI login code`,
            { cause: err },
          );
        }
        throw err;
      }
    }
    break;
  }
  const server = servers[0] as ServerType;
  const address = server.address() as AddressInfo | null;
  guardCfg.port = address?.port ?? config.port;

  // Flush anything queued while the hub was down. After `listen`, so the
  // port is already bound and a session that starts now cannot race the sweep.
  void sweepSpool({
    // Over the real socket, not `app.fetch`: in-process Requests carry a
    // single-use body stream, and the idempotency middleware reads the body
    // before `bodyLimit` does — every in-process replay died with a 500
    // "ReadableStream is locked". The network path is the one the CLI uses.
    // R5-01: bounded, so a hung handler cannot pin the replay lock forever.
    fetch: (req: Request) => fetch(req, { signal: AbortSignal.timeout(10_000) }),
    token: guardCfg.token,
    port: guardCfg.port,
    log,
  });

  const watcher = startWatcher(ledger);
  if (opts.watch === false) watcher.close();

  /** Reap dead sessions, refresh live checkouts, reindex as a watch backstop. */
  const sweep = async (): Promise<void> => {
    try {
      await weakFs.refresh();
      await sessions.reap();
      // A `leak` hold whose token rotation failed is retried
      // from here, so it can lift on its own once the cause is fixed. No-op
      // unless such a hold is active; the ledger's own write debounce would
      // otherwise never fire on a quiet ledger and the hold would hold until
      // somebody restarted the hub.
      await ledger.git.retrySecurityHold();
      await gitCache.refreshLive();
      await repoWatcher.sync();
      // Trigger (b): 30 min of silence with activity since the last
      // summary. Driven from the sweep rather than a timer per session — the
      // hub already wakes up here and the condition is one indexed query.
      await summarizer.flushIdle();
      await ledger.queue.run(() => ledger.reindex());
      // A file repaired by a reindex between startups still gets fixed.
      await ledger.migrateRepairedItems();
      // Hub.log and the SQLite WAL both grew without bound.
      const rotated = await rotateLog(ledger.paths.logPath);
      if (rotated.rotated) log(`hub.log rotated at ${rotated.size} B → hub.log.1`);
      if (rotated.skippedSymlink) {
        log(`SECURITY: ${ledger.paths.logPath} is a symlink — rotation skipped, not following it`);
      }
      store.checkpoint();
    } catch (err) {
      log(`sweep: ${String(err)}`);
    }
  };

  const timers: NodeJS.Timeout[] = [];
  if (opts.periodic !== false) {
    wake.start();
    stalls.start();
    // The gate is asked at the TIMER, not inside `sweep()` — the
    // handle's `sweep()` is how tests and `GET /v1/repos/:slug` force a pass
    // and must stay unconditional. `whenAllowed` runs the job now or once the
    // post-wake hold expires.
    const runSweep = (): void => {
      void stalls.job('sweep', sweep);
    };
    const sweepTimer = setInterval(() => {
      if (wake.whenAllowed(runSweep)) runSweep();
    }, config.sweepIntervalMs);
    sweepTimer.unref?.();
    timers.push(sweepTimer);
    const runReindex = (): void => {
      void stalls
        .job('reindex', () => ledger.queue.run(() => ledger.reindex()))
        .catch((err: unknown) => log(`periodic reindex: ${String(err)}`));
    };
    const reindexTimer = setInterval(() => {
      if (wake.whenAllowed(runReindex)) runReindex();
    }, config.reindexIntervalMs);
    reindexTimer.unref?.();
    timers.push(reindexTimer);

    // SPEC F3 §15: Monday 09:00 local, only with LEDGER_GROOM_WEEKLY=1.
    // Re-armed after every run rather than a fixed 7-day interval, so a hub that
    // lives for months does not drift off Monday and a DST change does not move
    // the hour.
    if (config.groomWeekly && config.headless) {
      const armGroom = (): void => {
        const at = nextMondayNine(new Date());
        const delay = Math.max(1_000, at.getTime() - Date.now());
        const t = setTimeout(() => {
          // Grooming spawns `claude` and walks the whole ledger — the
          // heaviest job there is. A machine woken at 09:00 Monday runs it a
          // few seconds later instead, and re-arms either way.
          const runGroom = (): void => {
            void headless
              .runGroom({ session: 'weekly' })
              .catch((err: unknown) => log(`weekly grooming: ${String(err)}`))
              .finally(armGroom);
          };
          if (wake.whenAllowed(runGroom)) runGroom();
        }, delay);
        t.unref?.();
        timers.push(t);
        log(`weekly grooming scheduled for ${at.toISOString()}`);
      };
      armGroom();
    }
  }

  // F3b: the loop starts last (the hub already serves), only with LEDGER_SYNC=1 and an enrolled ledger.
  const sync = await startSync({ ledger, store, config, log, start: opts.periodic !== false });

  log(`agent-ledger on http://127.0.0.1:${guardCfg.port} · ledger ${ledger.paths.root} · fts ${store.engine}`);

  return {
    port: guardCfg.port,
    url: `http://127.0.0.1:${guardCfg.port}`,
    token,
    uiSecret: guardCfg.uiSecret,
    ledger,
    watcher,
    store,
    sessions,
    hooks,
    gitCache,
    repoWatcher,
    bus,
    guardSwitch,
    coord,
    editGuard,
    gitGuard,
    headless,
    replies,
    summarizer,
    pending,
    wake,
    stalls,
    sync,
    sweep,
    async close(): Promise<void> {
      for (const t of timers) clearInterval(t);
      wake.stop();
      stalls.stop();
      watcher.close();
      repoWatcher.close();
      gitCache.stop();
      await hooks.settled().catch(() => undefined);
      // A worker run holds a child process; closing under it would leak it.
      await replies.background.catch(() => undefined);
      await Promise.all(servers.map(closeOne));
      // waits for a running cycle (never kills one mid-APPLY) BEFORE the ledger goes away
      await sync?.stop();
      await ledger.close();
      store.close();
    },
  };
}
