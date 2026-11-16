/** The ledger service: md files in, md files out, one serial writer.
 *
 *  Every mutation runs inside `queue.run(...)` — that includes id allocation,
 *  so the device counter (`counters/<device_id>.yml`) can never hand the same id
 *  to two concurrent `POST /v1/items`. Writes are tmp+rename (SPEC §6.2).
 *
 *  Ledger format 2 (docs/multi-device-spec.md §2): `repos.yml` is portable (no
 *  `path`, no `next`), checkout paths live in `.hub/local.yml`, counters in
 *  `counters/`, this machine's identity in `.hub/device.yml`. `repos()` still
 *  returns the MERGED view (`path`, `next`, `graphify`) so callers did not change.
 */

import { createHash } from 'node:crypto';
import { mkdir, readdir, realpath, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import {
  appendLog,
  applyItem,
  canTransition,
  contextTemplate,
  decisionsTemplate,
  DONE_REF_HINT,
  escapeStructuralLines,
  generate,
  isOpen,
  isDoneRef,
  itemFromDoc,
  journalLine,
  newItemDoc,
  nextDecisionNumber,
  parseDecisions,
  parseItemId,
  formatItemId,
  isIntakeUnprocessed,
  parseIntake,
  parseItem,
  parseJournal,
  repoKindOf,
  reposSyncedFileSchema,
  SEP,
  serializeDecision,
  serializeIntake,
  serializeItem,
  transitionError,
  type Decision,
  type IntakeRecord,
  type IntakeStatus,
  type Item,
  type ItemRepair,
  type ItemFrontmatter,
  type ItemStatus,
  type JournalEvent,
  type PlanStep,
  type RepoConfig,
  type RepoIdentity,
  type RepoKind,
  type ReposFile,
  type Transition,
} from '@agent-ledger/shared';
import {
  configureSnowflakeWorker,
  day,
  ensurePrivateDir,
  isOwnedByMe,
  isoLocal,
  month,
  renameRetry,
  sanitizeLine,
  shortSession,
  stamp,
} from '@agent-ledger/shared';
import { expandHome, type HubConfig } from '../config.ts';
import { conflict, invalid, notFound, LedgerError } from '../errors.ts';
import { gitToplevel, LedgerGit } from '../git.ts';
import { normalizeGitPath, samePathGit } from '../gitpath.ts';
import { readOriginHint, readRootSha } from '../gitreader.ts';
import { MemoryIndex, type ItemFilter, type LedgerIndex, type StoredItem } from '../index-store.ts';
import {
  COUNTER_MAX,
  isAbsoluteLike,
  LEDGER_FORMAT,
  loadOrCreateDevice,
  readAllCounters,
  readCounterFile,
  readLedgerFormat,
  readLocalFile,
  writeCounterFile,
  writeLedgerFormat,
  writeLocalFile,
  type DeviceIdentity,
  type RepoLocal,
} from './device.ts';
import { appendLine, ensureDir, ensureFile, readText, tighten, writeAtomic } from './fsops.ts';
import { LedgerPaths } from './paths.ts';
import { SerialQueue } from './queue.ts';

export interface LedgerDeps {
  config: HubConfig;
  log?: (line: string) => void;
  index?: LedgerIndex;
  /** False right after a wake (or boot) — the ledger's own commit +
   *  gitleaks scan is one of the heavy jobs that must not run into the storm.
   *  Absent → always allowed (tests, CLI consumers). */
  heavyAllowed?: () => boolean;
  /** How long until `heavyAllowed()` turns true again. */
  heavyRetryInMs?: () => number;
}

export interface RepoRegisterInput {
  slug: string;
  prefix?: string | undefined;
  path?: string | null | undefined;
  /** Default `repo`. `system` / `vps` have no path and no git check. */
  kind?: RepoKind | undefined;
  /** `vps` only, informational ssh alias / hostname. */
  host?: string | undefined;
  graphify?: string | null | undefined;
  docs?: string[] | undefined;
  /** Only `ledger repo add --onboarded` sets this; auto-registration never does. */
  onboarded?: boolean | undefined;
}

export interface CreateItemInput {
  repo: string;
  title: string;
  kind: string;
  priority: string;
  owner: string;
  area?: string | null | undefined;
  why?: string | undefined;
  rec?: string | undefined;
  steps: string[];
  blocked_by: string[];
  requested_by?: string | null | undefined;
  intake?: string | null | undefined;
  aliases: string[];
  proposed: boolean;
  status?: string | undefined;
  session?: string | null | undefined;
  agent?: string | null | undefined;
}

/** `.hub/` (token, log) and `*.tmp` (half-written atomic-write files) must
 *  never reach a commit (S1). Repaired at every boot, not just created once —
 *  a `.gitignore` a human wrote before agent-ledger existed would otherwise never
 *  gain these lines, and `git add -A` would pick up `.hub/token`. */
const GITIGNORE_LINES = ['.hub/', '*.tmp'];
const GITIGNORE = `${GITIGNORE_LINES.join('\n')}\n`;

/** Ledger files are LF on every platform (parsers tolerate CRLF, writers emit LF).
 *  Stops Windows `core.autocrlf` from rewriting them and making every file dirty. */
const GITATTRIBUTES_LINE = '* text eol=lf';
/** Byte-exact `.gitattributes` a fresh ledger writes; pinned in sync mode (ingress rejects any other text). */
const GITATTRIBUTES = `${GITATTRIBUTES_LINE}\n`;

export class Ledger {
  readonly paths: LedgerPaths;
  readonly config: HubConfig;
  readonly index: LedgerIndex;
  readonly queue = new SerialQueue();
  readonly git: LedgerGit;
  /** file → reason. Surfaced by `/v1/healthz`; last good version stays indexed. */
  readonly warnings = new Map<string, string>();
  /** File → item + repaired optional fields, waiting for the migration. */
  private readonly repaired = new Map<string, { id: string; repairs: ItemRepair[] }>();
  /** File → `mtime:size` already logged, so one bad file logs once. */
  private readonly logged = new Map<string, string>();
  /** File → sha1 of the bytes the index was built from. The 60 s
   *  reindex is a *backstop*, so in steady state it re-parses nothing: reading
   *  813 md files costs tens of ms, parsing their YAML + body cost ~150 ms of
   *  synchronous work a minute, which is what delayed the healthz probe.
   *  Keyed on content, not `mtime:size`: two writes inside one filesystem
   *  timestamp tick are normal in tests and in a fast `ledger` burst. */
  private readonly parsedHash = new Map<string, string>();

  private reposRaw: ReposFile = {};
  /** `.hub/local.yml` as last read OK. */
  private localRaw = new Map<string, RepoLocal>();
  /** False while `.hub/local.yml` is unreadable: never overwrite it then. */
  private localOk = true;
  /** This device's counter file, `{slug: last allocated}`. */
  private counters = new Map<string, number>();
  /** True once an own counter state is known; allocation refuses without it. */
  private countersLoaded = false;
  /** Format-1 `next - 1` still present in `repos.yml`; folded into the counter
   *  file before the key is ever dropped (counter must never go down). */
  private legacyFloor = new Map<string, number>();
  /** `repos.yml` still carries `path`/`next`/`graphify`/absolute docs. */
  private legacyPresent = false;
  private deviceIdentity: DeviceIdentity | null = null;
  /** `ledger.format` as read at boot, raised to {@link LEDGER_FORMAT} once the
   *  migration wrote the marker. Below 2 (migration window) the legacy
   *  `path`/`next`/`graphify` of `repos.yml` are still read; from 2 on that file
   *  is synced, i.e. peer-controlled, and they are ignored. */
  private formatNum = 1;

  private readonly logFn: (line: string) => void;

  constructor(deps: LedgerDeps) {
    this.config = deps.config;
    this.paths = new LedgerPaths(deps.config.ledgerDir);
    this.index = deps.index ?? new MemoryIndex();
    this.logFn = deps.log ?? ((line) => process.stderr.write(`${line}\n`));
    this.git = new LedgerGit({
      root: this.paths.root,
      commitDebounceMs: deps.config.commitDebounceMs,
      pushIntervalMs: deps.config.pushIntervalMs,
      push: deps.config.push,
      log: this.logFn,
      // S1 lockdown / hold / release must leave an auditable trail, not
      // just a log line that scrolls away. Written directly (not through
      // `appendJournalEvent`) because that one calls `git.touch()` and this runs
      // from inside the commit cycle.
      journal: async (type, fields) => {
        await this.appendJournal('agent-ledger', null, type, fields);
      },
      ...(deps.heavyAllowed === undefined ? {} : { heavyAllowed: deps.heavyAllowed }),
      ...(deps.heavyRetryInMs === undefined ? {} : { heavyRetryInMs: deps.heavyRetryInMs }),
    });
  }

  log(line: string): void {
    this.logFn(line);
  }

  /** This machine's identity (`.hub/device.yml`); only valid after `init()`. */
  get device(): DeviceIdentity {
    if (this.deviceIdentity === null) throw new Error('ledger is not initialised');
    return this.deviceIdentity;
  }

  /* ---------------- boot ---------------- */

  async init(): Promise<void> {
    await ensureDir(this.paths.root, 0o700);
    await tighten(this.paths.root, 0o700);
    // Before ANY other write: a ledger written by a newer hub (higher
    // `ledger.format`) has a layout this code does not understand. Fail closed.
    const format = await readLedgerFormat(this.paths.formatFile);
    this.formatNum = format;
    // win32: a plain mkdir inherits the parent's ACL (e.g. BUILTIN\\Users write under a shared
    // temp/data root), which the token/hooks trust checks rightly refuse. Create `.hub` private
    // (DACL {me, SYSTEM}, inheritance removed). POSIX keeps the mode-based path unchanged.
    if (process.platform === 'win32') await ensurePrivateDir(this.paths.hubDir);
    else await ensureDir(this.paths.hubDir, 0o700);
    await this.git.init();
    await this.ensureGitignore();
    await this.ensureGitattributes();
    // Device identity decides the id slot and the snowflake worker: load it
    // before anything can mint an id. Process-wide on purpose: `generate()` is
    // called from the DB layer too.
    this.deviceIdentity = await loadOrCreateDevice(this.paths.deviceYml, {
      countersDir: this.paths.countersDir,
      formatFile: this.paths.formatFile,
      root: this.paths.root,
    });
    configureSnowflakeWorker(this.device.slot);
    const created = await ensureFile(
      this.paths.reposYml,
      stringifyYaml({ ops: { kind: 'system', prefix: 'OPS' } }, { lineWidth: 0 }),
      0o600,
    );
    await this.loadRepos();
    const migrated = await this.migrateToV2(format);
    if (created) await this.ensureRepoFiles('ops');
    await this.reindex();
    if (created) this.git.touch('initialized ledger');
    else if (migrated) this.git.touch('ledger format 2 migration');
  }

  /**
   * Format 1 → 2, idempotent. Order is crash-safe: counters (`next` folded in)
   * and `.hub/local.yml` are written BEFORE `repos.yml` loses `path`/`next`, and
   * the `ledger.format` marker goes last, so an interrupted run simply repeats.
   * A `repos.yml` that does not parse is left untouched (no marker either).
   */
  private async migrateToV2(format: number): Promise<boolean> {
    if (format >= LEDGER_FORMAT && !this.legacyPresent) return false;
    if (this.warnings.has(this.paths.reposYml)) {
      this.logFn('ledger format 2 migration skipped: repos.yml is not valid');
      return false;
    }
    if (this.legacyPresent) {
      if (!this.localOk) {
        // Moving paths out of repos.yml while local.yml cannot be written would lose them.
        this.logFn('ledger format 2 migration skipped: .hub/local.yml is not valid');
        return false;
      }
      for (const [slug, cfg] of Object.entries(this.reposRaw)) {
        if (cfg.identity !== undefined || cfg.path === null || repoKindOf(cfg) !== 'repo') continue;
        const identity = await this.identityFor(cfg.path);
        if (identity !== undefined) this.reposRaw[slug] = { ...cfg, identity };
      }
      await this.saveRepos();
    }
    if (format < LEDGER_FORMAT) await writeLedgerFormat(this.paths.formatFile);
    this.formatNum = LEDGER_FORMAT;
    this.legacyPresent = false;
    this.logFn(`ledger migrated to format ${LEDGER_FORMAT}`);
    return true;
  }

  /** Portable identity of a checkout; best effort, never throws (empty repo,
   *  missing directory, git failure → no identity). */
  private async identityFor(path: string): Promise<RepoIdentity | undefined> {
    try {
      const dir = expandHome(path);
      // Fail closed: never run git in a checkout this user does not own (its
      // .git/config is attacker-controlled there). Unknown owner = no identity.
      if (!(await isOwnedByMe(await realpath(dir)))) return undefined;
      const root = await readRootSha(dir);
      if (root === null) return undefined;
      return { root_sha: root, origin_hint: await readOriginHint(dir) };
    } catch {
      return undefined;
    }
  }

  /** Create `.gitignore` when missing, or append any of `GITIGNORE_LINES`
   *  that an existing (human-written) `.gitignore` is missing (S1). */
  private async ensureGitignore(): Promise<void> {
    const existing = await readText(this.paths.gitignore);
    if (this.config.sync) {
      // F3b invariant 10: synced peers accept exactly this text, nothing else. Extra
      // lines would make every peer quarantine our push (`sync init` warns before this).
      if (existing !== GITIGNORE) await writeAtomic(this.paths.gitignore, GITIGNORE, 0o600);
      return;
    }
    if (existing === null) {
      await writeAtomic(this.paths.gitignore, GITIGNORE, 0o600);
      return;
    }
    const lines = new Set(existing.split('\n').map((l) => l.trim()));
    const missing = GITIGNORE_LINES.filter((l) => !lines.has(l));
    if (missing.length === 0) return;
    const next = `${existing.replace(/\n*$/, '\n')}${missing.join('\n')}\n`;
    await writeAtomic(this.paths.gitignore, next, 0o600);
  }

  /** Create `.gitattributes` with `* text eol=lf`, or PREPEND the line to a
   *  user-written file that lacks it (idempotent). Prepended, not appended:
   *  gitattributes is last-match-wins, so the user's later, more specific rules
   *  (`*.png binary`) keep precedence and nothing of theirs is rewritten. */
  private async ensureGitattributes(): Promise<void> {
    const existing = await readText(this.paths.gitattributes);
    if (this.config.sync) {
      if (existing !== GITATTRIBUTES) await writeAtomic(this.paths.gitattributes, GITATTRIBUTES, 0o600);
      return;
    }
    if (existing === null) {
      await writeAtomic(this.paths.gitattributes, `${GITATTRIBUTES_LINE}\n`, 0o600);
      return;
    }
    const has = existing
      .split(/\r?\n/)
      .some((l) => l.trim().replace(/\s+/g, ' ') === GITATTRIBUTES_LINE);
    if (has) return;
    await writeAtomic(this.paths.gitattributes, `${GITATTRIBUTES_LINE}\n${existing}`, 0o600);
  }

  /* ---------------- repos.yml ---------------- */

  private async loadRepos(): Promise<void> {
    const text = await readText(this.paths.reposYml);
    if (text === null) {
      this.reposRaw = {};
      this.legacyFloor = new Map();
      this.legacyPresent = false;
      return;
    }
    let parsed: unknown;
    try {
      parsed = parseYaml(text);
    } catch (err) {
      this.warnings.set(this.paths.reposYml, `invalid YAML: ${String(err)}`);
      return; // keep the last good version
    }
    const res = reposSyncedFileSchema.safeParse(parsed ?? {});
    if (!res.success) {
      const first = res.error.issues[0];
      this.warnings.set(
        this.paths.reposYml,
        `invalid repos.yml (${first?.path.join('.') ?? '?'}: ${first?.message ?? 'error'})`,
      );
      return;
    }
    this.warnings.delete(this.paths.reposYml);
    await this.loadLocal();
    await this.loadCounters();

    const merged: ReposFile = {};
    const floor = new Map<string, number>();
    let legacy = false;
    // Legacy keys are honoured ONLY while migrating 1 → 2. In format 2 the synced
    // file is peer-controlled: a `path` there would route sessions (and file
    // reads) at an attacker-chosen directory, a `next` would burn the id space.
    const migrating = this.formatNum < LEDGER_FORMAT;
    for (const [slug, s] of Object.entries(res.data)) {
      const loc = this.localRaw.get(slug);
      const own = this.counters.get(slug) ?? 0;
      let legacyNext = 0;
      if (migrating && s.next !== undefined) {
        if (s.next - 1 > COUNTER_MAX) this.logFn(`repos.yml: next of "${slug}" is implausibly large and was capped`);
        legacyNext = Math.min(s.next - 1, COUNTER_MAX);
        floor.set(slug, legacyNext);
      }
      if (
        migrating &&
        (s.path !== undefined ||
          s.next !== undefined ||
          s.graphify !== undefined ||
          (s.docs ?? []).some(isAbsoluteLike))
      ) {
        legacy = true;
      }
      const cfg: RepoConfig = {
        ...(s.kind === undefined ? {} : { kind: s.kind }),
        ...(s.host === undefined ? {} : { host: s.host }),
        prefix: s.prefix,
        path: loc?.path !== undefined ? loc.path : migrating ? (s.path ?? null) : null,
        next: Math.max(own, legacyNext) + 1,
      };
      const graphify = loc?.graphify !== undefined ? loc.graphify : migrating ? s.graphify : undefined;
      if (graphify !== undefined) cfg.graphify = graphify;
      if (s.graphify_rel !== undefined) cfg.graphify_rel = s.graphify_rel;
      if (s.identity !== undefined) cfg.identity = s.identity;
      const syncedDocs = migrating
        ? (s.docs ?? [])
        : (s.docs ?? []).filter((d) => !isAbsoluteLike(d) && !d.split(/[\\/]/).includes('..'));
      const docs = [...new Set([...syncedDocs, ...(loc?.docs ?? [])])];
      if (s.docs !== undefined || docs.length > 0) cfg.docs = docs;
      if (s.prefix_aliases !== undefined) cfg.prefix_aliases = s.prefix_aliases;
      if (s.onboarded !== undefined) cfg.onboarded = s.onboarded;
      if (s.contracts !== undefined) cfg.contracts = s.contracts;
      if (s.consumers !== undefined) cfg.consumers = s.consumers;
      merged[slug] = cfg;
    }
    this.reposRaw = merged;
    this.legacyFloor = floor;
    this.legacyPresent = legacy;
  }

  /** `.hub/local.yml`. Unreadable → keep the last good view and never overwrite it. */
  private async loadLocal(): Promise<void> {
    const local = await readLocalFile(this.paths.localYml);
    if (local === null) {
      this.localOk = false;
      this.warnings.set(this.paths.localYml, 'invalid .hub/local.yml — checkout paths unavailable, file left as is');
      return;
    }
    this.localOk = true;
    this.warnings.delete(this.paths.localYml);
    this.localRaw = local;
  }

  /** This device's counter file. First boot of the PRIMARY slot (`""`) seeds from
   *  the per-key max over every counter file, so a lost `.hub/device.yml`
   *  (new device id) can never restart numbering below existing ids. An
   *  unreadable file keeps the last good in-memory counters; with none, id
   *  allocation refuses (`countersLoaded` false) instead of guessing. */
  private async loadCounters(): Promise<void> {
    const file = this.paths.counterFile(this.device.device_id);
    try {
      const own = await readCounterFile(file);
      const disk =
        own ??
        (this.device.slot === ''
          ? await readAllCounters(this.paths.countersDir, (name) =>
              this.logFn(`counters/${name} is not valid and was ignored`),
            )
          : new Map<string, number>());
      // max(memory, disk): a counter file reset or truncated under a running hub
      // (or by a bad merge) can never move numbering backwards.
      const next = new Map(disk);
      for (const [slug, n] of this.counters) if (n > (next.get(slug) ?? 0)) next.set(slug, n);
      this.counters = next;
      this.countersLoaded = true;
      this.warnings.delete(file);
    } catch {
      this.warnings.set(file, 'invalid counter file — id allocation refused until it is fixed');
    }
  }

  private async saveCounters(): Promise<void> {
    await writeCounterFile(this.paths.counterFile(this.device.device_id), this.counters);
  }

  repos(): ReposFile {
    return structuredClone(this.reposRaw);
  }

  /** R4: every lookup into `repos.yml` goes through `hasOwn` — the key can be
   *  `repo_hint` or a hook-supplied slug, and `reposRaw['__proto__']` /
   *  `['constructor']` would otherwise resolve to an Object.prototype member
   *  instead of "unknown repo". `slugSchema` blocks those shapes at the edge;
   *  this is the second line, for callers that never saw a schema. */
  hasRepo(slug: string): boolean {
    return typeof slug === 'string' && Object.hasOwn(this.reposRaw, slug);
  }

  repo(slug: string): RepoConfig {
    if (!this.hasRepo(slug)) {
      throw notFound(`unknown repo "${slug}" — use \`ledger repo add\``);
    }
    return this.reposRaw[slug] as RepoConfig;
  }

  /** Slug or null, without throwing — for hook paths and `repo_hint`. */
  repoOrNull(slug: string | null | undefined): string | null {
    return typeof slug === 'string' && this.hasRepo(slug) ? slug : null;
  }

  /** Absolute checkout path for a repo, or null for a virtual repo. */
  repoPath(slug: string): string | null {
    if (!this.hasRepo(slug)) return null;
    const p = (this.reposRaw[slug] as RepoConfig).path;
    return p ? expandHome(p) : null;
  }

  /** Slug that owns an item id, honouring `prefix_aliases` (SPEC §4.2). */
  repoForItemId(id: string): string | null {
    const prefix = parseItemId(id.trim().toUpperCase())?.prefix;
    if (!prefix) return null;
    for (const [slug, cfg] of Object.entries(this.reposRaw)) {
      if (cfg.prefix === prefix) return slug;
      if (cfg.prefix_aliases?.includes(prefix)) return slug;
    }
    return null;
  }

  /**
   * Write the PORTABLE `repos.yml` (no `path`, `next`, `graphify`, absolute docs)
   * and `.hub/local.yml`. Any format-1 `next` is folded into the counter file
   * first, so dropping the key can never lower a counter.
   */
  private async saveRepos(): Promise<void> {
    await this.flushLegacyFloor();
    const synced: Record<string, Record<string, unknown>> = {};
    const local = new Map<string, RepoLocal>();
    for (const [slug, cfg] of Object.entries(this.reposRaw)) {
      const e: Record<string, unknown> = {};
      if (cfg.kind !== undefined) e.kind = cfg.kind;
      if (cfg.host !== undefined) e.host = cfg.host;
      e.prefix = cfg.prefix;
      const docsRel = (cfg.docs ?? []).filter((d) => !isAbsoluteLike(d));
      const docsAbs = (cfg.docs ?? []).filter(isAbsoluteLike);
      if (docsRel.length > 0) e.docs = docsRel;
      if (cfg.graphify_rel !== undefined) e.graphify_rel = cfg.graphify_rel;
      if (cfg.identity !== undefined) e.identity = cfg.identity;
      if (cfg.prefix_aliases !== undefined) e.prefix_aliases = cfg.prefix_aliases;
      if (cfg.onboarded !== undefined) e.onboarded = cfg.onboarded;
      if (cfg.contracts !== undefined) e.contracts = cfg.contracts;
      if (cfg.consumers !== undefined) e.consumers = cfg.consumers;
      synced[slug] = e;
      const loc: RepoLocal = {};
      if (cfg.path !== null) loc.path = cfg.path;
      if (cfg.graphify) loc.graphify = cfg.graphify;
      if (docsAbs.length > 0) loc.docs = docsAbs;
      if (Object.keys(loc).length > 0) local.set(slug, loc);
    }
    // Local first: if we die in between, a path is still known locally and the
    // stale synced entry is merely redundant — never the reverse.
    if (this.localOk) {
      await writeLocalFile(this.paths.localYml, local);
      this.localRaw = local;
    }
    const text = stringifyYaml(synced, { lineWidth: 0 });
    if ((await readText(this.paths.reposYml)) !== text) {
      await writeAtomic(this.paths.reposYml, text, 0o600);
    }
  }

  /** Persist `max(counter, legacy next - 1)` for every slug that still has a
   *  format-1 `next` in `repos.yml`, then forget the floor. */
  private async flushLegacyFloor(): Promise<void> {
    if (this.legacyFloor.size === 0) return;
    if (!this.countersLoaded) {
      throw new LedgerError(500, 'COUNTERS_INVALID', 'counter file is unreadable — refusing to rewrite repos.yml');
    }
    for (const [slug, n] of this.legacyFloor) {
      if (n > (this.counters.get(slug) ?? 0)) this.counters.set(slug, n);
    }
    await this.saveCounters(); // also repairs an unreadable file from the last good state
    this.legacyFloor = new Map();
  }

  private async ensureRepoFiles(slug: string): Promise<void> {
    await ensureDir(this.paths.repoDir(slug), 0o700);
    await ensureDir(this.paths.itemsDir(slug), 0o700);
    await ensureDir(this.paths.journalDir(slug), 0o700);
    await ensureFile(this.paths.contextFile(slug), contextTemplate(slug), 0o600);
    await ensureFile(this.paths.decisionsFile(slug), decisionsTemplate(slug), 0o600);
  }

  private derivePrefix(slug: string): string {
    const letters = slug.replace(/[^a-z]/g, '').toUpperCase();
    const taken = new Set(Object.values(this.reposRaw).map((r) => r.prefix));
    const candidates: string[] = [];
    const initials = slug
      .split('-')
      .map((part) => part.replace(/[^a-z]/g, '').toUpperCase())
      .filter((p) => p !== '')
      .map((p) => p[0] ?? '')
      .join('');
    if (initials.length >= 2) candidates.push(initials.slice(0, 4));
    for (let len = 2; len <= 4; len += 1) {
      if (letters.length >= len) candidates.push(letters.slice(0, len));
    }
    for (let i = 1; i < letters.length - 1; i += 1) {
      candidates.push(`${letters[0] ?? ''}${letters[i] ?? ''}${letters[i + 1] ?? ''}`);
    }
    for (const c of candidates) {
      if (c.length >= 2 && c.length <= 4 && !taken.has(c)) return c;
    }
    for (let n = 2; n < 100; n += 1) {
      const c = `${letters.slice(0, 2) || 'RP'}${n}`.slice(0, 4).toUpperCase();
      if (/^[A-Z]{2,4}$/.test(c) && !taken.has(c)) return c;
    }
    throw conflict(`cannot derive a free prefix for "${slug}"`);
  }

  /**
   * `ledger repo rm <slug>`.
   *
   * ARCHIVES, never deletes. The ledger is the memory of every session that
   * ever worked in that repo: journals, decisions, CONTEXT.md and the item
   * history are exactly the things a future session would want back if the
   * removal turns out to be a mistake. `<ledger>/<slug>/` is therefore MOVED to
   * `<ledger>/.archive/<slug>-<date>/`, and only the `repos.yml` entry and the
   * runtime rows actually go away.
   *
   * `ops` is refused: it is the hub's own bookkeeping repo, and removing it
   * would leave the hub without a place to journal the removal itself.
   *
   * Ordering matters. The repos.yml entry is dropped BEFORE the directory
   * moves, so a crash in between leaves an unreferenced directory (harmless,
   * recoverable) rather than a registered repo whose files are gone (every
   * later read of that repo would throw).
   */
  async removeRepo(
    slug: string,
    opts: {
      session?: string | null;
      /** H8-1: open claims/leases or live sessions `force: true` overrode —
       *  recorded on the SAME journal line so a forced removal is never
       *  silent about what it ran over. */
      forcedOverHolders?: readonly string[];
    } = {},
  ): Promise<{ slug: string; archived: string | null }> {
    if (slug === 'ops') {
      throw invalid('repo "ops" cannot be removed — it is the hub\'s own bookkeeping repo');
    }
    // OQ-6: `.archive/` is tracked, so with sync on a removal would replicate the move to every
    // peer (and ingress rejects deletes of repo files). Refused until an explicit unbind exists.
    if (this.config.sync) {
      throw conflict(`repo "${slug}" cannot be removed while LEDGER_SYNC=1 (it would propagate to every device)`);
    }
    return this.queue.run(async () => {
      await this.loadRepos();
      if (!this.hasRepo(slug)) throw notFound(`repo "${slug}" does not exist`);

      // Journal into `ops` BEFORE the repo's own dir moves — a line written
      // into `<slug>/journal` would be archived along with it and invisible.
      const journalFields =
        opts.forcedOverHolders && opts.forcedOverHolders.length > 0
          ? [slug, 'force', ...opts.forcedOverHolders]
          : [slug];
      await this.appendJournal('ops', opts.session ?? null, 'repo.removed', journalFields).catch(
        () => undefined,
      );

      delete this.reposRaw[slug];
      await this.saveRepos();

      const src = this.paths.repoDir(slug);
      let archived: string | null = null;
      const exists = await stat(src).then(() => true).catch(() => false);
      if (exists) {
        const archiveRoot = join(this.paths.root, '.archive');
        await mkdir(archiveRoot, { recursive: true, mode: 0o700 });
        // Date suffix, plus a counter if the same repo is removed twice in one
        // day — an existing target would make `rename` clobber or throw.
        const base = `${slug}-${day(new Date())}`;
        let dest = join(archiveRoot, base);
        for (let i = 2; await stat(dest).then(() => true).catch(() => false); i += 1) {
          dest = join(archiveRoot, `${base}-${i}`);
        }
        await renameRetry(src, dest);
        archived = dest;
      }

      // Decisions are read per call from disk — no in-memory cache to evict.
      this.git.touch(`-repo ${slug} (archived)`);
      return { slug, archived };
    });
  }

  async registerRepo(input: RepoRegisterInput): Promise<{ slug: string; cfg: RepoConfig }> {
    // `counters` and `intake` are top-level directories of the ledger itself.
    if (input.slug === 'counters' || input.slug === 'intake') {
      throw invalid(`"${input.slug}" is reserved — pick another slug`);
    }
    let path: string | null = null;
    const kind: RepoKind = input.kind ?? 'repo';
    const hasPath = input.path !== null && input.path !== undefined && input.path !== '';
    if (kind !== 'repo' && hasPath) {
      throw invalid(`repo kind "${kind}" has no path (no git checkout) — omit --path`);
    }
    if (kind !== 'vps' && input.host !== undefined) {
      throw invalid('host can only be set for kind "vps"');
    }
    if (hasPath) {
      const top = await gitToplevel(expandHome(input.path as string));
      if (!top) {
        throw invalid(
          `"${input.path}" is not a git repository (git rev-parse --show-toplevel failed)`,
        );
      }
      path = normalizeGitPath(top);
    }
    const identity = path === null ? undefined : await this.identityFor(path);
    return this.queue.run(async () => {
      await this.loadRepos();
      if (this.hasRepo(input.slug)) throw conflict(`repo "${input.slug}" already exists`);
      const prefix = input.prefix ?? this.derivePrefix(input.slug);
      const clash = Object.entries(this.reposRaw).find(([, cfg]) => cfg.prefix === prefix);
      if (clash) {
        throw conflict(`prefix "${prefix}" is already used by repo "${clash[0]}"`);
      }
      if (path) {
        const dup = Object.entries(this.reposRaw).find(
          ([, cfg]) => cfg.path && samePathGit(expandHome(cfg.path), path as string),
        );
        if (dup) throw conflict(`path "${path}" is already held by repo "${dup[0]}"`);
      }
      // A freshly registered repo has an empty ledger: the next session must be
      // told to fill CONTEXT.md and import existing TODO files before it treats
      // the ledger as authoritative (onboarding, SPEC §4.6 + F1 addendum).
      // A re-registered slug continues after its old counter (ids are never reused).
      const cfg: RepoConfig = {
        prefix,
        path,
        next: (this.counters.get(input.slug) ?? 0) + 1,
        onboarded: input.onboarded ?? false,
      };
      if (identity !== undefined) cfg.identity = identity;
      if (kind !== 'repo') cfg.kind = kind;
      if (kind === 'vps' && input.host) cfg.host = input.host;
      if (input.graphify) cfg.graphify = input.graphify;
      if (input.docs && input.docs.length > 0) cfg.docs = input.docs;
      this.reposRaw[input.slug] = cfg;
      await this.saveRepos();
      await this.ensureRepoFiles(input.slug);
      await this.loadDecisions(input.slug);
      this.git.touch(`+repo ${input.slug} (${prefix})`);
      return { slug: input.slug, cfg };
    });
  }

  /** Resolve a checkout path to a registered slug (CLI cwd → repo). */
  async repoForPath(dir: string): Promise<string | null> {
    const top = await gitToplevel(dir);
    if (!top) return null;
    for (const [slug, cfg] of Object.entries(this.reposRaw)) {
      if (cfg.path && samePathGit(expandHome(cfg.path), top)) return slug;
    }
    return null;
  }

  /**
   * `ledger repo bind <slug> <path>`: point an existing slug at a checkout on
   * THIS machine. Only `.hub/local.yml` changes (plus `identity` when the repo
   * had none). A checkout whose root commit differs from the recorded
   * `identity.root_sha` is refused — binding the wrong repo would route every
   * session in it into another project's ledger.
   */
  async bindRepo(slug: string, rawPath: string): Promise<RepoConfig> {
    if (!this.hasRepo(slug)) throw notFound(`unknown repo "${slug}" — use \`ledger repo add\``);
    // A7: ownership BEFORE any git runs in the directory (its .git/config is attacker-controlled
    // in a checkout another user owns), and again for the resolved toplevel. Fail closed.
    const notGit = (): LedgerError =>
      invalid(`"${rawPath}" is not a git repository (git rev-parse --show-toplevel failed)`);
    const notMine = (): LedgerError =>
      conflict(`"${rawPath}" is not owned by the current user — refusing to bind a checkout you do not own`);
    let realInput: string;
    try {
      realInput = await realpath(expandHome(rawPath));
    } catch {
      throw notGit();
    }
    if (!(await isOwnedByMe(realInput))) throw notMine();
    const top = await gitToplevel(realInput);
    if (!top) throw notGit();
    let realTop: string;
    try {
      realTop = await realpath(top);
    } catch {
      throw notGit();
    }
    if (!(await isOwnedByMe(realTop))) throw notMine();
    const path = normalizeGitPath(top);
    const identity = await this.identityFor(path);
    return this.queue.run(async () => {
      await this.loadRepos();
      const cfg = this.repo(slug);
      if (repoKindOf(cfg) !== 'repo') throw invalid(`repo kind "${repoKindOf(cfg)}" has no checkout to bind`);
      const dup = Object.entries(this.reposRaw).find(
        ([other, c]) => other !== slug && c.path && samePathGit(expandHome(c.path), path),
      );
      if (dup) throw conflict(`path "${path}" is already held by repo "${dup[0]}"`);
      if (cfg.identity !== undefined) {
        if (identity === undefined) {
          throw conflict(`cannot read the root commit of "${path}" — cannot verify it is repo "${slug}"`);
        }
        if (identity.root_sha !== cfg.identity.root_sha) {
          throw conflict(`"${path}" has a different root commit than repo "${slug}" — refusing to bind`);
        }
      }
      cfg.path = path;
      const learned = cfg.identity === undefined && identity !== undefined;
      if (learned) cfg.identity = identity;
      await this.saveRepos();
      if (learned) this.git.touch(`${slug} identity`);
      return cfg;
    });
  }

  /**
   * SessionStart in a checkout no slug points at: if exactly ONE registered repo
   * has this checkout's `root_sha` and no local path yet, bind it (local only).
   * Never creates a slug. Zero or several matches → `null` (the caller may
   * auto-register, or a human uses `ledger repo bind`). The caller must already
   * have established that the checkout belongs to this user.
   */
  async bindByRootSha(checkout: string): Promise<string | null> {
    const identity = await this.identityFor(checkout);
    if (identity === undefined) return null;
    return this.queue.run(async () => {
      await this.loadRepos();
      const path = normalizeGitPath(checkout);
      const held = Object.values(this.reposRaw).some(
        (c) => c.path && samePathGit(expandHome(c.path), path),
      );
      if (held) return null;
      // A template clone shares its root commit with the original, so root_sha alone
      // is only a hint — and `identity` arrives through the synced (peer-controlled)
      // repos.yml. Auto-bind needs an origin on BOTH sides and they must be equal;
      // anything else needs a human: `ledger repo bind <slug> <path>`.
      const hintMatch = (c: RepoConfig): boolean =>
        c.identity?.origin_hint != null &&
        identity.origin_hint !== null &&
        c.identity.origin_hint === identity.origin_hint;
      const matches = Object.entries(this.reposRaw).filter(
        ([, c]) =>
          repoKindOf(c) === 'repo' &&
          c.path === null &&
          c.identity?.root_sha === identity.root_sha &&
          hintMatch(c),
      );
      if (matches.length !== 1) return null;
      const [slug, cfg] = matches[0] as [string, RepoConfig];
      cfg.path = path;
      await this.saveRepos();
      this.logFn(`repo bound by root commit: ${slug}`);
      return slug;
    });
  }

  /* ---------------- reindex ---------------- */

  async reindex(): Promise<void> {
    await this.loadRepos();
    const slugs = new Set(Object.keys(this.reposRaw));
    for (const entry of await safeReaddir(this.paths.root)) {
      if (entry.startsWith('.') || entry === 'intake' || entry === 'counters' || entry === 'repos.yml') continue;
      const st = await safeStat(join(this.paths.root, entry));
      if (st?.isDirectory()) slugs.add(entry);
    }
    for (const slug of slugs) {
      await this.loadItems(slug);
      await this.loadJournalFiles(slug);
      await this.loadDecisions(slug);
      if (this.hasRepo(slug)) await this.detectOnboarded(slug);
    }
    await this.loadIntake();
    this.onReindex?.();
  }

  /** Set by the server so the SQLite search index follows every reindex. */
  onReindex: (() => void) | null = null;

  private async loadItems(slug: string): Promise<void> {
    const dir = this.paths.itemsDir(slug);
    for (const name of await safeReaddir(dir)) {
      if (!name.endsWith('.md')) continue;
      const file = join(dir, name);
      const text = await readText(file);
      if (text === null) continue;
      // Already in the index, byte for byte — parsing it again would
      // produce the identical record at the cost of a synchronous YAML parse.
      if (this.alreadyParsed(file, text)) continue;
      const repairs: ItemRepair[] = [];
      try {
        const { item, doc } = parseItem(text, file, repairs);
        // N-1: a read-time blank is only ever accepted for the `done` subtree —
        // the one field the repair knows how to write back, with the old text moved
        // into the item log. Any other repaired field would be silently
        // persisted by the next unrelated mutation (`writeItem` serializes the
        // repaired frontmatter), so it stays a hard error: the last good version
        // keeps being served and a human sees the warning.
        const unpersistable = repairs.filter(
          (r) => r.path !== 'done' && !r.path.startsWith('done.'),
        );
        if (unpersistable.length > 0) {
          throw new Error(
            `${file}: invalid frontmatter (${unpersistable
              .map((r) => r.path)
              .join(', ')}) — fix by hand, the hub does not rewrite it`,
          );
        }
        this.index.putItem({ item, doc, file });
        if (repairs.length === 0) {
          this.warnings.delete(file);
          this.logged.delete(file);
          continue;
        }
        // Indexed with the bad `done` field blanked — the item stays
        // visible. The file itself is fixed by `migrateRepairedItems()`.
        const detail = logSafe(repairs.map((r) => `${r.path}="${r.value}"`).join(', '));
        this.warnings.set(file, `repaired on read: ${detail}`);
        this.repaired.set(file, { id: item.fm.id, repairs });
        await this.logOnce(file, `reindex: ${basename(file)} — ${detail} blanked in the index`);
      } catch (err) {
        // Keep the last good version in the index; warn in /v1/healthz.
        this.warnings.set(file, logSafe(err instanceof Error ? err.message : String(err)));
        // Once per (path, mtime), not once a minute forever.
        await this.logOnce(file, `reindex: ${basename(file)} skipped — ${String(err)}`);
      }
    }
  }

  /**
   * True when `file` with exactly these bytes is already represented in
   * the in-memory index, so the reindex can skip the parse.
   *
   * Remembers the hash on the way through, so a first pass (or a changed file)
   * always parses. Warnings/repairs of a skipped file are left exactly as the
   * last parse of those same bytes produced them — re-parsing could not reach a
   * different verdict. A mutation always rewrites the file, so the next pass
   * sees new bytes; a hub restart starts with an empty map and parses
   * everything.
   */
  private alreadyParsed(file: string, text: string): boolean {
    const hash = createHash('sha1').update(text).digest('hex');
    if (this.parsedHash.get(file) === hash) return true;
    this.parsedHash.set(file, hash);
    return false;
  }

  /** The same unreadable file logs once until its bytes change.
   *  S-2: always one line — a YAML parse error quotes the offending file, so an
   *  item could otherwise forge a `SECURITY: …` line in `hub.log`. */
  private async logOnce(file: string, line: string): Promise<void> {
    const st = await safeStat(file);
    const key = `${st?.mtimeMs ?? 0}:${st?.size ?? 0}`;
    if (this.logged.get(file) === key) return;
    this.logged.set(file, key);
    this.logFn(logSafe(line));
  }

  /**
   * startup migration: items whose `done.version` held prose instead of
   * a ref. The text moves into the item log, the field becomes null, and the
   * write goes through the serial queue + tmp/rename like any other mutation.
   * Idempotent: once the file is clean, the reindex stops flagging it.
   */
  async migrateRepairedItems(): Promise<number> {
    const pending = [...this.repaired.entries()];
    let fixed = 0;
    for (const [file, { id, repairs }] of pending) {
      const rec = this.index.getItem(id);
      // S-5: the index is keyed by id; migrate only when it still points at the
      // very file this repair came from (two files claiming one id otherwise
      // clear the wrong warning).
      if (!rec || rec.file !== file) {
        this.repaired.delete(file);
        continue;
      }
      try {
        await this.queue.run(async () => {
          for (const r of repairs) {
            appendLog(
              rec.doc,
              rec.item,
              'hub',
              `migration: ${r.path} was not a valid ref, moved out of frontmatter: ${
                escapeStructuralLines(r.value)
              }`,
            );
          }
          await this.writeItem(rec);
        });
        this.repaired.delete(file);
        this.warnings.delete(file);
        this.logged.delete(file);
        fixed += 1;
        this.logFn(`migration: ${basename(file)} repaired (${repairs.length})`);
      } catch (err) {
        this.logFn(`migration: ${basename(file)} failed — ${String(err)}`);
      }
    }
    if (fixed > 0) this.git.touch(`migration (${fixed} items)`);
    return fixed;
  }

  private async loadJournalFiles(slug: string): Promise<void> {
    const dir = this.paths.journalDir(slug);
    for (const name of await safeReaddir(dir)) {
      if (!name.endsWith('.md')) continue;
      const file = join(dir, name);
      const text = await readText(file);
      if (text === null) continue;
      if (this.alreadyParsed(file, text)) continue;
      this.index.setJournal(slug, name.replace(/\.md$/, ''), collapseRolling(parseJournal(text, slug)));
    }
  }

  private async loadDecisions(slug: string): Promise<void> {
    const text = await readText(this.paths.decisionsFile(slug));
    this.index.setDecisions(slug, text === null ? [] : parseDecisions(text, slug));
  }

  private async loadIntake(): Promise<void> {
    for (const monthDir of await safeReaddir(this.paths.intakeRoot)) {
      const dir = this.paths.intakeDir(monthDir);
      for (const name of await safeReaddir(dir)) {
        if (!name.endsWith('.md')) continue;
        const file = join(dir, name);
        const text = await readText(file);
        if (text === null) continue;
        if (this.alreadyParsed(file, text)) continue;
        try {
          const { rec, doc } = parseIntake(text, file);
          this.index.putIntake({ rec, doc, file });
          this.warnings.delete(file);
        } catch (err) {
          this.warnings.set(file, err instanceof Error ? err.message : String(err));
        }
      }
    }
  }

  /* ---------------- items ---------------- */

  getItem(id: string): StoredItem {
    const rec = this.index.getItem(id);
    if (!rec) throw notFound(`item ${id} does not exist`);
    return rec;
  }

  listItems(filter: ItemFilter = {}): Item[] {
    if (filter.repo) this.repo(filter.repo);
    return this.index.listItems(filter).map((r) => r.item);
  }

  private async writeItem(rec: StoredItem): Promise<void> {
    rec.item.fm.updated = isoLocal();
    const text = serializeItem(rec.item, rec.doc);
    await writeAtomic(rec.file, text, 0o600);
    // Re-parse so the in-memory doc matches the bytes on disk exactly.
    const reparsed = parseItem(text, rec.file);
    this.index.putItem({ item: reparsed.item, doc: reparsed.doc, file: rec.file });
  }

  private async appendJournal(
    repo: string,
    session: string | null | undefined,
    type: string,
    fields: string[],
  ): Promise<void> {
    const at = new Date();
    const file = this.paths.journalFile(repo, month(at));
    if ((await readText(file)) === null) {
      await writeAtomic(file, `# ${repo} — journal ${month(at)}\n`, 0o600);
    }
    const line = journalLine({ at: stamp(at), session: shortSession(session), type, fields });
    await appendLine(file, line, 0o600);
    const events = collapseRolling(parseJournal((await readText(file)) ?? '', repo));
    this.index.setJournal(repo, month(at), events);
  }

  async createItem(input: CreateItemInput): Promise<Item> {
    this.repo(input.repo);
    for (const blocker of input.blocked_by) this.getItem(blocker);
    return this.queue.run(async () => {
      await this.loadRepos();
      const cfg = this.repo(input.repo);
      if (!this.countersLoaded) {
        throw new LedgerError(
          500,
          'COUNTERS_INVALID',
          'this device\'s counter file is unreadable — refusing to allocate ids (fix counters/ or restore it)',
        );
      }
      const slug = input.repo;
      let allocated = Math.max(this.counters.get(slug) ?? 0, this.legacyFloor.get(slug) ?? 0) + 1;
      // Never overwrite an existing item file, whatever the counter says (lost or
      // reset counter, hand-copied item): skip forward to the first free number.
      for (let tries = 0; ; tries += 1) {
        const taken = await stat(
          this.paths.itemFile(slug, formatItemId(cfg.prefix, this.device.slot, allocated)),
        ).then(() => true, () => false);
        if (!taken) break;
        if (tries >= 10_000) throw conflict(`no free item number found for repo "${slug}"`);
        allocated += 1;
      }
      const id = formatItemId(cfg.prefix, this.device.slot, allocated);
      // The counter moves BEFORE the item is written, so two concurrent creates can
      // never share an id; every failure path below puts it back.
      const before = this.counters.get(slug);
      this.counters.set(slug, allocated);
      cfg.next = allocated + 1;
      const restore = (): void => {
        if (this.counters.get(slug) !== allocated) return; // somebody allocated past us
        if (before === undefined) this.counters.delete(slug);
        else this.counters.set(slug, allocated - 1);
        cfg.next = allocated;
      };
      try {
        await this.saveCounters();
      } catch (err) {
        restore();
        throw err;
      }
      let created: Item;
      try {
        created = await this.writeNewItem(id, input);
      } catch (err) {
        // The counter is bumped before the item is written. If the write then
        // fails (ENOSPC, EACCES, a bad schema), keep the id reusable instead of
        // leaving a permanent hole in the sequence — but only when nobody has
        // allocated past us in the meantime.
        const wasCurrent = this.counters.get(slug) === allocated;
        restore();
        if (wasCurrent) {
          await this.saveCounters().catch(() => undefined);
          this.logFn(`${id}: write failed, id returned to counter=${allocated - 1}`);
        }
        throw err;
      }
      // Marking the intake record is a FOLLOW-UP effect, deliberately outside the
      // item's own write/rollback boundary above. The item exists on disk by
      // now; failing the create (and rolling the id back) because a second file
      // could not be updated would be the worse half-state. Logged, not thrown.
      if (input.intake !== null && input.intake !== undefined) {
        try {
          await this.markIntakeLinked(input.intake, created, input.session);
        } catch (err) {
          this.logFn(`${id}: could not mark intake ${input.intake}: ${String(err)}`);
        }
      }
      return created;
    });
  }

  /**
   * `ledger add --intake <id>` now marks the intake record itself — agents
   * kept forgetting the separate `ledger intake triage` step, so records stayed
   * `new` long after items had been cut from them. Explicit `triage` stays for
   * what this cannot express: `partial` and `--drop`.
   *
   * The status only moves FORWARD. A record that produced an item is processed,
   * so `new`/`partial` → `triaged` and `triaged` stays — nothing here ever
   * writes `new` back.
   *
   * Runs INSIDE the caller's `queue.run`: `SerialQueue` is not reentrant, so
   * this must not call `triage()` (which takes the queue itself).
   */
  private async markIntakeLinked(
    intakeId: string,
    item: Item,
    session: string | null | undefined,
  ): Promise<void> {
    const stored = this.index.getIntake(intakeId);
    // An unknown intake id is recorded on the item (`fm.intake`) and nothing else —
    // the same tolerance `createItem` always had for it.
    if (!stored) return;
    const rec = stored.rec;
    if (!rec.items.includes(item.fm.id)) rec.items.push(item.fm.id);
    if (!rec.triage.some((t) => t.item === item.fm.id)) {
      rec.triage.push({ item: item.fm.id, excerpt: item.fm.title });
    }
    rec.status = 'triaged';
    const text = serializeIntake(rec, stored.doc);
    await writeAtomic(stored.file, text, 0o600);
    const reparsed = parseIntake(text, stored.file);
    this.index.putIntake({ rec: reparsed.rec, doc: reparsed.doc, file: stored.file });
    await this.appendJournal(item.fm.repo, session, 'intake.linked', [rec.id, item.fm.id]);
    this.git.touch(`intake ${rec.id} → ${item.fm.id}`);
  }

  private async writeNewItem(id: string, input: CreateItemInput): Promise<Item> {
    const now = isoLocal();
    const status: ItemStatus = input.status
      ? (input.status as ItemStatus)
      : input.proposed
        ? 'proposed'
        : input.blocked_by.length > 0
          ? 'blocked'
          : 'open';
    const fm: ItemFrontmatter = {
      id,
      title: input.title,
      status,
      kind: input.kind as ItemFrontmatter['kind'],
      priority: input.priority as ItemFrontmatter['priority'],
      owner: input.owner,
      repo: input.repo,
      area: (input.area ?? null) as ItemFrontmatter['area'],
      paths: [],
      blocks: [],
      blocked_by: [...input.blocked_by],
      requested_by: input.requested_by ?? null,
      intake: input.intake ?? null,
      aliases: [...input.aliases],
      claimed_by: null,
      source: {
        session: input.session ?? null,
        agent: input.agent ?? null,
        commit: null,
      },
      done: null,
      created: now,
      updated: now,
    };
    const steps: PlanStep[] = input.steps.map((text, i) => ({ n: i + 1, done: false, text }));
    const item: Item = {
      fm,
      why: input.why ?? '',
      steps,
      rec: input.rec ?? '',
      comments: [],
      log: [
        {
          at: stamp(),
          session: shortSession(input.session),
          text: input.intake ? 'created from intake' : 'created',
        },
      ],
    };
    const doc = applyItem(newItemDoc(fm), item);
    const file = this.paths.itemFile(input.repo, id);
    await ensureDir(this.paths.itemsDir(input.repo), 0o700);
    const text = serializeItem(item, doc);
    await writeAtomic(file, text, 0o600);
    const stored = parseItem(text, file);
    this.index.putItem({ item: stored.item, doc: stored.doc, file });

    // Reciprocal `blocks` on the blocking items.
    for (const blockerId of input.blocked_by) {
      const blocker = this.index.getItem(blockerId);
      if (!blocker || blocker.item.fm.blocks.includes(id)) continue;
      blocker.item.fm.blocks.push(id);
      await this.writeItem(blocker);
    }

    await this.appendJournal(input.repo, input.session, 'item.created', [
      id,
      `${fm.kind} ${fm.priority}`,
      fm.title,
    ]);
    this.git.touch(`+${id}`);
    return stored.item;
  }

  /** `from → to` mapped onto the transition table of SPEC §4.4. */
  private transitionFor(from: ItemStatus, to: ItemStatus): Transition {
    if (to === 'open') {
      if (from === 'proposed') return 'open';
      if (from === 'doing') return 'release';
      if (from === 'blocked') return 'unblock';
      return 'reopen';
    }
    if (to === 'doing') return 'claim';
    if (to === 'blocked') return 'block';
    if (to === 'done') return 'done';
    if (to === 'dropped') return 'drop';
    throw invalid(`unknown target status "${to}"`);
  }

  private assertTransition(item: Item, t: Transition): void {
    if (!canTransition(item.fm.status, t)) {
      throw conflict(`${item.fm.id}: ${transitionError(item.fm.status, t)}`);
    }
  }

  /** Any mutation of one item: load, mutate, log, journal, write, unblock. */
  private mutate(
    id: string,
    session: string | null | undefined,
    logText: string | null,
    journal: { type: string; fields: string[] } | null,
    fn: (rec: StoredItem) => void | Promise<void>,
  ): Promise<Item> {
    return this.queue.run(async () => {
      const rec = this.getItem(id);
      const before = rec.item.fm.status;
      await fn(rec);
      if (logText) {
        rec.item.log.push({ at: stamp(), session: shortSession(session), text: logText });
      }
      await this.writeItem(rec);
      const after = this.getItem(id).item;
      if (journal) {
        await this.appendJournal(after.fm.repo, session, journal.type, journal.fields);
      }
      if (before !== after.fm.status && !isOpen(after.fm.status)) {
        await this.cascadeUnblock(id, session);
      }
      this.git.touch(`${id} ${before}→${after.fm.status}`);
      return this.getItem(id).item;
    });
  }

  /** A closed item can unblock others (SPEC §4.4: hub does it automatically). */
  private async cascadeUnblock(closedId: string, session: string | null | undefined): Promise<void> {
    for (const rec of this.index.listItems()) {
      if (!rec.item.fm.blocked_by.includes(closedId)) continue;
      if (rec.item.fm.status !== 'blocked') continue;
      const stillBlocked = rec.item.fm.blocked_by.some((bid) => {
        const other = this.index.getItem(bid);
        return other ? isOpen(other.item.fm.status) : true;
      });
      if (stillBlocked) continue;
      rec.item.fm.status = 'open';
      rec.item.log.push({
        at: stamp(),
        session: shortSession(session),
        text: `unblocked — closed ${rec.item.fm.blocked_by.join(', ')}`,
      });
      await this.writeItem(rec);
      await this.appendJournal(rec.item.fm.repo, session, 'item.status', [
        rec.item.fm.id,
        'blocked→open',
        'unblocked automatically',
      ]);
    }
  }

  async patchItem(
    id: string,
    patch: {
      title?: string;
      status?: string;
      owner?: string;
      kind?: string;
      priority?: string;
      area?: string | null;
      why?: string;
      rec?: string;
      steps?: string[];
      session?: string | null;
      why_note?: string;
    },
  ): Promise<Item> {
    const current = this.getItem(id).item;
    const changes: string[] = [];
    if (patch.status && patch.status !== current.fm.status) {
      this.assertTransition(current, this.transitionFor(current.fm.status, patch.status as ItemStatus));
    }
    const journal = patch.status
      ? {
          type: 'item.status',
          fields: [
            id,
            `${current.fm.status}→${patch.status}`,
            ...(patch.why_note ? [patch.why_note] : []),
          ],
        }
      : null;
    return this.mutate(
      id,
      patch.session,
      null,
      journal,
      (rec) => {
        const fm = rec.item.fm;
        if (patch.title !== undefined && patch.title !== fm.title) {
          changes.push('title');
          fm.title = patch.title;
        }
        if (patch.owner !== undefined && patch.owner !== fm.owner) {
          changes.push(`owner=${patch.owner}`);
          fm.owner = patch.owner;
        }
        if (patch.kind !== undefined && patch.kind !== fm.kind) {
          changes.push(`kind=${patch.kind}`);
          fm.kind = patch.kind as ItemFrontmatter['kind'];
        }
        if (patch.priority !== undefined && patch.priority !== fm.priority) {
          changes.push(`priority=${patch.priority}`);
          fm.priority = patch.priority as ItemFrontmatter['priority'];
        }
        if (patch.area !== undefined && patch.area !== fm.area) {
          changes.push(`area=${String(patch.area)}`);
          fm.area = patch.area as ItemFrontmatter['area'];
        }
        if (patch.why !== undefined) {
          changes.push('why');
          rec.item.why = patch.why;
        }
        if (patch.rec !== undefined) {
          changes.push('rec');
          rec.item.rec = patch.rec;
        }
        if (patch.steps !== undefined) {
          changes.push('plan');
          rec.item.steps = patch.steps.map((text, i) => ({ n: i + 1, done: false, text }));
        }
        if (patch.status !== undefined && patch.status !== fm.status) {
          changes.push(`${fm.status}→${patch.status}`);
          fm.status = patch.status as ItemStatus;
          if (fm.status === 'done' && !fm.done) {
            fm.done = { commit: null, version: null, at: isoLocal() };
          }
          if (fm.status === 'open') {
            fm.claimed_by = null;
            fm.paths = [];
            if (patch.status === 'open') fm.done = null;
          }
        }
        const note = patch.why_note ? ` — ${escapeStructuralLines(patch.why_note)}` : '';
        rec.item.log.push({
          at: stamp(),
          session: shortSession(patch.session),
          text: `edit: ${changes.join(', ') || 'no change'}${note}`,
        });
      },
    );
  }

  async claim(id: string, input: { session: string; paths: string[]; intent?: string }): Promise<Item> {
    const current = this.getItem(id).item;
    if (current.fm.status === 'doing' && current.fm.claimed_by) {
      const holder = current.fm.claimed_by.session;
      if (holder !== input.session) {
        throw conflict(`${id} is already held by session ${holder} (since ${current.fm.claimed_by.since})`);
      }
    }
    this.assertTransition(current, 'claim');
    const intent = input.intent ? ` · intent: ${input.intent}` : '';
    return this.mutate(
      id,
      input.session,
      `claim · ${input.paths.join(', ') || 'no paths'}${intent}`,
      { type: 'item.status', fields: [id, 'open→doing', input.paths.join(', ')] },
      (rec) => {
        rec.item.fm.status = 'doing';
        rec.item.fm.claimed_by = { session: input.session, since: isoLocal() };
        rec.item.fm.paths = [...input.paths];
      },
    );
  }

  async release(id: string, input: { session?: string | null; why?: string }): Promise<Item> {
    const current = this.getItem(id).item;
    this.assertTransition(current, 'release');
    return this.mutate(
      id,
      input.session,
      `release${input.why ? ` — ${input.why}` : ''}`,
      { type: 'item.status', fields: [id, 'doing→open', ...(input.why ? [input.why] : [])] },
      (rec) => {
        rec.item.fm.status = 'open';
        rec.item.fm.claimed_by = null;
        rec.item.fm.paths = [];
      },
    );
  }

  async done(id: string, input: { session?: string | null; ref?: string }): Promise<Item> {
    const current = this.getItem(id).item;
    this.assertTransition(current, 'done');
    const ref = input.ref?.trim() ?? '';
    // The write path validates with the same predicate the frontmatter
    // reader uses, so nothing lands on disk that a later reindex would reject.
    if (ref !== '' && !isDoneRef(ref)) {
      throw invalid(`invalid --ref "${ref.slice(0, 80)}": ${DONE_REF_HINT.replace('<ID>', id)}`);
    }
    const isCommit = /^[0-9a-f]{7,40}$/i.test(ref);
    return this.mutate(
      id,
      input.session,
      `done${ref ? ` · ${ref}` : ''}`,
      { type: 'item.status', fields: [id, `${current.fm.status}→done`, ...(ref ? [ref] : [])] },
      (rec) => {
        rec.item.fm.status = 'done';
        rec.item.fm.claimed_by = null;
        rec.item.fm.paths = [];
        rec.item.fm.done = {
          commit: isCommit ? ref : null,
          version: !isCommit && ref !== '' ? ref : null,
          at: isoLocal(),
        };
      },
    );
  }

  async drop(id: string, input: { session?: string | null; why: string }): Promise<Item> {
    const current = this.getItem(id).item;
    this.assertTransition(current, 'drop');
    return this.mutate(
      id,
      input.session,
      `dropped — ${input.why}`,
      { type: 'item.status', fields: [id, `${current.fm.status}→dropped`, input.why] },
      (rec) => {
        rec.item.fm.status = 'dropped';
        rec.item.fm.claimed_by = null;
        rec.item.fm.paths = [];
      },
    );
  }

  async dup(id: string, input: { session?: string | null; into: string }): Promise<Item> {
    if (id === input.into) throw invalid('an item cannot be a duplicate of itself');
    const target = this.getItem(input.into);
    const current = this.getItem(id).item;
    this.assertTransition(current, 'drop');
    const item = await this.mutate(
      id,
      input.session,
      `duplicate → ${input.into}`,
      { type: 'item.status', fields: [id, `${current.fm.status}→dropped`, `dup → ${input.into}`] },
      (rec) => {
        rec.item.fm.status = 'dropped';
        rec.item.fm.claimed_by = null;
        rec.item.fm.paths = [];
      },
    );
    if (!target.item.fm.aliases.includes(id)) {
      await this.mutate(input.into, input.session, `merged ${id}`, null, (rec) => {
        rec.item.fm.aliases.push(id);
      });
    }
    return item;
  }

  async block(
    id: string,
    input: { session?: string | null; by?: string; on?: 'human' },
  ): Promise<Item> {
    const current = this.getItem(id).item;
    this.assertTransition(current, 'block');
    if (input.by) {
      const blocker = this.getItem(input.by);
      const item = await this.mutate(
        id,
        input.session,
        `blocked ← ${input.by}`,
        { type: 'item.status', fields: [id, `${current.fm.status}→blocked`, `← ${input.by}`] },
        (rec) => {
          rec.item.fm.status = 'blocked';
          if (!rec.item.fm.blocked_by.includes(input.by as string)) {
            rec.item.fm.blocked_by.push(input.by as string);
          }
        },
      );
      if (!blocker.item.fm.blocks.includes(id)) {
        await this.mutate(input.by, input.session, `blokuje ${id}`, null, (rec) => {
          rec.item.fm.blocks.push(id);
        });
      }
      return item;
    }
    return this.mutate(
      id,
      input.session,
      'blocked ← human',
      { type: 'item.status', fields: [id, `${current.fm.status}→blocked`, '← human'] },
      (rec) => {
        rec.item.fm.status = 'blocked';
        rec.item.fm.owner = 'human';
      },
    );
  }

  async reopen(id: string, input: { session?: string | null; why: string }): Promise<Item> {
    const current = this.getItem(id).item;
    const t = current.fm.status === 'blocked' ? 'unblock' : 'reopen';
    this.assertTransition(current, t);
    return this.mutate(
      id,
      input.session,
      `reopen — ${input.why}`,
      { type: 'item.status', fields: [id, `${current.fm.status}→open`, input.why] },
      (rec) => {
        rec.item.fm.status = 'open';
        rec.item.fm.done = null;
        rec.item.fm.claimed_by = null;
      },
    );
  }

  async comment(
    id: string,
    input: { session?: string | null; author: string; text: string },
  ): Promise<{ item: Item; commentId: string }> {
    const commentId = generate();
    const item = await this.mutate(
      id,
      input.session,
      null,
      { type: 'item.comment', fields: [id, input.author] },
      (rec) => {
        rec.item.comments.push({
          at: stamp(),
          author: input.author,
          id: commentId,
          text: input.text,
        });
      },
    );
    return { item, commentId };
  }

  async step(id: string, input: { session?: string | null; n: number; done: boolean }): Promise<Item> {
    const current = this.getItem(id).item;
    const target = current.steps.find((s) => s.n === input.n);
    if (!target) throw notFound(`${id}: step ${input.n} does not exist`);
    return this.mutate(
      id,
      input.session,
      `krok ${input.n} ${input.done ? 'done' : 'undo'} · ${target.text}`,
      null,
      (rec) => {
        const s = rec.item.steps.find((x) => x.n === input.n);
        if (s) s.done = input.done;
      },
    );
  }

  /* ---------------- intake ---------------- */

  async createIntake(input: {
    text: string;
    channel: 'chat' | 'web';
    session?: string | null;
    repo_hint?: string | null;
  }): Promise<IntakeRecord> {
    return this.queue.run(async () => {
      const at = new Date();
      const id = generate();
      const rec: IntakeRecord = {
        id,
        at: isoLocal(at),
        channel: input.channel,
        session: input.session ?? null,
        repo_hint: input.repo_hint ?? null,
        status: 'new',
        items: [],
        text: input.text,
        triage: [],
        dropped: [],
      };
      const file = this.paths.intakeFile(month(at), id);
      await ensureDir(this.paths.intakeDir(month(at)), 0o700);
      const text = serializeIntake(rec);
      await writeAtomic(file, text, 0o600);
      const stored = parseIntake(text, file);
      this.index.putIntake({ rec: stored.rec, doc: stored.doc, file });
      this.git.touch(`intake +${id}`);
      return stored.rec;
    });
  }

  getIntake(id: string): IntakeRecord {
    const rec = this.index.getIntake(id);
    if (!rec) throw notFound(`intake record ${id} does not exist`);
    return rec.rec;
  }

  listIntake(status?: string): IntakeRecord[] {
    return this.index.listIntake(status).map((r) => r.rec);
  }

  /** What the brief and `ledger status` count — see `isIntakeUnprocessed`.
   *  Narrower than `listIntake('new')`, which also counted records that had
   *  items cut from them before this rule and records being triaged right now. */
  listIntakeUnprocessed(now: number = Date.now()): IntakeRecord[] {
    return this.listIntake('new').filter((rec) => isIntakeUnprocessed(rec, now));
  }

  async triage(
    id: string,
    input: {
      session?: string | null;
      items: string[];
      dropped: { text: string; reason: string }[];
      status?: IntakeStatus;
    },
  ): Promise<IntakeRecord> {
    const stored = this.index.getIntake(id);
    if (!stored) throw notFound(`intake record ${id} does not exist`);
    for (const itemId of input.items) this.getItem(itemId);
    return this.queue.run(async () => {
      const rec = stored.rec;
      for (const itemId of input.items) {
        if (!rec.items.includes(itemId)) rec.items.push(itemId);
        const item = this.index.getItem(itemId);
        if (!item) continue;
        const excerpt = item.item.fm.title;
        if (!rec.triage.some((t) => t.item === itemId)) rec.triage.push({ item: itemId, excerpt });
        if (item.item.fm.intake !== rec.id) {
          item.item.fm.intake = rec.id;
          item.item.log.push({
            at: stamp(),
            session: shortSession(input.session),
            text: `linked to intake ${rec.id}`,
          });
          await this.writeItem(item);
        }
      }
      for (const d of input.dropped) {
        if (!rec.dropped.some((x) => x.text === d.text)) rec.dropped.push(d);
      }
      rec.status = input.status ?? (input.items.length > 0 ? 'triaged' : 'partial');
      const text = serializeIntake(rec, stored.doc);
      await writeAtomic(stored.file, text, 0o600);
      const reparsed = parseIntake(text, stored.file);
      this.index.putIntake({ rec: reparsed.rec, doc: reparsed.doc, file: stored.file });
      // R4: `repo_hint` is free-form input from the CLI / web intake.
      const repo = this.repoOrNull(rec.repo_hint);
      const journalRepo =
        repo ?? this.index.getItem(input.items[0] ?? '')?.item.fm.repo ?? 'ops';
      await this.appendJournal(journalRepo, input.session, 'intake.triaged', [
        rec.id,
        rec.items.join(', ') || 'no items',
        ...(rec.dropped.length > 0 ? [`dropped ${rec.dropped.length}`] : []),
      ]);
      this.git.touch(`intake ${rec.id} → ${rec.items.join(',') || 'nothing'}`);
      return reparsed.rec;
    });
  }

  /* ---------------- decisions & journal ---------------- */

  listDecisions(repo?: string): Decision[] {
    if (repo) this.repo(repo);
    return this.index.listDecisions(repo);
  }

  async createDecision(input: {
    repo: string;
    title: string;
    why: string;
    related: string[];
    session?: string | null;
  }): Promise<Decision> {
    this.repo(input.repo);
    return this.queue.run(async () => {
      const file = this.paths.decisionsFile(input.repo);
      const existingText = (await readText(file)) ?? decisionsTemplate(input.repo);
      const existing = parseDecisions(existingText, input.repo);
      const n = nextDecisionNumber(existing);
      const body =
        input.related.length > 0
          ? `${input.why.trim()}\nRelated: ${input.related.join(' · ')}`
          : input.why.trim();
      const decision: Decision = { n, date: day(), title: input.title, body, repo: input.repo };
      const next = `${existingText.replace(/\s*$/, '')}\n\n${serializeDecision(decision)}`;
      await writeAtomic(file, next, 0o600);
      this.index.setDecisions(input.repo, parseDecisions(next, input.repo));
      await this.appendJournal(input.repo, input.session, 'decision', [
        `D${n}`,
        decision.title,
      ]);
      this.git.touch(`${input.repo} D${n}`);
      return decision;
    });
  }

  listJournal(repo?: string, sinceMs?: number): JournalEvent[] {
    if (repo) this.repo(repo);
    const events = this.index.listJournal(repo);
    if (sinceMs === undefined) return events;
    const cutoff = Date.now() - sinceMs;
    return events.filter((ev) => {
      const t = parseEventTime(ev.at);
      return t === null ? true : t >= cutoff;
    });
  }

  async appendJournalEntry(input: {
    repo: string;
    text: string;
    type: string;
    session?: string | null;
  }): Promise<JournalEvent> {
    this.repo(input.repo);
    return this.queue.run(async () => {
      const oneLine = input.text.replace(/\s*\n\s*/g, ' · ').trim();
      await this.appendJournal(input.repo, input.session, input.type, [oneLine]);
      this.git.touch(`${input.repo} ${input.type}`);
      return {
        at: stamp(),
        session: shortSession(input.session),
        type: input.type,
        fields: [oneLine],
        repo: input.repo,
      };
    });
  }

  async contextFor(repo: string): Promise<string | null> {
    return readText(this.paths.contextFile(repo));
  }

  /* ---------------- F1: journal from hooks and watchers ---------------- */

  /**
   * Append one journal event with pre-split fields. Unlike
   * `appendJournalEntry` this does not require the repo to exist in
   * `repos.yml` — the commit watcher and the session hooks can fire for a repo
   * that was just unregistered, and losing the event is worse than writing it
   * under its slug directory. Fields are sanitised at the sink (F-1).
   */
  async appendJournalEvent(
    repo: string,
    session: string | null | undefined,
    type: string,
    fields: string[],
  ): Promise<void> {
    await this.queue.run(async () => {
      await this.appendJournal(repo, session, type, fields);
      this.git.touch(`${repo} ${type}`);
    });
  }

  /**
   * Append this session's rolling summary line to the current month's file.
   *
   * The journal is APPEND-ONLY (ledger format 2: two devices merge journals as a
   * line union, and a rewrite would resurrect or lose lines). A rolling session
   * summary is the same fact restated more completely, so readers collapse
   * `session.summary` to the latest line per session (`collapseRolling`) —
   * the brief and `listJournal` still show one per session. A line identical to
   * the session's latest one is not appended again.
   *
   * Only ever used for `session.summary`; the signature takes the type so the
   * rule is visible at the call site rather than hidden in here.
   */
  async upsertJournalEvent(
    repo: string,
    session: string | null | undefined,
    type: 'session.summary',
    fields: string[],
  ): Promise<void> {
    await this.queue.run(async () => {
      const at = new Date();
      const file = this.paths.journalFile(repo, month(at));
      const short = shortSession(session) || '—';
      const line = sanitizeLine(journalLine({ at: stamp(at), session: short, type, fields }));
      let existing = await readText(file);
      if (existing === null) {
        await writeAtomic(file, `# ${repo} — journal ${month(at)}\n`, 0o600); // create only
        existing = '';
      }
      // Match on the session and type columns of the rendered line.
      const marker = `${SEP}${short}${SEP}${type}${SEP}`;
      const lines = existing.split(/\r?\n/);
      let latest: string | undefined;
      for (let i = lines.length - 1; i >= 0; i -= 1) {
        if ((lines[i] ?? '').includes(marker)) {
          latest = lines[i];
          break;
        }
      }
      // Identical apart from the minute stamp = nothing new to say.
      const stripAt = (l: string): string => l.replace(/^(\s*-\s*)\d{4}-\d{2}-\d{2} \d{2}:\d{2}/, '$1');
      if (latest === undefined || stripAt(latest.trim()) !== stripAt(line)) {
        await appendLine(file, line, 0o600);
      }
      this.index.setJournal(
        repo,
        month(at),
        collapseRolling(parseJournal((await readText(file)) ?? '', repo)),
      );
      this.git.touch(`${repo} ${type}`);
    });
  }

  /* ---------------- F1: commits and releases (SPEC §12) ---------------- */

  /** `Closes: <ID>` — close the item and stamp the commit on it. Idempotent:
   *  a second delivery of the same commit is a no-op.
   *
   *  G2: `id` comes from parsing a commit message trailer — it can name any
   *  item in the ledger, including one that belongs to a different repo than
   *  the one this commit came from (e.g. a copy-pasted `Closes: WEB-5` in an
   *  `acme` commit). Only close/stamp an item whose repo (by
   *  `repoForItemId`, which honours `prefix_aliases`) matches `slug` the
   *  commit was read from; a foreign ID is ignored and journalled, never
   *  silently resolved against another repo's item. */
  async closeByCommit(
    slug: string,
    id: string,
    commit: { sha: string; short: string; subject: string; at: string; session?: string | null },
  ): Promise<Item | null> {
    if (this.repoForItemId(id) !== slug) {
      await this.appendJournalEvent(slug, commit.session ?? null, 'item.status', [
        id,
        'ignored',
        commit.short,
        'Closes belongs to another repo',
      ]);
      return null;
    }
    const rec = this.index.getItem(id);
    if (!rec) return null;
    const fm = rec.item.fm;
    if (
      fm.status === 'done' &&
      fm.done !== null &&
      fm.done.commit !== null &&
      commitMatches(fm.done.commit, commit.sha)
    ) {
      return rec.item;
    }
    if (!isOpen(fm.status)) {
      // Already done/dropped by something else — record the commit, do not
      // resurrect a transition that a human closed deliberately.
      await this.logItem(slug, id, commit.session, `commit ${commit.short} · ${commit.subject}`);
      return this.index.getItem(id)?.item ?? null;
    }
    return this.mutate(
      id,
      commit.session,
      `done commitom ${commit.short} · ${commit.subject}`,
      { type: 'item.status', fields: [id, `${fm.status}→done`, commit.short, commit.subject] },
      (r) => {
        r.item.fm.status = 'done';
        r.item.fm.claimed_by = null;
        r.item.fm.paths = [];
        r.item.fm.done = { commit: commit.sha, version: null, at: isoLocal(new Date(commit.at)) };
        r.item.fm.source.commit = commit.sha;
      },
    );
  }

  /** `Refs: <ID>` — a log line on the item, no transition. G2: same
   *  cross-repo guard as `closeByCommit`. */
  async logItem(
    slug: string,
    id: string,
    session: string | null | undefined,
    text: string,
  ): Promise<Item | null> {
    if (this.repoForItemId(id) !== slug) {
      await this.appendJournalEvent(slug, session ?? null, 'item.status', [
        id,
        'ignored',
        'Refs belongs to another repo',
      ]);
      return null;
    }
    if (!this.index.getItem(id)) return null;
    return this.mutate(id, session, text, null, () => undefined);
  }

  /** A `v*` tag covering this item's closing commit (SPEC §12). */
  async setDoneVersion(id: string, version: string): Promise<Item | null> {
    const rec = this.index.getItem(id);
    if (!rec || rec.item.fm.done === null) return null;
    if (rec.item.fm.done.version === version) return rec.item;
    return this.mutate(id, null, `release ${version}`, null, (r) => {
      if (r.item.fm.done) r.item.fm.done.version = version;
    });
  }

  /** Items in `slug` closed by any of `shas` (full 40-hex) and still without
   *  a version. G3: scoped to `slug` and matched on the full sha — a 7-char
   *  abbreviation can collide between two different repos' commits, and an
   *  unscoped scan could tag an item from a different repo whose short sha
   *  happens to collide. */
  itemsClosedByCommits(slug: string, shas: readonly string[]): Item[] {
    return this.index
      .listItems()
      .map((r) => r.item)
      .filter((i) => {
        const done = i.fm.done;
        return (
          i.fm.repo === slug &&
          done !== null &&
          done.version === null &&
          done.commit !== null &&
          shas.some((sha) => commitMatches(done.commit as string, sha))
        );
      });
  }

  /* ---------------- F1: onboarding ---------------- */

  /** `ledger repo onboarded <slug>`. Queued, like every other ledger write. */
  async setOnboarded(slug: string, value = true): Promise<RepoConfig> {
    this.repo(slug);
    return this.queue.run(() => this.applyOnboarded(slug, value));
  }

  /** Unqueued body of `setOnboarded`. Callers must already hold the queue —
   *  `reindex()` runs on it, and re-entering `queue.run` from inside a queued
   *  job would deadlock (the inner job waits for the outer tail). */
  private async applyOnboarded(slug: string, value: boolean): Promise<RepoConfig> {
    await this.loadRepos();
    const cfg = this.repo(slug);
    if (cfg.onboarded === value) return cfg;
    cfg.onboarded = value;
    await this.saveRepos();
    this.git.touch(`${slug} onboarded=${String(value)}`);
    return cfg;
  }

  isOnboarded(slug: string): boolean {
    return this.repoOrNull(slug) !== null && this.repo(slug).onboarded === true;
  }

  /**
   * Declare a contract glob and/or a consumer for a repo.
   *
   * Additive and idempotent: adding the same glob twice is a no-op, and the
   * only way to remove one is `--rm`. `repos.yml` is the source of truth, so
   * the write goes through `saveRepos` (atomic, schema-validated on reload)
   * rather than mutating the in-memory config alone.
   *
   * A consumer must already be a registered repo — a typo would otherwise sit
   * in `repos.yml` and silently notify nobody.
   */
  async setContracts(
    slug: string,
    input: { add?: string[]; consumers?: string[]; rm?: string[]; rmConsumers?: string[] },
  ): Promise<RepoConfig> {
    this.repo(slug); // 404 before the queue, like every other repo mutator
    for (const consumer of input.consumers ?? []) {
      if (consumer === slug) throw invalid(`repo ${slug} cannot consume itself`);
      this.repo(consumer);
    }
    return this.queue.run(async () => {
      await this.loadRepos();
      const live = this.repo(slug);
      const merge = (
        current: string[] | undefined,
        add: string[] | undefined,
        rm: string[] | undefined,
      ): string[] | undefined => {
        const removed = new Set(rm ?? []);
        const next = [...new Set([...(current ?? []), ...(add ?? [])])].filter(
          (v) => !removed.has(v),
        );
        return next.length === 0 ? undefined : next;
      };
      const contracts = merge(live.contracts, input.add, input.rm);
      const consumers = merge(live.consumers, input.consumers, input.rmConsumers);
      if (contracts === undefined) delete live.contracts;
      else live.contracts = contracts;
      if (consumers === undefined) delete live.consumers;
      else live.consumers = consumers;
      await this.saveRepos();
      this.git.touch(`${slug} contracts`);
      return live;
    });
  }

  /**
   * A repo whose `CONTEXT.md` no longer matches the template has been filled in
   * by a session, so the onboarding nag has served its purpose — flip the flag
   * without waiting for `ledger repo onboarded`. Compared on the non-boilerplate
   * lines only, so whitespace edits do not count.
   */
  private async detectOnboarded(slug: string): Promise<void> {
    if (this.isOnboarded(slug)) return;
    const text = await readText(this.paths.contextFile(slug));
    if (text === null) return;
    if (!hasContentBeyondTemplate(text, contextTemplate(slug))) return;
    try {
      await this.applyOnboarded(slug, true);
      this.logFn(`${slug}: CONTEXT.md filled in → onboarded`);
    } catch (err) {
      this.logFn(`${slug}: could not set onboarded flag: ${String(err)}`);
    }
  }

  /* ---------------- F1: search corpus ---------------- */

  /** Everything the FTS index covers (SPEC §5: items, journal, decisions,
   *  intake, CONTEXT.md). md stays the source of truth — this is derived. */
  async searchDocs(): Promise<
    { kind: 'item' | 'journal' | 'decision' | 'intake' | 'context'; ref: string; repo: string; title: string; body: string }[]
  > {
    const docs: {
      kind: 'item' | 'journal' | 'decision' | 'intake' | 'context';
      ref: string;
      repo: string;
      title: string;
      body: string;
    }[] = [];
    for (const rec of this.index.listItems()) {
      const i = rec.item;
      docs.push({
        kind: 'item',
        ref: i.fm.id,
        repo: i.fm.repo,
        title: i.fm.title,
        body: [
          i.why,
          i.rec,
          i.steps.map((s) => s.text).join('\n'),
          i.comments.map((c) => c.text).join('\n'),
          i.log.map((l) => l.text).join('\n'),
          i.fm.aliases.join(' '),
        ].join('\n'),
      });
    }
    for (const ev of this.index.listJournal()) {
      docs.push({
        kind: 'journal',
        ref: `${ev.repo}/${ev.at}`,
        repo: ev.repo,
        title: `${ev.at} ${ev.type}`,
        body: ev.fields.join(' · '),
      });
    }
    for (const d of this.index.listDecisions()) {
      docs.push({
        kind: 'decision',
        ref: `D${d.n}`,
        repo: d.repo,
        title: d.title,
        body: d.body,
      });
    }
    for (const rec of this.index.listIntake()) {
      docs.push({
        kind: 'intake',
        ref: rec.rec.id,
        repo: rec.rec.repo_hint ?? 'ops',
        title: `intake ${rec.rec.at.slice(0, 16)}`,
        body: rec.rec.text,
      });
    }
    for (const slug of Object.keys(this.reposRaw)) {
      const text = await readText(this.paths.contextFile(slug));
      if (text === null) continue;
      docs.push({ kind: 'context', ref: slug, repo: slug, title: `${slug} CONTEXT.md`, body: text });
    }
    return docs;
  }

  async close(): Promise<void> {
    await this.queue.drain();
    await this.git.close();
  }
}

/**
 * `done.commit` compatibility (audit H5): older data can hold a 7-char
 * abbreviation of `full` (always the caller-supplied full 40-hex sha from
 * git). A `stored` value of plausible abbreviated length (7–39) is compared
 * as a prefix of `full`; anything else falls back to exact equality.
 *
 * Deliberately one-directional (G3 stays intact): a *short* `full` must NOT
 * match a full-length `stored` — `itemsClosedByCommits` takes attacker/log
 * -adjacent input as `full`, and a 7-char value there is documented to never
 * be "enough" on its own (see the G3 test), only a real full sha is.
 */
export function commitMatches(stored: string, full: string): boolean {
  if (stored.length >= 7 && stored.length <= 39) return full.startsWith(stored);
  return stored === full;
}

export function parseEventTime(at: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})$/.exec(at.trim());
  if (!m) return null;
  return new Date(
    Number(m[1]),
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
  ).getTime();
}

/** `session.summary` is a rolling fact appended again and again (the journal
 *  file is append-only); the index keeps only the LATEST line per session. */
export function collapseRolling(events: JournalEvent[]): JournalEvent[] {
  const last = new Map<string, number>();
  events.forEach((ev, i) => {
    if (ev.type === 'session.summary') last.set(ev.session, i);
  });
  return events.filter((ev, i) => ev.type !== 'session.summary' || last.get(ev.session) === i);
}

async function safeReaddir(dir: string): Promise<string[]> {
  try {
    return (await readdir(dir)).sort();
  } catch {
    return [];
  }
}

/** S-2: collapse to a single log/warning line, so nothing in a ledger file can
 *  forge a line of its own in `hub.log` or in `/v1/healthz`. */
function logSafe(text: string): string {
  return text.replace(/[\r\n\u2028\u2029]+/g, ' ').slice(0, 500);
}

async function safeStat(path: string): Promise<Awaited<ReturnType<typeof stat>> | null> {
  try {
    return await stat(path);
  } catch {
    return null;
  }
}

/** Non-empty, non-heading, non-placeholder lines — "did somebody write here?". */
function meaningfulLines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(
      (l) => l !== '' && !l.startsWith('#') && !/^[-*]\s*\(.*\)$/.test(l) && !/^[-*]\s*$/.test(l),
    );
}

/**
 * True when `text` contains at least one meaningful line the template does not.
 *
 * Counting lines was not enough: a filled-in `CONTEXT.md` can have exactly as
 * many lines as the skeleton (the skeleton's own `- dev:` / `- test:` stubs
 * count), so a real edit could score equal and the onboarding nag would never
 * clear. Set difference is deterministic and cannot tie.
 */
function hasContentBeyondTemplate(text: string, template: string): boolean {
  const skeleton = new Set(meaningfulLines(template));
  return meaningfulLines(text).some((line) => !skeleton.has(line));
}

export { LedgerError };
