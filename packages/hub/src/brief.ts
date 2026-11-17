/** Briefing for a new session — SPEC §9.
 *
 *  F1 adds the live header: `repo · branch ↑n · last release v0.x (MM-DD)`
 *  plus a `Live:` line per other live session with its item, idle time and
 *  claimed paths. Hard cap 30 lines (`full` lifts it to the whole open list +
 *  14 days). `live` is optional so `GET /v1/brief` without a session (and every
 *  F0 test) still works. */

import {
  isOpen,
  parseStamp,
  repoKindOf,
  type Decision,
  type GitHeadView,
  type Item,
  type JournalEvent,
  type ReleaseView,
  type SessionView,
  type TouchedView,
} from '@agent-ledger/shared';

/** Header tag for repos without a git checkout. A plain `repo` with no
 *  path stays "virtual repo" (old behaviour); system / vps are first-class,
 *  not a failure to find a checkout. */
function kindLabel(cfg: { kind?: 'repo' | 'system' | 'vps'; host?: string; path: string | null }): string {
  const kind = repoKindOf(cfg);
  if (kind === 'system') return ' · system';
  if (kind === 'vps') return cfg.host ? ` · vps ${cfg.host}` : ' · vps';
  return cfg.path ? '' : ' · virtual repo';
}
import { sessionTag } from './sessions.ts';
import type { Ledger } from './ledger/ledger.ts';
import type { RuntimeStore } from './db/store.ts';
import type { StaleEnv } from './stale.ts';
import { analyzeRepo, type RepoAnalysis, type TidyCommit } from './tidy.ts';

export interface BriefLive {
  sessions: SessionView[];
  /** The session the briefing is for — it is not listed as "somebody else". */
  self?: string | undefined;
  git?: GitHeadView | null | undefined;
  release?: ReleaseView | null | undefined;
  orphans?: TouchedView[] | undefined;
}

/** What the brief needs to show how long items have been idle. Every part is
 *  optional: without `store` the age comes from the md file alone, without
 *  `commits` there is no `looks-done` figure. */
export interface BriefStale {
  /** Runtime DB: `item_files` and claims count as activity. */
  store?: RuntimeStore | undefined;
  /** Commits of the briefed repo's own checkout (`loadTidyCommits`). */
  commits?: readonly TidyCommit[] | null | undefined;
  now?: number | undefined;
  env?: StaleEnv | undefined;
}

export interface BriefOptions {
  repo?: string | undefined;
  full?: boolean | undefined;
  live?: BriefLive | undefined;
  /** `CONTEXT.md may be stale …`, computed by the caller (it
   *  needs an fs stat, and the brief is synchronous below this line). */
  staleContext?: string | null | undefined;
  /** `startup` shows 3 queue rows instead of 5. `resume` with nothing
   *  new never reaches here — `sessionStart` answers with one line. */
  lean?: boolean | undefined;
  /** Item ages and the single `Stale:` line. */
  stale?: BriefStale | undefined;
  /** Sync halt facts; one `Sync:` line right under the header while halted. */
  sync?: BriefSync | undefined;
}

const MAX_LINES = 30;

/** Sync state for the brief (F3b B5, spec §7.3: "brief says so"). The caller passes only the halt facts it read
 *  from `.hub/sync/state.json`; free text (`detail`) is deliberately NOT part of it. */
export interface BriefSync {
  halt: { reason: string; cls: string; since: string } | null | undefined;
}

const SYNC_REASON_RE = /^[a-z][a-z0-9:-]{0,39}$/;
const SYNC_CLASSES = new Set(['no-contact', 'sticky', 'probe', 'd2', 'local', 'terminal']);

/** One line, or `null` when sync is healthy / unknown. Fields are whitelisted by shape, so a hostile or corrupt
 *  state file cannot put free text (or an instruction) into an agent's context. */
export function syncLine(sync: BriefSync | undefined): string | null {
  const h = sync?.halt;
  if (h === null || h === undefined) return null;
  const reason = SYNC_REASON_RE.test(h.reason) ? h.reason : 'unknown';
  const cls = SYNC_CLASSES.has(h.cls) ? h.cls : 'unknown';
  const since = /^\d{4}-\d{2}-\d{2}/.test(h.since) ? h.since.slice(0, 10) : '?';
  return `Sync: HALTED (${reason}, ${cls}) since ${since} — remote changes are not being applied; owner: ledger sync status`;
}

/** Rows of `Up next` in a lean (startup) brief. The full list is one
 *  `ledger brief --full` away, and it was the single biggest block in the
 *  measured brief. */
const LEAN_QUEUE = 3;
const RECENT_TYPES = new Set(['item.status', 'decision', 'session.summary', 'release']);

function recent(events: JournalEvent[], days: number): JournalEvent[] {
  const cutoff = Date.now() - days * 86_400_000;
  return events.filter((ev) => {
    if (!RECENT_TYPES.has(ev.type)) return false;
    if (ev.type === 'item.status' && !ev.fields.some((f) => f.includes('→done'))) return false;
    const t = parseStamp(ev.at);
    return t === null || t.getTime() >= cutoff;
  });
}

function eventDigest(ev: JournalEvent): string {
  const head = ev.at.slice(5, 10);
  const body = ev.fields.join(' ').replace(/\s+/g, ' ').trim();
  const text = body.length > 60 ? `${body.slice(0, 59)}…` : body;
  return `${head} ${text || ev.type}`;
}

function shortTitle(item: Item, max = 52): string {
  const t = item.fm.title.replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** Below this the age is noise — nobody needs `· 1d` on every row. */
const AGE_SUFFIX_MIN_DAYS = 3;

interface StaleView {
  /** ` · 23d` once an item has been idle for 3+ days, else empty. */
  suffix: (item: Item) => string;
  /** At most ONE line: `Stale: 4 (oldest 41d) · looks-done 2 → ledger tidy`. */
  line: string | null;
}

function staleView(analyses: readonly RepoAnalysis[], showLooksDone: boolean): StaleView {
  const infos = new Map<string, number>();
  let stale = 0;
  let oldest = 0;
  let looksDone = 0;
  for (const a of analyses) {
    for (const r of a.rows) {
      infos.set(r.item.fm.id, r.info.ageDays);
      if (!r.info.stale) continue;
      stale += 1;
      oldest = Math.max(oldest, r.info.ageDays);
      if (r.bucket === 'looks-done') looksDone += 1;
    }
  }
  return {
    suffix: (item) => {
      const d = infos.get(item.fm.id);
      return d !== undefined && d >= AGE_SUFFIX_MIN_DAYS ? ` · ${d}d` : '';
    },
    line:
      stale === 0
        ? null
        : `Stale: ${stale} (oldest ${oldest}d)${
            showLooksDone && looksDone > 0 ? ` · looks-done ${looksDone}` : ''
          } → ledger tidy`,
  };
}

/** `↑2 ↓1` — ahead/behind, omitted when zero or unknown. */
function aheadBehind(git: GitHeadView | null | undefined): string {
  if (!git) return '';
  const parts: string[] = [];
  if (git.ahead && git.ahead > 0) parts.push(`↑${git.ahead}`);
  if (git.behind && git.behind > 0) parts.push(`↓${git.behind}`);
  return parts.length > 0 ? ` ${parts.join(' ')}` : '';
}

function liveLines(live: BriefLive, full: boolean): string[] {
  const lines: string[] = [];
  const others = live.sessions.filter((s) => s.id !== live.self && s.liveness !== 'ended');
  for (const s of others.slice(0, full ? others.length : 4)) {
    const mins = Math.round(s.idle_ms / 60_000);
    const items = s.items.length > 0 ? ` ${s.items.join(',')}` : '';
    const agents = s.agents.length > 0 ? ` [${s.agents.slice(0, 3).join(',')}]` : '';
    lines.push(
      `Live: ${sessionTag(s)}${items} ${s.liveness}${agents} · ${
        mins === 0 ? 'just now' : `${mins} min`
      } · ${s.touched_count} files`,
    );
  }
  const orphans = live.orphans ?? [];
  if (orphans.length > 0) {
    lines.push(
      `Orphans (${orphans.length}): ${orphans
        .slice(0, 4)
        .map((o) => o.rel_path)
        .join(', ')}${orphans.length > 4 ? ' …' : ''} — ledger adopt`,
    );
  }
  return lines;
}

function repoBrief(
  ledger: Ledger,
  repo: string,
  full: boolean,
  context: string | null,
  live?: BriefLive | undefined,
  extra: {
    staleContext?: string | null | undefined;
    lean?: boolean | undefined;
    stale?: BriefStale | undefined;
  } = {},
): string[] {
  const cfg = ledger.repo(repo);
  const items = ledger.listItems({ repo });
  const open = items.filter((i) => isOpen(i.fm.status));
  const sv = staleView(
    [
      analyzeRepo(
        {
          ledger,
          store: extra.stale?.store,
          commits: extra.stale?.commits,
          now: extra.stale?.now,
          env: extra.stale?.env,
        },
        repo,
      ),
    ],
    extra.stale?.commits != null,
  );
  const doing = open.filter((i) => i.fm.status === 'doing');
  const lines: string[] = [];

  // SPEC §9 header: `acme · main ↑2 · last release v0.26.0 (09-28)`.
  // Without a git reader (no live context, virtual repo, unreadable checkout)
  // there is nothing to put there, so the counts stay on line 1 — that is the
  // F0 shape and the CLI/`brief` tests pin it.
  const git = live?.git;
  const release = live?.release;
  const gitBits = [
    git?.branch ? `${git.branch}${aheadBehind(git)}` : git ? 'detached HEAD' : null,
    release ? `last release ${release.tag}${release.at ? ` (${release.at.slice(5, 10)})` : ''}` : null,
  ].filter((p): p is string => p !== null && p !== '');
  const counts = `${open.length} open, ${doing.length} doing, ${items.length} total${
    kindLabel(cfg)
  }${cfg.onboarded === false ? ' · onboarded=false' : ''}`;

  if (gitBits.length > 0) {
    lines.push(`${repo} · ${gitBits.join(' · ')}`);
    lines.push(`${cfg.prefix} · ${counts}`);
  } else {
    lines.push(`${repo} · ${cfg.prefix} · ${counts}`);
  }

  const docs = cfg.docs && cfg.docs.length > 0 ? cfg.docs.join(', ') : 'none';
  lines.push(
    `Context: ${context ? 'CONTEXT.md' : 'CONTEXT.md missing'} · graphify: ${
      cfg.graphify ? cfg.graphify : 'no'
    } · docs: ${docs}`,
  );

  // Right under the `Context:` line it is about CONTEXT.md; anywhere
  // else it reads as an unrelated warning.
  if (extra.staleContext) lines.push(extra.staleContext);

  if (live) lines.push(...liveLines(live, full));

  const mine = open.filter((i) => i.fm.owner === 'human');
  if (mine.length > 0) {
    lines.push(`Needs you (${mine.length}):`);
    for (const i of mine.slice(0, full ? mine.length : 5)) {
      lines.push(`  ${i.fm.id} [${i.fm.kind}] ${i.fm.priority} ${shortTitle(i)}${sv.suffix(i)}`);
    }
  }

  const queue = full
    ? open.filter((i) => i.fm.owner !== 'human')
    : open.filter(
        (i) =>
          i.fm.owner !== 'human' &&
          (i.fm.priority === 'P0' || i.fm.priority === 'P1') &&
          (i.fm.status === 'open' || i.fm.status === 'doing'),
      );
  if (queue.length > 0) {
    const cap = full ? queue.length : extra.lean ? LEAN_QUEUE : 5;
    lines.push(`Up next (${queue.length}):`);
    for (const i of queue.slice(0, cap)) {
      lines.push(`  ${i.fm.id} ${i.fm.priority} ${i.fm.status} ${shortTitle(i)}${sv.suffix(i)}`);
    }
    if (queue.length > cap) lines.push(`  … +${queue.length - cap} — ledger ls --open`);
  }

  if (sv.line) lines.push(sv.line);

  const unprocessed = ledger.listIntakeUnprocessed();
  if (unprocessed.length > 0) {
    const last = unprocessed[0];
    lines.push(
      `Intake: ${unprocessed.length} unprocessed · last ${last?.channel ?? '?'} ${
        last?.at.slice(0, 16) ?? ''
      } (${last?.id ?? ''})`,
    );
  }

  const events = recent(ledger.listJournal(repo), full ? 14 : 7);
  if (events.length > 0) {
    lines.push(`${full ? '14' : '7'} days: ${events.slice(0, full ? 20 : 4).map(eventDigest).join(' · ')}`);
  }

  const decisions: Decision[] = ledger.listDecisions(repo).slice(0, 3);
  if (decisions.length > 0) {
    lines.push('Decisions:');
    for (const d of decisions) lines.push(`  D${d.n} ${d.date} ${d.title}`);
  }

  return lines;
}

function globalBrief(
  ledger: Ledger,
  full: boolean,
  live?: BriefLive | undefined,
  stale?: BriefStale | undefined,
): string[] {
  const repos = ledger.repos();
  const all = ledger.listItems();
  const open = all.filter((i) => isOpen(i.fm.status));
  const lines: string[] = [];
  // No git evidence across every repo here (that is one `git log` per repo),
  // so no `looks-done` — `ledger tidy --repo <r>` has it.
  const sv = staleView(
    Object.keys(repos).map((slug) =>
      analyzeRepo({ ledger, store: stale?.store, now: stale?.now, env: stale?.env }, slug),
    ),
    false,
  );
  lines.push(
    `ledger · ${Object.keys(repos).length} repos · ${open.length} open · ${
      all.length
    } items total`,
  );
  if (live) lines.push(...liveLines(live, full));
  for (const slug of Object.keys(repos).sort()) {
    const mine = open.filter((i) => i.fm.repo === slug);
    const human = mine.filter((i) => i.fm.owner === 'human').length;
    lines.push(
      `  ${slug}: ${mine.length} open${human > 0 ? ` · for you ${human}` : ''}`,
    );
  }
  const human = open.filter((i) => i.fm.owner === 'human');
  if (human.length > 0) {
    lines.push(`Needs you (${human.length}):`);
    for (const i of human.slice(0, full ? human.length : 5)) {
      lines.push(`  ${i.fm.id} [${i.fm.kind}] ${i.fm.priority} ${shortTitle(i)}${sv.suffix(i)}`);
    }
  }
  const queue = open.filter(
    (i) => i.fm.owner !== 'human' && (full || i.fm.priority === 'P0' || i.fm.priority === 'P1'),
  );
  if (queue.length > 0) {
    lines.push(`Up next (${queue.length}):`);
    for (const i of queue.slice(0, full ? queue.length : 5)) {
      lines.push(`  ${i.fm.id} ${i.fm.priority} ${i.fm.repo} ${shortTitle(i)}${sv.suffix(i)}`);
    }
  }
  if (sv.line) lines.push(sv.line);
  const unprocessed = ledger.listIntakeUnprocessed();
  if (unprocessed.length > 0) {
    lines.push(
      `Intake: ${unprocessed.length} unprocessed · last ${
        unprocessed[0]?.at.slice(0, 16) ?? ''
      }`,
    );
  }
  const events = recent(ledger.listJournal(), full ? 14 : 7);
  if (events.length > 0) {
    lines.push(`${full ? '14' : '7'} days: ${events.slice(0, full ? 20 : 4).map(eventDigest).join(' · ')}`);
  }
  return lines;
}

export async function buildBrief(ledger: Ledger, opts: BriefOptions = {}): Promise<string> {
  const full = opts.full ?? false;
  const lines = opts.repo
    ? repoBrief(ledger, opts.repo, full, await ledger.contextFor(opts.repo), opts.live, {
        staleContext: opts.staleContext,
        lean: opts.lean,
        stale: opts.stale,
      })
    : globalBrief(ledger, full, opts.live, opts.stale);
  const sl = syncLine(opts.sync);
  if (sl !== null) lines.splice(1, 0, sl);
  const footer = 'More: ledger brief --full · ledger history --since 14d';
  const body = full ? lines : lines.slice(0, MAX_LINES - 1);
  if (!full && lines.length > MAX_LINES - 1) {
    body[MAX_LINES - 2] = `… +${lines.length - (MAX_LINES - 2)} lines — ledger brief --full`;
  }
  body.push(footer);
  return `${body.join('\n')}\n`;
}
