/**
 * Automatic `session.summary`, no LLM anywhere.
 *
 * Every field is a fact the hub already recorded: the `changes` table (item
 * created / claimed / done / dropped), `session_facts` (commits attributed to
 * the session, files it touched, the `ledger log` text), and the session row (its
 * sidebar name). Nothing is summarised in the "compress prose" sense, because
 * that would need a model, cost money and occasionally lie.
 *
 * Writes to the journal only. **Nothing from this module ever enters an
 * agent's context** — the brief reads the journal and may quote a summary, but
 * that is the brief's own 30-line budget, not a new feed.
 *
 * Three triggers, one body:
 *  (a) SessionEnd — final state;
 *  (b) `IDLE_FLUSH_MS` of silence with activity since the last summary;
 *  (c) after a commit — updates the ROLLING line (`upsertJournalEvent`
 *      rewrites it in place), so ten commits still leave one summary.
 */

import { parseCommits, parseList, type ChangeRow, type RuntimeStore } from './db/store.ts';
import type { Ledger } from './ledger/ledger.ts';
import type { Sessions } from './sessions.ts';

export interface SummaryDeps {
  ledger: Ledger;
  store: RuntimeStore;
  sessions: Sessions;
}

/** A session quiet this long gets its summary written. */
export const IDLE_FLUSH_MS = 30 * 60_000;

/** Commits named in the line. Past five the shas stop being informative. */
const MAX_COMMITS = 5;
const MAX_ITEMS = 6;
const MAX_DIRS = 3;

export class Summarizer {
  private readonly deps: SummaryDeps;
  private readonly idleMs: number;

  constructor(deps: SummaryDeps, opts: { idleMs?: number } = {}) {
    this.deps = deps;
    this.idleMs = opts.idleMs ?? IDLE_FLUSH_MS;
  }

  /* ---------------- fact collection ---------------- */

  /** An edit or a Bash write. Cheap: one upsert, no journal IO. */
  noteFiles(session: string, repo: string, files: string[], now = Date.now()): void {
    if (files.length === 0) return;
    try {
      this.deps.store.addSessionFact({ session, repo, files, now });
    } catch {
      /* the summary is a convenience; never break the hook that fed it */
    }
  }

  /** An item route ran for this session (`changes` carries the detail,
   *  this only moves `last_at` so trigger (b) can fire). */
  noteActivity(session: string, repo: string, now = Date.now()): void {
    try {
      this.deps.store.addSessionFact({ session, repo, now });
    } catch {
      /* same */
    }
  }

  /** `ledger log` text becomes the summary's "why". */
  noteWhy(session: string, repo: string, why: string, now = Date.now()): void {
    const text = why.replace(/\s+/g, ' ').trim();
    if (text === '') return;
    try {
      this.deps.store.addSessionFact({ session, repo, why: text.slice(0, 300), now });
    } catch {
      /* same */
    }
  }

  /** Trigger (c). The rolling line is rewritten, not appended. */
  async onCommit(
    session: string | null,
    repo: string,
    commit: { short: string; subject: string },
    now = Date.now(),
  ): Promise<void> {
    if (session === null) return;
    this.deps.store.addSessionFact({
      session,
      repo,
      commits: [{ sha: commit.short, subject: commit.subject }],
      now,
    });
    await this.flush(session, repo, now);
  }

  /* ---------------- triggers ---------------- */

  /** Trigger (a). Called from the SessionEnd hook, for every repo the session
   *  accumulated facts in. */
  async onSessionEnd(session: string, now = Date.now()): Promise<void> {
    for (const repo of this.deps.store.sessionRepos(session)) {
      await this.flush(session, repo, now);
    }
  }

  /** Trigger (b). Driven by the hub sweep, not by a timer per session. */
  async flushIdle(now = Date.now()): Promise<number> {
    let written = 0;
    for (const row of this.deps.store.summariesDue(this.idleMs, now)) {
      if (await this.flush(row.session, row.repo, now)) written += 1;
    }
    return written;
  }

  /**
   * Write (or rewrite) the summary. Returns false when there is nothing new —
   * that is what keeps a commit storm, a SessionEnd right after a flush and the
   * idle sweep from all producing their own line.
   */
  async flush(session: string, repo: string, now = Date.now()): Promise<boolean> {
    const row = this.deps.store.getSessionFacts(session, repo);
    if (row === null) return false;
    if (row.flushed_last !== null && row.flushed_last >= row.last_at) return false;
    const fields = this.buildFields(session, repo, row.first_at, row.last_at, row);
    if (fields.length === 0) return false;
    try {
      await this.deps.ledger.upsertJournalEvent(repo, session, 'session.summary', fields);
    } catch (err) {
      this.deps.ledger.log(`session.summary ${repo}: ${String(err)}`);
      return false;
    }
    this.deps.store.markSummaryFlushed(session, repo, row.last_at, now);
    return true;
  }

  /* ---------------- the line ---------------- */

  private buildFields(
    session: string,
    repo: string,
    firstAt: number,
    lastAt: number,
    row: { files: string; file_count: number; commits: string; why: string | null },
  ): string[] {
    const fields: string[] = [`${hm(firstAt)}–${hm(lastAt)}`];

    const view = this.deps.sessions.get(session);
    const name = view?.title ?? null;
    if (name !== null && name.trim() !== '') fields.push(`"${clamp(name, 48)}"`);

    const changes = this.deps.store
      .changesByActor(session, firstAt)
      .filter((c) => c.repo === repo);
    const created = ids(changes, ['created']);
    const closed = ids(changes, ['done', 'dropped']);
    const claimed = ids(changes, ['claimed']).filter((id) => !closed.includes(id));
    if (created.length > 0) fields.push(`created ${list(created)}`);
    if (closed.length > 0) fields.push(`closed ${list(closed)}`);
    if (claimed.length > 0) fields.push(`claim ${list(claimed)}`);

    const commits = parseCommits(row.commits).slice(-MAX_COMMITS);
    if (commits.length > 0) {
      fields.push(
        `commits ${commits.map((c) => `${c.sha} ${clamp(c.subject, 40)}`).join('; ')}`,
      );
    }

    const files = parseList(row.files);
    if (row.file_count > 0) {
      const dirs = topDirs(files);
      fields.push(
        `${row.file_count} files${dirs.length > 0 ? ` (${dirs.join(', ')})` : ''}`,
      );
    }

    if (row.why !== null && row.why !== '') fields.push(`why: ${clamp(row.why, 200)}`);

    // Time window alone is not a summary — if nothing else landed, writing a
    // line would be noise in the journal and in every brief that reads it.
    return fields.length <= 2 ? [] : fields;
  }
}

function ids(changes: readonly ChangeRow[], kinds: readonly string[]): string[] {
  const out: string[] = [];
  for (const c of changes) {
    if (!kinds.includes(c.kind)) continue;
    if (!out.includes(c.item_id)) out.push(c.item_id);
  }
  return out;
}

function list(items: readonly string[]): string {
  const head = items.slice(0, MAX_ITEMS).join(', ');
  return items.length > MAX_ITEMS ? `${head} +${items.length - MAX_ITEMS}` : head;
}

/** Two path segments is the useful granularity in this fleet
 *  (`packages/hub/src/...` → `packages/hub`). */
function topDirs(files: readonly string[]): string[] {
  const counts = new Map<string, number>();
  for (const f of files) {
    const parts = f.split('/');
    const dir = parts.length <= 1 ? '.' : parts.slice(0, Math.min(2, parts.length - 1)).join('/');
    counts.set(dir, (counts.get(dir) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, MAX_DIRS)
    .map(([dir]) => dir);
}

function hm(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function clamp(s: string, max: number): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}
