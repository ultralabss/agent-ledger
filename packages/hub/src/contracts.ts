/**
 * Contract guard across repos.
 *
 * `repos.yml` gains two optional keys per repo:
 *
 *   api:
 *     contracts:
 *       - src/auth/**
 *       - docs/billing.md
 *     consumers: [web, mobile]
 *
 * When a commit in `api` touches a contract path, every consumer repo
 * gets (1) a one-line inbox message to each of its LIVE sessions and (2) one
 * `UNVERIFIED P1` item to verify the change. Both are deduped per
 * (commit, consumer) by `markOnce`, so a redelivered commit — a watcher
 * restart, a `sync()` after a crash — never doubles up.
 *
 * Token cost: ONE line per consumer session per contract commit. The commit is
 * named by sha7 + subject + at most three changed paths; the rest lives in the
 * item, which the agent reads only if it decides to.
 */

import { matchAny, toPosix } from './guard/globs.ts';
import type { RuntimeStore } from './db/store.ts';
import type { Ledger } from './ledger/ledger.ts';
import type { Sessions } from './sessions.ts';
import { frameUntrusted, redactSecrets, untrustedSnippet } from '@agent-ledger/shared';

export interface ContractDeps {
  ledger: Ledger;
  store: RuntimeStore;
  sessions: Sessions;
}

export interface ContractCommit {
  short: string;
  subject: string;
  files: readonly string[];
}

/** Paths named in the inbox line. The item carries the rest. */
const MAX_PATHS = 3;

export interface ContractNotice {
  consumer: string;
  item: string | null;
  sessions: string[];
}

/**
 * Notify consumers about a contract-touching commit. Returns what it did (for
 * tests and the hub log); never throws — it runs inside the commit watcher and
 * a failed notification must not stop `Closes:` from closing items.
 */
export async function notifyContractChange(
  deps: ContractDeps,
  repo: string,
  commit: ContractCommit,
): Promise<ContractNotice[]> {
  const cfg = deps.ledger.repos()[repo];
  const patterns = cfg?.contracts ?? [];
  const consumers = cfg?.consumers ?? [];
  if (patterns.length === 0 || consumers.length === 0) return [];

  const hits: string[] = [];
  for (const file of commit.files) {
    if (matchAny(patterns, toPosix(file)) === null) continue;
    hits.push(file);
  }
  if (hits.length === 0) return [];

  // Subject and paths are git-author-controlled — scrub secrets before
  // either reaches an item or an inbox line (`createItem`'s own secret guard
  // never sees this path, since it is built here, not passed to the API).
  const subject = redactSecrets(commit.subject).text;
  const safeHits = hits.map((f) => redactSecrets(f).text);

  // The same text, framed as data rather than instructions — one
  // header for the whole line, not per field.
  const hitsList = `${safeHits
    .slice(0, MAX_PATHS)
    .map((f) => untrustedSnippet(f, 80))
    .join(', ')}${hits.length > MAX_PATHS ? ` +${hits.length - MAX_PATHS}` : ''}`;
  const line = `⚠ contract ${repo} ${commit.short} — ${frameUntrusted(
    `${untrustedSnippet(subject, 160)} — ${hitsList}`,
  )}`;

  const out: ContractNotice[] = [];
  for (const consumer of consumers) {
    if (consumer === repo) continue;
    // Unknown slug: a typo in `repos.yml` must be visible, not silent.
    if (!deps.ledger.hasRepo(consumer)) {
      deps.ledger.log(`contract ${repo} ${commit.short}: consumer "${consumer}" is not in repos.yml`);
      continue;
    }
    // One item + one round of inbox per (source repo, commit, consumer),
    // forever. The key includes the source repo — a bare sha7 can
    // collide across unrelated repos, which would silently drop a real
    // notice from a second repo sharing a prefix.
    const markKey = `${repo}:${commit.short}:${consumer}`;
    if (!deps.store.markOnce('contract', markKey)) continue;

    const item = await createVerifyItem(deps, consumer, repo, commit, subject, safeHits);
    if (item === null) {
      // The claim is only "done" once the item exists. Undo it on
      // failure so a redelivered commit (watcher restart) gets a real retry
      // instead of being treated as already-handled.
      deps.store.clearMark('contract', markKey);
    }
    const sessions = deps.sessions
      .list({ repo: consumer, liveOnly: true })
      .map((s) => s.id);
    for (const to of sessions) {
      try {
        deps.store.addInbox({
          to_session: to,
          from_session: null,
          repo: consumer,
          item_id: item,
          body: line,
          // Hub-composed notice, not a client claim.
          origin: 'hub',
        });
      } catch (err) {
        deps.ledger.log(`contract ${repo} ${commit.short} → ${consumer}: inbox ${String(err)}`);
      }
    }
    out.push({ consumer, item, sessions });
  }
  return out;
}

async function createVerifyItem(
  deps: ContractDeps,
  consumer: string,
  repo: string,
  commit: ContractCommit,
  subject: string,
  hits: readonly string[],
): Promise<string | null> {
  try {
    const item = await deps.ledger.createItem({
      repo: consumer,
      // ≤ 60 chars by construction: slug + sha7 fit the ledger's title rule.
      title: `Verify contract change ${repo} ${commit.short}`,
      kind: 'UNVERIFIED',
      priority: 'P1',
      owner: 'agent',
      why: [
        frameUntrusted(`${repo} ${commit.short} ${untrustedSnippet(subject, 200)}`),
        `contract files: ${frameUntrusted(
          hits
            .slice(0, 10)
            .map((h) => untrustedSnippet(h, 80))
            .join(', '),
        )}`,
      ].join('\n'),
      rec: `Review the diff ${commit.short} in ${repo} and verify that ${consumer} still matches the contract.`,
      steps: [],
      blocked_by: [],
      aliases: [],
      proposed: false,
      session: null,
      agent: 'hub',
    });
    return item.fm.id;
  } catch (err) {
    deps.ledger.log(`contract ${repo} ${commit.short} → ${consumer}: item ${String(err)}`);
    return null;
  }
}
