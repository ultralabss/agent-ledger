/**
 * Read the ledger directly when the hub is down.
 *
 * md under `<ledger>/<repo>/items/*.md` is the source of truth (SPEC §5); the
 * hub is an index and a coordinator on top of it. So `ledger ls`, `ledger show` and
 * `ledger brief` do not have to fail when the hub is restarting — they can parse
 * the same files the hub would have parsed, using the *same* parser from
 * `@agent-ledger/shared`. No second format, no drift.
 *
 * Strictly read-only, and it says so: every offline answer is prefixed with
 * `(offline — from the ledger, no live data)` because what is genuinely missing is the
 * live layer — who holds what, git state, inbox, sessions. Presenting that as a
 * normal answer would be worse than failing.
 *
 * Commands that are *only* live data (`who`, `sessions`, `whose`, `search`,
 * `status`, `inbox`) stay at exit 3: there is nothing in md to fall back to and
 * a confidently empty answer would be a lie.
 */

import { readFile, readdir, realpath } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { OPEN_STATUSES, itemLine, parseItem, slugSchema } from '@agent-ledger/shared';
import type { Item, ItemStatus } from '@agent-ledger/shared';

export const OFFLINE_HEADER = '(offline — from the ledger, no live data)';

export interface OfflineFilter {
  repo?: string | undefined;
  status?: string | undefined;
  owner?: string | undefined;
  kind?: string | undefined;
  priority?: string | undefined;
  open?: boolean;
  session?: string | undefined;
}

/** Repo slugs = top-level directories that actually hold an `items/` dir. */
async function repoSlugs(ledgerDir: string): Promise<string[]> {
  const entries = await readdir(ledgerDir, { withFileTypes: true }).catch(() => []);
  const out: string[] = [];
  for (const e of entries) {
    if (!e.isDirectory() || e.name.startsWith('.')) continue;
    const items = await readdir(join(ledgerDir, e.name, 'items')).catch(() => null);
    if (items !== null) out.push(e.name);
  }
  return out.sort();
}

/**
 * `filter.repo` reaches `join()` as an offline caller's `--repo` value.
 * `slugSchema` rejects anything but `[a-z0-9-]+` (so no `..`, no `/`), and the
 * realpath containment check is defense in depth against a symlinked ledger
 * entry pointing outside it. A slug that fails either resolves to `null`, and
 * the caller treats that exactly like "repo has no items" — offline listing
 * is fail-soft by design (see `readItems`'s own doc comment).
 */
async function safeItemsDir(ledgerDir: string, slug: string): Promise<string | null> {
  if (!slugSchema.safeParse(slug).success) return null;
  const root = await realpath(ledgerDir).catch(() => null);
  if (root === null) return null;
  const candidate = await realpath(join(ledgerDir, slug, 'items')).catch(() => null);
  if (candidate === null) return null;
  if (candidate !== root && !candidate.startsWith(root + sep)) return null;
  return resolve(ledgerDir, slug, 'items');
}

/**
 * Parse every item md of the selected repos.
 *
 * A file that fails to parse is skipped rather than fatal: offline mode exists
 * because something is already wrong, and one hand-edited item must not take the
 * whole listing down with it.
 */
export async function readItems(ledgerDir: string, filter: OfflineFilter = {}): Promise<Item[]> {
  const slugs = filter.repo ? [filter.repo] : await repoSlugs(ledgerDir);
  const out: Item[] = [];
  for (const slug of slugs) {
    const dir = filter.repo ? await safeItemsDir(ledgerDir, slug) : join(ledgerDir, slug, 'items');
    if (dir === null) continue;
    for (const name of (await readdir(dir).catch(() => [] as string[])).sort()) {
      if (!name.endsWith('.md')) continue;
      const text = await readFile(join(dir, name), 'utf8').catch(() => null);
      if (text === null) continue;
      try {
        out.push(parseItem(text, join(dir, name)).item);
      } catch {
        continue;
      }
    }
  }
  return out.filter((i) => matches(i, filter));
}

function matches(item: Item, f: OfflineFilter): boolean {
  const fm = item.fm;
  if (f.status && fm.status !== f.status) return false;
  if (f.owner && fm.owner !== f.owner) return false;
  if (f.kind && fm.kind !== f.kind) return false;
  if (f.priority && fm.priority !== f.priority) return false;
  if (f.open && !OPEN_STATUSES.includes(fm.status as ItemStatus)) return false;
  if (f.session && fm.claimed_by?.session !== f.session && fm.source?.session !== f.session) {
    return false;
  }
  return true;
}

export async function offlineLs(ledgerDir: string, filter: OfflineFilter): Promise<string> {
  const items = await readItems(ledgerDir, filter);
  const lines = items.map((i) => itemLine(i));
  return [OFFLINE_HEADER, ...(lines.length > 0 ? lines : ['— no items —'])].join('\n');
}

export async function offlineShow(ledgerDir: string, id: string): Promise<string | null> {
  const items = await readItems(ledgerDir, {});
  const item = items.find((i) => i.fm.id === id.toUpperCase());
  if (item === undefined) return null;
  const fm = item.fm;
  const lines = [
    OFFLINE_HEADER,
    `${fm.id} [${fm.kind}] ${fm.priority} ${fm.status} ${fm.repo} — ${fm.title}`,
    `owner ${fm.owner}${fm.area ? ` · area ${fm.area}` : ''}${
      fm.claimed_by ? ` · held by ${fm.claimed_by.session?.slice(0, 4) ?? '?'}` : ''
    }`,
  ];
  if (item.why.trim() !== '') lines.push('', 'Why:', item.why.trim());
  if (item.steps.length > 0) {
    lines.push('', 'Plan:');
    for (const s of item.steps) lines.push(`  ${s.done ? '[x]' : '[ ]'} ${s.n}. ${s.text}`);
  }
  if (item.rec.trim() !== '') lines.push('', 'Recommendation:', item.rec.trim());
  // Comments and log last: they are the longest and the least useful offline.
  for (const cm of item.comments.slice(-3)) {
    lines.push('', `### ${cm.at} · ${cm.author}`, cm.text.trim());
  }
  return lines.join('\n');
}

/**
 * A deliberately small offline brief: open items by priority, per repo. No live
 * sessions, no git, no orphans — those do not exist without the hub, and a brief
 * that silently omits them while looking normal is how a session starts work on
 * a file somebody else holds.
 */
export async function offlineBrief(ledgerDir: string, repo?: string): Promise<string> {
  const items = await readItems(ledgerDir, { repo, open: true });
  const lines = [OFFLINE_HEADER, 'Hub is not running — the live part of the brief (sessions, git, orphans) is missing.'];
  const byRepo = new Map<string, Item[]>();
  for (const item of items) {
    const list = byRepo.get(item.fm.repo) ?? [];
    list.push(item);
    byRepo.set(item.fm.repo, list);
  }
  for (const [slug, list] of [...byRepo.entries()].sort()) {
    list.sort((a, b) => a.fm.priority.localeCompare(b.fm.priority));
    lines.push('', `${slug} — ${list.length} open`);
    for (const i of list.slice(0, 10)) {
      lines.push(`  ${i.fm.id} [${i.fm.kind}] ${i.fm.priority} ${i.fm.status} ${i.fm.title}`);
    }
    if (list.length > 10) lines.push(`  … +${list.length - 10}`);
  }
  if (byRepo.size === 0) lines.push('', '— no open items —');
  return lines.join('\n');
}
