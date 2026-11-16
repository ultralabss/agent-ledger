/**
 * `ledger release-notes` — SPEC §12, F3 item 16.
 *
 * Reads git (log only — the hub never mutates a code repo, SPEC §6.3) and pairs
 * `Closes:` trailers in the range with items from the ledger. The output is the
 * "Closed items" section a repo's own `scripts/release.sh` pastes into its
 * CHANGELOG; this command does not touch any other repo's scripts.
 *
 * `from`/`to` are validated by `gitRevSchema` at the API edge (no `-`, no `..`,
 * no spaces) because they become argv entries for `git log`.
 */

import { parseItemId, type ReleaseNotesResponse } from '@agent-ledger/shared';
import { readCommits, readTags, revParse } from './gitreader.ts';
import type { Ledger } from './ledger/ledger.ts';

export interface ReleaseNotesInput {
  repo: string;
  checkout: string;
  from?: string | undefined;
  to?: string | undefined;
}

export async function buildReleaseNotes(
  ledger: Ledger,
  input: ReleaseNotesInput,
): Promise<ReleaseNotesResponse> {
  const to = input.to ?? 'HEAD';
  // No `--from`: take the newest tag that is an ancestor of `to`, which is what
  // "since the last release" means. No tags at all → the whole history.
  let from = input.from ?? null;
  if (from === null) {
    const tags = await readTags(input.checkout, 50);
    for (const tag of tags) {
      if (tag.tag === to) continue;
      if ((await revParse(input.checkout, tag.tag)) !== null) {
        from = tag.tag;
        break;
      }
    }
  }
  const range = from === null ? to : `${from}..${to}`;
  const commits = await readCommits(input.checkout, range, 500);

  const seen = new Map<string, { id: string; title: string; commit: string | null }>();
  for (const commit of commits) {
    for (const id of commit.closes) {
      if (seen.has(id)) continue;
      const item = ledger.listItems().find((i) => i.fm.id === id) ?? null;
      seen.set(id, {
        id,
        title: item?.fm.title ?? '(item not in the ledger)',
        commit: commit.short,
      });
    }
  }
  const items = [...seen.values()].sort((a, b) => compareIds(a.id, b.id));

  const header = `## Closed items ${from === null ? to : `${from} → ${to}`}`;
  const markdown =
    items.length === 0
      ? `${header}\n\n_No items with a \`Closes:\` trailer in range._\n`
      : `${header}\n\n${items.map((i) => `- ${i.id} — ${i.title}`).join('\n')}\n`;

  return { repo: input.repo, from, to, items, markdown };
}

/** `ACME-9` before `ACME-10`: numeric part compared as a number. Within one
 *  prefix the primary slot (`""`, plain `ACME-5`) sorts before slot letters
 *  (`ACME-W1`), then by number. */
export function compareIds(a: string, b: string): number {
  const pa = parseItemId(a);
  const pb = parseItemId(b);
  if (pa && pb && pa.prefix === pb.prefix) {
    if (pa.slot !== pb.slot) return pa.slot < pb.slot ? -1 : 1;
    return pa.n - pb.n;
  }
  return a.localeCompare(b);
}
