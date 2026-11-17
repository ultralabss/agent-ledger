/** In-memory index over the md ledger.
 *
 *  F0 has no SQLite: the index is rebuilt from md at boot and kept fresh by
 *  `fs.watch`. Everything the HTTP layer reads goes through `LedgerIndex`, so
 *  F1 can drop in a `SqliteIndex` (same methods) without touching callers.
 */

import { isOpen } from '@agent-ledger/shared';
import type { Decision, IntakeRecord, Item, ItemStatus, JournalEvent } from '@agent-ledger/shared';
import type { MdDoc } from '@agent-ledger/shared';

export interface StoredItem {
  item: Item;
  /** Source document, kept so a rewrite preserves unknown sections. */
  doc: MdDoc;
  file: string;
}

export interface StoredIntake {
  rec: IntakeRecord;
  doc: MdDoc;
  file: string;
}

export interface ItemFilter {
  repo?: string;
  status?: ItemStatus;
  owner?: string;
  kind?: string;
  priority?: string;
  open?: boolean;
}

export interface LedgerIndex {
  putItem(rec: StoredItem): void;
  getItem(id: string): StoredItem | undefined;
  listItems(filter?: ItemFilter): StoredItem[];
  dropItem(id: string): void;

  putIntake(rec: StoredIntake): void;
  dropIntake(id: string): void;
  getIntake(id: string): StoredIntake | undefined;
  listIntake(status?: string): StoredIntake[];

  setJournal(repo: string, month: string, events: JournalEvent[]): void;
  listJournal(repo?: string): JournalEvent[];

  setDecisions(repo: string, decisions: Decision[]): void;
  listDecisions(repo?: string): Decision[];

  reset(): void;
}

const PRIORITY_ORDER: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };

export function compareItems(a: Item, b: Item): number {
  const p = (PRIORITY_ORDER[a.fm.priority] ?? 9) - (PRIORITY_ORDER[b.fm.priority] ?? 9);
  if (p !== 0) return p;
  return a.fm.updated < b.fm.updated ? 1 : a.fm.updated > b.fm.updated ? -1 : 0;
}

export class MemoryIndex implements LedgerIndex {
  private items = new Map<string, StoredItem>();
  private intake = new Map<string, StoredIntake>();
  private journal = new Map<string, JournalEvent[]>();
  private decisions = new Map<string, Decision[]>();

  putItem(rec: StoredItem): void {
    this.items.set(rec.item.fm.id, rec);
  }

  getItem(id: string): StoredItem | undefined {
    return this.items.get(id);
  }

  dropItem(id: string): void {
    this.items.delete(id);
  }

  listItems(filter: ItemFilter = {}): StoredItem[] {
    const out: StoredItem[] = [];
    for (const rec of this.items.values()) {
      const fm = rec.item.fm;
      if (filter.repo && fm.repo !== filter.repo) continue;
      if (filter.status && fm.status !== filter.status) continue;
      if (filter.owner && fm.owner !== filter.owner) continue;
      if (filter.kind && fm.kind !== filter.kind) continue;
      if (filter.priority && fm.priority !== filter.priority) continue;
      if (filter.open && !isOpen(fm.status)) continue;
      out.push(rec);
    }
    return out.sort((a, b) => compareItems(a.item, b.item));
  }

  putIntake(rec: StoredIntake): void {
    this.intake.set(rec.rec.id, rec);
  }

  dropIntake(id: string): void {
    this.intake.delete(id);
  }

  getIntake(id: string): StoredIntake | undefined {
    return this.intake.get(id);
  }

  listIntake(status?: string): StoredIntake[] {
    const out = [...this.intake.values()].filter((r) => !status || r.rec.status === status);
    return out.sort((a, b) => (a.rec.id < b.rec.id ? 1 : a.rec.id > b.rec.id ? -1 : 0));
  }

  setJournal(repo: string, month: string, events: JournalEvent[]): void {
    this.journal.set(`${repo}/${month}`, events);
  }

  listJournal(repo?: string): JournalEvent[] {
    const out: JournalEvent[] = [];
    for (const [key, events] of this.journal) {
      if (repo && !key.startsWith(`${repo}/`)) continue;
      out.push(...events);
    }
    return out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
  }

  setDecisions(repo: string, decisions: Decision[]): void {
    this.decisions.set(repo, decisions);
  }

  listDecisions(repo?: string): Decision[] {
    const out: Decision[] = [];
    for (const [slug, list] of this.decisions) {
      if (repo && slug !== repo) continue;
      out.push(...list);
    }
    return out.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : b.n - a.n));
  }

  reset(): void {
    this.items.clear();
    this.intake.clear();
    this.journal.clear();
    this.decisions.clear();
  }
}
