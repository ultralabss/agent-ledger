/** Typed merge engine for synced ledger files (docs/multi-device-spec.md §3.2).
 *
 *  Pure functions: text in, text out. No git, no network, no clock, no fs.
 *  Every merger is deterministic; where the spec asks for commutativity the
 *  result does not depend on which side is "ours" (the documented tie-breaks
 *  — `CONTEXT.md` keeps the local side, `claimed_by` keeps the remote side —
 *  are inputs, not clock or order accidents).
 */

export type SyncNoteType =
  /** Both sides changed the same field/text; the loser was preserved in the item. */
  | 'sync.conflict'
  /** A new claim did not survive the merge — the owning session needs an inbox note. */
  | 'sync.claim-lost'
  /** Same decision id, diverging bodies — both kept. */
  | 'sync.decision-conflict'
  /** CONTEXT.md diverged — local kept, the other version goes to a `proposed` item. */
  | 'sync.context-conflict';

export interface SyncNote {
  type: SyncNoteType;
  /** Item id / decision id, when the note is about one. */
  item?: string;
  field?: string;
  /** Device whose value lost / whose claim was dropped. */
  device?: string;
  session?: string;
  /** Single line, no secrets (field names and short value excerpts only). */
  detail: string;
}

export interface MergeCtx {
  ourDevice: string;
  theirDevice: string;
  /** True when `theirs` is the state already on remote `main` (push-order CAS:
   *  that side wins `claimed_by`). Swap it together with the sides. */
  remoteIsTheirs: boolean;
}

export interface MergeResult {
  merged: string;
  notes: SyncNote[];
}

export interface ContextMergeResult extends MergeResult {
  /** Set when CONTEXT.md conflicted: the caller files it as a `proposed` item. */
  proposedItem: { title: string; why: string; otherVersion: string } | null;
}
