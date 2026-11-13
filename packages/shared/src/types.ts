/** Domain types for the ledger. F0 subset of SPEC §4. */

export type ItemStatus = 'proposed' | 'open' | 'doing' | 'blocked' | 'done' | 'dropped';
export type ItemKind = 'BLOCKER' | 'DEPLOY' | 'RISK' | 'UNVERIFIED' | 'BACKLOG';
export type ItemPriority = 'P0' | 'P1' | 'P2' | 'P3';
export type ItemArea = 'server' | 'web' | 'mobile' | 'infra' | 'docs';
export type IntakeStatus = 'new' | 'triaged' | 'partial';
export type IntakeChannel = 'chat' | 'web';

export const ITEM_STATUSES: readonly ItemStatus[] = [
  'proposed',
  'open',
  'doing',
  'blocked',
  'done',
  'dropped',
];
export const ITEM_KINDS: readonly ItemKind[] = [
  'BLOCKER',
  'DEPLOY',
  'RISK',
  'UNVERIFIED',
  'BACKLOG',
];
export const ITEM_PRIORITIES: readonly ItemPriority[] = ['P0', 'P1', 'P2', 'P3'];
export const ITEM_AREAS: readonly ItemArea[] = ['server', 'web', 'mobile', 'infra', 'docs'];

export interface ClaimedBy {
  session: string;
  since: string;
}

export interface ItemSource {
  session: string | null;
  agent: string | null;
  commit: string | null;
}

export interface ItemDone {
  commit: string | null;
  version: string | null;
  at: string;
}

export interface ItemFrontmatter {
  id: string;
  title: string;
  status: ItemStatus;
  kind: ItemKind;
  priority: ItemPriority;
  owner: string;
  repo: string;
  area: ItemArea | null;
  paths: string[];
  blocks: string[];
  blocked_by: string[];
  requested_by: string | null;
  intake: string | null;
  aliases: string[];
  claimed_by: ClaimedBy | null;
  source: ItemSource;
  done: ItemDone | null;
  created: string;
  updated: string;
}

export interface PlanStep {
  n: number;
  done: boolean;
  text: string;
}

export interface ItemComment {
  at: string;
  author: string;
  id: string;
  text: string;
}

export interface LogLine {
  at: string;
  session: string;
  text: string;
}

/** Parsed item: frontmatter + the known body sections. Unknown sections stay
 *  in `raw` (see `md.ts`) so a rewrite never loses them. */
export interface Item {
  fm: ItemFrontmatter;
  why: string;
  steps: PlanStep[];
  rec: string;
  comments: ItemComment[];
  log: LogLine[];
}

/** `repo` = git checkout (or virtual repo, `path: null`), `system` =
 *  whole infra (no path, no git), `vps` = one production machine (no path). */
export type RepoKind = 'repo' | 'system' | 'vps';

export interface RepoConfig {
  /** Absent in old `repos.yml` — read it through `repoKindOf()`. */
  kind?: RepoKind;
  /** `kind: vps` only; ssh alias / hostname, informational. */
  host?: string;
  prefix: string;
  path: string | null;
  next: number;
  graphify?: string | null;
  docs?: string[];
  /** Old prefixes kept so `ACME-3` still resolves after a prefix rename (SPEC §4.2). */
  prefix_aliases?: string[];
  /** False until a session has filled `CONTEXT.md` and run `ledger repo onboarded`.
   *  Drives the ONBOARDING block in the SessionStart briefing. */
  onboarded?: boolean;
  /** Repo-relative globs that define this repo's public contract
   *  (`apps/server/src/**\/*.dto.ts`, `openapi.yaml`, a migration dir…). A
   *  commit touching one of these notifies `consumers`. */
  contracts?: string[];
  /** Repos that consume the contracts above. */
  consumers?: string[];
}

export type ReposFile = Record<string, RepoConfig>;

export function repoKindOf(cfg: { kind?: RepoKind | undefined }): RepoKind {
  return cfg.kind ?? 'repo';
}

export interface IntakeDropped {
  text: string;
  reason: string;
}

export interface IntakeRecord {
  id: string;
  at: string;
  channel: IntakeChannel;
  session: string | null;
  repo_hint: string | null;
  status: IntakeStatus;
  items: string[];
  text: string;
  triage: { item: string; excerpt: string }[];
  dropped: IntakeDropped[];
}

export type JournalType =
  | 'item.created'
  | 'item.status'
  | 'item.comment'
  | 'session.summary'
  | 'decision'
  | 'intake.triaged'
  | 'intake.linked'
  | 'release'
  | 'commit';

export interface JournalEvent {
  /** `YYYY-MM-DD HH:MM` local time. */
  at: string;
  /** 4 chars, or `—` when unknown. */
  session: string;
  type: string;
  fields: string[];
  repo: string;
}

export interface Decision {
  n: number;
  date: string;
  title: string;
  body: string;
  repo: string;
}

/* ---------------- Title limits ---------------- */

/** Hard cap on an item title (writes only). Longer → 422; detail belongs in
 *  `why`. Existing longer titles keep reading fine — only writes validate. */
export const TITLE_MAX = 80;
/** The CLI warns above this; the hub does not refuse. */
export const TITLE_WARN = 60;
