/** zod schemas. Every write validates here first; failure → 422. */

import { z } from 'zod';
import { isSingleLine } from './sanitize.ts';
import {
  ITEM_AREAS,
  ITEM_KINDS,
  ITEM_PRIORITIES,
  ITEM_STATUSES,
  TITLE_MAX,
} from './types.ts';

export const slugSchema = z
  .string()
  .regex(/^[a-z0-9-]+$/, 'slug must be [a-z0-9-]+');
export const prefixSchema = z
  .string()
  .regex(/^[A-Z]{2,4}$/, 'prefix must be 2–4 uppercase letters A–Z');
/** Device slot letter inside an item id (`ACME-W7`). `""` = the primary
 *  (existing) ledger, whose ids stay `ACME-142`. No I and O. */
export const slotSchema = z
  .string()
  .regex(/^[A-HJ-NP-Z]?$/, 'slot must be empty or one letter A-H J-N P-Z');

/** `PREFIX-<slot?><n>`; the `[A-HJ-NP-Z]` class must match `SLOT_LETTERS`. */
export const ITEM_ID_PATTERN = '[A-Z]{2,4}-[A-HJ-NP-Z]?[1-9][0-9]*';
export const ITEM_ID_RE = new RegExp(`^${ITEM_ID_PATTERN}$`);
/** Fresh global regex for scanning free text (`\b`-delimited). */
export function itemIdScanRe(): RegExp {
  return new RegExp(`\\b${ITEM_ID_PATTERN}\\b`, 'g');
}
export function isItemId(s: unknown): s is string {
  return typeof s === 'string' && ITEM_ID_RE.test(s);
}

export interface ParsedItemId {
  prefix: string;
  /** `""` = primary ledger. */
  slot: string;
  n: number;
}

/** Strict parse of one id; `null` for anything that is not exactly an id. */
export function parseItemId(id: string): ParsedItemId | null {
  const m = /^([A-Z]{2,4})-([A-HJ-NP-Z]?)([1-9][0-9]*)$/.exec(id);
  if (!m) return null;
  const n = Number(m[3]);
  if (!Number.isSafeInteger(n)) return null;
  return { prefix: m[1] as string, slot: m[2] as string, n };
}

export function formatItemId(prefix: string, slot: string, n: number): string {
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`item number must be a positive integer, got ${n}`);
  const id = `${prefix}-${slot}${n}`;
  if (!ITEM_ID_RE.test(id)) throw new Error(`not a valid item id: "${id}"`);
  return id;
}

export const itemIdSchema = z
  .string()
  .regex(ITEM_ID_RE, 'item id has the form PREFIX-n or PREFIX-<slot>n');
export const snowflakeIdSchema = z.string().regex(/^[1-9]\d{0,19}$/, 'not a snowflake id');

export const statusSchema = z.enum(ITEM_STATUSES as unknown as [string, ...string[]]);
export const kindSchema = z.enum(ITEM_KINDS as unknown as [string, ...string[]]);
export const prioritySchema = z.enum(ITEM_PRIORITIES as unknown as [string, ...string[]]);
export const areaSchema = z.enum(ITEM_AREAS as unknown as [string, ...string[]]);

/** `\n`, `\r` and control characters would break the one-line format (md/log
 *  injection). Same definition as `sanitizeLine` at the sink — the edge
 *  rejects, and the sink sanitises on top (content also arrives outside the API). */
export function singleLine<T extends z.ZodString>(schema: T): T {
  return schema.refine(isSingleLine, {
    message: 'must not contain a newline or control character',
  }) as unknown as T;
}

const textLine = singleLine(z.string().min(1).max(400));
/** Single-line path/glob — claim paths, touched, lease paths. */
export const pathLine = singleLine(z.string().min(1).max(300));

/**
 * Item title. Hard cap of {@link TITLE_MAX} characters — a long title is
 * unreadable in a list and the detail belongs in `--why` anyway. Applies on
 * write only (create/patch); `itemFrontmatterSchema` stays at 400 so existing
 * long titles still load and do not block reading the whole ledger.
 */
export const titleSchema = singleLine(
  z
    .string()
    .min(1)
    .max(TITLE_MAX, `title has at most ${TITLE_MAX} characters — put the detail in --why`),
);

/**
 * Comma-separated list of repo slugs (`?repo=a,b`). A single slug stays valid
 * input, so old clients are unchanged. Duplicates and empty entries are dropped.
 */
export const repoListSchema = z
  .string()
  .max(1000)
  .transform((raw) => [...new Set(raw.split(',').map((s) => s.trim()).filter(Boolean))])
  .refine((list) => list.length > 0 && list.length <= 50, {
    message: 'repo: give 1–50 comma-separated slugs',
  })
  .refine((list) => list.every((s) => /^[a-z0-9-]+$/.test(s)), {
    message: 'repo: every slug must be [a-z0-9-]+',
  });

export const claimedBySchema = z.object({
  session: z.string().min(1).max(64),
  since: z.string().min(1),
});

export const sourceSchema = z.object({
  session: z.string().max(64).nullable().default(null),
  agent: z.string().max(64).nullable().default(null),
  commit: z.string().max(64).nullable().default(null),
});

/* ---------- One shape for `done.version`, write and read ---------- */

/** `done.version` is a machine reference — a version, tag or sha, never prose.
 *  The write path (`--ref`) and the read path (frontmatter) both go through
 *  `isDoneRef`, so the hub can never store a value its own reindex rejects. */
export const DONE_REF_MAX = 64;
const DONE_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._+:@/-]*$/;

export function isDoneRef(value: string): boolean {
  return value.length > 0 && value.length <= DONE_REF_MAX && DONE_REF_RE.test(value);
}

export const DONE_REF_HINT =
  '--ref is a version, tag or commit sha (max 64 characters, no spaces) — ' +
  'put a sentence or a note in `ledger note <ID> "…"`';

const doneRefField = z
  .string()
  .max(DONE_REF_MAX)
  .nullable()
  .default(null)
  .refine((v) => v === null || isDoneRef(v), DONE_REF_HINT);

export const doneSchema = z.object({
  commit: z.string().max(64).nullable().default(null),
  version: doneRefField,
  at: z.string().min(1),
});

/** Frontmatter of `<repo>/items/<ID>.md` (SPEC §4.3). */
export const itemFrontmatterSchema = z.object({
  id: itemIdSchema,
  title: textLine,
  status: statusSchema,
  kind: kindSchema,
  priority: prioritySchema,
  owner: singleLine(z.string().min(1).max(64)),
  repo: slugSchema,
  area: areaSchema.nullable().default(null),
  paths: z.array(pathLine).default([]),
  blocks: z.array(itemIdSchema).default([]),
  blocked_by: z.array(itemIdSchema).default([]),
  requested_by: itemIdSchema.nullable().default(null),
  intake: snowflakeIdSchema.nullable().default(null),
  aliases: z.array(singleLine(z.string().min(1).max(200))).default([]),
  claimed_by: claimedBySchema.nullable().default(null),
  source: sourceSchema.default({ session: null, agent: null, commit: null }),
  done: doneSchema.nullable().default(null),
  created: z.string().min(1),
  updated: z.string().min(1),
});

export const intakeFrontmatterSchema = z.object({
  id: snowflakeIdSchema,
  at: z.string().min(1),
  channel: z.enum(['chat', 'web']),
  session: z.string().max(64).nullable().default(null),
  repo_hint: slugSchema.nullable().default(null),
  status: z.enum(['new', 'triaged', 'partial']),
  items: z.array(itemIdSchema).default([]),
});

/** `root_sha` = oldest root commit of the default branch (git object id). */
export const rootShaSchema = z
  .string()
  .regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/, 'root_sha must be a 40 or 64 char lowercase hex git object id');
/** `host/org/repo`, never credentials, scheme or query. */
export const originHintSchema = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/, 'origin_hint: only letters, digits and . _ : / -')
  .refine((v) => !v.split('/').includes('..'), 'origin_hint: no ".." segment');
export const repoIdentitySchema = z.object({
  root_sha: rootShaSchema,
  origin_hint: originHintSchema.nullable().default(null),
});

/** Repo-relative path: no absolute form, no drive, no `..`, no backslash. */
export const relPathSchema = z
  .string()
  .min(1)
  .max(300)
  .refine(
    (v) =>
      !/^(?:[\\/~]|[A-Za-z]:)/.test(v) && !v.includes('\\') && !v.split('/').includes('..'),
    'must be a relative path without ".."',
  );

/** What a ledger "repo" actually is. Absent in old `repos.yml` =
 *  `repo` (a git checkout, or a virtual repo with `path: null`). */
const hostSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._@:-]*$/, 'host: only letters, digits and . _ @ : -');

export const repoKindSchema = z.enum(['repo', 'system', 'vps']);

export const repoConfigSchema = z.object({
  kind: repoKindSchema.optional(),
  /** Informational ssh alias / hostname for `kind: vps`. */
  host: hostSchema.optional(),
  prefix: prefixSchema,
  path: z.string().nullable(),
  next: z.number().int().positive(),
  graphify: z.string().nullable().optional(),
  docs: z.array(z.string()).optional(),
  prefix_aliases: z.array(prefixSchema).max(10).optional(),
  onboarded: z.boolean().optional(),
  /** Added in ledger format 2 (see `repoSyncedSchema`). */
  graphify_rel: relPathSchema.optional(),
  identity: repoIdentitySchema.optional(),
  /** Repo-relative globs whose change is a public contract change.
   *  Bounded so a hand-edited `repos.yml` cannot turn every commit into a
   *  glob-matching sweep over hundreds of patterns. */
  contracts: z.array(singleLine(z.string().min(1).max(200))).max(40).optional(),
  /** Slugs that consume this repo's contracts and must be told. */
  consumers: z.array(slugSchema).max(40).optional(),
});

export const reposFileSchema = z.record(slugSchema, repoConfigSchema);

/* ---------- ledger format 2: synced repos.yml vs local .hub/local.yml ---------- */

/** One entry of the SYNCED `repos.yml` (format 2). No `path`, no `next`, no
 *  absolute path of any kind. `path` / `next` / `graphify` are accepted ONLY so a
 *  format-1 file can be read and migrated; the writer never emits them. */
export const repoSyncedSchema = z.object({
  kind: repoKindSchema.optional(),
  host: hostSchema.optional(),
  prefix: prefixSchema,
  docs: z.array(z.string()).optional(),
  graphify_rel: relPathSchema.optional(),
  identity: repoIdentitySchema.optional(),
  prefix_aliases: z.array(prefixSchema).max(10).optional(),
  onboarded: z.boolean().optional(),
  contracts: z.array(singleLine(z.string().min(1).max(200))).max(40).optional(),
  consumers: z.array(slugSchema).max(40).optional(),
  /* legacy (format 1), read-only */
  path: z.string().nullable().optional(),
  next: z.number().int().positive().optional(),
  graphify: z.string().nullable().optional(),
});
export const reposSyncedFileSchema = z.record(slugSchema, repoSyncedSchema);

/** `.hub/local.yml` (gitignored, never synced): this machine's checkout paths. */
export const repoLocalSchema = z.object({
  path: z.string().min(1).nullable().optional(),
  graphify: z.string().min(1).nullable().optional(),
  docs: z.array(z.string()).optional(),
});
export const reposLocalFileSchema = z.record(slugSchema, repoLocalSchema);

/* ---------- API request bodies ---------- */

export const repoCreateSchema = z.object({
  slug: slugSchema,
  prefix: prefixSchema.optional(),
  path: z.string().min(1).nullable().optional(),
  kind: repoKindSchema.optional(),
  host: hostSchema.optional(),
  graphify: z.string().min(1).nullable().optional(),
  docs: z.array(z.string().min(1)).optional(),
});

/** `POST /v1/repos/:slug/bind` — absolute path of a checkout on the hub's machine. */
export const repoBindSchema = z.object({
  path: z.string().min(1).max(4096),
});

/** `POST /v1/repos/:slug/contract`. Additive by default; `rm` /
 *  `rm_consumers` are the only way to take something out. */
export const repoContractSchema = z.object({
  add: z.array(singleLine(z.string().min(1).max(200))).max(40).optional(),
  consumer: z.array(slugSchema).max(40).optional(),
  rm: z.array(singleLine(z.string().min(1).max(200))).max(40).optional(),
  rm_consumer: z.array(slugSchema).max(40).optional(),
  // Who is asking — used to refuse a reply worker (`LEDGER_SESSION`
  // starts `worker-`) or a headless run (`headless-`) touching this
  // owner-level setting, and to log the actor on a real change.
  session: singleLine(z.string().max(64)).nullable().optional(),
});

export const itemCreateSchema = z.object({
  repo: slugSchema,
  title: titleSchema,
  kind: kindSchema.default('BACKLOG'),
  priority: prioritySchema.default('P2'),
  owner: singleLine(z.string().min(1).max(64)).default('agent'),
  area: areaSchema.nullable().optional(),
  why: z.string().max(20_000).optional(),
  rec: z.string().max(20_000).optional(),
  steps: z.array(singleLine(z.string().min(1).max(400))).max(50).default([]),
  blocked_by: z.array(itemIdSchema).default([]),
  requested_by: itemIdSchema.nullable().optional(),
  intake: snowflakeIdSchema.nullable().optional(),
  aliases: z.array(z.string().min(1).max(200)).default([]),
  proposed: z.boolean().default(false),
  status: statusSchema.optional(),
  session: singleLine(z.string().max(64)).nullable().optional(),
  agent: singleLine(z.string().max(64)).nullable().optional(),
  /** Skip the near-duplicate check. Set by `ledger add --force` after a
   *  human looked at the candidates and decided it really is a new item. */
  force: z.boolean().default(false),
});

export const itemPatchSchema = z
  .object({
    title: titleSchema.optional(),
    status: statusSchema.optional(),
    owner: singleLine(z.string().min(1).max(64)).optional(),
    kind: kindSchema.optional(),
    priority: prioritySchema.optional(),
    area: areaSchema.nullable().optional(),
    why: z.string().max(20_000).optional(),
    rec: z.string().max(20_000).optional(),
    steps: z.array(singleLine(z.string().min(1).max(400))).max(50).optional(),
    session: singleLine(z.string().max(64)).nullable().optional(),
    // why_note goes into a log line and a journal field — it must be one line.
    why_note: singleLine(z.string().max(400)).optional(),
    // Skip the near-duplicate check on a title rename, same escape
    // hatch `ledger add --force` already has for a fresh item.
    force: z.boolean().default(false),
  })
  // `force` carries a default, so it is always present after parsing — only
  // the OTHER keys decide whether this is a real patch.
  .refine((v) => Object.keys(v).some((k) => k !== 'force'), { message: 'empty PATCH' });

export const claimSchema = z.object({
  session: singleLine(z.string().min(1).max(64)).default('manual'),
  // Every element separately — `paths.join(', ')` goes into a log and a journal line.
  paths: z.array(pathLine).max(100).default([]),
  intent: singleLine(z.string().max(2000)).optional(),
});

export const releaseSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  // Goes into a log line and a journal field.
  why: singleLine(z.string().max(400)).optional(),
});

export const doneActionSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  // Rejected at the edge with the same predicate the frontmatter uses.
  ref: singleLine(z.string().max(DONE_REF_MAX))
    .optional()
    .refine((v) => v === undefined || v === '' || isDoneRef(v), DONE_REF_HINT),
});

export const dropSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  why: singleLine(z.string().min(1).max(400)),
});

export const dupSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  into: itemIdSchema,
});

export const blockSchema = z
  .object({
    session: singleLine(z.string().max(64)).nullable().optional(),
    by: itemIdSchema.optional(),
    on: z.literal('human').optional(),
  })
  .refine((v) => Boolean(v.by) !== Boolean(v.on), {
    message: 'give either --by <ID> or --on human',
  });

export const reopenSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  why: singleLine(z.string().min(1).max(400)),
});

export const commentSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  // The author goes into the `### at · author · cid` header.
  author: singleLine(z.string().min(1).max(64)).default('orchestrator'),
  text: z.string().min(1).max(20_000),
});

export const stepSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  n: z.number().int().positive(),
  done: z.boolean(),
});

export const intakeCreateSchema = z.object({
  text: z.string().min(1).max(200_000),
  channel: z.enum(['chat', 'web']).default('chat'),
  session: singleLine(z.string().max(64)).nullable().optional(),
  // repo_hint is used as a key into repos.yml — it must be a slug.
  repo_hint: slugSchema.nullable().optional(),
  /**
   * What to do with it. `send_to_session` requires a live `session`;
   * `triage_and_run` requires headless triage to be configured plus
   * `LEDGER_CLAUDE_BIN` (Claude Code adapter).
   */
  action: z.enum(['triage', 'send_to_session', 'triage_and_run']).default('triage'),
});

export const triageSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  items: z.array(itemIdSchema).default([]),
  dropped: z
    .array(z.object({ text: z.string().min(1).max(2000), reason: z.string().min(1).max(400) }))
    .default([]),
  status: z.enum(['triaged', 'partial']).optional(),
});

export const decisionCreateSchema = z.object({
  repo: slugSchema,
  title: textLine,
  why: z.string().min(1).max(20_000),
  related: z.array(z.string().min(1).max(200)).default([]),
  session: singleLine(z.string().max(64)).nullable().optional(),
});

export const journalCreateSchema = z.object({
  repo: slugSchema,
  text: z.string().min(1).max(20_000),
  type: z.string().regex(/^[a-z][a-z.]{1,30}$/).default('session.summary'),
  session: singleLine(z.string().max(64)).nullable().optional(),
});

export const itemQuerySchema = z.object({
  /** One slug or a comma list (`?repo=a,b`). */
  repo: repoListSchema.optional(),
  status: statusSchema.optional(),
  owner: z.string().min(1).max(64).optional(),
  kind: kindSchema.optional(),
  priority: prioritySchema.optional(),
  open: z.enum(['1', 'true', '0', 'false']).optional(),
  /** Items this session holds (`claimed_by.session`) or created (`source.session`). */
  session: singleLine(z.string().min(1).max(128)).optional(),
  /** Case- and diacritics-insensitive substring of the title. */
  q: singleLine(z.string().min(1).max(200)).optional(),
  format: z.enum(['json', 'line']).optional(),
});

/* ---------- F1: hooks, sessions, search ---------- */

/** Agent session id — hex/uuid-ish, but never trust the shape blindly. */
export const sessionIdSchema = singleLine(z.string().min(1).max(128));

export const HOOK_EVENTS = [
  'session-start',
  'user-prompt-submit',
  'pre-tool-use',
  'post-tool-use',
  'stop',
  'session-end',
] as const;

export type HookEvent = (typeof HOOK_EVENTS)[number];

export const hookEventSchema = z.enum(HOOK_EVENTS);

/**
 * Raw hook stdin of the Claude Code adapter (docs code.claude.com/docs/en/hooks).
 *
 * Deliberately permissive: unknown keys are ignored, every field is optional
 * except `session_id`, and nothing here is trusted as a filesystem path until
 * it has been realpath'd and matched against a registered repo. A future
 * Claude Code release adding fields must not 422 the hook (fail-open spirit).
 */
export const hookInputSchema = z
  .object({
    session_id: sessionIdSchema,
    transcript_path: singleLine(z.string().max(4096)).optional(),
    cwd: singleLine(z.string().max(4096)).optional(),
    hook_event_name: singleLine(z.string().max(64)).optional(),
    permission_mode: singleLine(z.string().max(64)).optional(),
    /** SessionStart: startup | resume | clear | compact */
    source: singleLine(z.string().max(32)).optional(),
    /** SessionEnd: clear | resume | logout | prompt_input_exit | other */
    reason: singleLine(z.string().max(64)).optional(),
    /** Subagent only. `session_id` stays the parent's. */
    agent_id: singleLine(z.string().max(128)).optional(),
    agent_type: singleLine(z.string().max(128)).optional(),
    tool_name: singleLine(z.string().max(128)).optional(),
    tool_input: z.record(z.string(), z.unknown()).optional(),
    tool_response: z.unknown().optional(),
    stop_hook_active: z.boolean().optional(),
    prompt: z.string().max(200_000).optional(),
    /** Set by `ledger hook` when `LEDGER_WORKER=1` is in its env — never
     *  sent by Claude Code itself. Marks a reply worker's own tool calls
     *  for the stricter worker guard, nothing else. */
    worker: z.boolean().optional(),
  })
  .passthrough();

export type HookInput = z.infer<typeof hookInputSchema>;

export const sessionQuerySchema = z.object({
  /** One slug or a comma list (`?repo=a,b`). */
  repo: repoListSchema.optional(),
  live: z.enum(['1', 'true', '0', 'false']).optional(),
  format: z.enum(['json', 'line']).optional(),
});

export const searchQuerySchema = z.object({
  q: singleLine(z.string().min(2).max(200)),
  repo: slugSchema.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(40),
  format: z.enum(['json', 'line']).optional(),
});

export const timelineQuerySchema = z.object({
  /** One slug or a comma list (`?repo=a,b`). */
  repo: repoListSchema.optional(),
  since: singleLine(z.string().max(16)).optional(),
  type: singleLine(z.string().max(64)).optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(200),
  format: z.enum(['json', 'line']).optional(),
});

export const whoseQuerySchema = z.object({
  path: singleLine(z.string().min(1).max(4096)),
  format: z.enum(['json', 'line']).optional(),
});

/** `GET /v1/repos/:slug/why?path=` — a file, directory or simple glob, either
 *  absolute (inside the repo) or repo-relative. The hub validates it again after
 *  `realpath`; this is only the shape. */
export const whyQuerySchema = z.object({
  path: singleLine(z.string().min(1).max(400)),
});

/** `GET /v1/repos/:slug/tidy?limit=&bucket=` */
export const tidyQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  bucket: z.enum(['looks-done', 'abandoned', 'unknown', 'review', 'fresh']).optional(),
});

/* ---------- F2: guard, intrude, inbox, orphans (SPEC §10, §11) ---------- */

/** An absolute path from a hook or the CLI. Never trusted before `realpath`. */
export const absPathSchema = singleLine(z.string().min(1).max(4096));

export const guardSetSchema = z.object({
  state: z.enum(['on', 'off']),
  session: singleLine(z.string().max(64)).nullable().optional(),
  why: singleLine(z.string().max(200)).optional(),
});

export const intrudeBeginSchema = z.object({
  session: singleLine(z.string().min(1).max(64)),
  repo: slugSchema,
  /** The item in the *intruding* session's ledger that justifies the change. */
  item: itemIdSchema.nullable().optional(),
  paths: z.array(pathLine).min(1).max(100),
  intent: singleLine(z.string().max(2000)).optional(),
  /** Set by `ledger intrude begin --force` after the user authorised it in chat. */
  force: z.boolean().default(false),
});

export const intrudeCommitSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  /** Full or short sha — validated against the checkout, never shell-expanded. */
  commit: z
    .string()
    .regex(/^[0-9a-fA-F]{7,40}$/, 'commit must be a sha (7–40 hex characters)'),
  note: singleLine(z.string().max(400)).optional(),
});

export const intrudeEndSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
});

export const inboxCreateSchema = z
  .object({
    /** Omit to broadcast to every live session in `repo` (SPEC §11 step 4). */
    to: singleLine(z.string().min(1).max(64)).nullable().optional(),
    // Mandatory on the public endpoint. `origin` (hub/web/session)
    // is never read from the request body — the server sets it itself — so a
    // bare `from_session == null` can no longer be forged into an unframed
    // "message from the hub" by simply omitting `from`.
    from: singleLine(z.string().min(1).max(64)),
    repo: slugSchema.nullable().optional(),
    item: itemIdSchema.nullable().optional(),
    body: singleLine(z.string().min(1).max(1000)),
  })
  .refine((v) => Boolean(v.to) || Boolean(v.repo), {
    message: 'give `to` (a session) or `repo` (broadcast to live sessions)',
  });

export const inboxQuerySchema = z.object({
  session: singleLine(z.string().min(1).max(64)),
  all: z.enum(['1', 'true', '0', 'false']).optional(),
  format: z.enum(['json', 'line']).optional(),
});

export const adoptSchema = z
  .object({
    // Optional — a UI cookie caller (a human at the browser right
    // now) needs no session id at all. A token caller still has to name a
    // registered, live, non-worker/headless session; the route enforces
    // that, not this schema.
    session: singleLine(z.string().min(1).max(64)).optional(),
    path: absPathSchema.optional(),
    item: itemIdSchema.optional(),
  })
  .refine((v) => Boolean(v.path) !== Boolean(v.item), {
    message: 'give either <path> or <item id>, not both',
  });

export const overrideSchema = z.object({
  // Optional, same reasoning as `adoptSchema.session` above.
  session: singleLine(z.string().min(1).max(64)).optional(),
  path: absPathSchema,
  /** Mandatory: an override without a reason is an accident, not a decision. */
  reason: singleLine(z.string().min(3).max(400)),
});

export const nudgeQuerySchema = z.object({
  session: singleLine(z.string().min(1).max(64)),
  threshold: z.coerce.number().int().min(1).max(10_000).default(20),
  /** The shell hook knows the wall clock; the hub does not guess it. */
  late: z.enum(['1', 'true', '0', 'false']).optional(),
  format: z.enum(['json', 'line', 'text']).optional(),
});

/* ---------- F3: headless triage, grooming, release notes ---------- */

export const intakeProcessSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  /** `process-pending` cap so one run cannot be handed 500 records. */
  limit: z.number().int().min(1).max(20).default(5),
  /**
   * After triage, start a worker on the created `owner: agent` P0/P1 items.
   * Same as `action: 'triage_and_run'` at creation, just triggered later —
   * and unlike it, it completes within this very request.
   */
  run: z.boolean().default(false),
});

export const groomSchema = z.object({
  session: singleLine(z.string().max(64)).nullable().optional(),
  repo: slugSchema.nullable().optional(),
});

/** A git rev the CLI may pass through. No `..`, no spaces, no option-looking
 *  values — this string becomes an argv entry for `git log`. */
export const gitRevSchema = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[A-Za-z0-9._\/-]+$/, 'rev may contain only [A-Za-z0-9._/-]')
  .refine((v) => !v.startsWith('-') && !v.includes('..'), {
    message: 'rev must not start with "-" or contain ".."',
  });

export const releaseNotesQuerySchema = z.object({
  from: gitRevSchema.optional(),
  to: gitRevSchema.default('HEAD'),
  format: z.enum(['json', 'markdown']).optional(),
});

/* ---------- User replies from the web UI ---------- */

/**
 * An empty `text` is valid and means "do what the Recommendation section says" —
 * the one-click approval in the UI. That is why this is `.max()` without
 * `.min(1)`, and why it is NOT `singleLine`: a reply is prose and may be
 * multi-line. It is sanitised at the sink (comment body, inbox line) instead.
 */
export const replyCreateSchema = z.object({
  text: z.string().max(4000).default(''),
  mode: z.enum(['auto', 'session', 'worker']).default('auto'),
});

/* ---------- Edit + dups ---------- */

export const dupsQuerySchema = z.object({
  // `findDuplicatePairs` is O(n²) over every open item of a repo — a
  // cross-repo scan (the old default when `repo` was omitted) multiplies
  // that by however many repos are registered. One repo, chosen by the
  // caller, bounds the comparison to what a single `ledger dups` run means.
  repo: repoListSchema,
  threshold: z.coerce.number().min(0.1).max(1).optional(),
  format: z.enum(['json', 'line']).optional(),
});

/** Read-only "have we already got this?" check. Writes nothing. */
export const checkQuerySchema = z.object({
  title: singleLine(z.string().min(1).max(400)),
  repo: repoListSchema.optional(),
  threshold: z.coerce.number().min(0.1).max(1).optional(),
  format: z.enum(['json', 'line']).optional(),
});
