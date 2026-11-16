/** Sync ingress validation (docs/multi-device-spec.md §7.3, §4.3; threats T13-T15).
 *
 *  Pure function over the changes an incoming commit range would bring into the
 *  ledger tree. No git, no network, no filesystem: the caller (F3b) lists the
 *  diff and hands the blobs in.
 *
 *  Threat model:
 *   - Actor: a compromised remote or a rogue/buggy peer device.
 *   - Protected: the local filesystem (checkout writes), the hub (no code runs
 *     from synced content), agents (secrets, prompt-injection carriers are
 *     handled elsewhere), the id space.
 *   - Failure modes: path traversal / Windows aliasing, symlinks and submodules,
 *     exec bits, `.gitattributes` drivers, oversized blobs, secrets, malformed
 *     frontmatter, hostile claim globs, case-folding collisions.
 *   - Stance: an allowlist; everything not named is REJECTED (fail-closed),
 *     a validator that throws rejects the file. Output never contains content,
 *     only the path (sanitised) and the rule that fired.
 */

import { parse as parseYaml } from 'yaml';
import {
  ITEM_ID_RE,
  RESERVED_SYNC_WORKER,
  isSnowflake,
  parseDevicesYaml,
  parseSnowflake,
  parseIntake,
  parseItem,
  reposSyncedFileSchema,
  scanSecrets,
} from '@agent-ledger/shared';
import { LEDGER_FORMAT, isAbsoluteLike, parseCounterFile } from '../ledger/device.ts';

export const MAX_FILE_BYTES = 256 * 1024;
export const MAX_PUSH_BYTES = 5 * 1024 * 1024;
/** DoS cap on the number of changed paths in one push. */
export const MAX_PUSH_CHANGES = 5000;
export const MAX_PATH_CHARS = 512;
export const MAX_CLAIM_GLOBS = 32;
export const MAX_CLAIM_GLOB_CHARS = 256;
const MAX_SLUG_CHARS = 100;

/** One path of the incoming diff. `mode`/`type` are git's (`100644`, `blob`). */
export interface IncomingChange {
  path: string;
  mode: string;
  type: string;
  size: number;
  /** Blob bytes. Required for every non-deleted change (no content = nothing to
   *  verify = rejected). */
  content?: string | Uint8Array;
  /** The diff removes this path (mode/type/content are then ignored). */
  deleted?: boolean;
}

export type IngressRule =
  | 'malformed'
  | 'duplicate'
  | 'path-invalid'
  | 'windows-name'
  | 'git-name'
  | 'symlink'
  | 'submodule'
  | 'exec'
  | 'mode'
  | 'type'
  | 'layout'
  | 'delete'
  | 'delete-protected'
  | 'hub-path'
  | 'size'
  | 'push-size'
  | 'push-count'
  | 'content-missing'
  | 'encoding'
  | 'case-collision'
  | 'secret'
  | 'schema'
  | 'frontmatter'
  | 'claim-glob'
  | 'gitattributes'
  | 'gitattributes-driver'
  | 'gitignore'
  | 'format'
  | 'reserved-worker';

export interface IngressRejection {
  path: string;
  rule: IngressRule;
}

export interface IngressResult {
  accepted: string[];
  rejected: IngressRejection[];
}

export interface IngressOpts {
  maxFileBytes?: number;
  maxPushBytes?: number;
  maxChanges?: number;
  /** Highest `ledger.format` this hub supports. */
  maxFormat?: number;
  /** `ledger.format` of the local tree. An incoming value below it is a downgrade
   *  (rule `format`); absent = no monotonic check (only `1..maxFormat`). */
  baseFormat?: number;
  /** Paths already in the local tree: a change that differs from one only by
   *  case is a collision on case-insensitive filesystems. */
  existingPaths?: Iterable<string>;
  /** Secret scanner; default = the shared hub scanner. Must return the findings
   *  (rule names only). A throw counts as a hit (fail-closed). */
  scan?: (text: string) => readonly unknown[];
}

/* ---------------- path rules ---------------- */

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const WIN_RESERVED_RE = /^(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[0-9\xb9\xb2\xb3]|lpt[0-9\xb9\xb2\xb3])$/i;
const WIN_BAD_CHARS_RE = /[<>:"|?*\\]/;
const SHORT_NAME_RE = /~[0-9]/;
const DRIVE_RE = /^[A-Za-z]:/;
const RESERVED_SLUGS = new Set(['counters', 'intake']);

/** `.hub/` is the hub's private state (token, device key, sync state): never part of a
 *  synced tree. Case-insensitive, and tolerant of the trailing dot/space aliases Windows
 *  and macOS fold onto the same directory, in ANY segment (not only the first). */
function isHubPath(path: string): boolean {
  for (const seg of path.split('/')) {
    if (seg.replace(/[. ]+$/, '').toLowerCase() === '.hub') return true;
  }
  return false;
}

/** `null` = fine. Names the first structural problem of a repo-relative path. */
function pathProblem(path: string): IngressRule | null {
  if (path.length === 0 || path.length > MAX_PATH_CHARS) return 'path-invalid';
  if (CONTROL_RE.test(path)) return 'path-invalid';
  if (path.startsWith('/') || path.endsWith('/') || path.includes('\\')) return 'path-invalid';
  if (DRIVE_RE.test(path)) return 'path-invalid';
  const segments = path.split('/');
  for (const seg of segments) {
    if (seg === '' || seg === '.' || seg === '..') return 'path-invalid';
  }
  for (const seg of segments) {
    if (windowsNameProblem(seg)) return 'windows-name';
  }
  for (const [i, seg] of segments.entries()) {
    if (/^\.git/i.test(seg)) {
      const rootAllowed = i === 0 && segments.length === 1 && (seg === '.gitignore' || seg === '.gitattributes');
      if (!rootAllowed) return 'git-name';
    }
  }
  return null;
}

/** A path SEGMENT that Windows (or its 8.3 / stream syntax) would alias, reserve or drop. */
export function windowsNameProblem(seg: string): boolean {
  if (WIN_BAD_CHARS_RE.test(seg)) return true; // `:` also covers NTFS streams
  if (seg.endsWith('.') || seg.endsWith(' ')) return true;
  if (SHORT_NAME_RE.test(seg)) return true; // `PROGRA~1` style aliases
  const stem = (seg.split('.')[0] ?? '').replace(/ +$/, '');
  return WIN_RESERVED_RE.test(stem);
}

/* ---------------- claim globs (§4.3) ---------------- */

/** `null` = every glob is acceptable, else the reason class (never the glob). */
export function claimGlobProblem(globs: readonly string[]): 'count' | 'glob' | null {
  if (!Array.isArray(globs) || globs.length > MAX_CLAIM_GLOBS) return 'count';
  for (const g of globs) {
    if (typeof g !== 'string' || g.length === 0 || g.length > MAX_CLAIM_GLOB_CHARS) return 'glob';
    if (CONTROL_RE.test(g)) return 'glob';
    if (g.startsWith('/') || g.includes('\\') || DRIVE_RE.test(g)) return 'glob';
    if (g.includes('..')) return 'glob';
  }
  return null;
}

/* ---------------- layout allowlist ---------------- */

type Kind =
  | 'repos'
  | 'devices'
  | 'counters'
  | 'format'
  | 'gitignore'
  | 'gitattributes'
  | 'context'
  | 'decisions'
  | 'item'
  | 'journal'
  | 'intake';

interface Classified {
  kind: Kind;
  slug?: string;
  id?: string;
}

const SLUG_RE = /^[a-z0-9-]+$/;
const DEVICE_COUNTER_RE = /^counters\/(d_[a-z2-7]{10})\.yml$/;
const JOURNAL_RE = /^([a-z0-9-]+)\/journal\/\d{4}-(?:0[1-9]|1[0-2])\.md$/;
const ITEM_FILE_RE = /^([a-z0-9-]+)\/items\/([A-Z]{2,4}-[A-HJ-NP-Z]?[1-9][0-9]*)\.md$/;
const INTAKE_RE = /^intake\/\d{4}-(?:0[1-9]|1[0-2])\/([1-9][0-9]{0,19})\.md$/;
const SLUG_FILE_RE = /^([a-z0-9-]+)\/(CONTEXT|DECISIONS)\.md$/;

function slugOk(slug: string): boolean {
  return SLUG_RE.test(slug) && slug.length <= MAX_SLUG_CHARS && !RESERVED_SLUGS.has(slug);
}

function classify(path: string): Classified | null {
  switch (path) {
    case 'repos.yml':
      return { kind: 'repos' };
    case 'devices.yml':
      return { kind: 'devices' };
    case 'ledger.format':
      return { kind: 'format' };
    case '.gitignore':
      return { kind: 'gitignore' };
    case '.gitattributes':
      return { kind: 'gitattributes' };
    default:
  }
  if (DEVICE_COUNTER_RE.test(path)) return { kind: 'counters' };
  let m = ITEM_FILE_RE.exec(path);
  if (m && slugOk(m[1] as string) && ITEM_ID_RE.test(m[2] as string)) {
    return { kind: 'item', slug: m[1] as string, id: m[2] as string };
  }
  m = SLUG_FILE_RE.exec(path);
  if (m && slugOk(m[1] as string)) {
    return { kind: m[2] === 'CONTEXT' ? 'context' : 'decisions', slug: m[1] as string };
  }
  m = JOURNAL_RE.exec(path);
  if (m && slugOk(m[1] as string)) return { kind: 'journal', slug: m[1] as string };
  m = INTAKE_RE.exec(path);
  if (m && isSnowflake(m[1])) return { kind: 'intake', id: m[1] as string };
  return null;
}

/* ---------------- content rules ---------------- */

const GITATTRIBUTES_EXACT = '* text eol=lf\n';
/** Pinned (F3b invariant 10): what a fresh ledger writes (`GITIGNORE` in ledger.ts).
 *  A peer that drops the `.hub/` line would get `.hub/device/key` staged. */
const GITIGNORE_EXACT = '.hub/\n*.tmp\n';
const DRIVER_ATTR_RE = /(?:^|\s)[-!]?(?:merge|filter|diff)(?:=|\s|$)/i;

function decode(content: string | Uint8Array): string | null {
  if (typeof content === 'string') return content.includes('\u0000') ? null : content;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(content);
    return text.includes('\u0000') ? null : text;
  } catch {
    return null;
  }
}

function reposProblem(text: string): boolean {
  let raw: unknown;
  try {
    raw = parseYaml(text, { maxAliasCount: 0 });
  } catch {
    return true;
  }
  const res = reposSyncedFileSchema.safeParse(raw ?? {});
  if (!res.success) return true;
  for (const e of Object.values(res.data)) {
    // Format 2 never emits these; their presence is a peer smuggling a local path
    // or a counter into the portable file.
    if (e.path !== undefined || e.next !== undefined || e.graphify !== undefined) return true;
    for (const d of e.docs ?? []) {
      if (isAbsoluteLike(d) || d.includes('\\') || d.split('/').includes('..') || CONTROL_RE.test(d)) return true;
    }
  }
  return false;
}

/** Content verdict for one live file. `null` = fine. */
function contentProblem(
  cls: Classified,
  path: string,
  text: string,
  maxFormat: number,
  baseFormat: number | undefined,
  scan: (text: string) => readonly unknown[],
): IngressRule | null {
  // Secrets first: whatever else is wrong, a secret hit is the headline.
  // devices.yml carries PUBLIC keys, which look like high-entropy tokens: validate
  // the file first, then scan it with the (structurally verified) keys removed.
  let scanText = text;
  if (cls.kind === 'devices') {
    try {
      const file = parseDevicesYaml(text);
      for (const d of file.devices) scanText = scanText.split(d.pubkey).join('<pubkey>');
    } catch {
      return 'schema';
    }
  }
  try {
    if (scan(scanText).length > 0) return 'secret';
  } catch {
    return 'secret';
  }
  switch (cls.kind) {
    case 'repos':
      return reposProblem(text) ? 'schema' : null;
    case 'devices':
      return null; // validated above
    case 'counters':
      try {
        parseCounterFile(text);
        return null;
      } catch {
        return 'schema';
      }
    case 'format': {
      const m = /^([0-9]{1,6})\n$/.exec(text);
      if (!m) return 'format';
      const n = Number(m[1]);
      if (baseFormat !== undefined && n < baseFormat) return 'format'; // downgrade
      return n >= 1 && n <= maxFormat ? null : 'format';
    }
    case 'gitignore':
      return text === GITIGNORE_EXACT ? null : 'gitignore';
    case 'gitattributes':
      if (text === GITATTRIBUTES_EXACT) return null;
      return text.split(/\r?\n/).some((l) => DRIVER_ATTR_RE.test(l)) ? 'gitattributes-driver' : 'gitattributes';
    case 'item': {
      let parsed;
      try {
        parsed = parseItem(text, path);
      } catch {
        return 'frontmatter';
      }
      const fm = parsed.item.fm;
      if (fm.id !== cls.id || fm.repo !== cls.slug) return 'frontmatter';
      return claimGlobProblem(fm.paths) === null ? null : 'claim-glob';
    }
    case 'intake':
      try {
        const rec = parseIntake(text, path).rec;
        return rec.id === cls.id ? null : 'frontmatter';
      } catch {
        return 'frontmatter';
      }
    default:
      // CONTEXT.md, DECISIONS.md, journal: free text, scanned above.
      return null;
  }
}

/* ---------------- entry point ---------------- */

/** Display form of an attacker-chosen path: capped, control characters removed. */
function shown(path: unknown): string {
  const s = typeof path === 'string' ? path : '(invalid)';
  let flat = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    const hidden =
      cp < 0x20 ||
      (cp >= 0x7f && cp <= 0x9f) ||
      (cp >= 0x200b && cp <= 0x200f) ||
      (cp >= 0x2028 && cp <= 0x202e) ||
      (cp >= 0x2060 && cp <= 0x2064) ||
      cp === 0xfeff;
    flat += hidden ? '?' : ch;
  }
  return flat.length > 200 ? flat.slice(0, 200) + String.fromCharCode(0x2026) : flat;
}

function isChange(c: unknown): c is IncomingChange {
  if (typeof c !== 'object' || c === null) return false;
  const o = c as Record<string, unknown>;
  return (
    typeof o.path === 'string' &&
    typeof o.mode === 'string' &&
    typeof o.type === 'string' &&
    typeof o.size === 'number' &&
    (o.deleted === undefined || typeof o.deleted === 'boolean') &&
    (o.content === undefined || typeof o.content === 'string' || o.content instanceof Uint8Array)
  );
}

function modeProblem(c: IncomingChange): IngressRule | null {
  if (c.type === 'commit' || c.mode === '160000') return 'submodule';
  if (c.mode === '120000') return 'symlink';
  if (!/^[0-7]{6}$/.test(c.mode)) return 'mode';
  if ((Number.parseInt(c.mode, 8) & 0o111) !== 0) return 'exec';
  if (c.mode !== '100644') return 'mode';
  if (c.type !== 'blob') return 'type';
  return null;
}

/**
 * Validate the changes of an incoming commit range. Returns the accepted paths and
 * the rejected ones with the rule that fired. Callers treat ANY rejection as
 * "quarantine the push" (F3b): a partial merge of a hostile range is not safe.
 * Deterministic, order-independent for collision rules, never throws.
 */
export function validateIncoming(changes: readonly unknown[], opts: IngressOpts = {}): IngressResult {
  const maxFile = opts.maxFileBytes ?? MAX_FILE_BYTES;
  const maxPush = opts.maxPushBytes ?? MAX_PUSH_BYTES;
  const maxChanges = opts.maxChanges ?? MAX_PUSH_CHANGES;
  const maxFormat = opts.maxFormat ?? LEDGER_FORMAT;
  const baseFormat =
    typeof opts.baseFormat === 'number' && Number.isInteger(opts.baseFormat) ? opts.baseFormat : undefined;
  const scan = opts.scan ?? scanSecrets;

  if (!Array.isArray(changes)) return { accepted: [], rejected: [{ path: '(push)', rule: 'malformed' }] };
  if (changes.length > maxChanges) return { accepted: [], rejected: [{ path: '(push)', rule: 'push-count' }] };

  const rejected = new Map<string, IngressRule>(); // keyed by raw path (first rule wins)
  const reject = (path: string, rule: IngressRule): void => {
    if (!rejected.has(path)) rejected.set(path, rule);
  };
  const live: { change: IncomingChange; cls: Classified }[] = [];
  const seen = new Map<string, number>();
  let total = 0;
  let malformed = 0;

  for (const raw of changes) {
    if (!isChange(raw)) {
      malformed += 1;
      continue;
    }
    seen.set(raw.path, (seen.get(raw.path) ?? 0) + 1);
  }

  for (const raw of changes) {
    if (!isChange(raw)) continue;
    const c = raw;
    if ((seen.get(c.path) ?? 0) > 1) {
      reject(c.path, 'duplicate');
      continue;
    }
    if (isHubPath(c.path)) {
      reject(c.path, 'hub-path'); // before every other rule: the headline for any `.hub/**` change, delete or not
      continue;
    }
    const pp = pathProblem(c.path);
    if (pp !== null) {
      reject(c.path, pp);
      continue;
    }
    const cls = classify(c.path);
    if (c.deleted === true) {
      if (cls === null) reject(c.path, 'layout');
      else if (cls.kind === 'item') reject(c.path, 'delete'); // invariant 4: soft, caller keeps the item
      // Every other file is load-bearing: deleting `devices.yml` resets the trust root
      // (base === null), `ledger.format`/pins/counters/repos/journal/context have no
      // legitimate delete either. Hard rejection, distinct from the soft item rule.
      else reject(c.path, 'delete-protected');
      continue;
    }
    const mp = modeProblem(c);
    if (mp !== null) {
      reject(c.path, mp);
      continue;
    }
    if (cls === null) {
      reject(c.path, 'layout');
      continue;
    }
    let text: string | null = null;
    let size = c.size;
    if (c.content === undefined) {
      reject(c.path, 'content-missing');
      continue;
    }
    size = typeof c.content === 'string' ? Buffer.byteLength(c.content, 'utf8') : c.content.byteLength;
    if (!Number.isInteger(c.size) || c.size < 0 || c.size !== size) {
      reject(c.path, 'size');
      continue;
    }
    total += size;
    if (size > maxFile) {
      reject(c.path, 'size');
      continue;
    }
    text = decode(c.content);
    if (text === null) {
      reject(c.path, 'encoding');
      continue;
    }
    if (cls.kind === 'intake' && parseSnowflake(cls.id as string).worker === RESERVED_SYNC_WORKER) {
      reject(c.path, 'reserved-worker'); // worker 1023 = hub-synthesised records only
      continue;
    }
    const cp = contentProblem(cls, c.path, text, maxFormat, baseFormat, scan);
    if (cp !== null) {
      reject(c.path, cp);
      continue;
    }
    live.push({ change: c, cls });
  }

  if (total > maxPush) return { accepted: [], rejected: [{ path: '(push)', rule: 'push-size' }] };

  // Case-insensitive collisions (macOS/Windows checkouts): file names AND every
  // directory prefix. All spellings in a group are rejected, so the verdict does
  // not depend on diff order.
  const spellings = new Map<string, Set<string>>();
  const note = (full: string): void => {
    const segs = full.split('/');
    for (let i = 1; i <= segs.length; i += 1) {
      const prefix = segs.slice(0, i).join('/');
      const key = prefix.toLowerCase();
      const set = spellings.get(key) ?? new Set<string>();
      set.add(prefix);
      spellings.set(key, set);
    }
  };
  for (const e of opts.existingPaths ?? []) if (typeof e === 'string') note(e);
  for (const { change } of live) note(change.path);
  const survivors: string[] = [];
  for (const { change } of live) {
    const segs = change.path.split('/');
    let clash = false;
    for (let i = 1; i <= segs.length && !clash; i += 1) {
      const prefix = segs.slice(0, i).join('/');
      clash = (spellings.get(prefix.toLowerCase())?.size ?? 0) > 1;
    }
    if (clash) reject(change.path, 'case-collision');
    else survivors.push(change.path);
  }

  const out: IngressRejection[] = [];
  for (const [path, rule] of rejected) out.push({ path: shown(path), rule });
  for (let i = 0; i < malformed; i += 1) out.push({ path: '(invalid)', rule: 'malformed' });
  return { accepted: survivors, rejected: out };
}
