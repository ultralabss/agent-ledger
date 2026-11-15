/**
 * Pure SDDL parser + trust evaluator (no I/O, no platform access).
 *
 * Threat model: another local account (or a planted ACE) gives itself write/read access
 * to a private path, or to a directory above it, so it can swap or read what we trust.
 * Windows reports the descriptor as SDDL; SDDL is SID-based, so the verdict does not
 * depend on the OS language (icacls text does).
 *
 * Fail-closed everywhere: an SDDL we cannot fully parse, a missing/NULL DACL, and any ACE
 * type other than plain allow/deny (conditional, callback, object ACEs) are refusals.
 * DENY ACEs are ignored on purpose: we never subtract them from an allow, so a deny can
 * not "rescue" a path that has a dangerous allow.
 */

export class SddlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SddlError';
  }
}

// ---- access masks ---------------------------------------------------------------------

export const GENERIC_ALL = 0x10000000;
export const GENERIC_WRITE = 0x40000000;
export const GENERIC_READ = 0x80000000;
export const GENERIC_EXECUTE = 0x20000000;
/** DELETE | WRITE_DAC | WRITE_OWNER | WRITE_ATTRIBUTES | DELETE_CHILD | WRITE_EA | APPEND | WRITE_DATA. */
export const WRITE_MASK = 0x000d0156;
/** FILE_READ_DATA / FILE_LIST_DIRECTORY. READ_CONTROL, traverse and attributes are not "read". */
export const READ_MASK = 0x00000001;
const DELETE = 0x00010000;
const WRITE_DAC = 0x00040000;
const WRITE_OWNER = 0x00080000;
const DELETE_CHILD = 0x00000040;
/**
 * What lets a principal replace, rename or re-ACL a directory that we sit under.
 * DELETE is in the set on purpose (the spec lists DELETE_CHILD/WRITE_DAC/WRITE_OWNER/GA/GW
 * only): renaming a directory needs DELETE on it, and the stock "Modify" grant
 * (0x1301bf, e.g. Authenticated Users on a child of C:\) holds DELETE but none of the others.
 */
export const ANCESTOR_MASK = DELETE_CHILD | WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_ALL | GENERIC_WRITE;

const RIGHT_TOKENS: Readonly<Record<string, number>> = {
  GA: GENERIC_ALL,
  GR: GENERIC_READ,
  GW: GENERIC_WRITE,
  GX: GENERIC_EXECUTE,
  RC: 0x00020000,
  SD: DELETE,
  WD: WRITE_DAC,
  WO: WRITE_OWNER,
  CC: 0x1,
  DC: 0x2,
  LC: 0x4,
  SW: 0x8,
  RP: 0x10,
  WP: 0x20,
  DT: 0x40,
  LO: 0x80,
  CR: 0x100,
  FA: 0x001f01ff,
  FR: 0x00120089,
  FW: 0x00120116,
  FX: 0x001200a0,
  KA: 0x000f003f,
  KR: 0x00020019,
  KW: 0x00020006,
  KX: 0x00020019,
};
/** Tokens that mean "write" even where their numeric value would not (directory-service rights). */
const WRITE_TOKENS = new Set(['FA', 'FW', 'GA', 'GW', 'WD', 'WO', 'SD', 'DC', 'CC', 'WP', 'SW', 'KA', 'KW']);

// ---- SIDs -----------------------------------------------------------------------------

export const SID_SYSTEM = 'S-1-5-18';
export const SID_ADMINISTRATORS = 'S-1-5-32-544';
export const SID_OWNER_RIGHTS = 'S-1-3-4';
export const SID_CREATOR_OWNER = 'S-1-3-0';
export const SID_TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';

const ALIASES: Readonly<Record<string, string>> = {
  AN: 'S-1-5-7',
  AO: 'S-1-5-32-548',
  AU: 'S-1-5-11',
  BA: SID_ADMINISTRATORS,
  BG: 'S-1-5-32-546',
  BO: 'S-1-5-32-551',
  BU: 'S-1-5-32-545',
  CD: 'S-1-5-32-574',
  CG: 'S-1-3-1',
  CO: SID_CREATOR_OWNER,
  CY: 'S-1-5-32-569',
  ED: 'S-1-5-9',
  HI: 'S-1-16-12288',
  IU: 'S-1-5-4',
  LS: 'S-1-5-19',
  LW: 'S-1-16-4096',
  ME: 'S-1-16-8192',
  MU: 'S-1-5-32-558',
  NO: 'S-1-5-32-556',
  NS: 'S-1-5-20',
  NU: 'S-1-5-2',
  OW: SID_OWNER_RIGHTS,
  PO: 'S-1-5-32-550',
  PS: 'S-1-5-10',
  PU: 'S-1-5-32-547',
  RC: 'S-1-5-12',
  RD: 'S-1-5-32-555',
  RE: 'S-1-5-32-552',
  RU: 'S-1-5-32-554',
  SI: 'S-1-16-16384',
  SO: 'S-1-5-32-549',
  SU: 'S-1-5-6',
  SY: SID_SYSTEM,
  WD: 'S-1-1-0',
  WR: 'S-1-5-33',
  AC: 'S-1-15-2-1',
};

const SID_RE = /^S-1-\d+(?:-\d+)+$/i;
const ALIAS_RE = /^[A-Z]{2}$/;

/** SID string or two-letter alias to a canonical upper-case SID. Unknown aliases stay `alias:XX`
 *  (never equal to a trusted SID). */
export function normalizeSid(raw: string): string {
  const t = raw.trim().toUpperCase();
  if (SID_RE.test(t)) return t;
  if (ALIAS_RE.test(t)) return ALIASES[t] ?? `alias:${t}`;
  throw new SddlError(`bad SID "${raw.slice(0, 60)}"`);
}

// ---- parser ---------------------------------------------------------------------------

export interface ParsedAce {
  /** `A` / `D` / anything else as written (OA, XA, ...). */
  type: string;
  flags: string[];
  /** Unsigned 32-bit mask. */
  rights: number;
  /** Rights written as 2-letter tokens (empty when numeric). */
  tokens: string[];
  /** Canonical SID. */
  sid: string;
  inheritOnly: boolean;
  /** OI or CI present: the ACE propagates to children. */
  inheritable: boolean;
  inherited: boolean;
}

export interface ParsedSddl {
  owner: string | null;
  group: string | null;
  dacl: {
    /** False when the descriptor has no `D:` section or says NO_ACCESS_CONTROL (a NULL DACL = everyone). */
    present: boolean;
    protected: boolean;
    aces: ParsedAce[];
  };
}

const ACE_FLAGS = new Set(['OI', 'CI', 'IO', 'NP', 'ID', 'SA', 'FA', 'TP', 'CR']);

function parseRights(raw: string): { mask: number; tokens: string[] } {
  if (/^0x[0-9a-f]{1,8}$/i.test(raw)) return { mask: Number.parseInt(raw, 16) >>> 0, tokens: [] };
  if (/^\d{1,10}$/.test(raw)) {
    const n = Number(raw);
    if (n > 0xffffffff) throw new SddlError('rights out of range');
    return { mask: n >>> 0, tokens: [] };
  }
  if (raw.length === 0 || raw.length % 2 !== 0) throw new SddlError(`bad rights "${raw.slice(0, 40)}"`);
  let mask = 0;
  const tokens: string[] = [];
  for (let i = 0; i < raw.length; i += 2) {
    const tok = raw.slice(i, i + 2).toUpperCase();
    const v = RIGHT_TOKENS[tok];
    if (v === undefined) throw new SddlError(`unknown rights token ${tok}`);
    mask |= v;
    tokens.push(tok);
  }
  return { mask: mask >>> 0, tokens };
}

function parseAce(body: string): ParsedAce {
  const f = body.split(';');
  if (f.length < 6) throw new SddlError('ACE has fewer than 6 fields');
  const type = (f[0] ?? '').toUpperCase();
  const flagStr = (f[1] ?? '').toUpperCase();
  if (flagStr.length % 2 !== 0) throw new SddlError('bad ACE flags');
  const flags: string[] = [];
  for (let i = 0; i < flagStr.length; i += 2) {
    const fl = flagStr.slice(i, i + 2);
    if (!ACE_FLAGS.has(fl)) throw new SddlError(`unknown ACE flag ${fl}`);
    flags.push(fl);
  }
  // Only plain allow/deny are understood. Everything else is kept as written so the
  // evaluator can refuse it by name instead of the parser guessing.
  const plain = type === 'A' || type === 'D';
  if (plain && (f.length > 6 || (f[3] ?? '') !== '' || (f[4] ?? '') !== '')) {
    throw new SddlError('allow/deny ACE carries object or condition fields');
  }
  const { mask, tokens } = plain ? parseRights(f[2] ?? '') : { mask: 0, tokens: [] as string[] };
  const sid = plain ? normalizeSid(f[5] ?? '') : 'unparsed';
  return {
    type,
    flags,
    rights: mask,
    tokens,
    sid,
    inheritOnly: flags.includes('IO'),
    inheritable: flags.includes('OI') || flags.includes('CI'),
    inherited: flags.includes('ID'),
  };
}

function splitAces(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === '(') {
      if (depth === 0) start = i + 1;
      depth += 1;
    } else if (ch === ')') {
      if (depth === 0) throw new SddlError('unbalanced ")"');
      depth -= 1;
      if (depth === 0) out.push(text.slice(start, i));
    } else if (depth === 0) {
      throw new SddlError('text between ACEs');
    }
  }
  if (depth !== 0) throw new SddlError('unbalanced "("');
  return out;
}

function parseDaclFlags(raw: string): { nullDacl: boolean; protectedDacl: boolean } {
  if (raw === 'NO_ACCESS_CONTROL') return { nullDacl: true, protectedDacl: false };
  let rest = raw.toUpperCase();
  let prot = false;
  while (rest.length > 0) {
    if (rest.startsWith('P')) {
      prot = true;
      rest = rest.slice(1);
    } else if (rest.startsWith('AR') || rest.startsWith('AI')) {
      rest = rest.slice(2);
    } else {
      throw new SddlError(`bad DACL flags "${raw.slice(0, 20)}"`);
    }
  }
  return { nullDacl: false, protectedDacl: prot };
}

/** Parse `O:..G:..D:..S:..`. Throws `SddlError` on anything unexpected. */
export function parseSddl(sddl: string): ParsedSddl {
  if (typeof sddl !== 'string' || sddl.length === 0 || sddl.length > 64 * 1024) {
    throw new SddlError('empty or oversized SDDL');
  }
  const s = sddl.trim();
  // Section markers are `X:` at parenthesis depth 0 (ACE bodies live at depth >= 1).
  const marks: { ch: string; at: number }[] = [];
  let depth = 0;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth < 0) throw new SddlError('unbalanced ")"');
    } else if (ch === ':' && depth === 0) {
      if (i === 0) throw new SddlError('stray ":"');
      marks.push({ ch: s[i - 1] ?? '', at: i });
    }
  }
  if (depth !== 0) throw new SddlError('unbalanced "("');
  if (marks.length === 0) throw new SddlError('no sections');
  const first = marks[0];
  if (first === undefined || first.at - 1 !== 0) throw new SddlError('text before first section');
  const sections = new Map<string, string>();
  marks.forEach((m, idx) => {
    if (!'OGDS'.includes(m.ch)) throw new SddlError(`unknown section ${m.ch}`);
    if (sections.has(m.ch)) throw new SddlError(`duplicate section ${m.ch}`);
    const next = marks[idx + 1];
    sections.set(m.ch, s.slice(m.at + 1, next === undefined ? s.length : next.at - 1));
  });

  const ownerRaw = sections.get('O');
  const groupRaw = sections.get('G');
  const daclRaw = sections.get('D');
  const owner = ownerRaw === undefined || ownerRaw === '' ? null : normalizeSid(ownerRaw);
  const group = groupRaw === undefined || groupRaw === '' ? null : normalizeSid(groupRaw);

  if (daclRaw === undefined) {
    return { owner, group, dacl: { present: false, protected: false, aces: [] } };
  }
  const paren = daclRaw.indexOf('(');
  const flagText = paren === -1 ? daclRaw : daclRaw.slice(0, paren);
  const aceText = paren === -1 ? '' : daclRaw.slice(paren);
  const fl = parseDaclFlags(flagText);
  const aces = splitAces(aceText).map(parseAce);
  return { owner, group, dacl: { present: !fl.nullDacl, protected: fl.protectedDacl, aces } };
}

// ---- evaluator ------------------------------------------------------------------------

export type SddlKind =
  /** A directory we own and keep private: protected DACL, nobody else reads or writes. */
  | 'private-dir'
  /** A non-secret file in a private dir: nobody else writes. */
  | 'private-file'
  /** A secret file (token): nobody else reads or writes. */
  | 'secret-file'
  /** A directory above a private path (existing, effective ACEs only). */
  | 'ancestor'
  /** The immediate parent of a directory we are about to create (inheritable ACEs count too). */
  | 'parent-of-new'
  /** A binary we execute. */
  | 'executable'
  /** A directory above an executable. */
  | 'exec-ancestor';

export interface SddlVerdict {
  ok: boolean;
  /** `OWNER` | `ACL` | `CHAIN` when `ok` is false. */
  code?: 'OWNER' | 'ACL' | 'CHAIN';
  reason?: string;
}

const OK: SddlVerdict = { ok: true };

function fail(code: 'OWNER' | 'ACL' | 'CHAIN', reason: string): SddlVerdict {
  return { ok: false, code, reason };
}

function isWrite(ace: ParsedAce): boolean {
  return (ace.rights & (WRITE_MASK | GENERIC_ALL | GENERIC_WRITE)) !== 0 || ace.tokens.some((t) => WRITE_TOKENS.has(t));
}

function isRead(ace: ParsedAce): boolean {
  return (ace.rights & (READ_MASK | GENERIC_READ | GENERIC_ALL)) !== 0;
}

/**
 * Decide whether the descriptor `sddl` is acceptable for `kind`, as principal `mySid`.
 * Never throws: an unparseable descriptor is a refusal.
 */
export function evaluateSddl(sddl: string, kind: SddlKind, ctx: { mySid: string }): SddlVerdict {
  let me: string;
  let p: ParsedSddl;
  try {
    me = normalizeSid(ctx.mySid);
    if (!SID_RE.test(me)) throw new SddlError('own SID is not a SID');
    p = parseSddl(sddl);
  } catch (err) {
    return fail(kind === 'ancestor' || kind === 'exec-ancestor' || kind === 'parent-of-new' ? 'CHAIN' : 'ACL', `unparseable security descriptor (${(err as Error).message})`);
  }
  const chain = kind === 'ancestor' || kind === 'exec-ancestor' || kind === 'parent-of-new';
  const exec = kind === 'executable' || kind === 'exec-ancestor';
  const denyCode = chain ? 'CHAIN' : 'ACL';

  // Trusted principals. TrustedInstaller is an OS service principal; it is accepted on
  // anything above a private path and on executables, never inside our private paths.
  const trusted = new Set([me, SID_SYSTEM, SID_ADMINISTRATORS, SID_OWNER_RIGHTS]);
  const trustedOwners = new Set([me, SID_SYSTEM, SID_ADMINISTRATORS]);
  if (chain || exec) {
    trusted.add(SID_TRUSTED_INSTALLER);
    trustedOwners.add(SID_TRUSTED_INSTALLER);
  }

  if (p.owner === null) return fail(chain || exec ? 'CHAIN' : 'OWNER', 'no owner in the security descriptor');
  const ownerOk = chain || exec ? trustedOwners.has(p.owner) : p.owner === me;
  if (!ownerOk) return fail(chain ? 'CHAIN' : 'OWNER', `owner is ${p.owner}`);

  if (!p.dacl.present) return fail(denyCode, 'NULL/absent DACL (everyone has full access)');
  if (kind === 'private-dir' && !p.dacl.protected) {
    return fail('ACL', 'DACL is not protected (inherits permissions from the parent)');
  }

  for (const ace of p.dacl.aces) {
    if (ace.type === 'D') continue; // ignored on purpose, see file header
    if (ace.type !== 'A') return fail(denyCode, `unsupported ACE type ${ace.type}`);
    const sidTrusted = trusted.has(ace.sid) || (ace.sid === SID_CREATOR_OWNER && ace.inheritOnly);
    if (sidTrusted) continue;
    const write = isWrite(ace);
    switch (kind) {
      case 'ancestor':
      case 'exec-ancestor':
        // Inherit-only ACEs do not apply to this directory itself.
        if (!ace.inheritOnly && (ace.rights & ANCESTOR_MASK) !== 0) {
          return fail('CHAIN', `${ace.sid} can modify/replace this directory`);
        }
        break;
      case 'parent-of-new':
        if (!ace.inheritOnly && (ace.rights & ANCESTOR_MASK) !== 0) {
          return fail('CHAIN', `${ace.sid} can modify/replace this directory`);
        }
        // What a child created here would inherit before we lock it down.
        if (ace.inheritable && write) return fail('CHAIN', `children would inherit write access for ${ace.sid}`);
        break;
      case 'executable':
      case 'private-file':
        if (write) return fail('ACL', `${ace.sid} has write access`);
        break;
      case 'private-dir':
      case 'secret-file':
        if (write) return fail('ACL', `${ace.sid} has write access`);
        if (isRead(ace)) return fail('ACL', `${ace.sid} has read access`);
        break;
    }
  }
  return OK;
}
