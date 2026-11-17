/** Commit signature verification done by the hub itself (docs/f3b-plan.md §1.1, §1.6; S16, S19; invariant 5).
 *
 *  Threat model:
 *   - Actor: a rogue peer or remote that crafts commits: unsigned, signed by a foreign/unknown key, signed for
 *     another namespace, tampered after signing, or with ambiguous headers (two `gpgsig`, header smuggling).
 *   - Protected: the identity of the signer. The signer is the KEY inside the signature, never the committer
 *     name/e-mail, never `git verify-commit` output, never an `allowed_signers` file maintained elsewhere.
 *   - Failure modes: verifying against a different key than the one that signed (key-mismatch confusion), a
 *     namespace swap (`agent-ledger-v1` signature accepted as a commit signature), a parser differential on the
 *     payload (the bytes verified differ from the bytes git hashed), a thrown error treated as "fine".
 *   - Stance: the raw commit bytes are split exactly the way git does it (payload = commit minus the `gpgsig`
 *     header and its continuation lines); the public key is parsed out of the SSHSIG blob and `ssh-keygen`
 *     verifies against an `allowed_signers` that contains exactly that one key, namespace `git`. The result says
 *     "this key signed these bytes"; whether the key is TRUSTED is the gate's decision. Malformed input is
 *     `valid: false`, never an exception (an environment failure is `verifier-error`, also invalid).
 */

import { parseEd25519Pub, verifyPayload } from '@agent-ledger/shared';
import { isSha } from './gitx.ts';
import { MAX_COMMIT_BYTES } from './objects.ts';

export type SigReason =
  | 'ok'
  | 'unsigned'
  | 'malformed-commit'
  | 'multiple-signatures'
  | 'malformed-armor'
  | 'unsupported-key'
  | 'namespace'
  | 'hash-algorithm'
  | 'bad-signature'
  | 'verifier-error';

export interface CommitHeaders {
  tree: string;
  parents: string[];
  authorLine: string;
  committerName: string;
  committerEmail: string;
  /** Unix seconds from the committer line (what the time binding uses). */
  committerTime: number;
  committerTz: string;
}

export interface SplitCommit {
  /** Exactly the bytes the signature covers (commit minus the `gpgsig` header block). */
  payload: Buffer;
  /** Armored SSH signature reassembled from the header, or `null` when there is none. */
  armor: string | null;
  signatureCount: number;
  /** `null` when the header block is not a well-formed commit. */
  headers: CommitHeaders | null;
}

const CONT = 0x20;
const LF = 0x0a;

/**
 * Split raw commit bytes into payload + `gpgsig`. Mirrors git: the header block ends at the first empty line;
 * a header line starting with a space continues the previous header; the `gpgsig` header and ITS continuation
 * lines are removed from the payload, everything else (other headers, `mergetag`, the message) is kept
 * byte-for-byte. Never throws.
 */
export function splitCommit(raw: Buffer): SplitCommit {
  const kept: Buffer[] = [];
  const sigLines: string[] = [];
  const keptHeaderLines: string[] = [];
  let signatureCount = 0;
  let inSig = false;
  let pos = 0;
  let sawBlank = false;
  while (pos < raw.length) {
    const nl = raw.indexOf(LF, pos);
    if (nl < 0) break; // header line without LF: no blank separator follows
    const line = raw.subarray(pos, nl);
    if (line.length === 0) {
      kept.push(raw.subarray(pos)); // blank line + message, unchanged
      sawBlank = true;
      break;
    }
    if (line[0] === CONT) {
      if (inSig) sigLines.push(line.subarray(1).toString('latin1'));
      else {
        kept.push(raw.subarray(pos, nl + 1));
        keptHeaderLines.push(line.toString('latin1'));
      }
    } else {
      const sp = line.indexOf(0x20);
      const name = (sp < 0 ? line : line.subarray(0, sp)).toString('latin1');
      if (name === 'gpgsig') {
        signatureCount++;
        inSig = true;
        if (signatureCount === 1) sigLines.push(sp < 0 ? '' : line.subarray(sp + 1).toString('latin1'));
      } else {
        inSig = false;
        kept.push(raw.subarray(pos, nl + 1));
        keptHeaderLines.push(line.toString('latin1'));
      }
    }
    pos = nl + 1;
  }
  const payload = Buffer.concat(kept);
  const armor = signatureCount === 0 ? null : `${sigLines.join('\n')}\n`;
  return { payload, armor, signatureCount, headers: sawBlank ? parseHeaders(keptHeaderLines) : null };
}

const IDENT_RE = /^(.*) <([^<>\n]*)> (\d{1,12}) ([+-]\d{4})$/;

function parseHeaders(lines: readonly string[]): CommitHeaders | null {
  let tree: string | null = null;
  const parents: string[] = [];
  let author: string | null = null;
  let committer: string | null = null;
  let order = 0; // tree < parent* < author < committer
  for (const line of lines) {
    if (line.startsWith(' ')) continue; // continuation of mergetag etc.
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const name = line.slice(0, sp);
    const value = line.slice(sp + 1);
    if (name === 'tree') {
      if (tree !== null || order !== 0 || !isSha(value)) return null;
      tree = value;
      order = 1;
    } else if (name === 'parent') {
      if (order < 1 || order > 1 || !isSha(value)) return null;
      parents.push(value);
    } else if (name === 'author') {
      if (author !== null || order < 1) return null;
      author = value;
      order = 2;
    } else if (name === 'committer') {
      if (committer !== null || order < 2) return null;
      committer = value;
      order = 3;
    }
  }
  if (tree === null || author === null || committer === null) return null;
  const m = IDENT_RE.exec(committer);
  if (m === null) return null;
  const time = Number(m[3]);
  if (!Number.isSafeInteger(time)) return null;
  return {
    tree,
    parents,
    authorLine: author,
    committerName: m[1] as string,
    committerEmail: m[2] as string,
    committerTime: time,
    committerTz: m[4] as string,
  };
}

/* ---------------- SSHSIG armor (PROTOCOL.sshsig) ---------------- */

export interface SshSigInfo {
  /** Canonical `ssh-ed25519 <base64>` of the key that signed. */
  pubkeyLine: string;
  namespace: string;
  hashAlgorithm: string;
}

const ARMOR_RE = /^-----BEGIN SSH SIGNATURE-----\n([A-Za-z0-9+/=\n]+)-----END SSH SIGNATURE-----\n?$/;
const MAX_ARMOR_CHARS = 4096;

class Reader {
  private pos = 0;
  private readonly buf: Buffer;
  constructor(buf: Buffer) {
    this.buf = buf;
  }
  take(n: number): Buffer | null {
    if (n < 0 || this.pos + n > this.buf.length) return null;
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  u32(): number | null {
    const b = this.take(4);
    return b === null ? null : b.readUInt32BE(0);
  }
  string(): Buffer | null {
    const n = this.u32();
    return n === null ? null : this.take(n);
  }
  get done(): boolean {
    return this.pos === this.buf.length;
  }
}

/** Parse the public key, namespace and hash algorithm out of an armored SSH signature. Strict; never throws. */
export function parseSshSignature(armor: string): SshSigInfo | { error: 'malformed-armor' | 'unsupported-key' } {
  if (typeof armor !== 'string' || armor.length > MAX_ARMOR_CHARS) return { error: 'malformed-armor' };
  const m = ARMOR_RE.exec(armor);
  if (m === null) return { error: 'malformed-armor' };
  const b64 = (m[1] as string).replace(/\n/g, '');
  if (b64 === '' || b64.length % 4 !== 0) return { error: 'malformed-armor' };
  const blob = Buffer.from(b64, 'base64');
  if (blob.toString('base64') !== b64) return { error: 'malformed-armor' };
  const r = new Reader(blob);
  const magic = r.take(6);
  if (magic === null || magic.toString('latin1') !== 'SSHSIG') return { error: 'malformed-armor' };
  if (r.u32() !== 1) return { error: 'malformed-armor' };
  const key = r.string();
  const ns = r.string();
  const reserved = r.string();
  const hashAlg = r.string();
  const sig = r.string();
  if (key === null || ns === null || reserved === null || hashAlg === null || sig === null || !r.done) {
    return { error: 'malformed-armor' };
  }
  const pub = parseEd25519Pub(`ssh-ed25519 ${key.toString('base64')}`);
  if (pub === null) return { error: 'unsupported-key' };
  return { pubkeyLine: pub.line, namespace: ns.toString('latin1'), hashAlgorithm: hashAlg.toString('latin1') };
}

/* ---------------- verification ---------------- */

export interface SigVerdict {
  /** True only for a good signature by exactly `pubkeyLine` over exactly the payload, namespace `git`. */
  valid: boolean;
  /** The key INSIDE the signature, when it could be parsed. Untrusted unless `valid`. */
  pubkeyLine: string | null;
  reason: SigReason;
  /** Parsed headers (parents, committer time); `null` for a malformed commit. */
  headers: CommitHeaders | null;
}

export interface VerifyCommitOptions {
  /** Private dir for the per-call scratch directory that holds the one-key `allowed_signers` (e.g. `<ledger>/.hub/sync/tmp`). */
  tmpRoot: string;
  /** Test seam: absolute ssh-keygen. Default = trusted resolution. */
  bin?: string;
  timeoutMs?: number;
}

export async function verifyCommitSignature(raw: Buffer, opts: VerifyCommitOptions): Promise<SigVerdict> {
  const verdict = (valid: boolean, pubkeyLine: string | null, reason: SigReason, headers: CommitHeaders | null): SigVerdict => ({
    valid,
    pubkeyLine,
    reason,
    headers,
  });
  try {
    if (!Buffer.isBuffer(raw) || raw.length === 0 || raw.length > MAX_COMMIT_BYTES) return verdict(false, null, 'malformed-commit', null);
    const split = splitCommit(raw);
    if (split.headers === null) return verdict(false, null, 'malformed-commit', null);
    if (split.signatureCount === 0 || split.armor === null) return verdict(false, null, 'unsigned', split.headers);
    if (split.signatureCount > 1) return verdict(false, null, 'multiple-signatures', split.headers);
    const info = parseSshSignature(split.armor);
    if ('error' in info) return verdict(false, null, info.error, split.headers);
    if (info.namespace !== 'git') return verdict(false, info.pubkeyLine, 'namespace', split.headers);
    if (info.hashAlgorithm !== 'sha256' && info.hashAlgorithm !== 'sha512') {
      return verdict(false, info.pubkeyLine, 'hash-algorithm', split.headers);
    }
    const ok = await verifyPayload(split.payload, split.armor, info.pubkeyLine, {
      tmpRoot: opts.tmpRoot,
      namespace: 'git',
      ...(opts.bin !== undefined ? { bin: opts.bin } : {}),
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    });
    return verdict(ok, info.pubkeyLine, ok ? 'ok' : 'bad-signature', split.headers);
  } catch {
    // ssh-keygen missing / timeout / scratch dir refused: not verified, and the caller can tell why.
    return verdict(false, null, 'verifier-error', null);
  }
}
