/**
 * Stop hook: recap check — SPEC §10.2.
 *
 * The rule is narrow on purpose: a recap line that carries a state tag
 * (by default `[BLOCKER]`, `[DEPLOY]`, `[RISK]`, `[UNVERIFIED]`; configurable via
 * `LEDGER_RECAP_TAGS`) but no item id on the
 * same line means the work exists only in the chat, which is exactly what the
 * ledger is supposed to end. Anything else — a tag with an id, a tag inside a
 * fenced code block, the word BLOCKER in prose — passes.
 *
 * Reading the transcript is the risky part, so it is fenced three ways:
 *  - the realpath must land inside `~/.claude/projects` (or `LEDGER_TRANSCRIPTS_DIR`
 *    in tests). A `transcript_path` is attacker-influenced input in the same way
 *    every other hook field is, and without this check `Stop` would be a
 *    read-any-file primitive for any local process that can reach the hub,
 *  - only the LAST 256 KB are read — a long session's transcript is tens of MB
 *    and the hook has a 1 s budget,
 *  - a malformed line is skipped, never thrown: a parse error must not turn Stop
 *    into a block (that would trap the session in a loop).
 */

// The hardened reader and the sandbox helpers now live in
// `../safeRead.ts` so `transcript.ts` reads the very same transcript path
// through the very same checks. Re-exported below: `recap.ts` has been the
// documented home of these helpers (and their tests) since an earlier round.
import {
  chainStable,
  insideAny,
  matchedRoot,
  parentChain,
  readTailVerified,
  resolveRoots,
  safeRealpath,
  snapshotChain,
} from '../safeRead.ts';

export {
  chainStable,
  insideAny,
  matchedRoot,
  parentChain,
  readTailVerified,
  resolveRoots,
  safeRealpath,
  snapshotChain,
};
export type { ComponentSnapshot, ReadWindow, VerifiedRead, VerifiedSkip } from '../safeRead.ts';

/** Default state tags (config `recapTags`, SPEC §10.2). */
export const DEFAULT_RECAP_TAGS: readonly string[] = ['BLOCKER', 'DEPLOY', 'RISK', 'UNVERIFIED'];

/**
 * `[TAG]` matcher built from the configured tag list. Tags are escaped, so a
 * config value can never inject regex syntax; an empty list falls back to the
 * defaults.
 */
export function buildTagRe(tags: readonly string[] = DEFAULT_RECAP_TAGS): RegExp {
  const safe = tags
    .map((t) => t.trim())
    .filter((t) => t !== '')
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const list = safe.length > 0 ? safe : [...DEFAULT_RECAP_TAGS];
  return new RegExp(`\\[(${list.join('|')})\\]`);
}

const TAG_RE = buildTagRe();
const ID_RE = /\b[A-Z]{2,5}-[A-HJ-NP-Z]?\d+\b/;
const MAX_TAIL = 256 * 1024;

export interface RecapCheck {
  /** True → the hook must emit the block envelope. */
  block: boolean;
  /** Offending lines, for the journal / debugging. Never echoed to the model. */
  lines: string[];
  /** Why no check happened (`null` when one did).
   *  H3-2: `aliased` is its own reason (not folded into `unreadable`) — a
   *  transcript that changed identity between the root check and the read is
   *  a TOCTOU signal worth its own log line, not silent, and worth telling
   *  apart from "the file just isn't there / has a hard link / nlink!=1". */
  skipped: 'no-path' | 'outside-roots' | 'unreadable' | 'aliased' | 'no-assistant-text' | null;
}

const PASS: RecapCheck = { block: false, lines: [], skipped: null };

/**
 * `transcript_path` → verdict. `stop_hook_active` is handled by the caller: when
 * Claude Code is already re-running Stop because of an earlier block, blocking
 * again is how you build an infinite loop.
 */
export async function checkRecap(
  transcriptPath: string | null | undefined,
  roots: readonly string[],
  tags: readonly string[] = DEFAULT_RECAP_TAGS,
): Promise<RecapCheck> {
  if (typeof transcriptPath !== 'string' || transcriptPath.trim() === '') {
    return { ...PASS, skipped: 'no-path' };
  }
  const real = await safeRealpath(transcriptPath);
  if (real === null) return { ...PASS, skipped: 'unreadable' };
  const root = matchedRoot(real, roots);
  if (root === null) return { ...PASS, skipped: 'outside-roots' };

  // `real` was checked against the roots a moment ago; reading it by
  // NAME would re-resolve the path and can land on a different file (the
  // classic realpath→open TOCTOU). `readTailVerified` opens once and proves
  // the open fd is the very inode we validated, AND (H3-1) that no directory
  // between `root` and `real` was swapped for a symlink in between.
  const out = await readTailVerified(root, real, MAX_TAIL);
  if (out.skipped !== null) return { ...PASS, skipped: out.skipped };
  const text = out.text;

  const last = lastAssistantText(text);
  if (last === null) return { ...PASS, skipped: 'no-assistant-text' };

  const lines = offendingLines(last, buildTagRe(tags));
  return { block: lines.length > 0, lines, skipped: null };
}

/** Lines that carry a state tag and no item id. Fenced code is ignored. */
export function offendingLines(text: string, tagRe: RegExp = TAG_RE): string[] {
  const out: string[] = [];
  let fenced = false;
  for (const raw of text.split('\n')) {
    const line = raw.trimEnd();
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    if (!tagRe.test(line)) continue;
    if (ID_RE.test(line)) continue;
    out.push(line.trim().slice(0, 200));
    if (out.length >= 10) break;
  }
  return out;
}

/**
 * Last assistant text block in a JSONL transcript.
 *
 * Two shapes are accepted, because the transcript format has changed before and
 * the hook must not go quiet when it changes again:
 *   {"type":"assistant","message":{"content":[{"type":"text","text":"…"}]}}
 *   {"role":"assistant","content":"…"}
 * Scanning runs from the end and stops at the first hit.
 */
export function lastAssistantText(jsonl: string): string | null {
  const lines = jsonl.split('\n');
  // The first line of a tail-read is very likely a fragment — drop it.
  for (let i = lines.length - 1; i >= 1; i -= 1) {
    const line = (lines[i] ?? '').trim();
    if (line === '' || !line.startsWith('{')) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    const text = assistantText(parsed);
    if (text !== null && text.trim() !== '') return text;
  }
  return null;
}

function assistantText(entry: unknown): string | null {
  if (entry === null || typeof entry !== 'object') return null;
  const rec = entry as Record<string, unknown>;
  const message = (rec.message ?? rec) as Record<string, unknown>;
  const role = message.role ?? rec.role ?? rec.type;
  if (role !== 'assistant') return null;
  const content = message.content;
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return null;
  const parts: string[] = [];
  for (const block of content) {
    if (block === null || typeof block !== 'object') continue;
    const b = block as Record<string, unknown>;
    if (b.type !== 'text') continue;
    if (typeof b.text === 'string') parts.push(b.text);
  }
  return parts.length > 0 ? parts.join('\n') : null;
}

/* ---------------- io helpers ---------------- */

// `safeRealpath` / `matchedRoot` / `insideAny` / `parentChain` /
// `snapshotChain` / `chainStable` / `readTailVerified` / `resolveRoots` moved
// verbatim to `../safeRead.ts` and are re-exported at the top of this file —
// `transcript.ts` needed the same hardened read and a second copy of a TOCTOU
// check is how the two drift apart. The old name-based `readTail` is gone with
// them: `transcript.ts` was its only caller and it was the finding.
