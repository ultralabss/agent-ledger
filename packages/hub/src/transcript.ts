/**
 * Recover the session's sidebar name from its transcript.
 *
 * Claude Code does not hand the session title to hooks, but it does write it
 * into the transcript JSONL as `{"type":"custom-title","customTitle":"…"}`.
 * The line repeats every time the user renames the session, so the LAST one
 * wins. Two fallbacks, in descending trustworthiness:
 *
 *   1. `custom-title`  → the name the user actually sees in the sidebar
 *   2. `summary`       → Claude Code's own generated summary of the session
 *   3. first user text → what the session was originally asked to do
 *
 * Everything here is untrusted input from a file path the caller supplied, so:
 *  - the realpath must land under `~/.claude/projects` (or `LEDGER_TRANSCRIPTS_DIR`),
 *    reusing `safeRead.ts`'s sandbox — without it this is a read-any-file
 *    primitive — and the read itself goes through the verified (`O_NOFOLLOW` +
 *    `fstat` identity + parent-chain) reader, not an open by name,
 *  - only the last {@link TAIL_BYTES} are read for the title/summary and only the
 *    first {@link HEAD_BYTES} for the prompt fallback, so a 40 MB transcript
 *    costs two small reads,
 *  - the recovered string is single-lined, capped at {@link TITLE_CAP} and secret
 *    scanned. A finding means *no title at all* — a session name is a nicety and
 *    is never worth writing a leaked key into the DB and then into the web UI.
 *  - a malformed line is skipped, never thrown: this runs from hooks, which are
 *    fail-open.
 */

import { sanitizeLine } from '@agent-ledger/shared';
import { matchedRoot, readHeadVerified, readTailVerified, safeRealpath } from './safeRead.ts';
import { scanSecrets } from './security/secrets.ts';

export type TitleSource = 'claude' | 'summary' | 'prompt';

export interface TranscriptTitle {
  title: string;
  source: TitleSource;
}

/** The title/summary lines live at the end — a rename is appended, not patched. */
const TAIL_BYTES = 512 * 1024;
/** The first user message is near the start. 64 KB covers a long opening prompt. */
const HEAD_BYTES = 64 * 1024;
/** DB/UI cap. Matches `SessionView.title`'s documented limit. */
export const TITLE_CAP = 120;
/** The prompt fallback is a summary, not a transcript — keep it short. */
const PROMPT_CAP = 60;

/**
 * Read the best available title for a transcript, or `null`.
 *
 * `roots` must already be realpath'd (`resolveRoots`), same as for the recap
 * check — on macOS a symlinked home makes a raw compare never match.
 */
export async function readTranscriptTitle(
  transcriptPath: string | null | undefined,
  roots: readonly string[],
): Promise<TranscriptTitle | null> {
  if (typeof transcriptPath !== 'string' || transcriptPath.trim() === '') return null;
  if (roots.length === 0) return null;
  const real = await safeRealpath(transcriptPath);
  if (real === null) return null;
  // The root that matched is what the parent-chain check is walked
  // from, so it has to be carried into the read — not just "some root matched".
  const root = matchedRoot(real, roots);
  if (root === null) return null;

  // `real` was validated a moment ago; reading it BY NAME (the old
  // `readTail`/`readHead` pair) re-resolves the path and can land on a
  // different file — the classic realpath→open TOCTOU, and here it would pull
  // arbitrary file content into a session title that is stored in the DB and
  // rendered in the web UI. The verified reader opens once under `O_NOFOLLOW`
  // and proves the fd is the inode we checked.
  const tail = await readTailVerified(root, real, TAIL_BYTES);
  if (tail.skipped === null) {
    const found = scanTail(tail.text);
    if (found !== null) return found;
  } else if (tail.skipped === 'aliased') {
    // An aliased transcript is a TOCTOU signal, not a missing title: do not
    // fall through to a second read of the same suspect path.
    return null;
  }

  const head = await readHeadVerified(root, real, HEAD_BYTES);
  if (head.skipped !== null) return null;
  const prompt = firstUserText(head.text);
  if (prompt === null) return null;
  const clean = clamp(prompt, PROMPT_CAP);
  return clean === null ? null : { title: clean, source: 'prompt' };
}

/**
 * Last `custom-title` wins; a `summary` is only used when no custom title
 * exists anywhere in the tail. Both scans run over the same buffer in one pass.
 */
export function scanTail(jsonl: string): TranscriptTitle | null {
  let customTitle: string | null = null;
  let summary: string | null = null;
  for (const line of jsonl.split('\n')) {
    const trimmed = line.trim();
    // A tail read almost always starts mid-line; that fragment simply fails to
    // parse and is skipped, which is the same handling as any corrupt line.
    if (trimmed === '' || !trimmed.startsWith('{')) continue;
    let entry: unknown;
    try {
      entry = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (entry === null || typeof entry !== 'object') continue;
    const rec = entry as Record<string, unknown>;
    if (rec['type'] === 'custom-title' && typeof rec['customTitle'] === 'string') {
      customTitle = rec['customTitle'];
    } else if (rec['type'] === 'summary' && typeof rec['summary'] === 'string') {
      summary = rec['summary'];
    }
  }
  const title = clamp(customTitle, TITLE_CAP);
  if (title !== null) return { title, source: 'claude' };
  const fromSummary = clamp(summary, TITLE_CAP);
  if (fromSummary !== null) return { title: fromSummary, source: 'summary' };
  return null;
}

/**
 * First `{"type":"user"}` entry's text. Claude Code writes the message either as
 * a plain string or as a content-block array; both shapes appear in real
 * transcripts, so both are handled.
 */
export function firstUserText(jsonl: string): string | null {
  for (const line of jsonl.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || !trimmed.startsWith('{')) continue;
    let entry: unknown;
    try {
      entry = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (entry === null || typeof entry !== 'object') continue;
    const rec = entry as Record<string, unknown>;
    if (rec['type'] !== 'user') continue;
    const message = rec['message'];
    if (message === null || typeof message !== 'object') continue;
    const content = (message as Record<string, unknown>)['content'];
    if (typeof content === 'string' && content.trim() !== '') return content;
    if (Array.isArray(content)) {
      for (const block of content) {
        if (block === null || typeof block !== 'object') continue;
        const b = block as Record<string, unknown>;
        if (b['type'] === 'text' && typeof b['text'] === 'string' && b['text'].trim() !== '') {
          return b['text'];
        }
      }
    }
  }
  return null;
}

/**
 * Single-line, trim, cap, then secret scan. Returns `null` when the result is
 * empty or carries a finding — the caller then stores no title at all.
 *
 * Order matters: scan the *stored* form, not the raw one, so what the scanner
 * approved is byte-for-byte what lands in the DB.
 */
function clamp(raw: string | null, max: number): string | null {
  if (raw === null) return null;
  const line = sanitizeLine(raw).trim();
  if (line === '') return null;
  const cut = line.length > max ? `${line.slice(0, max - 1).trimEnd()}…` : line;
  if (scanSecrets(cut).length > 0) return null;
  return cut;
}
