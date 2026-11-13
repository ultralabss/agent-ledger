/**
 * Hook output envelopes — SPEC §10.2/§10.3.
 *
 * All of them are built here, in one place, because the exact JSON shape is the
 * contract with Claude Code and a typo turns a deny into a silent allow. Every
 * reason string goes through `sanitizeLine` first: it is assembled from item
 * titles, paths and intents, all of which are free text the hub did not author,
 * and a raw `\n` inside a JSON string is fine for JSON but destroys the
 * single-line reason the UI and the transcript show.
 */

import { sanitizeField, type PostToolUseBlockOutput, type PostToolUseContextOutput, type PreToolUseDenyOutput, type StopBlockOutput } from '@agent-ledger/shared';

/** Reasons are read by a human in a transcript — long enough to be actionable. */
const MAX_REASON = 1200;

/** `permissionDecision: deny` (SPEC §10.3). Allow prints NOTHING, never `{}`. */
export function preToolUseDeny(reason: string): string {
  const payload: PreToolUseDenyOutput = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: sanitizeField(reason, MAX_REASON),
    },
  };
  return `${JSON.stringify(payload)}\n`;
}

export type PostToolMode = 'additionalContext' | 'block';

/**
 * The single PostToolUse writer (SPEC §10.2).
 *
 * `additionalContext` is the documented envelope: the text is appended to the
 * model's context and the tool result stands. `block` is the fallback for a
 * build that ignores `additionalContext` — it surfaces the text as a blocked
 * tool result, which is louder and costs a turn, so it is opt-in via config
 * (`LEDGER_HUB_POST_TOOL_MODE=block`) and the orchestrator verifies which one the
 * installed Claude Code actually honours.
 */
export function postToolUseOutput(text: string, mode: PostToolMode = 'additionalContext'): string {
  const body = sanitizeField(text, MAX_REASON);
  if (body === '') return '';
  if (mode === 'block') {
    const payload: PostToolUseBlockOutput = { decision: 'block', reason: body };
    return `${JSON.stringify(payload)}\n`;
  }
  const payload: PostToolUseContextOutput = {
    hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: body },
  };
  return `${JSON.stringify(payload)}\n`;
}

/** Stop: the only block the recap check emits (SPEC §10.2). */
export function stopBlock(reason: string): string {
  const payload: StopBlockOutput = { decision: 'block', reason: sanitizeField(reason, MAX_REASON) };
  return `${JSON.stringify(payload)}\n`;
}

export const RECAP_BLOCK_REASON =
  'Write the leftovers to the ledger (ledger add) and reference the ID in the recap.';
