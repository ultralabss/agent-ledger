/**
 * The secret scanner now lives in `@agent-ledger/shared`.
 *
 * Reason: the CLI has to run the same scan *before* a write lands in
 * the offline spool, otherwise a queued record could carry a secret to disk in
 * plaintext and the hub's 422 would arrive far too late. Two copies of a scanner
 * drift, so there is one — and this file stays as the hub's import path so no
 * call site had to change.
 */
export type { SecretFinding } from '@agent-ledger/shared';
export { redactSecrets, scanSecrets, shannon } from '@agent-ledger/shared';
