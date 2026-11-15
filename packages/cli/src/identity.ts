/**
 * Is the answering hub the one that serves OUR ledger directory? `/v1/healthz`
 * reports `ledger` only to a caller with the right token, so a foreign process
 * (or a hub of another ledger) on the port yields `undefined` or a different
 * path. Paths are compared by realpath (a symlinked $HOME must still match).
 *
 * Lives in its own module so `index.ts` and `doctor.ts` can share it without an
 * import cycle.
 */

import { realpath } from 'node:fs/promises';
import { hubIdentity, type IdentityDeps } from '@agent-ledger/shared';

export async function hubServesLedger(reported: unknown, ledgerDir: string): Promise<boolean> {
  if (typeof reported !== 'string' || reported === '') return false;
  const real = (p: string): Promise<string> => realpath(p).catch(() => p);
  return (await real(reported)) === (await real(ledgerDir));
}

export type IdentityVerdict = { ok: true } | { ok: false; unidentified: boolean; detail: string };

/**
 * T12: does the (unauthenticated) `/v1/healthz` body come from a hub of THIS machine flavour
 * and THIS ledger? Decided before the bearer token is attached, so a WSL CLI reaching a Windows
 * hub through localhost forwarding (or the reverse) never hands its token over.
 *
 * Fail-closed: missing or malformed `platform` / `ledger_id` is a refusal, never a pass. A
 * misconfiguration guard, not authentication — the token stays the authority.
 */
export function hubIdentityVerdict(
  body: unknown,
  ledgerDir: string,
  deps: IdentityDeps = {},
): IdentityVerdict {
  const o = body !== null && typeof body === 'object' ? (body as { platform?: unknown; ledger_id?: unknown }) : {};
  if (typeof o.platform !== 'string' || typeof o.ledger_id !== 'string' || o.ledger_id === '') {
    return { ok: false, unidentified: true, detail: 'the service on this port did not name its platform and ledger' };
  }
  const want = hubIdentity(ledgerDir, deps);
  if (o.platform !== want.platform) {
    return { ok: false, unidentified: false, detail: `hub runs on ${o.platform.slice(0, 16)}, this CLI on ${want.platform}` };
  }
  if (o.ledger_id !== want.ledger_id) {
    return { ok: false, unidentified: false, detail: 'hub serves a different ledger directory' };
  }
  return { ok: true };
}

export function identityRefusal(v: Extract<IdentityVerdict, { ok: false }>): string {
  return v.unidentified
    ? `refusing to send the hub token: ${v.detail} (older hub, or another service — restart the hub, \`ledger doctor\`)`
    : `port held by another agent-ledger (WSL vs Windows?) — ${v.detail}. One hub per machine: stop the other one or set LEDGER_HUB_PORT`;
}
