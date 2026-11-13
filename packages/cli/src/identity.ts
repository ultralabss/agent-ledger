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

export async function hubServesLedger(reported: unknown, ledgerDir: string): Promise<boolean> {
  if (typeof reported !== 'string' || reported === '') return false;
  const real = (p: string): Promise<string> => realpath(p).catch(() => p);
  return (await real(reported)) === (await real(ledgerDir));
}
