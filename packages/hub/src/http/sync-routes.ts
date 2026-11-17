/** Loopback sync routes, mounted under `/v1/sync` (F3b B4c, docs/f3b-b4-plan.md §1.4; T-B4-1/2/7/9/12/13).
 *
 *  Threat model:
 *   - Actor: an agent session that holds the hub token (it is shared with every session), a worker / headless run,
 *     a script that guesses device ids, fingerprints or commit ids through the answers, a caller that replays a
 *     request, one that floods the routes or pins the single-flight slot.
 *   - Protected: the human decisions (resume, accept a quarantined tip, confirm a revocation, register a device)
 *     run only through `requireOwner` (UI cookie, or a token plus a registered LIVE non-worker/headless session);
 *     the answers of the two decision routes are ONE `refused` for every failure and a shared limiter locks them
 *     after 5 failures in 10 minutes until `resume`; `status` carries a sanitised host token, never the URL;
 *     every accepted human action appends one journal line of tokens. No route takes a URL, a path or a ref name.
 *   - Failure modes: enumeration (uniform answer + constant minimum latency + limiter), replay (the loop methods
 *     bind to the current halt tip / commit and are idempotent: a stale or repeated request is `refused` or a no-op),
 *     body flood (1 KB cap before the body is read), parallel device adds (one in flight, then the loop's own BUSY).
 *   - Stance: routes call EXISTING `SyncLoop` methods and `addDeviceSynced`; they never touch `StateStore` or git.
 *     Nothing from git stderr, a URL or key material is returned or journalled.
 */

import { Hono, type Context } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { z } from 'zod';
import { listDevices } from '@agent-ledger/shared';
import { LedgerError } from '../errors.ts';
import type { Ledger } from '../ledger/ledger.ts';
import { addDeviceSynced, type AddSyncedCode, type AddSyncedInput, type AddSyncedResult } from '../sync/deviceadd.ts';
import { MinGap, RouteLimiter, type SyncLoop } from '../sync/loop.ts';

export interface SyncRouteDeps {
  ledger: Ledger;
  /** `null` = sync is off on this hub. */
  loop: () => SyncLoop | null;
  /** The app's owner gate: throws 403 unless a human (cookie) or a live non-worker/headless session (token). */
  requireOwner: (c: Context, session: string | null | undefined) => void;
  /** Tests. */
  limiter?: RouteLimiter;
  triggerGap?: MinGap;
  /** Minimum latency of the decision routes (ms, default 120): `ok` and `refused` take the same time. */
  padMs?: number;
  addDevice?: (loop: SyncLoop, input: AddSyncedInput) => Promise<AddSyncedResult>;
}

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
const DEVICE_ID_RE = /^d_[a-z2-7]{10}$/;
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const session = z.string().max(200).optional();

const resumeSchema = z.strictObject({ session });
const confirmSchema = z.strictObject({ id: z.string().regex(DEVICE_ID_RE), fp: z.string().regex(FP_RE), session });
const acceptSchema = z.strictObject({ sha: z.string().regex(SHA_RE), secret_ack: z.boolean().optional(), session });
const addSchema = z.strictObject({ pubkey: z.string().max(200), label: z.string().max(40), fp: z.string().max(60), session });

/** Fixed text per failure code: nothing from the operation leaks into the message. */
const ADD_MESSAGES: Record<AddSyncedCode, string> = {
  INVALID: 'the public key, label or fingerprint is not valid',
  FP_MISMATCH: 'the fingerprint does not match that public key — refusing',
  HALTED: 'sync is halted: resolve the halt first (ledger sync status)',
  NOT_SYNCED: 'this ledger is not in sync with the remote right now — try again in a moment',
  NOT_MEMBER: 'this device is not a registered, active member of the device registry',
  SLOT_BUSY: 'another device add won the slot race three times — try again',
  SLOTS_EXHAUSTED: 'all device slots are in use',
  REFUSED: 'the registry change was refused',
  REMOTE: 'the remote did not accept the change (nothing was changed locally)',
  LOCAL: 'a local error stopped the add (nothing was pushed)',
  BUSY: 'another sync operation is running — try again',
  TIMEOUT: 'the operation ran out of time (a later cycle may still complete it; re-run the add to approve)',
  STOPPED: 'the hub is shutting down',
};

export function syncRoutes(deps: SyncRouteDeps): Hono {
  const r = new Hono();
  const limiter = deps.limiter ?? new RouteLimiter();
  const triggerGap = deps.triggerGap ?? new MinGap(5000);
  const padMs = deps.padMs ?? 120;
  const addDevice = deps.addDevice ?? ((loop, input) => addDeviceSynced(loop, input));
  let addInFlight = false;

  // 1 KB before the body is read: every body here is a few tokens
  r.use(
    '*',
    bodyLimit({
      maxSize: 1024,
      onError: (c) => {
        c.header('connection', 'close');
        return c.json({ error: 'PAYLOAD_TOO_LARGE', message: 'request body > 1 KB' }, 413);
      },
    }),
  );

  const need = (): SyncLoop => {
    const loop = deps.loop();
    if (loop === null) throw new LedgerError(409, 'SYNC_OFF', 'sync is off on this hub (LEDGER_SYNC=1 and an enrolled ledger are required)');
    return loop;
  };

  async function parse<S extends z.ZodType>(c: Context, schema: S): Promise<z.infer<S>> {
    let raw: unknown;
    try {
      raw = await c.req.json();
    } catch {
      raw = {};
    }
    const res = schema.safeParse(raw ?? {});
    if (!res.success) throw new LedgerError(422, 'INVALID', 'invalid request body'); // never echoes a value
    return res.data;
  }

  const journal = (type: string, who: string | undefined, fields: string[]): Promise<void> =>
    deps.ledger.appendJournalEvent('agent-ledger', who ?? null, type, fields).catch(() => {
      deps.ledger.log(`sync route: journal line ${type} could not be written`);
    });

  /** `ok` and `refused` leave no sooner than `padMs` after the request started (no early-exit oracle). */
  async function answer(c: Context, started: number, ok: boolean): Promise<Response> {
    const wait = padMs - Math.abs(Date.now() - started);
    if (wait > 0) await new Promise<void>((resolve) => setTimeout(resolve, wait));
    return c.json({ answer: ok ? 'ok' : 'refused' }, 200);
  }

  /* ---------- status (token or cookie) ---------- */

  r.get('/status', async (c) => {
    const loop = need();
    const st = await loop.status();
    const rows = await listDevices(deps.ledger.paths.root).catch(() => []);
    const active = rows.filter((d) => d.status === 'active');
    return c.json({
      enabled: true,
      remote_host: loop.remoteHost(),
      loop: st,
      locked: limiter.locked,
      devices: rows.map((d) => ({ id: d.id, slot: d.slot, label: d.label, fingerprint: d.fingerprint, status: d.status, trusted: d.trusted, self: d.self })),
      // OQ-6: a device registered by a peer is NOT trusted here until the human approves it
      unapproved: active.filter((d) => !d.trusted && !d.self).map((d) => ({ id: d.id, slot: d.slot, label: d.label, fingerprint: d.fingerprint })),
      single_trusted_device: active.filter((d) => d.trusted).length <= 1,
    });
  });

  /* ---------- trigger (token; 1 per 5 s) ---------- */

  r.post('/trigger', (c) => {
    const loop = need();
    if (!triggerGap.take()) throw new LedgerError(429, 'RATE_LIMITED', 'one manual sync trigger per 5 seconds');
    loop.trigger('manual');
    return c.json({ ok: true });
  });

  /* ---------- human gate from here on ---------- */

  r.post('/resume', async (c) => {
    const loop = need();
    const input = await parse(c, resumeSchema);
    deps.requireOwner(c, input.session);
    const res = await loop.resume();
    limiter.reset();
    await journal('sync.resume', input.session, [`cleared=${String(res.cleared)}`]);
    return c.json({ ok: true, cleared: res.cleared });
  });

  r.post('/confirm-revocation', async (c) => {
    const started = Date.now();
    const loop = need();
    const input = await parse(c, confirmSchema);
    deps.requireOwner(c, input.session);
    if (limiter.locked) return answer(c, started, false);
    const res = await loop.confirmRevocation(input.id, input.fp);
    if (!res.ok) {
      limiter.fail(); // unknown device, wrong fingerprint, no halt, unreadable: all the same answer
      return answer(c, started, false);
    }
    await journal('sync.confirm', input.session, [`device=${input.id}`, `fp=${input.fp}`]);
    return answer(c, started, true);
  });

  r.post('/accept', async (c) => {
    const started = Date.now();
    const loop = need();
    const input = await parse(c, acceptSchema);
    deps.requireOwner(c, input.session);
    if (limiter.locked) return answer(c, started, false);
    const res = await loop.acceptQuarantine(input.sha, { secretAck: input.secret_ack === true });
    if (!res.ok) {
      limiter.fail();
      return answer(c, started, false);
    }
    await journal('sync.accept', input.session, [`tip=${input.sha}`, `secret_ack=${String(input.secret_ack === true)}`]);
    return answer(c, started, true);
  });

  r.post('/device-add', async (c) => {
    const loop = need();
    const input = await parse(c, addSchema);
    deps.requireOwner(c, input.session);
    if (limiter.locked) throw new LedgerError(409, 'LOCKED', 'too many refused attempts — `ledger sync resume` unlocks the sync routes');
    if (addInFlight) throw new LedgerError(409, 'BUSY', ADD_MESSAGES.BUSY);
    addInFlight = true;
    let res: AddSyncedResult;
    try {
      res = await addDevice(loop, { pubkey: input.pubkey, label: input.label, fp: input.fp });
    } finally {
      addInFlight = false;
    }
    if (!res.ok) {
      if (res.code === 'INVALID' || res.code === 'FP_MISMATCH' || res.code === 'REFUSED') limiter.fail();
      throw new LedgerError(res.code === 'INVALID' ? 422 : 409, res.code, ADD_MESSAGES[res.code]);
    }
    await journal('device.add', input.session, [
      `device=${res.id}`,
      `slot=${res.slot === '' ? '-' : res.slot}`,
      `fp=${res.fp}`,
      `commit=${res.commit ?? '-'}`,
      `applied=${String(res.applied)}`,
      `approved=${String(res.approved)}`,
    ]);
    return c.json(res);
  });

  return r;
}
