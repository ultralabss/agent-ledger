/** `ledger sync` (trigger) · `status` · `resume` · `accept <sha>` · `confirm-revocation <id> --fp` (F3b B4c,
 *  docs/f3b-b4-plan.md §1.4, §2.5; T-B4-1, T-B4-12, T-B4-13). `sync init|join` live in `sync-enrol.ts` (offline,
 *  hub stopped) and are dispatched by `index.ts`.
 *
 *  Threat model:
 *   - Actor: an agent or script that runs this CLI with the shared hub token (nothing but a human at a terminal
 *     may accept a quarantined tip or confirm a revocation), a hostile peer whose device label / halt detail ends
 *     up on the operator's terminal.
 *   - Protected: the decision commands need an interactive terminal and make the human RETYPE the commit id /
 *     fingerprint (an agent cannot answer a prompt that reads the TTY); the hub gates them again (`requireOwner`).
 *     Everything printed passes `safeOutput` (no escapes, no bidi); no URL is ever printed (the hub never sends
 *     one). These commands never spool: a decision that could not be delivered is NOT queued and replayed.
 *   - Stance: exit 0 ok · 2 refused / conflict · 3 hub not running · 4 invalid input or no terminal.
 */

import { safeOutput, type SyncStatusResponse } from '@agent-ledger/shared';
import { bool, flag, type Args } from './args.ts';
import { CliError, HubClient, readEnvConfig, type CliEnvConfig, type HubResponse } from './client.ts';

export interface SyncIo {
  out: (line: string) => void;
  err: (line: string) => void;
  env: NodeJS.ProcessEnv;
  /** Whether stdin / stdout are terminals. Absent = not a TTY (tests, pipes). */
  tty?: { stdin: boolean; stdout: boolean };
  /** Interactive prompt (tests inject one; a real TTY gets readline). */
  ask?: (prompt: string) => Promise<string | null>;
}

/** The two calls this module makes (tests inject a fake; production = `HubClient`, never the spooling client). */
export interface SyncHub {
  get(path: string): Promise<HubResponse>;
  post(path: string, payload?: unknown): Promise<HubResponse>;
}

export const SYNC_USAGE = `  ledger sync                               ask the hub for a sync cycle now
  ledger sync status [--json]               remote host, halt, devices, devices awaiting approval
  ledger sync resume                        clear a no-contact / sticky halt and unlock the decision routes
  ledger sync accept <sha> [--secret-acknowledged]   accept ONE quarantined tip (terminal; retype the commit id)
  ledger sync confirm-revocation <id> --fp <SHA256:…>   confirm a revocation halt (terminal; retype the fingerprint)
  ledger sync init --remote <url> | join <url>        enrol this ledger (hub stopped; see \`ledger sync init --help\`)`;

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
const DEVICE_ID_RE = /^d_[a-z2-7]{10}$/;
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

const clean = (s: string, max = 200): string => safeOutput(s, max);
const short = (sha: string | null): string => (sha === null ? '-' : sha.slice(0, 10));

function fail(io: SyncIo, message: string, code = 4): number {
  io.err(`ledger: ${message}`);
  return code;
}

/** A decision needs a human: a terminal on both ends and a retyped value. `true` = the human confirmed. */
async function retype(io: SyncIo, what: string, expected: string): Promise<boolean | 'no-tty'> {
  if (io.tty?.stdin !== true || io.tty.stdout !== true) return 'no-tty';
  const ask = io.ask ?? (await (await import('./tidy.ts')).makeReadlineAsk()).ask;
  const answer = await ask(`${what}\nretype to confirm: `);
  return answer !== null && answer.trim() === expected;
}

export async function cmdSync(args: Args, io: SyncIo, hub?: SyncHub): Promise<number> {
  const sub = args.positional[1];
  let cfg: CliEnvConfig;
  try {
    cfg = readEnvConfig(io.env);
  } catch (err) {
    if (err instanceof CliError) return fail(io, err.message, err.exitCode);
    throw err;
  }
  const client: SyncHub = hub ?? new HubClient(cfg);
  try {
    switch (sub) {
      case undefined:
      case 'now':
      case 'trigger':
        await client.post('/v1/sync/trigger', {});
        io.out('sync requested');
        return 0;
      case 'status':
        return await status(args, io, client);
      case 'resume': {
        const res = await client.post('/v1/sync/resume', sessionBody(cfg));
        io.out((res.json as { cleared?: boolean } | null)?.cleared === true ? 'resumed: the halt is cleared, a cycle was requested' : 'nothing to clear (a halt that needs a human decision stays: ledger sync status); a cycle was requested');
        return 0;
      }
      case 'accept':
        return await accept(args, cfg, io, client);
      case 'confirm-revocation':
        return await confirmRevocation(args, cfg, io, client);
      default:
        return fail(io, `usage:\n${SYNC_USAGE}`);
    }
  } catch (err) {
    if (err instanceof CliError) return fail(io, clean(err.message), err.exitCode);
    throw err;
  }
}

function sessionBody(cfg: CliEnvConfig): { session?: string } {
  return cfg.session === null ? {} : { session: cfg.session };
}

async function status(args: Args, io: SyncIo, client: SyncHub): Promise<number> {
  const res = await client.get('/v1/sync/status');
  if (bool(args, 'json')) {
    io.out(JSON.stringify(res.json));
    return 0;
  }
  const s = res.json as SyncStatusResponse | null;
  if (s === null || typeof s !== 'object' || s.enabled !== true) return fail(io, 'unexpected answer from the hub', 4);
  const l = s.loop;
  io.out(
    `sync: ${l.started ? (l.running ? 'running a cycle' : 'idle') : 'stopped'} · remote ${clean(s.remote_host ?? '-', 80)} · accepted ${short(l.accepted)}` +
      (l.lastCycle === null ? '' : ` · last ${clean(l.lastCycle.outcome, 60)} ${clean(l.lastCycle.at, 40)}`),
  );
  if (l.stateError) io.out('sync state file is unreadable: the loop is halted (config) — `ledger doctor`');
  if (l.halt === null) {
    io.out('halt: none');
  } else {
    io.out(`halt: ${clean(l.halt.reason, 80)} (${l.halt.cls}) since ${clean(l.halt.since, 40)} · tip ${short(l.halt.tip)}${l.halt.rule === null ? '' : ` · rule ${clean(l.halt.rule, 40)}`} — ${clean(l.halt.detail, 160)}`);
    if (l.halt.d2 !== null) io.out(`revocation of ${l.halt.d2.deviceIds.map((d) => clean(d, 14)).join(', ')} awaits a human: ledger sync confirm-revocation <id> --fp <SHA256:…>`);
    if (l.halt.cls === 'probe' && l.halt.reason.startsWith('quarantine:')) io.out(`quarantined tip ${short(l.halt.tip)}: inspect it, then \`ledger sync accept <sha>\` (terminal) if it is overridable`);
  }
  if (l.pushBlocked !== null) io.out(`push blocked: rule ${clean(l.pushBlocked.rule, 40)} on ${short(l.pushBlocked.tip)}`);
  if (l.backoff !== null && l.backoff.failures > 0) io.out(`backoff: ${String(l.backoff.failures)} failed cycles${l.backoff.lastError === null ? '' : ` (${clean(l.backoff.lastError, 60)})`}`);
  for (const d of s.devices) {
    io.out(`device ${d.id} slot ${d.slot === '' ? '-' : clean(d.slot, 4)} ${clean(d.label, 40)} ${d.status}${d.self ? ' (this device)' : ''}${d.status === 'active' ? (d.trusted ? ' trusted' : ' NOT-APPROVED') : ''} ${clean(d.fingerprint, 60)}`);
  }
  for (const d of s.unapproved) {
    io.out(`WARNING: device ${d.id} (${clean(d.label, 40)}) was registered by a peer but is NOT trusted here: compare its fingerprint, then \`ledger device approve ${d.id} --fp ${clean(d.fingerprint, 60)}\``);
  }
  if (s.single_trusted_device) io.out('WARNING: only one trusted device — losing it loses write access to the remote history; add a second one (ledger device add)');
  if (s.locked) io.out('the decision routes are LOCKED after repeated refusals: `ledger sync resume` unlocks them');
  return 0;
}

async function accept(args: Args, cfg: CliEnvConfig, io: SyncIo, client: SyncHub): Promise<number> {
  // `--secret-acknowledged` is not in the parser's boolean list: placed before the sha it would swallow it
  const swallowed = flag(args, 'secret-acknowledged');
  const sha = args.positional[2] ?? (swallowed !== undefined && SHA_RE.test(swallowed) ? swallowed : undefined);
  const secretAck = bool(args, 'secret-acknowledged') || swallowed !== undefined;
  if (sha === undefined || !SHA_RE.test(sha)) return fail(io, 'usage: ledger sync accept <sha> [--secret-acknowledged] — the full commit id of the quarantined tip');
  const ok = await retype(io, `accept the quarantined tip ${sha}${secretAck ? ' (and acknowledge that a secret was removed from it)' : ''}`, sha);
  if (ok === 'no-tty') return fail(io, 'accepting a quarantined tip needs an interactive terminal: a human retypes the commit id (or use the web UI)');
  if (!ok) return fail(io, 'the retyped commit id did not match — nothing was accepted');
  const res = await client.post('/v1/sync/accept', { sha, ...(secretAck ? { secret_ack: true } : {}), ...sessionBody(cfg) });
  if ((res.json as { answer?: string } | null)?.answer !== 'ok') return fail(io, 'refused (no matching quarantined tip, not overridable, or the routes are locked) — `ledger sync status`', 2);
  io.out(`accepted ${short(sha)}: the next cycle re-validates it with your override`);
  return 0;
}

async function confirmRevocation(args: Args, cfg: CliEnvConfig, io: SyncIo, client: SyncHub): Promise<number> {
  const id = args.positional[2];
  const fp = flag(args, 'fp');
  if (id === undefined || !DEVICE_ID_RE.test(id) || fp === undefined || !FP_RE.test(fp)) {
    return fail(io, 'usage: ledger sync confirm-revocation <d_id> --fp <SHA256:…> — the id and key fingerprint named by the halt');
  }
  const ok = await retype(io, `confirm that device ${id} (${fp}) is revoked`, fp);
  if (ok === 'no-tty') return fail(io, 'confirming a revocation needs an interactive terminal: a human retypes the fingerprint (or use the web UI)');
  if (!ok) return fail(io, 'the retyped fingerprint did not match — nothing was confirmed');
  const res = await client.post('/v1/sync/confirm-revocation', { id, fp, ...sessionBody(cfg) });
  if ((res.json as { answer?: string } | null)?.answer !== 'ok') return fail(io, 'refused (no revocation is waiting for that device and fingerprint, or the routes are locked) — `ledger sync status`', 2);
  io.out(`confirmed the revocation of ${id}: the next cycle applies it`);
  return 0;
}
