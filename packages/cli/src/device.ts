/** `ledger device init|list|add|approve|revoke` (multi-device F2, docs/multi-device-spec.md §2.1, §6; `add` = F3b B4c,
 *  docs/f3b-b4-plan.md §1.3).
 *
 *  Local: it never talks to the hub or the network (so it works before a hub exists and cannot be driven by
 *  anything but the person at this shell) — with ONE exception: `device add` on an ENROLLED ledger (`.hub/sync.yml`
 *  exists) goes through the hub's push-first route and never through the file path (hub down = exit 3), and it
 *  needs a terminal where the human retypes the fingerprint. Output is one line per fact and never contains key
 *  material (fingerprints only). */

import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import {
  DevicesError,
  SshKeygenError,
  TrustError,
  addDevice,
  approveDevice,
  defaultLedgerDir,
  expandHome,
  initDevice,
  listDevices,
  parseEd25519Pub,
  revokeDevice,
  safeOutput,
  type SyncDeviceAddResponse,
} from '@agent-ledger/shared';
import { bool, flag, type Args } from './args.ts';
import { CliError, HubClient, readEnvConfig, type HubResponse } from './client.ts';

export interface DeviceIo {
  out: (line: string) => void;
  err: (line: string) => void;
  env: NodeJS.ProcessEnv;
  /** Whether stdin / stdout are terminals. Absent = not a TTY (tests, pipes). */
  tty?: { stdin: boolean; stdout: boolean };
  /** Interactive prompt (tests inject one; a real TTY gets readline). */
  ask?: (prompt: string) => Promise<string | null>;
  /** Test seam: the hub call of `device add` on an enrolled ledger (production = `HubClient`, never spooled). */
  hub?: { post(path: string, payload?: unknown): Promise<HubResponse> };
}

export const DEVICE_USAGE = `  ledger device init [--label <x>] [--root]  create this device's ed25519 key (idempotent; --root = first device)
  ledger device list [--json]               registered devices
  ledger device add '<pubkey>' --label <x> --fp <SHA256:…>  register a joining device (fingerprint as printed on it), then trust it here
  ledger device approve <id> --fp <SHA256:…>  trust that device's key on THIS machine (fingerprint as printed on that device)
  ledger device revoke <id> --reason "<why>"  permanent; its key is no longer trusted`;

function ledgerDirOf(env: NodeJS.ProcessEnv): string {
  return env.LEDGER_DIR?.trim() ? expandHome(env.LEDGER_DIR.trim()) : defaultLedgerDir();
}

const slotText = (slot: string): string => (slot === '' ? '-' : slot);

export async function cmdDevice(args: Args, io: DeviceIo): Promise<number> {
  const sub = args.positional[1];
  const dir = ledgerDirOf(io.env);
  try {
    switch (sub) {
      case 'init': {
        const label = flag(args, 'label');
        const r = await initDevice(dir, { ...(label !== undefined ? { label } : {}), root: bool(args, 'root') });
        io.out(`device ${r.deviceId} (${r.label}, slot ${slotText(r.slot)})`);
        io.out(`key ${r.fingerprint} — ${r.keyCreated ? 'created' : 'already present, kept'}`);
        io.out(
          r.registeredRoot
            ? 'registered as the first (root) device in devices.yml; its key is trusted here'
            : r.inDevicesYml
              ? 'registered in devices.yml'
              : 'not registered in devices.yml yet (first device: re-run with --root; others join in F3)',
        );
        return 0;
      }
      case 'list': {
        const rows = await listDevices(dir);
        if (bool(args, 'json')) {
          io.out(JSON.stringify(rows));
          return 0;
        }
        if (rows.length === 0) io.out('no devices registered (ledger device init --root)');
        for (const d of rows) {
          io.out(
            `${d.id} slot ${slotText(d.slot)} ${d.label} ${d.status}${d.self ? ' (this device)' : ''}` +
              `${d.status === 'active' ? (d.trusted ? ' trusted' : ' NOT-APPROVED') : ''} ${d.fingerprint}`,
          );
        }
        return 0;
      }
      case 'add':
        return await addCmd(args, dir, io);
      case 'approve': {
        const id = args.positional[2];
        const fp = flag(args, 'fp');
        if (id === undefined || fp === undefined) return fail(io, 'usage: ledger device approve <id> --fp <SHA256:…>');
        const r = await approveDevice(dir, id, fp);
        io.out(r.added ? `approved ${id}: its key is now trusted on this machine` : `${id} was already approved`);
        return 0;
      }
      case 'revoke': {
        const id = args.positional[2];
        const reason = flag(args, 'reason');
        if (id === undefined || reason === undefined) return fail(io, 'usage: ledger device revoke <id> --reason "<why>"');
        await revokeDevice(dir, id, reason);
        io.out(`revoked ${id}: its key is no longer trusted (revocation is permanent; remove its deploy key on the git host too)`);
        return 0;
      }
      default:
        return fail(io, `usage:\n${DEVICE_USAGE}`);
    }
  } catch (err) {
    // Error text can derive from files a peer writes (devices.yml) or a tool's stderr: strip
    // ANSI / bidi / control characters before it reaches the terminal (DK-2).
    if (err instanceof DevicesError || err instanceof SshKeygenError) return fail(io, safeOutput(err.message));
    if (err instanceof TrustError) return fail(io, `refused: ${safeOutput(err.message)}`);
    // `device` runs outside the entry's CliError handler: a hub that is down is exit 3, a refusal exit 2
    if (err instanceof CliError) return fail(io, safeOutput(err.message), err.exitCode);
    throw err;
  }
}

function fail(io: DeviceIo, message: string, code = 4): number {
  io.err(`ledger: ${message}`);
  return code;
}

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

/** `.hub/sync.yml` exists = enrolled (even a broken file: fail closed, the hub route decides). */
async function isEnrolled(dir: string): Promise<boolean> {
  return (await lstat(join(dir, '.hub', 'sync.yml')).catch(() => null)) !== null;
}

/** TRUSTED side of enrolment. Not enrolled: register in `devices.yml` (file path, as before) and approve the key
 *  with the SAME human-typed fingerprint; a crashed run is repeated safely (`DEVICE_EXISTS` falls through to the
 *  approval). Enrolled: only through the hub, after the human retyped the fingerprint on a terminal. */
async function addCmd(args: Args, dir: string, io: DeviceIo): Promise<number> {
  const pubkey = args.positional[2];
  const label = flag(args, 'label');
  const fp = flag(args, 'fp');
  if (pubkey === undefined || label === undefined || fp === undefined) {
    return fail(io, "usage: ledger device add '<pubkey>' --label <x> --fp <SHA256:…> (the key line and fingerprint the joining device printed)");
  }
  const pub = parseEd25519Pub(pubkey);
  if (pub === null || pub.line !== pubkey) return fail(io, 'public key must be exactly `ssh-ed25519 <base64>` (no comment, no options)');
  if (!FP_RE.test(fp)) return fail(io, 'the fingerprint must look like SHA256:… (as printed on the joining device)');
  if (!(await isEnrolled(dir))) {
    let slot: string | null = null;
    try {
      slot = (await addDevice(dir, pubkey, label, fp)).slot;
    } catch (err) {
      if (!(err instanceof DevicesError && err.code === 'DEVICE_EXISTS')) throw err;
    }
    const r = await approveDevice(dir, pub.deviceId, fp);
    io.out(slot === null ? `${pub.deviceId} is already registered (${label})` : `registered ${pub.deviceId} slot ${slot} (${label}) ${fp}`);
    io.out(r.added ? `approved ${pub.deviceId}: its key is now trusted on this machine` : `${pub.deviceId} was already approved`);
    return 0;
  }
  if (io.tty?.stdin !== true || io.tty.stdout !== true) {
    return fail(io, 'device add on a synced ledger needs an interactive terminal: the human retypes the fingerprint (nothing was changed)');
  }
  const ask = io.ask ?? (await (await import('./tidy.ts')).makeReadlineAsk()).ask;
  const typed = await ask(`add device ${pub.deviceId} (${label}) with key ${fp} to the synced registry\nretype the fingerprint to confirm: `);
  if (typed === null || typed.trim() !== fp) return fail(io, 'the retyped fingerprint did not match — nothing was changed');
  const cfg = readEnvConfig(io.env);
  const hub = io.hub ?? new HubClient(cfg);
  const res = await hub.post('/v1/sync/device-add', { pubkey, label, fp, ...(cfg.session === null ? {} : { session: cfg.session }) });
  const r = res.json as SyncDeviceAddResponse | null;
  if (r === null || r.ok !== true) return fail(io, 'unexpected answer from the hub', 4);
  io.out(r.existing ? `${r.id} is already registered (slot ${r.slot === '' ? '-' : r.slot})` : `registered ${r.id} slot ${r.slot} (${label}) ${r.fp}`);
  if (r.commit !== null) io.out(`commit ${r.commit}`);
  if (r.approved) io.out(`approved ${r.id}: its key is now trusted on this machine`);
  else if (r.applied) io.out(`NOT approved yet: re-run this command, or \`ledger device approve ${r.id} --fp ${r.fp}\``);
  else io.out('pushed, but not applied locally yet (a later cycle does it): re-run this command afterwards to approve the key');
  if (r.commit !== null) io.out(`on the joining device: ledger sync join --continue --add-commit ${r.commit}`);
  else if (r.existing) io.out('already registered earlier: on the joining device pass the commit that added it: ledger sync join --continue --add-commit <sha> (see `git log` of devices.yml in the ledger)');
  return 0;
}
