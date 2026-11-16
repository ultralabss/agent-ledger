/** `ledger device init|list|approve|revoke` (multi-device F2, docs/multi-device-spec.md §2.1, §6).
 *
 *  Purely local: it never talks to the hub or the network, so it works before a hub
 *  exists and cannot be driven by anything but the person at this shell. Output is one
 *  line per fact and never contains key material (fingerprints only). */

import {
  DevicesError,
  SshKeygenError,
  TrustError,
  approveDevice,
  defaultLedgerDir,
  expandHome,
  initDevice,
  listDevices,
  revokeDevice,
} from '@agent-ledger/shared';
import { bool, flag, type Args } from './args.ts';

export interface DeviceIo {
  out: (line: string) => void;
  err: (line: string) => void;
  env: NodeJS.ProcessEnv;
}

export const DEVICE_USAGE = `  ledger device init [--label <x>] [--root]  create this device's ed25519 key (idempotent; --root = first device)
  ledger device list [--json]               registered devices
  ledger device approve <id>                trust that device's key on THIS machine
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
      case 'approve': {
        const id = args.positional[2];
        if (id === undefined) return fail(io, 'usage: ledger device approve <id>');
        const r = await approveDevice(dir, id);
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
    if (err instanceof DevicesError || err instanceof SshKeygenError) return fail(io, err.message);
    if (err instanceof TrustError) return fail(io, `refused: ${err.message}`);
    throw err;
  }
}

function fail(io: DeviceIo, message: string): number {
  io.err(`ledger: ${message}`);
  return 4;
}
