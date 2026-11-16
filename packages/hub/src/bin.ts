#!/usr/bin/env node
/** launchd entry point. stdout/stderr go to `<ledger>/.hub/hub.log`. */

import { hubLog } from './log.ts';
import { startHub } from './server.ts';
import { LedgerFormatError } from './ledger/device.ts';

const hub = await startHub().catch((err: unknown) => {
  // A ledger written by a newer hub: say so in one line (exit 78 = EX_CONFIG),
  // not as a stack trace that looks like a crash.
  if (err instanceof LedgerFormatError) {
    hubLog(`agent-ledger: ${err.message}`);
    process.exit(78);
  }
  throw err;
});

let closing = false;
const shutdown = (signal: string): void => {
  if (closing) return;
  closing = true;
  // Through the same stamped sink as every other hub line — a restart
  // is the one event where knowing the exact second matters most.
  hubLog(`agent-ledger: ${signal} → committing ledger and exiting`);
  void hub.close().then(
    () => process.exit(0),
    (err: unknown) => {
      hubLog(`agent-ledger: shutdown error: ${String(err)}`);
      process.exit(1);
    },
  );
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
