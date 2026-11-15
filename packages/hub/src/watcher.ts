/** Hand edits in an editor must land in the index too (SPEC §4.1).
 *  `fs.watch` recursive (macOS/Windows) with a debounce; a reindex runs on the
 *  write queue so it never interleaves with a write in flight. */

import { watch, type FSWatcher } from 'node:fs';
import { toPosix } from './gitpath.ts';
import type { Ledger } from './ledger/ledger.ts';

export interface Watcher {
  close(): void;
  /** Resolves once every pending reindex has run (tests). */
  settled(): Promise<void>;
}

export const IGNORE = /(^|\/)(\.hub|\.git)(\/|$)|\.tmp$/;

export function startWatcher(ledger: Ledger, debounceMs = 150): Watcher {
  let timer: NodeJS.Timeout | null = null;
  let pending: Promise<void> = Promise.resolve();
  let fsw: FSWatcher | null = null;

  const schedule = (): void => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      pending = ledger.queue
        .run(() => ledger.reindex())
        .catch((err: unknown) => {
          ledger.log(`reindex failed: ${String(err)}`);
        });
    }, debounceMs);
    timer.unref?.();
  };

  try {
    fsw = watch(ledger.paths.root, { recursive: true }, (_event, filename) => {
      if (filename && IGNORE.test(toPosix(filename.toString()))) return;
      schedule();
    });
    fsw.on('error', (err) => ledger.log(`watcher error: ${String(err)}`));
  } catch (err) {
    ledger.log(`watcher unavailable: ${String(err)}`);
  }

  return {
    close(): void {
      if (timer) clearTimeout(timer);
      fsw?.close();
    },
    async settled(): Promise<void> {
      await pending;
      await ledger.queue.drain();
    },
  };
}
