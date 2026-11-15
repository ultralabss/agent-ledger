/**
 * Weak-filesystem bypass visibility (I5, owner decision 9).
 *
 * A path on a filesystem that cannot express private permissions only runs because
 * `LEDGER_ALLOW_WEAK_FS=1` (platformTrust's `FsCaps.bypassed`). That must never be silent:
 * one `WARNING: weak filesystem` hub.log line per path, and the list in the authenticated
 * `/v1/healthz` (`fs_weak`, web banner, `ledger doctor`).
 *
 * Probing failures are not weak-FS symptoms (a missing directory, a refusal): they are skipped
 * here — the code that needs the directory refuses on its own.
 */

import { probeFs, type FsCaps } from '@agent-ledger/shared';

export type FsProbe = (dir: string) => Promise<FsCaps>;

export interface WeakFsTarget {
  /** Directory actually probed (a probe file is created in it — never the user's checkout). */
  probeDir: string;
  /** What is reported to humans (the ledger root, not its private `.hub`). */
  label: string;
}

export class WeakFsMonitor {
  private readonly active = new Map<string, string>();
  private readonly targets: () => readonly WeakFsTarget[];
  private readonly log: (line: string) => void;
  private readonly probe: FsProbe;

  constructor(targets: () => readonly WeakFsTarget[], log: (line: string) => void, probe: FsProbe = probeFs) {
    this.targets = targets;
    this.log = log;
    this.probe = probe;
  }

  /** Re-probe (platformTrust caches for 10 min, so this is cheap); log a path once per episode. */
  async refresh(): Promise<void> {
    for (const t of this.targets()) {
      let caps: FsCaps;
      try {
        caps = await this.probe(t.probeDir);
      } catch {
        this.active.delete(t.label);
        continue;
      }
      if (!caps.bypassed) {
        this.active.delete(t.label);
        continue;
      }
      if (this.active.has(t.label)) continue;
      const why = caps.reasons.length > 0 ? caps.reasons.join(', ') : 'capabilities missing';
      this.active.set(t.label, why);
      this.log(
        `WARNING: weak filesystem ${t.label} (${caps.fsType}: ${why}) — LEDGER_ALLOW_WEAK_FS=1 bypass is active, ` +
          'private-permission checks are relaxed on it',
      );
    }
  }

  /** Paths currently running on the bypass. Empty unless the bypass is active. */
  paths(): string[] {
    return [...this.active.keys()];
  }
}
