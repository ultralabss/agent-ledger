/**
 * Guard kill switch — SPEC §10.
 *
 * State lives in `<ledger>/.hub/guard` (one word, `on` or `off`) so it survives
 * a hub restart, and `LEDGER_HUB_GUARD=off` pins it for the whole process — that
 * is the escape hatch when a guard bug blocks real work and nobody wants to
 * find the state file first. Every change is journalled: turning the guard off
 * is a decision, and §15 says decisions leave a trace.
 *
 * `off` means EVERY guard answers allow — the edit guard, the git guard and the
 * Stop recap check. It does not switch off attribution: `touched`, leases and
 * the inbox keep working, otherwise turning the guard off would quietly destroy
 * the data the next session needs.
 */

import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { GuardState, GuardStatus } from '@agent-ledger/shared';
import type { Ledger } from '../ledger/ledger.ts';

export interface GuardSwitchDeps {
  ledger: Ledger;
  /** `null` = no env pin. */
  envState: 'on' | 'off' | null;
}

export class GuardSwitch {
  private readonly ledger: Ledger;
  private readonly envState: 'on' | 'off' | null;
  private readonly file: string;
  private fileState: GuardState | null;

  constructor(deps: GuardSwitchDeps) {
    this.ledger = deps.ledger;
    this.envState = deps.envState;
    this.file = join(deps.ledger.paths.hubDir, 'guard');
    this.fileState = readState(this.file);
  }

  get status(): GuardStatus {
    if (this.envState !== null) {
      return { state: this.envState, source: 'env', pinned: true };
    }
    if (this.fileState !== null) {
      return { state: this.fileState, source: 'file', pinned: false };
    }
    return { state: 'on', source: 'default', pinned: false };
  }

  /** The one question every guard asks. */
  get enabled(): boolean {
    return this.status.state === 'on';
  }

  /**
   * Persist a new state. Returns the status afterwards. An env pin is not
   * overwritten silently — the file is still written (so the pin can be removed
   * and the intent survives), but `status` keeps reporting the pinned value and
   * `pinned: true` tells the caller why.
   */
  async set(next: GuardState, input: { session?: string | null; why?: string } = {}): Promise<GuardStatus> {
    // S3: decide on the file state before/after the write, not on `status.state`
    // — with an env pin (`LEDGER_HUB_GUARD=off`) `status.state` is bound to the
    // pin and does not change even when the file state really changes (on→off
    // or back). Without this a write under a pinned guard would leave no trace
    // in the journal (§15).
    const beforeFile = this.fileState;
    this.fileState = next;
    try {
      writeFileSync(this.file, `${next}\n`, { encoding: 'utf8', mode: 0o600 });
      try {
        chmodSync(this.file, 0o600); // S6: an existing file would otherwise keep its old permissions
      } catch (err) {
        this.ledger.log(`guard switch: chmod ${this.file} failed: ${String(err)}`);
      }
    } catch (err) {
      this.ledger.log(`guard switch: write ${this.file} failed: ${String(err)}`);
    }
    if (beforeFile !== next) {
      // `ops` is the virtual repo for hub-level events (SPEC §4.2).
      await this.journal(next, input);
    }
    return this.status;
  }

  private async journal(next: GuardState, input: { session?: string | null; why?: string }): Promise<void> {
    try {
      await this.ledger.appendJournalEvent('ops', input.session ?? null, 'guard', [
        `guard ${next}`,
        ...(input.why ? [input.why] : []),
      ]);
    } catch (err) {
      this.ledger.log(`guard switch: journal failed: ${String(err)}`);
    }
  }

  /** One line for the briefing / `ledger guard status`. */
  line(): string {
    const s = this.status;
    if (s.state === 'on') return `Guard: on (${s.source})`;
    return `Guard: OFF — the guards protect nothing (${s.source}${s.pinned ? ', LEDGER_HUB_GUARD' : ''}). Turn on: ledger guard on`;
  }
}

function readState(file: string): GuardState | null {
  try {
    const raw = readFileSync(file, 'utf8').trim().toLowerCase();
    if (raw === 'off') return 'off';
    if (raw === 'on') return 'on';
    return null;
  } catch {
    return null;
  }
}
