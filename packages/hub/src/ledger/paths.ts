import { join } from 'node:path';
import { DEVICE_ID_RE, ITEM_ID_RE } from '@agent-ledger/shared';

/** `d_` + 10 base32 chars. The only shape allowed into a counter file name.
 *  Defined once in shared (sshkey.ts) so the CLI and the hub cannot drift. */
export { DEVICE_ID_RE };

export class LedgerPaths {
  readonly root: string;

  constructor(root: string) {
    this.root = root;
  }

  get reposYml(): string {
    return join(this.root, 'repos.yml');
  }

  get hubDir(): string {
    return join(this.root, '.hub');
  }

  get tokenPath(): string {
    return join(this.hubDir, 'token');
  }

  get logPath(): string {
    return join(this.hubDir, 'hub.log');
  }

  get gitignore(): string {
    return join(this.root, '.gitignore');
  }

  get gitattributes(): string {
    return join(this.root, '.gitattributes');
  }

  /** Format marker (`2\n`), committed with the ledger. */
  get formatFile(): string {
    return join(this.root, 'ledger.format');
  }

  /** Sync state directory (local, gitignored via `.hub/`). */
  get syncDir(): string {
    return join(this.hubDir, 'sync');
  }

  /** APPLY crash marker (F3b B3, docs/f3b-b3-plan.md §2). While it exists `LedgerGit.commit()` must not
   *  `add -A`: the worktree may be half-way between two trees. Basename fixed here, written by `sync/apply.ts`. */
  get inflightMarker(): string {
    return join(this.syncDir, 'inflight.json');
  }

  /** This machine's identity — local, gitignored (`.hub/`). */
  get deviceYml(): string {
    return join(this.hubDir, 'device.yml');
  }

  /** This machine's checkout paths — local, gitignored (`.hub/`). */
  get localYml(): string {
    return join(this.hubDir, 'local.yml');
  }

  /** Synced. One file per device; a device writes only its own. */
  get countersDir(): string {
    return join(this.root, 'counters');
  }

  counterFile(deviceId: string): string {
    if (!DEVICE_ID_RE.test(deviceId)) throw new Error('invalid device id');
    return join(this.countersDir, `${deviceId}.yml`);
  }

  get intakeRoot(): string {
    return join(this.root, 'intake');
  }

  intakeDir(month: string): string {
    return join(this.intakeRoot, month);
  }

  intakeFile(month: string, id: string): string {
    return join(this.intakeDir(month), `${id}.md`);
  }

  repoDir(slug: string): string {
    return join(this.root, slug);
  }

  itemsDir(slug: string): string {
    return join(this.root, slug, 'items');
  }

  itemFile(slug: string, id: string): string {
    if (!ITEM_ID_RE.test(id)) throw new Error('invalid item id');
    return join(this.itemsDir(slug), `${id}.md`);
  }

  journalDir(slug: string): string {
    return join(this.root, slug, 'journal');
  }

  journalFile(slug: string, month: string): string {
    return join(this.journalDir(slug), `${month}.md`);
  }

  contextFile(slug: string): string {
    return join(this.root, slug, 'CONTEXT.md');
  }

  decisionsFile(slug: string): string {
    return join(this.root, slug, 'DECISIONS.md');
  }
}
