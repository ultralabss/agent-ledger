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
