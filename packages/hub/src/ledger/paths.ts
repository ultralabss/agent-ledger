import { join } from 'node:path';

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
