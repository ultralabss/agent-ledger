/** `startHub` refuses to start while an enrolment marker exists (docs/f3b-b4-plan.md §2.5; T-B4-5, E-2): in EVERY mode
 *  (also `LEDGER_SYNC=0`), with one fixed line and an exit code of its own, before anything can write or commit.
 *  The marker is written by hand here (strict schema, private modes) so this test does not depend on the enrolment
 *  writer. POSIX only (modes). */

import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { ENROL_EXIT_CODE, ENROL_REFUSAL, EnrolInProgressError, startHub } from './server.ts';
import { tempConfig } from './test-helpers.ts';

const posix = process.platform !== 'win32';

async function plantMarker(dir: string, text: string): Promise<void> {
  const d = join(dir, '.hub', 'sync');
  await mkdir(d, { recursive: true, mode: 0o700 });
  await chmod(join(dir, '.hub'), 0o700);
  await chmod(d, 0o700);
  await writeFile(join(d, 'enrol.json'), text, { mode: 0o600 });
}

const marker = (o: Record<string, unknown> = {}): string =>
  JSON.stringify({ v: 1, kind: 'join', stage: 'awaiting-add', pid: process.pid, startedAt: new Date().toISOString(), remote: 'git@example.com:me/ledger.git', ...o });

for (const mode of ['off', 'on'] as const) {
  test(`marker present, LEDGER_SYNC ${mode}: no start, one fixed line, exit code ${String(ENROL_EXIT_CODE)}, nothing written`, { skip: !posix }, async () => {
    const tmp = await tempConfig({ sync: mode === 'on' });
    const logs: string[] = [];
    try {
      await plantMarker(tmp.dir, marker());
      await assert.rejects(
        startHub({ config: tmp.config, log: (l) => logs.push(l), watch: false, periodic: false }),
        (err: unknown) => err instanceof EnrolInProgressError && err.exitCode === ENROL_EXIT_CODE && err.message === ENROL_REFUSAL,
      );
      assert.ok(logs.includes(ENROL_REFUSAL), 'the fixed line is logged');
      assert.ok(!logs.some((l) => l.includes('example.com') || l.includes('me/ledger')), 'no marker content, no URL');
      assert.equal(await lstat(join(tmp.dir, '.git')).catch(() => null), null, 'ledger.init() never ran: no git init, nothing to commit');
      assert.equal(await lstat(join(tmp.dir, 'devices.yml')).catch(() => null), null);
      assert.equal(await lstat(join(tmp.dir, 'counters')).catch(() => null), null, 'no item id could have been minted');
      assert.ok((await readFile(join(tmp.dir, '.hub', 'sync', 'enrol.json'), 'utf8')).includes('awaiting-add'), 'the marker is left alone');
    } finally {
      await tmp.cleanup();
    }
  });
}

test('an unreadable / invalid marker is refused too (fail closed), and removing it lets the hub start', { skip: !posix }, async () => {
  const tmp = await tempConfig();
  try {
    await plantMarker(tmp.dir, '{ not json');
    await assert.rejects(startHub({ config: tmp.config, log: () => undefined, watch: false, periodic: false }), (err: unknown) => err instanceof EnrolInProgressError);
    await plantMarker(tmp.dir, marker({ kind: 'nope' }));
    await assert.rejects(startHub({ config: tmp.config, log: () => undefined, watch: false, periodic: false }), (err: unknown) => err instanceof EnrolInProgressError);
    const { rm } = await import('node:fs/promises');
    await rm(join(tmp.dir, '.hub', 'sync', 'enrol.json'));
    const hub = await startHub({ config: tmp.config, log: () => undefined, watch: false, periodic: false });
    await hub.close();
  } finally {
    await tmp.cleanup();
  }
});

test('boot order: the crash replay of an interrupted APPLY (phase 1) runs BEFORE the marker check, which runs BEFORE ledger.init()', async () => {
  const src = await readFile(new URL('./server.ts', import.meta.url), 'utf8');
  const replay = src.indexOf('await bootReplayGit(ledger, log)');
  const check = src.indexOf('await enrolMarkerPresent(ledger)');
  const init = src.indexOf('await ledger.init()');
  assert.ok(replay > 0 && check > replay && init > check, `replay ${String(replay)} < marker check ${String(check)} < init ${String(init)}`);
});
