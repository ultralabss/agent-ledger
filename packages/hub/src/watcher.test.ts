import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import test from 'node:test';
import { openTestLedger } from './test-helpers.ts';
import { startWatcher } from './watcher.ts';

async function waitFor(check: () => boolean, ms = 4000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return check();
}

test('watcher: a manual md edit gets indexed', async (t) => {
  const fx = await openTestLedger();
  const watcher = startWatcher(fx.ledger, 20);
  t.after(async () => {
    watcher.close();
    await fx.cleanup();
  });
  await fx.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const item = await fx.ledger.createItem({
    repo: 'acme',
    title: 'original',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    steps: [],
    blocked_by: [],
    aliases: [],
    proposed: false,
  });
  const file = fx.ledger.paths.itemFile('acme', item.fm.id);

  await writeFile(file, (await readFile(file, 'utf8')).replace('title: original', 'title: manual'), 'utf8');
  assert.ok(
    await waitFor(() => fx.ledger.getItem(item.fm.id).item.fm.title === 'manual'),
    'watcher did not index the manual edit',
  );

  await writeFile(file, '---\nid: ACME-1\nstatus: nonsense\n---\n', 'utf8');
  assert.ok(await waitFor(() => fx.ledger.warnings.size === 1), 'missing warning for the invalid md');
  assert.equal(fx.ledger.getItem(item.fm.id).item.fm.title, 'manual');
});
