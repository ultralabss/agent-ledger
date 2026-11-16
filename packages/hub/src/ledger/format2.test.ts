/** Ledger format 2 (multi-device F1): format marker, device identity, per-device
 *  counters, portable repos.yml + local.yml, append-only journal, root_sha binding.
 *  docs/multi-device-spec.md §2, §8, §9. */

import assert from 'node:assert/strict';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { parse as parseYaml } from 'yaml';
import { snowflake, slotWorkerId } from '@agent-ledger/shared';
import { skipOnWin32 } from '@agent-ledger/shared/testing';
import { git } from '../git.ts';
import { originHintFromUrl, readRootSha } from '../gitreader.ts';
import { makeCommittedRepo, tempConfig, type TempLedger } from '../test-helpers.ts';
import { LedgerFormatError, newDeviceId, readAllCounters } from './device.ts';
import { Ledger } from './ledger.ts';

const base = {
  kind: 'BACKLOG',
  priority: 'P2',
  owner: 'agent',
  steps: [] as string[],
  blocked_by: [] as string[],
  aliases: [] as string[],
  proposed: false,
};

/** Ledger on `tmp.dir`; closed by the returned `close` (commit on shutdown needs an identity). */
async function open(tmp: TempLedger): Promise<{ ledger: Ledger; logs: string[]; close: () => Promise<void> }> {
  const logs: string[] = [];
  const ledger = new Ledger({ config: tmp.config, log: (l) => logs.push(l) });
  await ledger.init();
  await git(tmp.dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(tmp.dir, ['config', 'user.name', 'agent-ledger test']);
  let closed = false;
  return {
    ledger,
    logs,
    close: async () => {
      if (closed) return;
      closed = true;
      await ledger.close();
    },
  };
}

/** A repo whose root commit differs from every other fixture's (`makeCommittedRepo`
 *  makes byte-identical `chore: init` commits, i.e. equal shas within one second). */
async function distinctRepo(label: string): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const { makeCodeRepo } = await import('../test-helpers.ts');
  const repo = await makeCodeRepo(label);
  const res = await git(repo.path, [
    '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '--allow-empty', '-q', '-m', `root of ${label}`,
  ]);
  assert.equal(res.code, 0, res.stderr);
  return repo;
}

async function exists(p: string): Promise<boolean> {
  return stat(p).then(() => true, () => false);
}

async function yaml(p: string): Promise<any> {
  return parseYaml(await readFile(p, 'utf8'));
}

/** A format-1 ledger as an old hub left it: `path`/`next` in repos.yml, no marker, no counters. */
async function writeFormat1(dir: string, repos: string): Promise<void> {
  await mkdir(join(dir, 'ops', 'items'), { recursive: true });
  await writeFile(join(dir, 'repos.yml'), repos, 'utf8');
}

/* ---------------- F1.6 format marker ---------------- */

test('F1.6: a fresh ledger gets ledger.format 2, device.yml (slot ""), portable repos.yml', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  assert.equal((await readFile(join(tmp.dir, 'ledger.format'), 'utf8')).trim(), '2');
  const dev = await yaml(join(tmp.dir, '.hub', 'device.yml'));
  assert.match(dev.device_id, /^d_[a-z2-7]{10}$/);
  assert.equal(dev.slot, '');
  assert.equal(ledger.device.slot, '');
  const repos = await yaml(join(tmp.dir, 'repos.yml'));
  assert.deepEqual(repos, { ops: { kind: 'system', prefix: 'OPS' } });
  // the identity file and local paths stay out of git
  assert.match(await readFile(join(tmp.dir, '.gitignore'), 'utf8'), /^\.hub\/$/m);
});

test('F1.6: a ledger with a HIGHER format is refused before anything is written', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await writeFile(join(tmp.dir, 'ledger.format'), '3\n', 'utf8');
  const ledger = new Ledger({ config: tmp.config, log: () => undefined });
  await assert.rejects(() => ledger.init(), (err: unknown) => {
    assert.ok(err instanceof LedgerFormatError);
    assert.match((err as Error).message, /upgrade the hub/);
    return true;
  });
  assert.deepEqual((await readdir(tmp.dir)).sort(), ['ledger.format'], 'nothing else was created');
});

test('F1.6: an unreadable or nonsensical marker is refused too (fail closed)', async (t) => {
  for (const junk of ['abc', '', '2.5', '0', '-1', '2\nextra', '99999999999']) {
    const tmp = await tempConfig();
    t.after(tmp.cleanup);
    await writeFile(join(tmp.dir, 'ledger.format'), junk, 'utf8');
    const ledger = new Ledger({ config: tmp.config, log: () => undefined });
    await assert.rejects(() => ledger.init(), LedgerFormatError, JSON.stringify(junk));
  }
});

/* ---------------- F1.2 + F1.3 migration from format 1 ---------------- */

test('migration: next → counters, path/graphify → local.yml, identity added, marker last; idempotent', async (t) => {
  const code = await makeCommittedRepo('f2mig');
  t.after(code.cleanup);
  const rootSha = (await git(code.path, ['rev-list', '--max-parents=0', 'HEAD'])).stdout.trim();
  await code.commit('first', { 'a.txt': 'a' });
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await writeFormat1(
    tmp.dir,
    [
      'ops:',
      '  kind: system',
      '  prefix: OPS',
      '  path: null',
      '  next: 1',
      'acme:',
      '  prefix: ACME',
      `  path: ${code.path}`,
      '  next: 143',
      '  graphify: /home/me/acme/graphify-out',
      '  docs:',
      '    - docs/a.md',
      '    - /home/me/notes/abs.md',
      'virt:',
      '  prefix: VR',
      '  path: null',
      '  next: 3',
      '',
    ].join('\n'),
  );
  const first = await open(tmp);
  t.after(first.close);

  // synced file: nothing absolute, no counter
  const synced = await readFile(join(tmp.dir, 'repos.yml'), 'utf8');
  assert.doesNotMatch(synced, /\bpath:/);
  assert.doesNotMatch(synced, /\bnext:/);
  assert.doesNotMatch(synced, /graphify:/);
  assert.equal(synced.includes(code.path), false, 'no absolute checkout path in the synced file');
  assert.equal(synced.includes('/home/me'), false, 'no absolute path of any kind');
  const parsed = parseYaml(synced);
  assert.equal(parsed.acme.identity.root_sha, rootSha);
  assert.deepEqual(parsed.acme.docs, ['docs/a.md']);
  assert.equal(parsed.virt.identity, undefined);

  // local file: this machine's paths
  const local = await yaml(join(tmp.dir, '.hub', 'local.yml'));
  assert.equal(local.acme.path, code.path);
  assert.equal(local.acme.graphify, '/home/me/acme/graphify-out');
  assert.deepEqual(local.acme.docs, ['/home/me/notes/abs.md']);

  // counters: last allocated = old next - 1; the view is unchanged
  const counters = await yaml(join(tmp.dir, 'counters', `${first.ledger.device.device_id}.yml`));
  assert.deepEqual(counters, { acme: 142, virt: 2 });
  const view = first.ledger.repos();
  assert.equal(view.acme?.next, 143);
  assert.equal(view.acme?.path, code.path);
  assert.equal(view.acme?.graphify, '/home/me/acme/graphify-out');
  assert.deepEqual(view.acme?.docs, ['docs/a.md', '/home/me/notes/abs.md']);
  assert.equal(view.virt?.next, 3);
  assert.equal(view.virt?.path, null);
  assert.equal((await readFile(join(tmp.dir, 'ledger.format'), 'utf8')).trim(), '2');

  // the very next id continues the old sequence, with no slot letter
  const item = await first.ledger.createItem({ ...base, repo: 'acme', title: 'continues' });
  assert.equal(item.fm.id, 'ACME-143');
  await first.close();

  // idempotent: a second boot rewrites nothing
  const before = {
    repos: await readFile(join(tmp.dir, 'repos.yml'), 'utf8'),
    local: await readFile(join(tmp.dir, '.hub', 'local.yml'), 'utf8'),
    counters: await readFile(join(tmp.dir, 'counters', `${first.ledger.device.device_id}.yml`), 'utf8'),
    device: await readFile(join(tmp.dir, '.hub', 'device.yml'), 'utf8'),
    format: await readFile(join(tmp.dir, 'ledger.format'), 'utf8'),
  };
  const second = await open(tmp);
  t.after(second.close);
  assert.equal(second.logs.some((l) => /migrated to format/.test(l)), false, 'no second migration');
  assert.equal(await readFile(join(tmp.dir, 'repos.yml'), 'utf8'), before.repos);
  assert.equal(await readFile(join(tmp.dir, '.hub', 'local.yml'), 'utf8'), before.local);
  assert.equal(await readFile(join(tmp.dir, 'counters', `${second.ledger.device.device_id}.yml`), 'utf8'), before.counters);
  assert.equal(await readFile(join(tmp.dir, '.hub', 'device.yml'), 'utf8'), before.device);
  assert.equal(await readFile(join(tmp.dir, 'ledger.format'), 'utf8'), before.format);
  assert.equal(second.ledger.repos().acme?.next, 144);
  const again = await second.ledger.createItem({ ...base, repo: 'acme', title: 'and on' });
  assert.equal(again.fm.id, 'ACME-144');
});

test('migration never lowers a counter: existing counter file larger than legacy next wins', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  // a hub that crashed after writing counters but before dropping `next`
  const deviceId = newDeviceId();
  await mkdir(join(tmp.dir, '.hub'), { recursive: true });
  await writeFile(join(tmp.dir, '.hub', 'device.yml'), `device_id: ${deviceId}\nlabel: mac\nslot: ""\n`, 'utf8');
  await mkdir(join(tmp.dir, 'counters'), { recursive: true });
  await writeFile(join(tmp.dir, 'counters', `${deviceId}.yml`), 'acme: 500\n', 'utf8');
  await writeFormat1(tmp.dir, 'acme:\n  prefix: ACME\n  path: null\n  next: 10\n');
  const { ledger, close } = await open(tmp);
  t.after(close);
  assert.equal(ledger.repos().acme?.next, 501);
  assert.equal(ledger.device.device_id, deviceId);
  assert.deepEqual(await yaml(join(tmp.dir, 'counters', `${deviceId}.yml`)), { acme: 500 });
  const item = await ledger.createItem({ ...base, repo: 'acme', title: 'x' });
  assert.equal(item.fm.id, 'ACME-501');
});

test('migration is skipped (nothing rewritten) when repos.yml does not parse', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await writeFormat1(tmp.dir, 'acme: [this is: not valid\n');
  const { ledger, logs, close } = await open(tmp);
  t.after(close);
  assert.equal(await readFile(join(tmp.dir, 'repos.yml'), 'utf8'), 'acme: [this is: not valid\n');
  assert.equal(await exists(join(tmp.dir, 'ledger.format')), false, 'no marker on a half-understood ledger');
  assert.ok(logs.some((l) => /migration skipped/.test(l)));
  assert.ok(ledger.warnings.has(ledger.paths.reposYml));
});

test('a legacy repos.yml written AFTER boot is still read (path/next honoured, not rewritten on read)', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  const legacy = 'old:\n  prefix: OL\n  path: ~/nowhere\n  next: 7\n';
  await writeFile(ledger.paths.reposYml, legacy, 'utf8');
  await ledger.reindex();
  assert.equal(ledger.repos().old?.next, 7);
  assert.equal(ledger.repos().old?.path, '~/nowhere');
  assert.equal(await readFile(ledger.paths.reposYml, 'utf8'), legacy);
  // first mutation folds `next` into the counters before the key disappears
  await ledger.registerRepo({ slug: 'new1', prefix: 'NW', path: null });
  assert.doesNotMatch(await readFile(ledger.paths.reposYml, 'utf8'), /\bnext:/);
  const counters = await yaml(join(tmp.dir, 'counters', `${ledger.device.device_id}.yml`));
  assert.equal(counters.old, 6);
  assert.equal((await ledger.createItem({ ...base, repo: 'old', title: 'x' })).fm.id, 'OL-7');
});

/* ---------------- F1.2 counters ---------------- */

test('F1.2: counter file holds {slug: last}, device writes only its own file', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  await ledger.createItem({ ...base, repo: 'acme', title: 'a' });
  await ledger.createItem({ ...base, repo: 'acme', title: 'b' });
  const files = await readdir(join(tmp.dir, 'counters'));
  assert.deepEqual(files, [`${ledger.device.device_id}.yml`]);
  assert.deepEqual(await yaml(join(tmp.dir, 'counters', files[0] as string)), { acme: 2 });
  assert.doesNotMatch(await readFile(join(tmp.dir, 'repos.yml'), 'utf8'), /\bnext:/);
});

test('F1.2: 40 concurrent creates in one hub → unique ids, counter equals the count', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const items = await Promise.all(
    Array.from({ length: 40 }, (_u, i) => ledger.createItem({ ...base, repo: 'acme', title: `p${i}` })),
  );
  assert.equal(new Set(items.map((i) => i.fm.id)).size, 40);
  const counters = await yaml(join(tmp.dir, 'counters', `${ledger.device.device_id}.yml`));
  assert.equal(counters.acme, 40);
});

test('F1.2: a failing counter write rolls the id back, no item file is left behind', { skip: skipOnWin32('POSIX-only: chmod') }, async (t) => {
  const { chmod } = await import('node:fs/promises');
  const tmp = await tempConfig();
  t.after(async () => {
    await chmod(join(tmp.dir, 'counters'), 0o700).catch(() => undefined);
    await tmp.cleanup();
  });
  const { ledger, close } = await open(tmp);
  t.after(close);
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  assert.equal((await ledger.createItem({ ...base, repo: 'acme', title: 'one' })).fm.id, 'ACME-1');
  await chmod(join(tmp.dir, 'counters'), 0o500);
  await assert.rejects(() => ledger.createItem({ ...base, repo: 'acme', title: 'two' }));
  assert.equal(ledger.repo('acme').next, 2, 'in-memory counter restored');
  assert.equal(await exists(ledger.paths.itemFile('acme', 'ACME-2')), false, 'item not written after a failed counter write');
  await chmod(join(tmp.dir, 'counters'), 0o700);
  assert.equal((await ledger.createItem({ ...base, repo: 'acme', title: 'two again' })).fm.id, 'ACME-2');
});

test('F1.2: unreadable counter file → creates are refused, nothing is guessed', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const deviceId = newDeviceId();
  await mkdir(join(tmp.dir, '.hub'), { recursive: true });
  await writeFile(join(tmp.dir, '.hub', 'device.yml'), `device_id: ${deviceId}\nlabel: mac\nslot: ""\n`, 'utf8');
  await mkdir(join(tmp.dir, 'counters'), { recursive: true });
  await writeFile(join(tmp.dir, 'counters', `${deviceId}.yml`), 'acme: [not, a, number]\n', 'utf8');
  const { ledger, close } = await open(tmp);
  t.after(close);
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  await assert.rejects(
    () => ledger.createItem({ ...base, repo: 'acme', title: 'x' }),
    (err: any) => err.code === 'COUNTERS_INVALID',
  );
  assert.equal((await readdir(ledger.paths.itemsDir('acme'))).length, 0);
});

test('F1.2: lost device.yml (new device id, still slot "") cannot restart numbering below existing ids', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const a = await open(tmp);
  await a.ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  for (let i = 0; i < 3; i += 1) await a.ledger.createItem({ ...base, repo: 'acme', title: `t${i}` });
  const oldId = a.ledger.device.device_id;
  await a.close();
  const { rm } = await import('node:fs/promises');
  await rm(join(tmp.dir, '.hub', 'device.yml'));
  const b = await open(tmp);
  t.after(b.close);
  assert.notEqual(b.ledger.device.device_id, oldId);
  assert.equal(b.ledger.repos().acme?.next, 4, 'seeded from the per-key max over counters/*.yml');
  assert.equal((await b.ledger.createItem({ ...base, repo: 'acme', title: 'after loss' })).fm.id, 'ACME-4');
});

test('F1.2: an existing item file is never overwritten, the allocator skips past it', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const first = await ledger.createItem({ ...base, repo: 'acme', title: 'precious' });
  const file = ledger.paths.itemFile('acme', first.fm.id);
  const original = await readFile(file, 'utf8');
  // counter loses its memory (restored from an old backup, hand edit)
  await writeFile(join(tmp.dir, 'counters', `${ledger.device.device_id}.yml`), 'acme: 0\n', 'utf8');
  await ledger.reindex();
  const second = await ledger.createItem({ ...base, repo: 'acme', title: 'new' });
  assert.equal(second.fm.id, 'ACME-2');
  assert.equal(await readFile(file, 'utf8'), original);
});

test('readAllCounters: per-key max, only d_* names, a bad file is ignored and reported', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const dir = join(tmp.dir, 'counters');
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'd_aaaaaaaaaa.yml'), 'acme: 5\nweb: 1\n', 'utf8');
  await writeFile(join(dir, 'd_bbbbbbbbbb.yml'), 'acme: 9\nops: 2\n', 'utf8');
  await writeFile(join(dir, 'd_cccccccccc.yml'), 'acme: [oops]\n', 'utf8');
  await writeFile(join(dir, 'evil.yml'), 'acme: 99999\n', 'utf8');
  await writeFile(join(dir, 'd_dddddddddd.txt'), 'acme: 99999\n', 'utf8');
  const bad: string[] = [];
  const all = await readAllCounters(dir, (n) => bad.push(n));
  assert.deepEqual([...all].sort(), [['acme', 9], ['ops', 2], ['web', 1]]);
  assert.deepEqual(bad, ['d_cccccccccc.yml']);
});

/* ---------------- F1.4 device identity + slot ---------------- */

test('F1.4: slot letter in device.yml → ids carry it, snowflake worker follows the slot', async (t) => {
  const prevWorker = snowflake.workerId;
  t.after(() => snowflake.setWorkerId(prevWorker));
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const deviceId = newDeviceId();
  await mkdir(join(tmp.dir, '.hub'), { recursive: true });
  await writeFile(join(tmp.dir, '.hub', 'device.yml'), `device_id: ${deviceId}\nlabel: win\nslot: W\n`, 'utf8');
  const { ledger, close } = await open(tmp);
  t.after(close);
  assert.equal(snowflake.workerId, slotWorkerId('W'));
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  const a = await ledger.createItem({ ...base, repo: 'acme', title: 'a' });
  const b = await ledger.createItem({ ...base, repo: 'acme', title: 'b' });
  assert.deepEqual([a.fm.id, b.fm.id], ['ACME-W1', 'ACME-W2']);
  assert.equal(ledger.repoForItemId('ACME-W2'), 'acme');
  assert.equal(ledger.repoForItemId('ACME-I2'), null);
  assert.equal(ledger.getItem('ACME-W1').item.fm.title, 'a');
  assert.ok(await exists(join(tmp.dir, 'acme', 'items', 'ACME-W1.md')));
});

test('F1.4: slot "" keeps today\'s worker id and plain ids (single-machine regression)', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  assert.equal(snowflake.workerId, 1);
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  assert.equal((await ledger.createItem({ ...base, repo: 'acme', title: 'x' })).fm.id, 'ACME-1');
});

test('F1.4: an invalid device.yml refuses to start and is not regenerated', async (t) => {
  for (const body of ['not: [valid', 'device_id: ../../etc\nlabel: x\nslot: ""\n', 'device_id: d_aaaaaaaaaa\nlabel: x\nslot: I\n', 'device_id: d_aaaaaaaaaa\nlabel: x\nslot: AB\n']) {
    const tmp = await tempConfig();
    t.after(tmp.cleanup);
    await mkdir(join(tmp.dir, '.hub'), { recursive: true });
    await writeFile(join(tmp.dir, '.hub', 'device.yml'), body, 'utf8');
    const ledger = new Ledger({ config: tmp.config, log: () => undefined });
    await assert.rejects(() => ledger.init(), (err: any) => err.code === 'DEVICE_INVALID', body);
    assert.equal(await readFile(join(tmp.dir, '.hub', 'device.yml'), 'utf8'), body);
  }
});

test('path allowlists: counter file names, item file names, reserved slugs', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  for (const bad of ['../x', 'd_AAAAAAAAAA', 'd_aaaaaaaaa', 'd_aaaaaaaaaaa', 'd_aaaaaaaaa1', 'x', '', 'd_aaaaaaaaaa/../x']) {
    assert.throws(() => ledger.paths.counterFile(bad), /invalid device id/, bad);
  }
  for (const bad of ['../ACME-1', 'ACME-1/../../x', 'acme-1', 'ACME-1.md', 'C:\\x', '']) {
    assert.throws(() => ledger.paths.itemFile('acme', bad), /invalid item id/, bad);
  }
  for (const slug of ['counters', 'intake']) {
    await assert.rejects(() => ledger.registerRepo({ slug, path: null }), /reserved/);
  }
});

/* ---------------- F1.5 journal append ---------------- */

test('F1.5: session.summary is appended, never rewritten; readers still see one per session', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  await ledger.registerRepo({ slug: 'acme', prefix: 'ACME', path: null });
  await ledger.upsertJournalEvent('acme', 'aaaa-1', 'session.summary', ['first']);
  const file = ledger.paths.journalFile('acme', new Date().toISOString().slice(0, 7));
  const afterFirst = await readFile(file, 'utf8');
  await ledger.upsertJournalEvent('acme', 'aaaa-1', 'session.summary', ['second']);
  await ledger.upsertJournalEvent('acme', 'aaaa-1', 'session.summary', ['second']); // identical → no new line
  await ledger.upsertJournalEvent('acme', 'bbbb-2', 'session.summary', ['other session']);
  const text = await readFile(file, 'utf8');
  assert.ok(text.startsWith(afterFirst), 'earlier bytes are untouched (append-only)');
  assert.equal(text.split('\n').filter((l) => l.includes('session.summary')).length, 3);
  const events = ledger.listJournal('acme').filter((e) => e.type === 'session.summary');
  assert.equal(events.length, 2, 'collapsed to the latest per session');
  assert.deepEqual(events.map((e) => e.fields.join(' ')).sort(), ['other session', 'second']);
  // a fresh hub rebuilds the same view from the file
  await close();
  const again = await open(tmp);
  t.after(again.close);
  assert.deepEqual(
    again.ledger.listJournal('acme').filter((e) => e.type === 'session.summary').length,
    2,
  );
});

/* ---------------- F1.3 identity, binding ---------------- */

test('originHintFromUrl: host/org/repo only, credentials never survive', () => {
  const cases: [string, string | null][] = [
    ['https://github.com/acme/app.git', 'github.com/acme/app'],
    ['https://user:ghp_SECRETTOKEN123@github.com/acme/app.git', 'github.com/acme/app'],
    ['https://x-access-token:abc@host.example:8443/o/r/', 'host.example/o/r'],
    ['git@github.com:acme/app.git', 'github.com/acme/app'],
    ['ssh://git@git.example.com:2222/team/repo.git', 'git.example.com/team/repo'],
    ['https://github.com/acme/app?token=abc#frag', 'github.com/acme/app'],
    ['/local/path/repo', null],
    ['file:///local/path/repo', null],
    ['', null],
    ['https://host/..%2f..', null],
    ['https://host/a/../b', null],
  ];
  for (const [raw, want] of cases) {
    const got = originHintFromUrl(raw);
    assert.equal(got, want, raw);
    if (got !== null) {
      assert.doesNotMatch(got, /SECRET|ghp_|token|abc@|:/i, `no credential in ${got}`);
    }
  }
});

test('F1.3: registerRepo records root_sha + origin_hint in repos.yml, path only in local.yml', async (t) => {
  const code = await makeCommittedRepo('f2id');
  t.after(code.cleanup);
  await code.commit('root', { 'a.txt': 'a' });
  await git(code.path, ['remote', 'add', 'origin', 'https://bob:hunter2token@github.com/acme/app.git']);
  const rootSha = (await git(code.path, ['rev-list', '--max-parents=0', 'HEAD'])).stdout.trim();
  await code.commit('second', { 'b.txt': 'b' });
  assert.equal(await readRootSha(code.path), rootSha, 'oldest root commit');
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  const { ledger, close } = await open(tmp);
  t.after(close);
  await ledger.registerRepo({ slug: 'app', prefix: 'APP', path: code.path });
  const synced = await readFile(join(tmp.dir, 'repos.yml'), 'utf8');
  const parsed = parseYaml(synced);
  assert.deepEqual(parsed.app.identity, { root_sha: rootSha, origin_hint: 'github.com/acme/app' });
  assert.equal(synced.includes(code.path), false);
  assert.equal(synced.includes('hunter2token'), false, 'no credential in the synced file');
  assert.equal(synced.includes('bob'), false);
  assert.equal((await yaml(join(tmp.dir, '.hub', 'local.yml'))).app.path, ledger.repo('app').path);
});

test('F1.3: root_sha of an empty repo / a missing dir is null, never throws', async (t) => {
  const { makeCodeRepo } = await import('../test-helpers.ts');
  const empty = await makeCodeRepo('f2empty');
  t.after(empty.cleanup);
  assert.equal(await readRootSha(empty.path).catch(() => 'threw'), null);
});

test('F1.3: unknown checkout binds by root_sha (no slug created); wrong or ambiguous → null', async (t) => {
  const code = await makeCommittedRepo('f2bind');
  t.after(code.cleanup);
  await code.commit('root', { 'a.txt': 'a' });
  const other = await distinctRepo('f2other');
  t.after(other.cleanup);

  // machine A registers; machine B gets only the synced repos.yml
  const a = await tempConfig();
  t.after(a.cleanup);
  const la = await open(a);
  t.after(la.close);
  await la.ledger.registerRepo({ slug: 'app', prefix: 'APP', path: code.path });
  const b = await tempConfig();
  t.after(b.cleanup);
  await writeFile(join(b.dir, 'repos.yml'), await readFile(join(a.dir, 'repos.yml'), 'utf8'), 'utf8');
  const lb = await open(b);
  t.after(lb.close);
  assert.equal(lb.ledger.repos().app?.path, null, 'no path travels in the synced file');
  const slugsBefore = Object.keys(lb.ledger.repos()).sort();

  assert.equal(await lb.ledger.bindByRootSha(other.path), null, 'unrelated checkout is not bound');
  assert.equal(await lb.ledger.bindByRootSha(code.path), 'app');
  assert.deepEqual(Object.keys(lb.ledger.repos()).sort(), slugsBefore, 'no slug was created');
  assert.equal(lb.ledger.repos().app?.path, lb.ledger.repoPath('app'));
  assert.equal((await yaml(join(b.dir, '.hub', 'local.yml'))).app.path, lb.ledger.repoPath('app'));
  assert.doesNotMatch(await readFile(join(b.dir, 'repos.yml'), 'utf8'), /\bpath:/);
  // already bound → nothing to do
  assert.equal(await lb.ledger.bindByRootSha(code.path), null);
});

test('F1.3: same root commit but a different origin (template clone) is not auto-bound', async (t) => {
  const code = await makeCommittedRepo('f2tpl');
  t.after(code.cleanup);
  await git(code.path, ['remote', 'add', 'origin', 'https://github.com/someone/else.git']);
  const sha = (await git(code.path, ['rev-list', '--max-parents=0', 'HEAD'])).stdout.trim();
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await writeFile(
    join(tmp.dir, 'repos.yml'),
    `app:\n  prefix: APP\n  identity:\n    root_sha: ${sha}\n    origin_hint: github.com/acme/app\n`,
    'utf8',
  );
  const { ledger, close } = await open(tmp);
  t.after(close);
  assert.equal(await ledger.bindByRootSha(code.path), null);
  assert.equal(ledger.repos().app?.path, null);
  // explicit human bind still works (root matches)
  assert.equal((await ledger.bindRepo('app', code.path)).path, ledger.repoPath('app'));
});

test('F1.3: two unbound slugs with the same root_sha are ambiguous → not bound', async (t) => {
  const code = await makeCommittedRepo('f2amb');
  t.after(code.cleanup);
  await code.commit('root', { 'a.txt': 'a' });
  const sha = (await git(code.path, ['rev-list', '--max-parents=0', 'HEAD'])).stdout.trim();
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await writeFile(
    join(tmp.dir, 'repos.yml'),
    `one:\n  prefix: ONE\n  identity:\n    root_sha: ${sha}\ntwo:\n  prefix: TWO\n  identity:\n    root_sha: ${sha}\n`,
    'utf8',
  );
  const { ledger, close } = await open(tmp);
  t.after(close);
  assert.equal(await ledger.bindByRootSha(code.path), null);
  assert.equal(ledger.repos().one?.path, null);
  assert.equal(ledger.repos().two?.path, null);
});

test('F1.3: `repo bind` verifies the root commit and refuses a different repo or a held path', async (t) => {
  const code = await makeCommittedRepo('f2bind2');
  t.after(code.cleanup);
  await code.commit('root', { 'a.txt': 'a' });
  const other = await distinctRepo('f2bind3');
  t.after(other.cleanup);
  const sha = (await git(code.path, ['rev-list', '--max-parents=0', 'HEAD'])).stdout.trim();
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await writeFile(
    join(tmp.dir, 'repos.yml'),
    `app:\n  prefix: APP\n  identity:\n    root_sha: ${sha}\nlegacy:\n  prefix: LEG\n`,
    'utf8',
  );
  const { ledger, close } = await open(tmp);
  t.after(close);
  await assert.rejects(() => ledger.bindRepo('app', other.path), /different root commit/);
  await assert.rejects(() => ledger.bindRepo('nope', code.path), /unknown repo/);
  await assert.rejects(() => ledger.bindRepo('app', join(tmp.dir, 'not-a-repo')), /not a git repository/);
  const cfg = await ledger.bindRepo('app', code.path);
  assert.equal(cfg.path, ledger.repoPath('app'));
  await assert.rejects(() => ledger.bindRepo('legacy', code.path), /already held by repo "app"/);
  // a slug without identity learns it from the first verified checkout
  const learned = await ledger.bindRepo('legacy', other.path);
  assert.ok(learned.identity?.root_sha);
  assert.match(await readFile(join(tmp.dir, 'repos.yml'), 'utf8'), /identity:/);
});

test('local.yml unreadable: paths stay unavailable, the file is never overwritten, migration waits', async (t) => {
  const tmp = await tempConfig();
  t.after(tmp.cleanup);
  await mkdir(join(tmp.dir, '.hub'), { recursive: true });
  await writeFile(join(tmp.dir, '.hub', 'local.yml'), 'acme: [broken\n', 'utf8');
  await writeFormat1(tmp.dir, 'acme:\n  prefix: ACME\n  path: ~/keep-me\n  next: 5\n');
  const { ledger, logs, close } = await open(tmp);
  t.after(close);
  assert.ok(logs.some((l) => /local\.yml is not valid/.test(l)));
  assert.match(await readFile(join(tmp.dir, 'repos.yml'), 'utf8'), /path: ~\/keep-me/, 'legacy path not dropped');
  assert.equal(await readFile(join(tmp.dir, '.hub', 'local.yml'), 'utf8'), 'acme: [broken\n');
  assert.equal(await exists(join(tmp.dir, 'ledger.format')), false);
  assert.ok(ledger.warnings.has(ledger.paths.localYml));
});
