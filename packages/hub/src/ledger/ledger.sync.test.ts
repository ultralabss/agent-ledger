/** F3b B3b: `Ledger` side of the sync APPLY — targeted `reindexPaths`, constructor wiring of the marker and the
 *  signing identity, and the lock-order source scan (docs/f3b-b3-plan.md §1.7, §3). */

import assert from 'node:assert/strict';
import { chmod, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, resolveSshKeygen } from '@agent-ledger/shared';
import { git } from '../git.ts';
import { verifyCommitSignature } from '../sync/sigverify.ts';
import { tempConfig } from '../test-helpers.ts';
import { Ledger } from './ledger.ts';

const posix = process.platform !== 'win32';
const skip = posix ? false : 'POSIX only';

const base = {
  kind: 'BACKLOG',
  priority: 'P2',
  owner: 'agent',
  steps: [] as string[],
  blocked_by: [] as string[],
  aliases: [] as string[],
  proposed: false,
};

async function open(sync = false): Promise<{ ledger: Ledger; dir: string; logs: string[]; cleanup: () => Promise<void> }> {
  const tmp = await tempConfig({ sync });
  const logs: string[] = [];
  const ledger = new Ledger({ config: tmp.config, log: (l) => logs.push(l) });
  await ledger.init();
  await git(tmp.dir, ['config', 'user.email', 'test@agent-ledger.local']);
  await git(tmp.dir, ['config', 'user.name', 'agent-ledger test']);
  await git(tmp.dir, ['config', 'commit.gpgsign', 'false']);
  return {
    ledger,
    dir: tmp.dir,
    logs,
    cleanup: async () => {
      await ledger.close().catch(() => undefined);
      await tmp.cleanup();
    },
  };
}

const titleOf = (l: Ledger, id: string): string => l.getItem(id).item.fm.title;
const run = <T>(l: Ledger, fn: () => Promise<T>): Promise<T> => l.queue.run(fn);
const rel = (id: string): string => `ops/items/${id}.md`;

/* ---------------- paths ---------------- */

test('paths: syncDir and the APPLY marker live under .hub/ (local, never synced)', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const p = fx.ledger.paths;
  assert.equal(p.syncDir, join(p.root, '.hub', 'sync'));
  assert.equal(p.inflightMarker, join(p.root, '.hub', 'sync', 'inflight.json'));
});

/* ---------------- reindexPaths ---------------- */

test('reindexPaths picks up a rewritten item although the content-hash skip would not (P-4)', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const { ledger } = fx;
  const item = await ledger.createItem({ ...base, repo: 'ops', title: 'one' });
  const id = item.fm.id;
  const file = ledger.paths.itemFile('ops', id);
  const t1 = await readFile(file);
  await run(ledger, () => ledger.reindex()); // remembers the hash of t1
  await ledger.patchItem(id, { title: 'two' }); // index + file now t2
  await writeFile(file, t1); // a remote revert back to the exact bytes the hash was taken from

  await run(ledger, () => ledger.reindex());
  assert.equal(titleOf(ledger, id), 'two', 'the 60 s backstop skips it: stale record (the problem)');

  await run(ledger, () => ledger.reindexPaths([rel(id)]));
  assert.equal(titleOf(ledger, id), 'one', 'reindexPaths re-reads the changed file');
});

test('reindexPaths: an unparseable item is DROPPED (backstop keeps the last good one); a later mutation is notFound', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const { ledger } = fx;
  const a = (await ledger.createItem({ ...base, repo: 'ops', title: 'backstop' })).fm.id;
  const b = (await ledger.createItem({ ...base, repo: 'ops', title: 'strict' })).fm.id;
  const garbage = '---\nid: [unterminated\n  : : :\n---\nbody\n';

  await writeFile(ledger.paths.itemFile('ops', a), garbage);
  await run(ledger, () => ledger.reindex());
  assert.equal(titleOf(ledger, a), 'backstop', 'unchanged: the 60 s backstop keeps the last good version');

  await writeFile(ledger.paths.itemFile('ops', b), garbage);
  await run(ledger, () => ledger.reindexPaths([rel(b)]));
  assert.throws(() => ledger.getItem(b), { status: 404 });
  await assert.rejects(ledger.patchItem(b, { title: 'would overwrite remote work' }), { status: 404 });
  assert.ok(ledger.warnings.has(ledger.paths.itemFile('ops', b)), 'surfaced in healthz warnings');
  assert.ok(fx.logs.some((l) => /no longer parses after a sync apply/.test(l)));
  // the unparseable bytes were not rewritten by anything
  assert.equal(await readFile(ledger.paths.itemFile('ops', b), 'utf8'), garbage);

  // the backstop does not resurrect it (hash already seen) and does not touch the other one
  await run(ledger, () => ledger.reindex());
  assert.throws(() => ledger.getItem(b), { status: 404 });
  assert.equal(titleOf(ledger, a), 'backstop');
});

test('reindexPaths: an item file deleted by the apply leaves the index', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const { ledger } = fx;
  const id = (await ledger.createItem({ ...base, repo: 'ops', title: 'gone' })).fm.id;
  await rm(ledger.paths.itemFile('ops', id));
  await run(ledger, () => ledger.reindexPaths([rel(id)]));
  assert.throws(() => ledger.getItem(id), { status: 404 });
});

test('reindexPaths: repos.yml reload; counters reload never decreases the counter; other devices ignored', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const { ledger } = fx;
  const first = (await ledger.createItem({ ...base, repo: 'ops', title: 'n1' })).fm.id;
  const num = (id: string): number => Number(/(\d+)$/.exec(id)?.[1]);

  await writeFile(ledger.paths.reposYml, 'ops:\n  kind: system\n  prefix: OPS\nzzz:\n  prefix: ZZZ\n');
  assert.equal(ledger.repos().zzz, undefined);
  await run(ledger, () => ledger.reindexPaths(['repos.yml']));
  assert.equal(ledger.repos().zzz?.prefix, 'ZZZ');

  const own = `counters/${ledger.device.device_id}.yml`;
  await writeFile(join(ledger.paths.root, own), 'ops: 0\n'); // reset under a running hub
  await run(ledger, () => ledger.reindexPaths([own, 'counters/d_aaaaaaaaaa.yml']));
  const second = (await ledger.createItem({ ...base, repo: 'ops', title: 'n2' })).fm.id;
  assert.ok(num(second) > num(first), `counter must not go backwards (${first} → ${second})`);

  await writeFile(join(ledger.paths.root, own), 'ops: 500\n'); // a merge raised it
  await run(ledger, () => ledger.reindexPaths([own]));
  const third = (await ledger.createItem({ ...base, repo: 'ops', title: 'n3' })).fm.id;
  assert.ok(num(third) > 500, `a higher on-disk counter is honoured (${third})`);
});

test('reindexPaths: a new slug directory (items, journal, decisions) arrives and is indexed; onReindex fires', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const { ledger } = fx;
  const id = (await ledger.createItem({ ...base, repo: 'ops', title: 'moves' })).fm.id;
  let reindexed = 0;
  ledger.onReindex = () => {
    reindexed += 1;
  };
  await run(ledger, () => ledger.reindexPaths(['ops/journal/2026-11.md', 'ops/DECISIONS.md', rel(id)]));
  assert.equal(reindexed, 1);
  assert.equal(titleOf(ledger, id), 'moves');
});

test('reindexPaths: hostile / malformed paths are ignored without throwing or touching anything', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const { ledger } = fx;
  const id = (await ledger.createItem({ ...base, repo: 'ops', title: 'safe' })).fm.id;
  await run(ledger, () =>
    ledger.reindexPaths([
      '',
      '/etc/passwd',
      '../outside/items/x.md',
      'ops/items/../../escape',
      '.hub/token',
      '.hub/sync/inflight.json',
      'ops\\items\\x.md',
      'ops/items/a\0b.md',
      '..',
      'Not A Slug/items/x.md',
    ]),
  );
  assert.equal(titleOf(ledger, id), 'safe');
});

test('reindexPaths is entered with the queue held and never takes it (runs inside queue.run without deadlock)', async (t) => {
  const fx = await open();
  t.after(fx.cleanup);
  const done = run(fx.ledger, () => fx.ledger.reindexPaths([]));
  const timeout = new Promise<string>((r) => setTimeout(() => r('deadlock'), 5_000));
  assert.notEqual(await Promise.race([done.then(() => 'ok'), timeout]), 'deadlock');
});

/* ---------------- constructor wiring ---------------- */

test('the APPLY marker pauses ledger commits (sync off too)', { skip }, async (t) => {
  const fx = await open(false);
  t.after(fx.cleanup);
  const { ledger } = fx;
  await ledger.git.flush();
  const before = (await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim();
  await ledger.createItem({ ...base, repo: 'ops', title: 'during apply' });
  await mkdir(ledger.paths.syncDir, { recursive: true, mode: 0o700 }); // the apply creates it before the marker
  await writeFile(ledger.paths.inflightMarker, '{}');
  await ledger.git.flush();
  assert.equal((await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim(), before, 'no commit while marked');
  await rm(ledger.paths.inflightMarker);
  await ledger.git.flush();
  assert.notEqual((await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim(), before);
});

test('sync on, not enrolled (no devices.yml, no key): commits as before', { skip }, async (t) => {
  const fx = await open(true);
  t.after(fx.cleanup);
  await fx.ledger.createItem({ ...base, repo: 'ops', title: 'plain' });
  await fx.ledger.git.flush();
  const raw = (await git(fx.dir, ['cat-file', 'commit', 'HEAD'])).stdout;
  assert.doesNotMatch(raw, /gpgsig/);
});

test('sync on + device key: the ledger commits signed by this device', { skip }, async (t) => {
  const fx = await open(true);
  t.after(fx.cleanup);
  const { ledger } = fx;
  const keyDir = join(ledger.paths.hubDir, 'device');
  await mkdir(keyDir, { recursive: true, mode: 0o700 });
  await chmod(keyDir, 0o700);
  await generateKeyPair(join(keyDir, 'key'), await resolveSshKeygen());
  await ledger.createItem({ ...base, repo: 'ops', title: 'signed' });
  await ledger.git.flush();
  const raw = Buffer.from((await git(fx.dir, ['cat-file', 'commit', 'HEAD'])).stdout, 'utf8');
  const v = await verifyCommitSignature(raw, { tmpRoot: ledger.paths.syncDir });
  assert.equal(v.valid, true, v.reason);
  const email = (await git(fx.dir, ['log', '-1', '--format=%ce'])).stdout.trim();
  assert.equal(email, `${ledger.device.device_id}@devices.agent-ledger.invalid`);
});

test('sync on + devices.yml but the key is GONE: the commit is refused, never made unsigned', { skip }, async (t) => {
  const fx = await open(true);
  t.after(fx.cleanup);
  const { ledger } = fx;
  await ledger.git.flush();
  const before = (await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim();
  await writeFile(join(ledger.paths.root, 'devices.yml'), '# enrolled once\n');
  await ledger.createItem({ ...base, repo: 'ops', title: 'must not go out unsigned' });
  await ledger.git.flush();
  assert.equal((await git(fx.dir, ['rev-parse', 'HEAD'])).stdout.trim(), before);
  assert.ok(fx.logs.some((l) => /git commit failed/.test(l)), 'refused by the signing step, not skipped');
});

test('sync off: commits stay unsigned even when a device key exists', { skip }, async (t) => {
  const fx = await open(false);
  t.after(fx.cleanup);
  const { ledger } = fx;
  const keyDir = join(ledger.paths.hubDir, 'device');
  await mkdir(keyDir, { recursive: true, mode: 0o700 });
  await chmod(keyDir, 0o700);
  await generateKeyPair(join(keyDir, 'key'), await resolveSshKeygen());
  await ledger.createItem({ ...base, repo: 'ops', title: 'local only' });
  await ledger.git.flush();
  assert.doesNotMatch((await git(fx.dir, ['cat-file', 'commit', 'HEAD'])).stdout, /gpgsig/);
});

/* ---------------- lock order: nothing inside queue.run awaits the git chain (§3 rule 1) ---------------- */

/** Bodies of every `queue.run(` call in `src` (naive but string/comment aware paren matching). */
function queueRunBodies(src: string): string[] {
  const out: string[] = [];
  const needle = 'queue.run(';
  let from = 0;
  for (;;) {
    const at = src.indexOf(needle, from);
    if (at < 0) return out;
    let i = at + needle.length;
    const start = i;
    let depth = 1;
    while (i < src.length && depth > 0) {
      const c = src[i] as string;
      const n = src[i + 1];
      if (c === '/' && n === '/') i = src.indexOf('\n', i) < 0 ? src.length : src.indexOf('\n', i);
      else if (c === '/' && n === '*') i = src.indexOf('*/', i + 2) < 0 ? src.length : src.indexOf('*/', i + 2) + 1;
      else if (c === "'" || c === '"' || c === '`') {
        i += 1;
        while (i < src.length && src[i] !== c) i += src[i] === '\\' ? 2 : 1;
      } else if (c === '(') depth += 1;
      else if (c === ')') depth -= 1;
      i += 1;
    }
    out.push(src.slice(start, i));
    from = start;
  }
}

const FORBIDDEN = /\.(?:flush|runExclusive|retrySecurityHold)\s*\(|\bgit\.close\s*\(|\bledger\.close\s*\(/;

test('scan helper: finds queue bodies and flags a flush inside one', () => {
  const bad = "async f() { return this.queue.run(async () => { await this.git.flush(); }); }\nasync g() { await this.git.flush(); }";
  const bodies = queueRunBodies(bad);
  assert.equal(bodies.length, 1);
  assert.match(bodies[0] as string, FORBIDDEN);
  const ok = "x = this.queue.run(() => this.reindex()); // flush() in a comment\n";
  assert.doesNotMatch(queueRunBodies(ok).join('\n'), FORBIDDEN);
});

test('source scan: no queue.run body in hub/src calls flush/runExclusive/close (lock order R -> Q only)', async () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const files: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.name.endsWith('.ts') && !e.name.endsWith('.test.ts') && e.name !== 'testkit-remote.ts') files.push(p);
    }
  };
  await walk(root);
  assert.ok(files.length > 20, 'scan found the sources');
  let bodies = 0;
  for (const f of files) {
    for (const body of queueRunBodies(await readFile(f, 'utf8'))) {
      bodies += 1;
      assert.doesNotMatch(body, FORBIDDEN, `${f}: a queue.run body awaits the commit chain (deadlock with runExclusive)`);
    }
  }
  assert.ok(bodies > 10, 'scan saw the queue bodies');
  await stat(root);
});
