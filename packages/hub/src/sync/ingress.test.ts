/** F3a ingress validation (docs/multi-device-spec.md §7.3, §4.3; T13, T14, T15). Pure: no git, no fs. */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  itemFrontmatterSchema,
  newItemDoc,
  parseEd25519Pub,
  renderDevicesYaml,
  serializeIntake,
  serializeMd,
} from '@agent-ledger/shared';
import {
  claimGlobProblem,
  validateIncoming,
  windowsNameProblem,
  type IncomingChange,
  type IngressRule,
} from './ingress.ts';

function blob(path: string, content: string | Uint8Array, over: Partial<IncomingChange> = {}): IncomingChange {
  const size = typeof content === 'string' ? Buffer.byteLength(content, 'utf8') : content.byteLength;
  return { path, mode: '100644', type: 'blob', size, content, ...over };
}

function itemMd(id: string, repo: string, extra: Record<string, unknown> = {}): string {
  const fm = itemFrontmatterSchema.parse({
    id,
    title: 'a title',
    status: 'open',
    kind: 'BACKLOG',
    priority: 'P2',
    owner: 'agent',
    repo,
    created: '2026-11-16T10:00:00.000Z',
    updated: '2026-11-16T10:00:00.000Z',
    ...extra,
  });
  return serializeMd(newItemDoc(fm as never));
}

const WIRE = Buffer.from([0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), 0, 0, 0, 32]);
function devicesYml(): string {
  const pub = `ssh-ed25519 ${Buffer.concat([WIRE, randomBytes(32)]).toString('base64')}`;
  const id = parseEd25519Pub(pub)?.deviceId as string;
  return renderDevicesYaml({
    devices: [
      { id, label: 'mac', slot: '', pubkey: pub, added: '2026-11-16T10:00:00.000Z', added_by: id, revoked: null, role: 'owner' },
    ],
  });
}

const ROOT_SHA = 'a'.repeat(40);
const REPOS = `acme:\n  prefix: ACME\n  identity:\n    root_sha: ${ROOT_SHA}\n    origin_hint: github.com/acme/app\n`;
const GOOD_DEV = 'abcdefgh23';

/** A realistic, fully valid push. */
function goodPush(): IncomingChange[] {
  return [
    blob('repos.yml', REPOS),
    blob('devices.yml', devicesYml()),
    blob(`counters/d_${GOOD_DEV}.yml`, 'acme: 12\n'),
    blob('ledger.format', '2\n'),
    blob('.gitignore', '.hub/\n*.tmp\n'),
    blob('.gitattributes', '* text eol=lf\n'),
    blob('acme/CONTEXT.md', '# acme\n'),
    blob('acme/DECISIONS.md', '# decisions\n'),
    blob('acme/items/ACME-12.md', itemMd('ACME-12', 'acme', { paths: ['packages/hub/**', 'docs/*.md'] })),
    blob('acme/items/ACME-W3.md', itemMd('ACME-W3', 'acme')),
    blob('acme/journal/2026-11.md', '# acme — journal 2026-11\n'),
    blob(
      'intake/2026-11/1789130426000123.md',
      serializeIntake({
        id: '1789130426000123',
        at: '2026-11-16T10:00:00.000Z',
        channel: 'chat',
        session: null,
        repo_hint: 'acme',
        status: 'new',
        items: [],
        text: 'do a thing',
        triage: [],
        dropped: [],
      }),
    ),
  ];
}

function rulesOf(changes: IncomingChange[], opts = {}): Map<string, IngressRule> {
  const res = validateIncoming(changes, opts);
  return new Map(res.rejected.map((r) => [r.path, r.rule]));
}

test('a realistic valid push is accepted in full', () => {
  const push = goodPush();
  const res = validateIncoming(push);
  assert.deepEqual(res.rejected, []);
  assert.deepEqual(res.accepted.sort(), push.map((c) => c.path).sort());
});

/* ---------------- T14: paths ---------------- */

test('T14: traversal, absolute, drive and UNC paths are rejected', () => {
  const bad = [
    '../escape.md',
    'acme/../../x.md',
    'acme/items/../../../x.md',
    '/etc/passwd',
    'C:\\Windows\\x.md',
    'C:/x.md',
    '\\\\server\\share\\x.md',
    'acme\\items\\ACME-1.md',
    'acme//CONTEXT.md',
    './repos.yml',
    'acme/./CONTEXT.md',
    'acme/CONTEXT.md/',
    '',
    'acme/CONTEXT\u0000.md',
    'acme/CONT\nEXT.md',
    `acme/${'a'.repeat(600)}.md`,
  ];
  const rules = rulesOf(bad.map((p) => blob(p, 'x\n')));
  assert.equal(rules.size, bad.length - 0, 'every path has its own verdict');
  for (const r of rules.values()) assert.equal(r, 'path-invalid');
  assert.deepEqual(validateIncoming(bad.map((p) => blob(p, 'x\n'))).accepted, []);
});

test('T14: Windows-invalid names (reserved, trailing dot/space, ADS, 8.3, bad chars)', () => {
  const bad = [
    'acme/items/CON.md',
    'con/CONTEXT.md',
    'acme/journal/NUL.md',
    'prn/CONTEXT.md',
    'aux.x/CONTEXT.md',
    'com1/CONTEXT.md',
    'lpt9/CONTEXT.md',
    'acme/CONTEXT.md.',
    'acme/CONTEXT.md ',
    'acme/CONTEXT.md:stream',
    'acme/CONTEXT.md::$DATA',
    'acme/items/ACME-1~1.md',
    'PROGRA~1/CONTEXT.md',
    'acme/CON*TEXT.md',
    'acme/CONTEXT?.md',
    'acme/"x".md',
  ];
  const rules = rulesOf(bad.map((p) => blob(p, 'x\n')));
  for (const p of bad) assert.equal(rules.get(p), 'windows-name', p);
  assert.equal(windowsNameProblem('CONTEXT.md'), false, 'CONTEXT is not CON');
  assert.equal(windowsNameProblem('console-log'), false);
  assert.equal(windowsNameProblem('ACME-12.md'), false);
});

test('T14: other .git* names are rejected, root .gitignore/.gitattributes are allowed', () => {
  const bad = ['.git/config', '.gitmodules', 'acme/.gitignore', 'acme/.gitattributes', '.GIT/hooks/pre-commit', 'acme/items/.gitkeep'];
  const rules = rulesOf(bad.map((p) => blob(p, 'x\n')));
  for (const p of bad) assert.equal(rules.get(p), 'git-name', p);
  assert.equal(validateIncoming([blob('.gitignore', '.hub/\n*.tmp\n')]).rejected.length, 0);
});

test('T14: layout allowlist — anything not named is rejected (fail-closed)', () => {
  const bad = [
    'README.md',
    'acme/notes.md',
    'acme/items/acme-1.md',
    'acme/items/ACME-0.md',
    'acme/items/ACME-12.txt',
    'acme/items/sub/ACME-12.md',
    'acme/journal/2026-13.md',
    'acme/journal/2026-1.md',
    'acme/journal/2026-11.md.bak',
    'ACME/CONTEXT.md',
    'a_b/CONTEXT.md',
    'counters/CONTEXT.md',
    'counters/d_short.yml',
    'counters/d_abcdefghij.yml', // i, j are not base32
    'counters/nested/d_abcdefgh23.yml',
    'intake/CONTEXT.md',
    'intake/2026-11/abc.md',
    'intake/2026-11/0123.md',
    'intake/2026-13/123.md',
    '.hub/token',
    '.hub/device.yml',
    'extra.yml',
    'devices.yaml',
    'acme/\u00e9.md',
    'acme/CONTEXT\u202e.md',
  ];
  const rules = rulesOf(bad.map((p) => blob(p, 'x\n')));
  for (const p of bad) assert.ok(rules.has(p.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202e]/g, '?')), `rejected: ${p}`);
  assert.deepEqual(validateIncoming(bad.map((p) => blob(p, 'x\n'))).accepted, []);
});

test('T14: symlink, submodule, exec bit, odd modes and types are rejected', () => {
  const rules = rulesOf([
    blob('acme/CONTEXT.md', '../../etc/passwd', { mode: '120000' }),
    blob('acme/DECISIONS.md', 'x\n', { mode: '100755' }),
    blob('acme/journal/2026-11.md', 'x\n', { mode: '100664' }),
    blob('acme/items/ACME-1.md', '', { mode: '160000', type: 'commit' }),
    blob('repos.yml', 'x\n', { mode: '040000', type: 'tree' }),
    blob('devices.yml', 'x\n', { mode: '100644', type: 'tree' }),
    blob('ledger.format', '2\n', { mode: 'oops' }),
  ]);
  assert.equal(rules.get('acme/CONTEXT.md'), 'symlink');
  assert.equal(rules.get('acme/DECISIONS.md'), 'exec');
  assert.equal(rules.get('acme/journal/2026-11.md'), 'mode');
  assert.equal(rules.get('acme/items/ACME-1.md'), 'submodule');
  assert.equal(rules.get('repos.yml'), 'mode');
  assert.equal(rules.get('devices.yml'), 'type');
  assert.equal(rules.get('ledger.format'), 'mode');
});

test('T14: case-insensitive collisions reject every spelling (files, directories, existing tree)', () => {
  // An uppercase twin never gets past the layout allowlist in the first place.
  const a = validateIncoming([blob('acme/CONTEXT.md', 'x\n'), blob('Acme/CONTEXT.md', 'y\n')]);
  assert.deepEqual(a.rejected, [{ path: 'Acme/CONTEXT.md', rule: 'layout' }]);
  const b = validateIncoming(
    [blob('acme/items/ACME-1.md', itemMd('ACME-1', 'acme')), blob('acme/items/ACME-2.md', itemMd('ACME-2', 'acme'))],
    { existingPaths: ['ACME/items/ACME-1.md'] },
  );
  assert.equal(b.rejected.find((r) => r.path === 'acme/items/ACME-1.md')?.rule, 'case-collision');
  assert.equal(b.rejected.find((r) => r.path === 'acme/items/ACME-2.md')?.rule, 'case-collision', 'shared directory spelling clashes too');
  assert.deepEqual(b.accepted, []);
  // case-only twin of an existing file
  const c = validateIncoming([blob('acme/CONTEXT.md', 'x\n')], { existingPaths: ['acme/context.md'] });
  assert.equal(c.rejected[0]?.rule, 'case-collision');
  // same path re-sent exactly as it exists is fine (an edit)
  assert.deepEqual(validateIncoming([blob('acme/CONTEXT.md', 'x\n')], { existingPaths: ['acme/CONTEXT.md'] }).rejected, []);
  // order independent
  const d = validateIncoming([blob('acme/journal/2026-11.md', 'a\n'), blob('acme/journal/2026-11.MD', 'b\n')]);
  assert.deepEqual(d.accepted, ['acme/journal/2026-11.md']);
  assert.deepEqual(d.rejected, [{ path: 'acme/journal/2026-11.MD', rule: 'layout' }]);
  // a directory-level twin of an existing tree is a collision for everything below it
  const e = validateIncoming([blob('acme/journal/2026-11.md', 'a\n')], { existingPaths: ['ACME/journal/2026-10.md'] });
  assert.equal(e.rejected[0]?.rule, 'case-collision');
});

test('duplicate paths in one push are rejected', () => {
  const res = validateIncoming([blob('acme/CONTEXT.md', 'a\n'), blob('acme/CONTEXT.md', 'b\n')]);
  assert.deepEqual(res.accepted, []);
  assert.equal(res.rejected[0]?.rule, 'duplicate');
});

/* ---------------- sizes ---------------- */

test('size: 256 KB per file, 5 MB per push, declared size must match, no content = rejected', () => {
  const big = 'x'.repeat(256 * 1024 + 1);
  assert.equal(rulesOf([blob('acme/CONTEXT.md', big)]).get('acme/CONTEXT.md'), 'size');
  assert.deepEqual(validateIncoming([blob('acme/CONTEXT.md', 'x'.repeat(256 * 1024))]).rejected, []);
  assert.equal(rulesOf([blob('acme/CONTEXT.md', 'abc\n', { size: 1 })]).get('acme/CONTEXT.md'), 'size');
  assert.equal(rulesOf([blob('acme/CONTEXT.md', 'abc\n', { size: -1 })]).get('acme/CONTEXT.md'), 'size');
  assert.equal(rulesOf([blob('acme/CONTEXT.md', 'abc\n', { size: Number.NaN })]).get('acme/CONTEXT.md'), 'size');
  const noContent: IncomingChange = { path: 'acme/CONTEXT.md', mode: '100644', type: 'blob', size: 4 };
  assert.equal(rulesOf([noContent]).get('acme/CONTEXT.md'), 'content-missing');

  const chunk = 'y'.repeat(200 * 1024);
  const push = Array.from({ length: 30 }, (_, i) => blob(`s${i}/CONTEXT.md`, chunk));
  const res = validateIncoming(push);
  assert.deepEqual(res.accepted, []);
  assert.deepEqual(res.rejected, [{ path: '(push)', rule: 'push-size' }]);
  assert.deepEqual(validateIncoming([blob('a/CONTEXT.md', 'ab'), blob('b/CONTEXT.md', 'cd')], { maxPushBytes: 3 }).rejected, [
    { path: '(push)', rule: 'push-size' },
  ]);
  assert.deepEqual(
    validateIncoming([blob('a/CONTEXT.md', 'ab'), blob('b/CONTEXT.md', 'cd')], { maxChanges: 1 }).rejected,
    [{ path: '(push)', rule: 'push-count' }],
  );
});

test('encoding: NUL bytes and invalid UTF-8 are rejected, valid bytes accepted', () => {
  assert.equal(rulesOf([blob('acme/CONTEXT.md', 'a\u0000b\n')]).get('acme/CONTEXT.md'), 'encoding');
  assert.equal(rulesOf([blob('acme/CONTEXT.md', new Uint8Array([0x61, 0xff, 0xfe]))]).get('acme/CONTEXT.md'), 'encoding');
  assert.deepEqual(validateIncoming([blob('acme/CONTEXT.md', new TextEncoder().encode('ok \u00e9\n'))]).rejected, []);
});

test('malformed entries are rejected, never thrown on', () => {
  const res = validateIncoming([null, 7, { path: 1 }, blob('acme/CONTEXT.md', 'x\n')] as unknown[]);
  assert.deepEqual(res.accepted, ['acme/CONTEXT.md']);
  assert.equal(res.rejected.filter((r) => r.rule === 'malformed').length, 3);
  assert.equal(validateIncoming('nope' as unknown as unknown[]).rejected[0]?.rule, 'malformed');
});

/* ---------------- T15: .gitattributes, format ---------------- */

test('T15: .gitattributes must be exactly `* text eol=lf`; merge=/filter=/diff= are drivers', () => {
  assert.deepEqual(validateIncoming([blob('.gitattributes', '* text eol=lf\n')]).rejected, []);
  const drivers = [
    '* text eol=lf\n*.md merge=union\n',
    '* text eol=lf\n* filter=evil\n',
    '* text eol=lf\n*.md diff=textconv\n',
    '* merge=ours\n',
    '* text eol=lf\n*.md -diff\n',
    '* text eol=lf\n* !merge\n',
    '*.md FILTER=lfs\n',
  ];
  for (const text of drivers) {
    assert.equal(rulesOf([blob('.gitattributes', text)]).get('.gitattributes'), 'gitattributes-driver', JSON.stringify(text));
  }
  for (const text of ['', '* -text\n', '* text eol=lf', '* text eol=lf\r\n', '* text eol=lf\n\n', '* text=auto\n', '* text eol=lf\n*.png binary\n']) {
    assert.equal(rulesOf([blob('.gitattributes', text)]).get('.gitattributes'), 'gitattributes', JSON.stringify(text));
  }
});

test('ledger.format: `<n>\\n`, n within the supported format', () => {
  assert.deepEqual(validateIncoming([blob('ledger.format', '2\n')]).rejected, []);
  assert.deepEqual(validateIncoming([blob('ledger.format', '1\n')]).rejected, []);
  for (const text of ['3\n', '2', '2\n\n', ' 2\n', '0\n', 'two\n', '', '02x\n', '9999999\n']) {
    assert.equal(rulesOf([blob('ledger.format', text)]).get('ledger.format'), 'format', JSON.stringify(text));
  }
  assert.deepEqual(validateIncoming([blob('ledger.format', '3\n')], { maxFormat: 3 }).rejected, []);
});

/* ---------------- T13: secrets ---------------- */

test('T13: a secret in any synced file is rejected, and the verdict never repeats it', () => {
  const secret = `ghp_${'A1b2C3d4E5f6G7h8I9j0'}KLMNOPqrst`;
  const files = ['acme/CONTEXT.md', 'acme/DECISIONS.md', 'acme/journal/2026-11.md', '.gitignore'];
  const res = validateIncoming(files.map((p) => blob(p, `token here: ${secret}\n`)));
  assert.deepEqual(res.accepted, []);
  assert.deepEqual(new Set(res.rejected.map((r) => r.rule)), new Set(['secret']));
  assert.equal(JSON.stringify(res).includes(secret), false, 'content never in the verdict');
  // inside an item body
  const item = itemMd('ACME-5', 'acme') + `\npassword = "hunter2hunter2"\n`;
  assert.equal(rulesOf([blob('acme/items/ACME-5.md', item)]).get('acme/items/ACME-5.md'), 'secret');
  // PEM header
  assert.equal(rulesOf([blob('acme/CONTEXT.md', '-----BEGIN OPENSSH PRIVATE KEY-----\n')]).get('acme/CONTEXT.md'), 'secret');
});

test('T13: a scanner that throws fails closed; a custom scanner is honoured', () => {
  const boom = rulesOf([blob('acme/CONTEXT.md', 'x\n')], {
    scan: () => {
      throw new Error('scanner down');
    },
  });
  assert.equal(boom.get('acme/CONTEXT.md'), 'secret');
  const custom = rulesOf([blob('acme/CONTEXT.md', 'forbidden-word\n')], { scan: (t: string) => (t.includes('forbidden') ? [1] : []) });
  assert.equal(custom.get('acme/CONTEXT.md'), 'secret');
});

/* ---------------- schema / frontmatter ---------------- */

test('yml files: schema violations and smuggled local paths are rejected', () => {
  const bad: [string, string][] = [
    ['repos.yml', 'acme: [oops\n'],
    ['repos.yml', 'acme:\n  prefix: acme\n'],
    ['repos.yml', 'acme:\n  prefix: ACME\n  path: /home/me/acme\n'],
    ['repos.yml', 'acme:\n  prefix: ACME\n  next: 9\n'],
    ['repos.yml', 'acme:\n  prefix: ACME\n  graphify: /home/me/g\n'],
    ['repos.yml', 'acme:\n  prefix: ACME\n  docs:\n    - /etc/passwd\n'],
    ['repos.yml', 'acme:\n  prefix: ACME\n  docs:\n    - ../../secret.md\n'],
    ['repos.yml', 'acme:\n  prefix: ACME\n  docs:\n    - C:\\x\\y.md\n'],
    ['repos.yml', 'a: &x {prefix: ACME}\nb: *x\n'],
    ['devices.yml', 'devices: nope\n'],
    ['devices.yml', 'devices:\n  - id: d_aaaaaaaaaa\n'],
    ['counters/d_abcdefgh23.yml', 'acme: -1\n'],
    ['counters/d_abcdefgh23.yml', 'acme: 99999999999\n'],
    ['counters/d_abcdefgh23.yml', 'acme: "7"\n'],
    ['counters/d_abcdefgh23.yml', ''],
    ['counters/d_abcdefgh23.yml', '# nothing\n'],
    ['counters/d_abcdefgh23.yml', '- 1\n- 2\n'],
  ];
  for (const [path, text] of bad) {
    assert.equal(rulesOf([blob(path, text)]).get(path), 'schema', `${path}: ${JSON.stringify(text)}`);
  }
  assert.deepEqual(validateIncoming([blob('counters/d_abcdefgh23.yml', '{}\n')]).rejected, []);
});

test('items: frontmatter schema, id/repo must match the path, claim globs validated', () => {
  const rules = rulesOf([
    blob('acme/items/ACME-1.md', 'no frontmatter at all\n'),
    blob('acme/items/ACME-2.md', itemMd('ACME-3', 'acme')), // id != file name
    blob('acme/items/ACME-4.md', itemMd('ACME-4', 'other')), // repo != dir
    blob('acme/items/ACME-5.md', itemMd('ACME-5', 'acme').replace('status: open', 'status: hacked')),
    blob('acme/items/ACME-6.md', '---\nid: ACME-6\n'), // unclosed
    blob('acme/items/ACME-7.md', itemMd('ACME-7', 'acme', { paths: ['../../etc/passwd'] })),
    blob('acme/items/ACME-8.md', itemMd('ACME-8', 'acme', { paths: ['/abs/**'] })),
    blob('acme/items/ACME-9.md', itemMd('ACME-9', 'acme', { paths: ['C:/x/**'] })),
    blob('acme/items/ACME-10.md', itemMd('ACME-10', 'acme', { paths: ['a\\b'] })),
    blob('acme/items/ACME-11.md', itemMd('ACME-11', 'acme', { paths: Array.from({ length: 33 }, (_, i) => `p${i}/**`) })),
    blob('acme/items/ACME-12.md', itemMd('ACME-12', 'acme', { paths: [`${'a/'.repeat(130)}x`] })),
    blob('acme/items/ACME-13.md', itemMd('ACME-13', 'acme', { paths: Array.from({ length: 32 }, (_, i) => `p${i}/**`) })),
  ]);
  assert.equal(rules.get('acme/items/ACME-1.md'), 'frontmatter');
  assert.equal(rules.get('acme/items/ACME-2.md'), 'frontmatter');
  assert.equal(rules.get('acme/items/ACME-4.md'), 'frontmatter');
  assert.equal(rules.get('acme/items/ACME-5.md'), 'frontmatter');
  assert.equal(rules.get('acme/items/ACME-6.md'), 'frontmatter');
  for (const n of [7, 8, 9, 10, 11, 12]) assert.equal(rules.get(`acme/items/ACME-${n}.md`), 'claim-glob', `ACME-${n}`);
  assert.equal(rules.has('acme/items/ACME-13.md'), false, '32 globs is the limit');
});

const del = (path: string): IncomingChange => ({ path, mode: '000000', type: '', size: 0, deleted: true });

test('items are never deleted (soft `delete`); unknown paths follow the layout allowlist', () => {
  const rules = rulesOf([del('acme/items/ACME-1.md'), del('../x'), del('README.md')]);
  assert.equal(rules.get('acme/items/ACME-1.md'), 'delete');
  assert.equal(rules.get('../x'), 'path-invalid');
  assert.equal(rules.get('README.md'), 'layout');
});

test('F-3: deleting ANY non-item file is a hard `delete-protected` rejection (devices.yml = trust-root reset)', () => {
  const paths = [
    'devices.yml',
    'ledger.format',
    '.gitattributes',
    '.gitignore',
    'repos.yml',
    `counters/d_${GOOD_DEV}.yml`,
    'acme/CONTEXT.md',
    'acme/DECISIONS.md',
    'acme/journal/2026-11.md',
    'intake/2026-11/1789130426000123.md',
  ];
  const res = validateIncoming(paths.map(del));
  assert.deepEqual(res.accepted, []);
  assert.equal(res.rejected.length, paths.length);
  for (const r of res.rejected) assert.equal(r.rule, 'delete-protected', r.path);
  // mixed with an item delete: each keeps its own rule so the caller can tell soft from hard
  const mixed = rulesOf([del('devices.yml'), del('acme/items/ACME-1.md')]);
  assert.equal(mixed.get('devices.yml'), 'delete-protected');
  assert.equal(mixed.get('acme/items/ACME-1.md'), 'delete');
});

test('F-2: `.hub/**` is rejected (rule hub-path) in every spelling, for writes and deletes', () => {
  const bad = [
    '.hub/token',
    '.hub/device/key',
    '.HUB/device/key',
    '.Hub/x.md',
    '.hub',
    '.hub./token', // trailing dot alias (Windows)
    '.hub /token', // trailing space alias
    'acme/.hub/x',
    'acme/items/.HUB/ACME-1.md',
  ];
  const changes = bad.map((p) => blob(p, 'x\n'));
  const rules = rulesOf(changes);
  for (const p of bad) assert.equal(rules.get(p), 'hub-path', p);
  const res = validateIncoming([...bad.map(del), ...goodPush()]);
  assert.deepEqual(new Set(res.rejected.map((r) => r.rule)), new Set(['hub-path']));
  assert.equal(res.accepted.length, goodPush().length, 'rest of a valid push unaffected');
  // look-alikes are not `.hub`
  for (const p of ['.hubx/a', 'hub/a', 'acme/hub.md']) {
    assert.notEqual(rulesOf([blob(p, 'x\n')]).get(p), 'hub-path', p);
  }
});

test('F-2: `.gitignore` is pinned byte-exact (a missing `.hub/` line is the token-leak vector)', () => {
  assert.deepEqual(validateIncoming([blob('.gitignore', '.hub/\n*.tmp\n')]).rejected, []);
  for (const text of [
    '',
    '*.tmp\n',
    '.hub/\n',
    '*.tmp\n.hub/\n',
    '.hub/\n*.tmp',
    '.hub/\r\n*.tmp\r\n',
    '.hub/\n*.tmp\n\n',
    '.hub/\n*.tmp\n!.hub/token\n',
    '# .hub/\n*.tmp\n',
    '.hub/\n*.tmp\nnode_modules/\n',
  ]) {
    assert.equal(rulesOf([blob('.gitignore', text)]).get('.gitignore'), 'gitignore', JSON.stringify(text));
  }
});

test('F-4: ledger.format is monotonic against baseFormat', () => {
  assert.deepEqual(validateIncoming([blob('ledger.format', '2\n')], { baseFormat: 2 }).rejected, []);
  assert.deepEqual(validateIncoming([blob('ledger.format', '3\n')], { baseFormat: 2, maxFormat: 3 }).rejected, []);
  assert.equal(rulesOf([blob('ledger.format', '1\n')], { baseFormat: 2 }).get('ledger.format'), 'format', 'downgrade');
  // no baseFormat: only the 1..maxFormat window applies (unchanged behaviour)
  assert.deepEqual(validateIncoming([blob('ledger.format', '1\n')]).rejected, []);
  // junk baseFormat is ignored, not trusted
  assert.deepEqual(validateIncoming([blob('ledger.format', '1\n')], { baseFormat: Number.NaN }).rejected, []);
});

test('1.6: intake names whose snowflake worker is 1023 are rejected; other workers pass', () => {
  const good = goodPush().find((c) => c.path.startsWith('intake/')) as IncomingChange;
  const text = good.content as string;
  const idFor = (worker: number): string => String((1789130426000n << 22n) | (BigInt(worker) << 12n) | 5n);
  const mk = (worker: number): IncomingChange => {
    const id = idFor(worker);
    return blob(`intake/2026-11/${id}.md`, text.replace('1789130426000123', id));
  };
  const reserved = mk(1023);
  assert.equal(rulesOf([reserved]).get(reserved.path), 'reserved-worker');
  for (const w of [0, 1, 2, 25, 1022]) {
    const c = mk(w);
    assert.equal(rulesOf([c]).has(c.path), false, `worker ${w}`);
  }
});

test('intake: schema and id/file-name match', () => {
  const good = goodPush().find((c) => c.path.startsWith('intake/')) as IncomingChange;
  const text = good.content as string;
  const rules = rulesOf([
    blob('intake/2026-11/1789130426000999.md', text), // id inside != file name
    blob('intake/2026-11/1789130426000124.md', 'plain text\n'),
  ]);
  assert.equal(rules.get('intake/2026-11/1789130426000999.md'), 'frontmatter');
  assert.equal(rules.get('intake/2026-11/1789130426000124.md'), 'frontmatter');
});

/* ---------------- claim globs (§4.3) ---------------- */

test('claimGlobProblem: §4.3 rules', () => {
  assert.equal(claimGlobProblem(['src/**', 'docs/*.md', 'a/b/c.ts']), null);
  assert.equal(claimGlobProblem([]), null);
  for (const bad of ['../x', 'a/../b', '/abs', 'C:\\x', 'c:/x', 'a\\b', 'a\u0000b', 'a\nb', 'a\u007fb', '', 'x'.repeat(257)]) {
    assert.equal(claimGlobProblem([bad]), 'glob', JSON.stringify(bad));
  }
  assert.equal(claimGlobProblem(['x'.repeat(256)]), null);
  assert.equal(claimGlobProblem(Array.from({ length: 32 }, (_, i) => `p${i}`)), null);
  assert.equal(claimGlobProblem(Array.from({ length: 33 }, (_, i) => `p${i}`)), 'count');
  assert.equal(claimGlobProblem([7 as unknown as string]), 'glob');
});

test('rejections never carry content and cap/sanitise the path', () => {
  const res = validateIncoming([blob(`evil\u001b[31m\n${'z'.repeat(400)}.md`, 'x\n')]);
  const p = res.rejected[0]?.path ?? '';
  assert.ok(p.length <= 201);
  assert.equal(/[\u0000-\u001f\u007f]/.test(p), false);
  assert.deepEqual(Object.keys(res.rejected[0] ?? {}).sort(), ['path', 'rule']);
});

test('F3A-1: whitespace-run / line-count bombs rejected fast, before the secret scan', () => {
  let called = 0;
  const scan = (): never[] => { called += 1; return []; };
  const t0 = performance.now();
  const bomb = rulesOf([blob('acme/CONTEXT.md', '\n'.repeat(250_000))], { scan });
  const spaces = rulesOf([blob('acme/CONTEXT.md', ' '.repeat(5000))], { scan });
  const lines = rulesOf([blob('acme/CONTEXT.md', 'a\n'.repeat(20_001))], { scan });
  assert.ok(performance.now() - t0 < 1000);
  assert.equal(bomb.get('acme/CONTEXT.md'), 'whitespace-run');
  assert.equal(spaces.get('acme/CONTEXT.md'), 'whitespace-run');
  assert.equal(lines.get('acme/CONTEXT.md'), 'whitespace-run');
  assert.equal(called, 0, 'scanner never ran');
  assert.equal(rulesOf([blob('acme/CONTEXT.md', `a${' '.repeat(4096)}b\n`)], { scan }).size, 0);
});
