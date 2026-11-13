import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  DEFAULT_THRESHOLD,
  MAX_DUPLICATE_PAIRS,
  canonicalTokens,
  findDuplicatePairs,
  findDuplicates,
  titleSimilarity,
} from './dedupe.ts';
import {
  VOCAB_CONCEPT_COUNT,
  VOCAB_FORM_COUNT,
  canonicalWord,
  hasPolarityConflict,
  stemWord,
} from './dedupe-vocab.ts';

/**
 * Calibration table — the synonym half of the spec.
 *
 * `SAME` rows are one piece of work phrased twice in different words. `APART`
 * rows are the trap the vocabulary creates: titles that now share almost every
 * canonical token and still describe different work. A false positive here is
 * worse than a false negative (a wrong 409 blocks a real item), so `APART` is
 * the half that must never regress.
 */
const SAME: readonly (readonly [string, string])[] = [
  ['Add Google login', 'Implement Google sign-in'],
  ['Fix token rotation', 'Repair rotating tokens'],
  ['DB migration for new column', 'Database migrations: new columns'],
  ['DB backup before deploy', 'Back up the database before deployment'],
  ['Apple login on mobile', 'Sign in with Apple on phone'],
  ['Verify DB backups on production', 'Check database backup in prod'],
  ['Session rotation on logout', 'Rotate sessions at logout'],
  ['Error when deploying the web app', 'Deploy failure on web'],
  ['Password change must log out user', 'Changing password logs out user'],
  ['Tests for migrations', 'Migration tests'],
  ['Remove secrets from logs', 'Delete credentials from log output'],
  ['Increase upload limit', 'Raise the upload limit'],
  ['Docs for API keys', 'Documentation for the API key'],
  ['Postgres query performance', 'Query speed in Postgres'],
  ['Deploy new version to production', 'Ship the new version to prod'],
  ['Fix CI build failure', 'Repair failing CI build'],
  ['Add index on items.repo column', 'Create an index for the items repo column'],
  ['Email notification for user', 'Notify user by mail'],
  ['Delete subscription via API', 'Cancel subscription via API'],
  ['Encrypt secrets in config', 'Encryption of credentials in configuration'],
  ['Rotate webhook keys', 'Key rotation for webhooks'],
  ['Restore DB from backup on staging', 'Recover database from a backup in stage'],
  ['Throttle login attempts', 'Rate limit sign-in attempts'],
  ['Delete old logs from disk', 'Remove stale log files from storage'],
  ['Hub crashes on startup', 'Hub crash at start'],
];

const APART: readonly (readonly [string, string, string])[] = [
  ['Add Google login', 'Remove Google login', 'add/remove'],
  ['DB backup', 'Restore DB from backup', 'backup/restore — containment trap'],
  ['Login with Google', 'Logout with Google', 'login/logout'],
  ['Enable CSP on web', 'Disable CSP on web', 'enable/disable'],
  ['Implement Google sign-in', 'Delete Google sign-in', 'add/remove, synonym side'],
  ['Export invoices to CSV', 'Import invoices from CSV', 'import/export'],
  ['Increase upload limit', 'Decrease upload limit', 'increase/decrease'],
  ['Lock account after 5 attempts', 'Unlock account after 5 attempts', 'lock/unlock'],
  ['Start worker', 'Stop worker', 'start/stop'],
  ['Grant export permission', 'Revoke export permission', 'grant/revoke'],
  ['Encrypt secrets in config', 'Decrypt secrets in config', 'encrypt/decrypt'],
  ['Deploy to production', 'Deploy to dev', 'environments do not merge'],
  ['Verify DB backups on production', 'Verify DB backups on staging', 'prod/staging'],
  ['Login on web', 'Login on mobile', 'web/mobile is twice the work'],
  ['Deploy web to Hetzner', 'Deploy mobile to App Store', 'web/mobile'],
  ['Add index on items.repo', 'Add index on items.session', 'different column'],
  ['Token rotation', 'Key rotation', 'token is not key'],
  ['Fix token rotation', 'Fix token expiry', 'different token property'],
  ['DB backup before deploy', 'File backup before deploy', 'different backup subject'],
  ['Tests for migrations', 'Tests for billing', 'different area'],
  ['Password: minimum length', 'Password: reset via email', 'only the word password'],
  ['User without organization', 'User without subscription', 'only the word user'],
  ['Docs for API keys', 'Docs for webhooks', 'only docs + api'],
  ['DB migration for new column', 'Rollback of DB migration', 'migration is not its rollback'],
  ['Fix CI build failure', 'Fix CI lint failure', 'build is not lint'],
  ['Delete old logs', 'Delete old backups', 'different deletion subject'],
  ['Verify DB backups', 'Delete DB backups', 'verifying is not deleting'],
  ['Throttle login', 'Throttle signup', 'login is not signup'],
];

test('synonym pairs of the same work are duplicates', () => {
  for (const [a, b] of SAME) {
    const score = titleSimilarity(a, b);
    assert.ok(
      score >= DEFAULT_THRESHOLD,
      `false negative: "${a}" ~ "${b}" → ${score.toFixed(3)} < ${DEFAULT_THRESHOLD}\n` +
        `  A: ${[...canonicalTokens(a)].join(' ')}\n  B: ${[...canonicalTokens(b)].join(' ')}`,
    );
  }
  assert.ok(SAME.length >= 20, `SAME table has only ${SAME.length} pairs`);
});

test('similar but different things are not duplicates (no false positives)', () => {
  for (const [a, b, why] of APART) {
    const score = titleSimilarity(a, b);
    assert.ok(
      score < DEFAULT_THRESHOLD,
      `false positive: "${a}" ~ "${b}" → ${score.toFixed(3)} ≥ ${DEFAULT_THRESHOLD} (${why})\n` +
        `  A: ${[...canonicalTokens(a)].join(' ')}\n  B: ${[...canonicalTokens(b)].join(' ')}`,
    );
  }
  assert.ok(APART.length >= 20, `APART table has only ${APART.length} pairs`);
});

test('canonicalisation is symmetric and keeps self-similarity', () => {
  for (const [a, b] of [...SAME, ...APART.map(([x, y]) => [x, y] as const)]) {
    assert.equal(titleSimilarity(a, b), titleSimilarity(b, a));
    assert.equal(titleSimilarity(a, a), 1);
  }
});

test('vocabulary has 80–150 concepts and no form collisions', () => {
  assert.ok(
    VOCAB_CONCEPT_COUNT >= 80 && VOCAB_CONCEPT_COUNT <= 150,
    `concepts: ${VOCAB_CONCEPT_COUNT}`,
  );
  // Importing the module at all proves there is no form mapped to two
  // canonical tokens — the builder throws on a clash.
  assert.ok(VOCAB_FORM_COUNT > VOCAB_CONCEPT_COUNT * 2);
});

test('vocabulary maps synonyms and inflections to the same token', () => {
  for (const [first, second, canonical] of [
    ['implement', 'add', 'add'],
    ['repair', 'fix', 'fix'],
    ['defect', 'bug', 'bug'],
    ['deployment', 'deploy', 'deploy'],
    ['validate', 'verify', 'verify'],
    ['erase', 'delete', 'remove'],
    ['signin', 'logon', 'login'],
    ['signout', 'logout', 'logout'],
    ['passphrase', 'password', 'password'],
    ['account', 'user', 'user'],
    ['tests', 'testing', 'test'],
    ['migrate', 'migration', 'migration'],
    ['dump', 'backup', 'backup'],
  ] as const) {
    assert.equal(canonicalWord(first), canonical, first);
    assert.equal(canonicalWord(second), canonical, second);
  }
});

test('stemming leaves short words alone and never cuts a root below 4 chars', () => {
  // Short words are left completely alone: too little left to be a root.
  for (const w of ['repo', 'web', 'hub', 'dev', 'api', 'items']) {
    assert.equal(stemWord(w), w, w);
  }
  assert.equal(stemWord('tokens'), 'token');
  assert.equal(stemWord('indexes'), 'index');
  assert.equal(stemWord('sessions'), 'session');
  assert.equal(stemWord('queries'), 'query');
  assert.equal(stemWord('stopped'), 'stop');
  // Inflected forms converge on one stem.
  assert.equal(stemWord('rotating'), stemWord('rotate'));
  assert.equal(stemWord('rotated'), stemWord('rotates'));
  // Plural `-s` is not stripped after s/u/i.
  assert.equal(stemWord('access'), 'access');
  assert.equal(stemWord('status'), 'status');
  // `-ing` would leave a 3-char stem here, so the suffix stays.
  assert.equal(stemWord('string'), 'string');
});

test('polarity guard reports only a two-sided conflict', () => {
  assert.ok(hasPolarityConflict(new Set(['add', 'login']), new Set(['remove', 'login'])));
  // One-sided: "Deploy" vs "Deploy to prod" is still the same item.
  assert.ok(!hasPolarityConflict(new Set(['deploy']), new Set(['deploy', 'production'])));
  assert.ok(!hasPolarityConflict(new Set(['add', 'login']), new Set(['add', 'password'])));
});

test('findDuplicates finds a reworded duplicate of an open item', () => {
  const open = [
    { id: 'ACME-1', title: 'Add login with Google' },
    { id: 'ACME-2', title: 'Remove login with Google' },
    { id: 'ACME-3', title: 'Fix token rotation' },
  ];
  const hits = findDuplicates('Implement Google sign-in', open);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.id, 'ACME-1');
});

/** Audit D1: the grooming view must not return an unbounded pair list. */
test('findDuplicatePairs holds the pair-count cap', () => {
  // 120 near-identical titles → ~7 000 pairs above the threshold uncapped.
  const items = Array.from({ length: 120 }, (_, i) => ({
    id: `ACME-${i}`,
    title: 'Fix token rotation on production',
  }));
  assert.equal(findDuplicatePairs(items).length, MAX_DUPLICATE_PAIRS);
  assert.equal(findDuplicatePairs(items, DEFAULT_THRESHOLD, 10).length, 10);
  // Below the cap the result is still complete.
  assert.equal(findDuplicatePairs(items.slice(0, 3)).length, 3);
});

/** Audit D4: the cached token set must not be mutable through the return. */
test('canonicalTokens does not hand out a mutable reference into the cache', () => {
  const title = 'Add login with Google';
  const first = canonicalTokens(title);
  assert.ok(first.has('add'));
  // `ReadonlySet` is compile-time only, so prove the runtime invariant that
  // matters: a second call sees exactly what the first one did.
  assert.deepEqual([...canonicalTokens(title)], [...first]);
  assert.equal(titleSimilarity(title, 'Implement Google sign-in'), 1);
});

/**
 * Canonicalisation must not make the create path slow. The guard
 * is p95 over repeated scans of 100 open items, which is the shape of a real
 * `POST /v1/items` dedupe check on the busiest repo.
 */
test('findDuplicates over 100 open items: p95 < 5 ms', () => {
  const open = Array.from({ length: 100 }, (_, i) => ({
    id: `ACME-${i}`,
    title: `${i % 2 === 0 ? 'Repair' : 'Fix'} token rotation in module ${i} on production`,
  }));
  const samples: number[] = [];
  for (let run = 0; run < 200; run += 1) {
    // Fresh needle each run so the memo cache cannot hide the real work.
    const needle = `Fix token rotation in module ${run} on production`;
    const t0 = performance.now();
    findDuplicates(needle, open);
    samples.push(performance.now() - t0);
  }
  samples.sort((x, y) => x - y);
  const p95 = samples[Math.floor(samples.length * 0.95)] ?? 0;
  assert.ok(p95 < 5, `p95 = ${p95.toFixed(3)} ms`);
});
