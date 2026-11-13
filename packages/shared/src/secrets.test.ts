import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redactSecrets, scanSecrets } from './secrets.ts';

/** All "secrets" below are synthetic and were never valid. */
function hit(text: string, rule?: string): void {
  const f = scanSecrets(text);
  assert.ok(f.length > 0, `should have been detected: ${text.slice(0, 40)}`);
  if (rule) {
    assert.ok(
      f.some((x) => x.rule.split('+').includes(rule)),
      `expected rule ${rule}, got ${f.map((x) => x.rule).join(',')}`,
    );
  }
  for (const x of f) {
    assert.ok(x.start >= 0 && x.end <= text.length && x.start < x.end, 'range within the text');
  }
}

function clean(text: string): void {
  const f = scanSecrets(text);
  assert.deepEqual(
    f.map((x) => `${x.rule}@${x.start}-${x.end}`),
    [],
    `false positive on: ${text}`,
  );
}

test('Stripe', () => {
  hit('key sk_live_51H8xAbCdEfGhIjKlMnOpQrSt', 'stripe-key');
  hit('sk_test_51H8xAbCdEfGhIjKlMnOpQrSt', 'stripe-key');
  hit('rk_live_51H8xAbCdEfGhIjKlMnOpQrSt', 'stripe-key');
  hit('whsec_AbCdEfGhIjKlMnOpQrStUvWxYz01', 'stripe-webhook-secret');
});

test('GitHub', () => {
  hit('ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123', 'github-token');
  for (const p of ['gho_', 'ghu_', 'ghs_', 'ghr_']) {
    hit(`${p}AbCdEfGhIjKlMnOpQrStUvWxYz0123`, 'github-token');
  }
  hit('github_pat_11ABCDEFG0aBcDeFgHiJkL_MnOpQrStUvWxYz0123456', 'github-pat');
});

test('Slack, AWS, Google', () => {
  hit('xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOp', 'slack-token');
  hit('xoxp-1234567890-1234567890123-AbCdEfGhIjKlMnOp', 'slack-token');
  hit('AKIAIOSFODNN7EXAMPLE', 'aws-access-key-id');
  hit('ASIAIOSFODNN7EXAMPLE', 'aws-access-key-id');
  hit('AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r', 'google-api-key');
});

test('Anthropic, OpenAI', () => {
  hit('sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx', 'anthropic-key');
  hit('sk-proj-AbCdEfGhIjKlMnOpQrStUvWx', 'openai-key');
  hit('sk-AbCdEfGhIjKlMnOpQrStUvWxYz01', 'openai-key');
});

test('PEM a JWT', () => {
  hit('-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n', 'pem-private-key');
  hit('-----BEGIN PRIVATE KEY-----', 'pem-private-key');
  hit('-----BEGIN OPENSSH PRIVATE KEY-----', 'pem-private-key');
  hit(
    'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    'jwt',
  );
});

test('URL s heslom', () => {
  hit('postgres://hub:Sup3rT4jne@db.internal:5432/hub', 'url-password');
  hit('https://admin:hunter2pass@dashboard.example.com/', 'url-password');
});

test('priradenia', () => {
  hit('DB_PASSWORD=Sup3rT4jneHeslo', 'secret-assignment');
  hit('api_key: "AbCdEf0123456789"', 'secret-assignment');
  hit('apikey = Zx9Qw8Er7Ty6Ui5Op', 'secret-assignment');
  hit('{"token":"aB3dE5gH7jK9mN1p"}', 'secret-assignment');
  hit('secret: Passw0rd12345', 'secret-assignment');
  hit('ACCESS_KEY=AbCd1234EfGh5678', 'secret-assignment');
});

test('high entropy without a known prefix', () => {
  hit('backup: p9Xk2Lm4Qz7Rv1Nt8Wy3Bc6Hd5Jf0Gs', 'high-entropy');
  hit('Zm9vYmFyQmF6MTIzNEFiQ2RFZkdoSWo0NQ', 'high-entropy');
});

test('NO false positives — ids, hashes, paths, dates', () => {
  clean('commit 9f2c1ab');
  clean('commit 9f2c1ab3d4e5f60718293a4b5c6d7e8f90a1b2c3');
  clean('git diff 4b825dc642cb6eb9a060e54bf8d69288fbee4904..HEAD');
  clean('id 7241889432101351425 · c7243950112345678999');
  clean('uuid 550e8400-e29b-41d4-a716-446655440000');
  clean('UUID 550E8400-E29B-41D4-A716-446655440000');
  clean('/home/user/projects/acme/agent-ledger/packages/hub/src/security/index.ts');
  clean('~/.config/agents/reviewer.md and ./packages/hub/src/index.ts');
  clean('https://github.com/acme/agent-ledger/pull/142#issuecomment-1234567890');
  clean('http://127.0.0.1:4747/v1/items?repo=agent-ledger&status=open');
  clean('version v1.24.3 · 0.4.0-rc.1 · node 22.22.2');
  clean('2026-09-28T14:10:26.123Z and 1789130426000');
  clean('ACME-142, WEB-13, F0/F2');
});

test('NO false positives — prose sentences and commands', () => {
  clean('The hub token lives in .hub/token, never write its value into an item.');
  clean('The Postgres password is in 1Password, not here.');
  clean('Please set the token and password per the docs, do not publish the values.');
  clean("ssh acme-app 'cat /srv/acme/.env'");
  clean('export API_KEY=$STRIPE_KEY && export TOKEN=${HUB_TOKEN}');
  clean('password: <your password>');
  clean('token = "REDACTED"');
  clean('secret: changeme');
  clean('DB_PASSWORD=process.env.DB_PASSWORD');
  clean('token: null');
  clean('api_key = your_key_here');
});

test('NO false positives — long identifiers and base64 without entropy', () => {
  clean('PostToolUseHookPayloadSchemaV2 a getRepoDirtyFilesWithOwners');
  clean('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  clean('SCREAMING_SNAKE_CASE_CONSTANT_NAME_HERE');
  clean('THIS_IS_A_VERY_LONG_ENV_VAR_NAME_NO_VALUE');
  clean('----------------------------------------');
});

test('redactSecrets: replaces and never returns the value', () => {
  const secret = 'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123';
  const { text, findings } = redactSecrets(`see ${secret} now`);
  assert.equal(findings.length, 1);
  assert.ok(!text.includes(secret));
  assert.ok(!text.includes('AbCdEfGhIjKlMnOp'));
  assert.match(text, /^see \[REDACTED:[a-z+-]+\] now$/);
});

test('redactSecrets: multiple findings, order and offsets hold', () => {
  const { text, findings } = redactSecrets(
    'a sk_live_51H8xAbCdEfGhIjKlMnOpQrSt b AKIAIOSFODNN7EXAMPLE c',
  );
  assert.equal(findings.length, 2);
  assert.ok(findings[0].end <= findings[1].start, 'disjoint and sorted');
  assert.equal(text, 'a [REDACTED:stripe-key] b [REDACTED:aws-access-key-id] c');
});

test('redactSecrets: overlapping findings merge into one', () => {
  const line = 'GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123';
  const findings = scanSecrets(line);
  assert.equal(findings.length, 1, 'assignment + github + entropy = 1 range');
  assert.ok(findings[0].rule.includes('+'), 'merged rule carries both names');
  const { text } = redactSecrets(line);
  assert.equal((text.match(/\[REDACTED:/g) ?? []).length, 1);
  assert.ok(!text.includes('ghp_'));
});

test('redactSecrets: clean text stays byte for byte', () => {
  const src = 'Ordinary record with commit 9f2c1ab and path /srv/acme/.env\n';
  const { text, findings } = redactSecrets(src);
  assert.equal(text, src);
  assert.deepEqual(findings, []);
});

test('edges: empty and non-string input', () => {
  assert.deepEqual(scanSecrets(''), []);
  // @ts-expect-error runtime guard
  assert.deepEqual(scanSecrets(undefined), []);
  assert.deepEqual(redactSecrets('').findings, []);
});

test('a secret in the middle of an md block is found and the range matches exactly', () => {
  const secret = 'AKIAIOSFODNN7EXAMPLE';
  const text = `## Log\n\n- configured \`${secret}\` in CI\n`;
  const f = scanSecrets(text);
  assert.equal(f.length, 1);
  assert.equal(text.slice(f[0].start, f[0].end), secret);
});
