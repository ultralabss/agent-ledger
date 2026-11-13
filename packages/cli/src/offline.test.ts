/** Regression test: `readItems`' `--repo` filter must not escape the ledger. */

import assert from 'node:assert/strict';
import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { readItems } from './offline.ts';

const ITEM_MD = `---
id: AP-1
title: Test item
status: open
kind: BACKLOG
priority: P2
owner: agent
repo: app
area: null
paths: []
blocks: []
blocked_by: []
requested_by: null
intake: null
aliases: []
claimed_by: null
source:
  session: null
  agent: null
  commit: null
done: null
created: 2026-09-28T14:02:00+02:00
updated: 2026-09-28T14:02:00+02:00
---

## Why

## Plan

## Recommendation

## Comments

## Log
`;

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'offline-test-'));
}

test('readItems with a legitimate slug reads as before', async () => {
  const ledger = await tmp();
  await mkdir(join(ledger, 'app', 'items'), { recursive: true });
  await writeFile(join(ledger, 'app', 'items', 'AP-1.md'), ITEM_MD, 'utf8');

  const items = await readItems(ledger, { repo: 'app' });
  assert.equal(items.length, 1);
  assert.equal(items[0]?.fm.id, 'AP-1');
});

test('readItems rejects --repo with traversal characters and does not read outside the ledger', async () => {
  const ledger = await tmp();
  await mkdir(join(ledger, 'app', 'items'), { recursive: true });
  await writeFile(join(ledger, 'app', 'items', 'AP-1.md'), ITEM_MD, 'utf8');

  const outside = await tmp();
  await mkdir(join(outside, 'secret', 'items'), { recursive: true });
  await writeFile(
    join(outside, 'secret', 'items', 'SEC-1.md'),
    ITEM_MD.replace('id: AP-1', 'id: SEC-1').replace('repo: app', 'repo: secret'),
    'utf8',
  );

  for (const badRepo of ['../secret', '../../etc', 'a/../../secret', join(outside, 'secret')]) {
    const items = await readItems(ledger, { repo: badRepo });
    assert.deepEqual(items, [], `repo=${badRepo} must not read outside the ledger`);
  }
});

test('readItems rejects a slug whose items/ is a symlink outside the ledger', async () => {
  const ledger = await tmp();
  const outside = await tmp();
  await mkdir(join(outside, 'items'), { recursive: true });
  await writeFile(
    join(outside, 'items', 'SEC-1.md'),
    ITEM_MD.replace('id: AP-1', 'id: SEC-1').replace('repo: app', 'repo: evil'),
    'utf8',
  );
  // Slug itself passes `slugSchema` — only the realpath containment check
  // catches this one.
  await mkdir(join(ledger, 'evil'), { recursive: true });
  await symlink(join(outside, 'items'), join(ledger, 'evil', 'items'));

  const items = await readItems(ledger, { repo: 'evil' });
  assert.deepEqual(items, [], 'symlinked items/ escaping the ledger must not be read');
});
