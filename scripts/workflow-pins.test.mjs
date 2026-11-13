import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", ".github", "workflows");
const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));

export function violations(name, text) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    const m = line.match(/^\s*-?\s*uses:\s*(\S+)/);
    if (m && !m[1].startsWith("./") && !/@[0-9a-f]{40}$/.test(m[1])) out.push(`${name}:${i + 1}: action not pinned to a full SHA: ${m[1]}`);
    if (/pull_request_target|workflow_run/.test(line) && !line.trim().startsWith("#")) out.push(`${name}:${i + 1}: forbidden trigger`);
  });
  if (!/^permissions:/m.test(text)) out.push(`${name}: missing top-level permissions`);
  if (/permissions:\s*write-all|:\s*write\b/.test(text.replace(/^\s*#.*$/gm, ""))) out.push(`${name}: write permission`);
  return out;
}

test("detector flags tag-pinned action and pull_request_target", () => {
  const bad = "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n";
  assert.equal(violations("bad.yml", bad).length, 2);
});

test("all workflows pin actions to full SHA, read-only token, no pull_request_target", () => {
  assert.ok(files.length > 0);
  const all = files.flatMap((f) => violations(f, readFileSync(join(dir, f), "utf8")));
  assert.deepEqual(all, []);
});
