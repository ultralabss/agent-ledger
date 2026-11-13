import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runGate } from "./deps-gate.mjs";

const ALLOW = "dep typescript\ndep zod\nbuild esbuild\n";

function repo(rootPkg, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "dg-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify(rootPkg));
  if (extra.ws) writeFileSync(join(dir, "pnpm-workspace.yaml"), extra.ws);
  if (extra.pnpmfile) writeFileSync(join(dir, ".pnpmfile.cjs"), "module.exports = {};");
  if (extra.lock) writeFileSync(join(dir, "pnpm-lock.yaml"), extra.lock);
  for (const [name, pkg] of Object.entries(extra.installed ?? {})) {
    const d = join(dir, "node_modules", ".pnpm", `${name}@1.0.0`, "node_modules", name);
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "package.json"), JSON.stringify({ name, version: "1.0.0", ...pkg }));
  }
  return dir;
}

test("clean repo passes", () => {
  const d = repo({ devDependencies: { typescript: "^5.9.3" } }, { installed: { esbuild: { scripts: { postinstall: "node x" } } } });
  assert.deepEqual(runGate(d, ALLOW), []);
});

test("new direct dependency outside allowlist fails", () => {
  const d = repo({ dependencies: { "left-padz": "^1.0.0" } });
  assert.match(runGate(d, ALLOW).join("\n"), /new dependency "left-padz"/);
});

test("git/url dependency fails even if name is allowed", () => {
  const d = repo({ dependencies: { zod: "github:evil/zod" } });
  assert.match(runGate(d, ALLOW).join("\n"), /not a registry range/);
});

test("workspace lifecycle script fails", () => {
  const d = repo({ scripts: { postinstall: "curl x | sh" } });
  assert.match(runGate(d, ALLOW).join("\n"), /lifecycle script "postinstall"/);
});

test("installed package with postinstall outside build allowlist fails", () => {
  const d = repo({}, { installed: { "evil-pkg": { scripts: { postinstall: "node steal.js" } } } });
  assert.match(runGate(d, ALLOW).join("\n"), /evil-pkg@1\.0\.0: has an install script/);
});

test("gypfile package outside allowlist fails", () => {
  const d = repo({}, { installed: { native: { gypfile: true } } });
  assert.match(runGate(d, ALLOW).join("\n"), /native@1\.0\.0/);
});

test("lockfile tarball resolution fails", () => {
  const d = repo({}, { lock: "packages:\n  x@1.0.0:\n    resolution: {tarball: https://evil.example.com/x.tgz}\n" });
  assert.match(runGate(d, ALLOW).join("\n"), /non-registry resolution/);
});

test("malformed allowlist throws", () => {
  assert.throws(() => runGate(repo({}), "wat foo\n"), /bad line/);
});

test("npm alias to another package fails even if the key is allowed", () => {
  const d = repo({ dependencies: { zod: "npm:evil-pkg@1.0.0" } });
  assert.match(runGate(d, ALLOW).join("\n"), /not a registry range/);
});

test("owner/repo shorthand, jsr, catalog and path specifiers fail", () => {
  for (const r of ["evil/zod", "jsr:@evil/zod", "catalog:", "./local", "../x"]) {
    assert.match(runGate(repo({ dependencies: { zod: r } }), ALLOW).join("\n"), /not a registry range/, r);
  }
});

test("block-style lockfile tarball resolution fails", () => {
  const d = repo({}, { lock: "packages:\n  x@1.0.0:\n    resolution:\n      tarball: https://evil.example.com/x.tgz\n" });
  assert.match(runGate(d, ALLOW).join("\n"), /non-registry resolution/);
});

test("git resolution and git package keys in lockfile fail", () => {
  assert.match(runGate(repo({}, { lock: "packages:\n  x@1.0.0:\n    resolution: {type: git, repo: https://evil.example.com/x.git, commit: abc}\n" }), ALLOW).join("\n"), /non-registry/);
  assert.match(runGate(repo({}, { lock: "packages:\n  x@https://evil.example.com/x.tgz:\n    resolution: {integrity: sha512-aaa}\n" }), ALLOW).join("\n"), /non-registry reference/);
});

test("overrides, patches, pnpmfile and unlisted allowBuilds fail", () => {
  assert.match(runGate(repo({ pnpm: { overrides: { zod: "github:evil/zod" } } }), ALLOW).join("\n"), /overrides/);
  assert.match(runGate(repo({ pnpm: { patchedDependencies: { "zod@1.0.0": "p.patch" } } }), ALLOW).join("\n"), /patchedDependencies/);
  assert.match(runGate(repo({}, { pnpmfile: true }), ALLOW).join("\n"), /pnpmfile/);
  assert.match(runGate(repo({}, { ws: "packages:\n  - x\nallowBuilds:\n  evil-pkg: true\n" }), ALLOW).join("\n"), /allowBuilds "evil-pkg"/);
  assert.deepEqual(runGate(repo({}, { ws: "packages:\n  - x\nallowBuilds:\n  esbuild: true\n" }), ALLOW), []);
});

test("SC-4: quoted-key resolution fields fail (flow and block style)", () => {
  const cases = [
    "packages:\n  x@1.0.0:\n    resolution: {'tarball': 'https://evil.example.com/x.tgz'}\n",
    "packages:\n  x@1.0.0:\n    resolution: {\"tarball\": file:../x.tgz}\n",
    "packages:\n  x@1.0.0:\n    resolution:\n      \"tarball\": ../x.tgz\n",
    "packages:\n  x@1.0.0:\n    resolution:\n      integrity: sha512-aaa\n      'repo': ./x\n",
  ];
  for (const lock of cases) assert.ok(runGate(repo({}, { lock }), ALLOW).length > 0, lock);
});

test("SC-4: plain integrity resolutions pass (flow and block)", () => {
  const lock = "packages:\n  x@1.0.0:\n    resolution: {integrity: sha512-aaa}\n  y@1.0.0:\n    resolution:\n      integrity: sha512-bbb\n    engines: {node: '>=18'}\n";
  assert.deepEqual(runGate(repo({}, { lock }), ALLOW), []);
});
