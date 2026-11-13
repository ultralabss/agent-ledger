#!/usr/bin/env node
// Supply-chain gate: fail CI when tracked source contains patterns a backdoor needs.
// Usage: node scripts/forbidden-patterns.mjs            (scans git-tracked files)
//        node scripts/forbidden-patterns.mjs <dir|file> (scans a path, used by tests)
// A hit outside ALLOW is an error. Adding to ALLOW needs CODEOWNERS review (see CONTRIBUTING.md).
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, extname, sep } from "node:path";
import { pathToFileURL } from "node:url";

// rule id -> regex over a single line (comments are not stripped on purpose).
export const RULES = {
  eval: /\beval\b(?!\s*:)/,
  "new-function": /\bFunction\b|\.constructor\s*\(|\bGeneratorFunction\b/,
  "vm-run": /\bvm\.run\w*\s*\(|\brunIn(?:This|New)Context\b|\bnew\s+(?:vm\.)?Script\b|from\s+["'](?:node:)?vm["']|require\(\s*["'](?:node:)?vm["']\s*\)/,
  "dynamic-code": /\bimport\s*\(\s*[^"'`\s)]|\bimport\s*\(\s*(?:"[^"]*"|'[^']*'|`[^`]*`)\s*[+,]|\brequire\s*\(\s*[^"'`\s)]|\bcreateRequire\b|\bglobalThis\s*\[|\bprocess\.(?:binding|dlopen|_linkedBinding)\b|\bnew\s+Worker\b|from\s+["'](?:node:)?(?:worker_threads|module)["']/,
  "child-process": /\bchild_process\b/,
  fetch: /\bfetch\s*\(|\bWebSocket\b|\bXMLHttpRequest\b|\bsendBeacon\b|\bEventSource\b/,
  "http-request": /\bhttps?\.(?:request|get)\s*\(|from\s+["'](?:node:)?(?:https?|http2|tls|dgram|dns)(?:\/promises)?["']|require\(\s*["'](?:node:)?(?:https?|http2|tls|dgram|dns)["']\s*\)/,
  net: /\bnet\.(?:connect|createConnection|Socket)\b|from\s+["'](?:node:)?net["']|require\(\s*["'](?:node:)?net["']\s*\)/,
  "curl-pipe-sh": /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/,
  base64: /[A-Za-z0-9+/]{200,}={0,2}/,
  "long-line": /^.{2001,}$/,
  // zero-width, bidi controls, BOM, soft hyphen, Unicode tag chars, variation selectors
  // (U+FE0F after a non-ASCII character is the normal emoji presentation selector)
  "bidi-invisible": /[\u061C\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFE00-\uFE0E\uFEFF\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]|(?<=[\x00-\x7F])\uFE0F/u,
};

// Exact files allowed to use a rule (reviewed uses). Everything else is a failure.
// Keep it short; every entry is a place a reviewer must look at. Exact paths only.
export const ALLOW = {
  "child-process": [
    "scripts/build-hook.mjs",
    "packages/cli/src/index.ts",
    "packages/cli/src/open.ts",
    "packages/cli/src/selfheal.ts",
    "packages/hub/src/git.ts",
    "packages/hub/src/gitleaks.ts",
    "packages/hub/src/headless.ts",
    "packages/hub/src/replies.ts",
  ],
  fetch: [
    "install.sh",
    "packages/cli/src/client.ts",
    "packages/cli/src/doctor.ts",
    "packages/cli/src/hook.ts",
    "packages/cli/src/update-check.ts",
    "packages/hub/src/server.ts",
    "packages/hub/src/spool-sweep.ts",
    "packages/web/src/api/client.tsx",
    "packages/web/src/hooks/useSSE.tsx",
  ],
  "http-request": ["packages/cli/src/hook-send.ts"],
  eval: ["packages/hub/src/guard/worker-guard.ts", "packages/hub/src/guard/worker-guard.test.ts", "packages/hub/src/headless.ts", "packages/hub/src/replies.ts"],
  "dynamic-code": ["packages/cli/src/hook-bash.test.ts"],
  net: ["packages/hub/src/server.ts"],
  "curl-pipe-sh": ["packages/hub/src/guard/worker-guard.ts", "packages/hub/src/guard/worker-guard.test.ts"],
  "bidi-invisible": ["packages/shared/src/md.ts"],
};
// Network and process rules are relaxed in test files only (hostile fixtures, local servers).
const TEST_FILE = /\.test\.(?:ts|mjs|js)$|(^|\/)test-helpers\.ts$/;
const TEST_RELAXED = new Set(["child-process", "fetch", "http-request", "net"]);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".next", "coverage"]);
const TEXT_EXT = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".sh", ".yml", ".yaml", ".json", ".toml", ".md", ".txt", ".css", ".html", ".tmpl", ".plist", ".service", ".snippet", ".cjs"]);
// Rules that do not apply to docs/data (they legitimately discuss or contain such text).
const DOC_ONLY_RULES = new Set(["bidi-invisible"]);
// Rules that also apply inside comment-only lines (hidden text, blobs).
const TEXT_RULES = new Set(["bidi-invisible", "base64", "long-line", "curl-pipe-sh"]);
const LOCKFILES = new Set(["pnpm-lock.yaml"]);

function allowed(rule, rel) {
  if (TEST_RELAXED.has(rule) && TEST_FILE.test(rel)) return true;
  return (ALLOW[rule] ?? []).includes(rel);
}

/** @returns {{rule:string,file:string,line:number,text:string}[]} */
export function scanText(text, rel, opts = {}) {
  const useAllow = opts.useAllow ?? true;
  const ext = extname(rel);
  const isDoc = ext === ".md" || ext === ".txt" || LOCKFILES.has(rel.split("/").pop());
  const out = [];
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    // `/* x */ eval(y)` is code, so a block-comment line must not continue after `*/`.
    const commentOnly = /^\s*\/\//.test(line) || (/^\s*(?:\/\*|\*)/.test(line) && !/\*\/\s*\S/.test(line));
    for (const [rule, re] of Object.entries(RULES)) {
      if (commentOnly && !TEXT_RULES.has(rule)) continue;
      if (isDoc && !DOC_ONLY_RULES.has(rule)) continue;
      if (rel.endsWith(".json") && (rule === "base64" || rule === "long-line")) continue;
      if (!re.test(line)) continue;
      if (useAllow && allowed(rule, rel)) continue;
      out.push({ rule, file: rel, line: i + 1, text: line.trim().slice(0, 120) });
    }
  });
  return out;
}

function listFiles(root) {
  const st = statSync(root);
  if (st.isFile()) return [root];
  const acc = [];
  for (const e of readdirSync(root, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = join(root, e.name);
    if (e.isDirectory()) acc.push(...listFiles(p));
    else if (e.isFile()) acc.push(p);
  }
  return acc;
}

export function scanPath(target, base = target, opts = {}) {
  const files = opts.files ?? listFiles(target);
  const findings = [];
  for (const f of files) {
    if (!TEXT_EXT.has(extname(f)) && !f.endsWith(".snippet")) continue;
    const rel = relative(base, f).split(sep).join("/");
    // The scanner's own rule table must mention the patterns it looks for.
    if (rel === "scripts/forbidden-patterns.mjs" || rel === "scripts/forbidden-patterns.test.mjs") continue;
    findings.push(...scanText(readFileSync(f, "utf8"), rel, opts));
  }
  return findings;
}

function main() {
  const arg = process.argv[2];
  let findings;
  if (arg) {
    findings = scanPath(arg, arg, { useAllow: false });
  } else {
    const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
    const files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
      .split("\0").filter(Boolean).map((f) => join(root, f));
    findings = scanPath(root, root, { files });
  }
  for (const f of findings) console.error(`${f.file}:${f.line}: forbidden pattern [${f.rule}]: ${f.text}`);
  if (findings.length) {
    console.error(`\n${findings.length} forbidden pattern(s). See CONTRIBUTING.md "Forbidden in contributions".`);
    process.exit(1);
  }
  console.log("forbidden-patterns: ok");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();
