#!/usr/bin/env node
// Supply-chain gate for dependencies. Fails when:
//  1. a package.json (root or packages/*) declares a direct dependency not listed in
//     .github/allowed-deps.txt, or one that is not a registry range (git/url/file/link),
//  2. a workspace package.json defines preinstall/install/postinstall/prepare,
//  3. pnpm-lock.yaml resolves anything from a tarball URL or git repo,
//  3b. the lockfile is parsed (not regexed): every package resolution is only a sha integrity,
//      requiresBuild needs `build`, bundledDependencies needs `bundle`, no non-registry keys;
//  4. an installed package (node_modules/.pnpm) has an install script or gypfile and is
//     not listed as `build <name>`.
// Usage: node scripts/deps-gate.mjs [root]   (default: repo root, run after `pnpm install --ignore-scripts`)
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "pnpm:devPreinstall"];
// A registry range or dist-tag only: no protocol, alias (npm:), path, owner/repo or catalog.
const REGISTRY_RANGE = /^[\w.\-^~<>=*|+\s]+$/;

export function parseAllow(text) {
  const dep = new Set();
  const build = new Set();
  const bundle = new Set();
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    if (!line) continue;
    const [kind, name] = line.split(/\s+/);
    if (kind === "dep" && name) dep.add(name);
    else if (kind === "build" && name) build.add(name);
    else if (kind === "bundle" && name) bundle.add(name);
    else throw new Error(`allowed-deps: bad line "${raw}"`);
  }
  return { dep, build, bundle };
}

function checkOverride(errors, rel, label, value, isBuild = false) {
  if (isBuild) return; // allowBuilds values are booleans; names are checked against `build` below
  if (!REGISTRY_RANGE.test(String(value))) errors.push(`${rel}: ${label}=${value} is not a registry range`);
}

// The YAML parser is `yaml`, already an allowlisted dependency of packages/shared. It is
// resolved from this repo (not from the scanned root) so the gate can scan fixtures.
const HERE = dirname(fileURLToPath(import.meta.url));
function loadYaml() {
  return createRequire(join(HERE, "..", "packages", "shared", "package.json"))("yaml");
}

const INTEGRITY = /^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/;
const SOURCE_IN_KEY = /@(?:https?:|git[+:@]|github:|gitlab:|bitbucket:|file:|link:|ssh:|jsr:|npm:)|(?:^|\/)(?:git\+|https?:\/\/)/;
const SOURCE_VERSION = /^(?:git|github:|gitlab:|bitbucket:|https?:|file:|ssh:|jsr:|npm:|catalog:)|^link:(?!\.\.\/[\w-]+$)/;

/** Structured check of pnpm-lock.yaml (fail closed on any parse problem). */
export function checkLockfile(text, build, bundle = new Set()) {
  const errors = [];
  let doc;
  try {
    // Anchors and aliases are resolved by the parser; a low alias cap stops expansion bombs.
    doc = loadYaml().parse(text, { maxAliasCount: 50, uniqueKeys: true });
  } catch (e) {
    return [`pnpm-lock.yaml: cannot be parsed safely (${String(e.message).split("\n")[0].slice(0, 80)})`];
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return ["pnpm-lock.yaml: unexpected structure"];

  for (const [key, entry] of Object.entries(doc.packages ?? {})) {
    if (SOURCE_IN_KEY.test(key)) errors.push(`pnpm-lock.yaml: packages["${key}"] is not a registry package`);
    const res = entry?.resolution;
    if (!res || typeof res !== "object" || Array.isArray(res)) {
      errors.push(`pnpm-lock.yaml: packages["${key}"] has no resolution object`);
    } else {
      const keys = Object.keys(res);
      if (keys.length !== 1 || keys[0] !== "integrity" || !INTEGRITY.test(String(res.integrity))) {
        errors.push(`pnpm-lock.yaml: packages["${key}"] resolution must be only a sha integrity (found: ${keys.join(",") || "none"})`);
      }
    }
    const name = key.replace(/^(@?[^@]+)@.*$/, "$1");
    if (entry?.requiresBuild && !build.has(name)) errors.push(`pnpm-lock.yaml: packages["${key}"] requiresBuild and "${name}" is not listed as "build ${name}"`);
    for (const f of ["bundledDependencies", "bundleDependencies"]) {
      if (entry && f in entry && !bundle.has(name) && !(Array.isArray(entry[f]) && entry[f].length === 0)) errors.push(`pnpm-lock.yaml: packages["${key}"] has ${f}`);
    }
  }
  for (const key of Object.keys(doc.snapshots ?? {})) {
    if (SOURCE_IN_KEY.test(key)) errors.push(`pnpm-lock.yaml: snapshots["${key}"] is not a registry package`);
  }
  for (const [imp, body] of Object.entries(doc.importers ?? {})) {
    for (const f of DEP_FIELDS) {
      for (const [name, v] of Object.entries(body?.[f] ?? {})) {
        const ver = String(v?.version ?? "");
        const spec = String(v?.specifier ?? "");
        if (SOURCE_VERSION.test(ver) || (SOURCE_VERSION.test(spec) && !spec.startsWith("workspace:"))) {
          errors.push(`pnpm-lock.yaml: importers["${imp}"].${f}.${name} points outside the registry (${ver || spec})`);
        }
      }
    }
  }
  return errors;
}

function readJson(p) {
  return JSON.parse(readFileSync(p, "utf8"));
}

function workspaceManifests(root) {
  const out = [join(root, "package.json")];
  const pk = join(root, "packages");
  if (existsSync(pk)) {
    for (const e of readdirSync(pk, { withFileTypes: true })) {
      const f = join(pk, e.name, "package.json");
      if (e.isDirectory() && existsSync(f)) out.push(f);
    }
  }
  return out.filter((f) => existsSync(f));
}

function installedPackages(root) {
  const base = join(root, "node_modules", ".pnpm");
  const found = [];
  if (!existsSync(base)) return found;
  for (const d of readdirSync(base)) {
    const nm = join(base, d, "node_modules");
    if (!existsSync(nm) || !statSync(nm).isDirectory()) continue;
    for (const n of readdirSync(nm)) {
      const names = n.startsWith("@") ? readdirSync(join(nm, n)).map((x) => `${n}/${x}`) : [n];
      for (const name of names) {
        const pj = join(nm, name, "package.json");
        if (existsSync(pj)) found.push({ name, pj });
      }
    }
  }
  return found;
}

export function runGate(root, allowText) {
  const { dep, build, bundle } = parseAllow(allowText);
  const errors = [];

  for (const f of workspaceManifests(root)) {
    const rel = f.slice(root.length + 1);
    const pkg = readJson(f);
    for (const s of LIFECYCLE) {
      if (pkg.scripts?.[s]) errors.push(`${rel}: lifecycle script "${s}" is forbidden`);
    }
    for (const field of ["overrides", "resolutions"]) {
      for (const [name, range] of Object.entries(pkg[field] ?? {})) checkOverride(errors, rel, `${field}.${name}`, range);
    }
    for (const field of ["overrides", "allowBuilds"]) {
      for (const [name, range] of Object.entries(pkg.pnpm?.[field] ?? {})) checkOverride(errors, rel, `pnpm.${field}.${name}`, range, field === "allowBuilds");
    }
    for (const field of ["patchedDependencies", "packageExtensions"]) {
      if (pkg.pnpm?.[field] && Object.keys(pkg.pnpm[field]).length) errors.push(`${rel}: pnpm.${field} is forbidden`);
    }
    for (const field of DEP_FIELDS) {
      for (const [name, range] of Object.entries(pkg[field] ?? {})) {
        if (String(range).startsWith("workspace:")) continue;
        if (!REGISTRY_RANGE.test(String(range))) errors.push(`${rel}: ${name}@${range} is not a registry range`);
        if (!dep.has(name)) errors.push(`${rel}: new dependency "${name}" is not in .github/allowed-deps.txt`);
      }
    }
  }

  for (const f of [".pnpmfile.cjs", ".pnpmfile.mjs", "pnpmfile.cjs"]) {
    if (existsSync(join(root, f))) errors.push(`${f}: pnpmfile hooks run on install and are forbidden`);
  }
  const ws = join(root, "pnpm-workspace.yaml");
  if (existsSync(ws)) {
    const text = readFileSync(ws, "utf8");
    const m = /^allowBuilds:\s*\n((?:[ \t]+.*\n?)*)/m.exec(text);
    for (const line of (m?.[1] ?? "").split("\n")) {
      const k = /^\s+['"]?([^'":\s]+)['"]?\s*:\s*true\b/.exec(line);
      if (k && !build.has(k[1])) errors.push(`pnpm-workspace.yaml: allowBuilds "${k[1]}" is not listed as "build ${k[1]}"`);
    }
    for (const key of ["patchedDependencies", "packageExtensions", "catalog", "catalogs", "overrides"]) {
      if (new RegExp(`^${key}:`, "m").test(text)) errors.push(`pnpm-workspace.yaml: "${key}" is not allowed (not checked by the gate)`);
    }
  }

  const lock = join(root, "pnpm-lock.yaml");
  if (existsSync(lock)) errors.push(...checkLockfile(readFileSync(lock, "utf8"), build, bundle));

  const seen = new Set();
  for (const { name, pj } of installedPackages(root)) {
    let p;
    try { p = readJson(pj); } catch { continue; }
    const s = p.scripts ?? {};
    const risky = ["preinstall", "install", "postinstall"].some((k) => s[k]) || p.gypfile === true;
    const key = `${name}@${p.version}`;
    if (risky && !build.has(name) && !seen.has(key)) {
      seen.add(key);
      errors.push(`${key}: has an install script (requiresBuild) and is not listed as "build ${name}"`);
    }
  }
  return errors;
}

function main() {
  const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), ".."));
  const allow = readFileSync(join(root, ".github", "allowed-deps.txt"), "utf8");
  const errors = runGate(root, allow);
  for (const e of errors) console.error(`deps-gate: ${e}`);
  if (errors.length) process.exit(1);
  console.log("deps-gate: ok");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();
