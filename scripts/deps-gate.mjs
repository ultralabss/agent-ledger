#!/usr/bin/env node
// Supply-chain gate for dependencies. Fails when:
//  1. a package.json (root or packages/*) declares a direct dependency not listed in
//     .github/allowed-deps.txt, or one that is not a registry range (git/url/file/link),
//  2. a workspace package.json defines preinstall/install/postinstall/prepare,
//  3. pnpm-lock.yaml resolves anything from a tarball URL or git repo,
//  4. an installed package (node_modules/.pnpm) has an install script or gypfile and is
//     not listed as `build <name>`.
// Usage: node scripts/deps-gate.mjs [root]   (default: repo root, run after `pnpm install --ignore-scripts`)
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "pnpm:devPreinstall"];
// A registry range or dist-tag only: no protocol, alias (npm:), path, owner/repo or catalog.
const REGISTRY_RANGE = /^[\w.\-^~<>=*|+\s]+$/;

export function parseAllow(text) {
  const dep = new Set();
  const build = new Set();
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*/, "").trim();
    if (!line) continue;
    const [kind, name] = line.split(/\s+/);
    if (kind === "dep" && name) dep.add(name);
    else if (kind === "build" && name) build.add(name);
    else throw new Error(`allowed-deps: bad line "${raw}"`);
  }
  return { dep, build };
}

function checkOverride(errors, rel, label, value, isBuild = false) {
  if (isBuild) return; // allowBuilds values are booleans; names are checked against `build` below
  if (!REGISTRY_RANGE.test(String(value))) errors.push(`${rel}: ${label}=${value} is not a registry range`);
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
  const { dep, build } = parseAllow(allowText);
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
  if (existsSync(lock)) {
    let blockIndent = -1; // indent of a block-style `resolution:` line, -1 when outside one
    readFileSync(lock, "utf8").split("\n").forEach((line, i) => {
      const n = i + 1;
      const indent = line.length - line.trimStart().length;
      if (blockIndent >= 0) {
        if (line.trim() && indent > blockIndent) {
          const key = /^\s*['"]?([\w.-]+)['"]?\s*:/.exec(line)?.[1];
          if (key !== "integrity") errors.push(`pnpm-lock.yaml:${n}: unexpected resolution field: ${line.trim().slice(0, 100)}`);
        } else blockIndent = -1;
      }
      if (/^\s*resolution:\s*$/.test(line)) blockIndent = indent;
      // Flow style: `resolution: {integrity: ...}` may contain only `integrity`.
      const flow = /^\s*resolution:\s*\{(.*)\}\s*$/.exec(line);
      if (flow) {
        for (const m of flow[1].matchAll(/(?:^|,)\s*['"]?([\w.-]+)['"]?\s*:/g)) {
          if (m[1] !== "integrity") errors.push(`pnpm-lock.yaml:${n}: unexpected resolution field "${m[1]}"`);
        }
      }
      // Any tarball/repo/commit/directory/type key, in flow or block style, anywhere in the lockfile.
      if (/(?:^|[\s{,])['"]?(?:tarball|repo|commit|directory|type)['"]?\s*:/.test(line)) {
        errors.push(`pnpm-lock.yaml:${n}: non-registry resolution: ${line.trim().slice(0, 100)}`);
      }
      // Package keys / versions that point outside the registry.
      if (/@(?:https?:|git[+:@]|github:|file:|link:|ssh:)|(?:^|\s)(?:'?[^\s]*@)?(?:git\+|https?:\/\/)/.test(line) && !/^\s*resolution:/.test(line) && !/integrity/.test(line)) {
        if (/^\s+'?[^\s]+'?:\s*(?:'?(?:git\+|https?:|github:|file:|link:)[^\s]*'?)?\s*$/.test(line) || /@(?:https?:|git[+:@]|github:|file:)/.test(line)) {
          errors.push(`pnpm-lock.yaml:${n}: non-registry reference: ${line.trim().slice(0, 100)}`);
        }
      }
    });
  }

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
