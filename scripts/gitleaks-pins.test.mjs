import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_PINS_PATH,
  assertExtractedLayout,
  assertZipSafeLayout,
  assetName,
  digestMatchesPin,
  listZipMembers,
  loadPins,
  parsePins,
  sha256Hex,
} from "./gitleaks-pins.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TOOL = join(HERE, "gitleaks-pins.mjs");

/** Minimal "stored" zip writer: enough to exercise the central-directory reader. */
function zip(names) {
  const locals = [];
  const cens = [];
  let off = 0;
  for (const name of names) {
    const n = Buffer.from(name, "utf8");
    const data = Buffer.from("x");
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x800, 6);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(n.length, 26);
    const local = Buffer.concat([lh, n, data]);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x800, 8);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(n.length, 28);
    ch.writeUInt32LE(off, 42);
    cens.push(Buffer.concat([ch, n]));
    locals.push(local);
    off += local.length;
  }
  const cd = Buffer.concat(cens);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(names.length, 8);
  eocd.writeUInt16LE(names.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

test("pins file: schema, every digest is 64 lowercase hex, version matches the asset names", () => {
  const pins = loadPins();
  assert.match(pins.version, /^\d+\.\d+\.\d+$/);
  for (const k of ["linux_x64", "linux_arm64", "darwin_x64", "darwin_arm64", "windows_x64"]) {
    assert.match(pins.assets[k], /^[0-9a-f]{64}$/, k);
    assert.match(assetName(pins.version, k), new RegExp(`^gitleaks_${pins.version.replaceAll(".", "\\.")}_${k}\\.(zip|tar\\.gz)$`));
  }
  assert.equal(assetName(pins.version, "windows_x64").endsWith(".zip"), true);
  const raw = JSON.parse(readFileSync(DEFAULT_PINS_PATH, "utf8"));
  assert.equal(raw.source, `https://github.com/gitleaks/gitleaks/releases/download/v${pins.version}/`);
  assert.equal(new Set(Object.values(pins.assets)).size, Object.keys(pins.assets).length, "digests are distinct");
});

test("pins parser refuses malformed documents (fail-closed)", () => {
  const ok = { version: "8.30.1", assets: { linux_x64: "a".repeat(64) } };
  assert.doesNotThrow(() => parsePins(JSON.stringify(ok)));
  for (const bad of [
    "not json",
    "[]",
    JSON.stringify({ ...ok, version: "latest" }),
    JSON.stringify({ ...ok, version: "8.30" }),
    JSON.stringify({ version: "8.30.1", assets: {} }),
    JSON.stringify({ version: "8.30.1" }),
    JSON.stringify({ ...ok, assets: { linux_x64: "A".repeat(64) } }),
    JSON.stringify({ ...ok, assets: { linux_x64: "a".repeat(63) } }),
    JSON.stringify({ ...ok, assets: { "linux_x64/../x": "a".repeat(64) } }),
    JSON.stringify({ ...ok, assets: { freebsd_x64: "a".repeat(64) } }),
  ]) {
    assert.throws(() => parsePins(bad), undefined, bad.slice(0, 60));
  }
});

test("install.sh has no version escape hatch and takes digests only from the repo", () => {
  const sh = readFileSync(join(HERE, "..", "install.sh"), "utf8");
  assert.doesNotMatch(sh, /GITLEAKS_VERSION:-\d/, "no hard-coded default version / override");
  assert.doesNotMatch(sh, /checksums\.txt["']?\s*"?\$url_sums|url_sums/, "no checksum file fetched over the download channel");
  assert.match(sh, /gitleaks-pins\.mjs/);
  assert.match(sh, /check-file/);
});

test("digest comparison: only the pinned digest for that key passes", () => {
  const pins = parsePins(JSON.stringify({ version: "8.30.1", assets: { linux_x64: sha256Hex("good"), darwin_x64: sha256Hex("other") } }));
  assert.equal(digestMatchesPin(pins, "linux_x64", sha256Hex("good")), true);
  assert.equal(digestMatchesPin(pins, "linux_x64", sha256Hex("evil")), false);
  assert.equal(digestMatchesPin(pins, "linux_x64", sha256Hex("other")), false, "another platform's digest");
  assert.equal(digestMatchesPin(pins, "windows_x64", sha256Hex("good")), false, "no pin");
  assert.equal(digestMatchesPin(pins, "linux_x64", "GOOD"), false);
  assert.equal(digestMatchesPin(pins, "__proto__", sha256Hex("good")), false);
});

test("CLI check-file: sha mismatch rejected (fixture, no network)", () => {
  const dir = mkdtempSync(join(tmpdir(), "glpin-"));
  const f = join(dir, "gitleaks.tar.gz");
  writeFileSync(f, "not the pinned archive");
  const r = spawnSync(process.execPath, [TOOL, "check-file", "linux_x64", f], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /does NOT match/);
  const none = spawnSync(process.execPath, [TOOL, "check-file", "linux_armv7", f], { encoding: "utf8" });
  assert.equal(none.status, 2, "no pin => refused");
  assert.equal(spawnSync(process.execPath, [TOOL, "version"], { encoding: "utf8" }).stdout.trim(), loadPins().version);
});

test("zip layout: single gitleaks.exe, benign siblings OK, anything that could escape is refused", () => {
  const good = ["LICENSE", "README.md", "gitleaks.exe"];
  assert.deepEqual(listZipMembers(zip(good)), good);
  assert.doesNotThrow(() => assertZipSafeLayout(listZipMembers(zip(good))));
  const bad = {
    "../evil": ["gitleaks.exe", "../evil"],
    "nested traversal": ["gitleaks.exe", "a/../../evil.exe"],
    "absolute": ["gitleaks.exe", "/etc/passwd"],
    "backslash": ["gitleaks.exe", "..\\evil.dll"],
    "drive": ["gitleaks.exe", "C:evil.dll"],
    "ads": ["gitleaks.exe", "gitleaks.exe:evil"],
    "subdir member": ["bin/gitleaks.exe"],
    "missing member": ["LICENSE", "README.md"],
    "duplicate member": ["gitleaks.exe", "gitleaks.exe"],
    "case variant": ["gitleaks.exe", "GITLEAKS.EXE"],
    "trailing dot": ["gitleaks.exe", "x.dll."],
    "control char": ["gitleaks.exe", "a\nb"],
  };
  for (const [label, names] of Object.entries(bad)) {
    assert.throws(() => assertZipSafeLayout(listZipMembers(zip(names))), undefined, label);
  }
  assert.throws(() => listZipMembers(Buffer.from("PK garbage")));
  assert.throws(() => listZipMembers(Buffer.alloc(0)));
});

test("CLI zip-members accepts the layout of the real release and rejects a hostile fixture", () => {
  const dir = mkdtempSync(join(tmpdir(), "glzip-"));
  const ok = join(dir, "ok.zip");
  const evil = join(dir, "evil.zip");
  writeFileSync(ok, zip(["LICENSE", "README.md", "gitleaks.exe"]));
  writeFileSync(evil, zip(["gitleaks.exe", "../evil"]));
  assert.equal(spawnSync(process.execPath, [TOOL, "zip-members", ok]).status, 0);
  assert.equal(spawnSync(process.execPath, [TOOL, "zip-members", evil]).status, 1);
});

test("extracted layout: exactly one regular gitleaks.exe, nothing else, no symlink", () => {
  const mk = () => mkdtempSync(join(tmpdir(), "glx-"));
  const ok = mk();
  writeFileSync(join(ok, "gitleaks.exe"), "x");
  assert.doesNotThrow(() => assertExtractedLayout(ok));
  assert.equal(spawnSync(process.execPath, [TOOL, "check-extracted", ok]).status, 0);

  const empty = mk();
  assert.throws(() => assertExtractedLayout(empty));
  const extra = mk();
  writeFileSync(join(extra, "gitleaks.exe"), "x");
  writeFileSync(join(extra, "evil.dll"), "x");
  assert.throws(() => assertExtractedLayout(extra));
  assert.equal(spawnSync(process.execPath, [TOOL, "check-extracted", extra]).status, 1);
  const dirInstead = mk();
  mkdirSync(join(dirInstead, "gitleaks.exe"));
  assert.throws(() => assertExtractedLayout(dirInstead));
  const link = mk();
  writeFileSync(join(link, "real"), "x");
  try {
    symlinkSync(join(link, "real"), join(link, "gitleaks.exe"));
  } catch {
    return; // no symlink privilege (Windows without developer mode): the other cases already ran
  }
  assert.throws(() => assertExtractedLayout(link)); // two entries AND a symlink
  const only = mk();
  const target = join(mk(), "t");
  writeFileSync(target, "x");
  symlinkSync(target, join(only, "gitleaks.exe"));
  assert.throws(() => assertExtractedLayout(only));
});
