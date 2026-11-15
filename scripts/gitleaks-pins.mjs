#!/usr/bin/env node
// Shared verification helper for install.sh and install.ps1 (spec S7, invariant I8):
// no gitleaks binary is used unless its archive digest equals the sha256 recorded in
// the repository (`ops/gitleaks-pins.json`). The digest is NEVER fetched from the network.
//
// Usage (exit 0 = ok, 1 = refused, 2 = usage / no pin):
//   node scripts/gitleaks-pins.mjs version
//   node scripts/gitleaks-pins.mjs asset <key>                  prints the asset file name
//   node scripts/gitleaks-pins.mjs check-file <key> <file>      archive digest == pin
//   node scripts/gitleaks-pins.mjs zip-members <zip>            Windows zip layout is safe
//   node scripts/gitleaks-pins.mjs check-extracted <dir>        after `tar.exe -xf`: dir holds exactly gitleaks.exe
import { createHash, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_PINS_PATH = join(HERE, "..", "ops", "gitleaks-pins.json");

const VERSION_RE = /^\d+\.\d+\.\d+$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const KEY_RE = /^(?:linux|darwin|windows)_(?:x64|arm64)$/;

/** Parse and validate a pins document. Throws on anything unexpected (fail-closed). */
export function parsePins(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Error("pins: not valid JSON");
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) throw new Error("pins: not an object");
  if (typeof doc.version !== "string" || !VERSION_RE.test(doc.version)) throw new Error("pins: bad version");
  const assets = doc.assets;
  if (assets === null || typeof assets !== "object" || Array.isArray(assets)) throw new Error("pins: no assets");
  const keys = Object.keys(assets);
  if (keys.length === 0) throw new Error("pins: empty assets");
  for (const k of keys) {
    if (!KEY_RE.test(k)) throw new Error(`pins: unknown asset key ${JSON.stringify(k)}`);
    if (typeof assets[k] !== "string" || !SHA_RE.test(assets[k])) throw new Error(`pins: bad sha256 for ${k}`);
  }
  return { version: doc.version, assets: { ...assets } };
}

export function loadPins(path = DEFAULT_PINS_PATH) {
  return parsePins(readFileSync(path, "utf8"));
}

/** Official release asset name for a pin key (`windows_*` is a zip, the rest tar.gz). */
export function assetName(version, key) {
  if (!VERSION_RE.test(version) || !KEY_RE.test(key)) throw new Error("bad version or key");
  return `gitleaks_${version}_${key}.${key.startsWith("windows_") ? "zip" : "tar.gz"}`;
}

export function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

/** Timing-safe digest comparison against the pin for `key`. Unknown key => false. */
export function digestMatchesPin(pins, key, actualHex) {
  const want = Object.hasOwn(pins.assets, key) ? pins.assets[key] : undefined;
  if (want === undefined || typeof actualHex !== "string" || !SHA_RE.test(actualHex)) return false;
  return timingSafeEqual(Buffer.from(want, "utf8"), Buffer.from(actualHex, "utf8"));
}

/**
 * Member names of a zip, read from the central directory (no extraction). Throws on
 * anything malformed, encrypted-looking or Zip64 (the gitleaks release zips are neither).
 */
export function listZipMembers(buf) {
  const EOCD = 0x06054b50;
  const CEN = 0x02014b50;
  const min = Math.max(0, buf.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("zip: no end-of-central-directory record");
  const total = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (total === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) throw new Error("zip: zip64 not supported");
  if (cdOff + cdSize > eocd) throw new Error("zip: central directory out of range");
  const names = [];
  let p = cdOff;
  for (let n = 0; n < total; n += 1) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CEN) throw new Error("zip: bad central directory entry");
    const flags = buf.readUInt16LE(p + 8);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    if (p + 46 + nameLen > buf.length) throw new Error("zip: truncated name");
    // Bit 11 = UTF-8 names; anything else is decoded as latin1 and checked below anyway.
    names.push(buf.toString(flags & 0x800 ? "utf8" : "latin1", p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;
  }
  if (names.length !== total) throw new Error("zip: entry count mismatch");
  return names;
}

/**
 * The Windows extraction takes exactly ONE named member (`gitleaks.exe`) and nothing else.
 * Refuse the archive when that member is missing or duplicated, or when ANY member name could
 * land outside the target (separators, `..`, drive/ADS colon, absolute, control characters,
 * trailing dot/space). Benign extra top-level files (LICENSE, README.md) are tolerated because
 * they are never extracted.
 */
export function assertZipSafeLayout(names, member = "gitleaks.exe") {
  let seen = 0;
  for (const name of names) {
    if (name === "" || /[\\/:\x00-\x1f\x7f]/.test(name) || name === "." || name === ".." || /[. ]$/.test(name)) {
      throw new Error(`zip: unsafe member name ${JSON.stringify(name)}`);
    }
    if (name === member) seen += 1;
    else if (name.toLowerCase() === member.toLowerCase()) throw new Error("zip: case-variant duplicate of the target member");
  }
  if (seen !== 1) throw new Error(`zip: expected exactly one ${member}`);
}

/**
 * After the Windows extraction (`%SystemRoot%\\System32\\tar.exe -xf <zip> -C <fresh private dir> gitleaks.exe`)
 * the fresh directory must contain exactly one entry: a regular file `gitleaks.exe` that is not a
 * symlink / junction / reparse point. Anything else means the extraction did something unexpected.
 */
export function assertExtractedLayout(dir, member = "gitleaks.exe") {
  const entries = readdirSync(dir);
  if (entries.length !== 1 || entries[0] !== member) throw new Error(`extract: expected exactly ${member}`);
  const st = lstatSync(join(dir, member));
  if (st.isSymbolicLink() || !st.isFile()) throw new Error(`extract: ${member} is not a regular file`);
}

function main(argv) {
  const [cmd, a, b] = argv;
  try {
    const pins = loadPins();
    if (cmd === "version" && a === undefined) {
      process.stdout.write(`${pins.version}\n`);
      return 0;
    }
    if (cmd === "asset" && a !== undefined && b === undefined) {
      if (!Object.hasOwn(pins.assets, a)) return 2;
      process.stdout.write(`${assetName(pins.version, a)}\n`);
      return 0;
    }
    if (cmd === "check-file" && a !== undefined && b !== undefined) {
      if (!Object.hasOwn(pins.assets, a)) {
        process.stderr.write(`gitleaks-pins: no pin for ${a}\n`);
        return 2;
      }
      if (digestMatchesPin(pins, a, sha256Hex(readFileSync(b)))) return 0;
      process.stderr.write(`gitleaks-pins: sha256 of the archive does NOT match the in-repo pin for ${a}\n`);
      return 1;
    }
    if (cmd === "zip-members" && a !== undefined && b === undefined) {
      assertZipSafeLayout(listZipMembers(readFileSync(a)));
      return 0;
    }
    if (cmd === "check-extracted" && a !== undefined && b === undefined) {
      assertExtractedLayout(a);
      return 0;
    }
    process.stderr.write("usage: gitleaks-pins.mjs version | asset <key> | check-file <key> <file> | zip-members <zip> | check-extracted <dir>\n");
    return 2;
  } catch (err) {
    process.stderr.write(`gitleaks-pins: ${err instanceof Error ? err.message : "error"}\n`);
    return 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) process.exitCode = main(process.argv.slice(2));
