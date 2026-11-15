/**
 * Precompile the `ledger hook` fast path to plain JavaScript.
 *
 * Measured on this machine (40 samples per variant, stub hub on loopback):
 *
 *   bare `node -e ""`                        p50 16.2 ms   p95 17.2 ms
 *   .mjs, stdin only                         p50 19.7 ms   p95 23.7 ms
 *   .mjs, stdin + fetch to the hub           p50 45.6 ms   p95 55.6 ms
 *   .ts  (today) stdin + fetch to the hub    p50 63.1 ms   p95 69.0 ms
 *
 * So Node's on-the-fly type stripping of `bin.ts` + `hook.ts` costs ~17 ms of
 * the 67 ms budget — more than any other single item we control. `--no-warnings`
 * made no measurable difference (63.3 vs 63.1 p50) and is not used. A keep-alive
 * agent is pointless for a one-request process, as the task notes.
 *
 * This script strips the types ahead of time with the TypeScript compiler that
 * is already a devDependency: no new runtime dependency, no `bun`, and the
 * `.ts` sources stay authoritative. The shim falls back to running the `.ts`
 * directly whenever `dist/` is missing or older than its sources, so a stale
 * or absent build is a slow hook, never a broken one.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = join(root, 'packages', 'cli', 'src');
const outDir = join(root, 'packages', 'cli', 'dist', 'hook');

/** Only the modules on the hot path. `index.ts` is deliberately NOT built: the
 *  slow path can keep paying for type stripping, and building it would drag in
 *  the whole `@agent-ledger/shared` graph.
 *
 *  `hook-bash.ts` + `hook-inbox.ts` are statically imported
 *  by `hook.ts`, `hook-send.ts` is imported dynamically (so `node:http` stays
 *  off the startup path) — all of them still have to exist as `.js` next to it,
 *  or the fast path would fall back to type stripping at the import.
 *
 *  `selfheal.ts` is also dynamic: it is imported only after a
 *  refused connection, so `node:child_process` never loads on a healthy hook. */
const ENTRIES = [
  'hook.ts',
  'hook-bash.ts',
  'hook-inbox.ts',
  'hook-send.ts',
  'selfheal.ts',
  'bin.ts',
];

/** Shared modules the hook imports by relative path (`../../shared/src/<x>.ts`). Dependency-free
 *  (node: builtins only) so they can sit next to the hook as `<x>.js`. */
const SHARED_ENTRIES = ['paths.ts'];

function transpile(source, fileName) {
  const out = ts.transpileModule(source, {
    fileName,
    compilerOptions: {
      target: ts.ScriptTarget.ES2023,
      module: ts.ModuleKind.ESNext,
      isolatedModules: true,
      verbatimModuleSyntax: true,
      removeComments: false,
    },
  });
  return out.outputText;
}

await mkdir(outDir, { recursive: true });

for (const entry of ENTRIES) {
  const source = await readFile(join(srcDir, entry), 'utf8');
  let js = transpile(source, entry);
  // `./hook.ts` / `./hook-*.ts` → the `.js` built here; `./index.ts` → back to
  // the source tree, because the slow path is not compiled.
  js = js
    .replace(/(['"])\.\/(hook(?:-[a-z]+)?|selfheal)\.ts\1/g, "'./$2.js'")
    .replace(/(['"])\.\.\/\.\.\/shared\/src\/([a-z]+)\.ts\1/g, "'./$2.js'")
    .replace(/(['"])\.\/index\.ts\1/g, `'${join(srcDir, 'index.ts')}'`);
  const name = entry.replace(/\.ts$/, '.js');
  await writeFile(join(outDir, name), js, 'utf8');
  process.stdout.write(`build-hook: ${name}\n`);
}

for (const entry of SHARED_ENTRIES) {
  const source = await readFile(join(root, 'packages', 'shared', 'src', entry), 'utf8');
  const name = entry.replace(/\.ts$/, '.js');
  await writeFile(join(outDir, name), transpile(source, entry), 'utf8');
  process.stdout.write(`build-hook: ${name}\n`);
}
