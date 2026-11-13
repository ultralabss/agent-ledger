#!/usr/bin/env node

// Fast path first: `ledger hook <event>` runs on every tool call, so it must not
// pay for loading the arg parser, the hub client and every command handler.
// Node strips types per module at startup; skipping `./index.ts` here measured
// ~6 ms per hook (66 → 60 ms p50). Everything else takes the normal route.
if (process.argv[2] === 'hook') {
  const { runHook } = await import('./hook.ts');
  process.exitCode = await runHook(process.argv[3] ?? '', {
    out: (line) => process.stdout.write(`${line}\n`),
    env: process.env,
  });
} else {
  const { run } = await import('./index.ts');
  process.exitCode = await run(process.argv.slice(2), {
    out: (line) => process.stdout.write(`${line}\n`),
    err: (line) => process.stderr.write(`${line}\n`),
    env: process.env,
    cwd: process.cwd(),
    tty: { stdin: process.stdin.isTTY === true, stdout: process.stdout.isTTY === true },
  });
}
