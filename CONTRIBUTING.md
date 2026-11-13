# Contributing

Thanks for helping. Keep changes small and focused.

## Setup

Node >= 22.18 and pnpm.

```sh
pnpm install
pnpm typecheck
pnpm test
```

Tests use `node:test` and temporary directories only; they never touch your real
`~/.ledger`. Run a single file with `node --test packages/hub/src/some.test.ts`.
There is no build step for the TypeScript sources (Node type stripping): use
`erasableSyntaxOnly`-compatible syntax (no enums, no parameter properties).

## Guidelines

- Read [docs/SPEC.md](docs/SPEC.md) first. Code comments reference its section numbers.
- English only: code, comments, messages, docs.
- Every change needs a test. Security-relevant code (token, Origin/Host checks, secret
  scanner, guards, process spawning, installers) needs a test for the failing case.
- Do not weaken a guard to make a test pass. Fail closed on security checks.
- No real names, paths, tokens or customer data in fixtures: use `acme`, `example.com`,
  `/home/user`.
- Optional features stay behind their `LEDGER_*` flag and default to off.
- Conventional Commits (`feat:`, `fix:`, `docs:`, ...), subject <= 50 characters.

## Pull requests

Describe what changed and why, and say how you tested it. CI runs typecheck and tests
on Node 22.

## Security issues

See [SECURITY.md](SECURITY.md); do not file them as public issues.

By contributing you agree that your contribution is licensed under the MIT License.
