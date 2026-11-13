# AGENTS.md: rules for agents working in this repo

Installing Agent Ledger for a user? Follow [INSTALL.md](INSTALL.md); this file is
for changing the code.

## Layout

- `packages/hub`: the local hub (HTTP API on 127.0.0.1, git-backed ledger, guards).
- `packages/cli`: the `ledger` command and the hook entry points.
- `packages/shared`: code shared by both. `packages/web`: the web UI.
- `adapters/claude-code`: optional Claude Code hooks installer.
- `install.sh` / `uninstall.sh`: user-level service and shim installer.
- `docs/SPEC.md`: the spec. Code comments cite its section numbers.

## Commands

```sh
pnpm install
pnpm typecheck
pnpm test                                    # or: node --test <file>
```

Tests use `node:test` and temporary directories only. They must never touch the
real `~/.ledger`, `~/.claude` or a real service (use a throwaway `HOME` and a
unique `AGENT_LEDGER_LABEL`).

## Rules

- English only: code, comments, messages, docs.
- Every change needs a test; security-relevant code needs a test for the failing
  case. Do not weaken a guard to make a test pass; fail closed.
- No real names, paths, tokens or customer data in fixtures (`acme`, `example.com`).
- Optional features stay behind their `LEDGER_*` flag and default to off.
- Never edit a ledger directory by hand: use the `ledger` CLI.
- Nothing outside `$HOME` and nothing in `~/.claude` without explicit user
  consent (see the flags in `install.sh --help`).
- Do not run `git checkout`, `git stash` or `git reset` in a shared working tree,
  and commit only your own files.
- Conventional Commits, subject <= 50 characters. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Using the ledger while you work here

Add the section from [`examples/AGENTS.md.snippet`](examples/AGENTS.md.snippet) to
your own instructions: `ledger brief` at session start, `ledger claim` before a
larger change, `ledger done` when finished.
