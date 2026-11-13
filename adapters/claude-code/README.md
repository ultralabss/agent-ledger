# Claude Code adapter (optional)

The ledger core is agent-agnostic: the `ledger` CLI and the local HTTP API on
`127.0.0.1` are all any agent needs (see `examples/AGENTS.md.snippet`). This
adapter adds Claude Code hooks so that the ledger can also act *for* the agent:
brief it at session start, block edits to files another session has claimed,
and keep the ledger's idea of "who works where" accurate without the agent
having to remember to call anything.

Nothing in this directory runs unless you install it, and `install.sh` never
touches `~/.claude`.

## What gets installed

`install-hooks.mjs` adds eight entries to `~/.claude/settings.json`. Each one is
the command `<path to the ledger shim> hook <event>`, with a 5 s timeout:

| Claude Code event | Matcher | Hub event | What the hub does |
|---|---|---|---|
| `SessionStart` | none | `session-start` | registers the session, injects the repo brief |
| `UserPromptSubmit` | none | `user-prompt-submit` | delivers pending inbox messages |
| `PreToolUse` | `Edit\|Write\|MultiEdit\|NotebookEdit` | `pre-tool-use` | file guard: denies edits to files claimed by another session |
| `PreToolUse` | `Bash` | `pre-tool-use` | guards shell commands that write files claimed by another session |
| `PostToolUse` | `Edit\|Write\|MultiEdit\|NotebookEdit` | `post-tool-use` | records touched files for the session |
| `PostToolUse` | `Bash` | `post-tool-use` | same, for files changed through the shell |
| `Stop` | none | `stop` | optional recap check (`LEDGER_RECAP_GUARD=1`) |
| `SessionEnd` | none | `session-end` | marks the session ended, releases what it held |

Entries from other tools are never modified: an entry is "ours" only when its
command is exactly `<shim> hook <event>`, so re-running is a no-op and
`--uninstall` removes exactly these eight.

## Install, preview, uninstall

```bash
# 1. preview: prints a diff, writes nothing, creates no directories
node adapters/claude-code/install-hooks.mjs --dry-run

# 2. install: shows the target file and the entries it will add, then asks you to type "yes"
node adapters/claude-code/install-hooks.mjs

# remove exactly the entries it added (same confirmation)
node adapters/claude-code/install-hooks.mjs --uninstall
```

Flags:

- `--yes`: skip the prompt. Required when stdin is not a TTY (scripts, CI); without a TTY and without `--yes` the script refuses and changes nothing.
- `--settings <file>`: target a different settings file (default `~/.claude/settings.json`).
- `--ledger <path>`: the shim path to write into the hook commands (default `~/.local/bin/ledger`).

Safety properties: a backup `settings.json.bak.<timestamp>` is written before
every change; the write is atomic (tmp file + rename); a symlinked or dangling
`settings.json` (dotfiles managers) is followed and stays a symlink; an
exclusive lock file serialises overlapping runs; invalid JSON is never
overwritten.

## Fail-open behaviour

Every hook has a hard 1 s budget inside the hub (5 s outer timeout in
`settings.json`). If the hub is down, slow or unreachable, the hook exits 0 and
the agent carries on: a ledger outage never blocks your editor. Writes made while
the hub is down are spooled to disk and sent when it is back (`ledger wait`).
The one exception is deliberate: when the hub *is* reachable and says a file is
claimed by another live session, the edit is denied with an explanation.

Kill switch: `ledger guard off` (or `LEDGER_HUB_GUARD=off` in the hub's
environment) turns every guard into "allow" until the hub restarts.

## Optional: commit nudge

`hooks/auto-commit-nudge.sh` is a `Stop` hook that asks the hub (`GET /v1/nudge`)
whether *this* session has piled up enough uncommitted files of its own to be
worth a reminder, and prints the exact `git commit --only -- <files>` command.
Other sessions' files are never counted or mentioned. It is not installed by
`install-hooks.mjs`; add it to `settings.json` by hand if you want it.

## Other agents

Codex, Aider, Cursor, a plain shell script: anything that can run a command or
send an HTTP request can use the ledger without this adapter. The CLI is the
documented interface (`ledger brief`, `ledger claim`, `ledger note`,
`ledger done`, ...); the HTTP API lives under `http://127.0.0.1:<port>/v1/` and
needs the token in `<ledger dir>/.hub/token`. Paste `examples/AGENTS.md.snippet`
into the agent's instruction file and you have the protocol without hooks.
