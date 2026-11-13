# Agent Ledger

Shared memory for parallel AI coding agents. Every session sees who is working on
what, which files are taken, what was decided and what is still open.

Open source (MIT) · by Ultra Labs · local only, no cloud.

```
$ ledger claim ACME-41 --paths "apps/web/**" --intent "checkout form"
ACME-41 claimed by session a9f2 · apps/web/**

# another session tries to edit a claimed file (via the optional agent adapter):
PreToolUse · denied: apps/web/** is held by session a9f2 (ACME-41)
```

## What it is

- **Items.** Tasks with a state, kind, priority, owner, plan and log. One item = one
  markdown file with YAML frontmatter, in a git repository you own.
- **Claims and guards.** A session claims an item and the paths it will change. A
  guard (an agent hook, optional) denies edits to files another live session holds.
- **Coordination.** `ledger who <repo>` shows live sessions, their files and checkout
  state; `ledger whose <path>` tells you who owns an uncommitted file.
- **Memory.** `ledger brief` gives a new session what is running, what is next, what
  happened recently and the decisions taken. `ledger history` and `ledger search`
  (SQLite FTS5) dig deeper.
- **Intake.** Throw unstructured text at `ledger intake "<text>"`; it is stored
  verbatim, then triaged into items.
- **Web UI.** A local dashboard served by the hub: what is happening now, what waits
  for you, history and comments.

Markdown in git is the source of truth. The SQLite database only holds live state and
a search index and is rebuilt from the markdown if lost.

## Install

Requirements: Node >= 22.18, pnpm, git; macOS or Linux (Windows: planned).

```sh
git clone https://github.com/ultralabss/agent-ledger.git
cd agent-ledger && ./install.sh
```

`install.sh` installs dependencies, builds the web UI, creates the ledger directory
(`~/.ledger`, a git repository), puts a `ledger` shim in `~/.local/bin`, and installs a
background service (launchd on macOS, a systemd user unit on Linux). Useful flags:
`--no-service`, `--port <n>` (if 4747 is taken; the installer fails with a clear message
instead of skipping), `--allow-brew` (let it run `brew install gitleaks` as a fallback;
writes outside `$HOME`), `--help`. The service label is `AGENT_LEDGER_LABEL`
(default `io.agent-ledger.hub`). `./uninstall.sh` removes the service, the shim and the
Claude Code hooks (if you installed them); it never touches your ledger data.

Then:

```sh
ledger status                         # is this ledger's hub up?
ledger repo add acme-shop --path ~/projects/acme-shop --prefix ACME
ledger open                           # sign in to the web UI (one-time code)
```

### Install with your AI agent

Paste this into your coding agent (the repo is private for now, so replace `<repo-url>`):

```text
Install Agent Ledger from <repo-url>: follow INSTALL.md
```

The agent checks prerequisites, runs `./install.sh`, verifies that the hub on the
port is this ledger's hub, and asks you before it registers a project, edits your
`AGENTS.md`, installs Claude Code hooks, or touches graphify. The web UI is at
`http://ledger.localhost:4747` (or your port): `*.localhost` resolves to loopback by
itself, so it needs no `/etc/hosts` entry and no `sudo`.

### Connect an agent

The core is agent-agnostic: any agent that can run a shell command can use the CLI
(`ledger brief`, `ledger claim`, `ledger note`, `ledger done`) or the HTTP API on
`127.0.0.1`. Paste [`examples/AGENTS.md.snippet`](examples/AGENTS.md.snippet) into your
`AGENTS.md` / `CLAUDE.md` equivalent.

For Claude Code there is an optional adapter that wires session hooks (briefing at
session start, file and git guards, inbox delivery):

```sh
node adapters/claude-code/install-hooks.mjs --dry-run   # show the diff, write nothing
node adapters/claude-code/install-hooks.mjs             # asks for confirmation, backs up settings.json
```

See [`adapters/claude-code/README.md`](adapters/claude-code/README.md).

## Usage

```sh
ledger intake "checkout form needs the tax field; error page is unreadable"
ledger add "Tax field in checkout" --repo acme-shop --kind BACKLOG --priority P1
ledger claim ACME-41 --paths "apps/web/**" --intent "checkout form"
ledger note ACME-41 "cart total needs the tax field from the API"
ledger decide --repo acme-shop "Prices are integer cents" --why "no float rounding in totals"
ledger who acme-shop                  # who works where, which files
ledger whose apps/web/cart.tsx        # owner of an uncommitted file
ledger done ACME-41 --ref a1b2c3d     # or commit with a `Closes: ACME-41` trailer
ledger brief acme-shop                # what a new session should know
ledger history --repo acme-shop --since 7d
ledger search "tax field"
```

`ledger --help` lists every command. Exit codes: 0 ok, 2 conflict, 3 hub not running,
4 validation, 5 secret scanner refused the text. If the hub is down, writes are queued
in a local spool and replayed automatically (`ledger wait`).

## Architecture

```
packages/shared/   types, zod schemas, markdown parser, ids, time, secret scanner, API contract
packages/hub/      Hono server on 127.0.0.1, ledger writer, SQLite (node:sqlite) runtime state,
                   git reader, watchers, guards, brief builder, web UI server
packages/cli/      `ledger ...` and the fast hook transport (`ledger hook <event>`)
packages/web/      React + Vite dashboard
adapters/          optional agent integrations (claude-code)
examples/          instruction snippet, repos.yml, headless `ledger-keeper` agent
docs/SPEC.md       full specification
```

Node runs the TypeScript sources directly (type stripping, no build step except the web
UI). Data layout:

```
~/.ledger/                     a git repository (LEDGER_DIR)
  repos.yml
  acme-shop/
    CONTEXT.md  DECISIONS.md
    items/ACME-41.md
    journal/2026-11.md
  intake/2026-11/<id>.md
  .hub/                        gitignored: hub.sqlite, hub.log, token
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `LEDGER_DIR` | `~/.ledger` | Ledger git repository (the data) |
| `LEDGER_HUB_PORT` | `4747` | Hub port (loopback only) |
| `LEDGER_HUB_URL` | `http://127.0.0.1:$LEDGER_HUB_PORT` | Where the CLI connects |
| `LEDGER_PUSH` | `0` | `1` = hub pushes the ledger repo to `origin` periodically. Off by default: nothing leaves your machine |
| `LEDGER_SESSION` | – | Session id used in logs and `claim` |
| `LEDGER_AGENT` | `orchestrator` | Author of comments |
| `LEDGER_REPO` | – | Home repo of the session |
| `LEDGER_SPOOL_DIR` | `$XDG_STATE_HOME/agent-ledger/spool` | Offline write queue |
| `LEDGER_INTRUDE` | `0` | `1` = enable cross-repo `ledger intrude` leases |
| `LEDGER_RECAP_GUARD` | `0` | `1` = Stop-hook check that tagged recap lines carry an item id |
| `LEDGER_RECAP_TAGS` | `BLOCKER,DEPLOY,RISK,UNVERIFIED` | Tags the recap guard checks |
| `LEDGER_WEB_REPLIES` | `0` | `1` = replies typed in the web UI are routed to agents |
| `LEDGER_HEADLESS` | `0` | `1` = hub may spawn an agent CLI headlessly (triage, grooming) |
| `LEDGER_AGENTS_DIR` | – | Directory with `ledger-keeper.md` (see `examples/agents/`) |
| `LEDGER_CLAUDE_BIN` | – | Absolute path of the agent CLI for headless runs |
| `LEDGER_HUB_GUARD` | – | `off` pins every guard to allow until restart |

More (timers, trust pins for the headless binary): `docs/SPEC.md`, `packages/hub/src/config.ts`.
Optional features answer HTTP 403 `{"error":"feature_disabled"}` when off.

## Security notes

- The hub binds `127.0.0.1` only and checks the `Host` header (DNS-rebinding defence).
- Every API call, reads included, needs the bearer token (`.hub/token`, mode 0600) or the
  web UI cookie obtained with a one-time code (`ledger open`).
- Text sent to intake passes a secret scanner and is stored redacted
  (`[REDACTED:<rule>]`); other fields containing secrets are rejected.
- Ledger commits are scanned with gitleaks (a copy pinned and hash-checked by `install.sh`).
  A missing copy is reported loudly; a tampered, stale or failing scanner pauses the ledger commit.
- Ledger text is data, never instructions: it is framed as untrusted when handed to agents.
- Spawned processes use absolute paths and no shell.

Read [SECURITY.md](SECURITY.md) to report a vulnerability.

## Limits

- Single user, single machine. No multi-user auth, no remote access, no TLS.
- macOS and Linux only for now. The Claude Code adapter is the only agent adapter shipped.
- Guards only see what agents report through hooks; a process that ignores them can still
  edit files. Claims are cooperation, not a security boundary.
- Headless runs execute an external agent CLI you configure; they are off by default.
- Pre-1.0: expect breaking changes between minor versions.

## Development

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm hub          # run the hub in the foreground
pnpm ledger status
```

See [CONTRIBUTING.md](CONTRIBUTING.md). License: [MIT](LICENSE).
