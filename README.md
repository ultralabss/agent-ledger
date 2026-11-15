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
  state; `ledger whose <path>` tells you who owns an uncommitted file;
  `ledger why <path|dir|glob>` tells you which items, claims, decisions and commits
  stand behind a path (metadata only, never file content; gitignored paths answer
  nothing).
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

Requirements: Node >= 22.18, pnpm, git; macOS, Linux, native Windows (PowerShell) or WSL2.
See [Platform support](#platform-support) for what is verified and what is not.

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

Native Windows (a normal, **not elevated** PowerShell, from the cloned repository):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

`install.ps1` only orchestrates; every trust decision (private directories and their ACLs,
the generated shims, the gitleaks digest and archive checks) is made by node through
`ledger setup` and `scripts/gitleaks-pins.mjs`. It puts `ledger.cmd`, `ledger.ps1` and a Git
Bash `ledger` shim in `%LOCALAPPDATA%\agent-ledger\bin` (added to your user PATH only after
you confirm), and registers a Task Scheduler task `agent-ledger` (at logon, as you, not
elevated). `.\uninstall.ps1` removes the task, shims, PATH entry and hooks and keeps the ledger;
`-Purge` also deletes it after you type `delete`. Details and limits: [INSTALL.md](INSTALL.md).

## Platform support

| Platform | CI-verified | Manually verified | Unverified |
|---|---|---|---|
| Linux, ext4 | yes (`ubuntu-latest`) | none recorded | - |
| macOS, APFS | yes (`macos-latest`) | none recorded | - |
| Windows, NTFS | yes (`windows-latest`, a Windows Server image) | **none** | Windows 11 client, installer end to end |
| WSL2 (ext4 inside the distro) | no | **none** | everything |
| Windows ARM64, ReFS, Dev Drive | no | no | everything |

Plainly: **no real Windows 11 client and no WSL2 were available to the maintainers.** The Windows
code paths (PowerShell, `icacls`, SDDL parsing, Task Scheduler, the `.ps1` installer) run in CI on a
Windows Server runner and, locally, only against fakes and fixtures. That runner is elevated, so
the real-ACL tests skip there (the installer and the hub refuse to run elevated). Treat Windows and
WSL2 as "implemented and tested against fixtures", not as "proven on your machine"; reports from real
machines are welcome. The CI column is only as good as the last green run of
`.github/workflows/ci.yml`.

**Refused filesystems.** The ledger, spool and token must live on a filesystem that can keep them
private. exFAT, FAT/FAT32, NFS, SMB and WSL `DrvFs` (`/mnt/c/...`) cannot express owners, modes or
ACLs, so the hub and the installer REFUSE them (fail-closed). The only bypass is
`LEDGER_ALLOW_WEAK_FS=1` (exactly `1`, in the environment, never read from the repo or the ledger).
It relaxes only what the filesystem cannot express (mode bits, owner, hard-link counts, ACLs on
non-ACL volumes), never the symlink / reparse-point / regular-file / identity checks, and it is
loud: a warning in the hub log, `fs_weak` in `/v1/healthz`, a banner in the web UI and
`ledger doctor` exiting 2. Move the ledger instead of using it when you can.

**Known v1 limits.**

- The Task Scheduler task briefly flashes a console window at logon (no wrapper in v1).
- One hub per machine: a hub in WSL and one in Windows share `127.0.0.1:4747`. Pick one; `ledger
  doctor` reports two ledgers as an error.
- Headless features and Claude Code hooks need a native `claude.exe`; the npm `claude.cmd` shim is
  refused on Windows (no shell is ever used to start a child process).
- On a profile path with non-ASCII characters `ledger.cmd` is not generated (cmd.exe would read it
  in the OEM code page); `ledger.ps1` and the Git Bash shim are.
- Paths containing `%`, `!` or `"` are refused by the installer (they would be re-interpreted by
  cmd.exe), as are paths over 259 characters unless long paths are enabled.

Then:

```sh
ledger status                         # is this ledger's hub up?
ledger repo add acme-shop --path ~/projects/acme-shop --prefix ACME
ledger open                           # sign in to the web UI (one-time code)
```

### Install with your AI agent

Paste this into your coding agent:

```text
Install Agent Ledger from https://github.com/ultralabss/agent-ledger : follow INSTALL.md
```

The agent checks prerequisites, runs `./install.sh`, verifies that the hub on the
port is this ledger's hub, and asks you before it registers a project, edits your
`AGENTS.md`, installs Claude Code hooks, or touches graphify. The web UI is at
`http://ledger.localhost:4747` (or your port): `*.localhost` resolves to loopback by
itself, so it needs no `/etc/hosts` entry and no `sudo`. `ledger open` signs you in
there with a one-time code.

The hub accepts exactly three `Host` values, each with its own port and nothing else:
`127.0.0.1`, `localhost` and `ledger.localhost`. Any other name, including every
other `*.localhost`, is refused (DNS-rebinding defence). The sign-in cookie is
host-only, so a browser signed in on `ledger.localhost` is a separate session from
one on `127.0.0.1`.

- **Name resolution.** Safari, Chrome and Firefox map `*.localhost` to loopback
  themselves, and so does `curl`. The hub listens on `127.0.0.1` only. A client that
  resolves `ledger.localhost` to `::1` first (some resolvers return both) gets
  "connection refused" on IPv6 and should fall back to IPv4; if a client does not,
  use `http://127.0.0.1:<port>` (same UI, accepted by the hub). Resolvers without
  `*.localhost` support (some Linux setups) need the same fallback.
- **Port.** The default `4747` is not reserved; pick another with `LEDGER_HUB_PORT`
  (for example in the service unit) and the URL becomes
  `http://ledger.localhost:<port>`. A port-less URL would need port 80 (root or a
  reverse proxy), which this project deliberately does not set up.

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
ledger why apps/web/cart.tsx          # items, claims, decisions, commits behind a path
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
- The ledger is private data (tasks, decisions, history of all your projects). Never push it to a
  public repository, and never give it the same remote as your code: it needs its own private
  remote, or none. `ledger doctor` warns when the ledger remote equals the code remote or looks
  public (offline heuristics; `ledger doctor --online` additionally asks GitHub's public API once
  whether a github.com remote is publicly visible).

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
