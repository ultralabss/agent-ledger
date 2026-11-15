# Install Agent Ledger (instructions for an AI agent)

You are an AI coding agent asked to install Agent Ledger on the user's machine.
Follow these steps in order. Do not skip the questions: they are marked **ASK**.
Never edit files in the ledger directory by hand, never run `sudo`, never edit
`/etc/hosts`. If you need the user to run a command in their own terminal,
give exactly one at a time and wait for its output before the next one.

`<repo-dir>` = the directory of this checkout (where `install.sh` lives).

## 1. Check prerequisites

```sh
node -v        # must be >= 22.18
git --version
pnpm --version
```

If one is missing or too old, stop and tell the user what to install (Node:
https://nodejs.org, pnpm: `corepack enable`). Supported: macOS, Linux, native Windows and WSL2
(see the support matrix in `README.md`; Windows and WSL2 are not verified on real machines).

## 2. Run the installer

```sh
cd <repo-dir> && ./install.sh
```

What it does, all under `$HOME`: `pnpm install`, builds the web UI, creates the
ledger directory (`~/.ledger`, a git repository), writes the `ledger` shim to
`~/.local/bin`, and installs the hub as a user service (launchd on macOS,
systemd user unit on Linux).

- Port: the hub uses 4747 by default. If another process owns it the installer
  stops with a clear message (it never silently continues). Re-run with
  `./install.sh --port <n>` (or `LEDGER_HUB_PORT=<n>`). Use the same port for
  every `ledger` command afterwards (`export LEDGER_HUB_PORT=<n>`).
- gitleaks (second secret check before every ledger commit) is downloaded from the official
  GitHub release and verified against the sha256 pins in the repository
  (`ops/gitleaks-pins.json`: version + digest per asset). The digest is never fetched from the
  network, and there is no `GITLEAKS_VERSION=` override: to upgrade gitleaks, change the pins
  file (version and digests from the official `gitleaks_<ver>_checksums.txt`) in a reviewed
  commit and re-run `./install.sh`. A digest mismatch discards the download. Only if the
  download fails and `brew` exists does the installer offer `brew install gitleaks`; that
  writes outside `$HOME`, so it happens only with `./install.sh --allow-brew` (or an
  interactive yes). Do not pass `--allow-brew` unless the user agreed.
- `~/.local/bin` must be in `PATH` (the installer prints a note if it is not).

### Native Windows

Use PowerShell, **not elevated** (both scripts and the hub refuse to run as Administrator), and the
same checkout:

```powershell
cd <repo-dir>
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Options: `-LedgerDir <path>`, `-Port <n>`, `-NodePath <absolute node.exe>`, `-NoService`,
`-SkipGitleaks`, `-AddToPath`. Same requirements as above (node >= 22.18, pnpm, Git for Windows in its
standard location). What it does, all inside your profile:

- the node half (`node packages/cli/src/bin.ts setup --platform-init`) verifies node.exe, creates the
  private directories (ledger, `.hub`, `.hub\bin`, `%LOCALAPPDATA%\agent-ledger` and its `bin`) with an
  ACL for you and SYSTEM only, writes `hub.env` (private, read by `node --env-file`) and the shims
  `ledger.cmd`, `ledger.ps1` and `ledger` (Git Bash) into `%LOCALAPPDATA%\agent-ledger\bin`;
- gitleaks: pinned digest check (`scripts/gitleaks-pins.mjs check-file windows_x64`), zip layout check,
  extraction with `System32\tar.exe` into a fresh private directory, layout check, then a verified copy
  with `.sha256` and `.origin` next to it in `<ledger>\.hub\bin`. On any failure nothing is installed
  and the hub commits without the second check;
- the shim directory goes on your user PATH **only after you answer yes** (or pass `-AddToPath`);
- Task Scheduler task `agent-ledger`: at logon, as you, interactive, run level Limited, started with
  `node.exe --env-file=<hub.env> <hub bin.ts>`. v1 limit: a console window flashes at logon.

A path that fails `assertShimSafePath` (`%`, `!`, `"`, control characters, over 259 characters) aborts
the install; it is refused, never escaped. Call `ledger status` from a new terminal or the full shim
path. A native `claude.exe` is required for headless features; `claude.cmd` is refused.

**Claude Code hooks on Windows.** `install-hooks.mjs` writes `"<node.exe>" "<bin.ts>" hook <event>`
(forward slashes, node.exe and the script directly, never a `.cmd`). `hooks/auto-commit-nudge.sh` is
still a bash script (it needs `bash`, `curl`, `sed`, `tr`, which Git Bash provides); wire it as
`bash <path>/auto-commit-nudge.sh` by hand if you want it. A node rewrite is not done yet.

**WSL2.** Use `./install.sh` inside the distro and keep the ledger on the distro's own filesystem
(ext4), not under `/mnt/c`: DrvFs is refused. Do not run a second hub on the Windows side.

**Weak filesystems.** exFAT, FAT, NFS, SMB and DrvFs are refused; `LEDGER_ALLOW_WEAK_FS=1` bypasses
that with loud warnings (see `README.md`, Platform support). Do not set it on the user's behalf.

## 3. Verify the hub is THIS ledger's hub

```sh
ledger status
```

Expected first line: `hub ok · port <port> · ledger <ledger-dir> · ...`.
`ledger status` exits non-zero (3) and says "does not answer for ledger" when a
different process, or a hub of another ledger directory, owns the port. Treat
that as a failed install, not as success. Also check that the printed
`<ledger-dir>` is the directory you expect (default `~/.ledger`). If the command
is not found, call `~/.local/bin/ledger status`. `ledger doctor` explains a hub
that does not answer: service state (launchd on macOS, the systemd user unit and
linger on Linux), whether the answering hub serves this ledger directory, the
`ledger` shim on `PATH`, the hook entries and the ledger remote. `ledger doctor
--json` prints the same checks as `{schema, platform, checks:[{id, status, detail}],
summary}` (status `ok|warn|fail|info`; exit code 1 only for `fail`).

**The ledger is private.** It holds the tasks, decisions and history of every
project on the machine. Do not push it to a public repository, do not give it
the same remote as the code of any project. If the user wants a ledger remote, **ASK** and use a
separate private repository; the default is no remote. `ledger doctor` warns
when the ledger remote equals the code remote or looks public. It works offline;
`ledger doctor --online` makes one unauthenticated request to GitHub's public
API (owner/repo only) to confirm a github.com remote is not publicly visible.

The web UI is at `http://ledger.localhost:<port>` (default
`http://ledger.localhost:4747`). `*.localhost` resolves to loopback by itself:
no `/etc/hosts` entry and no `sudo` needed. `ledger open` opens it and signs
you in with a one-time code. The hub also answers on `127.0.0.1:<port>` and
`localhost:<port>`, but on no other `*.localhost` name. If a browser or client
cannot resolve `ledger.localhost`, use `http://127.0.0.1:<port>` instead.

## 4. Register the user's project

**ASK:** "Which project directory should I add to the ledger?" Propose the
current working directory but wait for the answer. Then:

```sh
ledger repo add <slug> --path <absolute-project-path> --prefix <XX>
ledger repo ls
```

`<slug>` is a short lowercase name, `<XX>` a 2-5 letter prefix for item ids.
Add only the projects the user names.

## 5. Agent instructions snippet (after confirmation)

**ASK:** "May I append the ledger section to this project's `AGENTS.md`
(or `CLAUDE.md`)?" On yes, append the contents of `examples/AGENTS.md.snippet`
to that file (create it if it does not exist). Show the user what you added.
Do not change anything else in the file. The snippet includes the rule "hand the human
terminal commands one at a time, wait for the output"; do not drop that line.

## 6. Optional: Claude Code hooks

Only for users of Claude Code. **ASK:** "Install the Agent Ledger hooks into
`~/.claude/settings.json`? They brief each session, guard files another session
has claimed and record touched files." Do nothing without an explicit yes.

```sh
node <repo-dir>/adapters/claude-code/install-hooks.mjs --dry-run   # show the diff first
node <repo-dir>/adapters/claude-code/install-hooks.mjs --yes       # only after the user said yes
```

The script backs up `settings.json` and only adds or removes its own entries.
Details: `adapters/claude-code/README.md`.

## 7. Optional: graphify

**ASK:** "Do you use graphify (a code knowledge-graph tool, Python)? Should I
note it for the ledger integration?" This is optional and nothing is installed
without the user's consent.

- `ledger doctor` prints `graphify: found (<path>)` or `graphify: not found
  (optional)`. You can also check `command -v graphify`, `uvx --version` or
  `pipx --version`.
- If graphify is already in `PATH` and the user wants it: `ledger repo add`
  accepts `--graphify <path>` to point a repo at its graph output.
- If it is not installed, do not install it for the user. Tell them it is
  optional and how to get it (their Python tooling: `uvx` or `pipx`), and move
  on. There is no dedicated graphify command in the ledger yet.

## 8. Report back

Tell the user: the ledger directory, the port, the web UI address, which
projects were registered, whether the snippet and the hooks were added, and
whether gitleaks is active (`ledger status` prints a line when it is missing).

## Uninstall

```sh
cd <repo-dir> && ./uninstall.sh
```

(Windows: `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1`; it removes the task, the
shims, `hub.env`, the PATH entry and the hooks, and keeps the ledger unless you pass `-Purge` and
type `delete` to confirm.)

Removes the service, the `ledger` shim and, when `node` is available, the Claude
Code hook entries (the same as `node adapters/claude-code/install-hooks.mjs
--uninstall`). The ledger directory is never touched: it is a git repository
with the user's history, and deleting it is the user's decision.
