# Install Agent Ledger (instructions for an AI agent)

You are an AI coding agent asked to install Agent Ledger on the user's machine.
Follow these steps in order. Do not skip the questions: they are marked **ASK**.
Never edit files in the ledger directory by hand, never run `sudo`, never edit
`/etc/hosts`.

`<repo-dir>` = the directory of this checkout (where `install.sh` lives).

## 1. Check prerequisites

```sh
node -v        # must be >= 22.18
git --version
pnpm --version
```

If one is missing or too old, stop and tell the user what to install (Node:
https://nodejs.org, pnpm: `corepack enable`). Supported: macOS and Linux.

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
- gitleaks (second secret check before every ledger commit) is downloaded and
  checksum-verified. Only if that fails and `brew` exists does the installer
  offer `brew install gitleaks`; that writes outside `$HOME`, so it happens only
  with `./install.sh --allow-brew` (or an interactive yes). Do not pass
  `--allow-brew` unless the user agreed.
- `~/.local/bin` must be in `PATH` (the installer prints a note if it is not).

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
that does not answer.

The web UI is at `http://ledger.localhost:<port>` (default
`http://ledger.localhost:4747`). `*.localhost` resolves to loopback by itself:
no `/etc/hosts` entry and no `sudo` needed. `ledger open` gives a one-time
sign-in code.

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
Do not change anything else in the file.

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

Removes the service, the `ledger` shim and, when `node` is available, the Claude
Code hook entries (the same as `node adapters/claude-code/install-hooks.mjs
--uninstall`). The ledger directory is never touched: it is a git repository
with the user's history, and deleting it is the user's decision.
