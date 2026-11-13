# Examples

| File | What it is |
|---|---|
| `AGENTS.md.snippet` | Agent-agnostic instructions to paste into `AGENTS.md`, `CLAUDE.md` or any other agent instruction file. Teaches an agent to read the brief, claim work, note findings and close items. |
| `repos.yml` | A sample `repos.yml` (acme example). Normally maintained by `ledger repo add`; shows the optional `contracts` / `consumers` keys. |
| `agents/ledger-keeper.md` | A generic agent definition for headless triage and grooming. Copy it into the agents directory your agent CLI reads, or point `LEDGER_AGENTS_DIR` at a directory that contains it. |

## Optional features (all off by default)

Set these in the environment of the hub. `install.sh` copies any of them that
are set when you run it into the launchd/systemd service environment.

| Variable | Effect |
|---|---|
| `LEDGER_HEADLESS=1` | The hub may spawn an agent CLI headlessly (intake triage, weekly grooming, reply workers). Needs `LEDGER_CLAUDE_BIN`; `./install.sh --headless` sets both. |
| `LEDGER_AGENTS_DIR=<dir>` | Directory with agent definitions (such as `agents/ledger-keeper.md`) used by the headless runs. |
| `LEDGER_INTRUDE=1` | Enables `ledger intrude`: a short, leased edit in a repo another session is working in, plus contract change notices between repos (`contracts` / `consumers` in `repos.yml`). |
| `LEDGER_RECAP_GUARD=1` | Claude Code adapter: a Stop-hook check of the agent's closing "Needs you" recap. A line that uses one of the recap tags must carry an item id from the ledger. |
| `LEDGER_RECAP_TAGS=BLOCKER,DEPLOY,RISK,UNVERIFIED` | Comma list of tags the recap guard requires an item id for. |
| `LEDGER_WEB_REPLIES=1` | Replies typed in the web UI are routed back to agents (the session that owns the item, or a reply worker). |
| `LEDGER_GROOM_WEEKLY=1` | Weekly grooming run (Monday 09:00 local). Needs `LEDGER_HEADLESS=1`. |
| `LEDGER_PUSH=1` | The hub pushes the ledger repository to its git remote periodically. |

Everything works without any of them: the core is the CLI, the HTTP API on
127.0.0.1, and plain markdown in a git repository.
