# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `ledger why <path|dir|glob>` and `GET /v1/repos/:slug/why?path=`: items, live claims with intent, decisions, session summaries and git trailers behind a path. Metadata only; gitignored paths answer nothing; output is framed as data.
- The hub accepts `ledger.localhost:<port>` (exactly that name) next to `127.0.0.1` and `localhost`; `ledger open` and the installer banner use it.

## [0.1.0] — 2026-11-13

First public release.

### Added
- Items with states (`proposed`, `open`, `doing`, `blocked`, `done`, `dropped`), kinds (`BLOCKER`, `DEPLOY`, `RISK`, `UNVERIFIED`, `BACKLOG`) and priorities (`P0`–`P3`), stored as plain markdown in a git repository.
- Claims with an edit/git guard: sessions see which files other sessions hold.
- `ledger who`, `ledger whose`, `ledger brief`, `ledger history`, `ledger search` (SQLite FTS5), intake bin, decisions journal.
- Local hub on `127.0.0.1` with bearer token, Host/Origin allowlist and a web UI.
- Offline spool: writes made while the hub is down are queued and replayed.
- `install.sh` with a launchd (macOS) or systemd user unit (Linux) service.
- Claude Code adapter in `adapters/claude-code/` (hooks installer with `--dry-run`, backup and consent).
- Optional features, all off by default: `LEDGER_INTRUDE`, `LEDGER_RECAP_GUARD`, `LEDGER_WEB_REPLIES`, `LEDGER_HEADLESS`, `LEDGER_PUSH`.
