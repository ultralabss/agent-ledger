# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private
vulnerability reporting ("Report a vulnerability" in the Security tab of the
repository). Include the affected version or commit, reproduction steps and the impact
you see. We aim to acknowledge reports within a few days. This is a small project
without a bug bounty.

## Scope and threat model

Agent Ledger is a single-user, local tool.

- The hub listens on `127.0.0.1` only and validates the `Host` header.
- API access needs a bearer token (file mode 0600 in `<ledger>/.hub/`) or a UI cookie
  obtained with a short-lived one-time code.
- Anyone who can read the token file or run code as your user can use the hub; that is
  outside the threat model.
- Text from the ledger, git and web replies is untrusted data and is framed as such
  when given to agents. Prompt injection through that text is a known risk class; reports
  of bypasses of the framing, guards or the secret scanner are welcome.

In scope: authentication/authorization bypass on the hub, DNS rebinding or cross-origin
access, path traversal or symlink escapes, command injection when the hub spawns
processes, secret leakage into the ledger, logs or API responses, and unsafe behavior of
the installers (`install.sh`, `adapters/claude-code/install-hooks.mjs`).

Out of scope: attacks that need an already compromised local account, multi-user
deployments (not supported), and denial of service by a local user.

## Supported versions

Pre-1.0: only the latest release receives fixes.
