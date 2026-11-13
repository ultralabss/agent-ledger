# Repository settings (maintainer checklist)

These GitHub settings cannot be stored in files. Apply them before the repository is
made public, then tick them off. Nothing here is changed by code or CI.

## 0. Files to finish

- [x] `CODEOWNERS` names `@fiuipko` (organization `ultralabss`, repo `agent-ledger`). Make sure
      this account has write access, otherwise code-owner review is silently skipped; add a
      second owner or a team once there is one.
- [ ] Enable GitHub Actions only after the pinned workflows are on `main`.

## 1. Account

- [ ] 2FA with a hardware security key (passkey or FIDO2) on every account with write
      access; no SMS fallback. Keep at least two keys.
- [ ] Sign commits and tags with an SSH or GPG key registered as a *signing* key.

## 2. Branch ruleset for `main` (Settings, Rules, Rulesets)

- [ ] Require a pull request before merging; require review from Code Owners;
      1+ approval; dismiss stale approvals on new commits; require approval of the
      most recent push; require conversation resolution.
- [ ] Require status checks, branch up to date: `test`, `forbidden-patterns`,
      `deps-gate`, `gitleaks`, `workflow-lint`.
- [ ] Require signed commits; require linear history.
- [ ] Block force pushes and deletions. Leave "Allow bypass" empty: no bypass for
      admins either.

## 3. Tag ruleset for `v*`

- [ ] Restrict creation, update and deletion of `v*` tags to the owner only; block
      force updates. Releases come from signed tags (`git verify-tag`).

## 4. Actions (Settings, Actions, General)

- [ ] Workflow permissions: Read repository contents; do not allow Actions to create
      or approve pull requests.
- [ ] Fork pull request workflows: require approval for all outside collaborators
      (not only first-time); do not send secrets or write tokens to fork PRs.
- [ ] Allow actions: select "Allow owner, and select non-owner actions" or allow only
      GitHub-authored plus the pinned `zizmorcore/zizmor-action`; enable "Require
      actions to be pinned to a full-length commit SHA".
- [ ] Never add `pull_request_target` or `workflow_run` workflows (a test in
      `scripts/workflow-pins.test.mjs` fails on them).
- [ ] No repository or organization secrets are needed for CI; keep it that way.

## 5. Security (Settings, Code security)

- [ ] Private vulnerability reporting: on.
- [ ] Dependency graph and Dependabot alerts: on. Dependabot security updates and
      version updates: off, and never auto-merge (updates arrive as reviewed PRs).
- [ ] Secret scanning: on. Push protection: on.
- [ ] Code scanning (CodeQL default setup): optional, on if available.

## 6. General

- [ ] Disable Wikis and Projects if unused; Discussions on only if you will moderate.
- [ ] Collaborators: nobody has write access by default; contributors use forks.
- [ ] Restrict who can comment or open issues on a spam wave (interaction limits).
- [ ] If an AI agent reviews PRs, give it a fine-grained read-only token (contents:
      read, pull requests: read; no write, no workflows); it must follow `AGENTS.md`.

## Verify

```sh
git log --show-signature -1
gh api repos/<owner>/agent-ledger/branches/main/protection  # or the rulesets API
```
