# F3b plan: sync loop, init/join, doctor, wiring (AL-5)

Status: PLAN, awaiting owner approval. No F3b code yet. Origin: Fable plan 2026-11-16, owner answers to OQ-1/2/4/6 same day.
Folds in: AL-12 (F2 audit DK-1,2,4-8), AL-14 (DK-9), decision D2, F1 audit lows A4/A7. Spec: `multi-device-spec.md`.
Paths relative to `packages/` unless absolute. `hub/` = `hub/src/`, `shared/` = `shared/src/`, `cli/` = `cli/src/`. Line cites at HEAD `ddb99a9`. UNVERIFIED = not checked in code/git.

## 0. Findings that change scope (verified in code)

| # | Finding | Evidence | Consequence |
|---|---|---|---|
| F-1 | Spec §2.1 (join self-registers) contradicts F2 gate: slotted entry cannot self-register, new entry must be `added_by` signer | `shared/devices.ts:89,291` | Decided OQ-1 = trusted device adds. Spec §2.1 amended in B5 |
| F-2 | Ingress accepts any `.gitignore` text | `hub/sync/ingress.ts:322` | Peer drops `.hub/` line, `git add -A` (`hub/git.ts:1240`) stages `.hub/device/key`. Pin `.gitignore`, exclude `.hub` in add pathspec |
| F-3 | Ingress accepts deletion of every non-item file incl. `devices.yml` | `ingress.ts:417-419` | Delete of `devices.yml` => `base===null` (`devices.ts:243`) = trust-root reset. Reject |
| F-4 | `ledger.format` may go down | `ingress.ts:298` | Monotonic rule |
| F-5 | Hub prepends to user-written `.gitattributes`, ingress accepts exact text only | `ledger.ts:337-347` vs `ingress.ts:224` | `sync init` normalises (`--normalize`) |
| F-6 | `repo rm` moves slug to tracked `.archive/` | `ledger.ts:629,663` | OQ-6 = refuse in sync mode, local unbind only |
| F-7 | No `mergeDevices` / `mergeRepos` | grep `hub/sync/merge/*` | Add both |
| F-8 | Worker 1023 used for sync-comment ids but primary may set env 1023 | `merge/common.ts:123`; `shared/snowflake.ts:174` | Reserve formally (§1.6) |
| F-9 | git wrapper inherits full env, unsigned, global identity, push by remote name | `git.ts:318,1327,1345` | Hardened sync runner + signing (`shared/sshkey.ts:350` unused) |
| F-10 | `verifyPayload` hardcodes namespace `agent-ledger-v1`; git uses `git` | `sshkey.ts:329` | Namespace parameter |
| F-11 | `last_seen` not identity field: any signer may set it on any entry | `devices.ts:207-208` | New gate rule (D2) |
| F-12 | `LEDGER_SYNC` absent; `syncVerify` parsed, unused | `hub/config.ts:110,140` | New flags §5 |
| F-13 | Journal already append-only; writer mutex `Ledger.queue`; commits serialised by `LedgerGit.running` | `ledger.ts:1041,1819`; `git.ts:634,833` | Apply holds both |
| F-14 | AL-10 byte-identical duplicate of AL-9 | item files | Close AL-10 as dup |

## 1. Architecture

### 1.1 New modules (`hub/sync/`)
| File | Role |
|---|---|
| `gitx.ts` | Hardened git runner: env allowlist, protocol allowlist, URL validation, `GIT_SSH_COMMAND`, timeouts |
| `objects.ts` | Read-only by sha: rev-parse, rev-list, merge-base, ls-tree -r -l, diff-tree -r --raw, cat-file --batch |
| `sigverify.ts` | Split raw commit into payload + `gpgsig`; parse SSHSIG for pubkey; verify with ssh-keygen ns `git` against exactly that key |
| `gate.ts` | Pure per-commit verdicts: signer status, devices gate, D2 class, counters ownership, time binding, warn/enforce matrix |
| `merge/devices.ts`, `merge/repos.ts`, `merge/tree.ts` | Typed mergers; tree dispatcher (base/ours/theirs -> blobs + `SyncNote[]`), soft-reverts item deletes |
| `notes.ts` | Pure: SyncNote / ingress rejections -> journal lines + inbox messages |
| `treebuild.ts` | temp index, `hash-object -w --no-filters`, `write-tree`, `commit-tree -S`, `update-ref <new> <old>` |
| `state.ts` | `.hub/sync/state.json` (halt, backoff, accepted mirror, D2 confirmations), `.hub/sync/inflight.json` |
| `apply.ts` | Critical section: worktree update, ref CAS, reindex, note delivery |
| `cycle.ts`, `loop.ts` | State machine; triggers, single-flight, backoff+jitter |
| `enrol.ts` | `sync init` (migration commit), `sync join` |

Changed: `hub/git.ts`, `hub/ledger/ledger.ts`, `hub/sync/ingress.ts`, `shared/devices.ts`, `shared/devicestore.ts`, `shared/sshkey.ts`, `shared/snowflake.ts`, `hub/config.ts`, `hub/server.ts`, `cli/index.ts`, new `cli/sync.ts`, `cli/doctor-checks.ts`, `cli/doctor.ts`.

### 1.2 Refs
`refs/ledger-sync/incoming` (raw fetch scratch), `refs/ledger-sync/accepted` (A, last validated/pushed remote tip, moved only by CAS), `refs/heads/main` (L). Remote = validated URL from `.hub/sync.yml`, never remote name; `remote.origin.*` not consulted.

### 1.3 Cycle
```
IDLE -> COMMIT_PENDING -> FETCH -> ANCESTRY -> VALIDATE -> {UP_TO_DATE | FF | MERGE}
     -> APPLY -> PUSH -> DONE
PUSH non-ff -> FETCH (max 3/cycle) -> BACKOFF ; transient -> BACKOFF (30 s..15 min, +-20 %) ; sticky -> HALT(reason)
```
HALT reasons: `auth`, `hostkey`, `history-rewrite`, `quarantine:<rule>`, `quarantine:revocation-root`, `quarantine:revocation-self`, `config`, `format`, `inflight`. Local work continues in every HALT (invariant 8 of spec).

1. COMMIT_PENDING: `ledger.git.flush()`; held commit (S1 hold, gitleaks) => transient `local-hold`.
2. FETCH (no locks, 20 s): `fetch --no-tags --no-recurse-submodules --no-write-fetch-head <url> +refs/heads/main:refs/ledger-sync/incoming`; `F = rev-parse` once; all later work by sha.
3. ANCESTRY (hub's own; git non-ff rule outside `refs/heads/*` UNVERIFIED): F==A up to date; A ancestor of F new commits; else HALT `history-rewrite`.
4. VALIDATE (no locks): per commit in `A..F` (topo, cap 2000): signature + `gate.ts`; names/modes via `diff-tree --raw`; `validateIncoming` on range diff with blobs from `cat-file --batch`, `existingPaths = ls-tree -r L`; names/modes pass over full tree of F.
5. Critical section `LedgerGit.runExclusive(() => ledger.queue.run(...))`: flush, `L = rev-parse main`, clean worktree required. FF if L ancestor of F; else merge from (merge-base, L, F) via `merge/tree.ts`, blobs `hash-object --no-filters`, tree in temp index (`.hub/sync/tmp`), `commit-tree -S` parents (L, F). Journal notes appended inside M (one atomic commit).
6. APPLY: write `inflight.json {L,M,F,notes}` -> `read-tree -m -u L M` -> `update-ref main M L` -> `ledger.reindexPaths(changed)` -> deliver inbox notes -> delete marker. `LedgerGit.commit()` refuses while marker exists; boot replays (idempotent) or HALT `inflight`.
7. PUSH (outside critical section): egress self-check (`validateIncoming` on `A..M`), `push --no-verify <url> <M>:refs/heads/main` (by sha, no force). Success => `update-ref accepted M A`.

### 1.4 TOCTOU
Validate+merge read only object ids from one F and one L; worktree never validation/merge input; merge output in temp index; `update-ref` always with expected old (main and accepted); push sends validated sha; `read-tree` before `update-ref` + marker (crash never leaves HEAD ahead of worktree, which `add -A` would commit as a revert); local writers excluded by `Ledger.queue` and `LedgerGit.running` during APPLY.

### 1.5 Hardened runner (`gitx.ts`)
- Reuse `buildGitGlobalArgs` (`git.ts:202`), add `-c protocol.allow=never -c protocol.ssh.allow=always -c protocol.ext.allow=never -c core.sshCommand= -c credential.helper= -c fetch.fsckObjects=true -c transfer.fsckObjects=true -c gc.auto=0`.
- Env allowlist (PATH, HOME/USERPROFILE, SystemRoot, TEMP, SSH_AUTH_SOCK) + `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<empty private file>`, `GIT_TERMINAL_PROMPT=0`, `GIT_SSH_COMMAND=<abs ssh> -F none -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<.hub/sync/known_hosts> -o GlobalKnownHostsFile=<null> [-i key]`. All other `GIT_*` dropped.
- URL: `ssh://` or scp form only; reject leading `-`, whitespace, control, `ext::`, `fd::`, `file://`, `http(s)://`, bare paths. Local path only via constructor option for tests, never env.
- Per-cycle parse of `.git/config`, HALT `config` on anything outside allowlist (`core.*` known, `remote "origin"` url/fetch, `branch "main"`); no `url.*.insteadOf`, `include`, `filter`, `core.sshCommand`, `gpg.*`. `--` before positionals.

### 1.6 Decisions inside the plan
- **Worker 1023** = hub-synthesised sync records only (sync-comment ids; future engine ids). Never a device slot, never env-selectable: `configureSnowflakeWorker` rejects 1023; ingress rejects intake names with worker 1023. Capacity: primary 1, letters 24 -> workers 2..25; 26..1022 unassigned; lifetime device cap 25 < `DEVICES_MAX_ENTRIES=64` (`devices.ts:17`).
- **Committer identity:** name = device label, email `<device_id>@devices.agent-ledger.invalid`, via `-c user.name/-c user.email` on every hub commit; hint only, authority = verified key.
- **Pinned files (format 2, byte-exact):** `.gitattributes` = `* text eol=lf\n` (matches `ingress.ts:224`, `ledger.ts:153`); `.gitignore` = `.hub/\n*.tmp\n` (`ledger.ts:148-149`). Ingress rejects anything else. Sync mode: `ensureGitattributes/ensureGitignore` write exact; `sync init` refuses extra lines unless `--normalize`.
- **Commit path:** `git add -A -- . ':(exclude).hub'`; S1 invariant widened to any tracked/staged `.hub/**` (case-insensitive).
- **`last_seen`:** device updates only its own entry, max once/24 h, only in a cycle that already pushes.
- **Time:** trust never compares `added`/`revoked.at` to a clock. Signer acceptable for commit C iff registered and non-revoked in `devices.yml` of every parent of C (ancestry). Timestamps bound to introducing commit: `|value - committer time| <= 15 min` else devices change rejected. (D2: bound to commit time.)
- **Merge commits:** `devices.yml(M)` must byte-equal `render(mergeDevices(base,P1,P2))` recomputed by verifier; `counters/<x>.yml(M)` = per-key max.
- **Item deletes** (spec §3.2): if only rejections are rule `delete`, force merge path, keep item, journal `sync.reject`. Any other rule quarantines the range.
- Signature verification on raw commit bytes by the hub (not `git verify-commit` output).

## 2. Security

### 2.1 Threat table
| ID | Threat | Mitigation | Test (`hub/sync/`) |
|---|---|---|---|
| S1 | Replay / ref rollback | ancestry vs `accepted`; behind/diverged => HALT `history-rewrite` | `threat.rollback.test.ts` |
| S2 | Remote force-push of main | same; never force | `threat.rewrite.test.ts` |
| S3 | Withheld refs / remote lies about push | `accepted`=pushed sha; next fetch must contain it; doctor unseen devices | `threat.rollback.test.ts` |
| S4 | TOCTOU fetch->write | §1.4 | `threat.toctou.test.ts` |
| S5 | Crash mid-apply | marker + replay; commit blocked while marker | `apply.crash.test.ts` |
| S6 | Huge push DoS | 20 s kill; caps 2000 commits/5000 changes/256 KB/5 MB (`ingress.ts:33-35`); object growth cap 50 MB then HALT `quarantine:oversize` (git has no client pack limit, UNVERIFIED) | `threat.dos.test.ts` |
| S7 | Push-reject loop, merge ping-pong | 3 refetch then jittered backoff; notes inside M | `threat.dos.test.ts`, `soak.test.ts` |
| S8 | Stale locks | transient `local-git` + backoff; device lock pid+age sweep; never delete young `index.lock` | `threat.dos.test.ts` |
| S9 | Hooks | empty verified hooks dir (`git.ts:235-283`), `--no-verify` | `threat.exec.test.ts` |
| S10 | Attributes/filters/drivers | pinned `.gitattributes`; `--no-filters`; no `git merge`; no checkout of rejected trees | `threat.exec.test.ts` |
| S11 | Config injection via fetched files | `.git*` names other than pinned reject (`ingress.ts:123-128`); `--no-recurse-submodules`; config allowlist | `threat.exec.test.ts` |
| S12 | ssh options / URL schemes | URL validator, `protocol.*.allow`, `-F none`, fixed options, `--` | `gitx.test.ts` |
| S13 | Secret exfil via `.gitignore` | pinned, pathspec exclude, widened invariant | `threat.hubpath.test.ts` |
| S14 | `.hub/**` incoming | explicit rule `hub-path` per commit + full F tree | `threat.hubpath.test.ts` |
| S15 | Device loss / stolen key | revocation by ancestry; revoked rejected in warn too; doctor reminder to remove deploy key | `threat.revoked.test.ts` |
| S16 | Self-add to `devices.yml` | gate on every commit touching file, warn+enforce; signer = key from verified signature | `threat.devices.test.ts` |
| S17 | Un-revoke / removal / pubkey swap / delete | `acceptDevicesChange` (`devices.ts:228`) + delete rule | `threat.devices.test.ts` |
| S18 | Slot spoof / reuse | slot unique incl. revoked (`devices.ts:80`); commit by X may change only `counters/X.yml`; item ids by X carry X slot | `threat.slot.test.ts` |
| S19 | Committer-email spoof | email never authority; mismatch with verified key => reject | `threat.devices.test.ts` |
| S20 | Stolen device revokes root/receiver (D2) | never auto-applied: HALT `quarantine:revocation-*` until human confirmation | `threat.d2.test.ts` |
| S21 | Backdated/future `revoked.at`/`added`; foreign `last_seen` | commit-time binding; `last_seen` own entry only | `threat.d2.test.ts` |
| S22 | Anonymous-readable remote | doctor: anonymous `ls-remote` must fail | `cli/doctor-remote.test.ts` |
| S23 | MITM / host key change | own known_hosts, StrictHostKeyChecking=yes, HALT `hostkey` | `threat.transport.test.ts` |
| S24 | Auth failure storm | HALT `auth`, no retry | `threat.transport.test.ts` |
| S25 | Format downgrade/unknown newer | monotonic; HALT `format` | `ingress.test.ts` |
| S26 | Local egress breaks peers | egress self-check before push | `threat.egress.test.ts` |

### 2.2 Invariants
1. `main` advanced only by `update-ref <new> <old>`, old ancestor of new.
2. No sync git command has `--force`, `-f` or `+` refspec on `refs/heads/*` (static grep test + runtime assert in `gitx.ts`).
3. No worktree/index byte changes before full `A..F` passed VALIDATE.
4. Validation/merge inputs are object ids from one F and one L per cycle.
5. Commit touching `devices.yml` accepted only with valid signature by a key locally approved, registered and non-revoked in every parent; identical in warn and enforce.
6. Revoked key's commits after revocation (ancestry) never accepted, any mode.
7. Revocation of root or local device never changes local trust state, worktree or remote without human confirmation in `.hub/sync/state.json` (D2).
8. `added`, `revoked.at`, `last_seen` never feed a trust decision.
9. No tracked/staged path under `.hub/`; no incoming path under `.hub/`.
10. `.gitattributes`, `.gitignore` in any accepted tree byte-equal to pinned.
11. A device changes only its own counter file and own `last_seen`.
12. Hub never pushes a range its own ingress would reject.
13. No hook, filter, merge driver, fsmonitor, credential helper or non-ssh transport during sync.
14. Host key / auth failures stop loop; never retried or auto-accepted.
15. `LEDGER_SYNC=0` => no remote contact (except old `LEDGER_PUSH` backup).
16. N hubs applying same ops in any interleaving end with identical `main` trees.
17. Worker 1023 never in an id minted by `generate()`.

### 2.3 Inputs x outcome (per commit C in `A..F`; top-down, first match wins; Q = quarantine whole range)
| Signature | Paths/content | devices.yml change | warn | enforce |
|---|---|---|---|---|
| any | `.hub/` path, symlink, submodule, exec bit, non-allowlisted, pinned file differs, format downgrade, non-item delete | any | Q `sync.reject` | Q |
| any | secret hit in range diff | any | Q `sync.secret` (path+rule only) | Q |
| any | only item deletes rejected | none | accept via forced merge, item kept, `sync.reject` | same |
| valid, key revoked in a parent | any | any | Q `sync.reject` | Q |
| valid, trusted+active | ok | none | accept | accept |
| valid, trusted+active | ok | valid per `acceptDevicesChange`, not root/self revocation | accept | accept |
| valid, trusted+active | ok | revokes root or local device | HALT `quarantine:revocation-*` (D2) | same |
| valid, trusted+active | ok | invalid (un-revoke, removal, foreign `last_seen`, time unbound, slot reuse) | Q | Q |
| valid, registered, not approved locally | ok | none | accept + `sync.unverified` | Q |
| valid, registered, not approved | ok | any | Q | Q |
| valid, unknown key | ok | none | accept + warning | Q |
| unsigned/bad | ok | none | **OQ-4 ratchet:** if the claiming device was ever seen signing => Q; else accept + warning | Q |
| unsigned/unknown/bad | ok | any | Q `sync.reject` | Q |
| any | counters file of another device changed / item id with another device's slot | n/a | Q | Q |

Note mapping (`notes.ts`): `sync.conflict` <- `sync.conflict`, `sync.decision-conflict`, `sync.context-conflict` (CONTEXT conflict also creates `proposed` item from `ContextMergeResult.proposedItem`, `merge/types.ts:44`); `sync.reject` <- ingress rejections + reverted deletes; `sync.secret` <- rule `secret`; inbox `sync.claim-lost` <- notes whose `device` is local (`merge/item.ts:167`) via `store.addInbox` `origin:'hub'` (`db/store.ts:768`, `shared/api.ts:521`) + release local lease (lease API name UNVERIFIED). Claim-lost for sessions on other devices stays a Log line until v0.4.

### 2.4 D2 + owner decisions (resolved)
- **D2 (decision):** root/local-device revocation = quarantine + human confirmation, never automatic.
- **OQ-1 (A):** new device is added by a trusted device: joiner prints id + pubkey + fingerprint, trusted device runs `ledger device add ... --fp`, joiner adopts slot (`adoptSlot`). Gate unchanged; slot CAS among trusted devices.
- **OQ-2 (A):** after D2 quarantine, `ledger sync confirm-revocation <id> --fp`: self revoked + confirm => device detaches permanently (sync off, local data kept); root revoked + confirm => accept, trust continues with remaining approved devices.
- **OQ-4 (ratchet):** unsigned commits claiming a device seen signing before are rejected in warn too.
- **OQ-6 (A):** `repo rm` refused when sync on; local unbind only.
- Defaults taken without asking (owner may override): **OQ-3** SSH only in v0.3 (HTTPS needs the global git config the hardened runner ignores). **OQ-5** quarantine exit: content-rule failures clear automatically when a later commit fixes the range; signature/devices/structural failures need `ledger sync accept <full sha>` typed by a human.

## 3. Tests
Fixtures (`hub/sync/testkit-remote.ts`): bare repo as remote in private temp dir; `makeHub(n)` with real device keys (ssh-keygen), path-remote test option; helpers to push raw hostile commits (unsigned, foreign-signed, symlink, `.hub/x`, rewritten history).

| File | Covers |
|---|---|
| `gitx.test.ts` | S12, inv 2, 13: URL matrix, env scrub, argv never contains force |
| `objects.test.ts`, `treebuild.test.ts` | batch caps, `--no-filters` with hostile filter, temp index isolation, CAS failure |
| `sigverify.test.ts` | valid / tampered / wrong namespace / key mismatch SSHSIG vs principal / malformed armor |
| `gate.test.ts` | table-driven §2.3, both modes + ratchet |
| `merge/devices.test.ts`, `merge/repos.test.ts`, `merge/tree.test.ts` | determinism, revocation monotonic, `last_seen`, prefix collision, delete revert |
| `notes.test.ts` | mapping; no control chars, no content excerpts beyond `SyncNote.detail` |
| `cycle.test.ts` | ff, merge, up-to-date, push-reject x3, backoff, each HALT |
| `apply.crash.test.ts` | kill after marker / read-tree / update-ref; replay converges |
| `threat.*.test.ts` | one per row group §2.1 |
| `enrol.test.ts` | init single signed migration commit, pinned files; join adopts slot; slot CAS race; exhaustion; legacy id re-key |
| `soak.test.ts` | 3 hubs, flaky remote, 1000 random ops, identical `main` tree sha, no markers, no lost item, unique ids; seeded PRNG, slow tag |
| `cli/sync.test.ts`, `cli/doctor-remote.test.ts` | CLI surface, doctor incl. S22 |
| `shared/devices.test.ts`, `devicestore.test.ts`, `sshkey.test.ts` | AL-12, D2 |

## 4. Batches (Sonnet editors; Fable audit per gate)
Order: B0a || B0b -> B1 || B2 -> B3 -> B4 || B5 -> B6. Files disjoint between parallel batches. Batches touching auth/crypto/transport/devices gate go through security gate before the next starts. Max 1 audit/fix/re-audit cycle per batch group.

### B0a: device trust hardening (AL-12, D2 rules, enrol primitives) — gate: yes
Files: `shared/devices.ts`, `shared/devicestore.ts`, `shared/sshkey.ts`, 3 test files, `cli/device.ts`, `cli/device.test.ts`.
| Item | Fix | Test |
|---|---|---|
| DK-1 (`devicestore.ts:404`) | `approveDevice(dir,id,fingerprint)` SHA256 fp must match; CLI `approve <id> --fp`; id-from-pubkey derivation in `devicesInvariantProblem` | wrong/missing fp refused; non-derived id invalid |
| DK-2 (`devices.ts:111`) | fixed codes + field path instead of zod messages; sanitise CLI/doctor output | hostile YAML ANSI/bidi => clean one-line error |
| DK-4 (`devices.ts:25`) | pubkey valid only if `parseEd25519Pub(s)?.line === s` | trailing space/comment/alt padding rejected |
| DK-5 (`devicestore.ts:159`) | `assertPrivateFile` on `allowed_signers` before read; one lock for init/approve/revoke/add/adopt | 0666 refused; concurrent approve+revoke never resurrects revoked |
| DK-6 (`devicestore.ts:253`) | sweep `.gen-*` older than 10 min at init | stale removed, fresh kept |
| DK-7 (`devices.ts:243`) | root id derived from key; one-time re-key of legacy random id (`hub/ledger/device.ts:71`) by `sync init`; `init --root` refused on revoked root | legacy path; revoked root refusal |
| DK-8 (`sshkey.ts:296`) | `ensurePrivateDir` tmp root both platforms; `SLOTS_EXHAUSTED` | 0777 tmp root refused; 25th device refused |
| D2 | `acceptDevicesChange` returns `revokes:{root,ids[]}`; new rejects `last-seen-foreign`, `time-unbound` (commit time input) | table tests |
| F-10 | `verifyPayload(..., {namespace})` | git-ns sig verifies only with `git` |
| enrol | `addDevice(dir,pubkeyLine,label,fp)` (trusted side, lowest free slot), `adoptSlot(dir)` (joiner) | `devicestore.test.ts` |

### B0b: ingress, pins, snowflake, config, F1 lows — gate: yes
Files: `hub/sync/ingress.ts`+test, `shared/snowflake.ts`+test, `hub/config.ts`+test, `hub/gitreader.ts`+test, `hub/ledger/ledger.ts`+`ledger.f1.test.ts`.
- Ingress: rule `hub-path`; reject all deletes except items (soft); pinned `.gitignore`; format monotonic (`baseFormat`); intake worker 1023 rejected.
- Snowflake: reject env 1023; export `RESERVED_SYNC_WORKER` (`merge/common.ts:123` switches in B2).
- Config: `LEDGER_SYNC`, `LEDGER_SYNC_INTERVAL_MS` clamp.
- Ledger: exact pinned files when sync on; `repo rm` refusal (OQ-6); A7 bindRepo owner check (`ledger.ts:761`).
- A4: `originHintFromUrl` (`gitreader.ts:338`) never emits absolute path or token-shaped segment.
- F1 lows: A4 + A7 in F3b. A6 (local.yml invalid), A9 (shallow clone identity) deferred: `sync init` refuses on invalid `local.yml`, doctor warns on shallow clone. A5, A8 closed. Close AL-10 as dup of AL-9.

### B1: git plumbing (parallel B2) — gate: yes
`gitx.ts`, `objects.ts`, `treebuild.ts`, `sigverify.ts`, `testkit-remote.ts`, 4 tests. Depends B0a.

### B2: pure decision layer (parallel B1) — gate: yes
`gate.ts`, `merge/devices.ts`, `merge/repos.ts`, `merge/tree.ts`, `notes.ts`, `merge/types.ts`, `merge/index.ts`, `merge/common.ts`, 5 tests. Depends B0a, B0b.

### B3: loop and apply — gate: yes (highest risk)
`state.ts`, `apply.ts`, `cycle.ts`, `loop.ts`, `hub/git.ts`, `hub/ledger/ledger.ts` (`reindexPaths`, hash skip `ledger.ts:919`), `hub/server.ts`, `cycle.test.ts`, `apply.crash.test.ts`, `git.test.ts` additions.
`git.ts`: signing + identity args (`:1327`), add pathspec (`:1240`), `.hub/**` invariant, `runExclusive`, marker guard, `maybePush` (`:1338`) off when sync on.

### B4: enrolment and CLI (parallel B5) — gate: yes (trust bootstrap)
`enrol.ts`+test, `cli/sync.ts`+test, `cli/index.ts`, `hub/http/app.ts`, `shared/api.ts` (status+trigger route, loopback).
Commands: `ledger sync init --remote <url>`, `sync join <url>`, `sync`, `sync status`, `sync confirm-revocation <id> --fp`, `sync accept <sha>`, `sync resume`, `ledger device add`.
`init`: key + root, re-key legacy id, pinned files, `.hub/sync.yml`, host key pin with confirmed fingerprint, one signed commit `ledger: sync migration v2`, doctor remote checks pass, first push.
`join`: empty ledger dir; key; pin host key; clone via hardened runner; root fingerprint confirmation; full-tree ingress on tip; `devices.yml` history walk; prints id+pubkey+fp for trusted `device add` (OQ-1); adopts slot after add.

### B5: doctor, brief, docs (parallel B4) — gate: light
`cli/doctor-checks.ts`, `cli/doctor.ts`, tests, `cli/doctor-remote.test.ts`, `hub/brief.ts`, `docs/multi-device-spec.md` (amend §2.1, §7.3 per F-1..F-6), README/SPEC §18.
Doctor: anonymous `ls-remote` with empty credential env must fail; ssh scheme; host key pinned; `LEDGER_SYNC_VERIFY` mode; halt state; devices unseen >30 d; slots used >=20; git >=2.34; `.git/config` allowlist; pinned files exact; fix stale `formatCheck` text (`cli/doctor-checks.ts:30`).

### B6: threat + soak suites — final audit of whole F3b diff
`threat.*.test.ts` (~10), `soak.test.ts`, Windows CI entry. Test-only.

## 5. Rollout and platform
| Flag | Default | Meaning |
|---|---|---|
| `LEDGER_SYNC` | `0` | `1` starts loop; requires `.hub/sync.yml` else stays local |
| `LEDGER_SYNC_VERIFY` | `warn` | `enforce` quarantines unsigned/unapproved; devices gate, revoked-key rule, D2 identical in both |
| `LEDGER_SYNC_INTERVAL_MS` | `60000` | clamp 15 s..1 h |
| `LEDGER_PUSH` | `0` | backup push; ignored (log) when `LEDGER_SYNC=1` |

Stages: (1) B0 with sync off; (2) B1-B3 behind flag, local bare remotes only; (3) owner runs init on Mac + one join; (4) soak green on macOS/Linux/Windows before README claims change. Rollback `LEDGER_SYNC=0`.
Windows: `GIT_SSH_COMMAND` quoting via `shared/winquote.ts`; null-device for `GlobalKnownHostsFile` differs Git-for-Windows vs Windows OpenSSH (UNVERIFIED), pick one ssh binary and CI-test; `read-tree -u` on open files: retry + marker replay; `.hub/sync/` and temp index via `ensurePrivateDir` (`ledger.ts:249`); case-insensitive collisions via `existingPaths`; prefer explicit deploy key path over ssh-agent pipe; CRLF: `--no-filters`, mergers emit LF.

## 6. Risk
| Batch | P(high-sev at audit) | Why |
|---|---|---|
| B0a | 0.30 | trust-root code, lock, legacy re-key |
| B0b | 0.20 | small diffs, strong tests |
| B1 | 0.35 | env/ssh options, SSHSIG parsing, Windows |
| B2 | 0.30 | matrix completeness, merge-commit devices rule |
| B3 | 0.45 | concurrency with commit cycle, crash windows |
| B4 | 0.35 | TOFU bootstrap on join, migration commit |
| B5 | 0.10 | read-only checks |
| B6 | 0.05 | tests only |

Top risks: (1) APPLY interleaving with `LedgerGit.commit()` / S1 hold (`git.ts:1188-1336`): wrong order commits a revert of remote work; marker + `runExclusive`, crash test first. (2) Warn mode gives no crypto protection vs stolen deploy key; ratchet narrows it. (3) Merge commits + devices gate: recomputed `mergeDevices` must be byte-deterministic across platforms (YAML rendering) or honest merges get quarantined. (4) Join trusts history the remote serves; only human root-fingerprint check anchors it. (5) Fetch has no size limit before validation; growth cap reacts after the fact.
