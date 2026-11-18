# F3b B4: enrolment and CLI — detailed plan (AL-5)

Status: APPROVED 2026-11-17 (owner: OQ-1,2,3,5 = A; OQ-4,6,7,8,9 default A). Parent: `f3b-plan.md` §4 B4; template `f3b-b3-plan.md`. Paths relative to `packages/` (`hub/` = `hub/src/`, `shared/` = `shared/src/`, `cli/` = `cli/src/`). Line cites at HEAD `f1cb360`. UNVERIFIED = must be pinned by a test. AL item texts were not readable by the planner: dispositions in §9 follow `f3b-b3-plan.md` §8/§9 and code; confirm against the ledger.

## 0. Findings that change scope
| # | Finding | Evidence | Consequence |
|---|---|---|---|
| E-1 | Hub caches device identity and slot in memory; `rekeyLegacyDeviceId` / `adoptSlot` must run while no hub writes | `shared/devicestore.ts:527-531`, `hub/ledger/ledger.ts:276-284` | `sync init|join` run offline (hub stopped), guarded by an enrol marker the hub honours at boot (OQ-1) |
| E-2 | A joiner before adoption has slot `""` = the primary's slot; one item minted = duplicate ids | `hub/ledger/device.ts:159`, `devicestore.ts:818` | hub refuses to start while an enrol marker exists, in every mode (also `LEDGER_SYNC=0`) |
| E-3 | `clone --no-tags` writes `remote.origin.tagOpt`; `checkGitConfig` allows only `url`/`fetch` under `remote "origin"` -> HALT `config` on first cycle | `gitx.ts:631-638`, `gitx.ts:953-958` | AL-52: join uses `init` + `fetch <url>` (no `remote.*` at all); `Gitx.clone` deleted |
| E-4 | `Gitx.run` allowlist has `init`, `symbolic-ref`, `read-tree`, `update-ref`, no `clone`/`config`/`add`/`commit` | `gitx.ts:267-288` | enrol never edits `.git/config`; migration commit via `TreeBuilder` |
| E-5 | `StrictHostKeyChecking=yes` with an own empty `known_hosts`: first contact always fails | `gitx.ts:212-250` | new `hostkey.ts`: scan, human-confirmed fingerprint, private pin file |
| E-6 | PRECHECK halts `config` when `refs/ledger-sync/accepted` is missing or differs from `state.accepted` | `cycle.ts:280-291` | enrol creates the ref and the mirror as its last durable step |
| E-7 | `addDevice` writes the worktree `devices.yml`, lowest free slot, no approval | `devicestore.ts:744-783` | slot CAS needs a pure planner + push-first transaction; CLI approves after add |
| E-8 | `approveDevice` needs `requireMember`; a joiner is not a member | `devicestore.ts:663-675` | new `bootstrapSigners` for join (OQ-5) |
| E-9 | `onCommitted` installed by casting into private `opts` | `wire.ts:177-180`, `git.ts:588,712` | AL-51: `LedgerGit.setOnCommitted` |
| E-10 | D3 already in code: clean absolute path origin tolerated | `gitx.ts:917-927` | AL-38: regression tests + init/doctor messaging only |
| E-11 | E-mail literal in 2 producers, parser in gate | `git.ts:1537`, `wire.ts:162`, `gate.ts:147-148` | one `deviceEmail(id)` helper in shared; producers switch |
| E-12 | Hub token is shared with agent sessions; only `requireOwner` separates humans | `http/app.ts:490-496`, `http/guard.ts` | human-only sync routes need extra gates (OQ-2) |
| E-13 | Loop confirm answers distinguish `unknown-device` / `fingerprint-mismatch` | `loop.ts:262-275` | route collapses to one `refused` + rate limit (enumeration) |
| E-14 | `validateRange` quarantines a root commit; no validator for "no accepted base" | `f3b-b3-plan.md` §1.2 | new `genesis.ts` for join |

## 1. Flows (normative order)
Enrol marker `.hub/sync/enrol.json` `{v:1, kind:'init'|'join', stage, pid, startedAt, remote, F0?}` (private dir, never staged: `.hub` excluded). Rules for both flows: device lock D is never held across a prompt or a network call; nothing from git stderr or the URL is printed except to the invoking terminal (URL only as the user typed it); every ref move has an expected-old value; no force.

### 1.1 `ledger sync init --remote <url> [--label x] [--host-fp SHA256:..] [--normalize]`
1. Preconditions: hub not running (healthz probe on the configured port + marker `wx`); ledger is a git repo on `main`; `ledger.format` == 2 (else: start the hub once to migrate); `.hub/local.yml` valid (A6); clean `status`; no inflight marker; no `.hub/sync.yml` (unless resuming own marker); `checkGitConfig` clean (D3 path origin tolerated; `https://` origin refused with the removal command, OQ-7).
2. `validateRemoteUrl`. Write marker `stage:'start'`.
3. Identity: `initDevice(dir)` (key) -> `rekeyLegacyDeviceId(dir)` -> `initDevice(dir,{root:true})`. Order UNVERIFIED (rekey refuses once `devices.yml` exists, `devicestore.ts:537`); a revoked root is refused.
4. Pinned `.gitattributes` / `.gitignore` byte-exact; extra lines refuse unless `--normalize` (prints the dropped lines).
5. Host key: `hostkey.scan(host,port)` -> show type + `SHA256:` fp -> typed confirmation or `--host-fp` (mandatory when stdin is not a TTY) -> atomic private `known_hosts` (OQ-4).
6. Remote checks (`remotecheck.ts`): credential-less `ls-remote` must FAIL; authenticated `ls-remote` must succeed and show NO `refs/heads/main` (non-empty remote -> refuse, "use sync join"); remote differs from the code repo remote.
7. Migration commit M0 via `TreeBuilder`: tree(L) + `devices.yml`, counters rename, pinned files; message `ledger: sync migration v2`; identity `deviceEmail(id)`; `commit-tree -S` parent L; self-check `verifyCommitSignature` + full-tree `validateTreeShape`/`validateIncoming` on M0 (egress); marker `stage:'committed'`; `read-tree -m -u L M0`; `update-ref main M0 L`.
8. Write `.hub/sync.yml`; marker `stage:'pushing'`; `Gitx.push(url,M0)`. Non-ff/exists -> refuse, keep local commit, print recovery. Unknown outcome -> `ls-remote` decides.
9. `createRef(accepted,M0)` then `state.accepted=M0`; delete marker. Print device id, root key fingerprint (for joiners), next step `LEDGER_SYNC=1`.
Resume: re-run with a marker of the same kind and dead pid continues from `stage`; `--abort` removes marker and `sync.yml` only (never commits, keys, refs).

### 1.2 `ledger sync join <url> [--label x] [--host-fp ..] [--root-fp ..]`, then `--continue --add-commit <sha>` (mandatory, D5)
Phase 1:
1. Preconditions: hub not running; ledger dir absent, empty, or holding only `.hub/` of an own interrupted join. Never a dir with items.
2. Marker; `Gitx.initRepo(dir)` (`init --initial-branch=main`, UNVERIFIED on git 2.34); `initDevice(dir)` (non-root key).
3. Host key pin as 1.1.5. Credential-less `ls-remote` must fail.
4. `Gitx.fetch(url, main -> refs/ledger-sync/incoming)` 120 s; `F0 = rev-parse` once. Nothing is checked out yet.
5. `validateGenesis(store,F0)` (§2.3) -> root entry + chain-valid registry. Show root fp; typed confirmation or `--root-fp` (mandatory without TTY).
6. `bootstrapSigners(dir, registry, rootFp)` (OQ-5); `read-tree -m -u <empty> F0` (UNVERIFIED form; fallback `read-tree --reset -u F0` on the empty worktree); `update-ref main F0 <zero>`; `createRef(accepted,F0)`; marker `stage:'awaiting-add', F0`.
7. Print exactly: device id, canonical pubkey line, `SHA256:` fp, and the command for the trusted device `ledger device add '<pubkey>' --label <x> --fp <fp>`.
Phase 2 (`--continue`):
8. Fetch F1; `validateRange(A=F0, F=F1, L=F0)` with the bootstrap trust set and `verify=enforce` (join never runs in warn); own entry present, id == own key-derived id, not revoked; the MANDATORY `--add-commit <sha>` (D5; refused with `ADD_COMMIT_REQUIRED` when absent) must be a single-parent commit strictly after F0 and an ancestor of F1, validly signed by a device that is registered and not revoked in its parent registry nor in F1, whose only `devices.yml` change is adding exactly this joiner's entry (OQ-9 = B).
9. FF worktree F0 -> F1 (`read-tree -m -u F0 F1`, `update-ref main F1 F0`, `update-ref accepted F1 F0`); `pruneRevokedSigners` under D.
10. `adoptSlot(dir)`; add own key to `allowed_signers`; write `sync.yml`; `state.accepted=F1`; delete marker.
Not yet added -> exit 2 "waiting for `ledger device add` on a trusted device", marker kept.

### 1.3 `ledger device add <pubkey> --label x --fp <SHA256>` (trusted side)
- Not enrolled (`.hub/sync.yml` absent): local path as today (`addDevice`), then `approveDevice(dir,id,fp)` with the same human-confirmed fp. Re-run after a crash: `DEVICE_EXISTS` -> fall through to approve (idempotent).
- Enrolled: hub route only (hub down -> exit 3, never the file path). `deviceadd.ts` under `SyncLoop.exclusiveOp` (SF), max 3 attempts:
  1. run one cycle; require no halt, `main == accepted == remote tip` (local commits pushed first).
  2. under R+Q+D read `devices.yml@L`; `planAddDevice` (lowest never-used slot, `added` = commit time); build commit C (parent L, signed, only `devices.yml` changed) WITHOUT moving `main`.
  3. `Gitx.push(url,C)`. The remote's fast-forward rule is the CAS arbiter.
  4. success -> standard APPLY FF L -> C (inflight marker, reindex), CAS accepted L -> C, `approveDevice` equivalent under D, journal `device.add`. Non-ff -> drop C (unreferenced), back to 1 with a fresh slot. Unknown outcome -> fetch: tip == C apply, else drop.
  Exhausted -> `SLOT_BUSY`, nothing changed locally. Output: id, slot, fp, commit sha C.

### 1.4 Loopback routes (`hub/http/sync-routes.ts`, mounted under `/v1/sync`, 503 `sync_off` when `HubHandle.sync === null`)
| Route | Calls | Gate |
|---|---|---|
| `GET /status` | `loop.status()` + device/slot summary | token or cookie; no URL, only sanitised `remote_host` |
| `POST /trigger` | `loop.trigger('manual')` | token; 1 per 5 s |
| `POST /resume` | `loop.resume()` | human gate |
| `POST /confirm-revocation {id,fp}` | `loop.confirmRevocation` | human gate; answer `ok|refused` only; 5 failures / 10 min then locked until `resume` |
| `POST /accept {sha, secret_ack?}` | `loop.acceptQuarantine` | human gate; same limiter |
| `POST /device-add {pubkey,label,fp}` | `deviceadd` | human gate; body <= 1 KB; 1 in flight |
Human gate (OQ-2): `requireOwner` + session not `worker-*`/`headless-*`; CLI side refuses without a TTY and makes the human retype the sha / fp; every accepted call appends one journal line (tokens only). No route takes a URL or a path.

## 2. Modules and signatures
### 2.1 B4a primitives
- `shared/devices.ts`: `DEVICE_EMAIL_DOMAIN`, `deviceEmail(id): string` (throws on non-`DEVICE_ID_RE`), `deviceIdFromEmail(email): string|null`; `gate.ts:claimedDeviceFromEmail` delegates. `planAddDevice(devices, selfId, pub, label, nowMs): {next: DevicesFile, entry: DeviceEntry}` pure (throws `DEVICE_EXISTS`, `SLOTS_EXHAUSTED`, `LABEL_INVALID`).
- `shared/devicestore.ts`: `addDevice` rebuilt on `planAddDevice` (behaviour identical); `bootstrapSigners(dir, devices, rootFp): {added: string[]}` — only when `allowed_signers` is absent or empty, root entry fp must equal `rootFp` (`timingSafeEqual`), never adds a revoked key; `approveLocked` export for callers already holding D.
- `hub/git.ts`: `setOnCommitted(fn: (() => void) | null): void`; `onCommitted` leaves `LedgerGitOptions`; commit identity via `deviceEmail`.
- `hub/sync/gitx.ts`: `initRepo(dir)`; `clone` removed (+ argv test that no code path spawns `clone`); `lsRemoteAnonymous(cwd,url)` (no `-i`, no `SSH_AUTH_SOCK`); D3 tests.
- `hub/sync/hostkey.ts` (new): `scanHostKeys(host, port, {timeoutMs:10_000})` via trusted `ssh-keyscan` (same resolver as ssh; UNVERIFIED on Windows), output cap 16 KB, accepts only `ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa` lines for exactly the asked host; `fingerprintOf(line)`; `pinHostKey(syncDir, host, port, line)` (atomic, private, one line per host, `[host]:port` form, refuses to replace a different pinned key without `--repin`).
- `hub/sync/state.ts`: `readEnrolMarker`, `writeEnrolMarker`, `clearEnrolMarker` (strict schema, <= 4 KB, pid+age takeover: dead pid or > 24 h), `writeSyncConfig(dir, remote)` (atomic, private, re-validated).
### 2.2 `hub/sync/enrol.ts` (B4b)
`syncInit(o: InitInput, io: EnrolIo): Promise<InitResult>`; `syncJoin(o, io)`; `syncJoinContinue(o, io)`; `enrolAbort(dir)`. `EnrolIo{confirm(kind:'host'|'root', fp): Promise<boolean>; out(line)}` — the only human channel; tests fake it. Never throws raw git errors: `EnrolError(code)` with fixed codes (`HUB_RUNNING`, `NOT_EMPTY`, `REMOTE_NOT_EMPTY`, `REMOTE_PUBLIC`, `HOSTKEY_REFUSED`, `ROOT_FP_REFUSED`, `GENESIS:<rule>`, `DIRTY`, `FORMAT`, `PUSH_REJECTED`, `MARKER_BUSY`, ...). Test seam `crashAt(stage)`.
### 2.3 `hub/sync/genesis.ts` (B4b)
`validateGenesis(store, F, caps): Promise<{ok:true, root: DeviceEntry, devices: DevicesFile, signers: string[]} | {ok:false, rule: string}>`, never throws. Algorithm: `revList(F)` cap 20 000 commits (over -> `oversize`); `validateTreeShape(lsTree(F))` + full-tree `validateIncoming` (all paths as adds, format <= max); walk commits touching `devices.yml` oldest first: the introducing commit must hold exactly one entry (root, slot `""`, id derived from key), be signed by that key, and no ancestor may contain `devices.yml`; every later change must be signed by a key registered and non-revoked in every parent and pass `acceptDevicesChange` (time binding included); merges must satisfy the `mergeDevices` equality rule; tip F must be signed by a non-revoked registered key. Legacy commits before the introducing commit are unsigned and are accepted as history only (their content is covered by the full-tree check of F).
### 2.4 `hub/sync/remotecheck.ts` (B4b), used by enrol and doctor
`remoteChecks(deps): Promise<Check[]>` ids: `sync_remote_scheme`, `sync_hostkey_pinned`, `sync_remote_anonymous` (must fail; success = `fail`), `sync_remote_reachable`, `sync_remote_distinct` (vs code repo origin), `sync_git_config` (`checkGitConfig`; D3 path origin = `warn`), `sync_enrol_marker` (stale marker), `sync_devices_unapproved`, `sync_single_trusted_device` (warn). Network checks only with `--online`; details through `safeOutput`, host only.
### 2.5 B4c
- `hub/sync/loop.ts`: `exclusiveOp<T>(fn: (deps: CycleDeps) => Promise<T>): Promise<T>` (waits for the running cycle, blocks new ones, 90 s budget); `RouteLimiter`. No change to `gate()`/halt semantics.
- `hub/sync/deviceadd.ts`: `addDeviceSynced(loop, input): Promise<AddSyncedResult>` (§1.3).
- `hub/sync/wire.ts`: uses `ledger.git.setOnCommitted`; `enrolMarkerPresent(ledger)`.
- `hub/server.ts`: before `ledger.init()`: enrol marker present -> refuse to start with one fixed line (exit code distinct), in every mode; pass `sync` to `createApp`.
- `cli/sync.ts`: `ledger sync` (trigger), `status [--json]`, `resume`, `accept <sha> [--secret-acknowledged]`, `confirm-revocation <id> --fp`, and dispatch of `init|join` to `cli/sync-enrol.ts` (no hub client, no spool drain, like `device`).

## 3. Crash windows (enrol; marker stage is a hint, git state is truth)
| # | Crash after | State | Re-run |
|---|---|---|---|
| I1 | key / rekey / root registration | marker `start`, worktree dirty with `devices.yml` | idempotent primitives; continue |
| I2 | M0 built | orphan M0 | rebuild (deterministic content, new sha) |
| I3 | `read-tree` | main=L, wt=M0 | verify dirty paths == M0 blobs, `update-ref` |
| I4 | `update-ref`, before push | main=M0, remote empty | push |
| I5 | push sent, outcome unknown | remote empty or M0 | `ls-remote` |
| I6 | push ok, before accepted | accepted missing | create ref + mirror |
| J1 | fetch, before confirmation | objects only, no main | re-validate, ask again (confirmation is never persisted) |
| J2 | checkout F0 | marker `awaiting-add` | `--continue` |
| J3 | FF to F1, before `adoptSlot` | main=F1, slot `""`, hub blocked by marker | adopt, finish |
| J4 | adopted, before `sync.yml` | marker present | write, clear |
| A1 | C pushed, before local APPLY | remote=C, main=L | next cycle fast-forwards; approval missing -> `device list` shows NOT-APPROVED, re-run add approves |

## 4. Invariants
1. A device never mints an item id or a commit under a slot that the accepted remote history does not assign to its own key (hub blocked while enrol marker exists).
2. A `devices.yml` addition reaches `main` of an enrolled ledger only after the remote accepted exactly that commit (push-first CAS).
3. Slots are never reused; a lost CAS leaves no trace in any ref.
4. Trust bootstrap needs two human confirmations out of band: host key fp and root key fp. Neither is persisted as "confirmed" before the step that depends on it completes.
5. Nothing fetched is checked out, parsed as config, or executed before `validateGenesis` / `validateRange` passed. Enrol never writes `.git/config`; a fresh join config has no `remote.*`.
6. No force, no ref move without expected-old, no remote name, no URL from a route, env, or fetched content. URL sources: CLI argv, `.hub/sync.yml`, enrol marker.
7. Remote URL, git stderr, key material and prompts never reach journal, state, logs or route bodies; sanitised host token and `SHA256:` fingerprints only.
8. Every commit of an enrolled ledger (`devices.yml` or device key present) carries `deviceEmail(id)` and a valid signature or is not made (init included), independent of `LEDGER_SYNC`; the identity provider is asked at every commit (AL-86). An enrolled ledger never uses the legacy `git push` either.
9. D is never held across network or human input; every enrol lock has a bounded wait and a stale rule.
10. Human-only routes never widen what `SyncLoop` already permits (OQ-B/OQ-C rules unchanged).
11. `approve` always follows a fingerprint the human supplied in the same command; join bootstrap trust derives only from the confirmed root.
12. For a NON-enrolled ledger with `LEDGER_SYNC=0` and no marker, B4 adds no network contact and no behaviour change (commit argv, identity and legacy push as before). An enrolled ledger with sync off still signs (inv. 8) and starts normally; only the network stays untouched.

## 5. Inputs
| Input | Source | Validation | Cap | Sink |
|---|---|---|---|---|
| `--remote` / join url | argv (human) | `validateRemoteUrl` (ssh/scp only, no creds, no `-`) | 2 KB (existing) | `sync.yml`, marker, git argv after `--` |
| `--label` | argv | `labelSchema` | 32 | `device.yml`, `devices.yml`, `user.name` |
| `--fp`, `--host-fp`, `--root-fp` | argv / prompt | `^SHA256:[A-Za-z0-9+/]{43}$`, `timingSafeEqual` | 50 | compare only |
| pubkey line | argv / route | `parseEd25519Pub(s)?.line === s` | 200 | `devices.yml` |
| `<sha>`, `--add-commit` | argv / route | `isSha` | 64 | compare, `isAncestor` |
| device id | argv / route | `DEVICE_ID_RE` | 12 | lookup |
| `--normalize`, `--continue`, `--abort`, `--repin` | argv | boolean | - | flow |
| route JSON | loopback, token | zod strict, Host gate | 1 KB | loop methods |
| `LEDGER_DIR`, `LEDGER_HUB_URL` | env | existing (`expandHome`, loopback-only S2) | - | paths, client |
| `.hub/sync.yml`, `enrol.json`, `state.json` | local private files | strict schema, no YAML aliases, fail closed | 4 KB / existing | flow |
| `known_hosts` | local private file | written only by `pinHostKey` | 8 KB | ssh |
| `.git/config` | local | `checkGitConfig` | 256 KB | halt decision |
| pinned files, `local.yml`, `ledger.format` | worktree | byte-exact / schema | existing | migration commit |
| `ssh-keyscan` output | network, untrusted | line grammar, host match, key type allowlist | 16 KB, 10 s | fingerprint display, pin after confirmation |
| `ls-remote` output | network, untrusted | `^<sha>\trefs/heads/main$` | 4 KB | emptiness / tip decision |
| fetched objects | network, untrusted | fsck (`transfer.fsckObjects`), genesis / range validation | 120 s; object caps of `ObjectStore` | refs only after validation |
| git / ssh stderr | untrusted | `classifyNetError` patterns only | existing | class token |
| stdin confirmation | human (TTY required) | exact retype | 80 | boolean |

## 6. Threat model
| ID | Threat | Mitigation | Test |
|---|---|---|---|
| T-B4-1 | Enumeration: route answers reveal which device ids / fingerprints exist; status leaks URL; public remote lists the ledger | one `refused` answer + limiter; status has host token only; `sync_remote_anonymous` must fail before first push | `sync-routes.test` uniform answers, lockout; `remotecheck.test` anonymous success = fail; status snapshot has no URL |
| T-B4-2 | Replay of route calls (`accept`, `confirm`, `device-add`) | bound to (tip) / (commit,id) / key; idempotent; stale tip -> refused | replay each request twice and after tip change |
| T-B4-3 | Replay / rollback by the remote at join (stale history where a revoked device is active) | phase 2 requires own entry added by a trusted signer on top of F0; revocations in F0..F1 gated; MANDATORY verified `--add-commit` (D5) | `enrol.test` remote serves old tip, then forged branch; `--add-commit` mismatch |
| T-B4-4 | Slot race: two trusted devices add different joiners at once | push-first CAS, retry with fresh slot, loser unreferenced; merge with duplicate slot quarantines (UNVERIFIED `merge/devices.ts` clash behaviour) | `deviceadd.test` two hubs racing 50 seeded rounds: distinct slots, no orphan in refs; hostile raw commit with duplicate slot quarantined |
| T-B4-5 | TOCTOU slot adoption: hub starts mid-enrol, or mints ids before adopt | boot refusal on marker in every mode; `adoptSlot` refuses when counters exist | `server` test: marker -> no listen, no commit; `LEDGER_SYNC=0` too |
| T-B4-6 | TOCTOU validate -> checkout at join | F resolved once; worktree written from validated sha; refs CAS | remote moves between fetch and checkout |
| T-B4-7 | DoS on locks: CLI holding D during prompt/network, stale marker, route retries pinning SF, trigger spam, huge join fetch | no D across I/O; pid+age takeover; 90 s op budget, 3 attempts; limiter; 120 s fetch timeout + commit cap (residual: no byte cap before validation, master risk 5) | source scan: no `await io.confirm`/network inside `withDeviceLock`; stale marker takeover; `exclusiveOp` timeout releases SF; 2001-commit / 20 001-commit histories |
| T-B4-8 | Spoofed remote: MITM on first contact, attacker-seeded repo, wrong repo, hostile tree/hooks/submodules/config | host fp + root fp confirmations; `validateGenesis`; init+fetch (no hooks, no checkout, no `remote.*`); `validateTreeShape` | wrong host fp, wrong root fp, two root entries, unsigned registry intro, symlink / gitlink / `.hub/x` tip, repo with `devices.yml` planted before the "root" |
| T-B4-9 | Spoofed join request: attacker hands a trusted user a pubkey | fp required and compared; id derived from key; role fixed; journal + status line for every add | wrong fp, key with comment/options, replayed add |
| T-B4-10 | Double init against one remote / init onto a foreign ledger | remote must be empty; non-ff push refused, never forced | two inits racing; remote with existing `main` |
| T-B4-11 | Device loss: stolen joiner before adoption, lost root, lost only device, crashed enrol | entry revocable, slot retired; D2 flows unchanged; doctor warns on a single trusted device; `--abort` is local only | revoke-before-adopt -> `--continue` refuses; single-device warn; abort leaves keys and refs |
| T-B4-12 | Privilege escalation: agent with hub token calls human routes; worker/headless session; joiner self-registers or writes before adoption; `--normalize` used to drop content silently | human gate + TTY retype + journal; gate rejects self-registration (existing); marker block; normalize prints what it drops and needs the flag | route with worker/headless session 403; non-TTY CLI refuses; raw self-added entry quarantined; normalize output |
| T-B4-13 | Secret / URL leak into logs, journal, state, halt detail, route bodies, error text | invariant 7; fixed error codes; `safeOutput`; credentialed URL refused | grep-style test over hub log, journal, `state.json`, route bodies, thrown messages after each failing flow with a marker URL; `user:pw@host` refused |
| T-B4-14 | Unsigned or wrongly attributed migration / add commit | signing mandatory, self-verify before ref move, `deviceEmail` | missing key -> no commit, no ref change; e-mail equals helper output |
| T-B4-15 | Legacy id re-key loses or rewinds counters | `rekeyLocked` order (existing), runs before root registration, hub stopped | legacy ledger init: ids continue above old max; crash between copy and delete |
Residual (accepted): a local process running as the user can read the device key and state files, so OQ-2 gates stop accidents and automation, not a hostile local process; freshness of the remote cannot be proven to a first-time joiner beyond T-B4-3; `ssh-keyscan` is unauthenticated, the human fp check is the anchor.

## 7. Tests
- B4a: `devices.test.ts` (`deviceEmail` round trip, `planAddDevice` table), `devicestore.test.ts` (`bootstrapSigners` only on empty set, wrong root fp, revoked never added; `addDevice` unchanged), `git.sync.test.ts` (setter, replace, null, throwing hook does not break commit), `gitx.test.ts` (AL-52: config after `initRepo` passes `checkGitConfig` on macOS/Linux/Windows; no `clone` in any argv; AL-38 matrix: `/abs/path` ok, `C:\x` ok, relative, `file://`, `https://`, `ext::`, control, leading dash refused), `hostkey.test.ts` (grammar, host mismatch, repin refusal, private file), `state.test.ts` (marker schema, takeover, `writeSyncConfig`).
- B4b: `genesis.test.ts` (T-B4-8 rows, merges, time binding, caps), `enrol.test.ts` (WRITE FIRST: every crash stage I1-I6, J1-J4 converges; init happy path with legacy id; pinned files; join into non-empty dir refused; join end to end with a fake trusted device), `remotecheck.test.ts`, `cli/sync-enrol.test.ts` (TTY rule, exit codes, no URL on stderr).
- B4c: `deviceadd.test.ts`, `loop.test.ts` additions, `http/sync-routes.test.ts`, `cli/sync.test.ts`, `cli/device.test.ts` (approve after add, enrolled routing, hub down exit 3), `cli/doctor-remote.test.ts`, `sync.enrol.integration.test.ts` (3 real ledgers: init, join, add, adopt, concurrent adds, items converge, unique ids).

## 8. Sub-batches (file ownership disjoint)
Order: **B4a -> security gate -> B4b || B4c -> security gate**.
- **B4a:** `shared/devices.ts`+test, `shared/devicestore.ts`+test, `shared/index.ts`, `hub/git.ts`, `hub/git.sync.test.ts`, `hub/sync/gitx.ts`+test, `hub/sync/hostkey.ts`+test (new), `hub/sync/state.ts`+test, `hub/sync/gate.ts` (delegation only). Stress: no behaviour change for existing callers; `gateCommit` stays pure; existing tests pass unchanged.
- **B4b:** `hub/sync/enrol.ts`+test, `hub/sync/genesis.ts`+test, `hub/sync/remotecheck.ts`+test, `hub/sync/testkit-remote.ts`, `cli/sync-enrol.ts`+test. Stress: crash test first; all git through `Gitx`/`ObjectStore`/`TreeBuilder`; never `.git/config`; exports the signatures of §2.2 that B4c dispatches to.
- **B4c:** `hub/sync/deviceadd.ts`+test, `hub/sync/loop.ts`+test, `hub/sync/wire.ts`, `hub/server.ts`, `hub/http/sync-routes.ts`+test (new), `hub/http/app.ts` (mount line + `AppDeps.sync`), `shared/api.ts`, `cli/sync.ts`+test, `cli/device.ts`+test, `cli/index.ts`, `cli/doctor.ts`, `cli/doctor-remote.test.ts`, `hub/sync/sync.enrol.integration.test.ts`. Stress: routes call existing loop methods, never state directly; APPLY reused, not re-implemented; `cycle.ts`, `apply.ts`, `validate.ts` are NOT touched by B4.
Not owned by B4 (stay with B5): `cli/doctor-checks.ts` stale `formatCheck`, brief, spec amendments.

## 9. Ledger disposition
- AL-23 (B4 part, per b3 §8): device lock discipline for enrol and CLI device ops; `baseFormat`/`commitTimeMs` passed by `genesis.ts` and phase-2 `validateRange`. Slot CAS §1.3.
- AL-42 (assumed: approve after add / trust bootstrap; confirm text): §1.3, `bootstrapSigners`, OQ-5/6.
- AL-38 (D3 tolerate): regression matrix in `gitx.test.ts`; init message + doctor `warn`; no config editing (OQ-7).
- AL-52: init+fetch, `Gitx.clone` deleted (E-3).
- AL-51: `setOnCommitted` (E-9).
- AL-54..AL-60 (B3c open risks): B4 does not modify `cycle.ts`, `apply.ts`, `validate.ts`. Touch points: `loop.ts` (`exclusiveOp` must not change halt gating), `wire.ts`, `server.ts` boot order (marker check sits before replay phase 1 or right after it: decide at B4c so an interrupted APPLY is still replayed), `deviceadd` reusing APPLY FF. Any of those items landing in the same files must be sequenced before B4c.
- Deferred: `last_seen` write (OQ-8); byte cap before validation (B6).

## 10. Open questions for the owner (recommendation = A)
- **OQ-1** Enrol offline with the hub stopped (A, recommended: hub caches identity/slot, E-1/E-2) or online through routes (B).
- **OQ-2** Human-only routes vs agents holding the token: A `requireOwner` + refuse worker/headless + CLI TTY retype + journal (recommended); B UI cookie only; C nothing extra.
- **OQ-3** First push: A full local history + signed migration commit (recommended, keeps history); B orphan root commit.
- **OQ-4** Host key source: A `ssh-keyscan` + mandatory human fp confirmation (recommended); B built-in pins for known hosts; C manual `known_hosts` only.
- **OQ-5** Joiner trust after root fp: A all non-revoked devices of the validated chain (recommended); B root only, others by `device approve`.
- **OQ-6** Third device after an add elsewhere: A manual `device approve --fp`, doctor and status warn (recommended for B4); B auto-approve when the add commit is signed by a locally trusted key (changes APPLY, out of B4).
- **OQ-7** Legacy `remote.origin` at init: A leave `.git/config` alone, print removal command, tolerate absolute path, refuse `https://` (recommended); B init removes it.
- **OQ-8** `last_seen` write: A defer to B5 (recommended, keeps B4c small); B include in B4c.
- **OQ-9** Anti-rollback at `join --continue`: A optional `--add-commit <sha>` printed by `device add`; B mandatory; C none. **DECIDED (D5): B, mandatory in v0.3.**

## 11. Risk
| Batch | P(high-sev at audit) | Why |
|---|---|---|
| B4a | 0.20 | small, but touches trust store and `commit()` options |
| B4b | 0.40 | genesis validation is new trust code; crash windows; TOFU |
| B4c | 0.35 | push-first CAS reusing APPLY; human-gate semantics |
