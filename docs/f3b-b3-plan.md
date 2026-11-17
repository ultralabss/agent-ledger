# F3b B3: loop and apply — detailed plan (AL-5)

Status: APPROVED within F3b plan (`f3b-plan.md`); owner decisions OQ-A/B/C recorded §9. Origin: Fable plan 2026-11-17. Paths relative to `packages/` (`hub/` = `hub/src/`, `shared/` = `shared/src/`). Line cites at HEAD `83d4941`. UNVERIFIED = must be pinned by a test.

## 0. Findings that change scope
| # | Finding | Evidence | Consequence |
|---|---|---|---|
| P-1 | `flush()` chains onto `running`; calling it inside `runExclusive` deadlocks | `hub/git.ts:832-837` | `runExclusive(fn)` hands `fn` a `commitNow()` running `commit()` inline |
| P-2 | `commit()` returns void on ~12 exits | `git.ts:1188-1336` | Return `CommitOutcome` |
| P-3 | Local commit unsigned, global identity, full env | `git.ts:1327,318` | identity + signing `-c` args in sync mode; no unsigned fallback |
| P-4 | `writeItem` serialises in-memory record; `loadItems` keeps last good version on parse failure | `ledger.ts:1067-1074,934-939` | stale index after APPLY reverts remote work; `reindexPaths` inside queue drops unparseable items |
| P-5 | S1 journal callback writes directly, not via `queue` | `ledger.ts:211-217` | lock order `running -> queue` acyclic |
| P-6 | `withDeviceLock` private; hub never takes it | `shared/devicestore.ts:177` | export; AL-16 becomes reachable -> fix in B3a |
| P-7 | AL-40 already fixed (merge compares against any parent) | `gate.ts:224` | regression tests only |
| P-8 | `currentDevices` optional; undefined skips `revoked-current` | `gate.ts:92,238` | required (AL-46) |
| P-9 | verifier failure -> `valid:false, reason:'verifier-error'` | `sigverify.ts:263-266` | cycle treats as transient; never to gate (AL-43) |
| P-10 | row 7 skipped when owner null and for merges | `gate.ts:251-253` | fix (AL-43) |
| P-11 | `lsTree` no pathspec; no names-only checker; default caps 256 KB / 5 MB | `objects.ts:172,22-23` | carry-forward maps; new `validateTreeShape`; larger local caps |
| P-12 | `mergeTrees` unions all paths | `merge/tree.ts:106` | pass only changed paths + `devices.yml`,`repos.yml` |
| P-13 | `Gitx.run` allowlist lacks `add`,`commit`,`count-objects` | `gitx.ts:266-288` | APPLY on Gitx; local commit stays on `git()` |
| P-14 | Gitx spawns detached | `gitx.ts:412` | killed hub leaves `read-tree` running; replay waits for `index.lock` |
| P-15 | `refs/ledger-sync/accepted` only via `createRef`; no `.hub/sync.yml` reader | `treebuild.ts:194` | missing = HALT `config` (enrol is B4); tests use testkit |
| P-16 | `diff3.ts` spread push (AL-27) | `merge/diff3.ts` | fix in B3a |

## 1. Modules and signatures

### 1.1 `hub/sync/state.ts` (B3a)
```ts
export const SYNC_DIR='.hub/sync'; INFLIGHT_FILE='inflight.json'; STATE_FILE='state.json';
export type HaltClass='no-contact'|'sticky'|'probe'|'d2'|'local'|'terminal';
export type HaltReason='auth'|'hostkey'|'history-rewrite'|'config'|'format'|'inflight'|'detached'
  |'quarantine:revocation-root'|'quarantine:revocation-self'|`quarantine:${string}`;
export interface HaltState{reason;cls;since:string;tip:string|null;rule:string|null;detail:string;
  d2:{commit:string;deviceIds:string[];kind:'root'|'self'}|null}
export interface Confirmation{kind:'root'|'self';device_id;commit;fp;at}
export interface SyncState{v:1;halt:HaltState|null;backoff:{failures;nextAt;lastError};accepted:string|null;
  confirmations:Confirmation[] /*max 64*/;overrides:{tip;at;secretAck?:boolean}[] /*max16*/;seenSigning:string[] /*max64, grows only*/;
  strikes:{tip;n}|null;noted:{key;at}[] /*max200*/;pushBlocked:{rule;tip;since}|null;lastCycle:{...}|null}
export interface Inflight{v:1;id;createdAt;mode:'ff'|'merge';A;L;M;F;treeL;treeM;changed:string[] /*max 20000, assertTreePath*/;
  notes:{inbox;releaseLeases;proposed};stage:'prepared'|'ref-moved'|'notes-done'}
export class StateStore{static open(dir);read();update(fn);readInflight();writeInflight(m);clearInflight();inflightPath}
export function readSyncConfig(dir):Promise<{v:1;remote:string}|null>; // strict, <=4KB, maxAliasCount 0
export function nextBackoff(failures,rnd?):number; // 30s*2^n cap 15min +-20%
export function confirmationKey(commit,deviceId):string;
```
Single writer = hub process; B4 CLI goes via loopback routes to `SyncLoop`. Corrupt file fails closed (`StateError('CORRUPT')` -> HALT `config`; D2 halt recurs). Writes: tmp+fsync+rename+dir fsync; no secrets/URLs in `detail`.

### 1.2 `hub/sync/validate.ts` (B3c)
`validateRange(i: RangeInput): Promise<RangeOutcome>` NEVER throws. Outcomes: `ok{forcedMerge,notes,signers}` | `quarantine{rule,layer:'tree'|'provenance',notes}` | `halt-d2{reason,commit,deviceIds,notes}` | `format` | `transient{why}`. `classifySyncError(err, side)`: remote-side `ObjectsError`/`GitxError('CAPPED')`/unknown -> quarantine (`objects:<code>`,`oversize`,`internal`); `TIMEOUT` transient (3 strikes against same F -> quarantine `timeout`); local-side never quarantines.
Algorithm: (1) `revList(A,F,2000)` no first-parent (side branches, AL-46); limit = quarantine `oversize`. (2) carry-forward maps per commit `{devicesBlob,formatBlob,counters}` seeded by `lsTree(A)`, updated from `diffTreeRaw(parent0,sha)`; merge-base outside range cached. (3) per commit, parents first: `readCommitRaw`+`verifyCommitSignature` (`verifier-error` -> transient; null headers/root commit/>2 parents -> quarantine); changes from raw diff, blobs via two-phase `catFileBatch`; `validateIncoming(changes,{baseFormat: format@parent0,maxFormat})` (AL-23 always passes baseFormat); `gateCommit` with `commitTimeMs=committerTime*1000`, `claimedDevice` from email, `currentDevices` = devices.yml@L (required), `confirmedRevocations`, `merge` input for 2-parent. (4) range layer T, never overridable: `validateIncoming(diffTreeRaw(A,F),{baseFormat:format(A),existingPaths:lsTree(L)})`, `validateTreeShape(lsTree(F))`, format > maxFormat -> `format`. (5) `gateRange(verdicts)`; `halt` -> `halt-d2`.

### 1.3 `hub/sync/apply.ts` (B3c)
`ApplyHost{runExclusive,queueRun,reindexPaths,deliver,log}` (only coupling to Ledger; tests fake). `applyRemote(host,deps,plan)` -> `applied{mode,L,M,changed,proposed}`|`noop`|`quarantine`|`transient{local-hold|dirty|device-lock|local-git|budget}`. `replayGitPhase`, `replayNotesPhase`. Test seam `crashAt(point)`: `marker|read-tree|update-ref|reindex|notes|marker-delete`.
Normative step order inside `host.runExclusive(x => host.queueRun(...))`, 15 s total, 5 s per git call before marker:
1. `x.commitNow()`; anything but clean/committed -> transient `local-hold`.
2. `L=revParse(main)`; F ancestor of L -> `noop`.
3. FF if L ancestor of F and not forcedMerge; else merge: `base=mergeBase` (null -> quarantine `unrelated`); blobs only for paths changed base..L/base..F plus devices.yml, repos.yml; local caps 8 MB/obj, 64 MB total, local errors transient; `mergeTrees` (`!ok` -> quarantine); journal notes via `mapNotes` appended into merged journal blobs inside M (null repo -> `ops`); self-check `validateIncoming(merged vs L)` else quarantine `merge-output`; `buildTree`; if tree==tree(F) and L ancestor -> degrade to FF; else `commitTree` parents `[L,F]`, signing mandatory.
4. `withDeviceLock(..., {waitMs:2000})` (LOCKED -> transient): (a) `status --porcelain=v1 -z --untracked-files=all` empty else transient `dirty`; (b) durable `writeInflight(stage:'prepared')`; (c) `read-tree -m -u L M` (failure with main==L and index==tree(L): clear marker, transient); (d) `updateRef(main,M,L)`; (e) `pruneRevokedSigners`.
5. `host.reindexPaths(changed)`. 6. `host.deliver(notes)`, stage `notes-done`. 7. `clearInflight()`.
Never update-ref before read-tree; never marker for unvalidated M.

### 1.4 `hub/sync/cycle.ts` (B3c)
`runCycle(deps)` never throws; `classifyNetError(GitxResult)` -> auth|hostkey|non-ff|fsck|transient (stderr patterns, never echoed). Order: PRECHECK (inflight -> replay or HALT `inflight`; `checkGitConfig` problems -> HALT `config`; `A=revParse(accepted)` null or != `state.accepted` -> HALT `config`) -> COMMIT_PENDING (`flushLocal`, no lock) -> FETCH (20 s, F resolved once) -> ANCESTRY (F==A up to date; A ancestor of F ok; else HALT `history-rewrite`) -> SHORT-CIRCUIT (F ancestor of L0: CAS accepted A->F, go PUSH) -> VALIDATE -> APPLY -> CAS accepted A->F, add signers to `seenSigning` -> post-critical (gate warn-notes local only; proposed items as ordinary commits) -> PUSH (egress self-check per local commit F..L' and diff; non-`delete` rule sets `pushBlocked`, not HALT; `Gitx.push(url,L')` by sha no force; success CAS F->L'; non-ff refetch max 3 then backoff; unknown outcome transient).

### 1.5 `hub/sync/loop.ts` (B3c)
`SyncLoop{start,stop(awaits cycle, never kills mid-APPLY),trigger(why),status,resume,confirmRevocation(id,fp),acceptQuarantine(sha,{secretAck?})}`. Single-flight, coalesced rerun, 5 s debounce on commit trigger. `no-contact`/`d2`/`terminal` no remote contact; `probe`/`sticky` at most every 15 min. `resume` clears no-contact and sticky only. `acceptQuarantine` only if sha === `halt.tip` and layer provenance (see OQ-B).

### 1.6 `hub/git.ts` (B3b)
`CommitOutcome='clean'|'committed'|'held'|'deferred'|'inflight'|'error'`; options `sync`, `syncCommit?()`, `inflightMarker` (ALWAYS checked, also sync off), `onCommitted?`. `runExclusive` chains onto `running`, rejection never breaks chain; `commitNow` calls `commit()`. Marker guard first after `if(!enabled)`, before `tokenInvariant()`; re-arm timer 30 s. Pathspec at `:1240`: `add -A -- . ':(exclude,icase).hub'` (UNVERIFIED on git>=2.34; fallback `':(exclude).hub'` + staged check). S1 widening: `isHubPath` (segment lower-cased, trailing dots/spaces stripped == `.hub`); token path keeps `leak` flow; other tracked/staged `.hub/**` = `unsafe` hold, no token rotation, journal `s1.hold`; post-add staged check widened. Signing at `:1327`: `-c user.name=<label> -c user.email=<id>@devices.agent-ledger.invalid` + `gitSigningArgs` + `commit --no-verify -S`; failure -> `error`, no unsigned retry; `syncCommit()` null (not enrolled) = commit as before. `maybePush`: `if(!push||sync) return` + one log line.

### 1.7 `hub/ledger/ledger.ts`, `paths.ts` (B3b)
`paths.syncDir`, `paths.inflightMarker`. `reindexPaths(paths)` — caller MUST hold `queue` (not re-entrant): clear `parsedHash`; `repos.yml` -> `loadRepos`; `counters/<own>.yml` -> `loadCounters` (max(mem,disk)); per slug `loadItems`,`loadJournalFiles`,`loadDecisions`,`detectOnboarded`; `intake/` -> `loadIntake`; `onReindex?.()`. For this entry point only: unparseable item file -> `index.dropItem(id)` + `dropped` + warning (60 s backstop unchanged). Constructor passes `sync`,`inflightMarker`, lazy `syncCommit` to `LedgerGit`.

### 1.8 `hub/server.ts` (B3c)
Before `ledger.init()` (`:101`), regardless of `config.sync`: marker exists -> `replayGitPhase` (local only, inv 15 holds). After RuntimeStore up (`:147`), before listen: `replayNotesPhase`. When `config.sync`: no `readSyncConfig` -> log "staying local", no loop; else `Gitx.open`, build deps, `SyncLoop.start()` (unless `periodic===false`), `onCommitted -> loop.trigger('commit')`, `HubHandle.sync` for B4 routes, `close()` awaits `loop.stop()` before `ledger.close()`.

### 1.9 Changes to B0-B2 files (B3a)
- `gate.ts`: `currentDevices` required (undefined -> quarantine `malformed-input`); `confirmedRevocations: ReadonlySet<string>` of `confirmationKey(sha,id)`; at `:285` root revocation with all newly revoked root ids confirmed -> accept (`revocation-confirmed`); self revocation always halts (cycle turns confirmed one into `detached`); `GateVerdict.d2?`; AL-43: owner null + any counters/* change or item creation -> quarantine `unowned`; merge adding an item absent from both parents -> quarantine `merge-item-new` (needs `GateMergeInput.addedVsBoth`); AL-40 regression tests.
- `ingress.ts`: `validateTreeShape(entries)` reusing existing rules (no fork).
- `merge/diff3.ts`: loop instead of spread (AL-27).
- `shared/devicestore.ts`: export `withDeviceLock(dir,fn,{waitMs})`; `pruneRevokedSigners(dir)` (caller holds lock; only removes); AL-16 atomic stale takeover (second `wx` file `device.lock.takeover` around re-read/compare/rm, or rename-then-compare) with multi-process test.
- `gitx.ts`: `core.fsync=all` in `HARDENING_CONFIG` (UNVERIFIED which versions honour).

## 2. APPLY crash windows (git state is truth; marker names L,M,F; replay phase 1 runs before any writer)
| # | Crash after | State | Replay (idempotent) |
|---|---|---|---|
| W0 | commit-tree, before marker | orphan M, temp index | nothing; sweep `.hub/sync/tmp` >10 min at boot |
| W1 | marker written | main=index=wt=L | roll forward if M exists (`hasCommit`,`lsTree(M)`); else roll back, clear marker if status clean |
| W2 | during read-tree | main=L, index L or M, wt mixed, maybe stale `index.lock` | wait <=5 s for lock; remove only if >30 s old and marker exists; else HALT `inflight`; verify then `read-tree --reset -u M` |
| W3 | read-tree done | main=L, index=wt=M | commit guard blocks `add -A`; verify, `updateRef(main,M,L)` |
| W4 | update-ref done | main=index=wt=M | verify; boot full `reindex()`; running hub `reindexPaths(changed)` |
| W5 | reindex done | same | prune signers, deliver notes (at-least-once, <=20 dup inbox rows; lease release idempotent) |
| W6 | notes-done | same | clear marker |
| W7 | marker deleted, before accepted CAS | main=M, accepted=A | next cycle short-circuit, CAS A->F |
| W8 | push sent, before accepted CAS | remote=M, accepted=F | next fetch F'=M=L up to date, CAS F->M |
| W9 | push outcome unknown | remote F or M | transient; next fetch decides |
Verify (W2-W4): every dirty/untracked path must be in `marker.changed` and its `hash-object --no-filters` equal blob in L or M (or absent where absent); else HALT `inflight`, no mutation. Marker check first: main is L or M; M parents `[L,F]` (merge) or M==F with L ancestor (FF). Marker trust: `.hub/` is the local trust boundary; F not re-validated at replay. UNVERIFIED to pin in `apply.crash.test.ts`: `read-tree -m -u L M` verifies all paths before touching; `--reset -u M` acts as hard reset for tracked paths; killed `read-tree` leaves `index.lock`.

## 3. Lock ordering
Locks: SF (loop flag) -> R (`LedgerGit.running`, not re-entrant) -> Q (`Ledger.queue`, not re-entrant) -> D (`.hub/device.lock`, cross-process, bounded wait). Only allowed order SF->R->Q->D. Existing edges verified: `commit()` in R never takes Q; Q bodies only `git.touch()` (non-blocking); `close()` sequential; sweep sequential; watcher Q only; no non-test `flush()` inside queue job. Rules: (1) nothing inside `queue.run` awaits `flush/close/runExclusive` (source-scan test + dev assert `exclusiveActive`); (2) D innermost and short, 2 s wait -> transient abort before mutation; (3) timer flushes/`touch()` during APPLY queue behind R; (4) HTTP writers wait in Q <=15 s; VALIDATE/network outside all locks; (5) `stop()` waits for cycle; (6) non-hub writers covered by D for devices.yml/allowed_signers, else clean check under D + `read-tree -m` refusing dirty paths. R matters: a `commit()` between read-tree and update-ref would `add -A` tree M onto L, dropping the F parent.

## 4. HALT / quarantine state machine
`IDLE->PRECHECK->COMMIT_PENDING->FETCH->ANCESTRY->[SHORT-CIRCUIT]->VALIDATE->APPLY->NOTES->PUSH->DONE`; transient -> BACKOFF(30 s*2^n, cap 15 min, +-20%); push non-ff -> FETCH max 3.
| Reason | Class | Contact | Exit |
|---|---|---|---|
| `auth`,`hostkey` | no-contact | none (inv 14) | `sync resume` |
| `history-rewrite` | sticky | probe 15 min | `sync resume`, re-check |
| `quarantine:*` layer T | probe | fetch 15 min, same tip no re-validate | auto on passing new F; never overridable |
| `quarantine:*` per-commit provenance | probe | same | auto on repair, or `sync accept <tip>` (OQ-B) |
| `quarantine:revocation-root` | d2 | none | `confirmRevocation` re-gates, accepts, prune removes root key |
| `quarantine:revocation-self` | d2 | none | confirm -> `detached` |
| `detached` | terminal | never | none; local work continues |
| `config` | local | none, recheck each tick | auto when fixed |
| `format` | sticky | probe | hub upgrade |
| `inflight` | local | none | replay each tick; verify mismatch needs `sync resume` after human look |
`pushBlocked{rule}` (egress self-check fail) is not a halt. Local writes continue in all states; only marker guard pauses commits. D2 flow: gate `halt` -> `halt.d2` stored -> CLI `confirmRevocation(id,fp)` (fp must match pubkey of id in devices.yml@d2.commit) -> next cycle passes `confirmedRevocations`; confirmation bound to (commit,id).

## 5. Threat model addendum
| ID | Threat | Invariant | Mitigation |
|---|---|---|---|
| T-B3-1 | replay/rollback, tampering with accepted ref | accepted moves only by CAS to a remote-seen descendant; mirror must agree | ancestry check; `updateRef` NOT_FF + CAS; mirror mismatch HALT `config` |
| T-B3-2 | TOCTOU validate->apply | one F, one L per cycle; worktree never a merge input; main moves L->M with L read inside R+Q | F resolved once; merge inside critical section; clean check + read-tree under D |
| T-B3-3 | crash mid-apply commits a revert | marker blocks `add -A`/commit (sync on or off); replay before first writer | marker guard; replay before `ledger.init()` |
| T-B3-4 | stale in-memory index reverts remote work | no index record older than its file after APPLY | `reindexPaths` in Q with `dropItem`; merge-output self-check |
| T-B3-5 | concurrent devices.yml RMW | every devices.yml/allowed_signers write holds D; takeover atomic | AL-23, AL-16 |
| T-B3-6 | hostile data makes merger/objects/treebuild throw | F-side exception -> quarantine, no bytes applied; local-side never quarantines remote | `validateRange` never throws; `classifySyncError(side)`; AL-36/45/27 |
| T-B3-7 | DoS: huge range, slow objects, re-validation storm, ping-pong | bounded work per cycle/tip; warn-notes unbounded commits impossible | caps 2000/5000/256 KB/5 MB; strikes; same-tip skip; warn-notes local only, <=1 journal line per (rule,device)/24 h; one quarantine note per tip |
| T-B3-8 | privilege escalation: revoked key trusted, unsigned merge alters registry, side-branch revocation missed, verifier outage downgrade | `allowed_signers` never holds key revoked in devices.yml(main); every commit in A..F gated with `currentDevices`; verifier error accepts nothing | prune under D; AL-46/40/43; P-9 |
| T-B3-9 | D2 bypass | root/self revocation applied only with confirmation bound to (commit,id,fp); self never applies remotely | `confirmedRevocations`; `detached` |
| T-B3-10 | secret exfil / unsigned egress | no `.hub/**` staged; sync commits signed or not made; nothing pushed failing own ingress | pathspec, widened S1, no unsigned fallback, egress self-check |
| T-B3-11 | unvalidated/legacy push during sync | with `LEDGER_SYNC=1` only push = `Gitx.push(url,sha)` from cycle | `maybePush` off |
Residual (accepted): local commit still via `git()` with inherited env/global config (F-9; `-c` overrides + pinned `.gitattributes`; moving to Gitx out of B3); merge-commit content other than devices.yml/counters trusted from a trusted signer; notes at-least-once.

## 6. Tests (all via `makeKit()` testkit-remote, local bare remotes, real ssh-keygen keys)
Testkit additions (B3c): `makeLedgerHub(n)`, `fakeHost(hub)`, `flakyRemote()`.
- `state.test.ts` (a): atomic write, corrupt throws, strict schema, list caps, backoff bounds/jitter, inflight path validation, sync.yml strict.
- `gate.test.ts` (a): currentDevices undefined quarantines; `revoked-current` on stolen-key fork; unsigned/untrusted merge with devices.yml != P1/P2 quarantines both modes (AL-40); owner null counter/new item; merge adding item; root revocation confirmed accepts, wrong commit/id halts; self always halts.
- `ingress.test.ts` (a): `validateTreeShape` symlink, exec, gitlink, `.hub`, bad UTF-8, Windows names. `diff3.test.ts` (a): 200 000-line input.
- `devicestore.test.ts` (a): 8 child processes on stale lock, one holder at a time; approve racing prune never resurrects revoked key; prune only removes; `waitMs` honoured. `gitx.test.ts` (a): `core.fsync` in argv.
- `git.test.ts` + `git.sync.test.ts` (b): marker blocks commit sync on/off (summaries kept); `runExclusive` serialises vs timer flush, `commitNow` inline, rejecting fn keeps chain; force-added `.hub/x` -> unsafe hold, no token rotation; `.HUB/Device/key` variant; exclude never stages `.hub`; sync commit signed (verified by `verifyCommitSignature`); missing key -> `error`, no commit; `maybePush` never spawns with sync on; each `CommitOutcome`.
- `ledger.sync.test.ts` (b): `reindexPaths` picks up rewritten item despite hash skip; unparseable dropped, later mutation notFound; repos/counters reload, counter never decreases; source scan for flush inside queue bodies.
- `validate.test.ts` (c): side-branch root revocation halts D2; unsigned side-branch commit; 2001 commits `oversize`; missing object, oversized blob, commit >64 KB quarantine; verifier failure transient; baseFormat downgrade in range; root commit; octopus; merge-base outside range.
- `apply.crash.test.ts` (c, WRITE FIRST): per `CrashPoint`, FF and merge: throw, fresh deps, replay, assert tree(main)==tree(M), clean status, no marker, index reindexed, no commit on L in between; M missing rolls back; foreign edit on changed path halts `inflight` untouched; stale `index.lock` >30 s removed, young waits; pins 3 UNVERIFIED read-tree behaviours.
- `cycle.test.ts` (c): FF, merge, up to date, short-circuit after W7/W8; non-ff x3 then backoff; every HALT reason/class; rollback/rewrite halt; accepted mirror mismatch; remote moves between fetch and apply; local write between validate and apply; dirty/local-hold; throwing merger quarantines nothing applied; same tip not re-validated; warn-notes make no commits (two warn hubs settle <=3 cycles); D2 end to end; `pushBlocked`; missing sync.yml/accepted -> `config`; argv log has no force flag.
- `loop.test.ts` (c): single-flight coalescing; no contact in no-contact halts; `stop()` waits for APPLY; `resume` scope; fake clock.
- `sync.integration.test.ts` (c): two real ledgers + bare remote, concurrent `createItem` converges, no lost item; `revokeDevice` in child process during apply never loses entry; `LEDGER_SYNC=0` makes no fetch/push.

## 7. Sub-batches (file ownership disjoint)
Order: **B3a || B3b -> security gate -> B3c -> security gate**.
- **B3a (12 files):** `hub/sync/state.ts`+test, `gate.ts`+test, `ingress.ts`+test, `merge/diff3.ts`+test, `shared/devicestore.ts`+test, `hub/sync/gitx.ts`+test. Stress: `gateCommit` stays pure/never throws, new inputs required, existing tests pass `currentDevices`; never relax a quarantine; confirmation key (sha,id), self revocation never accepted; `withDeviceLock` non-re-entrant, `pruneRevokedSigners` takes no lock and never adds; AL-16 needs multi-process test; `state.ts` fail closed, durable writes, `ensurePrivateDir`; `validateTreeShape` reuses rule functions.
- **B3b (6 files):** `hub/git.ts`, `git.test.ts`, `git.sync.test.ts`(new), `hub/ledger/ledger.ts`, `paths.ts`, `ledger.sync.test.ts`(new). No dependency on B3a (marker path as option). Stress: `commit()` security-critical, add return values + 3 insertions without reordering S1/gitleaks logic, existing `git.*.test.ts` pass unchanged; `runExclusive` never calls `flush()`; marker guard unconditional; no unsigned fallback in sync mode; non-token `.hub` = `unsafe` hold; `reindexPaths` doesn't take `queue`; `dropItem` rule only for this entry point; `maybePush` off when sync.
- **B3c (12 files):** `validate.ts`+test, `apply.ts`+`apply.crash.test.ts`, `cycle.ts`+test, `loop.ts`+test, `hub/server.ts`, `testkit-remote.ts`, `sync.integration.test.ts`. May cut as c1 (validate, apply, tests, testkit) and c2 (cycle, loop, server, tests, integration). Stress: crash test first; §1.3 order normative; lock order SF->R->Q->D; all git via `Gitx`/`ObjectStore`/`TreeBuilder` (no `git()`, merge, checkout, reset, remote names, worktree as merge input); `validateRange`/`runCycle` never throw, classify by side; `verifier-error` never reaches gate; always pass `commitTimeMs`,`baseFormat`,`currentDevices`; gate full `A..F`; warn-notes never commit; replay phase 1 before `ledger.init()` even with `LEDGER_SYNC=0`; nothing from stderr/URL/blob content into journal/state/logs beyond sanitised tokens (`cleanText`); no `--force`/`-f`/`+refs/heads`.

## 8. Ledger disposition
AL-23: commitTimeMs+baseFormat always (§1.2), device lock around clean check/read-tree/update-ref/prune (B4 parts not B3). AL-36: `mergeTrees` already catches throws (`tree.ts:225-241`), cycle maps `!ok` to quarantine; two-phase `catFileBatch`; per-commit validation §1.2. AL-45: prune after apply and at replay; `confirmedRevocations`; `classifySyncError`. AL-46: required field, whole range, side-branch test. AL-40: regression tests then close. AL-43: owner null + merge item-slot in B3a, verifier-error in B3c. AL-38: decided tolerate. AL-42: B4 only. AL-16, AL-27: B3a. Deferred: `last_seen` write (B4), 50 MB object-growth cap S6 (B6).

## 9. Owner decisions (2026-11-17, AskUserQuestion)
- **OQ-A / AL-38: TOLERATE** a clean absolute-path `remote.origin.url` (inert in sync mode); `https://` origin still HALT `config`; B5 doctor warns, B4 `sync init` offers removal.
- **OQ-B: `sync accept <sha>` overrides signature rows only** (unsigned, unknown key, unapproved, ratchet), `email-mismatch`, per-commit ingress hits whose final tree is clean. Never: layer T tree safety, `revoked-signer`/`revoked-current`, devices.yml changes failing `acceptDevicesChange` or merge equality, D2.
- **OQ-C:** per-commit secret hit removed by a later commit is overridable only via `sync accept <sha> --secret-acknowledged` + journal `sync.secret` line.
