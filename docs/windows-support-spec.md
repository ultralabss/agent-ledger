# Windows (native + WSL) support and filesystem-permission robustness — spec

Status: approved plan (Opus), owner decisions fixed 2026-11-15.

## Owner decisions
1. Native Windows AND WSL supported.
2. Filesystem without POSIX permission semantics (exFAT/FAT/NFS/SMB/DrvFs): REFUSE fail-closed. Only bypass: `LEDGER_ALLOW_WEAK_FS=1` (exactly `1`, env only, never from repo/ledger config), always with a loud warning.
3. Windows ACLs via system binaries (PowerShell `Get-Acl` SDDL to read, `icacls` with `*SID` syntax to set). No native addon.
4. `claude.cmd` (npm shim) is refused on win32; require native `claude.exe`. Never `shell:true`.
5. One hub per machine (WSL + Windows): doctor reports an error when two ledgers exist.
6. Task Scheduler user task flashes a console at logon in v1 (documented, no conhost wrapper).
7. CI matrix: ubuntu-latest, windows-latest, macos-latest; no `continue-on-error`.
8. `BUILTIN\Administrators` ACEs are trusted on private dirs (parity with root on POSIX). Users / Authenticated Users / Everyone never.
9. Weak-FS bypass visible in hub log, `/v1/healthz` (`fs_weak`), web UI banner, `ledger doctor` (exit 2).
10. install.sh moves to in-repo gitleaks sha256 pins as well.

## Current defects (baseline)
- `shared/src/spool.ts:264,290,410`: `st.uid !== process.getuid?.()` always throws on win32; O_NOFOLLOW undefined on win32 (silent no protection); mode bits meaningless.
- `hub/src/security/token.ts:37,83,92`: hub cannot start on win32; token always "leaked"; `fs.link` fails on FAT/exFAT/SMB.
- `hub/src/pendingmark.ts:74-75` fail-open owner; `hub/src/sessions.ts:431` owner check skipped when uid undefined (fail-open).
- `spool.ts:715-729` takeLock recurses forever if rm fails (EPERM/EBUSY).
- `hub/src/git.ts:219` `core.hooksPath=/dev/null` resolves to `<drive>:\dev\null` on Git for Windows (any user can plant hooks); commit/push lack `--no-verify`. `GIT_CANDIDATES` POSIX-only.
- `cli/src/open.ts:25` `/usr/bin/open`; `selfheal.ts:33` `/bin/launchctl`; `expandHome` duplicated 4x without `~\`.
- `journal.ts:86` `split('\n')` keeps `\r`; claim globs case-sensitive; `safeRead.ts` uses Number for dev/ino.
- `install.sh` gitleaks checksum fetched over same channel (TOFU). CI ubuntu-only.

## Threat model (summary)
Actors: other local account, malicious repo/checkout, compromised download channel, untrusted agent input. Out of scope: same-user attacker, deliberate local admin, kernel.
T1 other-user access to ledger/spool/token/bin · T2 symlink/junction/reparse + TOCTOU · T3 hardlink plant / token leak · T4 lock DoS · T5 hook planting (`C:\dev\null`, reference-transaction) · T6 `.cmd` spawn injection (CVE-2024-27980) · T7 PATH/CWD hijack · T8 ACL inheritance drift · T9 shim/Task Scheduler escaping (`% ! " ^ &`, XML) · T10 gitleaks supply chain (zip-slip, TOFU) · T11 case-insensitive claim bypass (8.3 names, ADS, trailing dot, NFD) · T12 WSL2 dual ledger / bearer to wrong hub · T13 weak FS · T14 elevated install.

## Invariants (tests assert each)
- I1 No trust decision fail-open when platform info missing; `process.getuid` / `O_NOFOLLOW` only inside platformTrust (grep test).
- I2 Every private path is a real dir/file (no symlink/reparse), owned by current principal, writable only by {me, SYSTEM/root, Administrators}; secrets readable by nothing else.
- I3 Children: `spawn(absolutePath, argv[], {shell:false, windowsHide:true})`; forbidden-patterns rule `shell-true` with empty allowlist; `.cmd/.bat/.ps1` refused.
- I4 Git never runs repo-supplied/planted hooks: hooksPath = verified private empty dir on all OSes + `--no-verify` on commit/push.
- I5 Weak-FS bypass relaxes only what the FS cannot express (mode bits, uid, hardlinks, ACLs on non-ACL volumes); never symlink/reparse/regular-file/identity checks; never fixable misconfig.
- I6 One `samePath()` helper (casefold on win32, normalized separators, realpath.native).
- I7 Ledger files LF on disk and in git; readers accept `\r?\n`.
- I8 No binary fetched without in-repo sha256 for that asset.

## platformTrust design — `packages/shared/src/platformTrust.ts`
Single module replacing scattered uid/mode checks (spool, token, pendingmark, sessions, managedbin, git dirChain/checkCandidate cores). API: `probeFs(dir)->FsCaps{posixModes,ownerMatches,hardlinks,acl,fsType,caseInsensitive,weak}`, `ensurePrivateDir`, `assertPrivateDir`, `assertPrivateFile({secret})` (nlink===1), `openPrivate(path, append|excl|trunc|read, mode)`, `assertTrustedAncestors`, `resolveTrustedExecutable(candidates)`, `isOwnedByMe`. `TrustError.code`: SYMLINK|REPARSE|OWNER|PERMS|ACL|WEAK_FS|CHAIN|PROBE_FAILED|IDENTITY. Dependency-injected (`platform,getuid,fs,spawnFile,env,now`) for tests. Gets forbidden-patterns ALLOW entry (child_process).

POSIX backend: current logic moved without loosening (lstat, owner uid, 0o022 dirs, 0o177 secrets, sticky-root parent rule, writeBitsTrusted for binaries). probeFs once per dev: create `.ledger-fsprobe-<rand>` (wx, 0600), check uid + mode 0600, chmod 0640 and re-stat (silent no-op detection), link() and nlink==2, cleanup; any failure => weak. WSL: `/proc/sys/fs/binfmt_misc/WSLInterop` or os.release() /microsoft/i; mounts of type 9p/drvfs/v9fs (`/mnt/<x>`) are weak.

win32 backend: one locked PowerShell call per batch. Binary `${SystemRoot}\System32\WindowsPowerShell\v1.0\powershell.exe` (SystemRoot must match `/^[A-Za-z]:\\[^\\/:*?"<>|\r\n]+$/`, exe must exist, else PROBE_FAILED). Args `-NoProfile -NonInteractive -NoLogo -Command <FIXED_SCRIPT_CONSTANT>`; paths passed as JSON in env `LEDGER_TRUST_PATHS`, never interpolated; `shell:false`, `windowsHide`, 15 s timeout, 1 MB stdout cap. Script outputs JSON: my SID, elevated flag, per path `(Get-Acl -LiteralPath).Sddl`, Attributes (ReparsePoint), DriveFormat/DriveType, UNC flag. SDDL (not icacls text) because it is SID-based/locale-independent. icacls only to SET: `icacls <p> /inheritance:r /grant:r *<mySID>:(OI)(CI)F *S-1-5-18:(OI)(CI)F` (absolute System32 path, argv array, exit code only).
SDDL parser (pure, fixture-tested): owner must be mySID for private paths; DACL must be protected (`P`) on private dirs; allow ACEs with any bit of WRITE_MASK 0x000D0156 (or FA FW GA GW WD WO SD DC CC) only for {mySID, S-1-5-18, S-1-5-32-544, S-1-3-4, S-1-3-0 inherit-only}; read access (0x1/GENERIC_READ/FR/GA) to other SIDs on secrets/private dirs => refuse (token => rotate); inherit-only ACEs evaluated; deny ACEs ignored (conservative); conditional/callback/object ACEs, null DACL, unparseable => refuse; executables additionally allow TrustedInstaller. Ancestor chain: no untrusted SID with DELETE_CHILD|WRITE_DAC|WRITE_OWNER|GENERIC_ALL|GENERIC_WRITE; `C:\` allowed as ancestor but refused as direct parent of a dir we create (children inherit AU Modify). Volumes: NTFS/ReFS only; FAT32/exFAT/network/UNC => weak. openPrivate on win32: lstat (bigint) -> open -> fstat -> lstat; dev+ino equal and not symlink else IDENTITY. Cache keyed on (path,dev,ino,ctimeNs); hub reprobes at start and every 10 min. ensurePrivateDir: ancestors check -> mkdir -> icacls -> verify SDDL -> assert empty; on failure rmdir + refuse. Elevated => refuse ("do not run agent-ledger elevated").

Weak-FS bypass: `LEDGER_ALLOW_WEAK_FS` exactly `1`; probe `weak` -> `{bypassed:true}`; one WARNING line per path in hub log; `/v1/healthz` gains `fs_weak: string[]`; web red banner; `ledger doctor` WARN block first, exit 2; token write falls back link -> `open('wx')`.

## Work packages
Order: S1 -> {S2..S9 || B1..B5} -> B6, B7 -> B8 continuous -> B9.

### Security (crypto-auth-architect)
- S1 platformTrust core: `shared/src/platformTrust.ts`, `sddl.ts` (parser), `win-ps.ts` (fixed script + runner); export in `shared/src/index.ts`; forbidden-patterns ALLOW entry. Freeze API early.
- S2 spool migration: replace assertSafeParentDir/assertSafeDir/safeAppend owner check in spool.ts (~251-297, 405-417) with ensurePrivateDir/openPrivate('append'); random tmp names via openPrivate('excl') instead of fixed `${file}.tmp` (~750-752, 831-832); move isTrustedRootParent into posix backend.
- S3 token: `hub/src/security/token.ts` ensureDir -> ensurePrivateDir; never chmod-and-continue on dir we did not create (win32 refuse); readExisting via assertPrivateFile({secret:true}); ACL readable by others = leaked => rotate; nlink===1; weak-FS link fallback.
- S4 owner checks: `pendingmark.ts:70-76` (remove fail-open), `sessions.ts:431` (fail-closed via isOwnedByMe), `managedbin.ts`, `git.ts:47-165` -> resolveTrustedExecutable; `safeRead.ts`: bigint stats, casefold matchedRoot on win32, win32 identity path.
- S5 git hardening: `GIT_GLOBAL_ARGS`: `core.hooksPath=<ledger>/.hub/empty-hooks` (ensurePrivateDir, asserted empty before spawn batches), `--no-verify` on commit+push, `-c core.autocrlf=false -c core.eol=lf -c core.longpaths=true`; win32 GIT_CANDIDATES `%ProgramW6432%\Git\cmd\git.exe`, `%ProgramFiles%\Git\cmd\git.exe`, `%LOCALAPPDATA%\Programs\Git\cmd\git.exe` (env var must be absolute drive-rooted) via resolveTrustedExecutable.
- S6 spawn policy: `claudebin.ts`, `replies.ts`, `headless.ts`: win32 accept only `*.exe`; `.cmd/.bat/.ps1` refused with fix hint. `cli/src/open.ts`: win32 `${SystemRoot}\explorer.exe <url>` (ignore exit 1), Linux `/usr/bin/xdg-open`, WSL `/usr/bin/wslview` if trusted else `--print`. Add `shell-true` rule to `scripts/forbidden-patterns.mjs` + test.
- S7 gitleaks supply chain: `ops/gitleaks-pins.json` `{version, assets:{"<os>_<arch>": sha256}}` for linux, darwin, windows_x64 (zip); shared verification helper for install.sh and install.ps1; win32 extract with `${SystemRoot}\System32\tar.exe -xf <zip> -C <fresh private dir> gitleaks.exe` (single named member; reject reparse points/extra entries); managedbin on `.hub\bin\gitleaks.exe`; script test: every pin 64-hex and matches version.
- S8 guard canonicalization: `hub/src/guard/globs.ts`, `edit-guard.ts`: `canonicalRel(checkout, p)` = realpath.native (file, or parent+basename for new files), NFC, reject ADS (`:` after drive), trailing dot/space, `\\?\`, device names; casefold pattern+path when `probeFs(checkout).caseInsensitive` (stat-only, create nothing in user repo).
- S9 escaping validators: `shared/src/winquote.ts`: `assertShimSafePath` (reject `% ! "` CR LF control chars, >260 unless longpaths), `crtQuoteArg` (CommandLineToArgvW rules).

### Non-security (backend-architect)
- B1 retries + lock: `shared/src/fsretry.ts` `renameRetry` (win32 only EPERM/EBUSY/EACCES, 8 tries exp backoff <=2.5 s) and `rm({maxRetries:5,retryDelay:50})`; apply in `hub/src/ledger/fsops.ts:16`, `ledger.ts:373`, `ops/logrotate.ts:44`, `spool.ts:499,752,832`; `takeLock`: <=3 attempts, steal only if stale AND pid dead (`process.kill(pid,0)` ESRCH), never recurse after failed rm.
- B2 paths module: `shared/src/paths.ts`: `expandHome` (`~`, `~/`, `~\` on win32; refuse `~user`), `defaultLedgerDir`, `spoolDir` (win32 `%LOCALAPPDATA%\agent-ledger\spool`, absolute and under homedir else homedir fallback; posix XDG), `samePath()`; replace the 4 expandHome copies.
- B3 CRLF: `journal.ts:86`, `md.ts`, `decisions.ts`, spool readers `split(/\r?\n/)`; ledger init writes `.gitattributes` `* text eol=lf` (install.sh too); writers emit `\n`.
- B4 watcher/paths: `hub/src/watcher.ts:36` toPosix before IGNORE; normalize git `C:/...` output (`path.win32.normalize` + samePath) in `ledger.ts:394-438`, `gitreader.ts`.
- B5 hub identity: `/v1/healthz` adds `platform` and ledger realpath; `cli/src/client.ts` verifies before sending bearer; mismatch => CliError 3 "port held by another agent-ledger (WSL vs Windows?)". (Security reviews this diff.)
- B6 doctor: `cli/src/doctor.ts` + `doctor-win32.ts`: FS section via probeFs (ledger, spool, checkout) incl. weak/bypass WARN; win32 supervisor check `schtasks /Query /TN agent-ledger /XML` (action path only); WSL warns on `/mnt/c/Users/<user>/.ledger` and DrvFs ledger/spool; `selfheal.ts` win32 `schtasks /Run /TN agent-ledger` with same rate-limit.
- B7 installer: `install.ps1`, `uninstall.ps1` (run via `powershell -ExecutionPolicy Bypass -File`); refuse when elevated; absolute node.exe via resolveTrustedExecutable (>=22.18); `node packages/cli/src/bin.ts setup --platform-init` does dirs+ACLs through platformTrust; shims in `%LOCALAPPDATA%\agent-ledger\bin`: `ledger.cmd` (`@setlocal DisableDelayedExpansion` then `@"<node>" "<bin.ts>" %*`), `ledger.ps1`, sh shim for Git Bash; PATH add only after confirmation; Claude hooks use node.exe + script directly; Task Scheduler via `Register-ScheduledTask` objects (no XML strings), AtLogOn trigger, principal Interactive RunLevel Limited, hub env via `node --env-file=<%LOCALAPPDATA%\agent-ledger\hub.env>` (private file); paths failing assertShimSafePath abort; uninstall removes task/shims/PATH entry, ledger kept unless `-Purge` (confirm).
- B8 CI: `.github/workflows/ci.yml` matrix `[ubuntu-latest, windows-latest, macos-latest]`, `fail-fast:false`, same SHA-pinned actions, top-level `permissions: contents: read`, `defaults.run.shell: bash`, no `continue-on-error`; POSIX-only tests skipped explicitly with reason; extra ubuntu step `LEDGER_TEST_VFAT=1` loop vfat (sudo) for weak-FS tests; `scripts/workflow-pins.test.mjs` stays green + assertion that matrix includes windows-latest.
- B9 docs: README/INSTALL support matrix with columns CI-verified / manually verified / unverified. CI-verified: Linux ext4, Windows NTFS (Server runner), macOS. Manually verified: none yet (real Windows 11 client and WSL2 are NOT available). Refused: exFAT/FAT/NFS/SMB/DrvFs (explain `LEDGER_ALLOW_WEAK_FS`). Unverified: ARM64 Windows, ReFS, Dev Drive. SECURITY.md gets threat-table summary.

## Test plan (per threat; pure tests via injected deps / `path.win32`; real-OS tests `{skip: process.platform !== 'win32' && 'win32 only'}`)
T1 SDDL fixtures (C:\, C:\Users, profile, LocalAppData, Git dir, child of C:\ with inherited AU:M, null DACL, conditional ACE, Everyone:R token); win32 real: ensurePrivateDir gives `D:P` + allowed SIDs; `C:\ledger-test` refused.
T2 posix swapped-symlink + changing-ino fake lstat => IDENTITY; win32 junction => REPARSE.
T3 nlink 2 token refused/rotated; win32 ACL read for S-1-5-32-545 => rotate.
T4 rm always EPERM => takeLock false within 3 tries (assert call count); live-pid lock never stolen.
T5 GIT_GLOBAL_ARGS has no `/dev/null`; planted pre-commit / reference-transaction never run on commit/push; non-empty empty-hooks dir blocks git.
T6 claudeBin `.cmd` refused before spawn; `shell-true` pattern test.
T7 relative/empty env candidates dropped; malformed SystemRoot => PROBE_FAILED.
T8 ctimeNs change => reprobe; fixture without `P` refused.
T9 assertShimSafePath table; crtQuoteArg round-trip vs reference; `ledger.cmd` golden file.
T10 pins schema; zip with `../evil`/extra member rejected; sha mismatch rejected (fixture, no network).
T11 canonicalRel table (casing, NFD, `a.ts::$DATA`, `a.ts.`, CON); claim `src/auth/**` blocks `SRC/Auth/x.ts` on case-insensitive volumes.
T12 healthz mismatch => client refuses without sending Authorization; mocked mountinfo 9p => weak.
T13 fake probe (0777, uid 65534, chmod no-op, link ENOTSUP) => WEAK_FS; with `=1` runs + healthz `fs_weak` + doctor WARN + non-zero exit; `=true/yes` no effect; symlink and group-writable ext4 dir still refused; Linux vfat loop test CI-gated.
T14 fake elevated => refusal.
Grep test: no `process.getuid`/`O_NOFOLLOW` outside platformTrust; no bare `'git'`/`'claude'` spawn.
