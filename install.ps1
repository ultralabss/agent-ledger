<#
.SYNOPSIS
  Agent Ledger installer for native Windows. Idempotent; safe to re-run after `git pull`.

.DESCRIPTION
  Run from a normal (NOT elevated) PowerShell, from the cloned repository:

    powershell -ExecutionPolicy Bypass -File .\install.ps1

  This script only orchestrates. Every trust decision (private directories and their ACLs, the
  generated shims, hub.env, the gitleaks digest and layout checks) is made by node through
  `ledger setup` and `scripts\gitleaks-pins.mjs` - the same code the hub uses. Nothing is written
  outside your profile; nothing is installed machine-wide.

  Steps: pnpm install + web build -> private directories + hub.env + shims (node) -> verified
  gitleaks (pin check, zip layout check, System32 tar.exe into a fresh private directory) ->
  optional user PATH entry (asks first) -> Task Scheduler task `agent-ledger` (at logon, runs as
  you, not elevated) -> start + status.

  Known v1 limit: a console window flashes at logon when the hub starts.

.PARAMETER LedgerDir     Ledger directory (default %USERPROFILE%\.ledger, or $env:LEDGER_DIR).
.PARAMETER Port          Hub port (default 4747, or $env:LEDGER_HUB_PORT).
.PARAMETER NodePath      Absolute path of node.exe (>= 22.18). Default: standard install locations, then PATH.
.PARAMETER NoService     Do not register / start the scheduled task.
.PARAMETER SkipGitleaks  Do not fetch gitleaks (commits then go without the second secret check).
.PARAMETER AddToPath     Add the shim directory to your user PATH without asking.
#>
[CmdletBinding()]
param(
  [string]$LedgerDir,
  [int]$Port = 0,
  [string]$NodePath,
  [switch]$NoService,
  [switch]$SkipGitleaks,
  [switch]$AddToPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$TaskName = 'agent-ledger'
$TaskDescription = 'agent-ledger hub (started at logon by install.ps1)'
$Repo = $PSScriptRoot

function Fail([string]$Message) {
  Write-Error "install: $Message"
  exit 1
}

function Note([string]$Message) { Write-Host "    note: $Message" }

# --- guards -----------------------------------------------------------------------------------
if ($env:OS -ne 'Windows_NT') { Fail 'this installer is for Windows; use install.sh on macOS / Linux / WSL' }
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail 'refusing to run elevated: do not run agent-ledger as Administrator. Open a normal PowerShell and run it again.'
}

# --- node.exe: an absolute path, >= 22.18 (read from the file, nothing is executed yet) -------
function Get-NodeVersionFromFile([string]$Path) {
  $v = (Get-Item -LiteralPath $Path).VersionInfo.ProductVersion
  if ($v -match '^(\d+)\.(\d+)\.') { return [Version]('{0}.{1}' -f $Matches[1], $Matches[2]) }
  return $null
}

$candidates = @()
if ($NodePath) { $candidates += $NodePath }
else {
  $pf = [Environment]::GetFolderPath('ProgramFiles')
  $la = [Environment]::GetFolderPath('LocalApplicationData')
  if ($pf) { $candidates += (Join-Path $pf 'nodejs\node.exe') }
  if ($la) { $candidates += (Join-Path $la 'Programs\nodejs\node.exe') }
  $onPath = Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($onPath) { $candidates += $onPath.Source }
}
$Node = $null
foreach ($c in $candidates) {
  if ($c -notmatch '^[A-Za-z]:\\') { continue }
  if (-not (Test-Path -LiteralPath $c -PathType Leaf)) { continue }
  $ver = Get-NodeVersionFromFile $c
  if ($null -eq $ver) { continue }
  if ($ver -lt [Version]'22.18') { Note "$c is node $ver (< 22.18) - skipped"; continue }
  $Node = $c
  break
}
if (-not $Node) { Fail 'node.exe >= 22.18 not found - install Node from https://nodejs.org or pass -NodePath <absolute path>' }
Write-Host "==> node $Node"

if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) { Fail 'pnpm not found - install it (for example `corepack enable`)' }
$gitCandidates = @(
  (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Git\cmd\git.exe'),
  (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\Git\cmd\git.exe')
)
if (-not ($gitCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })) {
  Note 'Git for Windows was not found in its standard locations; the hub only uses git from there. Install it (winget install Git.Git).'
}

$Cli = Join-Path $Repo 'packages\cli\src\bin.ts'
$Pins = Join-Path $Repo 'scripts\gitleaks-pins.mjs'
if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { Fail "cannot find $Cli - run this script from the repository" }

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
  & $Exe @Arguments
  if ($LASTEXITCODE -ne 0) { Fail "$Exe $($Arguments -join ' ') failed (exit $LASTEXITCODE)" }
}

# --- dependencies + web build -------------------------------------------------------------------
Push-Location $Repo
try {
  Write-Host '==> pnpm install'
  Invoke-Checked 'pnpm' @('install', '--frozen-lockfile')
  if (Test-Path -LiteralPath (Join-Path $Repo 'packages\web')) {
    Write-Host '==> pnpm --filter @agent-ledger/web build'
    Invoke-Checked 'pnpm' @('--filter', '@agent-ledger/web', 'build')
  }
} finally { Pop-Location }

# --- node does the trust work: private dirs, hub.env, shims -------------------------------------
Write-Host '==> private directories, hub.env, shims (ledger setup --platform-init)'
$initArgs = @($Cli, 'setup', '--platform-init')
if ($LedgerDir) { $initArgs += @('--ledger-dir', $LedgerDir) }
if ($Port -gt 0) { $initArgs += @('--port', [string]$Port) }
$initOut = & $Node @initArgs
if ($LASTEXITCODE -ne 0) { Fail "setup --platform-init refused (exit $LASTEXITCODE) - see the message above" }
$Init = $initOut | Select-Object -Last 1 | ConvertFrom-Json
if (-not $Init.ok) { Fail 'setup --platform-init did not report success' }
Write-Host "    ledger  $($Init.ledgerDir)"
Write-Host "    shims   $($Init.binDir)  (cmd: $($Init.shims.cmd); ps1: $($Init.shims.ps1); sh: $($Init.shims.sh))"
foreach ($k in 'cmd', 'ps1', 'sh') {
  if ($Init.shims.$k -like 'skipped*') { Note "shim $k $($Init.shims.$k)" }
}

# --- gitleaks (second secret check in front of every commit) ------------------------------------
function Install-Gitleaks {
  $scratch = $null
  try {
    $ver = (& $Node $Pins 'version'); if ($LASTEXITCODE -ne 0) { throw 'no pinned gitleaks version' }
    $asset = (& $Node $Pins 'asset' 'windows_x64'); if ($LASTEXITCODE -ne 0) { throw 'no pin for windows_x64' }
    if ($ver -notmatch '^\d+\.\d+\.\d+$' -or $asset -notmatch '^gitleaks_\d+\.\d+\.\d+_windows_x64\.zip$') { throw 'unexpected pin output' }
    $sys32 = [Environment]::SystemDirectory
    $tar = Join-Path $sys32 'tar.exe'
    if (-not (Test-Path -LiteralPath $tar -PathType Leaf)) { throw 'System32\tar.exe not found (Windows 10 1803 or newer is needed)' }
    Write-Host "==> gitleaks v$ver (verified against ops/gitleaks-pins.json)"
    $scratch = (& $Node $Cli 'setup' '--private-dir' (Join-Path $Init.dataDir ('tmp-' + [guid]::NewGuid().ToString('N'))) | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or -not $scratch) { throw 'could not create a private scratch directory' }
    $zip = Join-Path $scratch $asset
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/gitleaks/gitleaks/releases/download/v$ver/$asset" -OutFile $zip
    & $Node $Pins 'check-file' 'windows_x64' $zip; if ($LASTEXITCODE -ne 0) { throw 'archive digest does not match the in-repo pin' }
    & $Node $Pins 'zip-members' $zip; if ($LASTEXITCODE -ne 0) { throw 'archive layout refused' }
    $out = (& $Node $Cli 'setup' '--private-dir' (Join-Path $scratch 'out') | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or -not $out) { throw 'could not create a private extraction directory' }
    & $tar '-xf' $zip '-C' $out 'gitleaks.exe'; if ($LASTEXITCODE -ne 0) { throw 'extraction failed' }
    & $Node $Pins 'check-extracted' $out; if ($LASTEXITCODE -ne 0) { throw 'extracted layout refused' }
    $placed = (& $Node $Cli 'setup' '--place-gitleaks' (Join-Path $out 'gitleaks.exe') '--ledger-dir' $Init.ledgerDir | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0) { throw 'could not place the verified copy' }
    Write-Host "    placed  $(($placed | ConvertFrom-Json).path)"
    return $true
  } catch {
    Note "gitleaks was NOT installed: $($_.Exception.Message). The hub commits the ledger without the second check; re-run this script when the cause is fixed."
    return $false
  } finally {
    if ($scratch -and (Test-Path -LiteralPath $scratch)) {
      $item = Get-Item -LiteralPath $scratch -Force
      if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
    }
  }
}
if ($SkipGitleaks) { Write-Host '==> gitleaks: skipped (-SkipGitleaks)' } else { [void](Install-Gitleaks) }

# --- user PATH (only after confirmation) --------------------------------------------------------
function Test-OnUserPath([string]$Dir) {
  $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
  try { $cur = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames') } finally { $key.Close() }
  foreach ($e in $cur.Split(';')) { if ($e.TrimEnd('\') -ieq $Dir.TrimEnd('\')) { return $true } }
  return $false
}
if (Test-OnUserPath $Init.binDir) {
  Write-Host "==> PATH: $($Init.binDir) is already on your user PATH"
} else {
  $yes = [bool]$AddToPath
  if (-not $yes) {
    try { $answer = Read-Host "Add $($Init.binDir) to your user PATH (so `ledger` works in new terminals)? [y/N]" } catch { $answer = '' }
    $yes = ($answer -match '^(y|yes)$')
  }
  if ($yes) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
      $cur = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
      $new = if ($cur) { $cur.TrimEnd(';') + ';' + $Init.binDir } else { $Init.binDir }
      $key.SetValue('Path', $new, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally { $key.Close() }
    Write-Host '==> PATH updated for your user (open a new terminal)'
  } else {
    Note "not added to PATH. Call the shim by full path or add $($Init.binDir) yourself."
  }
}

# --- Task Scheduler (objects, no XML strings; runs as you, limited, at logon) -------------------
function Test-PortFree([int]$P) {
  $c = New-Object Net.Sockets.TcpClient
  try {
    $r = $c.BeginConnect('127.0.0.1', $P, $null, $null)
    if ($r.AsyncWaitHandle.WaitOne(700) -and $c.Connected) { return $false }
    return $true
  } catch { return $true } finally { $c.Close() }
}

if ($NoService) {
  Write-Host '==> service: skipped (-NoService)'
  Write-Host "    start the hub yourself:  `"$($Init.node)`" $($Init.taskArguments)"
} else {
  $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($existing) {
    if ($existing.Description -ne $TaskDescription) {
      Fail "a scheduled task named '$TaskName' exists and was not created by this installer - remove or rename it first"
    }
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
  }
  if (-not (Test-PortFree $Init.port)) { Fail "port $($Init.port) is in use by another process - free it or re-run with -Port <n>" }
  Write-Host "==> scheduled task $TaskName (at logon, $($Identity.Name), not elevated)"
  $action = New-ScheduledTaskAction -Execute $Init.node -Argument $Init.taskArguments -WorkingDirectory $Repo
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $Identity.Name
  $taskPrincipal = New-ScheduledTaskPrincipal -UserId $Identity.Name -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Description $TaskDescription
  Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName

  Write-Host '==> status'
  $savedDir = $env:LEDGER_DIR; $savedPort = $env:LEDGER_HUB_PORT; $savedUrl = $env:LEDGER_HUB_URL
  $env:LEDGER_DIR = $Init.ledgerDir; $env:LEDGER_HUB_PORT = [string]$Init.port; $env:LEDGER_HUB_URL = ''
  $up = $false
  try {
    for ($i = 0; $i -lt 30 -and -not $up; $i++) {
      & $Node $Cli 'status' *> $null
      if ($LASTEXITCODE -eq 0) { $up = $true } else { Start-Sleep -Seconds 1 }
    }
    if ($up) { & $Node $Cli 'status' }
  } finally {
    $env:LEDGER_DIR = $savedDir; $env:LEDGER_HUB_PORT = $savedPort; $env:LEDGER_HUB_URL = $savedUrl
  }
  if (-not $up) { Fail "the hub did not answer on 127.0.0.1:$($Init.port) within 30 s - see $($Init.ledgerDir)\.hub" }
}

Write-Host @"

Agent Ledger is installed.
  ledger CLI:   $($Init.binDir)\ledger.cmd   (PowerShell: ledger.ps1, Git Bash: ledger)
  ledger data:  $($Init.ledgerDir)   (git repository; delete nothing by hand)
  hub env:      $($Init.hubEnv)

Optional: Claude Code hooks (adds entries to ~/.claude/settings.json only after you confirm; needs a native claude.exe).
Preview first, it writes nothing:
  & "$Node" "$(Join-Path $Repo 'adapters\claude-code\install-hooks.mjs')" --dry-run
Uninstall: powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
"@
