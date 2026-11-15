# CI only (windows-latest): run the test suite (`node --test`, same as `pnpm test`) as a NON-elevated local user.
# The hosted runner is an elevated Administrator and the product (T14) refuses
# to run elevated; that rule is NOT relaxed for CI. No password leaves this
# script: it is random, per run, and the account is deleted at the end.
$ErrorActionPreference = 'Stop'
$user = 'ledgertest'
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pw = [Convert]::ToBase64String($bytes) + 'aA1!'
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
New-LocalUser -Name $user -Password $sec -AccountNeverExpires -PasswordNeverExpires | Out-Null
try {
  $ws = (Get-Location).Path
  $nodeDir = Split-Path (Get-Command node).Source
  foreach ($p in @($ws, $env:RUNNER_TEMP, $nodeDir)) {
    if ($p -and (Test-Path $p)) { icacls $p /grant "${user}:(OI)(CI)M" /T /C /Q | Out-Null }
  }
  $cred = New-Object System.Management.Automation.PSCredential(".\$user", $sec)
  $log = Join-Path $env:RUNNER_TEMP 'nonelevated-test.log'
  # pnpm's shim lives in the runner profile (unreadable for this user); the root `test` script is plain node.
  # The runner's temp root grants BUILTIN\Users inheritable write, which the product's ancestor trust
  # check (correctly) refuses. A real install keeps its data under the user's own profile, so the test
  # user's TEMP is a directory inside ITS profile (ACL: user, SYSTEM, Administrators only).
  # Start-Process -Credential inherits the runner's USERPROFILE, so name the test user's profile explicitly.
  $lt = "$env:SystemDrive\Users\$user\lt"
  $cmd = "set PATH=$nodeDir;%PATH%&& mkdir `"$lt`"& set `"TEMP=$lt`"& set `"TMP=$lt`"& set `"TMPDIR=$lt`"& cd /d `"$ws`" && node --test --test-timeout=120000 `"packages/*/src/**/*.test.ts`" > `"$log`" 2>&1"
  $proc = Start-Process -FilePath cmd.exe -ArgumentList '/d','/s','/c',"`"$cmd`"" -Credential $cred -LoadUserProfile -WorkingDirectory $env:RUNNER_TEMP -PassThru -WindowStyle Hidden
  # Stream the log while the suite runs (a hang must be visible, not silent) and stop before the job limit.
  $deadline = (Get-Date).AddMinutes(17)
  $shown = 0
  while (-not $proc.HasExited) {
    Start-Sleep -Seconds 5
    if (Test-Path $log) {
      $lines = @(Get-Content $log -ErrorAction SilentlyContinue)
      if ($lines.Count -gt $shown) { $lines[$shown..($lines.Count - 1)]; $shown = $lines.Count }
    }
    if ((Get-Date) -gt $deadline) {
      Write-Host '##[error]non-elevated test run exceeded 17 min; killing it'
      & taskkill /F /T /PID $proc.Id | Out-Null
      throw 'tests hung (see log above: last output shows the file/test that never finished)'
    }
  }
  $lines = @(Get-Content $log -ErrorAction SilentlyContinue)
  if ($lines.Count -gt $shown) { $lines[$shown..($lines.Count - 1)] }
  if ($proc.ExitCode -ne 0) { throw "tests failed as non-elevated user (exit $($proc.ExitCode))" }
} finally {
  Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
}
