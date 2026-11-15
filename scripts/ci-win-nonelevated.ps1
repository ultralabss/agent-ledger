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
  $tmp = $env:RUNNER_TEMP
  # Start-Process -Credential inherits the runner's TEMP/HOME, which this user cannot write: point them at the granted temp dir.
  $cmd = "set PATH=$nodeDir;%PATH%&& set TEMP=$tmp&& set TMP=$tmp&& set TMPDIR=$tmp&& cd /d `"$ws`" && node --test `"packages/*/src/**/*.test.ts`" > `"$log`" 2>&1"
  $proc = Start-Process -FilePath cmd.exe -ArgumentList '/d','/s','/c',"`"$cmd`"" -Credential $cred -LoadUserProfile -WorkingDirectory $env:RUNNER_TEMP -Wait -PassThru -WindowStyle Hidden
  Get-Content $log
  if ($proc.ExitCode -ne 0) { throw "tests failed as non-elevated user (exit $($proc.ExitCode))" }
} finally {
  Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
}
