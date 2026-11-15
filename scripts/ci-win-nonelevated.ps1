# CI only (windows-latest): run `pnpm test` as a NON-elevated local user.
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
  $pnpmDir = Split-Path (Get-Command pnpm).Source
  foreach ($p in @($ws, $env:RUNNER_TEMP, $nodeDir, $pnpmDir, $env:LOCALAPPDATA)) {
    if ($p -and (Test-Path $p)) { icacls $p /grant "${user}:(OI)(CI)M" /T /C /Q | Out-Null }
  }
  $cred = New-Object System.Management.Automation.PSCredential(".\$user", $sec)
  $log = Join-Path $env:RUNNER_TEMP 'nonelevated-test.log'
  $cmd = "set PATH=$nodeDir;$pnpmDir;%PATH%&& cd /d `"$ws`" && pnpm test > `"$log`" 2>&1 && whoami /groups | findstr /i `"High Mandatory`" > nul && echo ELEVATED>> `"$log`""
  $proc = Start-Process -FilePath cmd.exe -ArgumentList '/d','/s','/c',"`"$cmd`"" -Credential $cred -LoadUserProfile -WorkingDirectory $env:RUNNER_TEMP -Wait -PassThru -WindowStyle Hidden
  Get-Content $log
  if ($proc.ExitCode -ne 0) { throw "pnpm test failed as non-elevated user (exit $($proc.ExitCode))" }
} finally {
  Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
}
