<#
.SYNOPSIS
  Intune custom compliance discovery script for Windows (plan 19b Task 13). Only reads
  state; it changes nothing.

.DESCRIPTION
  Prints one line of compressed JSON with:
    saiife_installed    true when the daemon's copy of saiife.exe is installed
    saiife_doctor_exit  `saiife doctor`'s exit code (0 pass, 1 warnings, 2 failures);
                        2 when saiife is installed but doctor cannot run, 99 when not
                        installed

  rules.json is compliant when saiife_installed is true and saiife_doctor_exit is 1 or less.
  Intune runs this as SYSTEM. doctor's output is discarded.
#>
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$bin = Join-Path $env:ProgramData 'saiife\bin\saiife.exe'
$installed = Test-Path -LiteralPath $bin -PathType Leaf
$code = 99
if ($installed) {
  $code = 2
  try {
    & $bin doctor --json *> $null
    $code = $LASTEXITCODE
  } catch {
    $code = 2
  }
}
@{ saiife_installed = [bool]$installed; saiife_doctor_exit = [int]$code } | ConvertTo-Json -Compress
