<#
.SYNOPSIS
  Intune Win32 app detection script (plan 19b Task 13). Only reads state.

.DESCRIPTION
  Exit 0 with a line on stdout: saiife is installed (the package's staging copy and the
  saiifed service both exist). Exit 1 with no output: it is not. Intune counts the app as
  detected only for exit 0 with output.

  A stopped service still counts as installed: Intune must not reinstall over it. The
  compliance policy (discovery.ps1) is what reports a service or a doctor that is unwell.
#>
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$staging = Join-Path $env:ProgramW6432 'saiife\saiife.exe'
if (-not (Test-Path -LiteralPath $staging -PathType Leaf)) { exit 1 }
if (-not (Get-Service -Name 'saiifed' -ErrorAction SilentlyContinue)) { exit 1 }
Write-Output 'saiife is installed'
exit 0
