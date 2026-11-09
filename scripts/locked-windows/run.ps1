<#
.SYNOPSIS
  Locked mode on a real Windows machine (plan 19b Task 12). CI ONLY.

.DESCRIPTION
  Creates local accounts, installs a real service, writes under C:\ProgramData and
  C:\Program Files, kills the daemon, squats pipes and runs attacks as a second account.
  It runs in the GitHub Actions job `locked-windows` (ci.yml) on throwaway runners, elevated.
  Anywhere else it refuses (exit 2) before doing anything.

    $env:SAIIFE_LOCKED_CI = '1'; ./scripts/locked-windows/run.ps1 -Binary "$PWD\target\ci-locked\saiife.exe"

  The binary is the ci-locked build, installed with --allow-test-build. The phases are in
  lib.ps1 and mirror scripts/locked-macos. A failed phase does not stop the ones after it,
  apart from the host preparation and the install, which everything later needs: this job
  is the first real Windows run, and the measurements must reach the owner even when an
  assertion fails first. Logs go to $env:SAIIFE_LOCKED_LOGS (default target\locked-windows-logs).
#>
[CmdletBinding()]
param([string]$Binary)

# Before anything else, so a developer's machine is left alone.
$onWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:SAIIFE_LOCKED_CI -ne '1' -or -not $onWindows) {
  Write-Output 'refusing: locked-windows tests run only in GitHub Actions CI on Windows (GITHUB_ACTIONS=true, SAIIFE_LOCKED_CI=1, Windows)'
  exit 2
}
if (-not $Binary -or -not [System.IO.Path]::IsPathRooted($Binary) -or -not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
  Write-Output 'usage: $env:SAIIFE_LOCKED_CI=1; run.ps1 -Binary <absolute path to the ci-locked saiife.exe>'
  exit 2
}
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Output 'refusing: locked-windows must run elevated (the runner is, with UAC off)'
  exit 2
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1

$Script:Here = $PSScriptRoot
$Script:Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$Script:Logs = if ($env:SAIIFE_LOCKED_LOGS) { $env:SAIIFE_LOCKED_LOGS } else { Join-Path $Script:Repo 'target\locked-windows-logs' }
$Script:Bin = $Binary
New-Item -ItemType Directory -Force -Path $Script:Logs | Out-Null

. (Join-Path $PSScriptRoot 'lib.ps1')

$code = 0
try {
  Invoke-Phase prepare_host { prepare_host } -Fatal
  Invoke-Phase phase_squat { phase_squat }
  Invoke-Phase phase_personal_squat { phase_personal_squat }
  Invoke-Phase phase_install { phase_install } -Fatal
  Invoke-Phase phase_acls { phase_acls }
  Invoke-Phase phase_hooks { phase_hooks }
  Invoke-Phase phase_fail_closed { phase_fail_closed }
  Invoke-Phase phase_attacks { phase_attacks }
  Invoke-Phase phase_measurements { phase_measurements }
  Invoke-Phase phase_cosign { phase_cosign }
  Invoke-Phase phase_doctor { phase_doctor }
  Invoke-Phase phase_approvals { phase_approvals }
  Invoke-Phase phase_lockdown { phase_lockdown }
  Invoke-Phase phase_reinstall_uninstall { phase_reinstall_uninstall }
} catch {
  Write-Host "::error::stopped: $($_.Exception.Message)"
  $code = 1
}
if ($Script:Failed.Count -gt 0) {
  $code = 1
}
Write-Host ''
foreach ($line in $Script:PhaseLines) { Write-Host $line }
if ($code -ne 0) {
  Write-Host "locked-windows failed: $($Script:Failed -join ', ')"
  Save-FailureLogs
} else {
  Write-Host "== locked-windows: all phases passed ($([System.Environment]::OSVersion.VersionString))"
}
Stop-Spawned
exit $code
