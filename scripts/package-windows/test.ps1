<#
.SYNOPSIS
  CI check of the Windows MSI and the Intune package (plan 19b Task 13). Runs only on a
  GitHub Actions runner (or with SAIIFE_PACKAGE_CI=1 on a throwaway VM), elevated: it
  installs and removes a real service and writes under C:\ProgramData and C:\Program Files.

.DESCRIPTION
  test.ps1 -Exe target\ci-locked\saiife.exe -Version 0.4.0 -LogDir target\package-windows-logs

  Checks, in this order, on a machine with no saiife:
    1. a fleet config that saiife refuses: the MSI fails, rolls back, and
       C:\Program Files\saiife is gone;
    2. a good fleet config naming claude,codex,gemini: msiexec /i exits 0, the service
       runs, doctor exits 1 or less, install.log holds doctor's text, detect.ps1 exits 0;
    3. an upgrade to a second build with a bumped version: the service restarts once and
       the managed files keep their SHA-256;
    4. msiexec /x: the warning is in the log, the service is gone, the audit and the fleet
       files stay, detect.ps1 exits 1;
    5. the .intunewin file exists and unpacks with its header.
  Any failed check ends the run with a nonzero exit.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$LogDir = 'target\package-windows-logs',
  [string]$OutDir = 'dist'
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -and $env:SAIIFE_PACKAGE_CI -ne '1') {
  Write-Output 'test.ps1 installs a real service and writes under C:\ProgramData: it runs only in CI'
  exit 2
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Output 'test.ps1 must run elevated'; exit 2 }

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($p in 'LogDir', 'OutDir') {
  $v = Get-Variable $p -ValueOnly
  if (-not [IO.Path]::IsPathRooted($v)) { Set-Variable $p (Join-Path (Get-Location) $v) }
}
New-Item -ItemType Directory -Force -Path $LogDir, $OutDir | Out-Null
$Exe = (Resolve-Path -LiteralPath $Exe).Path

$programFiles = Join-Path $env:ProgramW6432 'saiife'
$programData = 'C:\ProgramData\saiife'
$bin = Join-Path $programData 'bin\saiife.exe'
$fleetFiles = Join-Path $root 'deploy\intune-windows\fleet-files.ps1'
$detect = Join-Path $root 'deploy\intune-windows\detect.ps1'
$build = Join-Path $PSScriptRoot 'build.ps1'
$target = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$arch = if ($target -like 'aarch64-*') { 'arm64' } else { 'x64' }

$script:failures = 0
function Check([bool]$ok, [string]$what) {
  if ($ok) { Write-Output "ok   $what" } else { Write-Output "::error::FAIL $what"; $script:failures++ }
}
function Stop-IfFailed {
  if ($script:failures -gt 0) { Write-Output "::error::$script:failures check(s) failed"; exit 1 }
}
function Group([string]$name) { Write-Output "::group::$name" }

function Invoke-Msi([string[]]$msiArgs, [string]$log) {
  $p = Start-Process -FilePath msiexec.exe -ArgumentList ($msiArgs + @('/qn', '/l*v', "`"$log`"")) -Wait -PassThru
  return $p.ExitCode
}
function Invoke-Detect {
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $detect *> $null
  return $LASTEXITCODE
}
function Config-B64([string]$text) {
  [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($text))
}
function Service-Pid {
  $s = Get-CimInstance Win32_Service -Filter "Name='saiifed'" -ErrorAction SilentlyContinue
  if ($null -eq $s) { return $null }
  return $s.ProcessId
}
function Service-Exists { [bool](Get-Service -Name saiifed -ErrorAction SilentlyContinue) }
# Leaves the machine as it found it. Only on a CI runner: it removes the audit too.
function Reset-Machine {
  if (Service-Exists) {
    Stop-Service -Name saiifed -Force -ErrorAction SilentlyContinue
    & "$env:SystemRoot\System32\sc.exe" delete saiifed | Out-Null
  }
  foreach ($d in $programFiles, $programData, 'C:\Program Files\ClaudeCode', 'C:\ProgramData\OpenAI', 'C:\ProgramData\gemini-cli') {
    if (Test-Path -LiteralPath $d) {
      Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

# --- the builds ----------------------------------------------------------------------------
Group 'build the MSIs'
if (Test-Path -LiteralPath $programFiles) { Write-Output "::error::$programFiles exists: this runner is not clean"; exit 2 }
if (Service-Exists) { Write-Output '::error::saiifed exists: this runner is not clean'; exit 2 }

$parts = $Version.Split('-')[0].Split('.')
$v1 = $Version
$v2 = "$($parts[0]).$($parts[1]).$([int]$parts[2] + 1)"
& $build -Target $target -Version $v1 -Exe $Exe -OutDir $OutDir
# The second build differs in its bytes, so the daemon's copy changes and install restarts
# the service. An overlay after the last section keeps the PE valid.
$exe2 = Join-Path $LogDir 'saiife-v2.exe'
Copy-Item -LiteralPath $Exe -Destination $exe2 -Force
$fs = [IO.File]::Open($exe2, [IO.FileMode]::Append, [IO.FileAccess]::Write)
try { $x = [Text.Encoding]::ASCII.GetBytes('saiife-ci-upgrade'); $fs.Write($x, 0, $x.Length) } finally { $fs.Dispose() }
$out2 = Join-Path $LogDir 'v2'
& $build -Target $target -Version $v2 -Exe $exe2 -OutDir $out2 -Only msi
$msi1 = Join-Path $OutDir "saiife-$v1-$arch.msi"
$msi2 = Join-Path $out2 "saiife-$v2-$arch.msi"
Check (Test-Path -LiteralPath $msi1) "the first MSI exists ($msi1)"
Check (Test-Path -LiteralPath $msi2) "the second MSI exists ($msi2)"
Stop-IfFailed
Write-Output '::endgroup::'

$goodConfig = Config-B64 "version = 2`nlocked = true`n`n[approval]`napprovers = [`"group:Administrators`"]`n"
$agents = 'claude,codex,gemini'

# --- 1. a fleet file that saiife refuses ----------------------------------------------------
Group 'a broken fleet file rolls back'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fleetFiles -ConfigB64 (Config-B64 "version = 2`nlocked = false`n") -Agents $agents
Check ($LASTEXITCODE -eq 0) 'fleet-files.ps1 wrote the broken config'
$rc = Invoke-Msi @('/i', "`"$msi1`"") (Join-Path $LogDir 'msi-broken.log')
Check ($rc -ne 0) "the MSI failed (exit $rc)"
Check (-not (Test-Path -LiteralPath $programFiles)) "$programFiles is gone after the rollback"
Check (-not (Service-Exists)) 'no service was left behind'
Reset-Machine
Stop-IfFailed
Write-Output '::endgroup::'

# --- 2. install ------------------------------------------------------------------------------
Group 'install'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fleetFiles -ConfigB64 $goodConfig -Agents $agents
Check ($LASTEXITCODE -eq 0) 'fleet-files.ps1 wrote the fleet files'
Check ((Invoke-Detect) -eq 1) 'detect.ps1 exits 1 before the install'
$rc = Invoke-Msi @('/i', "`"$msi1`"") (Join-Path $LogDir 'msi-install.log')
Check ($rc -eq 0) "msiexec /i exits 0 (got $rc)"
Check (Service-Exists) 'the service exists'
Check ((Get-Service -Name saiifed -ErrorAction SilentlyContinue).Status -eq 'Running') 'the service is running'
Check (Test-Path -LiteralPath (Join-Path $programFiles 'saiife.exe')) 'the staging copy is in Program Files'
Check (Test-Path -LiteralPath $bin) 'the daemon copy is in ProgramData'
& $bin doctor *> (Join-Path $LogDir 'doctor-install.txt')
Check ($LASTEXITCODE -le 1) "doctor exits 1 or less (got $LASTEXITCODE)"
$installLog = 'C:\ProgramData\saiife\log\install.log'
Check ((Test-Path -LiteralPath $installLog) -and ((Get-Item -LiteralPath $installLog).Length -gt 0)) 'install.log holds the doctor text'
Check ((Invoke-Detect) -eq 0) 'detect.ps1 exits 0 after the install'
Stop-IfFailed
Write-Output '::endgroup::'

# --- 3. upgrade ------------------------------------------------------------------------------
Group 'upgrade'
$managed = @(
  'C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json',
  'C:\ProgramData\OpenAI\Codex\requirements.toml',
  'C:\ProgramData\gemini-cli\settings.json'
)
$before = @{}
foreach ($f in $managed) {
  Check (Test-Path -LiteralPath $f) "managed file exists: $f"
  if (Test-Path -LiteralPath $f) { $before[$f] = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash }
}
$pid1 = Service-Pid
$since = Get-Date
$rc = Invoke-Msi @('/i', "`"$msi2`"") (Join-Path $LogDir 'msi-upgrade.log')
Check ($rc -eq 0) "the upgrade exits 0 (got $rc)"
Check ((Get-Service -Name saiifed -ErrorAction SilentlyContinue).Status -eq 'Running') 'the service runs after the upgrade'
$pid2 = Service-Pid
Check (($null -ne $pid1) -and ($null -ne $pid2) -and ($pid1 -ne $pid2)) "the service restarted ($pid1 -> $pid2)"
# Service Control Manager event 7036 says "... entered the running state" once per start.
$starts = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7036; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'saiife' -and $_.Message -match 'running' })
Check ($starts.Count -eq 1) "the service started once during the upgrade (saw $($starts.Count))"
foreach ($f in $managed) {
  if ($before.ContainsKey($f)) {
    Check ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -eq $before[$f]) "unchanged by the upgrade: $f"
  }
}
Check ((Invoke-Detect) -eq 0) 'detect.ps1 exits 0 after the upgrade'
Stop-IfFailed
Write-Output '::endgroup::'

# --- 4. uninstall ----------------------------------------------------------------------------
Group 'uninstall'
$ulog = Join-Path $LogDir 'msi-uninstall.log'
$rc = Invoke-Msi @('/x', "`"$msi2`"") $ulog
Check ($rc -eq 0) "msiexec /x exits 0 (got $rc)"
$text = if (Test-Path -LiteralPath $ulog) { Get-Content -LiteralPath $ulog -Raw } else { '' }
Check ($text -match [regex]::Escape('removing the package uninstalls locked mode: agents on this machine will no longer be locked')) 'the warning is in msi.log'
Check (-not (Service-Exists)) 'the service is gone'
Check (-not (Test-Path -LiteralPath $programFiles)) 'Program Files\saiife is gone'
Check (Test-Path -LiteralPath 'C:\ProgramData\saiife\log\audit') 'the audit is kept'
Check (Test-Path -LiteralPath 'C:\ProgramData\saiife\etc\fleet\config.toml') 'the fleet files are kept'
Check ((Invoke-Detect) -eq 1) 'detect.ps1 exits 1 after the removal'
Stop-IfFailed
Write-Output '::endgroup::'

# --- 5. the Intune package ---------------------------------------------------------------------
Group 'the .intunewin file'
& $build -Target $target -Version $v1 -OutDir $OutDir -Only intunewin
$iw = Join-Path $OutDir "saiife-$v1-$arch.intunewin"
Check (Test-Path -LiteralPath $iw) "the .intunewin exists ($iw)"
if (Test-Path -LiteralPath $iw) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($iw)
  try {
    $names = @($zip.Entries | ForEach-Object { $_.FullName })
    Check ($names -contains 'IntuneWinPackage/Metadata/Detection.xml') 'it unpacks with its Detection.xml header'
    Check (@($names | Where-Object { $_ -like 'IntuneWinPackage/Contents/*.intunewin' }).Count -eq 1) 'it holds one encrypted content file'
    $entry = $zip.GetEntry('IntuneWinPackage/Metadata/Detection.xml')
    if ($null -ne $entry) {
      $r = New-Object IO.StreamReader($entry.Open())
      try { $xml = $r.ReadToEnd() } finally { $r.Dispose() }
      Check ($xml -match "<SetupFile>saiife-$([regex]::Escape($v1))-$arch\.msi</SetupFile>") 'its header names the MSI as the setup file'
    }
  } finally { $zip.Dispose() }
}
Write-Output '::endgroup::'

Reset-Machine
Stop-IfFailed
Write-Output 'package-windows: all checks passed'
exit 0
