# Offline test for install.ps1 (CI: windows-latest; `pwsh -File scripts/test-install.ps1`).
#
# Builds a fake release directory laid out like a GitHub release
# (saiife-<version>-<target>.zip plus SHA256SUMS) and runs install.ps1 against
# it through a file:// base. USERPROFILE, LOCALAPPDATA and TEMP point into a
# scratch dir under $env:RUNNER_TEMP (or the system temp dir). The user Path
# is real registry state on a runner, so it is saved first and restored in
# the finally block. No network is used.
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$installer = Join-Path $repo 'install.ps1'
$pwsh = (Get-Process -Id $PID).Path

$base = $env:RUNNER_TEMP
if ([string]::IsNullOrEmpty($base)) { $base = [System.IO.Path]::GetTempPath() }
$scratch = Join-Path $base ("p19a-t9-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null

$script:pass = 0
$script:fail = 0
function Ok([string]$Name) { Write-Output "ok   $Name"; $script:pass++ }
function Bad([string]$Name, [string]$Why) { Write-Output "FAIL $Name : $Why"; $script:fail++ }

# Both scripts must at least parse.
foreach ($f in @($installer, $PSCommandPath)) {
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errors) | Out-Null
  if ($errors.Count -gt 0) { Bad "parse $f" ($errors | Out-String) } else { Ok "parse $(Split-Path -Leaf $f)" }
}

function Get-Sha256([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

function New-ZipFrom([string]$Dir, [string]$Zip) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory($Dir, $Zip, [System.IO.Compression.CompressionLevel]::Optimal, $false)
}

# New-Release <dir> <version>: a zip per target (distinct bytes each) and a
# sorted SHA256SUMS covering both.
function New-Release([string]$Dir, [string]$Version) {
  New-Item -ItemType Directory -Path $Dir | Out-Null
  foreach ($t in @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')) {
    $stage = Join-Path $scratch ("stage-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $stage 'saiife.exe'), "MZ fake saiife $Version $t")
    Copy-Item (Join-Path $repo 'LICENSE') $stage
    Copy-Item (Join-Path $repo 'README.md') $stage
    New-ZipFrom $stage (Join-Path $Dir "saiife-$Version-$t.zip")
    Remove-Item -Recurse -Force $stage
  }
  Write-Sums $Dir
}

function Write-Sums([string]$Dir) {
  $lines = Get-ChildItem -LiteralPath $Dir -Filter 'saiife-*.zip' | Sort-Object Name |
    ForEach-Object { "$(Get-Sha256 $_.FullName)  $($_.Name)" }
  [System.IO.File]::WriteAllText((Join-Path $Dir 'SHA256SUMS'), (($lines -join "`n") + "`n"))
}

# Invoke-Install <case-dir> <release-dir-or-url> <arch> [extra install.ps1 args]:
# runs install.ps1 in a child pwsh with a redirected profile; returns
# @{ Status; Out; Dir }.
function Invoke-Install([string]$Case, [string]$Rel, [string]$Arch, [string[]]$ExtraArgs = @()) {
  New-Item -ItemType Directory -Force -Path (Join-Path $Case 'profile'), (Join-Path $Case 'local'), (Join-Path $Case 'tmp') | Out-Null
  $env:USERPROFILE = Join-Path $Case 'profile'
  $env:LOCALAPPDATA = Join-Path $Case 'local'
  $env:TEMP = Join-Path $Case 'tmp'
  $env:TMP = $env:TEMP
  $env:PROCESSOR_ARCHITECTURE = $Arch
  $env:PROCESSOR_ARCHITEW6432 = ''
  if ($Rel -match '^[a-z]+://') { $url = $Rel } else { $url = ([System.Uri]($Rel.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar)).AbsoluteUri }
  $out = & $pwsh -NoProfile -File $installer -BaseUrl $url @ExtraArgs 2>&1 | Out-String
  return @{ Status = $LASTEXITCODE; Out = $out; Dir = (Join-Path $Case 'local\Programs\saiife\bin') }
}

$origPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$saved = @{}
foreach ($n in 'USERPROFILE', 'LOCALAPPDATA', 'TEMP', 'TMP', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_ARCHITEW6432') {
  $saved[$n] = [Environment]::GetEnvironmentVariable($n)
}

try {
  # Never leave the runner's user Path pointing at test dirs, even on failure
  # of an earlier case: each case starts from the original value.
  function Reset-UserPath { [Environment]::SetEnvironmentVariable('Path', $origPath, 'User') }
  function Count-PathEntry([string]$Dir) {
    $p = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $p) { return 0 }
    return @($p.Split(';') | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') }).Count
  }

  # --- install_pinned_version (AMD64) -------------------------------------
  Reset-UserPath
  $c = Join-Path $scratch 'pinned'
  New-Release (Join-Path $c 'rel') '0.1.0'
  $r = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0')
  $exe = Join-Path $r.Dir 'saiife.exe'
  if ($r.Status -eq 0 -and (Test-Path $exe) -and
    ([System.IO.File]::ReadAllText($exe) -eq 'MZ fake saiife 0.1.0 x86_64-pc-windows-msvc') -and
    $r.Out.Contains("saiife 0.1.0 installed to $exe") -and $r.Out.Contains('saiife init')) { Ok 'install_pinned_version' }
  else { Bad 'install_pinned_version' "status=$($r.Status); $($r.Out)" }

  # --- install_latest (ARM64 picks the aarch64 zip) ------------------------
  Reset-UserPath
  $c = Join-Path $scratch 'latest'
  New-Release (Join-Path $c 'rel') '0.2.0'
  $r = Invoke-Install $c (Join-Path $c 'rel') 'ARM64'
  $exe = Join-Path $r.Dir 'saiife.exe'
  if ($r.Status -eq 0 -and (Test-Path $exe) -and
    ([System.IO.File]::ReadAllText($exe) -eq 'MZ fake saiife 0.2.0 aarch64-pc-windows-msvc') -and
    $r.Out.Contains('saiife 0.2.0 installed')) { Ok 'install_latest' }
  else { Bad 'install_latest' "status=$($r.Status); $($r.Out)" }

  # --- install_dir_override -------------------------------------------------
  Reset-UserPath
  $c = Join-Path $scratch 'custom-dir'
  New-Release (Join-Path $c 'rel') '0.1.0'
  $custom = Join-Path $c 'opt\bin'
  $r = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0', '-InstallDir', $custom)
  if ($r.Status -eq 0 -and (Test-Path (Join-Path $custom 'saiife.exe')) -and -not (Test-Path (Join-Path $r.Dir 'saiife.exe'))) { Ok 'install_dir_override' }
  else { Bad 'install_dir_override' "status=$($r.Status); $($r.Out)" }

  # --- path_added_once (user Path, two installs) ---------------------------
  Reset-UserPath
  $c = Join-Path $scratch 'path-once'
  New-Release (Join-Path $c 'rel') '0.1.0'
  $r1 = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0')
  $r2 = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0')
  if ($r1.Status -eq 0 -and $r2.Status -eq 0 -and (Count-PathEntry $r1.Dir) -eq 1 -and
    $r1.Out.Contains('user PATH') -and -not $r2.Out.Contains('user PATH')) { Ok 'path_added_once' }
  else { Bad 'path_added_once' "entries=$(Count-PathEntry $r1.Dir); $($r1.Out) / $($r2.Out)" }

  # --- checksum_mismatch_installs_nothing ------------------------------------
  Reset-UserPath
  $c = Join-Path $scratch 'mismatch'
  New-Release (Join-Path $c 'rel') '0.1.0'
  [System.IO.File]::AppendAllText((Join-Path $c 'rel\saiife-0.1.0-x86_64-pc-windows-msvc.zip'), 'corrupt')
  $r = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0')
  if ($r.Status -eq 1 -and $r.Out.Contains('saiife: checksum verification failed') -and
    -not (Test-Path (Join-Path $r.Dir 'saiife.exe')) -and (Count-PathEntry $r.Dir) -eq 0) { Ok 'checksum_mismatch_installs_nothing' }
  else { Bad 'checksum_mismatch_installs_nothing' "status=$($r.Status); $($r.Out)" }

  # --- missing_sums_file_installs_nothing (fail closed) -----------------------
  Reset-UserPath
  $c = Join-Path $scratch 'no-sums'
  New-Release (Join-Path $c 'rel') '0.1.0'
  Remove-Item (Join-Path $c 'rel\SHA256SUMS')
  $r = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0')
  if ($r.Status -eq 1 -and $r.Out.Contains('could not download') -and
    -not (Test-Path (Join-Path $r.Dir 'saiife.exe')) -and (Count-PathEntry $r.Dir) -eq 0) { Ok 'missing_sums_file_installs_nothing' }
  else { Bad 'missing_sums_file_installs_nothing' "status=$($r.Status); $($r.Out)" }

  # --- missing_sums_line_installs_nothing -------------------------------------
  Reset-UserPath
  $c = Join-Path $scratch 'missing-line'
  New-Release (Join-Path $c 'rel') '0.1.0'
  $kept = Get-Content (Join-Path $c 'rel\SHA256SUMS') | Where-Object { -not $_.EndsWith('-x86_64-pc-windows-msvc.zip') }
  [System.IO.File]::WriteAllText((Join-Path $c 'rel\SHA256SUMS'), (($kept -join "`n") + "`n"))
  $r = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0')
  if ($r.Status -eq 1 -and $r.Out.Contains('saiife: checksum verification failed') -and
    -not (Test-Path (Join-Path $r.Dir 'saiife.exe'))) { Ok 'missing_sums_line_installs_nothing' }
  else { Bad 'missing_sums_line_installs_nothing' "status=$($r.Status); $($r.Out)" }

  # --- zip_without_saiife_exe_installs_nothing (hash matches) -----------------
  Reset-UserPath
  $c = Join-Path $scratch 'no-exe'
  New-Release (Join-Path $c 'rel') '0.1.0'
  $stage = Join-Path $c 'stage'
  New-Item -ItemType Directory -Path $stage | Out-Null
  [System.IO.File]::WriteAllText((Join-Path $stage 'other.exe'), 'x')
  $zip = Join-Path $c 'rel\saiife-0.1.0-x86_64-pc-windows-msvc.zip'
  Remove-Item $zip
  New-ZipFrom $stage $zip
  Write-Sums (Join-Path $c 'rel')
  $r = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '0.1.0')
  if ($r.Status -eq 1 -and $r.Out.Contains('could not find saiife.exe') -and
    -not (Test-Path (Join-Path $r.Dir 'saiife.exe'))) { Ok 'zip_without_saiife_exe_installs_nothing' }
  else { Bad 'zip_without_saiife_exe_installs_nothing' "status=$($r.Status); $($r.Out)" }

  # --- unsupported_architecture (nothing is downloaded) -----------------------
  Reset-UserPath
  $c = Join-Path $scratch 'unsupported'
  New-Release (Join-Path $c 'rel') '0.1.0'
  $r = Invoke-Install $c (Join-Path $c 'rel') 'x86' @('-Version', '0.1.0')
  if ($r.Status -eq 1 -and $r.Out.Contains('saiife: unsupported platform: x86') -and
    -not (Test-Path (Join-Path $r.Dir 'saiife.exe'))) { Ok 'unsupported_architecture' }
  else { Bad 'unsupported_architecture' "status=$($r.Status); $($r.Out)" }

  # --- bad_version_rejected ---------------------------------------------------
  $c = Join-Path $scratch 'bad-version'
  New-Release (Join-Path $c 'rel') '0.1.0'
  $r = Invoke-Install $c (Join-Path $c 'rel') 'AMD64' @('-Version', '1.0/../x')
  if ($r.Status -eq 1 -and $r.Out.Contains('saiife: invalid version')) { Ok 'bad_version_rejected' }
  else { Bad 'bad_version_rejected' "status=$($r.Status); $($r.Out)" }

  # --- http_base_refused ------------------------------------------------------
  $c = Join-Path $scratch 'http-base'
  New-Item -ItemType Directory -Path $c | Out-Null
  $r = Invoke-Install $c 'http://example.invalid/rel/' 'AMD64' @('-Version', '0.1.0')
  if ($r.Status -eq 1 -and $r.Out.Contains('only https downloads are allowed')) { Ok 'http_base_refused' }
  else { Bad 'http_base_refused' "status=$($r.Status); $($r.Out)" }
}
finally {
  [Environment]::SetEnvironmentVariable('Path', $origPath, 'User')
  foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
  Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "test-install: $($script:pass) passed, $($script:fail) failed"
if ($script:fail -ne 0) { exit 1 }
