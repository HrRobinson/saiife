<#
.SYNOPSIS
  Builds the saiife MSI and the Intune Win32 package (plan 19b Task 13).

.DESCRIPTION
  build.ps1 -Target x86_64-pc-windows-msvc -Version 0.4.0

  Writes dist\saiife-<Version>-<arch>.msi and dist\saiife-<Version>-<arch>.intunewin
  (arch is x64 or arm64). WiX is installed as a dotnet tool at the version in
  packaging\windows\wix.version when it is missing. The Content Prep Tool is downloaded
  from the URL in scripts\package-windows\intunewin.version and its SHA-256 is checked
  before it runs.

  -Only msi         build the MSI and stop (release.yml signs it, then runs -Only intunewin)
  -Only intunewin   build the .intunewin from the MSI that is in -OutDir
  -Only all         both (the default)

  The MSI ProductVersion is the numeric part of -Version: a prerelease suffix is dropped,
  so 0.4.0-rc1 and 0.4.0 compare equal to Windows Installer.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')][string]$Target,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Exe = '',
  [string]$OutDir = 'dist',
  [ValidateSet('all', 'msi', 'intunewin')][string]$Only = 'all'
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$arch = if ($Target -like 'aarch64-*') { 'arm64' } else { 'x64' }
$base = "saiife-$Version-$arch"
if (-not [IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path (Get-Location) $OutDir }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$msi = Join-Path $OutDir "$base.msi"
$intunewin = Join-Path $OutDir "$base.intunewin"

function Fail([string]$why) {
  Write-Output "::error::build.ps1: $why"
  throw "build.ps1: $why"
}

function Run([string]$what, [scriptblock]$cmd) {
  & $cmd
  if ($LASTEXITCODE -ne 0) { Fail "$what failed with exit code $LASTEXITCODE" }
}

# Network fetches get 5 tries, 5, 10, 20 and 30 s apart, so a short outage (a 504 from
# GitHub or NuGet) does not fail the build. Checks on what was fetched stay with the caller.
function Retry-Wait([int]$try) { [int][Math]::Min(30, 5 * [Math]::Pow(2, $try - 1)) }

function Run-Retry([string]$what, [scriptblock]$cmd) {
  $tries = 5
  for ($i = 1; $i -le $tries; $i++) {
    & $cmd
    if ($LASTEXITCODE -eq 0) { return }
    if ($i -lt $tries) {
      $wait = Retry-Wait $i
      Write-Output "${what} failed with exit code $LASTEXITCODE (try $i of $tries); retrying in $wait s"
      Start-Sleep -Seconds $wait
    }
  }
  Fail "$what failed with exit code $LASTEXITCODE after $tries tries"
}

function Get-Download([string]$uri, [string]$outFile) {
  $tries = 5
  for ($i = 1; $i -le $tries; $i++) {
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $outFile
      return
    } catch {
      $why = $_.Exception.Message
      Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
      if ($i -eq $tries) { Fail "download of $uri failed after $tries tries: $why" }
      $wait = Retry-Wait $i
      Write-Output "download of $uri failed (try $i of $tries): $why; retrying in $wait s"
      Start-Sleep -Seconds $wait
    }
  }
}

function Build-Msi {
  if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.+-]+)?$') {
    Fail "version '$Version' is not major.minor.patch"
  }
  $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
  if ($major -gt 255 -or $minor -gt 255 -or $patch -gt 65535) {
    Fail "version '$Version' is out of range for an MSI ProductVersion"
  }
  $msiVersion = "$major.$minor.$patch"

  if ($Exe -eq '') { $Exe = Join-Path $root "target\$Target\release\saiife.exe" }
  foreach ($f in @($Exe, (Join-Path $root 'LICENSE'), (Join-Path $root 'README.md'))) {
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Fail "missing $f" }
  }

  $wixVersion = (Get-Content -LiteralPath (Join-Path $root 'packaging\windows\wix.version') -TotalCount 1).Trim()
  if ($wixVersion -notmatch '^\d+\.\d+\.\d+$') { Fail "wix.version holds '$wixVersion'" }
  $toolDir = Join-Path $env:USERPROFILE '.dotnet\tools'
  if (($env:PATH -split ';') -notcontains $toolDir) { $env:PATH = "$env:PATH;$toolDir" }

  $have = ''
  if (Get-Command wix -ErrorAction SilentlyContinue) {
    $have = ((& wix --version) | Select-Object -First 1) -replace '\+.*$', ''
  }
  if ($have -ne $wixVersion) {
    if ($have -ne '') { Run 'dotnet tool uninstall wix' { dotnet tool uninstall --global wix } }
    Run-Retry 'dotnet tool install wix' { dotnet tool install --global wix --version $wixVersion }
  }
  # The Util extension supplies WixQuietExec, which puts the actions' output in msi.log.
  $exts = & wix extension list --global
  if (-not ($exts | Select-String -SimpleMatch "WixToolset.Util.wixext $wixVersion")) {
    Run-Retry 'wix extension add' { wix extension add --global "WixToolset.Util.wixext/$wixVersion" }
  }

  $stage = Join-Path ([IO.Path]::GetTempPath()) ("p19b-t13-stage-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $stage | Out-Null
  try {
    Copy-Item -LiteralPath $Exe -Destination (Join-Path $stage 'saiife.exe')
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE'), (Join-Path $root 'README.md') -Destination $stage
    if (Test-Path -LiteralPath $msi) { Remove-Item -LiteralPath $msi -Force }
    Run 'wix build' {
      wix build -arch $arch -ext WixToolset.Util.wixext `
        -d "Version=$msiVersion" -d "SourceDir=$stage" `
        -o $msi (Join-Path $root 'packaging\windows\saiife.wxs')
    }
  } finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { Fail "wix did not write $msi" }
  Write-Output "built $msi"
}

function Build-Intunewin {
  if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { Fail "no MSI at ${msi}: build it first" }
  $pin = @{}
  Get-Content -LiteralPath (Join-Path $PSScriptRoot 'intunewin.version') | ForEach-Object {
    if ($_ -match '^([a-z0-9]+)=(.+)$') { $pin[$Matches[1]] = $Matches[2].Trim() }
  }
  foreach ($k in 'version', 'url', 'sha256') {
    if (-not $pin.ContainsKey($k)) { Fail "intunewin.version has no $k" }
  }
  if ($pin['url'] -notmatch '^https://') { Fail 'the Content Prep Tool URL is not https' }
  if ($pin['sha256'] -notmatch '^[0-9a-f]{64}$') { Fail 'intunewin.version has no SHA-256' }

  $work = Join-Path ([IO.Path]::GetTempPath()) ("p19b-t13-intune-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    $tool = Join-Path $work 'IntuneWinAppUtil.exe'
    # SAIIFE_DOWNLOAD_CACHE (CI): a folder actions/cache keeps. A copy there is used in
    # place of the download and gets the same SHA-256 check; a checked download goes there.
    $cacheDir = [string]$env:SAIIFE_DOWNLOAD_CACHE
    $cached = ''
    if ($cacheDir -ne '') { $cached = Join-Path $cacheDir "IntuneWinAppUtil-$($pin['sha256']).exe" }
    if (($cached -ne '') -and (Test-Path -LiteralPath $cached -PathType Leaf)) {
      Write-Output "IntuneWinAppUtil.exe from the cache: $cached"
      Copy-Item -LiteralPath $cached -Destination $tool
    } else {
      Get-Download $pin['url'] $tool
    }
    $got = (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $pin['sha256']) {
      Remove-Item -LiteralPath $tool -Force
      Fail "IntuneWinAppUtil.exe has SHA-256 $got, want $($pin['sha256'])"
    }
    if (($cached -ne '') -and -not (Test-Path -LiteralPath $cached -PathType Leaf)) {
      New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
      Copy-Item -LiteralPath $tool -Destination $cached
    }
    # The tool packs a whole folder: give it one holding the MSI alone.
    $src = Join-Path $work 'src'
    $out = Join-Path $work 'out'
    New-Item -ItemType Directory -Path $src, $out | Out-Null
    Copy-Item -LiteralPath $msi -Destination (Join-Path $src "$base.msi")
    Run 'IntuneWinAppUtil' { & $tool -c $src -s "$base.msi" -o $out -q }
    $made = Join-Path $out "$base.intunewin"
    if (-not (Test-Path -LiteralPath $made -PathType Leaf)) { Fail "IntuneWinAppUtil wrote no $base.intunewin" }
    if (Test-Path -LiteralPath $intunewin) { Remove-Item -LiteralPath $intunewin -Force }
    Move-Item -LiteralPath $made -Destination $intunewin
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Output "built $intunewin"
}

if ($Only -ne 'intunewin') { Build-Msi }
if ($Only -ne 'msi') { Build-Intunewin }
