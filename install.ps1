<#
.SYNOPSIS
  saiife installer for Windows (developer mode; no administrator rights).

.DESCRIPTION
  Download the file, read it, then run it (it is not meant to be piped into
  Invoke-Expression):

    powershell -ExecutionPolicy Bypass -File .\install.ps1
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Version 0.2.0

  The zip is verified against the release's SHA256SUMS before anything is
  unpacked or placed. A missing SHA256SUMS, a missing line for the zip, or a
  mismatch installs nothing. Downloads use https only (file:// is allowed for
  offline tests and local mirrors). The install directory is added to the
  user's Path (not the machine's), once.

.PARAMETER Version
  Version to install, for example 0.2.0 (default: latest).

.PARAMETER InstallDir
  Install directory (default: $env:LOCALAPPDATA\Programs\saiife\bin).

.PARAMETER BaseUrl
  Release download base URL (default: the GitHub releases URL).

  Supported: Windows on x86_64 (AMD64) and ARM64.
#>
[CmdletBinding()]
param(
  [string]$Version = '',
  [string]$InstallDir = '',
  [string]$BaseUrl = ''
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$RepoUrl = 'https://github.com/HrRobinson/saiife'

function Fail([string]$Message) {
  throw $Message
}

function Get-TargetName {
  $arch = $env:PROCESSOR_ARCHITEW6432
  if ([string]::IsNullOrEmpty($arch)) { $arch = $env:PROCESSOR_ARCHITECTURE }
  switch ($arch) {
    'AMD64' { return 'x86_64-pc-windows-msvc' }
    'ARM64' { return 'aarch64-pc-windows-msvc' }
    default { Fail "unsupported platform: $arch" }
  }
}

# Only [0-9A-Za-z.+-], non-empty.
function Test-Version([string]$Value) {
  if ($Value -notmatch '^[0-9A-Za-z.+-]+$') { Fail "invalid version: '$Value'" }
}

# Fetch <url> to <dest>. https (TLS 1.2 or newer) or file; never http.
function Get-Download([string]$Url, [string]$Dest) {
  $uri = [System.Uri]$Url
  switch ($uri.Scheme) {
    'file' {
      [System.IO.File]::Copy($uri.LocalPath, $Dest, $true)
    }
    'https' {
      # Windows PowerShell 5.1 may default to older protocols.
      try {
        [Net.ServicePointManager]::SecurityProtocol =
          [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      } catch { }
      $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -UseBasicParsing -Uri $uri.AbsoluteUri -OutFile $Dest
    }
    default { Fail "only https downloads are allowed: $Url" }
  }
}

function Test-PathEntryEqual([string]$A, [string]$B) {
  $x = $A.Trim().TrimEnd('\')
  $y = $B.Trim().TrimEnd('\')
  return [string]::Equals($x, $y, [System.StringComparison]::OrdinalIgnoreCase)
}

# Add <dir> to the user's Path once; never touches the machine Path.
function Add-UserPath([string]$Dir) {
  $current = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($null -eq $current) { $current = '' }
  foreach ($entry in $current.Split(';')) {
    if ($entry -ne '' -and (Test-PathEntryEqual $entry $Dir)) { return $false }
  }
  if ($current -eq '' -or $current.EndsWith(';')) { $new = "$current$Dir" } else { $new = "$current;$Dir" }
  [Environment]::SetEnvironmentVariable('Path', $new, 'User')
  # This session too.
  $inSession = $false
  foreach ($entry in $env:Path.Split(';')) {
    if ($entry -ne '' -and (Test-PathEntryEqual $entry $Dir)) { $inSession = $true }
  }
  if (-not $inSession) { $env:Path = "$env:Path;$Dir" }
  return $true
}

function Install-Saiife {
  # Platform first: an unsupported machine never downloads anything.
  $target = Get-TargetName

  if ($InstallDir -eq '') {
    if ([string]::IsNullOrEmpty($env:LOCALAPPDATA)) { Fail 'LOCALAPPDATA is not set; pass -InstallDir' }
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\saiife\bin'
  }

  $version = $Version
  if ($version.StartsWith('v')) { $version = $version.Substring(1) }
  if ($version -ne '') { Test-Version $version }

  if ($BaseUrl -ne '') {
    $base = $BaseUrl
  } elseif ($version -ne '') {
    $base = "$RepoUrl/releases/download/v$version/"
  } else {
    $base = "$RepoUrl/releases/latest/download/"
  }
  if (-not $base.EndsWith('/')) { $base = "$base/" }
  $scheme = ([System.Uri]$base).Scheme
  if ($scheme -ne 'https' -and $scheme -ne 'file') { Fail "only https downloads are allowed: $base" }

  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("saiife-install-" + [System.Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  $staged = ''
  try {
    $sumsPath = Join-Path $tmp 'SHA256SUMS'
    try {
      Get-Download "${base}SHA256SUMS" $sumsPath
    } catch {
      Fail "could not download ${base}SHA256SUMS"
    }

    # Lines are "<hex>  <name>" or "<hex> *<name>".
    $entries = @()
    foreach ($line in [System.IO.File]::ReadAllLines($sumsPath)) {
      if ($line -match '^([0-9A-Fa-f]{64}) [ *](.+)$') {
        $entries += , @($Matches[1], $Matches[2])
      }
    }

    if ($version -eq '') {
      # Latest: the zip name carries the version, so read it from the one
      # SHA256SUMS line for this target.
      $suffix = "-$target.zip"
      $found = @($entries | Where-Object {
          $_[1].StartsWith('saiife-') -and $_[1].Length -gt $suffix.Length -and $_[1].EndsWith($suffix)
        })
      if ($found.Count -ne 1) { Fail 'checksum verification failed' }
      $version = $found[0][1].Substring('saiife-'.Length)
      $version = $version.Substring(0, $version.Length - $suffix.Length)
      Test-Version $version
    }

    $zipName = "saiife-$version-$target.zip"
    $mine = @($entries | Where-Object { $_[1] -ceq $zipName })
    if ($mine.Count -ne 1) { Fail 'checksum verification failed' }
    $expected = $mine[0][0]

    $zipPath = Join-Path $tmp $zipName
    try {
      Get-Download "$base$zipName" $zipPath
    } catch {
      Fail "could not download $base$zipName"
    }

    # Verified before anything is unpacked or placed.
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
    if (-not [string]::Equals($actual, $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
      Fail 'checksum verification failed'
    }

    # Read only the saiife.exe entry (exact name), straight from the zip.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $exeTmp = Join-Path $tmp 'saiife.exe'
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
      $entry = $archive.Entries | Where-Object { $_.FullName -ceq 'saiife.exe' } | Select-Object -First 1
      if ($null -eq $entry) { Fail "could not find saiife.exe in $zipName" }
      $in = $entry.Open()
      try {
        $out = [System.IO.File]::Create($exeTmp)
        try { $in.CopyTo($out) } finally { $out.Dispose() }
      } finally { $in.Dispose() }
    } finally { $archive.Dispose() }

    try {
      New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    } catch {
      Fail "could not create $InstallDir"
    }
    $dest = Join-Path $InstallDir 'saiife.exe'
    $staged = Join-Path $InstallDir ".saiife.tmp.$PID"
    try {
      Copy-Item -LiteralPath $exeTmp -Destination $staged -Force
      Move-Item -LiteralPath $staged -Destination $dest -Force
      $staged = ''
    } catch {
      Fail "could not install to ${dest}: is saiife running?"
    }

    Write-Output "saiife $version installed to $dest"
    if (Add-UserPath $InstallDir) {
      Write-Output "Added $InstallDir to your user PATH; open a new terminal to pick it up."
    }
    Write-Output 'Next: run `saiife init`.'
  } finally {
    if ($staged -ne '' -and (Test-Path -LiteralPath $staged)) {
      Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

try {
  Install-Saiife
} catch {
  [Console]::Error.WriteLine("saiife: $($_.Exception.Message)")
  exit 1
}
