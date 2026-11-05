<#
.SYNOPSIS
  Writes the fleet files that `saiife system install --fleet` reads on Windows (plan 19b
  Task 13). Run it elevated (Intune platform script as SYSTEM, or a GPO startup script)
  BEFORE the MSI installs.

.DESCRIPTION
  Intune scripts take no parameters, so fill in the two defaults below, or pass the
  parameters from a GPO startup script or a test. Treat your copy as you would the config.

    ConfigB64  the base64 of config.toml (required; it must say locked = true)
    Agents     a comma list of agents, for example claude,codex,gemini.
               Empty: no install.toml, and install uses the recorded agents.

  Files written:
    C:\ProgramData\saiife\etc\fleet\config.toml
    C:\ProgramData\saiife\etc\fleet\install.toml

  saiife refuses fleet files in a folder that a non-admin could have written to. On a fresh
  machine C:\ProgramData\saiife does not exist, and a folder made here with the default
  permissions would inherit Users-writable entries from C:\ProgramData and be refused. So
  this script makes C:\ProgramData\saiife and etc with the descriptors saiife expects (the
  rows of crates/system/src/winacl.rs) before it writes anything.

  It refuses (exit 2, nothing written below the refused folder) when a folder it would
  write into is a junction or other reparse point, is owned by someone other than SYSTEM,
  Administrators or TrustedInstaller, or lets anyone else write. It never takes over a
  folder a user made: move it away first.

  Run it in 64-bit PowerShell (the Intune setting "Run script in 64-bit PowerShell host").
#>
[CmdletBinding()]
param(
  [string]$ConfigB64 = '',
  [string]$Agents = 'claude,codex,gemini'
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

function Refuse([string]$why) {
  [Console]::Error.WriteLine("saiife: fleet-files: $why")
  exit 2
}

# --- the input ---------------------------------------------------------------------------
if ($ConfigB64 -eq '') { Refuse 'no config: give the base64 of config.toml' }
try { $config = [Convert]::FromBase64String($ConfigB64) } catch { Refuse 'the config is not valid base64' }
if ($config.Length -eq 0) { Refuse 'the config is empty' }
if ($config.Length -gt 1048576) { Refuse 'the config is larger than 1 MiB' }

# The names go into a TOML file: only the known ones.
$agentList = @()
foreach ($a in ($Agents -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })) {
  if ($a -notin 'claude', 'codex', 'gemini') { Refuse "unknown agent: $a" }
  if ($a -in $agentList) { Refuse "agent listed twice: $a" }
  $agentList += $a
}
$installToml = ''
if ($agentList.Count -gt 0) {
  $installToml = 'agents = [' + (($agentList | ForEach-Object { '"' + $_ + '"' }) -join ', ') + "]`n"
}

# --- who we are --------------------------------------------------------------------------
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not ($isAdmin -or $me.User.Value -eq 'S-1-5-18')) { Refuse 'must run elevated (administrator or SYSTEM)' }

# --- the rows ----------------------------------------------------------------------------
# NT SERVICE\saiifed is a virtual account: its SID is derived from the name, so the
# lookup works before the service exists.
try {
  $svc = (New-Object Security.Principal.NTAccount('NT SERVICE\saiifed')).Translate([Security.Principal.SecurityIdentifier]).Value
} catch { Refuse "cannot find the SID of NT SERVICE\saiifed: $($_.Exception.Message)" }
if ($svc -notmatch '^S-1-5-80-[0-9-]+$') { Refuse "NT SERVICE\saiifed has an unexpected SID: $svc" }

# winacl.rs: ROOT, and PROGRAM_AND_CONFIG (the row of etc and everything below it).
$rootSddl = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;$svc)"
$etcSddl = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;$svc)"

$systemSid = 'S-1-5-18'
$adminsSid = 'S-1-5-32-544'
$installerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$creatorOwnerSid = 'S-1-3-0'
$trustedOwners = @($systemSid, $adminsSid, $installerSid)
$mayWrite = @($systemSid, $adminsSid, $installerSid, $creatorOwnerSid, $svc)
# WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles,
# WriteAttributes, Delete, ChangePermissions, TakeOwnership, GenericAll, GenericWrite.
$writeMask = 0x500D0156

function Test-Safe([string]$path, [bool]$isDir) {
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    Refuse "$path is a junction or symbolic link: saiife does not write through it (remove it first)"
  }
  if ($item.PSIsContainer -ne $isDir) { Refuse "$path is not what it should be: a folder where a file is expected, or the reverse" }
  $acl = Get-Acl -LiteralPath $path
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin $trustedOwners) {
    Refuse "$path is owned by $owner, not by SYSTEM or Administrators: saiife does not trust it (move it away first)"
  }
  foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -ne 'Allow') { continue }
    if (([int64]$r.FileSystemRights -band $writeMask) -eq 0) { continue }
    if ($r.IdentityReference.Value -notin $mayWrite) {
      Refuse "$path lets $($r.IdentityReference.Value) write: saiife does not trust it (move it away first)"
    }
  }
}

function New-ProtectedDir([string]$path, [string]$sddl) {
  $sec = New-Object Security.AccessControl.DirectorySecurity
  $sec.SetSecurityDescriptorSddlForm($sddl)
  $di = New-Object IO.DirectoryInfo $path
  if ($PSVersionTable.PSEdition -eq 'Core') {
    [IO.FileSystemAclExtensions]::Create($di, $sec)
  } else {
    $di.Create($sec)
  }
}

# Each folder: an existing one must pass the check; a missing one is made with its
# descriptor from the first moment, then checked in case another process got there first.
function Use-Dir([string]$path, [string]$sddl) {
  if (-not (Test-Path -LiteralPath $path)) {
    if ($sddl -eq '') {
      # Below etc: it inherits etc's entries, which are the row.
      New-Item -ItemType Directory -Path $path | Out-Null
    } else {
      New-ProtectedDir $path $sddl
    }
  }
  Test-Safe $path $true
}

$programData = Join-Path $env:SystemDrive 'ProgramData'
if ($programData -ne 'C:\ProgramData') { Refuse "the system drive is $env:SystemDrive: saiife supports C:\ProgramData only" }
$pd = Get-Item -LiteralPath $programData -Force
if ($pd.Attributes -band [IO.FileAttributes]::ReparsePoint) { Refuse "$programData is a junction or symbolic link" }

$saiife = Join-Path $programData 'saiife'
$etc = Join-Path $saiife 'etc'
$fleet = Join-Path $etc 'fleet'
Use-Dir $saiife $rootSddl
Use-Dir $etc $etcSddl
Use-Dir $fleet ''

# A file is written beside its name, then renamed in: the folder's entries are inherited, so
# the file has the row from its first moment. A name that is a link is refused.
function Write-FleetFile([string]$name, [byte[]]$bytes) {
  $target = Join-Path $fleet $name
  if (Test-Path -LiteralPath $target) { Test-Safe $target $false }
  $tmp = Join-Path $fleet ("$name." + [Guid]::NewGuid().ToString('N') + '.new')
  $fs = [IO.File]::Open($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
  try {
    Test-Safe $tmp $false
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    [IO.File]::Move($tmp, $target)
  } catch {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    throw
  }
}

Write-FleetFile 'config.toml' $config
$installPath = Join-Path $fleet 'install.toml'
if ($installToml -ne '') {
  Write-FleetFile 'install.toml' ([Text.UTF8Encoding]::new($false).GetBytes($installToml))
} elseif (Test-Path -LiteralPath $installPath) {
  # No agents given: a stale list from an earlier run must not outlive this one.
  Test-Safe $installPath $false
  Remove-Item -LiteralPath $installPath -Force
}

Write-Output "saiife: fleet-files: wrote $fleet"
exit 0
