<#
.SYNOPSIS
  Intune custom compliance discovery script for Windows (plan 19b Task 13). Only reads
  state; it changes nothing.

.DESCRIPTION
  Prints one line of compressed JSON with:
    saiife_installed    true when the package's saiife.exe is there and may be trusted
    saiife_doctor_exit  `saiife doctor`'s exit code (0 pass, 1 warnings, 2 failures);
                        2 when saiife.exe is missing, untrusted, or cannot run

  rules.json is compliant when saiife_installed is true and saiife_doctor_exit is 1 or less.
  Intune runs this as SYSTEM, so it runs only the staging copy in C:\Program Files\saiife,
  by its fixed path: that folder is admin-only. It never runs C:\ProgramData\saiife\bin,
  because on a machine with no install (or after a purge) any user can create that path.
  Before it runs the file, it and every folder above it down from C:\Program Files must be
  no junction or link, be owned by SYSTEM, Administrators or TrustedInstaller, and let no
  one else write. If a check fails it reports saiife_installed=false, doctor_exit=2, and
  runs nothing. doctor's output is discarded.
#>
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$exe = 'C:\Program Files\saiife\saiife.exe'
$chain = @('C:\Program Files', 'C:\Program Files\saiife', $exe)

$systemSid = 'S-1-5-18'
$adminsSid = 'S-1-5-32-544'
$installerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$creatorOwnerSid = 'S-1-3-0'
$trustedOwners = @($systemSid, $adminsSid, $installerSid)
$mayWrite = @($systemSid, $adminsSid, $installerSid, $creatorOwnerSid)
# The same mask as fleet-files.ps1: every right that writes, deletes or changes access.
$writeMask = 0x500D0156

# The same check as fleet-files.ps1's Test-Safe, returning a bool instead of exiting.
function Test-Trusted([string]$path, [bool]$isDir) {
  try {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
    if ($item.PSIsContainer -ne $isDir) { return $false }
    $acl = Get-Acl -LiteralPath $path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedOwners) { return $false }
    foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($r.AccessControlType -ne 'Allow') { continue }
      if (([int64]$r.FileSystemRights -band $writeMask) -eq 0) { continue }
      if ($r.IdentityReference.Value -notin $mayWrite) { return $false }
    }
    return $true
  } catch {
    return $false
  }
}

$installed = $true
for ($i = 0; $i -lt $chain.Count; $i++) {
  if (-not (Test-Trusted $chain[$i] ($i -lt $chain.Count - 1))) { $installed = $false; break }
}

$code = 2
if ($installed) {
  try {
    & $exe doctor --json *> $null
    $code = $LASTEXITCODE
  } catch {
    $code = 2
  }
}
@{ saiife_installed = [bool]$installed; saiife_doctor_exit = [int]$code } | ConvertTo-Json -Compress
