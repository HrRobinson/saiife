# A named pipe server another account holds on purpose (scripts/locked-windows, CI only).
# Its DACL lets everyone connect, so a client gets as far as its owner check; anything a
# client sends is counted in -Log. lib.ps1 ends it through its process handle.
#
# It listens, so it refuses to run outside the job, like run.ps1.
param(
  [Parameter(Mandatory = $true)][string]$Name,
  [Parameter(Mandatory = $true)][string]$Log,
  [Parameter(Mandatory = $true)][string]$Ready
)
if ($env:SAIIFE_LOCKED_CI -ne '1') {
  Write-Output 'refusing: squat-pipe.ps1 is started by locked-windows only (SAIIFE_LOCKED_CI=1)'
  exit 2
}
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Pipes.AccessControl
$everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$security = [System.IO.Pipes.PipeSecurity]::new()
$security.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
    $everyone, [System.IO.Pipes.PipeAccessRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow))
$server = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create(
  $Name, [System.IO.Pipes.PipeDirection]::InOut, 10,
  [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::FirstPipeInstance,
  65536, 65536, $security)
Set-Content -LiteralPath $Ready -Value 'listening'
$buffer = [byte[]]::new(65536)
while ($true) {
  $server.WaitForConnection()
  $bytes = 0
  try {
    while ($true) {
      $n = $server.Read($buffer, 0, $buffer.Length)
      if ($n -le 0) { break }
      $bytes += $n
    }
  } catch {
    Add-Content -LiteralPath $Log -Value "read ended: $($_.Exception.Message)"
  }
  Add-Content -LiteralPath $Log -Value "connection bytes=$bytes"
  try { $server.Disconnect() } catch { Add-Content -LiteralPath $Log -Value "disconnect: $($_.Exception.Message)" }
}
