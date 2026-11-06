<#
.SYNOPSIS
  The live lock checks on Windows (plan 19b Task 14; docs/lock-check.md).

.DESCRIPTION
  Runs inside a THROWAWAY Windows VM, elevated, never on your own machine. It
  writes the agents' system-wide managed settings and runs the agents as the
  local standard user `agent`. It refuses (exit 2) unless the OS is Windows and
  SAIIFE_LOCKCHECK_WINDOWS_VM=1, before it touches anything.

  It runs the same check tables as the Linux container and the macOS VM
  (checks-<agent>.sh, through lib.sh with LOCKCHECK_PLATFORM=windows), against
  the spec 5.3a paths:
    Claude Code  C:\Program Files\ClaudeCode\managed-settings.d\
    Codex        C:\ProgramData\OpenAI\Codex\requirements.toml
    Gemini CLI   C:\ProgramData\gemini-cli\settings.json
  Git Bash runs the tables. It cannot start a program as another user, so each
  agent run is a plan (lib.sh, "Windows plans"): this script writes the plan's
  files to C:\, starts the agent as `agent` through Git Bash, and hands back the
  logs and markers. The managed hooks run a stub, not saiife:
  C:\ProgramData\saiife\bin\saiife.exe is a small launcher (compiled here with the
  .NET Framework's csc.exe) that runs stub-saiife.sh in Git Bash, so the hook
  command is the real W9 one. The results go to
  target\lock-check\windows-<agent>-<UTC time>.tsv (and .log) in this checkout.

  What it touches: the three managed paths above, C:\ProgramData\saiife\bin (the
  stub), C:\lockcheck (the harness, the run dir and the project), the settings
  files under C:\Users\agent that the checks write (their contents are not kept:
  use a fresh VM clone), a staging dir in this user's TEMP, and
  target\lock-check\. It refuses to start when saiife is installed, when the
  HKLM Claude Code policy key exists, or when any of those paths already
  exists. It removes what it made at exit. The agents' login files are never
  written.

  Needs: Windows 11 23H2+ or Server 2022+, PowerShell 7 (pwsh), Git for Windows
  (Git Bash, with jq on its PATH or in C:\Program Files\Git\usr\bin), Node 22
  and the three agents installed for `agent`, the .NET Framework 4 compiler
  (csc.exe, part of Windows), and a standard (non-admin) local user `agent`
  logged in to each agent once, then logged off.

    $env:SAIIFE_LOCKCHECK_WINDOWS_VM = '1'
    pwsh -NoProfile -File scripts\lock-check\windows-vm.ps1 -Agent claude

  It asks for the password of `agent` once (Get-Credential).

  Not run yet: no recording exists, and the first run in a VM will settle what
  this script assumes (the hook shells, the stub's crash modes, the trust key
  Codex writes on Windows). docs/lock-check.md lists the open points.
#>
[CmdletBinding()]
param(
  [ValidateSet('claude', 'codex', 'gemini', 'all')]
  [string]$Agent,
  [string]$GitBash = 'C:\Program Files\Git\bin\bash.exe',
  [int]$AgentTimeout = 240
)

# The refusals come first, before anything is read or written.
$onWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
if (-not $onWindows) {
  Write-Output 'refusing: this runs only inside a throwaway Windows VM (this is not Windows)'
  exit 2
}
if ($env:SAIIFE_LOCKCHECK_WINDOWS_VM -ne '1') {
  Write-Output 'refusing: set SAIIFE_LOCKCHECK_WINDOWS_VM=1 to confirm this is a throwaway Windows VM (docs/lock-check.md)'
  exit 2
}
if (-not $Agent) {
  Write-Output 'usage: $env:SAIIFE_LOCKCHECK_WINDOWS_VM=1; pwsh -File windows-vm.ps1 -Agent <claude|codex|gemini|all>'
  exit 2
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
  Write-Output 'refusing: run it with PowerShell 7 (pwsh)'
  exit 2
}
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Output 'refusing: run it from an elevated terminal (Run as administrator)'
  exit 2
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

function Refuse([string]$Why) {
  Write-Output "windows-vm.ps1: refusing: $Why"
  exit 2
}

$Here = $PSScriptRoot
$Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$ManagedSrc = Join-Path $Repo 'crates\agents\tests\fixtures\managed'
if (-not (Test-Path -LiteralPath $ManagedSrc -PathType Container)) {
  Refuse "no managed fixtures at $ManagedSrc; run it from a saiife checkout"
}
if (-not (Test-Path -LiteralPath $GitBash -PathType Leaf)) {
  Refuse "no Git Bash at $GitBash (install Git for Windows, or pass -GitBash)"
}
$Csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $Csc -PathType Leaf)) {
  Refuse "no .NET Framework compiler at $Csc"
}

# The user `agent`: local, standard, with its profile at C:\Users\agent.
$user = Get-LocalUser -Name agent -ErrorAction SilentlyContinue
if (-not $user) { Refuse "there is no local user 'agent'; create a standard user named agent" }
$sid = $user.SID.Value
$admins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue
if ($admins | Where-Object { $_.SID.Value -eq $sid }) { Refuse "the user 'agent' is an administrator; it must be a standard user" }
$profileDir = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
if ($profileDir -ne 'C:\Users\agent') {
  Refuse "the profile of 'agent' is '$profileDir', not C:\Users\agent; log in as agent once"
}
if (Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue | Where-Object { $_.LogonType -in 2, 10, 11 } |
    Get-CimAssociatedInstance -ResultClassName Win32_Account -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $sid }) {
  Refuse "log 'agent' off first: the harness ends the agent's runs and replaces its settings"
}

# Nothing of saiife's, and none of the managed paths, may be there.
if (Get-Service -Name saiifed -ErrorAction SilentlyContinue) { Refuse 'the saiifed service exists; use a VM without saiife' }
if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\ClaudeCode') {
  Refuse 'HKLM\SOFTWARE\Policies\ClaudeCode exists, so Claude Code would ignore the managed files (spec W24)'
}
$claudeBase = 'C:\Program Files\ClaudeCode'
$codexBase = 'C:\ProgramData\OpenAI\Codex'
$geminiBase = 'C:\ProgramData\gemini-cli'
foreach ($p in @('C:\ProgramData\saiife', 'C:\lockcheck', "$claudeBase\managed-settings.d", "$claudeBase\managed-settings.json",
    "$codexBase\requirements.toml", "$geminiBase\settings.json")) {
  if (Test-Path -LiteralPath $p) { Refuse "$p exists; run this in a fresh VM clone" }
}

$cred = Get-Credential -UserName agent -Message 'The password of the local user agent (the agents run as agent)'
if (-not $cred) { Refuse 'no password given' }

# The dirs this run makes, removed at exit (deepest first).
$Made = [System.Collections.Generic.List[string]]::new()
foreach ($d in @('C:\ProgramData\OpenAI', $codexBase, $geminiBase, $claudeBase)) {
  if (-not (Test-Path -LiteralPath $d)) { $Made.Add($d) }
}
$Made.Add('C:\ProgramData\saiife')
$Made.Add('C:\lockcheck')

# What the plans may name, relative to C:\ (lib.sh writes them as `C/<rel>`).
$Allowed = @('Program Files/ClaudeCode', 'ProgramData/OpenAI/Codex', 'ProgramData/gemini-cli', 'ProgramData/saiife/bin',
  'lockcheck/bin', 'lockcheck/run', 'lockcheck/work', 'Users/agent')
# The agents' logins: read for a link, never written or removed.
$Logins = @('Users/agent/.claude/.credentials.json', 'Users/agent/.claude.json', 'Users/agent/.codex/auth.json',
  'Users/agent/.gemini/oauth_creds.json', 'Users/agent/.gemini/google_accounts.json')

function Get-Real([string]$Rel, [switch]$Read) {
  if ($Rel -match '(^|/)\.\.(/|$)' -or $Rel -match '[:\\]' -or $Rel.StartsWith('/')) { throw "a bad path in a plan: $Rel" }
  $ok = $false
  foreach ($a in $Allowed) { if ($Rel -eq $a -or $Rel.StartsWith("$a/")) { $ok = $true } }
  if (-not $ok) { throw "a plan names a path outside the lock-check paths: $Rel" }
  if (-not $Read -and $Logins -contains $Rel) { throw "a plan would write a login file: $Rel" }
  return 'C:\' + ($Rel -replace '/', '\')
}

function Get-Posix([string]$Win) {
  $p = $Win -replace '\\', '/'
  if ($p -match '^([A-Za-z]):/(.*)$') { return "/$($Matches[1].ToLower())/$($Matches[2])" }
  return $p
}

function Set-AdminAcl([string]$Path) {
  $flags = if (Test-Path -LiteralPath $Path -PathType Container) { '(OI)(CI)' } else { '' }
  & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:$($flags)F" "*S-1-5-32-544:$($flags)F" "*S-1-5-32-545:$($flags)RX" /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls $Path failed ($LASTEXITCODE)" }
}

function Set-AgentAcl([string]$Path) {
  $flags = if (Test-Path -LiteralPath $Path -PathType Container) { '(OI)(CI)' } else { '' }
  & icacls.exe $Path /grant "*$($sid):$($flags)F" /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls $Path failed ($LASTEXITCODE)" }
}

function Remove-Real([string]$Path) {
  if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
}

# The launcher: `<dir>\<name>.exe` runs `<dir>\<name>` (a bash script) in Git Bash
# with its arguments, stdin and exit code. Hooks on Windows need a program, and
# Codex and Gemini CLI start hooks without Git Bash.
$launcherSrc = @'
using System;
using System.Diagnostics;
using System.Text;
static class Launcher {
  const string Bash = @"__BASH__";
  static string Quote(string a) {
    if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
    var sb = new StringBuilder("\"");
    int bs = 0;
    foreach (char c in a) {
      if (c == '\\') { bs++; continue; }
      if (c == '"') { sb.Append('\\', bs * 2 + 1); sb.Append('"'); bs = 0; continue; }
      sb.Append('\\', bs); bs = 0; sb.Append(c);
    }
    sb.Append('\\', bs * 2);
    sb.Append('"');
    return sb.ToString();
  }
  static int Main(string[] args) {
    string exe = Process.GetCurrentProcess().MainModule.FileName;
    string script = exe.Substring(0, exe.Length - 4).Replace('\\', '/');
    var line = new StringBuilder(Quote(script));
    foreach (var a in args) { line.Append(' ').Append(Quote(a)); }
    var psi = new ProcessStartInfo(Bash, line.ToString()) { UseShellExecute = false };
    using (var p = Process.Start(psi)) { p.WaitForExit(); return p.ExitCode; }
  }
}
'@

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$Stage = Join-Path ([System.IO.Path]::GetTempPath()) "saiife-lockcheck-$stamp"
New-Item -ItemType Directory -Path $Stage | Out-Null
$Launcher = Join-Path $Stage 'launcher.exe'
Set-Content -LiteralPath "$Stage\launcher.cs" -Value $launcherSrc.Replace('__BASH__', $GitBash) -Encoding utf8
& $Csc /nologo /optimize /target:exe "/out:$Launcher" "$Stage\launcher.cs" | Out-Host
if ($LASTEXITCODE -ne 0) { Refuse 'the launcher did not compile' }

# The agent's environment: the system's, its own profile, Git Bash's tools and the
# agents' install dirs. Nothing of this admin session's.
$gitRoot = Split-Path (Split-Path $GitBash)
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$agentPath = @("$profileDir\AppData\Roaming\npm", "$profileDir\.local\bin", "$gitRoot\usr\bin", "$gitRoot\bin", $machinePath) -join ';'
$agentEnv = [ordered]@{
  SystemRoot = $env:SystemRoot; SystemDrive = $env:SystemDrive; windir = $env:windir; ComSpec = $env:ComSpec
  PATHEXT = $env:PATHEXT; OS = $env:OS; PROCESSOR_ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE
  NUMBER_OF_PROCESSORS = $env:NUMBER_OF_PROCESSORS; ProgramData = $env:ProgramData; ProgramFiles = $env:ProgramFiles
  'ProgramFiles(x86)' = ${env:ProgramFiles(x86)}; CommonProgramFiles = $env:CommonProgramFiles
  ALLUSERSPROFILE = $env:ALLUSERSPROFILE; PUBLIC = $env:PUBLIC; USERNAME = 'agent'; USERDOMAIN = $env:COMPUTERNAME
  USERPROFILE = $profileDir; HOME = $profileDir; APPDATA = "$profileDir\AppData\Roaming"
  LOCALAPPDATA = "$profileDir\AppData\Local"; TEMP = "$profileDir\AppData\Local\Temp"; TMP = "$profileDir\AppData\Local\Temp"
  PATH = $agentPath; TERM = 'dumb'
}

function Read-Nul([string]$File) {
  $t = [System.IO.File]::ReadAllText($File)
  if ($t.Length -eq 0) { return @() }
  return @($t.TrimEnd([char]0).Split([char]0))
}

# Apply a plan's mirror: each real path is deleted, then written from the plan.
function Invoke-Mirror([string]$Plan) {
  foreach ($line in [System.IO.File]::ReadAllLines("$Plan\mirror")) {
    if (-not $line) { continue }
    $f = $line.Split("`t")
    $kind = $f[0]
    $real = Get-Real $f[1]
    $src = Join-Path "$Plan\files" ($f[1] -replace '/', '\')
    switch ($kind) {
      'gone' { Remove-Real $real }
      'log' {
        New-Item -ItemType Directory -Force -Path (Split-Path $real) | Out-Null
        Set-Content -LiteralPath $real -Value $null -NoNewline
        Set-AgentAcl $real
      }
      { $_ -in 'admin', 'agent' } {
        Remove-Real $real
        New-Item -ItemType Directory -Force -Path (Split-Path $real) | Out-Null
        if (Test-Path -LiteralPath $src -PathType Container) {
          Copy-Item -LiteralPath $src -Destination $real -Recurse -Force
        } else {
          Copy-Item -LiteralPath $src -Destination $real -Force
        }
        if ($kind -eq 'admin') {
          # A launcher beside each script in a bin dir: the hooks name saiife.exe,
          # witness.exe and lc-touch.exe.
          if ($f[1] -like '*/bin') {
            foreach ($s in Get-ChildItem -LiteralPath $real -File | Where-Object { -not $_.Extension }) {
              Copy-Item -LiteralPath $Launcher -Destination "$($s.FullName).exe" -Force
            }
          }
          Set-AdminAcl $real
        } else {
          Set-AgentAcl $real
        }
      }
      'link' {
        $target = Get-Real $f[2] -Read
        Remove-Real $real
        if (Test-Path -LiteralPath $target -PathType Leaf) {
          New-Item -ItemType Directory -Force -Path (Split-Path $real) | Out-Null
          Copy-Item -LiteralPath $target -Destination $real -Force
          Set-AgentAcl $real
        }
      }
      default { throw "unknown mirror kind '$kind' in $Plan" }
    }
  }
}

# Run bash.exe as `agent` with the plan's argv and env. Exit 124 is a timeout.
function Invoke-AsAgent([string]$Plan) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $GitBash
  foreach ($a in Read-Nul "$Plan\argv") { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UserName = 'agent'
  $psi.Domain = $env:COMPUTERNAME
  $psi.Password = $cred.Password
  $psi.LoadUserProfile = $true
  $cwd = ([System.IO.File]::ReadAllText("$Plan\cwd")).Trim() -replace '/', '\'
  $psi.WorkingDirectory = if (Test-Path -LiteralPath $cwd) { $cwd } else { $profileDir }
  $psi.Environment.Clear()
  foreach ($k in $agentEnv.Keys) { $psi.Environment[$k] = $agentEnv[$k] }
  foreach ($kv in Read-Nul "$Plan\env") {
    $i = $kv.IndexOf('=')
    if ($i -gt 0) { $psi.Environment[$kv.Substring(0, $i)] = $kv.Substring($i + 1) }
  }
  $timeout = [int](([System.IO.File]::ReadAllText("$Plan\timeout")).Trim())
  $p = [System.Diagnostics.Process]::Start($psi)
  $p.StandardInput.Close()
  $out = $p.StandardOutput.ReadToEndAsync()
  $err = $p.StandardError.ReadToEndAsync()
  $code = 0
  if (-not $p.WaitForExit([Math]::Max($timeout, 1) * 1000)) {
    try { $p.Kill($true) } catch { Write-Host "  could not end the agent run: $($_.Exception.Message)" }
    [void]$p.WaitForExit(5000)
    $code = 124
  } else {
    $code = $p.ExitCode
  }
  $text = $(if ($out.Wait(5000)) { $out.Result } else { '' }) + $(if ($err.Wait(5000)) { $err.Result } else { '' })
  return [pscustomobject]@{ Code = $code; Output = $text }
}

function Invoke-Plan([string]$Plan) {
  $kind = ([System.IO.File]::ReadAllText("$Plan\kind")).Trim()
  $back = New-Item -ItemType Directory -Force -Path "$Plan\back"
  $code = 0
  $output = ''
  try {
    if ($kind -ne 'call') { Invoke-Mirror $Plan }
    if ($kind -ne 'restore') {
      $r = Invoke-AsAgent $Plan
      $code = $r.Code
      $output = $r.Output
    }
  } catch {
    $code = 125
    $output = "windows-vm.ps1: $($_.Exception.Message)"
    Write-Host "  plan $(Split-Path -Leaf $Plan): $output"
  }
  [System.IO.File]::WriteAllText("$back\output", $output)
  foreach ($n in 'calls.log', 'witness.log') {
    if (Test-Path -LiteralPath "C:\lockcheck\run\$n") { Copy-Item -LiteralPath "C:\lockcheck\run\$n" -Destination "$back\$n" -Force }
  }
  $markers = 'C:\lockcheck\work\project\markers'
  $names = if (Test-Path -LiteralPath $markers) { @(Get-ChildItem -LiteralPath $markers -File | ForEach-Object Name) } else { @() }
  [System.IO.File]::WriteAllLines("$back\markers", [string[]]$names)
  [System.IO.File]::WriteAllText("$back\exit", "$code`n")
  [System.IO.File]::WriteAllText("$Plan\done", '')
}

$outDir = Join-Path $Repo 'target\lock-check'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$commit = if ($env:SAIIFE_COMMIT) { $env:SAIIFE_COMMIT } else { (& git -C $Repo rev-parse --short HEAD 2>$null) }
$os = Get-CimInstance Win32_OperatingSystem
$image = "windows-$($os.BuildNumber)-$($env:PROCESSOR_ARCHITECTURE.ToLower())"

$agents = if ($Agent -eq 'all') { @('claude', 'codex', 'gemini') } else { @($Agent) }
$rc = 0
try {
  # The harness, readable by `agent`, written by admins only.
  New-Item -ItemType Directory -Force -Path 'C:\lockcheck\src', 'C:\lockcheck\managed', 'C:\lockcheck\work' | Out-Null
  Copy-Item -Path "$Here\*" -Destination 'C:\lockcheck\src' -Recurse -Force
  Copy-Item -Path "$ManagedSrc\*" -Destination 'C:\lockcheck\managed' -Recurse -Force
  Set-AdminAcl 'C:\lockcheck'
  Set-AgentAcl 'C:\lockcheck\work'

  foreach ($a in $agents) {
    $root = Join-Path $Stage "root-$a"
    $xchg = Join-Path $Stage "xchg-$a"
    New-Item -ItemType Directory -Force -Path $root, $xchg | Out-Null
    $tsv = Join-Path $outDir "windows-$a-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')).tsv"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $GitBash
    foreach ($x in @('-c', 'set -euo pipefail; source "$1/lib.sh"; lc_win_main "$2" "$3"', 'lockcheck',
        '/c/lockcheck/src', $a, (Get-Posix $tsv))) { [void]$psi.ArgumentList.Add($x) }
    $psi.UseShellExecute = $false
    $psi.Environment['LOCKCHECK_PLATFORM'] = 'windows'
    $psi.Environment['LC_ROOT'] = Get-Posix $root
    $psi.Environment['LC_WIN_XCHG'] = Get-Posix $xchg
    $psi.Environment['LC_MANAGED'] = 'C:/lockcheck/managed'
    $psi.Environment['AGENT_TIMEOUT'] = "$AgentTimeout"
    $psi.Environment['SAIIFE_COMMIT'] = "$commit"
    $psi.Environment['LOCKCHECK_WIN_IMAGE'] = $image
    $psi.Environment['LOCKCHECK_NODE_MODULES'] = Get-Posix "$profileDir\AppData\Roaming\npm\node_modules"
    $driver = [System.Diagnostics.Process]::Start($psi)
    # Answer each plan as it is ready, in order, until the tables are done.
    $next = 1
    while ($true) {
      $plan = Join-Path $xchg ('{0:D4}' -f $next)
      if (Test-Path -LiteralPath "$plan\ready") {
        Invoke-Plan $plan
        $next++
        continue
      }
      if ($driver.HasExited) { break }
      Start-Sleep -Milliseconds 200
    }
    if ($driver.ExitCode -ne 0) {
      Write-Host "windows-vm.ps1: $a ended with exit $($driver.ExitCode)"
      $rc = 1
    }
  }
} finally {
  foreach ($p in @("$claudeBase\managed-settings.d", "$claudeBase\managed-settings.json", "$codexBase\requirements.toml",
      "$codexBase\requirements.toml.tmp", "$geminiBase\settings.json")) {
    Remove-Real $p
  }
  for ($i = $Made.Count - 1; $i -ge 0; $i--) { Remove-Real $Made[$i] }
  Remove-Real $Stage
}
exit $rc
