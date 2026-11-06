# The phases of scripts/locked-windows/run.ps1 (CI only; see there). Dot-sourcing this file
# only defines functions and constants; run.ps1 checks the CI gate before it does. The phases
# and helpers mirror scripts/locked-macos/lib.sh; that file is never called.
#
# Nothing here has ever run: it was written without a Windows machine. A first failure may
# be this script's own. Three kinds of line matter to the owner, and go to measurements.txt
# and the step summary as well as the log:
#   MEASUREMENT  what really happened in an attack with no promise behind it; never asserted
#   READBACK     real descriptors and values, for the code that assumed them
#   an assertion failure, which ends its phase and fails the job
#
# Needs from run.ps1: Here, Repo, Logs, Bin (the ci-locked saiife.exe to install).

$Script:AgentName = 'agent'
$Script:ApproverName = 'approver'
$Script:ServiceName = 'saiifed'
$Script:Root = 'C:\ProgramData\saiife'
$Script:BinDir = "$Script:Root\bin"
$Script:Hook = "$Script:BinDir\saiife.exe"
$Script:HookForward = 'C:/ProgramData/saiife/bin/saiife.exe'
$Script:EtcDir = "$Script:Root\etc"
$Script:ConfigPath = "$Script:EtcDir\config.toml"
$Script:InstalledPath = "$Script:EtcDir\installed.toml"
$Script:StateDir = "$Script:Root\state"
$Script:VaultKey = "$Script:StateDir\keys\vault.key"
$Script:AuditKey = "$Script:StateDir\keys\audit.ed25519"
$Script:LogDir = "$Script:Root\log"
$Script:AuditDir = "$Script:LogDir\audit"
$Script:DaemonLog = "$Script:LogDir\daemon\daemon.log"
$Script:Pipe = '\\.\pipe\saiife'
$Script:ClaudeDir = 'C:\Program Files\ClaudeCode\managed-settings.d'
$Script:ClaudeManaged = "$Script:ClaudeDir\50-saiife.json"
$Script:ClaudeMcp = "$Script:ClaudeDir\60-saiife-mcp.json"
$Script:CodexReq = 'C:\ProgramData\OpenAI\Codex\requirements.toml'
$Script:GeminiSettings = 'C:\ProgramData\gemini-cli\settings.json'
$Script:AuditGroup = 'saiife-audit'
$Script:W11Line = 'pipe \\.\pipe\saiife exists and is not ours; refusing to start'
$Script:SameUserOff = 'same-user approval is off on Windows'
# W10, verbatim.
$Script:ServiceSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AU)'
# plant.c has the markers dir of this path in its source.
$Script:Work = 'C:\saiife-locked-ci'
$Script:Fixtures = "$Script:Repo\crates\cli\tests\fixtures"
$Script:CiConfig = "$Script:Here\config.toml"
$Script:UacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

$Script:Agent = $null
$Script:Approver = $null
$Script:Pwsh = (Get-Process -Id $PID).Path
$Script:Failed = [System.Collections.Generic.List[string]]::new()
$Script:PhaseLines = [System.Collections.Generic.List[string]]::new()
$Script:Spawned = [System.Collections.Generic.List[object]]::new()
$Script:SnippetCount = 0
$Script:ConfigBackup = $null
$Script:LockdownOn = $false
$Script:InstallOut = ''
$Script:ServiceSid = ''
$Script:AuditSid = ''
$Script:CopyBin = "$Script:Work\bin\saiife.exe"

# ------------------------------------------------------------ helpers

function Fail([string]$Message) { throw "FAIL: $Message" }

function Ok([string]$Message) { Write-Host "  ok: $Message" }

function Write-Finding([string]$Label, [string]$Name, [string]$Text) {
  $line = "$Label [$Name] ($([System.Environment]::OSVersion.Version)): $Text"
  Write-Host $line
  Add-Content -LiteralPath "$Script:Logs\measurements.txt" -Value $line
  if ($env:GITHUB_STEP_SUMMARY) {
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value "- ``$Label`` **$Name**: $($Text -replace '\r?\n', ' | ')"
  }
}

# What really happened in an attack. Nothing asserts these.
function Measure-Result([string]$Name, [string]$Text) { Write-Finding 'MEASUREMENT' $Name $Text }

# A real value read back from this machine.
function Read-Back([string]$Name, [string]$Text) { Write-Finding 'READBACK' $Name $Text }

function Invoke-Phase {
  param([string]$Name, [scriptblock]$Body, [switch]$Fatal)
  $started = Get-Date
  Start-Transcript -LiteralPath "$Script:Logs\$Name.log" -Force | Out-Null
  Write-Host ''
  Write-Host "== $Name"
  $error_text = $null
  try {
    & $Body
  } catch {
    $error_text = "$($_.Exception.Message)`n$($_.ScriptStackTrace)"
  }
  $secs = [int]((Get-Date) - $started).TotalSeconds
  if ($error_text) {
    $Script:Failed.Add($Name)
    $Script:PhaseLines.Add("FAILED  $Name (${secs}s): $(($error_text -split "`n")[0])")
    Write-Host "::error title=${Name}::$(($error_text -split "`n")[0])"
    Write-Host $error_text
  } else {
    $Script:PhaseLines.Add("passed  $Name (${secs}s)")
    Write-Host "== $Name passed (${secs}s)"
  }
  Stop-Transcript | Out-Null
  if ($error_text) {
    if ($Fatal) { throw "$Name failed, and the phases after it need it" }
    # The next phase starts from a known host.
    try { Restore-Baseline } catch { Write-Host "restoring after ${Name}: $($_.Exception.Message)" }
  }
}

function Wait-Until {
  param([int]$Seconds, [string]$What, [scriptblock]$Condition)
  $end = (Get-Date).AddSeconds($Seconds)
  while ($true) {
    if (& $Condition) { return }
    if ((Get-Date) -gt $end) { Fail "timed out after ${Seconds}s waiting for $What" }
    Start-Sleep -Milliseconds 500
  }
}

# A clean environment for an account, as `env -i` on macOS: the runner's GITHUB_* and its
# profile paths never reach the agent. What a pwsh or a loader needs and nothing else.
function Set-CleanEnvironment($Psi, $User) {
  $keep = @{}
  foreach ($k in 'SystemRoot', 'windir', 'SystemDrive', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)',
    'ProgramW6432', 'CommonProgramFiles', 'ComSpec', 'PATHEXT', 'NUMBER_OF_PROCESSORS', 'OS',
    'PROCESSOR_ARCHITECTURE', 'COMPUTERNAME') {
    $v = [System.Environment]::GetEnvironmentVariable($k)
    if ($v) { $keep[$k] = $v }
  }
  $systemRoot = $keep['SystemRoot']
  $keep['Path'] = "$systemRoot\System32;$systemRoot;$systemRoot\System32\WindowsPowerShell\v1.0;$(Split-Path -Parent $Script:Pwsh)"
  $keep['USERNAME'] = $User.Name
  $keep['USERDOMAIN'] = $env:COMPUTERNAME
  if ($User.Home) {
    $keep['USERPROFILE'] = $User.Home
    $keep['HOME'] = $User.Home
    $keep['APPDATA'] = "$($User.Home)\AppData\Roaming"
    $keep['LOCALAPPDATA'] = "$($User.Home)\AppData\Local"
    $keep['TEMP'] = "$($User.Home)\AppData\Local\Temp"
    $keep['TMP'] = "$($User.Home)\AppData\Local\Temp"
  }
  $Psi.Environment.Clear()
  foreach ($k in $keep.Keys) { $Psi.Environment[$k] = $keep[$k] }
}

# Starts a program, as $User when it is given (else as the elevated runner, in its own
# environment plus $ExtraEnv). System.Diagnostics.Process rather than Start-Process
# -Credential: both reach CreateProcessWithLogonW, but Start-Process builds its Process
# object after the child has started, so a hook that exits at once can raise "not running"
# and lose its exit code. Each call as a user is a new logon session.
function Start-As {
  param($User, [string]$Exe, [string[]]$Arguments = @(), [string]$Cwd, [string]$Stdin = '',
    [hashtable]$ExtraEnv = @{}, [switch]$KeepStdinOpen)
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $Exe
  foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $utf8 = [System.Text.UTF8Encoding]::new($false)
  $psi.StandardInputEncoding = $utf8
  $psi.StandardOutputEncoding = $utf8
  $psi.StandardErrorEncoding = $utf8
  if ($User) {
    $psi.UserName = $User.Name
    $psi.Domain = $env:COMPUTERNAME
    $psi.Password = $User.Password
    $psi.LoadUserProfile = $true
    Set-CleanEnvironment $psi $User
    $psi.WorkingDirectory = if ($Cwd) { $Cwd } elseif ($User.Project) { $User.Project } else { $Script:Work }
  } elseif ($Cwd) {
    $psi.WorkingDirectory = $Cwd
  }
  foreach ($k in $ExtraEnv.Keys) { $psi.Environment[$k] = $ExtraEnv[$k] }
  try {
    $p = [System.Diagnostics.Process]::Start($psi)
  } catch {
    $inner = $_.Exception
    while ($inner.InnerException) { $inner = $inner.InnerException }
    return [pscustomobject]@{ Process = $null; StartError = $inner.Message; OutTask = $null; ErrTask = $null }
  }
  $handle = [pscustomobject]@{
    Process = $p
    StartError = $null
    OutTask = $p.StandardOutput.ReadToEndAsync()
    ErrTask = $p.StandardError.ReadToEndAsync()
  }
  if ($Stdin) { $p.StandardInput.Write($Stdin) }
  if (-not $KeepStdinOpen) { $p.StandardInput.Close() }
  $Script:Spawned.Add($handle)
  return $handle
}

# Code is $null when the program could not start: StartError says why. 124 is a timeout.
function Wait-As {
  param($Handle, [int]$TimeoutSec = 60)
  if ($Handle.StartError) {
    return [pscustomobject]@{ Code = $null; Out = ''; Err = ''; TimedOut = $false; StartError = $Handle.StartError }
  }
  $p = $Handle.Process
  $timedOut = $false
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    $timedOut = $true
    try { $p.Kill($true) } catch { Write-Host "  could not end pid $($p.Id): $($_.Exception.Message)" }
    [void]$p.WaitForExit(5000)
  }
  # A child still holding the pipes must not hang the job.
  $out = if ($Handle.OutTask.Wait(5000)) { $Handle.OutTask.Result } else { '' }
  $err = if ($Handle.ErrTask.Wait(5000)) { $Handle.ErrTask.Result } else { '' }
  $code = if ($timedOut) { 124 } else { $p.ExitCode }
  [void]$Script:Spawned.Remove($Handle)
  return [pscustomobject]@{ Code = $code; Out = $out; Err = $err; TimedOut = $timedOut; StartError = $null }
}

function Invoke-As {
  param($User, [string]$Exe, [string[]]$Arguments = @(), [string]$Cwd, [string]$Stdin = '',
    [hashtable]$ExtraEnv = @{}, [int]$TimeoutSec = 60)
  $h = Start-As -User $User -Exe $Exe -Arguments $Arguments -Cwd $Cwd -Stdin $Stdin -ExtraEnv $ExtraEnv
  return Wait-As -Handle $h -TimeoutSec $TimeoutSec
}

# End every process this job started and has not waited for, through its handle.
function Stop-Spawned {
  foreach ($h in @($Script:Spawned)) {
    try { if (-not $h.Process.HasExited) { $h.Process.Kill($true); [void]$h.Process.WaitForExit(5000) } } catch { Write-Host "  stop: $($_.Exception.Message)" }
    [void]$Script:Spawned.Remove($h)
  }
}

# The elevated runner runs a program. Output is printed by the caller.
function Invoke-Admin {
  param([string]$Exe, [string[]]$Arguments = @(), [int]$TimeoutSec = 300)
  $r = Invoke-As -User $null -Exe $Exe -Arguments $Arguments -TimeoutSec $TimeoutSec
  if ($r.StartError) { Fail "$Exe could not start: $($r.StartError)" }
  return $r
}

# A pwsh command as a user. In a file: CreateProcessWithLogonW takes 1024 characters of
# command line, which an -EncodedCommand soon passes.
function Invoke-PwshAs {
  param($User, [string]$Code, [string]$Cwd, [int]$TimeoutSec = 90)
  $Script:SnippetCount++
  $file = "$Script:Work\snippets\s$($Script:SnippetCount).ps1"
  Set-Content -LiteralPath $file -Value $Code -Encoding utf8
  return Invoke-As -User $User -Exe $Script:Pwsh -Cwd $Cwd -TimeoutSec $TimeoutSec -Arguments @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $file)
}

# The installed saiife as a user. Sets nothing: returns Code, Out, Err.
function Invoke-SaiifeAs {
  param($User, [string[]]$Arguments, [string]$Exe = $Script:Hook, [int]$TimeoutSec = 150)
  return Invoke-As -User $User -Exe $Exe -Arguments $Arguments -TimeoutSec $TimeoutSec
}

function Get-DaemonPid {
  $s = Get-CimInstance Win32_Service -Filter "Name='$Script:ServiceName'"
  if ($s) { return [int]$s.ProcessId }
  return 0
}

function Get-ServiceState {
  $s = Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue
  if ($s) { return [string]$s.Status }
  return 'Missing'
}

function Test-PipeExists([string]$Name = $Script:Pipe) {
  return @([System.IO.Directory]::GetFiles('\\.\pipe\')) -contains $Name
}

function Test-DaemonReady { return (Get-ServiceState) -eq 'Running' -and (Test-PipeExists) }

function Wait-DaemonReady([int]$Seconds = 30) {
  Wait-Until $Seconds 'the service and its pipe' { Test-DaemonReady }
}

function Start-Saiifed {
  # After a crash or a squat the service manager may be restarting it at this moment.
  $last = ''
  foreach ($i in 1..10) {
    if (Test-DaemonReady) { return }
    try {
      Start-Service -Name $Script:ServiceName
    } catch {
      $last = $_.Exception.Message
      Start-Sleep -Seconds 2
    }
    if (Test-DaemonReady) { return }
    Start-Sleep -Seconds 1
  }
  Fail "the service did not start: $last; daemon.log: $(Get-DaemonLogTail)"
}

function Stop-Saiifed {
  Stop-Service -Name $Script:ServiceName -Force
  Wait-Until 20 'the service to stop' { (Get-ServiceState) -eq 'Stopped' }
}

function Get-DaemonLogTail {
  if (Test-Path -LiteralPath $Script:DaemonLog) {
    return (Get-Content -LiteralPath $Script:DaemonLog -Tail 30) -join ' | '
  }
  return '(no daemon.log)'
}

# The lines of a file another process may hold open for writing, such as the month file the
# daemon appends to. [IO.File]::ReadLines asks for FileShare.Read, which refuses to coexist
# with that writer (a sharing violation); this one shares read, write and delete, as the
# daemon's own open does (std's default share mode).
function Read-SharedLines([string]$Path) {
  $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
  $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
  try {
    $reader = [System.IO.StreamReader]::new($fs, [System.Text.UTF8Encoding]::new($false))
    try {
      $lines = [System.Collections.Generic.List[string]]::new()
      while ($null -ne ($line = $reader.ReadLine())) { $lines.Add($line) }
      return , $lines.ToArray()
    } finally { $reader.Dispose() }
  } finally { $fs.Dispose() }
}

# Every audit record, month files in order.
function Get-Records {
  if (-not (Test-Path -LiteralPath $Script:AuditDir)) { return @() }
  $files = Get-ChildItem -LiteralPath $Script:AuditDir -Filter '*.jsonl' -File | Sort-Object Name
  $out = foreach ($f in $files) {
    foreach ($line in (Read-SharedLines $f.FullName)) {
      if ($line) { $line | ConvertFrom-Json -Depth 32 }
    }
  }
  return @($out)
}

# Lines and bytes of the audit log: what a squatted restart loop would grow.
function Get-AuditSize {
  if (-not (Test-Path -LiteralPath $Script:AuditDir)) { return '0 files' }
  $files = @(Get-ChildItem -LiteralPath $Script:AuditDir -File)
  $bytes = ($files | Measure-Object -Property Length -Sum).Sum
  return "$($files.Count) files, $bytes bytes"
}

function Get-StartRecords { return @(Get-Records | Where-Object { $_.kind -eq 'daemon' -and $_.event -eq 'start' }) }

function Assert-LastStart([bool]$Want, [string]$What) {
  $last = @(Get-StartRecords)[-1]
  if ($last.previous_clean_stop -ne $Want) { Fail "${What}: previous_clean_stop is $($last.previous_clean_stop), want $Want" }
  Ok "${What}: previous_clean_stop $Want"
}

function Get-GuardRecords { return @(Get-Records | Where-Object { ($_.kind -eq 'guard' -or -not $_.kind) -and $_.decision }) }

# The newest guard record: this agent, this decision, and the identity the daemon read from
# the caller's token. The peer is a different user from the service: the first place
# OpenThreadToken runs against another user's token (W11).
function Assert-LastGuard {
  param([string]$AgentKind, [string]$Decision, [string]$WantInput, $Who = $Script:Agent)
  $r = @(Get-GuardRecords)[-1]
  $json = $r | ConvertTo-Json -Compress -Depth 16
  if ($r.agent -ne $AgentKind -or $r.decision -ne $Decision) { Fail "newest guard record is not $AgentKind/${Decision}: $json" }
  if ($r.sid -ne $Who.Sid) { Fail "newest guard record's sid is '$($r.sid)', want $($Who.Name)'s $($Who.Sid): $json" }
  if ($r.mode -ne 'locked') { Fail "newest guard record's mode is '$($r.mode)': $json" }
  if ($r.uid -eq 0) { Fail "a plain user's record has uid 0: $json" }
  if (-not ($r.peer.pid -gt 0)) { Fail "newest guard record has no peer pid: $json" }
  if ($WantInput -and $r.input -ne $WantInput) { Fail "newest guard record's input is '$($r.input)', want '$WantInput'" }
  Ok "audit record: $AgentKind $Decision by $($Who.Name) (sid $($r.sid), uid $($r.uid), peer pid $($r.peer.pid))"
}

# A recorded hook payload with its cwd in the agent's project dir.
function Get-Payload {
  param([string]$Fixture, [scriptblock]$Change, $Who = $Script:Agent)
  $p = Get-Content -LiteralPath "$Script:Fixtures\$Fixture" -Raw | ConvertFrom-Json -Depth 32
  $p.cwd = $Who.Project
  if ($Change) { & $Change $p }
  return ($p | ConvertTo-Json -Compress -Depth 32)
}

$Script:HookCode = $null
$Script:HookErr = ''

# The managed hook as a user, in its project dir, the payload on stdin as from its agent.
function Invoke-Hook {
  param([string]$AgentKind, [string]$Payload, $Who = $Script:Agent, [string]$Exe = $Script:Hook,
    [hashtable]$ExtraEnv = @{}, [string]$Cwd)
  $r = Invoke-As -User $Who -Exe $Exe -Cwd $Cwd -Stdin $Payload -ExtraEnv $ExtraEnv -TimeoutSec 30 -Arguments @(
    'check', '--managed', '--hook-exit', '--agent', $AgentKind)
  $Script:HookCode = $r.Code
  $Script:HookErr = if ($r.StartError) { "could not start: $($r.StartError)" } else { $r.Err.Trim() }
}

function Assert-Hook {
  param([int]$Want, [string]$Text, [string]$What, [string]$AgentKind, [string]$Payload, $Who = $Script:Agent)
  Invoke-Hook -AgentKind $AgentKind -Payload $Payload -Who $Who
  if ($Script:HookCode -ne $Want) { Fail "${What}: exit $($Script:HookCode), want $Want; stderr: $($Script:HookErr); daemon.log: $(Get-DaemonLogTail)" }
  if ($Text -and $Script:HookErr -notlike "*$Text*") { Fail "${What}: stderr lacks '$Text': $($Script:HookErr)" }
  Ok "${What}: exit $($Script:HookCode) ($($Script:HookErr))"
}

# A pwsh attempt as the agent: it must fail, with a permission error.
function Assert-Denied {
  param([string]$What, [string]$Code, $Who = $Script:Agent)
  $body = "`$ErrorActionPreference = 'Stop'; try { $Code; 'SUCCEEDED'; exit 0 } catch { `"`$(`$_.Exception.GetType().Name): `$(`$_.Exception.Message)`"; exit 1 }"
  $r = Invoke-PwshAs -User $Who -Code $body
  $text = "$($r.Out)$($r.Err)".Trim()
  if ($r.Code -eq 0) { Fail "$What succeeded as $($Who.Name): $text" }
  if ($text -notmatch 'denied|UnauthorizedAccess|Cannot open|not authorized|PermissionDenied') {
    Fail "$What failed without a permission error (exit $($r.Code)): $text"
  }
  Ok "${What}: $text"
}

# A program as the agent: it must fail, with a permission error in its output.
function Assert-ProgramDenied {
  param([string]$What, [string]$Exe, [string[]]$Arguments, $Who = $Script:Agent)
  $r = Invoke-As -User $Who -Exe $Exe -Arguments $Arguments
  $text = "$($r.Out)$($r.Err)".Trim()
  if ($r.Code -eq 0) { Fail "$What succeeded as $($Who.Name): $text" }
  if ($text -notmatch 'denied|FAILED 5') { Fail "$What failed without a permission error (exit $($r.Code)): $text" }
  Ok "${What}: $text"
}

function Get-Sha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

function New-RandomPassword {
  $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(24)
  # The suffix meets any complexity policy. Never printed.
  return ConvertTo-SecureString -String ([Convert]::ToBase64String($bytes) + 'aA1!') -AsPlainText -Force
}

function New-CiUser([string]$Name) {
  $password = New-RandomPassword
  New-LocalUser -Name $Name -Password $password -PasswordNeverExpires -AccountNeverExpires `
    -FullName "saiife CI $Name" -Description 'throwaway account of the locked-windows job' | Out-Null
  # BUILTIN\Users, by SID, as names are localized. It may be there already; the token is
  # read below.
  Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $Name -ErrorAction SilentlyContinue
  $sid = ([System.Security.Principal.NTAccount]::new($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
  $user = [pscustomobject]@{ Name = $Name; Password = $password; Sid = $sid; Home = $null; Project = $null }
  # The first logon makes the profile.
  $r = Invoke-As -User $user -Exe "$env:SystemRoot\System32\whoami.exe" -Arguments @('/all') -Cwd $Script:Work
  if ($r.StartError -or $r.Code -ne 0) { Fail "first logon of ${Name}: $($r.StartError) exit $($r.Code) $($r.Err)" }
  Write-Host $r.Out
  if ($r.Out -match 'S-1-5-32-544') { Fail "$Name holds Administrators: $($r.Out)" }
  if ($r.Out -notmatch 'S-1-5-32-545') { Fail "$Name does not hold Users: $($r.Out)" }
  $profile_row = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
  if (-not $profile_row) { Fail "no profile for $Name after its first logon" }
  $user.Home = $profile_row.LocalPath
  $user.Project = "$($user.Home)\project"
  # Created by the account, so it owns it.
  $r = Invoke-PwshAs -User $user -Cwd $user.Home -Code "New-Item -ItemType Directory -Path '$($user.Project)' | Out-Null"
  if ($r.Code -ne 0) { Fail "${Name}: project dir: $($r.Out)$($r.Err)" }
  $owner = (Get-Acl -LiteralPath $user.Project).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne $sid) { Fail "$($user.Project) is owned by $owner, want $sid" }
  Ok "user $Name (sid $sid, Users, not an admin, project $($user.Project), owned by it)"
  return $user
}

# A dir with an exact descriptor, whatever C:\ hands down.
function New-CiDir([string]$Path, [string]$Sddl) {
  New-Item -ItemType Directory -Force -Path $Path | Out-Null
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetSecurityDescriptorSddlForm($Sddl)
  Set-Acl -LiteralPath $Path -AclObject $acl
}

# `cl` from the Visual Studio on the runner, through a cmd that has run vcvars64.
function Invoke-Msvc([string]$CommandLine, [string]$Cwd) {
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $vs = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
  if (-not $vs) { Fail 'no Visual Studio with the C++ tools on this runner' }
  $bat = "$Script:Work\native\msvc-$(Get-Random).cmd"
  Set-Content -LiteralPath $bat -Encoding ascii -Value @(
    '@echo off',
    "call `"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul || exit /b 99",
    "cd /d `"$Cwd`" || exit /b 98",
    $CommandLine
  )
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\cmd.exe" -Arguments @('/c', $bat)
  Remove-Item -LiteralPath $bat
  return $r
}

# The probes. plant.c and measure.c are copied first, so objects stay out of the checkout.
function Build-Native {
  $n = "$Script:Work\native"
  if (Test-Path -LiteralPath "$n\measure.exe") { return }
  Copy-Item -LiteralPath "$Script:Here\plant.c", "$Script:Here\measure.c" -Destination $n
  $builds = @(
    'cl /nologo /W3 /MT /O1 /LD plant.c /Fe:saiife-plant-probe.dll /Fo:plant-dll.obj',
    'cl /nologo /W3 /MT /O1 /DCONTROL plant.c /Fe:control.exe /Fo:control.obj /link saiife-plant-probe.lib',
    'cl /nologo /W3 /MT /O1 /DCONTROL plant.c /Fe:control-flagged.exe /Fo:control-flagged.obj /link saiife-plant-probe.lib /DEPENDENTLOADFLAG:0x800',
    'cl /nologo /W3 /MT /O1 /DFAKE_HOOK plant.c /Fe:fake-hook.exe /Fo:fake-hook.obj',
    'cl /nologo /W3 /MT /O1 measure.c /Fe:measure.exe /Fo:measure.obj'
  )
  foreach ($b in $builds) {
    $r = Invoke-Msvc $b $n
    if ($r.Code -ne 0) { Fail "${b}: exit $($r.Code): $($r.Out) $($r.Err)" }
  }
  Ok 'built plant.c (DLL, control, flagged control, fake hook) and measure.c'
}

# `dumpbin`'s names of the DLLs a PE imports.
function Get-PeImports([string]$Path) {
  $r = Invoke-Msvc "dumpbin /nologo /dependents `"$Path`"" $Script:Work
  if ($r.Code -ne 0) { Fail "dumpbin /dependents ${Path}: $($r.Out) $($r.Err)" }
  return @(($r.Out -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[\w.-]+\.dll$' })
}

# ---------------------------------------------------- reading descriptors

$Script:SidAlias = @{
  SY = 'S-1-5-18'; BA = 'S-1-5-32-544'; BU = 'S-1-5-32-545'; AU = 'S-1-5-11'; NU = 'S-1-5-2'
  IU = 'S-1-5-4'; SU = 'S-1-5-6'; WD = 'S-1-1-0'; CO = 'S-1-3-0'
  TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
}
$Script:RightAlias = @{ FA = 0x1f01ff; FR = 0x120089; FW = 0x120116; FX = 0x1200a0; GA = 0x10000000; GR = 0x80000000L; GW = 0x40000000; GX = 0x20000000 }
# GENERIC_ALL, GENERIC_WRITE, WRITE_DAC, WRITE_OWNER, DELETE, FILE_DELETE_CHILD, FILE_WRITE_DATA,
# FILE_APPEND_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES: saiife_win's WRITE_LIKE.
$Script:WriteLike = 0x10000000 -bor 0x40000000 -bor 0x40000 -bor 0x80000 -bor 0x10000 -bor 0x40 -bor 0x2 -bor 0x4 -bor 0x10 -bor 0x100

function ConvertTo-Sid([string]$Text) {
  if ($Script:SidAlias.ContainsKey($Text)) { return $Script:SidAlias[$Text] }
  if ($Text -eq 'LA') {
    # This machine's built-in Administrator. Windows prints it by alias.
    $me = (Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' } | Select-Object -First 1).SID.Value
    return $me
  }
  return $Text
}

# An SDDL's owner, group, protected flag and ACEs. It does not need to read every form:
# anything it cannot read fails the check that asked.
function ConvertFrom-Sddl([string]$Sddl) {
  $m = [regex]::Match($Sddl, '^(?:O:(?<o>S-[\d-]+|[A-Z]{2}))?(?:G:(?<g>S-[\d-]+|[A-Z]{2}))?D:(?<f>[A-Z]*)(?<a>(?:\([^)]*\))*)(?:S:.*)?$')
  if (-not $m.Success) { Fail "cannot read SDDL: $Sddl" }
  $aces = foreach ($a in [regex]::Matches($m.Groups['a'].Value, '\(([^)]*)\)')) {
    $f = $a.Groups[1].Value -split ';'
    $right = $f[2]
    $mask = if ($Script:RightAlias.ContainsKey($right)) { [long]$Script:RightAlias[$right] }
    elseif ($right -like '0x*') { [Convert]::ToInt64($right.Substring(2), 16) }
    else { Fail "unknown right '$right' in $Sddl" }
    $flags = @(for ($i = 0; $i + 1 -lt $f[1].Length; $i += 2) { $f[1].Substring($i, 2) })
    [pscustomobject]@{ Type = $f[0]; Flags = @($flags | Sort-Object); Mask = $mask; Sid = (ConvertTo-Sid $f[5]) }
  }
  return [pscustomobject]@{
    Owner = (ConvertTo-Sid $m.Groups['o'].Value)
    Group = (ConvertTo-Sid $m.Groups['g'].Value)
    Protected = $m.Groups['f'].Value.Contains('P')
    Aces = @($aces)
  }
}

# The W14 row of a path, with <S> and <A> filled in; $null for a path with no row. From the
# plan's table, by hand: the debug command `saiife __expected-sddl` the brief names does not
# exist, and doctor's files.acl (phase_doctor) reads the same paths through winacl::expected.
function Get-W14Row([string]$Path) {
  $rx = '0x1200a9'
  $full = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
  $l = $Path.ToLowerInvariant()
  $root = $Script:Root.ToLowerInvariant()
  $row = $null
  if ($l -eq $root) { $row = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;$rx;;;BU)(A;;$rx;;;<S>)" }
  elseif ($l -eq "$root\bin" -or $l -eq "$root\bin\saiife.exe" -or $l -eq "$root\etc" -or $l.StartsWith("$root\etc\")) {
    $row = "O:BAG:SYD:PAI$full(A;OICI;$rx;;;BU)(A;OICI;$rx;;;<S>)"
  }
  elseif ($l -eq "$root\state\keys\vault.key") { $row = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;<S>)" }
  elseif ($l -eq "$root\state" -or $l.StartsWith("$root\state\")) { $row = "O:BAG:SYD:PAI$full(A;OICI;FA;;;<S>)" }
  elseif ($l -eq "$root\log") { $row = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;$rx;;;<S>)(A;;$rx;;;BU)" }
  elseif ($l -eq "$root\log\audit" -or $l.StartsWith("$root\log\audit\")) { $row = "O:BAG:SYD:PAI$full(A;OICI;FA;;;<S>)(A;OICI;$rx;;;<A>)" }
  elseif ($l -eq "$root\log\daemon" -or $l.StartsWith("$root\log\daemon\")) { $row = "O:BAG:SYD:PAI$full(A;OICI;FA;;;<S>)(A;OICI;FR;;;<A>)" }
  elseif ($l -in 'c:\program files\claudecode', 'c:\program files\claudecode\managed-settings.d',
    'c:\program files\claudecode\managed-settings.d\50-saiife.json',
    'c:\program files\claudecode\managed-settings.d\60-saiife-mcp.json',
    'c:\programdata\openai', 'c:\programdata\openai\codex', 'c:\programdata\openai\codex\requirements.toml',
    'c:\programdata\gemini-cli', 'c:\programdata\gemini-cli\settings.json') {
    $row = "O:BAG:SYD:PAI$full(A;OICI;$rx;;;BU)"
  }
  if ($row) { return $row.Replace('<S>', $Script:ServiceSid).Replace('<A>', $Script:AuditSid) }
  return $null
}

function Get-Grants($Sd) { return @($Sd.Aces | ForEach-Object { "$($_.Type) $($_.Sid) $('0x{0:x}' -f $_.Mask)" } | Sort-Object) }

# Mirrors winacl::actual_ok and actual_file_ok, plus the ruling for what an admin puts below
# `etc`. Returns "" or what is wrong.
function Test-Row([string]$Path, [string]$Row, [string]$ActualText) {
  $file = Test-Path -LiteralPath $Path -PathType Leaf
  $want = ConvertFrom-Sddl $Row
  $got = ConvertFrom-Sddl $ActualText
  if ($file) { foreach ($a in $want.Aces) { $a.Flags = @($a.Flags | Where-Object { $_ -notin 'OI', 'CI' }) } }
  $serviceWrites = @($want.Aces | Where-Object { $_.Sid -eq $Script:ServiceSid -and ($_.Mask -band $Script:WriteLike) -ne 0 }).Count -gt 0
  if (-not $got.Protected -and $want.Protected -and -not $serviceWrites) { return "not protected (no P): $ActualText" }
  if ($serviceWrites) {
    if ($got.Owner -notin 'S-1-5-18', 'S-1-5-32-544', $Script:SidAlias['TI'], $Script:ServiceSid) {
      return "owner $($got.Owner) on a row the service may write: $ActualText"
    }
    if (@($got.Aces | Where-Object { $_.Flags -contains 'IO' }).Count) { return "an inherit-only ACE: $ActualText" }
    if (((Get-Grants $got) -join ',') -ne ((Get-Grants $want) -join ',')) { return "grants differ: $ActualText, want $Row" }
    return ''
  }
  # Each ACE exact, but as a set: Get-Acl's .Sddl comes from .NET's CommonAcl, which sorts
  # explicit ACEs of one kind by SID (S-1-5-32-545 before S-1-5-80-...), so the order on disk
  # cannot be seen here (CI round 8: `log` read BU before the service, the row says the
  # reverse, and doctor's files.acl, which reads the raw descriptor in order, passed). Every
  # row is allow-only, so a deny ACE still differs. doctor checks the order.
  $aceSet = { param($sd) (@($sd.Aces | ForEach-Object { "$($_.Type) $($_.Flags -join '') $($_.Sid) $($_.Mask)" } | Sort-Object) -join ',') }
  $exact = $got.Owner -eq $want.Owner -and $got.Group -eq $want.Group -and $got.Protected -eq $want.Protected -and
  ((& $aceSet $got) -ceq (& $aceSet $want))
  if ($exact) { return '' }
  # Below `etc`, what an admin added may inherit and be owned by Administrators (ruling).
  if ($Path.ToLowerInvariant().StartsWith("$($Script:EtcDir.ToLowerInvariant())\")) {
    $writers = @($got.Aces | Where-Object { $_.Type -eq 'A' -and ($_.Mask -band $Script:WriteLike) -ne 0 -and $_.Sid -notin 'S-1-5-18', 'S-1-5-32-544' })
    if ($writers.Count -eq 0 -and $got.Owner -in 'S-1-5-18', 'S-1-5-32-544') {
      Read-Back 'etc-entry-not-exact' "$Path $ActualText"
      return ''
    }
  }
  return "reads $ActualText, want $Row"
}

# The keys and the vault stay on the runner: only descriptors are printed from there.
function Save-FailureLogs {
  $l = $Script:Logs
  try {
    foreach ($spec in @(
        @{ File = 'sc-qc.txt'; Args = @('qc', $Script:ServiceName) },
        @{ File = 'sc-sdshow.txt'; Args = @('sdshow', $Script:ServiceName) },
        @{ File = 'sc-qfailure.txt'; Args = @('qfailure', $Script:ServiceName) })) {
      $r = Invoke-As -User $null -Exe "$env:SystemRoot\System32\sc.exe" -Arguments $spec.Args
      Set-Content -LiteralPath "$l\$($spec.File)" -Value "exit $($r.Code)`n$($r.Out)$($r.Err)"
    }
    foreach ($dir in $Script:LogDir, $Script:EtcDir) {
      if (Test-Path -LiteralPath $dir) { Copy-Item -LiteralPath $dir -Destination "$l\$(Split-Path -Leaf $dir)" -Recurse -Force -ErrorAction Continue }
    }
    if (Test-Path -LiteralPath "$Script:Work\out") { Copy-Item -LiteralPath "$Script:Work\out" -Destination "$l\work-out" -Recurse -Force -ErrorAction Continue }
    Get-WinEvent -LogName System -MaxEvents 60 -ErrorAction SilentlyContinue |
      Where-Object { $_.ProviderName -eq 'Service Control Manager' } |
      ForEach-Object { "$($_.TimeCreated) $($_.Id) $($_.Message)" } | Set-Content -LiteralPath "$l\scm-events.txt"
    Write-Host '-- daemon.log (last lines)'
    Write-Host (Get-DaemonLogTail)
  } catch {
    Write-Host "collecting logs: $($_.Exception.Message)"
  }
}

# ------------------------------------------------- back to a known state

function Restore-UserGroups {
  foreach ($sid in 'S-1-5-32-544', 'S-1-5-32-551') {
    if ($Script:Agent) { Remove-LocalGroupMember -SID $sid -Member $Script:AgentName -ErrorAction SilentlyContinue }
  }
}

function Restore-Config {
  if ($Script:ConfigBackup -and (Test-Path -LiteralPath $Script:ConfigPath)) {
    # In place, so the file keeps its descriptor.
    [System.IO.File]::WriteAllText($Script:ConfigPath, $Script:ConfigBackup)
    $Script:ConfigBackup = $null
    if ((Get-ServiceState) -eq 'Running') { [void](Invoke-As -User $null -Exe "$env:SystemRoot\System32\sc.exe" -Arguments @('control', $Script:ServiceName, 'paramchange')) }
  }
}

function Restore-Lockdown {
  if ($Script:LockdownOn) {
    [void](Invoke-As -User $null -Exe $Script:Hook -Arguments @('lockdown', 'off'))
    $Script:LockdownOn = $false
  }
}

function Restore-Baseline {
  Stop-Spawned
  Restore-UserGroups
  if ((Get-ServiceState) -ne 'Missing') {
    Start-Saiifed
    Restore-Lockdown
    Restore-Config
  }
}

# ------------------------------------------------------------ the phases

function prepare_host {
  Write-Host "$([System.Environment]::OSVersion.VersionString), pwsh $($PSVersionTable.PSVersion)"
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\whoami.exe" -Arguments @('/all')
  Read-Back 'runner-token' ($r.Out -replace '\s+', ' ')
  if ((Get-Service seclogon).Status -ne 'Running') {
    Set-Service -Name seclogon -StartupType Manual
    Start-Service -Name seclogon
    Ok 'started the Secondary Logon service'
  }
  # A logon the daemon or the CLI made would show here: phase_approvals reads them.
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\auditpol.exe" -Arguments @('/set', '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')
  if ($r.Code -ne 0) { Fail "auditpol: $($r.Out)$($r.Err)" }

  New-CiDir $Script:Work 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
  foreach ($d in 'bin', 'native', 'snippets', 'scripts') { New-Item -ItemType Directory -Force -Path "$Script:Work\$d" | Out-Null }
  New-CiDir "$Script:Work\markers" 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)'
  New-CiDir "$Script:Work\out" 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)'
  Copy-Item -LiteralPath $Script:Bin -Destination $Script:CopyBin
  Copy-Item -LiteralPath "$Script:Here\squat-pipe.ps1" -Destination "$Script:Work\scripts\squat-pipe.ps1"

  $Script:Agent = New-CiUser $Script:AgentName
  $Script:Approver = New-CiUser $Script:ApproverName
}

# Review Focus 1: a dir already there, made by someone else. Install exits 2 naming it and
# writes nothing. W26 first, as the agent is at hand.
function Assert-InstallRefused([string]$What, [string]$Names) {
  $r = Invoke-Admin -Exe $Script:Bin -Arguments @('system', 'install', '--config', $Script:CiConfig,
    '--agents', 'claude,codex,gemini', '--approvers', $Script:ApproverName, '--non-interactive', '--allow-test-build')
  $text = "$($r.Out)$($r.Err)".Trim()
  Write-Host $text
  if ($r.Code -ne 2) { Fail "${What}: install exited $($r.Code), want 2: $text" }
  if ($text -notlike "*$Names*") { Fail "${What}: the refusal does not name ${Names}: $text" }
  if ((Get-ServiceState) -ne 'Missing') { Fail "${What}: install left a service" }
  foreach ($p in "$Script:BinDir", $Script:EtcDir, $Script:StateDir, $Script:ClaudeManaged) {
    if (Test-Path -LiteralPath $p) { Fail "${What}: install wrote $p" }
  }
  Ok "${What}: exit 2, names $Names, nothing written"
}

function Remove-Squat([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  if (-not $item) { return }
  if ($item.LinkType) { [System.IO.Directory]::Delete($Path) } else { Remove-Item -LiteralPath $Path -Recurse -Force }
}

function phase_squat {
  $r = Invoke-As -User $Script:Agent -Exe $Script:CopyBin -Arguments @('system', 'install', '--non-interactive', '--allow-test-build')
  if ($r.Code -ne 2 -or "$($r.Out)$($r.Err)" -notlike '*Run as administrator*') { Fail "W26: install from a plain token exited $($r.Code): $($r.Out)$($r.Err)" }
  Ok 'W26: a plain token is told to elevate (exit 2)'

  foreach ($spec in @(
      @{ Dir = $Script:Root; Remove = $Script:Root },
      @{ Dir = 'C:\ProgramData\gemini-cli'; Remove = 'C:\ProgramData\gemini-cli' },
      @{ Dir = 'C:\ProgramData\OpenAI\Codex'; Remove = 'C:\ProgramData\OpenAI' })) {
    $r = Invoke-PwshAs -User $Script:Agent -Code "New-Item -ItemType Directory -Path '$($spec.Dir)' | Out-Null"
    if ($r.Code -ne 0) { Fail "the agent could not create $($spec.Dir): $($r.Out)$($r.Err)" }
    $owner = (Get-Acl -LiteralPath $spec.Dir).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $Script:Agent.Sid) { Fail "$($spec.Dir) is owned by $owner, not the agent" }
    try {
      Read-Back "squatted-dir $($spec.Dir)" (Get-Acl -LiteralPath $spec.Dir).Sddl
      # The refusal may name the leaf or its parent; both hold this name.
      Assert-InstallRefused "agent-made $($spec.Dir)" (Split-Path -Leaf $spec.Remove)
    } finally {
      Remove-Squat $spec.Remove
    }
  }

  # A junction the agent placed, to a dir it owns.
  $target = "$($Script:Agent.Home)\junction-target"
  $code = "New-Item -ItemType Directory -Path '$target' | Out-Null; New-Item -ItemType Junction -Path '$Script:Root' -Target '$target' | Out-Null"
  $r = Invoke-PwshAs -User $Script:Agent -Code $code
  if ($r.Code -ne 0) { Fail "the agent could not place a junction: $($r.Out)$($r.Err)" }
  try {
    Assert-InstallRefused 'a junction at C:\ProgramData\saiife' 'saiife'
    if (@(Get-ChildItem -LiteralPath $target -Force).Count -ne 0) { Fail 'install wrote through the junction' }
    Ok 'nothing written through the junction'
  } finally {
    Remove-Squat $Script:Root
  }

  # The T7 review's ruling: an admin-made gemini-cli with stock inherited ACEs lets Users
  # plant settings.json, so W14 applies to the agents' own leaf dirs too. An admin must
  # correct the dir first. Fails until that round lands on the branch.
  New-Item -ItemType Directory -Path 'C:\ProgramData\gemini-cli' | Out-Null
  Read-Back 'stock-leaf-dir C:\ProgramData\gemini-cli' (Get-Acl -LiteralPath 'C:\ProgramData\gemini-cli').Sddl
  try {
    Assert-InstallRefused 'an admin-made gemini-cli that Users can add to' 'gemini-cli'
  } finally {
    Remove-Squat 'C:\ProgramData\gemini-cli'
  }
}

function Start-Squatter {
  param($Who, [string]$PipeName, [string]$Tag)
  $log = "$Script:Work\out\squat-$Tag.log"
  $ready = "$Script:Work\out\squat-$Tag.ready"
  Remove-Item -LiteralPath $log, $ready -Force -ErrorAction SilentlyContinue
  $h = Start-As -User $Who -Exe $Script:Pwsh -KeepStdinOpen -ExtraEnv @{ SAIIFE_LOCKED_CI = '1' } -Arguments @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "$Script:Work\scripts\squat-pipe.ps1",
    '-Name', $PipeName, '-Log', $log, '-Ready', $ready)
  if ($h.StartError) { Fail "squatter ($($Who.Name)) could not start: $($h.StartError)" }
  $end = (Get-Date).AddSeconds(45)
  while (-not (Test-Path -LiteralPath $ready)) {
    if ($h.Process.HasExited -or (Get-Date) -gt $end) {
      $r = Wait-As -Handle $h -TimeoutSec 1
      Fail "squatter ($($Who.Name)) did not start on ${PipeName}: exit $($r.Code): $($r.Out) $($r.Err)"
    }
    Start-Sleep -Milliseconds 300
  }
  return [pscustomobject]@{ Handle = $h; Log = $log; Who = $Who; PipeName = $PipeName }
}

# The job ends a squatter through its process handle.
function Stop-Squatter($Squatter) {
  try { $Squatter.Handle.Process.Kill($true) } catch { Write-Host "  squatter: $($_.Exception.Message)" }
  [void](Wait-As -Handle $Squatter.Handle -TimeoutSec 10)
}

function Assert-SquatterGotNothing($Squatter, [switch]$RequireConnection) {
  if ($RequireConnection) {
    # A client that never connected never met the owner check, so a quiet log proves nothing.
    Wait-Until 10 "a client's connection to the fake pipe $($Squatter.PipeName)" { Test-Path -LiteralPath $Squatter.Log }
  }
  $lines = if (Test-Path -LiteralPath $Squatter.Log) { @(Get-Content -LiteralPath $Squatter.Log) } else { @() }
  Write-Host "  squatter log: $($lines -join ' | ')"
  foreach ($l in $lines) {
    if ($l -match 'bytes=(\d+)' -and [int]$Matches[1] -gt 0) { Fail "a client sent $($Matches[1]) bytes to the fake pipe $($Squatter.PipeName)" }
  }
  Ok "the fake pipe got no bytes ($($lines.Count) log lines)"
}

function Get-DoctorSummary($Who, [string]$Exe) {
  $r = Invoke-As -User $Who -Exe $Exe -Arguments @('doctor', '--json') -TimeoutSec 120
  if ($r.StartError) { Fail "doctor could not start: $($r.StartError)" }
  try { $j = $r.Out | ConvertFrom-Json -Depth 32 } catch { Fail "doctor's output is not JSON (exit $($r.Code)): $($r.Out) $($r.Err)" }
  return [pscustomobject]@{ Code = $r.Code; Json = $j; Lines = @($j.checks | ForEach-Object { "$($_.id)=$($_.status)" } | Sort-Object) }
}

# A personal broker needs no locked host, and a locked host refuses one, so this runs before
# install: T11 and the integration could test only check_owner, with no second account.
function phase_personal_squat {
  $pipe = "\\.\pipe\saiife-user-$($Script:Agent.Sid)"
  $short = "saiife-user-$($Script:Agent.Sid)"

  $before = Get-DoctorSummary $Script:Agent $Script:CopyBin
  Read-Back 'doctor-personal-before' ($before.Lines -join ' ')

  # Control: with no squatter the broker starts as the agent and its client gets an answer.
  $broker = Start-As -User $Script:Agent -Exe $Script:CopyBin -Arguments @('daemon', '--user') -KeepStdinOpen
  if ($broker.StartError) { Fail "daemon --user could not start: $($broker.StartError)" }
  try {
    Wait-Until 30 'the personal pipe' {
      if ($broker.Process.HasExited) { Fail "daemon --user exited $($broker.Process.ExitCode) with no squatter: $($broker.ErrTask.Result)" }
      Test-PipeExists $pipe
    }
    $r = Invoke-SaiifeAs -User $Script:Agent -Exe $Script:CopyBin -Arguments @('secret', 'list')
    # Printed, not required: the vault key's Credential Manager entry is unverified in this
    # kind of logon, and the squat below does not depend on it.
    Read-Back 'personal-client-control' "secret list against the agent's own broker: exit $($r.Code): $($r.Out.Trim()) $($r.Err.Trim())"
    try { Read-Back 'personal-pipe' (Get-Acl -LiteralPath $pipe).Sddl } catch { Read-Back 'personal-pipe' "could not read: $($_.Exception.Message)" }
    # The second account cannot reach it.
    $r = Invoke-SaiifeAs -User $Script:Approver -Exe $Script:CopyBin -Arguments @('secret', 'list')
    Write-Host "  approver's own client, against its own absent broker: exit $($r.Code) $($r.Err)"
    $code = "[System.IO.File]::Open('$pipe', 'Open', 'ReadWrite', 'None').Dispose()"
    Assert-Denied "approver opening the agent's personal pipe" $code $Script:Approver
  } finally {
    try { $broker.Process.Kill($true) } catch { Write-Host "  broker: $($_.Exception.Message)" }
    [void](Wait-As -Handle $broker -TimeoutSec 10)
  }
  Wait-Until 15 'the personal pipe to go' { -not (Test-PipeExists $pipe) }

  # The squat: a second account takes the name while the broker is down.
  $s = Start-Squatter -Who $Script:Approver -PipeName $short -Tag 'personal'
  try {
    $r = Invoke-As -User $Script:Agent -Exe $Script:CopyBin -Arguments @('daemon', '--user') -TimeoutSec 30
    Write-Host "  daemon --user under the squat: exit $($r.Code): $($r.Err)"
    if ($r.TimedOut) { Fail 'daemon --user kept running under a squatter' }
    if ($r.Code -eq 0) { Fail 'daemon --user exited 0 under a squatter' }
    if ("$($r.Out)$($r.Err)" -notlike '*exists and is not ours*') { Fail "daemon --user did not name the squat: $($r.Err)" }
    Ok 'the broker refuses to start on a name someone else holds'

    $r = Invoke-SaiifeAs -User $Script:Agent -Exe $Script:CopyBin -Arguments @('secret', 'list')
    Write-Host "  secret list under the squat: exit $($r.Code): $($r.Err)"
    if ($r.Code -eq 0) { Fail "the agent's client took a squatter's pipe for its broker: $($r.Out)" }
    Assert-SquatterGotNothing $s -RequireConnection
    Ok "the client refuses another user's pipe before sending a byte"

    $during = Get-DoctorSummary $Script:Agent $Script:CopyBin
    Read-Back 'doctor-personal-during-squat' ($during.Lines -join ' ')
  } finally {
    Stop-Squatter $s
  }
  $after = Get-DoctorSummary $Script:Agent $Script:CopyBin
  Read-Back 'doctor-personal-after' ($after.Lines -join ' ')
  if (($before.Lines -join ' ') -cne ($after.Lines -join ' ')) { Fail "doctor changed after the squat ended: $($before.Lines -join ' ') -> $($after.Lines -join ' ')" }
  Ok 'doctor reads the same before and after'
}

function Invoke-Install {
  param([int[]]$Allowed, [string]$Config = $Script:CiConfig)
  $r = Invoke-Admin -Exe $Script:Bin -Arguments @('system', 'install', '--config', $Config,
    '--agents', 'claude,codex,gemini', '--approvers', $Script:ApproverName, '--non-interactive', '--allow-test-build')
  $Script:InstallOut = "$($r.Out)$($r.Err)"
  Write-Host $Script:InstallOut
  if ($r.Code -notin $Allowed) { Fail "system install exited $($r.Code), want one of: $($Allowed -join ', ')" }
  Ok "system install exit $($r.Code)"
}

function phase_install {
  Invoke-Install -Allowed 0
  if ($Script:InstallOut -notlike '*test build*') { Fail 'install did not warn about the test build' }
  if ($Script:InstallOut -notlike '*not Authenticode-signed*') { Fail 'install did not warn that the build is unsigned' }
  Wait-DaemonReady
  Ok "saiifed running (pid $(Get-DaemonPid))"
  $Script:ServiceSid = ([System.Security.Principal.NTAccount]::new('NT SERVICE', $Script:ServiceName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
  $Script:AuditSid = (Get-LocalGroup -Name $Script:AuditGroup).SID.Value
  $managed = Get-Content -LiteralPath $Script:ClaudeManaged -Raw
  if ($managed -notlike "*$Script:HookForward check --managed --hook-exit --agent claude*") { Fail "the managed hook is not the W9 command: $managed" }
  Ok 'the managed hook command is W9''s'
}

function phase_acls {
  # <S> is pure in the code; here it meets Windows.
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\sc.exe" -Arguments @('showsid', $Script:ServiceName)
  Write-Host $r.Out
  if ($r.Out -notmatch [regex]::Escape($Script:ServiceSid)) { Fail "sc.exe showsid does not give $($Script:ServiceSid): $($r.Out)" }
  Ok "service SID $($Script:ServiceSid)"

  # Every path, named or below a row. Real descriptors are printed for T8 whatever they say.
  $paths = [System.Collections.Generic.List[string]]::new()
  foreach ($p in $Script:Root, 'C:\Program Files\ClaudeCode', $Script:ClaudeDir, $Script:ClaudeManaged, $Script:ClaudeMcp,
    'C:\ProgramData\OpenAI', 'C:\ProgramData\OpenAI\Codex', $Script:CodexReq, 'C:\ProgramData\gemini-cli', $Script:GeminiSettings) {
    if (-not (Test-Path -LiteralPath $p)) { Fail "$p is missing after install" }
    $paths.Add($p)
  }
  foreach ($item in Get-ChildItem -LiteralPath $Script:Root -Recurse -Force) { $paths.Add($item.FullName) }
  $bad = [System.Collections.Generic.List[string]]::new()
  foreach ($p in $paths) {
    $text = (Get-Acl -LiteralPath $p).Sddl
    Read-Back 'descriptor' "$p $text"
    $row = Get-W14Row $p
    if (-not $row) { Write-Host "  no row: $p"; continue }
    # One descriptor this reader cannot parse must not hide the others.
    try { $wrong = Test-Row $p $row $text } catch { $wrong = $_.Exception.Message }
    if ($wrong) { $bad.Add("${p}: $wrong") }
  }
  foreach ($p in 'C:\', 'C:\ProgramData', 'C:\Program Files') { Read-Back 'ancestor' "$p $((Get-Acl -LiteralPath $p).Sddl)" }
  try { Read-Back 'pipe' "$Script:Pipe $((Get-Acl -LiteralPath $Script:Pipe).Sddl)" } catch { Read-Back 'pipe' "could not read: $($_.Exception.Message)" }

  # T8: who owns what an elevated admin creates. Servers and clients are said to differ: this
  # runner is a server, so nothing here settles a client. The policy value is printed for that.
  $lsa = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoDefaultAdminOwner' -ErrorAction SilentlyContinue
  Read-Back 'admin-owner-policy' "NoDefaultAdminOwner=$($lsa.NoDefaultAdminOwner) (0 Administrators, 1 the creator; absent uses the edition's default); $((Get-CimInstance Win32_OperatingSystem).Caption) ProductType=$((Get-CimInstance Win32_OperatingSystem).ProductType)"
  foreach ($probe in "$Script:EtcDir\ci-owner-probe.txt", 'C:\ProgramData\ci-owner-probe.txt', "$Script:Work\ci-owner-probe.txt") {
    Set-Content -LiteralPath $probe -Value 'who owns this'
    $acl = Get-Acl -LiteralPath $probe
    Read-Back 'who-owns-a-file-an-admin-creates' "$probe owner=$($acl.Owner) $($acl.Sddl)"
    if ($probe -like "$Script:EtcDir*") {
      $d = Get-DoctorSummary $null $Script:Hook
      $check = @($d.Json.checks | Where-Object { $_.id -eq 'files.acl' })[0]
      Read-Back 'doctor-with-admin-file-below-etc' "files.acl=$($check.status) $($check.detail)"
    }
    Remove-Item -LiteralPath $probe
  }

  # W10.
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\sc.exe" -Arguments @('qc', $Script:ServiceName)
  Read-Back 'sc-qc' ($r.Out -replace '\s+', ' ')
  if ($r.Out -notmatch 'SERVICE_START_NAME\s*:\s*NT SERVICE\\saiifed') { Fail "sc.exe qc: not NT SERVICE\saiifed: $($r.Out)" }
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\sc.exe" -Arguments @('sdshow', $Script:ServiceName)
  $shown = $r.Out.Trim()
  Read-Back 'sc-sdshow' $shown
  $dacl = ($shown -replace 'S:.*$', '')
  # Rights compare as sets: Windows may print the letters in its own order.
  $normal = {
    param($s) @([regex]::Matches($s, '\(A;;([A-Z]+);;;([A-Z]{2})\)') | ForEach-Object {
        $letters = @(for ($i = 0; $i -lt $_.Groups[1].Value.Length; $i += 2) { $_.Groups[1].Value.Substring($i, 2) }) | Sort-Object
        "$($_.Groups[2].Value)=$($letters -join '')"
      } | Sort-Object) -join ' '
  }
  if ((& $normal $dacl) -cne (& $normal $Script:ServiceSddl)) { Fail "sc.exe sdshow: $shown, want $($Script:ServiceSddl)" }
  Ok 'sc.exe sdshow is W10''s, sc.exe qc is the virtual account'
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\sc.exe" -Arguments @('qfailure', $Script:ServiceName)
  Read-Back 'sc-qfailure' ($r.Out -replace '\s+', ' ')

  if ($bad.Count) { Fail "descriptors differ from W14:`n$($bad -join "`n")" }
  Ok "$($paths.Count) paths read; each with a row matches W14"
}

function phase_hooks {
  $allow = Get-Payload 'claude\bash-allow.json'
  # The first record of a different user: the unverified step of W11. If OpenThreadToken is
  # denied to NT SERVICE\saiifed on another user's token, every peer fails closed here.
  Assert-Hook 0 '' 'a different-user client: claude Bash allow' claude $allow
  Assert-LastGuard claude allow 'ls -la'
  if ($Script:Agent.Sid -eq ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value) { Fail 'the agent is the runner' }
  Read-Back 'different-user-client' "the daemon as NT SERVICE\saiifed read $($Script:Agent.Sid) from a client's token"

  Assert-Hook 2 'BLOCKED by' 'claude Bash deny' claude (Get-Payload 'claude\bash-deny.json')
  Assert-LastGuard claude deny 'rm -rf /'
  Assert-Hook 0 '' 'codex Bash allow' codex (Get-Payload 'codex\bash-allow.json')
  Assert-LastGuard codex allow
  Assert-Hook 2 'BLOCKED by' 'codex Bash deny' codex (Get-Payload 'codex\bash-deny.json')
  Assert-LastGuard codex deny
  Assert-Hook 0 '' 'gemini shell allow' gemini (Get-Payload 'gemini\shell-allow.json')
  Assert-LastGuard gemini allow
  Assert-Hook 2 'BLOCKED by' 'gemini shell deny' gemini (Get-Payload 'gemini\shell-deny.json')
  Assert-LastGuard gemini deny
  Assert-Hook 2 'BLOCKED by guard.mcp' 'codex MCP tool of an unlisted server' codex (Get-Payload 'codex\mcp-tool.json')
  $write = Get-Payload 'claude\write.json' { param($p) $p.tool_input.file_path = "$Script:EtcDir\x" }
  Assert-Hook 2 'BLOCKED by core.lock' 'claude Write below etc' claude $write
  if (Test-Path -LiteralPath "$Script:EtcDir\x") { Fail "$Script:EtcDir\x exists" }

  # A third identity, in no scope: its token reaches the daemon too.
  $approverAllow = Get-Payload 'claude\bash-allow.json' $null $Script:Approver
  Invoke-Hook -AgentKind claude -Payload $approverAllow -Who $Script:Approver
  $last = @(Get-GuardRecords)[-1]
  Read-Back 'approver-hook' "exit $($Script:HookCode), stderr '$($Script:HookErr)', newest record sid $($last.sid) decision $($last.decision)"
  # The hook's own spelling, forward slashes, as the managed files run it.
  Invoke-Hook -AgentKind claude -Payload $allow -Exe $Script:HookForward
  if ($Script:HookCode -ne 0) { Fail "the hook by W9's spelling: exit $($Script:HookCode): $($Script:HookErr)" }
  Ok 'the hook by W9''s spelling works'

  $r = Invoke-Admin -Exe $Script:Hook -Arguments @('audit', 'verify')
  Write-Host $r.Out
  if ($r.Code -ne 0) { Fail "saiife audit verify exited $($r.Code): $($r.Err)" }
  Ok 'audit verify (elevated)'
}

function phase_fail_closed {
  $before = @(Get-StartRecords).Count
  Stop-Saiifed
  $cases = @(
    @('claude', 'claude\bash-deny.json'), @('claude', 'claude\bash-allow.json'),
    @('codex', 'codex\bash-deny.json'), @('codex', 'codex\bash-allow.json'),
    @('gemini', 'gemini\shell-deny.json'), @('gemini', 'gemini\shell-allow.json'))
  foreach ($c in $cases) {
    Assert-Hook 2 'fail closed' "service stopped: $($c[1])" $c[0] (Get-Payload $c[1])
  }
  Start-Saiifed
  Wait-Until 30 'the start record' { @(Get-StartRecords).Count -gt $before }
  Assert-LastStart $true 'after Stop-Service and Start-Service'

  $before = @(Get-StartRecords).Count
  $pid_before = Get-DaemonPid
  if (-not $pid_before) { Fail 'no daemon pid' }
  # CI only: the service manager's failure actions bring it back.
  Stop-Process -Id $pid_before -Force
  $started = Get-Date
  Wait-Until 5 "the service manager to restart the daemon after Stop-Process (pid $pid_before)" {
    $now = Get-DaemonPid
    $now -and $now -ne $pid_before
  }
  Ok "restarted in $([int]((Get-Date) - $started).TotalMilliseconds) ms: pid $pid_before -> $(Get-DaemonPid)"
  Wait-Until 30 'the start record after Stop-Process' { @(Get-StartRecords).Count -gt $before -and (Test-DaemonReady) }
  Assert-LastStart $false 'after Stop-Process and the restart'
  Assert-Hook 0 '' 'allow after the restart' claude (Get-Payload 'claude\bash-allow.json')
}

function attack_files {
  foreach ($p in $Script:ClaudeManaged, $Script:ClaudeMcp, $Script:CodexReq, $Script:GeminiSettings, $Script:ConfigPath,
    $Script:InstalledPath, $Script:Hook) {
    $sha = Get-Sha $p
    Assert-Denied "write $p" "[System.IO.File]::AppendAllText('$p', 'x')"
    if ((Get-Sha $p) -ne $sha) { Fail "$p changed" }
  }
  Assert-Denied "read $Script:VaultKey" "[void][System.IO.File]::ReadAllBytes('$Script:VaultKey')"
  Assert-Denied "read $Script:AuditKey" "[void][System.IO.File]::ReadAllBytes('$Script:AuditKey')"
  $forged = "$Script:AuditDir\forged.jsonl"
  Assert-Denied 'write the audit dir' "[System.IO.File]::WriteAllText('$forged', 'x')"
  if (Test-Path -LiteralPath $forged) { Fail "$forged exists" }
  Assert-Denied 'New-Item under C:\ProgramData\saiife' "[System.IO.File]::WriteAllText('$Script:Root\planted.txt', 'x')"
  Assert-Denied 'a dir under C:\ProgramData\saiife' "[void][System.IO.Directory]::CreateDirectory('$Script:Root\planted')"
  foreach ($p in "$Script:Root\planted.txt", "$Script:Root\planted") { if (Test-Path -LiteralPath $p) { Fail "$p exists" } }
}

function attack_service {
  $daemon = Get-DaemonPid
  $sc = "$env:SystemRoot\System32\sc.exe"
  Assert-Denied 'Stop-Service saiifed' 'Stop-Service -Name saiifed -Force'
  Assert-ProgramDenied 'sc.exe stop saiifed' $sc @('stop', $Script:ServiceName)
  Assert-ProgramDenied 'sc.exe config saiifed start= disabled' $sc @('config', $Script:ServiceName, 'start=', 'disabled')
  Assert-ProgramDenied 'sc.exe delete saiifed' $sc @('delete', $Script:ServiceName)
  Assert-Denied "Stop-Process on the daemon (pid $daemon)" "Stop-Process -Id $daemon -Force"
  if ((Get-DaemonPid) -ne $daemon) { Fail 'the daemon pid changed under the agent''s attempts' }
  if ((Get-ServiceState) -ne 'Running') { Fail "the service is $(Get-ServiceState)" }
  $r = Invoke-Admin -Exe $sc -Arguments @('qc', $Script:ServiceName)
  if ($r.Out -notmatch 'AUTO_START') { Fail "the start type changed: $($r.Out)" }
  Ok 'service unchanged'

  Assert-ProgramDenied 'reg add HKLM\SOFTWARE\Policies\ClaudeCode' "$env:SystemRoot\System32\reg.exe" @(
    'add', 'HKLM\SOFTWARE\Policies\ClaudeCode', '/v', 'Settings', '/d', '{}', '/f')
  if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Policies\ClaudeCode') { Fail 'the HKLM policy key exists' }
}

# Review Focus 2 and W11: the name is taken while the service is stopped. The daemon refuses
# with the log line, the audit log does not grow across its restarts, a hook as another user
# denies without writing to the fake pipe.
function attack_pipe_squat {
  Stop-Saiifed
  $s = Start-Squatter -Who $Script:Agent -PipeName 'saiife' -Tag 'system'
  $auditBefore = Get-AuditSize
  try {
    try {
      Start-Service -Name $Script:ServiceName
      Write-Host '  Start-Service returned'
    } catch {
      Write-Host "  Start-Service: $($_.Exception.Message)"
    }
    # The failure actions restart it after 1 s, three times. Long enough to see them all.
    $states = [System.Collections.Generic.List[string]]::new()
    foreach ($i in 1..20) { $states.Add((Get-ServiceState)); Start-Sleep -Seconds 1 }
    Read-Back 'service-under-squat' ($states -join ' ')
    if ((Get-ServiceState) -eq 'Running') { Fail "the service stayed running on a squatted pipe: $($states -join ' ')" }
    $log = Get-Content -LiteralPath $Script:DaemonLog -Raw
    if ($log -notlike "*$Script:W11Line*") { Fail "daemon.log lacks W11's line: $(Get-DaemonLogTail)" }
    Ok "daemon.log has W11's line"

    # Fails until the T5 review's change lands: records were written before the pipe bound.
    $auditAfter = Get-AuditSize
    if ($auditAfter -ne $auditBefore) { Fail "the restart loop grew the audit log: $auditBefore -> $auditAfter" }
    Ok "the audit log did not grow across the restarts ($auditAfter)"

    $approverPayload = Get-Payload 'claude\bash-allow.json' $null $Script:Approver
    Invoke-Hook -AgentKind claude -Payload $approverPayload -Who $Script:Approver
    if ($Script:HookCode -ne 2) { Fail "a hook as approver on a squatted pipe: exit $($Script:HookCode): $($Script:HookErr)" }
    Ok "hook as approver denied ($($Script:HookErr))"
    Assert-Hook 2 '' 'hook as the squatter itself' claude (Get-Payload 'claude\bash-allow.json')
    Assert-SquatterGotNothing $s -RequireConnection
  } finally {
    Stop-Squatter $s
  }
  Start-Saiifed
  Assert-Hook 0 '' 'allow once the squatter is gone and the service restarted' claude (Get-Payload 'claude\bash-allow.json')
}

# A4, W28. Limit: names that exist in System32 come from System32 under the default search
# order too, before the cwd or PATH, so a quiet hook alone would not prove the flag. The
# control pair shows the flag working on a DLL that exists nowhere else.
function attack_dll_plant {
  Build-Native
  $n = "$Script:Work\native"
  $r = Invoke-Msvc "dumpbin /nologo /loadconfig `"$Script:Hook`"" $Script:Work
  $flag = ($r.Out -split "`r?`n") | Where-Object { $_ -match 'Dependent' }
  Read-Back 'pe-dependent-load-flag' ($(if ($flag) { $flag.Trim() -join ' ' } else { "none printed: $($r.Out.Length) bytes of loadconfig" }))
  $imports = @(Get-PeImports $Script:Hook | Where-Object { $_ -notmatch '^(api|ext)-ms-' })
  Read-Back 'pe-imports' ($imports -join ' ')
  if ($imports.Count -eq 0) { Fail 'dumpbin found no imports in saiife.exe' }

  $marker = "$Script:Work\markers\plant.log"
  $cwd = "$($Script:Agent.Home)\plant-cwd"
  $pathDir = "$($Script:Agent.Home)\plant-path"
  $code = "foreach (`$d in '$cwd', '$pathDir') { New-Item -ItemType Directory -Force -Path `$d | Out-Null }"
  $r = Invoke-PwshAs -User $Script:Agent -Code $code
  if ($r.Code -ne 0) { Fail "plant dirs: $($r.Err)" }
  $dll = "$n\saiife-plant-probe.dll"

  # Controls: in the cwd only, on PATH only, and the flagged twin of both.
  $control = "$($Script:Agent.Home)\plant-exe\control.exe"
  $flagged = "$($Script:Agent.Home)\plant-exe\control-flagged.exe"
  New-Item -ItemType Directory -Force -Path "$($Script:Agent.Home)\plant-exe" | Out-Null
  Copy-Item -LiteralPath "$n\control.exe" -Destination $control
  Copy-Item -LiteralPath "$n\control-flagged.exe" -Destination $flagged

  Copy-Item -LiteralPath $dll -Destination "$cwd\saiife-plant-probe.dll"
  Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  $r = Invoke-As -User $Script:Agent -Exe $control -Cwd $cwd
  if ($r.Code -ne 0 -or -not (Test-Path -LiteralPath $marker)) { Fail "control, DLL in the cwd: exit $($r.Code), no marker: the probe proves nothing" }
  Ok "control: a program without the flag loads the DLL from its cwd ($(Get-Content -LiteralPath $marker -Raw))"
  Remove-Item -LiteralPath "$cwd\saiife-plant-probe.dll"

  Copy-Item -LiteralPath $dll -Destination "$pathDir\saiife-plant-probe.dll"
  Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  $path = "$pathDir;$env:SystemRoot\System32;$env:SystemRoot"
  $r = Invoke-As -User $Script:Agent -Exe $control -Cwd $Script:Agent.Project -ExtraEnv @{ Path = $path }
  if ($r.Code -ne 0 -or -not (Test-Path -LiteralPath $marker)) { Fail "control, DLL on PATH: exit $($r.Code), no marker: the probe proves nothing" }
  Ok 'control: a program without the flag loads the DLL from a dir on PATH'

  Copy-Item -LiteralPath $dll -Destination "$cwd\saiife-plant-probe.dll"
  Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  $r = Invoke-As -User $Script:Agent -Exe $flagged -Cwd $cwd -ExtraEnv @{ Path = $path } -TimeoutSec 20
  if (Test-Path -LiteralPath $marker) { Fail "the flagged control still loaded the planted DLL: $(Get-Content -LiteralPath $marker -Raw)" }
  # STATUS_DLL_NOT_FOUND. 124: the loader's hard-error dialog, which nobody here can dismiss,
  # says the same; the program did not run either way.
  if ($r.Code -notin -1073741515, 124) { Fail "the flagged control exited $($r.Code), want 0xC0000135" }
  Ok 'control: with /DEPENDENTLOADFLAG:0x800 the same program finds no such DLL and writes no marker'

  # The hook, with every import planted in its cwd and on PATH.
  foreach ($name in $imports) {
    Copy-Item -LiteralPath $dll -Destination "$cwd\$name"
    Copy-Item -LiteralPath $dll -Destination "$pathDir\$name"
  }
  Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  $allow = Get-Payload 'claude\bash-allow.json'
  Invoke-Hook -AgentKind claude -Payload $allow -Cwd $cwd -ExtraEnv @{ Path = $path }
  if (Test-Path -LiteralPath $marker) { Fail "A4: a planted DLL ran in the managed hook: $(Get-Content -LiteralPath $marker -Raw)" }
  # A planted import has no such exports: had the loader taken it, the hook could not start.
  if ($Script:HookCode -ne 0) { Fail "A4: the hook among planted DLLs exited $($Script:HookCode), want 0: $($Script:HookErr)" }
  Ok "A4: hook among planted copies of $($imports.Count) imports: allowed, no marker"

  # Beside the program: not the installed path, which the agent cannot write to, but the
  # first place the default search looks. What the flag does there, for the record.
  $copy = "$cwd\saiife.exe"
  Copy-Item -LiteralPath $Script:Hook -Destination $copy
  Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
  $r = Invoke-As -User $Script:Agent -Exe $copy -Cwd $cwd -Stdin $allow -Arguments @('check', '--managed', '--hook-exit', '--agent', 'claude') -TimeoutSec 30
  Measure-Result 'dll-planting-beside-a-copy' "a copy of saiife.exe among planted imports in the agent's dir: exit $($r.Code), start error '$($r.StartError)', marker: $(Test-Path -LiteralPath $marker), stderr: $($r.Err.Trim())"
}

# From a second account (T11, integration): the agent's personal pipe, on a locked host.
function attack_personal_on_locked {
  $before = Get-DoctorSummary $null $Script:Hook
  $s = Start-Squatter -Who $Script:Approver -PipeName "saiife-user-$($Script:Agent.Sid)" -Tag 'personal-locked'
  try {
    Assert-Hook 0 '' 'hook while the second account squats the agent''s personal pipe' claude (Get-Payload 'claude\bash-allow.json')
    $during = Get-DoctorSummary $null $Script:Hook
    Assert-SquatterGotNothing $s
  } finally {
    Stop-Squatter $s
  }
  $after = Get-DoctorSummary $null $Script:Hook
  Read-Back 'doctor-locked-personal-squat' "before $($before.Lines -join ' ') | during $($during.Lines -join ' ') | after $($after.Lines -join ' ')"
  if (($before.Lines -join ' ') -cne ($during.Lines -join ' ') -or ($before.Lines -join ' ') -cne ($after.Lines -join ' ')) {
    Fail 'doctor changed with the personal pipe squatted on a locked host'
  }
  Ok 'doctor is the same before, during and after: a locked host never uses that pipe'
}

function phase_attacks {
  $failures = [System.Collections.Generic.List[string]]::new()
  # Each stands alone: one found wrong must not hide the others.
  foreach ($attack in 'attack_files', 'attack_service', 'attack_pipe_squat', 'attack_dll_plant', 'attack_personal_on_locked') {
    Write-Host "-- $attack"
    try {
      & $attack
    } catch {
      $failures.Add("${attack}: $($_.Exception.Message)")
      Write-Host "  FAILED ${attack}: $($_.Exception.Message)"
      Restore-Baseline
    }
  }
  if ($failures.Count) { Fail ($failures -join ' || ') }
}

# The key=value lines of measure.exe, one line.
function Format-Probe($Result) {
  if ($Result.StartError) { return "could not start: $($Result.StartError)" }
  return "exit $($Result.Code); $(($Result.Out.Trim() -replace '\s*\r?\n\s*', '; ')); stderr: $($Result.Err.Trim())"
}

function measure_dosdevice {
  $m = "$Script:Work\native\measure.exe"
  $fake = "$($Script:Agent.Home)\fakec"
  $bin = "$fake\ProgramData\saiife\bin"
  $code = "New-Item -ItemType Directory -Force -Path '$bin' | Out-Null; Copy-Item -LiteralPath '$Script:Work\native\fake-hook.exe' -Destination '$bin\saiife.exe'"
  $r = Invoke-PwshAs -User $Script:Agent -Code $code
  if ($r.Code -ne 0) { Fail "fake tree: $($r.Err)" }
  $ready = "$Script:Work\out\dos-ready.txt"
  Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
  $relative = $fake.Substring(2)
  $h = Start-As -User $Script:Agent -Exe $m -Arguments @('dosdevice', $relative, $ready, $Script:Hook, '8') -Cwd $Script:Agent.Project
  if ($h.StartError) { Fail "measure dosdevice could not start: $($h.StartError)" }
  $end = (Get-Date).AddSeconds(30)
  while ((Get-Date) -lt $end -and -not ((Test-Path -LiteralPath $ready) -and (Get-Item -LiteralPath $ready).Length -gt 0)) { Start-Sleep -Milliseconds 200 }
  # While the map stands: another logon of the same user, and the runner.
  Invoke-Hook -AgentKind claude -Payload (Get-Payload 'claude\bash-deny.json')
  $other = "a hook in another logon session of agent, during the map: exit $($Script:HookCode) ($($Script:HookErr))"
  $runner = "the runner's view: hook file exists $(Test-Path -LiteralPath $Script:Hook), sha unchanged $((Get-Sha $Script:Hook) -eq (Get-Sha $Script:CopyBin))"
  $r = Wait-As -Handle $h -TimeoutSec 40
  $audit = (@(Get-GuardRecords)[-1] | ConvertTo-Json -Compress -Depth 8)
  Measure-Result 'DefineDosDevice-C' "as non-admin agent, session-local remap of C: to a dir it owns. $(Format-Probe $r). $other. $runner. child_exit 0 and hook_path_is under fakec mean the normal hook path ran the agent's program. Newest guard record: $audit"
}

function measure_share_mode {
  param([string]$Target, [string]$Tag, [switch]$RestartService)
  $m = "$Script:Work\native\measure.exe"
  $ready = "$Script:Work\out\hold-$Tag.ready"
  $stop = "$Script:Work\out\hold-$Tag.stop"
  Remove-Item -LiteralPath $ready, $stop -Force -ErrorAction SilentlyContinue
  $h = Start-As -User $Script:Agent -Exe $m -Arguments @('hold', $Target, $ready, $stop, '90') -Cwd $Script:Agent.Project
  if ($h.StartError) { Fail "measure hold could not start: $($h.StartError)" }
  $end = (Get-Date).AddSeconds(30)
  while ((Get-Date) -lt $end -and -not (Test-Path -LiteralPath $ready)) { Start-Sleep -Milliseconds 200 }
  $lines = [System.Collections.Generic.List[string]]::new()
  try {
    $payload = Get-Payload 'claude\bash-deny.json'
    Invoke-Hook -AgentKind claude -Payload $payload
    $lines.Add("deny fixture as agent: exit $($Script:HookCode) ($($Script:HookErr))")
    $allow = Get-Payload 'claude\bash-allow.json'
    Invoke-Hook -AgentKind claude -Payload $allow
    $lines.Add("allow fixture as agent: exit $($Script:HookCode) ($($Script:HookErr))")
    Invoke-Hook -AgentKind claude -Payload (Get-Payload 'claude\bash-allow.json' $null $Script:Approver) -Who $Script:Approver
    $lines.Add("as approver: exit $($Script:HookCode) ($($Script:HookErr))")
    $a = Invoke-As -User $null -Exe $Script:Hook -Stdin $allow -Arguments @('check', '--managed', '--hook-exit', '--agent', 'claude') -TimeoutSec 30
    $lines.Add("as the elevated runner: exit $($a.Code) start error '$($a.StartError)'")
    if ($RestartService) {
      $state = ''
      try {
        Stop-Saiifed
        try { Start-Service -Name $Script:ServiceName; $state = 'Start-Service returned' } catch { $state = "Start-Service: $($_.Exception.Message)" }
        Start-Sleep -Seconds 5
        $lines.Add("service restart under the lock: $state; state now $(Get-ServiceState)")
      } catch {
        $lines.Add("service restart under the lock: $($_.Exception.Message)")
      }
    }
  } finally {
    Set-Content -LiteralPath $stop -Value 'stop'
    $r = Wait-As -Handle $h -TimeoutSec 15
  }
  Start-Saiifed
  Invoke-Hook -AgentKind claude -Payload (Get-Payload 'claude\bash-allow.json')
  $lines.Add("after the release: allow exit $($Script:HookCode)")
  Measure-Result "share-mode-0-$Tag" "as non-admin agent, CreateFile($Target, GENERIC_READ, share 0). $(Format-Probe $r). $($lines -join '; ')"
}

function measure_terminate {
  $m = "$Script:Work\native\measure.exe"
  $sizeBefore = Get-AuditSize
  # The hook's parent ends it itself.
  $r = Invoke-As -User $Script:Agent -Exe $m -Arguments @('spawn-kill', $Script:Hook, 'claude', '0') -Cwd $Script:Agent.Project -TimeoutSec 30
  Measure-Result 'TerminateProcess-own-child' "as non-admin agent: a hook it started, TerminateProcess(hook, 0). $(Format-Probe $r). Audit $sizeBefore -> $(Get-AuditSize)"

  # Another process of the same user, in another logon session, ends a hook that waits on stdin.
  $pidFile = "$Script:Work\out\hook-pid-1.txt"
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  $sizeBefore = Get-AuditSize
  $parent = Start-As -User $Script:Agent -Exe $m -Arguments @('spawn-hold', $Script:Hook, 'claude', $pidFile, '20') -Cwd $Script:Agent.Project
  if ($parent.StartError) { Fail "measure spawn-hold could not start: $($parent.StartError)" }
  Wait-Until 10 'the hook''s pid' { Test-Path -LiteralPath $pidFile }
  $hookPid = (Get-Content -LiteralPath $pidFile -Raw).Trim()
  $kill = Invoke-As -User $Script:Agent -Exe $m -Arguments @('terminate', $hookPid, '0') -Cwd $Script:Agent.Project
  $r = Wait-As -Handle $parent -TimeoutSec 30
  Measure-Result 'TerminateProcess-other-process' "as non-admin agent: killer: $(Format-Probe $kill). The hook's parent saw: $(Format-Probe $r). 0 is a forged allow, if the agent reads the code. Audit $sizeBefore -> $(Get-AuditSize)"

  # The same, across users: the second account has no such right, or Windows says otherwise.
  $pidFile = "$Script:Work\out\hook-pid-2.txt"
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  $parent = Start-As -User $Script:Agent -Exe $m -Arguments @('spawn-hold', $Script:Hook, 'claude', $pidFile, '20') -Cwd $Script:Agent.Project
  if ($parent.StartError) { Fail "measure spawn-hold could not start: $($parent.StartError)" }
  Wait-Until 10 'the hook''s pid' { Test-Path -LiteralPath $pidFile }
  $hookPid = (Get-Content -LiteralPath $pidFile -Raw).Trim()
  $kill = Invoke-As -User $Script:Approver -Exe $m -Arguments @('terminate', $hookPid, '0') -Cwd $Script:Approver.Project
  $r = Wait-As -Handle $parent -TimeoutSec 30
  Measure-Result 'TerminateProcess-cross-user' "approver against agent's hook: $(Format-Probe $kill). Parent saw (control, the hook's own ending if the kill was refused): $(Format-Probe $r)"

  # Why the cross-user kill went as it did: the two accounts' groups as `whoami /groups`
  # sees them, started the way the hook's parent and the killer were. The probes above
  # already printed the hook's and the killer's own tokens (hook_group, killer_group, the
  # logon SID marked) and the hook's process descriptor (hook_sddl, target_sddl). A logon
  # SID both hold would explain it. Report-only: nothing here may fail the job.
  foreach ($who in @(@{ Tag = 'agent'; User = $Script:Agent }, @{ Tag = 'approver'; User = $Script:Approver })) {
    try {
      $g = Invoke-As -User $who.User -Exe "$env:SystemRoot\System32\whoami.exe" -Arguments @('/groups', '/fo', 'csv', '/nh') -Cwd $who.User.Project -TimeoutSec 30
      Measure-Result "TerminateProcess-cross-user-groups-$($who.Tag)" "whoami /groups as $($who.User.Name): $(Format-Probe $g)"
    } catch {
      Measure-Result "TerminateProcess-cross-user-groups-$($who.Tag)" "whoami /groups as $($who.User.Name) did not run: $($_.Exception.Message)"
    }
  }
}

# The attacks the T10 review named, from the non-admin agent, on this runner only. Nothing
# here is asserted about the outcome: only that the probe ran. The result decides how Windows
# locked mode is described. Whether a real agent reads a killed hook's 0 as an allow, or runs
# on when its hook cannot start, is each agent's own behaviour and is not measured here.
function phase_measurements {
  try {
    Build-Native
  } catch {
    Measure-Result 'all' "the probes could not be built, so nothing was measured: $($_.Exception.Message)"
    Write-Host "::warning title=phase_measurements::probes not built: $($_.Exception.Message)"
    return
  }
  $failures = [System.Collections.Generic.List[string]]::new()
  $steps = @(
    @{ Name = 'DefineDosDevice'; Do = { measure_dosdevice } },
    @{ Name = 'share mode 0 on saiife.exe'; Do = { measure_share_mode -Target $Script:Hook -Tag 'saiife-exe' -RestartService } },
    @{ Name = 'share mode 0 on config.toml'; Do = { measure_share_mode -Target $Script:ConfigPath -Tag 'config-toml' } },
    @{ Name = 'TerminateProcess'; Do = { measure_terminate } })
  foreach ($step in $steps) {
    try {
      & $step.Do
    } catch {
      $failures.Add("$($step.Name): $($_.Exception.Message)")
      Measure-Result $step.Name "the probe itself failed, so nothing was measured: $($_.Exception.Message)"
      Restore-Baseline
    }
  }
  # Reported, never failed: the owner asked for these to be measured, not gated. A probe
  # that could not run says so in measurements.txt and as a warning.
  foreach ($f in $failures) { Write-Host "::warning title=phase_measurements::probe did not run: $f" }
}

function Get-CheckStatus($Doctor, [string]$Id) {
  $c = @($Doctor.Json.checks | Where-Object { $_.id -eq $Id })
  if ($c.Count -eq 0) { return 'missing' }
  return $c[0].status
}

function Get-CheckDetail($Doctor, [string]$Id) {
  return (@($Doctor.Json.checks | Where-Object { $_.id -eq $Id })[0]).detail
}

function Set-Uac([int]$Lua, [int]$Consent, [int]$Secure) {
  Set-ItemProperty -LiteralPath $Script:UacKey -Name 'EnableLUA' -Value $Lua
  Set-ItemProperty -LiteralPath $Script:UacKey -Name 'ConsentPromptBehaviorAdmin' -Value $Consent
  Set-ItemProperty -LiteralPath $Script:UacKey -Name 'PromptOnSecureDesktop' -Value $Secure
}

# Review Focus 3. Values are only read by doctor; no reboot, so UAC itself stays as it was.
function doctor_admin_agent {
  $uac = Get-ItemProperty -LiteralPath $Script:UacKey
  $saved = @($uac.EnableLUA, $uac.ConsentPromptBehaviorAdmin, $uac.PromptOnSecureDesktop)
  Read-Back 'uac-values' "EnableLUA=$($saved[0]) ConsentPromptBehaviorAdmin=$($saved[1]) PromptOnSecureDesktop=$($saved[2])"
  $id = "user.$($Script:AgentName).root"
  try {
    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $Script:AgentName
    Set-Uac 1 5 1
    $d = Get-DoctorSummary $null $Script:Hook
    if ((Get-CheckStatus $d $id) -ne 'fail') { Fail "the agent in Administrators, default consent: $id is $(Get-CheckStatus $d $id), want fail: $(Get-CheckDetail $d $id)" }
    Ok "agent in Administrators, consent 5: $id fails ($(Get-CheckDetail $d $id))"

    Set-Uac 1 1 1
    $d = Get-DoctorSummary $null $Script:Hook
    if ((Get-CheckStatus $d $id) -ne 'warn') { Fail "credentials on the secure desktop: $id is $(Get-CheckStatus $d $id), want warn: $(Get-CheckDetail $d $id)" }
    Ok "agent in Administrators, consent 1 on the secure desktop: $id warns ($(Get-CheckDetail $d $id))"

    Set-Uac 0 1 1
    $d = Get-DoctorSummary $null $Script:Hook
    if ((Get-CheckStatus $d $id) -ne 'fail') { Fail "UAC off: $id is $(Get-CheckStatus $d $id), want fail" }
    Ok "the same with EnableLUA 0: $id fails"

    Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $Script:AgentName
    Add-LocalGroupMember -SID 'S-1-5-32-551' -Member $Script:AgentName
    Set-Uac 1 1 1
    $d = Get-DoctorSummary $null $Script:Hook
    if ((Get-CheckStatus $d $id) -ne 'fail') { Fail "Backup Operators: $id is $(Get-CheckStatus $d $id), want fail" }
    Ok "agent in Backup Operators: $id fails ($(Get-CheckDetail $d $id))"
  } finally {
    Restore-UserGroups
    if ($null -ne $saved[0]) { Set-ItemProperty -LiteralPath $Script:UacKey -Name 'EnableLUA' -Value $saved[0] }
    if ($null -ne $saved[1]) { Set-ItemProperty -LiteralPath $Script:UacKey -Name 'ConsentPromptBehaviorAdmin' -Value $saved[1] }
    if ($null -ne $saved[2]) { Set-ItemProperty -LiteralPath $Script:UacKey -Name 'PromptOnSecureDesktop' -Value $saved[2] }
  }
  $d = Get-DoctorSummary $null $Script:Hook
  if ((Get-CheckStatus $d $id) -ne 'pass') { Fail "agent back out of the groups: $id is $(Get-CheckStatus $d $id)" }
  Ok "agent out of the groups: $id passes"
}

function phase_doctor {
  $d = Get-DoctorSummary $null $Script:Hook
  foreach ($c in $d.Json.checks) { Write-Host "$(([string]$c.status).ToUpper())  $($c.id)  $($c.title): $($c.detail)" }
  $problems = [System.Collections.Generic.List[string]]::new()
  if ($d.Json.exit -ne $d.Code) { $problems.Add("doctor exited $($d.Code), its report says $($d.Json.exit)") }
  if ($d.Code -ne 1) { $problems.Add("doctor exited $($d.Code), want 1") }
  $failed = @($d.Json.checks | Where-Object { $_.status -eq 'fail' })
  if ($failed.Count) { $problems.Add("checks failed: $(($failed | ForEach-Object { "$($_.id): $($_.detail)" }) -join ' || ')") }
  foreach ($id in 'install.record', 'files.acl', 'files.installed', 'daemon.unit', 'daemon.health') {
    if ((Get-CheckStatus $d $id) -ne 'pass') { $problems.Add("$id is $(Get-CheckStatus $d $id): $(Get-CheckDetail $d $id)") }
  }
  if ((Get-CheckStatus $d 'files.binary') -ne 'warn') { $problems.Add("files.binary is $(Get-CheckStatus $d 'files.binary'), want warn: $(Get-CheckDetail $d 'files.binary')") }

  # A plain shell: a locked host never exits 0 from one (T8). This checks that a plain user's
  # QueryServiceConfig and sdshow succeed under W10's AU grant.
  $plain = Get-DoctorSummary $Script:Agent $Script:Hook
  Read-Back 'doctor-as-agent' "exit $($plain.Code): $($plain.Lines -join ' ')"
  if ($plain.Code -eq 0) { $problems.Add('doctor from a plain shell exited 0') }
  if ((Get-CheckStatus $plain 'doctor.elevation') -ne 'warn') { $problems.Add("doctor.elevation from a plain shell is $(Get-CheckStatus $plain 'doctor.elevation')") }

  try {
    doctor_admin_agent
  } catch {
    $problems.Add($_.Exception.Message)
  }
  if ($problems.Count) { Fail ($problems -join "`n") }
  Ok 'doctor exit 1, warnings only'
}

# ------------------------------------------------------------ approvals

function Set-ConfigTables {
  param([string]$TableRegex, [string]$NewTables)
  $text = [System.IO.File]::ReadAllText($Script:ConfigPath)
  if ($null -eq $Script:ConfigBackup) { $Script:ConfigBackup = $text }
  $skip = $false
  $kept = foreach ($line in ($text -split "`r?`n")) {
    if ($line -match '^\s*\[') { $skip = $line -match "^\s*\[($TableRegex)(\.[A-Za-z0-9_.-]*)?\]\s*(#.*)?$" }
    if (-not $skip) { $line }
  }
  # In place: the file keeps its descriptor.
  [System.IO.File]::WriteAllText($Script:ConfigPath, (($kept -join "`n") + "`n" + $NewTables))
}

function Get-PolicyCount { return @(Get-Records | Where-Object { $_.kind -eq 'policy' }).Count }

# SERVICE_CONTROL_PARAMCHANGE, then wait for the new `policy` record; a refused config fails.
function Invoke-ReloadChecked {
  $before = Get-PolicyCount
  $r = Invoke-Admin -Exe "$env:SystemRoot\System32\sc.exe" -Arguments @('control', $Script:ServiceName, 'paramchange')
  if ($r.Code -ne 0) { Fail "sc.exe control paramchange: $($r.Out)$($r.Err)" }
  Wait-Until 30 'a new policy record after the reload' { (Get-PolicyCount) -gt $before }
  $last = @(Get-Records | Where-Object { $_.kind -eq 'policy' })[-1]
  if ($last.result -eq 'rejected') { Fail "the daemon rejected the reloaded config: $($last | ConvertTo-Json -Compress -Depth 8); $(Get-DaemonLogTail)" }
  Ok "reload: policy $($last.result)"
}

function Get-Approvals([string]$Id) { return @(Get-Records | Where-Object { $_.kind -eq 'approval' -and "$($_.approval)" -eq $Id }) }

function Get-Refusal([string]$Id) { return @(Get-Approvals $Id | Where-Object { $_.action -eq 'refused' })[-1] }

function Test-HookAsks([string]$Payload) {
  Invoke-Hook -AgentKind claude -Payload $Payload
  return $Script:HookCode -eq 2 -and $Script:HookErr -like '*Needs approval: request #*'
}

function Get-AskedId {
  $m = [regex]::Match($Script:HookErr, 'Needs approval: request #(\d+)\.')
  if (-not $m.Success) { Fail "no request id in the hook's message: $($Script:HookErr)" }
  return $m.Groups[1].Value
}

function Assert-Pending([string]$Id, [string]$What) {
  $r = Invoke-SaiifeAs -User $Script:Agent -Arguments @('approvals', 'list', '--json')
  if ($r.Code -ne 0) { Fail "${What}: approvals list exited $($r.Code): $($r.Err)" }
  $list = @($r.Out | ConvertFrom-Json -Depth 32 | ForEach-Object { $_ })
  $row = @($list | Where-Object { "$($_.id)" -eq $Id })
  if ($row.Count -ne 1 -or $row[0].state -ne 'pending' -or $row[0].user -notmatch "(^|\\)$($Script:AgentName)`$") { Fail "${What}: #$Id is not pending for agent: $($r.Out)" }
  Ok "${What}: #$Id pending"
}

# 4625 for anyone, and 4624 network logons (type 3) of the agent: what a re-authentication
# with LogonUserW(NETWORK) would leave. Start-As's own logons are interactive (type 2).
function Get-LogonCounts([datetime]$Since) {
  $fail = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $Since } -ErrorAction SilentlyContinue)
  $good = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $Since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[5].Value -eq $Script:AgentName -and "$($_.Properties[8].Value)" -eq '3' })
  return [pscustomobject]@{ Failed = $fail.Count; Network = $good.Count }
}

# Owner ruling 2026-11-05 (W16). `saiife approve` is refused on Windows until T9's rewrite
# lands on the branch, so this phase fails until then; the ones around it still run.
function phase_approvals {
  if ($Script:InstallOut -notlike "*$Script:SameUserOff*") { Fail "install did not warn: $Script:SameUserOff" }
  Ok 'install says same-user approval is off'

  # The agent is listed too, so its own approval gets as far as the same_user rule.
  $tables = "`n[guard]`nask = [`"core.git/force-push`"]`n`n[approval]`napprovers = [`"$Script:ApproverName`", `"$Script:AgentName`"]`nsame_user = `"deny`"`n"
  Set-ConfigTables 'guard|approval' $tables
  Invoke-ReloadChecked
  $forced = Get-Payload 'claude\bash-deny.json' { param($p) $p.tool_input.command = 'git push --force origin main' }
  Wait-Until 30 'the ask rule after the reload' { Test-HookAsks $forced }
  $first = Get-AskedId
  Ok "ask rule: git push --force -> request #$first"
  Assert-Pending $first 'ask'

  # A separate account approves; the requester's retry is allowed, once.
  $r = Invoke-SaiifeAs -User $Script:Approver -Arguments @('approve', $first, '--note', 'locked-windows CI')
  if ($r.Code -ne 0) { Fail "approver: approve #$first exited $($r.Code): $($r.Err)" }
  Ok "approver (second account) approved #$first"
  $approved = @(Get-Approvals $first | Where-Object { $_.action -eq 'approved' })
  if ($approved.Count -eq 0 -or $approved[-1].by_sid -ne $Script:Approver.Sid) { Fail "#${first}: the approved record names '$($approved[-1].by_sid)', want $($Script:Approver.Sid)" }
  Ok "the record names the approver's SID"
  Assert-Hook 0 '' 'retry after the approval (the grant, used once)' claude $forced
  if (-not (Test-HookAsks $forced)) { Fail "third run: exit $($Script:HookCode), want a new request: $($Script:HookErr)" }
  $third = Get-AskedId
  if ($third -eq $first) { Fail "third run reused request #$first" }

  # same_user = "deny": the requester cannot approve its own.
  $r = Invoke-SaiifeAs -User $Script:Agent -Arguments @('approve', $third)
  if ($r.Code -ne 2) { Fail "agent approving its own #$third exited $($r.Code), want 2: $($r.Err)" }
  if ((Get-Refusal $third).rule -ne 'same_user') { Fail "#${third}: refusal rule '$((Get-Refusal $third).rule)', want same_user" }
  Assert-Pending $third 'after the refused self-approval'
  Ok 'same_user = deny: self-approval refused (exit 2, rule same_user)'

  # same_user = "reauth" acts as deny on Windows: no prompt, no password, no logon. Review
  # Focus 5, adapted: the agent retries in a loop and nothing changes. First show the Security
  # log would see a failed logon, or a silence below would prove nothing.
  $control = Get-Date
  $wrong = [pscustomobject]@{ Name = $Script:ApproverName; Password = (New-RandomPassword); Sid = ''; Home = $null; Project = $null }
  $w = Invoke-As -User $wrong -Exe "$env:SystemRoot\System32\whoami.exe" -Cwd $Script:Work
  if (-not $w.StartError) { Fail 'a logon with a wrong password started a process' }
  $wait = $null
  Wait-Until 20 'a 4625 for the deliberate wrong password (the control)' { $wait = Get-LogonCounts $control; $wait.Failed -ge 1 }
  Ok 'control: the Security log records a failed logon'

  $text = [System.IO.File]::ReadAllText($Script:ConfigPath) -replace 'same_user = "deny"', 'same_user = "reauth"'
  [System.IO.File]::WriteAllText($Script:ConfigPath, $text)
  Invoke-ReloadChecked
  Start-Sleep -Seconds 2
  $since = Get-Date
  foreach ($i in 1..5) {
    $started = Get-Date
    $r = Invoke-SaiifeAs -User $Script:Agent -Arguments @('approve', $third) -TimeoutSec 30
    $secs = [int]((Get-Date) - $started).TotalSeconds
    if ($r.TimedOut) { Fail "agent's approve #$i hung: a prompt?" }
    if ($r.Code -eq 0) { Fail "agent approved its own #$third under reauth (try $i): $($r.Out)" }
    if ("$($r.Out)$($r.Err)" -notlike "*$Script:SameUserOff*") { Fail "try ${i}: not W16's refusal: $($r.Err)" }
    $refusal = Get-Refusal $third
    if ($refusal.rule -ne 'reauth_unavailable' -or $refusal.reason -notlike "*$Script:SameUserOff*") { Fail "try ${i}: record: $($refusal | ConvertTo-Json -Compress -Depth 8)" }
    Ok "try ${i}: refused in ${secs}s, reauth_unavailable, W16's text, recorded"
  }
  Assert-Pending $third 'after the refusals'
  if (@(Get-Approvals $third | Where-Object { $_.action -eq 'approved' }).Count) { Fail "#$third was approved" }
  Start-Sleep -Seconds 3
  $after = Get-LogonCounts $since
  if ($after.Failed -ne 0 -or $after.Network -ne 0) { Fail "the refusals made logons: 4625 x $($after.Failed), network 4624 x $($after.Network)" }
  Ok 'no 4625 and no network logon of the agent in the Security log'

  $r = Invoke-SaiifeAs -User $Script:Approver -Arguments @('reject', $third)
  if ($r.Code -ne 0) { Fail "approver: reject #$third exited $($r.Code): $($r.Err)" }
  Ok "approver rejected #$third"
  Restore-Config
  Wait-DaemonReady
  Wait-Until 30 'the force-push to be blocked again' {
    Invoke-Hook -AgentKind claude -Payload $forced
    $Script:HookCode -eq 2 -and $Script:HookErr -like '*BLOCKED by*'
  }
  Ok 'config restored'
}

# ------------------------------------------------------------ lockdown

function Get-LastLockdown { return @(Get-Records | Where-Object { $_.kind -eq 'lockdown' })[-1] }

function Test-HookLockedOut([string]$Payload) {
  Invoke-Hook -AgentKind claude -Payload $Payload
  return $Script:HookCode -eq 2 -and $Script:HookErr -like '*saiife lockdown is on*'
}

function phase_lockdown {
  $allow = Get-Payload 'claude\bash-allow.json'
  Set-ConfigTables 'approval' "`n[approval]`napprovers = [`"$Script:ApproverName`"]`nsame_user = `"deny`"`n"
  Invoke-ReloadChecked

  $r = Invoke-SaiifeAs -User $Script:Agent -Arguments @('lockdown', 'on', '--scope', 'all', '--reason', 'agent')
  if ($r.Code -ne 2) { Fail "agent: lockdown on exited $($r.Code), want 2: $($r.Err)" }
  $rec = Get-LastLockdown
  if ($rec.action -ne 'on' -or $rec.decision -ne 'deny' -or $rec.rule -ne 'forbidden') { Fail "agent: lockdown on record: $($rec | ConvertTo-Json -Compress -Depth 8)" }
  Assert-Hook 0 '' 'hook after the refused lockdown on' claude $allow
  Ok 'agent (not an approver): lockdown on refused (exit 2, rule forbidden)'

  $Script:LockdownOn = $true
  $r = Invoke-Admin -Exe $Script:Hook -Arguments @('lockdown', 'on', '--scope', 'all', '--reason', 'locked-windows CI')
  if ($r.Code -ne 0) { Fail "elevated: lockdown on exited $($r.Code): $($r.Err)" }
  Wait-Until 30 'the hook to be locked out' { Test-HookLockedOut $allow }
  Ok "lockdown on (all): hook denied ($($Script:HookErr))"

  Restart-Service -Name $Script:ServiceName -Force
  Wait-DaemonReady
  Wait-Until 30 'the hook to stay locked out after the restart' { Test-HookLockedOut $allow }
  Ok 'lockdown survives Restart-Service'

  $r = Invoke-SaiifeAs -User $Script:Agent -Arguments @('lockdown', 'off')
  if ($r.Code -ne 2) { Fail "agent: lockdown off exited $($r.Code), want 2: $($r.Err)" }
  $rec = Get-LastLockdown
  if ($rec.action -ne 'off' -or $rec.decision -ne 'deny' -or $rec.rule -ne 'forbidden') { Fail "agent: lockdown off record: $($rec | ConvertTo-Json -Compress -Depth 8)" }
  Ok 'agent: lockdown off refused (exit 2, rule forbidden)'
  $r = Invoke-SaiifeAs -User $Script:Approver -Arguments @('lockdown', 'off')
  if ($r.Code -ne 2) { Fail "approver: lockdown off exited $($r.Code), want 2: $($r.Err)" }
  $rec = Get-LastLockdown
  if ($rec.action -ne 'off' -or $rec.decision -ne 'deny' -or $rec.rule -ne 'reauth_required') { Fail "approver: lockdown off record: $($rec | ConvertTo-Json -Compress -Depth 8)" }
  if (-not (Test-HookLockedOut $allow)) { Fail "lockdown was lifted by approver: $($Script:HookErr)" }
  Ok 'approver (not an admin, same_user = deny): lockdown off refused (rule reauth_required)'

  $r = Invoke-Admin -Exe $Script:Hook -Arguments @('lockdown', 'off')
  if ($r.Code -ne 0) { Fail "elevated: lockdown off exited $($r.Code): $($r.Err)" }
  $Script:LockdownOn = $false
  Assert-Hook 0 '' 'hook after lockdown was lifted' claude $allow
  Restore-Config
  Wait-DaemonReady
  Ok 'config restored'
}

# ------------------------------------------------------------ reinstall, uninstall

# The paths an installed.toml lists. TOML writes strings with backslashes as 'literal', or
# as "basic" with them doubled.
function Get-ListedPaths([string]$Text) {
  $unquote = {
    param($quote, $body)
    if ($quote -eq '"') { return $body.Replace('\\', '\') }
    return $body
  }
  $out = [System.Collections.Generic.List[string]]::new()
  foreach ($m in [regex]::Matches($Text, "(?m)^path\s*=\s*(?<q>['""])(?<v>.*?)\k<q>\s*$")) {
    $out.Add((& $unquote $m.Groups['q'].Value $m.Groups['v'].Value))
  }
  $dirs = [regex]::Match($Text, '(?ms)^dirs\s*=\s*\[(?<b>.*?)\]')
  if ($dirs.Success) {
    foreach ($m in [regex]::Matches($dirs.Groups['b'].Value, "(?<q>['""])(?<v>.*?)\k<q>")) {
      $out.Add((& $unquote $m.Groups['q'].Value $m.Groups['v'].Value))
    }
  }
  return @($out | Where-Object { [System.IO.Path]::IsPathRooted($_) })
}

function phase_reinstall_uninstall {
  $before = Get-DaemonPid
  Invoke-Install -Allowed 0
  if ((Get-DaemonPid) -ne $before) { Fail "a second install restarted the daemon: pid $before -> $(Get-DaemonPid)" }
  Ok "a reinstall over our own tree changes nothing (pid $before)"

  $listedText = [System.IO.File]::ReadAllText($Script:InstalledPath)
  $listed = Get-ListedPaths $listedText
  if ($listed.Count -eq 0) { Fail "no paths read from installed.toml: $listedText" }
  Read-Back 'installed-toml' ($listedText -replace '\r?\n', ' ')

  $r = Invoke-Admin -Exe $Script:Bin -Arguments @('system', 'uninstall')
  Write-Host "$($r.Out)$($r.Err)"
  if ($r.Code -ne 0) { Fail "system uninstall exited $($r.Code)" }
  $kept = @($Script:Root.ToLowerInvariant(), $Script:EtcDir.ToLowerInvariant(), $Script:ConfigPath.ToLowerInvariant(),
    "$($Script:EtcDir)\policy.d".ToLowerInvariant(), $Script:LogDir.ToLowerInvariant(), "$($Script:LogDir)\daemon".ToLowerInvariant())
  foreach ($p in $listed) {
    $l = $p.ToLowerInvariant()
    if ($l -in $kept -or $l.StartsWith($Script:StateDir.ToLowerInvariant()) -or $l.StartsWith($Script:AuditDir.ToLowerInvariant())) {
      if (-not (Test-Path -LiteralPath $p)) { Fail "uninstall removed $p" }
    } elseif (Test-Path -LiteralPath $p) {
      Fail "uninstall left $p"
    }
  }
  if (Test-Path -LiteralPath $Script:InstalledPath) { Fail "uninstall left $Script:InstalledPath" }
  foreach ($p in $Script:VaultKey, $Script:AuditKey, $Script:AuditDir) { if (-not (Test-Path -LiteralPath $p)) { Fail "uninstall removed $p" } }
  if (Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue) { Fail 'uninstall left the service' }
  Ok 'listed paths removed, kept ones kept, the service is gone'

  Invoke-Install -Allowed 0, 1
  Wait-DaemonReady
  $listedAgain = Get-ListedPaths ([System.IO.File]::ReadAllText($Script:InstalledPath))
  $r = Invoke-Admin -Exe $Script:Bin -Arguments @('system', 'uninstall', '--purge')
  Write-Host "$($r.Out)$($r.Err)"
  if ($r.Code -ne 0) { Fail "system uninstall --purge exited $($r.Code)" }
  foreach ($p in @($Script:Root) + $listedAgain) {
    if (Test-Path -LiteralPath $p) { Fail "purge left $p" }
  }
  if (Get-Service -Name $Script:ServiceName -ErrorAction SilentlyContinue) { Fail 'purge left the service' }
  if (Get-LocalGroup -Name $Script:AuditGroup -ErrorAction SilentlyContinue) { Fail "purge left the group $Script:AuditGroup" }
  Ok "purged: no tree, no service, no group $Script:AuditGroup"
}
