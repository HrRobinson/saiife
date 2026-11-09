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
# daemon lockdown::path_in: <state>\state\lockdown.json.
$Script:LockdownFlag = "$Script:StateDir\state\lockdown.json"
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
    try { Restore-Baseline } catch {
      $Script:PhaseLines.Add("FAILED  restoring after ${Name}: $($_.Exception.Message)")
      Write-Host "::error title=restoring after ${Name}::$($_.Exception.Message)"
    }
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
    # The next step starts only once the daemon has read it back (its `policy` record).
    if ((Get-ServiceState) -eq 'Running') { Invoke-ReloadChecked }
  }
}

# A lockdown left on would deny every hook of the phases after it: a failed `off` fails.
function Restore-Lockdown {
  if ($Script:LockdownOn) {
    $r = Invoke-As -User $null -Exe $Script:Hook -Arguments @('lockdown', 'off')
    if ($r.StartError) { Fail "restoring: lockdown off could not start: $($r.StartError)" }
    if ($r.Code -ne 0) { Fail "restoring: lockdown off exited $($r.Code): $($r.Out)$($r.Err)" }
    $Script:LockdownOn = $false
  }
}

function Restore-Baseline {
  Stop-Spawned
  Restore-UserGroups
  if ((Get-ServiceState) -ne 'Missing') {
    Start-Saiifed
    try { Restore-Lockdown } finally { Restore-Config }
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
  Assert-CosignAfterRestart 'after the restart'
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

# Unchanged since CI 11, so its numbers compare. With plan 20 each killed hook here also
# leaves a no_verdict record; phase_cosign asserts what the co-signer makes of a kill.
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

# ------------------------------------------------------------ the co-signer (plan 20)

$Script:CosignUrl = 'http://127.0.0.1:7433/v1/cosign/claude'
$Script:CosignPattern = 'http://127.0.0.1:7433/*'
$Script:CosignPort = 7433
# cosign.rs CosignDeny::text, and hooks.rs NO_VERDICT_REASON.
$Script:CosignNoVerdict = 'the saiife hook ended without a verdict'
$Script:CosignNoReport = 'no saiife hook reported a verdict for this call'
$Script:CosignDenied = 'saiife denied this call'

# The co-signer's deny body for $Reason, byte for byte (cosign.rs deny_body).
function Get-CosignDenyBody([string]$Reason) {
  return '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): ' + $Reason + '"}}'
}

# Claude Code's HTTP hook, simulated: one POST of a payload. Params only, so it also runs as a
# job (Start-Cosign). Status 0 is a request that failed (Error says why). At is when the
# answer came, as a UTC file time, to set against measure.exe's kill_at_filetime.
$Script:CosignPost = {
  param([string]$Url, [string]$Body, [hashtable]$Headers, [string]$Ready)
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $sw = $null
  try {
    if ($Ready) { [System.IO.File]::WriteAllText($Ready, 'ready') }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-WebRequest -Method Post -Uri $Url -ContentType 'application/json' -Body $Body -Headers $Headers `
      -SkipHttpErrorCheck -TimeoutSec 12 -NoProxy
    $content = $r.Content
    if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
    if ($null -eq $content) { $content = '' }
    return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$content; Ms = [int]$sw.ElapsedMilliseconds
      At = [DateTime]::UtcNow.ToFileTimeUtc(); Error = '' }
  } catch {
    $ms = if ($sw) { [int]$sw.ElapsedMilliseconds } else { 0 }
    return [pscustomobject]@{ Status = 0; Body = ''; Ms = $ms; At = [DateTime]::UtcNow.ToFileTimeUtc(); Error = $_.Exception.Message }
  }
}

# One co-sign request, now. Returns Status, Body, Ms, At, Error.
function Invoke-Cosign {
  param([string]$PayloadJson, [hashtable]$Headers = @{})
  return & $Script:CosignPost $Script:CosignUrl $PayloadJson $Headers ''
}

# The same request in a job, as Claude Code sends it beside the command hook. Returns once
# the job is about to send it.
function Start-Cosign([string]$PayloadJson) {
  $ready = "$Script:Work\out\cosign-ready-$([guid]::NewGuid().ToString('N')).txt"
  $job = Start-Job -ScriptBlock $Script:CosignPost -ArgumentList $Script:CosignUrl, $PayloadJson, @{}, $ready
  Wait-Until 60 'the co-sign job to start' { (Test-Path -LiteralPath $ready) -or ([string]$job.State -in 'Failed', 'Completed', 'Stopped') }
  return $job
}

function Receive-Cosign($Job) {
  $done = Wait-Job -Job $Job -Timeout 30
  if (-not $done) {
    Remove-Job -Job $Job -Force
    Fail 'the co-sign job did not finish in 30 s'
  }
  $out = @(Receive-Job -Job $Job)
  $state = [string]$Job.State
  Remove-Job -Job $Job -Force
  $last = @($out | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Status'] })
  if ($last.Count -eq 0) { Fail "the co-sign job ($state) returned no answer: $($out -join ' ')" }
  return $last[-1]
}

function Format-Cosign($Answer) {
  if ($Answer.Error) { return "request failed after $($Answer.Ms) ms: $($Answer.Error)" }
  $shown = if ($Answer.Body) { $Answer.Body } else { '(empty)' }
  return "$($Answer.Status) in $($Answer.Ms) ms, body $shown"
}

function Assert-CosignDeny($Answer, [string]$Reason, [string]$What) {
  if ($Answer.Status -ne 200 -or $Answer.Body -cne (Get-CosignDenyBody $Reason)) {
    Fail "${What}: co-sign answer $(Format-Cosign $Answer), want 200 with the deny body '$Reason'; daemon.log: $(Get-DaemonLogTail)"
  }
  Ok "${What}: co-signer denied in $($Answer.Ms) ms ($Reason)"
}

# A recorded payload with a tool_use_id of its own: the co-signer keeps a verdict per key for
# 60 s, and every earlier hook of the fixture shares its id.
function Get-CosignPayload([string]$Fixture, [string]$ToolUseId) {
  $change = { param($p) $p.tool_use_id = $ToolUseId }.GetNewClosure()
  return Get-Payload $Fixture $change
}

function New-ToolUseId { return "toolu_ci_$([guid]::NewGuid().ToString('N'))" }

function Write-Utf8File([string]$Path, [string]$Text) {
  [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

# A key=value line of measure.exe's output; $null when it printed none.
function Get-ProbeValue([string]$Out, [string]$Key) {
  $m = [regex]::Match($Out, '(?m)^' + [regex]::Escape($Key) + '=(.*?)\r?$')
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return $null
}

# The hook records (hooks.rs no_verdict_record, cosign.rs record) of one event.
function Get-HookRecords([string]$HookEvent) {
  return @(Get-Records | Where-Object { $_.kind -eq 'hook' -and $_.event -eq $HookEvent })
}

# The no_verdict records among those after the first $After (month files in order, so new
# records come last) of the hook with this pid: its `pid` is the pipe client's. Pids are
# reused, and phase_measurements leaves no_verdict records of its own.
function Find-NoVerdictRecords([int]$After, [string]$HookPid) {
  $all = @(Get-Records)
  if ($all.Count -le $After) { return @() }
  return @($all[$After..($all.Count - 1)] | Where-Object { $_.kind -eq 'hook' -and $_.event -eq 'no_verdict' -and "$($_.pid)" -eq $HookPid })
}

function Wait-NoVerdictRecord([int]$After, [string]$HookPid, [int]$Seconds) {
  Wait-Until $Seconds "the no_verdict record of hook pid $HookPid" { @(Find-NoVerdictRecords $After $HookPid).Count -gt 0 }
  return @(Find-NoVerdictRecords $After $HookPid)[-1]
}

function Assert-NoVerdictRecord($Record, [bool]$Bound, [string]$ToolUseId, [string]$What) {
  $json = $Record | ConvertTo-Json -Compress -Depth 8
  if ($Record.decision -ne 'no_verdict') { Fail "${What}: the hook record's decision is '$($Record.decision)': $json" }
  if ($Record.bound -ne $Bound) { Fail "${What}: the no_verdict record has bound=$($Record.bound), want ${Bound}: $json" }
  if ($Record.sid -ne $Script:Agent.Sid) { Fail "${What}: the no_verdict record's sid is '$($Record.sid)', want the agent's $($Script:Agent.Sid): $json" }
  if ($Record.agent -ne 'claude') { Fail "${What}: the no_verdict record's agent is '$($Record.agent)': $json" }
  if ($ToolUseId -and $Record.tool_use_id -ne $ToolUseId) { Fail "${What}: the no_verdict record's tool_use_id is '$($Record.tool_use_id)', want ${ToolUseId}: $json" }
  Ok "${What}: no_verdict record, bound $Bound, sid $($Record.sid), elapsed $($Record.elapsed_ms) ms"
}

# Who listens on 7433, the drop-in's HTTP hook, a squat by the agent, a browser's request.
function cosign_listen {
  $j = Get-Content -LiteralPath $Script:ClaudeManaged -Raw | ConvertFrom-Json -Depth 32
  $http = @($j.hooks.PreToolUse | ForEach-Object { $_.hooks } | Where-Object { $_.type -eq 'http' })
  if ($http.Count -ne 1 -or $http[0].url -ne $Script:CosignUrl -or $http[0].onFailure -ne 'block') {
    Fail "the drop-in's PreToolUse hooks lack the co-signer ($Script:CosignUrl, onFailure block): $($j.hooks.PreToolUse | ConvertTo-Json -Compress -Depth 8)"
  }
  if (@($j.allowedHttpHookUrls) -notcontains $Script:CosignPattern) { Fail "the drop-in's allowedHttpHookUrls lacks ${Script:CosignPattern}: $(@($j.allowedHttpHookUrls) -join ', ')" }
  Ok "the drop-in posts to $Script:CosignUrl (onFailure block) and allows $Script:CosignPattern"

  $daemonPid = Get-DaemonPid
  $rows = @(Get-NetTCPConnection -LocalPort $Script:CosignPort -State Listen -ErrorAction SilentlyContinue)
  $shown = ($rows | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) pid $($_.OwningProcess)" }) -join ', '
  Read-Back 'cosign-listener' "listening on ${Script:CosignPort}: $shown; the service's pid $daemonPid"
  if ($rows.Count -ne 1) { Fail "want one listener on port $Script:CosignPort, got $($rows.Count): $shown; daemon.log: $(Get-DaemonLogTail)" }
  if ($rows[0].LocalAddress -ne '127.0.0.1') { Fail "the co-signer listens on $($rows[0].LocalAddress), want 127.0.0.1" }
  if ([int]$rows[0].OwningProcess -ne $daemonPid) { Fail "port $Script:CosignPort is owned by pid $($rows[0].OwningProcess), not the service's $daemonPid" }
  Ok "127.0.0.1:$Script:CosignPort is the service's (pid $daemonPid)"

  # D6: SO_EXCLUSIVEADDRUSE. A plain bind, and one with SO_REUSEADDR, the squat it stops.
  $code = @'
foreach ($reuse in $false, $true) {
  $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 7433)
  try {
    if ($reuse) { $l.Server.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true) }
    $l.Start()
    "reuse=$reuse BOUND"
    $l.Stop()
  } catch {
    $e = $_.Exception
    while ($e.InnerException) { $e = $e.InnerException }
    $why = if ($e -is [System.Net.Sockets.SocketException]) { [string]$e.SocketErrorCode } else { $e.GetType().Name }
    "reuse=$reuse refused $why"
  }
}
'@
  $r = Invoke-PwshAs -User $Script:Agent -Code $code
  $text = "$($r.Out)$($r.Err)".Trim()
  Read-Back 'cosign-squat-as-agent' ($text -replace '\s*\r?\n\s*', '; ')
  if ($text -match 'BOUND') { Fail "the agent bound 127.0.0.1:$Script:CosignPort beside the service: $text" }
  if (([regex]::Matches($text, 'refused')).Count -ne 2) { Fail "the agent's bind attempts did not both report a refusal (exit $($r.Code)): $text" }
  Ok "the agent cannot bind 127.0.0.1:$Script:CosignPort, with or without SO_REUSEADDR ($($text -replace '\s*\r?\n\s*', '; '))"

  $a = Invoke-Cosign -PayloadJson (Get-CosignPayload 'claude\bash-allow.json' (New-ToolUseId)) -Headers @{ Origin = 'http://example.com' }
  if ($a.Status -ne 403) { Fail "a request with Origin: $(Format-Cosign $a), want 403" }
  Ok 'a request with an Origin header gets 403'
}

# The controls: an honest allow gets an empty 200, a deny the deny body. The request is sent
# first, as Claude Code may (Review Focus 2), and the hook runs beside it.
function cosign_controls {
  $allow = Get-CosignPayload 'claude\bash-allow.json' (New-ToolUseId)
  $job = Start-Cosign $allow
  Invoke-Hook -AgentKind claude -Payload $allow
  $hookCode = $Script:HookCode
  $hookErr = $Script:HookErr
  $a = Receive-Cosign $job
  if ($hookCode -ne 0) { Fail "the allow fixture's hook exited $hookCode, want 0: $hookErr" }
  if ($a.Status -ne 200 -or $a.Body -ne '') { Fail "allow: co-sign answer $(Format-Cosign $a), want 200 with an empty body; daemon.log: $(Get-DaemonLogTail)" }
  Ok "allow fixture: hook exit 0, co-signer 200 with an empty body in $($a.Ms) ms"

  $deny = Get-CosignPayload 'claude\bash-deny.json' (New-ToolUseId)
  $job = Start-Cosign $deny
  Invoke-Hook -AgentKind claude -Payload $deny
  $hookCode = $Script:HookCode
  $hookErr = $Script:HookErr
  $a = Receive-Cosign $job
  if ($hookCode -ne 2) { Fail "the deny fixture's hook exited $hookCode, want 2: $hookErr" }
  Assert-CosignDeny $a $Script:CosignDenied 'deny fixture'
}

# A25 with the co-signer on: the hook is bound and its worker hangs; another process of the
# agent ends it with TerminateProcess(hook, 0). The forged 0 still happens; the co-signer
# denies, and the daemon records the hook without a verdict.
function cosign_kill_bound {
  $m = "$Script:Work\native\measure.exe"
  $toolUseId = New-ToolUseId
  $payload = Get-CosignPayload 'claude\bash-allow.json' $toolUseId
  $payloadFile = "$Script:Work\out\cosign-kill-payload.json"
  $pidFile = "$Script:Work\out\cosign-kill-pid.txt"
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  Write-Utf8File $payloadFile $payload
  $countBefore = @(Get-Records).Count
  $sizeBefore = Get-AuditSize

  $hold = Start-As -User $Script:Agent -Exe $m -Cwd $Script:Agent.Project -ExtraEnv @{ SAIIFE_EVAL_FAULT = 'hang' } -Arguments @(
    'spawn-fed-hold', $Script:Hook, 'claude', $payloadFile, $pidFile, '20')
  if ($hold.StartError) { Fail "measure spawn-fed-hold could not start: $($hold.StartError)" }
  $killer = Start-As -User $Script:Agent -Exe $m -Cwd $Script:Agent.Project -Arguments @('terminate-bound', $pidFile, '0', '20')
  if ($killer.StartError) { Fail "measure terminate-bound could not start: $($killer.StartError)" }
  $job = Start-Cosign $payload
  $kill = Wait-As -Handle $killer -TimeoutSec 40
  $held = Wait-As -Handle $hold -TimeoutSec 40
  $answer = Receive-Cosign $job
  $hookPid = Get-ProbeValue $held.Out 'hook_pid'
  $childExit = Get-ProbeValue $held.Out 'child_exit'
  $killAt = Get-ProbeValue $kill.Out 'kill_at_filetime'
  $afterKill = if ($killAt) { [int](([long]$answer.At - [long]$killAt) / 10000) } else { $null }
  $facts = "child_exit=$childExit (0 is the forged allow); co-signer $(Format-Cosign $answer), $afterKill ms after the kill; killer: $(Format-Probe $kill); hook's parent: $(Format-Probe $held)"

  $record = $null
  try {
    if ((Get-ProbeValue $kill.Out 'terminate') -ne 'succeeded') { Fail "the kill did not happen: $facts" }
    if (-not $hookPid) { Fail "spawn-fed-hold printed no hook pid: $facts" }
    if ($childExit -ne '0') { Fail "the killed hook's exit is $childExit, want the forged 0: $facts" }
    Ok 'TerminateProcess(hook, 0) by another process of the agent: the hook''s parent sees exit 0'
    Assert-CosignDeny $answer $Script:CosignNoVerdict 'the killed hook''s call'
    # RECONNECT_GRACE (5 s) after the kill, not COSIGN_WAIT (8 s) after the request.
    if ($null -eq $afterKill -or $afterKill -gt 7000) { Fail "the co-signer answered $afterKill ms after the kill, want within 7000: $facts" }
    Ok "the co-signer answered $afterKill ms after the kill"
    $record = Wait-NoVerdictRecord $countBefore $hookPid 15
    Assert-NoVerdictRecord $record $true $toolUseId 'the killed bound hook'
    $cosigned = @(Get-HookRecords 'cosign_denied' | Where-Object { $_.tool_use_id -eq $toolUseId -and $_.reason -eq $Script:CosignNoVerdict })
    if ($cosigned.Count -eq 0) { Fail "no cosign_denied record for $toolUseId with reason '$Script:CosignNoVerdict'" }
    Ok 'a cosign_denied record names the call'
    $countAfter = @(Get-Records).Count
    if ($countAfter -le $countBefore) { Fail "the audit did not grow: $countBefore -> $countAfter records" }
    Ok "the audit grew: $countBefore -> $countAfter records ($sizeBefore -> $(Get-AuditSize))"
  } finally {
    $shownRecord = if ($record) { $record | ConvertTo-Json -Compress -Depth 8 } else { '(none)' }
    Measure-Result 'TerminateProcess-cosign' "as non-admin agent, a bound hook (worker hung) ended by another process with TerminateProcess(hook, 0): $facts. no_verdict record: $shownRecord. Audit $sizeBefore -> $(Get-AuditSize)"
  }
}

# The CI 11 spawn-hold case: the hook has said hook.begin and waits on stdin when it is
# ended, so it never bound a key (D5). The record says bound false; the co-signer cannot
# match the call and denies at its cap.
function cosign_kill_stdin {
  $m = "$Script:Work\native\measure.exe"
  $pidFile = "$Script:Work\out\cosign-stdin-pid.txt"
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  $countBefore = @(Get-Records).Count
  $parent = Start-As -User $Script:Agent -Exe $m -Arguments @('spawn-hold', $Script:Hook, 'claude', $pidFile, '20') -Cwd $Script:Agent.Project
  if ($parent.StartError) { Fail "measure spawn-hold could not start: $($parent.StartError)" }
  # spawn-hold creates the file before it writes the pid.
  Wait-Until 10 'the hook''s pid' { (Test-Path -LiteralPath $pidFile) -and "$(Get-Content -LiteralPath $pidFile -Raw)".Trim() }
  $hookPid = "$(Get-Content -LiteralPath $pidFile -Raw)".Trim()
  # hook.begin comes before stdin is read; the hook's own watchdog ends it at 7 s.
  Start-Sleep -Seconds 2
  $kill = Invoke-As -User $Script:Agent -Exe $m -Arguments @('terminate', $hookPid, '0') -Cwd $Script:Agent.Project
  $held = Wait-As -Handle $parent -TimeoutSec 30
  $childExit = Get-ProbeValue $held.Out 'child_exit'
  if ((Get-ProbeValue $kill.Out 'terminate') -ne 'succeeded') { Fail "the kill did not happen: $(Format-Probe $kill); parent: $(Format-Probe $held)" }
  if ($childExit -ne '0') { Fail "the hook killed on stdin exited $childExit, want the forged 0: $(Format-Probe $held)" }
  Ok 'the hook waiting on stdin, ended with TerminateProcess(hook, 0): its parent sees exit 0'
  $record = Wait-NoVerdictRecord $countBefore $hookPid 10
  Assert-NoVerdictRecord $record $false '' 'the hook killed on stdin'

  $toolUseId = New-ToolUseId
  $answer = Invoke-Cosign -PayloadJson (Get-CosignPayload 'claude\bash-allow.json' $toolUseId)
  Assert-CosignDeny $answer $Script:CosignNoReport 'the call whose hook never read it'
  # COSIGN_WAIT is 8 s from the request's arrival.
  if ($answer.Ms -lt 7000) { Fail "the co-signer answered in $($answer.Ms) ms, want about 8000 (its cap)" }
  Ok "the co-signer waited its cap: $($answer.Ms) ms"
  Measure-Result 'TerminateProcess-cosign-stdin' "as non-admin agent, a hook waiting on stdin ended with TerminateProcess(hook, 0): child_exit=$childExit; no_verdict record $($record | ConvertTo-Json -Compress -Depth 8); co-signer for its call: $(Format-Cosign $answer)"
}

# Doctor as the elevated runner, after the kills (plan 20 Task 6).
function cosign_doctor {
  $d = Get-DoctorSummary $null $Script:Hook
  $nv = Get-CheckStatus $d 'hooks.no-verdict'
  $cl = Get-CheckStatus $d 'cosign.listen'
  Read-Back 'doctor-cosign' "hooks.no-verdict=$nv ($(Get-CheckDetail $d 'hooks.no-verdict')); cosign.listen=$cl ($(Get-CheckDetail $d 'cosign.listen'))"
  $problems = [System.Collections.Generic.List[string]]::new()
  if ($nv -ne 'warn') { $problems.Add("hooks.no-verdict is $nv, want warn") }
  if ($cl -ne 'pass') { $problems.Add("cosign.listen is $cl, want pass") }
  if ($problems.Count) { Fail ($problems -join '; ') }
  Ok 'doctor: hooks.no-verdict warns, cosign.listen passes'
}

# After a restart: the co-signer binds again (SO_EXCLUSIVEADDRUSE refuses a bind over the last
# daemon's TIME_WAIT, so the daemon retries it), and co-signs an honest allow.
function Assert-CosignAfterRestart([string]$When) {
  Wait-Until 300 "doctor cosign.listen to pass $When" { (Get-CheckStatus (Get-DoctorSummary $null $Script:Hook) 'cosign.listen') -eq 'pass' }
  Ok "doctor cosign.listen: pass $When"
  $allow = Get-CosignPayload 'claude\bash-allow.json' (New-ToolUseId)
  $job = Start-Cosign $allow
  Invoke-Hook -AgentKind claude -Payload $allow
  $hookCode = $Script:HookCode
  $hookErr = $Script:HookErr
  $a = Receive-Cosign $job
  if ($hookCode -ne 0) { Fail "${When}: the allow fixture's hook exited $hookCode, want 0: $hookErr" }
  if ($a.Status -ne 200 -or $a.Body -ne '') { Fail "${When}: co-sign answer $(Format-Cosign $a), want 200 with an empty body; daemon.log: $(Get-DaemonLogTail)" }
  Ok "${When}: hook exit 0, co-signer 200 with an empty body in $($a.Ms) ms"
}

# The managed hook's budget on Windows: p95 of 50 allow calls as the agent within 130 ms
# (Global Constraints), timed in one pwsh of the agent so no logon is counted. p95 is the
# value at rank ceil(0.95 n), as scripts/bench-check.sh takes it.
function bench_managed {
  $runs = 50
  $budget = 130
  $payloadFile = "$Script:Work\out\bench-payload.json"
  Write-Utf8File $payloadFile (Get-Payload 'claude\bash-allow.json')
  $extra = 10
  $head = "`$Hook = '$Script:Hook'; `$PayloadFile = '$payloadFile'; `$Runs = $runs; `$Extra = $extra; `$Cwd = '$($Script:Agent.Project)'"
  $body = @'
$ErrorActionPreference = 'Stop'
$payload = [System.IO.File]::ReadAllText($PayloadFile)
$utf8 = [System.Text.UTF8Encoding]::new($false)
$inv = [System.Globalization.CultureInfo]::InvariantCulture
# Run 0 warms the file cache and is not counted.
foreach ($i in 0..$Runs) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new($Hook)
  foreach ($a in 'check', '--managed', '--hook-exit', '--agent', 'claude') { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardInputEncoding = $utf8
  $psi.WorkingDirectory = $Cwd
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEndAsync()
  $err = $p.StandardError.ReadToEndAsync()
  $p.StandardInput.Write($payload)
  $p.StandardInput.Close()
  $p.WaitForExit()
  $sw.Stop()
  [void]$out.Wait(5000)
  [void]$err.Wait(5000)
  if ($i -gt 0) { [string]::Format($inv, 'run {0:F1} {1}', $sw.Elapsed.TotalMilliseconds, $p.ExitCode) }
  $p.Dispose()
}
# Where the time goes, untimed by the budget: the floor (saiife.exe --version, a process
# start and exit with nothing judged), then calls with the hook's step trace
# (SAIIFE_HOOK_TIMING=1, honoured by this ci-locked build only), each line passed on.
foreach ($i in 0..$Extra) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new($Hook)
  [void]$psi.ArgumentList.Add('--version')
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEndAsync()
  $p.WaitForExit()
  $sw.Stop()
  [void]$out.Wait(5000)
  if ($i -gt 0) { [string]::Format($inv, 'floor {0:F1}', $sw.Elapsed.TotalMilliseconds) }
  $p.Dispose()
}
foreach ($i in 1..$Extra) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new($Hook)
  foreach ($a in 'check', '--managed', '--hook-exit', '--agent', 'claude') { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardInputEncoding = $utf8
  $psi.WorkingDirectory = $Cwd
  $psi.Environment['SAIIFE_HOOK_TIMING'] = '1'
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEndAsync()
  $err = $p.StandardError.ReadToEndAsync()
  $p.StandardInput.Write($payload)
  $p.StandardInput.Close()
  $p.WaitForExit()
  $sw.Stop()
  [void]$out.Wait(5000)
  [void]$err.Wait(5000)
  [string]::Format($inv, 'traced {0:F1} {1}', $sw.Elapsed.TotalMilliseconds, $p.ExitCode)
  foreach ($line in ($err.Result -split "`r?`n")) { if ($line -match '^saiife-timing ') { $line } }
  $p.Dispose()
}
'@
  $r = Invoke-PwshAs -User $Script:Agent -Code "$head`n$body" -Cwd $Script:Agent.Project -TimeoutSec 300
  if ($r.Code -ne 0) { Fail "the bench as the agent exited $($r.Code): $($r.Out) $($r.Err)" }
  $inv = [System.Globalization.CultureInfo]::InvariantCulture
  $times = [System.Collections.Generic.List[double]]::new()
  $bad = [System.Collections.Generic.List[string]]::new()
  # Step name -> its times over the traced calls, in first-seen order.
  $steps = [ordered]@{}
  $floor = [System.Collections.Generic.List[double]]::new()
  $traced = [System.Collections.Generic.List[double]]::new()
  foreach ($line in ($r.Out -split "`r?`n")) {
    if ($line -match '^run (\S+) (-?\d+)$') {
      $times.Add([double]::Parse($Matches[1], $inv))
      if ($Matches[2] -ne '0') { $bad.Add($Matches[2]) }
    } elseif ($line -match '^floor (\S+)$') {
      $floor.Add([double]::Parse($Matches[1], $inv))
    } elseif ($line -match '^traced (\S+) (-?\d+)$') {
      $traced.Add([double]::Parse($Matches[1], $inv))
      if ($Matches[2] -ne '0') { $bad.Add("traced $($Matches[2])") }
    } elseif ($line -match '^saiife-timing (\S+) (\S+)$') {
      if (-not $steps.Contains($Matches[1])) { $steps[$Matches[1]] = [System.Collections.Generic.List[double]]::new() }
      $steps[$Matches[1]].Add([double]::Parse($Matches[2], $inv))
    }
  }
  # Reported before the budget is judged, pass or fail: where the time goes.
  $median = {
    param($xs)
    $s = @($xs | Sort-Object)
    if ($s.Count -eq 0) { return [double]::NaN }
    if ($s.Count % 2) { return $s[($s.Count - 1) / 2] }
    return ($s[$s.Count / 2 - 1] + $s[$s.Count / 2]) / 2
  }
  $parts = [System.Collections.Generic.List[string]]::new()
  $parts.Add([string]::Format($inv, 'floor (saiife.exe --version) {0:F1}', (& $median $floor)))
  $parts.Add([string]::Format($inv, 'traced call {0:F1}', (& $median $traced)))
  foreach ($name in $steps.Keys) {
    $parts.Add([string]::Format($inv, '{0} {1:F2}', $name, (& $median $steps[$name])))
  }
  Measure-Result 'managed-hook-steps' ("medians in ms over $extra calls each (helper-thread and worker steps overlap the hook's own; total is the hook's main without its process start and exit): " + ($parts -join '; '))
  if ($times.Count -ne $runs) { Fail "the bench printed $($times.Count) runs, want ${runs}: $($r.Out) $($r.Err)" }
  if ($bad.Count) { Fail "$($bad.Count) bench runs did not allow (exits $($bad -join ', ')): $($r.Err)" }
  $sorted = @($times | Sort-Object)
  $k = [int][math]::Floor(($runs * 95 + 99) / 100)
  $p95 = $sorted[$k - 1]
  $median = if ($runs % 2) { $sorted[($runs - 1) / 2] } else { ($sorted[$runs / 2 - 1] + $sorted[$runs / 2]) / 2 }
  $line = [string]::Format($inv, 'managed hook, allow fixture as the agent, {0} runs: median {1:F1} ms, p95 {2:F1} ms, max {3:F1} ms (budget {4} ms)', $runs, $median, $p95, $sorted[-1], $budget)
  Measure-Result 'managed-hook-p95' $line
  if ($p95 -gt $budget) { Fail "the managed hook's p95 is over its budget: $line" }
  Ok $line
}

# Plan 20 Task 9: the co-signer on a real Windows. Unlike phase_measurements these steps are
# asserted; each runs even when one before it failed.
function phase_cosign {
  Build-Native
  $failures = [System.Collections.Generic.List[string]]::new()
  try {
    foreach ($step in 'cosign_listen', 'cosign_controls', 'cosign_kill_bound', 'cosign_kill_stdin', 'cosign_doctor', 'bench_managed') {
      Write-Host "-- $step"
      try {
        & $step
      } catch {
        $failures.Add("${step}: $($_.Exception.Message)")
        Write-Host "  FAILED ${step}: $($_.Exception.Message)"
        Restore-Baseline
      }
    }
  } finally {
    Get-Job | Remove-Job -Force
  }
  if ($failures.Count) { Fail ($failures -join ' || ') }
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

# The newest lockdown record is the elevated runner's change: allowed, and the SID the
# daemon read from the runner's token. Read right after the command, before any hook.
function Assert-AdminLockdown([string]$Action) {
  $rec = Get-LastLockdown
  if ($null -eq $rec) { Fail "elevated: lockdown ${Action}: no lockdown record" }
  $json = $rec | ConvertTo-Json -Compress -Depth 8
  $runner = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
  if ($rec.action -ne $Action -or $rec.decision -ne 'allow') { Fail "elevated: lockdown $Action record: $json" }
  if ($rec.sid -ne $runner) { Fail "elevated: lockdown $Action record's sid is '$($rec.sid)', want the runner's ${runner}: $json" }
  if ($Action -eq 'on' -and $rec.scope -ne 'all') { Fail "elevated: lockdown on record's scope is '$($rec.scope)', want all: $json" }
  Ok "audit record: lockdown $Action allow by the runner (sid $($rec.sid))"
}

# `saiife lockdown`, no subcommand: the daemon's view of the flag.
function Assert-LockdownStatusOff([string]$What) {
  $r = Invoke-Admin -Exe $Script:Hook -Arguments @('lockdown')
  $text = "$($r.Out)".Trim()
  if ($r.Code -ne 0 -or $text -ne 'lockdown: off') { Fail "${What}: saiife lockdown exited $($r.Code): $text $($r.Err)" }
  if (Test-Path -LiteralPath $Script:LockdownFlag) { Fail "${What}: $($Script:LockdownFlag) exists" }
  Ok "${What}: lockdown: off, no flag file"
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
  Assert-AdminLockdown 'on'
  if (-not (Test-Path -LiteralPath $Script:LockdownFlag -PathType Leaf)) { Fail "lockdown on: no flag file $($Script:LockdownFlag)" }
  # phase_acls ran before this file existed: W14's STATE row, read back here.
  $text = (Get-Acl -LiteralPath $Script:LockdownFlag).Sddl
  Read-Back 'descriptor' "$($Script:LockdownFlag) $text"
  $row = Get-W14Row $Script:LockdownFlag
  if (-not $row) { Fail "no W14 row for $($Script:LockdownFlag)" }
  $wrong = Test-Row $Script:LockdownFlag $row $text
  if ($wrong) { Fail "$($Script:LockdownFlag) differs from W14: $wrong" }
  Ok "flag file $($Script:LockdownFlag), its descriptor matches W14"
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
  Assert-AdminLockdown 'off'
  if (Test-Path -LiteralPath $Script:LockdownFlag) { Fail "lockdown off: the flag file $($Script:LockdownFlag) is still there" }
  Ok 'lockdown off: the flag file is gone'
  Assert-Hook 0 '' 'hook after lockdown was lifted' claude $allow
  # Waits for the daemon's policy record: the next phase starts on the restored config.
  Restore-Config
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
  $tomlBefore = [System.IO.File]::ReadAllText($Script:InstalledPath)
  $shaBefore = Get-Sha $Script:Hook
  Invoke-Install -Allowed 0
  if ((Get-DaemonPid) -ne $before) { Fail "a second install restarted the daemon: pid $before -> $(Get-DaemonPid)" }
  $tomlAfter = [System.IO.File]::ReadAllText($Script:InstalledPath)
  if ($tomlAfter -cne $tomlBefore) { Fail "a second install changed installed.toml:`n$tomlBefore`n->`n$tomlAfter" }
  $shaAfter = Get-Sha $Script:Hook
  if ($shaAfter -ne $shaBefore) { Fail "a second install changed $($Script:Hook): $shaBefore -> $shaAfter" }
  $shaBin = Get-Sha $Script:Bin
  if ($shaAfter -ne $shaBin) { Fail "$($Script:Hook) is $shaAfter, the installed build is $shaBin" }
  Ok "a reinstall over our own tree changes nothing (pid $before, installed.toml, binary $shaAfter)"
  Assert-LockdownStatusOff 'after the reinstall'

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
  # phase_lockdown lifted the flag, and a plain uninstall keeps state: none comes back.
  Assert-LockdownStatusOff 'after the uninstall and an install'
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
