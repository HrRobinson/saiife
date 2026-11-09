# Claude Code's two hooks for one tool call, simulated (plan 21; scripts/locked-windows, CI
# only). It runs as the agent and does what Claude Code does: it starts the command hook as
# its own child, with the payload on stdin, and sends the same payload to the co-signer from
# its own process (HttpClient, no proxy). Since plan 21 the service ties the hook that bound
# a call to the process that owns the co-sign connection: the binder must be at most 3
# parent steps under it (hooks.rs ASKER_MAX_DEPTH). So the request comes from here, never
# from the runner, and the hook and the forger are this process's children.
#
#   -Mode together  -Runs <n>: per run, the request first and the hook beside it. A run's
#                   payload gets tool_use_id <id>-r<i> when -Runs is above 1.
#   -Mode burst     -Runs <n>: n calls at once, each its request and its hook.
#   -Mode kill      the hook with its judgment hung (SAIIFE_EVAL_FAULT=hang), its pid and a
#                   newline in -PidFile for measure terminate-bound, and the request.
#   -Mode forge     forge-allow.ps1 as a child (it begins, then waits for its go file);
#                   with -WithHook the real hook (hung) first, then the forger binds and
#                   appends an allow, then measure terminate <hook> 0; then the request.
#                   The forger holds its connection until the answer is in.
#
# Output: key=value lines. A body is in base64 (<key>_b64). Times are in ms on one
# Stopwatch; an answer's time is when this process saw it (polled every 2 ms).
param(
  [Parameter(Mandatory = $true)][ValidateSet('together', 'burst', 'kill', 'forge')][string]$Mode,
  [Parameter(Mandatory = $true)][string]$Hook,
  [Parameter(Mandatory = $true)][string]$Payload,
  [Parameter(Mandatory = $true)][string]$Url,
  [Parameter(Mandatory = $true)][string]$Cwd,
  [Parameter(Mandatory = $true)][string]$Out,
  [int]$Runs = 1,
  [string]$PidFile = '',
  [string]$Forger = '',
  [string]$Measure = '',
  [switch]$WithHook
)
if ($env:SAIIFE_LOCKED_CI -ne '1') {
  Write-Output 'refusing: claude-sim.ps1 is started by locked-windows only (SAIIFE_LOCKED_CI=1)'
  exit 2
}
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1

$utf8 = [System.Text.UTF8Encoding]::new($false)
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$handler = [System.Net.Http.SocketsHttpHandler]::new()
$handler.UseProxy = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)

function Say([string]$Key, $Value) { [Console]::Out.WriteLine("$Key=$Value"); [Console]::Out.Flush() }
function B64([string]$Text) { return [Convert]::ToBase64String($utf8.GetBytes($Text)) }
function Now-Ms { return [int64]$clock.ElapsedMilliseconds }

# The co-sign request, as Claude Code's HTTP hook sends it: a POST with Content-Type
# application/json exactly, on its own connection.
function Start-Post([string]$Body) {
  $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Url)
  $req.Headers.ConnectionClose = $true
  $content = [System.Net.Http.ByteArrayContent]::new($utf8.GetBytes($Body))
  $content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
  $req.Content = $content
  return [pscustomobject]@{ Task = $client.SendAsync($req); SentMs = (Now-Ms); DoneMs = $null }
}

# Status, Body and Error of a finished request.
function Get-PostResult($Post) {
  $t = $Post.Task
  if ($t.IsFaulted -or $t.IsCanceled) {
    $e = if ($t.Exception) { $t.Exception.GetBaseException().Message } else { 'canceled' }
    return [pscustomobject]@{ Status = 0; Body = ''; Error = $e }
  }
  $r = $t.Result
  $body = $r.Content.ReadAsStringAsync().GetAwaiter().GetResult()
  return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$body; Error = '' }
}

# The command hook as this process's child, the payload on stdin.
function Start-Hook([string]$Body, [hashtable]$ExtraEnv = @{}) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new($Hook)
  foreach ($a in 'check', '--managed', '--hook-exit', '--agent', 'claude') { [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardInputEncoding = $utf8
  $psi.WorkingDirectory = $Cwd
  foreach ($k in $ExtraEnv.Keys) { $psi.Environment[$k] = $ExtraEnv[$k] }
  $p = [System.Diagnostics.Process]::Start($psi)
  $h = [pscustomobject]@{ P = $p; OutTask = $p.StandardOutput.ReadToEndAsync(); ErrTask = $p.StandardError.ReadToEndAsync(); ExitMs = $null }
  $p.StandardInput.Write($Body)
  $p.StandardInput.Close()
  return $h
}

# Polls hooks and requests until all are done or $Seconds pass, noting when each ended.
function Wait-All([object[]]$Hooks, [object[]]$Posts, [int]$Seconds = 30) {
  $end = (Now-Ms) + $Seconds * 1000
  while ($true) {
    $left = 0
    foreach ($h in $Hooks) { if ($null -eq $h.ExitMs) { if ($h.P.HasExited) { $h.ExitMs = Now-Ms } else { $left++ } } }
    foreach ($q in $Posts) { if ($null -eq $q.DoneMs) { if ($q.Task.IsCompleted) { $q.DoneMs = Now-Ms } else { $left++ } } }
    if ($left -eq 0 -or (Now-Ms) -gt $end) { return }
    Start-Sleep -Milliseconds 2
  }
}

function Get-HookErr($H) {
  if ($H.ErrTask.Wait(5000)) { return $H.ErrTask.Result.Trim() }
  return ''
}

function Get-ExitCode($H) {
  if ($H.P.HasExited) { return $H.P.ExitCode }
  return 'running'
}

# The payload of run $I: its own tool_use_id when there are several runs.
function Get-RunPayload([string]$Text, [int]$I) {
  if ($Runs -le 1) { return $Text }
  $j = $Text | ConvertFrom-Json -Depth 32
  $j.tool_use_id = "$($j.tool_use_id)-r$I"
  return ($j | ConvertTo-Json -Compress -Depth 32)
}

$text = [System.IO.File]::ReadAllText($Payload, $utf8)
Say 'sim_pid' $PID

if ($Mode -eq 'together') {
  foreach ($i in 1..$Runs) {
    $body = Get-RunPayload $text $i
    $post = Start-Post $body
    $h = Start-Hook $body
    Wait-All @($h) @($post)
    $r = Get-PostResult $post
    $after = if ($null -ne $post.DoneMs -and $null -ne $h.ExitMs) { $post.DoneMs - $h.ExitMs } else { 'none' }
    $total = if ($null -ne $post.DoneMs) { $post.DoneMs - $post.SentMs } else { 'none' }
    Say "run_$i" "$(Get-ExitCode $h) $($r.Status) $after $total $($r.Body.Length)"
    if ($r.Body) { Say "run_${i}_body_b64" (B64 $r.Body) }
    if ($r.Error) { Say "run_${i}_error" $r.Error }
    $err = Get-HookErr $h
    if ($err) { Say "run_${i}_hook_err_b64" (B64 $err) }
    $h.P.Dispose()
  }
} elseif ($Mode -eq 'burst') {
  $hooks = [System.Collections.Generic.List[object]]::new()
  $posts = [System.Collections.Generic.List[object]]::new()
  foreach ($i in 1..$Runs) {
    $body = Get-RunPayload $text $i
    $posts.Add((Start-Post $body))
    $hooks.Add((Start-Hook $body))
  }
  Wait-All $hooks.ToArray() $posts.ToArray() 40
  foreach ($i in 1..$Runs) {
    $q = $posts[$i - 1]
    $h = $hooks[$i - 1]
    $r = Get-PostResult $q
    $total = if ($null -ne $q.DoneMs) { $q.DoneMs - $q.SentMs } else { 'none' }
    Say "burst_$i" "$(Get-ExitCode $h) $($r.Status) $total $($r.Body.Length)"
    if ($r.Body) { Say "burst_${i}_body_b64" (B64 $r.Body) }
    if ($r.Error) { Say "burst_${i}_error" $r.Error }
  }
} elseif ($Mode -eq 'kill') {
  $h = Start-Hook $text @{ SAIIFE_EVAL_FAULT = 'hang' }
  Say 'hook_pid' $h.P.Id
  # The newline ends the pid: measure terminate-bound reads the file only once it has one.
  [System.IO.File]::WriteAllText($PidFile, "$($h.P.Id)`n")
  $post = Start-Post $text
  Wait-All @($h) @($post) 30
  $r = Get-PostResult $post
  Say 'child_exit' (Get-ExitCode $h)
  Say 'cosign_status' $r.Status
  Say 'cosign_body_b64' (B64 $r.Body)
  Say 'cosign_error' $r.Error
  Say 'cosign_ms' $(if ($null -ne $post.DoneMs) { $post.DoneMs - $post.SentMs } else { 'none' })
  Say 'cosign_after_exit_ms' $(if ($null -ne $post.DoneMs -and $null -ne $h.ExitMs) { $post.DoneMs - $h.ExitMs } else { 'none' })
  Say 'cosign_at_filetime' ([DateTime]::UtcNow.ToFileTimeUtc())
} else {
  $tag = [guid]::NewGuid().ToString('N')
  $ready = Join-Path $Out "forge-ready-$tag.txt"
  $go = Join-Path $Out "forge-go-$tag.txt"
  $fpsi = [System.Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
  foreach ($a in '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Forger, '-Payload', $Payload,
    '-Hold', '30', '-Ready', $ready, '-Go', $go) { [void]$fpsi.ArgumentList.Add($a) }
  $fpsi.UseShellExecute = $false
  $fpsi.CreateNoWindow = $true
  $fpsi.RedirectStandardOutput = $true
  $fpsi.RedirectStandardError = $true
  $fpsi.WorkingDirectory = $Cwd
  $forger = [System.Diagnostics.Process]::Start($fpsi)
  $fout = $forger.StandardOutput.ReadToEndAsync()
  $ferr = $forger.StandardError.ReadToEndAsync()
  Say 'forger_pid' $forger.Id
  $readText = {
    if (Test-Path -LiteralPath $ready) { try { return [System.IO.File]::ReadAllText($ready) } catch { return '' } }
    return ''
  }
  $end = (Now-Ms) + 60000
  while ((& $readText) -notmatch '^(begun|appended|failed)' -and -not $forger.HasExited -and (Now-Ms) -lt $end) { Start-Sleep -Milliseconds 10 }
  $h = $null
  if ($WithHook) {
    $h = Start-Hook $text @{ SAIIFE_EVAL_FAULT = 'hang' }
    Say 'hook_pid' $h.P.Id
    # Bound by then: hello, hook.begin, stdin and the bind take about 150 ms on these
    # runners; the hung judgment denies at 3 s.
    Start-Sleep -Milliseconds 1000
  }
  [System.IO.File]::WriteAllText($go, 'go')
  $end = (Now-Ms) + 30000
  while ((& $readText) -notmatch '^(appended|failed)' -and -not $forger.HasExited -and (Now-Ms) -lt $end) { Start-Sleep -Milliseconds 10 }
  Say 'forger_state' (& $readText)
  if ($h) {
    Say 'hook_running_at_kill' (-not $h.P.HasExited)
    $kpsi = [System.Diagnostics.ProcessStartInfo]::new($Measure)
    foreach ($a in 'terminate', "$($h.P.Id)", '0') { [void]$kpsi.ArgumentList.Add($a) }
    $kpsi.UseShellExecute = $false
    $kpsi.CreateNoWindow = $true
    $kpsi.RedirectStandardOutput = $true
    $k = [System.Diagnostics.Process]::Start($kpsi)
    $kout = $k.StandardOutput.ReadToEnd()
    $k.WaitForExit()
    foreach ($line in ($kout -split "`r?`n")) { if ($line -match '^terminate') { Say "kill_$($line.Split('=')[0])" $line.Substring($line.IndexOf('=') + 1) } }
    Wait-All @($h) @() 10
    Say 'child_exit' (Get-ExitCode $h)
  }
  $post = Start-Post $text
  Wait-All @() @($post) 20
  $r = Get-PostResult $post
  Say 'cosign_status' $r.Status
  Say 'cosign_body_b64' (B64 $r.Body)
  Say 'cosign_error' $r.Error
  Say 'cosign_ms' $(if ($null -ne $post.DoneMs) { $post.DoneMs - $post.SentMs } else { 'none' })
  # The forger is this process's child: ended through its handle.
  try { if (-not $forger.HasExited) { $forger.Kill() } } catch { Say 'forger_kill_error' $_.Exception.Message }
  [void]$forger.WaitForExit(10000)
  foreach ($line in ((& { if ($fout.Wait(5000)) { $fout.Result } else { '' } }) -split "`r?`n")) {
    if ($line) { Say 'forge' $line }
  }
  if ($ferr.Wait(5000) -and $ferr.Result) { Say 'forge_stderr_b64' (B64 $ferr.Result) }
}
$client.Dispose()
exit 0
