# Forge a hook's allow over \\.\pipe\saiife (plan 21; scripts/locked-windows, CI only).
#
# It does what any process of the agent's user can do with no code injection (spec §9.2
# A25): it opens the daemon's pipe, checks nothing (an attacker would not: no owner check),
# and sends the §8.7 frames the managed hook sends:
#   1. hello;
#   2. hook.begin {agent: "claude", event: "PreToolUse"};
#   3. hook.bind with the payload's key (saiife_ipc::hookkey: the agent, the session, the
#      tool call id and the SHA-256 of the canonical JSON of tool_input);
#   4. audit.append of a guard record with decision "allow", the key's tool_use_id and
#      input_sha256 beside it.
# Then it holds the connection open for -Hold seconds. The daemon holds the forger's allow
# for the key; the co-signer must still deny a call the policy denies (plan 21).
#
# With -Go, steps 3 and 4 wait until that file exists: claude-sim.ps1 starts the forger
# first (a pwsh start is slow), and lets it bind once the real hook has bound.
# -Ready gets 'begun' after step 2 and 'appended' after step 4.
#
#   forge-allow.ps1 -Payload <file> [-Hold <s>] [-Ready <file>] [-Go <file>]
#   forge-allow.ps1 -Payload <file> -KeyOnly
#
# -KeyOnly prints the payload's input_sha256 and connects to nothing: test (windows-latest)
# checks it against the hook's own hash (crates/ipc/src/hookkey.rs key_of_the_claude_fixture).
# Output: key=value lines. Exit 0 when every step was answered ok, 1 when the daemon refused
# one, 3 when the forger could not run.
param(
  [Parameter(Mandatory = $true)][string]$Payload,
  [double]$Hold = 0,
  [string]$Ready = '',
  [string]$Go = '',
  [switch]$KeyOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1

$utf8 = [System.Text.UTF8Encoding]::new($false)

# serde_json's string form: only '"', '\' and control characters are escaped (\b \t \n \f
# \r, else \u00xx in lower case); everything else stays as it is, written as UTF-8.
function ConvertTo-SerdeString([string]$Text) {
  $sb = [System.Text.StringBuilder]::new($Text.Length + 2)
  [void]$sb.Append('"')
  foreach ($c in $Text.ToCharArray()) {
    $n = [int]$c
    if ($c -eq [char]'"') { [void]$sb.Append('\"') }
    elseif ($c -eq [char]'\') { [void]$sb.Append('\\') }
    elseif ($n -eq 8) { [void]$sb.Append('\b') }
    elseif ($n -eq 9) { [void]$sb.Append('\t') }
    elseif ($n -eq 10) { [void]$sb.Append('\n') }
    elseif ($n -eq 12) { [void]$sb.Append('\f') }
    elseif ($n -eq 13) { [void]$sb.Append('\r') }
    elseif ($n -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $n)) }
    else { [void]$sb.Append($c) }
  }
  [void]$sb.Append('"')
  return $sb.ToString()
}

# hookkey::canonical_sha256's text: compact, each object's keys sorted by their UTF-8 bytes.
# Numbers: integers only, as written (serde_json prints floats with ryu; no CI payload has one).
function Add-Canonical([System.Text.Json.JsonElement]$E, [System.Text.StringBuilder]$Sb) {
  $kind = $E.ValueKind
  if ($kind -eq [System.Text.Json.JsonValueKind]::Object) {
    $props = @($E.EnumerateObject())
    $keys = [string[]]::new($props.Count)
    for ($i = 0; $i -lt $props.Count; $i++) { $keys[$i] = [Convert]::ToHexString($utf8.GetBytes($props[$i].Name)) }
    $items = [object[]]$props
    # Hex of the bytes, compared ordinally, orders as the bytes do.
    [Array]::Sort([Array]$keys, [Array]$items, [System.Collections.IComparer][System.StringComparer]::Ordinal)
    [void]$Sb.Append('{')
    for ($i = 0; $i -lt $items.Count; $i++) {
      if ($i -gt 0) { [void]$Sb.Append(',') }
      [void]$Sb.Append((ConvertTo-SerdeString $items[$i].Name))
      [void]$Sb.Append(':')
      Add-Canonical $items[$i].Value $Sb
    }
    [void]$Sb.Append('}')
  } elseif ($kind -eq [System.Text.Json.JsonValueKind]::Array) {
    [void]$Sb.Append('[')
    $first = $true
    foreach ($item in $E.EnumerateArray()) {
      if (-not $first) { [void]$Sb.Append(',') }
      $first = $false
      Add-Canonical $item $Sb
    }
    [void]$Sb.Append(']')
  } elseif ($kind -eq [System.Text.Json.JsonValueKind]::String) {
    [void]$Sb.Append((ConvertTo-SerdeString $E.GetString()))
  } elseif ($kind -eq [System.Text.Json.JsonValueKind]::Number) {
    $raw = $E.GetRawText()
    if ($raw -notmatch '^-?(0|[1-9][0-9]*)$') { throw "a non-integer number in tool_input ($raw): this forger hashes integers only" }
    [void]$Sb.Append($raw)
  } elseif ($kind -eq [System.Text.Json.JsonValueKind]::True) {
    [void]$Sb.Append('true')
  } elseif ($kind -eq [System.Text.Json.JsonValueKind]::False) {
    [void]$Sb.Append('false')
  } else {
    [void]$Sb.Append('null')
  }
}

# The first of $Names that is a non-empty string; $null when none is.
function Get-StringField([System.Text.Json.JsonElement]$Root, [string[]]$Names) {
  foreach ($n in $Names) {
    $v = [System.Text.Json.JsonElement]::new()
    if ($Root.TryGetProperty($n, [ref]$v) -and $v.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
      $s = $v.GetString()
      if ($s) { return $s }
    }
  }
  return $null
}

# hookkey::hook_key_value("claude", payload).
function Get-HookKey([System.Text.Json.JsonElement]$Root) {
  if ($Root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'the payload is not a JSON object' }
  $sb = [System.Text.StringBuilder]::new()
  $found = $false
  foreach ($n in 'tool_input', 'toolInput') {
    $v = [System.Text.Json.JsonElement]::new()
    if ($Root.TryGetProperty($n, [ref]$v) -and $v.ValueKind -ne [System.Text.Json.JsonValueKind]::Null) {
      Add-Canonical $v $sb
      $found = $true
      break
    }
  }
  if (-not $found) { [void]$sb.Append('null') }
  $hash = [System.Security.Cryptography.SHA256]::HashData($utf8.GetBytes($sb.ToString()))
  return [ordered]@{
    agent = 'claude'
    session = Get-StringField $Root @('session_id', 'sessionId')
    tool_use_id = Get-StringField $Root @('tool_use_id', 'toolUseId')
    input_sha256 = [Convert]::ToHexString($hash).ToLowerInvariant()
  }
}

function Say([string]$Key, $Value) { [Console]::Out.WriteLine("$Key=$Value"); [Console]::Out.Flush() }

$text = [System.IO.File]::ReadAllText($Payload, $utf8)
$doc = [System.Text.Json.JsonDocument]::Parse($text)
$root = $doc.RootElement
$key = Get-HookKey $root
if ($KeyOnly) {
  [Console]::Out.WriteLine($key.input_sha256)
  exit 0
}
# From here it connects to the daemon, which it does only in the job, like run.ps1.
if ($env:SAIIFE_LOCKED_CI -ne '1') {
  Write-Output 'refusing: forge-allow.ps1 is started by locked-windows only (SAIIFE_LOCKED_CI=1)'
  exit 2
}

$p = $text | ConvertFrom-Json -Depth 32
$command = ''
if ($p.PSObject.Properties['tool_input'] -and $p.tool_input -and $p.tool_input.PSObject.Properties['command']) { $command = [string]$p.tool_input.command }
$toolName = if ($p.PSObject.Properties['tool_name'] -and $p.tool_name) { [string]$p.tool_name } else { 'unknown' }
$project = if ($p.PSObject.Properties['cwd'] -and $p.cwd) { [string]$p.cwd } else { '' }
$hookEvent = if ($p.PSObject.Properties['hook_event_name'] -and $p.hook_event_name) { [string]$p.hook_event_name } else { 'PreToolUse' }

$Script:NextId = 1
$Script:PipeStream = $null

function Read-Exact([int]$Count) {
  $buf = [byte[]]::new($Count)
  $got = 0
  while ($got -lt $Count) {
    $n = $Script:PipeStream.Read($buf, $got, $Count - $got)
    if ($n -le 0) { throw [System.IO.EndOfStreamException]::new('the daemon closed the pipe') }
    $got += $n
  }
  return , $buf
}

# One request and its answer; a refusal throws 'refused: ...'.
function Invoke-Op([string]$Op, $OpArgs) {
  $id = $Script:NextId
  $Script:NextId++
  $req = [ordered]@{ id = $id; op = $Op }
  foreach ($k in $OpArgs.Keys) { $req[$k] = $OpArgs[$k] }
  $body = $utf8.GetBytes(($req | ConvertTo-Json -Compress -Depth 16))
  $n = $body.Length
  $frame = [byte[]]::new(4 + $n)
  $frame[0] = [byte](($n -shr 24) -band 0xff)
  $frame[1] = [byte](($n -shr 16) -band 0xff)
  $frame[2] = [byte](($n -shr 8) -band 0xff)
  $frame[3] = [byte]($n -band 0xff)
  [Array]::Copy($body, 0, $frame, 4, $n)
  $Script:PipeStream.Write($frame, 0, $frame.Length)
  $Script:PipeStream.Flush()
  $h = Read-Exact 4
  $len = ([int]$h[0] -shl 24) -bor ([int]$h[1] -shl 16) -bor ([int]$h[2] -shl 8) -bor [int]$h[3]
  if ($len -le 0 -or $len -gt 16MB) { throw "${Op}: an answer frame of $len bytes" }
  $ans = $utf8.GetString((Read-Exact $len)) | ConvertFrom-Json -Depth 32
  if ($ans.PSObject.Properties['id'] -eq $null -or [int64]$ans.id -ne $id) { throw "${Op}: the answer is not for request ${id}: $($ans | ConvertTo-Json -Compress -Depth 8)" }
  if ($ans.ok -ne $true) { throw "refused: ${Op}: $($ans.error): $($ans.message)" }
  return $ans
}

function Set-Ready([string]$What) {
  if ($Ready) { [System.IO.File]::WriteAllText($Ready, $What) }
}

Say 'forger_pid' $PID
Say 'input_sha256' $key.input_sha256
Say 'tool_use_id' $key.tool_use_id
$code = 0
try {
  # Identification, as the hook (crates/win/src/ffi/pipe.rs): the daemon reads the token.
  $Script:PipeStream = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'saiife', [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Identification)
  $Script:PipeStream.Connect(10000)
  $ans = Invoke-Op 'hello' ([ordered]@{ proto = 1; client = 'forge-allow' })
  Say 'hello' "ok mode=$($ans.mode)"
  [void](Invoke-Op 'hook.begin' ([ordered]@{ agent = 'claude'; event = $hookEvent }))
  Say 'begin' 'ok'
  Set-Ready 'begun'
  if ($Go) {
    $end = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath $Go)) {
      if ((Get-Date) -gt $end) { throw "no go file $Go in 30 s" }
      Start-Sleep -Milliseconds 10
    }
  }
  $bind = [ordered]@{}
  foreach ($k in $key.Keys) { $bind[$k] = $key[$k] }
  $bind['tool'] = $toolName
  [void](Invoke-Op 'hook.bind' $bind)
  Say 'bind' 'ok'
  $rec = [ordered]@{
    v = 1; agent = 'claude'; project = $project; session = $key.session; tool = $toolName
    input = $command; decision = 'allow'; saiife = 'forge-allow'
  }
  $append = [ordered]@{ rec = $rec; input_sha256 = $key.input_sha256 }
  if ($key.tool_use_id) { $append['tool_use_id'] = $key.tool_use_id }
  $ans = Invoke-Op 'audit.append' $append
  Say 'append' "ok seq=$($ans.seq)"
  Set-Ready 'appended'
  if ($Hold -gt 0) {
    Start-Sleep -Milliseconds ([int]($Hold * 1000))
    Say 'held_s' $Hold
  }
} catch {
  $m = $_.Exception.Message
  if ($m -like 'refused: *') { Say 'refused' $m.Substring(9); $code = 1 } else { Say 'error' "$($_.Exception.GetType().Name): $m"; $code = 3 }
  Set-Ready "failed: $m"
} finally {
  if ($Script:PipeStream) { $Script:PipeStream.Dispose() }
  $doc.Dispose()
}
exit $code
