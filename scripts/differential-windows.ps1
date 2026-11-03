<#
.SYNOPSIS
  Checks the guard's PowerShell and cmd readers against the real shells (plan 19a).

.DESCRIPTION
  CI only, on windows-latest, under PowerShell 7 and Windows PowerShell 5.1. It has
  never run anywhere else, so a first failure may be this script's own.

  - PowerShell: each fixture is parsed with
    [System.Management.Automation.Language.Parser]::ParseInput, never run. The command
    names and arguments must equal the words saiife read.
  - Aliases: every alias this shell has (Get-Alias) and the command it resolves to
    must read the same. Which exist depends on the version: see alias_only_51.
  - cmd: each fixture runs under cmd.exe in a throwaway directory. The only program
    that does anything is p19adiffstub, a batch file that logs that it ran. Whether it
    ran must agree with what saiife read. See the fixtures' header for `over`.
  - Paths: saiife's reading of a path against [IO.Path]::GetFullPath and cygpath.

  Any mismatch exits 1. A line the reader noted as not fully read is denied at the
  hook, so it counts as agreeing, and is printed. So is a line PowerShell cannot
  parse. Neither is compared, so a run that compared fewer lines than the floors below
  fails as well: a reader that notes everything agrees with everything.

  A bracket the reader folds to words is compared against the constants in the AST.

.PARAMETER Saiife
  A debug build of saiife: only those have __read-segments.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Saiife
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

# The fewest fixtures each shell must really compare. Raise these with the fixtures.
$PowerShellFloor = 55
$CmdFloor = 50

$Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Failures = New-Object System.Collections.Generic.List[string]
$Fixtures = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'differential-windows.fixtures.json'), $Utf8) | ConvertFrom-Json

$Work = Join-Path ([IO.Path]::GetTempPath()) ("p19a-diff-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work | Out-Null

function Add-Failure([string]$Message) {
  $script:Failures.Add($Message)
  Write-Output "MISMATCH $Message"
}

# Every request goes through one file each way, in UTF-8: a native pipe would pass
# the typographic quotes through the console's code page.
function Read-Lines($Requests) {
  $in = Join-Path $Work 'in.json'
  $out = Join-Path $Work 'out.json'
  [IO.File]::WriteAllText($in, (ConvertTo-Json -InputObject @($Requests) -Depth 4), $Utf8)
  & $Saiife __read-segments $in $out
  if ($LASTEXITCODE -ne 0) { throw "saiife __read-segments exited $LASTEXITCODE" }
  # In a variable first: Windows PowerShell 5.1's ConvertFrom-Json writes a JSON
  # array as one object, which would come back as a single element.
  $parsed = [IO.File]::ReadAllText($out, $Utf8) | ConvertFrom-Json
  return $parsed
}

function Get-Dashless([string]$Text) {
  if ($Text.Length -gt 0 -and [char]$Text[0] -in [char]0x2013, [char]0x2014, [char]0x2015) {
    return '-' + $Text.Substring(1)
  }
  return $Text
}

# The one statement of a block, if it is an expression: what the bracket's value is.
function Get-OnlyExpression($Statement) {
  if ($null -eq $Statement -or $Statement.GetType().Name -ne 'PipelineAst') { return $null }
  if ($Statement.PipelineElements.Count -ne 1) { return $null }
  $element = $Statement.PipelineElements[0]
  if ($element.GetType().Name -ne 'CommandExpressionAst' -or $element.Redirections.Count -gt 0) { return $null }
  return $element.Expression
}

function Get-BlockExpression($Block) {
  if ($Block.Statements.Count -ne 1) { return $null }
  return Get-OnlyExpression $Block.Statements[0]
}

# The strings of an expression that is only quoted strings, brackets and commas, which
# is what the reader folds. $null for anything else: `'.en'+'v'` is computed, and has
# no text to compare.
function Get-ConstantValues($Expression) {
  if ($null -eq $Expression) { return $null }
  switch ($Expression.GetType().Name) {
    'StringConstantExpressionAst' { return , [string[]]@($Expression.Value) }
    'ExpandableStringExpressionAst' { return , [string[]]@($Expression.Value) }
    'ParenExpressionAst' {
      $inner = Get-ConstantValues (Get-OnlyExpression $Expression.Pipeline)
      if ($null -eq $inner) { return $null }
      return , [string[]]$inner
    }
    { $_ -in 'ArrayExpressionAst', 'SubExpressionAst' } {
      $inner = Get-ConstantValues (Get-BlockExpression $Expression.SubExpression)
      if ($null -eq $inner) { return $null }
      return , [string[]]$inner
    }
    'ArrayLiteralAst' {
      $all = @()
      foreach ($e in $Expression.Elements) {
        $values = Get-ConstantValues $e
        if ($null -eq $values) { return $null }
        $all += $values
      }
      return , [string[]]$all
    }
  }
  return $null
}

function Get-ConstantTokens($Expression) {
  $values = Get-ConstantValues $Expression
  if ($null -eq $values) { return @() }
  return @($values | ForEach-Object { "S|$_" })
}

# The parser's arguments, as tokens: P|name for a parameter, S|text for anything else.
# A bracket that is not all constants has no text to compare; the commands inside it
# are found on their own. The reader keeps `$(…)`'s text, unless it folds to one string.
function Get-ElementToken($Element) {
  $name = $Element.GetType().Name
  switch ($name) {
    'CommandParameterAst' {
      if ($null -eq $Element.Argument) { return , ("P|-" + $Element.ParameterName) }
      $value = @(Get-ElementToken $Element.Argument) | ForEach-Object { $_.Substring(2) }
      return , ("P|-" + $Element.ParameterName + ':' + ($value -join ','))
    }
    'ArrayLiteralAst' {
      $all = @()
      foreach ($e in $Element.Elements) { $all += @(Get-ElementToken $e) }
      return $all
    }
    'StringConstantExpressionAst' { return , ("S|" + $Element.Value) }
    'ExpandableStringExpressionAst' { return , ("S|" + $Element.Value) }
    'ScriptBlockExpressionAst' { return @() }
    'ParenExpressionAst' { return Get-ConstantTokens $Element }
    'SubExpressionAst' {
      $values = Get-ConstantValues $Element
      if ($null -ne $values -and $values.Count -eq 1) { return , ("S|" + $values[0]) }
      return , ("S|" + $Element.Extent.Text)
    }
    'ArrayExpressionAst' { return Get-ConstantTokens $Element }
    'HashtableAst' { return @() }
    default { return , ("S|" + $Element.Extent.Text) }
  }
}

function Get-ParserCommands([string]$Line) {
  $tokens = $null
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($Line, [ref]$tokens, [ref]$errors)
  $commands = @()
  $targets = @()
  $found = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandBaseAst] }, $true)
  foreach ($c in $found) {
    foreach ($r in $c.Redirections) {
      if ($r -is [System.Management.Automation.Language.FileRedirectionAst]) {
        $target = @(Get-ElementToken $r.Location)
        if ($target.Count -gt 0 -and $target[0] -ine 'S|$null') { $targets += $target[0].Substring(2) }
      }
    }
    if ($c -isnot [System.Management.Automation.Language.CommandAst]) { continue }
    $words = @()
    foreach ($e in $c.CommandElements) { $words += @(Get-ElementToken $e) }
    # `& { … }`: only a block, whose commands are found on their own.
    if ($words.Count -eq 0) { continue }
    $words[0] = 'S|' + $words[0].Substring(2)
    $commands += , ($words -join "`n")
  }
  return @{
    Errors   = @($errors | ForEach-Object { $_.Message })
    Commands = @($commands | Sort-Object -CaseSensitive)
    Targets  = @($targets | Sort-Object -CaseSensitive)
  }
}

# What saiife read, in the same tokens. `-Path:` with its value in the next word is one
# parameter; redirections are compared on their own.
function Get-ReaderCommands($Read) {
  $commands = @()
  foreach ($command in @($Read.commands)) {
    $words = @()
    $skip = $false
    # The parser's first `--` is a parameter, and nothing after it is one.
    $dashes = $false
    foreach ($w in @($command)) {
      if ($skip) { $skip = $false; continue }
      if ($w.redirect) { $skip = $true; continue }
      if ($w.block) { continue }
      $text = Get-Dashless $w.text
      if (-not $dashes -and $text -ceq '--' -and -not $w.from_quote) {
        $dashes = $true
        $words += 'P|--'
        continue
      }
      if ($words.Count -gt 0 -and $words[-1] -match '^P\|.*:$') {
        $words[-1] = $words[-1] + $text
        continue
      }
      $param = (-not $dashes) -and (-not $w.from_quote) -and ($text -cmatch '^-[\p{L}_?]') -and ((-not $w.quoted) -or $text.Contains(':'))
      $words += $(if ($param) { "P|$text" } else { "S|$text" })
    }
    if ($words.Count -gt 0) {
      $words[0] = 'S|' + $words[0].Substring(2)
      $commands += , ($words -join "`n")
    }
  }
  $targets = @()
  foreach ($segment in @($Read.segments)) {
    $list = @($segment)
    for ($i = 0; $i -lt $list.Count - 1; $i++) {
      if ($list[$i].redirect) { $targets += $list[$i + 1].text }
    }
  }
  return @{ Commands = @($commands | Sort-Object -CaseSensitive); Targets = @($targets | Sort-Object -CaseSensitive) }
}

function Test-SameList($A, $B) {
  $separator = [string][char]1
  return ((@($A) -join $separator) -ceq (@($B) -join $separator))
}

function Test-PowerShell {
  $over = @($Fixtures.powershell_over)
  $lines = @($Fixtures.powershell) + $over
  $reads = Read-Lines @($lines | ForEach-Object { @{ dialect = 'powershell'; line = $_ } })
  $compared = 0
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $shown = ($line -replace "`r", '\r') -replace "`n", '\n'
    $parsed = Get-ParserCommands $line
    if ($parsed.Errors.Count -gt 0) {
      Write-Output "parse error, no real run: $shown :: $($parsed.Errors[0])"
      continue
    }
    if ($null -ne $reads[$i].note) {
      Write-Output "noted, denied at the hook: $shown :: $($reads[$i].note)"
      continue
    }
    $compared++
    $read = Get-ReaderCommands $reads[$i]
    if ($over -ccontains $line) {
      foreach ($c in $parsed.Commands) {
        if ($read.Commands -cnotcontains $c) {
          Add-Failure "powershell, a bypass: $shown`n  parser found: $c`n  reader: $($read.Commands -join ' ;; ')"
        }
      }
    } elseif (-not (Test-SameList $parsed.Commands $read.Commands)) {
      Add-Failure "powershell: $shown`n  parser: $($parsed.Commands -join ' ;; ')`n  reader: $($read.Commands -join ' ;; ')"
    }
    foreach ($t in $parsed.Targets) {
      if ($read.Targets -cnotcontains $t) {
        Add-Failure "powershell redirect: $shown`n  target $t is not among the reader's: $($read.Targets -join ', ')"
      }
    }
  }
  Write-Output "powershell: compared $compared of $($lines.Count) lines"
  if ($compared -lt $PowerShellFloor) {
    Add-Failure "powershell: compared only $compared lines, under the floor of $PowerShellFloor"
  }
}

# Lines read differently from the parser on purpose, each reading pinned, so that any
# other difference on them still fails. And lines that are only printed.
function Test-DocumentedLines {
  $documented = @($Fixtures.powershell_documented)
  $reads = @(Read-Lines @($documented | ForEach-Object { @{ dialect = 'powershell'; line = $_.line } }))
  for ($i = 0; $i -lt $documented.Count; $i++) {
    $d = $documented[$i]
    $parsed = Get-ParserCommands $d.line
    $read = Get-ReaderCommands $reads[$i]
    if (-not (Test-SameList $parsed.Commands @($d.parser)) -or -not (Test-SameList $read.Commands @($d.reader))) {
      Add-Failure "powershell, not as documented: $($d.line)`n  parser: $($parsed.Commands -join ' ;; ')`n  reader: $($read.Commands -join ' ;; ')"
    } else {
      Write-Output "documented over-read: $($d.line)"
    }
  }
  $report = @($Fixtures.powershell_report)
  $reads = @(Read-Lines @($report | ForEach-Object { @{ dialect = 'powershell'; line = $_ } }))
  for ($i = 0; $i -lt $report.Count; $i++) {
    $parsed = Get-ParserCommands $report[$i]
    $read = Get-ReaderCommands $reads[$i]
    Write-Output "report only: $($report[$i])`n  parser: $($parsed.Commands -join ' ;; ') > $($parsed.Targets -join ', ')`n  reader: $($read.Commands -join ' ;; ') > $($read.Targets -join ', ')"
  }
}

# Every alias this shell really has, and the fixtures' list on top. Case does not
# count: PowerShell's command names do not have it.
function Test-Aliases {
  Import-Module CimCmdlets -ErrorAction SilentlyContinue
  $real = @{}
  foreach ($a in Get-Alias) {
    $target = $a.ResolvedCommandName
    if ([string]::IsNullOrEmpty($target)) { $target = $a.Definition }
    $real[$a.Name] = $target
  }
  $only51 = @($Fixtures.alias_only_51)
  $is51 = $PSVersionTable.PSVersion.Major -le 5
  $over = @{}
  foreach ($o in @($Fixtures.alias_over)) { $over[$o.alias] = $o.reason }
  $names = @(@($Fixtures.aliases) + @($real.Keys) | Sort-Object -Unique)
  $pairs = @()
  foreach ($alias in $names) {
    if ($real.ContainsKey($alias)) {
      if ($only51 -contains $alias -and -not $is51) {
        Add-Failure "alias: $alias is an alias in $($PSVersionTable.PSVersion), and the fixtures say only 5.1 has it"
      }
      $pairs += , @($alias, $real[$alias])
    } elseif ($only51 -contains $alias -and -not $is51) {
      Write-Output "not an alias in $($PSVersionTable.PSVersion), as expected: $alias"
    } else {
      Add-Failure "alias: the fixtures name $alias, and $($PSVersionTable.PSVersion) has no such alias"
    }
  }
  $requests = @()
  foreach ($p in $pairs) {
    $requests += @{ dialect = 'powershell'; line = "$($p[0]) x y" }
    $requests += @{ dialect = 'powershell'; line = "$($p[1]) x y" }
  }
  $reads = Read-Lines $requests
  for ($i = 0; $i -lt $pairs.Count; $i++) {
    $alias = $pairs[$i][0]
    $a = ConvertTo-Json -InputObject $reads[2 * $i].segments -Depth 4 -Compress
    $b = ConvertTo-Json -InputObject $reads[2 * $i + 1].segments -Depth 4 -Compress
    if ($over.ContainsKey($alias)) {
      # All the command reads, and more: `[[…]]` without its outer brackets.
      if ($a.IndexOf($b.Substring(2, $b.Length - 4), [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Write-Output "documented over-read of an alias: $alias"
      } else {
        Add-Failure "alias: $alias no longer reads all that $($pairs[$i][1]) does`n  $a`n  $b"
      }
    } elseif ($a -ine $b) {
      Add-Failure "alias: $alias is $($pairs[$i][1]), which reads differently`n  $a`n  $b"
    } elseif ($reads[2 * $i].note -cne $reads[2 * $i + 1].note) {
      Add-Failure "alias: $alias is $($pairs[$i][1]), noted differently: $($reads[2 * $i].note) / $($reads[2 * $i + 1].note)"
    }
  }
  Write-Output "aliases: compared $($pairs.Count) in $($PSVersionTable.PSVersion)"
}

# Whether the stub ran: $true or $false, and $null for a line that did not finish.
function Invoke-CmdLine([string]$Line, [string]$Dir, [string]$Log) {
  if (Test-Path -LiteralPath $Log) { Remove-Item -LiteralPath $Log }
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
  # /s: the outer quotes come off and nothing else is touched. /d: no AutoRun.
  $info.Arguments = '/d /s /c "' + $Line + '"'
  $info.WorkingDirectory = $Dir
  $info.UseShellExecute = $false
  $info.RedirectStandardInput = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.EnvironmentVariables['PATH'] = $Dir + ';' + $env:PATH
  $info.EnvironmentVariables['P19A_LOG'] = $Log
  $info.EnvironmentVariables['P19A_STUB'] = 'p19adiffstub'
  $info.EnvironmentVariables['P19A_AMP'] = 'x & p19adiffstub b'
  $p = [Diagnostics.Process]::Start($info)
  $p.StandardInput.Close()
  $stdout = $p.StandardOutput.ReadToEndAsync()
  $stderr = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit(10000)) {
    # `start /b /wait cmd/c x` has hung here on a runner, and one line must not cost
    # the fixtures after it. What it means for the reader is decided by the caller.
    try { $p.Kill() } catch { }
    if (Test-Path -LiteralPath $Log) { return $true }
    return $null
  }
  $null = $stdout.Result
  $null = $stderr.Result
  return (Test-Path -LiteralPath $Log)
}

function Test-Cmd {
  $dir = Join-Path $Work 'cmd'
  New-Item -ItemType Directory -Path $dir | Out-Null
  $log = Join-Path $Work 'stub.log'
  [IO.File]::WriteAllText((Join-Path $dir 'p19adiffstub.cmd'), "@echo ran>>`"%P19A_LOG%`"`r`n", [Text.Encoding]::ASCII)
  [IO.File]::WriteAllText((Join-Path $dir 'p19a-probe.txt'), "probe`r`n", [Text.Encoding]::ASCII)
  $fixtures = @($Fixtures.cmd)
  $reads = Read-Lines @($fixtures | ForEach-Object { @{ dialect = 'cmd'; line = $_.line } })
  $compared = 0
  for ($i = 0; $i -lt $fixtures.Count; $i++) {
    $line = $fixtures[$i].line
    $shown = ($line -replace "`n", '\n')
    $over = $fixtures[$i].PSObject.Properties.Name -contains 'over'
    $ran = Invoke-CmdLine $line $dir $log
    $read = [bool]$reads[$i].sees_stub
    $noted = $null -ne $reads[$i].note
    if (-not $noted) { $compared++ }
    if ($null -eq $ran) {
      # No answer from the shell. Only a line the reader saw through is safe.
      if ($read -or $noted) {
        Write-Output "did not finish on cmd, and the reader judged the stub: $shown"
      } else {
        Add-Failure "cmd: it did not finish, and the reader did not see the stub: $shown"
      }
    } elseif ($ran -and -not $read -and -not $noted) {
      Add-Failure "cmd, a bypass: it ran the stub and the reader did not see it: $shown"
    } elseif (-not $ran -and $read -and -not $over) {
      Add-Failure "cmd: the reader saw a stub that did not run, and this is no documented over-read: $shown"
    } elseif ($ran -and -not $read) {
      Write-Output "noted, denied at the hook under cmd alone: $shown :: $($reads[$i].note)"
    }
  }
  Write-Output "cmd: compared $compared of $($fixtures.Count) lines"
  if ($compared -lt $CmdFloor) {
    Add-Failure "cmd: compared only $compared lines, under the floor of $CmdFloor"
  }
}

function Test-Paths {
  $fixtures = @($Fixtures.paths)
  $reads = Read-Lines @($fixtures | ForEach-Object { @{ dialect = 'path'; line = $_.raw } })
  $fold = { param($p) $p.Replace('\', '/').TrimEnd('/').ToLowerInvariant() }
  $cygpath = Get-Command cygpath -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $cygpath) {
    # Git for Windows has it, off PATH on some images.
    $inGit = Join-Path $env:ProgramFiles 'Git\usr\bin\cygpath.exe'
    if (Test-Path -LiteralPath $inGit) { $cygpath = Get-Command $inGit }
  }
  # The reader's working directory is C:\, so GetFullPath needs the same.
  $here = [Environment]::CurrentDirectory
  [Environment]::CurrentDirectory = 'C:\'
  try {
    for ($i = 0; $i -lt $fixtures.Count; $i++) {
      $raw = $fixtures[$i].raw
      $mine = [string]$reads[$i].path
      $want = switch ($fixtures[$i].reference) {
        'fullpath' { [IO.Path]::GetFullPath($raw) }
        'cygpath' {
          if ($null -eq $cygpath) { Add-Failure 'cygpath is not on PATH'; $null }
          else { & $cygpath.Source -w $raw }
        }
        default { $null }
      }
      if ($null -eq $want) {
        Write-Output "report only: $raw reads as $mine"
      } elseif ((& $fold $want) -cne (& $fold $mine)) {
        Add-Failure "path: $raw is $want, and the reader says $mine"
      }
    }
  } finally {
    [Environment]::CurrentDirectory = $here
  }
}

try {
  Write-Output "PowerShell $($PSVersionTable.PSVersion)"
  Test-PowerShell
  Test-DocumentedLines
  Test-Aliases
  Test-Cmd
  Test-Paths
} finally {
  Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:Failures.Count -gt 0) {
  Write-Output "$($script:Failures.Count) mismatches between saiife's readers and the real shells"
  exit 1
}
Write-Output 'the readers agree with the real shells on every fixture'
# The runner ends the step with `exit $LASTEXITCODE`.
exit 0
