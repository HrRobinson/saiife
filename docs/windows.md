# saiife on Windows

**Nothing here has run on a real Windows machine yet.** The code was compiled for
Windows and its pure logic was tested on Linux. The first real run is the
`windows-latest` CI job, including the check of the readers against real
PowerShell and cmd. Until that job is green, treat all of this page as designed
behaviour, not observed behaviour.

Supported: Windows 11 23H2 (build 22631) or later and Windows Server 2022 (build
20348) or later, on x64 and ARM64. Windows 10 is not supported.

## Developer mode

Developer mode needs no administrator rights. Download `install.ps1` from a release,
read it, then run it:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

It checks the zip against the release's `SHA256SUMS` and installs `saiife.exe` to
`%LOCALAPPDATA%\Programs\saiife\bin`, adding that folder to your user `Path` once.
Do not pipe it into `Invoke-Expression`. The zip's Authenticode signature is
checked too; a build that is not signed installs with a warning, and until the
project has a signing identity the signer's name is not pinned.

Then run `saiife init` in a project, as on the other platforms. The hook is
`saiife check --hook-exit --agent <agent>`, found through `Path`, in Git Bash,
PowerShell and cmd alike.

The audit log is in `%LOCALAPPDATA%\saiife\audit`, not the roaming `%APPDATA%`, so
a roaming profile never syncs it. Its files get no ACL of their own: they rely on
your profile's `AppData\Local` allowing only you, SYSTEM and Administrators.
`SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` still win.

A project hooked before this version needs `saiife init` once: the old matcher does
not include the `PowerShell` tool, so those calls skip the hook. `saiife status`
warns `hook matcher predates the PowerShell tool; run saiife init to update`.

Developer mode on Windows has the same trust model as on other platforms: it stops
mistakes and helpful bypasses, not a determined agent running as you. See
[threats](threats.md#setup-developer).

## Shells and the guard

The guard reads a command the way the shell that will run it reads it:

| Call | Read as |
|---|---|
| Claude Code `Bash` | POSIX (on Windows this is Git Bash) |
| Claude Code `PowerShell` | PowerShell, on every OS |
| Codex `Bash`, Gemini CLI `run_shell_command`, on a Windows host | PowerShell and POSIX; the stricter verdict wins. A third cmd reading can add a deny |
| An unknown or renamed shell tool on a Windows host | Same as Codex and Gemini CLI |

Cmdlets, their aliases and cmd builtins are translated to their POSIX equivalents
(`Remove-Item -r -fo x` is `rm -r -f x`, `rd /s /q x` too), so the packs apply
as they are. The packs' Windows rules (drive roots, `format`, `reg`, `icacls`,
`sc`, `taskkill` and the rest) are compiled only on Windows, whichever shell a line
comes from, Git Bash included. Linux and macOS never compile them, and WSL counts as
Linux. Parameters match by unambiguous prefix. `powershell -c`,
`-EncodedCommand`, `cmd /c`, `iex` of one literal string, `Invoke-Command
-ScriptBlock` and `& { … }` are judged inside. `wsl CMD` is judged as a POSIX line.
A program is judged by its name, without directory or extension, in every shell:
`rm.exe`, `git.cmd` and `C:\Git\usr\bin\cat.exe` are `rm`, `git` and `cat`, past
`sudo`, `env` and the other wrappers too. A Windows tool's `-x` is its `/x`.

A value PowerShell computes is unknown, not the words it is written in: `('.en'+'v')`,
`'{0}'-f'x'`, `'x'[0]` and `'x'.Trim()`. Only a bracket of whole quoted words is read
as those words (`('.env')`, `('a','b')`). On a path that is a deny, and so it is on an
argument of a command a pack names (`saiife ('in'+'it') --off`, `Stop-Process -Name $x`).

Paths are folded to one spelling before the path rules run: `\` and `/`, drive
case, `\\?\C:\`, `\\localhost\c$\`, `/c/` and `/cygdrive/c/`, trailing dots and
spaces, and `::$DATA`. `~`, `$HOME`, `$env:USERPROFILE` and `%USERPROFILE%` all mean
your profile.

What happens when the guard cannot judge something:

| Case | Developer mode |
|---|---|
| The PowerShell or cmd reader cannot read the line (`$x` as a path, `.ps1` scripts, .NET calls, `Set-Alias`), under the PowerShell tool or the PowerShell reading of a Codex or Gemini CLI call | denied, and recorded as a deny |
| A broken payload from the PowerShell tool | `error_denied` |
| Out of time, or a panic | `error_allowed`. A rule that matches the remaining segments of a line still denies it |
| A shell line over 256 KiB | `error_denied`, and the agent is told to split it |
| From Git Bash, a nested `powershell`, `pwsh` or `cmd` the reader cannot read (`-File x.ps1`, `-enc` that does not decode, a .NET call) | denied, and recorded as a deny |
| A shell with no command to read, so it runs its stdin (`echo x \| cmd`, `cat f \| bash`, `cmd < f`), or `wsl` with an option the guard does not know | denied, and recorded as a deny |
| A note from the POSIX reading itself, or from the cmd reading under Codex and Gemini CLI | `error_allowed` |

## Limits

- **Nothing has run on real Windows until CI does.** The readers' grammar comes from
  documentation and reasoning. `scripts/differential-windows.ps1` compares them
  with `[System.Management.Automation.Language.Parser]::ParseInput` and with
  harmless `cmd.exe` probes on `windows-latest`. It covers the assumptions listed
  in the script, not all of PowerShell.
- **Same-line reassignment is not resolved.** `export HOME=/tmp/x; cat ~/id_rsa` and
  `USERPROFILE=/tmp/x; cat $USERPROFILE/id_rsa` are judged with the old value, so a
  rule on `~/.ssh` can miss what really gets read. This is true on Linux and macOS
  too.
- **`eval 'cd ...'` is not tracked.** In `eval 'cd ~/.ssh' && cat id_rsa`, the guard
  does not carry the `cd` back out, so `id_rsa` is read as relative to the old
  directory. This is true on Linux and macOS too.
- **A dead mapped drive can stall into a recorded allow.** The hook resolves paths
  through the filesystem. If a mapped drive or a local symlink to a share hangs, the
  call runs out of time and, in developer mode, is allowed and recorded as
  `error_allowed`. A hung NFS mount does the same on Linux. The record shows it.
  So can a very long line, unless a rule matches a segment of it.
- **It blocks more than it should in places.** A command with no entry in the
  guard's table is treated as reading every path-shaped word it is given.
  `Test-Path .env` is denied, as are `npm run x .env`, `node ./x/.env` and a bare
  drive-shaped word such as `tool h:mm`. An agent is refused and tries another way.
- **UNC paths are lexical.** The hook does not touch a host named in a command, so a
  symlink on a share is not resolved: `\\host\share\link` is judged as written.
  `\\localhost\c$\…` and `\\127.0.0.1\c$\…` are read as `C:\…`.
- **Some writers are judged as reads.** `Start-BitsTransfer -Destination`,
  `Export-Certificate` and `Save-Module` get only a read of their paths, so a rule
  that blocks writes and not reads does not see them.
- **`pwsh -c '...'` from the `Bash` tool on Linux and macOS is not read inside at
  all,** and neither is `cmd` or `wsl`: those verdicts stay what they were before
  Windows support. On a Windows host all of them are read, and what cannot be read is
  denied.
- **Some wrappers are not read, on any OS.** `find . -exec cat .env \;`, `$(echo cat)
  .env` and `busybox rm -rf /` are not judged as the command they run. On Windows,
  add `git-bash -c ...` and a distro's own launcher (`ubuntu run ...`).
- **`wsl` under the readers is denied whatever follows,** `wsl --list` included. Only
  from Git Bash is it read, and `wsl --shutdown` is denied there, as an option the
  guard does not read.
- **`set NAME` in cmd is denied,** as `set` is: it prints every variable that starts
  with `NAME`, so it is a wildcard on the environment. `Get-Item Env:X` is allowed.
  `dir env:` is denied on Windows only. The `PowerShell` tool on Linux and macOS
  keeps its old verdict.
- **Out of scope for the readers:** aliases and functions defined in the same
  command (`Set-Alias`, `function f {…}`), the contents of `.ps1` scripts, .NET calls
  (`[IO.File]::Delete(…)`) and COM objects. Under the PowerShell reading these are
  denied rather than read. Under cmd only, on a Codex or Gemini CLI call, they
  are recorded.
- **Agents.** Every Windows lock label is `unverified`, and which shells Codex and
  Gemini CLI use comes from their docs, not a run.

## Speed

The hook is slower on Windows than on Linux and macOS, whose budget stays 50 ms p95.
On the GitHub `windows-latest` runner, starting any process costs 20.3 ms (median),
`saiife --version` 26.9 ms, and the hook 84.7 ms (median) and 90.4 ms (p95). With no
code change, runner noise has since moved that p95 from 83-87 ms to 102-114 ms. So the
owner set the Windows CI budget to 130 ms p95, which allows for slow runners. The
planned speed-up should tighten it; no figure is promised.

## Approvals in locked mode

**Same-user approval is off on Windows, as on macOS.** Approvals need a second account.
`same_user = "reauth"` acts as `"deny"`, and saiife never asks for or handles your Windows
password. See [approvals](approvals.md#windows).

The second account must approve **from a separate session**. `runas /user:approver` on the
agent's desktop does not count: anything the agent's user runs can capture what is typed
there. OpenSSH is probably refused, because the control pipe denies network logons. Switching
user and RDP should work, but **neither has been verified**.

## Locked mode

Locked mode on Windows is plan 19b. It is not available yet: `saiife system install`
is refused on Windows. The design is in the v2 spec, section 5.3a.
