# saiife on Windows

**What has run, and where.** saiife on Windows has run only on throwaway CI runners:
GitHub's `windows-latest`, `windows-2022` and `windows-2025`. They are Windows Server,
x64, with an administrator and UAC off. Nothing here has run on a person's Windows 11
machine or on ARM64. **Windows locked mode is a preview**: see
[Locked mode](#locked-mode) for why.

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

### In locked mode

- **Windows locked mode is a preview.** A process of the agent's own user has full
  access to the hook. It can end it with `TerminateProcess(hook, 0)`. For Claude Code
  the co-signer then denies the call. For Codex and Gemini CLI the call runs, and the
  daemon writes a `no_verdict` record. It can also forge the hook's allow, with no code
  injection: any process of the agent's user can open the pipe, send `hook.begin`, bind
  the call's key and append an allow, then end the real hook. The co-signer sees a
  recorded allow and accepts it. Code injected into the hook can do the same. Nothing
  stops that, not even the co-signer (see [Locked mode](#locked-mode)). This is the same class as running its
  own code outside the hook ([threats](threats.md), A21 and A25). Locked mode stays a
  preview until a later plan has the service judge each input itself.
- **The co-signer port.** The co-signer listens on `127.0.0.1:7433`, a fixed port. If
  another program holds it, Claude Code blocks every call and `doctor` fails
  `cosign.listen`. The service binds it so that no other program can share it, but
  while the service restarts (one second) a process of the agent's user could take it.
- **Codex and Gemini CLI.** Their fail-open gaps (the
  [fail-closed matrix](threats.md#fail-closed-matrix)) apply on Windows too, and their
  Windows hook shells come from their docs, not a run. Their Windows hooks are preview.
- **Lock labels.** Every Windows lock label is `unverified` until
  `scripts/lock-check/windows-vm.ps1` has run in a VM ([lock checks](lock-check.md#windows-in-a-throwaway-vm)).
  Until then each agent falls back to the Developer column for the hook rows.
- **OpenSSH sessions are probably denied.** The control pipe denies network logons
  (`NU`), and an OpenSSH logon is probably a network logon. An agent or an approver in
  an OpenSSH session then cannot reach the daemon, and its hooks deny. Not verified.
- **Restricted and low-integrity tokens keep their other groups.** Such a token is
  never counted as an admin. But it still holds the user's other groups, so a
  `group:<name>` rule in the policy (approvers, admins, scopes) still matches it.
- **Switching user and RDP** for approvals are not verified.
- **Session attribution** is by process name only. Windows gives no start time for a
  process, so a reused pid cannot be told apart. Nothing is allowed because of it.
- **Not on Windows:** the MCP gateway, the egress recipe and `syslog` to a local
  socket.
- **Where it ran.** Only on GitHub's Windows Server runners, x64, elevated, UAC off.
  ARM64 is built but its locked flow is not tested. A signed MSI and a real Intune or
  GPO rollout are not tested.

### In the guard

- **The readers come from documentation.** The readers' grammar comes from
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

## Speed

The hook is slower on Windows than on Linux and macOS, whose budget stays 50 ms p95.
On the GitHub `windows-latest` runner, starting any process costs 20.3 ms (median),
`saiife --version` 26.9 ms, and the hook 84.7 ms (median) and 90.4 ms (p95). With no
code change, runner noise has since moved that p95 from 83-87 ms to 102-114 ms. So the
owner set the Windows CI budget to 130 ms p95, which allows for slow runners. The
planned speed-up should tighten it; no figure is promised.

## Locked mode

Locked mode on Windows is plan 19b (v2.2). The design is in the v2 spec, section
5.3a.

**Windows locked mode is a preview.** A process that runs as the agent's own user can
end the hook with `TerminateProcess(hook, 0)`. The agent reads exit 0 as allow. Before
plan 20 the call the hook was judging then ran, and nothing was recorded: on
`windows-2022` and `windows-2025` the audit had the same size before and after. The
agent's user may do this because Windows gives a user full access to its own processes.
On Linux and macOS a kill cannot choose the exit code, so a killed hook does not read as
allow there. Use Windows locked mode against mistakes and helpful bypasses. Do not rely
on it against an agent that writes and runs its own code to get past the hook.

Plan 20 narrows this, and does not close it:

- **Claude Code** has a second managed hook, an HTTP hook to the daemon's co-signer on
  `127.0.0.1:7433`. The co-signer denies the call unless the command hook recorded an
  allow for it. A killed hook records nothing, so the call is denied.
- **Every agent:** the daemon notices a hook that ends without a verdict and writes a
  `hook` record with decision `no_verdict`. `doctor` warns (`hooks.no-verdict`). There is
  no automatic lockdown. For Codex and Gemini CLI that is all: the call still runs.
- **Not prevented:** a forged allow. It needs no code injection: any process of the
  agent's user can open the pipe, send `hook.begin`, bind the call's key and append an
  allow, then end the real hook. Code injected into the hook (the agent's user may write
  to the hook's memory) can do the same. Either way the co-signer sees a recorded allow
  and accepts it. Windows locked mode stays a preview until the service
  judges each co-signed input itself.

### Install

Install from an elevated terminal (Run as administrator), or with the MSI
([fleet](fleet.md#windows)):

```powershell
saiife system install
```

From a terminal that is not elevated it refuses: `run this from an elevated terminal
(Run as administrator)`, exit 2. It also refuses when the registry does not put the
system folders at `C:\Program Files` and `C:\ProgramData`, and it installs only a
release build. It changes nothing until every check has passed.

What it makes:

| What | Where |
|---|---|
| The binary the hooks run | `C:\ProgramData\saiife\bin\saiife.exe` |
| Config, policy and the install record | `C:\ProgramData\saiife\etc\config.toml`, `…\etc\policy.d`, `…\etc\installed.toml` |
| State and keys | `C:\ProgramData\saiife\state`, `…\state\keys\vault.key`, `…\state\keys\audit.ed25519` |
| Audit and the daemon's log | `C:\ProgramData\saiife\log\audit`, `…\log\daemon\daemon.log` |
| The service | `saiifed` ("saiife daemon"), auto start, as the virtual account `NT SERVICE\saiifed` |
| The control endpoint | the named pipe `\\.\pipe\saiife` |
| Claude Code's managed hooks | `C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json` (and `60-saiife-mcp.json`) |
| Codex's managed hooks | `C:\ProgramData\OpenAI\Codex\requirements.toml` |
| Gemini CLI's managed hooks | `C:\ProgramData\gemini-cli\settings.json` |

The managed hook command is
`C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent <agent>`. It
has forward slashes and no spaces, so Git Bash, PowerShell and cmd all run it as
written. That is why the binary is not under `C:\Program Files`.

### How the lock holds

- **Files.** Every path install makes gets an owner and a protected access list, so
  nothing is inherited from `C:\ProgramData`. Only SYSTEM and Administrators can write.
  Users can read and run the binary and the config. The service can write its state and
  the audit. `saiife doctor` reads each list back and compares it with the spec.
- **The service.** It runs as `NT SERVICE\saiifed`, which has its own SID, no password
  and no interactive logon. It restarts one second after any failure, without end.
  Only SYSTEM and Administrators can stop, reconfigure or delete it: CI checked that a
  plain user cannot. While it is down, every hook denies.
- **The pipe.** Its access list denies network logons and lets users connect, but not
  add a server instance. The daemon creates the first instance. If someone else holds
  the name, the daemon refuses to start and logs `pipe \\.\pipe\saiife exists and is not
  ours; refusing to start`, and the hooks deny meanwhile. A client checks that the
  pipe's owner is the service before it sends a byte.
- **Who is calling.** The daemon reads the caller's SID and groups from its token. A
  caller counts as an admin only at High integrity or above with no restricted SIDs.
  Every audit record carries the caller's `sid`. The `uid` in records and policy is a
  label made from the SID: 0 for SYSTEM and elevated admins, a hash otherwise. Policy
  names users as `name` or `DOMAIN\name`, matched by SID.
- **Code injected into the hook.** Release builds link the C runtime statically and load
  DLLs only from System32, and `doctor` checks that. CI planted DLLs beside a copy of
  `saiife.exe`; none was loaded.
- **The gateway.** There is no `gateway.sock`. The loopback TCP gateway is opt-in with
  `[gateway] tcp`, as on Linux. `saiife api` and `saiife mcp` use the pipe. The MCP
  gateway is Linux only ([MCP](mcp.md)).

### Doctor, uninstall, upgrades

- `saiife doctor`, from an elevated terminal, checks the service, the access lists, the
  binary (build, load flag, imports, signature), the managed files, Claude Code's
  `HKLM\SOFTWARE\Policies\ClaudeCode` key, UAC and the agent users. It prints
  `locked.preview` on every locked run. Some Linux checks have no Windows form yet, and
  `doctor` lists them.
- `saiife system uninstall` removes the service and the managed files and keeps the
  audit and the config. `--purge` removes the rest, but keeps `C:\ProgramData\saiife` while
  a managed file still names the binary, so that no user can put a file there that a
  hook would run.
- The MSI, Intune and GPO: see [fleet](fleet.md#windows).

### What CI tests

The `locked-windows` job runs on `windows-2022` and `windows-2025`, elevated. It
installs, reads every access list back, runs hooks as a second, standard user, checks
that hooks fail closed when the daemon is down or the pipe is squatted, approves from a
third account, turns lockdown on and off, and uninstalls. It also runs the attacks
below as the standard user, and records what they did. The `package-windows` job
installs, upgrades and removes the MSI, and forces a failure to check the rollback.

What the attacks did on both runners:

| Attack, as the agent's user | Result |
|---|---|
| `TerminateProcess(hook, 0)` on a hook it started | before plan 20: the call is allowed; nothing is recorded. With the co-signer: the co-sign request gets a deny, and a `no_verdict` record is written |
| `DefineDosDevice` to point `C:` at its own folder | refused (error 5) |
| A DLL planted beside a copy of `saiife.exe` | not loaded |
| Open `saiife.exe` or `config.toml` with share mode 0 | the open works; hooks still work |
| Stop, reconfigure or delete the service | refused |

In CI the second test account could also end the agent's hook. That is a property of
the test, not a hole: both accounts were started with `CreateProcessWithLogonW` from
one runner session, so both carry that session's logon SID (`S-1-5-5-0-…`), and the
hook's default access list grants that SID the right to end it. Two people logged in
separately do not share a logon SID.

## Approvals

**Same-user approval is off on Windows, as on macOS. Approvals need a second account,
from a separate session.** `same_user = "reauth"` acts as `"deny"`. There is no password
prompt and no re-authentication: saiife never asks for or handles your Windows password.
See [approvals](approvals.md#windows).

`runas /user:approver` on the agent's desktop does not count: anything the agent's user
runs can capture what is typed there. OpenSSH is probably refused, because the control
pipe denies network logons. Switching user and RDP should work, but **neither has been
verified**.

## Personal broker

`saiife daemon --user` runs on Windows too, as your own account. It is not a security
boundary, as on the other platforms: see [personal broker](personal-broker.md).

| What | Where |
|---|---|
| Config, state and audit | `%LOCALAPPDATA%\saiife\personal\config.toml`, `…\state`, `…\audit` |
| The endpoint | the pipe `\\.\pipe\saiife-user-<your SID>`, owned by your SID, open to your SID only |
| The vault key | a Credential Manager generic credential, `saiife:vault-key`, kept on this machine only (never roaming) |
| Start at logon | `saiife daemon --user --autostart on` sets the value `saiife-broker` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`; `off` removes it |

There is no `gateway.sock`: use `saiife api` or `saiife mcp`. `--print-unit` is for
systemd and launchd only. The broker refuses to run as a virtual or service account.

## Disk encryption

The vault key (`C:\ProgramData\saiife\state\keys\vault.key`) and the audit are protected
on a running machine by their access lists. Turn on BitLocker to protect them in backups,
disk images and on a stolen disk. `doctor` does not check BitLocker; it prints one
`disk.encryption` line that points here. DPAPI is not used, because install runs as an
admin and cannot seal a key for the service account.
