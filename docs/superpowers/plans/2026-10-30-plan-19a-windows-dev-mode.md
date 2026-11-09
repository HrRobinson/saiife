# Plan 19a — Windows, part 1: developer mode and the groundwork Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** saiife's developer mode (v1: the project hook guard and the masked JSONL audit) works on Windows 11 and Windows Server 2022 or later, on x64 and ARM64, for Claude Code, Codex and Gemini CLI. The guard reads PowerShell and cmd commands and Windows paths. Signed release zips and an `install.ps1` ship. The spec gains its Windows section, and the groundwork for locked mode (plan 19b) lands: the `saiife-win` crate, the Windows-target check and a `windows-latest` test cell.

**Architecture:**
- **Two plans.** 19a needs no admin rights anywhere and ships developer mode. Plan 19b (`2026-10-30-plan-19b-windows-locked-mode.md`) builds locked mode on top. Both plans share one set of decisions, written here in Global Constraints and copied into the spec by Task 1.
- **The guard learns two more shell dialects.** A PowerShell reader and a cmd reader turn their command text into the same `Segment`s the POSIX lexer produces. They translate the cmdlets and builtins that the v1 packs care about into their POSIX equivalents (`Remove-Item -Recurse -Force` becomes `rm -r -f`). So every existing pack rule applies, and the engine is unchanged.
- **Windows paths are canonicalized before path rules run.** One pure function handles drive letters, both slashes, case, `\\?\`, Git Bash `/c/`, alternate data streams, trailing dots and spaces, and the `USERPROFILE` spellings. Linux tests run all of it.
- **No FFI in 19a.** `saiife-win` starts with pure modules only: SID math and an SDDL reader. Its FFI module arrives in 19b.

**Tech Stack:** Rust workspace. No new third-party crates in 19a. New: `crates/win` (`saiife-win`, pure code only in 19a), `install.ps1`, `scripts/check-windows.sh`, `scripts/fake-cc.sh`. GitHub Actions `windows-latest`.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md` (v2) and `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` (v1). Windows has no spec section yet. Task 1 adds it from the decisions below. This plan covers:
- v1 developer mode on Windows (v1 §9.6 listed Windows as out of scope; Task 1 notes the change);
- the new v2 §5.3a (all of it is written now, as §5.3 was written before macOS was built), §1.4, D21;
- §4.2 (the new crate), §13 (the Windows test cell), §14 (release artifacts).

Plan 13 (macOS) sets the style and the patterns.

## Consumes (verify at build time)

- **Plan 13 must be merged first.** It provides:
  - `saiife_system::Platform { Linux, Macos }`, `Platform::current()`, `Platform::name()`, and `Layout::under_for`;
  - `scripts/check-unsafe.sh` and the workspace rule that every crate root has `#![forbid(unsafe_code)]` except `crates/darwin`;
  - the `cfg(unix)` gates on the daemon, IPC client, hook and CLI clients;
  - the release workflow's `startsWith(github.ref, 'refs/tags/v') && secrets.X || ''` pattern for signing secrets;
  - `lock::label_for(agent, macos: bool)`. This plan changes it to take a `Platform`-like argument (Task 8).

  Where plan 13 landed different names, plan 13 wins and this plan is adjusted before its task starts.
- **v1 code:** `saiife_guard::{lexer::{Word, Segment, split_segments_noted}, canon::{PathVars, canonicalize, path_forms, lexical_form}, payload::{classify, ToolCall, inline_payload}, engine::Engine}`; `saiife_agents::{Agent, claude::{MATCHER, MATCHER_V1}}`; `saiife_audit::store`; `scripts/test-install.sh`, `scripts/bench-check.sh`.

## Global Constraints

- **Standing rules (owner):**
  - **No Windows machine is available locally.** Every Windows decision is either a pure function, or sits behind `Platform`, `Host` or `Proc`, so the Linux tests run it. Windows-only code is compile-checked locally (below) and run in CI.
  - **Nothing privileged on the developer machine.** Never run sudo, su, root shells, `sc.exe`, `net.exe`, `icacls`, `takeown`, `reg`, `taskkill`, `runas`, PowerShell admin cmdlets, kill, pkill, killall or pgrep, not even to probe whether they exist. The same goes for `systemctl`, `launchctl` and docker. No writes outside the repo, the scratch dirs and `target/`.
  - In tests, child processes are stopped through their own handle (`Child::kill`), never by name.
  - These tools appear only in production code behind `Host` or `Reauth`, which tests replace with fakes, and in CI-only scripts.
  - **Admin and service tests run only in the `locked-windows` CI job** (plan 19b). In 19a nothing needs admin. CI-only scripts get `bash -n`/`shellcheck` locally, and PowerShell scripts get a parse check only in CI (`pwsh -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile(...)"`).
  - CI job ids contain no dots.
  - **Test isolation:** HOME, USERPROFILE, PATH, `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` point at tempdirs. `TMPDIR` and `SAIIFE_TEST_TMP` point to a short dir from `mktemp -d -p /home/jonas/projects/personal/saiife`, removed afterwards. On Windows CI, `TEMP`, `TMP` and `LOCALAPPDATA` point under `${{ runner.temp }}` too. Never use /tmp, the real home or `~/.claude`. No internet in tests.
  - **Internet:** implementers may use the web only to fetch public reference data: Microsoft Learn pages, the agents' public docs, crate docs and release dates.
- **How Windows code is verified without a Windows machine (checked on 2026-10-30 with rustc 1.99.0):**
  - `rustup target add x86_64-pc-windows-msvc` works on Linux; `cargo check` needs no linker.
  - One dependency, `ring` 0.17.14, runs a C build script. It fails without a C compiler for the target. With a fake compiler it passes. The check command is:

    ```bash
    CC_x86_64_pc_windows_msvc="$PWD/scripts/fake-cc.sh" AR_x86_64_pc_windows_msvc="$PWD/scripts/fake-cc.sh" \
      RUSTFLAGS="-D warnings" cargo check --workspace --all-targets --target x86_64-pc-windows-msvc
    ```

    Task 2 wraps it as `scripts/check-windows.sh`. `windows-sys` and the other pure-Rust Windows crates check fine this way.
  - On `main` (838a318) today, every library crate except `saiife-system` and `saiife-broker` already checks clean for that target. The failures are unix-only test helpers (`saiife-guard`, `saiife-agents`) and unix metadata calls (`saiife-system`: 113 errors; `saiife-broker`: 5 errors in `manifest.rs`). Task 3 fixes them.
  - Tests that need Windows but no admin run in the CI `test` job on `windows-latest`. Admin tests run in `locked-windows` (19b).
- **Unsafe boundary (decision W1):**
  - **A new crate, `crates/win` (`saiife-win`), is the second crate allowed to use `unsafe`**, after `saiife-darwin`. It mirrors `saiife-darwin`.
  - `unsafe` may appear only in `crates/win/src/ffi/*.rs`, and only under `cfg(windows)`. The crate root has `#![cfg_attr(not(windows), forbid(unsafe_code))]` and `#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]`. Every `unsafe` block has a `SAFETY:` comment. Every handle and every `LocalFree`/`NetApiBufferFree`/`CredFree` buffer is owned by a small RAII guard.
  - Its FFI dependency is `windows-sys = "=0.61.2"`, already in Cargo.lock. It is a target dependency under `cfg(windows)` only.
  - Why our own crate: no safe crate covers named-pipe client identity, SDDL ACLs and local group lookups together. Two needs do have safe crates, and those are used instead of FFI: `windows-service` (the SCM: create, configure, start, stop, delete, the dispatcher) and `winreg` (registry reads). `std` covers the pipe client open (`OpenOptionsExt::security_qos_flags`), reparse-point checks (`MetadataExt::file_attributes`) and `fs::canonicalize`. `rpassword` reads the console password.
  - **The complete list of FFI calls** (19b adds them, each in `crates/win/src/ffi/<area>.rs`; no other call may be added without updating this list and the spec):

    | Area (file) | Calls |
    |---|---|
    | Security descriptors (`sd.rs`) | `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `GetSecurityDescriptorOwner`, `GetSecurityDescriptorDacl`, `LocalFree` |
    | File ACLs (`acl.rs`) | `GetSecurityInfo`, `SetSecurityInfo` (each on a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT` and checked, so a final reparse point swapped in cannot redirect them), `GetFileInformationByHandle` (on the same handle before `SetSecurityInfo`: a non-directory with `nNumberOfLinks != 1` is refused, so a hard link cannot redirect a set to its target), `GetFinalPathNameByHandleW` (on the same handle before `SetSecurityInfo`: the path Windows opened must be the path asked for, so a junction swapped in higher up cannot redirect a set), `CreateDirectoryW` (with a descriptor) |
    | SIDs, accounts, local groups (`account.rs`) | `ConvertSidToStringSidW`, `ConvertStringSidToSidW`, `LookupAccountNameW`, `LookupAccountSidW`, `NetUserGetLocalGroups`, `NetLocalGroupGetMembers`, `NetApiBufferFree` |
    | Tokens (`token.rs`) | `GetCurrentProcess`, `OpenProcessToken`, `GetCurrentThread`, `OpenThreadToken`, `GetTokenInformation` (`TokenUser`, `TokenGroups`, `TokenIntegrityLevel`, `TokenRestrictedSids`), `CloseHandle` |
    | Pipes (`pipe.rs`) | `tokio::net::windows::named_pipe::ServerOptions::create_with_security_attributes_raw` (an `unsafe fn` of tokio), `GetNamedPipeClientProcessId`, `ImpersonateNamedPipeClient`, `RevertToSelf`, `GetSecurityInfo` (the pipe owner, client side) |
    | Process list (`proc.rs`) | `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW` |
    | Signature check (`trust.rs`) | `WinVerifyTrust` |
    | Personal broker keychain (`cred.rs`) | `CredReadW`, `CredWriteW`, `CredDeleteW`, `CredFree` |
    | Process setup and disk (`process.rs`) | `SetDefaultDllDirectories`, `SetStdHandle`, `GetDiskFreeSpaceExW` |
    | Worker job (`job.rs`) | `CreateJobObjectW`, `SetInformationJobObject` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), `AssignProcessToJobObject`: the managed hook's eval worker dies with the hook |
    | Sockets (`net.rs`, plan 20) | `setsockopt` (`SO_EXCLUSIVEADDRUSE`): the Claude Code co-signer's listener takes `127.0.0.1:7433` for itself before it binds |
    | Service entry (`service.rs`) | the `extern "system"` entry that `windows_service::define_windows_service!` expands to (its expansion contains `unsafe`, so the macro may be used only here) |

    That is 42 functions and one macro (`GetSecurityInfo` is listed twice), all in `crates/win/src/ffi/`: 41 `windows-sys` calls and the tokio call. The tokio call needs the crate feature `pipe-server` (`tokio` with `net`), which only `saiife-daemon` enables. So `saiife-win` stays tokio-free on the hook path.
  - `scripts/check-unsafe.sh` (plan 13) is extended: `unsafe` is allowed in `crates/darwin/` and in `crates/win/src/ffi/`, nowhere else. The crate-root rule accepts `crates/win/src/lib.rs` with its `cfg_attr` form. On Windows the crate denies `unsafe_code`, and one `#![allow(unsafe_code)]` at the top of `crates/win/src/ffi/mod.rs` covers `ffi`.
- **Tokio-free:** `guard`, `audit`, `policy`, `ipc`, `system`, `mcp`, `darwin` and `win` (without `pipe-server`) stay tokio-free. The CI gate `no tokio in hook crates` adds `-p saiife-win` and also runs on `windows-latest`.
- **Hook budget:** the hook path may cost at most +1 ms against `main` on Linux (`scripts/bench-check.sh`). On `windows-latest`, the developer hook's p95 must be under the 50 ms budget (D10), measured with `BENCH_MAX_P95_MS=50` (Task 10). If the runner cannot meet it, that is an owner decision, not a silent raise.
- **Commits:**
  - the branch is `plan-19a-windows-dev` from `main` after plan 13 merges;
  - each task is committed with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
  - never commit `.superpowers/`;
  - `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`;
  - no tags.
- **Decisions both plans rely on.** Task 1 copies each into the spec. W1 is above. The locked-mode ones (W9–W28) are in plan 19b's Global Constraints and are restated in its tasks.
  - **W2. Windows is a third platform, v2.2.** `Platform` gains `Windows`, with name `"windows"`. Supported: Windows 11 23H2 (build 22631) or later, and Windows Server 2022 (build 20348) or later, on x64 and ARM64. Windows 10 is out: its consumer ESU ended on 2026-10-13. Developer mode is v2.2 too; it needs no admin.
  - **W3. Developer mode audit dir:** `%LOCALAPPDATA%\saiife\audit` (`dirs::data_local_dir()`), not the roaming `%APPDATA%` that `dirs::data_dir()` gives on Windows, so a roaming profile never syncs the audit. Files get no explicit DACL: a profile's `AppData\Local` already allows only the user, SYSTEM and Administrators, which matches the Linux 0700/0600 intent. `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` still win.
  - **W4. Shell dialects.** The guard knows three: `Posix`, `PowerShell` and `Cmd`. The payload picks the dialect:
    - Claude Code `Bash` → `Posix` (on Windows it is Git Bash);
    - Claude Code `PowerShell` → `PowerShell`, on every OS (the tool also exists with `pwsh` on Linux and macOS);
    - Codex `Bash` and Gemini `run_shell_command` on a Windows host → **both** `PowerShell` and `Posix`, and the stricter verdict wins (deny > ask > allow; a rule hit beats no hit). Codex and Gemini run commands through PowerShell on Windows, but Gemini can be pointed at `cmd.exe` through `ComSpec`, so the guard does not rely on it;
    - on Linux and macOS, everything that is not Claude `PowerShell` stays `Posix`, as today.
  - **W5. What the PowerShell and cmd readers cover (the v1 packs' scope on Windows):**
    - Statement splitting on `;`, `|`, `&&`, `||` and newlines (cmd: `&`, `&&`, `||`, `|`), with quoting (`'…'`, `"…"`, backtick escapes; cmd `"…"` and `^`) and redirections (`>`, `>>`, `2>`, `*>`; cmd `>`, `>>`, `2>`), as `Word`s with the same flags the POSIX lexer sets.
    - External programs (`git`, `docker`, `kubectl`, `terraform`, `aws`, `az`, `gcloud`, `psql`, `mysql`, `mongosh`, `saiife`, …) pass through unchanged, with a trailing `.exe` dropped from argv[0] (case-insensitive). The git, cloud, container, db and iac packs then apply as they are.
    - A fixed table translates cmdlets, their aliases and cmd builtins to POSIX equivalents. Names are case-insensitive. PowerShell parameters match by unambiguous prefix (`-r`, `-rec`, `-Recurse`). Only the parameters in the table are translated; others pass through as written.

      | PowerShell (aliases) / cmd | Becomes | Parameters translated |
      |---|---|---|
      | `Remove-Item` (`ri`, `rm`, `rmdir`, `del`, `erase`, `rd`); cmd `del`, `erase`, `rd`, `rmdir` | `rm` | `-Recurse`→`-r`, `-Force`→`-f`, `-Path`/`-LiteralPath`→operand; cmd `/s`→`-r`, `/q` and `/f`→`-f` |
      | `Copy-Item` (`cp`, `copy`, `cpi`); cmd `copy`, `xcopy`, `robocopy` | `cp` | `-Recurse`→`-r`, `-Destination`→last operand |
      | `Move-Item` (`mv`, `move`, `mi`), `Rename-Item` (`ren`, `rni`); cmd `move`, `ren` | `mv` | `-Destination`/`-NewName`→last operand |
      | `Get-Content` (`gc`, `cat`, `type`); cmd `type` | `cat` | `-Path`/`-LiteralPath`→operand |
      | `Set-Content` (`sc` in 5.1), `Add-Content` (`ac`), `Out-File`, `Clear-Content` (`clc`) | a `>` redirect to the path | `-Path`/`-FilePath`/`-LiteralPath`→target |
      | `New-Item` (`ni`, `md`, `mkdir`) | `touch`, or `mkdir` with `-ItemType Directory` | `-Path`→operand |
      | `Get-ChildItem` (`gci`, `ls`, `dir`); cmd `dir` | `ls` | `-Recurse`→`-R` |
      | `Select-String` (`sls`); cmd `findstr` | `grep` | `-Path`→operand |
      | `Set-Location` (`cd`, `sl`, `chdir`), `Push-Location` (`pushd`); cmd `cd`, `chdir`, `pushd` | `cd` | `-Path`→operand |
      | `Stop-Process` (`kill`, `spps`); `taskkill` | `kill` | `-Id`/`/pid`→operand, `-Name`/`/im`→`-n <name>` |
      | `Invoke-WebRequest` (`iwr`, `curl`, `wget` in 5.1), `Invoke-RestMethod` (`irm`) | `curl` | `-Uri`→operand, `-OutFile`→`-o`, `-InFile`→`--data-binary @` |
      | `Start-Process` (`saps`, `start`); cmd `start` | argv `[FilePath, ArgumentList…]` | `-FilePath`, `-ArgumentList` |
      | `$env:NAME = v`; cmd `set NAME=v` | an assignment word `NAME=v` | — |

    - **Nested commands are judged inside,** as `sh -c` is today: `powershell`/`pwsh` with `-Command`/`-c` (the rest of the line), `-EncodedCommand`/`-enc`/`-e` (base64 of UTF-16LE, decoded, at most 64 KiB decoded), `cmd /c` and `cmd /k`, `Invoke-Expression`/`iex` with one literal string, `Invoke-Command -ScriptBlock { … }`, `& { … }` and `. { … }`. A nested string whose dialect is known is read in that dialect.
    - **What the readers cannot see is treated like the POSIX lexer's unresolved substitution** (`Word.has_substitution`), so the engine's existing handling applies (the same outcome `eval "$x"` gets today): `$var` and `$(…)` in a command position or an operand, `& $x`, `iex` of a non-literal, cmd `%VAR%` and `!VAR!`, an `-EncodedCommand` that does not decode, and a here-string with expansions.
    - **Out of scope, written down as limits** (as `cd` tracking is for POSIX in v2 §10): aliases and functions defined in the same command (`Set-Alias`, `function f {…}`), `.ps1` script contents, .NET calls (`[IO.File]::Delete(…)`), COM objects, and the registry provider beyond the core.lock rules below.
  - **W6. Windows paths** (pure, in `saiife-guard`). On a Windows host, each path operand is canonicalized before the path rules run:
    - both `\` and `/` separate; the result uses `/`, with the drive letter lower-cased (`c:/…`);
    - case is folded for matching (NTFS is case-insensitive by default);
    - `\\?\C:\…` and `\\.\C:\…` become `c:/…`; `\\?\UNC\host\share` and `\\host\share` stay UNC, and `\\localhost\c$\…`, `\\127.0.0.1\c$\…` and `\\?\UNC\localhost\c$\…` become `c:/…`;
    - Git Bash `/c/Users/…` and `/cygdrive/c/…` become `c:/Users/…`;
    - each component loses its trailing dots and spaces (Win32 strips them: `.env.` opens `.env`), and an alternate data stream suffix (`:stream`, `::$DATA`, `:$DATA`) is dropped, so `.env::$DATA` is `.env`;
    - `~`, `$HOME`, `$env:USERPROFILE`, `${env:USERPROFILE}` and `%USERPROFILE%` all mean the profile dir, and `$env:LOCALAPPDATA`/`%LOCALAPPDATA%`, `$env:APPDATA`/`%APPDATA%` and `$env:TEMP`/`%TEMP%` are known variables (`PathVars`);
    - when the path exists, `std::fs::canonicalize` resolves 8.3 short names (`PROGRA~1`), junctions and symlinks, as on unix. A path that does not exist keeps its lexical form.
    - Pack globs written with `~/` match profile paths on Windows. A rule written for `/etc/...` simply never matches a Windows path; Windows targets get their own rules (W7).
  - **W7. New pack rules** (each with `[[example]]` lines; all patterns apply on every OS, where they are harmless):
    - `core.filesystem`: recursive `rm` on `c:/`, `c:/windows`, `c:/program files`, `c:/program files (x86)`, `c:/programdata`, `c:/users` or `~`, for any drive letter; `format <drive>:`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`, `Initialize-Disk`, `diskpart`, `cipher /w`, `vssadmin delete shadows`, `wbadmin delete`;
    - `core.secrets`: `cmdkey /list`, `vaultcmd /list…`, `reg save|export` of `HKLM\SAM`, `HKLM\SECURITY` or `HKLM\SYSTEM`; the existing `~/.ssh`, `~/.aws`, `.env` path rules already cover the profile through W6;
    - `core.self`: writes and deletes under `%LOCALAPPDATA%/saiife` (the developer data dir), of the running `saiife.exe`, and of the project hook files;
    - `core.process`: `kill`/`taskkill`/`Stop-Process` of `saiife`;
    - `core.lock` (used in plan 19b): writes, deletes, `icacls`, `takeown` and `Set-Acl` under `c:/programdata/saiife`, `c:/program files/claudecode`, `c:/programdata/openai/codex` and `c:/programdata/gemini-cli`; `sc` or `sc.exe` with `stop|config|delete|failure|sdset saiifed`; `Stop-Service|Set-Service|Remove-Service saiifed`; `net stop saiifed`; `reg add|delete` and `Set-ItemProperty|Remove-ItemProperty|New-ItemProperty` on `HKLM\SOFTWARE\Policies\ClaudeCode`; `net localgroup saiife-audit … /add|/delete`.
  - **W8. Project hooks on Windows.** The project hook command stays `saiife check --hook-exit --agent <a>` through `PATH`; it works in Git Bash, PowerShell and cmd. Claude Code's project matcher gains `PowerShell` on every OS: `MATCHER = "Bash|PowerShell|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit"`. The current value becomes `MATCHER_V2`, and a project hooked with it (or `MATCHER_V1`) is upgraded in place, as plan 2's matcher is today. Claude Code's docs say to match `Bash|PowerShell` in hooks that inspect shell commands.
- **Spec values, verbatim, used by 19a:**
  - Claude Code PowerShell tool: tool name `PowerShell`, `tool_input.command`, on by default on Windows for claude.ai and Console accounts; `CLAUDE_CODE_USE_POWERSHELL_TOOL` (code.claude.com/docs/en/tools, "PowerShell tool");
  - Gemini CLI on Windows runs `powershell.exe -NoProfile -Command` (geminicli.com/docs/tools/shell/);
  - the developer config read by the hook on Windows is `C:\ProgramData\saiife\etc\config.toml` (W9 in plan 19b; the Linux value is `/etc/saiife/config.toml`).
- **References** (public docs; cite them in the spec section):
  - Claude Code settings and managed settings: code.claude.com/docs/en/settings, code.claude.com/docs/en/managed-settings, code.claude.com/docs/en/tools;
  - Codex managed configuration: learn.chatgpt.com/docs/enterprise/managed-configuration (formerly developers.openai.com/codex/enterprise/managed-configuration);
  - Gemini CLI configuration and shell tool: geminicli.com/docs/reference/configuration, geminicli.com/docs/tools/shell/;
  - Microsoft Learn: "Service accounts" (virtual accounts), "Named Pipe Security and Access Rights", `ImpersonateNamedPipeClient`, `GetNamedPipeClientProcessId`, `LogonUserW`, "Security Descriptor String Format", "Credentials Management" (`CredWriteW`), `UserConsentVerifier`, "Win32 app management in Microsoft Intune", "Code signing options for Windows app developers", Azure Artifact Signing quickstart;
  - devblogs.microsoft.com/commandline/af_unix-comes-to-windows (AF_UNIX on Windows has no peer credentials);
  - docs.github.com "About GitHub-hosted runners" (Windows runners run as an administrator with UAC disabled);
  - docs.rs: `windows-service` 0.8.1, `tokio::net::windows::named_pipe::ServerOptions`, `std::os::windows::fs::OpenOptionsExt`;
  - github.com/Azure/artifact-signing-action; docs.firegiant.com/wix/osmf/ (WiX v6+ maintenance fee).

## Review Focus

1. **Odd spellings of a protected Windows path.** `C:\Users\a\.ssh\id_rsa` written as `c:/USERS/a/.SSH/ID_RSA`, `\\?\C:\Users\a\.ssh\id_rsa`, `/c/Users/a/.ssh/id_rsa`, `~\.ssh\id_rsa`, `$env:USERPROFILE\.ssh\id_rsa`, `%USERPROFILE%\.ssh\id_rsa`, `\\localhost\c$\Users\a\.ssh\id_rsa`, and `.env.`, `.env ` and `.env::$DATA` for `.env`. Expected: every form gets the same decision as the canonical path (Task 4: `windows_spellings_canonicalize_alike`, `ads_and_trailing_dots_stripped`, `localhost_admin_share_is_local`).
2. **PowerShell abbreviations and aliases of a destructive delete.** `ri -r -fo C:\`, `rm -Recurse -Force -Path C:\Windows`, `Remove-Item -LiteralPath ~ -Recurse`, `del /s /q C:\` and `rd /s /q C:\Users`. Expected: each is denied by `core.filesystem` (Task 5: `remove_item_forms_translate_to_rm`; Task 7: the pack examples).
3. **Hidden inside another layer.** `powershell -enc <base64 of "Remove-Item -Recurse -Force C:\">`, `pwsh -c "rd /s /q C:\"` (cmd syntax inside PowerShell fails there, but `cmd /c "rd /s /q C:\"` does not), `iex 'Remove-Item -r -fo C:\'`, `Start-Process cmd -ArgumentList '/c rd /s /q C:\'`, and `& { Remove-Item -r -fo C:\ }`. Expected: denied. An `-enc` value that does not decode gets the unresolved-substitution outcome, never a silent allow by parse failure (Task 6: `encoded_command_judged_inside`, `bad_encoded_command_is_unresolved`).
4. **The dialect is not what the guard assumed.** A Codex or Gemini payload on Windows that is really cmd, or really POSIX. Expected: the stricter verdict of the two readings wins. Ordinary commands (`git status; npm test`, `Get-ChildItem -Recurse src`, `dir /s src`) stay allowed under both readings (Task 6: `strictest_of_both_dialects`, `benign_windows_commands_allowed_both_ways`).
5. **A project hooked before this plan, used with Claude Code's PowerShell tool.** The old matcher does not include `PowerShell`, so those calls skip the hook. Expected: `saiife status` warns `hook matcher predates the PowerShell tool; run saiife init to update`, and `saiife init` upgrades the matcher in place without touching other hooks (Task 8: `matcher_v2_project_upgraded`, `status_warns_on_old_matcher`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (spec), Task 2 (crate, gates, Windows check), Task 4 (Windows paths).
- **Wave 2 (parallel):** Task 3 (workspace builds and tests on Windows; needs 2), Task 5 (PowerShell reader; needs 4).
- **Wave 3 (parallel):** Task 6 (cmd reader, nesting, dialect choice; needs 5), Task 8 (agents; needs 3).
- **Wave 4 (parallel):** Task 7 (pack rules; needs 6), Task 9 (release, install.ps1, signing; needs 3).
- **Last:** Task 10 (bench and docs; needs everything), the gates, a whole-branch review, one fix wave, push, PR, CI (with `test (windows-latest)`). The owner merges. No tag.

**Shared files:** `.github/workflows/ci.yml` (Task 2 adds the gates and the Windows check, Task 3 the matrix cell, Task 9 the install test, Task 10 the bench step; separate hunks). `crates/guard/src/payload.rs` (Task 5 adds the tool name, Task 6 the dialect choice).

---

### Task 1: the spec's Windows section and notes

**Files:**
- Modify `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`:
  - **§5.3a "Files and permissions: Windows (v2.2)"**, new, right after §5.3. The section number §5.4 is taken by "How the lock holds", and about 400 references in code and docs point at §5.4–§5.6, so the Windows section is §5.3a. (This is a departure from the request to call it §5.4; it is listed in the departures.)
  - §1.4: replace the bullet `- Windows.` with nothing, and add "Windows locked mode (v2.2)" to the "Designed here, but shipped after v2.0" sentence.
  - §2, D21: the "Chosen" cell becomes `v2.0: Linux with systemd (Ubuntu 22.04+, Debian 12+, RHEL 9+). v2.1: macOS. v2.2: Windows 11 23H2+ and Windows Server 2022+, x64 and ARM64 (§5.3a).` The "Why" cell gains `Windows added on 2026-10-30 (owner decision); until then it was out of scope with no recorded reason.`
  - D8: the daemon user cell gains `NT SERVICE\saiifed (Windows, a virtual service account)`. D9 gains `On Windows: a named pipe, \\.\pipe\saiife, with the client identified by impersonation (§5.3a).` D12 gains `On Windows: C:\ProgramData\saiife\bin\saiife.exe (§5.3a).`
  - §4.2: the crate list gains `win/  NEW (v2.2): Windows FFI, the second crate allowed unsafe (§5.3a)`.
  - §15.2: a row "19a/19b — Windows developer mode, then locked mode (§5.3a)".
- Modify `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` §9.6: a note `Windows developer mode ships in v2.2 (plan 19a; v2 spec §5.3a).`
- Modify `crates/cli/tests/docs_wording.rs` (spec wording guards, if the test reads the spec; otherwise skip this file).

**Interfaces:** Produces the spec anchors that both plans cite: `§5.3a`, `§5.3a.1` (layout), `§5.3a.2` (identity and IPC), `§5.3a.3` (ACLs), `§5.3a.4` (approvals), `§5.3a.5` (guard dialects), `§5.3a.6` (packaging and signing), `§5.3a.7` (what is Linux-only).

- [ ] **Step 1:** write §5.3a from the decisions, as tables in the §5.2/§5.3 style. Its content, by subsection:
  - **5.3a.1 Layout:** W2 and W3 here, and plan 19b's W9 table (paths, the service, the pipe, the managed files, the hook command form).
  - **5.3a.2 Identity and IPC:** plan 19b's W10 (virtual account), W11 (pipe, impersonation, owner check, squatting), W12 (uid mapping, `sid` in records), W13 (gateway on TCP only), W25 (personal broker), W26 (install needs elevation).
  - **5.3a.3 ACLs:** plan 19b's W14 (the SDDL table and the ancestor rule) and W15 (the vault key).
  - **5.3a.4 Approvals:** plan 19b's W16 (same-user approval off, with the reason).
  - **5.3a.5 Guard:** W4–W8 here.
  - **5.3a.6 Packaging and signing:** plan 19b's W20–W23 and W28 (binary hardening), and W1 (the FFI boundary and its call list).
  - **5.3a.7 Linux-only or different:** plan 19b's W17 (session names only), W18 (MCP gateway refused), W19 (`run --secret`/`--cloud` on Windows), W24 (Claude HKLM policy), W27 (admin agent users).
  - Each subsection ends with its references (the list in Global Constraints).
- [ ] **Step 2:** apply the §1.4, D8, D9, D12, D21, §4.2, §15.2 and v1 §9.6 edits.
- [ ] **Step 3:** run `cargo test -p saiife --test docs_wording`; expect PASS (no wording guard is broken). Run `grep -n '^### 5.3a' docs/superpowers/specs/2026-10-19-saiife-v2-design.md`; expect one line.
- [ ] **Step 4:** commit `docs(spec): Windows (v2.2): section 5.3a, D21, 1.4 and the Windows decisions`.

### Task 2: the `saiife-win` crate (pure parts), the unsafe gate and the Windows check

**Files:**
- Create `crates/win/Cargo.toml` (`saiife-win`; `sha2 = "0.10"`; `[target.'cfg(windows)'.dependencies] windows-sys = { version = "=0.61.2", features = [...] }`, with an empty feature list in 19a; a `pipe-server` feature declared but empty until 19b).
- Create `crates/win/src/lib.rs`, `crates/win/src/sid.rs`, `crates/win/src/sddl.rs`, and `crates/win/src/ffi/mod.rs` (`#![cfg(windows)]`, empty in 19a).
- Create `scripts/fake-cc.sh` (if plan 13 did not add one; reuse it if it did) and `scripts/check-windows.sh`.
- Modify `scripts/check-unsafe.sh` and `.github/workflows/ci.yml` (the unsafe gate and the tokio gate gain `-p saiife-win`; a new ubuntu step `windows target check` runs `bash scripts/check-windows.sh`).

**Interfaces (Produces):**
- `sid::service_sid(service_name: &str) -> String`: `S-1-5-80-` followed by the five little-endian `u32`s of `SHA-1(UTF-16LE(upper(service_name)))`. (Add `sha1 = "0.10"`, the RustCrypto crate, pure Rust.)
- `sid::SYSTEM = "S-1-5-18"`, `sid::ADMINISTRATORS = "S-1-5-32-544"`, `sid::USERS = "S-1-5-32-545"`, `sid::AUTHENTICATED_USERS = "S-1-5-11"`, `sid::TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"`, `sid::NETWORK = "S-1-5-2"`.
- `sid::uid_of(sid: &str, elevated_admin: bool) -> u32` (decision W12 in plan 19b):
  - `0` when `sid == SYSTEM` or `elevated_admin`;
  - otherwise `0x4000_0000 | (u32::from_be_bytes(SHA-256(sid)[0..4]) & 0x3fff_ffff)`.
  So the result is never 0, never `u32::MAX`, and never below `0x4000_0000` (no clash with Linux-style ids in mixed fleets' audit views).
- `sid::valid_sid(s: &str) -> bool`: `S-1-<authority>(-<u32>){1,15}`.
- `sddl::Sd { owner: Option<String>, group: Option<String>, dacl_protected: bool, aces: Vec<Ace> }`, `sddl::Ace { allow: bool, flags: AceFlags, mask: u32, sid: String }`, `AceFlags { object_inherit, container_inherit, inherit_only, inherited }`.
- `sddl::parse(s: &str) -> Result<Sd, String>`: reads `O:`, `G:` and `D:` with `P`/`AI`/`AR` flags and `(A|D;flags;rights;;;sid)` ACEs. Rights are hex (`0x1200a9`) or the letter forms `GA GR GW GX FA FR FW FX RC SD WD WO`. SID aliases `SY BA BU AU WD OW CO NU IU AN` map to their SIDs. Anything else is an error, never a guess.
- `sddl::render(sd: &Sd) -> String`: canonical text (hex rights, full SIDs), so `parse(render(x)) == x`.
- `sddl::WRITE_LIKE: u32`: the union of `FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES|DELETE|WRITE_DAC|WRITE_OWNER|FILE_DELETE_CHILD|GENERIC_WRITE|GENERIC_ALL` (with their numeric values in the code).
- `sddl::writers(sd: &Sd) -> BTreeSet<String>`: the SIDs an allow ACE (not inherit-only) grants any `WRITE_LIKE` bit, minus a later-irrelevant deny is **not** subtracted (allow is enough to fail; conservative).
- The `saiife-win` crate root:
  - `#![cfg_attr(not(windows), forbid(unsafe_code))]`
  - `#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]`
  - `pub mod sid; pub mod sddl; #[cfg(windows)] pub mod ffi;`
- `scripts/check-windows.sh`: runs the command from Global Constraints, from the repo root, with `--target-dir target/check-windows`. It exits 2 with `rustup target add x86_64-pc-windows-msvc first` when the target is missing (it checks `rustup target list --installed`; it never installs).
- `scripts/fake-cc.sh`: writes an empty file for each `-o X`, `-FoX`, `/FoX`, `-out:X` and `/OUT:X` argument, then exits 0. It is for `cargo check` only; a comment says so.

- [ ] **Step 1: failing tests** (pure, run on Linux):
  - `trusted_installer_service_sid`: `service_sid("TrustedInstaller") == TRUSTED_INSTALLER` (a published SID, so this pins the algorithm);
  - `service_sid_is_case_insensitive`: `service_sid("saiifed") == service_sid("SAIIFED")`;
  - `uid_of_system_and_elevated_is_0`;
  - `uid_of_user_in_high_range` (for 1000 random valid SIDs: `>= 0x4000_0000`, `!= u32::MAX`, stable across calls);
  - `sddl_roundtrip` (five fixtures, including `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`);
  - `sddl_aliases_expand` (`BU` → `S-1-5-32-545`, `AU` → `S-1-5-11`);
  - `sddl_unknown_alias_is_error`;
  - `writers_finds_append_only_grant` (`(A;;0x4;;;BU)` lists BU);
  - `writers_ignores_inherit_only`.
- [ ] **Step 2:** run `cargo test -p saiife-win`; expect FAIL.
- [ ] **Step 3:** implement. Write `check-unsafe.sh`'s new allow rule. Write `fake-cc.sh` and `check-windows.sh`.
- [ ] **Step 4:** run `cargo test -p saiife-win`; expect PASS. Run `bash scripts/check-unsafe.sh`; expect 0. Put a stray `unsafe {}` in a scratch copy of `crates/win/src/sid.rs`; expect exit 1; revert. Run `bash scripts/check-windows.sh -p saiife-win`; expect no warnings. Run `bash -n` and `shellcheck` on the scripts.
- [ ] **Step 5:** commit `feat(win): saiife-win crate (service SIDs, uid mapping, SDDL), unsafe gate, Windows target check`.

### Task 3: the workspace builds and tests on Windows (developer mode)

**Files:**
- Modify `crates/system/src/*.rs` and `crates/system/src/lib.rs`: every module that uses unix metadata, modes, uids or rustix becomes `cfg(unix)`. On Windows the crate exposes `Platform` (with the new `Windows` variant) and `layout` only, plus a `supported::check_supported` that refuses with `NOT_SUPPORTED_YET = "locked mode on Windows arrives in plan 19b"` (19b replaces it).
- Modify `crates/broker/src/manifest.rs` (the owner/mode check of user manifest dirs, lines ~1111–1150): unix keeps it; Windows uses `fs::symlink_metadata` with `FILE_ATTRIBUTE_REPARSE_POINT` refused and no owner check in 19a (19b adds the DACL check through `saiife-win`). A code comment names the gap and the 19b task.
- Modify unix-only tests to `#[cfg(unix)]`: `crates/guard/src/canon.rs` (the symlink test), `crates/agents/tests/managed_fixtures.rs` (its unix-only parts), and every other one `scripts/check-windows.sh` flags.
- Modify `crates/audit/src/store.rs` (W3: `data_local_dir` on Windows), `crates/cli/src/paths.rs` and the developer config path (`C:\ProgramData\saiife\etc\config.toml` on Windows).
- Modify `crates/cli/src/main.rs`: on Windows, every locked-mode subcommand (`system`, `daemon`, `approve`, `secret`, `api`, `run --secret`, …) prints `saiife: locked mode on Windows arrives in plan 19b. Developer mode works.` and exits 2. Developer commands (`init`, `status`, `check`, `test`, `explain`, `packs`, `audit`, `audit --report`) work.
- Modify `.github/workflows/ci.yml`: `test.strategy.matrix.os` gains `windows-latest`. On Windows the steps are fmt, clippy, `cargo test --workspace --no-fail-fast` (with `SAIIFE_TEST_TMP`, `TMP`, `TEMP` and `LOCALAPPDATA` under `${{ runner.temp }}`), and the tokio gate. The Linux-only steps keep their `if: matrix.os == 'ubuntu-latest'`. `shell: bash` where a step uses bash.

**Interfaces:**
- Consumes plan 13's `Platform` and `Layout`.
- Produces:
  - `Platform::Windows`; `Platform::current()` returns it on Windows; `Platform::name()` is `"windows"`;
  - `saiife_audit::store::default_audit_dir() -> Option<PathBuf>`: `data_local_dir()/saiife/audit` on Windows, unchanged elsewhere;
  - `cli::paths::DEV_SYSTEM_CONFIG: &str`, `/etc/saiife/config.toml` on unix and `C:\ProgramData\saiife\etc\config.toml` on Windows;
  - `cli::LOCKED_ON_WINDOWS_LATER: &str` (the refusal text above).

- [ ] **Step 1: failing tests:**
  - `default_audit_dir_windows_is_local` (`cfg(windows)`; CI);
  - `platform_windows_name` (pure);
  - `locked_commands_refuse_on_windows` (`cfg(windows)`; `saiife system install` exits 2 with the exact text);
  - the CLI's developer-mode integration suites (`init`, `check`, `audit`) run on `windows-latest` with a temp `USERPROFILE`.
- [ ] **Step 2:** run `bash scripts/check-windows.sh`; expect the known errors. Run `cargo test --workspace`; Linux stays green.
- [ ] **Step 3:** implement the gates. Do not change Linux or macOS behaviour.
- [ ] **Step 4:** `bash scripts/check-windows.sh` is clean (`-D warnings`), `cargo test --workspace` passes on Linux, the macOS-target check (plan 13) is clean, and `bash scripts/check-unsafe.sh` exits 0. `test (windows-latest)` is seen green in CI at the end of the plan.
- [ ] **Step 5:** commit `feat: the workspace builds and runs developer mode on Windows`.

### Task 4: Windows path canonicalization in the guard

**Files:**
- Create `crates/guard/src/winpath.rs`.
- Modify `crates/guard/src/canon.rs` (`PathVars` gains the path style and the Windows variables), `crates/guard/src/pathrule.rs` (case-folded matching for `Windows`), `crates/guard/src/lib.rs`, and `crates/cli/src/paths.rs` (the CLI builds `PathVars` with `PathStyle::Windows` on Windows, with `USERPROFILE`, `LOCALAPPDATA`, `APPDATA` and `TEMP`).

**Interfaces (Produces):**
- `pub enum PathStyle { Posix, Windows }`; `PathStyle::host() -> PathStyle` (`Windows` under `cfg(windows)`).
- `PathVars::with_style(self, PathStyle) -> PathVars` and `PathVars::style() -> PathStyle`.
- `winpath::canonical(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Option<String>`: the W6 rules, returning `c:/…` text (or `//host/share/…` for real UNC), case preserved. It is lexical only (no filesystem access).
- `winpath::fold(s: &str) -> String`: lower-case for matching.
- `canon::canonicalize`, `path_forms` and `lexical_form` dispatch on `vars.style()`. In `Windows` style, `canonicalize` tries `std::fs::canonicalize` first when `cfg(windows)` and the path exists, strips the `\\?\` it returns, then applies `winpath::canonical`.
- Path rules compare `fold(path)` with `fold(glob)` when the style is `Windows`. A glob `~/x` expands with the profile dir in `/` form.

- [ ] **Step 1: failing tests** (pure, `PathStyle::Windows` set explicitly, `USERPROFILE` = `C:\Users\a`):
  - `windows_spellings_canonicalize_alike`: the nine forms in Review Focus 1 give `c:/Users/a/.ssh/id_rsa` (folded equal);
  - `ads_and_trailing_dots_stripped`: `.env.`, `.env `, `.env::$DATA`, `.env:x` → `.env`;
  - `localhost_admin_share_is_local`: `\\localhost\c$\x`, `\\127.0.0.1\C$\x`, `\\?\UNC\localhost\c$\x` → `c:/x`; `\\server\share\x` stays `//server/share/x`;
  - `git_bash_drive_paths`: `/c/Users/a`, `/cygdrive/c/Users/a` → `c:/Users/a`;
  - `relative_paths_join_cwd`: cwd `C:\p`, `..\q\.env` → `c:/q/.env`;
  - `env_var_spellings`: `$env:LOCALAPPDATA\saiife`, `%LOCALAPPDATA%\saiife`, `${env:LOCALAPPDATA}\saiife` agree;
  - `posix_style_unchanged`: the existing canon tests pass with `PathStyle::Posix`;
  - `secret_rule_matches_windows_profile`: an `Engine` with `core.secrets` and `PathStyle::Windows` denies reading `C:\Users\a\.ssh\id_rsa` through `Engine::evaluate_path`.
- [ ] **Step 2:** run `cargo test -p saiife-guard winpath canon`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `scripts/bench-check.sh` on Linux is within +1 ms of `main`; the Windows check is clean.
- [ ] **Step 5:** commit `feat(guard): Windows path canonicalization (drives, UNC, ADS, Git Bash, profile vars)`.

### Task 5: the PowerShell reader

**Files:**
- Create `crates/guard/src/pwsh.rs` and `crates/guard/src/wintable.rs` (the W5 translation table, shared with the cmd reader).
- Modify `crates/guard/src/payload.rs` (`SHELL_TOOLS` gains `PowerShell`) and `crates/guard/src/lib.rs`.

**Interfaces (Produces):**
- `pub enum Dialect { Posix, PowerShell, Cmd }`.
- `pwsh::split_segments_noted(cmd: &str) -> (Vec<Segment>, Option<&'static str>)`, with the same contract as `lexer::split_segments_noted`: each `Segment` is argv-order `Word`s, after translation. The note is `Some(reason)` when something was not fully read (the engine already records "not fully judged").
- `wintable::translate(argv: &[Word], dialect: Dialect) -> Vec<Word>`: the W5 table. argv[0] is matched case-insensitively, with any directory and a trailing `.exe` removed. Parameters match by unambiguous prefix among that cmdlet's table entries; an ambiguous prefix is left as written.
- `wintable::nested(argv: &[Word]) -> Option<(Dialect, String)>`: the nested command of `powershell`/`pwsh -Command|-c|-EncodedCommand|-enc|-e`, `cmd /c|/k`, `iex '<literal>'`, `Invoke-Command -ScriptBlock {…}`. Task 6 wires it into the engine.
- In the reader, `$name`, `${…}`, `$(…)` and `@(…)` in a word set `Word.has_substitution`; a script block `{ … }` given to `&`, `.`, `Invoke-Command` or `ForEach-Object` is read as nested PowerShell.

- [ ] **Step 1: failing tests** (pure):
  - `remove_item_forms_translate_to_rm`: `ri -r -fo C:\`, `Remove-Item -Recurse -Force -Path C:\Windows`, `rm -Recurse -Force C:\Users`, `del -r C:\x` → argv `rm -r -f …` (flags present as listed);
  - `ambiguous_prefix_left_as_written` (`Remove-Item -F x` is ambiguous between `-Force` and `-Filter`: no `-f`);
  - `statement_split`: `git status; Remove-Item -r x | Out-Null && echo ok` → 4 segments;
  - `quotes_and_backtick`: `'a;b'`, `"a;b"`, `` a`;b `` are one word;
  - `redirect_words`: `"x" > C:\p\.env` and `Set-Content -Path C:\p\.env -Value x` both give a redirect to `C:\p\.env`;
  - `variable_is_substitution`: `Remove-Item -r $p` sets `has_substitution` on the operand;
  - `exe_suffix_dropped`: `git.exe push --force` → `git push --force`;
  - `env_assignment`: `$env:AWS_PROFILE = 'x'` → assignment word;
  - `classify_powershell_tool`: `{"tool_name":"PowerShell","tool_input":{"command":"ls"}}` is `ToolCall::Shell`.
- [ ] **Step 2:** run `cargo test -p saiife-guard pwsh wintable`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass, plus `pwsh_never_panics`: a loop over 10 000 random strings from a fixed seed (no new crate; a small xorshift in the test) never panics. If the `fuzz/` dir has a lexer target, add a `pwsh` target beside it with the same shape.
- [ ] **Step 5:** commit `feat(guard): PowerShell reader with cmdlet translation`.

### Task 6: the cmd reader, nested commands and the dialect choice

**Files:**
- Create `crates/guard/src/cmdexe.rs`.
- Modify `crates/guard/src/engine.rs` (evaluate in a dialect; nested commands), `crates/guard/src/payload.rs` (`ToolCall::Shell` gains the dialect choice), `crates/cli/src/check.rs` (passes the agent and the host OS), and `crates/cli/src/eval.rs` (the worker gets the dialect).

**Interfaces:**
- Consumes `pwsh::split_segments_noted`, `wintable::{translate, nested}` and `Dialect` (Task 5).
- Produces:
  - `cmdexe::split_segments_noted(cmd: &str) -> (Vec<Segment>, Option<&'static str>)`, same contract; `%NAME%` and `!NAME!` set `has_substitution`;
  - `pub enum Dialects { One(Dialect), Strictest(Dialect, Dialect) }`;
  - `payload::dialects_for(agent: Option<&str>, tool: Option<&str>, windows_host: bool) -> Dialects`: the W4 rules (`Claude`+`Bash` → `One(Posix)`; any agent + `PowerShell` → `One(PowerShell)`; on a Windows host any other shell tool → `Strictest(PowerShell, Posix)`; otherwise `One(Posix)`);
  - `Engine::evaluate_in(&self, raw_cmd: &str, dialects: Dialects) -> Decision`. `Engine::evaluate(raw)` stays and means `evaluate_in(raw, Dialects::One(Dialect::Posix))`;
  - `Decision` ordering for `Strictest`: `Deny` > `Ask` > `Allow`; between two allows the one with a rule trace wins; between equal decisions the `PowerShell` one is reported;
  - nested commands found by `wintable::nested` are evaluated in their own dialect with the same budget, at most 8 levels deep (the POSIX nesting limit, if it has one; otherwise 8). Deeper is the unresolved-substitution outcome.

- [ ] **Step 1: failing tests:**
  - `cmd_rd_and_del_translate`: `rd /s /q C:\`, `del /s /q /f C:\Users\a` → `rm -r -f …`;
  - `cmd_caret_and_quotes`: `echo a^&b` is one segment; `"a&b"` one word;
  - `cmd_percent_var_is_substitution`;
  - `encoded_command_judged_inside`: `powershell -enc <base64 UTF-16LE of "Remove-Item -Recurse -Force C:\">` is denied with `core.filesystem` on;
  - `bad_encoded_command_is_unresolved`: `pwsh -e !!notbase64` gets the same `Decision` as POSIX `eval "$x"` in the same engine;
  - `cmd_inside_powershell`: `cmd /c "rd /s /q C:\"` is denied;
  - `iex_literal_judged`, `iex_variable_unresolved`;
  - `start_process_argument_list`: `Start-Process cmd -ArgumentList '/c rd /s /q C:\'` is denied;
  - `script_block_judged`: `& { Remove-Item -r -fo C:\ }` is denied;
  - `strictest_of_both_dialects`: a command that only one reading denies is denied under `Strictest`;
  - `benign_windows_commands_allowed_both_ways`: `git status; npm test`, `Get-ChildItem -Recurse src`, `dir /s src`, `Remove-Item -Recurse .\build` are allowed under `Strictest(PowerShell, Posix)` with the default packs;
  - `dialects_for_table` (every W4 row);
  - `posix_engine_unchanged` (the whole existing engine suite still passes through `evaluate`).
- [ ] **Step 2:** run `cargo test -p saiife-guard -p saiife`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; `scripts/bench-check.sh` and `--managed` on Linux stay within +1 ms of `main` (POSIX payloads take the old path).
- [ ] **Step 5:** commit `feat(guard): cmd reader, nested PowerShell/cmd commands, strictest-of-both on Windows hosts`.

### Task 7: Windows rules in the core packs

**Files:**
- Modify `crates/guard/packs/core.filesystem.toml`, `core.secrets.toml`, `core.self.toml`, `core.process.toml`, `core.lock.toml` (W7), with `[[example]]` entries for each new rule (`deny` and `allow` examples).
- Modify the pack tests that list rule ids, if any (`crates/guard/tests/`).

**Interfaces:**
- Consumes the translated forms from Tasks 5 and 6, and Task 4's `c:/` paths.
- Produces rule ids (so docs and `explain` can name them): `core.filesystem/windows-root-rm`, `core.filesystem/windows-format`, `core.secrets/windows-credential-dump`, `core.secrets/windows-hive-save`, `core.self/windows-data-dir`, `core.process/windows-kill-saiife`, `core.lock/windows-files`, `core.lock/windows-service`, `core.lock/windows-claude-policy`, `core.lock/windows-audit-group`. Each pattern is case-insensitive (`(?i)`) and accepts any drive letter.

- [ ] **Step 1: failing tests:** the pack example runner covers the new examples. At minimum:
  - deny: `Remove-Item -Recurse -Force C:\` (via translation), `rd /s /q D:\Windows`, `format C: /q`, `Format-Volume -DriveLetter C`, `Clear-Disk -Number 0`, `cmdkey /list`, `reg save HKLM\SAM sam.hiv`, `taskkill /im saiife.exe /f`, `sc.exe stop saiifed`, `Stop-Service saiifed`, `reg add HKLM\SOFTWARE\Policies\ClaudeCode /v Settings /d {}`, `icacls C:\ProgramData\saiife /grant Users:F`, `Set-Content C:\ProgramData\gemini-cli\settings.json '{}'`;
  - allow: `Remove-Item -Recurse .\build`, `rd /s /q C:\Users\a\proj\target`, `reg query HKLM\SOFTWARE\Policies\ClaudeCode`, `Get-Service saiifed`, `sc.exe query saiifed`, `format-table` (`Get-Process | Format-Table`).
- [ ] **Step 2:** run `cargo test -p saiife-guard packs`; expect FAIL.
- [ ] **Step 3:** write the rules.
- [ ] **Step 4:** the tests pass; `saiife packs` lists the new rules; the guard's latency test (50 ms budget) passes.
- [ ] **Step 5:** commit `feat(packs): Windows rules in core.filesystem, secrets, self, process and lock`.

### Task 8: agents on Windows (project hooks, matcher, detection, lock labels)

**Files:**
- Modify `crates/agents/src/claude.rs` (W8: `MATCHER` gains `PowerShell`; the old value becomes `MATCHER_V2`; upgrade both old matchers), `crates/agents/src/detect.rs` (Windows locations: `%USERPROFILE%\.claude`, `%USERPROFILE%\.codex`, `%USERPROFILE%\.gemini`; `claude.exe`/`codex.cmd`/`gemini.cmd` on `PATH` through `PATHEXT`), `crates/agents/src/lock.rs`, `crates/agents/tests/lock_check_fixtures.rs`, and `crates/cli/src/status_cmd.rs` (the old-matcher warning).
- Create `crates/agents/tests/fixtures/lock-check/windows/.gitkeep`.

**Interfaces (Produces):**
- `claude::MATCHER = "Bash|PowerShell|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit"`, `claude::MATCHER_V2 = "Bash|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit"`.
- `claude::matcher_is_outdated(m: &str) -> bool` (true for `MATCHER_V1` and `MATCHER_V2`).
- `status` prints `hook matcher predates the PowerShell tool; run saiife init to update` when the project hook uses an outdated matcher.
- `lock::LockPlatform { Linux, Macos, Windows }` and `lock::label_for(agent, LockPlatform) -> LockLabel` (replacing plan 13's `bool` form); every Windows label is `Unverified` until `windows/<agent>.tsv` recordings exist (plan 19b Task 14).
- `detect::agent_paths(home: &Path, windows: bool) -> AgentPaths` is pure; the `windows` flag picks the profile layout and `PATHEXT` lookup.

- [ ] **Step 1: failing tests:**
  - `matcher_covers_powershell`;
  - `matcher_v2_project_upgraded` (a project with `MATCHER_V2` is rewritten to `MATCHER`, other groups untouched, key order kept);
  - `status_warns_on_old_matcher` (CLI integration, temp home);
  - `windows_agent_paths` (pure);
  - `windows_labels_unverified_without_recordings`;
  - the fixtures test covers `windows/`.
- [ ] **Step 2:** run `cargo test -p saiife-agents -p saiife`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass on Linux; the Windows check is clean; the CLI `init` suite passes on `windows-latest` in CI.
- [ ] **Step 5:** commit `feat(agents): PowerShell in the Claude matcher, Windows detection and lock labels`.

### Task 9: Windows release builds, `install.ps1` and Authenticode signing

**Files:**
- Create `install.ps1`, `scripts/test-install.ps1`, `scripts/release/windows-sign-mode.sh`, `scripts/release/test-windows-sign-mode.sh`.
- Create `.cargo/config.toml` entries for `cfg(windows)` targets: `rustflags = ["-C", "target-feature=+crt-static", "-C", "link-arg=/DEPENDENTLOADFLAG:0x800"]` (static CRT, so no `vcruntime140.dll`; load-time DLLs searched in System32 only).
- Modify `.github/workflows/release.yml` and `.github/workflows/ci.yml` (shellcheck list; a `test` step on `windows-latest` running `pwsh -File scripts/test-install.ps1`; an ubuntu step running `bash scripts/release/test-windows-sign-mode.sh`).

**Interfaces:**
- **Release matrix** gains:
  - `x86_64-pc-windows-msvc` on `windows-latest`, `run: true`;
  - `aarch64-pc-windows-msvc` on `windows-latest` (cross-compiled; LLVM's `clang` on `PATH` for `ring`), `run: false`.
  - The architecture check reads the PE `Machine` field (`0x8664` or `0xAA64`) with a few lines of PowerShell.
  - The package is `saiife-<version>-<target>.zip` holding `saiife.exe`, `LICENSE` and `README.md`, listed in `SHA256SUMS` like the tarballs.
- **Signing (decision W21 in plan 19b; the secrets are passed only to the signing step):**
  - `WINDOWS_SIGN_AZURE_TENANT_ID`, `WINDOWS_SIGN_AZURE_CLIENT_ID`, `WINDOWS_SIGN_AZURE_CLIENT_SECRET`: an Entra app registration with the "Artifact Signing Certificate Profile Signer" role;
  - `WINDOWS_SIGN_ENDPOINT` (for example `https://weu.codesigning.azure.net/`), `WINDOWS_SIGN_ACCOUNT`, `WINDOWS_SIGN_PROFILE`.
  - Each is read as `${{ startsWith(github.ref, 'refs/tags/v') && secrets.WINDOWS_SIGN_… || '' }}`, so only tag pushes sign.
  - `windows-sign-mode.sh` reads the six variables: all set → `artifact-signing`; none set → `unsigned`; some set → exit 1 with `partial signing secrets: missing <names>`. It writes `dist/SIGNING-<target>.txt`.
  - In `artifact-signing` mode, the step `sign (Windows)` runs `Azure/artifact-signing-action` (pinned by commit SHA, the newest v2 release older than 14 days) with `files: target/<target>/release/saiife.exe`, `file-digest: SHA256`, `timestamp-rfc3161: http://timestamp.acs.microsoft.com`, `timestamp-digest: SHA256`. Then `signtool verify /pa /v` must pass.
  - In `unsigned` mode, a `::warning::Windows binaries are not Authenticode-signed: the signing secrets are not set`. The `publish` job appends `Windows binaries in this release are not Authenticode-signed; SmartScreen will warn on first run.` to `notes.md`.
  - Fork PRs and runs without the secrets stay green.
- **`install.ps1`** (developer mode, no admin): `-Version <v>` (default latest), `-InstallDir` (default `$env:LOCALAPPDATA\Programs\saiife\bin`), `-BaseUrl` (default the GitHub releases URL; tests pass `file://`). It downloads the zip for `$env:PROCESSOR_ARCHITECTURE` (`AMD64` → x86_64, `ARM64` → aarch64), checks it against `SHA256SUMS` (refusing a mismatch), unpacks `saiife.exe`, adds the dir to the **user** `Path` (`[Environment]::SetEnvironmentVariable(..., 'User')`) once, and prints the next step (`saiife init`). Any other architecture prints `unsupported platform: <arch>` and exits 1.
- `test-install.ps1` mirrors `scripts/test-install.sh` against a fake `file://` release under `$env:RUNNER_TEMP`, with `USERPROFILE`, `LOCALAPPDATA` and the user `Path` redirected (it restores the user `Path` value at the end): checksums, latest lookup, a bad checksum, an unsupported architecture, and the `Path` line added once.

- [ ] **Step 1: failing tests:**
  - `test-windows-sign-mode.sh` (Linux, offline): every combination of the six variables maps to its mode, and a partial set names the missing ones;
  - `test-install.ps1` (CI `windows-latest`).
- [ ] **Step 2:** run `bash scripts/release/test-windows-sign-mode.sh`; expect FAIL.
- [ ] **Step 3:** write the scripts, the config and the workflow steps.
- [ ] **Step 4:** the offline test passes; `bash -n` and `shellcheck` are clean. A `pull_request` dry run of `release.yml` builds both Windows zips in `unsigned` mode (seen in CI at the end).
- [ ] **Step 5:** commit `ci(release): Windows x64/ARM64 zips, static CRT, install.ps1, Authenticode via Artifact Signing when secrets exist`.

### Task 10: the Windows bench and the developer-mode docs

**Files:**
- Modify `scripts/bench-check.sh` (works under Git Bash on Windows: `saiife.exe`, `mktemp` fallback; `BENCH_MAX_P95_MS` from plan 13).
- Modify `.github/workflows/ci.yml`: a `test` step on `windows-latest`, `shell: bash`, `BENCH_MAX_P95_MS=50 bash scripts/bench-check.sh 50` (developer hook).
- Create `docs/windows.md` (developer mode now; a `## Locked mode` heading that says "plan 19b").
- Modify `docs/install.md` (the Windows line: `install.ps1`), `docs/agents/{claude-code,codex,gemini}.md` (Windows: shells, the PowerShell tool, the matcher upgrade), `docs/threats.md` (W5's limits), `README.md`, `CHANGELOG.md` (Unreleased), and `crates/cli/tests/docs_wording.rs`.

**Interfaces:** Consumes Tasks 3–9. Produces the doc anchors `docs/windows.md#developer-mode`, `#shells-and-the-guard`, `#limits`, `#locked-mode` (filled by 19b).

- [ ] **Step 1: failing tests:** `docs_wording`: `docs/windows.md` names `install.ps1`, `%LOCALAPPDATA%\saiife\audit`, `PowerShell` and `Windows 11 23H2`; `docs/threats.md` lists `Set-Alias` among the limits.
- [ ] **Step 2:** run `cargo test -p saiife --test docs_wording`; expect FAIL.
- [ ] **Step 3:** write the docs and the bench changes.
- [ ] **Step 4:** the docs test passes; `bash scripts/bench-check.sh --managed 20` on Linux still prints its numbers; `bash -n` and `shellcheck` are clean.
- [ ] **Step 5:** commit `docs: Windows developer mode; bench on windows-latest`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`; clippy `-D warnings`;
  - the tokio gate (with `saiife-win`) and `bash scripts/check-unsafe.sh`;
  - `cargo test --workspace` and `scripts/test-offline.sh`, with TMPDIR and SAIIFE_TEST_TMP set;
  - `bash scripts/check-windows.sh` and the macOS-target check;
  - `scripts/bench-check.sh` and `--managed` against `main` (Linux, +1 ms at most);
  - `bash -n` and `shellcheck` on the changed scripts; `scripts/release/test-windows-sign-mode.sh`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. CI must be green, including `test (windows-latest)` and its bench step. The owner merges. No tag.

## Follow-ups (not in this plan)

- PowerShell AST-level reading (functions, aliases defined inline, `.ps1` contents). The reader stays a boundary heuristic, as the POSIX lexer is.
- A `winget` manifest and a Scoop bucket for developer mode.

## Owner handwork

Nothing here runs on Claude's machine. 19a needs no admin anywhere.

- [ ] **Confirm the decisions and spec departures** listed in the plan 19 report (W1–W8 here; W9–W28 in plan 19b). In particular: Windows 10 is not supported (W2); the guard judges Codex and Gemini commands both ways on Windows (W4); the PowerShell limits (W5).
- [ ] **Code signing (needed for signed releases of 19a and 19b):**
  1. Check eligibility for Azure Artifact Signing (Microsoft Learn, "Code signing options for Windows app developers"). Organizations in the EU are eligible; individual developers are eligible only in the USA and Canada. If neither fits, tell Claude: the alternative is an OV certificate on a cloud HSM (DigiCert KeyLocker or SSL.com eSigner), which needs a different signing step.
  2. In the Azure portal: create an Artifact Signing account and a Public Trust certificate profile, and complete identity validation.
  3. Create an Entra app registration with a client secret. Give it the "Artifact Signing Certificate Profile Signer" role on the account.
  4. Set the GitHub secrets on HrRobinson/saiife:
     ```bash
     export GH_CONFIG_DIR=~/.config/gh-personal R=HrRobinson/saiife
     gh secret set WINDOWS_SIGN_AZURE_TENANT_ID -R $R
     gh secret set WINDOWS_SIGN_AZURE_CLIENT_ID -R $R
     gh secret set WINDOWS_SIGN_AZURE_CLIENT_SECRET -R $R
     gh secret set WINDOWS_SIGN_ENDPOINT -R $R     # e.g. https://weu.codesigning.azure.net/
     gh secret set WINDOWS_SIGN_ACCOUNT -R $R
     gh secret set WINDOWS_SIGN_PROFILE -R $R
     ```
  5. Push a test tag only when you are ready for a release. Signing runs on tag pushes only, so a `workflow_dispatch` run still shows `unsigned`.
- [ ] **A first look on real Windows** (optional for 19a; required in 19b): in a throwaway Windows 11 VM (UTM on your Mac with a Windows 11 ARM image, or a small Azure VM), run `irm <raw install.ps1 URL> | iex`, then `saiife init` in a project, and run Claude Code with the PowerShell tool on: a `Remove-Item -Recurse -Force C:\` request must be blocked, and `saiife audit` must show it.
