# Plan 19b — Windows, part 2: locked mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `saiife system install`, run from an elevated terminal, works on Windows 11 23H2+ and Windows Server 2022+, x64 and ARM64. It lays down `C:\ProgramData\saiife` with protected ACLs, runs `saiifed` as a Windows service under the virtual account `NT SERVICE\saiifed`, and writes the managed hooks for Claude Code, Codex and Gemini CLI. Hooks talk to the daemon over a named pipe that identifies each caller by its token. Same-user approval is off on Windows: an approval needs a second account. The personal broker uses Credential Manager. A signed MSI and Intune Win32 and GPO recipes deploy it. A `locked-windows` CI job proves it as admin on GitHub's Windows runners.

**Architecture:**
- **The same switch as macOS.** `Platform::Windows` (plan 19a) maps each Linux path constant to its Windows path in `Layout::at`. A Linux test builds a Windows layout under a tempdir (`C:\ProgramData\saiife\etc` becomes `<tmp>/C/ProgramData/saiife/etc`).
- **Unix modes become SDDL.** Each path has one expected security descriptor, written as SDDL text. The table is pure data. Install sets it, and doctor reads it back and compares, both through `Host`. Linux tests check the table and the logic with `FakeHost`.
- **Privileged actions stay behind `Host`:** the service manager (through the safe `windows-service` crate), `net.exe localgroup`, `sc.exe sdset`, registry reads (through `winreg`) and ACL reads and writes (through `saiife-win`).
- **IPC is a named pipe.** The daemon creates `\\.\pipe\saiife` with an owner and DACL of its own. It learns each caller's SID and groups by impersonating the client at identification level. The client checks that the pipe's owner is the service SID before it sends a byte. Everything above the transport (frames, ops, the audit) is unchanged.
- **Windows FFI lives only in `crates/win/src/ffi/`** (decision W1, plan 19a), and each call is listed there.

**Tech Stack:** Rust workspace. New dependencies, all `cfg(windows)` and pinned with `=` to the newest release older than 14 days on the day they are added:
- `windows-service` (0.8.1 or later) in `saiife-win` and `saiife-system`;
- `winreg` in `saiife-system` and `saiife-agents` (registry reads);
- `rpassword` in `saiife` (a console value without echo, for `secret add` and `connect`; never for approvals);
- `windows-sys =0.61.2` features for the W1 calls, and `tokio` (`net`) behind `saiife-win`'s `pipe-server` feature.

Tools in CI only: WiX Toolset v5.0.2 (`dotnet tool`), `signtool`, `IntuneWinAppUtil.exe` (Microsoft-Win32-Content-Prep-Tool, pinned by SHA-256), and the MSVC `cl` for test DLLs.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md` §5.3a (added by plan 19a Task 1), and on Windows: §5.6, §6.1, §6.2, §6.3, §6.6, §6.9.3, §6.10.2, §6.14, §6.15, §6.16, §8.5, §9.2, §9.3, §13 and §14.

Plans 13 and 18 set the style. Read plan 19a's Global Constraints first: its rules and decisions W1–W8 apply here unchanged.

## Consumes (verify at build time)

- **Plan 19a merged:** `saiife_win::{sid::{service_sid, uid_of, SYSTEM, ADMINISTRATORS, USERS, TRUSTED_INSTALLER, NETWORK}, sddl::{Sd, Ace, parse, render, writers, WRITE_LIKE}}`; `Platform::Windows`; `scripts/check-windows.sh`; the `core.lock/windows-*` rules; `lock::{LockPlatform, label_for}`; `cli::LOCKED_ON_WINDOWS_LATER` (removed here); the signing mode script and secrets.
- **Plan 13 merged:** `Host` with `run_input`, `FakeHost`/`FakeState`, `VaultKeyMode::DaemonFile`, `reauth::{Subject, MacAuthorize, parse_auth_hex}`, `sessions::{Proc, host_proc}`, `MCP_NEEDS_LINUX`, `validate_mcp(cfg, gateway_supported)`, `tcp_peer_refused` returning `None` off Linux, `personal::personal_paths_for(env, home, Platform)`, `PERSONAL_UNSUPPORTED`.
- **Plan 18 merged:** `fleet::{FLEET_DIR, FLEET_CONFIG, FLEET_INSTALL}`, `layout::PACKAGE_BINARY`, `system install --fleet`, `doctor files.package`, `deploy/` and `docs/fleet.md`.
- Where those plans landed different names, they win and this plan is adjusted before the task starts.

## Global Constraints

- **Plan 19a's Global Constraints apply in full:** the standing rules (no Windows machine, nothing privileged locally, `Child::kill` only, admin tests only in `locked-windows`, job ids without dots, test isolation), the Windows-target check, the unsafe boundary and its FFI list (W1), tokio-free crates, the hook budget and the commit rules.
- **The branch** is `plan-19b-windows-locked` from `main` after plan 19a and plan 18 merge.
- **FFI calls added by this plan** (each in `crates/win/src/ffi/<area>.rs`, each block with a `SAFETY:` comment, each handle or buffer in an RAII guard). This is the full W1 list; the table in plan 19a's Global Constraints is updated to match it in Task 2:
  - **sd.rs:** `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `ConvertSecurityDescriptorToStringSecurityDescriptorW`, `GetSecurityDescriptorOwner`, `GetSecurityDescriptorDacl`, `LocalFree`;
  - **acl.rs:** `GetSecurityInfo`, `SetSecurityInfo` (each on a handle opened with `FILE_FLAG_OPEN_REPARSE_POINT` and checked, so a final reparse point swapped in cannot redirect them), `GetFileInformationByHandle` (on the same handle before `SetSecurityInfo`: a non-directory with `nNumberOfLinks != 1` is refused, so a hard link cannot redirect a set to its target), `GetFinalPathNameByHandleW` (on the same handle before `SetSecurityInfo`: the path Windows opened must be the path asked for, so a junction swapped in higher up cannot redirect a set), `CreateDirectoryW` (with a security descriptor, so a new dir never exists with an inherited ACL);
  - **account.rs:** `ConvertSidToStringSidW`, `ConvertStringSidToSidW`, `LookupAccountNameW`, `LookupAccountSidW`, `NetUserGetLocalGroups`, `NetLocalGroupGetMembers`, `NetApiBufferFree`;
  - **token.rs:** `GetCurrentProcess`, `OpenProcessToken`, `GetCurrentThread`, `OpenThreadToken`, `GetTokenInformation` (`TokenUser`, `TokenGroups`, `TokenIntegrityLevel`, `TokenRestrictedSids`), `CloseHandle`;
  - **pipe.rs:** `tokio::net::windows::named_pipe::ServerOptions::create_with_security_attributes_raw`, `GetNamedPipeClientProcessId`, `ImpersonateNamedPipeClient`, `RevertToSelf`, `GetSecurityInfo` (the pipe owner, client side);
  - **proc.rs:** `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`; plan 21: `OpenProcess` (`PROCESS_QUERY_LIMITED_INFORMATION`), `GetProcessTimes`, `ProcessIdToSessionId` (the creation time and session of a process, where readable, for the co-signer's process-tree tie);
  - **trust.rs:** `WinVerifyTrust` (doctor's signature check: in-process, so an elevated doctor starts no PowerShell whose environment and HKCU settings the caller's user controls);
  - **cred.rs:** `CredReadW`, `CredWriteW`, `CredDeleteW`, `CredFree`;
  - **process.rs:** `SetDefaultDllDirectories` (`LOAD_LIBRARY_SEARCH_SYSTEM32`), `SetStdHandle` (`STD_ERROR_HANDLE`, for the service log), `GetDiskFreeSpaceExW`;
  - **job.rs:** `CreateJobObjectW`, `SetInformationJobObject` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), `AssignProcessToJobObject` (the managed hook's eval worker sits in a kill-on-close job, so it never outlives the hook; whole-branch review finding 8);
  - **net.rs** (plans 20 and 21): `setsockopt` (`SO_EXCLUSIVEADDRUSE`, on the Claude Code co-signer's listener before it binds `127.0.0.1:7433`, so no other process can bind that address beside it), `GetExtendedTcpTable` (`AF_INET`, `TCP_TABLE_OWNER_PID_CONNECTIONS`: the pid that owns a co-sign client's socket, tied to the binding hook's process tree; plan 21);
  - **service.rs:** the one `extern "system"` service entry that `windows_service::define_windows_service!` expands to. The macro's expansion contains `unsafe`, so it must live in `saiife-win` and nowhere else.

  That is 46 functions and one macro (`GetSecurityInfo` is listed twice), all in `crates/win/src/ffi/`: 45 `windows-sys` calls and the tokio call. If a failure of `RevertToSelf` is ever seen, the process calls `std::process::abort()`: it must never go on running as the client.
- **Decisions this plan makes** (W1–W8 are in plan 19a; each one here is restated in its task, and plan 19a Task 1 copies all of them into spec §5.3a):
  9. **W9. The Windows layout.** `windows_path(linux: &str) -> Option<&'static str>` maps:

     | Linux constant | Windows |
     |---|---|
     | `OPT_DIR`, `BIN_DIR`, `BINARY` | `C:\ProgramData\saiife`, `…\bin`, `…\bin\saiife.exe` |
     | `ETC_DIR`, `CONFIG`, `POLICY_D`, `INSTALLED`, `ca/`, `FLEET_DIR` | `C:\ProgramData\saiife\etc`, `…\etc\config.toml`, `…\etc\policy.d`, `…\etc\installed.toml`, `…\etc\ca`, `…\etc\fleet` |
     | `STATE_DIR`, `KEYS_DIR`, `AUDIT_KEY`, `VAULT_KEY` | `C:\ProgramData\saiife\state`, `…\state\keys`, `…\state\keys\audit.ed25519`, `…\state\keys\vault.key` |
     | `LOG_DIR`, `AUDIT_DIR`, `DAEMON_LOG` | `C:\ProgramData\saiife\log`, `…\log\audit`, `…\log\daemon\daemon.log` |
     | `RUN_DIR`, `SOCKET` | none: the control endpoint is the pipe `\\.\pipe\saiife` |
     | `UNIT` | none: the service `saiifed` in the service manager |
     | `CLAUDE_MANAGED_DIR`, `CLAUDE_MANAGED`, `CLAUDE_MCP` | `C:\Program Files\ClaudeCode\managed-settings.d`, `…\50-saiife.json`, `…\60-saiife-mcp.json` |
     | `CODEX_DIR`, `CODEX_REQUIREMENTS` | `C:\ProgramData\OpenAI\Codex`, `…\requirements.toml` |
     | `GEMINI_DIR`, `GEMINI_SETTINGS` | `C:\ProgramData\gemini-cli`, `…\settings.json` |
     | `PACKAGE_BINARY` (plan 18) | `C:\Program Files\saiife\saiife.exe` (the MSI's own copy) |
     | `POLKIT_*`, `PKCHECK` | none |

     - **The locked binary is `C:\ProgramData\saiife\bin\saiife.exe`, not under `C:\Program Files`.** The hook command must survive Git Bash, PowerShell and cmd without quoting, and a path with a space does not. The hook commands are `C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent <a>`: forward slashes, no spaces, so no shell eats a backslash and none needs quotes.
     - The paths come from Claude Code's docs (`C:\Program Files\ClaudeCode\`; it does not read the legacy `C:\ProgramData\ClaudeCode\managed-settings.json`), Codex's docs (`%ProgramData%\OpenAI\Codex\requirements.toml`) and Gemini CLI's docs (`C:\ProgramData\gemini-cli\settings.json`).
     - Install refuses unless the registry's `ProgramFilesDir` is `C:\Program Files` and `ProgramData` is `C:\ProgramData`: `non-default system folders are not supported in this version`. It never reads them from environment variables.
  10. **W10. The service identity is the virtual account `NT SERVICE\saiifed`.**
      - The service is `saiifed` (display name `saiife daemon`), own process, auto start, binary `C:\ProgramData\saiife\bin\saiife.exe` with arguments `daemon --system`, logon account `NT SERVICE\saiifed`, no password.
      - The service SID type is unrestricted. The account's SID is `service_sid("saiifed")`, a pure function, so every ACL can name it without a lookup.
      - Failure actions: restart after 1 s, three times, reset after 86 400 s, and also on non-crash failures. This is the analogue of `Restart=always`, `RestartSec=1`.
      - The service's own DACL is set with `sc.exe sdset saiifed D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AU)`. That is the Windows default plus query rights for Authenticated Users. Nobody but SYSTEM and Administrators can stop, pause, reconfigure or delete it.
      - Why a virtual account: it has its own SID (no shared `LocalService` identity), no password to manage, cannot log on interactively, and needs no user creation. A dedicated local user would need a password and its own hardening.
      - `SERVICE_CONTROL_PARAMCHANGE` reloads the policy (SIGHUP on Linux). Stop and shutdown are a clean stop (SIGTERM).
      - The daemon's stderr goes to `C:\ProgramData\saiife\log\daemon\daemon.log`. At service start, `SetStdHandle(STD_ERROR_HANDLE, <file>)` points it there; at start, a file over 10 MiB is renamed to `daemon.log.1` in the same dir. The log has its own dir because `<S>` has only RX on `…\log` and could neither rename nor create the file there.
  11. **W11. The control pipe.**
      - The name is `\\.\pipe\saiife`. Its security descriptor is `O:<S>G:<S>D:P(D;;GA;;;NU)(A;;GA;;;<S>)(A;;GA;;;SY)(A;;0x12019b;;;BU)`, with `<S> = service_sid("saiifed")`.
      - `0x12019b` is `FILE_GENERIC_READ | FILE_GENERIC_WRITE` without `FILE_APPEND_DATA`. For a pipe, `FILE_APPEND_DATA` is `FILE_CREATE_PIPE_INSTANCE`, so a client may connect but never add a server instance. Network logons are denied, and `reject_remote_clients(true)` is set too.
      - The first instance is created with `first_pipe_instance(true)`. If the name already exists, someone squatted it: the daemon writes `pipe \\.\pipe\saiife exists and is not ours; refusing to start` to its log and exits 1. The service manager retries every second, and the hooks deny meanwhile.
      - **Client:** it opens the pipe with `std` (`OpenOptionsExt::security_qos_flags(SECURITY_IDENTIFICATION)`), so the daemon may learn who the caller is but can never act as the caller. Then it reads the pipe's owner with `GetSecurityInfo`. An owner other than `<S>` (or the user's own SID for the personal broker) is `ClientError::Owner`, before a byte is sent. `ERROR_PIPE_BUSY` is retried every 10 ms until the deadline. The deadline covers each read and write through a reader thread, and when it passes, the hook denies and exits.
      - **Server:** after `connect().await`, one synchronous call (no `.await` inside) does `ImpersonateNamedPipeClient`, `OpenThreadToken(TOKEN_QUERY, OpenAsSelf = TRUE)`, `GetTokenInformation(TokenUser)`, `GetTokenInformation(TokenGroups)`, `GetTokenInformation(TokenIntegrityLevel)`, `GetTokenInformation(TokenRestrictedSids)` and `RevertToSelf`. It also reads `GetNamedPipeClientProcessId`, which is used for attribution only. A pipe peer counts as an elevated admin only at High integrity or above with no restricted SIDs: a low-integrity or restricted child of an elevated admin holds `Administrators` enabled, and is not uid 0.
      - Why not AF_UNIX: Windows supports AF_UNIX sockets but gives no peer credentials (devblogs.microsoft.com, "AF_UNIX comes to Windows"), and `SIO_AF_UNIX_GETPEERPID` gives only a pid. Opening another user's process from a service account is denied, so a pid alone gives no SID.
  12. **W12. uids on Windows.** The policy, the audit and the IPC types keep `uid: u32`.
      - On Windows the uid is `uid_of(sid, elevated_admin)`: `0` for SYSTEM and for a token with `BUILTIN\Administrators` enabled (an elevated admin, the Windows "root"); otherwise a stable 30-bit hash of the SID in `0x4000_0000..0x8000_0000`.
      - Audit records gain `"sid"` (the exact SID) on Windows, so the hash is never the only identity on record (§8.5 note).
      - Policy names users as `name` or `DOMAIN\name`. They are resolved with `LookupAccountNameW`.
      - `group:<name>` means a local group. A peer is in it when its token's groups hold that group's SID, which also counts domain groups nested into the local group.
      - Two configured principals that hash to the same uid are a load error, `uid collision between <a> and <b>; rename one or tell the saiife maintainers`. In practice this never happens.
      - The non-elevated token of an admin user is that user's own hash, not 0. This matches UAC: admin rights only count when elevated.
  13. **W13. The HTTP gateway on Windows is loopback TCP with the bearer token only** (`[gateway] tcp`, existing). There is no `gateway.sock`. `tcp_peer_refused` returns `None` on Windows, as on macOS: there are no gateway children, and the daemon's own uid cannot mint a token. `saiife api` and `saiife mcp` use the control pipe and need no gateway.
  14. **W14. ACLs.** Every path install creates gets an owner and a protected DACL. Inheritance from `C:\ProgramData` is cut. `<S>` is the service SID, `<A>` the SID of the local group `saiife-audit`, and `RX = 0x1200a9` (read and execute):

      | Path | SDDL |
      |---|---|
      | `C:\ProgramData\saiife` | `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;<S>)` |
      | `…\bin`, `…\bin\saiife.exe`, `…\etc` and everything below `etc` | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;<S>)` |
      | `…\state` and everything below it | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)` |
      | `…\state\keys\vault.key` | `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;<S>)` |
      | `…\log` | `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;<S>)(A;;0x1200a9;;;BU)` |
      | `…\log\audit` and everything below it | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;0x1200a9;;;<A>)` |
      | `…\log\daemon` and everything below it | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<S>)(A;OICI;FR;;;<A>)` |
      | the managed files and every dir install creates for them | `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)` |

      - **New dirs are created with their descriptor** (`CreateDirectoryW` with security attributes). So there is no moment where a user could add a file through the inherited `C:\ProgramData` ACL, which lets Users create entries.
      - **Our own paths** must satisfy `protected_ok`: the owner is SYSTEM, Administrators or TrustedInstaller; there is no reparse point; and `writers` ⊆ {SYSTEM, Administrators, TrustedInstaller, plus `<S>` where the table grants it}.
      - **An existing path that fails `protected_ok`** — for example a `C:\ProgramData\saiife`, `C:\ProgramData\OpenAI` or `C:\ProgramData\gemini-cli` created by a user, and so owned by them — is refused with exit 2 naming the path. Install never takes over a dir someone else may still control.
      - **Ancestors** (`C:\`, `C:\ProgramData`, `C:\Program Files`) must satisfy `ancestor_ok`: an owner that is SYSTEM, Administrators or TrustedInstaller (`C:\Program Files` is owned by TrustedInstaller by default), no reparse point, and no non-admin allow ACE (not inherit-only) with `WRITE_DAC`, `WRITE_OWNER`, `DELETE`, `FILE_DELETE_CHILD`, `GENERIC_WRITE` or `GENERIC_ALL`. Users may create new entries in `C:\ProgramData`; that is the default, and it is harmless, because they cannot rename or delete ours.
  15. **W15. The vault key** is `state\keys\vault.key`: 32 random bytes written by install, mode `daemon_file`, never rotated, readable only by `<S>` (plus SYSTEM and Administrators).
      - DPAPI is not used. Install runs as an admin, not as the virtual account, so it cannot seal a key for that account. A DPAPI key that the daemon makes at first start would be lost when the service profile is reset, and the vault with it.
      - On a running machine, the DACL is the barrier, as the file mode is on Linux. Disk encryption (BitLocker) protects backups and images. doctor does not probe it; it prints one Info line that points to the docs.
  16. **W16. Same-user approval is off on Windows (owner ruling 2026-11-05), as on macOS.**
      - `same_user = "reauth"` acts as `"deny"`. A same-user decision is refused with `reauth_unavailable` and `same-user approval is off on Windows: approvals need a second account, from a separate session`. No prompt, no cooldown, no password anywhere, no `LogonUserW`. A requester may still withdraw its own request.
      - Why: the agent's user can capture a console prompt, read the CLI that holds the password, print a prompt of its own or shadow `saiife`. One capture gives it the human's Windows password. See Task 9's report and spec §5.3a.4.
      - **The second account must approve from a separate session.** `runas` on the agent's desktop can be captured. OpenSSH is probably refused by W11's `NU` deny. Switching user and RDP are unverified; handwork step 6 checks them.
  17. **W17. Session attribution uses process names only.** `CreateToolhelp32Snapshot` gives each pid's parent and exe name for every user, with no rights needed. It gives no start time, so pid reuse cannot be detected. `ProcStat.start_time` is 0, and `cmdline` is `None` (as on macOS). Attribution only; nothing is allowed because of it. `node.exe` ancestors get `session = null`.
  18. **W18. The MCP gateway is refused on Windows.** `[mcp.<name>]` is a load error with `MCP_NEEDS_LINUX`, as on macOS. Windows has no Landlock analogue that saiife uses; AppContainer or a job object sandbox is a follow-up. `saiife mcp` (connector tools) works.
  19. **W19. `run --secret` and `run --cloud` work on Windows.**
      - A `run_allow` entry must be an absolute `X:\…\name.exe` path on a local fixed drive. UNC paths and relative paths are load errors.
      - The file must pass `protected_ok` with writers ⊆ {SYSTEM, Administrators, TrustedInstaller}, and every ancestor must pass `ancestor_ok`. There may be no reparse point anywhere in the chain. This check runs where the Linux `root_owned_chain` check runs.
      - The loader-variable scrub gains `COR_ENABLE_PROFILING`, `COR_PROFILER`, `COR_PROFILER_PATH`, `COR_PROFILER_PATH_32`, `COR_PROFILER_PATH_64`, `CORECLR_ENABLE_PROFILING`, `CORECLR_PROFILER`, `CORECLR_PROFILER_PATH*`, `DOTNET_STARTUP_HOOKS` and `__COMPAT_LAYER`, on every platform (harmless elsewhere).
  20. **W20. The MSI.**
      - Built with **WiX Toolset v5.0.2** (MS-RL). WiX v6 and later carry the Open Source Maintenance Fee for projects that earn revenue; that is an owner decision for later.
      - Per machine, one MSI per architecture (`x64`, `arm64`). A fixed `UpgradeCode` is generated once and never changed. `MajorUpgrade` is scheduled `afterInstallExecute`.
      - **It mirrors plan 18 decision 1:** the package owns only `C:\Program Files\saiife\saiife.exe` (`PACKAGE_BINARY`), its docs and one system `PATH` entry for that dir. A deferred custom action, run as SYSTEM, does `"[INSTALLFOLDER]saiife.exe" system install --fleet --package`.
      - `--package` maps exit 1 (installed, doctor warnings or failures) to 0, so the MSI succeeds, and writes the doctor text to `C:\ProgramData\saiife\log\install.log`. Exit 2 fails and rolls back.
      - On removal (`REMOVE="ALL"` and not `UPGRADINGPRODUCTCODE`), a deferred action runs `system uninstall` before the files go, printing plan 18's removal warning to the MSI log and the Application event log (`eventcreate` is not used; the line goes to `install.log` and the daemon's own `stop` record).
      - The fleet files are `C:\ProgramData\saiife\etc\fleet\config.toml` and `install.toml` (plan 18 formats). The deployment tool writes them before the MSI runs.
  21. **W21. Signing.** One signing step, with plan 19a's six `WINDOWS_SIGN_*` secrets, signs both `saiife.exe` builds and then both MSIs, on tag pushes only. `signtool verify /pa` runs after each. Unsigned builds still pass CI.
      - Since mid-2023, CA rules require code-signing keys to live in hardware, so a `.pfx` in a GitHub secret is not an option for a new certificate. Azure Artifact Signing (Microsoft's managed service) keeps the key in Microsoft's HSM.
      - EV certificates no longer give instant SmartScreen reputation. A new signed release builds reputation as it is downloaded. MSIs pushed by Intune or GPO are not checked by SmartScreen.
  22. **W22. Fleet recipes for Windows:**
      - **Intune Win32 app:** the MSI wrapped with `IntuneWinAppUtil.exe`; install `msiexec /i saiife-<v>-<arch>.msi /qn /l*v C:\ProgramData\saiife\log\msi.log`; uninstall `msiexec /x {ProductCode} /qn`; install behavior System. The detection script is `detect.ps1`: it writes to STDOUT and exits 0 only when the service is running and `saiife.exe doctor --json` exits 0 or 1. A platform script, `fleet-files.ps1`, is set as a dependency. Custom compliance uses `discovery.ps1` and `rules.json`, with `saiife_installed` (Boolean) and `saiife_doctor_exit` (Int64), as in plan 18's Linux recipe.
      - **GPO:** assign the MSI under Computer Configuration → Software Installation, from a share readable by Domain Computers. Put the fleet files there with Group Policy Preferences → Files. This is docs only.
  23. **W23. CI `locked-windows`:**
      - The matrix is `windows-2022` and `windows-2025`, both x64. GitHub's Windows runners run as an administrator with UAC disabled, so the job is elevated.
      - ARM64 is built and signed in the release, but its locked flow is owner handwork until a `windows-11-arm` cell is added (follow-up).
      - The scripts are PowerShell 7 (`pwsh`, preinstalled on the runners).
  24. **W24. Claude Code's HKLM policy wins over files.** If `HKLM\SOFTWARE\Policies\ClaudeCode` has a `Settings` value with a policy key, Claude Code uses that source and skips `managed-settings.json` and `managed-settings.d/` by default (code.claude.com, "How Claude Code combines managed sources").
      - Install and doctor read it with `winreg`. With a `Settings` value present and no `"managedSourcesBehavior": "merge"` in it, `agents.claude.policy` **fails**: `HKLM\SOFTWARE\Policies\ClaudeCode sets Claude Code's managed settings, so saiife's drop-in is ignored; add "managedSourcesBehavior": "merge" there, or put saiife's hooks in it`. Install exits 1 with the same line.
      - The user-writable HKCU key is never consulted by Claude Code when an admin source exists, so it is not checked.
  25. **W25. The personal broker (`saiife daemon --user`) on Windows:**
      - The state dir is `%LOCALAPPDATA%\saiife\personal`. The control pipe is `\\.\pipe\saiife-user-<SID>`, owned by the user's SID, with a DACL for that SID only (ruling: `personal_sddl` stays user-only). The client checks that the owner is its own SID.
      - The gateway is TCP plus the token only (W13).
      - The vault key is a Credential Manager generic credential: target `saiife:vault-key`, persist `CRED_PERSIST_LOCAL_MACHINE` (never roaming), blob 32 bytes, through `CredReadW`, `CredWriteW` and `CredDeleteW`.
      - Autostart is the value `saiife-broker` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, set to `"<exe>" daemon --user`, written by `saiife daemon --user --autostart on`.
      - As on Linux, this mode has no boundary against the same user (§6.6, §7).
  26. **W26. Install needs an elevated admin token** (uid 0 by W12). From a non-elevated shell it refuses: `run this from an elevated terminal (Run as administrator)`, exit 2.
  27. **W27. Agent users that can become admin.**
      - An agent user in `Administrators`, `Backup Operators`, `Server Operators`, `Hyper-V Administrators` or `Account Operators` is a doctor **fail**. Each is root-equivalent; by default, UAC elevates an admin with a consent click and no password (`ConsentPromptBehaviorAdmin = 5`).
      - It drops to a **warning** only for `Administrators`, and only when `ConsentPromptBehaviorAdmin = 1` (credentials on the secure desktop) and `PromptOnSecureDesktop = 1`: `agent user <u> is an administrator: elevation needs its password`.
  28. **W28. Binary hardening (the A4 analogue).**
      - Release and CI builds link the CRT statically and set `/DEPENDENTLOADFLAG:0x800` (plan 19a Task 9), so load-time DLLs come only from System32. The daemon and the CLI call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` first thing in `main`.
      - `binary::inspect_pe` refuses a debug build, a binary without the flag, and imports outside the allowlist. It warns on a missing Authenticode signature.
      - Windows has no `LD_PRELOAD`; DLL planting in the cwd or on `PATH` is the attack, and the `locked-windows` job tests it.
- **Spec values, verbatim:**
  - Claude Code: `C:\Program Files\ClaudeCode\managed-settings.json`, `managed-settings.d/`, and `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings` (`REG_SZ` or `REG_EXPAND_SZ`);
  - Codex: `%ProgramData%\OpenAI\Codex\requirements.toml`; `[features] hooks = true`; `allow_managed_hooks_only`;
  - Gemini CLI: `C:\ProgramData\gemini-cli\settings.json` (overridable by `GEMINI_CLI_SYSTEM_SETTINGS_PATH`, as on Linux; doctor already warns);
  - the refusal line `saiife: locked mode is not supported here: <why>. Developer mode works as before.`;
  - `doctor --json` is `{"saiife_doctor":1,"exit":<n>,"checks":[…]}`, with exit codes 0, 1 and 2.

## Review Focus

1. **A dir that already exists before install, made by someone else.** `C:\ProgramData\saiife`, `C:\ProgramData\OpenAI\Codex` or `C:\ProgramData\gemini-cli` created by the agent's user (so the user owns it and keeps `WRITE_DAC`), or a junction placed there. Expected: exit 2 naming the path, nothing written; a reinstall over our own earlier tree passes (Task 7: `user_owned_programdata_saiife_refused`, `junction_in_chain_refused`, `own_previous_tree_accepted`; Task 12: phase `squat`).
2. **A squatted pipe.** The agent's user creates `\\.\pipe\saiife` while the service is stopped or restarting. Expected: the daemon refuses to start, with the log line; every hook denies with `error_denied` because the owner check fails, and no record or payload reaches the fake server (Task 4: `client_refuses_foreign_pipe_owner`; Task 5: `daemon_refuses_existing_pipe`; Task 12: phase `attacks`).
3. **The agent user is a local admin.** UAC elevates it with one click. Expected: doctor fails host checks for that user unless the consent policy asks for credentials on the secure desktop, and then it warns (Task 8: `admin_agent_user_fails_by_default`, `admin_agent_user_warns_with_credential_prompt`, `backup_operators_fails`).
4. **Claude Code settings also pushed through HKLM** (Intune, GPO). Expected: install exits 1 and doctor fails `agents.claude.policy` with the W24 text. With `"managedSourcesBehavior": "merge"` in the HKLM JSON, it passes (Task 6: `hklm_settings_without_merge_fails`, `hklm_merge_passes`; Task 8).
5. **Same-user approval on Windows is off.** Expected: `same_user = "reauth"` refuses with W16's text and no prompt or password path exists (Task 9: `same_user_approval_is_off_on_windows`; Task 10's `same_user_approval_is_off_and_the_requester_can_withdraw`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (layout and ACL table), Task 3 (PE and service spec; pure parts).
- **Wave 2 (parallel):** Task 2 (FFI: SDs, ACLs, accounts, tokens; Windows `Host`; supported; needs 1), Task 4 (pipes and IPC; needs 2's `sd.rs` and `token.rs`, so start it after Task 2's Step 3 lands).
- **Wave 3 (parallel):** Task 5 (daemon; needs 2, 4), Task 6 (managed hooks; needs 1).
- **Wave 4 (parallel):** Task 7 (install and uninstall; needs 2, 3, 5, 6), Task 9 (re-authentication; needs 5).
- **Wave 5 (parallel):** Task 8 (doctor; needs 7), Task 10 (CLI clients and `run`; needs 4, 5), Task 11 (personal broker; needs 4, 5).
- **Wave 6 (parallel):** Task 12 (`locked-windows`; needs 7–11), Task 13 (MSI and recipes; needs 7).
- **Last:** Task 14 (lock-check harness, docs, spec notes), the gates, a whole-branch review, one fix wave, push, PR, CI (including both `locked-windows` cells and `package-windows`). The owner merges.

**Shared files:** `crates/system/src/install.rs` (Task 7 only), `crates/cli/src/main.rs` (Task 10; Task 11 adds `cmd_daemon_user`), `crates/daemon/src/lib.rs` (Task 5), `.github/workflows/ci.yml` (Tasks 12 and 13, separate jobs), `.github/workflows/release.yml` (Task 13).

---

### Task 1: the Windows layout and the ACL table (pure)

**Files:**
- Modify `crates/system/src/layout.rs` and `crates/system/src/default_config.rs`, `crates/policy/src/system.rs` (`DaemonCfg::default` on Windows), and `crates/cli/src/paths.rs` (`SYSTEM_PATHS` on Windows).
- Create `crates/system/src/winacl.rs`.

**Interfaces (Produces):**
- `layout::windows_path(linux: &str) -> Option<&'static str>`: the W9 table. `Layout::at` applies it when the platform is `Windows`, and `Layout::under_for(root, Platform::Windows)` puts `X:\a\b` at `<root>/X/a/b`. On real Windows, `Layout::system()` has root `C:\`.
- `pub enum Endpoint { Unix(PathBuf), Pipe(String) }` and `Layout::control_endpoint() -> Endpoint`: `Pipe(r"\\.\pipe\saiife")` on Windows, `Unix(at(SOCKET))` elsewhere.
- New constants: `WIN_PIPE = r"\\.\pipe\saiife"`, `WIN_PERSONAL_PIPE_PREFIX = r"\\.\pipe\saiife-user-"`, `WIN_SERVICE = "saiifed"`, `WIN_SERVICE_DISPLAY = "saiife daemon"`, `WIN_DAEMON_ACCOUNT = r"NT SERVICE\saiifed"`, `WIN_AUDIT_GROUP = "saiife-audit"`, `WIN_HOOK_BINARY = "C:/ProgramData/saiife/bin/saiife.exe"`, `CLAUDE_HKLM_KEY = r"SOFTWARE\Policies\ClaudeCode"`, `WIN_SERVICE_SDDL` (W10).
- `Layout::{daemon_user, audit_group, unit_name}()` on Windows: `WIN_DAEMON_ACCOUNT`, `WIN_AUDIT_GROUP`, `WIN_SERVICE`.
- `winacl::expected(layout: &Layout, path: &Path, audit_sid: &str) -> Option<String>`: the W14 SDDL for a path of the layout (`<S>` and `<A>` filled in), `None` for a path the table does not cover.
- `winacl::protected_ok(sd: &Sd, extra_writers: &[&str]) -> Result<(), String>` and `winacl::ancestor_ok(sd: &Sd) -> Result<(), String>` (W14), with texts `owned by <sid>, expected SYSTEM, Administrators or TrustedInstaller` and `<sid> may <right> here`.

- [ ] **Step 1: failing tests:**
  - `windows_paths_are_spec_values` (the full W9 table);
  - `under_for_windows_maps_every_constant`;
  - `control_endpoint_per_platform`;
  - `expected_sddl_table` (every W14 row, with a fixed `<A>`);
  - `vault_key_readable_only_by_service`;
  - `protected_ok_refuses_user_owner`, `protected_ok_refuses_user_write`, `protected_ok_refuses_append_only_grant`;
  - `ancestor_ok_accepts_programdata_default` (the real default `C:\ProgramData` SDDL as a fixture, from Microsoft's documented default);
  - `ancestor_ok_refuses_delete_child_for_users`;
  - `daemon_cfg_default_windows`;
  - `linux_and_macos_layouts_unchanged`.
- [ ] **Step 2:** run `cargo test -p saiife-system -p saiife-policy`; expect FAIL.
- [ ] **Step 3:** implement. `windows_path` is one `match`.
- [ ] **Step 4:** the tests pass; the Windows and macOS checks are clean.
- [ ] **Step 5:** commit `feat(system): Windows layout and ACL table (spec 5.3a)`.

### Task 2: `saiife-win` FFI for ACLs, accounts and tokens; the Windows `Host`; supported check

**Files:**
- Create `crates/win/src/ffi/{sd.rs, acl.rs, account.rs, token.rs}`; modify `crates/win/Cargo.toml` (the `windows-sys` features: `Win32_Foundation`, `Win32_Security`, `Win32_Security_Authorization`, `Win32_Storage_FileSystem`, `Win32_NetworkManagement_NetManagement`, `Win32_System_Threading`) and plan 19a's FFI table in `docs/superpowers/plans/2026-10-30-plan-19a-windows-dev-mode.md`.
- Modify `crates/system/src/host.rs` (Windows `RealHost`; `FakeHost` gains the Windows methods), `crates/system/src/supported.rs`, `crates/system/Cargo.toml` (Windows: `saiife-win`, `windows-service`, `winreg`), and `crates/policy/src/users.rs` (`WinDirectory`; `crates/policy/Cargo.toml` gains `saiife-win` on Windows).

**Interfaces:**
- Produces, in `saiife_win::ffi` (Windows only; each returns `io::Result` with the Win32 error code):
  - `sd::from_sddl(&str) -> io::Result<SecurityDescriptor>` (RAII over `LocalFree`); `SecurityDescriptor::as_ptr()`, `owner_sid()`, `dacl()`;
  - `acl::get_sddl(path: &Path) -> io::Result<String>` (owner, group and DACL);
  - `acl::set_sddl(path: &Path, sddl: &str) -> io::Result<()>` (owner, protected DACL and any group, through `SetSecurityInfo` on a no-follow handle; a hard-linked file is refused);
  - `acl::create_dir_with_sddl(path: &Path, sddl: &str) -> io::Result<()>`;
  - `account::lookup_name(name: &str) -> io::Result<(String /*sid*/, String /*DOMAIN\name*/)>`; `account::lookup_sid(sid: &str) -> io::Result<String /*DOMAIN\name*/>`;
  - `account::local_groups_of(user: &str) -> io::Result<Vec<String>>` (with `LG_INCLUDE_INDIRECT`); `account::local_group_members(group: &str) -> io::Result<Vec<String>>`;
  - `token::current() -> io::Result<TokenFacts>`, where `TokenFacts { sid: String, group_sids: Vec<String>, elevated_admin: bool }`. `elevated_admin` means `ADMINISTRATORS` is among the groups with `SE_GROUP_ENABLED` and without `SE_GROUP_USE_FOR_DENY_ONLY`;
  - `token::facts_of(token: HANDLE) -> io::Result<TokenFacts>` (shared with Task 4).
- Produces, in `saiife-system` (`Host` methods; `RealHost` on Windows, recorded by `FakeHost`; unix `RealHost` returns `Unsupported`):
  - `fn set_sddl(&self, path: &Path, sddl: &str) -> io::Result<()>`, `fn get_sddl(&self, path: &Path) -> io::Result<String>`, `fn create_dir_sddl(&self, path: &Path, sddl: &str) -> io::Result<()>`;
  - `fn lookup_sid(&self, name: &str) -> Option<String>`;
  - `fn reg_string(&self, key: &str, value: &str) -> Option<String>` and `fn reg_dword(&self, key: &str, value: &str) -> Option<u32>` (HKLM only);
  - `fn windows_build(&self) -> io::Result<WinBuild>`, where `WinBuild { build: u32, server: bool }` comes from `CurrentBuildNumber` and `InstallationType`;
  - `fn service(&self, op: ServiceOp) -> io::Result<ServiceState>` (Task 3 defines `ServiceOp`, `ServiceSpec` and `ServiceState`; `RealHost` maps them onto `windows-service`);
  - on Windows, `euid()` is `uid_of(token.sid, token.elevated_admin)`; `create_system_group` and `add_to_group`/`remove_from_group`/`delete_group` run `net.exe localgroup … /add|/delete` (exit code only, never the localized text); `create_system_user`, `delete_user` and `chown` return `Unsupported`.
  - `FakeState` gains `sddl: BTreeMap<PathBuf, String>`, `registry: BTreeMap<(String, String), RegValue>`, `build: WinBuild` (default 26100, server) and `services: BTreeMap<String, ServiceSpec>`; each call is recorded as a line.
- Produces, in `supported.rs`, on Windows:
  - `MIN_WIN_CLIENT_BUILD = 22631`, `MIN_WIN_SERVER_BUILD = 20348`;
  - a refusal reads `Windows build 19045 is not supported for locked mode (Windows 11 23H2 / Server 2022 or later)`;
  - also refused: non-default folders (W9), a Windows container (`HKLM\SYSTEM\CurrentControlSet\Control\ContainerType` present), and a non-elevated token (W26);
  - `NOT_SUPPORTED_OS` becomes `locked mode needs Linux, macOS or Windows`.
- Produces, in `policy::users`: `WinDirectory` implements `Directory` (W12). `user()` returns `UserEntry { uid: uid_of(sid, false), gid: 0 }`; `name_of()` answers from a cache of the SIDs this process resolved or saw; `group()` and `groups_of()` use the `account` calls. Names may contain spaces and `\`; `valid_name` on Windows refuses only empty names, control characters and a leading `-`.

- [ ] **Step 1: failing tests:**
  - pure, on Linux: `windows_supported_from_22631`, `windows_19045_refused` (the exact text), `server_2022_supported`, `container_refused`, `non_default_program_files_refused`, `not_elevated_refused`, `fake_host_records_sddl_and_registry`, `net_localgroup_argv`;
  - Windows CI (`test` job, no admin): `current_token_has_user_sid`, `lookup_name_of_own_user_roundtrips`, `get_sddl_of_temp_dir_parses`, `set_sddl_on_temp_dir_roundtrips` (on a dir under `RUNNER_TEMP`, with the runner user's own SID as owner), `create_dir_with_sddl_has_no_inherited_aces`, `local_groups_of_runner_includes_users`.
- [ ] **Step 2:** run `cargo test -p saiife-system -p saiife-policy`; expect FAIL. The Windows check fails (missing FFI).
- [ ] **Step 3:** implement. Update plan 19a's FFI table if the list changed.
- [ ] **Step 4:** the tests pass; the Windows check is clean; `bash scripts/check-unsafe.sh` exits 0; the tokio gate is clean.
- [ ] **Step 5:** commit `feat(win): ACL, account and token FFI; Windows Host and supported check`.

### Task 3: PE inspection and the service spec

**Files:**
- Modify `crates/system/src/binary.rs`.
- Create `crates/system/src/winservice.rs`.

**Interfaces (Produces):**
- `binary::inspect_pe(bytes: &[u8]) -> Result<PeInfo, String>`. It reads `MZ` → `PE\0\0` → the optional header (PE32+ only; PE32 is refused with `32-bit binaries are not supported`), the import directory, the security directory and the load config's `DependentLoadFlags`.
- `pub struct PeInfo { pub machine: u16, pub signed: bool, pub imports: Vec<String>, pub dependent_load_flags: u16, pub debug_marker: bool }`. `signed` means a non-empty security directory; its validity is checked by `signtool` in CI and by `Get-AuthenticodeSignature` in doctor (Task 8).
- `PeInfo::problems(&self, allow: &[&str]) -> Vec<String>`: the debug marker (the same marker the ELF and Mach-O checks use); `DependentLoadFlags & 0x800 == 0`; and any import not in `allow`, unless it starts with `api-ms-win-` or `ext-ms-win-` (API sets, which the loader maps without a file search). `PeInfo::warnings()` holds `not Authenticode-signed (spec 5.3a.6)`.
- `binary::PE_IMPORT_ALLOWLIST: &[&str]`: start with `kernel32.dll`, `ntdll.dll`, `advapi32.dll`, `bcrypt.dll`, `bcryptprimitives.dll`, `ws2_32.dll`, `userenv.dll`, `crypt32.dll`, `secur32.dll`, `netapi32.dll`, `ole32.dll`, `oleaut32.dll`, `shell32.dll` and `iphlpapi.dll`. The implementer reads the real import list of the CI build (`dumpbin /imports` in the `locked-windows` job log, or `inspect_pe` printing them) and freezes it here. Every entry must be a System32 DLL.
- `winservice::ServiceSpec { name, display, binary: PathBuf, args: Vec<String>, account: String, start: StartKind, sid_type: SidType, failure: FailurePolicy, sddl: String }` with `ServiceSpec::saiifed(layout: &Layout) -> ServiceSpec` (the W10 values) and `fingerprint() -> String` (SHA-256 of a canonical `key=value;…` text). `installed.toml` records it as `FileKind::Service`.
- `winservice::ServiceOp { Query, Create(ServiceSpec), Update(ServiceSpec), Start, Stop { wait: Duration }, Delete, SetSddl(String), ParamChange }` and `ServiceState { Missing, Stopped, Running { pid: u32 }, Other(String) }`.

- [ ] **Step 1: failing tests** (a test helper `pe_fixture(flags: PeFixture) -> Vec<u8>` builds minimal PE32+ bytes):
  - `pe_reads_machine_and_imports`, `pe32_refused`, `missing_dependent_load_flag_refused`, `foreign_import_refused`, `api_set_imports_allowed`, `unsigned_warns`, `debug_marker_refused`, `elf_is_not_pe`;
  - `own_test_binary_parses` (Windows CI: `inspect_pe(current_exe())` is `Ok` and the flag is set, which proves Task 9 of plan 19a took effect in test builds too);
  - `saiifed_spec_values` (every W10 value), `fingerprint_changes_with_any_field`.
- [ ] **Step 2:** run `cargo test -p saiife-system binary winservice`; expect FAIL.
- [ ] **Step 3:** implement. The parser works on the bytes alone; no external tool.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(system): PE import/signature/load-flag check and the saiifed service spec`.

### Task 4: the named pipe: server, client and peer identity

**Files:**
- Create `crates/win/src/ffi/pipe.rs`; modify `crates/win/Cargo.toml` (`pipe-server = ["dep:tokio"]`, `tokio = { version = "1", features = ["net"], optional = true }`; `windows-sys` gains `Win32_System_Pipes`).
- Modify `crates/ipc/src/lib.rs` (`peer` and `client` exist on Windows too), `crates/ipc/src/peer.rs`, `crates/ipc/src/client.rs` (a Windows transport behind the same `Client` API), `crates/ipc/Cargo.toml` (Windows: `saiife-win`).

**Interfaces:**
- Consumes `token::facts_of`, `sd::from_sddl` (Task 2) and `sid::{service_sid, uid_of}`.
- Produces, in `saiife_win::ffi::pipe`:
  - `create_server(name: &str, sddl: &str, first: bool) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer>` (feature `pipe-server`). It sets `first_pipe_instance(first)`, `reject_remote_clients(true)`, `max_instances(254)` and byte mode;
  - `client_facts(pipe: &impl AsRawHandle) -> io::Result<PipeClient>`, where `PipeClient { facts: TokenFacts, pid: u32 }`. It is synchronous and impersonates, reads and reverts in one call (W11). A failing `RevertToSelf` aborts the process;
  - `owner_sid(handle: &impl AsRawHandle) -> io::Result<String>`.
- Produces, in `saiife-ipc`:
  - `PeerCred` gains `pub sid: Option<String>` and `pub group_sids: Vec<String>` (`None` and empty on unix);
  - `peer::pipe_peer(server: &NamedPipeServer) -> io::Result<PeerCred>` (Windows): `uid = uid_of(sid, elevated_admin)`, `gid = 0`;
  - `client::Client::connect_pipe(name: &str, expect_owner: &str, deadline: Instant) -> Result<Client, ClientError>` (Windows). The existing `Client::connect(…)` keeps its signature; on Windows, its callers in the CLI pass the layout's `Endpoint`, and a `Pipe` endpoint goes through `connect_pipe` with `expect_owner = service_sid("saiifed")`;
  - `client::system_sid() -> String` (Windows).
- The frame codec, `hello` and every op are unchanged.

- [ ] **Step 1: failing tests:**
  - pure: `pipe_sddl_has_no_create_instance_for_users` (parse `W11`'s SDDL: the BU ACE lacks `0x4`; NU is denied), `peer_cred_unix_has_no_sid`;
  - Windows CI (no admin; a server created by the test with the runner user's own SID as owner): `pipe_roundtrip_hello`, `client_facts_names_the_runner`, `client_refuses_foreign_pipe_owner` (expect an owner SID that is not the creator's: `Owner` error, and the server sees zero bytes), `second_first_instance_fails`, `remote_clients_rejected_flag_set`, `pipe_busy_retried_until_deadline`, `deadline_bounds_a_silent_server` (200 ms; `Timeout`; the server task is dropped, not killed by name).
- [ ] **Step 2:** run `cargo test -p saiife-ipc -p saiife-win`; expect FAIL on the pure tests. The Windows check fails.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the Windows check is clean; the tokio gate shows no tokio in `cargo tree -e normal -p saiife-ipc -p saiife-win` (without `pipe-server`).
- [ ] **Step 5:** commit `feat(ipc): named pipe transport with token identity and pipe-owner check`.

### Task 5: the daemon on Windows

**Files:**
- Create `crates/win/src/ffi/{service.rs, process.rs, proc.rs}`.
- Modify `crates/daemon/Cargo.toml` (Windows: `saiife-win` with `pipe-server`), and in `crates/daemon/src/`: `lib.rs`, `start.rs`, `server.rs`, `signals.rs`, `sessions.rs`, `disk.rs`, `vault.rs`, `gateway.rs`, `forward_syslog.rs`, `forward_file.rs`, `notify.rs`, `writer.rs`/`ops.rs` (the record's `sid`), and `mcp_gateway/mod.rs`.
- Modify `crates/audit/src/record.rs` (`sid: Option<String>`, `skip_serializing_if = "Option::is_none"`), `crates/policy/src/load.rs` (the uid-collision check; `validate_mcp` gets `cfg!(target_os = "linux")` as today), and `crates/cli/src/main.rs` (`cmd_daemon` on Windows: `--system` inside the service dispatcher).

**Interfaces:**
- Consumes Tasks 1–4.
- Produces:
  - `saiife_win::ffi::service::run_as_service(name: &'static str, main: fn(ServiceCtl) -> i32) -> io::Result<()>`. `ServiceCtl` gives `stop: tokio::sync::Notify`-like signalling without tokio in `saiife-win`: a `std::sync::mpsc::Receiver<Control>` with `Control { Stop, Reload }`, plus `set_running()` and `set_stopped(code)`;
  - `saiife_win::ffi::process::{harden_dll_search(), redirect_stderr(file: File), disk_free_bytes(dir: &Path) -> io::Result<u64>}`;
  - `saiife_win::ffi::proc::snapshot() -> io::Result<Vec<ProcEntry>>`, where `ProcEntry { pid, ppid, exe: String }`;
  - `sessions::WinProc` implements `Proc` from one snapshot per lookup, cached for 200 ms. `stat` gives `ProcStat { ppid, comm: exe lower-cased without ".exe", start_time: 0 }`; `cmdline` is `None` (W17). `sessions::host_proc()` returns it on Windows;
  - the control server on Windows: an accept loop that keeps one free server instance ahead (create the next instance before handling the connected one), `pipe_peer` per connection, then the existing `connection` logic, made generic over `AsyncRead + AsyncWrite`. If the first instance cannot be created because the name exists, it logs the W11 line and exits 1;
  - `signals`: the `Control` channel from `run_as_service` feeds the existing stop and reload paths. Outside the service (tests), Ctrl+C stops it;
  - `disk::free_mb` uses `disk_free_bytes` on Windows;
  - `vault::open` accepts the Windows key when `get_sddl(key)` passes `winacl::protected_ok(…, &[])` and grants `<S>` read;
  - `start::VAULT_KEY_FILE` is `"vault.key"` on Windows;
  - the hostname is `COMPUTERNAME` from the service environment;
  - `forward_syslog`: on Windows, a local socket target is a load error, `syslog to a local socket is not available on Windows; use a udp, tcp or tls target`;
  - `gateway`: Windows serves only `serve_tcp`, and `[gateway] socket` settings are a load error there;
  - each record written for a Windows peer carries `sid`;
  - `policy::load`: two principals with the same uid are a load error (W12 text).

- [ ] **Step 1: failing tests:**
  - pure: `win_proc_walks_names_from_fixture_snapshot` (fake snapshot: `claude.exe` → `pwsh.exe` → `saiife.exe`: the session is Claude's), `node_ancestor_has_no_session`, `record_sid_serialized_only_when_set`, `uid_collision_is_load_error`, `local_syslog_refused_on_windows` (via a `windows: bool` parameter), `gateway_socket_setting_refused_on_windows`;
  - Windows CI (`test` job, no admin, the daemon in tempdirs as the runner user, outside the service manager): the daemon suites that start an unprivileged daemon (`crates/daemon/tests/*` without Landlock, polkit or `/proc`), on a test pipe name `\\.\pipe\saiife-test-<random>` and an owner of the runner's SID; `proc_snapshot_has_own_parent`; `disk_free_of_temp_is_positive`; `daemon_refuses_existing_pipe` (the test makes the pipe first).
- [ ] **Step 2:** run `cargo test -p saiife-daemon -p saiife-policy -p saiife-audit`; Linux passes unchanged and the new pure tests fail.
- [ ] **Step 3:** implement. Do not change Linux or macOS behaviour.
- [ ] **Step 4:** the tests pass; the Windows check is clean; `bash scripts/check-unsafe.sh` exits 0.
- [ ] **Step 5:** commit `feat(daemon): saiifed as a Windows service (pipes, token peers, Toolhelp sessions)`.

### Task 6: managed hooks for the three agents on Windows

**Files:**
- Modify `crates/agents/src/lib.rs`, `claude.rs`, `codex.rs`, `gemini.rs` and `crates/agents/Cargo.toml` (Windows: `winreg`).
- Modify `crates/system/src/layout.rs` (`managed_file` on Windows) and `crates/system/src/install.rs` call sites (pass the platform).

**Interfaces (Produces):**
- `Agent::managed_command_on(self, windows: bool) -> String`: on Windows it is `C:/ProgramData/saiife/bin/saiife.exe check --managed --hook-exit --agent <a>` (W9). `managed_command()` = `managed_command_on(cfg!(windows))`. The config-change command follows the same rule.
- `claude::managed_settings_for(windows: bool)`, `codex::install_managed_for(file, windows)` and `gemini::install_managed_for(file, windows)` write that command. Fingerprints are computed from what was written, so a Windows file and a Linux file differ only in the command.
- Codex on Windows writes `command` only, not `command_windows`. If the live check (Task 14) shows that Codex on Windows reads `command_windows` instead, the task adds it with the same value.
- `claude::hklm_policy(reg: &dyn Fn(&str, &str) -> Option<String>) -> HklmPolicy`, where `HklmPolicy { Absent, Merge, Overrides }`: `Merge` when the JSON in `Settings` has `"managedSourcesBehavior": "merge"`; `Overrides` for any other value with a policy key; `Absent` otherwise (W24).
- `claude::HKLM_OVERRIDES_TEXT` (the W24 text).

- [ ] **Step 1: failing tests:**
  - `windows_managed_commands` (all three agents, the exact strings);
  - `windows_claude_dropin_golden`, `windows_codex_requirements_golden`, `windows_gemini_settings_golden`;
  - `hklm_settings_without_merge_fails` (returns `Overrides`), `hklm_merge_passes` (`Merge`), `hklm_absent`, `hklm_only_control_keys_is_absent` (a value with only `managedSourcesBehavior` and `wslInheritsWindowsSettings` holds no policy key, so Claude Code moves on to the files);
  - `linux_managed_files_unchanged`.
- [ ] **Step 2:** run `cargo test -p saiife-agents`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(agents): Windows managed hooks for Claude Code, Codex and Gemini; HKLM policy check`.

### Task 7: `system install` and `system uninstall` on Windows

**Files:**
- Modify `crates/system/src/install.rs`, `crates/system/src/uninstall.rs`, `crates/system/src/fleet.rs` (plan 18: the Windows fleet paths; `--package`), `crates/policy/src/installed.rs` (`FileKind::Service`), and `crates/cli/src/system_cmd.rs` (`--package`).

**Interfaces:**
- Consumes Tasks 1, 2, 3, 5 and 6, and plan 18's `--fleet`.
- The Windows install sequence (`install` branches on `layout.platform()`):
  1. Check elevation and supported (Task 2).
  2. For every dir the sequence creates and every existing dir it writes into, run the W14 checks: our own paths must pass `protected_ok`, or be listed in an earlier `installed.toml` and still match the table; ancestors must pass `ancestor_ok`; any reparse point is refused. On any refusal, exit 2 before anything is written.
  3. Create the local group `saiife-audit` when it is missing, and look up its SID.
  4. Create `C:\ProgramData\saiife` and its subdirs with `create_dir_sddl` (W14), then the bin dir. Copy the binary in through `inspect_pe` (refusing on `problems()`, warning on `warnings()`; `--allow-test-build` as on Linux). Write `etc\` (config, policy.d, fleet when `--fleet`), `state\keys\vault.key` and the log files, each followed by `set_sddl` with its table entry.
  5. Write the three managed files. Create `C:\Program Files\ClaudeCode` and `managed-settings.d`, `C:\ProgramData\OpenAI\Codex` and `C:\ProgramData\gemini-cli` when they are missing, with descriptors. Read the HKLM policy (W24); `Overrides` adds a failure line.
  6. Service: `Query`. When it is missing, `Create`; when its spec differs, `Update`. Then `SetSddl(WIN_SERVICE_SDDL)`. Start it when it is stopped. When it runs and the binary, the spec or membership changed, `Stop` (10 s) and `Start`. When only `config.toml` changed, `ParamChange` (plan 18 decision 5).
  7. Wait 10 s for the pipe (connect with the owner check). The failure text ends with `(see C:\ProgramData\saiife\log\daemon\daemon.log)`.
  8. Write `installed.toml`, including `FileKind::Service` with the fingerprint, then run doctor as today.
- Uninstall on Windows:
  - `Stop` (wait 10 s; if it still runs, refuse, as `stopped_or_refuse` does), then `Delete`;
  - remove the files listed in `installed.toml`;
  - `--purge` also removes `state`, `log`, `etc` and the `saiife-audit` group;
  - managed files are removed only when their fingerprint still matches (as on Linux).
- `--package` (with `--fleet`): exit 1 becomes 0, and the doctor text is appended to `C:\ProgramData\saiife\log\install.log`.

- [ ] **Step 1: failing tests** (`Layout::under_for(tmp, Platform::Windows)`, `FakeHost` with canned SDDL for the ancestors, and a fake PE from Task 3's helper; module `windows_tests`, run on Linux):
  - `windows_fresh_install_writes_spec_paths_and_acls` (every W9 path exists and its recorded SDDL equals `winacl::expected`);
  - `windows_dirs_created_with_descriptor` (the fake records `create_dir_sddl`, never `create_dir` followed by `set_sddl`, for each dir);
  - `user_owned_programdata_saiife_refused`, `user_owned_codex_dir_refused`, `junction_in_chain_refused`, `own_previous_tree_accepted`;
  - `windows_service_created_then_unchanged_on_reinstall`, `windows_config_change_sends_paramchange`, `windows_binary_change_restarts`;
  - `windows_hklm_overrides_exits_1`;
  - `windows_unfit_binary_refused` (no load flag; a debug marker), `windows_unsigned_binary_warns`;
  - `windows_uninstall_removes_exactly_what_install_listed`, `windows_uninstall_refuses_when_service_will_not_stop`, `windows_purge_deletes_group`;
  - `package_flag_maps_exit_1_to_0`;
  - `installed_toml_service_kind_roundtrip` (policy).
- [ ] **Step 2:** run `cargo test -p saiife-system -p saiife-policy`; expect FAIL.
- [ ] **Step 3:** implement. Every existing Linux and macOS test passes unchanged.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(system): system install/uninstall on Windows (service, ACLs, managed hooks)`.

### Task 8: `saiife doctor` on Windows

**Files:**
- Modify `crates/system/src/doctor/{system.rs, host.rs, mod.rs}`, `crates/cli/src/doctor_cmd.rs` and `crates/cli/src/system_cmd.rs`.

**Interfaces:**
- Consumes Tasks 2, 3, 6 and 7.
- Produces, on Windows (the check ids are the existing ones unless marked new):
  - `system.supported`: the build and edition;
  - `daemon.unit`: the service spec matches the fingerprint in `installed.toml`, its SDDL equals `WIN_SERVICE_SDDL` (parsed, compared as `Sd`), and it is running;
  - `daemon.health`: as on Linux, over the pipe;
  - `files.binary`: `inspect_pe` problems fail and warnings warn. When signed, `WinVerifyTrust` must accept it, in-process: an elevated doctor starts no PowerShell, whose environment and HKCU settings the caller's user controls;
  - `files.acl` (new): every path in the W14 table has its expected descriptor; ancestors pass `ancestor_ok`;
  - `vault.key`: `daemon key file, readable only by NT SERVICE\saiifed`;
  - `reauth`: Info `same-user approval is off on Windows: approvals need a second account, from a separate session`;
  - `peer.pidfd`: Info `named pipe; caller identity from its token (the pid is used for attribution only)`;
  - `agents.claude.policy` (new): W24;
  - host checks per agent user: W27 (the groups through `account::local_groups_of`; the UAC values through `reg_dword` under `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`); agent binaries writable by the agent user warn as on Linux (`%USERPROFILE%\.local\bin\claude.exe`, `%APPDATA%\npm`);
  - `mcp.landlock`: Info `MCP gateway: Linux only in this version`;
  - the egress hint: Info `the egress recipe is Linux only`;
  - `disk.encryption` (new): Info `see docs/windows.md#disk-encryption for BitLocker` (W15).

- [ ] **Step 1: failing tests** (Linux, `Layout::under_for(tmp, Platform::Windows)`, `FakeHost` canned outputs after a fake install):
  - `windows_doctor_after_fake_install_fails_only_daemon_checks`;
  - `acl_drift_fails_files_acl` (one path with an extra `(A;;FA;;;BU)`);
  - `service_sddl_drift_fails_daemon_unit`;
  - `admin_agent_user_fails_by_default`, `admin_agent_user_warns_with_credential_prompt`, `backup_operators_fails`;
  - `hklm_overrides_fails_claude_policy`;
  - `windows_doctor_json_exit_codes`.
- [ ] **Step 2:** run `cargo test -p saiife-system doctor`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(doctor): Windows checks (service, ACLs, PE, UAC, HKLM policy)`.

### Task 9: same-user approval off on Windows

Rewritten by the owner's ruling of 2026-11-05 (W16). The first design, password re-authentication through `LogonUserW`, was never built.

**Files:** `crates/daemon/src/reauth.rs` (`SecondAccountOnly`), `approvers.rs` (`Refusal::SameUserOff`), `crates/system/src/layout.rs` (`WIN_SAME_USER_OFF`), `install_win.rs`, `crates/cli/src/approvals_cmd.rs` and `main.rs` (approvals run on Windows), `crates/cli/src/secret_cmd.rs` and `Cargo.toml` (`rpassword`, for secret values only).

- [x] Tests: `same_user_approval_is_off_on_windows`, and in Windows CI `same_user_approval_is_off_and_the_requester_can_withdraw`.
- [x] Docs and spec say the second account approves from a separate session, and which ways of doing that are unverified.

### Task 10: the CLI's locked mode on Windows (hook, clients, `run`)

**Files:**
- Modify in `crates/cli/src/`: `main.rs` (drop `LOCKED_ON_WINDOWS_LATER`; call `harden_dll_search()` first), `check_managed.rs`, `broker.rs`, `status_cmd.rs`, `api_cmd.rs`, `secret_cmd.rs`, `import_cmd.rs`, `connect_cmd.rs`, `lockdown_cmd.rs`, `env_cmd.rs`, `policy_cmd.rs`, `audit_locked.rs`, `mcp_cmd.rs`, `run_cmd.rs`. `mcp_spawn` stays Linux-only.
- Modify `crates/policy/src/load.rs` (`run_allow` on Windows) and the CLI integration tests that can run on Windows.

**Interfaces:**
- Consumes Tasks 4, 5, 7 and 9.
- Produces:
  - the managed hook on Windows connects through `Layout::control_endpoint()` and `Client::connect_pipe` (Task 4); every failure denies, as on Linux;
  - `run_cmd::is_loader_var(n)` gains the W19 names on every platform;
  - `load::RunAllowBad::{NotWindowsExe, Unc, Relative}` with texts `run_allow entry {e} must be an absolute path to an .exe on a local drive`;
  - `run_cmd::win::chain_ok(path: &Path, host: &dyn Host) -> Result<(), String>`: W19's file and ancestor checks;
  - `audit_locked`: an auditor on Windows is a peer whose `group_sids` holds the `saiife-audit` SID;
  - `policy reload` on Windows sends the IPC reload op as today (no `sc.exe` needed).

- [ ] **Step 1: failing tests:**
  - `loader_vars_include_dotnet_profilers` (all platforms);
  - `run_allow_windows_forms` (pure: `C:\Tools\aws.exe` passes; `\\srv\share\x.exe`, `tools\aws.exe` and `C:\Tools\aws` are refused with the texts);
  - `chain_ok_refuses_user_writable_dir` (FakeHost SDDL);
  - Windows CI: the CLI integration suites that start an unprivileged daemon in tempdirs (hook, `api`, `secret`, `run --secret`). The `run --secret` suite puts its test `.exe` in a temp dir owned by the runner, which `chain_ok` would refuse. So debug builds read `SAIIFE_TEST_TRUST_SID=<sid>`, which adds one SID to the trusted writers; release builds have no such seam.
- [ ] **Step 2:** run `cargo test -p saiife -p saiife-policy`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the Windows check is clean; `scripts/bench-check.sh --managed` on Linux is within +1 ms of `main`.
- [ ] **Step 5:** commit `feat(cli): locked mode clients, hook and run on Windows`.

### Task 11: the personal broker on Windows

**Files:**
- Create `crates/keychain/src/wincred.rs` and `crates/win/src/ffi/cred.rs` (`windows-sys` feature `Win32_Security_Credentials`).
- Modify `crates/keychain/src/lib.rs` (`platform()` returns `WinCredential` on Windows; the `DirKeychain` seam becomes `cfg(debug_assertions)` on all OSes), `crates/system/src/personal.rs`, `crates/system/src/user_unit.rs`, `crates/daemon/src/start.rs` (`personal_preflight`), and `crates/cli/src/main.rs` (`cmd_daemon_user`, `--autostart on|off`).

**Interfaces:**
- Consumes Tasks 4 and 5, and plan 13's `personal_paths_for`.
- Produces:
  - `saiife_win::ffi::cred::{read(target: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>>, write(target: &str, comment: &str, blob: &[u8]) -> io::Result<()>, delete(target: &str) -> io::Result<bool>}` (`CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`);
  - `keychain::WinCredential` implements `Keychain`; target `saiife:vault-key`; backend name `"windows-credential-manager"`;
  - `personal_paths_for(env, home, Platform::Windows)`: state under `%LOCALAPPDATA%\saiife\personal`, control pipe `WIN_PERSONAL_PIPE_PREFIX + <SID>`, no socket dir;
  - `user_unit::windows_run_value(exe: &Path) -> String` = `"<exe>" daemon --user`, under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `saiife-broker` (written with `winreg`);
  - `PERSONAL_UNSUPPORTED` becomes `saiife: the personal broker needs Linux, macOS or Windows`.

- [ ] **Step 1: failing tests:**
  - pure: `windows_personal_paths`, `windows_run_value_quotes_exe`, `personal_pipe_name_has_sid`;
  - Windows CI: `wincred_roundtrip` (write, read, delete a test target `saiife-test:<random>`), the plan 16 personal harness tests with the `DirKeychain` seam.
- [ ] **Step 2:** run `cargo test -p saiife-keychain -p saiife-system personal`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass; the Windows check is clean.
- [ ] **Step 5:** commit `feat(broker): saiife daemon --user on Windows (Credential Manager, per-user pipe)`.

### Task 12: the `locked-windows` CI job

**Files:**
- Create `scripts/locked-windows/{run.ps1, lib.ps1, config.toml, plant.c}`.
- Modify `.github/workflows/ci.yml`: the job `locked-windows`, plus a `test (windows-latest)` step that checks `run.ps1`'s refusal and parses every `.ps1` file.

**Interfaces:**
- Consumes the `saiife` CLI (Tasks 5–11) and the phase names of `scripts/locked-linux/lib.sh`.
- The job:
  - `strategy.matrix.os: [windows-2022, windows-2025]`, `timeout-minutes: 45`, `persist-credentials: false`, `defaults.run.shell: pwsh`;
  - build: `cargo build --locked --profile ci-locked --bin saiife` (static CRT and the load flag come from `.cargo/config.toml`);
  - run: `$env:SAIIFE_LOCKED_CI = '1'; ./scripts/locked-windows/run.ps1 -Binary "$PWD\target\ci-locked\saiife.exe"`;
  - on failure, upload `C:\ProgramData\saiife\log`, `etc`, the audit, `sc.exe qc saiifed`, `sc.exe sdshow saiifed` and the phase logs.
- `run.ps1` refuses (exit 2, nothing done) unless `GITHUB_ACTIONS=true`, `SAIIFE_LOCKED_CI=1` and the OS is Windows.
- The phases, in order:
  1. `prepare_host`: create local users `agent` and `approver` (`New-LocalUser`, random passwords, not admins), a project dir the agent owns, and `PSCredential`s for `Start-Process -Credential` (the Secondary Logon service is started if it is stopped).
  2. `phase_install`: `saiife system install --agents claude,codex,gemini --approvers approver --allow-test-build --non-interactive` exits 0 with the test-build warning.
  3. `phase_acls`: `(Get-Acl -LiteralPath <p>).Sddl` for every W14 path, parsed and compared with `saiife __expected-sddl <p>` (a debug-only hidden command that prints `winacl::expected`). Also `sc.exe sdshow saiifed` against W10, and `sc.exe qc saiifed` shows `SERVICE_START_NAME : NT SERVICE\saiifed`.
  4. `phase_hooks`: one fixture payload per agent through `Start-Process -Credential agent C:\ProgramData\saiife\bin\saiife.exe check --managed --hook-exit --agent <a>` (stdin and stdout through files in the agent's project dir). The audit record's `sid` is `agent`'s SID, and `pid` is set.
  5. `phase_fail_closed`:
     - after `Stop-Service saiifed`, every hook exits 2;
     - `Start-Service` brings it back;
     - `Stop-Process -Id <daemon pid> -Force` (CI only) is restarted by the service manager within 5 s, and the next `daemon`/`start` record has `previous_clean_stop = false`.
  6. `phase_attacks`, as `agent`, each attempt failing:
     - write each managed file, `C:\ProgramData\saiife\etc\config.toml` and the binary;
     - read `vault.key` and the audit key;
     - write the audit dir;
     - `Stop-Service saiifed`, `sc.exe config saiifed start= disabled` and `sc.exe delete saiifed` (access denied);
     - `Stop-Process` on the daemon (access denied);
     - `reg add HKLM\SOFTWARE\Policies\ClaudeCode /v Settings /d {} /f` (access denied);
     - `New-Item` under `C:\ProgramData\saiife` (access denied);
     - **squat:** with the service stopped by the job, `agent` creates `\\.\pipe\saiife` (a small PowerShell `NamedPipeServerStream` loop), then the job starts the service: it must fail to stay running with the W11 log line, and a hook run as `approver` must deny without writing to the fake pipe. The job then ends the squatter through its process handle and restarts the service;
     - **DLL planting (A4):** `plant.c` builds a DLL whose `DllMain` writes a marker file. It is copied into the agent's cwd and into a dir prepended to `PATH`, under the name of every import of `saiife.exe` that is not an API set. A hook run writes no marker. A control exe built from the same file with `-DCONTROL` and linked without `/DEPENDENTLOADFLAG` does write the marker, which proves the DLL works.
  7. `phase_doctor`: `saiife doctor --json` exits 1. The `files.binary` warning (unsigned test build) is among the warnings, and no check fails.
  8. `phase_approvals`:
     - `approver` approves an `agent` request;
     - `agent` tries to approve its own request with `same_user = "reauth"` → refused, `reauth_unavailable`, W16's text, recorded, and no logon in the Security log;
     - lockdown by a non-approver is refused.
  9. `phase_lockdown`: as in `locked-linux`.
  10. `phase_reinstall_uninstall`: a reinstall is unchanged; `uninstall` removes exactly the listed paths and the service (`Get-Service saiifed` fails); `--purge` removes the group and the tree.

- [ ] **Step 1:** write the scripts and the job. Port the generic helpers from `scripts/locked-linux/lib.sh` to PowerShell; do not call bash.
- [ ] **Step 2:** locally, nothing runs. In the `test (windows-latest)` cell: parse every `scripts/locked-windows/*.ps1` with `[System.Management.Automation.Language.Parser]::ParseFile` (no errors), and run `run.ps1` with `SAIIFE_LOCKED_CI` unset; expect `refusing: …` and exit 2.
- [ ] **Step 3:** commit `ci: locked-windows job (install, ACLs, fail-closed, attacks, pipe squat, DLL planting, uninstall)`.

### Task 13: MSI, release packages, Intune Win32 and GPO

**Files:**
- Create `packaging/windows/saiife.wxs`, `packaging/windows/wix.version` (`5.0.2`), `scripts/package-windows/{build.ps1, test.ps1}`.
- Create `deploy/intune-windows/{detect.ps1, fleet-files.ps1, discovery.ps1, rules.json, README.md}` and `scripts/package-windows/intunewin.version` (the Content Prep Tool release and its SHA-256).
- Modify `.github/workflows/ci.yml` (a job `package-windows` on `windows-2025`), `.github/workflows/release.yml` (MSIs and `.intunewin` files as assets; the MSIs go through the plan 19a signing step), `crates/system/src/layout.rs` (`PACKAGE_BINARY` on Windows) and `docs/fleet.md` (a `## Windows` section: `#intune-windows`, `#gpo`).

**Interfaces:**
- Consumes Task 7 (`--fleet --package`) and plan 18's fleet formats.
- `saiife.wxs` (W20): per-machine; `INSTALLFOLDER` = `[ProgramFiles64Folder]saiife`; the components are `saiife.exe`, `LICENSE`, `README.md` and a system `PATH` entry; a fixed `UpgradeCode` (generate once with `uuidgen`, commit, never change); `MajorUpgrade Schedule="afterInstallExecute"`; the custom actions `SaiifeInstall` (deferred, `Impersonate="no"`, after `InstallFiles`, condition `NOT REMOVE`) and `SaiifeUninstall` (deferred, `Impersonate="no"`, before `RemoveFiles`, condition `REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`). A failing install action rolls back.
- `build.ps1 -Target <triple> -Version <v>`: installs WiX `5.0.2` as a `dotnet tool` when it is missing; builds `dist/saiife-<v>-<arch>.msi` (`-arch x64|arm64`); builds `dist/saiife-<v>-<arch>.intunewin` with the pinned, hash-checked `IntuneWinAppUtil.exe`.
- `package-windows` (CI, admin):
  - `msiexec /i … /qn /l*v msi.log` with fleet files that name `claude,codex,gemini`. Expect exit 0, the service running and doctor exit 1 or less;
  - an upgrade to a second build with a bumped version: the service restarts once, and the managed files keep their SHA-256;
  - a broken fleet file: the MSI fails and rolls back, and `C:\Program Files\saiife` is gone;
  - `msiexec /x`: the warning is in `msi.log`, the service is gone, and the audit and fleet files are kept;
  - `detect.ps1` exits 0 after install and 1 after removal;
  - the `.intunewin` file exists and unpacks with its header.
- `release.yml`: the MSIs and `.intunewin` files are built after the zips, signed in `artifact-signing` mode, listed in `SHA256SUMS`, and the `publish` note from plan 19a covers them.

- [ ] **Step 1:** write `test.ps1` (the CI checks above) and run it in a `pull_request` CI run; expect FAIL before the package exists.
- [ ] **Step 2:** write the `.wxs`, the scripts and the recipes. `rules.json` follows Intune's custom-compliance schema, with `en_US` remediation strings pointing to `docs/fleet.md#intune-windows`.
- [ ] **Step 3:** locally: `xmllint --noout packaging/windows/saiife.wxs` (if installed) and `python3 -I -m json.tool deploy/intune-windows/rules.json`. CI runs the rest.
- [ ] **Step 4:** `package-windows` is green in CI at the end.
- [ ] **Step 5:** commit `feat(packaging): signed Windows MSI (WiX 5), Intune Win32 and GPO recipes`.

### Task 14: the Windows live lock check, labels, docs and spec notes

**Files:**
- Create `scripts/lock-check/windows-vm.ps1` and `crates/agents/tests/fixtures/lock-check/windows/` (recordings later).
- Modify `scripts/lock-check/{lib.sh, checks-claude.sh, checks-gemini.sh, checks-codex.sh, test-lib.sh}`: `LOCKCHECK_PLATFORM=windows` switches the managed paths to W9's (under `LC_ROOT` as `C/Program Files/ClaudeCode/…`) and `LC_HOME` to `C/Users/agent`, so the check tables stay one source.
- Modify `crates/agents/src/lock.rs` (Windows labels stay `Unverified` until recordings exist).
- Modify the docs: `docs/windows.md` (fill `#locked-mode`, `#disk-encryption`, `#approvals`, `#personal-broker`, `#limits`), `docs/install.md`, `docs/threats.md` (Windows rows: the pipe, UAC, DLL planting, HKLM), `docs/approvals.md`, `docs/personal-broker.md`, `docs/mcp.md`, `docs/lock-check.md`, `docs/agents/{claude-code,codex,gemini}.md`, `README.md`, `CHANGELOG.md`.
- Modify the spec: a "Built (plan 19b)" note under §5.3a, and the §15.2 row; and `crates/cli/tests/docs_wording.rs`.

**Interfaces:**
- `windows-vm.ps1 -Agent <claude|codex|gemini|all>`:
  - it runs elevated inside a throwaway Windows VM;
  - it refuses unless the OS is Windows and `SAIIFE_LOCKCHECK_WINDOWS_VM=1`;
  - it reads `lib.sh`'s check tables by running them through Git Bash with `LOCKCHECK_PLATFORM=windows` in "plan" mode (they print the managed files and prompts per check);
  - it writes the managed files itself, and starts each agent as the local user `agent` with `Start-Process -Credential`;
  - it writes `target\lock-check\windows-<agent>-<UTC>.tsv`.
- Spec notes: §5.3a "Built" (what changed from the design, if anything, during 19b), §8.5 (`sid`), §6.10.2 (W16), §6.9.3 (W17), §6.15 (W18), §6.14 (W19), §6.3 (W11, W13), §6.6 and §7 (W25), §5.6 (W27), §9.2 A4 (W28), §13 (the `locked-windows` and `package-windows` jobs), §14 (Windows release artifacts and signing modes).

- [ ] **Step 1: failing tests:**
  - `windows_labels_unverified_without_recordings` (from 19a) still passes, and the fixtures test covers `windows/`;
  - `test-lib.sh` gains `windows_platform_paths` (with `LC_ROOT` a tempdir: the Claude managed dir is `$LC_ROOT/C/Program Files/ClaudeCode/managed-settings.d`);
  - `docs_wording`: `docs/windows.md` names `NT SERVICE\saiifed`, `\\.\pipe\saiife`, `C:\ProgramData\saiife` and `separate session`; `docs/mcp.md` says the gateway is Linux-only.
- [ ] **Step 2:** run `cargo test -p saiife-agents -p saiife --test docs_wording` and `bash scripts/lock-check/test-lib.sh`; expect FAIL.
- [ ] **Step 3:** write the harness, the docs and the spec notes.
- [ ] **Step 4:** the tests pass; `bash -n` and `shellcheck` are clean; the `.ps1` parse check passes in CI.
- [ ] **Step 5:** commit `docs: Windows locked mode; lock-check harness for a Windows VM; spec notes`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`; clippy `-D warnings` (Linux, and in CI on Windows);
  - the tokio gate (with `saiife-win` without `pipe-server`) and `bash scripts/check-unsafe.sh`;
  - `cargo test --workspace` and `scripts/test-offline.sh`, with TMPDIR and SAIIFE_TEST_TMP set;
  - `bash scripts/check-windows.sh` and the macOS-target check;
  - `scripts/bench-check.sh` and `--managed` against `main` (Linux, +1 ms at most);
  - `bash -n` and `shellcheck` on the changed bash scripts; `scripts/lock-check/test-lib.sh`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. CI must be green, including `test (windows-latest)`, both `locked-windows` cells and `package-windows`. The owner merges. No tag.

## Follow-ups (not in this plan)

- An MCP gateway sandbox on Windows (AppContainer or a restricted token plus a job object).
- Pid-reuse-proof attribution (a process handle held from the pipe connection; needs `OpenProcess`, which a service account gets only for its own processes).
- A `windows-11-arm` cell in `locked-windows`.
- Windows Event Log as an audit forwarding target.
- DPAPI-sealed vault key once a safe recovery story exists.
- WiX v6+ (needs the owner's decision on the Open Source Maintenance Fee), and MSIX (no custom actions, so it cannot run `system install`; not planned).

## Owner handwork

Nothing here runs on Claude's machine. Everything privileged happens in CI or in a throwaway Windows VM, so no machine of yours is modified.

- [ ] **Confirm the spec departures** (each with its reason in the plan 19 report): §5.3a numbering; the binary in `C:\ProgramData` (W9); the virtual account (W10); the named pipe instead of a Unix socket (W11); hashed uids and `sid` in records (W12); gateway on TCP only (W13); no DPAPI (W15); same-user approval off (W16); session names only (W17); the MCP gateway refused (W18); HKLM policy fails doctor (W24); admin agent users fail (W27); WiX v5 (W20).
- [ ] **Signing:** set the six `WINDOWS_SIGN_*` secrets (plan 19a, Owner handwork). The same secrets sign the MSIs.
- [ ] **The real-Windows live lock check, in a throwaway VM:**
  1. Make a Windows 11 VM: UTM on your Mac with a Windows 11 ARM64 image, or a small Azure VM (`Standard_B2s`, Windows 11 Pro, x64). Use an evaluation or a licensed image.
  2. In the VM, as the admin: install Git for Windows (Git Bash), Node 22, and the agents system-wide (`npm install -g --prefix "C:\Program Files\nodejs-global" @anthropic-ai/claude-code @openai/codex @google/gemini-cli`, then add that dir to the system `PATH`). Create a standard (non-admin) user `agent`, log in as `agent` once, and sign in to each agent.
  3. Copy in the signed MSI from a release (or the `ci-locked` build), and a checkout of the repo. Put the fleet files in `C:\ProgramData\saiife\etc\fleet\` and run the MSI. `saiife doctor` (elevated) should pass except for expected warnings.
  4. Run `$env:SAIIFE_LOCKCHECK_WINDOWS_VM='1'; .\scripts\lock-check\windows-vm.ps1 -Agent all` elevated. Copy each `target\lock-check\windows-<agent>-*.tsv` to `crates/agents/tests/fixtures/lock-check/windows/<agent>.tsv` and send them to Claude, who sets the labels.
  5. Check the hook command form (W9): the `claude` rows must fire from `managed-settings.d` in both Git Bash and the PowerShell tool. For Codex, check whether `command` or `command_windows` is used (Task 6). Report anything that does not fire.
  6. **A second account, from a separate session.** As `agent`, trigger an `ask` rule and try `saiife approve <id>`: refused with W16's text, no prompt. Then, for each of **switch user**, **RDP** and **OpenSSH**: as `approver`, run `saiife approvals` and `saiife approve <id>`. Note which work. OpenSSH is expected to be refused (W11's `NU` deny). Report so the docs can name what works; until then they say these are unverified.
  7. **Claude Code via HKLM:** set a test `HKLM\SOFTWARE\Policies\ClaudeCode` `Settings` value with `{"model":"x"}`. `saiife doctor` must fail `agents.claude.policy`. Add `"managedSourcesBehavior":"merge"`; it must pass, and Claude's `/status` must list both sources. Remove the value.
  8. Download the release zip with Edge (so it gets Mark of the Web), unpack it and run `saiife --version`. On a signed release, SmartScreen may still warn until reputation builds; note what it shows.
  9. Restart the VM. The service must come back, and hooks must work without a reinstall.
  10. Uninstall from Settings → Apps. Then `Get-Service saiifed` must fail. Delete the VM.
- [ ] **Intune (optional, needs a tenant):** upload the `.intunewin` as a Win32 app with `detect.ps1`, and `fleet-files.ps1` as a dependency, to one test device. Check that a stopped service shows as not detected and non-compliant.
