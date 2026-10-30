# Plan 13 — macOS locked mode (v2.1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sudo saiife system install` works on macOS 15 or later, on Apple silicon and Intel. It creates the hidden `_saiife` user, runs `saiifed` as a launchd daemon, writes the §5.3 layout and the managed hooks for Claude Code, Codex and Gemini CLI, and registers the `com.saiife.approve` authorization right. The daemon reads peer identity with `LOCAL_PEERCRED` and `LOCAL_PEERPID`. Same-user approvals re-authenticate with the password or Touch ID. Release binaries are signed with a Developer ID, use the hardened runtime, and are notarized when the owner's secrets exist. A `locked-macos` CI job proves it all as root on GitHub's macOS runners.

**Architecture:**
- **One platform switch.** `saiife-system` gains `Platform { Linux, Macos }`. `Layout` carries it. `Layout::at(<Linux constant>)` maps the constants that differ on macOS (§5.3) to their macOS paths. The ~230 call sites stay as they are, and Linux tests can build a macOS layout under a tempdir.
- **Privileged actions stay behind `Host`.** macOS adds `dscl`, `dseditgroup`, `launchctl`, `sw_vers` and `security authorizationdb`. `FakeHost` records them. So the whole macOS install, uninstall and doctor run as unit tests on Linux.
- **The daemon, the IPC client, the hook and the CLI clients** stop being Linux-only. Their gates become `cfg(unix)`, except for the parts that stay Linux-only: Landlock, the MCP gateway, polkit, systemd, `SO_PEERPIDFD` and `/proc`.
- **Peer and process facts on macOS:**
  - `nix` gives `LOCAL_PEERCRED`, `LOCAL_PEERPID` and `getpwnam`, all through a safe API;
  - a new tiny crate, `saiife-darwin`, reads `sysctl(KERN_PROC_PID)`. It is the only crate in the workspace that may use `unsafe`.
- **Re-authentication.** The CLI makes an empty authorization reference and sends its external form. The daemon runs `/usr/bin/security authorize -u -i -d com.saiife.approve` on it, the same way it runs `pkcheck` on Linux.
- **Root tests live in CI only.** A new `locked-macos` job mirrors `locked-linux`. Release CI signs and notarizes when the secrets exist. Otherwise it ships ad-hoc-signed, hardened-runtime binaries and says so in the release notes.

**Tech Stack:** Rust workspace. New dependencies, all macOS-only:
- `nix` (features `socket`, `user`) in `ipc`, `policy`, `system` and `daemon`;
- `security-framework =3.7.0` in `cli`. It is already in Cargo.lock through `saiife-keychain`.

`nix` is pinned with `=` to its newest release older than 14 days on the day it is added. There is no `libproc` (its bindgen build step breaks the Linux-host macOS check) and no `plist` crate.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §5.3, the macOS halves of §6.3 and §6.10.2, and §6.9.3 on macOS;
- §5.6 on macOS (the admin rule), and §6.16 on macOS;
- §9.2 A4 and A5 on macOS;
- the §13 macOS lines ("The macOS job joins in v2.1", "macOS reauth is tested by hand in v2.1");
- the v2.1 done criteria (§14: points 1–4 and 7 on macOS, Intel and Apple silicon, signed and notarized);
- §15.2 row 13, and §17 question 1;
- the plan 16 note on `daemon --user` on macOS, and the plan 17 note on the gateway.

Plans 16 and 17 set the style.

## Consumes (verify at build time)

- **Plans 9b and 11:** `saiife_system::{Layout, Host, FakeHost, install, uninstall, doctor}`; `reauth::{Reauth, ReauthResult, PkCheck, Cooldowns, InFlight, REAUTH_TIMEOUT}` and its caller in `approvers.rs`; the phase names of `scripts/locked-linux/lib.sh`.
- **Plan 15:** `run_cmd::linux` (`run --secret`, `run --cloud`) and `fsops::root_owned_chain`.
- **Plan 16:** `saiife_keychain::MacKeychain` (compile-checked only until now), `personal::personal_paths`, `user_unit::launchd_plist_text` (unchanged), and `PERSONAL_NEEDS_LINUX`, which this plan removes.
- **Plan 17:** `system::sandbox` and `cli::mcp_spawn`, which stay `cfg(target_os = "linux")`, and `mcp_gateway::{unix_peer_refused, tcp_peer_refused}`.

## Global Constraints

- **Standing rules (owner):**
  - **Nothing privileged on the developer machine.** Never run sudo, su, root shells, `launchctl`, `dscl`, `dseditgroup`, `sysadminctl`, `security`, `codesign`, `systemctl`, polkit tools, docker, kill, pkill, killall or pgrep, not even to probe whether they exist. No writes to `/Library`, `/etc`, `/usr/local`, `/opt`, `/var` or `/private`. No managed agent settings on the host.
  - In tests, child processes are stopped through their own handle (`Child::kill`), never by name.
  - These tools appear only in production code behind `Host` or `Reauth`, which tests replace with fakes, and in CI-only scripts.
  - **Root and launchd tests run only in the `locked-macos` CI job.** On the dev machine, CI-only scripts get `bash -n` and `shellcheck` only, plus their refusal check, which exits before anything else.
  - CI job ids contain no dots.
  - **Test isolation:** HOME, PATH, `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` point at tempdirs. `TMPDIR` and `SAIIFE_TEST_TMP` point to a short dir from `mktemp -d -p /home/jonas/projects/personal/saiife`, removed afterwards. Never use /tmp, the real home or `~/.claude`. No internet in tests.
  - **Internet:** implementers may use the web only to fetch public reference data: Apple man pages for `security`, `launchd.plist` and `dscl`; the `nix` docs; crate release dates.
- **How macOS code is verified without a Mac:**
  - Every macOS decision is either a pure function or sits behind `Platform`, `Host` or `Proc`, so Linux runs its tests. For example, `Layout::under_for(tmp, Platform::Macos)` with `FakeHost`.
  - Code that only compiles on macOS is checked locally with `RUSTFLAGS="-D warnings" cargo check --workspace --all-targets --target x86_64-apple-darwin`, using the fake `cc` from plan 12's gate.
  - Tests that need a real Mac but no root run in the CI `test` job on `macos-latest`. Tests that need root run in `locked-macos`.
- **Unsafe boundary (decision 1):**
  - Every crate keeps `#![forbid(unsafe_code)]`, except the new `crates/darwin` (`saiife-darwin`).
  - `saiife-darwin` holds exactly one FFI call: `sysctl` with `{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}`, read into `libc::kinfo_proc`. It has `#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]`, and each `unsafe` block has a `SAFETY:` comment.
  - Why a crate of our own: no safe crate wraps `KERN_PROC_PID` without a bindgen build step (`libproc`), which would break the Linux-host macOS check. `sysinfo` is large, and how it reads other users' processes on macOS is unclear.
  - `LOCAL_PEERCRED`, `LOCAL_PEERPID`, `getpwnam_r` and `getgrnam_r` come from `nix`'s safe API.
  - The Authorization Services calls go through `security-framework`'s safe API (client side) and through the `/usr/bin/security` subprocess (daemon side).
  - A CI gate, `scripts/check-unsafe.sh`, fails when `unsafe` appears outside `crates/darwin`, or when a crate root other than darwin lacks `#![forbid(unsafe_code)]`.
- **Tokio-free:** `guard`, `audit`, `policy`, `ipc`, `system`, `mcp` and the new `darwin` crate stay tokio-free. The CI gate `no tokio in hook crates` also runs on `macos-latest`, so macOS-only dependencies are covered, and it adds `-p saiife-darwin`. The hook path may cost at most +1 ms against `main` on Linux, and its p95 must be under 40 ms on macOS (§13).
- **Commits:**
  - the branch is `plan-13-macos` from `main` (838a318 or later);
  - each task is committed with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
  - never commit `.superpowers/`;
  - `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`;
  - no tags.
- **Spec values, verbatim (§5.3):**
  - the users and groups are `_saiife` and `_saiifeaudit`, created with `dscl`, with uid/gid from the 200–400 range, `IsHidden = 1` and shell `/usr/bin/false`;
  - the state dir is `/var/db/saiife` (0700 `_saiife`);
  - the plist is `/Library/LaunchDaemons/com.saiife.saiifed.plist` (root:wheel 0644), with `UserName = _saiife`, `KeepAlive = true` and `RunAtLoad = true`;
  - the vault key is `/var/db/saiife/keys/vault.key` (0400 `_saiife`);
  - Claude managed settings live under `/Library/Application Support/ClaudeCode/`, Gemini's in `/Library/Application Support/GeminiCli/settings.json`, and Codex's in `/etc/codex/requirements.toml`;
  - peer credentials are `LOCAL_PEERCRED` (uid) and `LOCAL_PEERPID` (pid);
  - process ancestry comes from `sysctl(KERN_PROC_PID)`;
  - the right is `com.saiife.approve`, with Touch ID or the password each time (`timeout = 0`);
  - release binaries use a Developer ID and the hardened runtime, and are notarized.
- **Spec notes** (each is added to the spec in Task 14; decisions 2–13 below).
- **Decisions this plan makes** (each is restated in its task):
  1. **Unsafe boundary:** see above.
  2. **The socket dir is `/var/db/saiife-run`, not `/var/run/saiife`.**
     - `/var/run` is root:daemon 0775, so the daemon user cannot create a dir there at start, and `/var/run` is cleared at boot.
     - Install creates `/var/db/saiife-run` (0755 `_saiife`). It lasts across reboots, and the daemon replaces stale sockets at bind as it does today.
     - The client checks the dir owner exactly as on Linux. `[daemon] socket_dir` defaults to it on macOS.
  3. **The daemon acquires the right; the CLI does not.**
     - The CLI makes an empty `Authorization` (security-framework `Authorization::default()`) and sends its 32-byte external form as `auth` (64 lowercase hex chars) in `approval.decide`. It keeps the reference alive until the answer comes back.
     - The daemon runs `/usr/bin/security authorize -u -i -d com.saiife.approve`, with the external form on stdin, an empty environment except `PATH=/usr/bin:/bin`, and a 120 s timeout (its own child, killed through its handle).
     - The prompt appears in the approver's login session, as polkit's does.
     - Why: with `timeout = 0` (the spec), a credential the CLI got cannot be reused by a second check in the daemon. This is Apple's helper-tool pattern, and it keeps the Linux flow.
     - Fallback, if the owner's live check shows that the prompt cannot come from the daemon's child: the CLI acquires the right itself and the rule becomes `shared = false` with `timeout = 30`. That is a second spec departure, and it needs the owner's word.
  4. **The right's definition**, written with `security authorizationdb write com.saiife.approve`:
     - `class = user`, `authenticate-user = true`, `session-owner = true`, `shared = false`, `timeout = 0`, `allow-root = false`, `version = 1`;
     - a `comment`, and a `default-prompt` of `saiife wants to approve your own pending request. Check the request number in your terminal first.`

     This is `authenticate-session-owner` with the spec's `timeout = 0`, written out in full.
  5. **Re-authentication outcomes.** `security authorize` answers `YES (0)` or `NO (<code>)`:
     - `-60005` (denied) and `-60006` (canceled) are `Denied`;
     - `-60007` (interaction not allowed, for example SSH or no GUI) is `Unavailable`;
     - any other code, no answer, a signal or the timeout is `Error`.

     If the right is missing, `same_user = "reauth"` acts as `deny`, and `doctor` warns `re-authentication unavailable: approvals need a second account` (the Linux fallback text).
  6. **Session attribution on macOS uses process names only.** `KERN_PROCARGS2` (the command line) is readable only for one's own uid, so a `node` ancestor never matches an agent, and Gemini CLI under node gets `session = null` (the stricter shared bucket). Attribution only; nothing is allowed because of it.
  7. **The MCP gateway stays Linux-only in v2.1.**
     - On macOS, `[mcp.<name>]` is a load error: `the MCP gateway needs Linux (Landlock) in this version`. This is the same mechanism as plan 17's personal-broker refusal.
     - `saiife mcp` (connector tools) works on macOS.
     - `sandbox-exec` is deprecated and is not used.
  8. **`[gateway] tcp` on macOS.** Without `/proc`, the daemon cannot find a TCP peer's uid, so `tcp_peer_refused` returns `None` on macOS. This is safe because macOS has no gateway children, and the daemon's own uid cannot mint the bearer token (the control socket refuses own-uid peers in locked mode). The token is still required.
  9. **`saiife daemon --user` works on macOS** (it was refused until this port). When `XDG_RUNTIME_DIR` is unset, the runtime dir is `~/Library/Caches/saiife` (0700, created if missing) and the sockets are in `run/` below it. A socket path over 103 bytes is refused with a clear line. The keychain is `MacKeychain`.
  10. **`run --secret` and `run --cloud` work on macOS.**
      - `DYLD_*` is scrubbed with the loader variables. This happens on every platform, because it is harmless on Linux.
      - A `run_allow` entry under `/etc`, `/var` or `/tmp` is a load error on macOS, with a hint to write `/private/...`. Those are symlinks there, and a link in `run_allow` never grants its target.
  11. **Claude Code on macOS uses the drop-in dir** `/Library/Application Support/ClaudeCode/managed-settings.d/` (`50-saiife.json` and `60-saiife-mcp.json`), as on Linux.
      - If the owner's macOS live check shows that drop-ins are ignored there, install switches to the whole file `managed-settings.json`, and refuses when a foreign one exists.
      - `doctor` warns when an MDM profile (`/Library/Managed Preferences/com.anthropic.claudecode.plist`) also sets managed settings.
  12. **Lock labels are per platform.** macOS labels come from `crates/agents/tests/fixtures/lock-check/macos/<agent>.tsv`. Until the owner records those, they are `unverified`, so the project hook keeps judging and `status` says so.
  13. **Smaller departures:**
      - **Minimum macOS 15** (Sequoia), the oldest macOS Apple still updates in October 2026. This answers §17 question 1.
      - **The vault key mode is `daemon_file`.** On macOS, `installed.toml` has `systemd = 0` and gains `auth_rights`.
      - **The plist has `ThrottleInterval = 1`,** like Linux `RestartSec=1`.
      - **The daemon's stderr goes to `/var/log/saiife/daemon.log`,** because macOS has no journal for it.
      - **Install requires the hardened runtime, and an ad-hoc signature only warns.** A release built without the secrets ships ad-hoc signed with the hardened runtime, so A4 holds, but it is not notarized.
      - **Notarization uses an Apple ID with an app-specific password.** A bare binary cannot be stapled, so Gatekeeper checks the ticket online.
      - **On macOS, an agent user in the `admin` group is a warning** ("sudo needs its password"). A NOPASSWD rule is still a failure (§5.6).

## Review Focus

1. **`/etc`, `/var` and `/tmp` are root-owned symlinks into `/private` on macOS.**
   - The root-owned-chain checks (doctor, `secret.lease`, install's ancestor checks) must accept exactly those three links, when root owns them and they point at `private/<same name>`. Any other symlink must still fail.
   - A `run_allow` entry through them is refused with a hint (Task 3: `trusted_system_links_only_the_three`, `root_owned_chain_accepts_private_etc`; Task 9: `run_allow_through_var_symlink_refused_with_hint`; Task 2: `client_accepts_socket_dir_behind_var_link`).
2. **A Mac whose MDM profile also delivers Claude Code managed settings.** Claude Code may then ignore the file drop-in. Expected: install and doctor both warn, naming the profile path (Task 6: `macos_install_warns_on_claude_mdm_profile`; Task 11: `claude_mdm_profile_warns`).
3. **A peer pid that exits, is reused, or has `node` as an ancestor.** macOS has no pidfd. Expected:
   - the session is `null`, never a crash and never another session;
   - re-authentication is tied to the authorization reference, and the existing start-time re-check still refuses a pid that changed (Task 7: `node_ancestor_has_no_session`, `gone_pid_has_no_session`, `mac_proc_start_time_detects_reuse`).
4. **An existing `_saiife` account, or a uid/gid already taken in 200–400.** MDM tools and other daemons create hidden accounts too. Expected:
   - install picks an id free among both users and groups;
   - it reuses a hidden `_saiife` that has `/usr/bin/false` as its shell;
   - it refuses a login-capable `_saiife`, or a full range, with one clear line (Task 4: `pick_free_id_skips_users_and_groups`, `pick_free_id_full_range_is_none`; Task 6: `existing_login__saiife_refused`, `existing_hidden__saiife_reused`).
5. **A same-user approval from SSH, a locked screen or a hung prompt.** Expected:
   - `Unavailable` is refused as "re-authentication unavailable", recorded, and starts no cooldown;
   - a hung `security` child is killed at the timeout and refused as an error;
   - an approval with no `auth` field is refused, never approved (Task 8: `interaction_not_allowed_is_unavailable`, `unavailable_starts_no_cooldown`, `hung_security_is_killed_at_timeout`, `missing_auth_is_unavailable`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (darwin crate, unsafe gate), Task 3 (platform layout), Task 5 (plist, Mach-O), Task 13 (release signing).
- **Wave 2 (parallel):** Task 2 (peer creds and lookups; needs 1), Task 4 (supported check and macOS `Host`; needs 3).
- **Wave 3 (parallel):** Task 6 (install and uninstall; needs 3, 4, 5), Task 7 (daemon; needs 1, 2, 3).
- **Wave 4 (parallel):** Task 8 (re-authentication; needs 7), Task 9 (CLI on macOS; needs 2, 3, 7), Task 10 (personal broker; needs 3, 7), Task 11 (doctor; needs 4, 5, 6).
- **Wave 5 (parallel):** Task 12 (`locked-macos` CI; needs 6–11), Task 14 (lock-check harness, labels, docs, spec notes).
- **Last:** the gates, a whole-branch review, one fix wave, push, PR, CI (including `locked-macos`). The owner merges.

**Shared files** (keep these edits small):
- `crates/daemon/src/lib.rs`: Task 7 flips the gates, and Task 10 drops `PERSONAL_NEEDS_LINUX`.
- `crates/cli/src/main.rs`: Task 9 does the gates and the daemon defaults, and Task 10 does `cmd_daemon_user`.
- `.github/workflows/ci.yml`: Task 1 adds the unsafe gate and runs the tokio gate on macOS, Task 12 adds the job and the bench, and Task 13 adds the offline test of the signing script.

---

### Task 1: `saiife-darwin` crate and the unsafe gate

**Files:**
- Create `crates/darwin/Cargo.toml` (`saiife-darwin`; `libc = "0.2"` under `cfg(target_os = "macos")` only) and `crates/darwin/src/lib.rs`.
- Create `scripts/check-unsafe.sh`.
- Modify `.github/workflows/ci.yml`:
  - a step `unsafe only in saiife-darwin` running `bash scripts/check-unsafe.sh` on both OSes;
  - the tokio gate without its `if: matrix.os == 'ubuntu-latest'`, plus `-p saiife-darwin`.

**Interfaces (Produces):**
- `pub struct ProcInfo { pub ppid: u32, pub uid: u32, pub comm: String, pub start_us: u64 }`
  - `comm` is `kp_proc.p_comm`, at most 16 bytes, lossy UTF-8;
  - `start_us` is `kp_proc.p_starttime` in microseconds;
  - `uid` is `kp_eproc.e_ucred.cr_uid`.
- `pub fn proc_info(pid: u32) -> Option<ProcInfo>`, macOS only. It returns `None` for pid 0, for pid > `i32::MAX`, when sysctl fails, and when the returned size is not `size_of::<kinfo_proc>()` (a gone pid).
- On other OSes the crate is empty and keeps `#![forbid(unsafe_code)]` (`#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]`).

- [ ] **Step 1: failing tests** (`#[cfg(target_os = "macos")]`; they run in the CI `test` job):
  - `own_pid_has_parent_and_comm`: `ppid == std::os::unix::process::parent_id()`, and `uid` is the own uid;
  - `pid_1_is_launchd_owned_by_root`: `comm == "launchd"`, `uid == 0`. This shows that reading another user's process works;
  - `missing_pid_is_none`: `i32::MAX as u32`, `0` and `u32::MAX` all give `None`;
  - `start_time_stable_across_calls`.
- [ ] **Step 2:** write `scripts/check-unsafe.sh`. It runs `grep -rnw --include='*.rs' unsafe crates`, ignores comment lines and `crates/darwin/`, and fails on any hit. It also fails when a `crates/*/src/{lib,main}.rs` other than darwin lacks `#![forbid(unsafe_code)]`. Run `bash scripts/check-unsafe.sh`; expect exit 0 on `main`.
- [ ] **Step 3:** implement `proc_info`. Run the macOS-target check; expect no warnings. Run `cargo test -p saiife-darwin` on Linux; expect it to build an empty crate.
- [ ] **Step 4:** run `bash scripts/check-unsafe.sh`; expect exit 0. Add a stray `unsafe {}` to a scratch copy and expect exit 1. Then revert the copy.
- [ ] **Step 5:** commit `feat(darwin): KERN_PROC_PID reader, the one unsafe crate, with a CI gate`.

### Task 2: peer credentials and user lookups on macOS (`ipc`, `policy`)

**Files:**
- Modify `crates/ipc/Cargo.toml` (macOS: `nix` with `socket` and `user`; `saiife-darwin`), `crates/ipc/src/lib.rs` (`peer` and `client` become `cfg(unix)`), `crates/ipc/src/peer.rs`, and `crates/ipc/src/client.rs` (its test module becomes `cfg(all(test, unix))`).
- Modify `crates/policy/Cargo.toml` (macOS: `nix` with `user`) and `crates/policy/src/users.rs`.

**Interfaces:**
- Consumes `saiife_darwin::proc_info`.
- Produces (the signatures are unchanged):
  - `peer::peer_cred(sock: impl AsFd) -> io::Result<PeerCred>`. On macOS: `getsockopt(LocalPeerCred)` gives the uid and `groups()[0]` as the gid, and `getsockopt(LocalPeerPid)` gives the pid;
  - `peer::comm(pid) -> Option<String>`, through `proc_info` on macOS;
  - `client::system_uid(name)` and `client::system_entry(uid)`: on macOS through `nix::unistd::User::{from_name, from_uid}`, because a `dscl` user is not in `/etc/passwd`. Linux keeps reading `/etc/passwd`;
  - `Getent`: on macOS, `user`, `name_of` and `group` go through `nix::unistd::{User, Group}` (macOS has no `getent`). `groups_of` keeps `id -Gn`.

- [ ] **Step 1: failing tests:**
  - `peer_cred_of_socketpair_is_self` now runs on macOS too;
  - `system_uid_of_root_is_0` (unix): `system_uid("root") == Some(0)`, and `system_entry(0)` is named `root`;
  - `getent_finds_root_and_wheel` (macOS): `group("wheel").gid == 0`;
  - `client_accepts_socket_dir_behind_var_link` (macOS): a 0755 socket dir created under `std::env::temp_dir()` (which lives in `/var/folders`), given once through `/var/...` and once through `/private/var/...`. Both pass the owner check.
- [ ] **Step 2:** run `cargo test -p saiife-ipc -p saiife-policy`; the Linux tests pass unchanged. Run the macOS-target check; expect it to fail (`peer` is missing on macOS).
- [ ] **Step 3:** implement. Keep `rustix` for Linux.
- [ ] **Step 4:** the Linux tests pass, the macOS-target check is clean, and `bash scripts/check-unsafe.sh` exits 0.
- [ ] **Step 5:** commit `feat(ipc): LOCAL_PEERCRED/LOCAL_PEERPID and macOS user lookups`.

### Task 3: the platform switch and the macOS layout

**Files:**
- Modify `crates/system/src/layout.rs`, `crates/system/src/fsops.rs`, `crates/system/src/default_config.rs`, `crates/policy/src/system.rs` (`DaemonCfg::default`), and `crates/cli/src/paths.rs` (`SYSTEM_PATHS`).

**Interfaces (Produces):**
- `pub enum Platform { Linux, Macos }`, with these methods:
  - `Platform::current() -> Option<Platform>` (`None` on other OSes);
  - `Platform::name() -> &'static str` (`"linux"`, `"macos"`).
- `Layout::under_for(root, Platform) -> Layout` and `Layout::platform() -> Platform`.
  - `Layout::system()` and `Layout::under(root)` use `Platform::current().unwrap_or(Platform::Linux)`.
- `pub fn macos_path(linux: &str) -> Option<&'static str>` maps:
  - `STATE_DIR` → `/var/db/saiife`;
  - `KEYS_DIR` → `/var/db/saiife/keys`;
  - `AUDIT_KEY` → `/var/db/saiife/keys/audit.ed25519`;
  - `VAULT_KEY` → `/var/db/saiife/keys/vault.key`;
  - `RUN_DIR` → `/var/db/saiife-run`;
  - `SOCKET` → `/var/db/saiife-run/saiife.sock`;
  - `UNIT` → `/Library/LaunchDaemons/com.saiife.saiifed.plist`;
  - `CLAUDE_MANAGED_DIR`, `CLAUDE_MANAGED` and `CLAUDE_MCP` → under `/Library/Application Support/ClaudeCode/managed-settings.d/`;
  - `GEMINI_DIR` → `/Library/Application Support/GeminiCli`;
  - `GEMINI_SETTINGS` → `/Library/Application Support/GeminiCli/settings.json`.

  `Layout::at` applies it when the platform is `Macos`. Every other constant is the same on both platforms.
- New constants:
  - `DAEMON_LOG = "/var/log/saiife/daemon.log"`;
  - `CLAUDE_MDM_PROFILE = "/Library/Managed Preferences/com.anthropic.claudecode.plist"`;
  - `MACOS_DAEMON_USER = "_saiife"`, `MACOS_DAEMON_GROUP = "_saiife"`, `MACOS_AUDIT_GROUP = "_saiifeaudit"`;
  - `LAUNCHD_LABEL = "com.saiife.saiifed"`.
- `Layout::{daemon_user, daemon_group, audit_group, unit_name}() -> &'static str`. On macOS, `unit_name` is `LAUNCHD_LABEL`.
- `fsops::trusted_link_target(link: &Path, target: &Path) -> bool`: true only for `/etc`, `/var` and `/tmp` → `private/<same name>`. `root_owned_chain` accepts such a link when root owns it, then walks on through the target. Use one helper for the install ancestor checks too.
- `default_config` and `DaemonCfg::default()` use `_saiife` and `/var/db/saiife-run` on macOS. `paths::SYSTEM_PATHS` uses the macOS values on macOS (`SAIIFE_STATE`, `SAIIFE_RUN`, `SAIIFE_UNIT`), so `core.lock` and `core.self` cover them.

- [ ] **Step 1: failing tests:**
  - `macos_paths_are_spec_values` (the full table above);
  - `under_for_macos_maps_every_differing_constant`;
  - `linux_layout_unchanged` (the existing tests stay as they are);
  - `names_per_platform`;
  - `trusted_system_links_only_the_three`: `/etc`→`private/etc` is true; `/etc`→`/tmp/x`, `/opt`→`private/opt` and `/var`→`private/etc` are false;
  - `root_owned_chain_accepts_private_etc` (macOS: `/etc/hosts` is OK, and a symlink in a tempdir still fails);
  - `daemon_cfg_default_macos` (macOS);
  - `system_paths_macos_values`.
- [ ] **Step 2:** run `cargo test -p saiife-system -p saiife-policy -p saiife`; expect FAIL.
- [ ] **Step 3:** implement. `macos_path` is one `match` on the constants.
- [ ] **Step 4:** the tests pass, and the macOS-target check is clean.
- [ ] **Step 5:** commit `feat(system): Platform and the macOS layout (spec 5.3)`.

### Task 4: supported-system check and the macOS `Host`

**Files:**
- Modify `crates/system/src/supported.rs` and `crates/system/src/host.rs` (macOS: `nix` with `user` in `crates/system/Cargo.toml`).

**Interfaces:**
- Consumes `Layout::platform()`.
- Produces, in `supported.rs`:
  - `check_supported(layout, host)` decides by `layout.platform()`, and refuses when `Platform::current()` is `None`;
  - `NOT_LINUX` is renamed `NOT_SUPPORTED_OS = "locked mode needs Linux or macOS"`;
  - `MIN_MACOS: (u32, u32) = (15, 0)`;
  - on macOS, `Support::Supported { distro: "macOS <ver>", systemd: 0 }`;
  - a refusal reads `macOS 14.6 is not supported for locked mode (macOS 15 or later)`.
- Produces, in `host.rs`:
  - new `Host` methods:
    - `fn launchctl(&self, args: &[&str]) -> io::Result<CmdOutput>` (`/bin/launchctl`);
    - `fn macos_version(&self) -> io::Result<(u32, u32)>` (`/usr/bin/sw_vers -productVersion`);
    - `fn run_input(&self, program: &str, args: &[&str], input: &[u8], timeout: Duration) -> io::Result<CmdOutput>`;
  - constants `DSCL = "/usr/bin/dscl"`, `DSEDITGROUP = "/usr/sbin/dseditgroup"`, `LAUNCHCTL`, `SW_VERS` and `SECURITY = "/usr/bin/security"`;
  - `pub fn pick_free_id(uids: &BTreeSet<u32>, gids: &BTreeSet<u32>) -> Option<u32>`: the lowest id in `MACOS_ID_RANGE = 200..=400` that is in neither set;
  - `pub fn parse_dscl_ids(out: &str) -> BTreeSet<u32>`, which reads `dscl . -list /Users UniqueID` or `/Groups PrimaryGroupID`;
  - `argv_dscl_group(name, gid) -> Vec<Vec<String>>`: `-create /Groups/<g>`, then `PrimaryGroupID`, `RealName` and `Password '*'`;
  - `argv_dscl_user(name, uid, gid) -> Vec<Vec<String>>`: `-create /Users/<u>`, then `UniqueID`, `PrimaryGroupID`, `UserShell /usr/bin/false`, `NFSHomeDirectory /var/empty`, `RealName "saiife daemon"`, `Password '*'` and `IsHidden 1`;
  - add and remove a member with `dseditgroup -o edit -a|-d <u> -t user <g>`; delete with `dscl . -delete /Users/<u>` or `/Groups/<g>`;
  - on macOS, `RealHost` uses these for `create_system_group`, `create_system_user`, `add_to_group`, `remove_from_group` and `delete_*`. Its `user`, `group_id` and `group_members` use `nix`, and `users_with_primary_gid` uses `dscl . -search /Users PrimaryGroupID <gid>`;
  - `FakeState` gains `macos: (u32, u32)` (default `(15, 0)`). `CREATED_NAMES` gains the macOS names. `launchctl` and `run_input` calls are recorded as lines (`run_input` records the input length, never the bytes).

- [ ] **Step 1: failing tests:**
  - `macos_supported_from_15`;
  - `macos_14_refused` (the exact text);
  - `sw_vers_parse`: `"15.1"` → `(15, 1)`, `"26.0.1"` → `(26, 0)`, `"x"` → error;
  - `pick_free_id_skips_users_and_groups`;
  - `pick_free_id_full_range_is_none`;
  - `parse_dscl_ids`;
  - `dscl_user_argv_is_hidden_with_false_shell`;
  - `fake_host_records_launchctl_and_run_input`;
  - `macos_names_are_valid` (`_saiife` and `_saiifeaudit` pass `valid_name`).
- [ ] **Step 2:** run `cargo test -p saiife-system`; expect FAIL.
- [ ] **Step 3:** implement. Production `exec` gains an optional stdin, and `run_input` is that call.
- [ ] **Step 4:** the tests pass, the macOS-target check is clean, and the existing Linux supported tests are unchanged except for the renamed constant.
- [ ] **Step 5:** commit `feat(system): macOS supported check and Host (dscl, launchctl)`.

### Task 5: launchd plist text and Mach-O inspection

**Files:**
- Create `crates/system/src/launchd.rs`.
- Modify `crates/system/src/binary.rs` and `crates/system/src/lib.rs`.

**Interfaces (Produces):**
- `launchd::SERVICE = "system/com.saiife.saiifed"`.
- `launchd::plist_text() -> String`, a fixed text with:
  - `Label com.saiife.saiifed`;
  - `ProgramArguments [/opt/saiife/bin/saiife, daemon, --system]`;
  - `UserName _saiife`, `GroupName _saiife`, `InitGroups true`;
  - `RunAtLoad true`, `KeepAlive true`, `ThrottleInterval 1`;
  - `Umask 23` (octal 027);
  - `SoftResourceLimits` and `HardResourceLimits` with `Core 0`;
  - `StandardOutPath` and `StandardErrorPath` set to `/var/log/saiife/daemon.log`.
- `binary::inspect_macho(bytes: &[u8]) -> Result<MachInfo, String>`. It reads a thin 64-bit Mach-O (`0xfeedfacf`) only, and refuses a universal binary (`0xcafebabe`) with `universal binaries are not supported; use the per-architecture release`. It finds `LC_CODE_SIGNATURE` (`0x1d`), the SuperBlob (`0xfade0cc0`) and the CodeDirectory (`0xfade0c02`), whose flags hold `CS_ADHOC = 0x2` and `CS_RUNTIME = 0x10000`. A non-empty CMS blob (slot `0x10000`) together with no `CS_ADHOC` means `Signed`.
- `pub struct MachInfo { pub hardened_runtime: bool, pub signature: Signature, pub profile: Profile }` and `pub enum Signature { Unsigned, AdHoc, Signed }`.
- `MachInfo::problems() -> Vec<String>` lists the refusals: unsigned, no hardened runtime, debug assertions. `MachInfo::warnings() -> Vec<String>` lists the ad-hoc case: `ad-hoc signature: not a Developer ID build (spec 5.3)`.

- [ ] **Step 1: failing tests** (they build Mach-O bytes in a test helper `macho_fixture(flags: u32, cms: bool) -> Vec<u8>`):
  - `plist_matches_golden` (a full golden copy in the test);
  - `plist_has_spec_keys` (`UserName`, `KeepAlive` and `RunAtLoad` with exact values);
  - `hardened_runtime_flag_read`;
  - `adhoc_is_warning_not_refusal`;
  - `unsigned_refused`;
  - `no_runtime_refused`;
  - `fat_binary_refused`;
  - `elf_is_not_macho`;
  - `debug_marker_refused`;
  - `own_test_binary_parses` (macOS CI: `inspect_macho` of `current_exe()` is `Ok`).
- [ ] **Step 2:** run `cargo test -p saiife-system launchd binary`; expect FAIL.
- [ ] **Step 3:** implement. No external tools; the parser works on the bytes alone.
- [ ] **Step 4:** the tests pass.
- [ ] **Step 5:** commit `feat(system): launchd plist and Mach-O signature/hardened-runtime check`.

### Task 6: `system install` and `system uninstall` on macOS

**Files:**
- Create `crates/system/src/authright.rs`.
- Modify `crates/system/src/install.rs`, `crates/system/src/uninstall.rs`, and `crates/policy/src/installed.rs`.

**Interfaces:**
- Consumes `Platform`, the macOS `Host` methods, `launchd::{plist_text, SERVICE}` and `binary::inspect_macho`.
- Produces, in `installed.rs`:
  - `VaultKeyMode::DaemonFile` (serde `"daemon_file"`);
  - `Installed.auth_rights: Vec<String>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`).

  The plist is recorded as `FileKind::Unit`.
- Produces, in `authright.rs`:
  - `RIGHT = "com.saiife.approve"`;
  - `RIGHT_PLIST` (decision 4, the exact XML);
  - `write_args() -> [&str; 3]` (`authorizationdb write com.saiife.approve`) and `remove_args()`;
  - `read_ok(stdout: &str) -> Result<(), String>`. After whitespace is squeezed, the output must hold `<key>session-owner</key><true/>`, `<key>shared</key><false/>` and `<key>timeout</key><integer>0</integer>`.
- The macOS install sequence (`install` branches on `layout.platform()`):
  1. Check root, then supported.
  2. Refuse an existing `_saiife` that is not hidden with shell `/usr/bin/false`, or has uid ≥ 500.
  3. Create the groups `_saiife` and `_saiifeaudit`, then the user `_saiife` with one `pick_free_id` value (used as gid too when free), then the membership.
  4. Copy the binary to `/opt/saiife/bin` (create `/opt` and `/opt/saiife` root:wheel 0755 when missing, recorded as created). Use `inspect_macho` instead of the ELF check.
  5. Write `/etc/saiife`.
  6. Register the auth right through `run_input(SECURITY, write_args, RIGHT_PLIST)`. On failure, warn and set `same_user = "deny"`, as with polkit.
  7. Create the state and log paths:
     - `/var/db/saiife` (0700) and `keys/` (0700);
     - `vault.key` (32 random bytes, 0400 `_saiife`, never rotated);
     - `/var/db/saiife-run` (0755 `_saiife`);
     - `/var/log/saiife` (root 0755), and `audit/` (`_saiife:_saiifeaudit` 2750);
     - `daemon.log` (`_saiife:_saiifeaudit` 0640).
  8. Write the plist (root:wheel 0644).
  9. Write the managed files at the macOS paths. Warn when `CLAUDE_MDM_PROFILE` exists.
  10. Start: if `launchctl print system/com.saiife.saiifed` exits 0, run `kickstart -k` when something changed; otherwise run `bootstrap system <plist>` and then `enable system/com.saiife.saiifed`.
  11. Wait 10 s for the socket. The failure text ends `(see /var/log/saiife/daemon.log)`.
- Uninstall on macOS:
  - run `launchctl bootout system/com.saiife.saiifed` (a warning on failure). If `print` still exits 0, refuse, as `stopped_or_refuse` does;
  - remove the listed files;
  - run `security authorizationdb remove <right>` for each `auth_rights` entry;
  - `--purge` also deletes the created users and groups with `dscl . -delete`.

- [ ] **Step 1: failing tests** (`Layout::under_for(tmp, Platform::Macos)`, `FakeHost`, and a fake signed Mach-O from Task 5's helper; module `macos_tests`, `cfg(all(test, unix))`):
  - `macos_fresh_install_writes_spec_paths_and_modes` (a table of every §5.3 path with its mode and its chown);
  - `macos_install_creates_hidden_users_in_range` (the `dscl` lines, with `UniqueID` in 200..=400, `IsHidden 1` and `UserShell /usr/bin/false`);
  - `macos_vault_key_0400_daemon_file_mode`;
  - `macos_install_registers_auth_right` (the `run_input` line; `auth_rights == ["com.saiife.approve"]`; `same_user = "reauth"`);
  - `macos_auth_right_failure_warns_and_denies`;
  - `macos_start_bootstraps_then_kickstarts_on_change`;
  - `macos_second_install_unchanged`;
  - `existing_login__saiife_refused`;
  - `existing_hidden__saiife_reused`;
  - `macos_managed_paths` (Claude `…/managed-settings.d/50-saiife.json`; Gemini `/Library/Application Support/GeminiCli/settings.json`; Codex `/etc/codex/requirements.toml`);
  - `macos_install_warns_on_claude_mdm_profile`;
  - `macos_unfit_binary_refused_on_the_real_system` (mirror `unfit_binary_is_refused_on_the_real_system`: an unsigned image and one with no runtime flag are refused, and an ad-hoc image warns);
  - `macos_uninstall_removes_exactly_what_install_listed` (with the `bootout` and `authorizationdb remove` lines);
  - `macos_purge_deletes_created_users_with_dscl`;
  - `installed_toml_daemon_file_roundtrip` (policy).
- [ ] **Step 2:** run `cargo test -p saiife-system -p saiife-policy`; expect FAIL.
- [ ] **Step 3:** implement. Keep the Linux path byte-identical: every existing Linux test passes unchanged.
- [ ] **Step 4:** the tests pass, and the macOS-target check is clean.
- [ ] **Step 5:** commit `feat(system): system install/uninstall on macOS (launchd, _saiife, auth right)`.

### Task 7: the daemon on macOS

**Files:**
- Modify `crates/daemon/Cargo.toml` (macOS: `saiife-darwin`, `nix`).
- Modify these files in `crates/daemon/src/`:
  - `lib.rs` (each `cfg(target_os = "linux")` module becomes `cfg(unix)`);
  - `sessions.rs`, `start.rs`, `signals.rs`, `forward_syslog.rs`, `gateway.rs`;
  - `mcp_gateway/mod.rs` (spawning and the pidfd stay `cfg(target_os = "linux")`; on macOS `has_children()` is always false);
  - `notify.rs`.
- Modify `crates/policy/src/mcp.rs` (decision 7) and `crates/cli/src/main.rs` (`cmd_daemon` defaults).
- Enable the daemon test modules and `crates/daemon/tests/*` on unix, except the Landlock, polkit and `/proc` ones.

**Interfaces:**
- Consumes `peer_cred` (Task 2), `proc_info` (Task 1) and the macOS layout values (Task 3).
- Produces:
  - `sessions::MacProc` (macOS) implements `Proc`. `stat` returns `ProcStat { ppid, comm, start_time: start_us }`, and `cmdline` is always `None` (decision 6);
  - `sessions::host_proc() -> Box<dyn Proc + Send + Sync>`: `RealProc::new("/proc")` on Linux and `MacProc` on macOS. `start.rs` uses it;
  - `start::VAULT_KEY_FILE`: `"vault-key"` on Linux, `"vault.key"` on macOS;
  - `vault::open` accepts the macOS key: 0400, owned by the daemon uid;
  - `cmd_daemon` defaults on macOS: state dir `/var/db/saiife`, credentials dir `/var/db/saiife/keys`;
  - on macOS, the no-core-dump step uses `rustix::process::setrlimit(Resource::Core, 0, 0)`; Linux keeps `set_dumpable_behavior`;
  - on macOS, `chmod_socket` goes straight to its `statat` + `chmodat` branch, because `O_PATH` and `/proc/self/fd` do not exist there;
  - the hostname comes from `rustix::system::uname().nodename()` on macOS;
  - `forward_syslog::DEFAULT_SOCKET`: `/dev/log` on Linux, `/var/run/syslog` on macOS;
  - `tcp_peer_refused` returns `None` on macOS (decision 8);
  - `saiife_policy::mcp::MCP_NEEDS_LINUX = "the MCP gateway needs Linux (Landlock) in this version"`, returned by `validate_mcp(cfg, gateway_supported: bool)`, which the loader calls with `cfg!(target_os = "linux")`.

- [ ] **Step 1: failing tests:**
  - `node_ancestor_has_no_session` (fake `Proc`: comm `node`, cmdline `None` → session `None`; runs everywhere);
  - `gone_pid_has_no_session`;
  - `mcp_refused_when_gateway_unsupported` (the exact text);
  - `mac_proc_walks_to_parent` (macOS: spawn `/bin/sleep 5` and stop it with `Child::kill`; its `ppid` is the test's pid and its comm is `sleep`);
  - `mac_proc_start_time_detects_reuse` (macOS: a stored start time other than the real one does not match);
  - `vault_key_file_name_per_platform`.

  Beyond these, the whole existing daemon suite runs on `macos-latest` (an unprivileged daemon in tempdirs, the own uid as the daemon user).
- [ ] **Step 2:** run `cargo test -p saiife-daemon -p saiife-policy`; the Linux tests still pass and the new ones fail. The macOS-target check fails.
- [ ] **Step 3:** implement. Do not change Linux behaviour.
- [ ] **Step 4:** the Linux tests pass, the macOS-target check is clean, and `bash scripts/check-unsafe.sh` exits 0.
- [ ] **Step 5:** commit `feat(daemon): saiifed on macOS (peer creds, KERN_PROC_PID sessions, launchd)`.

### Task 8: macOS re-authentication (`com.saiife.approve`)

**Files:**
- Modify these files in `crates/daemon/src/`: `reauth.rs`, `approvers.rs`, `approval_ops.rs`, `lockdown.rs`, `ops.rs` (pick `PkCheck` or `MacAuthorize` by platform).
- Modify `crates/ipc/src/msg.rs` (the `approval.decide` doc: `auth`).
- Modify `crates/cli/Cargo.toml` (macOS: `security-framework = "=3.7.0"`) and `crates/cli/src/approvals_cmd.rs`.

**Interfaces:**
- Consumes the Task 7 daemon and `authright::{RIGHT, read_ok}`.
- Produces, in `reauth.rs`:
  - `pub struct Subject { pub pid: u32, pub start: u64, pub uid: u32, pub auth: Option<[u8; 32]> }`;
  - the trait becomes `fn check(&self, who: &Subject, detail: &str, timeout: Duration) -> ReauthResult`. `PkCheck` ignores `auth`;
  - `pub struct MacAuthorize { security: PathBuf }`, with `new()` (`/usr/bin/security`) and `with_path(..)`. It builds on every unix, so Linux tests use fake scripts;
  - `MacAuthorize::argv() -> Vec<String>` = `["authorize", "-u", "-i", "-d", "com.saiife.approve"]`. The 32 bytes go on stdin, and the environment holds only `PATH=/usr/bin:/bin`;
  - `pub fn parse_answer(code: Option<i32>, out: &str) -> ReauthResult` (decision 5). It reads the first line of stdout or stderr matching `^(YES|NO) \((-?\d+)\)`;
  - `available()`: `security` is a root-owned regular file, and `security authorizationdb read com.saiife.approve` passes `read_ok` within 5 s;
  - `pub fn parse_auth_hex(s: &str) -> Result<[u8; 32], String>` (exactly 64 lowercase hex chars).
- In `approval_ops`: a same-user approval on macOS with no `auth` is `ReauthUnavailable("the approving CLI sent no authorization")`, and bad hex is `bad_request`.
- In the CLI (macOS): `approvals_cmd::mac::external_form() -> Result<(Authorization, String), String>`. The `Authorization` is held until `approval.decide` answers. No `pkttyagent` on macOS. The line printed before the prompt is unchanged (`saiife: approving request #…`).

- [ ] **Step 1: failing tests** (Linux, with fake `security` scripts in a tempdir, as the pkcheck tests do):
  - `yes_is_authorized`;
  - `canceled_is_denied` (`NO (-60006)`);
  - `denied_is_denied` (`-60005`);
  - `interaction_not_allowed_is_unavailable` (`-60007`);
  - `other_code_is_error`;
  - `external_form_written_on_stdin_exactly` (the fake runs `cat > $out`; the file holds the 32 bytes);
  - `env_is_path_only`;
  - `hung_security_is_killed_at_timeout` (the fake sleeps; timeout 200 ms; `Error`; the child has been reaped);
  - `unavailable_starts_no_cooldown`;
  - `missing_auth_is_unavailable`;
  - `bad_auth_hex_is_bad_request`;
  - `pkcheck_unchanged_with_subject` (the existing pkcheck tests, ported to `Subject`);
  - `external_form_is_32_bytes` (macOS CI: `Authorization::default()` works without a prompt).
- [ ] **Step 2:** run `cargo test -p saiife-daemon reauth approv`; expect FAIL.
- [ ] **Step 3:** implement. Reuse `spawn`, `first_line`, `InFlight` and `Cooldowns`.
- [ ] **Step 4:** the tests pass, and the macOS-target check is clean.
- [ ] **Step 5:** commit `feat(approvals): macOS re-authentication through com.saiife.approve`.

### Task 9: the CLI's locked mode on macOS (hook, clients, `run`)

**Files:**
- Modify these files in `crates/cli/src/` (their `cfg(target_os = "linux")` gates become `cfg(unix)`): `check_managed.rs`, `main.rs`, `broker.rs`, `status_cmd.rs`, `api_cmd.rs`, `secret_cmd.rs`, `import_cmd.rs`, `connect_cmd.rs`, `lockdown_cmd.rs`, `env_cmd.rs`, `policy_cmd.rs`, `audit_locked.rs`, `mcp_cmd.rs` and `run_cmd.rs`. `mcp_spawn` stays Linux-only.
- Modify `crates/policy/src/load.rs` (`run_allow` on macOS).
- Modify `crates/guard/packs/core.lock.toml`, with examples.
- Change the `#![cfg(target_os = "linux")]` of `crates/cli/tests/*.rs` to `cfg(unix)` wherever no Landlock, polkit or systemd is needed.

**Interfaces:**
- Consumes Tasks 2, 3 and 7.
- Produces:
  - `run_cmd::is_loader_var(n)` is also true for `DYLD_*`, on every platform (decision 10);
  - `load::RunAllowBad::ThroughSystemLink`, with the text `run_allow entry {e} goes through the {link} symlink on macOS; write {/private/...} instead`. It is checked by `run_allow_problem_for(list, macos: bool)`, and the loader passes `cfg!(target_os = "macos")` (the policy crate cannot see `Platform`);
  - the `audit_locked` auditor group comes from `Layout::audit_group()`;
  - two new `core.lock` rules, with `security`, `dseditgroup` and `dscl` added to `triggers`:
    - `core.lock/authorizationdb`: `(?i)^security\s+authorizationdb\s+(?:write|remove|merge)\b`;
    - `core.lock/saiife-accounts`: `(?i)^(?:dseditgroup|dscl)\s.*\b_saiife`;
  - each refusal text that said "needs Linux in this version (macOS: v2.1)" now says `locked mode needs Linux or macOS` and appears only on other OSes.

- [ ] **Step 1: failing tests:**
  - `loader_vars_include_dyld` (`DYLD_INSERT_LIBRARIES` and `DYLD_LIBRARY_PATH` are removed);
  - `run_allow_through_var_symlink_refused_with_hint` (pure, `Platform::Macos`; `/var/x` gives the hint, `/usr/bin/curl` passes, and Linux does not refuse `/var/x`);
  - `core.lock` examples:
    - `security authorizationdb write com.saiife.approve allow` is denied;
    - `security find-generic-password` is not matched by these rules;
    - `dseditgroup -o edit -a agent -t user _saiifeaudit` is denied.

  Beyond these, the CLI integration suites that start an unprivileged daemon run on `macos-latest`.
- [ ] **Step 2:** run `cargo test -p saiife -p saiife-policy -p saiife-guard`; expect FAIL.
- [ ] **Step 3:** implement. Gate flips only where Task 7's daemon or Task 2's client already compile on macOS.
- [ ] **Step 4:** the tests pass, the macOS-target check is clean, and `scripts/bench-check.sh --managed` on Linux is within +1 ms of `main`.
- [ ] **Step 5:** commit `feat(cli): locked mode clients, hook and run on macOS`.

### Task 10: personal broker (`daemon --user`) on macOS

**Files:**
- Modify `crates/system/src/personal.rs`, `crates/daemon/src/lib.rs` and `start.rs` (`personal_preflight`), and `crates/cli/src/main.rs` (`cmd_daemon_user`).

**Interfaces:**
- Consumes `Platform`, the Task 7 daemon and `saiife_keychain::from_env` (which returns `MacKeychain` on macOS).
- Produces:
  - `personal::personal_paths_for(env, home, Platform) -> Result<PersonalPaths, String>`. `personal_paths` calls it with the current platform;
  - on macOS with no `XDG_RUNTIME_DIR`, the runtime is `<home>/Library/Caches/saiife` (`MACOS_RUNTIME_REL = "Library/Caches/saiife"`) and `socket_dir` is `<runtime>/run`. The preflight creates the runtime dir 0700 when it is missing, then runs `check_runtime_dir` as before;
  - `MAX_SOCKET_PATH = 103`; a longer `gateway.sock` path is refused with `the personal broker's socket path is too long for macOS (<n> bytes); set XDG_RUNTIME_DIR to a shorter dir`;
  - `PERSONAL_NEEDS_LINUX` becomes `PERSONAL_UNSUPPORTED = "saiife: the personal broker needs Linux or macOS"`.

- [ ] **Step 1: failing tests** (pure, on Linux):
  - `macos_paths_without_xdg_runtime`;
  - `macos_xdg_runtime_wins`;
  - `macos_runtime_created_0700`;
  - `macos_socket_path_too_long_refused` (a 70-char home);
  - `linux_paths_unchanged`.

  Beyond these, the plan 16 personal harness tests (`DirKeychain` seam) run on `macos-latest`.
- [ ] **Step 2:** run `cargo test -p saiife-system personal`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass, and the macOS-target check is clean.
- [ ] **Step 5:** commit `feat(broker): saiife daemon --user on macOS`.

### Task 11: `saiife doctor` on macOS

**Files:**
- Modify `crates/system/src/doctor/{system.rs, host.rs, mod.rs}`, `crates/cli/src/doctor_cmd.rs` and `crates/cli/src/system_cmd.rs`.

**Interfaces:**
- Consumes Tasks 4, 5 and 6.
- Produces, on macOS (the check ids are the existing ones unless marked new):
  - `system.supported`: macOS 15 or later;
  - `daemon.unit`: the plist matches its `installed.toml` fingerprint, and `launchctl print system/com.saiife.saiifed` exits 0;
  - `daemon.health`: as on Linux;
  - `files.binary`: from `inspect_macho`. No hardened runtime fails, ad-hoc warns, `Signed` passes;
  - `vault.key`: `daemon key file, 0400 _saiife`;
  - `reauth`: the right passes `read_ok`; otherwise a warning with `REAUTH_UNAVAILABLE`;
  - `peer.pidfd`: Info, `LOCAL_PEERCRED and LOCAL_PEERPID (the pid is used for attribution only)`;
  - `agents.claude.mdm` (new): Warn when `CLAUDE_MDM_PROFILE` exists, with the text `an MDM profile sets Claude Code managed settings (<path>); Claude Code may ignore saiife's managed-settings.d drop-in`;
  - host checks: an agent user in `admin` is a Warn, `agent user <u> is an admin: sudo needs its password`. NOPASSWD stays a Fail;
  - `mcp.landlock`: Info, `MCP gateway: Linux only in this version`;
  - the egress hint: Info, `macOS has no per-uid firewall in pf; the egress recipe is Linux only`.

- [ ] **Step 1: failing tests** (Linux, `Layout::under_for(tmp, Platform::Macos)`, `FakeHost` canned outputs):
  - `macos_doctor_after_fake_install_fails_only_daemon_checks`;
  - `adhoc_binary_warns`;
  - `no_runtime_binary_fails`;
  - `auth_right_missing_warns_reauth_unavailable`;
  - `auth_right_with_timeout_nonzero_warns`;
  - `claude_mdm_profile_warns`;
  - `admin_agent_user_warns`;
  - `macos_peer_identity_info`;
  - `macos_doctor_json_exit_codes` (0/1/2 as specified).
- [ ] **Step 2:** run `cargo test -p saiife-system doctor`; expect FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** the tests pass, and the macOS-target check is clean.
- [ ] **Step 5:** commit `feat(doctor): macOS checks (launchd, signature, auth right, MDM)`.

### Task 12: the `locked-macos` CI job

**Files:**
- Create `scripts/locked-macos/{run.sh, lib.sh, config.toml, inject.c}`.
- Modify `.github/workflows/ci.yml`:
  - the job `locked-macos`;
  - the `shellcheck` list gains `scripts/locked-macos/*.sh`;
  - a `test` step on macOS: `BENCH_MAX_P95_MS=40 bash scripts/bench-check.sh --managed 50`.
- Modify `scripts/bench-check.sh` to support `BENCH_MAX_P95_MS` (fail above it) and BSD `mktemp`.

**Interfaces:**
- Consumes the `saiife` CLI (Tasks 6–11) and the phase names of `scripts/locked-linux/lib.sh`.
- The job:
  - `strategy.matrix.os: [macos-15, macos-15-intel]` (check both labels exist on the day; they cover Apple silicon and Intel), `timeout-minutes: 40`, `persist-credentials: false`;
  - build: `cargo build --locked --profile ci-locked --bin saiife`, then `codesign --force --options runtime --sign - target/ci-locked/saiife` (ad-hoc plus the hardened runtime);
  - run: `SAIIFE_LOCKED_CI=1 SAIIFE_LOCKED_LOGS=… bash scripts/locked-macos/run.sh "$PWD/target/ci-locked/saiife"`;
  - on failure, upload `daemon.log`, `/etc/saiife`, the audit and the `launchctl print` output.
- `run.sh` refuses (exit 2, nothing done) unless `GITHUB_ACTIONS=true`, `SAIIFE_LOCKED_CI=1`, `uname` is `Darwin` and it runs as a non-root user. It calls `sudo` itself.
- The phases, in order:
  1. `prepare_host`: creates the users `agent` and `approver` with `sudo dscl` (not admins), random passwords, and a project dir.
  2. `phase_install`: `sudo saiife system install --agents claude,codex,gemini --approvers approver --allow-test-build --non-interactive`; exit 0 with the test-build warning.
  3. `phase_modes`: every §5.3 path's owner, group and mode through `stat -f '%Su:%Sg %Lp'`, plus `dscl . -read /Users/_saiife` (`IsHidden 1`, `UserShell /usr/bin/false`, uid in 200–400).
  4. `phase_hooks`: one fixture payload per agent through `sudo -u agent /opt/saiife/bin/saiife check --managed --agent <a>`. The record's `uid` is `agent`'s uid and `pid` is set (`LOCAL_PEERCRED`/`LOCAL_PEERPID`).
  5. `phase_fail_closed`:
     - after `sudo launchctl bootout system/com.saiife.saiifed`, every hook exits 2;
     - `bootstrap` brings it back;
     - `sudo kill -9 <daemon pid>` (CI only) is restarted by launchd within 5 s, and the next `daemon`/`start` has `previous_clean_stop = false`.
  6. `phase_attacks`, as `agent`, each attempt failing:
     - write each managed file, the plist and `/etc/saiife/config.toml`;
     - read `vault.key` and the audit key;
     - write the audit dir;
     - `kill` the daemon (EPERM);
     - `launchctl bootout system/com.saiife.saiifed`;
     - create a socket in `/var/db/saiife-run`;
     - `security authorizationdb write com.saiife.approve allow`;
     - **A4:** `DYLD_INSERT_LIBRARIES=<inject.dylib>` (built with `cc -dynamiclib inject.c`; its constructor writes a marker) on a hook call. No marker appears. A control program built with `cc` from the same file (`-DCONTROL`, no hardened runtime) does write the marker, which proves the dylib works. A platform binary such as `/usr/bin/env` is no control: SIP strips `DYLD_*` there too.
  7. `phase_doctor`: `sudo saiife doctor --json` exits 1. The `files.binary` warning (ad-hoc test build) is among the warnings, `reauth` passes, and no check fails.
  8. `phase_approvals`:
     - `approver` approves an `agent` request;
     - `agent` approving its own request is refused, with reason "re-authentication unavailable" (the runner has no GUI), and recorded;
     - lockdown by a non-approver is refused.
  9. `phase_lockdown`: as in locked-linux.
  10. `phase_reinstall_uninstall`:
      - a reinstall is unchanged;
      - `uninstall` removes exactly the listed paths, the plist and the auth right (`security authorizationdb read com.saiife.approve` fails);
      - `--purge` removes `_saiife` and both groups.

- [ ] **Step 1:** write the scripts and the job. Copy the generic helpers from `scripts/locked-linux/lib.sh` with BSD flags. Do not source the Linux file.
- [ ] **Step 2:** run `bash -n scripts/locked-macos/*.sh` and `shellcheck scripts/locked-macos/*.sh`; expect them clean.
- [ ] **Step 3:** run `env -u GITHUB_ACTIONS bash scripts/locked-macos/run.sh /bin/true; echo $?`; expect `refusing: …` and `2`. That is the only local run.
- [ ] **Step 4:** in the `test` job, `BENCH_MAX_P95_MS` is honoured. Locally, `bash scripts/bench-check.sh --managed 20` on Linux still prints its numbers (no limit set).
- [ ] **Step 5:** commit `ci: locked-macos job (install, modes, fail-closed, attacks, A4, uninstall)`.

### Task 13: release signing, hardened runtime and notarization

**Files:**
- Create `scripts/release/macos-sign.sh` and `scripts/release/test-macos-sign.sh`.
- Modify `.github/workflows/release.yml` (`pull_request.paths` gains `scripts/release/**`) and `.github/workflows/ci.yml` (the `shellcheck` list, plus an ubuntu `test` step running `bash scripts/release/test-macos-sign.sh`).

**Interfaces:**
- Secret names, exact (passed only to the signing step, never job-wide):
  - `MACOS_SIGN_P12_BASE64`: the Developer ID Application certificate and key, as `.p12`, base64;
  - `MACOS_SIGN_P12_PASSWORD`;
  - `MACOS_SIGN_IDENTITY`: for example `Developer ID Application: Jonas … (TEAMID1234)`;
  - `APPLE_TEAM_ID`;
  - `APPLE_NOTARY_APPLE_ID`;
  - `APPLE_NOTARY_PASSWORD`: an app-specific password.
- `macos-sign.sh <binary> <target>`:
  - `signing_mode` reads the six variables:
    - all set gives `developer-id`;
    - none set gives `ad-hoc`;
    - some set fails with `partial signing secrets: missing <names>`.
  - **developer-id:**
    1. A temporary keychain in `$RUNNER_TEMP`: `security create-keychain`, then `import -P … -T /usr/bin/codesign`, then `set-key-partition-list -S apple-tool:,apple:`.
    2. `codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY"`.
    3. `codesign --verify --strict --verbose=2`. `codesign -d --verbose=4` must show `runtime` and `Authority=Developer ID Application`.
    4. `ditto -c -k --keepParent` the binary into a zip, then `xcrun notarytool submit … --apple-id --team-id --password --wait --output-format json`; the status must be `Accepted`.
    5. A trap deletes the keychain.
  - **ad-hoc:** `codesign --force --options runtime --sign -`, a `::warning::macOS binaries are not signed with a Developer ID or notarized: the signing secrets are not set`, and the same runtime check.
  - Both modes write `dist/SIGNING-<target>.txt` = the mode.
  - `SAIIFE_SIGN_DRY_RUN=1` prints the mode and the commands, and runs none of them. The offline test uses it.
- `release.yml`:
  - a step `sign (macOS)` after `cargo build` and before `saiife --version`, `if: runner.os == 'macOS'`;
  - `SIGNING-*.txt` uploaded with the tarball artifact (but not as a release asset);
  - the `publish` job appends `macOS binaries in this release are ad-hoc signed and not notarized.` to `notes.md` when any `SIGNING-*` says `ad-hoc`;
  - the `install-test` job on macOS runs `codesign --verify --strict` on the installed binary.

  Fork PRs and runs without the secrets stay green in the `ad-hoc` mode.

- [ ] **Step 1: failing offline test** (`test-macos-sign.sh`, which runs on Linux and calls no tool):
  - every combination of the six variables maps to its mode (none → `ad-hoc`, all → `developer-id`, any other → exit 1 naming the missing ones);
  - the dry run prints `--options runtime` in both modes and `notarytool submit` only in `developer-id`.
- [ ] **Step 2:** run `bash scripts/release/test-macos-sign.sh`; expect FAIL.
- [ ] **Step 3:** write the script and the workflow steps.
- [ ] **Step 4:** the offline test passes, and `bash -n` and `shellcheck` are clean. A `pull_request` dry run of `release.yml` builds `ad-hoc` on both macOS targets (seen in CI at the end).
- [ ] **Step 5:** commit `ci(release): Developer ID signing, hardened runtime, notarization when secrets exist`.

### Task 14: the macOS live lock check, per-platform labels, docs and spec notes

**Files:**
- Create `scripts/lock-check/macos-vm.sh`.
- Modify `scripts/lock-check/{lib.sh, checks-claude.sh, checks-gemini.sh, checks-codex.sh, test-lib.sh}`: `LOCKCHECK_PLATFORM=macos` switches the managed paths to the §5.3 ones and `LC_HOME` to `/Users/agent`.
- Modify `crates/agents/src/lock.rs` and `crates/agents/tests/lock_check_fixtures.rs`; create `crates/agents/tests/fixtures/lock-check/macos/.gitkeep`.
- Modify these docs:
  - `docs/install.md` (a macOS locked-mode section);
  - `docs/threats.md` (A4 on macOS; egress is Linux only);
  - `docs/approvals.md` (the macOS prompt; SSH means a second account);
  - `docs/personal-broker.md` (macOS paths and Keychain);
  - `docs/mcp.md` (the gateway is Linux-only in v2.1);
  - `docs/lock-check.md` (the macOS VM steps);
  - `docs/agents/{claude-code,codex,gemini}.md` (the macOS paths and labels);
  - `README.md`, and `CHANGELOG.md` (Unreleased).
- Modify the spec (the notes below), and `crates/cli/tests/docs_wording.rs`.

**Interfaces:**
- `lock::label_for(agent: Agent, macos: bool) -> LockLabel`. `label(agent)` = `label_for(agent, cfg!(target_os = "macos"))`. Every macOS label is `Unverified` until a `macos/<agent>.tsv` recording exists, and the fixtures test checks both tables against the recordings.
- `macos-vm.sh <claude|codex|gemini|all>`:
  - it runs inside a throwaway macOS VM, as root through `sudo`;
  - it refuses unless `uname` is `Darwin` and `SAIIFE_LOCKCHECK_MACOS_VM=1`;
  - it runs the same check tables as `in-container.sh` against the macOS paths, as the unprivileged user `agent`;
  - it writes `target/lock-check/macos-<agent>-<UTC>.tsv`.
- **Spec notes:**
  - §5.3: the socket dir (decision 2), the key mode, `daemon.log`, `ThrottleInterval`, the Claude drop-in (decision 11), and the `nix`/`saiife-darwin` boundary;
  - §6.10.2: the daemon acquires the right (decisions 3–5);
  - §6.9.3: names only on macOS (decision 6);
  - §6.15: the gateway is Linux-only in v2.1 (decision 7);
  - §6.3: `[gateway] tcp` on macOS (decision 8);
  - §6.6 and §7: `daemon --user` on macOS is built (decision 9);
  - §6.14: the `DYLD_*` scrub and the `/private` hint (decision 10);
  - §17 Q1: macOS 15 (decision 13);
  - §8.1: the `socket_dir` comment;
  - §14: the release signing modes.

- [ ] **Step 1: failing tests:**
  - `macos_labels_unverified_without_recordings`;
  - the fixtures test covers `macos/`;
  - `test-lib.sh` gains `macos_platform_paths` (with `LC_ROOT` a tempdir and `LOCKCHECK_PLATFORM=macos`, the Claude managed dir is `$LC_ROOT/Library/Application Support/ClaudeCode/managed-settings.d`);
  - `macos-vm.sh` refuses outside Darwin (exit 2);
  - `docs_wording`: `docs/install.md` names `_saiife`, `/var/db/saiife-run` and `macOS 15`; `docs/mcp.md` says the gateway is Linux-only.
- [ ] **Step 2:** run `cargo test -p saiife-agents -p saiife --test docs_wording` and `bash scripts/lock-check/test-lib.sh`; expect FAIL.
- [ ] **Step 3:** write the harness, the labels and the docs. Apply the spec notes.
- [ ] **Step 4:** the tests pass, `bash -n` and `shellcheck` are clean, and `bash scripts/lock-check/macos-vm.sh all; echo $?` on Linux prints the refusal and `2`.
- [ ] **Step 5:** commit `docs: macOS locked mode; lock-check harness for a macOS VM; spec notes`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`; clippy `-D warnings`;
  - the tokio gate (with `saiife-darwin`) and `bash scripts/check-unsafe.sh`;
  - `cargo test --workspace` and `scripts/test-offline.sh`, with TMPDIR and SAIIFE_TEST_TMP set;
  - the macOS-target check;
  - `scripts/bench-check.sh` and `--managed` against `main` (Linux, +1 ms at most);
  - `bash -n` and `shellcheck` on the changed scripts;
  - `scripts/lock-check/test-lib.sh` and `scripts/release/test-macos-sign.sh`.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. CI must be green, including `test (macos-latest)` and both `locked-macos` cells. The owner merges. No tag.

## Follow-ups (not in this plan)

- A macOS sandbox for MCP gateway children (Endpoint Security or a separate uid). The gateway stays Linux-only until then.
- `LOCAL_PEERTOKEN` (an audit token with a pid version) for pid-reuse-proof attribution on macOS. It needs FFI that `nix` lacks.
- A notarized `.pkg` and MDM recipes (plan 18). Log rotation for `daemon.log` (newsyslog).
- The App Store Connect API key as a second notarization login.

## Owner handwork

Nothing here runs on Claude's machine. Everything privileged happens in CI or in a throwaway macOS VM on your Mac, so your own Mac is not modified.

- [ ] **Confirm the spec departures:**
  - the socket dir is `/var/db/saiife-run` (decision 2);
  - the daemon acquires `com.saiife.approve` (decision 3);
  - session attribution uses names only (decision 6);
  - the MCP gateway is Linux-only in v2.1 (decision 7);
  - the `[gateway] tcp` own-uid check is skipped (decision 8);
  - the minimum is macOS 15 (decision 13);
  - ad-hoc releases are allowed without the secrets (decision 13).
- [ ] **Apple account and certificate:**
  1. Join the Apple Developer Program. Note your Team ID (Membership page).
  2. In Xcode → Settings → Accounts (or on developer.apple.com → Certificates), create a **Developer ID Application** certificate. In Keychain Access, export it with its private key as `saiife-devid.p12`, with a strong password.
  3. On appleid.apple.com → Sign-In and Security → App-Specific Passwords, create one named `saiife-notary`.
- [ ] **GitHub secrets** (repository secrets on HrRobinson/saiife). Run these on your Mac:
  ```bash
  export GH_CONFIG_DIR=~/.config/gh-personal R=HrRobinson/saiife
  base64 -i saiife-devid.p12 | gh secret set MACOS_SIGN_P12_BASE64 -R $R
  gh secret set MACOS_SIGN_P12_PASSWORD -R $R      # the .p12 password
  gh secret set MACOS_SIGN_IDENTITY -R $R          # e.g. Developer ID Application: Your Name (TEAMID1234)
  gh secret set APPLE_TEAM_ID -R $R                # TEAMID1234
  gh secret set APPLE_NOTARY_APPLE_ID -R $R        # your Apple ID e-mail
  gh secret set APPLE_NOTARY_PASSWORD -R $R        # the app-specific password
  ```
  Then run `release.yml` with `workflow_dispatch` on a `v*` tag ref (for example `gh workflow run release.yml -R $R --ref v2.1.0-rc1`, after pushing that tag), not on `main`: the build step passes the signing secrets only when `github.ref` is a `refs/tags/v*` ref, so a run on `main` gets empty secrets and builds ad-hoc. A `workflow_dispatch` run never publishes (publishing needs a tag push). Both macOS build logs must say `developer-id`, and the notarization status must be `Accepted`. Delete the local `.p12` afterwards.
- [ ] **The real-Mac live lock check, in a throwaway VM:**
  1. Run `brew install cirruslabs/cli/tart`, then `tart clone ghcr.io/cirruslabs/macos-sequoia-base:latest saiife-lock`, then `tart run saiife-lock` (log in as admin/admin).
  2. In the VM:
     - install Node 22 and the agents system-wide: `sudo npm install -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli`;
     - create a standard (non-admin) user `agent` in System Settings → Users & Groups;
     - log in as `agent` once and sign in to each agent.
  3. Copy in the signed binary from the `workflow_dispatch` run (the `dist-aarch64-apple-darwin` artifact) and a checkout of the repo. Run `sudo ./saiife system install --agents claude,codex,gemini --approvers admin`. `sudo saiife doctor` should pass except for expected warnings.
  4. Run `SAIIFE_LOCKCHECK_MACOS_VM=1 sudo -E bash scripts/lock-check/macos-vm.sh all`. Copy each `target/lock-check/macos-<agent>-*.tsv` to `crates/agents/tests/fixtures/lock-check/macos/<agent>.tsv` and send them to Claude, who sets the labels.
  5. Check that the Claude drop-in is honoured. The `claude` rows fire from `managed-settings.d`. If they do not, tell Claude to switch to the whole file (decision 11).
  6. **Same-user approval is off on macOS**, logged in to the GUI as `agent`, in Terminal:
     - as root, set `[approval] approvers = ["agent", "admin"]` and keep `same_user = "deny"` (what install writes on macOS); then `sudo launchctl kill SIGHUP system/com.saiife.saiifed` to reload;
     - make an agent request hit an `ask` rule, then run `saiife approve <id>` as `agent` → refused (rule `same_user`, exit 2). No dialog appears;
     - as root run `saiife lockdown on`; then as `agent` run `saiife lockdown off` → refused with `reauth_required` (exit 2), and lockdown stays on. No dialog appears;
     - as root set `same_user = "reauth"` and reload. `saiife approve <id>` and `saiife lockdown off` as `agent` → both refused with `reauth_unavailable` (exit 2). Still no dialog;
     - from the second account (`ssh admin@<vm>`, then `saiife approve <id>`) → approved. As root, `saiife lockdown off` works. Put `same_user = "deny"` back.

     If any dialog appears, or `agent` approves its own request or lifts lockdown, report it.
  7. **A4 on the signed binary:**
     - `codesign -dv --verbose=4 /opt/saiife/bin/saiife` shows `flags=0x10000(runtime)` and `Authority=Developer ID Application`;
     - `DYLD_INSERT_LIBRARIES=/tmp/x.dylib /opt/saiife/bin/saiife --version` loads nothing (use `scripts/locked-macos/inject.c`).
  8. Download the release tarball with Safari (so it is quarantined), unpack it and run `saiife --version`. Gatekeeper must not block it.
  9. Restart the VM. The daemon must come back (`RunAtLoad`), with sockets in `/var/db/saiife-run`, and hooks must work without a reinstall.
  10. `sudo saiife system uninstall --purge`. Then `dscl . -read /Users/_saiife` must fail. Then `tart delete saiife-lock`.
- [ ] Intel is covered by the `macos-15-intel` CI cells. A run on a real Intel Mac is optional.
