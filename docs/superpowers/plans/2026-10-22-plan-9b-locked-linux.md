# Plan 9b — Locked mode on Linux (privileged) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sudo saiife system install` turns a supported Linux host into a locked host: users and groups, `/opt/saiife/bin/saiife`, `/etc/saiife`, the systemd unit with the right vault-key variant, managed hook files for Claude Code, Codex and Gemini CLI, `installed.toml`. The daemon starts, and `doctor` checks the host. `system uninstall` removes exactly what was installed. The hooks gain `--event config-change`, the `[guard.mcp]` deny, quiet project hooks and the developer-mode `fail = "closed"` opt-in. The `core.lock` pack is on when `locked = true`. Root-only tests run only in a new CI job, `locked-linux`.

**Architecture:** There is one new tokio-free crate, `crates/system` (`saiife-system`). It holds:
- `Layout`: every §5.2 path under a root prefix; `/` in production, a tempdir in tests;
- the `Host` trait, which carries every privileged action (users, groups, chown, systemctl, systemd-creds, container detection, running programs): `RealHost` in production, and `FakeHost`, which keeps its state in `<root>/.fakehost.json`;
- the supported-system check, the unit text, install, uninstall and `doctor`.

`installed.toml` is read on the hook path, so its model lives in `saiife-policy`. The managed-file writers extend the existing per-agent modules in `saiife-agents`. The hidden flag `--root <dir>` on `system`, `doctor`, `status` and `init` selects `Layout::under(dir)` + `FakeHost`. Unit and integration tests therefore run unprivileged. Real root runs only in `scripts/locked-linux/run.sh` inside the `locked-linux` CI job.

**Tech Stack:** Rust workspace; new crate `saiife-system` (deps already in `Cargo.lock`: `serde`, `serde_json`, `toml`, `toml_edit`, `sha2`, `time`, `getrandom`, `zeroize`, `thiserror`, `rustix` with `fs`, `process`, `system`); systemd 249/255; GitHub Actions `ubuntu-22.04`/`ubuntu-24.04`.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers §0 decision 8, §5.1, §5.2, §5.4, §5.4.1, §5.5 (the rejected options stay out), §5.6, §6.1.1, §6.1.3, §6.1.4, §6.16, §6.17, §7 (`system install`/`uninstall`, `doctor`, and `status`/`init`/`init --off` in locked mode), §8.3, §9.3, §11 and §13 (supported-system check, fail-closed, daemon integration). It follows the outline in `2026-10-22-plan-9a-daemon-core.md` § "Later sub-plans", and plan 9a sets the style. Plan 9a's interfaces are used as merged on `main` (6962b5b).

## Global Constraints

- **Never run anything privileged on a developer machine.** No `sudo`, no root, no systemd units installed, no writes to `/etc`, `/opt`, `/var` or `/run`, no managed agent settings written to the host, no docker for subagents. Every privileged action goes through `Host` and every path through `Layout`. Tests use `--root <tmp>` or `Layout::under(tmp)` with `FakeHost`. Scratch dirs come from `mktemp -d -p /home/jonas/projects/personal/saiife` (`/tmp` has a quota). Run local tests as `TMPDIR=$(mktemp -d -p /home/jonas/projects/personal/saiife) cargo test --workspace`.
- **Real root tests run only in the CI job `locked-linux`** (matrix `ubuntu-22.04`, `ubuntu-24.04`; job ids have no dots). `scripts/locked-linux/run.sh` exits 2 with `refusing: locked-linux tests run only as root in CI (SAIIFE_LOCKED_CI=1)` unless `SAIIFE_LOCKED_CI=1` and euid 0. `cargo test` never runs them. Actions are pinned to the full SHAs already used in `.github/workflows/ci.yml`. The new job's checkout sets `persist-credentials: false`, and top-level `permissions: contents: read` stays.
- **Spec values, verbatim:**
  - §5.2 paths, owners and modes:
    - `/opt/saiife`, `/opt/saiife/bin`, `/opt/saiife/bin/saiife`: root:root 0755.
    - `/etc/saiife`: root:root 0755.
    - `config.toml`, `policy.d/*.toml`, `installed.toml`: root:root 0644.
    - `/etc/saiife/credstore/vault-key`: root:root 0600 (systemd ≥ 250) or root:saiife 0640 (systemd < 250).
    - `/etc/systemd/system/saiifed.service`: root:root 0644.
    - `/var/lib/saiife`: saiife:saiife 0700. `/var/lib/saiife/keys/audit.ed25519`: 0600.
    - `/var/log/saiife/audit`: saiife:saiife-audit 2750. Its `YYYY-MM.jsonl` files: 0640.
    - `/run/saiife`: saiife:saiife 0755. `saiife.sock`: 0666.
    - The managed files: root:root 0644.
  - Users and groups: user `saiife`, group `saiife`, group `saiife-audit`.
  - The §5.4.1 unit text (Task 1). The §8.3 managed file contents are byte-for-byte the fixtures in `crates/agents/tests/fixtures/managed/`.
  - Managed paths: `/etc/claude-code/managed-settings.d/50-saiife.json`, `/etc/codex/requirements.toml`, `/etc/gemini-cli/settings.json`.
  - `doctor` exit codes: 0 when everything passes, 1 on a warning, 2 on a failure.
  - The MCP warning text: `MCP server <name> bypasses saiife: its requests are not brokered or limited`.
  - Claude Code minimum version: `2.1.295`.
  - Root-equivalent groups: `docker`, `lxd`, `incus`, `libvirt`, `disk`.
- **Supported systems (§0 decision 8):** Ubuntu 22.04+, Debian 12+, RHEL 9+ (and `ID_LIKE` rhel ≥ 9), each with systemd running. `install` refuses everything else (Alpine, containers, no systemd, macOS) with one line: `saiife: locked mode is not supported here: <why>. Developer mode works as before.` On macOS the 9a text applies: `saiife: locked mode needs Linux in this version (macOS: v2.1)`. Exit 2.
- **Fail closed in locked mode.** Every new `--managed` path (config-change, MCP deny, an unreadable settings file) ends in exit 2 + stderr + a record when the daemon is reachable. **Developer mode is unchanged** unless `/etc/saiife` says otherwise (Task 5). Its median in `scripts/bench-check.sh 50` stays within +1 ms of `main`; put both numbers in the PR.
- **Dependencies:** no new external crates are planned. If one is needed, use a release published at least 14 days ago (check with `cargo info`; pin `=` otherwise). `saiife-system`, `saiife-policy`, `saiife-ipc`, `saiife-guard` and `saiife-audit` stay free of tokio. Extend the CI no-tokio gate with `-p saiife-system`.
- `#![forbid(unsafe_code)]` in `saiife-system`. OS calls go through `rustix` or `std::process::Command`, always with absolute program paths: `/usr/sbin/useradd`, `/usr/sbin/groupadd`, `/usr/sbin/usermod`, `/usr/sbin/userdel`, `/usr/sbin/groupdel`, `/usr/bin/systemctl`, `/usr/bin/systemd-creds`, `/usr/bin/systemd-detect-virt`, `/usr/bin/sudo`. If a program is missing, the error names it.
- **Git:** branch `plan-9b-locked-linux`. Stage explicit paths. Merge to main only through a PR. Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

**Parallel groups.**
- Wave 1: Tasks 1 (A), 2 (B) and 3 (C) touch disjoint crates and files. Run them in parallel.
- Wave 2: Tasks 4 (D, needs 1), 5 (E, needs 1 and 3) and 6 (F, needs 1). They are disjoint except `crates/cli/src/main.rs`, where each adds its own enum variant or flags, and `crates/system/src/lib.rs` (Tasks 4 and 6 each add one `pub mod` line). The controller merges those lines.
- Wave 3: Task 7 (G, needs 6) and Task 8 (H, needs 4, 5 and 6) touch disjoint files.

**9a follow-ups, where they land:**

| Follow-up (ledger / PR #13) | Task |
|---|---|
| Owner and mode checks on the key dir and key file (+ symlinked parent, partial key file left by a crash) | 2 (daemon start), 4 (install), 6 (doctor) |
| Agent users must resolve through `/etc/passwd`; NSS-only users are denied | 7 (doctor `user.<name>.passwd`, fail) |
| `core.lock` protects the locked-mode paths. The worker's path rules covered only `$SAIIFE_BIN` (+ its ancestors) and per-user `~/.local/share/saiife` dirs, not `/etc/saiife`, `/var/lib/saiife`, `/var/log/saiife`, `/run/saiife`, the managed agent settings or the unit | 3 |
| The hook can't write `error_denied` when the `/etc` config is invalid | 6 (doctor `config.valid`, fail), 8 (status) |
| `previous_clean_stop` reads false after a lost key (the unsigned `key_rotate` hides the stop record) | 2 |
| `rate_limited` reason text is wrong for connection-cap refusals | 2 |
| Timing-sensitive `chain::tests::parallel_appends_keep_the_chain` | 2 |
| Timing-sensitive `check_managed::worker_never_reading_stdin_denies` | 5 |
| Group-writable socket-dir test; `encode` accepts a non-object; `set_timeouts` error → `Connect` (ipc) | left: cosmetic; no behaviour change in locked mode |
| Config-reader fallback race / non-Linux post-open check / exec-only project root / `OutsideProject` wording | left: developer-path hardening, plan 12 sweep |
| `Getent` PATH fallback; all-digit names as uids; scope lookup by name; `groups_of` failure reads as no groups | left: plan 10 (connector scopes are the first authority use) |
| Stale `load()`, far-file fragment, chain-less far file (ChainWriter) | left: documented limits |
| `startup_check` trusts the line before its window | left: documented limit |
| `ts` stamped before enqueue; client-planted `extra.client_ts`; RLIMIT edge; probabilistic stop test | left: attribution only / no fail-open path |
| `WORKER_PID` reuse window; concurrent `exit` vs `_exit`; empty passwd home; vague reason over the worker IO cap | left: no fail-open path; a vague reason only |
| `retention_months` deletion | left: plan 12 (9a open question 13) |

## Review Focus

1. **Agent config files that already exist at a managed path.** `/etc/codex/requirements.toml` or `/etc/gemini-cli/settings.json` may already hold the admin's own entries. Install adds only saiife's tagged entry and keeps everything else byte-for-byte. Uninstall removes only that entry, and deletes the file only if install created it. Tests: Task 4 `codex_requirements_keeps_admin_entries`, `gemini_settings_keeps_admin_entries`, `uninstall_keeps_preexisting_codex_file`.
2. **A `saiife` user, `/var/lib/saiife` or `keys/` that already exists and is wrong.** Examples: a human account named `saiife` (uid ≥ 1000 or a login shell), a state dir with mode 0755, a key dir owned by someone else. Install refuses and names the path and the problem. It never adopts or chowns these. Tests: Task 4 `existing_human_saiife_user_refused`, `existing_state_dir_wrong_mode_refused`; Task 2 `key_dir_wrong_owner_refused`.
3. **`/etc/saiife/config.toml` becomes invalid after install** (an admin typo). Every managed hook then denies, and nothing is recorded, because the socket dir and daemon user are unknown. `doctor` must fail loudly and name the error, and `status` must say that calls are denied without records. Tests: Task 6 `invalid_config_fails_and_says_no_records`; Task 8 `status_reports_invalid_system_config`.
4. **`doctor` run as root reads files inside an agent user's home.** A symlink to `/etc/shadow`, a FIFO or a 2 GiB file must never be followed, block, or be read past 1 MiB, and no secret value is ever printed. Test: Task 7 `secret_scan_never_follows_symlinks_or_blocks`.
5. **Install that fails halfway, then uninstall.** If the daemon does not start, or a step errors after users were created, `installed.toml` already lists what was made. `uninstall` removes exactly that, skips listed paths that are gone, and never touches unlisted paths. Tests: Task 4 `start_failure_still_writes_installed_and_exits_2`, `uninstall_after_partial_install_is_clean`.

---

### Task 1: Foundation — `Layout`, `Host`, supported-system check, unit text, `installed.toml`, lock labels  [wave 1, group A]

**Files:**
- Create: `crates/system/Cargo.toml` (`saiife-system`; deps `saiife-agents`, `saiife-policy`, `saiife-ipc`, `serde`, `serde_json`, `toml`, `toml_edit`, `sha2`, `time`, `getrandom`, `zeroize`, `thiserror`; unix `rustix` `fs`/`process`/`system`; dev `tempfile`)
- Create: `crates/system/src/{lib.rs, layout.rs, host.rs, supported.rs, unit.rs}`
- Create: `crates/policy/src/installed.rs`; modify `crates/policy/src/lib.rs` (`pub mod installed;`)
- Create: `crates/agents/src/lock.rs`; modify `crates/agents/src/lib.rs` (`pub mod lock;`, `Agent::managed_command`)
- Modify: `.github/workflows/ci.yml` (no-tokio gate gains `-p saiife-system`)
- Test: unit tests in each new module; `crates/agents/tests/lock_check_fixtures.rs`

**Interfaces:**
- Produces (`layout.rs`):
  - `pub const` path strings, verbatim from §5.2: `OPT_DIR`, `BIN_DIR`, `BINARY`, `ETC_DIR`, `CONFIG`, `POLICY_D`, `CREDSTORE` (`/etc/saiife/credstore`), `VAULT_KEY`, `INSTALLED`, `UNIT` (`/etc/systemd/system/saiifed.service`), `STATE_DIR`, `KEYS_DIR`, `AUDIT_KEY`, `LOG_DIR` (`/var/log/saiife`), `AUDIT_DIR`, `RUN_DIR`, `SOCKET`, `CLAUDE_MANAGED_DIR`, `CLAUDE_MANAGED`, `CODEX_DIR` (`/etc/codex`), `CODEX_REQUIREMENTS`, `GEMINI_DIR` (`/etc/gemini-cli`), `GEMINI_SETTINGS`.
  - `pub const DAEMON_USER: &str = "saiife"; DAEMON_GROUP = "saiife"; AUDIT_GROUP = "saiife-audit"; UNIT_NAME = "saiifed.service";`
  - `pub struct Layout { root: PathBuf }` with:
    - `system() -> Layout` (root `/`) and `under(root: impl Into<PathBuf>) -> Layout`;
    - `root(&self) -> &Path` and `is_system(&self) -> bool`;
    - `at(&self, abs: &str) -> PathBuf`: the root joined with `abs` minus its leading `/`;
    - `managed_file(&self, a: Agent) -> PathBuf`.
- Produces (`host.rs`):
  - `pub struct CmdOutput { pub status: i32, pub stdout: String, pub stderr: String }`
  - `pub struct UserInfo { pub uid: u32, pub gid: u32, pub home: PathBuf, pub shell: String }`
  - `pub trait Host: Send + Sync` with:
    - `euid(&self) -> u32`
    - `user(&self, name: &str) -> Option<UserInfo>` and `group_id(&self, name: &str) -> Option<u32>`
    - `create_system_group(&self, name: &str) -> io::Result<()>`, `create_system_user(&self, name: &str, group: &str) -> io::Result<()>`, `add_to_group(&self, user: &str, group: &str) -> io::Result<()>`, `delete_user(&self, name: &str) -> io::Result<()>`, `delete_group(&self, name: &str) -> io::Result<()>`
    - `chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()>`: never follows a symlink
    - `systemctl(&self, args: &[&str]) -> io::Result<CmdOutput>`
    - `systemd_version(&self) -> io::Result<u32>`
    - `encrypt_credential(&self, name: &str, secret: &[u8], out: &Path) -> io::Result<()>`
    - `container(&self) -> Option<String>`
    - `run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<CmdOutput>`
  - `pub struct RealHost;` These are the only calls that need root:
    - `useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid <group> <name>`
    - `groupadd --system`, `usermod -aG`, `rustix::fs::chownat(.., AtFlags::SYMLINK_NOFOLLOW)`
    - `systemd-creds encrypt --name=<name> - <out>` with the secret on stdin
    - `systemd-detect-virt --container`: exit 0 → `Some(stdout)`
    - `systemctl --version`, whose first line is `systemd <N> (…)`
  - `pub struct FakeHost` with `open(root: &Path) -> io::Result<FakeHost>`. Its state lives in `<root>/.fakehost.json` and survives across processes:
    - `users`, `groups`: by default every created or queried name maps to `getuid()`/`getgid()`, so owner checks pass in tests;
    - `chowns`: recorded, not applied;
    - `calls`: every `systemctl` / `run` call as one string;
    - `systemd`: default 255; `container`: default null;
    - `run`: canned outputs keyed by `"<program> <args…>"`, default status 1 with empty output.
    - `FakeHost::set(&self, f: impl FnOnce(&mut FakeState))` lets tests change ids, the systemd version, the container value and canned outputs.
  - `pub fn host_for(layout: &Layout) -> Box<dyn Host>`: `RealHost` when `layout.is_system()`, else `FakeHost::open(root)`.
- Produces (`supported.rs`):
  - `pub enum Support { Supported { distro: String, systemd: u32 }, Refused(String) }`
  - `pub fn check_supported(layout: &Layout, host: &dyn Host) -> Support` reads `<root>/etc/os-release` and `<root>/run/systemd/system`. It checks, in order:
    - not Linux → `locked mode needs Linux in this version (macOS: v2.1)`;
    - `host.container()` is `Some(c)`, or `<root>/.dockerenv` or `<root>/run/.containerenv` exists → `inside a container (<c>): developer mode only`;
    - `/run/systemd/system` is missing → `systemd is not running; locked mode needs systemd`;
    - systemd < 247 → `systemd <n> is too old (247 or later is needed for LoadCredential)`;
    - `ID=alpine` → `Alpine: developer mode only`;
    - ubuntu with `VERSION_ID` ≥ 22.04, debian ≥ 12, `ID=rhel` or `ID_LIKE` containing `rhel` with major ≥ 9 → `Supported`;
    - anything else → `<PRETTY_NAME> is not supported for locked mode (Ubuntu 22.04+, Debian 12+, RHEL 9+)`.
  - `pub fn refusal_line(why: &str) -> String` = `format!("saiife: locked mode is not supported here: {why}. Developer mode works as before.")`
- Produces (`unit.rs`):
  - `pub fn unit_text(systemd: u32) -> String`. For ≥ 250 it is the §5.4.1 block verbatim, the `# systemd < 250` comment line included, ending in one `\n`. For < 250 it is the same text with the `LoadCredentialEncrypted=…` line replaced by `LoadCredential=vault-key:/etc/saiife/credstore/vault-key` and the comment line removed.
  - `pub fn vault_key_mode(systemd: u32) -> VaultKeyMode` (`Credential` if ≥ 250, else `File`).
- Produces (`saiife_policy::installed`, tokio-free, read on the hook path):
  - `pub const INSTALLED_VERSION: u32 = 1;`
  - `pub enum VaultKeyMode { Credential, File }` (serde lowercase)
  - `pub enum FileKind { Binary, Unit, Config, VaultKey, Managed }` (snake_case)
  - `pub struct InstalledFile { pub path: PathBuf, pub sha256: String, pub kind: FileKind, pub created: bool }`
  - `pub struct ManagedAgent { pub agent: String, pub path: PathBuf, pub sha256: String, pub whole_file: bool, pub created_file: bool }`. For a whole file, `sha256` covers the file. For an entry it is the entry fingerprint (§8.3: Codex, and Gemini the same way).
  - `pub struct Installed { pub version: u32, pub saiife: String, pub installed_at: String, pub systemd: u32, pub vault_key: VaultKeyMode, pub users: Vec<String>, pub groups: Vec<String>, pub dirs: Vec<PathBuf>, pub files: Vec<InstalledFile>, pub agents: Vec<ManagedAgent> }`. `users`, `groups` and `dirs` list only what install created, in creation order. `deny_unknown_fields`.
  - `impl Installed { pub fn has_managed(&self, agent: &str) -> bool }`
  - `pub fn read_installed(path: &Path) -> Result<Option<Installed>, String>`: `Ok(None)` when missing. The read uses `O_NOFOLLOW | O_NONBLOCK`, accepts a regular file only, at most 1 MiB.
  - `pub fn write_installed(path: &Path, i: &Installed) -> io::Result<()>`: a temp file at 0644, synced, then renamed.
- Produces (`saiife_agents::lock`):
  - `pub enum LockLabel { Lockable, LockableWithGaps, LockableWithCaveats, NotLockable, Unverified }`
  - `id()`: `lockable`, `lockable-with-gaps`, `lockable-with-caveats`, `not-lockable`, `unverified`.
  - `wording()`: `lockable`, `lockable, fail-open gaps listed`, `lockable with caveats`, `not lockable`, `unverified` (docs/lock-check.md).
  - `pub fn label(agent: Agent) -> LockLabel`: Claude `Lockable` (plan 7 recording); Codex and Gemini `Unverified`.
- Produces (`saiife_agents`): `Agent::managed_command(self) -> String` = `"/opt/saiife/bin/saiife check --managed --hook-exit --agent <name>"`.

- [ ] **Step 1: Failing tests.**
  - `layout.rs`: `under_joins_every_path` (`Layout::under("/x").at(AUDIT_KEY) == "/x/var/lib/saiife/keys/audit.ed25519"`); `system_paths_are_spec_values` (each const, spelled out).
  - `host.rs`: `fake_host_state_survives_reopen`; `fake_host_records_systemctl_calls`; `fake_host_ids_default_to_own_uid`; `fake_chown_is_recorded_not_applied`; `real_systemd_version_parses` (factored `parse_systemd_version("systemd 249 (249.11-0ubuntu3)\n+PAM …") == Some(249)`, `"garbage"` → None).
  - `supported.rs` (each with a `<root>/etc/os-release` fixture and `run/systemd/system` dir):
    - `ubuntu_2204_and_2404_supported`; `ubuntu_2004_refused`;
    - `debian_12_supported`; `debian_11_refused`;
    - `rhel_9_and_rocky_9_supported`; `rhel_8_refused`;
    - `alpine_refused_developer_mode_only` (the text contains `Alpine: developer mode only`);
    - `container_refused` (FakeHost `container = "docker"`, and separately `<root>/.dockerenv`);
    - `no_systemd_refused`;
    - `systemd_246_refused`;
    - `refusal_line_is_exact`.
  - `unit.rs`:
    - `unit_255_is_spec_text`: the whole string equals a `const SPEC_UNIT` written in the test by copying §5.4.1;
    - `unit_249_uses_load_credential`: it contains `LoadCredential=vault-key:/etc/saiife/credstore/vault-key\n` and contains neither `LoadCredentialEncrypted` nor `# systemd < 250`. Every other line is identical.
  - `installed.rs`:
    - `round_trip`;
    - `missing_is_none`;
    - `unknown_key_is_error`;
    - `symlink_refused`;
    - `fifo_does_not_block` (returns `Err` in under 1 s);
    - `has_managed_by_agent_name`.
  - `lock.rs`:
    - `claude_label_matches_recording`: reads `tests/fixtures/lock-check/claude.tsv`, takes the `# label=` line, and compares it to `label(Claude).id()`;
    - `unrecorded_agents_are_unverified`: no `codex.tsv`/`gemini.tsv` → `Unverified`. When a recording lands, the test fails until `label()` is updated.
    - `wording_matches_lock_check_doc`.
- [ ] **Step 2:** `cargo test -p saiife-system -p saiife-policy -p saiife-agents` fails to compile or fails.
- [ ] **Step 3:** Implement. `FakeHost` is compiled always, not only under `cfg(test)`: the binary uses it behind the hidden `--root` flag.
- [ ] **Step 4:** `cargo test --workspace` green, clippy `-D warnings` clean, the no-tokio gate (with `-p saiife-system`) prints `0`.
- [ ] **Step 5:** Commit `feat(system): layout, host trait, supported-system check, unit text, installed.toml, lock labels`.

### Task 2: Daemon and audit follow-ups  [wave 1, group B]

**Files:**
- Modify: `crates/audit/src/sign.rs` (key dir and key file checks, crash-safe create), `crates/audit/src/chain.rs` (`startup_check`; the test wait), `crates/daemon/src/ops.rs`, `crates/daemon/src/server.rs`, `crates/daemon/src/start.rs` (audit group)
- Test: unit tests in those files; `crates/cli/tests/daemon.rs`

**Interfaces:**
- Produces (`sign.rs`):
  - `AuditKey::load_or_create(path)` keeps its signature and calls `pub fn load_or_create_owned(path: &Path, owner: u32) -> io::Result<(AuditKey, bool)>` with `geteuid()`. The checks:
    - the key's parent dir (`keys/`), when it exists, is checked with `lstat`: a real directory, owned by `owner`, `mode & 0o077 == 0`;
    - the parent's parent (the state dir) is not a symlink and not group- or world-writable;
    - if `keys/` is missing, it is created 0700 with `mkdirat` relative to an `O_NOFOLLOW | O_DIRECTORY` fd of the state dir;
    - the key file, after its `O_NOFOLLOW` open, is checked with `fstat`: owned by `owner`, mode 0600, 32 bytes.
    - Each failure is `Err` naming the path, the owner wanted and the one found, or the mode wanted and the one found.
  - The first key is created crash-safe: write `.audit.ed25519.tmp` (`O_EXCL`, 0600, synced), then `hard_link` it to the final name and remove the temp file. `AlreadyExists` from the link means another process won: load that key. A temp file left by a crash is removed first (with `unlink`, which never follows).
- Produces (`chain.rs`): `startup_check` ignores `key_rotate` records, like checkpoints, when it sets `last_clean_stop`.
  - `pub(crate) fn append_chained_wait(dir: &Path, rec: Record, wait: Duration) -> io::Result<u64>`; `append_chained` = `append_chained_wait(.., LOCK_WAIT)`.
- Produces (`ops.rs`): `pub enum Notice { Requests, Connections, LowDisk }`.
  - `Ctx::notice(&self, uid: u32, n: Notice)` dedupes per `(uid, Notice)`, once a minute.
  - Events: `Requests` and `Connections` → `"rate_limited"`; `LowDisk` → `"low_disk"`.
  - Reasons, exact:
    - `Requests`: `uid {uid} is over its request limits (64 in flight, 1000/s)`
    - `Connections`: `uid {uid} is over its connection limits (32 open per uid, or the daemon's total)`
    - `LowDisk`: `uid {uid}: audit volume below [audit] min_free_mb`
- Produces (`start.rs`):
  - `fn adopt_audit_group(dir: &Path, gid: u32) -> io::Result<u32 /* files changed */>`: when the dir's gid is not `gid`, chown (uid unchanged, `SYMLINK_NOFOLLOW`) the dir and every regular `*.jsonl` in it.
  - At start, after `ChainWriter::open`: if group `saiife-audit` exists (`Directory::group`), call it. An error is one stderr warning, not a refusal.
  - Why: systemd's `LogsDirectory=` gives the dir to the unit's `Group=saiife` on every start, and §5.2 wants `saiife-audit` (Open questions, item 3).

- [ ] **Step 1: Failing tests.**
  - `sign.rs`:
    - `key_dir_wrong_owner_refused`: `load_or_create_owned(path, getuid() + 1)` → `Err` whose text contains `owned by uid`;
    - `key_dir_group_readable_refused` (existing `keys/` at 0750);
    - `key_dir_symlink_refused` (`keys` → another 0700 dir);
    - `state_dir_world_writable_refused`;
    - `key_file_wrong_owner_refused`;
    - `crash_leftover_tmp_is_replaced`: a 5-byte `.audit.ed25519.tmp` exists → a key is created, the final file is 32 bytes, the temp file is gone;
    - `concurrent_create_yields_one_key`: two threads call `load_or_create` → the same public key.
    - Every existing 9a key test stays green.
  - `chain.rs`: `clean_stop_survives_lost_key`. Writer A appends a `kind "daemon"`, `event "stop"` record; drop; open with key B (writes the unsigned `key_rotate`) → `startup_check(1000).last_clean_stop == true`.
  - `parallel_appends_keep_the_chain` uses `append_chained_wait(.., Duration::from_secs(30))`; its assertions are unchanged.
  - `ops.rs`: `notice_reasons_are_exact` (all three strings); `connection_and_request_notices_dedupe_separately`.
  - `start.rs`: `adopt_audit_group_changes_dir_and_files`, using the test user's primary gid on a dir chowned to it (a no-op succeeds and returns 0). The real group change is asserted in CI (Task 8).
  - `crates/cli/tests/daemon.rs`: `restart_with_lost_key_after_clean_stop_is_clean`. SIGTERM, delete the key file, start again → `daemon`/`start` has `previous_clean_stop` true; `verify` exit 1 with `UnsignedKeyRotate` (a lost key is still reported).
- [ ] **Step 2:** `cargo test -p saiife-audit -p saiife-daemon && cargo test -p saiife --test daemon` fails.
- [ ] **Step 3:** Implement. `server.rs` passes `Notice::Connections` at the connection cap and `Notice::Requests` at `try_begin`.
- [ ] **Step 4:** Run `cargo test --workspace` (TMPDIR as in Global Constraints) and clippy clean. Then run `for i in $(seq 20); do cargo test -p saiife-audit parallel_appends_keep_the_chain -q || break; done`: 20 passes.
- [ ] **Step 5:** Commit `fix(daemon): key dir and file owner checks, clean stop after a lost key, exact refusal reasons, audit group`.

### Task 3: `core.lock` pack and the locked-mode path variables  [wave 1, group C]

**Files:**
- Create: `crates/guard/packs/core.lock.toml`, `docs/packs/core.lock.md`, `crates/guard/tests/corpus_lock.rs`
- Modify: `crates/guard/src/builtins.rs` (register it), `crates/guard/src/pathrule.rs` (`VARIABLES`), `crates/policy/src/effective.rs` (`active_packs`), `crates/cli/src/paths.rs`, `crates/cli/src/eval.rs` (`EvalRequest.locked`), `crates/cli/src/check_managed.rs` (fill it)
- Test: `corpus_lock.rs`, `effective.rs` units, `paths.rs` units, `crates/cli/tests/check_managed.rs`

**Interfaces:**
- Produces (`pathrule.rs`): `VARIABLES` gains `SAIIFE_ETC`, `SAIIFE_STATE`, `SAIIFE_LOG`, `SAIIFE_RUN`, `SAIIFE_OPT` and `SAIIFE_UNIT`.
- Produces (`paths.rs`):
  - `#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)] pub struct LockedPaths { pub etc: PathBuf, pub audit_dir: PathBuf, pub socket_dir: PathBuf }`
  - `pub fn path_vars_locked(cwd: Option<&Path>, project: Option<&Path>, locked: Option<&LockedPaths>) -> PathVars`. `path_vars(cwd, project)` = `path_vars_locked(cwd, project, None)`.
  - The new variables are always bound to their §5.2 defaults: `/etc/saiife`, `/var/lib/saiife`, `/var/log/saiife`, `/run/saiife`, `/opt/saiife`, `/etc/systemd/system/saiifed.service`.
  - With `locked`, these are added as extra values: `etc` → `SAIIFE_ETC`, `audit_dir` → `SAIIFE_AUDIT_DIR`, `socket_dir` → `SAIIFE_RUN`.
- Produces (`eval.rs`): `EvalRequest` gains `#[serde(default)] pub locked: Option<LockedPaths>`, and the worker's `engine_for` uses `path_vars_locked`.
  - `check_managed` sets it to `LockedPaths { etc: <system config's parent dir>, audit_dir: cfg.audit.dir, socket_dir: cfg.daemon.socket_dir }`.
- Produces (`effective.rs`): `active_packs` adds `core.lock` when `cfg.locked` and the catalog has it. This changes the `policy` hash of locked hosts, which is expected.
- Pack `core.lock` (`default_on = false`, `version = 1`, triggers covering every command rule's first word). Command rules use `whole_segment = true` so that wrappers stay visible:
  - privilege changes: `sudo`, `su`, `doas`, `pkexec`, `run0` as the segment's first word; `osascript` with `with administrator privileges`;
  - the service:
    - `systemctl` with any argument containing `saiifed`;
    - `launchctl` with an argument starting `com.saiife.`;
    - `kill`, `pkill` or `killall` naming `saiifed`;
  - persistence:
    - `crontab`, `at` and `systemd-run … --user`;
    - `launchctl load` or `bootstrap`;
  - safety switches: `--dangerously-bypass-hook-trust` anywhere in the segment, or an assignment `GEMINI_CLI_SYSTEM_SETTINGS_PATH=` or `GEMINI_CLI_SYSTEM_DEFAULTS_PATH=`.
  - `deny_path` with `access = "write"`:
    - `~/.config/systemd/user/**`, `~/Library/LaunchAgents/**`, `~/.config/autostart/**`;
    - `$SAIIFE_ETC/**`, `$SAIIFE_OPT/**`, `$SAIIFE_LOG/**`, `$SAIIFE_AUDIT_DIR/**`, `$SAIIFE_RUN/**`, `$SAIIFE_UNIT`, each plus an `ancestors = true` twin;
    - `/etc/claude-code/managed-settings.d/**`, `/etc/claude-code/managed-settings.d`, `/etc/claude-code/managed-settings.json`;
    - `/etc/codex/requirements.toml`, `/etc/codex`;
    - `/etc/gemini-cli/settings.json`, `/etc/gemini-cli`.
  - `deny_path` with `access = "any"`: `$SAIIFE_STATE/**`, plus an ancestors twin for writes.
  - Every reason says what the rule protects (the §6.17 "why" line).

- [ ] **Step 1: Failing tests.**
  - `corpus_lock.rs`, with the engine built from `core.lock` and vars bound as in production:
    - denied: `sudo ls`, `sudo -u root id`, `su -`, `doas sh`, `pkexec bash`, `run0 id`, `osascript -e 'do shell script "x" with administrator privileges'`;
    - denied: `systemctl stop saiifed`, `systemctl --now disable saiifed.service`, `pkill saiifed`, `killall -9 saiifed`, `launchctl bootout system/com.saiife.saiifed`;
    - denied: `crontab -e`, `echo x | at now`, `systemd-run --user sh`, `launchctl load ~/Library/LaunchAgents/x.plist`;
    - denied: `codex --dangerously-bypass-hook-trust`, `GEMINI_CLI_SYSTEM_SETTINGS_PATH=/tmp/s gemini`;
    - path writes denied: `/etc/saiife/config.toml`, `/etc/saiife`, `/etc` (ancestor), `/var/lib/saiife/keys/audit.ed25519` (read too), `/var/log/saiife/audit/2026-11.jsonl`, `/run/saiife/saiife.sock`, `/opt/saiife/bin/saiife`, `/etc/systemd/system/saiifed.service`, `/etc/claude-code/managed-settings.d/50-saiife.json`, `/etc/codex/requirements.toml`, `/etc/gemini-cli/settings.json`, `~/.config/systemd/user/x.service`;
    - allowed: `systemctl status nginx`, `ls /etc/saiife`, a Read of `/etc/saiife/config.toml`, `kill 1234`, `atop`, `suspend-test`, `sudoku`.
  - `docs_pages.rs` (existing) passes once `docs/packs/core.lock.md` exists.
  - `effective.rs`: `locked_adds_core_lock` (`locked = true` → ids contain `core.lock`; `locked = false` → they do not).
  - `paths.rs`: `locked_paths_add_values` (`SAIIFE_AUDIT_DIR` holds both the per-user default and the config dir; `SAIIFE_ETC` holds `/etc/saiife` and the given dir).
  - `crates/cli/tests/check_managed.rs`:
    - `managed_write_to_daemon_audit_dir_denied`: a Claude `Write` to `<TestDaemon audit_dir>/x.jsonl` → exit 2, stderr starts `BLOCKED by core.lock`;
    - `managed_sudo_denied`: Bash `sudo ls` → exit 2, `BLOCKED by core.lock`.
    - `managed_deny_exit_2` still names `core.filesystem` for `rm -rf /`.
- [ ] **Step 2:** `cargo test -p saiife-guard --test corpus_lock && cargo test -p saiife-policy && cargo test -p saiife --test check_managed` fails.
- [ ] **Step 3:** Implement. The developer path binds the new variables but does not activate `core.lock` (`default_on = false`), so developer decisions are unchanged.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean, `scripts/bench-check.sh 50`: the developer median is within +1 ms of `main`.
- [ ] **Step 5:** Commit `feat(guard): core.lock pack, on in locked mode; protects saiife's system paths and the managed agent settings`.

### Task 4: `saiife system install` / `uninstall`  [wave 2, group D; needs Task 1]

**Files:**
- Create: `crates/system/src/{install.rs, uninstall.rs, default_config.rs, fsops.rs}`; modify `crates/system/src/lib.rs`
- Modify: `crates/agents/src/claude.rs` (`managed_settings`), `crates/agents/src/codex.rs` and `crates/agents/src/gemini.rs` (`install_managed`, `remove_managed`, `managed_entry`), `crates/agents/src/json_hooks.rs` (file-path variants), `crates/agents/src/lib.rs` (`is_saiife_command` accepts the absolute path)
- Create: `crates/cli/src/system_cmd.rs`; modify `crates/cli/src/main.rs` (`System { action }`) and `crates/cli/Cargo.toml`
- Test: unit tests in `install.rs`/`uninstall.rs`, `crates/agents/tests/managed_fixtures.rs`, `crates/cli/tests/system_install.rs`

**Interfaces:**
- Consumes: Task 1 `Layout`, `Host`, `host_for`, `check_supported`, `refusal_line`, `unit_text`, `vault_key_mode`, `Installed`, `write_installed`, `read_installed`, `Agent::managed_command`; 9a `saiife_policy::load_and_check`.
- Produces (agents):
  - `claude::managed_settings() -> &'static str`: byte-for-byte the fixture `managed/claude/50-saiife.json`;
  - `codex::install_managed(file: &Path) -> Result<Change, AgentError>` (sets `[features] hooks = true` and appends saiife's group per §8.3 with `toml_edit`; keeps everything else), `codex::remove_managed(file: &Path) -> Result<Change, AgentError>`, `codex::managed_entry(file: &Path) -> Result<Option<String>, AgentError>` (fingerprint);
  - `gemini::install_managed`, `gemini::remove_managed` and `gemini::managed_entry` do the same for `hooks.BeforeTool` in JSON.
  - A fresh file from either writer equals its §8.3 fixture semantically (same parsed value).
- Produces (`install.rs`):
  - `pub struct InstallOptions { pub config: Option<PathBuf>, pub agents: Vec<Agent>, pub approvers: Vec<String>, pub non_interactive: bool }`
  - `pub struct InstallReport { pub changed: Vec<String>, pub unchanged: Vec<String>, pub started: bool }`
  - `#[derive(thiserror::Error)] pub enum InstallError { NotRoot, Unsupported(String), Refused { path: PathBuf, detail: String }, Step { step: String, detail: String } }`
  - `pub fn install(layout: &Layout, host: &dyn Host, opts: &InstallOptions, binary: &Path) -> Result<InstallReport, InstallError>`
  - The steps, in order. Each is idempotent. Each one that creates something is recorded before the next step runs. `installed.toml` is rewritten after every step that created something, so a failure part-way leaves an accurate list.
    1. `layout.is_system() && host.euid() != 0` → `NotRoot`. Then `check_supported`.
    2. Refuse an existing `saiife` user with uid ≥ 1000, or a shell outside `/usr/sbin/nologin`, `/sbin/nologin`, `/bin/false`, `/usr/bin/false`. Refuse an existing `STATE_DIR`, `KEYS_DIR` or `AUDIT_KEY` that is not owned by the `saiife` uid or has the wrong mode (0700 dirs, 0600 file). Never adopt them.
    3. Groups `saiife` and `saiife-audit`, then user `saiife` (primary group `saiife`), then `add_to_group(saiife, saiife-audit)`.
    4. `/opt/saiife`, `/opt/saiife/bin`, then the binary: copy `binary` to a temp file in `BIN_DIR`, chmod 0755, rename. Skipped when the sha256 is the same.
    5. `/etc/saiife` 0755 and `policy.d` 0755. Then `config.toml` 0644:
       - `--config <file>` is validated with `load_and_check` and must say `locked = true`, else `Refused`. It replaces the current file.
       - Without `--config`, an existing file is kept, and a missing one gets `default_config(..)`.
    6. `credstore` 0700 root:root. `vault-key` only if missing, never rotated:
       - `Credential`: 32 bytes from `getrandom`, encrypted with `encrypt_credential("vault-key", ..)`, root:root 0600;
       - `File`: the 32 raw bytes, written `O_EXCL`, root:saiife 0640.
       - The plain bytes live in a `Zeroizing` buffer.
    7. The unit, 0644.
    8. Managed files for `opts.agents`:
       - Claude: dir `CLAUDE_MANAGED_DIR` 0755, file 0644 = `managed_settings()`;
       - Codex and Gemini: dir 0755, then `install_managed`, then file 0644 root:root.
       - Agents installed before but not named now are left as they are: install only adds.
    9. `systemctl daemon-reload`. If the unit or the binary changed while the service is active: `systemctl restart saiifed.service`; else `systemctl enable --now saiifed.service`. A non-zero status → `Step { step: "start", detail: <stderr> + " (see: journalctl -u saiifed)" }`.
    10. `layout.is_system()`: wait at most 10 s for `SOCKET` to exist, else `Step`.
  - Every chown goes through `host.chown` with ids from `host.user`/`host.group_id`. Modes are set with `fchmod` on the opened file or dir, never by path after the fact.
- Produces (`default_config.rs`):
  - `pub fn default_config(layout: &Layout, approvers: &[String]) -> String`.
  - It starts `version = 2\nlocked = true\n`, then every other §8.1 key as a comment holding its default.
  - With approvers, it writes an uncommented `[approval]\napprovers = [..]`.
  - Under a non-system layout it also writes uncommented `[daemon] socket_dir`, `[audit] dir` (both under the root) and `user = "<own user>"`, so tests never point at the real `/run` or `/var`.
  - The result passes `load_system`.
- Produces (`uninstall.rs`):
  - `pub struct UninstallOptions { pub purge: bool }`
  - `pub fn uninstall(layout: &Layout, host: &dyn Host, opts: &UninstallOptions) -> Result<Vec<String> /* removed */, InstallError>`
  - Steps:
    1. No `installed.toml` → `Ok(vec![])`.
    2. `systemctl disable --now saiifed.service` (a failure is a warning).
    3. Managed agents: a whole file is removed even if changed (say `changed since install`); an entry goes through `remove_managed`, and the file is deleted only if `created_file` and nothing else is left.
    4. Then the unit, `daemon-reload`, the binary, and listed dirs under `/opt` if empty.
  - Kept unless `--purge`: `/etc/saiife` (config, policy.d, credstore), the state dir, the audit, and the users and groups. Without `--purge`, `installed.toml` is removed last.
  - `--purge` also removes those, in reverse creation order, and deletes only the users and groups in `installed.users`/`groups`.
  - Listed paths that are gone are skipped. Unlisted paths are never touched.
- Produces (cli):
  - `saiife system install [--config <file>] [--agents claude,codex,gemini] [--approvers <list>] [--non-interactive] [--root <dir> (hidden)]`.
  - `saiife system uninstall [--keep-audit | --purge] [--root <dir> (hidden)]`. `--keep-audit` is the default, and it conflicts with `--purge`.
  - `--agents` defaults to all three.
  - Exit codes:
    - `NotRoot` → `saiife: system install needs root (run it with sudo)`, exit 2;
    - `Unsupported(why)` → `refusal_line(why)`, exit 2;
    - other errors → `saiife: install failed at <step>: <detail>`, exit 2;
    - success → exit 0. Task 8 adds the doctor run.

- [ ] **Step 1: Failing tests.**
  - `managed_fixtures.rs`:
    - `claude_managed_settings_is_fixture` (bytes equal);
    - `codex_fresh_file_matches_fixture` and `gemini_fresh_file_matches_fixture` (parsed equal);
    - `codex_requirements_keeps_admin_entries`: a file with `[features]\nweb_search = true\n` plus another `[[hooks.PreToolUse]]` → after install both remain, saiife's group is appended, and `hooks = true` is set. `remove_managed` gives back the original keys.
    - `gemini_settings_keeps_admin_entries` (same for JSON);
    - `install_managed_twice_is_unchanged`;
    - `is_saiife_command_accepts_managed_path`.
  - `install.rs` (`Layout::under(tmp)`, `FakeHost`, `<tmp>/etc/os-release` Ubuntu 24.04, `<tmp>/run/systemd/system`):
    - `fresh_install_writes_every_path_with_spec_modes`: every §5.2 path install creates exists with its mode (`stat`). The FakeHost chown log has root:root for every one of them. Install creates no state, run or log dir: systemd does that.
    - `systemd_249_writes_plain_vault_key_and_load_credential`: `vault-key` 0640, chowned to root:saiife, 32 bytes; the unit has `LoadCredential=`.
    - `systemd_255_encrypts_vault_key`: FakeHost `calls` holds `systemd-creds encrypt --name=vault-key`.
    - `installed_toml_lists_everything_with_fingerprints`: `files` hold the binary, unit and config; `agents` has 3 entries whose `sha256` equal `sha256(file)` (Claude) or `managed_entry(file)` (Codex/Gemini).
    - `second_install_is_unchanged_and_keeps_config`: an admin edit to `config.toml` survives; `report.changed` is empty; FakeHost has `enable --now`, not `restart`.
    - `binary_change_restarts`.
    - `config_flag_validated`: an unknown key → `Refused`, nothing written under `/etc/saiife` (the users may exist).
    - `existing_human_saiife_user_refused` (FakeHost user `saiife` uid 1001, shell `/bin/bash`).
    - `existing_state_dir_wrong_mode_refused` (`<tmp>/var/lib/saiife` 0755).
    - `start_failure_still_writes_installed_and_exits_2`: canned `systemctl enable --now` status 1 → `Step { step: "start" }`; `installed.toml` lists the users, groups and files.
    - `unsupported_writes_nothing` (alpine os-release → `Unsupported`; `<tmp>` holds only `etc/os-release` and `.fakehost.json`).
  - `uninstall.rs`:
    - `uninstall_removes_exactly_what_install_listed`: after install + uninstall, the only paths left are `/etc/saiife/{config.toml,policy.d,credstore/vault-key}`, `.fakehost.json` and `etc/os-release`;
    - `purge_removes_all_and_created_users`;
    - `uninstall_keeps_preexisting_codex_file` (the admin's file existed before install → after uninstall it equals the original);
    - `uninstall_after_partial_install_is_clean` (listed paths deleted by hand → no error);
    - `uninstall_without_installed_is_noop`.
  - `crates/cli/tests/system_install.rs`:
    - `install_without_root_refused`: no `--root`, as the test user → exit 2, stderr `needs root`. Nothing runs, because the check comes before any step.
    - `install_and_uninstall_under_root_flag`: exit 0 both times.
    - `keep_audit_conflicts_with_purge`.
- [ ] **Step 2:** Run `cargo test -p saiife-agents -p saiife-system && cargo test -p saiife --test system_install`. The tests fail.
- [ ] **Step 3:** Implement. `fsops.rs` holds the helpers: `create_dir_mode`, `write_file_atomic(path, bytes, mode)`, `sha256_file`, `remove_if_listed`. Each opens with `O_NOFOLLOW` and refuses a symlink at a target path.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean.
- [ ] **Step 5:** Commit `feat(system): system install and uninstall (users, binary, /etc/saiife, unit, vault key, managed hooks, installed.toml)`.

### Task 5: Hook behaviour — `--event config-change`, `[guard.mcp]` deny, quiet project hooks, developer `fail = "closed"`  [wave 2, group E; needs Tasks 1 and 3]

**Files:**
- Create: `crates/cli/src/system_view.rs`, `crates/cli/tests/fixtures/claude/config-change.json`, `crates/cli/tests/fixtures/claude/mcp-tool.json`
- Modify: `crates/cli/src/main.rs` (`Check` flags), `crates/cli/src/check.rs`, `crates/cli/src/check_managed.rs`, `crates/cli/src/eval.rs`
- Test: `crates/cli/tests/check_managed.rs`, `crates/cli/tests/check_project.rs`, `eval.rs` units

**Interfaces:**
- Consumes: Task 1 `read_installed`, `Installed::has_managed`; Task 3 `EvalRequest.locked`.
- Produces (`main.rs`):
  - `Check` gains `#[arg(long, value_parser = ["config-change"], requires = "managed")] event: Option<String>`.
  - `--system-config` loses `requires = "managed"` and stays hidden: the developer path uses it as its `/etc` override in tests.
- Produces (`eval.rs`):
  - `EvalRequest` gains `#[serde(default)] pub event: Option<String>`.
  - `pub const LOCKED_SETTINGS_KEYS: [&str; 5] = ["hooks", "disableAllHooks", "permissions", "env", "apiKeyHelper"];`
  - `pub fn judge_config_change(payload: &str) -> EvalAnswer`. It reads `source` and `file_path`; `tool` = `"ConfigChange"`; `input` = `"<source> <file_path>"`.
    - `source == "policy_settings"` → `Allow`, reason `managed settings changed`.
    - Otherwise `file_path` must be absolute. It is opened `O_NONBLOCK`, must be a regular file of at most 1 MiB, and is parsed as JSON.
    - Missing → `Allow`, reason `settings file removed`.
    - Unreadable or unparsable → `Deny`, pack `core.self`, rule `config-change`, reason `settings change could not be checked: <why>`.
    - A top-level key from `LOCKED_SETTINGS_KEYS` present → `Deny`, pack `core.self`, rule `config-change`, reason `settings change touches <key> (hooks, disableAllHooks, permissions, env and apiKeyHelper are locked during a session)`.
    - Else `Allow`.
  - `worker_main` dispatches on `event`.
  - `pub enum McpCheck { NotMcp, Allowed, Denied(String) }`
  - `pub fn mcp_check(agent: &str, tool: &str, allow: &[String]) -> McpCheck`:
    - `claude`/`codex`: `mcp__<server>__…`; the server is the text up to the next `__`;
    - `gemini`: `mcp_…`, allowed iff `tool` starts with `mcp_<s>_` for a listed `s`;
    - other agents: both forms.
    - `Denied` carries the server, or the whole tool name when it is ambiguous (Gemini).
- Produces (`check_managed.rs`):
  - `run(agent, system_config, event: Option<&str>)`.
  - Before spawning the worker: `mcp_check(agent, tool, &cfg.guard.mcp.allow_servers)`. `Denied(s)` → a `deny` record with pack `guard.mcp`, rule `mcp_server_not_allowed`, reason `MCP server <s> is not in [guard.mcp] allow_servers`; stderr `BLOCKED by guard.mcp: <reason>`; exit 2.
  - With `event = config-change`, the worker gets `event` and no packs are needed.
- Produces (`system_view.rs`, developer path only):
  - `pub struct SystemView { pub managed_agents: Vec<String>, pub fail_closed: bool }`
  - `pub fn read(config: &Path) -> SystemView`. `installed.toml` is the config's sibling. Read the config as a raw `toml::Table`, without the full loader.
  - `fail_closed` = `locked == true` or `[guard] fail == "closed"`, set explicitly.
  - A missing file reads as the v1 default. An invalid one → v1 default plus one stderr warning `saiife: warning: <path> ignored: <error>`.
- Produces (`check.rs`): `run(packs, hook_exit, agent, system_config: Option<&Path>)`. The default is `/etc/saiife/config.toml`. `SystemView` is read once:
  - If `managed_agents` contains `agent`: drain stdin, capped at `PARSE_MAX_BYTES`, then exit 0 silently with no record (§6.1.1).
  - If `fail_closed`: every site that writes `error_allowed` today writes `error_denied` and answers deny instead. With `--hook-exit`: exit 2 + `saiife: BLOCKED (fail closed): <reason>`. Without it: the JSON deny payload.

- [ ] **Step 1: Failing tests.**
  - `eval.rs`:
    - `config_change_with_hooks_key_denied`: a temp settings file `{"hooks":{}}` with source `user_settings`;
    - `config_change_harmless_allowed` (`{"theme":"dark"}`);
    - `config_change_policy_settings_allowed`;
    - `config_change_unparsable_denied`;
    - `config_change_fifo_denied_quickly` (under 1 s);
    - `config_change_relative_path_denied`;
    - `mcp_check_claude` (`mcp__linear__create` with `["linear"]` → `Allowed`; `mcp__other__x` → `Denied("other")`; `Bash` → `NotMcp`);
    - `mcp_check_gemini_prefix` (`mcp_linear_x` with `["linear"]` → `Allowed`);
    - `mcp_check_double_underscore_server_name`.
  - `check_managed.rs` (with `TestDaemon`):
    - `config_change_touching_hooks_denied_and_recorded`: exit 2, a record with tool `ConfigChange` and decision `deny`;
    - `config_change_harmless_allowed_and_recorded`;
    - `unlisted_mcp_server_denied`: the `codex/mcp-tool.json` and `claude/mcp-tool.json` fixtures → exit 2, stderr `BLOCKED by guard.mcp`, a record with rule `mcp_server_not_allowed`;
    - `listed_mcp_server_allowed_not_judged`: config `[guard.mcp] allow_servers = [<server>]` → exit 0, reason `tool not judged`;
    - `event_requires_managed`: `check --event config-change` without `--managed` → clap exit 2.
    - `worker_never_reading_stdin_denies` becomes robust: assert exit 2 and a record `error_denied` whose reason starts `guard worker failed`, with `elapsed >= 3000 ms && elapsed < 7000 ms` (the parent watchdog), instead of the 4.5 s ceiling.
  - `check_project.rs` (developer path, `--system-config <tmp>/etc/saiife/config.toml`):
    - `project_hook_quiet_when_agent_managed`: `installed.toml` lists `claude` → `bash-deny.json` gives exit 0, empty stdout and stderr, and no record in `SAIIFE_AUDIT_DIR`;
    - `project_hook_works_for_unmanaged_agent`: only `codex` is managed → the Claude hook denies as v1;
    - `developer_fail_closed_opt_in`: config `version = 2\n[guard]\nfail = "closed"\n` plus `malformed/not-json.txt` with `--hook-exit` → exit 2, stderr `fail closed`, record `error_denied`;
    - `developer_default_still_fails_open` (no `/etc` file → `error_allowed`, exit 0);
    - `invalid_system_config_fails_open_with_warning`.
- [ ] **Step 2:** `cargo test -p saiife --test check_managed --test check_project && cargo test -p saiife eval` fails.
- [ ] **Step 3:** Implement. The developer path imports only `system_view` (toml + `saiife_policy::installed`), never the full policy loader.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean. `scripts/bench-check.sh 50` on `main` and on the branch: the developer median is within +1 ms. `scripts/bench-check.sh --managed 50`: p95 < 40 ms.
- [ ] **Step 5:** Commit `feat(check): config-change event, [guard.mcp] deny, quiet project hooks under managed ones, developer fail-closed opt-in`.

### Task 6: `saiife doctor` — framework and system checks  [wave 2, group F; needs Task 1]

**Files:**
- Create: `crates/system/src/doctor/{mod.rs, report.rs, system.rs}`, `crates/system/src/testing.rs`; modify `crates/system/src/lib.rs`
- Create: `crates/cli/src/doctor_cmd.rs`; modify `crates/cli/src/main.rs` (`Doctor { #[arg(long)] user: Option<String>, #[arg(long)] json: bool, #[arg(long, hide = true)] root: Option<PathBuf> }`)
- Test: unit tests in `system.rs` and `report.rs`; `crates/cli/tests/doctor.rs`

**Interfaces:**
- Consumes: Task 1 (`Layout`, `Host`, `check_supported`, `read_installed`, `LockLabel`/`label`); 9a `load_and_check`, `Getent`, `Directory`, `Client::connect`, `system_uid`, `OP_STATUS`.
- Produces (`report.rs`):
  - `pub enum Status { Pass, Warn, Fail, Info }` (serde lowercase)
  - `pub struct Check { pub id: String, pub status: Status, pub title: String, pub detail: String }`
  - `pub struct Report { pub checks: Vec<Check> }` with:
    - `exit_code(&self) -> u8`: 2 if any `Fail`, else 1 if any `Warn`, else 0; `Info` never counts;
    - `to_json(&self) -> serde_json::Value` = `{"saiife_doctor":1,"exit":<n>,"checks":[{"id","status","title","detail"}]}`;
    - `to_text(&self) -> String`: one line per check, `PASS|WARN|FAIL|INFO  <id>  <title>` and, if the detail is non-empty, `: <detail>`. The last line is `doctor: <n> failures, <m> warnings`.
- Produces (`mod.rs`):
  - `pub struct DoctorOptions { pub user: Option<String> }`
  - `pub struct Ctx<'a> { pub layout: &'a Layout, pub host: &'a dyn Host, pub dir: &'a dyn Directory, pub installed: Option<Installed>, pub config: Result<LoadedPolicy, String>, pub as_root: bool, pub opts: &'a DoctorOptions }`
  - `pub fn run(layout: &Layout, host: &dyn Host, dir: &dyn Directory, opts: &DoctorOptions) -> Report`. It builds the `Ctx`, then `system::checks(&ctx)` and, from Task 7, `host::checks(&ctx)`.
- Checks in `system.rs`. Each id is fixed; the status follows in parentheses.
  - `system.supported`: Fail when refused (decision 8).
  - `install.record`: when `installed.toml` is missing, one `Info` `locked mode is not installed: developer mode checks only`, and the locked checks below are skipped.
  - `config.valid`: Fail on a load or scope error (decision 6). Detail `<error>. Every managed hook call is denied, and nothing is recorded`.
  - `paths.owner` (§5.6 item 2): every directory from `/` down to `BINARY`, plus `/etc/saiife`, `config.toml`, every `policy.d/*.toml`, `installed.toml` and `credstore`, is owned by root (`host.user("root")`) and not group- or world-writable (Fail). Each offender is named.
  - `files.installed`: every `installed.files` and `installed.agents` entry exists and its sha256 matches (Fail, naming the path and `changed since install` or `missing`).
  - `files.modes`: the §5.2 owner:group and mode of `STATE_DIR`, `KEYS_DIR`, `AUDIT_KEY`, the audit dir (`2750`, group `saiife-audit`), `RUN_DIR`, `SOCKET` (0666), `vault-key` (by `installed.vault_key`), and the unit (Fail). A path the caller cannot `lstat` (non-root) → `Info` `not checked (run as root)`.
  - `keys` (the 9a follow-up): `KEYS_DIR` is a real dir, owned by the daemon user, mode 0700; `AUDIT_KEY` is a regular file, owned by the daemon user, mode 0600, 32 bytes (Fail).
  - `daemon.unit`: `systemctl is-active saiifed.service` prints `active` (Fail otherwise).
  - `daemon.health`: `Client::connect(socket_dir, system_uid(daemon user), now + 2 s)`, then `status`.
    - Pass detail: `chain <id>, head seq <n>, last checkpoint seq <m>`.
    - Fail on any `ClientError`, with the error text.
    - Fail when `policy_ok` is false: `policy not loaded: connector calls are denied`.
  - `agents.<name>.label`, for each managed agent: Pass when `Lockable`, else Warn with `wording()`.
  - `mcp.<server>` (decision 10): Warn, one per `allow_servers` entry, title `MCP server <s> bypasses saiife: its requests are not brokered or limited`.
  - `vault.key` (Info): `encrypted systemd credential` or `plain key file (systemd < 250)`, from `installed.vault_key`.
  - `peer.pidfd` (Info): `SO_PEERPIDFD available` when uname's release is ≥ 6.5, else `SO_PEERCRED only`.
  - `reauth` and `forwarding` (Info): `not configured` (plans 11 and 12).
- Produces (cli): `saiife doctor [--user <name>] [--json] [--root <dir>]`. It prints `to_text` or `to_json` and exits with `exit_code`. `--user` other than oneself needs root: else exit 2, `saiife: --user <name> needs root`.

- [ ] **Step 1: Failing tests** (`Layout::under(tmp)`, `FakeHost`, after `install()` from Task 4 when it exists. Until then, build the tree with `pub fn saiife_system::testing::fake_install(root: &Path) -> Installed` (`#[doc(hidden)]`). It writes the §5.2 files and dirs with their modes, including the state, keys and audit dirs systemd would make, plus an `installed.toml`. Keep the helper either way: Task 8's cli tests use it, and this task does not depend on Task 4.)
  - `report.rs`: `exit_code_rules` (Info only → 0; one Warn → 1; Warn + Fail → 2); `json_shape`.
  - `system.rs`:
    - `fake_install_fails_only_daemon_checks`: the only Fail checks are `daemon.unit` and `daemon.health`, because no daemon runs. Assert per check, not the exit code.
    - `invalid_config_fails_and_says_no_records` (detail contains `nothing is recorded`);
    - `group_writable_etc_fails` (`/etc/saiife` 0775 → `paths.owner` Fail naming it);
    - `ancestor_owned_by_other_uid_fails` (FakeHost maps `root` to `getuid()+1`);
    - `changed_managed_file_fails`;
    - `missing_unit_fails`;
    - `key_dir_0750_fails`;
    - `key_file_wrong_size_fails`;
    - `unverified_agent_warns` (codex managed → Warn `unverified`);
    - `mcp_server_warns_with_exact_text`;
    - `not_installed_is_info_only` (with no `installed.toml`, the only locked-mode line is `install.record` Info);
    - `vault_key_mode_reported`.
  - `crates/cli/tests/doctor.rs`:
    - `doctor_json_exit_matches_report`;
    - `doctor_sees_running_daemon`: write `<root>/etc/saiife/config.toml` = `TestDaemon::config_text` → `daemon.health` Pass with `head seq`;
    - `doctor_user_other_than_self_needs_root`.
- [ ] **Step 2:** `cargo test -p saiife-system doctor && cargo test -p saiife --test doctor` fails.
- [ ] **Step 3:** Implement. `systemctl` runs through `host.systemctl` and every other program through `host.run(.., 5 s)`. Doctor never execs a binary the agent user can write.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean.
- [ ] **Step 5:** Commit `feat(doctor): saiife doctor with install, file, key, daemon, label and MCP checks; --json; exit 0/1/2`.

### Task 7: `doctor` — per-user host preconditions and plaintext-secret scan  [wave 3, group G; needs Task 6]

**Files:**
- Create: `crates/system/src/doctor/{host.rs, secrets.rs}`; modify `crates/system/src/doctor/mod.rs` (one call)
- Modify: `crates/ipc/src/client.rs` (`entry_by_name`)
- Test: unit tests in `host.rs`/`secrets.rs`; `crates/cli/tests/doctor.rs`

**Interfaces:**
- Consumes: Task 6 `Ctx`, `Check`, `Status`; Task 1 `Host::run`, `LockLabel`; 9a `saiife_ipc::client::{uid_by_name, PasswdEntry}`, `saiife_policy::{Directory, Scope}`, `saiife_agents::integrity`.
- Produces (`ipc`): `pub fn entry_by_name(passwd: &str, name: &str) -> Option<PasswdEntry>`. `PasswdEntry` gains `home: PathBuf` if it lacks it.
- Produces (`host.rs`):
  - `pub struct AgentUser { pub name: String, pub uid: u32, pub home: PathBuf, pub in_passwd: bool }`
  - `pub fn agent_users(ctx: &Ctx) -> Vec<AgentUser>`. As root: the users of every `[[scope]]`, with `group:<g>` expanded through `Directory`, or only `--user`. Otherwise: the caller. Deduplicated and sorted.
  - `pub const ROOT_EQUIVALENT_GROUPS: [&str; 5] = ["docker", "lxd", "incus", "libvirt", "disk"];`
  - `pub const CLAUDE_MIN: (u32, u32, u32) = (2, 1, 295);`
  - `pub fn parse_agent_version(out: &str) -> Option<(u32, u32, u32)>` reads the first `N.N.N` in the output.
  - `pub fn checks(ctx: &Ctx) -> Vec<Check>`. Per user `<u>`, ids fixed:
    - `user.<u>.passwd` (the 9a follow-up, ruling 19): found by `Directory` but not in `<root>/etc/passwd` → Fail, `<u> is not in /etc/passwd (NSS-only): locked-mode hooks deny every call for this user`.
    - `user.<u>.root` (§5.6 item 1):
      - Fail when the user is in a `ROOT_EQUIVALENT_GROUPS` group (named);
      - as root, Fail when `/usr/bin/sudo -n -l -U <u>` lists a `NOPASSWD` rule;
      - as the user, Fail when `/usr/bin/sudo -n true` exits 0.
      - With sudo missing, the sudo half passes with detail `sudo not installed`.
    - `user.<u>.agent-binaries`: each agent binary found in the current `PATH` or in `~/.local/bin`, `~/.claude/local`, `~/.npm-global/bin` or `~/.bun/bin` of `<u>`. It is a Warn when the binary or its dir is owned by `<u>` or is group- or world-writable: `<path> is writable by <u>: the agent can patch itself and skip hooks (install agents system-wide)`.
    - `user.<u>.agent-version`, only when the caller is `<u>` and not root: `claude --version` via `host.run(.., 5 s)`. Below `CLAUDE_MIN` → Fail `Claude Code <v> is older than 2.1.295 (onFailure: "block")`. As root → Info `not checked as root (run saiife doctor as <u>)`.
    - `user.<u>.secrets`: one Warn per finding from `secrets::scan`, naming the path and what was found, never the value.
    - `user.<u>.model-login` (Info, decision 5): `local model` when `~/.claude/settings.json` `env.ANTHROPIC_BASE_URL` or a Codex `[model_providers.*] base_url` points to `localhost`, `127.0.0.1` or `::1`; else `the agent holds its own model-provider login (not brokered in v2)`.
    - `user.<u>.leftover-hooks` (§12): Warn listing the project roots whose integrity record (in `<home>/.local/share/saiife`) holds a hook for a managed agent: `run saiife init --off in <project>`.
  - Once per host:
    - `proc.hidepid`: Warn when `/proc/mounts` (`<root>/proc/mounts` under a test root) mounts `proc` with `hidepid=1`, `2`, `invisible` or `noaccess` (§5.6);
    - `secrets.none`: Info `no plaintext credentials found` when no user has a finding.
- Produces (`secrets.rs`):
  - `pub struct Finding { pub path: PathBuf, pub what: String }`
  - `pub const HOME_PATHS: [&str; 11] = [".aws/credentials", ".config/gcloud", ".azure", ".kube/config", ".docker/config.json", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".config/gh/hosts.yml", ".vault-token"];`
  - `pub fn scan(home: &Path, project_roots: &[PathBuf]) -> Vec<Finding>`:
    - Each file is opened `O_NOFOLLOW | O_NONBLOCK`, must be regular, is read to at most 1 MiB, and is never followed through a symlink.
    - Dirs (`.config/gcloud`, `.azure`) are found when they are non-empty.
    - `.npmrc` counts when it holds `_authToken` or `_auth`; `.pypirc` and `.netrc` when they hold `password`; `.docker/config.json` when it holds a non-empty `auth`; the rest when non-empty.
    - `.env*` files under each project root count, walked depth ≤ 4, at most 10 000 entries, never following symlinks. A project root is a scope's `projects` glob up to its first wildcard.
    - MCP configs (`~/.claude.json` `mcpServers.*.env`/`headers`, `~/.codex/config.toml` `[mcp_servers.*.env]`, `~/.gemini/settings.json` `mcpServers.*.env`/`headers`): every non-empty value whose key contains `TOKEN`, `KEY`, `SECRET`, `PASSWORD` or `AUTHORIZATION` (case-insensitive) → `MCP server <s> holds a credential in <key>`.

- [ ] **Step 1: Failing tests.**
  - `host.rs`, with `FixedDirectory`, a `<root>/etc/passwd`, and FakeHost canned `sudo` outputs:
    - `nss_only_user_fails`;
    - `docker_group_member_fails`;
    - `nopasswd_rule_fails` (canned `sudo -n -l -U agent` output with `(ALL) NOPASSWD: ALL`);
    - `password_sudo_passes`;
    - `user_writable_agent_binary_warns`;
    - `claude_version_gate` (`2.1.294 (Claude Code)` → Fail; `2.1.308 (Claude Code)` → Pass);
    - `hidepid_warns` (`proc /proc proc rw,hidepid=invisible 0 0`);
    - `scope_group_users_expanded`;
    - `local_model_detected`;
    - `leftover_project_hook_listed`.
  - `secrets.rs`:
    - `finds_each_home_path_without_values`: the finding text never contains the planted value `s3cr3t-VALUE`;
    - `npmrc_without_token_not_reported`;
    - `env_files_under_project_found`;
    - `mcp_token_found_by_key_name`;
    - `secret_scan_never_follows_symlinks_or_blocks`: `~/.npmrc` is a symlink to a file holding `_authToken`, `~/.netrc` is a FIFO, and `~/.git-credentials` is a 2 GiB sparse file → no symlink finding, the scan returns within 1 s, and at most 1 MiB is read (checked through a test counter).
  - `crates/cli/tests/doctor.rs`: `doctor_as_user_checks_self` (HOME pointed at a tempdir with a `.netrc` holding a password → Warn naming the path; stdout lacks the password).
- [ ] **Step 2:** `cargo test -p saiife-system doctor && cargo test -p saiife --test doctor` fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean.
- [ ] **Step 5:** Commit `feat(doctor): host preconditions per agent user, NSS check, agent binaries and versions, plaintext-secret scan`.

### Task 8: Locked `status` / `init`, install runs `doctor`, the `locked-linux` CI job  [wave 3, group H; needs Tasks 4, 5 and 6]

**Files:**
- Modify: `crates/cli/src/status_cmd.rs`, `crates/cli/src/init_cmd.rs`, `crates/cli/src/system_cmd.rs` (doctor at the end), `crates/cli/src/main.rs` (hidden `--root` on `Status` and `Init`)
- Create: `scripts/locked-linux/run.sh`, `scripts/locked-linux/config.toml`, `scripts/locked-linux/lib.sh`
- Modify: `.github/workflows/ci.yml` (job `locked-linux`; the shellcheck line adds `scripts/locked-linux/*.sh`), `CHANGELOG.md` (`## Unreleased`), `docs/install.md` (a "Locked mode (Linux)" section: install, uninstall, doctor, supported systems, lock labels)
- Test: `crates/cli/tests/status_cmd.rs`, `crates/cli/tests/init_cmd.rs`, `crates/cli/tests/system_install.rs`

**Interfaces:**
- Consumes: Task 4 `install`/`uninstall`; Task 5 `SystemView`; Task 6 `doctor::run`, `Report`; Task 1 `label`.
- Produces (status): when `<root>/etc/saiife/installed.toml` exists, `status` prints a `Locked mode` block before the v1 checks:
  - `mode: locked (installed <installed_at>, saiife <version>)`
  - `daemon: running, chain <id>, head seq <n>, last checkpoint seq <m>`, or `daemon: not answering (<error>): every managed hook call is denied`
  - `policy: <hash>`, or `policy: invalid (<error>): every managed hook call is denied and nothing is recorded`
  - one line per managed agent: `agent <name>: managed hook, <label wording>`
  - one line per MCP server, the exact warning text.
  - Exit 1 when the daemon does not answer, the policy is invalid, or a managed file's fingerprint differs. Pending approvals and lockdown come in plan 11.
- Produces (init): in locked mode (`installed.toml` present):
  - `init` writes `.saiife/config.toml` as today (packs only). It writes no project hook for an agent with a managed hook, and prints `<agent>: managed hook installed by the admin; no project hook written`.
  - `init --off` removes the project hook entries of every agent and keeps `.saiife/config.toml`. It prints `managed hooks stay (remove them with: sudo saiife system uninstall)`.
- Produces (`system_cmd.rs`): after a successful install, run `doctor::run` and print its text. The exit is 0 when the doctor exit is 0 or 1, and 1 when it is 2, with the line `saiife: installed, but doctor found failures: fix them before relying on the lock`. Install errors stay exit 2.
- Produces (CI): job `locked-linux`:
  ```yaml
  locked-linux:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-22.04, ubuntu-24.04]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@b725eda525362e7cf34af9a7243cac1e3f01a7ec # stable
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2
      - run: cargo build --bin saiife
      - name: install, fail-closed matrix, uninstall (root, this job only)
        run: sudo env SAIIFE_LOCKED_CI=1 bash scripts/locked-linux/run.sh "$PWD/target/debug/saiife"
  ```
  This is a debug build, so the `SAIIFE_EVAL_FAULT` seam exists.
- `scripts/locked-linux/run.sh <binary>` (`set -euo pipefail`; the gate from Global Constraints first). The phases are functions in `lib.sh`; each prints `== <phase>` and fails the job on the first broken assertion.
  1. `useradd -m agent-ci`. Run `system install --config scripts/locked-linux/config.toml --agents claude,codex,gemini --non-interactive`. That config has `locked = true` and `[[scope]] name = "ci" users = ["agent-ci"]`. Expect exit 0 or 1. Then `systemctl is-active saiifed` → `active`.
  2. Check every §5.2 row with `stat -c '%U:%G %a'`: the installed paths, `/var/lib/saiife` `saiife:saiife 700`, `/var/log/saiife/audit` `saiife:saiife-audit 2750` (also after `systemctl restart saiifed`), `/run/saiife/saiife.sock` `saiife:saiife 666`. The vault key is `root:root 600` on systemd ≥ 250, `root:saiife 640` on 249, and the unit has the matching `LoadCredential*` line.
  3. As `agent-ci` (`sudo -u agent-ci`), with each fixture's `cwd` rewritten to agent-ci's home through `jq`:
     - `claude/bash-allow.json` → exit 0;
     - `claude/bash-deny.json`, `codex/bash-deny.json`, `gemini/shell-deny.json` → exit 2;
     - `codex/mcp-tool.json` → exit 2 `guard.mcp`;
     - a Write to `/etc/saiife/x` → exit 2 `core.lock`;
     - `SAIIFE_EVAL_FAULT=segv`, then `=hang` → exit 2;
     - `saiife audit verify` as root → exit 0.
  4. Fail-closed:
     - `systemctl stop saiifed`: the deny fixture and the allow fixture for each of the three agents → exit 2, stderr `fail closed`. Then `systemctl start saiifed`; the newest `daemon`/`start` has `previous_clean_stop` true.
     - `systemctl kill -s KILL saiifed`, wait for the restart, then `previous_clean_stop` is false.
     - Set `min_free_mb = 99999999` in `config.toml`, run `systemctl reload saiifed`, then the allow fixture → exit 2. Restore and reload.
  5. Attacks on the files, as `agent-ci`: writing `/etc/saiife/config.toml`, `/etc/claude-code/managed-settings.d/50-saiife.json` or `/opt/saiife/bin/saiife`, reading `/var/lib/saiife/keys/audit.ed25519`, and `kill` of the daemon pid all fail with a permission error.
  6. `saiife doctor --json` as root: the `daemon.health`, `files.installed`, `keys`, `paths.owner` and `user.agent-ci.root` checks pass.
  7. Run `system install` a second time: exit 0, no `restart` in the journal. Then `system uninstall`. Every path in the saved copy of `installed.toml` is gone, except the kept ones (`/etc/saiife/config.toml`, `vault-key`, `/var/lib/saiife`, `/var/log/saiife`), and `systemctl status saiifed` says not found. Then `system uninstall --purge` after a reinstall: nothing under `/etc/saiife`, `/var/lib/saiife`, `/var/log/saiife` or `/opt/saiife`; `getent passwd saiife` is empty.

- [ ] **Step 1: Failing tests.**
  - `status_cmd.rs` (with `--root`, a `fake_install` tree, and the config's `socket_dir` pointing at a `TestDaemon`):
    - `status_shows_locked_block_and_labels` (`agent claude: managed hook, lockable`; `agent codex: managed hook, unverified`);
    - `status_reports_daemon_down` (exit 1, `every managed hook call is denied`);
    - `status_reports_invalid_system_config` (exit 1, `nothing is recorded`);
    - `status_prints_mcp_warning`.
  - `init_cmd.rs`:
    - `locked_init_writes_no_hook_for_managed_agent` (no `.claude/settings.json` hook, config written);
    - `locked_init_off_removes_leftover_project_hooks_keeps_config`.
  - `system_install.rs`: `install_under_root_runs_doctor` (stdout holds `doctor:`; exit 1 because `daemon.health` fails under FakeHost; no line `install failed`).
- [ ] **Step 2:** `cargo test -p saiife --test status_cmd --test init_cmd --test system_install` fails.
- [ ] **Step 3:** Implement. Write the CI job and the scripts. `shellcheck scripts/locked-linux/*.sh` clean. Running `bash scripts/locked-linux/run.sh x` as the developer prints the refusal and exits 2. That is the only local run of the script.
- [ ] **Step 4: Verify.**
  - `cargo test --workspace` and clippy clean.
  - `scripts/bench-check.sh 50` against `main`: developer median within +1 ms.
  - Push the branch. Green CI includes `locked-linux (ubuntu-22.04)` and `locked-linux (ubuntu-24.04)`.
  - Put the bench numbers and the two systemd versions the jobs printed in the PR.
- [ ] **Step 5:** CHANGELOG `## Unreleased`:
  - `saiife system install`/`uninstall` (Ubuntu 22.04+, Debian 12+, RHEL 9+; systemd);
  - `saiife doctor`;
  - the `core.lock` pack;
  - `check --event config-change`;
  - the `[guard.mcp]` deny;
  - project hooks go quiet under managed hooks;
  - developer `fail = "closed"` opt-in;
  - lock labels: Claude Code lockable; Codex and Gemini CLI unverified.
- [ ] **Step 6:** Commit `feat(system): locked status and init, install runs doctor, locked-linux CI job on ubuntu 22.04 and 24.04`.

---

## Open questions settled in this plan

1. **Lock label wording.** §6.16 says "locked / locked with caveats / not lockable", while the plan 7 harness and `docs/lock-check.md` use `lockable`, `lockable-with-gaps`, `lockable-with-caveats`, `not-lockable` and `unverified`. This plan uses the plan 7 ids and wording, the ones the recorded fixtures carry. Codex and Gemini CLI have no recording and are `unverified`: they still get managed hooks (decision 9), `doctor` warns and `status` shows the label.
2. **Uninstall flags.** §7 has `[--keep-audit]` plus "kept unless `--purge`". The default keeps the audit, the state, the vault key, `/etc/saiife` and the users and groups. `--keep-audit` is accepted as that default and conflicts with `--purge`. `--purge` removes everything install made.
3. **The audit dir group.** systemd's `LogsDirectory=` gives the dir to the unit's `Group=saiife` on each start, but §5.2 says `saiife:saiife-audit`. The unit stays verbatim. Install adds `saiife` to `saiife-audit`, the daemon re-groups the dir and its files at start (Task 2), and CI checks the result after a restart.
4. **The unit for systemd < 250.** It is the §5.4.1 text with the `LoadCredentialEncrypted=` line swapped for `LoadCredential=vault-key:/etc/saiife/credstore/vault-key` and the `# systemd < 250` comment dropped.
5. **`/etc/saiife/credstore`** has no mode in the spec: root:root 0700. systemd reads the credential as root, and the vault-key modes stay verbatim.
6. **The vault key is created in 9b,** although the vault comes in plan 10: the unit names the credential, and systemd will not start the unit without it. It is never rotated by a reinstall.
7. **The ConfigChange payload has no diff.** The hook judges the changed file as it is now. A change from `user_settings`, `project_settings` or `local_settings` is denied when that file holds any of the five locked keys at the top level, or cannot be read. `policy_settings` is allowed. Cost: a mid-session edit to a settings file that already holds `permissions` is denied and applies at the next session. The field names `source` and `file_path` follow Claude Code's hook docs and are confirmed by the plan 9c live run.
8. **Developer `fail = "closed"` (§11)** is read from `/etc/saiife/config.toml`: an explicit `[guard] fail = "closed"`, or `locked = true` (which forces closed, §8.1). A missing file means v1 behaviour. An invalid file means v1 plus a warning.
9. **MCP names on Gemini** (`mcp_<server>_<tool>`) are ambiguous when server names contain `_`. A tool is allowed when it starts with `mcp_<listed>_`. Cost: on Gemini, an unlisted server named `<listed>_x` passes. Gemini is `unverified` anyway.
10. **`system install --mcp-allow` and `--managed-hooks-only`** (§6.1.4, §8.3) are deferred to plan 12. They are not in the 9b outline, and the hook-level `[guard.mcp]` deny already enforces the list.
11. **NSS-only agent users** stay denied (9a ruling 19). `doctor` fails them, and no NSS crate is added.
12. **Install exit codes:**
    - 2: install error or unsupported system;
    - 1: installed, but `doctor` found a failure;
    - 0: otherwise.
    - `--agents` defaults to all three. Install only adds managed hooks; removing one takes `uninstall`.
13. **`/usr/local/bin/saiife`** (optional in §5.2) is not created: it could replace a v1 user install, and hooks never use it.
14. **Doctor never runs agent binaries as root,** because they may be user-writable. The version check runs only when a user checks themselves. Re-authentication and forwarding answer `not configured` (Info) until plans 11 and 12.
15. **Supported RHEL family:** `ID_LIKE` containing `rhel` with major ≥ 9 (Rocky, Alma) counts as RHEL 9+. systemd < 247 (no `LoadCredential`) is refused.
16. **`installed.toml` format** (the spec gives only its purpose): Task 1's `Installed`. It lists only what install created, with fingerprints for the binary, unit, config and managed files or entries.
17. **Deferred §11 and §7 items:** `saiife audit` reading through the daemon goes to plan 12 (§6.4.5). Pending approvals and lockdown in `status` go to plan 11.

### Task 9: `core.process` pack — broad process kills  [added 2026-10-22 by the owner; after Task 3, before the final review]

**Why:** during this plan's build a subagent ran `pkill -n` / `pkill -o`, which killed the owner's newest and oldest processes and crashed the machine. `saiife test` allowed both. No pack covers "kill everything / the session".

**Files:** `crates/guard/packs/core.process.toml` (new, `default_on = true`), `crates/guard/tests/corpus_process.rs` (new), `docs/packs/core.process.md` (new, examples checked by `docs_pages`), `crates/guard/src/builtins.rs` (register).

**Behaviour:** deny commands that signal processes without naming a specific target, judged on the effective command after wrapper peeling and with the same getopt/signal-word handling Task 3 built for pkill/killall:
- `pkill`/`pgrep`-kill with `-n`/`--newest` or `-o`/`--oldest` and no pattern; `pkill`/`killall` with only `-u`/`-U`/`-g`/`-G`/`-s`/`-P`/`-t` selectors and no pattern;
- `kill` with pid `-1` (all processes), `0`/`-0` (own process group), or `1` (init); `killall5`;
- `killall` with `-u <user>` and no name; `pkill .` / `pkill ''` / `pkill -f .` (pattern matching everything).
Allowed: `kill 12345`, `kill %1`, `pkill node`, `pkill -f 'npm run dev'`, `killall -HUP nginx`, `kill -l`, `pgrep -a node`.

**Steps:** failing corpus tests (deny and allow lists above, each behind `timeout`/`setsid`/`nice` wrappers too) → implement → `cargo test -p saiife-guard` (all corpora + docs_pages) → full workspace + clippy + fmt + darwin check → commit `feat(guard): core.process pack blocks broad process kills`.

**Safety (binding for implementer and reviewer):** never execute kill, pkill, killall, killall5, pgrep or any process-control tool; verify only through the engine (judges text) and man pages.
