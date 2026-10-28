# Plan 16 — Personal broker mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A developer with no root runs `saiife daemon --user`: the same daemon as locked mode, but running as the logged-in user. It serves `$XDG_RUNTIME_DIR/saiife/` to that uid only and keeps its vault key in the OS keychain (the freedesktop Secret Service on Linux, with a macOS Keychain backend that compiles and waits for the v2.1 daemon port). `saiife secret`, `saiife connect`, `saiife api`, `saiife run --secret` and `saiife policy reload` work against it in developer mode. Every page that mentions it says it is **not a security boundary**.

**Architecture:**
- A new tokio-free-at-the-API crate, `saiife-keychain`, holds:
  - a sync `Keychain` trait;
  - a `FakeKeychain`, plus a debug-only `DirKeychain` seam for end-to-end tests;
  - the Secret Service backend, written as logic over an `SsBus` seam with a zbus implementation. That implementation is tested against an in-process zbus p2p server, so no session bus is needed;
  - the macOS backend over `security-framework`.
- The daemon gains a `DaemonMode::Personal` branch. Personal mode:
  - reads the vault key from the keychain (one item; `vault.bin` stays the store);
  - refuses every peer whose uid is not its own;
  - binds a 0700 dir with 0600 sockets;
  - writes its own unsigned chain, with `mode = "personal"`;
  - treats its own user as admin and approver;
  - synthesizes a scope when the config names none.
- `saiife-system` gains the personal paths and the systemd `--user` unit and launchd plist text. The CLI gains one resolver that picks the locked daemon or the personal broker.
- The guard gains rules that turn the obvious key readers into clear denials (a mistake layer, not a boundary).

**Tech Stack:**
- Rust workspace.
- New dependencies, all pinned:
  - `zbus =5.19.0`: `default-features = false`, features `["tokio"]`; tests add `p2p`;
  - `security-framework =3.7.0`, already in Cargo.lock; macOS only;
  - `tokio =1.53.2` with `rt`, the version the daemon pins.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §15.2 row 16 and decision 7;
- §1.1 (the Personal broker row);
- §5.5 (the per-user daemon row);
- §6.6 (the Personal broker bullet);
- §6.9.1 (project `allow` in personal broker mode);
- §6.10.2 (any approval from the same user);
- §6.11 (`env use` in personal mode; only the docs line here, because environments come with plan 14);
- §7 rows `daemon --system | --user` and `secret … (user, personal broker)`;
- §8.5 (`mode = "personal"`);
- §10, the Personal broker column;
- table D13.

Plans 11 and 12 set the style.

## Global Constraints

- **No privileged or process-control tools on the dev machine.** Never run sudo, root, systemctl (not even `systemctl --user`), launchctl, polkit tools, docker, kill, pkill, killall or pgrep. This holds for implementers and reviewers. Tests check only the generated unit and plist text. CI-only scripts (the new `scripts/personal-broker/ss-smoke.sh`) are validated locally with `bash -n` only. Shellcheck is fine if it is installed; never run it through docker.
- **Test isolation:**
  - Set `TMPDIR` and `SAIIFE_TEST_TMP` to a short dir made by `mktemp -d -p /home/jonas/projects/personal/saiife`, and remove it afterwards.
  - Every personal-mode test sets `XDG_RUNTIME_DIR` (a 0700 dir), `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME` and `HOME` inside that dir.
  - Never use /tmp, the real home, `~/.claude`, the real session bus or the real keychain.
  - No internet: connectors go to loopback mocks with `rcgen` certificates.
  - The personal harness (Task 5) sets `DBUS_SESSION_BUS_ADDRESS=unix:path=<test dir>/no-bus`, which is a dead path. A test that forgets `SAIIFE_TEST_KEYCHAIN` then fails with "no session bus" and never reaches the desktop keyring.
- **Internet:** implementers may use the web only to fetch public reference data (crate release dates, the Secret Service and Keychain API docs). Tests never use the network.
- **Test seams** that an integration test drives through the CLI binary are gated by `debug_assertions`, never `cfg(test)`. This covers `SAIIFE_TEST_KEYCHAIN` and `--locked-marker`.
- **Hook path untouched:** `guard`, `audit`, `policy`, `ipc` and `system` stay tokio-free. The CI tokio gate is unchanged, and `saiife-keychain` is not on the hook path. The developer hook (`saiife check`) does not talk to the broker.
- **Dependencies:**
  - Every crate this plan adds to Cargo.lock must have a release older than 14 days (cut-off 2026-10-14).
  - zbus 6.0.0 (2026-10-16) and 6.1.0 (2026-10-23) are too new. Use `=5.19.0` (2026-08-09).
  - After adding it, list the new lock entries with `git diff Cargo.lock | grep -A1 '^+name'`. Check each one's date on crates.io, and step any too-new one back with `cargo update -p <crate> --precise <older>`.
  - No crate that needs a C library: the release binary is static musl, so no `dbus`/libdbus and no `openssl`.
- **Commits:**
  - The branch is `plan-16-personal-broker` from `main`.
  - Each task is committed in its worktree and cherry-picked onto the plan branch, with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Never commit `.superpowers/`.
  - Never commit token-shaped literals. Build fake tokens at runtime with `concat!`.
  - `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`.
  - No tags.
- **Spec values, verbatim:**
  - `saiife daemon --system | --user`. `--user` is personal broker mode (`$XDG_RUNTIME_DIR/saiife/`).
  - Record `mode` ∈ `developer`, `personal`, `locked`.
  - §10, Personal broker column. Use these labels:
    - mistake: "same as developer";
    - helpful bypass: "partly";
    - brokered credential: "**partly**: key is in the keychain; a same-user script can read it (Linux)";
    - external service beyond rules: "partly (no boundary; workflow only)";
    - audit erase: "same";
    - every other row: "not covered".
  - §1.1 wording: "trying connectors on your own machine; **not a security boundary**".
  - §6.6 wording: "any process of the same user can read these on Linux, and on macOS after one click the user may give".
  - §6.10.2 wording: "Personal broker mode … allows any approval from the same user. The docs say this is a workflow aid, not a control."
  - The §10 wording rule, verbatim: "the agent never holds a credential for a brokered service; it holds its own model-provider login unless you run a local model".
  - §6.4.4: no signing key in a mode where the key would sit in the user's own home ("a key in the user's own home proves nothing").
- **Decisions this plan makes** (the spec is silent or open; each is restated in its task):
  1. **One keychain item holds the vault key; `vault.bin` stays the store.**
     - The item is a 32-byte key, with service `saiife` and account `vault-key`. On Secret Service its attributes are `application=saiife`, `saiife-item=vault-key`.
     - Secrets stay in the §8.9 file at `<state>/vault/vault.bin`, sealed under that key.
     - Why:
       - plan 11 seals approval bodies and results with the vault key, so a key is needed anyway;
       - one item means one unlock prompt and one macOS access list;
       - the vault code (atomic writes, `last_used`, `allowed_services`, metadata) is reused unchanged;
       - §10 already says "key is in the keychain";
       - reading one item of the same user's keychain is the same effort as reading all of them, so the protection is equal.
     - This departs from the §6.6 wording "each secret is one item". Task 8 adds a note to §6.6, and the owner confirms it (Owner handwork).
  2. **Paths:**
     - sockets: `$XDG_RUNTIME_DIR/saiife/`, dir 0700, `saiife.sock` and `gateway.sock` 0600;
     - config: `$XDG_CONFIG_HOME/saiife/broker/config.toml`, with `policy.d/`, `connectors/` and `ca/` beside it;
     - state: `$XDG_STATE_HOME/saiife/broker/`, 0700 (vault, approvals, grants, tokens, lockdown, import-backup unused);
     - audit: `$XDG_DATA_HOME/saiife/broker/audit/`, kept separate from the developer hook's `<data>/saiife/audit`. The `ChainWriter` holds the chain flock for its whole life, which would push every developer hook record off the chain.
     - The XDG fallbacks follow the XDG spec: `~/.config`, `~/.local/state` and `~/.local/share`. Relative values are ignored.
     - `XDG_RUNTIME_DIR` is required. It must be absolute, a real dir (no symlink), owned by the euid and mode 0700. Anything else refuses the start.
  3. **The peer check is same uid only.** Root is refused too. The control and gateway connections close before the hello when `peer.uid != own_uid`. The 0700 dir already keeps other non-root uids out, so this is the second layer.
  4. **Audit:** the broker writes its own chain with `WriterOptions { mode: "personal", key: None }`, so there are no signed checkpoints (§6.4.4). The daemon's writer stamps `mode` on every record it writes, which covers connector records the broker pipeline labels `developer`. `saiife audit --broker` and `saiife audit verify --broker` read that dir.
  5. **Config:** the §8.1 format.
     - `saiife daemon --user` creates a minimal one (`version = 2` plus comments, 0600) when it is missing.
     - `locked = true` refuses the start.
     - `[daemon]`, `[admin]` and `[audit] dir` are ignored with one warning each, because the paths above are fixed.
     - No `[[scope]]` gives an implicit scope `personal` for the own user, listing every configured service. Given scopes are used as written, with a warning if none names the own user.
     - Local connectors and `ca/` must be owned by the own uid, not root.
  6. **Roles:** the own uid is admin and approver. Same-user approvals need no re-authentication (§6.10.2).
     - `secret import` is refused in personal mode with `personal broker: use secret add`. It is not supported with a backup in the personal state dir, for two reasons:
       - Import moves plaintext out of reach of the agent's uid. Here the vault key is readable by that same uid, so the move protects nothing, and §10 would overstate it.
       - The 7-day backup exists because an admin edits another user's files. In personal mode it would be a second plaintext copy in the user's own home.
     - This gets a spec note.
  7. **Policy mode:** the daemon decides with `saiife_policy::Mode::Developer`, so project overlays may `allow` (§6.9.1). This applies at both places the daemon builds a `PolicySnapshot`: `PolicyState::from_loaded` in ops.rs and `no_policy_snapshot` in api_ops.rs. Records still say `personal` (decision 4). No new policy `Mode` variant, which keeps `policy` and `broker` untouched for plan 14.
  8. **Secret Service via zbus `=5.19.0`, `plain` session.** The bus is the user's own, so DH session encryption adds dependencies and no protection.
     - zbus runs on a current-thread tokio runtime inside the backend, created per call. The daemon calls the keychain only in `start`, before its own runtime exists. A nested `block_on` would panic, so the backend asserts `tokio::runtime::Handle::try_current().is_err()`.
     - A locked collection prompts through `Prompt.Prompt("")` with a 120 s wait. A dismissed prompt is `KeychainError::Locked`.
  9. **macOS:** the `MacKeychain` generic password is created by the saiife binary, so the default access list names that binary (§6.6 "access list").
     - It compiles and is checked on the macOS CI runner. It is not run there.
     - `saiife daemon --user` on macOS refuses with `saiife: the personal broker needs Linux in this version (macOS: with the v2.1 daemon port)`. Plan 13 ports the daemon to macOS; this backend is ready for it.
  10. **A locked host wins.**
      - `daemon --user` refuses when `/etc/saiife/installed.toml` exists. The test seam is a hidden debug-only `--locked-marker <path>`.
      - The CLI resolver prefers a locked config (`/etc/saiife/config.toml` with `locked = true`, or `--config`) and never falls back to the broker there.
  11. **Vault key lifecycle:**
      - neither a key nor `vault.bin`: create a random 32-byte key (`getrandom`) and store it;
      - a key: use it;
      - no key but a `vault.bin`: never re-key. The vault is `Unavailable("the vault key is missing from the keychain; <path> was kept")`;
      - keychain unavailable or locked: the vault is `Unavailable(<reason>)`, the daemon stays up for audit, and connectors fail closed. This is the existing `vault_unavailable` record.
  12. **Keeping the agent from the key, honestly:**
      - the key lives only in `Zeroizing` memory;
      - the daemon is non-dumpable (`PR_SET_DUMPABLE 0`, already in `start`), which blocks same-uid `ptrace` and `/proc/<pid>/mem`;
      - guard rules deny the obvious readers (Task 7).
      - Not prevented: a same-user script calling the Secret Service, or killing the broker and binding its socket. The docs say so.
  13. **Start at login:** `saiife daemon --user --print-unit systemd|launchd` prints the unit or the plist to stdout. It writes no file and runs no service manager. The docs give the commands to install it.
  14. **Test seam:** debug builds honour `SAIIFE_TEST_KEYCHAIN=<dir>`, which selects `DirKeychain`: one 0600 file per item in a 0700 dir. Release builds have no such seam. This is the same pattern as `SAIIFE_TEST_CA_OWNER`.
  15. **`CtxInit` defaults:** `CtxInit::minimal(…)` builds every optional field. Later plans add a field together with its default there, and every literal uses `..CtxInit::minimal(…)`. A `Default` derive is not possible, because `WriterHandle` and `Directory` have no default.
- **Spec notes** (Task 8 adds each one to the spec; the owner confirms them under Owner handwork):
  - §6.6: one keychain item holds the vault key, and the secrets stay in `vault.bin` under it (decision 1).
  - §6.6, §7: `saiife daemon --user` on macOS is refused until the plan 13 daemon port. The macOS Keychain backend is built and compile-checked (decision 9).
  - §7 `secret import`: refused in personal broker mode (decision 6).

## Seams this plan owns (plan 16 merges first; plans 14, 15 and 17 consume these)

- `crates/daemon/src/ops.rs`:
  - `pub enum Mode { Locked, Personal }` with `pub fn as_str(self) -> &'static str` (`"locked"` / `"personal"`). Inside ops.rs the policy type is imported as `saiife_policy::Mode as PolicyMode`.
  - `pub fn policy_mode(self) -> saiife_policy::Mode`, which gives `Locked` for `Locked` and `Developer` for `Personal`.
  - `Ctx.mode: Mode` (pub field), and `pub fn trusted_owner(&self) -> u32`: 0 when locked, `own_uid` when personal.
  - `pub fn check_services_owned(l: &LoadedPolicy, config_path: &Path, owner: u32) -> Result<Catalog, String>`. The existing `check_services(l, p)` stays as `check_services_owned(l, p, 0)`.
  - `pub fn from_loaded_in(l: &LoadedPolicy, catalog: &[PackInfo], connectors: Catalog, mode: Mode) -> PolicyState`. The existing `from_loaded` stays as `from_loaded_in(…, Mode::Locked)`.
  - `pub fn hello_in(id: u64, mode: &str) -> Value`.
  - `CtxInit { …, pub mode: Mode }` and `pub fn CtxInit::minimal(writer: WriterHandle, writer_cfg: WriterConfig, directory: Arc<dyn Directory + Send + Sync>, state_dir: &Path) -> CtxInit`. It gives:
    - `mode: Locked`, `own_uid: getuid()` and `own_user: ""`;
    - every path under `state_dir`;
    - `vault: Unavailable("not configured")`, `upstream: Err("not configured")` and `approvals: Err("not configured")`;
    - `Limiter::default()`;
    - tokens, lockdown and grants opened under `state_dir`;
    - an invalid `PolicyState`.
- `crates/daemon/src/personal.rs` (Task 4) and `start.rs` (Task 5):
  - `pub struct PersonalCfg { pub own_user: String, pub own_uid: u32, pub socket_dir: PathBuf, pub audit_dir: PathBuf }`
  - `pub(crate) fn load_policy(mode: Mode, config: &Path, dir: &dyn Directory, catalog: &[PackInfo], personal: Option<&PersonalCfg>) -> Result<(LoadedPolicy, Catalog, PolicyState), String>`. This is the one load path for start and reload: `load_and_check`, then `personal::apply` when `Some`, then `check_ask`, then `check_services_owned` with the owner, then `from_loaded_in`.
- `crates/system/src/personal.rs`: `pub struct PersonalPaths { pub socket_dir: PathBuf, pub config: PathBuf, pub state_dir: PathBuf, pub audit_dir: PathBuf }` and `pub fn personal_paths(env: &dyn Fn(&str) -> Option<OsString>, home: Option<&Path>) -> Result<PersonalPaths, String>`.
- `crates/cli/src/broker.rs`:
  - `pub(crate) enum Target { Locked { config: PathBuf, socket_dir: PathBuf, owner_uid: u32 }, Personal { config: PathBuf, socket_dir: PathBuf, owner_uid: u32 } }`, with `pub(crate) fn is_locked(&self) -> bool` and `pub(crate) fn config(&self) -> &Path`;
  - `pub(crate) fn resolve(config_flag: Option<&Path>, system_config: &Path, env: &dyn Fn(&str) -> Option<OsString>) -> Result<Target, String>`;
  - `pub(crate) fn connect(t: &Target, deadline: Instant) -> Result<Client, ClientError>`.

## Review Focus

1. **The keychain lost the key but `vault.bin` is there.** This happens after a new keyring, a `secret-tool clear` or a different desktop session. The broker must never create a new key over the old vault. The vault is unavailable, the file stays byte-identical, and the reason names the file (Task 4: `missing_key_with_existing_vault_never_rekeys`).
2. **Another uid reaches the personal socket** (root, or a dir with loose modes). The connection is closed before any answer, on both sockets (Task 5: `foreign_uid_closed_before_hello`, `foreign_uid_gateway_closed`).
3. **`XDG_RUNTIME_DIR` is unset, relative, a symlink, foreign-owned or 0755.** The start is refused with a line naming the problem; it never falls back to /tmp (Task 3: `runtime_dir_table`).
4. **No session bus, no Secret Service, or a dismissed unlock prompt.** The daemon still starts, writes `vault_unavailable` with the reason, and connector calls are denied rather than crashing or hanging. A prompt that never completes times out (Task 2: `dismissed_prompt_is_locked`, `prompt_timeout_is_locked`; Task 5: `personal_without_keychain_serves_audit`).
5. **A locked host plus a stray personal broker.** `saiife secret add` on a locked host must reach the system daemon, never `$XDG_RUNTIME_DIR/saiife` (Task 6: `locked_host_wins`). `daemon --user` refuses there (Task 5: `personal_refused_on_locked_host`).

---

## Task order and parallelism

- Wave 1, in parallel: Task 1 (keychain crate core), Task 3 (personal paths and unit text, in the `system` crate), Task 7 (guard rules and pack docs).
- Wave 2, in parallel: Task 2 (Secret Service; needs 1), Task 4 (daemon personal helpers and `vault::open_with_key`; needs 1).
- Wave 3: Task 5 (daemon wiring plus `daemon --user`; needs 2, 3 and 4).
- Wave 4: Task 6 (the CLI resolver and the commands in developer mode; needs 5).
- Wave 5: Task 8 (docs, CI smoke script, spec note, CHANGELOG).

**Shared files with plan 14** (round A). Plan 16 merges first, and plan 14 rebases onto it. Each change is small and additive:
- `crates/daemon/src/ops.rs`: the seams listed above, plus an `is_admin` branch.
- `crates/daemon/src/api_ops.rs`: `no_policy_snapshot` takes the mode (`ctx.mode.policy_mode()`).
- The 4 `CtxInit` literals move to `..CtxInit::minimal(…)`:
  - `daemon/src/start.rs`;
  - `daemon/tests/gateway.rs`;
  - `cli/tests/approvals.rs`;
  - `cli/tests/approvals_cmd.rs`.

  A grep finds 4 literals, not 5. Any literal plan 14 adds rebases onto `minimal`.
- `crates/cli/src/main.rs`: the `Daemon` args `--print-unit` and `--locked-marker`, and `Audit` `--broker`.
- `crates/cli/src/api_cmd.rs`: `connect` uses the resolver.
- `Cargo.lock`: both plans add crates. Regenerate on merge with `cargo update -w` only; never bump pins.

This plan does not touch `policy/src/system.rs`, the broker registry or `ipc/src/msg.rs`.

---

### Task 1: `saiife-keychain` crate: trait, fake, dir seam, macOS backend

**Files:**
- Create:
  - `crates/keychain/Cargo.toml` (`saiife-keychain`; `security-framework = "=3.7.0"` under `cfg(target_os = "macos")`);
  - `crates/keychain/src/{lib.rs, fake.rs, dir.rs, macos.rs}`.
- `#![forbid(unsafe_code)]`.

**Interfaces:**
- Produces:
  - `pub struct ItemId { pub service: &'static str, pub account: &'static str }`
  - `pub const VAULT_KEY: ItemId = ItemId { service: "saiife", account: "vault-key" }`
  - `pub const VAULT_KEY_LABEL: &str = "saiife personal broker: vault key"`
  - `pub trait Keychain: Send + Sync { fn get(&self, id: &ItemId) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError>; fn set(&self, id: &ItemId, label: &str, secret: &[u8]) -> Result<(), KeychainError>; fn delete(&self, id: &ItemId) -> Result<bool, KeychainError>; fn backend(&self) -> &'static str; }`
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub enum KeychainError { Unavailable(String), Locked(String), Other(String) }` with `Display`. Messages never contain secret bytes.
  - `pub struct FakeKeychain`, with `new()`, `fail_next(KeychainError)`, `set_locked(bool)` and `calls() -> Vec<&'static str>`.
  - `pub struct DirKeychain { dir: PathBuf }` (`#[cfg(debug_assertions)]`): file `<dir>/<service>.<account>`, 0600, in a 0700 dir; symlinks refused.
  - `#[cfg(target_os = "macos")] pub struct MacKeychain`, over `security_framework::passwords::{get_generic_password, set_generic_password, delete_generic_password}`. `errSecItemNotFound` (-25300) → `Ok(None)` or `Ok(false)`.
  - `pub fn platform() -> Result<Box<dyn Keychain>, KeychainError>`:
    - Linux: Task 2's `SecretService::session()`. Until Task 2 lands, `Unavailable("no keychain backend")`.
    - macOS: `MacKeychain`.
    - Elsewhere: `Unavailable`.
  - `pub fn from_env() -> Result<Box<dyn Keychain>, KeychainError>`: in debug builds, `SAIIFE_TEST_KEYCHAIN` → `DirKeychain`; otherwise `platform()`.

- [ ] **Step 1: failing tests.**
  - `fake_roundtrip_get_set_delete`
  - `fake_locked_is_locked_error`
  - `fake_fail_next_once`
  - `dir_keychain_modes_0600_0700`
  - `dir_keychain_refuses_symlinked_item`
  - `dir_keychain_missing_is_none`
  - `error_display_never_has_secret`: set `b"s3cr3t-bytes"`, force each error, and assert that the `Display` and `Debug` output don't contain it.
- [ ] **Step 2: run them and see them fail.** `cargo test -p saiife-keychain`
- [ ] **Step 3: implement.** Also run `cargo check -p saiife-keychain --target x86_64-apple-darwin` with the fake `cc` from plan 12's gate, so `MacKeychain` compiles.
- [ ] **Step 4: run them and see them pass.**
- [ ] **Step 5: commit.** `feat(keychain): Keychain trait, fake, test dir seam and macOS backend`

### Task 2: Secret Service backend over zbus

**Files:**
- Create `crates/keychain/src/secret_service/{mod.rs, bus.rs, zbus_bus.rs}`.
- Create the test `crates/keychain/tests/secret_service_p2p.rs`.
- Modify `crates/keychain/Cargo.toml`:
  - Linux dependencies: `zbus = { version = "=5.19.0", default-features = false, features = ["tokio"] }` and `tokio = { version = "=1.53.2", features = ["rt", "net", "time"] }`;
  - Linux dev-dependencies: zbus with `["tokio", "p2p"]`.
- Modify `lib.rs` so that `platform()` returns this backend.

**Interfaces:**
- Consumes: Task 1's `Keychain`, `ItemId` and `KeychainError`.
- Produces:
  - `pub trait SsBus: Send + Sync`: one method per Secret Service call the backend uses (`OpenSession("plain")`, `ReadAlias`, `SearchItems`, `Unlock`, `Prompt` with a wait, `GetSecret`, `CreateItem` with `replace = true`, `Delete`). Object paths are `String`, and secret bytes come back as `Zeroizing<Vec<u8>>`. The implementer picks the exact shapes.
  - `pub struct SecretService<B: SsBus> { bus: B, prompt_wait: Duration }`, which implements `Keychain`, with `backend() == "secret-service"`.
  - `pub const PROMPT_WAIT: Duration = Duration::from_secs(120)`.
  - `SecretService::<ZbusBus>::session() -> Result<Self, KeychainError>`.
  - `pub struct ZbusBus { conn: zbus::Connection, rt: tokio::runtime::Runtime }`, with `ZbusBus::session()` (no `DBUS_SESSION_BUS_ADDRESS`, or a connect failure, gives `Unavailable("no session bus: …")`) and `#[doc(hidden)] ZbusBus::over(conn)` for tests.
- Behaviour (decision 8). The order that matters for security:
  - `get` refuses more than one matching item rather than guessing which one to read.
  - `get` unlocks, prompting if needed, before it reads.
  - `set` writes only to the `default` alias collection; with no alias it is `Unavailable`.
  - `ServiceUnknown` and connect failures are `Unavailable`, never a panic or a hang.
  - Every zbus call asserts that there is no current tokio runtime.

- [ ] **Step 1: failing tests.**
  - Logic, with a `FakeBus` in `mod.rs` tests:
    - `get_none_when_no_item`
    - `get_unlocks_locked_item_then_reads`
    - `dismissed_prompt_is_locked`
    - `prompt_timeout_is_locked`: `FakeBus` never completes; use `prompt_wait = 50ms`
    - `two_items_is_error`
    - `set_without_default_alias_is_unavailable`
    - `set_replaces_existing`
  - p2p, with a minimal in-test Secret Service (`#[zbus::interface]` for Service, Collection, Item and Prompt) served over `tokio::net::UnixStream::pair()` with `connection::Builder::unix_stream(..).p2p().server(guid)`. These run on a plain `#[test]` thread, so the backend owns the runtime, while the server runs on its own thread with its own runtime:
    - `p2p_roundtrip_set_get_delete`
    - `p2p_secret_bytes_exact`: 32 bytes including `0x00`
    - `p2p_attributes_and_label`: the server saw `application=saiife`, `saiife-item=vault-key` and `VAULT_KEY_LABEL`
    - `p2p_service_unknown_is_unavailable`
  - `session_without_bus_env_is_unavailable`: clear `DBUS_SESSION_BUS_ADDRESS` in a child process (`assert_cmd`-style re-exec of the test binary with a filter), so the test env stays clean.
- [ ] **Step 2: run them and see them fail.** `cargo test -p saiife-keychain`
- [ ] **Step 3: implement.** Then check the new Cargo.lock entries against the 14-day rule (Global Constraints).
- [ ] **Step 4: run them and see them pass.** Then run `cargo tree -e normal -p saiife-guard -p saiife-audit -p saiife-policy -p saiife-ipc -p saiife-system | grep -c tokio`, which must print `0`.
- [ ] **Step 5: commit.** `feat(keychain): Secret Service backend over zbus (plain session)`

### Task 3: personal paths and login unit text (`saiife-system`)

**Files:**
- Create `crates/system/src/personal.rs` and `crates/system/src/user_unit.rs`.
- Modify `crates/system/src/lib.rs` (the `pub mod` lines).

**Interfaces:**
- Produces:
  - `pub struct PersonalPaths { pub socket_dir: PathBuf, pub config: PathBuf, pub state_dir: PathBuf, pub audit_dir: PathBuf }`, laid out per decision 2.
  - `pub fn personal_paths(env: &dyn Fn(&str) -> Option<OsString>, home: Option<&Path>) -> Result<PersonalPaths, String>`. A missing or relative `XDG_RUNTIME_DIR` → `Err("XDG_RUNTIME_DIR is not set or not absolute; log in through a session manager or run as a systemd --user unit")`.
  - `pub fn check_runtime_dir(dir: &Path, euid: u32) -> Result<(), String>`, applied to the `$XDG_RUNTIME_DIR` dir itself, per decision 2.
  - `pub const USER_UNIT_NAME: &str = "saiife-broker.service"`
  - `pub const LAUNCHD_LABEL: &str = "com.saiife.broker"`
  - `pub fn user_unit_text(exe: &Path) -> Result<String, String>`: the exe must be absolute; `%` becomes `%%`; a path with whitespace, `"` or `\` is refused.
  - `pub fn launchd_plist_text(exe: &Path) -> Result<String, String>`: the exe must be absolute and is XML-escaped.
- Exact unit text, with `{exe}` substituted:

```ini
[Unit]
Description=saiife personal broker (not a security boundary)

[Service]
Type=notify
ExecStart={exe} daemon --user
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=1
RuntimeDirectory=saiife
RuntimeDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
LockPersonality=yes
LimitCORE=0

[Install]
WantedBy=default.target
```

- The plist uses `Label` = `com.saiife.broker`, `ProgramArguments` = `[exe, daemon, --user]`, `RunAtLoad` true, `KeepAlive` = `{SuccessfulExit: false}` and `ProcessType` = `Background`.

- [ ] **Step 1: failing tests.**
  - `paths_from_xdg_vars`
  - `paths_fall_back_to_home`
  - `relative_xdg_values_ignored`
  - `runtime_dir_table`: unset, relative, a symlink, foreign-owned (simulated by passing `euid + 1`), 0755 and a regular file are all refused; a 0700 own dir passes
  - `unit_text_exact`: byte equality with the block above, for `/opt/x/saiife`
  - `unit_escapes_percent`
  - `unit_refuses_relative_or_spaced_exe`
  - `plist_escapes_xml_and_parses_shape`: contains `<string>com.saiife.broker</string>` and `<string>--user</string>`
- [ ] **Step 2: run them and see them fail.** `cargo test -p saiife-system personal user_unit`
- [ ] **Step 3: implement.**
- [ ] **Step 4: run them and see them pass.** Then rerun the tokio gate.
- [ ] **Step 5: commit.** `feat(system): personal broker paths and login unit text`

### Task 4: the daemon's personal helpers and `vault::open_with_key`

**Files:**
- Create `crates/daemon/src/personal.rs` (Linux).
- Modify:
  - `crates/daemon/src/vault.rs`: split `open` into `read_key` + `pub fn open_with_key(key: Zeroizing<[u8; 32]>, vault_file: &Path) -> VaultState`, so `open` keeps its behaviour;
  - `crates/daemon/src/lib.rs`: the module line;
  - `crates/daemon/Cargo.toml`: `saiife-keychain = { path = "../keychain" }`.

**Interfaces:**
- Consumes: Task 1's `Keychain`, `VAULT_KEY` and `VAULT_KEY_LABEL`.
- Produces:
  - `pub fn vault_key(kc: &dyn Keychain, vault_file: &Path) -> Result<Zeroizing<[u8; 32]>, String>`, per decision 11. A stored value that is not 32 bytes → `Err("the keychain's vault key is not 32 bytes")`.
  - `pub fn open_vault(kc: &dyn Keychain, vault_file: &Path) -> VaultState`, which wraps `vault_key` + `open_with_key`. An `Err` becomes `Unavailable(reason)`.
  - `pub const PERSONAL_CONFIG: &str`: `version = 2` plus the comment lines `# saiife personal broker: not a security boundary (docs/personal-broker.md).` and `# saiife connect <service> writes policy.d/<service>.toml.`
  - `pub fn ensure_config(path: &Path) -> io::Result<bool>`: writes `PERSONAL_CONFIG` 0600 in a 0700 dir when missing; never overwrites; returns `true` when it created the file.
  - `pub struct PersonalCfg`, as listed under "Seams this plan owns".
  - `pub fn apply(cfg: &mut SystemConfig, raw: &toml::Table, p: &PersonalCfg) -> Vec<String>`, per decision 5. It sets `daemon.socket_dir` and `audit.dir` and synthesizes the scope, and returns the warnings.
  - `pub fn admits(own_uid: u32, peer_uid: u32) -> bool`, which is `peer_uid == own_uid`.

- [ ] **Step 1: failing tests.**
  - `fresh_key_created_once`: the fake shows one `set`, and a second call is a `get` only
  - `existing_key_used`
  - `missing_key_with_existing_vault_never_rekeys`: write a `vault.bin`, use an empty fake, assert `Unavailable` contains the path, no `set` call, and the file bytes are unchanged
  - `locked_keychain_is_unavailable_with_reason`
  - `short_key_refused`
  - `open_with_key_matches_open`: the same vault opens both ways
  - `ensure_config_creates_0600_never_overwrites`
  - `apply_synthesizes_personal_scope`: the scope is named `personal`, with users `[own]` and every service
  - `apply_keeps_given_scopes_and_warns_without_own_user`
  - `apply_overrides_paths_and_warns_on_daemon_admin_audit_dir`
  - `admits_same_uid_only`: own true; own+1, 0 and `u32::MAX` false
- [ ] **Step 2: run them and see them fail.** `cargo test -p saiife-daemon personal vault`
- [ ] **Step 3: implement.**
- [ ] **Step 4: run them and see them pass.**
- [ ] **Step 5: commit.** `feat(daemon): personal broker helpers and vault key from the keychain`

### Task 5: `DaemonMode::Personal` wiring and `saiife daemon --user`

**Files:**
- Modify:
  - `crates/daemon/src/lib.rs`: `DaemonOptions.mode`;
  - `start.rs`;
  - `ops.rs` (shared);
  - `api_ops.rs` (shared): `no_policy_snapshot(hash, mode)`;
  - `server.rs`, `gateway.rs`, `writer.rs`;
  - `approvers.rs`, `approval_ops.rs`, `lockdown.rs`;
  - `secret_ops.rs`: refuse import in personal mode;
  - `crates/audit/src/chain.rs`: `pub fn mode(&self) -> &str` on `ChainWriter`;
  - `crates/cli/src/main.rs` (shared): `cmd_daemon`.
- Test: `crates/cli/tests/personal_broker.rs`, plus `crates/cli/tests/common/personal.rs`. The harness is like `common/daemon.rs` and sets:
  - `SAIIFE_TEST_KEYCHAIN`;
  - the XDG vars;
  - `HOME`;
  - `DBUS_SESSION_BUS_ADDRESS=unix:path=<tmp>/no-bus`, a dead path.
- Move the 4 `CtxInit` literals to `..CtxInit::minimal(…)`: `start.rs`, `daemon/tests/gateway.rs`, `cli/tests/approvals.rs` and `cli/tests/approvals_cmd.rs`.
- Update `crates/cli/tests/daemon.rs::daemon_requires_system_flag`: no flag, or both flags, is exit 2.

**Interfaces:**
- Consumes:
  - Task 3's `PersonalPaths`, `personal_paths`, `check_runtime_dir`, `user_unit_text` and `launchd_plist_text`;
  - Task 4's `open_vault`, `ensure_config`, `apply` and `admits`;
  - Task 1's `from_env`.
- Produces:
  - `pub enum DaemonMode { System, Personal { socket_dir: PathBuf, audit_dir: PathBuf, keychain: Box<dyn saiife_keychain::Keychain>, locked_marker: PathBuf } }` in `lib.rs`, cross-platform.
  - `DaemonOptions { …, mode: DaemonMode }`. In personal mode, `config` and `state_dir` are the personal paths and `credentials_dir` is `None`.
  - In `ops.rs` and `start.rs`: every item under "Seams this plan owns", with exactly those signatures. Also `is_admin`: in `Personal`, it is `uid == own_uid`.
  - In `approvers.rs`: `pub fn personal_may_decide(own_uid: u32, peer_uid: u32) -> Result<(), Refusal>`. It is used in place of `may_decide` at `approval_ops.rs` and `lockdown.rs` when `ctx.mode == Personal`. `approval_ops::is_approver` is true for the own uid there.
- `start.rs`, in personal mode. The order that matters for security:
  1. Before anything is created, refuse:
     - euid 0;
     - an existing `locked_marker`;
     - a bad `XDG_RUNTIME_DIR`;
     - `locked = true`.
  2. Read the vault key (`open_vault`) before the tokio runtime is built.
  3. Bind the sockets with `(0o700, 0o600)` and an euid-owned dir (root is not accepted). The system mode keeps `(0o755, 0o666)`.
  4. The rest follows from decisions 4, 5 and 7 and `load_policy`:
     - no signing key and no `regroup_audit_dir`;
     - the CA and connectors owner is `ctx.trusted_owner()`.
- `server::connection` and `gateway::connection` return right after `peer_cred` when `!admits(ctx.own_uid, peer.uid)` in `Personal`. The hello answer comes from `hello_in(id, ctx.mode.as_str())`.
- The `writer.rs` append sets `rec.mode = Some(chain.mode().into())` before every append. This is a no-op in locked mode.
- `cmd_daemon`:
  - `--user` → `personal_paths(std::env::var_os, dirs::home_dir())`, then `from_env()`; a keychain `Err` still starts the daemon, with `Unavailable`. Clap `--locked-marker` is hidden and debug-only; the default is `saiife_system::layout::INSTALLED`.
  - `--print-unit systemd|launchd` (requires `--user`) prints the text for `std::env::current_exe()` and exits 0.
  - On a non-Linux system, `--user` prints the decision 9 line and exits 2.

- [ ] **Step 1: failing tests**, in `personal_broker.rs` unless noted:
  - `hello_mode_personal`
  - `socket_dir_0700_sockets_0600`
  - `config_created_on_first_start`
  - `secret_add_list_through_broker_as_own_user`: raw `Client` calls with `secret.add` and `secret.list`; the value is absent from the audit and the vault files
  - `vault_survives_restart_same_key`
  - `personal_without_keychain_serves_audit`: `SAIIFE_TEST_KEYCHAIN` points to a file, so the keychain errors; the daemon is up, `vault_unavailable` is recorded, and `secret.add` is refused
  - `every_record_mode_personal`: includes a connector record from a loopback mock
  - `audit_chain_has_no_key_and_verifies`
  - `personal_refused_as_locked_config`
  - `personal_refused_on_locked_host`: `--locked-marker` points at an existing file
  - `personal_refuses_bad_runtime_dir`
  - `same_user_approval_allowed`: an `ask` operation, then `approval.decide` from the same uid, then done
  - `implicit_scope_allows_configured_service`
  - `project_allow_overlay_honoured`: the overlay came through `from_loaded_in(…, Personal)`
  - `no_policy_snapshot_mode_follows_ctx`: a unit test in `api_ops.rs`, where Personal gives `PolicyMode::Developer` and Locked gives `PolicyMode::Locked`
  - `ctx_init_minimal_builds`: a `Ctx` from `CtxInit { own_uid: 7, ..CtxInit::minimal(…) }` answers `status`
  - `harness_without_keychain_seam_never_reaches_desktop`: the harness env with `SAIIFE_TEST_KEYCHAIN` removed. The daemon starts, and `vault_unavailable`'s reason contains `no session bus` within 5 s. No `secret-tool` or bus process is involved.
  - `local_connector_owned_by_user_loads`
  - `secret_import_refused_personal`
  - `print_unit_systemd_and_launchd`: stdout matches `user_unit_text` and `launchd_plist_text` for the test binary path
  - Daemon unit tests that build a `Ctx` with `own_uid = getuid() + 1` and `Mode::Personal` and serve a real `UnixStream` pair:
    - `foreign_uid_closed_before_hello`: the read gives EOF, no answer bytes
    - `foreign_uid_gateway_closed`
  - Locked regression: the existing `hello_answers_proto_1_and_mode_locked` still passes, and `locked_records_still_locked`.
- [ ] **Step 2: run them and see them fail.** `cargo test -p saiife --test personal_broker`, then `cargo test -p saiife-daemon foreign_uid`
- [ ] **Step 3: implement**, per the bullets above.
- [ ] **Step 4: run them and see them pass.** Then run the whole daemon and CLI suites to catch locked-mode regressions.
- [ ] **Step 5: commit.** `feat(daemon): personal broker mode (saiife daemon --user)`

### Task 6: the CLI in developer mode: `secret`, `connect`, `api`, `run`, `policy reload`, `audit --broker`, `status`

**Files:**
- Create `crates/cli/src/broker.rs`.
- Modify:
  - `secret_cmd.rs`: `linux::call` uses the resolver; `Import` is refused in personal mode;
  - `connect_cmd.rs`: the personal config dir, `load_local_with(dir, builtin(), getuid)`, the policy file 0600, and a missing config → `start the broker first: saiife daemon --user`;
  - `api_cmd.rs` (shared): `connect` uses the resolver, and the overlay merge uses `Mode::Developer` in personal mode;
  - `approvals_cmd.rs` and `audit_locked.rs`: the connection only;
  - `audit_cmd.rs` and `main.rs` (shared): `--broker`;
  - `status_cmd.rs`: one line.

**Interfaces:**
- Consumes: Task 3's `personal_paths`; Task 5's daemon.
- Produces:
  - `pub(crate) enum Target { Locked { config: PathBuf, socket_dir: PathBuf, owner_uid: u32 }, Personal { config: PathBuf, socket_dir: PathBuf, owner_uid: u32 } }`
  - `pub(crate) fn resolve(config_flag: Option<&Path>, system_config: &Path, env: &dyn Fn(&str) -> Option<OsString>) -> Result<Target, String>`, per decision 10:
    1. a flag → Locked, as today;
    2. else `system_config` with `locked = true` → Locked;
    3. else Personal, with `owner_uid = getuid()`.
  - `pub(crate) fn connect(t: &Target, deadline: Instant) -> Result<Client, ClientError>`, which uses `Client::connect(socket_dir, owner_uid, …)`. For `Personal`, the hello `mode` must be `personal`; anything else is `Protocol("not a personal broker")`.
  - Unreachable broker message: `cannot reach the personal broker at <dir>: start it with saiife daemon --user (docs/personal-broker.md)`.
  - `saiife audit --broker` and `saiife audit verify --broker` read `PersonalPaths.audit_dir` with the existing developer readers. Every line is labelled `personal broker, not a security boundary`.
  - `status`: when the personal socket answers hello, it prints `  personal broker: running (not a security boundary)`. Otherwise nothing.

- [ ] **Step 1: failing tests.**
  - Unit tests in `broker.rs`:
    - `locked_host_wins`
    - `flag_is_locked`
    - `no_locked_config_is_personal`
    - `unlocked_system_config_is_personal`
  - CLI tests with the Task 5 harness:
    - `secret_add_list_rotate_remove_personal`
    - `connect_personal_writes_policy_0600_and_secret`
    - `connect_personal_without_config_says_start_broker`
    - `api_call_through_broker_loopback_mock`
    - `run_secret_through_broker`
    - `policy_reload_personal`
    - `audit_broker_lists_and_verifies`
    - `status_shows_personal_broker`
    - `secret_import_refused_personal_cli`
    - `broker_down_message`
- [ ] **Step 2: run them and see them fail.** `cargo test -p saiife broker personal`
- [ ] **Step 3: implement.**
- [ ] **Step 4: run them and see them pass**, plus the whole CLI suite.
- [ ] **Step 5: commit.** `feat(cli): secret, connect, api and audit against the personal broker`

### Task 7: guard rules for the personal broker (mistake layer)

**Files:**
- Modify:
  - `crates/guard/packs/core.secrets.toml`;
  - `crates/guard/packs/core.self.toml`, bumping the `version` of both;
  - `docs/packs/core.secrets.md` and `docs/packs/core.self.md` (`docs_pages.rs` keeps them in sync);
  - `crates/guard/tests/corpus_secrets.rs` and `corpus_self.rs`.

**Interfaces:**
- `core.secrets` denies, with reason `reads saiife's vault key from the keychain`:
  - `secret-tool (lookup|search) … saiife`;
  - `security (find|dump)-generic-password … saiife` and `security dump-keychain`;
  - `gdbus|busctl|dbus-send|qdbus … org.freedesktop.secrets` with `GetSecret`/`SearchItems`.
- `core.self` denies:
  - `systemctl --user (stop|disable|mask|kill|restart|edit) saiife-broker`;
  - `launchctl (bootout|unload|kill|remove) … com.saiife.broker`;
  - write-tool globs `$XDG_CONFIG_HOME/saiife/broker/**`, `~/.config/saiife/broker/**`, `~/.local/state/saiife/broker/**` and `~/.local/share/saiife/broker/**`. Reading stays allowed, as the pack says.
- Triggers are extended so the prefilter sees `secret-tool`, `security`, `org.freedesktop.secrets`, `saiife-broker` and `com.saiife.broker`.

- [ ] **Step 1: failing corpus rows.**
  - Deny:
    - `secret-tool lookup application saiife`
    - `security find-generic-password -s saiife -w`
    - `busctl --user call org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.Secret.Service SearchItems …`
    - `systemctl --user stop saiife-broker.service`
    - a Write to `~/.config/saiife/broker/config.toml`
  - Allow:
    - `secret-tool lookup application other`
    - `security find-generic-password -s github`
    - `systemctl --user status saiife-broker`
    - `cat ~/.config/saiife/broker/config.toml`
- [ ] **Step 2: run them and see them fail.** `cargo test -p saiife-guard corpus_secrets corpus_self docs_pages`
- [ ] **Step 3: implement**, following core.lock's patterns.
- [ ] **Step 4: run them and see them pass.** Check the guard latency tests too.
- [ ] **Step 5: commit.** `feat(guard): deny reading the broker's vault key and stopping the broker`

### Task 8: docs, CI smoke test, spec note, CHANGELOG

**Files:**
- Create `docs/personal-broker.md` and `scripts/personal-broker/ss-smoke.sh`.
- Modify:
  - `docs/threats.md`: the Personal broker section, with the §10 labels verbatim;
  - `README.md`: one paragraph with the §1.1 wording and the §10 wording rule;
  - `CHANGELOG.md` (Unreleased);
  - `.github/workflows/ci.yml`: one ubuntu step;
  - `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`: the three spec notes from Global Constraints, one line each, at §6.6 and at the §7 rows `daemon --system | --user` and `secret … import`. Each is prefixed `Built (plan 16):`.

**Content of `docs/personal-broker.md`:**
- Start with what it is: "not a security boundary" and "a workflow aid, not a control" (§6.10.2).
- The setup:
  - `saiife daemon --user`;
  - `saiife daemon --user --print-unit systemd > ~/.config/systemd/user/saiife-broker.service`, then the user runs `systemctl --user daemon-reload` and `systemctl --user enable --now saiife-broker` themselves;
  - the launchd plist, marked for after the v2.1 daemon port.
- The paths table (decision 2).
- `saiife connect`, `saiife secret`, `saiife api`, `saiife audit --broker`, and `env use` (§6.11, once plan 14 lands).
- What protects the key and what does not (decision 12): the §6.6 sentence verbatim, plus that the agent can stop the broker and bind its socket.
- The lost-key recovery: the vault is kept; restore the keyring or remove `vault.bin` and add the secrets again.

**The CI script** runs in CI only, in a throwaway `HOME`/XDG tree under `dbus-run-session`, with `gnome-keyring-daemon` unlocked by a random password. It proves three things:
- a `secret add` through the broker creates exactly one 32-byte `application=saiife saiife-item=vault-key` item (checked with `secret-tool`);
- the secret survives a broker restart;
- the value is built at runtime.

The CI step installs `gnome-keyring libsecret-tools dbus` first.

- [ ] Write the docs, then:
  - run `bash -n scripts/personal-broker/ss-smoke.sh`;
  - run `cargo test -p saiife-guard docs_pages` and the docs link check, if one exists;
  - commit `docs: personal broker mode, threats, CI Secret Service smoke test`.

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`, clippy `-D warnings`, and the tokio gate;
  - `cargo test --workspace` and `scripts/test-offline.sh`, with `TMPDIR` and `SAIIFE_TEST_TMP` set;
  - the macOS-target check: `RUSTFLAGS="-D warnings" cargo check --workspace --all-targets --target x86_64-apple-darwin` with the fake `cc`. This covers `MacKeychain`;
  - a musl build check: `cargo build --locked --profile ci-locked --target x86_64-unknown-linux-musl --bin saiife`. It proves zbus brings no C dependency;
  - `scripts/bench-check.sh` against `main`, which proves the hook path is unchanged.
- [ ] Whole-branch review (Opus), one fix wave and a scoped re-review. Then push, open the PR and let CI run (including the macOS runner and the smoke step). The owner merges. No tag.

## Self-review

- **Spec coverage:**
  - §7 `daemon --user`: Task 5.
  - Keychain vault, Linux and macOS (§6.6, D13): Tasks 1, 2 and 4.
  - `secret`/`connect` in developer mode (§7, decision 7): Task 6.
  - §6.9.1 project allow: Task 5, `project_allow_overlay_honoured`.
  - §6.10.2: Task 5, `same_user_approval_allowed`.
  - §8.5 `personal`: Task 5, `every_record_mode_personal`.
  - §10 column: Task 8.
  - §5.5 per-user unit: Tasks 3 and 8.
  - §6.11 `env use`: docs only, because the command comes with plan 14.
  - §6.19 "mode per host" in the report: the records carry `mode`. The report already groups by mode, so nothing more is needed here.
- **Types:** `Keychain`, `ItemId` and `KeychainError` (Task 1) are used unchanged in Tasks 2, 4 and 5. `PersonalPaths` (Task 3) appears in Tasks 4, 5 and 6. `ops::Mode` is distinct from `saiife_policy::Mode`; Task 5 names both.
- **Proportion:** signatures, test names and one fixed text (the unit, which the tests compare byte for byte). No function bodies.

## Owner handwork

- [ ] **Confirm** the spec notes:
  - decision 1: one keychain item for the vault key, with `vault.bin` kept. Otherwise ask for per-secret items as §6.6 words it;
  - decision 9: the macOS personal broker is refused until plan 13;
  - decision 6: `secret import` is refused in personal mode.
- [ ] On a Linux desktop session (GNOME Keyring, and KWallet if you use KDE):
  - start `saiife daemon --user`, run `saiife connect` for one real service, and see the "saiife personal broker: vault key" item in Seahorse;
  - restart, and the secret still works;
  - lock the keyring and start again, and an unlock prompt appears;
  - dismiss it, and `vault_unavailable` is in `saiife audit --broker`.
- [ ] Install the systemd `--user` unit from `--print-unit systemd` by hand. Log out and back in, and the broker is running.
- [ ] After plan 13 (the macOS daemon port): run `saiife daemon --user` on a Mac. The Keychain item's access list names the saiife binary, and a different binary reading it gets the one-click prompt (§6.6).

## Appendix: attack cases for the owner's red-team suite

- A same-user script runs `secret-tool lookup application saiife saiife-item vault-key`, then decrypts `vault.bin` (expected: it succeeds; documented).
- The agent kills the broker and binds its own `saiife.sock` to capture the next `saiife secret add` value (expected: it succeeds; documented).
- The agent writes `~/.config/saiife/broker/policy.d/x.toml` to allow an operation (expected: a guard denial through the write tool; a script still succeeds).
- The agent sets `XDG_RUNTIME_DIR` to a dir it controls for the user's next `saiife secret add` (expected: the client's owner check passes because it is the same uid, so this is documented).
- Root connecting to the personal socket (expected: closed before hello).
