# Plan 9a — Daemon core (unprivileged) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `saiife daemon --system` runs as an ordinary user against temp dirs. It owns the audit chain (a single writer, signed Ed25519 checkpoints, key rotation), and `saiife check --managed` judges each call in a worker child, sends `audit.append` and fails closed. `saiife audit verify` checks checkpoint signatures. Developer mode does not change.

**Architecture:** There are two new tokio-free crates. `ipc` holds the §8.7 frame codec, the message types, a blocking `UnixStream` client that checks the socket owner, and peer credentials. `policy` parses `/etc/saiife/config.toml` and `policy.d/` (§8.1). It checks one scope per uid, does the add-only project merge (§8.2) and computes the effective-policy hash. The `audit` crate gains a `ChainWriter` that holds the chain lock for its whole life, plus signing (`sign.rs`) and signature checks in `verify`. One new crate, `daemon`, links tokio. It runs the control server, a single audit-writer thread fed by a bounded channel, checkpoint timers and SIGHUP/SIGTERM handling. The CLI gains `daemon`, `check --managed` and the hidden worker `__eval`. Everything here runs without root. Install, systemd, managed hook files and red-team tests come in plans 9b and 9c.

**Tech Stack:** Rust workspace. New crates: `saiife-ipc`, `saiife-policy`, `saiife-daemon`. New dependencies: `tokio` (daemon only), `ed25519-dalek`, `base64`, `zeroize`, plus `rustix` features `net`/`fs`.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers §4.1 and §4.2, §5.4.1 (only the daemon's own duties: `Type=notify` readiness and `PR_SET_DUMPABLE`), §6.1.2, §6.2, §6.3, §6.4.2, §6.4.3 item 2, §8.1, §8.2, §8.5, §8.6, §8.7, §9.3 (the rows saiife controls: engine crash, daemon down), §11 (worker, 1 MiB payload) and §13 (chain: forged checkpoint and key rotation; fail-closed; performance). Plans 8 (`2026-10-22-plan-8-audit-chain.md`) and 7 (`2026-10-19-plan-7-lock-gate.md`) set the style.

## Global Constraints

- **No root anywhere in 9a.** Nothing needs root, systemd, sudo, docker or the real `/etc`, `/var`, `/opt` or `/run`. Every path can be configured. Tests use tempdirs, with scratch under `mktemp -d -p /home/jonas/projects/personal/saiife` (`/tmp` has a quota). Nothing writes managed agent settings to the host. Tests point `HOME`, `PATH`, `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` at tempdirs. `saiife init` never runs against the real home or the repo.
- **Path overrides for tests and admins:** `saiife daemon --system [--config <file>] [--state-dir <dir>]`, and `saiife check --managed [--system-config <file>]`, a hidden flag. Defaults are `/etc/saiife/config.toml` and `$STATE_DIRECTORY`, else `/var/lib/saiife`. `policy.d/` is the config file's sibling directory. Socket and audit dirs come from the config (`[daemon] socket_dir`, `[audit] dir`). Managed hook files (9b) never pass the overrides.
- **No tokio in the hook path:** `guard`, `audit`, `policy` and `ipc` stay free of tokio and networking. Only `daemon` links tokio (§4.2). Gate: `cargo tree -e normal -p saiife-guard -p saiife-audit -p saiife-policy -p saiife-ipc | grep -c tokio` prints `0`. This is a CI step in the `test` job from Task 6 on.
- **Unsafe code:** every new crate has `#![forbid(unsafe_code)]`. OS calls go through `rustix`.
- **Platforms:** the daemon, peer credentials and `check --managed` are Linux-only (`cfg(target_os = "linux")`, decision 2). On macOS, `saiife daemon` and `check --managed` print `saiife: locked mode needs Linux in this version (macOS: v2.1)` and exit 2. The whole workspace still builds and tests green on `macos-latest`.
- **Developer mode is unchanged:** `saiife check` without `--managed` keeps every behaviour, test and output. Its median in `scripts/bench-check.sh` stays within +1 ms of `main` (run both, put the numbers in the PR). Locked-mode full hook call (worker + ack): p95 < 40 ms (§6.1.2, §13).
- **Spec values, verbatim:**
  - frame = `u32` big-endian length followed by UTF-8 JSON, at most 1 MiB (1 048 576 bytes). The first frame is `hello` with `proto: 1`.
  - request `{"id": <u64>, "op": "<name>", ...}`; answer `{"id", "ok": true, ...}` or `{"id", "ok": false, "error": "<code>", "message": "..."}`.
  - op names `hello`, `audit.append`, `status`.
  - socket file `saiife.sock`, mode 0666.
  - ack timeout 2 s; worker timeout 3 s.
  - per uid, at most 64 requests in flight and 1 000 audit appends per second. Above that the answer is `busy`.
  - `min_free_mb` 512; `checkpoint_every` 1000; `checkpoint_interval` `"15m"`; `fsync` `"checkpoint"` means fdatasync at checkpoints and every 1 s.
  - checkpoint signed message: `saiife-checkpoint-v1\n<chain id>\n<head_seq>\n<head hex>\n<ts>` (no trailing newline).
  - genesis `key` is `ed25519:` + base64 of the SPKI DER, which starts `MCowBQYDK2VwAyEA`.
  - signing key file `<state>/keys/audit.ed25519`, 0600.
- **Locked records:** `mode` is `"locked"` in every record the daemon writes. `audit.append` takes only `kind = "guard"`. The daemon always sets `seq`, `prev`, `uid`, `user`, `host` and `peer`.
- **Fail closed in `--managed`:** every error, panic, worker failure, refusal or missing ack ends in exit 2, a reason on stderr and `error_denied`. Nothing in `--managed` falls back to allow.
- **Dependencies:** use versions that exist and were published at least two weeks ago, and prefer the §4.2 list: `tokio = "1.47"` (features `rt`, `net`, `io-util`, `sync`, `time`, `signal`, `macros`), `ed25519-dalek = { version = "2.2", default-features = false, features = ["std", "zeroize"] }`, `base64 = "0.22"`, `zeroize = "1.8"`, `rustix = "1"` (add `net`, `fs`). After `cargo update -p <crate>`, run `cargo info <crate>` and confirm the resolved release is older than 14 days. If it is newer, pin the previous patch with `=`. Skip `uuid`: `chain::uuid_v4` already exists. Skip `sd-notify`: readiness is one datagram (Task 6).
- `serde_json` is built with `preserve_order` across the workspace (feature unification through `agents`), so `Map` keeps insertion order. Canonical JSON must therefore sort keys explicitly (Task 3).
- **Git:** stage explicit paths. Merges to main only through a PR. Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

**Carry-overs, where they land:**

| # | Carry-over | Task |
|---|---|---|
| 1 | TOCTOU between `confine()` and `open()` in `config::read_bounded` | 1 |
| 2 | Unbounded blocking `std::fs::read` of the project config in `init_cmd.rs` and `status_cmd.rs` | 1 |
| 3 | Chain tail after a clock rollback of more than one month | 4 |
| 4 | 1 s chain-lock wait vs the 50 ms hook budget | 4 and 7 |

For carry-over 4: in locked mode the daemon's single writer holds the lock, and the managed hook never opens `.chain.lock`. In developer mode the 1 s wait stays. The record is written after the verdict, outside the guard's 50 ms engine budget and inside the 10 s hook timeout, so developer behaviour stays unchanged.

## Review Focus

1. **Daemon stops in the middle of a call.** The daemon dies or closes the connection after `hello` but before the ack. The hook must deny with exit 2 and never hang past the 2 s ack timeout. After a restart, the chain continues with `previous_clean_stop = false`. Tests: Task 7 `daemon_closes_after_hello_denies`, Task 6 `restart_after_kill_says_unclean`.
2. **Two writers on one audit dir.** A second daemon, or a developer-mode hook whose `SAIIFE_AUDIT_DIR` points at the daemon's dir. The chain must never fork: the second daemon refuses to start, and the stray hook's record lands unchained. Tests: Task 4 `second_writer_is_refused` and `writer_holds_lock_so_dev_append_goes_unchained`, Task 6 `second_daemon_same_dirs_refused`.
3. **Clock goes back more than a month,** in either mode. Records stay on one chain in the newest file, and `verify` exits 0. Tests: Task 4 `clock_rollback_over_a_month_stays_on_the_chain` and `writer_follows_newest_file_after_rollback`.
4. **Hostile or stuck clients.** Covers a zero-length, oversized or non-JSON frame, a first frame that is not `hello`, and a client that sends half a frame and stalls. The daemon closes only that connection, and other clients keep getting acks within 1 s. A connection holding an incomplete frame for 5 s is closed. Tests: Task 6 `oversized_frame_closes_connection`, `first_frame_must_be_hello`, `half_frame_client_does_not_block_others`.
5. **Signing key file is missing, the wrong size, the wrong mode or a symlink.** On first start the daemon creates the key. If the key is lost later, the chain shows an unsigned `key_rotate` and `verify` reports it. A file with a bad mode, bad size or a symlink makes the daemon refuse to start with a clear message, and it never silently replaces the key. Tests: Task 5 `key_file_wrong_mode_refused`, `key_file_symlink_refused`, `lost_key_is_unsigned_rotate`; Task 6 `daemon_refuses_bad_key_file`.

---

### Task 1: One bounded, race-free project config reader (carry-overs 1, 2)

**Files:**
- Modify: `crates/agents/src/config.rs` (`read_bounded`, `confine`, `load_hashed`, `ensure`), `crates/agents/Cargo.toml` (unix: `rustix = { version = "1", features = ["fs"] }`)
- Modify: `crates/cli/src/init_cmd.rs` (reads at ~112, 127, 134, 190, 375), `crates/cli/src/status_cmd.rs` (`config_drift`, ~394)
- Test: unit tests in `config.rs`; `crates/cli/tests/init_cmd.rs`, `crates/cli/tests/status_cmd.rs`

**Interfaces:**
- Produces:
  - `pub fn read_config_bytes(project: &Path) -> Result<Option<Vec<u8>>, AgentError>` returns `Ok(None)` when `<project>/.saiife/config.toml` does not exist. It enforces the same limits as today: `MAX_CONFIG_BYTES` (64 KiB), regular files only, a symlink is followed only while it stays inside the project, and the read never blocks.
  - `load_hashed` and `ensure` use it.
- **Linux:** open the project root with `O_DIRECTORY | O_RDONLY | O_CLOEXEC`. Then call `rustix::fs::openat2(root_fd, ".saiife/config.toml", RDONLY | NONBLOCK | NOCTTY | CLOEXEC, Mode::empty(), ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS)`. The kernel resolves symlinks only inside the root, so there is no window between check and open. `EXDEV` maps to `AgentError::OutsideProject`.
- **Fallback** when `openat2` fails with `ENOSYS` or `EPERM` (old kernel, seccomp), and always on macOS: today's `confine()` and open, then a post-open check. The opened fd's real path (`/proc/self/fd/<n>` on Linux, `rustix::fs::getpath` on macOS) must start with the canonical root, or the read is refused. The fallback is `fn read_fallback(project: &Path, before_open: impl FnOnce()) -> Result<Option<Vec<u8>>, AgentError>`. The hook argument is a test seam; production passes `|| {}`.

- [ ] **Step 1: Failing tests.**
  - In `config.rs`:
    - `config_symlink_outside_is_refused`: config is a symlink to a file outside → `Err(OutsideProject)`, and the outside file is never opened (it is a FIFO, so the test would hang if it were).
    - `saiife_dir_symlink_outside_is_refused`: `.saiife` is a symlink to an outside dir.
    - `symlink_inside_project_is_followed`.
    - `missing_config_is_none`.
    - `fifo_config_does_not_hang`: returns `Err` in under 1 s.
    - `fallback_refuses_dir_swapped_after_confine`: inside `before_open`, rename `.saiife` away and symlink it to an outside dir holding `config.toml` → `Err`.
    - `fallback_reads_normal_config`.
  - In cli tests:
    - `init_with_fifo_config_does_not_hang`: `.saiife/config.toml` is a FIFO → `saiife init --agent claude` exits non-zero within 5 s (spawn with a timeout).
    - `status_with_oversized_config_reports_it`: a 65 KiB config → stdout says `cannot be read` and `larger than 64 KiB`, exit 1.
    - `status_with_fifo_config_does_not_hang`.
- [ ] **Step 2:** `cargo test -p saiife-agents config && cargo test -p saiife --test init_cmd --test status_cmd` — the new tests fail or hang. Run the cli ones with `timeout 60`.
- [ ] **Step 3:** Implement. In `init_cmd.rs` and `status_cmd.rs`, every `std::fs::read(<root>.join(CONFIG_REL))` becomes `config::read_config_bytes(root)`. In `config_drift`, `Ok(None)` is the "was removed" branch and `Err(e)` prints `cannot be read: <e>` through `sanitize`.
- [ ] **Step 4:** `cargo test --workspace` green; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **Step 5:** Commit `fix(config): one bounded, race-free project config read for hook, init and status`.

### Task 2: `crates/ipc` — frames, messages, blocking client, peer credentials

**Files:**
- Create: `crates/ipc/Cargo.toml` (`saiife-ipc`; deps: `serde`, `serde_json`, `thiserror = "1"`; unix: `rustix = { version = "1", features = ["net", "fs", "process"] }`; dev: `tempfile`), `crates/ipc/src/{lib.rs, frame.rs, msg.rs, client.rs, peer.rs}`
- Test: unit tests in each module

**Interfaces:**
- Produces (`frame.rs`):
  - `pub const MAX_FRAME: usize = 1_048_576;`
  - `pub enum FrameError { Empty, TooLarge(usize), NotUtf8, NotJson, NotObject, Closed, Io(std::io::Error) }` (thiserror).
  - `pub fn encode(v: &serde_json::Value) -> Result<Vec<u8>, FrameError>`
  - `pub fn body_len(header: [u8; 4]) -> Result<usize, FrameError>`: 0 → `Empty`; anything over `MAX_FRAME` → `TooLarge`.
  - `pub fn decode(body: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>, FrameError>`
  - `pub fn read_frame(r: &mut impl std::io::Read) -> Result<Map, FrameError>`: EOF before or inside a frame → `Closed`.
  - `pub fn write_frame(w: &mut impl std::io::Write, v: &Value) -> Result<(), FrameError>`
- Produces (`msg.rs`):
  - `pub const PROTO: u64 = 1;`
  - `pub const SOCKET_NAME: &str = "saiife.sock";`
  - op constants `OP_HELLO = "hello"`, `OP_AUDIT_APPEND = "audit.append"`, `OP_STATUS = "status"`, `OP_AUDIT_ROTATE_KEY = "audit.rotate_key"`.
  - `pub struct Request { pub id: u64, pub op: String, pub args: Map }` with `to_value(&self) -> Value` and `from_map(Map) -> Result<Request, ErrorCode>`. A missing or non-u64 `id`, or a missing `op`, gives `BadRequest`.
  - `pub enum ErrorCode { BadFrame, BadRequest, HelloRequired, UnknownOp, Forbidden, Busy, LowDisk, Unavailable, Internal }`, serialized snake_case, plus `as_str()`.
  - `pub fn ok(id: u64, fields: Map) -> Value`
  - `pub fn err(id: u64, code: ErrorCode, message: &str) -> Value`
- Produces (`client.rs`):
  - `pub struct Client` (fields private) with `pub fn connect(socket_dir: &Path, daemon_uid: u32, deadline: Instant) -> Result<Client, ClientError>`. Before it connects:
    - `socket_dir` (lstat) must be a directory owned by `daemon_uid` and not group- or world-writable.
    - `socket_dir/saiife.sock` (lstat) must be a socket owned by `daemon_uid`.
    - Read and write timeouts are set to the time left until `deadline`.
    - It sends `hello {proto: 1, client: CARGO_PKG_VERSION}` and requires `ok` with `proto == 1`.
  - `pub fn call(&mut self, op: &str, args: Map, deadline: Instant) -> Result<Map, ClientError>`: increasing ids from 1; the answer `id` must match.
  - `pub fn hello_answer(&self) -> &Map`
  - `pub enum ClientError { Owner { path: PathBuf, detail: String }, Connect(io::Error), Timeout, Frame(FrameError), Refused { code: String, message: String }, Protocol(String) }`. A read or write timeout maps to `Timeout`.
  - `pub fn uid_by_name(passwd: &str, name: &str) -> Option<u32>` parses `/etc/passwd` text.
  - `pub fn system_uid(name: &str) -> Option<u32>` reads `/etc/passwd`. The daemon user is a local system user, so no NSS spawn happens on the hook path.
- Produces (`peer.rs`, Linux):
  - `pub struct PeerCred { pub uid: u32, pub gid: u32, pub pid: u32 }`
  - `pub fn peer_cred(sock: impl AsFd) -> io::Result<PeerCred>` (`rustix::net::sockopt::socket_peercred`)
  - `pub fn comm(pid: u32) -> Option<String>`: `/proc/<pid>/comm`, trimmed, at most 16 chars.

- [ ] **Step 1: Failing tests.**
  - `frame.rs`:
    - `round_trip`.
    - `header_is_big_endian_length`: `encode(&json!({"a":1}))` starts `[0,0,0,7]`, then `{"a":1}`.
    - `exactly_1_mib_accepted_one_more_refused`: `body_len(1_048_576u32.to_be_bytes())` is Ok; `1_048_577` → `TooLarge`.
    - `zero_length_is_empty`.
    - `non_utf8_refused`.
    - `array_is_not_object`.
    - `eof_inside_body_is_closed`.
  - `msg.rs`: `request_without_id_is_bad_request`, `error_codes_serialize_snake_case` (`HelloRequired` → `"hello_required"`, `LowDisk` → `"low_disk"`).
  - `client.rs` (Linux; a std `UnixListener` thread is the fake daemon):
    - `refuses_dir_owned_by_other_uid`: `daemon_uid = getuid()+1` → `Owner`, and the listener never accepts.
    - `refuses_group_writable_dir`: dir mode 0775 → `Owner`.
    - `refuses_regular_file_as_socket`.
    - `hello_then_call_round_trip`.
    - `answer_id_mismatch_is_protocol_error`.
    - `silent_server_times_out`: deadline 200 ms → `Timeout`, returned in under 1 s.
    - `refused_answer_maps_code`: `{"ok":false,"error":"busy"}` → `Refused { code: "busy", .. }`.
    - `uid_by_name_parses_passwd`: `"root:x:0:0::/root:/bin/sh\nsaiife:x:991:991::/:/usr/sbin/nologin\n"` → `saiife` = 991; `nobody` → `None`.
  - `peer.rs`: `peer_cred_of_socketpair_is_self`: uid == `getuid()`, pid == `std::process::id()`.
- [ ] **Step 2:** `cargo test -p saiife-ipc` fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean. `cargo tree -e normal -p saiife-ipc | grep -c tokio` prints `0`.
- [ ] **Step 5:** Commit `feat(ipc): control-socket frames, blocking client with owner check, peer credentials`.

### Task 3: `crates/policy` — `/etc` config, drop-ins, one scope per uid, add-only merge, policy hash

**Files:**
- Create: `crates/policy/Cargo.toml` (`saiife-policy`; deps: `serde`, `serde_json`, `toml = "0.8"`, `sha2 = "0.10"`, `thiserror = "1"`; dev: `tempfile`), `crates/policy/src/{lib.rs, system.rs, load.rs, duration.rs, users.rs, scope.rs, project.rs, effective.rs}`
- Create: `crates/policy/tests/fixtures/etc/config.toml` (the §8.1 block verbatim) and `crates/policy/tests/fixtures/etc/policy.d/shopify.toml` (the §8.1 drop-in verbatim)
- Test: unit tests per module; `crates/policy/tests/load.rs`

**Interfaces:**
- Produces (`system.rs`): `pub struct SystemConfig` and its section structs. All use `#[serde(deny_unknown_fields)]`, and every default is the §8.1 value:
  - `version: u32` must be 2.
  - `locked: bool`
  - `daemon: DaemonCfg { user: String = "saiife", socket_dir: PathBuf = "/run/saiife" }`
  - `admin: AdminCfg { groups: Vec<String> }`
  - `guard: GuardCfg { packs, ask: Vec<String>, budget_ms: u64 = 50, fail: Fail = Closed, mcp: McpCfg { allow_servers: Vec<String> } }`
  - `audit: AuditCfg { dir: PathBuf = "/var/log/saiife/audit", retention_months: u32 = 24, checkpoint_every: u64 = 1000, checkpoint_interval: Duration = 15 min, min_free_mb: u64 = 512, fsync: Fsync = Checkpoint, forward: BTreeMap<String, toml::Table> }`
  - `approval: ApprovalCfg { approvers, same_user: SameUser = Deny, timeout = 30 min, grant_ttl = 15 min }`
  - `notify: toml::Table`
  - `gateway: GatewayCfg { tcp: String = "", max_response_bytes: u64 = 5242880, upstream_timeout = 30 s }`
  - `services: BTreeMap<String, toml::Table>`
  - `scope: Vec<Scope>`
  - `example: Vec<toml::Table>`
  - `pub struct Scope { name, users: Vec<String>, projects: Vec<String>, services: Vec<String>, env: Option<String> }`
  - `pub enum Fail { Open, Closed }`, `pub enum Fsync { Always, Checkpoint }`, `pub enum SameUser { Deny, Reauth }` (all lowercase).
  - `forward`, `notify`, `services` and `example` stay raw tables: plans 10 to 12 give them types and with that their own unknown-key checks.
  - With `locked = true`, `guard.fail` is forced to `Closed`.
  - A `profile` key at the top level or in a `[[scope]]` is `Reserved` ("reserved for v3", §18).
- `duration.rs`: `pub fn parse_duration(s: &str) -> Result<Duration, String>` accepts `<n>s`, `<n>m`, `<n>h` with n ≥ 1.
- Produces (`load.rs`):
  - `pub struct LoadedPolicy { pub config: SystemConfig, pub files: Vec<(String, String)> /* file name, sha256 hex, in read order */, pub warnings: Vec<String> }`
  - `pub fn load_system(config_file: &Path) -> Result<LoadedPolicy, PolicyError>`: reads `config_file`, then `<its dir>/policy.d/*.toml` in name order. Only regular files are read, each at most 1 MiB.
  - Merge rules for drop-ins:
    - They may hold only `[guard] packs/ask`, `[guard.mcp] allow_servers`, `[services.*]`, `[[scope]]` and `[[example]]`. Anything else → `Invalid { path, detail: "<key> may only be set in config.toml" }`.
    - Arrays are joined in name order.
    - A service defined in a second file → `DuplicateService { name, first, second }`.
    - Two scopes with one name → `Invalid`.
  - `pub enum PolicyError { Io { path, source }, Parse { path, detail }, Invalid { path, detail }, Reserved { path, key }, DuplicateService { name: String, first: String, second: String }, ScopeConflict { user: String, scopes: Vec<String> /* sorted */ } }`. `Parse` keeps toml's message, which names the unknown key.
- Produces (`users.rs`):
  - `pub trait Directory { fn user(&self, name: &str) -> Option<UserEntry>; fn name_of(&self, uid: u32) -> Option<String>; fn group(&self, name: &str) -> Option<GroupEntry>; fn groups_of(&self, user: &str) -> Vec<String>; }`
  - `pub struct UserEntry { pub uid: u32, pub gid: u32 }` and `pub struct GroupEntry { pub gid: u32, pub members: Vec<String> }`.
  - `pub struct Getent;` runs `getent passwd|group <name>` and `id -Gn <user>`, so NSS/sssd users count.
  - `pub struct FixedDirectory` with `from_text(passwd: &str, group: &str)`, for tests (primary group from passwd, supplementary groups from group members).
- Produces (`scope.rs`):
  - `pub fn check_scopes(cfg: &SystemConfig, dir: &dyn Directory) -> Result<(), PolicyError>`. For each scope, collect the uids of its users entries and of the members of its `group:` entries. Any uid in two scopes → `ScopeConflict` naming the user and both scopes. Unknown users and groups are skipped.
  - `pub fn scope_for<'a>(cfg: &'a SystemConfig, dir: &dyn Directory, user: &str) -> Result<Option<&'a Scope>, PolicyError>` uses the user's current groups. It is the per-request check of §8.1 and catches primary-group-only members, which load time cannot list.
  - `pub fn load_and_check(config_file: &Path, dir: &dyn Directory) -> Result<LoadedPolicy, PolicyError>`
- Produces (`project.rs`):
  - `pub struct ServiceOverlay { pub allow: Vec<String>, pub ask: Vec<String>, pub deny: Vec<String> }`
  - `pub struct ProjectOverlay { pub version: i64, pub packs: Vec<String>, pub env: Option<String>, pub services: BTreeMap<String, ServiceOverlay> }`
  - `pub fn parse_project(bytes: &[u8]) -> Result<ProjectOverlay, PolicyError>` accepts version 1 and 2. Unknown keys are ignored here, as in v1: the project config holds no authority in locked mode.
  - `pub enum Mode { Developer, Locked }`
  - `pub struct Merged { pub packs: Vec<String>, pub services: BTreeMap<String, ServiceOverlay>, pub notes: Vec<String> }`
  - `pub fn merge_project(system_packs: &[String], p: &ProjectOverlay, mode: Mode) -> Merged`. Packs are the system packs plus the project packs: a project never removes one. In `Locked` mode the project's `allow` lists, `env` and `locked` are dropped, each with a note such as `allow for shopify ignored in locked mode`. Every list is deduplicated and keeps its order.
- Produces (`effective.rs`):
  - `pub struct PackInfo { pub id: String, pub version: u32, pub default_on: bool }`
  - `pub fn active_packs(cfg: &SystemConfig, catalog: &[PackInfo], project: Option<&Merged>) -> (Vec<PackInfo>, Vec<String>)`: default-on, plus `[guard] packs`, plus project packs, sorted by id. Unknown ids produce warnings and are skipped.
  - `pub fn effective_policy(cfg: &SystemConfig, packs: &[PackInfo], project: Option<&Merged>) -> serde_json::Value` = `{"saiife_policy":1,"system":<cfg as JSON; durations as whole seconds>,"packs":[{"id","version"}],"project":<Merged without notes, or null>}`.
  - `pub fn canonical_json(v: &Value) -> String`: compact, with object keys sorted recursively by byte order.
  - `pub fn policy_hash(v: &Value) -> String` = `"sha256:" + hex(sha256(canonical_json(v)))`.

- [ ] **Step 1: Failing tests.**
  - `tests/load.rs`:
    - `spec_example_parses`: the fixtures give `checkpoint_every` 1000, `checkpoint_interval` 900 s, `min_free_mb` 512, `fsync` Checkpoint, `daemon.user` `"saiife"`, scope `shop-agent` with users `["agent-shop"]`, `guard.packs` `["db.postgres"]`, `services` holding `shopify`, `files` naming both files with 64-hex hashes.
    - `defaults_when_sections_missing`: `version = 2\nlocked = true\n` → the same defaults, and `fail` Closed.
    - `unknown_key_is_error`: `[audit]\ncheckpoint_evry = 5` → `Parse` whose detail contains `checkpoint_evry`.
    - `version_must_be_2`.
    - `profile_is_reserved`: top level and inside a scope.
    - `locked_forces_fail_closed`: `fail = "open"` + `locked = true` → Closed.
    - `dropins_join_guard_arrays_in_name_order`: `20-b.toml` packs `["y"]`, `10-a.toml` packs `["x"]` → `["db.postgres","x","y"]`.
    - `service_defined_twice_is_error`: the message names both files.
    - `dropin_cannot_set_daemon`.
    - `symlinked_dropin_is_refused`.
  - `scope.rs` (with `FixedDirectory`):
    - `scope_conflict_direct`: alice in scopes `a` and `b` → `ScopeConflict { user: "alice", scopes: ["a","b"] }`.
    - `scope_conflict_through_group`: `a` users `["alice"]`, `b` users `["group:devs"]`, devs members `alice` → conflict.
    - `disjoint_scopes_ok`.
    - `scope_for_sees_primary_group`: bob's primary group is devs, with no member line → `scope_for("bob")` gives `b`; listed in two scopes → `ScopeConflict`.
  - `project.rs`:
    - `locked_merge_is_add_only`: system `["core.git","db.postgres"]`, project `packs = []` plus `[services.shopify] allow=["x:read"] deny=["products:write"] ask=["y:write"]`, `env = "dev"` → packs still `["core.git","db.postgres"]`; shopify allow empty, deny and ask kept; 2 notes.
    - `developer_merge_keeps_allow`.
    - `v1_file_parses`: `version = 1\npacks = ["db.postgres"]\nlocked = false\n`.
  - `effective.rs`:
    - `canonical_json_is_exact`: `{"b":{"d":1,"c":[{"z":0,"y":1}]},"a":""}` → `{"a":"","b":{"c":[{"y":1,"z":0}],"d":1}}`.
    - `hash_ignores_toml_order`: the same config with sections reordered gives the same hash.
    - `hash_changes_with_pack_version`.
    - `hash_changes_with_project_deny`.
    - `unknown_pack_is_warning`.
- [ ] **Step 2:** `cargo test -p saiife-policy` fails.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean. `cargo tree -e normal -p saiife-policy | grep -c tokio` prints `0`.
- [ ] **Step 5:** Commit `feat(policy): /etc config and drop-ins, one scope per uid, add-only project merge, policy hash`.

### Task 4: `ChainWriter` (single writer) and clock rollback (carry-overs 3, 4)

**Files:**
- Modify: `crates/audit/src/chain.rs`, `crates/audit/src/store.rs` (`open_append_mode(path, mode: u32)`; `open_append` stays 0600), `crates/audit/src/lib.rs`
- Test: unit tests in `chain.rs`

**Interfaces:**
- Consumes: plan 8's `find_tail`, `genesis`, `target_file`, `sha256_hex`, `ZERO_PREV`, `LOCK_FILE`.
- Produces:
  - `pub struct WriterOptions { pub mode: String, pub saiife: String, pub genesis_key: Option<String> /* "ed25519:<spki b64>" */ }`
  - `pub struct ChainWriter` (private fields: dir, lock `File`, head `Option<(u64, String)>`, chain id, host, current file, records since last checkpoint)
  - `ChainWriter::open(dir: &Path, opts: WriterOptions) -> io::Result<ChainWriter>`:
    - creates `dir` 0750 if missing, and never changes the mode of an existing dir (2750 under systemd);
    - takes `.chain.lock` with one `try_lock` and no wait. If the lock is held: `io::Error::other("another process holds the audit chain lock (<path>)")`;
    - holds the lock until drop;
    - finds the tail once, with no `MAX_SCAN` budget: it scans back to the last chained line.
  - `pub fn append(&mut self, rec: Record) -> io::Result<u64>`:
    - sets `seq`, `prev`, `host`;
    - the target is `max(record's month file, current newest file)` with no one-month limit, because the daemon owns the dir and nothing else can plant a file;
    - writes genesis first if there is no chain: `mode` from opts, plus `key` = `genesis_key` in `extra` when set;
    - files are created 0640;
    - one `write_all` per record; updates head.
  - `pub fn head(&self) -> Option<(u64, &str)>`, `pub fn chain_id(&self) -> Option<&str>`, `pub fn host(&self) -> Option<&str>`
  - `pub fn sync(&self) -> io::Result<()>` (`sync_data` of the current file)
  - **Developer mode, carry-over 3:** `target_file` also follows the newest month file when it is more than one month ahead, provided its last chained line's `ts` starts with that file's own `YYYY-MM`. The chain itself wrote that file, so it was not planted. A planted `9999-12.jsonl` that is empty, v1, or holds a line with another month is still not followed.

- [ ] **Step 1: Failing tests** in `chain.rs`:
  - `writer_genesis_carries_key_and_mode`: genesis line has `"mode":"locked"`, `"key":"ed25519:abc"`, `seq` 0.
  - `writer_continues_existing_chain`: 3 × `append_chained`, then `ChainWriter::open` + 2 appends → seqs 4 and 5; `verify(dir).exit_code() == 0`.
  - `writer_follows_newest_file_after_rollback`: a record at 2026-12, then one at 2025-01 → both in `2026-12.jsonl`, verify 0.
  - `second_writer_is_refused`: the error text contains `holds the audit chain lock`.
  - `writer_holds_lock_so_dev_append_goes_unchained`: with the writer open, `append_chained` → `written_unchained(&e).is_some()`.
  - `writer_files_are_0640`.
  - `writer_head_is_hash_of_last_line`.
  - `clock_rollback_over_a_month_stays_on_the_chain`: `append_chained` at 2026-12 twice, then at 2026-09 → the third lands in `2026-12.jsonl` with seq 3; verify 0.
  - `planted_far_future_file_is_not_followed`: an empty `9999-12.jsonl` and one holding a `ts` 2026-10 line are both ignored.
- [ ] **Step 2:** `cargo test -p saiife-audit chain` fails.
- [ ] **Step 3:** Implement. Factor the shared tail and genesis code so that `append_chained` and `ChainWriter` share it.
- [ ] **Step 4:** `cargo test --workspace`, clippy clean.
- [ ] **Step 5:** Commit `feat(audit): single-writer ChainWriter; keep the chain across clock rollbacks`.

### Task 5: Signed checkpoints, key rotation, `verify` checks signatures

**Files:**
- Create: `crates/audit/src/sign.rs`; `crates/audit/tests/fixtures/v2-locked/2026-11.jsonl` (generated once, committed)
- Modify: `crates/audit/Cargo.toml` (`ed25519-dalek`, `base64`, `zeroize` per Global Constraints), `crates/audit/src/chain.rs`, `crates/audit/src/verify.rs`, `crates/audit/tests/tamper.rs`, `crates/audit/tests/v010_reader.rs`, `crates/cli/src/audit_cmd.rs` (verify output), `.github/workflows/ci.yml` (`compat-v010` also reads `v2-locked`)
- Test: `sign.rs` unit tests, `tamper.rs`, `v010_reader.rs`, `crates/cli/tests/audit_verify.rs`

**Interfaces:**
- Consumes: Task 4 `ChainWriter`, `WriterOptions`.
- Produces (`sign.rs`):
  - `pub struct AuditKey` wraps `ed25519_dalek::SigningKey` (zeroized on drop).
  - `AuditKey::generate() -> io::Result<AuditKey>`: a 32-byte seed from `getrandom`.
  - `AuditKey::load_or_create(path: &Path) -> io::Result<(AuditKey, bool /* created */)>`:
    - the file holds exactly 32 raw bytes, mode 0600;
    - it is opened with `O_NOFOLLOW`;
    - it is created with `O_EXCL`, parent dir 0700;
    - any other size or mode, or a symlink → `Err` naming the path and the problem.
  - `AuditKey::save_new(path: &Path, key: &AuditKey) -> io::Result<()>`: tmp file 0600, then rename.
  - `pub fn spki(&self) -> String` = `"ed25519:" + base64(30 2a 30 05 06 03 2b 65 70 03 21 00 ‖ pk)`.
  - `pub fn fingerprint(&self) -> String` = `"ed25519:" + sha256_hex(pk)`.
  - `pub fn sign_b64(&self, msg: &[u8]) -> String`
  - `pub fn fingerprint_of(spki: &str) -> Option<String>`
  - `pub fn verify_b64(spki: &str, msg: &[u8], sig_b64: &str) -> bool`
  - `pub fn checkpoint_message(chain: &str, head_seq: u64, head: &str, ts: &str) -> String` = `format!("saiife-checkpoint-v1\n{chain}\n{head_seq}\n{head}\n{ts}")`
  - `pub fn key_rotate_message(chain: &str, head_seq: u64, head: &str, new_key: &str, ts: &str) -> String` = `format!("saiife-key-rotate-v1\n{chain}\n{head_seq}\n{head}\n{new_key}\n{ts}")`
- Produces (`chain.rs`):
  - `WriterOptions` gains `key: Option<AuditKey>`. `genesis_key` is derived from it.
  - `ChainWriter::open` finds the key in force, from the newest `genesis` or `key_rotate` `key`/`new_key`. If that is not this key's `spki`, it writes a `key_rotate` with `sig: null`, `reason: "previous signing key missing"`.
  - `pub fn checkpoint(&mut self, ts: OffsetDateTime) -> io::Result<Option<u64>>` returns `None` when no record has been written since the last checkpoint. Otherwise it writes `kind "checkpoint"`, `tool "checkpoint"`, `agent`/`project`/`input` `""`, `decision` allow, `head_seq` = current head seq, `head` = current head hash, `key` = fingerprint, `sig` = signature over `checkpoint_message` with the record's own `ts` string.
  - `pub fn rotate_key(&mut self, new: AuditKey) -> io::Result<u64>`: `kind "key_rotate"`, `key` = old fingerprint, `new_key` = new spki, `head_seq`/`head`, `sig` by the old key.
  - `pub fn records_since_checkpoint(&self) -> u64`
  - `pub fn startup_check(&self, records: usize) -> StartupCheck` with `pub struct StartupCheck { pub recent: Result<(), String> /* first break, described */, pub last_checkpoint: Option<u64>, pub last_clean_stop: bool }`. It re-verifies the last `records` (1 000 from the daemon) chained lines and the newest checkpoint among them against the key in force. `last_clean_stop` is true when the last non-checkpoint record is `kind "daemon"` with `event "stop"`.
- Produces (`verify.rs`):
  - `VerifyReport` gains `pub last_checkpoint: Option<(u64, String)> /* seq, ts */` and `pub key: Option<String> /* fingerprint in force at the end */`.
  - `BreakKind` gains `BadCheckpoint`, `CheckpointWithoutKey`, `BadKeyRotate`, `UnsignedKeyRotate`.
  - Algorithm, added to plan 8's:
    - The genesis `key` sets the key in force.
    - A checkpoint needs a key, else `CheckpointWithoutKey`. It also needs `head_seq == seq - 1`, `head == prev`, `key == fingerprint_of(key in force)` and a valid `sig`, else `BadCheckpoint`.
    - A `key_rotate` whose `sig` is valid under the old key switches the key. `sig` null → `UnsignedKeyRotate`, then switch. An invalid sig → `BadKeyRotate`, and the key is not switched.

| BreakKind | `describe()` |
|---|---|
| BadCheckpoint | `checkpoint does not match its signature or the records before it (records were changed, or the checkpoint is forged)` |
| CheckpointWithoutKey | `checkpoint in a chain that has no signing key` |
| BadKeyRotate | `signing key change not signed by the previous key` |
| UnsignedKeyRotate | `signing key replaced without the previous key (the daemon's key file was lost or removed)` |

- [ ] **Step 1: Failing tests.**
  - `sign.rs`:
    - `checkpoint_message_is_exact`: `checkpoint_message("c", 5, "ab", "2026-11-02T08:30:00.000Z") == "saiife-checkpoint-v1\nc\n5\nab\n2026-11-02T08:30:00.000Z"`.
    - `spki_has_spec_prefix`: starts with `ed25519:MCowBQYDK2VwAyEA`, base64-decodes to 44 bytes.
    - `sign_verify_round_trip_and_tamper`.
    - `key_file_is_0600_32_bytes`.
    - `key_file_wrong_mode_refused` (0644).
    - `key_file_wrong_size_refused`.
    - `key_file_symlink_refused`.
  - `tamper.rs`, each with a keyed `ChainWriter`, 25 guard records and a checkpoint:
    - `checkpoints_verify`: exit 0, `checkpoints` 1, `last_checkpoint.0` 26.
    - `forged_checkpoint_signature`: change one base64 char of `sig` → first break `BadCheckpoint` at that line.
    - `rewritten_history_with_other_key`: rebuild the whole log with key B but keep A's genesis key, recomputing every `prev` → `BadCheckpoint`.
    - `key_rotation_verifies`: rotate, 3 records, checkpoint → exit 0, `key` = new fingerprint.
    - `key_rotate_signed_by_wrong_key` → `BadKeyRotate`.
    - `lost_key_is_unsigned_rotate`: open with A, drop, open with B → exit 1, `UnsignedKeyRotate`; a later checkpoint by B verifies.
    - `checkpoint_in_developer_chain_is_break` → `CheckpointWithoutKey`.
    - `startup_check_reports_edited_recent_line`.
    - `startup_check_ok_and_clean_stop`.
  - `v010_reader.rs`: `v010_reader_parses_locked_fixture`, covering every line of `v2-locked/2026-11.jsonl` (genesis with key, 3 guard, checkpoint, key_rotate, checkpoint, `daemon` stop).
  - `audit_verify.rs`: `verify_prints_last_checkpoint`. On the fixture dir, stdout holds `last checkpoint: seq ` and `key ed25519:`, and no `developer mode:` line.
- [ ] **Step 2:** Run; the tests fail.
- [ ] **Step 3:** Implement. Generate the fixture with a throwaway test (`#[ignore]`, run once), commit it as a static file, and add `tests/fixtures/v2-locked` to the `compat-v010` job's loop (same assertions as for `v2`).
- [ ] **Step 4:** `cargo test --workspace`, clippy clean.
- [ ] **Step 5:** Commit `feat(audit): Ed25519 checkpoints and key rotation; verify checks signatures`.

### Task 6: `crates/daemon` — control server, audit writer, checkpoints, reload, stop

**Files:**
- Create: `crates/daemon/Cargo.toml` (`saiife-daemon`; deps: `saiife-audit`, `saiife-ipc`, `saiife-policy`, `tokio`, `serde_json`, `time`; unix: `rustix = { version = "1", features = ["fs", "process", "net"] }`)
- Create: `crates/daemon/src/{lib.rs, start.rs, server.rs, ops.rs, writer.rs, limits.rs, disk.rs, notify.rs}`
- Modify: `crates/cli/src/main.rs` (`Daemon { #[arg(long)] system: bool, #[arg(long)] user: bool, #[arg(long)] config: Option<PathBuf>, #[arg(long = "state-dir")] state_dir: Option<PathBuf> }`), `crates/cli/Cargo.toml`, `.github/workflows/ci.yml` (no-tokio gate step)
- Create: `crates/cli/tests/common/daemon.rs` (test helper), `crates/cli/tests/daemon.rs`

**Interfaces:**
- Consumes: Task 2 (frames, `peer_cred`, `comm`, `ErrorCode`, ops), Task 3 (`load_and_check`, `Getent`, `Directory`, `active_packs`, `effective_policy`, `policy_hash`, `PackInfo`), Tasks 4 and 5 (`ChainWriter`, `AuditKey`, `StartupCheck`).
- Produces:
  - `pub struct DaemonOptions { pub config: PathBuf, pub state_dir: PathBuf, pub catalog: Vec<PackInfo>, pub directory: Box<dyn Directory + Send + Sync> }`
  - `pub fn run(opts: DaemonOptions) -> std::process::ExitCode` builds a `current_thread` tokio runtime.
  - CLI dispatch rules:
    - `saiife daemon` without `--system` → `saiife: use \`saiife daemon --system\` (personal broker mode, --user, comes after v2.0)`, exit 2.
    - `--user` → the same message.
    - `catalog` comes from `Catalog::builtin()` (id, version, default_on).
  - Writer API (`writer.rs`):
    - `pub struct WriterHandle { tx: std::sync::mpsc::SyncSender<Job> }` with `pub async fn append(&self, rec: Record) -> Result<u64, String>`. A `tokio::sync::oneshot` carries the seq back.
    - The writer is one dedicated thread that owns the `ChainWriter`. It is fed by `sync_channel(1024)` and loops on `recv_timeout(1 s)`. One thread is one writer, so records are ordered and the chain needs no lock (§4.1); file IO stays off the runtime.
    - Jobs: `Append`, `Checkpoint`, `RotateKey`, `Stop`.
    - It writes a checkpoint after every `checkpoint_every` records, and every `checkpoint_interval` when records came in.
    - `fsync = "always"` → `sync()` before each ack. `"checkpoint"` → `sync()` at each checkpoint and on every 1 s tick that saw writes.
  - `limits.rs`: `pub struct Limits` with `try_begin(uid, now: Instant) -> Result<InFlight, ErrorCode::Busy>`. At most 64 in flight per uid; a token bucket of 1000 per second per uid, burst 1000. `InFlight` decrements on drop.
  - `disk.rs`: `pub fn free_mb(dir: &Path) -> io::Result<u64>` (`rustix::fs::statvfs`, `f_bavail * f_frsize`), cached for 1 s.
  - `notify.rs`: `pub fn ready()`. When `NOTIFY_SOCKET` is set (a path, or `@abstract`), it sends `READY=1` as one `UnixDatagram`; otherwise it does nothing.

**Startup** (`start.rs`, in order; §6.2):
1. Refuse to start (exit 2, one stderr line each) when:
   - not Linux;
   - euid 0: `the daemon must run as the daemon user, not root`;
   - euid ≠ the uid of `[daemon] user` per `Directory`: `the daemon runs as <name> per [daemon] user, not uid <n>`;
   - the config lacks `locked = true`.
   An unreadable or invalid config does not count here: the daemon starts on §8.1 defaults (step 3).
2. `rustix::process::set_dumpable_behavior(NotDumpable)`.
3. `load_and_check(config, directory)`. If that fails, keep going with no policy: audit is accepted (connectors would be denied from plan 10 on). Paths come from the defaults, and a `kind "daemon"`, `event "policy_invalid"`, `reason` = error text record is written after step 5.
4. `AuditKey::load_or_create(<state>/keys/audit.ed25519)`. An error → exit 2 with the message.
5. `ChainWriter::open(audit.dir, mode "locked", key)`, then `startup_check(1000)`. A held lock → exit 2.
6. Write `kind "daemon"`, `event "start"`, `previous_clean_stop`, `chain_check` (`"ok"` or `"broken: <describe>"`, with a warning on stderr; the daemon continues from the physical tail). Then, with a policy, write `kind "policy"`, `result "loaded"`, `files` `[{"name","sha256"}]`, `policy` = hash.
7. `socket_dir`: create 0755 if missing. Remove a stale `saiife.sock` only if it is a socket owned by this uid. Bind, then chmod 0666.
8. `notify::ready()`, then serve.

**Daemon-written records:** `v` 2, `mode "locked"`, `uid`/`user` = the daemon's own, `agent`/`project` `""`, `tool` = kind, `input` = short summary (`start`, `stop`, `loaded`, …), `decision` allow, `policy` = the current hash or absent.

**Connections** (`server.rs`):
- Read `peer_cred` once per connection.
- Each frame: 4-byte header, then body, with 5 s to complete a frame once its first byte arrived. No timeout while idle between frames.
- The first frame must be `hello`, else `hello_required` and close.
- A bad frame → `bad_frame` answer with id 0, then close.
- Unknown op → `unknown_op`.
- Every op except `hello` runs inside `Limits::try_begin`.

**Ops** (`ops.rs`):
- `hello` → `{proto: 1, daemon: <version>, mode: "locked"}`.
- `audit.append { rec }`:
  - `rec` must parse as `Record` with `kind == "guard"`, else `forbidden`;
  - free space < `min_free_mb` and peer uid ≠ the daemon's own → `low_disk`;
  - the daemon sets `v` 2, `mode "locked"`, `uid` = peer uid, `user` = `name_of(uid)` (cached per uid), `extra["peer"] = {"pid", "comm"}`, and clears `seq`/`prev`/`host`;
  - after the writer → `{seq}`;
  - a writer error → `internal`.
  - Each refusal for `busy` or `low_disk` writes at most one `daemon` record per uid per minute (`event "rate_limited"` or `"low_disk"`, `reason` naming the uid).
- `status` → `{mode, daemon, chain, head_seq, head, last_checkpoint_seq, policy (hash or null), policy_ok, uptime_s}`.
- `audit.rotate_key` (spec addition, see Open Questions): admin only, meaning uid 0 or a member of an `[admin] groups` group via `groups_of`; else `forbidden`. It saves the new key with `save_new`, writes `key_rotate` and answers `{seq, key: <fingerprint>}`.

**Signals:**
- SIGHUP: reload. An invalid policy is refused: write `kind "policy"`, `result "rejected"`, `reason`, and keep the old one. A valid policy is swapped in one step and a `result "loaded"` record is written.
- SIGTERM and SIGINT: stop accepting, write `daemon`/`stop`, a checkpoint and `sync`, remove the socket, exit 0.

- [ ] **Step 1: Failing unit tests.**
  - `limits.rs`: `rate_bucket_allows_1000_per_second_then_busy` (injected `Instant`s), `inflight_cap_is_64_per_uid` (65th `Busy`; another uid unaffected; drop frees one).
  - `disk.rs`: `floor_refuses_only_non_daemon_uids`. The check is factored as `fn disk_gate(free_mb: u64, min_free_mb: u64, peer_uid: u32, daemon_uid: u32) -> Result<(), ErrorCode>`.
  - `notify.rs`: `ready_sends_ready_1`, using a bound datagram socket in a tempdir and `NOTIFY_SOCKET` set for the call (pass the value in as a parameter; no global env mutation).
  - `writer.rs`: `checkpoint_after_every_n`. With `checkpoint_every` 5 and 12 appends there are 2 checkpoints; `fsync` mode is honoured (`Always` calls `sync` per append, counted through a test hook).
- [ ] **Step 2: Failing integration tests** in `crates/cli/tests/daemon.rs` (Linux only). Helper `common::daemon::TestDaemon::start(opts)`:
  - writes `<tmp>/etc/config.toml`: `version = 2`, `locked = true`, `[daemon] user = <own user name>`, `socket_dir = <tmp>/run`; `[audit] dir = <tmp>/audit`, `checkpoint_every`/`checkpoint_interval` from opts;
  - spawns `saiife daemon --system --config <tmp>/etc/config.toml --state-dir <tmp>/state` with `HOME` and `SAIIFE_*` pointed at `<tmp>`;
  - waits at most 5 s for the socket;
  - kills the daemon on drop;
  - offers `client()` (a `saiife_ipc::Client`) and `verify()`, which runs `saiife audit verify` with `SAIIFE_AUDIT_DIR=<tmp>/audit`.
  Tests:
  - `daemon_requires_system_flag`: `saiife daemon` → exit 2, stderr names `--system`.
  - `daemon_refuses_wrong_user`: config `user = "root"` → exit 2, stderr contains `per [daemon] user`.
  - `daemon_refuses_bad_key_file`: a 0644 key → exit 2, stderr names `audit.ed25519`.
  - `hello_answers_proto_1_and_mode_locked`.
  - `append_returns_increasing_seq_and_chain_verifies`: 10 appends; `verify` exit 0; each guard record has `uid` = own uid, `mode` `"locked"`, `peer.pid` = the test process pid.
  - `append_overwrites_identity_fields`: client-sent `uid` 0, `user` `"root"`, `seq` 99, `host` `"x"`, `mode` `"developer"` are all replaced.
  - `append_non_guard_kind_is_forbidden`: `connector`, `checkpoint` and `genesis` → `forbidden`; nothing written.
  - `first_frame_must_be_hello`.
  - `oversized_frame_closes_connection`: header 1_048_577 → EOF; a new client still gets an ack.
  - `half_frame_client_does_not_block_others`: one client sends 2 bytes and stalls; another client's append is acked within 1 s; the staller is closed after about 5 s.
  - `parallel_clients_keep_one_chain`: 8 threads × 50 appends → 400 distinct seqs; `verify` exit 0.
  - `checkpoint_on_interval`: interval `"1s"`, 1 append, wait 2.5 s → exactly 1 checkpoint; wait 2 s more with no appends → still 1.
  - `sigterm_writes_stop_and_checkpoint`: the last two records are `daemon`/`stop` and a checkpoint; exit 0; socket removed; `verify` exit 0 with `checkpoints` ≥ 1.
  - `restart_after_kill_says_unclean`: SIGKILL, start again → `daemon`/`start` with `previous_clean_stop` false; same `chain` id; `verify` exit 0.
  - `second_daemon_same_dirs_refused`: exit 2, stderr contains `holds the audit chain lock`.
  - `invalid_policy_at_start_still_accepts_audit`: an unknown key → `daemon`/`policy_invalid` record; append acked; `status.policy_ok` false.
  - `sighup_reload_rejects_invalid_and_loads_valid`: invalid edit + SIGHUP → `policy` `result "rejected"`, `status.policy` unchanged; valid edit + SIGHUP → `result "loaded"`, new hash.
  - `rotate_key_needs_admin`: without `[admin] groups` → `forbidden`; with `groups = [<own primary group>]` → ok; `verify` exit 0 and the report's `key` is the new fingerprint.
- [ ] **Step 3:** Run; the tests fail.
- [ ] **Step 4:** Implement. Add the CI step `no tokio in hook crates` (ubuntu `test` job): `test "$(cargo tree -e normal -p saiife-guard -p saiife-audit -p saiife-policy -p saiife-ipc | grep -c tokio)" = 0`.
- [ ] **Step 5:** `cargo test --workspace` (Linux and macOS: the macOS build compiles the daemon stubs only), clippy clean, the no-tokio gate prints `0`.
- [ ] **Step 6:** Commit `feat(daemon): control server, single audit writer, signed checkpoints, reload and stop`.

### Task 7: `saiife check --managed` — worker child, daemon ack, fail closed; bench

**Files:**
- Create: `crates/cli/src/eval.rs` (shared judging + the `__eval` worker), `crates/cli/src/check_managed.rs`
- Modify: `crates/cli/src/check.rs`: move `expand_targets`, `judge_paths`, `rank` and the classify-to-decision mapping into `eval.rs`; the developer path calls them unchanged.
- Modify: `crates/cli/src/main.rs`: `Check` gains `#[arg(long)] managed: bool` and `#[arg(long = "system-config", hide = true)] system_config: Option<PathBuf>`; add the hidden subcommand `#[command(name = "__eval", hide = true)] Eval`.
- Modify: `scripts/bench-check.sh` (`--managed`), `CHANGELOG.md` (`## Unreleased`)
- Test: `crates/cli/tests/check_managed.rs`; `eval.rs` unit tests

**Interfaces:**
- Consumes: Task 1 `read_config_bytes`, `find_project_root`; Task 2 `Client`, `system_uid`; Task 3 `load_system`, `parse_project`, `merge_project(Mode::Locked)`, `active_packs`, `effective_policy`, `policy_hash`; Task 6 `TestDaemon`.
- Produces (`eval.rs`):
  - `#[derive(Serialize, Deserialize)] pub struct EvalRequest { pub payload: String, pub packs: Vec<String>, pub budget_ms: u64 }`
  - `#[derive(Serialize, Deserialize)] pub struct EvalAnswer { pub verdict: Verdict, pub input: String, pub tool: Option<String>, pub pack: Option<String>, pub rule: Option<String>, pub reason: Option<String> }`
  - `pub enum Verdict { Allow, Deny, Unjudged }`, snake_case. `Unjudged` covers a payload error, an over-budget engine, an unresolvable path, a glob too large, or a shell command over `MAX_PAYLOAD_BYTES`.
  - `pub fn judge(payload: &str, packs: &[String], budget: Duration) -> EvalAnswer`. A tool the guard does not judge → `Allow` with reason `tool not judged` (§6.1.1).
  - `pub fn worker_main() -> ExitCode`: reads one `EvalRequest` JSON from stdin (at most 64 MiB + envelope), writes one `EvalAnswer` JSON to stdout, exit 0. In debug builds only, `SAIIFE_EVAL_FAULT=abort|segv|hang|overflow` triggers the fault, as a test seam: `std::process::abort`, `rustix::process::kill_process(getpid, Signal::SEGV)`, a 10 s sleep, unbounded recursion. Release builds compile it out (`#[cfg(debug_assertions)]`).
- Produces (`check_managed.rs`): `pub fn run(agent: &str, system_config: &Path) -> ExitCode`, with this flow (§6.1.2):
  1. Read stdin with the `PARSE_MAX_BYTES` cap. Over the cap or unreadable → deny.
  2. `load_system(system_config)`. An error, or `locked` not true → deny (`saiife policy could not be loaded: …`).
  3. Find the project from the payload `cwd`, then `read_config_bytes`, `parse_project`, `merge_project(.., Mode::Locked)`. An invalid project config is ignored with a stderr warning: the system policy alone applies.
  4. Compute the pack ids with `active_packs`, and `policy` with `policy_hash(effective_policy(..))`.
  5. Spawn the worker: `std::env::current_exe()` + `__eval`. Every `SAIIFE_*` variable is removed (`env_remove`), except `SAIIFE_EVAL_FAULT` in debug builds. `HOME`, `USER` and `PATH` are kept for path rules. Write `EvalRequest` to its stdin and close it.
  6. While the worker runs, `Client::connect([daemon] socket_dir, system_uid([daemon] user), now + 2 s)`.
  7. Worker answer. A non-zero exit, a signal, unparsable output, or no answer within 3 s (kill it) → `error_denied`, reason `guard worker failed (<signal or status>)`.
  8. Build the record. `Allow` → `allow`; `Deny` → `deny`; `Unjudged` → `error_denied` with the worker's reason. `mode "locked"`, `policy`, `permission_mode`. No `uid`/`user`/`host`/`seq`/`prev`.
  9. `audit.append` with deadline send + 2 s. On `Ok(seq)`, answer per decision. Connect failure, `Refused`, `Timeout` or `Protocol` → deny. The reason goes to stderr only: no record, because nobody could write it (§6.1.2).
  10. Answers: allow → exit 0, nothing on stdout or stderr. Deny → exit 2 and stderr `BLOCKED by <pack>: <reason>`. Error → exit 2 and stderr `saiife: BLOCKED (fail closed): <reason>`.
  11. The whole run is inside `catch_unwind`: a panic → exit 2, `saiife: BLOCKED (fail closed): saiife crashed`.
- The managed path never reads `SAIIFE_AUDIT_DIR` or `SAIIFE_DATA_DIR`, and never opens `.chain.lock`.
- `--managed` implies `--hook-exit`. Lockdown and `ask` (§6.1.2) come in plan 11, the `[guard.mcp]` deny and `--event config-change` in 9b.

- [ ] **Step 1: Failing tests.**
  - `eval.rs`:
    - `judge_matches_developer_engine`: for `rm -rf /`, `ls` and a Read of `~/.ssh/id_rsa`, `judge` gives the same pack and rule as the dev path.
    - `oversized_shell_is_unjudged`: a 300 KiB command → `Unjudged`.
    - `untouched_tool_is_allow_not_judged`.
  - `check_managed.rs` (Linux), with a running `TestDaemon` and the payload fixtures `crates/cli/tests/fixtures/*`:
    - `managed_allow_is_silent_and_recorded`: `ls` → exit 0, empty stdout and stderr. The daemon log has a guard record with `mode` `"locked"`, `policy` matching `^sha256:[0-9a-f]{64}$`, `uid` own, `seq` ≥ 1.
    - `managed_deny_exit_2`: `rm -rf /` → exit 2, stderr starts `BLOCKED by core.filesystem`, record `deny`.
    - `daemon_down_denies`: no daemon → exit 2, stderr contains `fail closed`, nothing written anywhere under the test's `SAIIFE_AUDIT_DIR`.
    - `daemon_not_acking_denies`: a fake daemon (own std listener in a dir owned by the test user) answers `hello` and never acks → exit 2; elapsed between 2.0 and 3.5 s.
    - `daemon_closes_after_hello_denies`.
    - `socket_owner_mismatch_denies`: config `user = "root"`, socket dir owned by the test user → exit 2, stderr names the owner check; the fake listener never sees a connection.
    - `worker_abort_denies`, `worker_segv_denies`, `worker_overflow_denies`: each → exit 2, and the daemon record is `error_denied` with reason starting `guard worker failed`.
    - `worker_hang_denies_after_3s`: elapsed between 3.0 and 4.5 s.
    - `managed_ignores_saiife_env`: `SAIIFE_AUDIT_DIR` and `SAIIFE_DATA_DIR` set to a tempdir → that dir stays empty and has no `.chain.lock`; the record is in the daemon's dir.
    - `managed_large_shell_payload_denies`: 300 KiB → exit 2, record `error_denied`.
    - `project_config_is_add_only`: project `packs = []` → `rm -rf /` still denied; project `packs = ["db.postgres"]` → `psql -c 'DROP DATABASE prod'` denied.
    - `policy_hash_changes_with_project_deny`: two calls with different `[services.x] deny` give different `policy`.
    - `unparseable_system_config_denies`.
    - `developer_check_untouched`: no `--managed`, same payload as `managed_deny_exit_2` → dev behaviour, record `mode` `"developer"` in `SAIIFE_AUDIT_DIR`. The existing `check_*` suites stay unchanged and green.
- [ ] **Step 2:** Run; the tests fail.
- [ ] **Step 3:** Implement. Keep all `--managed` code out of the developer path's imports, so the developer path's startup does not grow.
- [ ] **Step 4:** `scripts/bench-check.sh --managed [N]`:
  - writes the `TestDaemon`-style config under its scratch dir;
  - starts `saiife daemon --system --config …` in the background, with a trap that kills it;
  - runs N `saiife check --managed --system-config … --agent claude` calls per payload;
  - prints `median` and `p95` ms per call.
  Without `--managed`, the output is unchanged.
- [ ] **Step 5: Verify:**
  - `cargo test --workspace`, clippy clean;
  - `scripts/bench-check.sh 50` on `main` and on this branch: the dev median is within +1 ms;
  - `scripts/bench-check.sh --managed 50`: p95 < 40 ms.
  Put all three outputs in the PR description.
- [ ] **Step 6:** CHANGELOG `## Unreleased`:
  - `saiife daemon --system` (single audit writer, signed checkpoints);
  - `saiife check --managed` (worker process, fails closed);
  - `audit verify` checks checkpoint signatures;
  - project config reads are bounded and race-free in `init` and `status`.
  Note that locked mode is not installable until plan 9b.
- [ ] **Step 7:** Commit `feat(check): --managed hook path with worker and daemon ack, failing closed; managed bench`.

---

## Open questions settled in this plan

1. **Shell payload cap.** §6.1.2 says to deny shell payloads over 1 MiB. The engine judges commands only up to `MAX_PAYLOAD_BYTES` (256 KiB), so `--managed` denies (`error_denied`) anything the engine cannot judge, from 256 KiB up.
2. **Deadlines.** The worker gets 3 s and the ack 2 s, both verbatim (§6.1.2). §9.3's "internal deadline of 3 s" is read as the worker deadline. The worst case is about 5 s, inside the 10 s hook timeout.
3. **Checkpoint key fields.** `key` in a checkpoint is `ed25519:<sha256 hex of the 32-byte public key>`. The spec leaves `<fingerprint>` open.
4. **Key rotation.** `key_rotate` signs `saiife-key-rotate-v1\n<chain>\n<head_seq>\n<head>\n<new key spki>\n<ts>` with the old key, and carries `key`, `new_key` and `sig`. It is triggered by a new admin-only op, `audit.rotate_key` (not in the §8.7 table). A lost key file shows as an unsigned `key_rotate`, which `verify` reports. The daemon refuses a key file with the wrong mode or size, or a symlink.
5. **Audit writer.** "One task fed by a bounded channel" (§4.1) is built as one dedicated thread fed by a `sync_channel(1024)`. That keeps the same ordering, and blocking file IO stays off the tokio runtime.
6. **Test overrides.** `daemon --config/--state-dir` and the hidden `check --system-config` exist for tests. Managed hook files (9b) never pass them. An agent calling `check --system-config <own>` itself can only add guard claims, which §9.4 already allows.
7. **Peer credentials.** 9a uses `SO_PEERCRED` only; the pid is attribution (`peer`). `SO_PEERPIDFD` and the start-time check belong to the process-tree walk for sessions (§6.9.3, plan 10).
8. **Scope overlap at load time** sees explicit users and supplementary group members, through `getent`. Primary-group-only members are caught by the per-request `scope_for`, which plan 10 uses for connector calls.
9. **`policy.d` drop-ins** may set only `[guard]` packs/ask, `[guard.mcp]`, `[services.*]`, `[[scope]]` and `[[example]]`. Everything else belongs in `config.toml`. The spec names only arrays and services.
10. **Invalid project config in locked mode** is ignored with a warning. Add-only means the system policy alone still applies, so failing closed on the whole agent is not needed.
11. **`saiife daemon --system` refuses a config without `locked = true`.** The daemon serves only locked mode in v2.0; personal broker mode comes after v2.0.
12. **Refusal records.** `busy` and `low_disk` refusals are recorded at most once per uid per minute, so a flood (A9) cannot itself flood the log.
13. **Deferred to later plans.** `retention_months` deletion and `diff_summary` in `policy` records go to plan 12. Lockdown and `ask` in the hook go to plan 11.
14. **Developer-mode lock wait** stays 1 s (carry-over 4, see Global Constraints).

## Later sub-plans

**Plan 9b — Locked mode on Linux (privileged).** About 0.75 week. Written when 9a is merged.
- **Spec:** §0 decision 8, §5.1, §5.2, §5.4, §5.4.1, §5.5, §5.6, §6.1.1, §6.1.3, §6.1.4, §6.16, §6.17, §7 (`system install/uninstall`, `doctor`, `status`/`init`/`init --off` in locked mode), §8.3, §9.3, §11.
- **Install and uninstall:**
  - `saiife system install` creates the users and groups (`saiife`, `saiife-audit`), puts the binary in `/opt/saiife/bin` and writes `/etc/saiife` (a commented default or `--config`).
  - It writes the §5.4.1 unit and chooses `LoadCredentialEncrypted` (systemd ≥ 250) or a plain root:saiife 0640 key file with `LoadCredential` (systemd < 250, from `systemctl --version`).
  - It writes the managed hook files per §8.3. Claude Code is labelled lockable. Codex and Gemini follow their plan 7 fixture labels, unverified until the live checks pass.
  - It writes `installed.toml` with fingerprints, then starts the daemon and runs `doctor`.
  - The supported-system check refuses Alpine, containers, non-systemd systems and macOS with a clear message.
  - `system uninstall [--keep-audit|--purge]` removes exactly what `installed.toml` lists.
- **Hook behaviour:**
  - `check --event config-change` (Claude Code).
  - A project hook goes quiet when its agent has a managed hook.
  - The `[guard.mcp]` deny for unlisted servers, with `status`/`doctor` warnings per listed server.
- **Commands and packs:**
  - `doctor` (§5.6 and §6.16; its re-authentication and forwarding parts answer "not configured" until plans 11 and 12; `--json`; exit 0/1/2).
  - The `core.lock` pack, on by default when `locked = true`.
  - The §11 behaviour changes, including the developer-mode `fail = "closed"` opt-in.
- **Tests:** fail-closed matrix tests. Root-only tests run only in a new CI job, `locked-linux`, on GitHub `ubuntu-22.04` and `ubuntu-24.04` runners (sudo available, covering systemd 249 and 255), never locally.
- **Uses from 9a:** `ipc` client, `policy` loader and merge, `saiife daemon --system`, `check --managed` + worker, `ChainWriter`/checkpoints, the bounded config reader.

**Plan 9c — Red-team suite A1–A10, A16–A18.** About 0.25 week. Written when 9b is merged.
- **Spec:** §9.2 rows A1–A10 and A16–A18, §13 "Red-team suite", §14 point 3 (partial).
- **Deliverables:**
  - One script per attack: `scripts/redteam/aNN-<name>.sh` plus a runner, `scripts/redteam/run.sh`. They run as the unprivileged agent user in the `locked-linux` CI job after `system install`.
  - Each attack is attempted by script, not by tool call. It must fail. Where the daemon can see the attempt, there must be a record, checked through `saiife audit verify` and an `audit` read as auditor.
  - A10 checks the state dir and key file permissions. Its vault half is re-run in plan 10.
  - A17 checks that the project `env` is ignored in locked mode. `env use` comes in plan 14.
  - The "two scopes, policy refused" case from §13 is covered too.
- **Uses from 9a:** daemon `audit.append` identity overwrite (A8), back-pressure and disk floor (A9), chain and checkpoints (A7), add-only merge (A18).
- **Uses from 9b:** the installed layout, managed hooks, `core.lock` (A16) and the CI job.

**Estimate:** 9a + 9b + 9c is about 2 weeks, matching §15.1 plan 9. 9a is the largest at about 1 week.
