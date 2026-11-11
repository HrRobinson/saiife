# Plan 34: boxes control plane (v3 step 3, the part that needs no VM): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Depends on plan 28 Tasks 7–8 landing first** (`crates/wire`: `BoxSource`, its DTOs, `BoxId`, `BoxState`, `BoxError`, `check_text`, `FakeBoxSource`, `conformance::check`, feature `fake`). Branch this plan off `v3-dev` only after plan 28 is merged there. Plan 29 is **not** a dependency; Task 8 says what to do whether or not plan 29 Task 1 (the `OP_BOX_*` constants) and Task 2 (`Ctx.boxes`) have landed.
> It does **not** depend on the box spike (plan 25). Everything that does is listed under "Waits on spike" at the end.

**Goal:** The box manager without a real VM:
- a `Vmm` trait (create, boot, pause, resume, stop, snapshot, status, destroy) with a `FakeVmm`, and a `GuestLink` trait (prompt, terminal, diff) with `NoGuest` and `FakeGuest`;
- the §7.7 state machine, per-box state on disk under `<state>/boxes/<id>/`, and recovery after a daemon restart;
- §7.6 capacity, admission and the FIFO queue;
- §7.8 templates: the TOML format, loading from the one trusted directory, and the built-in `claude-code`;
- `impl saiife_wire::BoxSource` over the manager, passing plan 28's conformance kit;
- daemon `box.*` ops on the control socket (owner check, lockdown, audit, a 5 s tick) and the `saiife box ...` CLI, all running against `FakeVmm` in tests.

**Architecture:**
- **One new tokio-free crate, `saiife-boxes` (`crates/boxes`)**, holds the whole control plane: state machine, store, capacity, templates, both traits and their fakes (feature `fake`), the `Manager`, and `ManagerSource` (the `BoxSource` impl). It depends on `saiife-wire` for the shared types and never re-declares them.
- **The manager is synchronous and owns time through an injected clock.** Every `Vmm` and `GuestLink` method must return within about a second; slow things (boot readiness, the agent finishing a turn) arrive later as `GuestEvent`s. The daemon calls the manager from `spawn_blocking` and drives `Manager::tick` every 5 s.
- **Admission runs only in `spawn` and `tick`.** A stop, discard or done never starts a queued box in the same call, so callers (and the conformance kit) see a stable queue; the next tick admits.
- **The release daemon has no boxes.** The manager is built only when the daemon is compiled with the `fake-vmm` feature *and* `SAIIFE_BOX_FAKE_VMM=1` is set. Otherwise every `box.*` op answers `unavailable` with "boxes are not available in this version", and `Ctx.boxes` stays plan 28's `NoBoxes`. The Cloud Hypervisor driver (after the spike) replaces `FakeVmm` behind the same trait.
- **The daemon never reads a user's repo (§5.1).** `spawn` stores the repo's display name and the path the CLI gave as plain metadata; the repo disk is a later plan.

**Tech Stack:** Rust. `saiife-wire` (path, plan 28), `saiife-touch` (path, for `TouchClass`), `serde`, `serde_json`, `toml = "0.8"`, all already in `Cargo.lock`. Dev: `tempfile = "3"`. The daemon adds `saiife-boxes` and, if plan 29 has not, `saiife-wire`. No new crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §5 (architecture, §5.1 privileges), §7 (all; this plan implements §7.6, §7.7, §7.8 and the control side of §7.3), §9 (the `BoxSource` consumer), §11 step 3, §12, §13, §15. Seam: `docs/superpowers/plans/2026-11-11-plan-28-workspace-wire.md` Tasks 7–8. Op names: `2026-11-11-plan-29-workspace-link.md` Task 1. What the spike measures: `2026-11-11-plan-25-box-spike.md` (branch `box-spike`).

## Decisions

- **B1. Crate and placement.** `crates/boxes`, package `saiife-boxes`, lib `saiife_boxes`. `ManagerSource` lives in this crate (so the conformance kit runs without a daemon); the daemon holds it as `Ctx.boxes`.
- **B2. No `Stopped` state.** §7.7 has none and plan 28's `BoxState` is fixed. `stop` turns the VM off and moves Starting/Running/Paused to `Done` with `vm_on = false` (the work stays reviewable). `stop` of a `Queued` box moves it to `Discarded`. `stop` of Done/Landed/Discarded is `Ok` and changes nothing (plan 28: idempotent).
- **B3. Revise of a box whose VM is off** re-enters admission: the comment is kept as `pending_prompt` and the box goes `Done → Queued`; on `Ready` the manager sends the pending prompt. With the VM on, the comment is sent and the box goes `Done → Running`.
- **B4. Boot failure** (a `Vmm` error in create/boot, or no `Ready` within `BOOT_TIMEOUT_SECS`) moves the box to `Discarded` with `error` set and keeps its directory until `gc`, for the logs.
- **B5. Ids** are `b1`, `b2`, … from a persisted counter, never reused (short to type in `saiife box attach b3`; valid `BoxId`s).
- **B6. Queue** is strict FIFO: only the head is admitted; a head that does not fit blocks the rest. `Start::Queue` (the CLI default) joins the queue and may start at once; `Start::Now` starts now or fails `Busy` (it never jumps a non-empty queue). A box that could not fit even on an empty host is refused `Invalid` at spawn, never queued forever.
- **B7. vCPU rule:** committed vCPUs + new ≤ `VCPU_OVERCOMMIT × (threads − RESERVE_THREADS)`, i.e. 2 × (12 − 2) = 20 on the owner's machine. The spec says "vCPUs ≤ 2× threads" and "host reserve … 2 threads"; this reads them together.
- **B8. Owners.** Each box records `owner_uid` (the CLI peer at spawn). On the control socket, a peer that is not the owner, root or an `[admin]` member gets `not_found` for that box (no existence leak); `box.list` shows the peer's own boxes, or all for an admin with `all: true`.
- **B9. Workspace scope.** `ManagerSource::new(mgr, owner: Option<u32>)`. Personal mode passes `Some(ctx.own_uid)`: the Workspace sees and spawns as that user. Locked mode passes `None`: the Workspace sees every box, and `spawn` answers `Unavailable("Workspace spawn in locked mode needs the device owner")` until `SpawnReq` carries one (proposed contract addition, see Contract changes).
- **B10. Template login credential is not a "secret".** `[agent] credential` names the vault secret the gateway adds to model calls; `secrets` lists extra named connectors. `wire().has_secrets` counts only `secrets`, so spawning the built-in `claude-code` from the Workspace is Signed, not Touch (§9.5).
- **B11. Templates dir.** Locked: `<dir of ctx.config_path>/templates.d` (`/etc/saiife/templates.d`), and a file is used only if it is a regular file (not a symlink), owned by root and not group- or world-writable. Personal: `$XDG_CONFIG_HOME/saiife/templates.d` (default `~/.config/...`), owned by the user. Never a project directory. A file named like the built-in replaces it. A bad file is skipped with a warning; it never stops the others loading.
- **B12. `scripts/spike/` stays.** Plan 25 says to delete it "when step 3's first plan starts"; this plan does not, because the owner may not have run the spike yet. The first post-spike plan deletes it.

## Contract changes

No name in plan 28 changes. Additions, flagged for the owner:

| Item | Addition | Why |
|---|---|---|
| `saiife_ipc::msg` | `OP_BOX_DONE = "box.done"`, `OP_BOX_GC = "box.gc"` (control socket only; MachineOnly) | §7.7 `saiife box done` and `gc`. Added to `saiife_wire::level::IPC_OPS` so `every_ipc_op_is_classified` passes; not in `REMOTE`. |
| `SpawnReq` (plan 28) | proposed later: `owner_uid: Option<u32>` filled by plan 29's dispatcher from the device owner | B9; not done here, the trait stays as plan 28 wrote it. |
| `BoxSource::pending_actions` / `complete` | this plan returns `vec![]` / `NotFound` | `land` and `push` records need the diff transport (Waits on spike). |

## Global Constraints

Copied from `.superpowers/sdd/hard-rules.md` (owner); every task obeys them.

- **Never run privileged or process-control tools.** No sudo, no root, no systemd units, systemctl or `systemctl --user`, no writes to /etc, /opt, /var or /run, no managed agent settings on the host, no docker. Never execute kill, pkill, killall, pgrep, sudo, su, systemctl, loginctl, crontab, pkcheck, pkttyagent, pkexec, nft, even to probe; `--help`/man pages only. No pgrep, ps-polling or `kill -0` in wait or Monitor loops; use `run_in_background` and wait for the notification. `Child::kill` on a child your own test spawned is allowed.
- **No VM, no Cloud Hypervisor, no `/dev/kvm`** in this plan, ever. Tests use `FakeVmm` and `FakeGuest` only. Never run `scripts/spike/box-spike.sh` (except `--help`), `scripts/locked-linux/*`, `scripts/demo-locked.sh`, CI-only smoke scripts, red-team scripts, or `scripts/bench-check.sh --managed`.
- **Scratch files** carry the plan and task in their name (`p34-tN-...`), never contain the word "fix", and are never someone else's.
- **Guard refusals:** never reformulate a refused command to get around it (no splitting, encoding or indirection). Owner ruling 2026-11-02: after a refusal you may use Read, Edit or Write, or split the command, only for files in your own worktree or scratch dir, and list every refusal in your report. Hard stop and report for anything privileged, any process-control tool, anything outside your worktree or scratch dir, or a second refusal of the same action.
- **Test isolation:** export `TMPDIR` and `SAIIFE_TEST_TMP` to a dir made with `mktemp -d -p /home/jonas/projects/personal/saiife`; /tmp has a quota. In tests point `HOME`, `PATH`, `SAIIFE_DATA_DIR`, `SAIIFE_AUDIT_DIR` and `XDG_*` at tempdirs; set `DBUS_SESSION_BUS_ADDRESS` to a dead path near the keychain. Never run `saiife init` on the real home or the repo; never touch `~/.claude` or the real desktop keyring. Remove your scratch dir at the end.
- **Network:** tests never use the network.
- **Git:** first thing in your worktree, `git merge --ff-only p34-boxes-control-plane`. Commit only in your worktree, stage explicit paths, never push or force-push, never commit `.superpowers/`. No token-shaped literals (build fakes with `concat!`). Trailer, exactly: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Before committing:** `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings`; tests of the crates you touched pass. Keep non-Linux stubs compiling: consume their args, leave no field unread on macOS.
- **Code rules:** guard, audit, policy, ipc, system (and wire, and this plan's **boxes**) stay tokio-free. New dependencies pinned to a version older than 14 days; prefer crates already in `Cargo.lock` (this plan adds none).
- **Reporting:** do not spawn subagents. Write `task-N-report.md` at your worktree root and leave it uncommitted.
- **Disk and load:** `CARGO_INCREMENTAL=0`, one target dir, `cargo ... -j 4` and `-- --test-threads=4`. Remove extra target dirs. A missing build cache is not a code failure; rebuild.
- **No unsafe:** `[lints] workspace = true` in `crates/boxes/Cargo.toml` and `#![forbid(unsafe_code)]` at column 0 of `crates/boxes/src/lib.rs` (`scripts/check-unsafe.sh`).
- **Portable:** `saiife-boxes` compiles on Linux, macOS and Windows (`bash scripts/check-windows.sh -p saiife-boxes` clean); the owner/mode checks in B11 are `#[cfg(unix)]` with a non-unix branch that refuses every file.
- **Every task** (worktree `.worktrees/p34`, branch `p34-boxes-control-plane` off `v3-dev` after plan 28 merged):
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p34-tN-XXXXXX)"
  export SAIIFE_TEST_TMP="$TMPDIR"
  export CARGO_INCREMENTAL=0
  cargo test -p saiife-boxes --features fake -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  ```

### Fixed values

| Name | Value | Source |
|---|---|---|
| default box | `vcpus = 2`, `mem_mib = 4096`, `mem_max_mib = 8192`, `disk_gib = 30` | §7.6 |
| `RESERVE_MEM_MIB` | `8192` | §7.6 |
| `RESERVE_THREADS` | `2` | §7.6 |
| `VCPU_OVERCOMMIT` | `2` | §7.6, B7 |
| `DISK_HEADROOM_GIB` | `30` (free disk ≥ 30 GiB + the box's `disk_gib`) | §7.6 |
| `VMM_OVERHEAD_MIB` | `0` (**provisional**: the spike's idle Rss sets it) | Waits on spike |
| `BOOT_TIMEOUT_SECS` | `300` (**provisional**: the spike's cold boot sets it) | B4 |
| `DONE_IDLE_SECS` | `30` (turn finished and no activity for 30 s → `Done`) | §7.7 |
| `TICK_SECS` | `5` (daemon) | this plan |
| default `idle_stop_mins` | `120` | §7.6 "template-set" |
| state root | `<state_dir>/boxes/` (0700); per box `<id>/box.json` (0600), marker `<id>/.saiife-box` with content `saiife.managed box <id>\n`; counter `next-id` (0600) | §7.3 "labelled" |
| `BoxRecord.version` | `1` | |
| session id | `"box-" + id` | §7.7 "every box is a v2 session" |
| template file | `*.toml`, ≤ `64 * 1024` bytes, name `[a-z0-9][a-z0-9-]{0,39}` equal to the file stem | B11 |
| size bounds | `vcpus 1..=32`, `mem_mib 512..=262144`, `mem_max_mib ≥ mem_mib`, `disk_gib 4..=1024` | this plan |
| audit | `kind = "box"`; action = the op suffix (`spawn`, `stop`, …) or `tick`; `extra = {box, session, template, from, to, via}` (`via`: `cli`, `workspace`, `tick`) | §7.7, §7.5 |
| CLI exit codes | `0` ok, `2` refused (not found, wrong state, invalid, busy, lockdown), `5` daemon unreachable or boxes unavailable | as `saiife lockdown` |

## Review Focus

1. **Daemon restart with boxes in flight:** some VMs gone, some still running, a queue of three. Expected: gone VMs move their box to `Done` with `vm_on = false` and `error = "the VM was gone after a daemon restart"`; live ones keep their state; the queue keeps its order and nothing boots twice (Task 6: `restart_marks_lost_vms_done`, `restart_keeps_live_vms`, `restart_keeps_queue_order`).
2. **A hostile or corrupt state dir:** a `box.json` with an unknown field, a record whose `id` differs from its folder, a box folder that is a symlink to `$HOME`, a folder with no marker. Expected: each is skipped and named in the warnings; `gc` and `discard` never delete through a symlink or a folder without the matching marker (Task 4: `bad_records_are_skipped_and_named`, `remove_refuses_a_symlinked_dir`, `orphans_skip_unmarked_dirs`).
3. **Capacity edges:** a template bigger than the host can ever hold, an exact fit, a head-of-queue box that does not fit while a smaller one behind it would. Expected: `Invalid` at spawn (never queued forever); the exact fit is admitted; strict FIFO keeps the smaller one waiting (Task 3: `never_fits_is_refused`, `exact_fit_is_admitted`; Task 6: `queue_head_blocks`).
4. **Adversarial template files:** stem and `name` differ, an unknown key, egress `"*"` or `"https://x"`, a group-writable or symlinked file in locked mode, a 1 MB file, two broken files beside one good one. Expected: each bad one is skipped with a warning naming the file and reason; the good one and the built-in still load (Task 2: `bad_files_are_skipped_others_load`, `locked_mode_trusts_only_root_owned_files`, `egress_rules`).
5. **Another local user, and lockdown, on the control socket:** user B stops, steers or lists user A's box; lockdown `all` is on and someone spawns, resumes, revises or says. Expected: B gets `not_found` and B's `box.list` is empty, an admin sees A's box; under lockdown `all` the power-giving ops are refused with rule `lockdown` and a deny record, while `stop`, `pause` and `discard` still work (Task 8: `other_user_gets_not_found`, `admin_sees_all`, `lockdown_refuses_power_ops_only`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (crate, modules, errors, state machine, CI gate).
- **Wave 2 (parallel):** Task 2 (templates), Task 3 (capacity), Task 4 (store), Task 5 (`Vmm`, `GuestLink`, fakes). Each owns its own module file.
- **Wave 3:** Task 6 (manager; needs 1–5).
- **Wave 4 (parallel):** Task 7 (`ManagerSource` + conformance; needs 6), Task 8 (daemon; needs 6, and 7 for `Ctx.boxes`). If run in parallel, Task 8 wires `Ctx.boxes` last, after Task 7 merges.
- **Wave 5:** Task 9 (CLI; needs 8).
- **Last:** gates, whole-branch review against Review Focus, one fix wave, PR to `v3-dev` (owner merges).

**Shared files:** `crates/boxes/src/lib.rs` and `error.rs`. Task 1 declares every module (an empty file with one `//!` line) and every `BoxesError` variant, so later tasks add none.

---

### Task 1: the crate, errors, state machine and CI gate (size S)

**Files:**
- Create: `crates/boxes/Cargo.toml`, `crates/boxes/src/lib.rs`, `src/error.rs`, `src/state.rs`; empty-with-`//!` `src/{template,capacity,store,vmm,guest,manager,source}.rs`, `src/vmm/fake.rs`, `src/guest/fake.rs` (fakes behind `#[cfg(feature = "fake")]`).
- Modify: `.github/workflows/ci.yml:151` (append ` -p saiife-boxes` to the "no tokio in hook crates" `cargo tree` line).

**Interfaces (Produces):**
```rust
// Cargo.toml: [features] fake = ["saiife-wire/fake"]; deps saiife-wire, saiife-touch (paths), serde (derive), serde_json, toml 0.8; dev tempfile 3
pub use saiife_wire::{BoxError, BoxId, BoxState};
// error.rs: infrastructure errors (BoxError is the caller-facing one)
#[derive(Debug)] pub enum BoxesError { Io { path: PathBuf, source: io::Error }, State { path: PathBuf, msg: String }, Template { path: PathBuf, msg: String }, Vmm(String) }
impl From<BoxesError> for BoxError { /* -> BoxError::Unavailable(display text) */ }
// state.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event { Admit, Ready, Pause, Resume, Finish, Revise, Requeue, Stop, Land, Discard, BootFailed, VmLost }
pub fn transition(from: BoxState, ev: Event) -> Result<BoxState, BoxError>;   // Err = WrongState { state: from }
pub fn holds_capacity(state: BoxState, vm_on: bool) -> bool;   // vm_on && state in {Starting, Running, Paused, Done, Landed}
```
Transition table (everything not listed is `WrongState`):

| from | Admit | Ready | Pause | Resume | Finish | Revise | Requeue | Stop | Land | Discard | BootFailed | VmLost |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Queued | Starting | | | | | | | Discarded | | Discarded | | |
| Starting | | Running | | | | | | Done | | Discarded | Discarded | Done |
| Running | | | Paused | | Done | | | Done | | Discarded | | Done |
| Paused | | | | Running | | | | Done | | Discarded | | Done |
| Done | | | | | | Running | Queued | Done | Landed | Discarded | | Done |
| Landed | | | | | | Running | Queued | Landed | Landed | Discarded | | Landed |
| Discarded | | | | | | | | Discarded | | Discarded | | |

- [ ] **Step 1: Write the failing tests** (`state.rs`): `table_matches_spec` (every cell above, including a loop asserting each blank cell is `WrongState { state: from }`), `stop_is_idempotent_on_terminal_states`, `capacity_follows_vm` (`holds_capacity(Done, true)`, `!holds_capacity(Done, false)`, `!holds_capacity(Queued, true)`).
- [ ] **Step 2: Run** `cargo test -p saiife-boxes` → FAIL (no `transition`).
- [ ] **Step 3: Implement** `transition` as one `match (from, ev)`.
- [ ] **Step 4: Run** → PASS; `cargo tree -e normal -p saiife-boxes | grep -c tokio` → `0`.
- [ ] **Step 5: Commit** `feat(boxes): crate, errors and the box state machine (spec §7.7)`.

---

### Task 2: templates (size M)

**Files:** Modify `crates/boxes/src/template.rs`; create `crates/boxes/tests/templates.rs`, `crates/boxes/src/builtin/claude-code.toml` (`include_str!`).

**Interfaces (Produces):**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] pub struct Size { pub vcpus: u32, pub mem_mib: u64, pub mem_max_mib: u64, pub disk_gib: u64 }
impl Default for Size { /* 2, 4096, 8192, 30 */ }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum AgentKind { ClaudeCode }          // "claude-code"
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Login { ApiKey, Subscription }    // "api-key" | "subscription" (§7.9)
#[derive(Debug, Clone, PartialEq, Eq)] pub enum ImageRef { Default, Pinned(String) }  // "default" | "base-<64 lowercase hex>"
#[derive(Debug, Clone, PartialEq, Eq)] pub struct EgressRule { pub host: String, pub port: u16 }  // "host[:port]", port default 443; host lowercase DNS, optional leading "*."; no scheme, path, "*" alone, or empty label
#[derive(Debug, Clone, PartialEq)]
pub struct BoxTemplate { pub name: String, pub description: String, pub agent: AgentKind, pub command: Vec<String>, pub login: Login, pub credential: String, pub image: ImageRef, pub size: Size, pub egress: Vec<EgressRule>, pub secrets: Vec<String>, pub rules_profile: String, pub touch: Vec<saiife_touch::TouchClass>, pub idle_stop_mins: u32 }
impl BoxTemplate { pub fn wire(&self) -> saiife_wire::Template; }   // has_secrets = !secrets.is_empty(), has_egress = !egress.is_empty() (B10)
pub fn parse(name_from_stem: &str, text: &str) -> Result<BoxTemplate, String>;
pub fn builtin() -> Vec<BoxTemplate>;   // [claude-code]
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Trust { RootOwned, OwnedBy(u32) }
#[derive(Debug, Clone, PartialEq, Eq)] pub struct TemplateWarning { pub file: PathBuf, pub reason: String }
pub fn load_dir(dir: &Path, trust: Trust) -> (Vec<BoxTemplate>, Vec<TemplateWarning>);   // builtins, replaced by same-named files; sorted by name; a missing dir = builtins, no warning
```
File format (`deny_unknown_fields` at every level; all sections but `[agent]` optional with the defaults shown):
```toml
name = "claude-code"
description = "Claude Code in its TUI"
[agent]
kind = "claude-code"
command = ["claude"]
login = "api-key"            # or "subscription"
credential = "anthropic"     # vault secret name the gateway adds (B10)
[image]
base = "default"
[size]                       # defaults: Fixed values
vcpus = 2
mem_mib = 4096
mem_max_mib = 8192
disk_gib = 30
[egress]
allow = []                   # e.g. ["registry.npmjs.org", "*.crates.io:443"]
[secrets]
names = []
[rules]
profile = "default"          # §10.5; stored, not used until step 5
[touch]
classes = ["land", "push_protected"]   # saiife_touch::TouchClass::from_name; unknown = error
[idle]
stop_after_mins = 120
```
Secret and profile names follow the template name rule. `command` is non-empty, each element non-empty with no NUL.

- [ ] **Step 1: Write the failing tests:** `builtin_claude_code` (name, `Login::ApiKey`, credential `"anthropic"`, default size, empty egress and secrets, touch `[Land, PushProtected]`, `wire().has_secrets == false`), `full_file_roundtrip`, `defaults_apply`, `unknown_key_is_refused`, `stem_must_match_name`, `size_bounds` (`vcpus = 0`, `mem_max_mib < mem_mib`, `disk_gib = 2048` refused), `egress_rules` (`"registry.npmjs.org"` → port 443; `"*.crates.io:443"` ok; `"*"`, `"https://x.org"`, `"x.org/path"`, `"X.org"`, `"a..b"`, `"x.org:0"`, `"x.org:99999"` refused), `unknown_touch_class_is_refused`, `pinned_image_must_be_hex` (`base-` + 63 hex refused), `bad_files_are_skipped_others_load` (in a tempdir: `good.toml`, `bad1.toml` with unknown key, `bad2.toml` 1 MB, `notes.txt`; → `[claude-code, good]` and two warnings naming `bad1.toml` and `bad2.toml`), `file_replaces_builtin`, `missing_dir_is_builtins`, `locked_mode_trusts_only_root_owned_files` (`#[cfg(unix)]`: a file owned by the test uid with `Trust::RootOwned` is skipped with reason containing `"not owned by root"`; with `Trust::OwnedBy(own_uid)` and mode `0o664` skipped with `"group- or world-writable"`; a symlink skipped with `"symlink"`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** with `toml::from_str` into private raw structs, then validate into `BoxTemplate`. Read files with `symlink_metadata` first, then `File::open` + `metadata` on the handle (size, owner, mode from `std::os::unix::fs::MetadataExt`), then read at most 64 KiB + 1.
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `feat(boxes): templates: format, trusted loading, built-in claude-code (spec §7.8)`.

---

### Task 3: capacity and admission (size S)

**Files:** Modify `crates/boxes/src/capacity.rs`.

**Interfaces:**
- Consumes: `Size` (Task 2).
- Produces:
```rust
pub const RESERVE_MEM_MIB: u64 = 8192; pub const RESERVE_THREADS: u32 = 2; pub const VCPU_OVERCOMMIT: u32 = 2;
pub const DISK_HEADROOM_GIB: u64 = 30; pub const VMM_OVERHEAD_MIB: u64 = 0;   // provisional, see Waits on spike
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub struct HostFacts { pub mem_total_mib: u64, pub mem_avail_mib: u64, pub threads: u32, pub disk_free_mib: u64, pub cpu_pct: Option<u8> }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub struct Committed { pub mem_mib: u64, pub vcpus: u32 }
#[derive(Debug, Clone, PartialEq, Eq)] pub enum Refusal { Memory { need_mib: u64, free_mib: u64 }, Cpu { need: u32, free: u32 }, Disk { need_mib: u64, free_mib: u64 } }
impl Refusal { pub fn message(&self) -> String; }   // e.g. "needs 4096 MiB of box memory, 2048 MiB is free"
pub fn admit(h: &HostFacts, c: &Committed, s: &Size) -> Result<(), Refusal>;
pub fn fits_ever(h: &HostFacts, s: &Size) -> Result<(), Refusal>;   // admit with Committed::default()
pub fn slots(h: &HostFacts, c: &Committed) -> (u32, u32);            // (total, free), counted in default-size boxes
```
Rules (saturating arithmetic everywhere): memory `c.mem_mib + s.mem_mib + VMM_OVERHEAD_MIB ≤ mem_total_mib − RESERVE_MEM_MIB`; cpu `c.vcpus + s.vcpus ≤ VCPU_OVERCOMMIT × (threads − RESERVE_THREADS)`; disk `disk_free_mib ≥ (DISK_HEADROOM_GIB + s.disk_gib) × 1024`. Checked in that order; the first failing one is returned. Disk uses the live free figure, so it is not added to `Committed`.

- [ ] **Step 1: Write the failing tests:** `owner_machine_fits_six_default_boxes` (`mem_total_mib = 32768`, `threads = 12`, disk 500 GiB: `slots == (6, 6)`; after committing 5 → `(6, 1)`), `exact_fit_is_admitted` (free memory exactly `s.mem_mib`), `one_mib_short_is_memory`, `cpu_limit_is_twenty_on_twelve_threads`, `disk_needs_headroom` (free = 59 GiB, box 30 GiB → `Disk`), `never_fits_is_refused` (`mem_mib = 65536` on 32 GiB → `fits_ever` is `Memory`), `tiny_host_has_no_slots` (`mem_total_mib = 4096` → `(0, 0)`, no underflow panic), `message_text`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): capacity and admission (spec §7.6)`.

---

### Task 4: on-disk store (size M)

**Files:** Modify `crates/boxes/src/store.rs`; create `crates/boxes/tests/store.rs`.

**Interfaces:**
- Consumes: `BoxId`, `BoxState` (wire), `Size` (Task 2), `VmHandle` (Task 5: define it here if Task 5 has not merged; Task 5 then re-exports it from `vmm`; the struct is fixed below).
- Produces:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct VmHandle { pub id: BoxId, pub driver: String, pub data: String }   // opaque to the manager
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)] #[serde(deny_unknown_fields)]
pub struct BoxRecord {
    pub version: u32, pub id: BoxId, pub state: BoxState, pub owner_uid: u32, pub session: String,
    pub template: String, pub size: Size, pub repo: String, pub repo_dir: Option<String>, pub task: String,
    pub created_at: u64, pub started_at: Option<u64>, pub updated_at: u64,
    pub queue_seq: Option<u64>, pub vm: Option<VmHandle>, pub vm_on: bool, pub keep: bool, pub lands: u32,
    pub last_activity: u64, pub turn_finished_at: Option<u64>, pub pending_prompt: Option<String>, pub error: Option<String>,
}
pub struct Store { /* root */ }
impl Store {
    pub fn open(root: PathBuf) -> Result<Store, BoxesError>;          // create_dir_all, mode 0700 on unix
    pub fn root(&self) -> &Path;
    pub fn box_dir(&self, id: &BoxId) -> PathBuf;
    pub fn claim_id(&self) -> Result<BoxId, BoxesError>;              // read next-id (missing = 1), loop: create_dir(b<n>) (AlreadyExists -> n+1), write marker, write next-id = n+1 atomically
    pub fn save(&self, r: &BoxRecord) -> Result<(), BoxesError>;      // box.json.tmp.<pid> then rename; 0600; refuses unless the dir's marker matches r.id
    pub fn load(&self, id: &BoxId) -> Result<Option<BoxRecord>, BoxesError>;
    pub fn list(&self) -> Result<(Vec<BoxRecord>, Vec<String>), BoxesError>;   // sorted by id; bad entries skipped, each named in the warnings
    pub fn remove(&self, id: &BoxId) -> Result<(), BoxesError>;      // symlink_metadata must be a real dir with the matching marker, then remove_dir_all
    pub fn orphans(&self) -> Result<Vec<BoxId>, BoxesError>;         // marked dirs with no readable box.json; unmarked dirs and symlinks never listed
}
```
A `list` entry is skipped when: the folder name is not a `BoxId`, the folder is a symlink, the marker is missing or names another id, `box.json` fails to parse (unknown field, bad JSON), `version != 1`, or `record.id` differs from the folder.

- [ ] **Step 1: Write the failing tests:** `claim_ids_are_sequential_and_never_reused` (`b1`, `b2`; remove `b2`; next is `b3`; a pre-existing `b3/` dir → `b4`), `save_load_roundtrip`, `save_is_atomic` (no `*.tmp.*` left; mode `0o600` on unix), `bad_records_are_skipped_and_named` (unknown field, id mismatch, missing marker, `version: 2`, non-id folder `README` → 0 records, 5 warnings each naming its folder), `remove_refuses_a_symlinked_dir` (`#[cfg(unix)]`: `b9` → symlink to a tempdir holding a marker for `b9` and a canary file; `remove` errs and the canary survives), `remove_refuses_wrong_marker`, `orphans_skip_unmarked_dirs`, `list_ignores_tmp_files`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** (pattern: `crates/dev/src/project.rs` `save`/`read_state`). **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): per-box state on disk, labelled and atomic (spec §7.3)`.

---

### Task 5: the `Vmm` and `GuestLink` seams and their fakes (size M)

**Files:** Modify `crates/boxes/src/vmm.rs`, `src/vmm/fake.rs`, `src/guest.rs`, `src/guest/fake.rs`.

**Interfaces (Produces):**
```rust
// vmm.rs
pub use crate::store::VmHandle;
#[derive(Debug, Clone, PartialEq, Eq)] pub struct VmSpec { pub id: BoxId, pub size: Size, pub image: ImageRef, pub dir: PathBuf }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum VmStatus { Created, Running, Paused, Off, Gone }
#[derive(Debug, Clone, PartialEq, Eq)] pub enum VmmError { Unavailable(String), Failed(String) }
/// The VM driver. Every method returns within about a second: `boot`
/// starts the VM and returns; readiness arrives later as `GuestEvent::Ready`.
/// `stop` and `destroy` are idempotent (Ok on an Off or Gone VM). `status`
/// never errs for a VM it does not know: that is `Gone`.
pub trait Vmm: Send + Sync {
    fn create(&self, spec: &VmSpec) -> Result<VmHandle, VmmError>;
    fn boot(&self, h: &VmHandle) -> Result<(), VmmError>;
    fn pause(&self, h: &VmHandle) -> Result<(), VmmError>;
    fn resume(&self, h: &VmHandle) -> Result<(), VmmError>;
    fn stop(&self, h: &VmHandle) -> Result<(), VmmError>;
    fn snapshot(&self, h: &VmHandle, dest: &Path) -> Result<(), VmmError>;   // VM must be paused
    fn status(&self, h: &VmHandle) -> VmStatus;
    fn destroy(&self, h: &VmHandle) -> Result<(), VmmError>;               // frees VMM resources; the store removes the dir
}
// vmm/fake.rs (feature "fake")
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum VmOp { Create, Boot, Pause, Resume, Stop, Snapshot, Destroy }
#[derive(Debug, Clone, PartialEq, Eq)] pub struct VmCall { pub op: VmOp, pub id: BoxId }
pub struct FakeVmm { /* Mutex<state> */ }
impl FakeVmm {
    pub fn new() -> FakeVmm;
    pub fn fail_next(&self, op: VmOp, msg: &str);   // the next call of op errs Failed(msg)
    pub fn set_status(&self, id: &BoxId, s: VmStatus);   // e.g. Gone, to simulate a crash
    pub fn calls(&self) -> Vec<VmCall>;
}
impl Vmm for FakeVmm { /* Created -> boot -> Running -> pause -> Paused ...; pause of a non-Running VM errs; snapshot writes dest/snapshot.fake */ }
// guest.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum GuestEvent { Ready, Activity, TurnFinished, Exited }
#[derive(Debug, Clone, PartialEq, Eq)] pub enum GuestError { Unavailable(String), NotConnected }
/// The `saiife-guest/1` channel (later plan). Prompt types text + Enter into the agent's PTY.
pub trait GuestLink: Send + Sync {
    fn prompt(&self, id: &BoxId, text: &str) -> Result<(), GuestError>;
    fn terminal(&self, id: &BoxId, after: Option<u64>) -> Result<saiife_wire::TermBatch, GuestError>;
    fn diff(&self, id: &BoxId) -> Result<saiife_wire::DiffSummary, GuestError>;
}
pub struct NoGuest;   // every call: Unavailable("the guest channel is not built yet")
impl From<GuestError> for BoxError { /* Unavailable(m) -> Unavailable(m); NotConnected -> Unavailable("the box is not connected") */ }
// guest/fake.rs (feature "fake")
pub struct FakeGuest { /* Mutex */ }
impl FakeGuest { pub fn new() -> FakeGuest; pub fn prompts(&self) -> Vec<(BoxId, String)>; pub fn set_terminal(&self, id: &BoxId, frames: Vec<saiife_wire::TermFrame>); pub fn set_diff(&self, id: &BoxId, d: saiife_wire::DiffSummary); pub fn disconnect(&self, id: &BoxId); }
impl GuestLink for FakeGuest { /* prompt errs NotConnected after disconnect; terminal pages by seq like plan 28's fake; diff of an unset id is Unavailable */ }
```

- [ ] **Step 1: Write the failing tests** (in-module, `--features fake`): `fake_vmm_lifecycle` (create, boot → Running, pause → Paused, resume, stop → Off, stop again Ok, destroy, status → Gone), `fake_vmm_pause_needs_running`, `fail_next_fails_once`, `set_status_gone`, `snapshot_writes_into_dest`, `no_guest_is_unavailable`, `fake_guest_records_prompts`, `fake_guest_disconnect`, `fake_guest_terminal_pages_by_seq`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `cargo test -p saiife-boxes` without `fake` still builds.
- [ ] **Step 5: Commit** `feat(boxes): Vmm and GuestLink seams, FakeVmm and FakeGuest`.

---

### Task 6: the manager (size L)

**Files:** Modify `crates/boxes/src/manager.rs`; create `crates/boxes/tests/manager.rs` (`#![cfg(feature = "fake")]`).

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces:
```rust
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;           // Unix seconds
pub type HostProbe = Arc<dyn Fn() -> HostFacts + Send + Sync>;
pub struct ManagerInit { pub store: Store, pub vmm: Arc<dyn Vmm>, pub guest: Arc<dyn GuestLink>, pub templates: Vec<BoxTemplate>, pub host: HostProbe, pub clock: Clock }
#[derive(Debug, Clone, PartialEq, Eq)] pub struct SpawnArgs { pub template: String, pub repo: String, pub repo_dir: Option<String>, pub task: String, pub start: saiife_wire::Start, pub owner_uid: u32 }
#[derive(Debug, Clone, PartialEq, Eq)] pub struct Change { pub id: BoxId, pub from: BoxState, pub to: BoxState, pub why: &'static str }
#[derive(Debug, Clone, PartialEq, Eq, Default)] pub struct GcReport { pub removed: Vec<BoxId> }
pub struct Manager { /* Mutex<Inner { records: BTreeMap<BoxId, BoxRecord>, next_seq: u64, ... }> + init */ }
impl Manager {
    pub fn open(init: ManagerInit) -> Result<(Manager, Vec<String>), BoxesError>;   // loads the store, recovers; warnings = store + recovery notes
    pub fn templates(&self) -> Vec<BoxTemplate>;
    pub fn get(&self, id: &BoxId) -> Result<BoxRecord, BoxError>;
    pub fn list(&self) -> Vec<BoxRecord>;    // plan 28's overview order: running, paused, done, queued (by queue position), starting, then the rest; ties by id
    pub fn queue(&self) -> Vec<BoxId>;       // queued ids, head first
    pub fn queue_pos(&self, id: &BoxId) -> Option<u32>;   // 1-based
    pub fn capacity(&self) -> (HostFacts, Committed);
    pub fn spawn(&self, a: &SpawnArgs) -> Result<BoxRecord, BoxError>;
    pub fn pause(&self, id: &BoxId) -> Result<Change, BoxError>;
    pub fn resume(&self, id: &BoxId) -> Result<Change, BoxError>;
    pub fn stop(&self, id: &BoxId, keep: bool) -> Result<Change, BoxError>;
    pub fn discard(&self, id: &BoxId) -> Result<Change, BoxError>;
    pub fn done(&self, id: &BoxId) -> Result<Change, BoxError>;          // §7.7 `saiife box done`
    pub fn say(&self, id: &BoxId, msg: &str) -> Result<(), BoxError>;    // Running only
    pub fn revise(&self, id: &BoxId, comment: &str) -> Result<Change, BoxError>;
    pub fn reorder(&self, ids: &[BoxId]) -> Result<(), BoxError>;
    pub fn guest_event(&self, id: &BoxId, ev: GuestEvent) -> Result<Option<Change>, BoxError>;
    pub fn tick(&self) -> Vec<Change>;
    pub fn gc(&self) -> Result<GcReport, BoxesError>;
}
```
Behaviour (each line is one test below):
- **spawn:** `check_text(task, MAX_TASK_BYTES)` (an empty task is allowed: skip the check when `task.is_empty()`), `check_text(repo, 256)`; unknown template → `Invalid("unknown template <name>")`; `fits_ever` fails → `Invalid(refusal.message())`; `Start::Now` with a non-empty queue or `admit` failing → `Busy`, and no id is claimed; otherwise claim an id, write the record `Queued` with `queue_seq = next_seq`, `pending_prompt = Some(task)` when the task is non-empty, then run the admission pass.
- **admission pass** (spawn and tick only): while the head fits (`admit` against `Committed` = sum of `size.mem_mib` and `size.vcpus` over records where `holds_capacity`): `Admit` → `Starting`, `vmm.create` then `vmm.boot`, `vm_on = true`, `started_at = now`. A `Vmm` error → `BootFailed` (`Discarded`, `error = "boot failed: <msg>"`, VM destroyed, dir kept) and the pass continues with the next head.
- **Ready:** `Starting → Running`, `last_activity = now`; then if `pending_prompt` is set, `guest.prompt` it and clear it (a prompt error is kept in `error`, the box still runs).
- **Activity:** `last_activity = now`, `turn_finished_at = None`. **TurnFinished:** `turn_finished_at = Some(now)`. **Exited:** `Running → Done` (`Finish`).
- **tick:** (1) `Starting` and `now − started_at ≥ BOOT_TIMEOUT_SECS` → stop + destroy the VM, `BootFailed`, `error = "boot timed out"`; (2) `Running` and `turn_finished_at` set and `now − max(turn_finished_at, last_activity) ≥ DONE_IDLE_SECS` → `Finish`; (3) `vm_on` and `now − last_activity ≥ idle_stop_mins × 60` (the template's; a deleted template → default) → VM stop, `vm_on = false` (Running/Paused → `Done` via `Stop`; Done/Landed stay); (4) the admission pass. Returns every change.
- **pause / resume:** the transition first (so `WrongState` costs no VMM call), then `vmm.pause`/`resume`; a VMM error leaves the state unchanged and is `Unavailable`.
- **stop(keep):** Queued → `Discarded` (no VMM call, `queue_seq = None`). VM on: if `keep`, `vmm.pause` (when Running) and `vmm.snapshot(dir/snapshot)` first; a snapshot error → `Unavailable("snapshot failed: …")` with the box resumed and unchanged. Then `vmm.stop`, `vm_on = false`, `keep = keep`, transition `Stop`. Terminal and VM-off states: `Ok`, no VMM call.
- **discard:** VM on → `vmm.stop` + `vmm.destroy` (errors logged into the warning, not fatal), then `store.remove`; the record leaves memory. Returned `Change.to` is `Discarded`.
- **done:** `Finish` (Running only; `WrongState` otherwise).
- **say:** `check_text(msg, MAX_STEER_BYTES)`; Running only; `guest.prompt`.
- **revise:** `check_text(comment, MAX_STEER_BYTES)`; Done or Landed only. VM on → `guest.prompt(comment)` first (an error → `Unavailable`, state unchanged), then `Revise` → Running, `turn_finished_at = None`. VM off → `pending_prompt = Some(comment)`, `Requeue` → Queued at the tail.
- **reorder:** `ids` must be exactly the queued set (same members, no duplicates) or `Invalid("reorder must list every queued box once")`; then `queue_seq` is reassigned in the given order.
- **open (recovery):** for every record with `vm_on`: `vmm.status` → `Gone`/`Off` → `VmLost` (`Done` or `Landed`), `vm_on = false`, `error = "the VM was gone after a daemon restart"`; `Running`/`Paused` → keep, and reconcile `Running ⇄ Paused` to the VMM's answer; `Created` while `Starting` → keep (the boot timeout handles it). Queue order = ascending `queue_seq`; `next_seq` = max + 1.
- **gc:** removes every `Discarded` record's dir and every `store.orphans()` dir.
- Every state change saves the record before the method returns; `updated_at = now` on each.

- [ ] **Step 1: Write the failing tests** (helper `world(host_boxes: u32)` builds a tempdir store, `FakeVmm`, `FakeGuest`, the built-in template, a `HostFacts` with `mem_total_mib = 8192 + host_boxes × 4096`, `threads = 12`, ample disk, and a settable clock): `spawn_starts_when_room`, `spawn_queues_when_full`, `now_is_busy_when_full_and_claims_no_id`, `unknown_template_is_invalid`, `never_fits_is_invalid`, `task_with_escape_is_invalid`, `queue_head_blocks` (head needs 8 GiB, a 4 GiB box behind it, 4 GiB free → neither starts), `ready_sends_the_task_once`, `turn_finished_then_idle_is_done` (29 s no, 30 s yes; an `Activity` in between resets), `exited_is_done`, `boot_failure_discards_and_keeps_dir`, `boot_timeout_discards`, `idle_stop_turns_vm_off`, `stop_running_is_done_vm_off`, `stop_queued_is_discarded`, `stop_twice_is_ok_and_calls_vmm_once`, `stop_keep_snapshots_first`, `stop_keep_snapshot_failure_changes_nothing`, `stop_does_not_admit_until_tick`, `pause_resume_roundtrip`, `pause_wrong_state_makes_no_vmm_call`, `say_needs_running`, `revise_running_box_is_wrong_state`, `revise_done_vm_on_prompts_and_runs`, `revise_done_vm_off_requeues_and_prompts_on_ready`, `revise_prompt_failure_keeps_done`, `reorder_rules` (missing id, extra id, duplicate → `Invalid`; reversed → `queue()` reversed), `discard_removes_dir_and_frees_capacity`, `list_order_matches_plan_28`, `restart_marks_lost_vms_done`, `restart_keeps_live_vms`, `restart_keeps_queue_order`, `gc_removes_discarded_and_orphans`.
- [ ] **Step 2: Run** `cargo test -p saiife-boxes --features fake --test manager` → FAIL.
- [ ] **Step 3: Implement.** One `Mutex<Inner>`, held across VMM and guest calls (they are bounded by the trait contract); recover from poisoning with `into_inner` as `crates/dev/src/docker/fake.rs:53` does.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): the box manager: queue, lifecycle, recovery (spec §7.6, §7.7)`.

---

### Task 7: `ManagerSource`, the `BoxSource` impl, and the conformance kit (size M)

**Files:** Modify `crates/boxes/src/source.rs`; create `crates/boxes/tests/conformance.rs` (`#![cfg(feature = "fake")]`).

**Interfaces:**
- Consumes: `Manager` (Task 6); plan 28 Task 7 (`BoxSource`, DTOs, `check_text`, `MAX_*`) and Task 8 (`saiife_wire::conformance::{Fixture, check}`).
- Produces:
```rust
pub struct ManagerSource { /* mgr: Arc<Manager>, owner: Option<u32> */ }
impl ManagerSource { pub fn new(mgr: Arc<Manager>, owner: Option<u32>) -> ManagerSource; }
impl saiife_wire::BoxSource for ManagerSource { … }
pub fn info(r: &BoxRecord, queue_pos: Option<u32>) -> saiife_wire::BoxInfo;
```
Mapping:

| `BoxSource` | `Manager` | Notes |
|---|---|---|
| `overview` | `list`, `capacity`, `slots` | boxes filtered by `owner` when `Some`; `load = Some(Load { cpu_pct, mem_used_mb: total − avail, mem_total_mb })` when `cpu_pct` is `Some`, else `None` |
| `list` | `list` | same filter |
| `terminal`, `diff` | `get` then `GuestLink` | unknown or other owner's id → `NotFound` |
| `stop` | `stop(id, false)` | |
| `pause`, `resume`, `discard`, `reorder`, `revise` | same name | `reorder` with `owner = Some(u)` must list exactly the queued boxes of `u` |
| `steer` | `say` | |
| `pending_actions` | none | `vec![]` (land is a later plan) |
| `complete` | none | always `NotFound` |
| `templates` | `templates().wire()` | |
| `spawn` | `spawn` with `owner_uid = owner`, `repo_dir = None` | `owner = None` → `Unavailable("Workspace spawn in locked mode needs the device owner")` (B9) |

- [ ] **Step 1: Write the failing tests:** `manager_source_passes_conformance` (a `world(2)` from Task 6's helper, made reusable as `tests/common/mod.rs`: spawn `b1`, `b2` as uid 1000, send `Ready` to both, `done(b2)`, spawn `b3`, `b4` (queued); `src = ManagerSource::new(mgr, Some(1000))`; `check(&Fixture { source: &src, running: b1, done: b2, queued: vec![b3, b4], template: "claude-code".into() })` is `Ok`), `owner_filter_hides_other_users` (box of uid 1001, source owner `Some(1000)` → `list()` empty, `stop` → `NotFound`), `locked_source_cannot_spawn`, `diff_goes_through_the_guest` (`FakeGuest::set_diff` → returned as is; with `NoGuest` → `Unavailable`), `overview_load_and_slots`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): BoxSource over the box manager, passing the conformance kit`.

---

### Task 8: daemon wiring: `box.*` ops, owner, lockdown, audit, tick (size L)

**Files:**
- Create: `crates/daemon/src/box_ops.rs`, `crates/daemon/tests/boxes.rs` (`#![cfg(all(unix, feature = "fake-vmm"))]`).
- Modify: `crates/daemon/Cargo.toml` (deps `saiife-boxes = { path = "../boxes" }`, `saiife-wire = { path = "../wire" }` if absent; `[features] fake-vmm = ["saiife-boxes/fake"]`), `crates/daemon/src/lib.rs` (`mod box_ops`), `crates/daemon/src/ops.rs` (`Ctx.box_manager`, `CtxInit`, `test_ctx`, `dispatch_conn` routes), `crates/daemon/src/start.rs` and `crates/daemon/src/personal.rs` (build the manager next to `approvals::dir_in(&state_dir)`, start the tick), `crates/ipc/src/msg.rs`, `crates/wire/src/level.rs` (`IPC_OPS`).

**Interfaces:**
- Consumes: `Manager`, `ManagerSource`, `load_dir`, `Trust`, `HostFacts` (Tasks 2–7); `ctx.peer_is_admin(peer).await`, `ctx.lockdown.get()`, `ctx.record(kind, input)` + `ctx.writer.append(rec).await` (pattern `crates/daemon/src/lockdown.rs:384-456`).
- Produces:
```rust
// ipc msg.rs: if plan 29 Task 1 has landed, reuse its OP_BOX_* consts; otherwise add exactly its lines
// (plan 29 Task 1, the "Frame actions" block) and note it in the report: whichever plan lands second drops its copy.
pub const OP_BOX_DONE: &str = "box.done";   // {id} -> BoxInfo
pub const OP_BOX_GC: &str = "box.gc";       // {} -> {removed: [id]}
// ops.rs
pub box_manager: Option<Arc<saiife_boxes::Manager>>,   // None = boxes unavailable
// box_ops.rs
pub fn dir_in(state_dir: &Path) -> PathBuf;                       // state_dir/boxes
pub fn templates_dir(mode: &Mode, config_path: &Path, env: &dyn Fn(&str) -> Option<OsString>) -> (PathBuf, saiife_boxes::template::Trust);   // B11
pub fn host_facts(boxes_dir: &Path, prev_cpu: &Mutex<Option<(u64, u64)>>) -> saiife_boxes::capacity::HostFacts;   // /proc/meminfo MemTotal/MemAvailable, available_parallelism, rustix statvfs, /proc/stat delta; non-Linux: Default (nothing fits)
pub fn build(state_dir: &Path, mode: &Mode, config_path: &Path) -> Result<Option<(Arc<saiife_boxes::Manager>, Vec<String>)>, String>;   // Some only with feature fake-vmm and SAIIFE_BOX_FAKE_VMM=1
pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value;
pub fn start_tick(ctx: Arc<Ctx>);   // tokio interval TICK_SECS; spawn_blocking(mgr.tick()); one record per Change, via "tick"
```
Ops on the control socket (args validated with `BoxId::parse` and `check_text` before the manager is called; every manager call in `spawn_blocking`):

| op | args | answer | lockdown `all` | record |
|---|---|---|---|---|
| `box.spawn` | `{template, repo, repo_dir?, task, start: "now"\|"queue"}` | `BoxInfo` | refused | yes |
| `box.list` | `{all?: bool}` | `{boxes: [BoxInfo], slots_total, slots_free}` | allowed | no |
| `box.templates` | `{}` | `{templates: [Template], warnings: [{file, reason}]}` | allowed | no |
| `box.pause` / `box.stop {id, keep?}` / `box.discard` / `box.done` | `{id}` | `BoxInfo` (discard: `{id}`) | allowed | yes |
| `box.resume` / `box.revise {id, comment}` / `box.steer {id, msg}` | | `BoxInfo` / `{}` | refused | yes |
| `box.reorder` | `{ids}` (the peer's queued boxes; an admin may pass all) | `{}` | allowed | yes |
| `box.gc` | `{}` | `{removed}` | allowed | yes (admin or own boxes only: non-admin removes only its own) |
| `box.diff`, `box.term.read` | `{id}` | as plan 29 | allowed | no |

- `box_manager == None` → every op above answers `ErrorCode::Unavailable` with `"boxes are not available in this version"`.
- `BoxError` → `ErrorCode`: `NotFound`, `WrongState`, `Invalid` → `BadRequest` with `rule` = `BoxError::rule()` in the answer map; `Busy` → `Busy`; `Unavailable` → `Unavailable`. Lockdown refusal → `ErrorCode::Lockdown`, rule `lockdown`, a deny record.
- Owner check (B8): before any per-box op, `get(id)`; `owner_uid != peer.uid` and not root and not `peer_is_admin` → `not_found` (the same answer as a missing id).
- `Ctx.boxes`: if plan 29 Task 2's field exists, `build` also sets `ctx.boxes = Arc::new(ManagerSource::new(mgr, owner))` with `owner = Some(ctx.own_uid)` in personal mode and `None` in locked mode (B9); if it does not exist yet, leave a one-line note in the report (plan 29 wires it).
- Startup: `build` warnings (store, recovery, templates) go to stderr as `saiifed: boxes: <warning>`; with `fake-vmm` on, log `saiifed: boxes use a fake VM (test build)` once.
- Add `box.done`, `box.gc` (and the plan 29 `box.*` names if this plan added them) to `saiife_wire::level::IPC_OPS`.

- [ ] **Step 1: Write the failing tests** (`tests/boxes.rs`, `ops::test_ctx` on a tempdir with `box_manager` built over `FakeVmm` + `FakeGuest` and a fixed `HostFacts` closure for 2 boxes; peers via the existing test `Directory`): `unavailable_without_manager` (default `test_ctx` → every op `unavailable`), `spawn_list_stop_roundtrip`, `spawn_is_recorded_with_session` (record `kind == "box"`, `extra.session == "box-b1"`, `extra.via == "cli"`), `other_user_gets_not_found` (uid 2001's `stop`/`steer`/`diff` of uid 2000's box → `not_found`; `box.list` empty), `admin_sees_all` (`all: true`), `lockdown_refuses_power_ops_only` (lockdown `all`: spawn, resume, revise, steer → `lockdown` + deny record; stop, pause, discard → ok), `bad_id_is_bad_request` (`"../b1"`), `escape_in_task_is_bad_request`, `tick_records_changes` (advance the clock past `DONE_IDLE_SECS` after `TurnFinished` → one `tick` record `from: running, to: done`), `templates_lists_warnings` (a bad file in the personal templates dir), `gc_by_non_admin_removes_only_own`. In `crates/wire/tests/ipc_names.rs` (or plan 28's scan test): `box_done_and_gc_are_machine_only`.
- [ ] **Step 2: Run** `cargo test -p saiife-daemon --features fake-vmm --test boxes -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement.** Route in `dispatch_conn` (`crates/daemon/src/ops.rs:1172`) the ops in the table to `crate::box_ops::handle`.
- [ ] **Step 4: Run** → PASS; also `cargo test -p saiife-daemon -j 4 -- --test-threads=4` without the feature (unchanged suite passes); `cargo test -p saiife-wire --features fake`; `bash scripts/check-windows.sh -p saiife-daemon -p saiife-boxes`.
- [ ] **Step 5: Commit** `feat(daemon): box.* ops over the box manager, behind a fake VM in tests`.

---

### Task 9: `saiife box ...` CLI (size M)

**Files:**
- Create: `crates/cli/src/box_cmd.rs`, `crates/cli/tests/box_cmd.rs` (`#![cfg(all(unix, feature = "fake-vmm"))]`).
- Modify: `crates/cli/src/main.rs` (`Cmd::Box`, the no-wildcard match at `main.rs:423-450`, dispatch beside `Cmd::Dev` at `main.rs:666`), `crates/cli/Cargo.toml` (`[features] fake-vmm = ["saiife-daemon/fake-vmm"]`), `crates/cli/tests/common/daemon.rs` (`Opts.env: Vec<(String, String)>` passed to the daemon process, if no such field exists).

**Interfaces:**
- Consumes: Task 8's ops; `crate::broker::resolve_here(config)`, `crate::secret_cmd::linux::call_to` (its `Stop` maps to exit codes), `crate::text::sanitize` for every string from the daemon.
- Produces:
```rust
#[derive(Subcommand)]
pub enum BoxAction {
    /// Start a box from a template, or queue it if the machine is full.
    #[command(visible_alias = "run-agent")]
    Spawn { #[arg(long, default_value = "claude-code")] template: String, #[arg(long, default_value = ".")] repo: PathBuf, #[arg(long)] task: Option<String>, /// Start now or fail; never queue.
            #[arg(long)] now: bool },
    /// List your boxes (all boxes for an admin with --all).
    Ls { #[arg(long)] json: bool, #[arg(long)] all: bool },
    Say { id: String, msg: String },
    Pause { id: String }, Resume { id: String },
    Stop { id: String, /// Keep a snapshot of the VM.
           #[arg(long)] keep: bool },
    Discard { id: String, #[arg(long)] yes: bool },
    Done { id: String },
    Revise { id: String, comment: String },
    /// Reorder the queue: list every queued box once, head first.
    Reorder { ids: Vec<String> },
    Templates { #[arg(long)] json: bool },
    Gc,
}
pub fn run(config: Option<PathBuf>, action: BoxAction) -> ExitCode;   // non-unix: NOT_SUPPORTED_OS, exit 5
```
- `Spawn`: `repo` is canonicalized; `repo` sent = its folder name, `repo_dir` = the absolute path string; the CLI does not read the repo yet (repo in is a later plan). Prints `box <id> <state>` (and `queue position <n>` when queued).
- `Ls` table columns: `ID  STATE  TEMPLATE  REPO  AGE  QUEUE  TASK`; `AGE` as `3m`, `2h`, `1d`; `TASK` sanitized and cut to 40 chars with `…`; a box with `error` gets a second indented line `  error: <sanitized>`. Footer: `slots: <free> of <total> free`.
- `Discard` asks `Discard box <id> and delete its disks? [y/N]` on a TTY unless `--yes`; with no TTY and no `--yes` it refuses (exit 2), as `saiife dev down --volumes` does.
- `attach`, `diff` and `land` are **not** added here (Waits on spike).

- [ ] **Step 1: Write the failing tests** (`tests/box_cmd.rs`, a `TestDaemon` with `env = [("SAIIFE_BOX_FAKE_VMM","1")]`): `spawn_then_ls_shows_the_box`, `ls_json_shape` (keys `boxes`, `slots_total`, `slots_free`), `full_machine_queues_and_now_refuses` (exit 2, stderr contains `busy`), `stop_twice_is_ok`, `discard_without_tty_or_yes_refuses`, `revise_running_is_exit_2_wrong_state`, `hostile_task_is_sanitized_in_ls` (a task containing `\u{202e}` is accepted, and `ls` prints it as the visible text `\u{202E}` (`saiife_audit::text::sanitize`), never the raw character; a task containing ESC `\x1b` is refused with exit 2), `templates_lists_builtin`, `run_agent_alias_spawns`, `unavailable_without_fake_env_is_exit_5` (a `TestDaemon` without the env → exit 5, stderr `boxes are not available in this version`).
- [ ] **Step 2: Run** `cargo test -p saiife --features fake-vmm --test box_cmd -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement.** **Step 4: Run** → PASS; the default `cargo test -p saiife` suite is unchanged; `cargo test -p saiife --test docs_wording` passes on the new help text.
- [ ] **Step 5: Commit** `feat(cli): saiife box spawn|ls|say|pause|resume|stop|discard|done|revise|reorder|templates|gc`.

---

## Gates (after Task 9)

- [ ] `cargo test -p saiife-boxes --features fake` and without the feature; `cargo test -p saiife-daemon --features fake-vmm` and without; `cargo test -p saiife --features fake-vmm --test box_cmd`; all with `-j 4 -- --test-threads=4`.
- [ ] `cargo clippy --workspace --all-targets -j 4 -- -D warnings`; `bash scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife-boxes -p saiife-daemon -p saiife`.
- [ ] `cargo tree -e normal -p saiife-boxes | grep -c tokio` → `0`; `git diff v3-dev -- Cargo.lock` adds only the `saiife-boxes` package entry (and `saiife-wire` under the daemon if plan 29 had not added it).
- [ ] `grep -rn 'fake-vmm' .github/workflows/release*.yml` finds nothing (the feature never ships).
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev` (owner merges).

---

## Waits on spike (later step 3 plans, after the owner's run of plan 25)

Each item names what it needs from `docs/superpowers/research/2026-11-11-box-spike-results.md` (plan 25 Task 6) and where it plugs into this plan.

| Later work | Plugs into | Needs from the spike |
|---|---|---|
| **Cloud Hypervisor driver** (`ChVmm: Vmm`, REST over the API socket with `hyper`, §7.1) | `Vmm` trait (Task 5); replaces `FakeVmm` in `box_ops::build` | That CH v54.1 runs unprivileged with only `/dev/kvm` (and whether `/dev/vhost-vsock` is needed at all, which changes §5.1's `system install`); the exact pause/resume/snapshot/shutdown API calls that worked; stopping the VMM without signals; whether `--landlock` boots and with which rules; firmware vs direct kernel boot and the cold/warm boot time, which sets `BOOT_TIMEOUT_SECS`. The `saiife-box` user, cgroups and `Delegate=yes` need root and are not in the spike: they need their own owner-run check. |
| **Capacity numbers** | `VMM_OVERHEAD_MIB`, admission memory rule (Task 3), idle ballooning (§7.6, not built here) | Host Rss/Pss of an idle box and with dockerd + one container; how much `drop_caches` + free page reporting gives back; whether `resize --balloon` works, to decide the 10-min balloon-down target, and whether admission keeps counting the full 4 GiB (spec: "about 5 boxes"; Task 3 currently counts 6 on 32 GiB). |
| **Base image build and distribution** (§7.2: recipe, custom kernel, signed `base-<sha256>`, `saiife box image pull/build`) | `ImageRef` (Task 2), `VmSpec.image` | Whether the stock Ubuntu kernel runs nested Docker with no NIC (else the custom kernel is the first risk); the base's actual size; erofs vs ext4. |
| **Disk layout** (§7.3: RO base + sparse data disk, image GC while snapshots reference it) | `VmSpec.dir`, `Store::box_dir`, disk admission | Sparse overlay growth vs data written; whether qcow2 backing works as measured or the separate data disk is built; snapshot size and restore consistency with one backing level (§13), which decides whether `stop --keep` stays in v3.0 (§7.7). |
| **vsock gateway + allow-listed CONNECT proxy** (§7.4: per-box listener, `ANTHROPIC_BASE_URL`, audit per host and bytes) | template `egress` and `secrets` (Task 2), lockdown enforcement for boxes | CH's vsock multiplexer paths (`<sock>_<port>`) and throughput; image pulls through the proxy are not measured by the spike and need their own check. |
| **`saiife-guest/1` channel** (PTY, ready marker, Stop hook → `TurnFinished`, terminal stream §9.4) | `GuestLink` and `GuestEvent` (Task 5); replaces `NoGuest`; `saiife box attach` | Guest-to-host vsock behaviour and the ready-marker timing; guest init design. |
| **Repo in / diff out** (§7.5: `mke2fs -d` repo disk, diff export, the adversarial importer of §12, `saiife box diff/land`, `land` touch records, `BoxSource::pending_actions`/`complete`) | `SpawnArgs.repo_dir`, `GuestLink::diff`, Task 7's `pending_actions` | `mke2fs -d` time for a real repo and the size formula; vsock throughput for large diffs. Land also needs plan 26's `TouchClass::Land` records. |
| **Claude Code login in the box** (§7.9: API key and subscription token via placeholder swap; terms check; fallback "credential inside box (weaker)") | template `login` and `credential` (Task 2) | The spike does **not** answer this (plan 25 Task 6 moves it to step 3's gateway plan); it needs the owner's API key and `claude setup-token`, run by the owner. |
| **Delete `scripts/spike/`** and its CI line | none | Only after the owner has run the spike and filled the results doc (B12). |
