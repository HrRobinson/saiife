# Plan 37: disks per box, repo in, and capacity numbers (v3 step 3, VM half 3 of 6): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Reconciled 2026-11-12** against plan 34 as built on `v3-p34` (`ee5e264`) and its rulings R5, R8, R20, R25, R28, R31. Changes:
> 1. **Already in plan 34 (not rebuilt here):** the template bound `disk_gib 10..=1024` (`crates/boxes/src/template.rs:314`, R8); `VMM_OVERHEAD_MIB = 256` (`capacity.rs:15`), `charge_mib` (`capacity.rs:58`), the overhead counted per box in `Committed` and in `admit`/`slots`, and the tests `owner_machine_fits_five_default_boxes` and `exact_fit` (R5); `SpawnArgs.repo_image` and `SpawnArgs.base_manifest: Option<PathBuf>` (`manager.rs:74`, `:76`), which plan 34 refuses with `Invalid("repo disks are not supported yet")` (`manager.rs:320`). Task 1 drops its template edit; Task 5 drops the overhead constant and those two tests; Task 4 replaces the refusal instead of adding fields.
> 2. D7: plan 34 built no balloon-down (the `Vmm` trait has no balloon call), so nothing is dropped; `mem_max_mib` stays reserved.
> 3. `Client::call(&mut self, op, args: Map<String, Value>, deadline: Instant)` (`crates/ipc/src/client.rs:466`): `call_with_fds` takes the same `args` map and a deadline.
> 4. `dispatch_conn` is `crates/daemon/src/ops.rs:1192` on `v3-dev` (not `:1172`); `Conn` is `ops.rs:1144`.
> 5. `box.spawn` on the control socket takes `{template, repo, repo_dir?, task?, start?}` (`box_ops.rs:501-535`) and answers `{box: BoxInfo}` (nested, R20), not a flat `BoxInfo`.
> 6. `box.list` answers `{boxes: [BoxInfo + error?], slots_total, slots_free}` (`box_ops.rs:831-860`); R28 puts per-box extras on each entry, so disk usage is an entry key `disk_mib`, not a top-level `disk` map.
> 7. The disk-floor pause needs a reason on the record: plan 34's `Manager::pause(id)` (`manager.rs:463`) sets no `error`, so Task 5 adds `Manager::pause_for(id, why)`. Its records go through a generalised `write_tick_records` (`box_ops.rs:383`, action `disk_low`).
> 8. `gc` (`manager.rs:770`) continues past per-box errors after plan 34's final fix wave (R31); the incoming sweep follows that rule.
> 9. Global Constraints: branch `v3-p37`; builds with `CARGO_PROFILE_DEV_DEBUG=0`.

> **Depends on:** plan 34 merged; plan 35 Task 1 (scaffold: `Tools`, `BoxPaths`, `Layout`, `boxproto::manifest` stub). Task 1 here unblocks plan 35 Task 5; Task 2 unblocks plan 36 Task 5. Plan 39 (diff out, land) builds on Task 3's base manifest and base ref.

**Goal:** Every box gets its disks, the repo goes in, and admission uses measured numbers:
- the root disk is a per-box qcow2 overlay on the read-only raw base (the spike's layout, `backing_files=on`), grown to the template's `disk_gib`;
- the repo goes in as its own ext4 disk built by the CLI, as the user, with `mke2fs -d` (no root, no mount), from tracked plus untracked-not-ignored files, with a base manifest and a snapshot commit the land step builds on;
- the CLI hands the repo image and the manifest to the daemon as file descriptors over the control socket, so the daemon never opens a path in the user's home (§5.1);
- `VMM_OVERHEAD_MIB = 256` (spike: count 4 GiB + 256 MiB per box, so 5 default boxes on this machine); a host-disk floor pauses boxes before the host fills; `gc` sweeps what boxes leave behind.

**Architecture:**
- **No separate data disk in v3.0** (decision D1). The spike folded §7.3's in-guest overlay and data disk into one host-side qcow2 overlay, and that is what was measured: restore stayed consistent over one backing level, growth is sparse, and `/var/lib/docker`, home and caches all land on it. Discard still deletes the box dir.
- **Overlay and repo image are built with host tools through plan 35's `Tools`:** `qemu-img create` (port of `make_overlay`) and `mke2fs -d` (port of `make_repo_disk`). Tests use fake scripts.
- **File descriptors over the control socket** (`saiife_ipc::fdpass`, safe code over `rustix::net::{sendmsg, recvmsg}` with `ScmRights`). A connection may stash at most 4 passed fds for the next op on the same connection; they are closed when the op ends or the connection drops.
- **The manager places the disks:** plan 34's `SpawnArgs.repo_image` and `SpawnArgs.base_manifest` (already there, refused today) carry paths in `<boxes>/.incoming/`; `Manager::spawn_changes` renames them into the new box dir right after `claim_id` and before the record is saved, so no box is ever admitted without its repo disk.

**Tech Stack:** Rust; `rustix` (`net`, `fs` features, already in `Cargo.lock`), `ring`, `serde_json`. No new crates.

**Spec:** §5.1 (the user's files are touched only by the CLI), §7.3, §7.5 (In), §7.6, §12, §15 ("no reflinks on ext4"). Spike: `scripts/spike/disks.sh` (`make_overlay`, `snapshot_repo`, `make_repo_disk`, the `du -s` fix of `6f68634`); results "Numbers for step 3 planning" and anomaly B.

## Decisions

- **D1. No data disk** (above). `VmSpec.dir` holds `root.qcow2` and `repo.img`; nothing else is attached.
- **D2. `qemu-img` is a host dependency** (package `qemu-img` on Arch, `qemu-utils` on Debian/Ubuntu), at `/usr/bin/qemu-img`. Writing qcow2 headers ourselves is avoidable risk; preflight (plan 35 Task 7) names the package. **Owner check.**
- **D3. Overlay size.** `qemu-img create -q -f qcow2 -F raw -b <base> <dir>/root.qcow2 <disk_gib>G`; the guest grows its root partition at boot (plan 36 `saiife-growroot.service`). The template bound `disk_gib 10..=1024` (the base is 10 GiB, plan 36 I5) is already plan 34's (`template.rs:314`, R8).
- **D4. Repo image size** (spike formula, with the anomaly-B fix): `mib = ceil((2 × bytes + 256 MiB) / 1 MiB)`, where `bytes` = Σ over files of `size` rounded up to 4096, plus 4096 per directory and per symlink. `mke2fs -q -t ext4 -L repo -d <staging> <img> <mib>M`.
- **D5. Repo caps:** `REPO_MAX_BYTES = 8 GiB` (sum as in D4), `REPO_MAX_FILES = 200_000`; over either, spawn refuses and names the biggest top-level dirs (likely a missing ignore rule).
- **D6. Capacity.** `VMM_OVERHEAD_MIB = 256` (spike proposal: the 4 GiB guest RAM can become fully resident under a build, plus a margin for the VMM). With `RESERVE_MEM_MIB = 8192` this host (31839 MiB) admits 5 default boxes, as §7.6 says. **Built by plan 34** (`capacity.rs:15`, `charge_mib` `:58`, R5); nothing to do here.
- **D7. No balloon-down in v3.0.** The spike showed free page reporting returns 90 % of freed guest memory by itself, while a 2 GiB balloon took only 194 MiB more. `mem_max_mib` stays in the template as a reserved field and is not used; plan 34 built no balloon call, so nothing is removed. **Owner check.**
- **D8. Host-disk floor.** `DISK_FLOOR_GIB = 10`: when the boxes filesystem has less free, the tick pauses every `Running` box (`error = "paused: the host disk is almost full"`, one audit record each) and admission already refuses (plan 34's rule needs 30 GiB + the box's disk). Resume is by hand.
- **D9. Snapshot commit.** At spawn the CLI writes the snapshot as a git commit in the user's repo with plumbing only (no hooks, no filters run): blobs with `git hash-object -w --no-filters`, a temporary index, `write-tree`, `commit-tree [-p HEAD]`. After spawn it sets `refs/saiife/box-<id>/base`. Plan 39 lands on top of it, so uncommitted edits the box saw are the base, not part of the agent's diff.

## Global Constraints

Plan 35's Global Constraints apply (including `CARGO_PROFILE_DEV_DEBUG=0`), with worktree `.worktrees/p37`, branch `v3-p37`, scratch prefix `p37-tN-`. **Never run the real `qemu-img` or `mke2fs` in a test** (fake scripts via `SAIIFE_TOOL_QEMU_IMG`, `SAIIFE_TOOL_MKE2FS`); real `git` in tempdir repos is allowed (existing tests do this), with `HOME` and `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`.

### Fixed values

| Name | Value | Source |
|---|---|---|
| overlay command | `qemu-img create -q -f qcow2 -F raw -b <base> <out> <N>G` | spike `make_overlay` |
| repo snapshot list | `git -C <repo> ls-files -z -co --exclude-standard` | spike `snapshot_repo` |
| repo image command | `mke2fs -q -t ext4 -L repo -d <staging> <img> <mib>M` | spike `make_repo_disk` |
| `REPO_MAX_BYTES`, `REPO_MAX_FILES` | `8 << 30`, `200_000` | D5 |
| staging dir | `$XDG_CACHE_HOME/saiife/box-spawn/<16 hex>/` (0700), removed after spawn | |
| incoming dir | `<boxes>/.incoming/<16 hex>/` (0700); swept by `gc` after 3600 s | |
| `VMM_OVERHEAD_MIB` | `256` (plan 34, `capacity.rs:15`) | D6, spike |
| `DISK_FLOOR_GIB` | `10` | D8 |
| fd stash | ≤ 4 fds per connection; op `box.fds` `{n}` then one byte `0x46` with `n` fds | Task 2 |
| `BaseManifest.version` | `1` | |
| base ref | `refs/saiife/box-<id>/base` | D9 |
| snapshot commit message | `saiife box snapshot\n\nSaiife-Box-Snapshot: <manifest sha256>\n` | D9 |

`BaseManifest` (`boxproto::manifest`, JSON, `deny_unknown_fields`): `{version, repo (display name), base_commit: Option<40|64 hex>, snapshot_commit: hex, files: u64, bytes: u64, entries: BTreeMap<path, {kind: "file"|"symlink", mode: 420|493 /* 0o644|0o755; symlinks 0 */, size, sha256}>}`. Paths are the `ls-files` paths: UTF-8, relative, `/`-separated, no `.git` component (non-UTF-8 paths are refused at spawn with their bytes escaped in the message).

## Review Focus

1. **A repo that is mostly build output, or a huge single file** (no `.gitignore` for `target/`, a 9 GiB video). Expected: spawn refuses before any image is built, names the cap and the biggest top-level dirs, and leaves no staging dir (Task 3: `oversized_repo_is_refused_with_top_dirs`, `staging_is_removed_on_failure`).
2. **Odd work-tree entries** (a file deleted but still tracked, a symlink to `/etc/passwd`, a FIFO, a submodule, an untracked nested repo, a path with a newline, a non-UTF-8 name). Expected: deleted files skipped; the symlink copied as a symlink (its target is data, never followed on the host); FIFO, submodule and nested repo skipped with a warning each; the newline path copied (NUL-separated list); the non-UTF-8 name refused (Task 3: `odd_entries`).
3. **fd passing abuse** (an op that sends 5 fds, a directory or a socket fd as the repo image, an image that is not ext4, the CLI closing the connection after the fds). Expected: refused or cleaned up; no fd leaks across connections (Task 2: `too_many_fds_are_refused`, `stash_is_dropped_with_the_connection`; Task 4: `repo_fd_must_be_an_ext4_file`).
4. **A crash between staging and admission** (the daemon dies after writing `.incoming`, the CLI dies before setting the base ref). Expected: `gc` removes the stale incoming dir after an hour; plan 39's land recreates a missing base ref from `snapshot_commit` (Task 4: `incoming_is_swept_by_gc`; Task 3: `base_ref_can_be_recreated`).
5. **The host disk filling up while boxes write** (overlays are sparse and each may grow to 30 GiB). Expected: below 10 GiB free the tick pauses running boxes with a clear error and audit records; nothing is deleted (Task 5: `disk_floor_pauses_running_boxes`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (overlay), Task 2 (fd passing, sparse copy), Task 3 (CLI snapshot and repo image).
- **Wave 2 (parallel):** Task 4 (daemon intake, manager placement; needs 2, 3), Task 5 (capacity, floor, usage, gc).
- **Wave 3:** Task 6 (smoke fragment).

---

### Task 1: the root overlay (size S)

**Files:** Modify `crates/boxhost/src/disk.rs`. (The `disk_gib` bound of D3 is plan 34's already: `template.rs:314`.)

**Interfaces (Produces):**
```rust
pub fn make_overlay(tools: &Tools, base: &Path, out: &Path, virtual_gib: u64) -> Result<(), String>;
// refuses: base not absolute, base or out containing ',', ':' or whitespace (qemu option syntax), out existing;
// writes <out>.tmp then renames; on failure removes the tmp and returns the tool's stderr
```
- [ ] **Step 1: Write the failing tests** (fake `qemu-img` records argv and writes the last-but-one argument): `overlay_argv_is_pinned`, `overlay_refuses_unsafe_paths`, `overlay_refuses_existing_out`, `overlay_failure_leaves_nothing`. (Plan 34's `size_bounds` already refuses `disk_gib = 9` and accepts `10`.)
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): per-box qcow2 overlay on the read-only base (spec §7.3, spike layout)`.

---

### Task 2: fd passing and sparse copy (size M)

**Files:** Create `crates/ipc/src/fdpass.rs`; modify `crates/ipc/src/lib.rs`, `crates/ipc/src/client.rs` (`call_with_fds`), `crates/ipc/src/msg.rs` (`OP_BOX_FDS = "box.fds"`, MachineOnly; add to `saiife_wire::level::IPC_OPS`), `crates/daemon/src/ops.rs` (the connection-scoped stash), `crates/boxhost/src/disk.rs` (`copy_sparse`).

**Interfaces (Produces):**
```rust
// ipc fdpass.rs (#[cfg(unix)])
pub const FD_BYTE: u8 = 0x46;
pub const MAX_FDS: usize = 4;
pub fn send_fds(sock: impl AsFd, fds: &[BorrowedFd<'_>]) -> io::Result<()>;              // one byte FD_BYTE + ScmRights
pub fn recv_fds(sock: impl AsFd, max: usize) -> io::Result<Vec<OwnedFd>>;               // exactly one byte; more than max fds -> InvalidData (all received fds closed)
// ipc client.rs
impl Client { pub fn call_with_fds(&mut self, op: &str, args: Map<String, Value>, fds: &[BorrowedFd<'_>], deadline: Instant) -> Result<Map<String, Value>, ClientError>; }   // as Client::call (client.rs:466); sends {op: "box.fds", n}, then send_fds, then the real request
// daemon ops.rs
impl Conn { pub fn take_fds(&self) -> Vec<OwnedFd>; }   // the stash, emptied
// boxhost disk.rs
pub fn copy_sparse(src: &File, dst: &File) -> io::Result<u64>;   // set_len(src len), then SEEK_DATA/SEEK_HOLE over src, copying data runs only; returns bytes copied
```
**Step 0 (read before coding):** confirm that `dispatch_conn` (`crates/daemon/src/ops.rs:1192` on `v3-dev`; `Conn` at `:1144`) reads each frame with exact-length reads and no read-ahead buffer. If it buffers, the `box.fds` handler must take the raw stream before the next read; note which in the report. The `box.fds` handler calls `recv_fds` through tokio's `UnixStream::async_io(Interest::READABLE, …)` and stores the fds on the `Conn`; a second `box.fds` while fds are stashed is `bad_request`; any op other than the ones that take fds (`box.spawn`, `box.image.import`) clears and closes the stash.

- [ ] **Step 1: Write the failing tests:** ipc `send_recv_roundtrip` (`UnixStream::pair`, two tempfiles, contents read through the received fds), `too_many_fds_are_refused` (5 fds with `max = 4`: error, and `/proc/self/fd` count unchanged after), `no_fd_is_ok_empty`; daemon `fds_reach_the_next_op` and `stash_is_dropped_with_the_connection` (test op wiring through `test_ctx`), `second_box_fds_is_bad_request`; boxhost `copy_sparse_keeps_holes` (1 GiB `set_len` file with 4 KiB written at 0 and at 512 MiB: copy has equal bytes and `st_blocks * 512 < 1 MiB`), `copy_sparse_of_dense_file`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `bash scripts/check-windows.sh -p saiife-ipc` (fdpass is `#[cfg(unix)]`).
- [ ] **Step 5: Commit** `feat(ipc): pass file descriptors over the control socket; sparse file copy`.

---

### Task 3: the CLI repo snapshot, base manifest and repo image (size L)

**Files:** Create `crates/cli/src/box_repo.rs`, `crates/cli/tests/box_repo.rs`; modify `crates/boxproto/src/manifest.rs`.

**Interfaces (Produces):**
```rust
// boxproto manifest.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields, rename_all = "snake_case")] pub enum EntryKind { File, Symlink }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)] pub struct Entry { pub kind: EntryKind, pub mode: u32, pub size: u64, pub sha256: String }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)]
pub struct BaseManifest { pub version: u32, pub repo: String, pub base_commit: Option<String>, pub snapshot_commit: String, pub files: u64, pub bytes: u64, pub entries: BTreeMap<String, Entry> }
impl BaseManifest { pub fn parse(text: &str) -> Result<BaseManifest, String>; pub fn sha256(&self) -> String; }   // version 1; every key passes `check_path`
// cli box_repo.rs
pub struct Snapshot { pub staging: PathBuf, pub manifest: BaseManifest, pub warnings: Vec<String> }
pub fn snapshot(tools: &Tools, repo: &Path, cache: &Path) -> Result<Snapshot, String>;
pub fn repo_image_mib(m: &BaseManifest, dirs: u64) -> u64;      // D4
pub fn make_repo_image(tools: &Tools, s: &Snapshot) -> Result<PathBuf, String>;   // <staging>/../repo.img
pub fn snapshot_commit(tools: &Tools, repo: &Path, s: &Snapshot) -> Result<String, String>;   // D9; also fills manifest.snapshot_commit
pub fn set_base_ref(tools: &Tools, repo: &Path, id: &BoxId, commit: &str) -> Result<(), String>;   // git update-ref refs/saiife/box-<id>/base <commit> "" (create only)
```
`boxproto::manifest::check_path(p: &str) -> Result<(), String>` is defined in **this** task (plan 39's delta validator reuses it): non-empty, ≤ 4096 bytes, each component 1..=255 bytes, no NUL, no `\` , not absolute, no `.` or `..` component, no component equal to `.git` in any letter case.

`snapshot` (port of `snapshot_repo`, in Rust, no `tar`): `git rev-parse --show-toplevel` must equal the canonical repo path (refuse a subdirectory with a hint); `git rev-parse --verify -q HEAD` → `base_commit` (unborn → `None`); `ls-files -z -co --exclude-standard`, then per path: `check_path`; `symlink_metadata` missing → skip silently (deleted); a dir (submodule, nested repo, trailing `/`) → skip with warning; a symlink → recreate it in staging with the same target bytes, entry `Symlink`, `sha256` of the target bytes, `mode 0`; a regular file → copy (`std::fs::copy` with `O_NOFOLLOW` source open), mode `0o755` if any x bit else `0o644`, entry `File`; anything else → skip with warning. Caps (D5) are checked while walking, before copying the file that would cross them. Staging files are written 0644/0755; dirs 0755.

`snapshot_commit`: `GIT_INDEX_FILE=<staging>/../index git read-tree --empty`; `git hash-object -w --no-filters --stdin-paths` over the staged files (in manifest order) and `git hash-object -w --stdin` per symlink target; `git update-index --index-info` with `100644|100755|120000 <oid>\t<path>` lines; `git write-tree`; `git commit-tree <tree> [-p <base_commit>] -F -` with the fixed message. Every git call: `-c core.hooksPath=/dev/null -c core.fsmonitor=false`, env `GIT_TERMINAL_PROMPT=0`.

- [ ] **Step 1: Write the failing tests** (`tests/box_repo.rs`, a real tempdir git repo, fake `mke2fs` that records argv and writes the image path): `snapshot_copies_tracked_untracked_and_edits` (a committed file with an uncommitted edit, an untracked file, an ignored file: the first two in staging with the edited content, the ignored one absent; `base_commit` set), `odd_entries` (Review Focus 2), `manifest_hashes_and_modes`, `image_size_formula` (D4, exact `mib` for a fixture manifest), `mke2fs_argv_is_pinned`, `oversized_repo_is_refused_with_top_dirs` (`REPO_MAX_FILES` lowered through a debug-only `SAIIFE_TEST_REPO_MAX_FILES`), `staging_is_removed_on_failure`, `snapshot_commit_tree_matches_staging` (`git ls-tree -r <commit>` equals the manifest; `HEAD` and the index unchanged; no hook ran: a `pre-commit` hook that writes a marker is never triggered), `unborn_repo_has_no_parent`, `subdir_is_refused`, `base_ref_can_be_recreated` (`set_base_ref` twice: the second is `Ok` when it already points at the same commit, an error when it points elsewhere); boxproto `check_path_rules` (`a/b` ok; `""`, `/a`, `a/../b`, `./a`, `a//b`, `.GIT/config`, `x/.git`, `a\b`, 256-byte component refused).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): repo snapshot, base manifest, snapshot commit and the mke2fs -d repo disk (spec §7.5 In)`.

---

### Task 4: daemon intake and manager placement (size M)

**Files:** Create `crates/daemon/src/box_repo.rs`; modify `crates/daemon/src/box_ops.rs` (`box.spawn` takes the stash), `crates/boxes/src/manager.rs` (`SpawnArgs`, `spawn`, `gc`), `crates/cli/src/box_cmd.rs` (`Spawn` builds the snapshot, calls `call_with_fds`, sets the base ref, removes staging).

**Interfaces:**
- Consumes: Task 2 (`take_fds`, `copy_sparse`), Task 3 (`BaseManifest`, `snapshot`, `make_repo_image`, `snapshot_commit`, `set_base_ref`).
- Produces:
```rust
// boxes manager.rs: plan 34's SpawnArgs already has repo_image and base_manifest (manager.rs:74, :76); this task
// replaces the refusal at manager.rs:320 with: both or neither (one alone is Invalid before an id is claimed); paths inside <store root>/.incoming/
// spawn_changes: after claim_id, rename repo_image -> <dir>/repo.img and base_manifest -> <dir>/base.json, before saving the record; a rename error releases the id's dir and returns Unavailable
// gc: also removes <root>/.incoming/* older than 3600 s (mtime)
// daemon box_repo.rs
pub fn intake(boxes_root: &Path, fds: Vec<OwnedFd>) -> Result<(PathBuf, PathBuf, BaseManifest), String>;   // returns (repo_image, base_manifest, parsed)
```
`intake` checks, in order: exactly 2 fds; each `fstat` a regular file; image size ≤ 2 × `REPO_MAX_BYTES` + 256 MiB; bytes 1080..1082 of the image are `0x53 0xEF` (ext4 magic, little-endian `0xEF53` at superblock offset 56); manifest ≤ 64 MiB and parses; then `copy_sparse` both into a fresh `.incoming/<16 hex>/` (image 0640, manifest 0600). The `box.spawn` answer is unchanged (plan 34's nested `{box: BoxInfo}`, R20); the record's `repo` display name comes from the manifest (≤ `MAX_REPO_BYTES`, `manager.rs:45`). Without fds `box.spawn` still works (no repo disk), as plan 34 tests expect.

CLI `Spawn` order (a hidden `--timings` flag prints each step's milliseconds to stderr for the smoke script): snapshot → image → snapshot commit → `call_with_fds("box.spawn", …, [image, manifest])` → `set_base_ref(id)` → remove staging (also on every error path). A failed `set_base_ref` warns (`land will recreate it`) and still exits 0.

- [ ] **Step 1: Write the failing tests:** boxes `spawn_places_repo_disk_before_admission` (FakeVmm's `create` sees `<dir>/repo.img`), `spawn_without_repo_is_unchanged`, `repo_image_without_manifest_is_invalid` (no id claimed: the counter is unchanged), `rename_failure_releases_the_id`, `incoming_is_swept_by_gc` (mtime set back 2 h with `File::set_modified`); daemon `repo_fd_must_be_an_ext4_file` (a tempfile without the magic → `bad_request`; a directory fd → `bad_request`), `intake_copies_into_incoming`, `spawn_with_fds_roundtrip`; CLI (`--features fake-vmm`, `TestDaemon`) `spawn_sends_repo_and_sets_base_ref`, `spawn_cleans_staging_on_error`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): repo disk in at spawn, handed over as fds and placed before admission`.

---

### Task 5: capacity numbers, disk floor, usage and gc (size S)

**Files:** Modify `crates/boxes/src/capacity.rs` (floor only), `crates/boxes/src/manager.rs` (`pause_for`), `crates/boxhost/src/disk.rs` (`usage`), `crates/daemon/src/box_ops.rs` (tick floor; `box.list` entries), `crates/cli/src/box_cmd.rs` (`Ls` `DISK` column).

**Interfaces (Produces):**
```rust
// capacity.rs: VMM_OVERHEAD_MIB = 256 and charge_mib are plan 34's (capacity.rs:15, :58); not touched
pub const DISK_FLOOR_GIB: u64 = 10;          // capacity.rs
pub fn below_floor(h: &HostFacts) -> bool;   // h.disk_free_mib < DISK_FLOOR_GIB * 1024 (HostFacts.disk_free_mib, capacity.rs:23)
// manager.rs
impl Manager { pub fn pause_for(&self, id: &BoxId, why: &str) -> Result<Change, BoxError>; }   // pause() plus record.error = why
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)] pub struct DiskUsage { pub root_bytes: u64, pub repo_bytes: u64, pub snapshot_bytes: u64 }   // allocated (st_blocks × 512)
pub fn usage(paths: &BoxPaths) -> DiskUsage;  // boxhost disk.rs; missing files count 0
```
- Tick (daemon, `tick_once`, `box_ops.rs:354`): when `below_floor`, `mgr.pause_for(id, "paused: the host disk is almost full")` for each `Running` box, one audit record per box through `write_tick_records` generalised to take the action (`action = "disk_low"`, `via = "tick"`); logged once per crossing, not every tick.
- `box.list` entries gain `disk_mib` (allocated MiB) beside plan 34's `BoxInfo` fields and R28's `error`; `Ls` prints `DISK` after `AGE` (e.g. `412M`, `3.1G`).

- [ ] **Step 1: Write the failing tests:** capacity `below_floor_rule` (10 GiB free → false, 10 GiB − 1 MiB → true); manager `pause_for_sets_error`; daemon `disk_floor_pauses_running_boxes` (`SAIIFE_BOX_FAKE_SLOTS`-style host with 9 GiB free through `build_with`'s env: running boxes `Paused` with the error, one `disk_low` record each, a second tick writes no new record), `list_reports_disk_per_entry` (`boxes[0].disk_mib` present; no top-level `disk` key); boxhost `usage_counts_allocated_bytes`. (Plan 34 already has `owner_machine_fits_five_default_boxes` and the 256 MiB `exact_fit`.)
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): host-disk floor and disk usage per box`.

---

### Task 6: the smoke fragment (size S)

**Files:** Create `scripts/box-smoke.d/20-disks.sh`.

Owner-run checks (result keys): spawn with `REPO=<path>` (default: this checkout) and read `repo_snapshot_ms`, `repo_mkfs_ms`, `repo_img_bytes`, `repo_files` from `saiife box spawn --timings` (a hidden flag Task 4 adds that prints the step times to stderr); inside the box the file count under `/work` equals `repo_files` (`repo_files_in_guest`); `overlay_after_boot` and `overlay_after_build` (the 200 MiB build of plan 36's fragment) from `saiife box ls --json` entries' `disk_mib`; free page reporting: VMM Rss after the build and 20 s after a guest `drop_caches` (`rss_after_build_kib`, `rss_after_drop_kib`); start boxes until the sixth queues on a 32 GiB host (`slots_total = 5`); fill the host disk is **not** tested (destructive), the floor is unit-tested.

- [ ] **Step 1:** write the fragment (it also prints the spike's re-run advice: run with no agent builds on the host); `bash -n`; shellcheck if installed.
- [ ] **Step 2: Commit** `test(boxes): owner smoke for disks, repo in and capacity`.

---

## Gates

- [ ] `cargo test -p saiife-ipc -p saiife-boxproto -p saiife-boxhost --features fake -p saiife-boxes --features fake -p saiife-daemon --features fake-vmm -p saiife --features fake-vmm`; also the daemon and CLI suites without features; `-j 4 -- --test-threads=4`.
- [ ] clippy; `check-unsafe.sh`; `check-windows.sh -p saiife-ipc -p saiife-boxes -p saiife-daemon -p saiife`; tokio gate `0` (ipc stays tokio-free: `fdpass` is plain `rustix`).
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`.

## Owner handwork

- [ ] Decide D2 (`qemu-img` as a host dependency) and D7 (no balloon-down).
- [ ] Run `scripts/box-smoke.sh --only disks` on a quiet host (the spike's anomalies A and B came from parallel builds).
