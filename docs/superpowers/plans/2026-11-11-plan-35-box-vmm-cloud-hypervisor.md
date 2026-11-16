# Plan 35: the Cloud Hypervisor `Vmm` driver (v3 step 3, VM half 1 of 6): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Reconciled 2026-11-12** against plan 34 as built on `v3-p34` (`ee5e264`; its final fix wave R29–R31 is still open) and its ledger rulings. Changes:
> 1. Names checked: `Vmm`, `VmSpec { id, size, image, dir }`, `VmStatus { Created, Running, Paused, Off, Gone }`, `VmmError { Unavailable, Failed }` (`crates/boxes/src/vmm.rs`); `VmHandle { id, driver, data: String }` is defined in `store.rs:20` and re-exported by `vmm.rs`; `Vmm::snapshot(&self, h, dest: &Path)` and the manager passes `<box>/snapshot` (`manager.rs:552`). The boxes crate's feature is `fake`; `fake-vmm` is the daemon's and CLI's.
> 2. **Already in plan 34 (not rebuilt here):** `BOOT_TIMEOUT_SECS = 90` (`manager.rs:39`, R8), the template bounds `vcpus 1..=32`, `mem_mib 512..=262144`, `disk_gib 10..=1024` (`template.rs:310-317`), `VMM_OVERHEAD_MIB = 256` (`capacity.rs:15`, R5). Task 7 no longer edits `manager.rs`.
> 3. `box_ops::build(state_dir, mode, config_path) -> Result<Option<Built>, String>` with `build_with(.., env)` and `Built { manager, warnings, template_warnings }` (`box_ops.rs:201-233`, R21); `ManagerInit { store, vmm, guest, templates, host, clock }` (`manager.rs:56`). Task 7's wiring is written against these.
> 4. `dir_in(state_dir)` (`box_ops.rs:75`) takes no mode: V5 changes its signature to `dir_in(state_dir, mode)`.
> 5. Task 6: `crates/system` has no install `Step` type; install is `install_locked(..)` with `InstallOptions` (`install.rs:51`, `:406`) over `&dyn Host` (`host.rs:158`), tested with `saiife_system::testing`. Rewritten to that pattern.
> 6. The CI tokio gate is the `no tokio in hook crates` step, `ci.yml:164` on `v3-dev` (`:176` on `v3-p34`, which already lists `saiife-boxes`), not `:151`.
> 7. Restart and recovery (plan 34 R29, R31, pending): the manager will save the record with `vm: Some(h)` right after `create` and before `boot`, and recover `Starting` records that have a handle; `ChVmm::status` of a created but never booted handle is `Off` (test added). The manager's recovery changes are audited by plan 34's fix wave, not here.
> 8. Readiness: plan 34's `fake_ready` (R26) runs only in `fake-vmm` builds; with `ChVmm` a box stays `Starting` until plan 38's `GuestEvent::Ready`, and the 90 s boot timeout discards it before plan 38 lands (owner smoke uses `--task ""` and checks `starting` → timeout until then).
> 9. Global Constraints: `CARGO_PROFILE_DEV_DEBUG=0` for every build (disk, plan 30 R-0); branch `v3-p35` (the controller's naming).
> 10. The manager never parses `VmHandle.data` (`store.rs:17`): the image id reaches it through plan 36's `Vmm::image_id`, not by reading the JSON.
> 11. Task 7: a failed preflight is reported through a new `Ctx.box_unavailable` (plan 34's `handle` answers a fixed `UNAVAILABLE` when `box_manager` is `None`, `box_ops.rs:661-663`).

> **As built on `v3-p35` (2026-11-12): what Task 7 and later plans must know.**
> 1. `Layout.vault` (R18): daemon-owned, never VMM-writable; it holds `<id>.marker`, `<id>.snap/` and `<id>.pid`. `Layout.boxes` is the VMM's runtime root (personal `<state>/box-run`, R37), never the records (see item 7's table). Locked dir modes (R26): `/var/lib/saiife-box` root:saiife-box 0750, `boxes/` saiife:saiife-box 3770, `images/` and `vault/` 2750.
> 2. Liveness comes only from `Launcher::exited` (R19); this supersedes Review Focus 4's "status answers from the API socket". The API only refines Running/Paused/Created of a live process; a live VMM whose API says Shutdown is Running, and `destroy` removes a box's state only once the launcher says gone (Task 7 round 2, I1). Tests re-root the locked layout with the debug-only `SAIIFE_TEST_BOX_ROOT`; a re-rooted locked layout never reaches the system bus (M1); a test root that is not absolute or resolves to `/` or into the real locked roots is an error, never the real layout (M-4). Every CLI `TestDaemon` sets `SAIIFE_TEST_BOX_ROOT=<its dir>/box-root`, and the debug-only `SAIIFE_TEST_KVM` replaces `/dev/kvm` in the personal preflight (M-2), so no test reads the host's install or `/dev/kvm`. Unit bus: `NoSuchUnit` = gone, any other bus error = alive (R27).
> 3. Restore only from the hashed vault copy: `LaunchSpec.restore: Option<PathBuf>` = `<vault>/<id>.snap` (R20), one-shot (R13); `VmHooks::restore_refused` must be audited by the daemon (R14).
> 4. `ChVmmInit.vmm_uid` must be the `saiife-box` uid in locked mode; `landlock = true` unconditionally outside tests (R23). `StopTimes` has `force_s` (35 s): the wait after a unit's force stop; a run whose exit shows up later still gets `after_off` once, on the next `status`/`stop`/`boot`/`destroy`.
> 5. `destroy` may return `Failed` when the exit is unconfirmed: keep the box dir then. `destroy` is bounded to about a second (R41): it asks for the stop (the reaper runs the ladder) and, when the VMM is still booting or stopping, returns `Failed("the VMM is still stopping")` keeping every file (runtime dir, vault, pid record); state goes only once the launcher says gone. Plan 34's manager tick retries `destroy` for every Discarded record that still holds `vm` and clears `vm` (and the destroy failure in `error`) once it succeeds; gc retries it too.
> 6. The runtime dir's `snapshot/` is made by `saiife __box-vmm` (0770, as the VMM user) before the exec and only ever emptied by fd while the box lives (Landlock binds its rule to that inode); `destroy` removes it with the runtime dir. A snapshot copy is capped at `mem_mib` + 64 MiB (`mem_mib` from the handle's `data`), `config.json`/`state.json` at 16 MiB.
> 7. Locked mode, Task 7 (as built, rulings R37/R38): the box store keeps plan 34's `Store::open` (0700 root and box dirs) in the daemon's own state dir in both modes; the R34 shared-store mode was reverted. Record files are read fd-relative, O_NOFOLLOW, plain file of the daemon uid with one link, else the box is corrupt (never trusted, never removed). The overlay is fchmodded 0660 by `ChVmm::create` in locked mode, also when it already exists (R35). The box unit sees only its own runtime dir (rw), `images/` (ro) and its own `vault/<id>.snap` (ro) under a read-only tmpfs over `/var/lib/saiife-box` (final review I6). `system install --boxes` refuses a daemon user other than `saiife` (the polkit rule names it). Real boxes need the daemon feature `boxes` (off by default; CI only, never a release workflow until plan 41).
>
>    | | personal | locked | holds | written by |
>    |---|---|---|---|---|
>    | records | `<state>/boxes/<id>/` (0700) | `/var/lib/saiife/boxes/<id>/` (the daemon's StateDirectory, 0700) | `box.json`, marker, `next-id`; plans 37-39: `base.json`, `term.cast`, `lands/`, `placeholder`, review/land state | the daemon only |
>    | runtime | `<state>/box-run/<id>/` (0700) | `/var/lib/saiife-box/boxes/<id>/` (2770 under the 3770 sticky root) | `vm.json`, `api.sock`, `vsock.sock*`, `serial.log`, `ch.log`, `root.qcow2`, `repo.img`, `snapshot/` | the daemon (`ChVmm::create`) and the VMM |
>    | vault | `<state>/box-vault/` (0700) | `/var/lib/saiife-box/vault/` (2750) | `<id>.marker`, `<id>.snap/`, `<id>.pid` | the daemon only (the VMM reads its own `.snap`) |
>
>    `VmSpec.dir` is the record dir (`ChVmmInit.records/<id>`, checked); `snapshot(h, dest)` checks `dest = <record dir>/snapshot` and never writes it (the VMM writes the runtime `snapshot/`, sealed into the vault). `destroy`, after a confirmed exit, removes the runtime dir by fd and the box's vault entries; an unconfirmed exit keeps everything. Personal mode: the VMM runs as the user, so its Landlock rules (runtime dir, disks, its vault copy read-only) are the boundary; they never cover the record dirs.
> 8. Owner-smoke checks (not testable here): CH v54 snapshot file names and `VmConfig` fields against `check_config`; Landlock with the pre-made snapshot dir (CH writes a snapshot under `--landlock`); CH reading the vault copy at restore under Landlock and the unit's binds; the unit's `BindPaths` box dir is writable under `ProtectSystem=strict`.
> 9. `check_spec`'s symlink walk starts at `/`: a user whose state dir has a symlinked ancestor is refused. Before personal boxes ship, walk only below the canonicalised `allowed.boxes`.
> 10. **Plan 37 merge checklist** (R40 amended; plan 37 is not merged into `v3-p35`):
>     - at the merge `open_manager` passes `disk_place: box_ops::disk_place()` (never `None`) on both the fake and the real paths;
>     - the placer puts `base.json` and `repo.img` in the RECORD dir (`<state>/boxes/<id>/`); plan 37's `names_in` and `.incoming` are unchanged (`.incoming` under the daemon-only store root);
>     - `ChVmm::create` moves `<records>/<id>/repo.img` into the runtime dir by fd (`renameat`, `O_NOFOLLOW`, a regular file of the daemon uid with nlink 1, a copy on `EXDEV`, `fchmod` 0660 in locked mode as for the overlay); `base.json` never leaves the record dir;
>     - delete `BoxPaths::base_manifest` from the merge result;
>     - `layout::boxes_in` names only the record root, and `Layout::personal.boxes` stays `<state>/box-run`;
>     - the locked roots `/var/lib/saiife/boxes` (records, the daemon's StateDirectory, 0700) and `/var/lib/saiife-box/boxes` (runtime, 3770) are distinct by design.
>     - The hint for a missing default image is `saiife_boxhost::image::DEFAULT_IMAGE_HINT` (R43), used by `Store::resolve` and the preflight; plan 36 Task 5 removes the part after the semicolon ("making it the default ... is not in this build yet") and adds `--help` CLI tests. `box_image_cmd.rs`'s own `next:` line (parsed by `05-image.sh`) is separate and unchanged.
> 11. Restore checks `state.json` too (integration, 2026-11-16): `snapshot::check_state` runs in `verify` on the hashed bytes. One vCPU state per vCPU (`snapshots.cpu-manager.snapshots` keyed `"0"`..), the memory manager's JSON-encoded state with `boot_ram` = `current_ram` = the sum of `guest_ram_mappings` sizes = `mem_mib` MiB, no virtio-mem mapping, every hotplug slot unused, the saved `memory_ranges.data` at most the RAM, and the `memory-ranges` file at most the RAM plus `SLACK_MIB`. The snapshot `platform` section may hold CH's defaults only (one PCI segment; no `tdx`, `sev_snp`, iommufd, IOMMU segments, OEM strings or SMBIOS fields). Anything else, or a state that cannot be parsed, boots cold with `restore_refused`. Owner smoke: confirm the ids `cpu-manager` and `memory-manager` and the field names on a real CH v54 snapshot (from source, not captured); if they differ every restore boots cold (fail closed).
> 12. Honest limit: the outside-CH cap is the template maximum, not the box's size. The locked unit file (written by the root installer) has fixed `MemoryMax=262400M` (`template::MAX_MEM_MIB` + `launch::VMM_OVERHEAD_MIB` 256 MiB = `launch::UNIT_MEMORY_MAX_MIB`), `MemorySwapMax=0` (or `MemoryMax=` only moves pages to swap), `CPUQuota=3200%` (`MAX_VCPUS` x 100%), `TasksMax=512` and `LimitNOFILE=4096`. The daemon is never given `set-property` (polkit cannot restrict which properties, so it could loosen `DeviceAllow=` or the paths): the rule stays start/stop only. Per-box exactness is layer 1: the spec the daemon rebuilds every boot (`check_limits`) and the snapshot's `config.json`/`state.json` bounds (item 11). Owner smoke: the overhead and `TasksMax` are enough for CH. **Personal-mode gap:** `ChildLauncher` sets no cap at all; the VMM shares the daemon's cgroup, so a compromised VMM is bounded only by the user's own limits.

> **Build order (owner ruling 2026-11-12):** boxes (plans 35–40) do not ship in a release before plan 41 (`2026-11-12-plan-41-linux-fido-helper.md`, the Linux FIDO helper) is done: without it a Linux release `saiife box land` cannot touch a key. They may be built and merged into `v3-dev` before then; the release that first enables them must contain plan 41.

> **Owner-approved contract additions (2026-11-12):** `TouchClass::Steer` (plan 31), `IssueKey::{Web, Land, Push}` (plans 31, 39), `Vmm::image_id` (plan 36; this plan's `ChVmm` answers it from its handle's `image`, note 10). No longer flagged.

> **Depends on plan 34 being merged into `v3-dev`** (`crates/boxes`: `Vmm`, `VmSpec`, `VmHandle`, `VmStatus`, `VmmError`, `Manager`, `box_ops::build`, the boxes `fake` feature behind the daemon's `fake-vmm`). Task 5 also needs **plan 37 Task 1** (`disk::make_overlay`) and Task 7 needs **plan 36 Task 4** (`image::Store` as `ImageResolver`). Task 1 of this plan is the scaffold every other VM-half plan (36–40) builds on: it runs first, alone.

**Goal:** Replace `FakeVmm` with a real driver:
- `ChVmm: saiife_boxes::Vmm` runs one unprivileged Cloud Hypervisor v54.0 process per box, driven over its REST API on a Unix socket, with Landlock on;
- the VMM is started through a small helper, `saiife __box-vmm <dir>`, that checks the launch spec and the binary's pinned digest, then execs Cloud Hypervisor; personal mode runs it as a child of the daemon, locked mode as a systemd template unit `saiife-box@<id>.service` under the `saiife-box` user;
- every call is bounded by a timeout, and stop is the spike's ladder: power button, then `vmm.shutdown`, then the launcher's last resort;
- `saiife box vmm fetch` downloads the pinned VMM and firmware; `saiife doctor` reports box readiness.

**Architecture:**
- **New crates (Task 1), all tokio-free:** `saiife-boxhost` (`crates/boxhost`, unix-only: everything the host does to a VM), `saiife-boxproto` (`crates/boxproto`, portable: the `saiife-guest/1` protocol and the delta format), `saiife-guest` (`crates/guest`, Linux-only: the in-box init). Task 1 declares every module plans 35–40 fill, so those plans add none.
- **The API client is a small synchronous HTTP/1.1 client over `std::os::unix::net::UnixStream`**, not hyper: `Vmm` is a sync trait, the API is eight fixed calls with tiny JSON bodies, and a tokio-free crate keeps the CI tokio gate. (Spec §7.1 says "with `hyper`"; this is a deviation, flagged.)
- **The daemon never builds a Cloud Hypervisor command line.** It writes `<box>/vm.json` (a `LaunchSpec`); the helper validates it against the dirs it derives itself (never from the file), checks the binary's SHA-256 against the pin, builds argv with `launch::argv` (a port of `scripts/spike/vm.sh` `ch_boot`) and execs.
- **Locked mode replaces §5.1's `Delegate=yes` with a template unit.** Each VMM is `saiife-box@<id>.service` (`User=saiife-box`, `DeviceAllow=/dev/kvm rw`, its own cgroup from systemd). The daemon starts and stops it with systemd's D-Bus `StartUnit`/`StopUnit`, allowed by a polkit rule that matches only that unit pattern and only the `saiife` user. Root is needed once, at `saiife system install --boxes`.
- **Host-side listeners are bound before boot** by `VmHooks` (vsock listeners from plan 38, gateway listeners from plans 38 and 40), so the guest never connects to a socket that is not there yet.

**Tech Stack:** Rust. `serde`, `serde_json`, `ring` (SHA-256), `rustix` (already in `Cargo.lock`); the daemon adds `zbus = "=5.19.0"` (already in `Cargo.lock` via `saiife-keychain`). No new crates.

**Spec:** `docs/superpowers/specs/2026-11-10-saiife-v3-design.md` §5, §5.1, §7.1, §7.6, §7.7, §11 step 3, §12, §15. Plan 34 (`Vmm` seam, "Waits on spike"). Spike recipe: `scripts/spike/vm.sh` (`ch_launch`, `ch_boot`, `ch_stop`, `ch_api`) and `box-spike.sh` (pins) on branch `v3-box-spike`; results `docs/superpowers/research/2026-11-11-box-spike-results.md` on that branch.

## Decisions

- **V1. Pins (owner ruling "CH/firmware binaries by pinned digest").** Cloud Hypervisor `v54.0` (`cloud-hypervisor-static`), firmware `CLOUDHV.fd` of edk2 release `ch-97eeb7b09`; digests copied from `scripts/spike/box-spike.sh`. `ch-remote` is not used. A binary whose SHA-256 differs from the pin is refused at fetch **and at every launch**.
- **V2. Stop ladder** (port of `ch_stop`, the trait's "returns within about a second" kept): `stop` sends `vm.power-button` (ACPI, the guest's systemd powers off) and returns. A per-VM reaper thread waits `power_s = 60` s for the VMM to exit, then `PUT vmm.shutdown` and waits `shutdown_s = 30` s, then the launcher's `force_stop`: `Child::kill` of the daemon's own child (personal), or `StopUnit` (locked; systemd ends the cgroup). That last step is the only signal anywhere, and it is sent by the launcher, never by a `kill` tool. **Owner check.**
- **V3. Snapshot blocks.** `snapshot` is the one call that may take long (spike: 14 s for 4 GiB); it is bounded at 120 s and documented as the trait's exception. Restore happens in `boot` when `<box>/snapshot/config.json` exists (`--restore source_url=file://…`, then `vm.resume`).
- **V4. `BOOT_TIMEOUT_SECS = 90`**: already taken by plan 34 (`crates/boxes/src/manager.rs:39`, its R8); the spike's cold boot is 4.2 s and its worst loaded warm boot 27 s.
- **V5. Box root dirs.** Locked: `/var/lib/saiife-box/boxes` and `/var/lib/saiife-box/images` (group `saiife-box`, setgid, 2770/2750), because the daemon's own `StateDirectory` is 0700 and the VMM user cannot enter it. Personal: plan 34's `<state>/boxes` and `<state>/images`. This changes plan 34's `box_ops::dir_in(state_dir)` (`box_ops.rs:75`) to `dir_in(state_dir, mode: &Mode)` (flagged).
- **V6. VMM dir.** Locked `/opt/saiife/vmm` (root, 0755, written by `system install --boxes`); personal `$XDG_DATA_HOME/saiife/vmm` (0700, written by `saiife box vmm fetch`).
- **V7. Socket paths ≤ 100 bytes** (`sockaddr_un` limit with margin, as the spike checked). `create` refuses a box dir whose longest socket path (`vsock.sock_5003`) would exceed it.
- **V8. Paths are CH-option-safe.** Cloud Hypervisor splits option values on `,` and `=`: `check_spec` refuses any path with `,`, `=`, whitespace, a control character or non-UTF-8 bytes.
- **V9. Debug-only seams.** `SAIIFE_TOOL_<NAME>` overrides a tool path and `SAIIFE_TEST_NO_PIN=1` skips the digest check **only when `cfg!(debug_assertions)`**, the same rule as `sandbox::SPAWN_HELPER_SEAM`. Release builds ignore both.

## Global Constraints

Owner hard rules (`.superpowers/sdd/hard-rules.md`) bind every task. The ones this plan meets most:
- **No VM, no Cloud Hypervisor, no `/dev/kvm`, no passt, no real `qemu-img` or `mke2fs` in any test or agent command.** Tests use the `saiife-fake-ch` test binary (Task 3), fake tool scripts in tempdirs, and recorded fixtures. Real VMs run only in the owner's `scripts/box-smoke.sh`; agents only `bash -n` and shellcheck it. Never run `scripts/spike/box-spike.sh` (except `--help`).
- No sudo, systemctl, kill, pkill, pgrep or other process-control tools; `Child::kill` on a child your own test spawned is allowed. No writes to /etc, /opt, /var, /run. No docker. No `~/.claude`.
- Tests never use the network. `saiife box vmm fetch` tests use a fake `curl` that copies a local file.
- Test isolation: `TMPDIR` and `SAIIFE_TEST_TMP` from `mktemp -d -p /home/jonas/projects/personal/saiife p35-tN-XXXXXX`; `HOME`, `PATH`, `SAIIFE_DATA_DIR`, `SAIIFE_AUDIT_DIR`, `XDG_*` at tempdirs. Socket paths in tests must stay under 100 bytes: make box dirs with short names directly under `$TMPDIR`.
- Disk: every build with `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` (plan 30 R-0: several builders share one disk).
- Git: worktree `.worktrees/p35`, branch `v3-p35` off `v3-dev` after plan 34 merged; stage explicit paths; never push; never commit `.superpowers/`; trailer exactly `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No token-shaped literals.
- Code: `saiife-boxhost`, `saiife-boxproto`, `saiife-guest` stay tokio-free (CI gate, Task 1); `[lints] workspace = true` and `#![forbid(unsafe_code)]` at column 0 of each `lib.rs`. Non-unix builds keep compiling: the daemon and CLI depend on `saiife-boxhost` only under `[target.'cfg(unix)'.dependencies]`.
- Before committing: `cargo fmt --all`; `cargo clippy --workspace --all-targets -j 4 -- -D warnings`; tests of touched crates pass; `CARGO_INCREMENTAL=0`, `-j 4`, `-- --test-threads=4`. Do not spawn subagents; write `task-N-report.md` at the worktree root, uncommitted.
- Every task:
  ```bash
  export TMPDIR="$(mktemp -d -p /home/jonas/projects/personal/saiife p35-tN-XXXXXX)" SAIIFE_TEST_TMP="$TMPDIR" CARGO_INCREMENTAL=0
  cargo test -p saiife-boxhost -p saiife-boxproto -j 4 -- --test-threads=4
  cargo fmt --all && cargo clippy --workspace --all-targets -j 4 -- -D warnings
  ```

### Fixed values

| Name | Value | Source |
|---|---|---|
| `CH_VERSION` | `"v54.0"` | spike |
| `CH_URL` | `https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static` | spike |
| `CH_SHA256` | `4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b` | spike (GitHub release API digest) |
| `FW_VERSION` | `"ch-97eeb7b09"` | spike |
| `FW_URL` | `https://github.com/cloud-hypervisor/edk2/releases/download/ch-97eeb7b09/CLOUDHV.fd` | spike |
| `FW_SHA256` | `dc2fc8f0e43b96712d9fccc52a3a590769606412b3e1bc911d217addd3bef624` | spike |
| VMM dir files | `cloud-hypervisor` (0755), `CLOUDHV.fd` (0644) | V6 |
| box dir files | `vm.json` (0640), `api.sock`, `vsock.sock` (+ `vsock.sock_<port>`), `serial.log`, `ch.log`, `root.qcow2`, `repo.img`, `base.json`, `snapshot/`, `term.cast`, `lands/`, `placeholder` | this plan, 37–40 |
| `VmHandle.driver` | `"ch-v54.0"`; `VmHandle.data` (a `String`, `store.rs:23`) = JSON text `{"launcher":"child"\|"unit","image":"base-<sha256>"}` | |
| guest vsock CID | `3` | spike |
| API timeouts | connect 1 s; call 2 s; snapshot 120 s | V3 |
| `StopTimes` default | `power_s = 60`, `shutdown_s = 30` | V2, spike `ch_stop` |
| `BOOT_TIMEOUT_SECS` | `90` | V4 |
| `MAX_SOCK_PATH` | `100` bytes | V7 |
| unit | `saiife-box@<id>.service`, id `b[0-9]{1,9}` | plan 34 B5 |
| polkit rule file | `/etc/polkit-1/rules.d/50-saiife-box.rules` | |
| locked roots | `/var/lib/saiife-box/{boxes,images}`, `/opt/saiife/vmm` | V5, V6 |

## Review Focus

1. **A tampered `vm.json`** (a disk path to `/etc/shadow`, a `..` component, a symlinked box dir, a path with `,` that smuggles a second CH option, an id that differs from the folder). Expected: the helper refuses before exec, names the field, and execs nothing (Task 4: `helper_refuses_paths_outside`, `helper_refuses_option_smuggling`, `helper_refuses_symlinked_dir`, `helper_refuses_id_mismatch`).
2. **A swapped VMM binary** (one byte changed in `cloud-hypervisor`). Expected: `box vmm fetch` refuses it and the helper refuses to launch it, in release builds always (Task 2: `fetch_refuses_wrong_digest`; Task 4: `helper_refuses_unpinned_binary`).
3. **A guest that ignores the power button, or a VMM that hangs.** Expected: `stop` returns at once; the VMM is gone after `power_s + shutdown_s` plus the last resort; `status` is `Off`; nothing leaks (Task 5: `stop_ladder_escalates`, `stop_returns_within_a_second`, `hung_api_times_out`).
4. **Daemon restart while VMs run** (personal mode: the child handles are lost). Expected: `status` answers from the API socket (`Running`/`Paused`), a dead socket is `Gone`, and a later `stop` still works through the API (Task 5: `status_after_restart_uses_the_api`, `stop_after_restart_without_child`).
5. **A polkit rule that grants more than intended** (another unit, another verb, another user). Expected: the rule text allows only `start`/`stop` of `saiife-box@b<digits>.service` for user `saiife` (Task 6: `polkit_rule_is_narrow`).

---

## Task order and parallelism

- **Wave 1:** Task 1 (scaffold for plans 35–40). Nothing else in plans 35–40 starts before it merges.
- **Wave 2 (parallel):** Task 2 (pins, fetch), Task 3 (API client, fake CH), Task 4 (launch spec, helper), Task 6 (locked launcher, install).
- **Wave 3:** Task 5 (`ChVmm`; needs 2–4 and plan 37 Task 1).
- **Wave 4:** Task 7 (daemon wiring, doctor, smoke; needs 5, 6 and plan 36 Task 4).

---

### Task 1: scaffold for the VM half (size S)

**Files:**
- Create: `crates/boxproto/{Cargo.toml,src/lib.rs,src/frame.rs,src/msg.rs,src/ports.rs,src/delta.rs,src/manifest.rs}`; `crates/boxhost/{Cargo.toml,src/lib.rs,src/layout.rs,src/paths.rs,src/tools.rs,src/pins.rs,src/ch.rs,src/launch.rs,src/vmm.rs,src/preflight.rs,src/disk.rs,src/image.rs,src/bake.rs,src/vsock.rs,src/guest.rs,src/term.rs,src/review.rs}`; `crates/guest/{Cargo.toml,src/lib.rs,src/env.rs,src/control.rs,src/events.rs,src/pty.rs,src/setup.rs,src/export.rs}`; `assets/box/guest/README.md` (one line: "guest files baked into the base image; owned by plan 38"); `scripts/box-smoke.sh`, `scripts/box-smoke.d/.keep`.
- Modify: root `Cargo.toml` (members), `.github/workflows/ci.yml` (the `no tokio in hook crates` step, `:164` on `v3-dev`, `:176` once plan 34 is merged: append ` -p saiife-boxhost -p saiife-boxproto -p saiife-guest` to its `cargo tree` line).

**Interfaces (Produces):**
```rust
// boxproto lib.rs
pub const PROTO: &str = "saiife-guest/1";
// boxhost layout.rs
#[derive(Debug, Clone, PartialEq, Eq)] pub struct Layout { pub boxes: PathBuf, pub images: PathBuf, pub vmm: PathBuf, pub locked: bool }
impl Layout { pub fn locked() -> Layout; pub fn personal(state_dir: &Path, data_home: &Path) -> Layout; }   // V5, V6
// boxhost paths.rs: one box dir (every file name of the Fixed values table)
#[derive(Debug, Clone)] pub struct BoxPaths { pub dir: PathBuf }
impl BoxPaths { pub fn new(dir: PathBuf) -> BoxPaths; pub fn vm_json(&self) -> PathBuf; pub fn api_sock(&self) -> PathBuf; pub fn vsock(&self) -> PathBuf;
  pub fn vsock_port(&self, port: u32) -> PathBuf;   // "<vsock>_<port>" (CH multiplexer)
  pub fn serial(&self) -> PathBuf; pub fn ch_log(&self) -> PathBuf; pub fn root_disk(&self) -> PathBuf; pub fn repo_disk(&self) -> PathBuf;
  pub fn base_manifest(&self) -> PathBuf; pub fn snapshot_dir(&self) -> PathBuf; pub fn term_cast(&self) -> PathBuf; pub fn lands_dir(&self) -> PathBuf; pub fn placeholder(&self) -> PathBuf;
  pub fn longest_socket(&self) -> PathBuf; }   // vsock_port(5003)
// boxhost tools.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Tool { Ch, QemuImg, Mke2fs, Gpgv, Curl, Passt, MkfsVfat, Mcopy, Git }
#[derive(Debug, Clone)] pub struct Tools { /* paths */ }
impl Tools {
  pub fn system(vmm_dir: &Path) -> Tools;        // Ch = vmm_dir/cloud-hypervisor; others /usr/bin/<qemu-img|mke2fs|gpgv|curl|passt|mkfs.vfat|mcopy|git>
  pub fn with_env(self, env: &dyn Fn(&str) -> Option<OsString>) -> Tools;   // SAIIFE_TOOL_CH, SAIIFE_TOOL_QEMU_IMG, …; debug builds only (V9)
  pub fn path(&self, t: Tool) -> &Path;
  pub fn run(&self, t: Tool, args: &[&OsStr], timeout: Duration) -> Result<std::process::Output, ToolError>;   // env cleared but PATH=/usr/bin:/bin, LANG=C.UTF-8; stdin null
}
#[derive(Debug)] pub enum ToolError { Missing { tool: Tool, path: PathBuf }, Failed { tool: Tool, status: Option<i32>, stderr: String }, Timeout { tool: Tool, secs: u64 }, Io(io::Error) }
```
`Tools::run` waits with a bounded loop on `Child::try_wait` (50 ms steps) and calls `Child::kill` on its own child at the timeout. `stderr` is cut to 4 KiB.

`scripts/box-smoke.sh` (owner-run; header comment names what it touches as `box-spike.sh` does: `/dev/kvm`, the network for `image build`, disk under `$SAIIFE_BOX_SMOKE_WORK`): refuses root and `SUDO_USER` (port `refuse_root`), sources every `scripts/box-smoke.d/[0-9][0-9]-*.sh` in order, runs the `smoke_<name>` function each defines, prints `ok:`/`FAIL:` per check and a results block between `----- BEGIN BOX SMOKE RESULTS -----` and `----- END BOX SMOKE RESULTS -----`. `--list` prints the fragments; `--only <name>` runs one. Each plan 35–40 adds exactly one fragment file, so no two plans edit the same smoke file.

- [ ] **Step 1: Write the failing tests:** `boxhost::paths` `vsock_port_naming` (`vsock_port(5000)` ends with `vsock.sock_5000`), `layout_locked_paths` (V5/V6 values), `layout_personal_paths`; `boxhost::tools` `system_paths`, `env_override_is_debug_only` (asserts the override applies iff `cfg!(debug_assertions)`), `run_times_out_and_kills_own_child` (a script `sleep 30` under `$TMPDIR` with a 1 s timeout → `ToolError::Timeout`, returns in < 3 s), `run_reports_stderr`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** the crates (every other module an empty file with one `//!` line naming the plan that fills it). **Step 4: Run** → PASS; `cargo tree -e normal -p saiife-boxhost -p saiife-boxproto -p saiife-guest | grep -c tokio` → `0`; `bash -n scripts/box-smoke.sh`.
- [ ] **Step 5: Commit** `feat(boxes): scaffold boxhost, boxproto and guest crates, and box-smoke.sh`.

---

### Task 2: pins and `saiife box vmm fetch` (size S)

**Files:** Modify `crates/boxhost/src/pins.rs`; create `crates/cli/src/box_vmm_cmd.rs`; modify `crates/cli/src/box_cmd.rs` (plan 34's `BoxAction`: add `Vmm { #[command(subcommand)] action: VmmAction }`).

**Interfaces (Produces):**
```rust
pub const CH_VERSION: &str; pub const CH_URL: &str; pub const CH_SHA256: &str; pub const FW_VERSION: &str; pub const FW_URL: &str; pub const FW_SHA256: &str;   // Fixed values
pub fn sha256_file(path: &Path) -> io::Result<String>;               // lowercase hex, streamed in 1 MiB reads
pub fn verify(path: &Path, want: &str) -> Result<(), String>;        // "…: sha256 <got>, pinned <want>"
pub fn fetch(tools: &Tools, url: &str, want: &str, dest: &Path, mode: u32) -> Result<(), String>;
#[derive(Subcommand)] pub enum VmmAction { /// Download the pinned Cloud Hypervisor and firmware.
  Fetch { #[arg(long)] dir: Option<PathBuf> }, /// Show the pinned versions and whether the files match.
  Status }
```
`fetch` (port of `fetch_one`/`fetch_pinned`): an existing `dest` with the right digest is kept; else `curl --proto =https --tlsv1.2 -fsSL --retry 2 -o <dest>.part <url>` (timeout 600 s), `verify(<dest>.part)`, `chmod`, rename. A wrong digest removes the `.part` and errs. `Fetch` defaults to the personal VMM dir; in locked mode it says `run "sudo saiife system install --boxes"` and exits 2.

- [ ] **Step 1: Write the failing tests** (fake `curl` script: copies `$FAKE_SRC` to the `-o` argument): `fetch_writes_and_verifies`, `fetch_keeps_a_matching_file` (fake curl not called: it writes a marker when run), `fetch_refuses_wrong_digest` (`.part` removed, `dest` absent, message names both digests), `verify_names_both_digests`, CLI `vmm_status_shows_pins` (`saiife box vmm status` prints `cloud-hypervisor v54.0` and `missing`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): pinned Cloud Hypervisor and firmware, saiife box vmm fetch`.

---

### Task 3: the Cloud Hypervisor API client and `saiife-fake-ch` (size M)

**Files:** Modify `crates/boxhost/src/ch.rs`; create `crates/boxhost/src/bin/fake_ch.rs` (`[[bin]] name = "saiife-fake-ch"`, `required-features = ["fake"]`), `crates/boxhost/tests/fixtures/ch-v54.0/*.http`, `crates/boxhost/tests/ch_api.rs`.

**Interfaces (Produces):**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Action { Pause, Resume, PowerButton, Snapshot, ShutdownVmm }
impl Action { pub fn path(self) -> &'static str; }   // /api/v1/vm.pause, vm.resume, vm.power-button, vm.snapshot, vmm.shutdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum VmState { Created, Running, Paused, Shutdown }   // vm.info "state"
#[derive(Debug, Clone, PartialEq, Eq)] pub enum ApiError { NoSocket, Timeout, Http { status: u16, body: String }, Bad(String) }
pub struct Api { /* sock: PathBuf */ }
impl Api {
  pub fn new(sock: PathBuf) -> Api;
  pub fn ping(&self) -> Result<String, ApiError>;                     // GET /api/v1/vmm.ping -> "version"
  pub fn state(&self) -> Result<VmState, ApiError>;                   // GET /api/v1/vm.info
  pub fn put(&self, a: Action, body: Option<&serde_json::Value>, timeout: Duration) -> Result<(), ApiError>;   // 200 and 204 are Ok
  pub fn snapshot(&self, dest: &Path) -> Result<(), ApiError>;        // put(Snapshot, {"destination_url": "file://<dest>"}, 120 s)
}
```
Wire format: `<METHOD> <path> HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n` + `Content-Type: application/json\r\nContent-Length: <n>\r\n` (always, `0` without a body) + `\r\n`. Response: status line, headers (≤ 64 lines, ≤ 8 KiB), body by `Content-Length` or to EOF, at most 64 KiB (`Bad("response too large")`). Connect refused or a missing socket → `NoSocket`; read/write timeouts via `set_read_timeout`/`set_write_timeout` → `Timeout`.

Fixtures (`*.http`, raw response bytes): `vmm.ping.200`, `vm.info.running.200`, `vm.info.paused.200`, `vm.info.created.200`, `vm.info.shutdown.200`, `vm.pause.204`, `vm.pause.500` (body `InvalidStateTransition`), `vm.snapshot.204`. Their bodies follow Cloud Hypervisor v54.0's `vmm/src/api/openapi/cloud-hypervisor.yaml` (public reference data; fetching it is allowed), with a first comment line `# synthesized from the v54.0 OpenAPI; re-recorded by box-smoke.sh RECORD=1`. The client ignores leading `#` lines only in the fixture loader, never on the wire.

`saiife-fake-ch` (test binary, feature `fake`): parses the argv `launch::argv` produces (unknown flag → exit 2), writes its argv as JSON lines to `<dir of --api-socket>/fake-ch.argv`, binds `--api-socket path=…`, serves the fixtures by route, keeps a state machine (`Running` at start, or `Paused` after `--restore`), and exits 0 on `vmm.shutdown` or 200 ms after `vm.power-button`. Knobs (env): `FAKE_CH_IGNORE_POWER=1` (power button changes nothing), `FAKE_CH_HANG=1` (accept, never answer), `FAKE_CH_EXIT_AT_START=<code>`.

- [ ] **Step 1: Write the failing tests:** unit `request_bytes_are_exact` (pinned bytes for `put(Pause, None)` and for `snapshot("/b/s")`), `parses_each_fixture`, `content_length_and_eof_bodies`, `oversized_response_is_bad`, `missing_socket_is_no_socket`; integration (`tests/ch_api.rs`, `--features fake`, starts `env!("CARGO_BIN_EXE_saiife-fake-ch")` as its own child): `ping_state_pause_resume`, `pause_when_paused_is_http_500`, `hung_api_times_out` (`FAKE_CH_HANG=1`, `state()` → `Timeout` in < 3 s), `power_button_exits_the_fake`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): Cloud Hypervisor API client over the Unix socket, fake CH for tests`.

---

### Task 4: the launch spec and `saiife __box-vmm` (size M)

**Files:** Modify `crates/boxhost/src/launch.rs`; create `crates/cli/src/box_vmm_helper.rs`; modify `crates/cli/src/main.rs` (hidden `Cmd::BoxVmm { dir: PathBuf, #[arg(long)] locked: bool }` as `__box-vmm`).

**Interfaces (Produces):**
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Boot { Firmware { fw: PathBuf }, Kernel { kernel: PathBuf, cmdline: String } }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)]
pub struct LaunchSpec { pub version: u32 /* 1 */, pub id: BoxId, pub vcpus: u32, pub mem_mib: u64, pub base: PathBuf, pub repo: bool, pub boot: Boot, pub landlock: bool, pub restore: bool }
pub struct Allowed { pub boxes: PathBuf, pub images: PathBuf, pub vmm: PathBuf }
impl Allowed { pub fn for_layout(l: &Layout) -> Allowed; }
pub fn check_spec(spec: &LaunchSpec, paths: &BoxPaths, allowed: &Allowed) -> Result<(), String>;
pub fn argv(spec: &LaunchSpec, paths: &BoxPaths) -> Vec<OsString>;    // pure, pinned by test
pub fn write_spec(spec: &LaunchSpec, paths: &BoxPaths) -> Result<(), String>;   // vm.json.tmp then rename, 0640
pub fn read_spec(paths: &BoxPaths) -> Result<LaunchSpec, String>;       // ≤ 16 KiB, regular file, not a symlink
```
`argv` (port of `ch_boot`, in this order; `<d>` = the box dir):
```
--firmware <fw>                                  | --kernel <kernel> --cmdline <cmdline>
--disk path=<d>/root.qcow2,image_type=qcow2,backing_files=on [path=<d>/repo.img,image_type=raw]
--cpus boot=<vcpus>
--memory size=<mem_mib>M
--vsock cid=3,socket=<d>/vsock.sock
--balloon size=0,free_page_reporting=on,deflate_on_oom=on
[--landlock --landlock-rules path=<base>,access=r [path=<d>/snapshot,access=rw]]
--serial file=<d>/serial.log --console off
--api-socket path=<d>/api.sock
```
With `restore = true` the argv is only `--restore source_url=file://<d>/snapshot` and `--api-socket path=<d>/api.sock` (the restored config carries the rest; spike `ch_restore`). The snapshot Landlock rule is added when `<d>/snapshot` may be written (always when `landlock`).

`check_spec` refuses (each message names the field): `version != 1`; `id` differs from the dir's file name; the dir not directly under `allowed.boxes`, or any component of it a symlink (`symlink_metadata` walk); `base` not a regular file directly under `allowed.images`; `fw`/`kernel` not under `allowed.vmm` or `allowed.images`; any path or the cmdline breaking V8; `vcpus` outside `1..=32`, `mem_mib` outside `512..=262144` (plan 34 bounds); the longest socket path over `MAX_SOCK_PATH`.

Helper `saiife __box-vmm <dir> [--locked]`: `Allowed` from `Layout::locked()` with `--locked`, else from the personal layout of the running user; `read_spec`, `check_spec`, `pins::verify(Tools::system(vmm).path(Ch), CH_SHA256)` (skipped only under V9), the firmware too when `Boot::Firmware`; stdout and stderr to `ch.log` (append, 0640); then `CommandExt::exec`. Any refusal prints `saiife __box-vmm: <reason>` to stderr and exits 3; exec failure exits 4.

- [ ] **Step 1: Write the failing tests:** `argv_is_pinned_firmware`, `argv_is_pinned_kernel_no_repo`, `argv_restore_is_short`, `argv_without_landlock`, `spec_roundtrip_and_unknown_field_refused`, `helper_refuses_paths_outside` (base under `$TMPDIR/elsewhere`), `helper_refuses_option_smuggling` (base `…/a,image_type=raw` and cmdline with `\n`), `helper_refuses_symlinked_dir`, `helper_refuses_id_mismatch`, `socket_path_too_long_is_refused`; CLI (`tests/box_vmm_helper.rs`, debug build): `helper_execs_the_tool_with_argv` (`SAIIFE_TOOL_CH` = a script that writes `"$@"` to a file; `SAIIFE_TEST_NO_PIN=1`), `helper_refuses_unpinned_binary` (no `SAIIFE_TEST_NO_PIN`, a script as CH → exit 3, message names `sha256`).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): launch spec and the __box-vmm helper that checks it before exec`.

---

### Task 5: `ChVmm`, the driver (size L)

**Files:** Modify `crates/boxhost/src/vmm.rs`, `crates/boxhost/src/launch.rs` (launchers); create `crates/boxhost/tests/ch_vmm.rs` (`--features fake`).

**Interfaces:**
- Consumes: `saiife_boxes::vmm::{Vmm, VmSpec, VmHandle, VmStatus, VmmError}`, `saiife_boxes::template::{ImageRef, Size}` (plan 34; `ImageRef::{Default, Pinned(String)}` with `Pinned` holding `base-<64 hex>`, `template.rs:44`, `:300-305`); Tasks 2–4; `crate::disk::make_overlay(tools: &Tools, base: &Path, out: &Path, virtual_gib: u64) -> Result<(), String>` (plan 37 Task 1).
- Produces:
```rust
// launch.rs
pub trait Launcher: Send + Sync {
  fn start(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String>;   // returns once the process is started
  fn exited(&self, id: &BoxId) -> Option<bool>;                         // None: not started by this launcher (e.g. after a daemon restart)
  fn force_stop(&self, id: &BoxId) -> Result<(), String>;
  fn kind(&self) -> &'static str;                                      // "child" | "unit"
}
pub struct ChildLauncher { /* program + fixed args, Mutex<BTreeMap<BoxId, Child>> */ }
impl ChildLauncher { pub fn helper(saiife_bin: PathBuf) -> ChildLauncher;      // runs `<saiife_bin> __box-vmm <dir>`
                     pub fn direct(program: PathBuf) -> ChildLauncher; }        // tests: runs `<program> <argv(read_spec)>`
// vmm.rs
#[derive(Debug, Clone, PartialEq, Eq)] pub struct ResolvedImage { pub id: String /* base-<sha256> */, pub raw: PathBuf, pub sha256: String, pub virtual_gib: u64, pub boot: Boot }
pub trait ImageResolver: Send + Sync { fn resolve(&self, r: &ImageRef) -> Result<ResolvedImage, String>; }
pub trait VmHooks: Send + Sync {
  fn before_boot(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String>;   // bind host listeners; an error fails the boot
  fn after_off(&self, id: &BoxId);                                              // VMM exited or destroyed
}
#[derive(Debug, Clone, Copy)] pub struct StopTimes { pub power_s: u64, pub shutdown_s: u64 }
impl Default for StopTimes { /* 60, 30 */ }
pub struct ChVmmInit { pub layout: Layout, pub tools: Tools, pub images: Arc<dyn ImageResolver>, pub launcher: Arc<dyn Launcher>, pub hooks: Vec<Arc<dyn VmHooks>>, pub landlock: bool, pub stop: StopTimes }
pub struct ChVmm { /* init + Mutex<BTreeMap<BoxId, VmRun>> */ }
impl ChVmm { pub fn new(init: ChVmmInit) -> ChVmm; }
impl saiife_boxes::vmm::Vmm for ChVmm { … }
```
Behaviour (one test each):
- **create:** `BoxPaths::new(spec.dir)`; socket length check (V7); `images.resolve(&spec.image)`; `spec.size.disk_gib < image.virtual_gib` → `Failed("the box disk (<n> GiB) is smaller than the base image (<m> GiB)")`; `make_overlay(root.qcow2)` unless it exists (a restart keeps the overlay); `write_spec` with `repo = repo_disk().exists()`, `restore = snapshot_dir()/config.json exists`. Returns `VmHandle { id, driver: "ch-v54.0", data: {"launcher": kind, "image": image.id} }` (JSON text). The manager never reads `data` (`store.rs:17`); plan 36 Task 5 adds `Vmm::image_id(&h)`, which `ChVmm` answers from this `image`.
- **boot:** every hook's `before_boot` (the first error → `Failed`, earlier hooks get `after_off`); `launcher.start`; wait up to 10 s for `api.sock` (port of `ch_launch`'s wait; an early exit → `Failed("the VMM exited at start; see ch.log")` with the last 20 lines of `ch.log`); with `restore`, `put(Resume)`; start the reaper thread. Returns without waiting for the guest (readiness is `GuestEvent::Ready`, plan 38).
- **pause / resume:** `put(Pause|Resume, 2 s)`; `Http`/`Timeout`/`NoSocket` → `Failed(<text>)`.
- **stop:** VM already off → `Ok`. Else `put(PowerButton)` (an error is logged and the reaper escalates at once) and return. Reaper: wait `power_s` for exit (`launcher.exited` or, without a child, `api.sock` refusing), then `put(ShutdownVmm)`, wait `shutdown_s`, then `force_stop`. On exit: hooks' `after_off`, remove `api.sock` and the vsock sockets.
- **snapshot(h, dest):** must be `Paused` (else `Failed("pause first")`); `dest` must equal `paths.snapshot_dir()` (the manager passes `<box>/snapshot`, `manager.rs:552`; else `Failed`); `remove_dir_all(dest)` then `Api::snapshot(dest)`.
- **status:** known run → exited? `Off` : `state()` mapped (`Created`, `Running`, `Paused`, `Shutdown`→`Off`; `NoSocket`/`Timeout` → `Off` when the process has exited, else `Running`). Unknown run (daemon restart) → `state()` mapped; `NoSocket` → `Off` when `vm.json` exists in the box dir (created, never booted, or exited: plan 34 R31 saves the handle before `boot`), else `Gone`.
- **destroy:** `stop` if not off, wait for the reaper (≤ `power_s + shutdown_s + 5`), forget the run; never deletes files (the store removes the dir).

- [ ] **Step 1: Write the failing tests** (`ChildLauncher::direct(fake-ch)`, a fixed resolver over a 1-byte "base", a fake `qemu-img` script that writes the overlay file, `StopTimes { power_s: 1, shutdown_s: 1 }`, box dirs `$TMPDIR/b1`): `create_writes_spec_and_overlay`, `create_refuses_small_disk`, `create_keeps_existing_overlay`, `boot_runs_hooks_then_vmm` (hook order recorded; `fake-ch.argv` equals `argv(spec)`), `hook_failure_fails_boot_and_unwinds`, `early_exit_reports_ch_log` (`FAKE_CH_EXIT_AT_START=1`), `pause_resume_and_status`, `stop_returns_within_a_second`, `stop_ladder_escalates` (`FAKE_CH_IGNORE_POWER=1`: exit via `vmm.shutdown` within 3 s), `stop_ladder_force_stops_a_hung_vmm` (`FAKE_CH_HANG=1`: `Child::kill` by the launcher, `status` → `Off`), `stop_twice_is_ok`, `snapshot_needs_pause`, `snapshot_refuses_other_dest`, `restore_boots_paused_then_resumes`, `status_after_restart_uses_the_api` (a second `ChVmm` with a fresh launcher over the same dir → `Running`), `status_of_created_unbooted_is_off` (a second `ChVmm` over a dir with `vm.json` and no `api.sock` → `Off`; a dir without `vm.json` → `Gone`), `stop_after_restart_without_child`, `after_off_runs_once`, `destroy_is_idempotent`.
- [ ] **Step 2: Run** `cargo test -p saiife-boxhost --features fake --test ch_vmm -j 4 -- --test-threads=4` → FAIL.
- [ ] **Step 3: Implement.** One `Mutex` per `ChVmm`, never held across an API call or a wait; the reaper owns its run's state through an `Arc`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): ChVmm drives Cloud Hypervisor over its API, with a stop ladder and no stray signals`.

---

### Task 6: locked mode: the unit launcher and `system install --boxes` (size M)

**Files:** Modify `crates/boxhost/src/launch.rs` (`UnitLauncher`, `UnitBus`); create `crates/system/src/boxes_install.rs`; modify `crates/system/src/install.rs` (the `--boxes` steps), `crates/system/src/unit.rs` (daemon unit additions when boxes are installed), `crates/cli/src/system_cmd.rs` (`--boxes` flag); create `crates/daemon/src/box_unit.rs` (zbus `UnitBus`).

**Interfaces (Produces):**
```rust
// boxhost launch.rs
pub trait UnitBus: Send + Sync { fn start(&self, unit: &str) -> Result<(), String>; fn stop(&self, unit: &str) -> Result<(), String>; fn active(&self, unit: &str) -> Result<bool, String>; }
pub fn unit_name(id: &BoxId) -> Result<String, String>;   // "saiife-box@<id>.service"; id must match b[0-9]{1,9}
pub struct UnitLauncher { /* Arc<dyn UnitBus> */ }
impl UnitLauncher { pub fn new(bus: Arc<dyn UnitBus>) -> UnitLauncher; }
impl Launcher for UnitLauncher { /* start -> bus.start; exited -> Some(!active); force_stop -> bus.stop; kind "unit" */ }
#[cfg(feature = "fake")] pub struct FakeUnitBus { /* records calls, settable active */ }
// system boxes_install.rs
pub const BOX_UNIT: &str;            // the template unit text below
pub const POLKIT_RULE: &str;         // the rule below
/// The --boxes part of a locked install, after the v2 steps of `install_locked` (install.rs:406).
/// There is no step type in crates/system: like the rest of install.rs it acts through `&dyn Host`
/// (host.rs:158) on paths from `Layout`, so tests run it on `saiife_system::testing`'s temp root.
pub fn install_boxes(layout: &crate::layout::Layout, host: &dyn crate::host::Host, daemon_user: &str, vmm_dir: Option<&Path>) -> Result<(), crate::install::InstallError>;
pub fn uninstall_boxes(layout: &crate::layout::Layout, host: &dyn crate::host::Host) -> Result<(), crate::install::InstallError>;
// install.rs: InstallOptions (install.rs:51) gains `pub boxes: bool, pub vmm_dir: Option<PathBuf>`
// daemon box_unit.rs
pub struct SystemdBus { /* zbus::Connection (system bus), tokio Handle */ }
impl SystemdBus { pub async fn connect() -> Result<SystemdBus, String>; }
impl saiife_boxhost::launch::UnitBus for SystemdBus { /* Handle::block_on of Manager.StartUnit(unit, "fail"), StopUnit(unit, "replace"), GetUnit + Unit.ActiveState == "active"|"activating" */ }
```
`BOX_UNIT` (`/etc/systemd/system/saiife-box@.service`):
```ini
[Unit]
Description=saiife box %i (Cloud Hypervisor)
[Service]
Type=exec
User=saiife-box
Group=saiife-box
SupplementaryGroups=kvm
ExecStart=/opt/saiife/bin/saiife __box-vmm /var/lib/saiife-box/boxes/%i --locked
UMask=0007
NoNewPrivileges=yes
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
PrivateNetwork=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/saiife-box/boxes/%i
ReadOnlyPaths=/var/lib/saiife-box/images /opt/saiife/vmm
TimeoutStopSec=30
KillMode=control-group
Restart=no
```
`POLKIT_RULE`:
```js
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "saiife") {
    var unit = action.lookup("unit"), verb = action.lookup("verb");
    if (/^saiife-box@b[0-9]{1,9}\.service$/.test(unit) && (verb == "start" || verb == "stop")) {
      return polkit.Result.YES;
    }
  }
});
```
The rule file goes into the first of `saiife_system::polkit::POLKIT_RULES_DIRS` (`polkit.rs:12`) under the layout root. `--boxes` steps (after the v2 steps): create system group and user `saiife-box` (no login shell, no home), add `saiife-box` to `kvm`, add the daemon user `saiife` to group `saiife-box`; create `/var/lib/saiife-box` (root:saiife-box 2770), `boxes/` (saiife:saiife-box 2770), `images/` (saiife:saiife-box 2750); fetch the VMM into `/opt/saiife/vmm` with `pins::fetch` (or copy from `--vmm-dir <dir>`, verified); write `BOX_UNIT` and `POLKIT_RULE`; the daemon unit gains `SupplementaryGroups=saiife-box` and `ReadWritePaths=/var/lib/saiife-box`. Uninstall removes all of it (images and boxes only after the existing confirmation pattern).

- [ ] **Step 1: Write the failing tests:** `unit_name_rules` (`b3` ok; `b`, `x1`, `b1/../x`, `b1234567890` refused), `unit_launcher_calls_the_bus` (`FakeUnitBus`), `box_unit_text_is_pinned`, `polkit_rule_is_narrow` (the text contains the exact regex, the two verbs and `subject.user == "saiife"`, and no other `return polkit.Result`), `install_boxes_on_fake_root` (`saiife_system::testing::fake_install(root)` then `install_boxes`: the user/group calls recorded by the fake `Host` in order, the dirs with their modes and groups, the unit and rule files under the root), `install_without_boxes_is_unchanged`, `uninstall_boxes_removes_unit_and_rule`, `daemon_unit_with_boxes` (the two added lines; without `--boxes` the unit is byte-identical to today's).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** `SystemdBus` has no unit test (needs a system bus); it is exercised by the smoke fragment. **Step 4: Run** → PASS; `bash scripts/check-windows.sh -p saiife-system`.
- [ ] **Step 5: Commit** `feat(system): saiife-box@ template unit, narrow polkit rule, system install --boxes`.

---

### Task 7: daemon wiring, doctor, and the smoke fragment (size M)

**Files:** Create `crates/daemon/src/box_vmm.rs`, `scripts/box-smoke.d/10-vmm.sh`; modify `crates/daemon/src/box_ops.rs` (plan 34 `build_with` `:215`, `dir_in` `:75`, `handle`'s unavailable answer `:661-663`), `crates/daemon/src/ops.rs` (`Ctx.box_unavailable: Option<String>` beside `box_manager`, `ops.rs:396` on `v3-p34`), `crates/boxhost/src/preflight.rs`, `crates/system/src/doctor/host.rs` (a "boxes" section). `crates/boxes/src/manager.rs` is not touched: `BOOT_TIMEOUT_SECS = 90` is plan 34's already (R8), and so is `VMM_OVERHEAD_MIB` (R5).

**Interfaces:**
- Consumes: `ChVmm` (Task 5), `UnitLauncher` + `SystemdBus` (Task 6), `image::Store: ImageResolver` (plan 36 Task 4), plan 34 `box_ops::build`.
- Produces:
```rust
// boxhost preflight.rs
#[derive(Debug, Clone, PartialEq, Eq)] pub struct Check { pub name: &'static str, pub ok: bool, pub detail: String }
pub fn checks(layout: &Layout, tools: &Tools, kvm: &Path) -> Vec<Check>;   // vmm pins, firmware pin, kvm rw (personal only), qemu-img, mke2fs present, landlock ABI (saiife_system::sandbox::landlock_abi, sandbox.rs:297), images dir has a default image
pub fn ready(c: &[Check]) -> Result<(), String>;                           // first failing check's detail
// daemon box_vmm.rs (crate::ops::Mode)
pub fn real_vmm(layout: &Layout, mode: &Mode, hooks: Vec<Arc<dyn VmHooks>>) -> Result<Arc<dyn saiife_boxes::vmm::Vmm>, String>;
// daemon box_ops.rs: build_with now returns Result<Result<Built, String /* why boxes are unavailable */>, String /* state error */>
```
`box_ops::build_with` order: (1) feature `fake-vmm` and `SAIIFE_BOX_FAKE_VMM=1` (`FAKE_ENV`, `box_ops.rs:46`; with `SAIIFE_BOX_FAKE_SLOTS`, R24) → plan 34's `build_fake` with `FakeVmm` and `FakeGuest` (unchanged, `box_ops.rs:236`); (2) otherwise, on Linux, `preflight::ready` → `real_vmm` with `ChildLauncher::helper(current_exe)` (personal) or `UnitLauncher::new(SystemdBus)` (locked), `landlock = true`, into `Manager::open(ManagerInit { store, vmm, guest: Arc::new(NoGuest), templates, host, clock })` (`manager.rs:56`, `:197`); (3) a failed check gives `Ok(Err(detail))`: `Ctx.box_manager` stays `None` and `Ctx.box_unavailable = Some(detail)`, which `handle` answers instead of `UNAVAILABLE` (e.g. `boxes need the pinned VMM: run "saiife box vmm fetch"`). Non-Linux builds keep plan 34's `UNAVAILABLE`. `dir_in(state_dir, mode)` returns `Layout::locked().boxes` in locked mode (V5); every caller (`build_fake`, `host_facts`' disk probe) passes the mode. The plan 38 and 40 hooks are passed in by their plans; until they land, `hooks` is empty and `GuestLink` stays `NoGuest` (`crates/boxes/src/guest.rs:30`). The fake-only tick helper `fake_ready` (plan 34 R26) stays behind `fake-vmm`.

`10-vmm.sh` (owner-run) checks: `saiife box vmm status` all pinned; `saiife doctor` boxes section ok; spawn a box from the default image with `--task ""` and see the VMM up (`api.sock` answers `vmm.ping`) within 90 s (the box itself reaches `running` only with plan 38's `Ready`; before plan 38 it is discarded by the 90 s boot timeout with `error` naming it, which the fragment checks instead); `ch.log` shows Landlock on (no "landlock" error); `saiife box pause`, `resume`; `saiife box stop` and the VMM process gone within 95 s (`/proc/<pid>` gone; the pid from `ch.log`'s directory's unit or child, read, never signalled); boot ms cold (5 runs) and VMM Rss idle from `smaps_rollup` as result keys `boot_cold_ms_median`, `rss_idle_kib`; `RECORD=1` re-records the API fixtures with `curl --unix-socket <api.sock>` into `crates/boxhost/tests/fixtures/ch-v54.0/` for the owner to commit. Locked mode (when `/etc/systemd/system/saiife-box@.service` exists): the unit runs as `saiife-box` (`systemctl show -p User` is read-only and allowed for the owner), and the daemon user cannot start `saiife-box@x1.service` (refused by polkit).

- [ ] **Step 1: Write the failing tests:** `preflight` unit tests `missing_vmm_names_fetch`, `wrong_digest_fails`, `kvm_not_writable_fails` (a tempfile with mode 0400 as `kvm`), `ready_reports_first_failure`; daemon `tests/boxes.rs` additions: `unavailable_message_names_the_failed_check` (no VMM in the personal layout, no `SAIIFE_BOX_FAKE_VMM` → every `box.*` op answers `unavailable` with `saiife box vmm fetch` in the text), `fake_env_still_wins` (`fake-vmm` build with `SAIIFE_BOX_FAKE_VMM=1` and no VMM → plan 34's fake manager), `locked_dir_is_saiife_box` (`dir_in(state, &Mode::Locked)`), `personal_dir_is_unchanged`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; plan 34's whole daemon box suite with `--features fake-vmm` is unchanged; `bash -n scripts/box-smoke.sh scripts/box-smoke.d/10-vmm.sh`; shellcheck if installed.
- [ ] **Step 5: Commit** `feat(daemon): real boxes behind a preflight, ChVmm in personal and locked mode`.

---

## Gates

- [ ] `cargo test -p saiife-boxhost --features fake`, `-p saiife-boxproto`, `-p saiife-boxes --features fake`, `-p saiife-daemon --features fake-vmm` and without, `-p saiife-system`, `-p saiife`; all `-j 4 -- --test-threads=4`.
- [ ] `cargo clippy --workspace --all-targets -j 4 -- -D warnings`; `bash scripts/check-unsafe.sh`; `bash scripts/check-windows.sh -p saiife-boxes -p saiife-daemon -p saiife-system -p saiife`.
- [ ] tokio gate `0` for the three new crates; `git diff v3-dev -- Cargo.lock` adds only the three new packages (and `zbus` under the daemon).
- [ ] `grep -rn 'fake-ch\|SAIIFE_TEST_NO_PIN' .github/workflows/release*.yml` finds nothing.
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev` (owner merges).

## Owner handwork

- [ ] Run `scripts/box-smoke.sh --only vmm` in personal mode, then after `sudo saiife system install --boxes` in locked mode; paste the results block into the PR. Re-record the API fixtures with `RECORD=1` and commit them.
- [ ] Decide V2 (the launcher's last resort is the only signal) and V5 (locked box dirs under `/var/lib/saiife-box`, replacing §5.1's `Delegate=yes`).
