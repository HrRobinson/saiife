# Plan 36: the base image: `saiife box image build|import|ls|default|rm` (v3 step 3, VM half 2 of 6): Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Reconciled 2026-11-12** against plan 34 as built on `v3-p34` (`ee5e264`) and its rulings R8, R20, R22, R25. Changes:
> 1. **Already in plan 34 (not rebuilt here):** `BoxRecord.image: Option<String>` with `#[serde(default)]` (`crates/boxes/src/store.rs:53`) and `Change.image: Option<String>` (`manager.rs:88`), both always `None` today (R8). Task 5 fills them; it adds no field.
> 2. `VmHandle.data` is opaque to the manager (`store.rs:17`): the manager learns the image through a new `Vmm::image_id(&self, h: &VmHandle) -> Option<String>` with a default `None` (flagged contract addition on plan 34's trait), which `ChVmm` answers from its own `data` and `FakeVmm` from a settable field. The manager never parses `data`.
> 3. Control-socket arguments: the request envelope's `id` overwrites an `id` argument (`Request::from_map` removes it, `crates/ipc/src/msg.rs:318-322`; plan 34 R25), and `msg::ok` drops an answer field named `id` (`msg.rs:384-393`; plan 27 R-J, plan 34 R20). So `box.image.default` and `box.image.rm` take `{image}`, and `box.image.import` answers `{image}`.
> 4. Audit records: there is no `ctx.record("box", …)` helper for box ops; plan 34 writes `ctx.record("box", input)` with `extra = {action, box, template, from, to, via}` through its private `box_rec` (`crates/daemon/src/box_ops.rs:406-428`) and `ctx.writer.append`. Image records follow that shape (`box: null`) with the image keys added; `box_rec` becomes `pub(crate)`.
> 5. Admission records: a box admitted at its own spawn is covered by the spawn record (plan 34 R22, `box_ops.rs:797-829`), queue heads by tick records (`write_tick_records`, `box_ops.rs:383`). `extra.image` goes into both; the test checks both paths.
> 6. Admin check: `(peer.sid.is_none() && peer.uid == 0) || ctx.peer_is_admin(&peer)` as plan 34's `handle` (`box_ops.rs:707`).
> 7. `every_ipc_op_is_classified` fails on `v3-dev` today (plan 26's `touch.*` ops are missing from `IPC_OPS`, fixed on `v3-p30` `30eaa5a` and `v3-p34` `b66e829`); Task 5's gate assumes those merged.
> 8. Global Constraints: branch `v3-p36`; builds with `CARGO_PROFILE_DEV_DEBUG=0`.
> 9. Smoke: audit queries use `jq` over the audit `*.jsonl` (`saiife audit` has no JSON output; plan 27 R-I).

> **Depends on:** plan 34 merged; plan 35 Task 1 (scaffold) and Task 2 (`pins::fetch`, `Tools`); plan 37 Task 2 (`saiife_ipc::fdpass`, `disk::copy_sparse`) for Task 5 only. The guest files it bakes (`assets/box/guest/**`) are plan 38's; this plan copies that directory as it finds it, so it builds in parallel with plan 38 and only the smoke run needs both.

**Goal:** A developer can build the box base image locally and hand it to the daemon:
- `saiife box image build` ports the spike's bake (`scripts/spike/bake.sh`, `guest/spike-bake.sh`): the Ubuntu 24.04 cloud image, **verified through `SHA256SUMS.gpg` against Ubuntu's signing key**, booted once with a network card over passt to install the box contents, then frozen read-only as `base-<sha256>.raw` with a manifest;
- the guest is trimmed per the spike's list (journald volatile, `multi-user.target`, containerd not at boot, the masked units) and Docker stores layers once (`containerd-snapshotter` off), with a smoke check on the 2× growth;
- every container image the recipe names is pinned by digest, Claude Code is pinned by version and SHA-256, and the image's SHA-256 is recorded in the audit log at import and at every box start;
- no initramfs is built; direct kernel boot is a **measured stretch goal** (the image carries the `-kvm` kernel and the smoke script times both paths).

**Architecture:**
- **The build runs in the CLI, as the user** (spec §7.2: a developer option that needs host tooling). It needs `/dev/kvm`, `passt`, `qemu-img`, `mkfs.vfat`, `mcopy`, `curl` and `gpgv`, all through plan 35's `Tools`. The daemon never downloads or builds an image.
- **`saiife box image import`** passes the finished raw image to the daemon as a file descriptor (plan 37's `fdpass`); the daemon checks the SHA-256 against the manifest, copies it sparsely into its image store and writes an audit record. Locked mode: import is admin-only, and an unsigned (local) image is labelled so.
- **Signed distribution (`saiife box image pull`) is release infrastructure** (spec §7.2, §11 step 3, owner-only release steps) and is not built here; the manifest has a `signature` field reserved for it.
- **Bake inputs travel on a second vfat disk** ("payload", 512 MiB): the `saiife` static binary, the guest assets, the Claude Code binary (fetched and verified on the host), and the bake script. The cloud-init seed (4 MiB vfat, `CIDATA`) only starts the bake script. Outputs (the package list, the kernel for direct boot) come back on the same payload disk and are read with `mcopy` (no mount, no root).

**Tech Stack:** Rust; `serde`, `serde_json`, `toml 0.8`, `ring`; host tools via `Tools`. No new crates.

**Spec:** §7.2, §7.8 (image per template), §11 step 3, §12, §13 (nested Docker), §15. Owner rulings "Supply chain" (binding): verify Ubuntu `SHA256SUMS.gpg` against Ubuntu's signing key; pin every container image by digest; record the base image SHA-256 in the audit log; CH and firmware by pinned digest. Spike: `scripts/spike/bake.sh` (`render_user_data`, `make_seed`, `bake_passt`, `freeze_base`), `guest/spike-bake.sh`, `guest/user-data.tmpl`; results doc "Guest trimming list" and "Base image".

## Decisions

- **I1. Ubuntu chain.** Release `noble/release-20261017` (the spike's). The build downloads `SHA256SUMS` and `SHA256SUMS.gpg` from the release dir and runs `gpgv --status-fd 1 --keyring <assets/box/ubuntu-cloudimage-keyring.gpg> SHA256SUMS.gpg SHA256SUMS`; it requires a `[GNUPG:] VALIDSIG` line whose primary-key fingerprint (the last field) equals `UBUNTU_CLOUD_FPR`, then takes the line for `ubuntu-24.04-server-cloudimg-amd64.img` and checks the download against it. The recipe's `ubuntu.sha256` pin (the spike's value) must also match: a re-signed release with another image is refused until the pin is updated.
- **I2. Key.** `UBUNTU_CLOUD_FPR = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"` (the "UEC Image Automatic Signing Key", `cdimage@ubuntu.com`). **The owner verifies this fingerprint against Ubuntu's published key and exports the keyring file** (`gpg --export --export-options export-minimal <fpr> > assets/box/ubuntu-cloudimage-keyring.gpg`); agents do not fetch keys. Until the file exists the build refuses with that instruction.
- **I3. Claude Code** is the native Linux x64 binary, pinned in the recipe by `version`, `url` and `sha256`; it is fetched on the host by `pins::fetch` and travels on the payload disk. The recipe ships with `sha256 = "UNPINNED"`, which the build refuses (as the spike's `UNPINNED`); the owner fills it from Anthropic's release manifest. A Claude Code update is a new image (§7.2).
- **I4. Container images** in the recipe must be `name@sha256:<64 hex>`; a tag without a digest is refused at recipe load. The default recipe pre-pulls none.
- **I5. Base size.** The base is resized to `BASE_VIRTUAL_GIB = 10` (the spike used 30). Plan 37 grows each box's overlay to the template's `disk_gib` and the guest grows its root partition at boot (`saiife-growroot.service`, ported from the spike's guestfs finish unit). Actual size ceiling `BASE_MAX_ACTUAL_GIB = 5` (spike proposal), checked after the bake.
- **I6. Trim list** (spike results, "Guest trimming list"): mask `multipathd`, `apport`, `rsyslog`, `udisks2`, `polkit`, `grub-common`, `ubuntu-fan`, `setvtrgb`, `snapd.service`, `snapd.socket`, `snapd.seeded.service`, `systemd-networkd-wait-online.service`, `apt-daily.timer`, `apt-daily-upgrade.timer`, `unattended-upgrades.service`; `cloud-init` disabled after the bake; `/etc/systemd/journald.conf.d/saiife.conf` = `[Journal]\nStorage=volatile\nRuntimeMaxUse=32M\n`; `systemctl set-default multi-user.target`; `containerd.service` and `docker.service` disabled, `docker.socket` enabled; `/etc/docker/daemon.json` = `{"features":{"containerd-snapshotter":false},"proxies":{"http-proxy":"http://127.0.0.1:3128","https-proxy":"http://127.0.0.1:3128","no-proxy":"localhost,127.0.0.0/8"}}` (ports from `saiife_boxproto::ports`, plan 38). `systemd-random-seed` stays (CH provides virtio-rng). **Owner check: `polkit` masked** (nothing in the box needs it in v3.0).
- **I7. Box user.** The bake creates `agent` (uid 1000, groups `docker`, `sudo` with `NOPASSWD`), home `/home/agent`, and the mount point `/work` (fstab `LABEL=repo /work ext4 defaults,nofail,x-systemd.device-timeout=5s 0 2`). The agent is root-equivalent, as §15 says; running Claude Code as a non-root user avoids its root refusal. Plan 40 relies on it.
- **I8. Direct kernel boot (stretch).** The bake installs `linux-image-kvm` (virtio and ext4 built in) beside the generic kernel and copies `/boot/vmlinuz-<ver>-kvm` to the payload disk; the build stores it as `base-<sha>.vmlinuz` with cmdline `console=ttyS0 root=LABEL=cloudimg-rootfs rw quiet`. The manifest's `boot` is `firmware` unless `--direct-kernel` is given **and** the owner's smoke run showed it boots. No initramfs is built either way.
- **I9. Manifest** `base-<sha>.json` (`deny_unknown_fields`, `version = 1`), every value below recorded at build time; `signature: null` for local builds (reserved for release signing).

## Global Constraints

Plan 35's Global Constraints apply unchanged (including `CARGO_PROFILE_DEV_DEBUG=0`), with worktree `.worktrees/p36`, branch `v3-p36`, scratch prefix `p36-tN-`. In particular: **never run passt, Cloud Hypervisor, `qemu-img`, `gpgv`, `curl`, `mkfs.vfat` or `mcopy` for real in a test** (every one is a fake script under `$TMPDIR` named through plan 35's debug-only `SAIIFE_TOOL_*` seams); never fetch over the network; never touch `/dev/kvm`. The bake script is checked with `bash -n` and shellcheck only.

### Fixed values

| Name | Value | Source |
|---|---|---|
| `UBUNTU_RELEASE` | `release-20261017` | spike |
| release dir | `https://cloud-images.ubuntu.com/releases/noble/release-20261017/` | spike |
| image file | `ubuntu-24.04-server-cloudimg-amd64.img` | spike |
| `ubuntu.sha256` pin | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` | spike |
| `UBUNTU_CLOUD_FPR` | `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81` | I2 (owner verifies) |
| keyring | `assets/box/ubuntu-cloudimage-keyring.gpg` (owner-exported) | I2 |
| `BASE_VIRTUAL_GIB` | `10` | I5 |
| `BASE_MAX_ACTUAL_GIB` | `5` | spike |
| bake VM | 2 vCPU, 4096 MiB `shared=on`, `--net vhost_user=true,socket=<w>/passt.sock`, no vsock, firmware boot; disks: base (raw), seed (4 MiB vfat `CIDATA`), payload (512 MiB vfat `SAIIFE`) | spike `bake_passt` |
| bake timeout | `1800` s | spike |
| success marker | `SAIIFE-BAKE-OK` alone on a serial line | spike `bake_check` |
| package list | payload `out/packages.txt` (`dpkg-query -W -f '${Package} ${Version}\n'`) | I9 |
| store | `<images>/base-<sha256>.raw` (0440), `.json`, optional `.vmlinuz`; `<images>/default` (one line: the id) | |
| audit | `kind = "box"`, action `image_import` / `image_default` / `image_remove`, plan 34's `extra = {action, box: null, template: null, from: null, to: null, via: "cli"}` (`box_ops.rs:406`) plus `{image, sha256, signed, ubuntu, claude}`; box admission records (spawn and tick) add `extra.image` = `base-<sha256>` | ruling |

Manifest fields: `version, id, sha256, virtual_gib, actual_bytes, built_at, builder ("saiife <version>"), recipe_sha256, ubuntu {release, image_sha256, sums_signer}, vmm {ch_version, ch_sha256, fw_version, fw_sha256}, saiife {version, sha256}, claude {version, sha256}, packages [{name, version}], images [{name, digest}], boot ("firmware" | {kernel: file name, cmdline}), signature (null)`.

## Review Focus

1. **A tampered or swapped Ubuntu download** (bad signature, a good signature by another key, a `SHA256SUMS` without the image's line, an image whose hash matches the signed list but not the recipe pin, a `SHA256SUMS` with two lines for the image). Expected: refused before any boot, with the reason (Task 2: `bad_signature_is_refused`, `other_signer_is_refused`, `missing_line_is_refused`, `pin_mismatch_is_refused`, `duplicate_line_is_refused`).
2. **An unpinned input** (a container image by tag, Claude Code `UNPINNED`, a missing keyring). Expected: refused at recipe load, naming the field (Task 1: `tag_without_digest_is_refused`, `unpinned_claude_is_refused`; Task 2: `missing_keyring_names_the_owner_step`).
3. **A bake that half-works** (the VM exits without `SAIIFE-BAKE-OK`, the marker only inside a `set -x` echo, the base grows past 5 GiB, passt never makes its socket). Expected: no image is written, the temp files are removed, the logs are kept under `<out>/logs-<ts>/` (Task 3: `marker_must_be_a_line_of_its_own`, `failed_bake_keeps_logs_removes_image`, `oversized_base_is_refused`).
4. **A hostile import** (a manifest whose `sha256` does not match the file, a symlink, a manifest with an unknown key, a non-admin peer in locked mode, an id not matching `base-<64 hex>`). Expected: refused and nothing lands in the store; an accepted import writes one audit record with the SHA-256 (Task 5: `import_checks_sha256`, `import_is_admin_only_locked`, `import_refuses_bad_manifest`).
5. **Removing the image a box still uses** (a running box, a `Done` box with its VM off, a kept snapshot). Expected: refused, naming the boxes; `default` cannot be removed (Task 5: `rm_refuses_an_image_in_use`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (recipe, manifest), Task 2 (Ubuntu chain), Task 3 (bake script and seed/payload builders).
- **Wave 2:** Task 4 (`build` command and store resolver; needs 1–3).
- **Wave 3:** Task 5 (daemon store ops, import, audit; needs 4 and plan 37 Task 2), Task 6 (smoke fragment; needs 4).

---

### Task 1: recipe and manifest (size S)

**Files:** Modify `crates/boxhost/src/image.rs`; create `assets/box/recipe.toml`.

**Interfaces (Produces):**
```rust
#[derive(Debug, Clone, PartialEq, Eq)] pub struct Recipe { pub ubuntu_release: String, pub ubuntu_sha256: String, pub packages: Vec<String>, pub images: Vec<PinnedImage>, pub claude: ClaudePin, pub direct_kernel: bool }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] pub struct PinnedImage { pub name: String, pub digest: String }   // from "name@sha256:<64 hex>"
#[derive(Debug, Clone, PartialEq, Eq)] pub struct ClaudePin { pub version: String, pub url: String, pub sha256: String }
pub fn parse_recipe(text: &str) -> Result<Recipe, String>;             // deny_unknown_fields; I3, I4
pub const DEFAULT_RECIPE: &str = include_str!("../../../assets/box/recipe.toml");
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(deny_unknown_fields)] pub struct Manifest { /* the fields listed above */ }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")] pub enum ManifestBoot { Firmware, Kernel { kernel: String, cmdline: String } }
pub fn image_id(sha256: &str) -> String;                                // "base-" + sha256
pub fn parse_image_id(s: &str) -> Result<String, String>;              // returns the sha256; "base-" + 64 lowercase hex
impl Manifest { pub fn parse(text: &str) -> Result<Manifest, String>; pub fn to_json(&self) -> String; }   // version 1 only
```
`assets/box/recipe.toml`:
```toml
[ubuntu]
release = "release-20261017"
sha256 = "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94"
[packages]
apt = ["docker.io", "socat", "git", "ca-certificates", "curl", "build-essential", "pkg-config", "python3", "python3-venv", "cloud-guest-utils", "linux-image-kvm"]
[images]
pull = []
[claude]
version = "UNPINNED"
url = "UNPINNED"
sha256 = "UNPINNED"
[boot]
direct_kernel = false
```
Apt names must match `[a-z0-9][a-z0-9+.-]{0,62}`.

- [ ] **Step 1: Write the failing tests:** `default_recipe_parses_but_claude_is_unpinned` (`parse_recipe` errs naming `claude.sha256`), `pinned_recipe_parses`, `tag_without_digest_is_refused` (`busybox:1.36`), `digest_must_be_64_hex`, `bad_apt_name_is_refused` (`"x; rm -rf /"`), `unknown_key_is_refused`, `manifest_roundtrip` (a full manifest to JSON and back), `manifest_version_2_is_refused`, `image_id_rules`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): image recipe with pinned inputs, and the base manifest`.

---

### Task 2: the verified Ubuntu download (size M)

**Files:** Modify `crates/boxhost/src/image.rs` (`ubuntu` submodule `src/image/ubuntu.rs`); create `crates/boxhost/tests/fixtures/gpgv/*.status` (recorded `--status-fd` outputs: good, bad signature, other key, no signature).

**Interfaces (Produces):**
```rust
pub const UBUNTU_CLOUD_FPR: &str = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
pub const UBUNTU_IMAGE: &str = "ubuntu-24.04-server-cloudimg-amd64.img";
pub fn release_url(release: &str, file: &str) -> String;              // the release dir + file
pub fn check_signature(tools: &Tools, keyring: &Path, sums: &Path, sig: &Path) -> Result<(), String>;   // I1
pub fn parse_validsig(status: &str) -> Option<String>;                // primary fingerprint from "[GNUPG:] VALIDSIG …"
pub fn sum_for(sums_text: &str, file: &str) -> Result<String, String>;   // exactly one "<64 hex> *<file>" or "<64 hex>  <file>" line
pub fn fetch_verified(tools: &Tools, cache: &Path, recipe: &Recipe, keyring: &Path) -> Result<PathBuf, String>;   // cached image path
```
`check_signature`: exit status 0 **and** a `VALIDSIG` fingerprint equal to `UBUNTU_CLOUD_FPR` **and** no `BADSIG`/`ERRSIG`/`EXPKEYSIG`/`REVKEYSIG` line. `fetch_verified`: `SHA256SUMS` and `.gpg` are downloaded fresh each build (no digest to pin them by), the image through `pins::fetch` with the signed sum, then the recipe pin compared. Cache: `$XDG_CACHE_HOME/saiife/box-image/`.

- [ ] **Step 1: Write the failing tests** (fake `gpgv` prints a fixture to the status fd and exits with its code; fake `curl` copies from a fixture dir): `parse_validsig_takes_primary_fpr`, `good_signature_passes`, `bad_signature_is_refused`, `other_signer_is_refused`, `exit_zero_without_validsig_is_refused`, `missing_line_is_refused`, `duplicate_line_is_refused`, `pin_mismatch_is_refused`, `missing_keyring_names_the_owner_step` (message contains `gpg --export`), `fetch_verified_uses_the_cache`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): Ubuntu cloud image verified through SHA256SUMS.gpg and a pinned key`.

---

### Task 3: bake script, seed and payload (size M)

**Files:** Create `assets/box/bake/saiife-bake.sh`, `assets/box/bake/user-data.tmpl`, `assets/box/bake/saiife-growroot.service`; modify `crates/boxhost/src/bake.rs`.

**Interfaces (Produces):**
```rust
pub struct BakeInputs { pub saiife_bin: PathBuf, pub claude_bin: PathBuf, pub guest_assets: PathBuf /* assets/box/guest */, pub recipe: Recipe }
pub fn render_user_data(tmpl: &str, bake_sh: &str) -> String;          // port of render_user_data: base64 of the script into @SAIIFE_BAKE_B64@
pub fn make_seed(tools: &Tools, out: &Path, user_data: &str) -> Result<(), String>;    // 4 MiB vfat CIDATA: user-data + meta-data (instance-id: saiife-bake, local-hostname: box)
pub fn make_payload(tools: &Tools, out: &Path, inputs: &BakeInputs) -> Result<(), String>;   // 512 MiB vfat SAIIFE: saiife, claude, guest/**, recipe.env, out/
pub fn bake_argv(base: &Path, seed: &Path, payload: &Path, fw: &Path, work: &Path) -> Vec<OsString>;   // bake VM row of Fixed values
pub fn bake_check(serial_log: &str) -> bool;                            // SAIIFE-BAKE-OK on a line of its own, CRs removed
pub fn is_static_elf(path: &Path) -> Result<bool, String>;             // no PT_INTERP program header
pub fn read_out(tools: &Tools, payload: &Path, name: &str, dest: &Path) -> Result<(), String>;   // mcopy -i <payload> ::out/<name> <dest>
```
`recipe.env` carries only `APT_PACKAGES=…`, `PULL_IMAGES=name@sha256:…` (space separated) and `DIRECT_KERNEL=0|1`, each value checked by Task 1's rules, so the guest script never evaluates free text.

`saiife-bake.sh` (guest, root, `set -euxo pipefail`; port of `spike-bake.sh all`): mount the payload (`LABEL=SAIIFE`) at `/mnt/saiife` read-write; `apt-get update && apt-get install -y --no-install-recommends $APT_PACKAGES`; install `/mnt/saiife/saiife` → `/usr/local/bin/saiife` (0755) and `/mnt/saiife/claude` → `/usr/local/bin/claude` (0755); copy `/mnt/saiife/guest/units/*` to `/etc/systemd/system/` and enable each unit listed in `/mnt/saiife/guest/enable.list` (plan 38 writes both); install and enable `saiife-growroot.service` (`Type=oneshot`, `After=systemd-remount-fs.service`, `ExecStart=-/usr/bin/growpart /dev/vda 1`, `ExecStart=/usr/sbin/resize2fs /dev/vda1`, `WantedBy=multi-user.target`; both commands are no-ops once grown; ported from the spike's guestfs finish unit); create the `agent` user and `/work` (I7); write `daemon.json` and journald drop-in, mask/disable per I6, `systemctl set-default multi-user.target`; start Docker once and `docker pull` each `PULL_IMAGES` entry, check `docker image inspect --format '{{index .RepoDigests 0}}'` equals the pin, then stop `docker.service docker.socket`; with `DIRECT_KERNEL=1` copy the newest `/boot/vmlinuz-*-kvm` to `/mnt/saiife/out/vmlinuz`; write `out/packages.txt`; `touch /etc/cloud/cloud-init.disabled`; `apt-get clean`; `sync`; `fstrim -av || true`; `echo SAIIFE-BAKE-OK >/dev/ttyS0`. `user-data.tmpl` (port of the spike's): `package_update: false`, `write_files` of the script, `runcmd: [[bash, /usr/local/sbin/saiife-bake.sh]]`, `power_state: {mode: poweroff, timeout: 60}`.

- [ ] **Step 1: Write the failing tests:** `user_data_embeds_the_script` (base64 decodes back), `seed_and_payload_call_mkfs_and_mcopy` (fake tools record argv: `mkfs.vfat -n CIDATA`, `-n SAIIFE`, `mcopy -i … ::`), `bake_argv_is_pinned`, `marker_must_be_a_line_of_its_own` (`+ echo SAIIFE-BAKE-OK` is false; `SAIIFE-BAKE-OK\r` is true), `static_elf_check` (a tiny ELF fixture with and without `PT_INTERP`, built as byte arrays in the test), `recipe_env_holds_only_checked_values`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement**; `bash -n assets/box/bake/saiife-bake.sh`; shellcheck if installed. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(boxes): bake script with the spike's trim list, seed and payload disks`.

---

### Task 4: `saiife box image build` and the store resolver (size L)

**Files:** Create `crates/cli/src/box_image_cmd.rs`; modify `crates/cli/src/box_cmd.rs` (`BoxAction::Image { #[command(subcommand)] action: ImageAction }`), `crates/boxhost/src/image.rs` (`Store`).

**Interfaces:**
- Consumes: Tasks 1–3; plan 35 `pins`, `Tools`, `Layout`, `ResolvedImage`, `ImageResolver`, `Boot`.
- Produces:
```rust
#[derive(Subcommand)] pub enum ImageAction {
  /// Build a base image locally (needs /dev/kvm, passt, qemu-img, mtools, curl, gpgv).
  Build { #[arg(long)] recipe: Option<PathBuf>, #[arg(long)] out: Option<PathBuf>, #[arg(long)] saiife_bin: Option<PathBuf>, #[arg(long)] direct_kernel: bool },
  /// Hand a built image to the daemon.
  Import { path: PathBuf, #[arg(long)] default: bool },
  Ls { #[arg(long)] json: bool },
  Default { id: String },
  Rm { id: String },
}
pub struct Store { /* dir */ }
impl Store {
  pub fn open(dir: PathBuf) -> Result<Store, String>;
  pub fn list(&self) -> Vec<(Manifest, Vec<String>)>;     // with warnings per bad entry
  pub fn default_id(&self) -> Option<String>;
  pub fn set_default(&self, id: &str) -> Result<(), String>;
  pub fn insert(&self, raw_src: &mut File, manifest: &Manifest, kernel: Option<&mut File>) -> Result<(), String>;   // copy_sparse into .tmp, sha256 check, rename; 0440
  pub fn remove(&self, id: &str) -> Result<(), String>;
}
impl ImageResolver for Store { /* ImageRef::Default -> default_id; Pinned(id) -> that id; ResolvedImage { boot from manifest: Firmware{fw = vmm/CLOUDHV.fd} | Kernel{<images>/<id>.vmlinuz, cmdline} } */ }
```
`Build` steps (each a function in `box_image_cmd.rs`, the order of the spike's `bake`): `preflight` (tools present, `/dev/kvm` rw, 20 GiB free in `out`, socket path ≤ 100 bytes); recipe load (refuses `UNPINNED`); `--saiife-bin` (default `current_exe`) must be a static ELF, else `build saiife for x86_64-unknown-linux-musl, or pass --saiife-bin`; VMM pins ok (`saiife box vmm fetch` hint); `fetch_verified`; `pins::fetch(claude)`; `qemu-img convert -O raw` into `<out>/base.tmp`, `qemu-img resize -f raw base.tmp 10G`; seed + payload; start `passt -f --vhost-user --one-off --socket-path <w>/passt.sock` as a child (wait ≤ 10 s for the socket), start CH with `bake_argv` as a child, wait ≤ 1800 s for exit (bounded `try_wait` loop; at the timeout `Child::kill` on both own children); `bake_check(serial.log)`; read `out/packages.txt` (and `vmlinuz` when asked); `chmod 0444`, `sha256_file`, actual size ≤ 5 GiB; rename to `<out>/base-<sha>.raw`, write the manifest beside it. On any failure: remove `base.tmp`, copy `serial.log`, `ch.log`, `passt.log` to `<out>/logs-<UTC ts>/`, exit 1. Prints the image id and `saiife box image import <path>` as the next step.

- [ ] **Step 1: Write the failing tests** (`crates/cli/tests/box_image_build.rs`, debug build, every tool a fake script: fake CH writes `SAIIFE-BAKE-OK` to its `--serial file=` and fakes `out/packages.txt` through a fake `mcopy`): `build_produces_image_and_manifest` (manifest fields: ubuntu sha, `sums_signer == UBUNTU_CLOUD_FPR`, vmm pins, saiife sha, claude pin, packages parsed, `boot == Firmware`), `build_refuses_dynamic_saiife`, `build_refuses_unpinned_claude`, `failed_bake_keeps_logs_removes_image`, `oversized_base_is_refused` (the actual-size reader is injected as `fn(&Path) -> io::Result<u64>`, since a test cannot allocate 5 GiB; it returns 5 GiB + 1), `bake_timeout_kills_own_children` (timeout 2 s through a debug-only `SAIIFE_TEST_BAKE_TIMEOUT`); boxhost `store_resolves_default_and_pinned`, `store_insert_checks_sha256`, `store_lists_and_warns`, `resolver_kernel_boot`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(cli): saiife box image build, a verified and trimmed base image`.

---

### Task 5: daemon image store ops, import and audit (size M)

**Files:** Create `crates/daemon/src/box_images.rs`; modify `crates/daemon/src/box_ops.rs` (route `box.image.*`; `box_rec` `pub(crate)`; `extra.image` in the spawn record and in `write_tick_records`), `crates/ipc/src/msg.rs` (ops), `crates/wire/src/level.rs` (`IPC_OPS`), `crates/boxes/src/vmm.rs` (`Vmm::image_id`), `crates/boxes/src/vmm/fake.rs` (a settable image), `crates/boxes/src/manager.rs` (fill the existing `image` fields at admission), `crates/boxhost/src/vmm.rs` (`ChVmm::image_id`), `crates/cli/src/box_image_cmd.rs` (`Import`, `Ls`, `Default`, `Rm`).

**Interfaces:**
- Consumes: `Store` (Task 4); `saiife_ipc::Client::call_with_fds`, the daemon's `Conn::take_fds` and `saiife_boxhost::disk::copy_sparse` (plan 37 Task 2); plan 34's `box_rec` (`box_ops.rs:406`), `BoxRecord.image` (`store.rs:53`) and `Change.image` (`manager.rs:88`), both already present.
- Produces:
```rust
// ipc msg.rs (MachineOnly). Never an argument or answer key named `id` (msg.rs:318-322, :384-393).
pub const OP_BOX_IMAGE_LS: &str = "box.image.ls";           // {} -> {images: [Manifest + {default: bool, in_use: [box id]}], warnings}
pub const OP_BOX_IMAGE_IMPORT: &str = "box.image.import";   // {manifest, default?} + fds [raw, kernel?] -> {image}
pub const OP_BOX_IMAGE_DEFAULT: &str = "box.image.default"; // {image} -> {}
pub const OP_BOX_IMAGE_RM: &str = "box.image.rm";           // {image} -> {}
// boxes vmm.rs (addition to plan 34's trait, default keeps FakeVmm-free impls compiling)
fn image_id(&self, h: &VmHandle) -> Option<String> { None }
```
- Import: the peer must be root or an `[admin]` member in locked mode (`(peer.sid.is_none() && peer.uid == 0) || ctx.peer_is_admin(&peer)`, as `box_ops.rs:707`; any local peer of the daemon's own uid in personal mode); the manifest parses; `fds[0]` is a regular file (`fstat`), its SHA-256 equals `manifest.sha256`; `Store::insert`; audit `image_import` with `signed: manifest.signature.is_some()` (always `false` in this plan). `--default` also sets the default (one more record).
- Rm: refused when any box record names the image (`BoxRecord.image`, plan 34's field, resolved at admission), or when it is the default.
- Admission: right after `vmm.create`, `Manager` sets `BoxRecord.image` and `Change.image` from `vmm.image_id(&h)` (`ChVmm` reads its own `data` JSON `"image"`), and `box_ops` puts it in `extra.image` of the spawn record (a box admitted at its own spawn, R22) and of tick records (queue heads) (ruling: the base image SHA-256 is in the audit log for every box start).
- The CLI `Import` opens the file read-only with `O_NOFOLLOW` and sends it with `Client::call_with_fds` (plan 37 Task 2); `Ls` prints `ID  DEFAULT  UBUNTU  CLAUDE  SIZE  IN USE`.

- [ ] **Step 1: Write the failing tests** (daemon `tests/box_images.rs`, personal and locked `test_ctx`): `import_checks_sha256`, `import_refuses_a_symlink_fd_target` (the CLI side refuses to open a symlink: `O_NOFOLLOW`), `import_refuses_bad_manifest`, `import_is_admin_only_locked`, `import_writes_one_record_with_sha256`, `default_and_ls`, `default_and_rm_take_image_not_id` (over the real socket through `Client::call`: `{image: "base-…"}` works; the answer of `import` has `image`), `rm_refuses_an_image_in_use`, `rm_refuses_the_default`, `admission_record_names_the_image` (`FakeVmm` set to answer `image_id = Some("base-…")`: a box spawned with room has `extra.image` on its spawn record; a queued box admitted later has it on its tick record; `BoxRecord.image` is set), `manager_never_parses_handle_data` (a `FakeVmm` handle whose `data` is not JSON still admits), `old_box_json_without_image_loads` (plan 34's record shape).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; `every_ipc_op_is_classified` passes.
- [ ] **Step 5: Commit** `feat(daemon): box image store, import over a passed fd, image hash in the audit log`.

---

### Task 6: the smoke fragment (size S)

**Files:** Create `scripts/box-smoke.d/05-image.sh`.

Owner-run checks, in order, each a result key: `saiife box image build` with the owner-pinned recipe succeeds (`image_build_s`); the manifest's `sums_signer` is `UBUNTU_CLOUD_FPR`; actual size (`image_actual_bytes`) ≤ 5 GiB; `saiife box image import --default`; the audit log has the `image_import` record with the SHA-256 (`jq` over the audit `*.jsonl`: `saiife audit` has no JSON output, plan 27 R-I); a box boots and `systemd-analyze` and `systemd-analyze blame` on its **cold** boot are captured into results (`systemd_analyze_cold`, `systemd_blame_cold`; this finishes the spike's trim list); inside the box (through plan 38's channel or plan 40's `say`): `systemctl is-enabled containerd.service` is `disabled`, `journalctl --header` shows volatile storage, `systemctl get-default` is `multi-user.target`; **Docker growth check:** `docker build` of `FROM busybox@sha256:<pin>` with a 200 MiB random `RUN` (as the spike's) grows the overlay by ≤ 1.3 × 200 MiB (`overlay_growth_ratio`; the spike measured 2.03 with the containerd store); **direct kernel stretch:** rebuild with `--direct-kernel`, boot 5 times, `boot_kernel_ms_median` beside the firmware `boot_cold_ms_median`; the owner keeps direct boot only if it reaches ready and is faster (target ≤ 2 s, ceiling 5 s).

- [ ] **Step 1:** write the fragment; `bash -n`; shellcheck if installed.
- [ ] **Step 2: Commit** `test(boxes): owner smoke for the base image, trim list, Docker growth and direct boot`.

---

## Gates

- [ ] `cargo test -p saiife-boxhost --features fake`, `-p saiife-daemon --features fake-vmm`, `-p saiife --features fake-vmm`, `-p saiife-wire --features fake`; `-j 4 -- --test-threads=4`.
- [ ] clippy, `check-unsafe.sh`, `check-windows.sh -p saiife-daemon -p saiife -p saiife-boxes`; tokio gate `0`.
- [ ] `grep -rn 'UNPINNED' assets/box/recipe.toml` still shows the Claude pin unfilled (the owner fills it; agents never invent a digest).
- [ ] Whole-branch review against Review Focus; one fix wave; PR to `v3-dev`.

## Owner handwork

- [ ] Verify `UBUNTU_CLOUD_FPR` against Ubuntu's published key and export the keyring into `assets/box/ubuntu-cloudimage-keyring.gpg` (I2).
- [ ] Fill the Claude Code pin in `assets/box/recipe.toml` (I3).
- [ ] Run `scripts/box-smoke.sh --only image`; decide direct kernel boot (I8) and the `polkit` mask (I6) from the results.
- [ ] Release pipeline (later, owner-only): build, sign and host the image; `saiife box image pull` verifies the release-key signature over the manifest.
