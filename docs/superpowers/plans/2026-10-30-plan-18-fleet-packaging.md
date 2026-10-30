# Plan 18 — Fleet packaging: `.deb`, `.rpm`, macOS `.pkg`, MDM recipes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A company rolls out locked mode with its normal tools. It drops two fleet files, then installs a `.deb`, an `.rpm` or (after plan 13) a signed, notarized `.pkg`. Jamf, Intune and Ansible recipes do this and report `doctor` back.

**Architecture:**
- **The package ships one binary and two maintainer scripts. It does not lay down locked mode itself.**
  - The binary goes to a staging path, `/usr/libexec/saiife/saiife`, with a `/usr/bin/saiife` symlink.
  - `postinst` (and `%post`) runs `/usr/libexec/saiife/saiife system install --fleet`.
  - `prerm` (and `%preun`) runs `system uninstall` on removal only.
  - `system install` keeps doing everything else, as today: users, `/opt/saiife/bin/saiife`, `/etc/saiife`, the unit, the managed hooks, `installed.toml` and `doctor`.
- **A new flag, `system install --fleet`, reads `/etc/saiife/fleet/`.** It holds `config.toml` (the §8.1 format) and `install.toml` (the agents and approvers). The MDM tool writes these files; the package never owns them.
- **Tooling:**
  - nfpm builds both Linux formats from one config, without root.
  - A CI job `package-linux` installs, upgrades and removes the `.deb` on real Ubuntu runners. It installs and removes the `.rpm` in a Rocky Linux 9 container.
  - The release builds, signs and checksums the packages.
  - The recipes live under a new `deploy/` dir.

**Tech Stack:**
- Rust workspace: `crates/system` and `crates/cli`. No new crate dependencies.
- nfpm (a Go binary, pinned by version and SHA-256), POSIX `sh` maintainer scripts and GitHub Actions.
- Ansible (lint only) and Intune and Jamf script recipes.
- After plan 13: `pkgbuild`, `productbuild`, `notarytool` and `stapler`.

**Spec:** `docs/superpowers/specs/2026-10-19-saiife-v2-design.md`. This plan covers:
- §15.2 row 18;
- §16.1 row "Fleet packages";
- §12 step 5 (fleets);
- §7 rows `system install` and `system uninstall`;
- §5.2 and §5.3 (the paths the package must not own);
- §6.16 ("fleet tools can run it on a schedule").

Plans 12 and 17 set the style.

## Global Constraints

- **Standing rules (plans 12 and 17):**
  - **Nothing privileged on the dev machine.** That means no sudo, root, `dpkg -i`, `rpm -i`, `dnf`, `apt-get install`, `installer`, `systemctl`, `launchctl`, docker or ansible runs, and no writes to `/etc`, `/opt`, `/var` or `/usr`.
  - **No process-control tools, not even to probe them:** kill, pkill, killall, pgrep, su, loginctl. CI scripts use what they need, in CI only.
  - **Allowed locally:** `nfpm package`, because it needs no root (it writes the archive headers as uid 0 itself). `shellcheck`, `bash -n`, `sh -n` and `ansible-lint` may run if they are installed. They are linters and execute nothing on the machine.
  - **CI-only scripts** (`scripts/package-linux/*`, `scripts/locked-linux/*`) refuse to run outside GitHub Actions, as `scripts/locked-linux/run.sh` does. Locally they are checked with `bash -n` only.
  - **Test isolation:** `TMPDIR` and `SAIIFE_TEST_TMP` point to a short dir from `mktemp -d -p /home/jonas/projects/personal/saiife`, removed afterwards. Never use /tmp, the real home or `~/.claude`. No internet in tests.
  - **No `unsafe`.** Every crate keeps `#![forbid(unsafe_code)]`. `crates/system` stays tokio-free.
  - **Commits:**
    - the branch is `plan-18-fleet-packaging` from `main` (838a318 or later);
    - each task is committed with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
    - never commit `.superpowers/`, key material or token-shaped literals;
    - `gh` needs `GH_CONFIG_DIR=$HOME/.config/gh-personal`;
    - no tags.
  - **CI job ids** contain no dots: `package-linux`, `ansible-lint`, `linux-packages`, `package-test`, `macos-pkg`.
- **Decision 1: the package runs `system install`. It does not lay down locked mode declaratively.** Why:
  - `system install` creates users and groups, checks every directory it writes below, keeps the vault key, writes the managed hooks and records each path with its SHA-256 in `installed.toml`. `uninstall` and `doctor` trust that record. If dpkg or rpm owned the same paths, each file would have two owners, and a dpkg-owned unit or hook file would be removed or changed behind `installed.toml`'s back.
  - So the package owns exactly three paths: `/usr/libexec/saiife/saiife` (the staging copy), the dir it is in, and the symlink `/usr/bin/saiife` → `/usr/libexec/saiife/saiife`. It also ships docs under `/usr/share/doc/saiife/`. It never ships a path under `/opt/saiife`, `/etc`, `/var`, `/run` or `/usr/share/polkit-1`. A Rust test pins this (Task 2).
  - `install` copies the bytes it runs from to `/opt/saiife/bin/saiife`, as it does today. The hooks call only that path.
  - Packages may not write `/usr/local`, so the spec's optional `/usr/local/bin/saiife` symlink (§5.2) becomes `/usr/bin/saiife` in packages.
- **Decision 2: the fleet files.** The spec names `--config <file>` and the §8.1 format, but no path. This plan fixes these paths:
  - `/etc/saiife/fleet/config.toml`: the §8.1 system config (`locked = true`). When it is there, `--fleet` passes it as `--config`, so it is checked and copied to `/etc/saiife/config.toml` on every run. **The MDM's file wins over local edits.** Admins edit the fleet file; `docs/fleet.md` says so.
  - `/etc/saiife/fleet/install.toml`: `agents = ["claude", "codex", "gemini"]` and `approvers = ["group:…"]`, both optional (`deny_unknown_fields`).
  - The agents come from `install.toml` when it lists them. Otherwise they are the agents recorded in `installed.toml`, so an upgrade never adds an agent the admin left out. With neither, they are all three (the CLI default).
  - The dir and both files must be root's and not writable by group or others, and the files must be regular files opened with `O_NOFOLLOW`, at most 1 MiB. Anything else is refused with exit 2 before anything changes.
  - `policy.d/*.toml` stays the admin's: the MDM writes `/etc/saiife/policy.d/` directly and runs `saiife policy reload`.
- **Decision 3: maintainer scripts.** The same two POSIX `sh` scripts serve deb and rpm:
  - `postinst` runs install on `configure`, `abort-upgrade`, `abort-remove` and `abort-deconfigure` (deb), or `1` and `2` (rpm). An exit code of 2 (install error or unsupported host) fails the script. An exit code of 1 (installed, but doctor found failures) passes, because the doctor text is already printed. Why: a fleet package exists to lock. Exiting 0 with no lock is the silent failure this plan must avoid.
  - `prerm` runs uninstall only on `remove` (deb) or `0` (rpm). An upgrade (`upgrade` or `1`) does nothing.
  - On deb, a failing `postinst` leaves the package half-configured until it is fixed. On rpm, a failing `%post` is a loud scriptlet error, but rpm keeps the package installed. `docs/fleet.md` states both, and the recipes check `doctor`.
- **Decision 4: upgrades with a running daemon.** dpkg and rpm replace only the staging copy, so the running daemon and the hooks keep using the old `/opt` binary until `postinst`. Then `install` replaces `/opt/saiife/bin/saiife` atomically (`write_file_atomic`, rename) and restarts `saiifed.service` because the binary changed (existing code). The managed hook files are never removed during an upgrade. During the restart the hooks fail closed (spec §9.3).
- **Decision 5: config changes reload the daemon.** Today `install` writes a new `config.toml` but restarts only on a binary, unit or membership change. A running daemon kept the old policy. Now, when `config.toml` changed and no restart is due, `install` runs `systemctl reload saiifed.service` (the unit's `ExecReload` sends SIGHUP). This fixes manual `--config` runs too.
- **Decision 6: removal.** The package uninstalls locked mode on removal, as spec §7 lets root do. It is never silent:
  - `prerm` prints `saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked` to stderr;
  - the same line goes to syslog with `logger -t saiife -p auth.warning`, when `logger` exists;
  - the daemon's own `stop` record ends the chain and is forwarded (plan 12).

  There is no removal block: root can remove anything.
- **Decision 7: purge.** `system uninstall` without `--purge` keeps the audit, the vault key, the state, the config and the users (spec §7), and package purge does the same. The audit is evidence, and dpkg's purge runs after the binary is gone. For a full wipe, run `sudo saiife system uninstall --purge` first, then remove the package. `prerm` then finds nothing to uninstall.
- **Decision 8: nfpm.** It runs without root, builds deb and rpm from one YAML, maps the arch names (amd64/arm64 → x86_64/aarch64) and signs rpm natively. cargo-deb and cargo-generate-rpm would need two configs and two tools. Pin the newest nfpm release that is older than 14 days on the day it is added. Its version and the SHA-256 of the `Linux_x86_64` tarball go in `packaging/linux/nfpm.version`, and CI checks the hash before it runs nfpm.
- **Decision 9: signing.**
  - The rpm is signed by nfpm when the secret `PKG_GPG_PRIVATE_KEY` (armored) is set, with the passphrase in `PKG_GPG_PASSPHRASE`.
  - The deb is not signed per file; apt verifies repositories, not `.deb` files. Instead, `SHA256SUMS` covers every asset, and the same key makes `SHA256SUMS.asc` (`gpg --detach-sign --armor`).
  - Without the secrets, CI and the release stay green and log `::notice::packages are unsigned (PKG_GPG_PRIVATE_KEY not set)`.
  - The public key lives in `deploy/keys/saiife-packages.asc`, which the owner commits.
  - No apt or yum repository is in this plan (follow-up).
- **Decision 10: what the rpm test covers.** Locked mode refuses containers by design (`supported.rs`). So the Rocky 9 container test covers the payload, the modes, the scriptlet wiring, the loud refusal, the upgrade of the staging copy and a clean removal. The full locked flow on RHEL 9 is owner handwork on a VM. The full flow runs in CI on the Ubuntu deb jobs.
- **Decision 11: no image builds.** In a chroot or image build (no running systemd), `postinst` fails with the refusal line. Golden images install the package at first boot instead (follow-up: a first-boot unit).
- **Spec values, verbatim:**
  - the paths `/opt/saiife/bin/saiife`, `/etc/saiife/config.toml`, `/etc/saiife/installed.toml` and `/etc/systemd/system/saiifed.service`, and the macOS path `/Library/LaunchDaemons/com.saiife.saiifed.plist`;
  - the user `saiife` and the macOS user `_saiife`;
  - the refusal line `saiife: locked mode is not supported here: <why>. Developer mode works as before.`;
  - `doctor --json` is `{"saiife_doctor":1,"exit":<n>,"checks":[…]}`, and its exit codes are 0, 1 and 2;
  - install's exit codes are 0, 1 and 2 (docs/install.md).
- **Spec notes** (Task 6 adds each to the spec):
  - §7: `system install` gains `--fleet`;
  - §12 step 5 names the fleet files and the packages;
  - §15.2 row 18 says what is built.

## Review Focus

1. **A fleet file another user can change:** a group-writable `/etc/saiife/fleet`, a fleet file owned by a non-root uid, or a symlink to a user's file. Expected: exit 2 naming the path, nothing written (Task 1: `fleet_dir_group_writable_refused`, `fleet_file_not_root_owned_refused`, `fleet_symlink_refused`).
2. **An upgrade while agents are working.** Expected: the daemon is restarted once and the new binary's fingerprint is in `installed.toml`. The managed hook files keep their SHA-256, the chain verifies with `stop` then `start`, and there is no moment where a hook file is missing (Task 3: phase `upgrade`).
3. **A fleet config change pushed by the MDM without a package change.** Expected: `install --fleet` copies it, and the running daemon reloads it (SIGHUP, same MainPID). The new policy hash shows in `status` (Task 1: `config_change_reloads_running_daemon`; Task 3: phase `config-change`).
4. **`apt-get remove` or `dnf remove` run by mistake.** Expected: the warning on stderr and in syslog, and a `stop` record in the chain. The audit, config and fleet files are kept. A failed uninstall keeps the package installed, so the lock stays (Task 3: phase `remove`).
5. **A `postinst` that fails half-way** (a bad fleet file, the daemon does not start). Expected: deb is left half-configured with the refusal on screen. Fixing the file and running `dpkg --configure -a` completes the install, with no leftovers from the failed run (Task 3: phase `refusal`).

---

## Task order and parallelism

- **Wave 1 (parallel):** Task 1 (`--fleet`, reload, doctor) and Task 2 (nfpm, maintainer scripts, layout guard). Task 2 only names the flag, so it does not need Task 1's code to build.
- **Wave 2:** Task 3 (CI `package-linux`; needs 1 and 2). Task 5 (Ansible and Intune Linux; needs 1's file formats) runs in parallel.
- **Wave 3:** Task 4 (release; needs 2 and 3), then Task 6 (docs; needs everything above).
- **Then:** the gates, a whole-branch review, one fix wave, push, PR and CI. The owner merges.
- **Task 7 is not part of this branch.** It starts on a new branch after plan 13 merges (see its header).

**Shared files:** `.github/workflows/ci.yml` (Tasks 2, 3 and 5 add jobs and shellcheck paths in separate hunks; cherry-pick in task order), `.github/workflows/release.yml` (Task 4, later Task 7), `crates/cli/src/system_cmd.rs` (Task 1 only).

---

### Task 1: `system install --fleet`, reload on config change, doctor `files.package`

**Files:**
- Create `crates/system/src/fleet.rs`.
- Modify:
  - `crates/system/src/lib.rs` (`pub mod fleet;`);
  - `crates/system/src/layout.rs` (the constants below);
  - `crates/system/src/install.rs` (`Run::config` returns `bool`; `Run::start` reloads);
  - `crates/system/src/doctor/system.rs` (new check);
  - `crates/cli/src/system_cmd.rs` (the flag).
- Test: unit tests in `fleet.rs`, `install.rs` and `doctor/system.rs`, plus `crates/cli/tests/system_install.rs`.

**Interfaces:**
- Consumes:
  - `install::{InstallOptions, InstallError, check_trusted_owner_mode}`;
  - `saiife_policy::installed::read_installed`;
  - `saiife_agents::Agent::{ALL, from_name}`.
- Produces:
  - `layout.rs`:
    - `pub const FLEET_DIR: &str = "/etc/saiife/fleet";`
    - `pub const FLEET_CONFIG: &str = "/etc/saiife/fleet/config.toml";`
    - `pub const FLEET_INSTALL: &str = "/etc/saiife/fleet/install.toml";`
    - `pub const PACKAGE_BINARY: &str = "/usr/libexec/saiife/saiife";` (Linux)
  - `fleet.rs`: `#[derive(Deserialize)] #[serde(deny_unknown_fields)] pub struct FleetInstall { pub agents: Option<Vec<String>>, #[serde(default)] pub approvers: Vec<String> }`.
  - `pub fn fleet_options(layout: &Layout, host: &dyn Host) -> Result<InstallOptions, InstallError>` returns:
    - `config: Some(layout.at(FLEET_CONFIG))` when that file exists;
    - `agents` as in decision 2;
    - `approvers` from `install.toml`;
    - `non_interactive: true` and `allow_test_build: false`.

    Refusals are `InstallError::Refused { path, detail }` with the logical path (`/etc/saiife/fleet/…`). An unknown agent name is `unknown agent "x" (claude, codex, gemini)`. A missing `FLEET_DIR` is not an error; it means no fleet files.
  - CLI: `--fleet` on `SystemAction::Install`, `conflicts_with_all = ["config", "agents", "approvers"]`, help `Read the install options from /etc/saiife/fleet/ (packages and MDM tools)`. It works with the hidden `--root`.

- [ ] **Step 1: failing tests.** In `fleet.rs`, under `#[cfg(all(test, target_os = "linux"))]`, with the `install::tests::env` helper:
  - `fleet_reads_config_and_agents`: `install.toml` says `agents = ["claude", "codex"]` → `opts.agents == [Claude, Codex]`, `opts.config == Some(<root>/etc/saiife/fleet/config.toml)`, `non_interactive`.
  - `fleet_without_files_uses_recorded_agents`: an earlier install with `--agents claude`, no fleet dir → `[Claude]`.
  - `fleet_without_anything_defaults_to_all_agents` → `Agent::ALL`.
  - `fleet_dir_group_writable_refused` (mode 0775 → `Refused`, path `/etc/saiife/fleet`).
  - `fleet_file_not_root_owned_refused` (FakeHost chown to a non-root uid).
  - `fleet_symlink_refused` (`config.toml` is a symlink).
  - `fleet_file_over_1_mib_refused`.
  - `fleet_install_toml_unknown_key_refused` (`agent = [...]`, the detail names the key).
  - `fleet_unknown_agent_refused`.

  In `install.rs` tests:
  - `config_change_reloads_running_daemon`: `set_active`, then install with a changed `--config` → calls contain `systemctl reload saiifed.service` and no `restart`.
  - `same_config_no_reload`.
  - `binary_and_config_change_restarts_only`: a restart, no reload.

  In `doctor/system.rs`:
  - `package_binary_same_passes`;
  - `package_binary_drift_warns`: the detail is `the package's /usr/libexec/saiife/saiife differs from /opt/saiife/bin/saiife: run sudo /usr/libexec/saiife/saiife system install --fleet`;
  - `no_package_binary_no_check`: the check id is absent.

  In `crates/cli/tests/system_install.rs`:
  - `fleet_install_under_root_flag`: writes `<root>/etc/saiife/fleet/{config.toml,install.toml}` and runs `system install --fleet --root <r>` → `<r>/etc/saiife/config.toml` equals the fleet bytes, and only the managed files of the listed agents exist;
  - `fleet_conflicts_with_config`: clap usage error, exit 2.
- [ ] **Step 2:** run `cargo test -p saiife-system fleet config_change package_binary` and `cargo test -p saiife --test system_install fleet`; expect FAIL (does not compile).
- [ ] **Step 3: implement.**
  - `fleet_options`: walk `FLEET_DIR`, then each file, with one `O_NOFOLLOW` open, as `read_previous` does. Check owner and mode with `check_trusted_owner_mode`.
  - `Run::config` returns whether it wrote. `install` keeps the flag, and `Run::start(changed, config_changed)` issues `reload` when `config_changed && active && !changed`.
  - Doctor check `files.package` ("package binary"): only when `PACKAGE_BINARY` exists and `installed.toml` is present. It compares SHA-256s with `fsops::sha256_file`: Pass when they are equal, Warn with the text above when they differ.
  - In `system_cmd.rs`, `--fleet` builds the options through `fleet_options(&layout, host)` and reports a refusal with `report_error("install", e)`.
- [ ] **Step 4:** the tests pass. `cargo clippy --workspace --all-targets -- -D warnings` is clean. `cargo tree -e normal -p saiife-system | grep -c tokio` prints 0.
- [ ] **Step 5:** commit `feat(system): system install --fleet, reload on config change, doctor files.package`.

### Task 2: Linux packages: nfpm config, maintainer scripts, layout guard

**Files:**
- Create:
  - `packaging/linux/nfpm.yaml`;
  - `packaging/linux/scripts/postinst` and `packaging/linux/scripts/prerm` (POSIX sh, 0755);
  - `packaging/linux/build.sh`;
  - `packaging/linux/nfpm.version`;
  - `packaging/linux/lintian-overrides`;
  - `crates/system/tests/packaging.rs`.
- Modify `.github/workflows/ci.yml` (shellcheck job: add `packaging/linux/build.sh`, plus `shellcheck -s sh packaging/linux/scripts/*`).

**Interfaces:**
- Consumes: `PACKAGE_BINARY` and the §5.2 path constants from Task 1's `layout.rs`. The flag `--fleet` by name.
- Produces:
  - `bash packaging/linux/build.sh <static saiife binary> <version> <amd64|arm64> <out dir>` writes `saiife_<version>_<amd64|arm64>.deb` and `saiife-<version>-1.<x86_64|aarch64>.rpm`, and prints their paths. It needs `nfpm` on `PATH`.
  - The rpm is signed when `SAIIFE_PKG_GPG_KEY_FILE` is set, with `NFPM_RPM_PASSPHRASE` from the caller. The script exports `NFPM_RPM_KEY_FILE` only then.
  - Package name `saiife`; `Recommends: polkitd | policykit-1` (deb) and `polkit` (rpm); no `Depends` (static binary).
  - Contents:
    - `/usr/libexec/saiife/saiife` (0755 root:root);
    - the symlink `/usr/bin/saiife` → `/usr/libexec/saiife/saiife`;
    - `/usr/share/doc/saiife/README.md`;
    - the license: `/usr/share/doc/saiife/copyright` (deb) or `/usr/share/licenses/saiife/LICENSE` (rpm).
  - `nfpm.yaml` sets the metadata: `license: FSL-1.1-ALv2`, `homepage: https://github.com/HrRobinson/saiife`, and `maintainer: HrRobinson <126027636+HrRobinson@users.noreply.github.com>` (the owner may change it). `version` comes from `${SAIIFE_VERSION}`, `arch` from `${SAIIFE_ARCH}`, `scripts.postinstall` and `scripts.preremove`.

- [ ] **Step 1: failing tests** in `crates/system/tests/packaging.rs`. Read the repo files as text, with no YAML dependency: collect the `dst:` values of `nfpm.yaml` by line.
  - `package_owns_no_installed_path`: no `dst` equals, or is below, `OPT_DIR`, `ETC_DIR`, `UNIT`, `STATE_DIR`, `LOG_DIR`, `RUN_DIR`, `POLKIT_DIR`, `CLAUDE_MANAGED_DIR`, `CODEX_DIR`, `GEMINI_DIR` or `/usr/local`.
  - `package_ships_the_staging_binary`: a `dst` equals `PACKAGE_BINARY`.
  - `postinst_runs_fleet_install`: the script contains `"{PACKAGE_BINARY} system install --fleet"` and maps exit 1 to 0.
  - `prerm_uninstalls_on_remove_only`: the script contains `"{PACKAGE_BINARY} system uninstall"` once, inside the `remove|0)` branch, and it has the exact warning line from decision 6.
  - `scripts_are_posix_sh`: line 1 is `#!/bin/sh`, with no `[[`, `local` or `$'`.
- [ ] **Step 2:** run `cargo test -p saiife-system --test packaging`; expect FAIL (no files).
- [ ] **Step 3: write the files.**
  - `postinst`:
    - `set -e`;
    - a `case "$1"` on the args from decision 3, and any other arg exits 0;
    - `rc=0; /usr/libexec/saiife/saiife system install --fleet || rc=$?`;
    - exit 0 when `rc` is 1, else `exit "$rc"`.
  - `prerm`:
    - `case "$1" in remove|0)`: print the warning, call `logger … || true`, then run uninstall and let its exit code fail the script;
    - every other arg exits 0.
  - `build.sh`:
    - `set -euo pipefail`;
    - checks that the binary is static (`file -b` says `statically linked` or `static-pie linked`, as release.yml does);
    - stages it in `mktemp -d`, then runs `nfpm package --config packaging/linux/nfpm.yaml --packager deb|rpm --target <out>`.
  - `lintian-overrides`: only `statically-linked-binary` and `no-manual-page`, each with a one-line reason comment.
- [ ] **Step 4:**
  - The tests pass.
  - `bash -n packaging/linux/build.sh` and `sh -n packaging/linux/scripts/*` are clean.
  - If `nfpm` is installed locally (no root needed), `cargo build --release --target x86_64-unknown-linux-musl -p saiife` and `build.sh … amd64 "$TMPDIR/pkg"` print two paths. Otherwise Task 3's CI is the check.
- [ ] **Step 5:** commit `feat(packaging): deb and rpm via nfpm; postinst runs system install --fleet`.

### Task 3: CI job `package-linux`: install, upgrade, remove

**Files:**
- Create:
  - `scripts/package-linux/run.sh` (the dispatcher and guard);
  - `scripts/package-linux/deb.sh` (phases on the runner, sudo inside);
  - `scripts/package-linux/rpm-container.sh` (runs inside the container as root);
  - `scripts/package-linux/fleet-config.toml` (minimal: `locked = true`, `[approval] approvers = ["group:saiife-approvers"]`; it must pass `saiife policy check`).
- Modify `.github/workflows/ci.yml` (the job, plus shellcheck paths `scripts/package-linux/*.sh`).

**Interfaces:**
- Consumes: Task 2's `build.sh` and package names; Task 1's fleet paths; `scripts/locked-linux/lib.sh` helpers (`phase`, `ok`, `fail`, `on_exit`), sourced.
- Produces:
  - `SAIIFE_PACKAGE_CI=1 bash scripts/package-linux/run.sh <deb|rpm> <dist dir> [<old pkg> <new pkg>]`. It refuses unless `GITHUB_ACTIONS=true`, `SAIIFE_PACKAGE_CI=1` and the user is not root, with the same refusal style as locked-linux.
  - `PHASES` (env, default all) selects phases. Task 4 reuses this with `PHASES="fresh remove"`.
  - The rpm signature check runs when `SAIIFE_PKG_PUBKEY` names a file.
- Job `package-linux`, `timeout-minutes: 30`, matrix `include`:
  - `{os: ubuntu-22.04, kind: deb}`;
  - `{os: ubuntu-24.04, kind: deb}`;
  - `{os: ubuntu-24.04, kind: rpm}`.

  Steps:
  1. checkout, the toolchain with the musl target, musl-tools, rust-cache;
  2. `cargo build --release --locked --target x86_64-unknown-linux-musl -p saiife` (the strict release build; no `--allow-test-build` anywhere in this job);
  3. download nfpm and check the SHA-256 from `nfpm.version`;
  4. make the old package with version `<cargo version>` and the new one with `<cargo version>+ci1`. The new package's binary is `objcopy --add-section .saiife_ci=<file containing "upgrade">` of the same build, so its bytes differ and stay static;
  5. `run.sh`;
  6. on failure, upload logs as `package-linux-logs-<os>-<kind>`.

  The rpm row runs `docker run --rm -v <dist>:/dist:ro -v <repo>/scripts/package-linux:/t:ro rockylinux/rockylinux:9@sha256:<digest> sh /t/rpm-container.sh`, with the digest pinned at build time.

- [ ] **Step 1:** write the phases. Each one is `phase "<name>"` with `ok` or `fail` lines.
  - **deb.sh** (on the Ubuntu runner, sudo inside):
    1. `refusal`: install the fleet dir with mode 0777 and the two fleet files, then `apt-get install ./old.deb` → it fails, and its output names `/etc/saiife/fleet`. `dpkg -s saiife` says half-configured. Run `chmod 0755` and `dpkg --configure -a` → it succeeds.
    2. `fresh`: it writes the fleet files (with `install.toml` saying `agents = ["claude", "codex"]`) and installs `old.deb`, unless `refusal` already did. Check that `/etc/saiife/config.toml` is byte-equal to the fleet file, and that the Claude and Codex managed files exist and the Gemini one does not. `saiifed` is active. The SHA-256 of `/opt/saiife/bin/saiife` equals the one of `/usr/libexec/saiife/saiife` and the one in `installed.toml`. `saiife doctor` exits ≤ 1. `saiife audit verify` passes.
    3. `config-change`: add a commented line and change one value in the fleet config, then run `sudo /usr/libexec/saiife/saiife system install --fleet` → the MainPID is unchanged, and the journal shows the reload. `saiife policy show` prints the new hash.
    4. `upgrade`: record the MainPID and the managed-file SHA-256s, then `apt-get install ./new.deb` → the MainPID changed and the `/opt` binary equals the new one. The managed SHA-256s are unchanged, and `audit verify` passes with a `stop` then a `start` record.
    5. `remove`: `apt-get remove -y saiife` → stderr has the exact decision-6 line, and `journalctl -t saiife` has it too. The unit, the `/opt` binary and the managed files are gone. `/var/log/saiife/audit`, `/etc/saiife/config.toml` and `/etc/saiife/fleet/` are kept. The last audit record is `stop`.
    6. `purge`: reinstall `old.deb` (the users are reused), run `sudo /opt/saiife/bin/saiife system uninstall --purge`, then `apt-get purge -y saiife` → the output has `nothing to uninstall`, and no path from §5.2 is left except the fleet files.
    7. `lintian`: `lintian --fail-on error --suppress-tags-from-file packaging/linux/lintian-overrides new.deb`.
  - **rpm-container.sh** (refuses unless `/.dockerenv` exists and `SAIIFE_PACKAGE_CI=1`):
    1. `dnf install -y /dist/old.rpm` → the output has `locked mode is not supported here`, and `rpm -q saiife` succeeds. `/usr/libexec/saiife/saiife --version` prints the version, and `/usr/bin/saiife` is the symlink. `rpm -qlv` shows 0755 root. `/opt/saiife` and the unit do not exist.
    2. `rpm -Uvh /dist/new.rpm` → the same refusal, and the staging SHA-256 equals the new binary's.
    3. `dnf remove -y saiife` → the output has `nothing to uninstall`, and the payload is gone.
    4. If `SAIIFE_PKG_PUBKEY` is set: `rpm --import` it, then `rpm -K` → `digests signatures OK`.
- [ ] **Step 2:** `bash -n` all three scripts and `shellcheck` them if installed. Do not run them locally: they refuse anyway.
- [ ] **Step 3:** add the job, then push the branch and watch the job (CI is the test). Fix until all three rows are green.
- [ ] **Step 4:** commit `ci(package-linux): install, upgrade and remove the deb on Ubuntu, the rpm on Rocky 9`.

### Task 4: release: packages, signing, checksums, draft test

**Files:** Modify `.github/workflows/release.yml`.

**Interfaces:**
- Consumes: Task 2's `build.sh`; Task 3's `run.sh` with `PHASES`; the `build` job's artifacts `dist-<target>`.
- Produces:
  - Release assets: `saiife_<v>_amd64.deb`, `saiife_<v>_arm64.deb`, `saiife-<v>-1.x86_64.rpm`, `saiife-<v>-1.aarch64.rpm`, `SHA256SUMS` over all eight files, and `SHA256SUMS.asc` when signed.
  - Secrets used: `PKG_GPG_PRIVATE_KEY` and `PKG_GPG_PASSPHRASE` only.

- [ ] **Step 1: job `linux-packages`.**
  - `needs: [check-version, build]`, `runs-on: ubuntu-latest`, matrix `{arch: amd64, target: x86_64-unknown-linux-musl}` and `{arch: arm64, target: aarch64-unknown-linux-musl}`.
  - It downloads `dist-<target>`, extracts the binary from the tarball (the packaged bytes are the tarball's bytes), installs the pinned nfpm and runs `build.sh`.
  - When `PKG_GPG_PRIVATE_KEY` is non-empty, it writes the key to a 0600 file in `$RUNNER_TEMP`, exports `SAIIFE_PKG_GPG_KEY_FILE` and `NFPM_RPM_PASSPHRASE`, and removes the file in an `always()` step. Otherwise it prints the decision-9 notice.
  - It uploads `pkg-<arch>`.
- [ ] **Step 2: `publish`.**
  - `needs` adds `linux-packages`, and it downloads `pkg-*` too.
  - The count check becomes 4 tarballs, 2 `.deb` and 2 `.rpm`. `sha256sum` covers all eight.
  - When the key is set, it imports the key into a throwaway `GNUPGHOME` and runs `gpg --batch --pinentry-mode loopback --passphrase-fd 0 --detach-sign --armor SHA256SUMS`.
  - `gh release create` gets the new files.
- [ ] **Step 3: job `package-test`.**
  - `needs: [check-version, publish]`, tag pushes only, matrix `kind: [deb, rpm]` on `ubuntu-24.04`.
  - It downloads the draft, then runs `SAIIFE_PACKAGE_CI=1 PHASES="fresh remove" bash scripts/package-linux/run.sh <kind> rel`.
  - The rpm row sets `SAIIFE_PKG_PUBKEY=deploy/keys/saiife-packages.asc` when that file exists and the release is signed.
  - `release` now needs `[install-test, package-test]`.
- [ ] **Step 4:** add `packaging/**` and `scripts/package-linux/**` to the PR `paths` trigger. The PR dry-run then runs `build` and `linux-packages` (unsigned). Check that the PR run is green.
- [ ] **Step 5:** commit `ci(release): ship deb and rpm, sign rpm and SHA256SUMS when the key is set`.

### Task 5: deploy recipes for Linux: Ansible role, Intune Linux compliance

**Files:**
- Create:
  - `deploy/ansible/playbook.yml` (`hosts: saiife_fleet`, `become: true`, `roles: [saiife]`; never `localhost`);
  - `deploy/ansible/roles/saiife/{defaults/main.yml, tasks/main.yml, meta/main.yml, templates/install.toml.j2}`;
  - `deploy/ansible/.ansible-lint` (profile `production`);
  - `deploy/intune/linux/discovery.sh` and `deploy/intune/linux/rules.json`.
- Modify:
  - `.github/workflows/ci.yml` (job `ansible-lint`; shellcheck path `deploy/intune/linux/discovery.sh`);
  - `crates/system/tests/packaging.rs` (one test).

**Interfaces:**
- Consumes: Task 1's fleet paths and `install.toml` keys; Task 2's package names; `doctor --json` exit codes.
- Produces role variables (`defaults/main.yml`):
  - `saiife_version`;
  - `saiife_package_base_url: "https://github.com/HrRobinson/saiife/releases/download/v{{ saiife_version }}"`;
  - `saiife_package_sha256: {}` (a dict from package file name to SHA-256; required);
  - `saiife_config_src` (a path on the controller; required);
  - `saiife_agents: [claude, codex, gemini]` and `saiife_approvers: []`;
  - `saiife_policy_d_src: ""` (an optional dir of drop-ins);
  - `saiife_rpm_gpg_check: true`;
  - `saiife_doctor_fail_on: 2`.

  Intune settings: `saiife_installed` (Boolean) and `saiife_doctor_exit` (Int64).

- [ ] **Step 1: failing test** in `packaging.rs`: `intune_rules_match_discovery`. Parse `rules.json` with `serde_json` (already a dev-dependency). Every `SettingName` must occur in `discovery.sh`. The rules must be `saiife_installed IsEquals true` and `saiife_doctor_exit LessEquals 1`.
- [ ] **Step 2:** run it; expect FAIL.
- [ ] **Step 3: role tasks, in order:**
  1. Assert that the distribution is supported (Ubuntu ≥ 22.04, Debian ≥ 12, `ansible_os_family == "RedHat"` ≥ 9) with `ansible_service_mgr == "systemd"`, and that the required variables are set.
  2. `/etc/saiife` and `/etc/saiife/fleet`: 0755 root:root.
  3. Copy `config.toml` and template `install.toml` (0644 root:root), then register the result.
  4. Optional `policy.d` drop-ins (0644), registered.
  5. `get_url` the package for `ansible_architecture` into `/var/cache/saiife/` with `checksum: sha256:…`.
  6. `apt: deb=` or `dnf: name=<file> disable_gpg_check: "{{ not saiife_rpm_gpg_check }}"`, registered.
  7. When the fleet files changed and the package task did not (its `postinst` already ran install): run `command: /usr/libexec/saiife/saiife system install --fleet` with `changed_when: "'nothing changed' not in result.stdout"` and `failed_when: result.rc == 2`.
  8. When only drop-ins changed: `command: /opt/saiife/bin/saiife policy reload`.
  9. `command: /opt/saiife/bin/saiife doctor --json` with `changed_when: false`, `failed_when: rc >= saiife_doctor_fail_on`. Show the failing check ids with `debug`.

  `discovery.sh` (POSIX sh, run as root by Intune):
  - if `/opt/saiife/bin/saiife` is executable, run `doctor --json >/dev/null 2>&1` and keep its exit code, with `saiife_installed` true;
  - otherwise `saiife_installed` is false and the exit code is 2;
  - print one JSON line with the two settings. Do not depend on jq.

  `rules.json` uses the Intune custom-compliance schema, with `en_US` remediation strings that point to `docs/fleet.md`.
- [ ] **Step 4:**
  - The test passes, and `sh -n deploy/intune/linux/discovery.sh` is clean.
  - CI job `ansible-lint`: `pipx run --spec ansible-lint==<pinned> ansible-lint deploy/ansible`, with the version pinned at build time. It is green.
  - Locally, run `ansible-lint` only if it is installed. Never run `ansible` or `ansible-playbook` (except `--syntax-check`, through ansible-lint).
- [ ] **Step 5:** commit `feat(deploy): Ansible role and Intune Linux compliance script`.

### Task 6: docs and spec notes

**Files:**
- Create `docs/fleet.md`.
- Modify `docs/install.md` (a new `### Packages (.deb, .rpm)` under "Locked mode (Linux)"), `README.md` (one line and a link), `CHANGELOG.md` (one bullet in the top unreleased section) and the spec (the three notes).

**Interfaces:** Consumes the copy and paths from Tasks 1–5. Produces the doc anchors `docs/fleet.md#fleet-files`, `#upgrades`, `#removal`, `#verify-packages`, `#ansible` and `#intune-linux`, and a `## macOS (v2.1)` placeholder that says "after plan 13", which Task 7 fills.

- [ ] **Step 1:** write `docs/fleet.md` in plain short sentences. It covers:
  - what the package owns and what `system install` owns (decision 1);
  - the two fleet files with full examples, and that the fleet config wins over local edits;
  - the exit codes and the deb and rpm failure behaviour (decision 3);
  - upgrades (decision 4);
  - removal and the warning (decision 6), and the full wipe (decision 7);
  - verifying packages: `sha256sum -c SHA256SUMS`, `gpg --verify SHA256SUMS.asc`, `rpm --import` and `rpm -K`;
  - the Ansible example inventory and run (`ansible-playbook -i inventory deploy/ansible/playbook.yml`), on the admin's controller;
  - Intune Linux: upload `discovery.sh` and `rules.json` as a custom compliance policy. Intune cannot push Linux packages, so pair it with Ansible or another tool;
  - limits: containers and image builds (decisions 10 and 11), no apt or yum repo yet, and secrets are per machine (`saiife secret add` as root).

  The `docs_wording.rs` test covers the new file automatically.
- [ ] **Step 2:** add the spec notes:
  - §7: append to the `system install` behavior: "`--fleet` reads `/etc/saiife/fleet/config.toml` and `install.toml` (plan 18)";
  - §12 step 5: "Packages (`.deb`, `.rpm`; macOS `.pkg` after plan 13) run `system install --fleet`; see docs/fleet.md";
  - §15.2 row 18: append "Built (plan 18): Linux packages, Ansible, Intune Linux; `.pkg`, Jamf and Intune macOS after plan 13".
- [ ] **Step 3:** run `cargo test -p saiife --test docs_wording`; it passes. Check that every link in `docs/fleet.md` resolves to a file in the repo.
- [ ] **Step 4:** commit `docs: fleet packaging, recipes and spec notes`.

### Task 7: macOS `.pkg`, Jamf and Intune macOS — **after plan 13 merges**

**Start this task only after plan 13 (macOS locked mode) is on `main`, on a new branch `plan-18b-macos-pkg`.** Before Step 1, the controller replaces every `<P13:…>` placeholder below with plan 13's real names, and checks the assumptions in Consumes. Where plan 13 differs, plan 13 wins and this task is adjusted.

**Files:**
- Create:
  - `packaging/macos/build-pkg.sh`;
  - `packaging/macos/scripts/postinstall` (POSIX sh);
  - `packaging/macos/distribution.xml`;
  - `deploy/jamf/{fleet-files.sh, extension-attribute.sh, uninstall.sh}`;
  - `deploy/intune/macos/{fleet-files.sh, custom-attribute.sh}`.
- Modify:
  - `crates/system/src/layout.rs` (the macOS `PACKAGE_BINARY` = `/usr/local/libexec/saiife/saiife` under `cfg(target_os = "macos")`; SIP protects `/usr` except `/usr/local`);
  - `crates/system/tests/packaging.rs`;
  - `.github/workflows/release.yml` and `ci.yml`;
  - `docs/fleet.md` (fill `## macOS (v2.1)`).

**Interfaces:**
- Consumes (assumed from plan 13; verify):
  - `saiife system install` and `uninstall` work on macOS with the §5.3 layout (`_saiife`, `/Library/LaunchDaemons/com.saiife.saiifed.plist`, `/var/db/saiife`);
  - `check_supported` passes on supported macOS;
  - Task 1's `fleet_options` works there unchanged;
  - release CI signs each darwin binary with Developer ID Application and the hardened runtime, and notarizes it, through a reusable step or script `<P13:SIGN_STEP>`;
  - secrets: `<P13:MACOS_CERT_P12>`, `<P13:MACOS_CERT_PASSWORD>`, `<P13:APPLE_TEAM_ID>`, `<P13:NOTARY_KEY_P8>`, `<P13:NOTARY_KEY_ID>`, `<P13:NOTARY_ISSUER_ID>`;
  - a macOS locked CI job `<P13:CI_JOB>` whose setup this task mirrors.
- New secrets in this task: `MACOS_INSTALLER_CERT_P12` and `MACOS_INSTALLER_CERT_PASSWORD` (Developer ID **Installer**, which differs from the Application cert). If plan 13's p12 already holds both identities, use plan 13's secrets instead.
- Produces:
  - `saiife-<v>.pkg`: one universal binary (`lipo -create` of the two signed darwin builds, signed again after lipo with plan 13's identity and options), identifier `com.saiife.pkg`;
  - the payload `/usr/local/libexec/saiife/saiife` and the symlink `/usr/local/bin/saiife` (allowed on macOS);
  - `postinstall` does what Linux `postinst` does, for target volume `/` only (`$3`). For any other volume it exits 0 with `saiife: not the boot volume; run system install --fleet after boot`.

- [ ] **Step 1: failing tests** in `packaging.rs`, under `#[cfg(target_os = "macos")]`, with the Linux tests kept:
  - `pkg_postinstall_runs_fleet_install`;
  - `pkg_payload_owns_no_installed_path` (the paths in `build-pkg.sh`'s payload list against §5.3).
- [ ] **Step 2: `build-pkg.sh <universal binary> <version> <out>`.**
  1. Build the payload root.
  2. `pkgbuild --root … --scripts packaging/macos/scripts --identifier com.saiife.pkg --version <v> --install-location /`.
  3. `productbuild --distribution distribution.xml`, with `--sign "<identity>"` when the installer identity is in the keychain.
  4. Then `xcrun notarytool submit --wait` (key from `<P13:NOTARY_*>`), `xcrun stapler staple`, `pkgutil --check-signature` and `spctl -a -vv -t install`.

  Without the secrets, it builds an unsigned pkg and prints `::notice::pkg unsigned`. The release then leaves the pkg out, and never publishes an unsigned pkg.
- [ ] **Step 3:** release job `macos-pkg` (needs `build` and plan 13's signing) adds `saiife-<v>.pkg` to the assets and to `SHA256SUMS`. The CI job `macos-pkg` on `macos-latest` (CI only) does three things:
  - `sudo installer -pkg … -target /` with the fleet files written first, then checks that `launchctl print system/com.saiife.saiifed` is running and `doctor` exits ≤ 1;
  - `sudo sh deploy/jamf/uninstall.sh` → the warning line is printed and the plist and managed files are gone, and `pkgutil --pkgs` no longer lists `com.saiife.pkg`;
  - a reinstall works.
- [ ] **Step 4: Jamf recipe.**
  - `fleet-files.sh`: Jamf parameter 4 is the base64 of `config.toml`, and parameter 5 is a comma list of agents. It writes `/etc/saiife/fleet/` with 0755/0644 root:wheel and runs with priority "Before" in the same policy as the pkg.
  - `extension-attribute.sh`: prints `<result>pass|warn|fail|not installed</result>` from the `doctor --json` exit code.
  - `uninstall.sh`: prints and logs the decision-6 line, runs `/opt/saiife/bin/saiife system uninstall`, removes `/usr/local/libexec/saiife` and the symlink, then runs `pkgutil --forget com.saiife.pkg`.
  - Note for the controller: if plan 13 needs Full Disk Access for `doctor`'s secret scan, add a PPPC profile `deploy/jamf/saiife-pppc.mobileconfig` for `/opt/saiife/bin/saiife` (code requirement from its signature).
- [ ] **Step 5: Intune macOS recipe.**
  - `fleet-files.sh`: the same as Jamf, but with the values as variables at the top, because Intune scripts take no parameters.
  - `custom-attribute.sh`: prints the doctor exit code.
  - `docs/fleet.md` explains the PKG app upload, which needs the signed pkg.
- [ ] **Step 6:** `sh -n` all the new scripts; `shellcheck` runs in CI. Commit `feat(packaging): signed, notarized macOS pkg; Jamf and Intune macOS recipes`.

---

## Finish

- [ ] **Gates:**
  - `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; the tokio gate;
  - `cargo test --workspace` and `scripts/test-offline.sh`, with `TMPDIR` and `SAIIFE_TEST_TMP` set;
  - the macOS-target check (`RUSTFLAGS="-D warnings" cargo check --workspace --all-targets --target x86_64-apple-darwin` with a fake `cc`; `fleet.rs` builds on both);
  - `bash -n` and `sh -n` on every new script.
- [ ] CI green: `package-linux` (3 rows), `ansible-lint`, `shellcheck`, and the release dry-run on the PR.
- [ ] Whole-branch review (Opus), one fix wave, scoped re-review, push, PR. The owner merges. No tag.

## Follow-ups (not in this plan)

- Signed apt and yum repositories (a `Release`/`InRelease` file and `repomd.xml`) with the same key, so `unattended-upgrades` and `dnf-automatic` pick up new versions.
- An upgrade test from the previous released package, once one exists.
- A first-boot unit for golden images (decision 11).
- A KVM-based Rocky 9 VM job that runs the full locked flow from the rpm.
- Fleet secrets: a documented `secret add` flow for Ansible (`no_log`) and for MDMs.

## Owner handwork

- [ ] Confirm these spec departures and decisions:
  - the new `--fleet` flag and the `/etc/saiife/fleet/` paths (decision 2);
  - a failing install fails the package (decision 3);
  - removal uninstalls without a block (decision 6);
  - purge keeps the audit (decision 7);
  - `/usr/bin/saiife` instead of `/usr/local/bin/saiife` in packages.
- [x] The nfpm `maintainer` is the owner's noreply address (the owner may change it).
- [ ] Create the package signing key: an offline primary key with a signing subkey. Add the armored subkey as `PKG_GPG_PRIVATE_KEY` and its passphrase as `PKG_GPG_PASSPHRASE` in the repo secrets. Commit the public key as `deploy/keys/saiife-packages.asc`, and publish its fingerprint in `docs/fleet.md` and on the website.
- [ ] On a RHEL 9 (or Rocky 9) VM: `dnf install` the signed rpm with fleet files, then `doctor`, an upgrade and `dnf remove`. Record the result in the PR (decision 10).
- [ ] Run the Ansible role from your controller against one Ubuntu and one RHEL test VM, never your workstation.
- [ ] Intune Linux: upload `discovery.sh` and `rules.json` to a test tenant with one enrolled Ubuntu device. Check that a stopped daemon shows non-compliant.
- [ ] After plan 13 and Task 7:
  - apply for and add the Developer ID Installer certificate;
  - run the Jamf policy (fleet files, then the pkg, then the extension attribute) on a test Mac in a Jamf tenant;
  - run the Intune macOS PKG app and custom attribute on a test Mac;
  - check Gatekeeper with `spctl` on a clean Mac.
