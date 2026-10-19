# Plan 5c — Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship saiife v0.1.0: prebuilt binaries for 4 targets with SHA-256
checksums on GitHub Releases, a checksum-verifying `install.sh`, and CI
hygiene left over from plan 5b.

**Architecture:** A new `.github/workflows/release.yml` builds on a `v*` tag
(and on `workflow_dispatch` as a dry run that uploads workflow artifacts
only), packages each target as a tarball, writes `SHA256SUMS`, publishes the
release with `install.sh` attached, then installs from the published release
on three native runners. `install.sh` is POSIX `sh` and is tested in CI
against a local fake release directory, so the test needs no network.

**Tech Stack:** GitHub Actions, Rust (`rustup target add`, musl-tools),
POSIX sh, curl, `sha256sum`/`shasum`.

**Spec:** `docs/superpowers/specs/2026-10-13-saiife-cli-v1-design.md` §8, §12.1.

## Global Constraints

- Targets (spec §8, verbatim): `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`.
- Install location (spec §8): `~/.local/bin`, or `/usr/local/bin` with sudo.
- No network calls at runtime in the binary (spec §8). `install.sh` is the only network user; its tests run offline.
- The tag `v0.1.0` is pushed by the controller only after the user says yes. No task pushes tags or creates releases.
- CI job names `test (ubuntu-latest)`, `test (macos-latest)`, `offline` are required checks: never rename them.
- Actions are pinned to a major version already used in `ci.yml` where possible (`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`); new actions pinned to a full major (`actions/upload-artifact@v4`, `actions/download-artifact@v4`).
- Stage explicit paths; never `git checkout` an old commit in the shared tree; scratch under `mktemp -d -p /home/jonas/projects/personal/saiife`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Shared interface (Tasks 1 and 2 both rely on this)

- Asset per target: `saiife-<version>-<target>.tar.gz` where `<version>` has no leading `v` (e.g. `saiife-0.1.0-aarch64-apple-darwin.tar.gz`). It contains one directory `saiife-<version>-<target>/` holding `saiife`, `LICENSE`, `README.md`.
- `SHA256SUMS`: one line per tarball, `<64 lowercase hex>  <filename>` (two spaces, `sha256sum` format), sorted by filename.
- `install.sh` is attached to the release as an asset.
- Download base: `https://github.com/HrRobinson/saiife/releases/download/v<version>/` for a pinned version, `https://github.com/HrRobinson/saiife/releases/latest/download/` for latest. `install.sh` reads `SAIIFE_DOWNLOAD_BASE` to override the base (used by tests with a `file://` URL).

## Review Focus

1. `install.sh` with a checksum mismatch or a missing `SHA256SUMS` line — must abort before anything is written to the install dir (Task 2 test).
2. `install.sh` on an unsupported OS/arch (e.g. FreeBSD, armv7) — clear message, exit 1, nothing downloaded (Task 2 test).
3. A tag whose version differs from `Cargo.toml` (`v0.1.1` with `version = "0.1.0"`) — release workflow fails before building (Task 1 step).
4. `install.sh | sh` when `~/.local/bin` is not on PATH — install succeeds and prints the exact line to add (Task 2 test).
5. The x86_64 macOS binary built on an arm64 runner — must really be x86_64 (`lipo -archs` / `file` check in Task 1).

---

### Task 1: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`
- Modify: `Cargo.toml` (`[profile.release]`: keep existing settings; add `strip = true` if not present)

**Interfaces:** Produces the assets in "Shared interface".

Workflow shape:
- `on: push: tags: ['v*']` and `workflow_dispatch`.
- `permissions: contents: read` at top; `contents: write` only on the publish job.
- Job `check-version`: on a tag, fail unless `${GITHUB_REF_NAME#v}` equals the workspace `version` in `Cargo.toml` (read with `cargo metadata --no-deps --format-version 1` + `jq`, or grep the `[workspace.package]` table). On `workflow_dispatch`, use the Cargo version.
- Job `build` (needs check-version), matrix:
  - `x86_64-unknown-linux-musl` on `ubuntu-latest` (apt `musl-tools`)
  - `aarch64-unknown-linux-musl` on `ubuntu-24.04-arm` (apt `musl-tools`, native)
  - `x86_64-apple-darwin` on `macos-latest` (`rustup target add`, cross)
  - `aarch64-apple-darwin` on `macos-latest`
  Steps: `cargo build --release --locked --target $T -p saiife`; verify the binary's architecture (`file` on Linux must say the expected arch and "statically linked"; `lipo -archs` on macOS must print exactly `x86_64` or `arm64`); run `saiife --version` where the runner can execute it (all but x86_64-apple-darwin); package per Shared interface; upload as artifact `dist-$T`.
- Job `publish` (needs build; `if: startsWith(github.ref, 'refs/tags/v')`): download all `dist-*`, write `SHA256SUMS` (sorted), `gh release create "$GITHUB_REF_NAME" --title "saiife $GITHUB_REF_NAME" --notes-file <CHANGELOG section for the version> dist/*.tar.gz dist/SHA256SUMS install.sh` with `GH_TOKEN: ${{ github.token }}`.
- Job `install-test` (needs publish), matrix `ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest`: `curl -fsSL https://github.com/HrRobinson/saiife/releases/download/$GITHUB_REF_NAME/install.sh | SAIIFE_VERSION=${GITHUB_REF_NAME#v} sh`, then `~/.local/bin/saiife --version` prints the version.

- [ ] **Step 1:** Write `release.yml` as above.
- [ ] **Step 2:** Validate: `actionlint` if installable via `go`/binary download is not allowed offline — instead run `python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' .github/workflows/release.yml` if PyYAML exists, else parse with `ruby -ryaml`; report which. Build locally for `x86_64-unknown-linux-musl` if the target and musl-gcc are installed; otherwise say so.
- [ ] **Step 3: Commit** `ci: release workflow for 4 targets with SHA256SUMS`

### Task 2: install.sh and its offline test

**Files:**
- Create: `install.sh` (repo root)
- Create: `scripts/test-install.sh`
- Modify: `.github/workflows/ci.yml` (add a step `bash scripts/test-install.sh` to the `test` job on both OSes; do not rename jobs)

**Interfaces:** Consumes "Shared interface".

`install.sh` (POSIX sh, `set -eu`, works with `curl … | sh`):
- Options via env: `SAIIFE_VERSION` (default latest), `SAIIFE_INSTALL_DIR` (default `$HOME/.local/bin`), `SAIIFE_DOWNLOAD_BASE` (override). Flag `--system` installs to `/usr/local/bin` using `sudo` only for the final move.
- Detect: `uname -s` Linux/Darwin, `uname -m` x86_64|amd64 → x86_64, arm64|aarch64 → aarch64. Anything else: `saiife: unsupported platform: <os>/<arch>` to stderr, exit 1, before any download.
- Latest without `SAIIFE_VERSION`: download from the `latest/download/` base; the tarball name needs a version, so first fetch `SHA256SUMS` from that base and take the version from the single line whose filename ends in `-<target>.tar.gz`.
- Download into a `mktemp -d` dir (trap removes it); verify with `sha256sum -c` or `shasum -a 256 -c` against the matching `SHA256SUMS` line only; mismatch or no line → `saiife: checksum verification failed` exit 1, nothing installed.
- Extract, `install -m 0755` (or `cp` + `chmod`) into the install dir (create it), print `saiife <version> installed to <dir>/saiife`.
- If the install dir is not in `PATH`, print: `Add it to your PATH: export PATH="<dir>:$PATH"`.
- Needs `curl` or `wget`; neither → clear error, exit 1.

`scripts/test-install.sh` (bash, no network): build `target/release/saiife` (or use `SAIIFE_BIN`), create a fake release dir with a tarball for the host target and `SHA256SUMS` per the Shared interface, then run `install.sh` with `SAIIFE_DOWNLOAD_BASE=file://<dir>/` and a temp `HOME`, asserting:
- `install_pinned_version`: `SAIIFE_VERSION=0.1.0` → installed binary runs `--version`.
- `install_latest`: no `SAIIFE_VERSION` → version taken from `SHA256SUMS`.
- `checksum_mismatch_installs_nothing`: corrupt the tarball → exit 1, message, install dir has no `saiife`.
- `missing_sums_line_installs_nothing`: `SHA256SUMS` without the host line → exit 1.
- `unsupported_platform`: run with a `uname` stub on PATH printing `FreeBSD` → exit 1 with `unsupported platform`, no download attempted (fake base dir has a marker the test checks was not read — or simply assert the message and exit code).
- `path_hint`: install dir not in PATH → output contains `export PATH=`.
Scratch via `mktemp -d` honouring `TMPDIR`.

- [ ] **Step 1:** Write `scripts/test-install.sh`; run it → fails (no install.sh).
- [ ] **Step 2:** Write `install.sh`; run the test → all pass (run with `TMPDIR` under `mktemp -d -p /home/jonas/projects/personal/saiife`). Also run it under `unshare -rn` with `SAIIFE_BIN` prebuilt.
- [ ] **Step 3:** Run `sh -n install.sh` and, if available, `dash install.sh --help`-free syntax check `dash -n install.sh` (POSIX).
- [ ] **Step 4:** Add the CI step; commit `feat: install.sh with checksum verification, tested offline in CI`

### Task 3: CI hygiene and plan-5b test leftovers

**Files:**
- Modify: `.github/workflows/ci.yml` (new job `shellcheck` on ubuntu-latest: `shellcheck install.sh scripts/*.sh`; ubuntu runners ship shellcheck)
- Modify: `scripts/*.sh`, `install.sh` only as needed to pass shellcheck (no behaviour change)
- Modify: `scripts/bench-check.sh` (binary path honours `CARGO_TARGET_DIR`: `"${CARGO_TARGET_DIR:-$repo/target}/release/saiife"`)
- Modify: `crates/cli/tests/broken_pipe.rs` (new case `hook_exit_deny_with_stdout_closed_exits_2`: `check --hook-exit --agent claude` with a deny payload and stdout closed → exit 2)

- [ ] **Step 1:** Add the broken_pipe test; run it → passes (behaviour already correct; it is a pin).
- [ ] **Step 2:** Fix bench-check.sh.
- [ ] **Step 3:** Add the shellcheck job. shellcheck is not installed locally: fix findings by reading the scripts carefully for the common SC codes (quoting, `local` in sh, `[ ]` vs `[[ ]]` in sh); the CI run is the gate (controller checks it on the PR).
- [ ] **Step 4:** Commit `ci: shellcheck job; bench honours CARGO_TARGET_DIR; hook-exit closed-stdout pin`

### Task 4: Install docs, changelog, version

**Files:**
- Create: `docs/install.md`
- Create: `CHANGELOG.md`
- Modify: `README.md` (install section)
- Modify: `docs/superpowers/plans/2026-10-13-saiife-v1-roadmap.md` (plan 5 row status; strike 5c items done here)

Content:
- README install: `curl -fsSL https://github.com/HrRobinson/saiife/releases/latest/download/install.sh | sh`, one line saying it verifies the SHA-256 checksum and installs to `~/.local/bin`; link to `docs/install.md`. Remove "first release pending"; keep build-from-source as an alternative.
- `docs/install.md`: one-liner; pinned version (`SAIIFE_VERSION=0.1.0`); `--system`; manual install (download tarball + `SHA256SUMS`, `sha256sum -c --ignore-missing`, extract); supported platforms (the 4 targets); uninstall (`saiife init --off` in each project, then delete the binary; data under `$SAIIFE_DATA_DIR`/default data dir and the audit log location — check `crates/cli/src/paths.rs` for the real defaults); "saiife makes no network calls; only install.sh downloads".
- `CHANGELOG.md`: `## 0.1.0 — <release date placeholder YYYY-MM-DD>` with a short list: guard packs (13), audit log + masking, `audit --report`, `init`/`status`/tamper detection for Claude Code, Codex, Gemini CLI, docs, demo. Note Codex/Gemini not yet verified live. The release workflow uses this section as release notes (Task 1 extracts the `## <version>` section up to the next `## `).
- docs_links_resolve must pass.

- [ ] **Step 1:** Write the docs; run `cargo test -p saiife-guard --test docs_pages` → pass.
- [ ] **Step 2:** Commit `docs: install guide, changelog for 0.1.0, README install line`

---

## After the plan (controller, user-gated)

1. Open the PR; after CI is green, run the release workflow with `workflow_dispatch` on the PR branch (dry run: builds 4 targets, no publish) and check the artifacts.
2. User merges the PR.
3. **Ask the user:** "Tag v0.1.0 and publish?" Only on yes: set the CHANGELOG date, tag `v0.1.0` on main via PR-merged commit, push the tag, watch `publish` and `install-test`.
4. Run the one-liner on this machine into a sandbox `SAIIFE_INSTALL_DIR` and `HOME` to confirm.
