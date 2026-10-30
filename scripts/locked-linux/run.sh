#!/usr/bin/env bash
# Locked mode on a real machine (spec §13 "Daemon integration", plan 9b
# Task 8): `system install` as root, the §5.2 owners and modes, managed
# hooks as an unprivileged agent user, the fail-closed matrix (§9.3),
# attacks on the installed files, `doctor`, reinstall, uninstall and purge.
#
# CI ONLY. This creates system users, writes /etc, /opt, /var and /run,
# installs and kills a systemd service. It runs in the GitHub Actions job
# `locked-linux` (ci.yml) on throwaway ubuntu-22.04 and ubuntu-24.04
# runners, as the runner user, and uses `sudo` itself for every privileged
# step. Anywhere else it refuses before doing anything.
#
#   SAIIFE_LOCKED_CI=1 bash scripts/locked-linux/run.sh <saiife binary>
#
# The binary must be the static ci-locked build (Cargo.toml: musl, debug
# assertions on): the SAIIFE_EVAL_FAULT test seam exists only with debug
# assertions, and install refuses anything but a static binary. It is
# installed with --allow-test-build. On a failure the journal, the audit log and /etc/saiife are
# copied to $SAIIFE_LOCKED_LOGS (default target/locked-linux-logs) for the
# job to upload.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${SAIIFE_LOCKED_CI:-}" != "1" || "$(id -u)" == "0" ]]; then
    echo "refusing: locked-linux tests run only in GitHub Actions CI (GITHUB_ACTIONS=true, SAIIFE_LOCKED_CI=1, as a non-root user with sudo; the script calls sudo itself)" >&2
    exit 2
fi
if [[ $# -ne 1 || ! -x "$1" || "$1" != /* ]]; then
    echo "usage: SAIIFE_LOCKED_CI=1 bash scripts/locked-linux/run.sh <absolute path to the ci-locked saiife binary>" >&2
    exit 2
fi

BIN="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LOGS="${SAIIFE_LOCKED_LOGS:-$REPO/target/locked-linux-logs}"
export BIN HERE REPO LOGS

# shellcheck source=scripts/locked-linux/lib.sh
source "$HERE/lib.sh"
# shellcheck source=scripts/demo-locked.sh
source "$REPO/scripts/demo-locked.sh"

mkdir -p "$LOGS"
WORK="$(mktemp -d)"
export WORK
trap 'on_exit $?' EXIT

# The MCP gateway's spawn helper (plan 17 Task 5), unprivileged and before
# anything is installed: the runner's kernel must have Landlock (ABI >= 1),
# so the sandbox tests run for real here instead of asserting the
# no-Landlock fallback.
phase_mcp_sandbox() {
    phase "mcp spawn helper and Landlock sandbox"
    local tmp="$WORK/mcp-spawn"
    mkdir -p "$tmp"
    (cd "$REPO" && TMPDIR="$tmp" SAIIFE_TEST_TMP="$tmp" SAIIFE_REQUIRE_LANDLOCK=1 \
        cargo test --locked -p saiife --test mcp_spawn -- --nocapture) \
        || fail "mcp_spawn tests (Landlock ABI >= 1 required on this runner)"
    ok "mcp_spawn tests passed with Landlock"
}

phase_mcp_sandbox
prepare_host
phase_install
phase_modes
phase_hooks
phase_fail_closed
phase_attacks
phase_doctor
phase_approvals
phase_lockdown
phase_demo
phase_reinstall_uninstall

echo "== locked-linux: all phases passed (systemd $(systemd_version))"
