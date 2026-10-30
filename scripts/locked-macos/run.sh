#!/usr/bin/env bash
# Locked mode on a real Mac (plan 13 Task 12, spec §5.3 and §13 "Daemon
# integration"): `system install` as root, the §5.3 owners and modes,
# managed hooks as an unprivileged agent user, the fail-closed matrix
# (§9.3), attacks on the installed files including DYLD_INSERT_LIBRARIES
# (A4), `doctor`, approvals from a second account, lockdown, reinstall,
# uninstall and purge. The phases mirror scripts/locked-linux/lib.sh.
#
# CI ONLY. This creates local accounts with dscl, writes /etc, /opt,
# /Library and /var, registers an authorization right, and loads, kills
# and boots out a launchd daemon. It runs in the GitHub Actions job
# `locked-macos` (ci.yml) on throwaway macos-15 (Apple silicon) and
# macos-15-intel runners, as the runner user, and uses `sudo` itself for
# every privileged step. Anywhere else it refuses before doing anything.
#
#   SAIIFE_LOCKED_CI=1 bash scripts/locked-macos/run.sh <saiife binary>
#
# The binary must be the ci-locked build (debug assertions on, for the
# SAIIFE_EVAL_FAULT seam), signed ad hoc with the hardened runtime
# (`codesign --force --options runtime --sign -`). It is installed with
# --allow-test-build. On a failure daemon.log, the audit log, /etc/saiife,
# the plist and `launchctl print` are copied to $SAIIFE_LOCKED_LOGS
# (default target/locked-macos-logs) for the job to upload.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${SAIIFE_LOCKED_CI:-}" != "1" ||
    "$(uname -s)" != "Darwin" || "$(id -u)" == "0" ]]; then
    echo "refusing: locked-macos tests run only in GitHub Actions CI on macOS (GITHUB_ACTIONS=true, SAIIFE_LOCKED_CI=1, Darwin, as a non-root user with sudo; the script calls sudo itself)" >&2
    exit 2
fi
if [[ $# -ne 1 || ! -x "$1" || "$1" != /* ]]; then
    echo "usage: SAIIFE_LOCKED_CI=1 bash scripts/locked-macos/run.sh <absolute path to the signed ci-locked saiife binary>" >&2
    exit 2
fi

BIN="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LOGS="${SAIIFE_LOCKED_LOGS:-$REPO/target/locked-macos-logs}"
export BIN HERE REPO LOGS

# shellcheck source=scripts/locked-macos/lib.sh
source "$HERE/lib.sh"

mkdir -p "$LOGS"
# Below /private/tmp, not the runner's 0700 $TMPDIR: the agent user loads
# the A4 library from here. The dir itself stays the runner's.
WORK="$(mktemp -d /private/tmp/saiife-locked-macos.XXXXXX)"
chmod 0755 "$WORK"
export WORK
trap 'on_exit $?' EXIT

prepare_host
phase_install
phase_modes
phase_hooks
phase_fail_closed
phase_attacks
phase_doctor
phase_approvals
phase_lockdown
phase_reinstall_uninstall
# A deferred failure (A4) still fails the job, after every phase ran.
deferred_failures

echo "== locked-macos: all phases passed (macOS $(sw_vers -productVersion), $(uname -m))"
