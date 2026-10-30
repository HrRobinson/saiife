#!/usr/bin/env bash
# The saiife .deb and .rpm on real machines (plan 18, Task 3): install and
# its refusal, a fleet config change, an upgrade, remove, purge and lintian
# on the Ubuntu runner; the rpm payload, scriptlet wiring, loud refusal,
# upgrade and removal in a Rocky 9 container.
#
# CI ONLY. The deb phases create system users, write /etc, /opt, /var and
# /run and install a systemd service. They run in the GitHub Actions job
# `package-linux` (ci.yml) on throwaway ubuntu-22.04 and ubuntu-24.04
# runners, as the runner user, and use `sudo` themselves for every
# privileged step. Anywhere else this refuses before doing anything.
#
#   SAIIFE_PACKAGE_CI=1 bash scripts/package-linux/run.sh <deb|rpm> <dist dir> [<old pkg> <new pkg>]
#
# With no package names, the single package of that kind in <dist dir> is
# used as both. PHASES (env, default all) selects phases, space separated:
#   deb: refusal fresh config-change upgrade remove purge lintian
#   rpm: fresh upgrade remove signature
# The rpm signature phase runs when SAIIFE_PKG_PUBKEY names a file.
# On a failure the logs are copied to $SAIIFE_PACKAGE_LOGS (default
# target/package-linux-logs) for the job to upload.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${SAIIFE_PACKAGE_CI:-}" != "1" || "$(id -u)" == "0" ]]; then
    echo "refusing: package-linux tests run only in GitHub Actions CI (GITHUB_ACTIONS=true, SAIIFE_PACKAGE_CI=1, as a non-root user with sudo; the script calls sudo itself)" >&2
    exit 2
fi
usage="usage: SAIIFE_PACKAGE_CI=1 bash scripts/package-linux/run.sh <deb|rpm> <dist dir> [<old pkg> <new pkg>]"
if [[ $# -ne 2 && $# -ne 4 ]]; then
    echo "$usage" >&2
    exit 2
fi
KIND="$1"
case "$KIND" in
    deb | rpm) ;;
    *)
        echo "$usage" >&2
        exit 2
        ;;
esac
[[ -d "$2" ]] || {
    echo "$usage (no such dir: $2)" >&2
    exit 2
}
DIST="$(cd "$2" && pwd)"
if [[ $# -eq 4 ]]; then
    OLD="$3"
    NEW="$4"
    [[ "$OLD" == /* ]] || OLD="$PWD/$OLD"
    [[ "$NEW" == /* ]] || NEW="$PWD/$NEW"
else
    shopt -s nullglob
    pkgs=("$DIST"/*."$KIND")
    shopt -u nullglob
    if [[ ${#pkgs[@]} -ne 1 ]]; then
        echo "$usage (want exactly one .$KIND in $DIST without package names, found ${#pkgs[@]})" >&2
        exit 2
    fi
    OLD="${pkgs[0]}"
    NEW="${pkgs[0]}"
fi
[[ -f "$OLD" && -f "$NEW" ]] || {
    echo "$usage (no such package: $OLD or $NEW)" >&2
    exit 2
}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LOGS="${SAIIFE_PACKAGE_LOGS:-$REPO/target/package-linux-logs}"
# Pinned at build time (plan 18, decision 10): the multi-arch index of
# rockylinux/rockylinux:9.
ROCKY_IMAGE="rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f"
export HERE REPO LOGS OLD NEW DIST KIND
mkdir -p "$LOGS"

if [[ "$KIND" == rpm ]]; then
    args=(--rm -v "$DIST:/dist:ro" -v "$HERE:/t:ro"
        -e SAIIFE_PACKAGE_CI=1
        -e "SAIIFE_OLD_RPM=$(basename "$OLD")" -e "SAIIFE_NEW_RPM=$(basename "$NEW")")
    [[ -z "${PHASES:-}" ]] || args+=(-e "PHASES=$PHASES")
    if [[ -n "${SAIIFE_PKG_PUBKEY:-}" ]]; then
        [[ -f "$SAIIFE_PKG_PUBKEY" ]] || {
            echo "SAIIFE_PKG_PUBKEY is not a file: $SAIIFE_PKG_PUBKEY" >&2
            exit 2
        }
        args+=(-v "$(realpath "$SAIIFE_PKG_PUBKEY"):/pubkey.asc:ro" -e SAIIFE_PKG_PUBKEY=/pubkey.asc)
    fi
    docker run "${args[@]}" "$ROCKY_IMAGE" sh /t/rpm-container.sh 2>&1 | tee "$LOGS/rpm-container.log"
    exit "${PIPESTATUS[0]}"
fi

# shellcheck source=scripts/locked-linux/lib.sh
source "$REPO/scripts/locked-linux/lib.sh"
# shellcheck source=scripts/package-linux/deb.sh
source "$HERE/deb.sh"

WORK="$(mktemp -d)"
export WORK
# lib.sh's on_exit also calls these; there is nothing of theirs to undo here.
cleanup_lockdown() { :; }
cleanup_demo() { :; }
cleanup_approvals() { :; }
trap 'pkg_on_exit $?' EXIT

PHASES="${PHASES:-refusal fresh config-change upgrade remove purge lintian}"
want() { [[ " $PHASES " == *" $1 "* ]]; }

if want refusal; then phase_refusal; fi
if want fresh; then phase_fresh; fi
if want config-change; then phase_config_change; fi
if want upgrade; then phase_upgrade; fi
if want remove; then phase_remove; fi
if want purge; then phase_purge; fi
if want lintian; then phase_lintian; fi

echo "== package-linux deb: all phases passed ($PHASES; systemd $(systemd_version))"
