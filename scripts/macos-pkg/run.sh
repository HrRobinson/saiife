#!/usr/bin/env bash
# The saiife pkg on a real Mac (plan 18, Task 7): the build, the payload, the
# fleet files through the Jamf recipe, `installer`, its SIP refusal, the fleet
# install from the staging copy, doctor, the MDM attributes, the Jamf
# uninstall and a reinstall.
#
# CI ONLY. This writes /etc, /opt, /usr/local, /Library and /var, runs
# `installer` and loads a launchd daemon. It runs in the GitHub Actions job
# `macos-pkg` (ci.yml) on throwaway runners, as the runner user, and uses
# `sudo` itself for every privileged step. Anywhere else it refuses before
# doing anything.
#
#   SAIIFE_PACKAGE_CI=1 bash scripts/macos-pkg/run.sh <saiife binary>
#
# The binary must be the ci-locked build, signed ad hoc with the hardened
# runtime, as for locked-macos. Why, and what this proves:
#
# The runners have SIP off, and a release binary never honours the
# SIP seam. So with SIP off, the real postinstall can only ever refuse. That
# refusal is asserted first (loud, exit non-zero, nothing changed). Then the
# ci-locked staging copy from the pkg runs the postinstall's own command by
# hand, with the seam and --allow-test-build, so the rest of the flow runs for
# real: fleet files through /etc, launchd, doctor, uninstall, reinstall.
# What this cannot prove on a runner: postinstall passing with a real install.
# Its exit-code mapping is tested in crates/system/tests/packaging.rs.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || "${SAIIFE_PACKAGE_CI:-}" != "1" ||
    "$(uname -s)" != "Darwin" || "$(id -u)" == "0" ]]; then
    echo "refusing: macos-pkg tests run only in GitHub Actions CI on macOS (GITHUB_ACTIONS=true, SAIIFE_PACKAGE_CI=1, Darwin, as a non-root user with sudo; the script calls sudo itself)" >&2
    exit 2
fi
if [[ $# -ne 1 || ! -x "$1" || "$1" != /* ]]; then
    echo "usage: SAIIFE_PACKAGE_CI=1 bash scripts/macos-pkg/run.sh <absolute path to the signed ci-locked saiife binary>" >&2
    exit 2
fi

BIN="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LOGS="${SAIIFE_PACKAGE_LOGS:-$REPO/target/macos-pkg-logs}"
WORK="$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP is not set}/macos-pkg.XXXXXX")"
mkdir -p "$LOGS"

STAGING=/usr/local/libexec/saiife/saiife
LINK=/usr/local/bin/saiife
OPT_BIN=/opt/saiife/bin/saiife
FLEET=/etc/saiife/fleet
PLIST=/Library/LaunchDaemons/com.saiife.saiifed.plist
SERVICE=system/com.saiife.saiifed
CLAUDE_MANAGED="/Library/Application Support/ClaudeCode/managed-settings.d/50-saiife.json"
SIP_LINE="saiife: locked mode on macOS needs System Integrity Protection: without it the hardened runtime does not stop library injection (DYLD_INSERT_LIBRARIES). Enable SIP (Recovery: csrutil enable) and run install again."
REMOVAL_LINE="saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked"
ARCH="$(uname -m)"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}
ok() { echo "  ok: $*"; }
phase() {
    echo
    echo "== $*"
}

# shellcheck disable=SC2329 # invoked by the EXIT trap
on_exit() {
    local code="$1"
    if [[ "$code" != 0 ]]; then
        echo "macos-pkg failed (exit $code); collecting logs in $LOGS" >&2
        # shellcheck disable=SC2024 # the logs are the runner's; only the read needs root
        sudo -n tail -n 400 /var/log/install.log >"$LOGS/install.log" 2>&1 || true
        # shellcheck disable=SC2024 # the logs are the runner's; only the read needs root
        sudo -n cat /var/log/saiife/daemon.log >"$LOGS/daemon.log" 2>&1 || true
        # shellcheck disable=SC2024 # the logs are the runner's; only the read needs root
        sudo -n launchctl print "$SERVICE" >"$LOGS/launchctl-print.txt" 2>&1 || true
        # shellcheck disable=SC2024 # the logs are the runner's; only the read needs root
        sudo -n ls -laR /etc/saiife /usr/local/libexec/saiife /opt/saiife >"$LOGS/ls.txt" 2>&1 || true
        cp "$WORK"/*.out "$LOGS/" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap 'on_exit $?' EXIT

SIP_STATUS="$(/usr/bin/csrutil status 2>&1 || true)"
SIP_ON=""
[[ "$SIP_STATUS" == "System Integrity Protection status: enabled." ]] && SIP_ON=1
echo "csrutil: $SIP_STATUS"

# A root command with the debug-build seam, on a host with SIP off.
as_root_seam() {
    if [[ -n "$SIP_ON" ]]; then
        sudo -n "$@"
    else
        sudo -n /usr/bin/env SAIIFE_TEST_ALLOW_SIP_OFF=1 "$@"
    fi
}

running() {
    sudo -n launchctl print "$SERVICE" 2>/dev/null | grep -q 'state = running'
}

wait_running() {
    local end=$((SECONDS + 30))
    until running; do
        ((SECONDS < end)) || fail "$1: $SERVICE is not running after 30 s"
        sleep 0.5
    done
    ok "$1: launchctl print $SERVICE: running"
}

# Owner, group and mode of the dirs the payload passes through.
shared_dirs() {
    stat -f '%N %Su:%Sg %Lp' /usr/local /usr/local/bin
}

# `expect_mode <env...>`: prints the mode, or "fails" when the script failed.
expect_mode() {
    local want="$1" got
    shift
    got="$(/usr/bin/env -i PATH="$PATH" GITHUB_ACTIONS=true SAIIFE_PKG_PRINT_MODE=1 "$@" \
        bash "$REPO/packaging/macos/build-pkg.sh" 2>/dev/null)" || got=fails
    [[ "$got" == "$want" ]] || fail "secrets [$*]: mode is $got, want $want"
    ok "secrets [$*]: $got"
}

phase "1. the signing mode follows the secrets"
NOTARY=(APPLE_TEAM_ID=t APPLE_NOTARY_APPLE_ID=a APPLE_NOTARY_PASSWORD=p)
expect_mode unsigned
expect_mode fails MACOS_INSTALLER_CERT_P12=x
expect_mode fails MACOS_INSTALLER_CERT_PASSWORD=x
expect_mode fails MACOS_INSTALLER_CERT_P12=x MACOS_INSTALLER_CERT_PASSWORD=y
expect_mode signed MACOS_INSTALLER_CERT_P12=x MACOS_INSTALLER_CERT_PASSWORD=y "${NOTARY[@]}"
expect_mode signed MACOS_SIGN_P12_BASE64=x MACOS_SIGN_P12_PASSWORD=y "${NOTARY[@]}"
expect_mode fails MACOS_INSTALLER_CERT_P12=x MACOS_INSTALLER_CERT_PASSWORD=y APPLE_TEAM_ID=t

phase "2. build the unsigned pkg"
VERSION="$("$BIN" --version | awk '{ print $2 }')"
PKG="$(bash "$REPO/packaging/macos/build-pkg.sh" "$BIN" "$VERSION" "$ARCH" "$WORK/out")"
[[ "$PKG" == "$WORK/out/saiife-$VERSION-$ARCH.pkg" ]] || fail "unexpected pkg path: $PKG"
[[ "$(cat "$PKG.mode")" == unsigned ]] || fail "the mode file says $(cat "$PKG.mode")"
ok "built $PKG"

phase "3. the payload owns only the staging copy and its link"
pkgutil --expand "$PKG" "$WORK/expanded"
lsbom -s "$WORK/expanded/saiife-component.pkg/Bom" | LC_ALL=C sort >"$WORK/bom.out"
cat >"$WORK/bom-want.out" <<'EOF'
.
./usr
./usr/local
./usr/local/bin
./usr/local/bin/saiife
./usr/local/libexec
./usr/local/libexec/saiife
./usr/local/libexec/saiife/saiife
EOF
diff -u "$WORK/bom-want.out" "$WORK/bom.out" || fail "the payload differs"
[[ -e "$WORK/expanded/saiife-component.pkg/Scripts" ]] || fail "the pkg has no scripts"
ok "payload as expected"

phase "4. the fleet files, through the Jamf recipe"
sudo -n sh "$REPO/deploy/jamf/fleet-files.sh" / ci-host root \
    "$(base64 <"$HERE/fleet-config.toml" | tr -d '\n')" claude,codex,gemini
[[ "$(sudo -n stat -f '%Su:%Sg %Lp' "$FLEET")" == "root:wheel 755" ]] || fail "$FLEET: wrong owner or mode"
for f in config.toml install.toml; do
    [[ "$(sudo -n stat -f '%Su:%Sg %Lp' "$FLEET/$f")" == "root:wheel 644" ]] || fail "$FLEET/$f: wrong owner or mode"
done
sudo -n cmp "$FLEET/config.toml" "$HERE/fleet-config.toml" || fail "$FLEET/config.toml differs"
[[ "$(sudo -n cat "$FLEET/install.toml")" == 'agents = ["claude", "codex", "gemini"]' ]] ||
    fail "$FLEET/install.toml: $(sudo -n cat "$FLEET/install.toml")"
ok "fleet files are root:wheel, 0755 and 0644"

# The postinstall must refuse; with SIP on, the test build is what it refuses.
install_refused() {
    local what="$1" code=0 lines
    lines="$(sudo -n cat /var/log/install.log | wc -l | tr -d ' ')"
    # shellcheck disable=SC2024 # the output file is the runner's
    sudo -n installer -pkg "$PKG" -target / >"$WORK/installer.out" 2>&1 || code=$?
    cat "$WORK/installer.out"
    [[ "$code" != 0 ]] || fail "$what: installer exited 0, but install must refuse"
    # shellcheck disable=SC2024 # the output file is the runner's
    sudo -n tail -n "+$((lines + 1))" /var/log/install.log >"$WORK/install-log.out"
    if [[ -n "$SIP_ON" ]]; then
        grep -qF 'test build' "$WORK/install-log.out" || fail "$what: no test-build refusal in install.log"
    else
        grep -qF "$SIP_LINE" "$WORK/install-log.out" || fail "$what: no SIP refusal in install.log"
    fi
    grep -qF 'saiife: locked mode is NOT active' "$WORK/install-log.out" ||
        fail "$what: the postinstall did not say that locked mode is not active"
    [[ -f "$STAGING" ]] || fail "$what: $STAGING is missing"
    [[ -L "$LINK" && "$(readlink "$LINK")" == "$STAGING" ]] || fail "$what: $LINK is not the link"
    ok "$what: installer exit $code, the refusal is in install.log, the payload is in place"
}

# The postinstall's command, by hand, with the test build's flag and seam.
fleet_install() {
    local what="$1" code=0
    as_root_seam "$STAGING" system install --fleet --allow-test-build >"$WORK/install.out" 2>&1 || code=$?
    cat "$WORK/install.out"
    [[ "$code" -le 1 ]] || fail "$what: system install --fleet exited $code"
    wait_running "$what"
    sudo -n cmp "$FLEET/config.toml" /etc/saiife/config.toml || fail "$what: the fleet config was not copied"
    sudo -n cmp "$STAGING" "$OPT_BIN" || fail "$what: $OPT_BIN is not the staging copy"
    ok "$what: system install --fleet exit $code, config and binary in place"
}

phase "5. installer: the postinstall refuses loudly, nothing changes"
before_dirs="$(shared_dirs)"
install_refused "first install"
for p in /opt/saiife /etc/saiife/config.toml /etc/saiife/installed.toml /var/db/saiife "$PLIST"; do
    if sudo -n test -e "$p"; then fail "the refused install created $p"; fi
done
ok "the refused install changed nothing else"
[[ "$(shared_dirs)" == "$before_dirs" ]] || fail "the pkg changed /usr/local: $before_dirs -> $(shared_dirs)"
ok "the pkg left /usr/local and /usr/local/bin alone"

phase "6. the fleet install from the staging copy"
fleet_install "fleet install"
sudo -n test -f "$CLAUDE_MANAGED" || fail "no managed hooks for claude"

phase "7. doctor and the MDM attributes"
code=0
as_root_seam "$OPT_BIN" doctor --json >"$WORK/doctor.out" 2>"$WORK/doctor-err.out" || code=$?
[[ "$code" -le 1 ]] || { cat "$WORK/doctor.out" "$WORK/doctor-err.out"; fail "doctor exited $code"; }
[[ "$(jq -r '.checks[] | select(.id == "files.package") | .status' "$WORK/doctor.out")" == pass ]] ||
    { cat "$WORK/doctor.out"; fail "doctor files.package does not pass"; }
ok "doctor exit $code, files.package passes"
got="$(as_root_seam sh "$REPO/deploy/jamf/extension-attribute.sh")"
[[ "$got" == "<result>warn</result>" || "$got" == "<result>pass</result>" ]] || fail "extension attribute: $got"
ok "extension attribute: $got"
got="$(as_root_seam sh "$REPO/deploy/intune/macos/custom-attribute.sh")"
[[ "$got" == "$code" ]] || fail "custom attribute: $got, want $code"
ok "custom attribute: $got"

phase "8. the Jamf uninstall"
# shellcheck disable=SC2024 # the output file is the runner's
sudo -n sh "$REPO/deploy/jamf/uninstall.sh" >"$WORK/uninstall.out" 2>&1 || {
    cat "$WORK/uninstall.out"
    fail "uninstall.sh failed"
}
cat "$WORK/uninstall.out"
grep -qxF "$REMOVAL_LINE" "$WORK/uninstall.out" || fail "uninstall.sh did not print the warning line"
for p in "$PLIST" "$CLAUDE_MANAGED" "$OPT_BIN" "$STAGING" "$LINK"; do
    if sudo -n test -e "$p" || sudo -n test -L "$p"; then fail "uninstall.sh left $p"; fi
done
if pkgutil --pkgs | grep -qx com.saiife.pkg; then fail "pkgutil still lists com.saiife.pkg"; fi
if sudo -n launchctl print "$SERVICE" >/dev/null 2>&1; then fail "the job is still loaded"; fi
ok "plist, managed files, staging copy, link and receipt are gone; the job is not loaded"
got="$(sudo -n sh "$REPO/deploy/jamf/extension-attribute.sh")"
[[ "$got" == "<result>not installed</result>" ]] || fail "extension attribute after uninstall: $got"

phase "9. a reinstall works"
install_refused "reinstall"
fleet_install "reinstall"

echo
echo "== macos-pkg: all phases passed (macOS $(sw_vers -productVersion), $ARCH)"
