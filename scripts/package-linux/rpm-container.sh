#!/bin/sh
# The saiife .rpm in a Rocky 9 container (plan 18, Task 3, decision 10).
# Locked mode refuses containers by design, so this covers the payload, the
# modes, the scriptlet wiring, the loud refusal, the upgrade of the staging
# copy and a clean removal. The full locked flow runs on the Ubuntu deb jobs.
#
# CI ONLY. Run by scripts/package-linux/run.sh as root inside the container:
#   docker run --rm -v <dist>:/dist:ro -v <scripts>:/t:ro -e SAIIFE_PACKAGE_CI=1 \
#       -e SAIIFE_OLD_RPM=<file> -e SAIIFE_NEW_RPM=<file> <image> sh /t/rpm-container.sh
# PHASES (env, default all): fresh upgrade remove signature. The signature
# phase runs when SAIIFE_PKG_PUBKEY names a file.
set -eu

if [ ! -f /.dockerenv ] || [ "${SAIIFE_PACKAGE_CI:-}" != "1" ]; then
    echo "refusing: rpm-container.sh runs only inside the package-linux CI container (/.dockerenv and SAIIFE_PACKAGE_CI=1)" >&2
    exit 2
fi
OLD="/dist/${SAIIFE_OLD_RPM:?SAIIFE_OLD_RPM is not set}"
NEW="/dist/${SAIIFE_NEW_RPM:?SAIIFE_NEW_RPM is not set}"
[ -f "$OLD" ] && [ -f "$NEW" ] || {
    echo "no such package: $OLD or $NEW" >&2
    exit 2
}
PHASES="${PHASES:-fresh upgrade remove signature}"
OUT=/tmp/p18-t3-rpm
mkdir -p "$OUT"
PKG_BIN=/usr/libexec/saiife/saiife
REFUSAL='locked mode is not supported here'

phase() {
    echo
    echo "== $*"
}
ok() {
    echo "  ok: $*"
}
fail() {
    echo "FAIL: $*" >&2
    exit 1
}
want() {
    case " $PHASES " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}
# `has <file> <text>`: the output file has the text.
has() {
    grep -qF -- "$2" "$1"
}
sha() {
    sha256sum "$1" | cut -d' ' -f1
}

phase_fresh() {
    phase "fresh: dnf install refuses loudly, the payload is in place"
    dnf install -y --setopt=install_weak_deps=False "$OLD" >"$OUT/install.out" 2>&1 || true
    cat "$OUT/install.out"
    has "$OUT/install.out" "$REFUSAL" || fail "dnf install output lacks '$REFUSAL'"
    ok "the scriptlet refused: $REFUSAL"
    rpm -q saiife >/dev/null || fail "rpm -q saiife: the package is not installed (rpm keeps it after a failed %post)"
    ok "the package stays installed"
    version="$(rpm -q --qf '%{VERSION}' saiife)"
    "$PKG_BIN" --version | grep -qF "$version" || fail "$PKG_BIN --version does not print $version: $("$PKG_BIN" --version)"
    ok "$PKG_BIN --version prints $version"
    [ -L /usr/bin/saiife ] && [ "$(readlink /usr/bin/saiife)" = "$PKG_BIN" ] || fail "/usr/bin/saiife is not a symlink to $PKG_BIN"
    ok "/usr/bin/saiife is a symlink to $PKG_BIN"
    rpm -q --qf '[%{FILEMODES:perms} %{FILEUSERNAME} %{FILEGROUPNAME} %{FILENAMES}\n]' saiife >"$OUT/files.txt"
    cat "$OUT/files.txt"
    grep -qx -- "-rwxr-xr-x root root $PKG_BIN" "$OUT/files.txt" || fail "$PKG_BIN is not 0755 root:root in the rpm"
    ok "$PKG_BIN is 0755 root:root"
    [ ! -e /opt/saiife ] || fail "/opt/saiife exists in a container"
    [ ! -e /etc/systemd/system/saiifed.service ] || fail "the unit exists in a container"
    ok "no /opt/saiife and no unit"
}

phase_upgrade() {
    phase "upgrade: rpm -Uvh refuses again and replaces the staging copy"
    dnf install -y cpio >"$OUT/cpio.out" 2>&1 || {
        cat "$OUT/cpio.out"
        fail "cannot install cpio"
    }
    mkdir -p "$OUT/new"
    (cd "$OUT/new" && rpm2cpio "$NEW" | cpio -idm --quiet ./usr/libexec/saiife/saiife) || fail "cannot extract the new binary"
    new_sha="$(sha "$OUT/new/usr/libexec/saiife/saiife")"
    rpm -Uvh "$NEW" >"$OUT/upgrade.out" 2>&1 || true
    cat "$OUT/upgrade.out"
    has "$OUT/upgrade.out" "$REFUSAL" || fail "rpm -Uvh output lacks '$REFUSAL'"
    ok "the scriptlet refused again"
    [ "$(sha "$PKG_BIN")" = "$new_sha" ] || fail "$PKG_BIN is not the new binary ($new_sha)"
    ok "the staging copy is the new binary ($new_sha)"
}

phase_remove() {
    phase "remove: dnf remove finds nothing to uninstall and clears the payload"
    dnf remove -y saiife >"$OUT/remove.out" 2>&1 || {
        cat "$OUT/remove.out"
        fail "dnf remove failed"
    }
    cat "$OUT/remove.out"
    has "$OUT/remove.out" 'nothing to uninstall' || fail "dnf remove output lacks 'nothing to uninstall'"
    ok "prerm found nothing to uninstall"
    if rpm -q saiife >/dev/null 2>&1; then fail "rpm still knows saiife"; fi
    [ ! -e "$PKG_BIN" ] && [ ! -L /usr/bin/saiife ] && [ ! -e /usr/libexec/saiife ] || fail "the payload is not gone"
    ok "the payload is gone"
}

phase_signature() {
    if [ -z "${SAIIFE_PKG_PUBKEY:-}" ]; then
        echo "  (signature phase skipped: SAIIFE_PKG_PUBKEY is not set)"
        return 0
    fi
    phase "signature: rpm -K verifies with the package key"
    [ -f "$SAIIFE_PKG_PUBKEY" ] || fail "SAIIFE_PKG_PUBKEY is not a file: $SAIIFE_PKG_PUBKEY"
    rpm --import "$SAIIFE_PKG_PUBKEY" || fail "rpm --import failed"
    for f in "$OLD" "$NEW"; do
        rpm -K "$f" >"$OUT/K.out" 2>&1 || {
            cat "$OUT/K.out"
            fail "rpm -K failed for $f"
        }
        cat "$OUT/K.out"
        has "$OUT/K.out" 'digests signatures OK' || fail "rpm -K for $f does not say 'digests signatures OK'"
        ok "$(basename "$f"): digests signatures OK"
    done
}

if want fresh; then phase_fresh; fi
if want upgrade; then phase_upgrade; fi
if want remove; then phase_remove; fi
if want signature; then phase_signature; fi
echo "== package-linux rpm: all phases passed ($PHASES)"
