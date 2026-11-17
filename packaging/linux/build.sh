#!/usr/bin/env bash
# Build the deb and rpm with nfpm (plan 18, Task 2).
# usage: build.sh <static saiife binary> <saiife-fido helper> <version> <amd64|arm64> <out dir>
# The helper (plan 41) is the dynamically linked binary of
# scripts/release/build-fido-helper.sh, for the same arch.
# A '-' in the version becomes '~' (0.3.0-rc.1 -> 0.3.0~rc.1).
# Signs the rpm when SAIIFE_PKG_GPG_KEY_FILE is set (passphrase in
# NFPM_RPM_PASSPHRASE, from the caller): nfpm.yaml's rpm.signature.key_file
# expands NFPM_RPM_KEY_FILE, which an empty value leaves unsigned.
set -euo pipefail

if [ "$#" -ne 5 ]; then
    echo "usage: $0 <static saiife binary> <saiife-fido helper> <version> <amd64|arm64> <out dir>" >&2
    exit 2
fi
bin=$1
fido=$2
version=$3
arch=$4
out=$5

case "$arch" in
    amd64) rpm_arch=x86_64; elf_arch='x86-64' ;;
    arm64) rpm_arch=aarch64; elf_arch='ARM aarch64' ;;
    *) echo "build.sh: arch must be amd64 or arm64, got '$arch'" >&2; exit 2 ;;
esac
# A Cargo prerelease (0.3.0-rc.1) sorts before its release only as
# 0.3.0~rc.1 in dpkg and rpm, and rpm forbids '-' in a version.
version=$(printf '%s' "$version" | tr '-' '~')
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.~+][0-9A-Za-z.~+]+)?$'; then
    echo "build.sh: version must look like 1.2.3 (optionally 1.2.3-rc.1 or 1.2.3~rc.1), got '$version'" >&2
    exit 2
fi
echo "build.sh: package version $version" >&2
[ -f "$bin" ] || { echo "build.sh: no such binary: $bin" >&2; exit 2; }
[ -f "$fido" ] || { echo "build.sh: no such helper: $fido" >&2; exit 2; }
command -v nfpm >/dev/null || { echo "build.sh: nfpm is not on PATH" >&2; exit 2; }

# A package for every distro needs a static binary (same check as release.yml).
desc=$(file -b "$bin")
case "$desc" in
    *"statically linked"*|*"static-pie linked"*) ;;
    *) echo "build.sh: binary is not statically linked: $desc" >&2; exit 1 ;;
esac

# The helper links libc and libudev dynamically, for this arch.
fdesc=$(file -b "$fido")
case "$fdesc" in
    *"dynamically linked"*) ;;
    *) echo "build.sh: helper is not dynamically linked: $fdesc" >&2; exit 1 ;;
esac
case "$fdesc" in
    *"$elf_arch"*) ;;
    *) echo "build.sh: helper is not a $elf_arch binary: $fdesc" >&2; exit 1 ;;
esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -m 0755 "$bin" "$stage/saiife"
install -m 0755 "$fido" "$stage/saiife-fido"
install -m 0644 "$root/README.md" "$stage/README.md"
install -m 0644 "$root/LICENSE" "$stage/LICENSE"
# Debian policy wants a changelog; gzip -9n (no name, no mtime) is reproducible.
gzip -9n -c "$root/CHANGELOG.md" >"$stage/changelog.gz"
chmod 0644 "$stage/changelog.gz"
install -m 0644 "$root/packaging/linux/lintian-overrides" "$stage/lintian-overrides"

export SAIIFE_STAGE=$stage SAIIFE_VERSION=$version
if [ -n "${SAIIFE_PKG_GPG_KEY_FILE:-}" ]; then
    export NFPM_RPM_KEY_FILE=$SAIIFE_PKG_GPG_KEY_FILE
else
    export NFPM_RPM_KEY_FILE=
fi

cd "$root"
deb="$out/saiife_${version}_${arch}.deb"
rpm="$out/saiife-${version}-1.${rpm_arch}.rpm"
SAIIFE_ARCH=$arch nfpm package --config packaging/linux/nfpm.yaml --packager deb --target "$deb" >&2
SAIIFE_ARCH=$arch nfpm package --config packaging/linux/nfpm.yaml --packager rpm --target "$rpm" >&2
echo "$deb"
echo "$rpm"
