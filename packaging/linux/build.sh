#!/usr/bin/env bash
# Build the deb and rpm with nfpm (plan 18, Task 2).
# usage: build.sh <static saiife binary> <version> <amd64|arm64> <out dir>
# Signs the rpm when SAIIFE_PKG_GPG_KEY_FILE is set (passphrase in
# NFPM_RPM_PASSPHRASE, from the caller).
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <static saiife binary> <version> <amd64|arm64> <out dir>" >&2
    exit 2
fi
bin=$1
version=$2
arch=$3
out=$4

case "$arch" in
    amd64) rpm_arch=x86_64 ;;
    arm64) rpm_arch=aarch64 ;;
    *) echo "build.sh: arch must be amd64 or arm64, got '$arch'" >&2; exit 2 ;;
esac
[ -f "$bin" ] || { echo "build.sh: no such binary: $bin" >&2; exit 2; }
command -v nfpm >/dev/null || { echo "build.sh: nfpm is not on PATH" >&2; exit 2; }

# A package for every distro needs a static binary (same check as release.yml).
desc=$(file -b "$bin")
case "$desc" in
    *"statically linked"*|*"static-pie linked"*) ;;
    *) echo "build.sh: binary is not statically linked: $desc" >&2; exit 1 ;;
esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -m 0755 "$bin" "$stage/saiife"
install -m 0644 "$root/README.md" "$stage/README.md"
install -m 0644 "$root/LICENSE" "$stage/LICENSE"
install -m 0644 "$root/packaging/linux/lintian-overrides" "$stage/lintian-overrides"

export SAIIFE_STAGE=$stage SAIIFE_VERSION=$version
if [ -n "${SAIIFE_PKG_GPG_KEY_FILE:-}" ]; then
    export NFPM_RPM_KEY_FILE=$SAIIFE_PKG_GPG_KEY_FILE
else
    unset NFPM_RPM_KEY_FILE
fi

cd "$root"
deb="$out/saiife_${version}_${arch}.deb"
rpm="$out/saiife-${version}-1.${rpm_arch}.rpm"
SAIIFE_ARCH=$arch nfpm package --config packaging/linux/nfpm.yaml --packager deb --target "$deb" >&2
SAIIFE_ARCH=$arch nfpm package --config packaging/linux/nfpm.yaml --packager rpm --target "$rpm" >&2
echo "$deb"
echo "$rpm"
