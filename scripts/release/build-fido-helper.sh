#!/usr/bin/env bash
# Build the dynamically linked saiife-fido helper (plan 41, F5) against
# glibc 2.31 in a pinned debian:bullseye container.
#
#   build-fido-helper.sh <amd64|arm64> <out dir>     writes <out dir>/saiife-fido
#
# CI-only: it runs docker and downloads a toolchain. Check it locally with
# `bash -n` and shellcheck only. It refuses to run as root and on a host whose
# `uname -m` is not the requested arch (the container is native, never emulated).
#
# The repo is mounted read-only; cargo's target dir, CARGO_HOME and RUSTUP_HOME
# live in a writable scratch dir, and the container runs as the invoking
# uid:gid, so the output is not root-owned. The toolchain is the one
# rust-toolchain.toml names, installed with a minimal profile.
set -euo pipefail

# Pinned (plan 18 decision 10, plan 41 R7): the multi-arch OCI index of
# debian:bullseye, from registry-1.docker.io manifests/bullseye
# (docker-content-digest) and the hub.docker.com tag API, which agree;
# tag updated 2026-08-25, verified 2026-11-12.
# Bullseye's regular security support ended 2026-08-31. The image's default apt
# sources are used. If CI's `apt-get update` starts failing because the suite
# moved, switch the sources to archive.debian.org (verified by the image's keyring).
DEBIAN_IMAGE="debian:bullseye@sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9"
# rustup-init 1.29.2 from static.rust-lang.org; the SHA-256 values are from the
# published rustup-init.sha256 files (verified 2026-11-12).
RUSTUP_VERSION="1.29.2"
RUSTUP_SHA256_X86_64="5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4"
RUSTUP_SHA256_AARCH64="a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697"

die() { echo "build-fido-helper.sh: $*" >&2; exit 1; }

[ "$#" -eq 2 ] || { echo "usage: $0 <amd64|arm64> <out dir>" >&2; exit 2; }
arch=$1
out=$2

# A reset pin must be set again before this runs.
for pin in DEBIAN_IMAGE RUSTUP_SHA256_X86_64 RUSTUP_SHA256_AARCH64; do
  [ "${!pin}" != UNPINNED ] || die "$pin is UNPINNED; pin it before building (plan 41 R7)"
done
case "$DEBIAN_IMAGE" in
  *@sha256:*) ;;
  *) die "DEBIAN_IMAGE must be pinned by digest (@sha256:), got $DEBIAN_IMAGE" ;;
esac

case "$arch" in
  amd64) host_arch=x86_64; triple=x86_64-unknown-linux-gnu
         rustup_sha=$RUSTUP_SHA256_X86_64; elf_arch='x86-64'
         ld_so='ld-linux-x86-64.so.2' ;;
  arm64) host_arch=aarch64; triple=aarch64-unknown-linux-gnu
         rustup_sha=$RUSTUP_SHA256_AARCH64; elf_arch='ARM aarch64'
         ld_so='ld-linux-aarch64.so.1' ;;
  *) echo "build-fido-helper.sh: arch must be amd64 or arm64, got '$arch'" >&2; exit 2 ;;
esac

[ "$(id -u)" -ne 0 ] || die "refusing to run as root"
[ "$(uname -m)" = "$host_arch" ] || die "host is $(uname -m), not $host_arch: build $arch on a native runner"
command -v docker >/dev/null || die "docker is not on PATH"

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/home"

# Runs inside the container as the invoking user.
inner='set -euo pipefail
export HOME=/work/home CARGO_HOME=/work/cargo RUSTUP_HOME=/work/rustup CARGO_TARGET_DIR=/work/target
export PATH="$CARGO_HOME/bin:$PATH"
curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors --connect-timeout 20 -o /work/rustup-init \
  "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${TRIPLE}/rustup-init"
echo "${RUSTUP_SHA256}  /work/rustup-init" | sha256sum -c -
chmod +x /work/rustup-init
/work/rustup-init -y --profile minimal --default-toolchain none --no-modify-path
cd /src
# cargo reads the channel from rust-toolchain.toml and rustup installs it.
cargo build --release --locked -p saiife-fido --features hid --bin saiife-fido
install -m 0755 "$CARGO_TARGET_DIR/release/saiife-fido" /out/saiife-fido'

# apt needs root, so the container starts as root, installs the packages, then
# drops to the invoking uid:gid (setpriv, from util-linux) for the build.
docker run --rm \
  -v "$root:/src:ro" -v "$work:/work" -v "$out:/out" \
  -e RUSTUP_VERSION="$RUSTUP_VERSION" -e TRIPLE="$triple" -e RUSTUP_SHA256="$rustup_sha" \
  -e INNER="$inner" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  "$DEBIAN_IMAGE" bash -euo pipefail -c '
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates curl gcc libc6-dev libudev-dev pkg-config binutils util-linux
    chown -R "$HOST_UID:$HOST_GID" /work
    exec setpriv --reuid="$HOST_UID" --regid="$HOST_GID" --clear-groups bash -c "$INNER"
  '

bin="$out/saiife-fido"
[ -f "$bin" ] || die "the build wrote no $bin"

# F5: glibc symbol versions at or below 2.31.
top=$(objdump -T "$bin" | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1 || true)
[ -n "$top" ] || die "no GLIBC_ symbol versions found in $bin"
[ "$(printf '%s\n%s\n' "$top" GLIBC_2.31 | sort -V | tail -1)" = GLIBC_2.31 ] \
  || die "$bin needs $top, above the GLIBC_2.31 ceiling"
echo "build-fido-helper.sh: glibc ceiling $top (<= GLIBC_2.31)" >&2

# F5: the NEEDED libraries are an allowlist.
allowed=" libudev.so.1 libc.so.6 libm.so.6 libgcc_s.so.1 libpthread.so.0 libdl.so.2 librt.so.1 $ld_so "
needed=$(readelf -d "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
[ -n "$needed" ] || die "$bin has no NEEDED entries; it must be dynamically linked"
for lib in $needed; do
  case "$allowed" in
    *" $lib "*) ;;
    *) die "$bin needs $lib, which is not on the allowlist" ;;
  esac
done
echo "build-fido-helper.sh: NEEDED: $(echo "$needed" | tr '\n' ' ')" >&2

desc=$(file -b "$bin")
case "$desc" in
  *"dynamically linked"*) ;;
  *) die "$bin is not dynamically linked: $desc" ;;
esac
case "$desc" in
  *"$elf_arch"*) ;;
  *) die "$bin is not a $elf_arch binary: $desc" ;;
esac
echo "build-fido-helper.sh: $bin: $desc" >&2
