#!/usr/bin/env bash
# Compile-checks the workspace for Windows from Linux (plan 19a): no Windows
# machine and no linker, since `cargo check` links nothing. ring's build script
# runs a C compiler for the target, so scripts/fake-cc.sh stands in for it,
# through the target's own CC/AR variables only.
#
# Usage: bash scripts/check-windows.sh [cargo check args]
# With no args it checks --workspace; `-p saiife-win` narrows it. Exits 2 when
# the target is missing: it never installs anything.
set -euo pipefail

target=x86_64-pc-windows-msvc

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Captured first: `rustup | grep -q` can die of SIGPIPE under pipefail.
installed="$(rustup target list --installed 2>/dev/null || true)"
if ! grep -qx "$target" <<<"$installed"; then
    echo "rustup target add $target first" >&2
    exit 2
fi

if [ "$#" -eq 0 ]; then
    set -- --workspace
fi

export CC_x86_64_pc_windows_msvc="$PWD/scripts/fake-cc.sh"
export AR_x86_64_pc_windows_msvc="$PWD/scripts/fake-cc.sh"

RUSTFLAGS="-D warnings" \
    cargo check --all-targets --target "$target" --target-dir target/check-windows "$@"

# Clippy too (CI runs it on windows-latest); --keep-going reports every crate.
cargo clippy --all-targets --target "$target" --target-dir target/check-windows \
    --keep-going "$@" -- -D warnings
