#!/usr/bin/env bash
# Unsafe boundary gate (plan 13, decision 1): `unsafe` may appear only in
# crates/darwin (saiife-darwin).
#
# The compiler does the real enforcement: the workspace Cargo.toml sets
# `[workspace.lints.rust] unsafe_code = "forbid"` and every crate but darwin
# opts in with `[lints] workspace = true`, which covers lib, bins, tests,
# examples and build scripts. This script keeps that wiring from being
# dropped, and backs it with a grep. It fails when:
#   - the workspace lint, or a crate's `[lints] workspace = true` (darwin
#     aside), is missing;
#   - a crate root crates/*/src/lib.rs or crates/*/src/main.rs, darwin's
#     aside, lacks `#![forbid(unsafe_code)]` at column 0 (an inner attribute
#     inside `mod m {}` does not count);
#   - outside crates/darwin/, a .rs file under crates/ has `unsafe` as Rust
#     syntax (followed by `{`, `(`, a comment, `fn`, `impl`, `trait`, `extern`
#     or the end of the line), an `extern` block, or a `no_mangle`,
#     `export_name` or `link_section` attribute. Lines that start, after
#     whitespace, with `//` or `/*` are skipped;
#   - crates/darwin/src/lib.rs drops its `unsafe_op_in_unsafe_fn` /
#     `undocumented_unsafe_blocks` lints, its non-macOS forbid or its macOS
#     deny, or crates/darwin/src has other than exactly two
#     `allow(unsafe_code)` sites.
#
# Known limit: `unsafe` that a dependency's macro expands into our code is
# invisible to the grep. The compiler lint still catches it, unless the macro
# marks its expansion with `#[allow(unsafe_code)]` itself.
#
# Usage: bash scripts/check-unsafe.sh [repo root]   (default: this repo)
# Read-only; safe to run anywhere.
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$root"
if [ ! -d crates ]; then
    echo "check-unsafe: no crates/ dir under $root" >&2
    exit 2
fi

fail=0
err() {
    echo "check-unsafe: $*" >&2
    fail=1
}

# Prints 1 when TOML file $1 has key line $3 inside table [$2].
in_table() {
    awk -v table="[$2]" -v key="$3" '
        /^[[:space:]]*\[/ { cur = $0; sub(/[[:space:]]*(#.*)?$/, "", cur); sub(/^[[:space:]]*/, "", cur); next }
        cur == table && $0 ~ key { found = 1 }
        END { print found ? 1 : 0 }
    ' "$1"
}

# 1. The compiler lint is wired up.
if [ ! -e Cargo.toml ] || [ "$(in_table Cargo.toml workspace.lints.rust '^[[:space:]]*unsafe_code[[:space:]]*=[[:space:]]*"forbid"')" != 1 ]; then
    err 'Cargo.toml lacks [workspace.lints.rust] unsafe_code = "forbid"'
fi
for m in crates/*/Cargo.toml; do
    [ -e "$m" ] || continue
    case "$m" in crates/darwin/*) continue ;; esac
    if [ "$(in_table "$m" lints '^[[:space:]]*workspace[[:space:]]*=[[:space:]]*true')" != 1 ]; then
        err "$m lacks [lints] workspace = true"
    fi
done

# 2. Every other crate root forbids unsafe code, at column 0.
for f in crates/*/src/lib.rs crates/*/src/main.rs; do
    [ -e "$f" ] || continue
    case "$f" in crates/darwin/*) continue ;; esac
    if ! grep -qE '^#!\[forbid\(unsafe_code\)\][[:space:]]*$' "$f"; then
        err "$f lacks #![forbid(unsafe_code)] at column 0"
    fi
done

# 3. The keyword outside crates/darwin. `grep -w` alone also hits prose such
# as "lockdown dir unsafe" or CSP's 'unsafe-inline' in string literals, so a
# hit must look like Rust syntax.
pre='(^|[^[:alnum:]_"'"'"'-])'
kw="${pre}unsafe([[:space:]]*(\$|[{(]|//|/\\*)|[[:space:]]+(fn|impl|trait|extern)([^[:alnum:]_]|\$))"
kw="$kw|${pre}extern([[:space:]]+\"[^\"]*\")?[[:space:]]*(\$|\\{)"
kw="$kw|#!?\\[[[:space:]]*(unsafe[[:space:]]*\\([[:space:]]*)?(no_mangle|export_name|link_section)"
hits="$(grep -rnE --include='*.rs' "$kw" crates \
    | grep -v '^crates/darwin/' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*)' || true)"
if [ -n "$hits" ]; then
    err "unsafe outside crates/darwin:"
    printf '%s\n' "$hits" >&2
fi

# 4. The darwin crate keeps its own guard rails.
d=crates/darwin/src/lib.rs
if [ -e "$d" ]; then
    grep -qE '^#!\[deny\(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks\)\]' "$d" \
        || err "$d lacks #![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]"
    grep -qE '^#!\[cfg_attr\(not\(target_os = "macos"\), forbid\(unsafe_code\)\)\]' "$d" \
        || err "$d lacks #![cfg_attr(not(target_os = \"macos\"), forbid(unsafe_code))]"
    grep -qE '^#!\[cfg_attr\(target_os = "macos", deny\(unsafe_code\)\)\]' "$d" \
        || err "$d lacks #![cfg_attr(target_os = \"macos\", deny(unsafe_code))]"
    allows="$(grep -rhE --include='*.rs' 'allow\([^)]*unsafe_code' crates/darwin/src \
        | grep -cvE '^[[:space:]]*(//|/\*)' || true)"
    if [ "$allows" != 2 ]; then
        err "crates/darwin/src has $allows allow(unsafe_code) sites, want exactly 2"
    fi
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "check-unsafe: ok (unsafe only in crates/darwin)"
