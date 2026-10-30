#!/usr/bin/env bash
# Unsafe boundary gate (plan 13, decision 1): `unsafe` may appear only in
# crates/darwin (saiife-darwin). It fails when:
#   - an `unsafe` keyword (block, fn, impl, trait, extern, attribute) appears
#     in a .rs file under crates/ outside crates/darwin/, comment lines left
#     out;
#   - a crate root crates/*/src/lib.rs or crates/*/src/main.rs, darwin's
#     aside, lacks `#![forbid(unsafe_code)]`;
#   - crates/darwin/src/lib.rs drops its `unsafe_op_in_unsafe_fn` /
#     `undocumented_unsafe_blocks` lints or its non-macOS forbid.
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

# 1. The keyword outside crates/darwin. `grep -w` alone also hits prose such
# as "lockdown dir unsafe" or CSP's 'unsafe-inline' in string literals, so a
# hit must look like Rust syntax: `unsafe` followed by `{`, `(`, `fn`, `impl`,
# `trait`, `extern` or the end of the line (a block opened on the next line).
kw='(^|[^[:alnum:]_"'"'"'-])unsafe([[:space:]]*($|[{(])|[[:space:]]+(fn|impl|trait|extern)([^[:alnum:]_]|$))'
hits="$(grep -rnE --include='*.rs' "$kw" crates \
    | grep -v '^crates/darwin/' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*)' || true)"
if [ -n "$hits" ]; then
    echo "check-unsafe: unsafe outside crates/darwin:" >&2
    printf '%s\n' "$hits" >&2
    fail=1
fi

# 2. Every other crate root forbids unsafe code.
forbid='^[[:space:]]*#!\[forbid\(unsafe_code\)\][[:space:]]*$'
for f in crates/*/src/lib.rs crates/*/src/main.rs; do
    [ -e "$f" ] || continue
    case "$f" in crates/darwin/*) continue ;; esac
    if ! grep -qE "$forbid" "$f"; then
        echo "check-unsafe: $f lacks #![forbid(unsafe_code)]" >&2
        fail=1
    fi
done

# 3. The darwin crate keeps its own guard rails.
d=crates/darwin/src/lib.rs
if [ -e "$d" ]; then
    if ! grep -qE '^#!\[deny\(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks\)\]' "$d"; then
        echo "check-unsafe: $d lacks #![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]" >&2
        fail=1
    fi
    if ! grep -qE '^#!\[cfg_attr\(not\(target_os = "macos"\), forbid\(unsafe_code\)\)\]' "$d"; then
        echo "check-unsafe: $d lacks #![cfg_attr(not(target_os = \"macos\"), forbid(unsafe_code))]" >&2
        fail=1
    fi
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "check-unsafe: ok (unsafe only in crates/darwin)"
