#!/usr/bin/env bash
# Offline test for install.sh.
#
# Builds (or takes) a saiife binary, packs it into a fake release directory
# laid out like a GitHub release (saiife-<version>-<target>.tar.gz plus
# SHA256SUMS), then runs install.sh against it through a file:// download
# base with a throwaway HOME. No network is used.
#
#   bash scripts/test-install.sh
#   SAIIFE_BIN=target/release/saiife bash scripts/test-install.sh
#
# Scratch comes from `mktemp -d` (honours TMPDIR) and is removed on exit.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
installer="$repo/install.sh"

if [ -z "${SAIIFE_BIN:-}" ]; then
  (cd "$repo" && cargo build --release --quiet)
  SAIIFE_BIN="$repo/target/release/saiife"
fi
if [ ! -x "$SAIIFE_BIN" ]; then
  echo "test-install: no executable saiife binary at $SAIIFE_BIN" >&2
  exit 1
fi

scratch="$(mktemp -d)"
scratch="$(cd "$scratch" && pwd -P)"
trap 'rm -rf "$scratch"' EXIT

# Host target name as install.sh computes it.
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) echo "test-install: unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac
case "$(uname -s)" in
  Linux) target="$arch-unknown-linux-musl" ;;
  Darwin) target="$arch-apple-darwin" ;;
  *) echo "test-install: unsupported host os $(uname -s)" >&2; exit 1 ;;
esac

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# make_release <dir> <version>: tarball for the host target plus a decoy
# tarball for another target, and a sorted SHA256SUMS covering both.
make_release() {
  local dir="$1" version="$2" other name stage f
  mkdir -p "$dir"
  if [ "$target" = "x86_64-unknown-linux-musl" ]; then
    other="aarch64-unknown-linux-musl"
  else
    other="x86_64-unknown-linux-musl"
  fi
  for t in "$target" "$other"; do
    name="saiife-$version-$t"
    stage="$scratch/stage-$RANDOM-$name"
    mkdir -p "$stage/$name"
    cp "$SAIIFE_BIN" "$stage/$name/saiife"
    cp "$repo/LICENSE" "$repo/README.md" "$stage/$name/"
    tar -czf "$dir/$name.tar.gz" -C "$stage" "$name"
    rm -rf "$stage"
  done
  : >"$dir/SHA256SUMS"
  # The glob expands sorted, like the old `ls | sort`.
  for f in "$dir"/saiife-*.tar.gz; do
    printf '%s  %s\n' "$(sha256 "$f")" "$(basename "$f")" >>"$dir/SHA256SUMS"
  done
}

pass=0
fail=0
ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1: $2"; fail=$((fail + 1)); }

# run_install <case-dir> <release-dir> [env...]: runs install.sh with a fresh
# HOME, curl forced, and output captured in <case-dir>/out; sets $status.
run_install() {
  local case_dir="$1" rel="$2"
  shift 2
  mkdir -p "$case_dir/home"
  set +e
  env -i \
    PATH="${TEST_PATH:-/usr/bin:/bin:/usr/sbin:/sbin}" \
    HOME="$case_dir/home" \
    TMPDIR="$case_dir" \
    SAIIFE_DOWNLOAD_BASE="file://$rel/" \
    "$@" \
    sh "$installer" >"$case_dir/out" 2>&1
  status=$?
  set -e
}

# --- install_pinned_version ---------------------------------------------------
c="$scratch/pinned"
make_release "$c/rel" 0.1.0
run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
bin="$c/home/.local/bin/saiife"
if [ "$status" -eq 0 ] && [ -x "$bin" ] && "$bin" --version >/dev/null 2>&1 &&
  grep -q "saiife 0.1.0 installed to $c/home/.local/bin/saiife" "$c/out"; then
  ok install_pinned_version
else
  bad install_pinned_version "status=$status; $(cat "$c/out")"
fi

# --- install_latest -----------------------------------------------------------
c="$scratch/latest"
make_release "$c/rel" 0.2.0
run_install "$c" "$c/rel"
bin="$c/home/.local/bin/saiife"
if [ "$status" -eq 0 ] && [ -x "$bin" ] && "$bin" --version >/dev/null 2>&1 &&
  grep -q "saiife 0.2.0 installed" "$c/out"; then
  ok install_latest
else
  bad install_latest "status=$status; $(cat "$c/out")"
fi

# --- custom install dir (SAIIFE_INSTALL_DIR) ----------------------------------
c="$scratch/custom-dir"
make_release "$c/rel" 0.1.0
run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0 SAIIFE_INSTALL_DIR="$c/opt/bin"
if [ "$status" -eq 0 ] && [ -x "$c/opt/bin/saiife" ] &&
  [ ! -e "$c/home/.local/bin/saiife" ]; then
  ok install_dir_override
else
  bad install_dir_override "status=$status; $(cat "$c/out")"
fi

# --- checksum_mismatch_installs_nothing ---------------------------------------
c="$scratch/mismatch"
make_release "$c/rel" 0.1.0
printf 'corrupt' >>"$c/rel/saiife-0.1.0-$target.tar.gz"
run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
if [ "$status" -eq 1 ] && grep -q "saiife: checksum verification failed" "$c/out" &&
  [ ! -e "$c/home/.local/bin/saiife" ]; then
  ok checksum_mismatch_installs_nothing
else
  bad checksum_mismatch_installs_nothing "status=$status; $(cat "$c/out")"
fi

# --- missing_sums_line_installs_nothing ---------------------------------------
c="$scratch/missing-line"
make_release "$c/rel" 0.1.0
grep -v -- "-$target.tar.gz\$" "$c/rel/SHA256SUMS" >"$c/rel/SHA256SUMS.new"
mv "$c/rel/SHA256SUMS.new" "$c/rel/SHA256SUMS"
run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
if [ "$status" -eq 1 ] && grep -q "saiife: checksum verification failed" "$c/out" &&
  [ ! -e "$c/home/.local/bin/saiife" ]; then
  ok missing_sums_line_installs_nothing
else
  bad missing_sums_line_installs_nothing "status=$status; $(cat "$c/out")"
fi

# --- symlink_member_installs_nothing -----------------------------------------
# The tarball's saiife is a symlink to a private file outside the release, and
# SHA256SUMS matches it (whoever controls the tarball controls the sums too).
c="$scratch/symlink-member"
mkdir -p "$c/rel" "$c/stage/saiife-0.1.0-$target"
printf 'secret\n' >"$c/victim"
chmod 0600 "$c/victim"
ln -s "$c/victim" "$c/stage/saiife-0.1.0-$target/saiife"
tar -czf "$c/rel/saiife-0.1.0-$target.tar.gz" -C "$c/stage" "saiife-0.1.0-$target"
printf '%s  %s\n' "$(sha256 "$c/rel/saiife-0.1.0-$target.tar.gz")" \
  "saiife-0.1.0-$target.tar.gz" >"$c/rel/SHA256SUMS"
run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
perms="$(find "$c/victim" -perm 0600 -print)"
if [ "$status" -eq 1 ] && grep -q "not a regular file" "$c/out" &&
  [ ! -e "$c/home/.local/bin/saiife" ] && [ ! -L "$c/home/.local/bin/saiife" ] &&
  [ "$perms" = "$c/victim" ]; then
  ok symlink_member_installs_nothing
else
  bad symlink_member_installs_nothing "status=$status victim-still-0600=${perms:-no}; $(cat "$c/out")"
fi

# --- substring_sums_line_installs_nothing -------------------------------------
# The only line for the host tarball names x<filename>: no exact match.
for mode in pinned latest; do
  c="$scratch/substring-$mode"
  make_release "$c/rel" 0.1.0
  sed "s/  saiife-0.1.0-$target.tar.gz\$/  xsaiife-0.1.0-$target.tar.gz/" \
    "$c/rel/SHA256SUMS" >"$c/rel/SHA256SUMS.new"
  mv "$c/rel/SHA256SUMS.new" "$c/rel/SHA256SUMS"
  if [ "$mode" = pinned ]; then
    run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
  else
    run_install "$c" "$c/rel"
  fi
  if [ "$status" -eq 1 ] && grep -q "saiife: checksum verification failed" "$c/out" &&
    [ ! -e "$c/home/.local/bin/saiife" ]; then
    ok "substring_sums_line_installs_nothing ($mode)"
  else
    bad "substring_sums_line_installs_nothing ($mode)" "status=$status; $(cat "$c/out")"
  fi
done

# --- bad_version_rejected -----------------------------------------------------
c="$scratch/bad-version"
make_release "$c/rel" 0.1.0
run_install "$c" "$c/rel" SAIIFE_VERSION='1.0/../x'
if [ "$status" -eq 1 ] && grep -q "saiife: invalid version" "$c/out" &&
  [ ! -e "$c/home/.local/bin/saiife" ]; then
  ok bad_version_rejected
else
  bad bad_version_rejected "status=$status; $(cat "$c/out")"
fi

# --- unsupported_platform -----------------------------------------------------
# uname reports FreeBSD; curl/wget stubs record any download attempt.
c="$scratch/unsupported"
make_release "$c/rel" 0.1.0
mkdir -p "$c/stub"
cat >"$c/stub/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) echo FreeBSD ;;
  -m) echo x86_64 ;;
  *) echo FreeBSD ;;
esac
EOF
for tool in curl wget; do
  printf '#!/bin/sh\ntouch "%s/downloaded"\nexit 1\n' "$c" >"$c/stub/$tool"
done
chmod +x "$c/stub/"*
TEST_PATH="$c/stub:/usr/bin:/bin:/usr/sbin:/sbin" run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
if [ "$status" -eq 1 ] && grep -q "saiife: unsupported platform: FreeBSD/x86_64" "$c/out" &&
  [ ! -e "$c/downloaded" ] && [ ! -e "$c/home/.local/bin/saiife" ]; then
  ok unsupported_platform
else
  bad unsupported_platform "status=$status; $(cat "$c/out")"
fi

# --- path_hint ----------------------------------------------------------------
c="$scratch/path-hint"
make_release "$c/rel" 0.1.0
run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
if [ "$status" -eq 0 ] &&
  grep -qF "Add it to your PATH: export PATH=\"$c/home/.local/bin:\$PATH\"" "$c/out"; then
  ok path_hint
else
  bad path_hint "status=$status; $(cat "$c/out")"
fi

# --- no_path_hint_when_on_path ------------------------------------------------
c="$scratch/on-path"
make_release "$c/rel" 0.1.0
TEST_PATH="$c/home/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  run_install "$c" "$c/rel" SAIIFE_VERSION=0.1.0
if [ "$status" -eq 0 ] && ! grep -q "export PATH=" "$c/out"; then
  ok no_path_hint_when_on_path
else
  bad no_path_hint_when_on_path "status=$status; $(cat "$c/out")"
fi

echo "test-install: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
