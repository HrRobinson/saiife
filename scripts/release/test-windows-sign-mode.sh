#!/usr/bin/env bash
# Offline test for windows-sign-mode.sh: every combination of the six signing
# variables maps to its mode, and a partial set names the missing ones.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/windows-sign-mode.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

names=(WINDOWS_SIGN_AZURE_TENANT_ID WINDOWS_SIGN_AZURE_CLIENT_ID
  WINDOWS_SIGN_AZURE_CLIENT_SECRET WINDOWS_SIGN_ENDPOINT WINDOWS_SIGN_ACCOUNT
  WINDOWS_SIGN_PROFILE)
target=x86_64-pc-windows-msvc

fail=0
check() { echo "FAIL: $*" >&2; fail=1; }

# run_mode <mask>: bit i of mask sets names[i] to a dummy value. stdout is the
# mode; stderr carries the warning or the error.
run_mode() {
  local mask="$1" i
  local -a envs=()
  for i in "${!names[@]}"; do
    if (( (mask >> i) & 1 )); then envs+=("${names[$i]}=dummy-$i"); fi
  done
  rm -rf "$work/run"
  mkdir "$work/run"
  (cd "$work/run" && env -i PATH="$PATH" HOME="$work" "${envs[@]}" bash "$script" "$target")
}

for mask in $(seq 0 63); do
  rc=0
  out="$(run_mode "$mask" 2>"$work/err")" || rc=$?
  err="$(cat "$work/err")"
  case "$mask" in
    0)
      [ "$rc" -eq 0 ] || check "mask 0: exit $rc: $err"
      [ "$out" = unsigned ] || check "mask 0: stdout is '$out', want unsigned"
      grep -qF '::warning::Windows binaries are not Authenticode-signed: the signing secrets are not set' <<<"$err" \
        || check "mask 0: no warning: $err"
      [ "$(cat "$work/run/dist/SIGNING-$target.txt")" = unsigned ] || check "mask 0: SIGNING file"
      ;;
    63)
      [ "$rc" -eq 0 ] || check "mask 63: exit $rc: $err"
      [ "$out" = artifact-signing ] || check "mask 63: stdout is '$out', want artifact-signing"
      if grep -q 'dummy-' <<<"$out$err"; then check "mask 63: a secret value was printed"; fi
      [ "$(cat "$work/run/dist/SIGNING-$target.txt")" = artifact-signing ] || check "mask 63: SIGNING file"
      ;;
    *)
      [ "$rc" -eq 1 ] || check "mask $mask: expected exit 1, got $rc"
      missing=()
      for i in "${!names[@]}"; do
        if ! (( (mask >> i) & 1 )); then missing+=("${names[$i]}"); fi
      done
      want="partial signing secrets: missing ${missing[*]}"
      grep -qF -- "$want" <<<"$err" || check "mask $mask: want '$want', got: $err"
      if [ -e "$work/run/dist/SIGNING-$target.txt" ]; then check "mask $mask: wrote a SIGNING file"; fi
      ;;
  esac
done

# The mode also goes to $GITHUB_OUTPUT when set.
rm -rf "$work/run"
mkdir "$work/run"
(cd "$work/run" && env -i PATH="$PATH" GITHUB_OUTPUT="$work/out" bash "$script" "$target" >/dev/null 2>&1)
grep -qx 'mode=unsigned' "$work/out" || check "GITHUB_OUTPUT lacks mode=unsigned"

# Bad usage.
rc=0
(cd "$work" && env -i PATH="$PATH" bash "$script" >/dev/null 2>&1) || rc=$?
[ "$rc" -ne 0 ] || check "no-argument run succeeded"

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "test-windows-sign-mode: ok"
