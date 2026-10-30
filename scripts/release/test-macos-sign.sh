#!/usr/bin/env bash
# Offline test for macos-sign.sh: secret-presence logic and the dry run.
# Runs on Linux. Stub tools on PATH fail the test if anything calls them.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/macos-sign.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir "$work/bin"
for tool in security codesign xcrun ditto; do
  printf '#!/bin/sh\necho "stub %s called" >&2\nexit 99\n' "$tool" > "$work/bin/$tool"
  chmod +x "$work/bin/$tool"
done

names=(MACOS_SIGN_P12_BASE64 MACOS_SIGN_P12_PASSWORD MACOS_SIGN_IDENTITY
  APPLE_TEAM_ID APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD)

fail=0
check() { echo "FAIL: $*" >&2; fail=1; }

# run_sign <mask>: bit i of mask sets names[i] to a dummy value.
run_sign() {
  local mask="$1" i
  local -a envs=(PATH="$work/bin:$PATH" GITHUB_ACTIONS=true SAIIFE_SIGN_DRY_RUN=1
    RUNNER_TEMP="$work")
  for i in "${!names[@]}"; do
    if (( (mask >> i) & 1 )); then envs+=("${names[$i]}=dummy-$i"); fi
  done
  rm -rf "$work/run"
  mkdir "$work/run"
  (cd "$work/run" && env -i HOME="$work" "${envs[@]}" bash "$script" target/saiife aarch64-apple-darwin)
}

for mask in $(seq 0 63); do
  rc=0
  out="$(run_sign "$mask" 2>&1)" || rc=$?
  case "$mask" in
    0)
      [ "$rc" -eq 0 ] || check "mask 0: exit $rc: $out"
      grep -q 'mode: ad-hoc' <<<"$out" || check "mask 0: not ad-hoc: $out"
      grep -q -- '--options runtime' <<<"$out" || check "mask 0: no --options runtime"
      if grep -q 'notarytool submit' <<<"$out"; then check "mask 0: notarytool in ad-hoc"; fi
      [ "$(cat "$work/run/dist/SIGNING-aarch64-apple-darwin.txt")" = ad-hoc ] \
        || check "mask 0: SIGNING file is not ad-hoc"
      ;;
    63)
      [ "$rc" -eq 0 ] || check "mask 63: exit $rc: $out"
      grep -q 'mode: developer-id' <<<"$out" || check "mask 63: not developer-id: $out"
      grep -q -- '--options runtime' <<<"$out" || check "mask 63: no --options runtime"
      grep -q 'notarytool submit' <<<"$out" || check "mask 63: no notarytool submit"
      if grep -q 'dummy-' <<<"$out"; then check "mask 63: a secret value was printed"; fi
      [ "$(cat "$work/run/dist/SIGNING-aarch64-apple-darwin.txt")" = developer-id ] \
        || check "mask 63: SIGNING file is not developer-id"
      ;;
    *)
      [ "$rc" -eq 1 ] || check "mask $mask: expected exit 1, got $rc"
      missing=()
      for i in "${!names[@]}"; do
        if ! (( (mask >> i) & 1 )); then missing+=("${names[$i]}"); fi
      done
      want="partial signing secrets: missing ${missing[*]}"
      grep -qF -- "$want" <<<"$out" || check "mask $mask: want '$want', got: $out"
      ;;
  esac
done

# Outside GitHub Actions the script refuses.
rc=0
out="$(cd "$work" && env -i PATH="$work/bin:$PATH" SAIIFE_SIGN_DRY_RUN=1 bash "$script" x aarch64-apple-darwin 2>&1)" || rc=$?
{ [ "$rc" -ne 0 ] && grep -q 'GitHub Actions' <<<"$out"; } \
  || check "no refusal outside GitHub Actions: rc=$rc $out"

# Bad usage.
rc=0
(cd "$work" && env -i PATH="$PATH" GITHUB_ACTIONS=true bash "$script" >/dev/null 2>&1) || rc=$?
[ "$rc" -ne 0 ] || check "no-argument run succeeded"

# Non-dry path against stubs: the notarytool status gate.
mkdir "$work/fake"
cat > "$work/fake/security" <<'STUB'
#!/bin/sh
if [ "$1" = list-keychains ] && [ "$2" = -d ] && [ "$#" -eq 3 ]; then
  echo '    "/Users/runner/Library/Keychains/login.keychain-db"'
fi
exit 0
STUB
cat > "$work/fake/codesign" <<'STUB'
#!/bin/sh
case "$1" in
  -d) echo "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1+2" >&2
      echo "Authority=Developer ID Application: Test (TEAMID1234)" >&2 ;;
esac
exit 0
STUB
cat > "$work/fake/ditto" <<'STUB'
#!/bin/sh
for last; do :; done
: > "$last"
STUB
cat > "$work/fake/xcrun" <<'STUB'
#!/bin/sh
case "$STUB_NOTARY" in
  accepted) echo '{"id":"x","status":"Accepted"}' ;;
  invalid) echo '{"id":"x","status":"Invalid"}' ;;
  *) echo 'this is not json' ;;
esac
STUB
chmod +x "$work/fake/security" "$work/fake/codesign" "$work/fake/ditto" "$work/fake/xcrun"
: > "$work/fake/saiife"

run_real() {
  rm -rf "$work/real"
  mkdir -p "$work/real/tmp"
  (cd "$work/real" && env -i HOME="$work" PATH="$work/fake:$PATH" GITHUB_ACTIONS=true \
    RUNNER_TEMP="$work/real/tmp" STUB_NOTARY="$1" \
    MACOS_SIGN_P12_BASE64=aGVsbG8= MACOS_SIGN_P12_PASSWORD=p MACOS_SIGN_IDENTITY=i \
    APPLE_TEAM_ID=t APPLE_NOTARY_APPLE_ID=a APPLE_NOTARY_PASSWORD=n \
    bash "$script" "$work/fake/saiife" aarch64-apple-darwin)
}

rc=0
out="$(run_real accepted 2>&1)" || rc=$?
[ "$rc" -eq 0 ] || check "notary Accepted failed: rc=$rc $out"
rc=0
out="$(run_real invalid 2>&1)" || rc=$?
{ [ "$rc" -ne 0 ] && grep -q "expected Accepted" <<<"$out"; } || check "notary Invalid did not fail: rc=$rc $out"
rc=0
out="$(run_real garbage 2>&1)" || rc=$?
{ [ "$rc" -ne 0 ] && grep -q "'unknown'" <<<"$out"; } || check "notary garbage did not fail as unknown: rc=$rc $out"

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "test-macos-sign: ok"
