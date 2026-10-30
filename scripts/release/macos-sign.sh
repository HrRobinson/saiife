#!/usr/bin/env bash
# Sign (and, with a Developer ID, notarize) one macOS release binary.
#
#   macos-sign.sh <binary> <target>
#
# CI-only: refuses to run outside GitHub Actions, because the developer-id
# mode imports a certificate into a keychain and calls Apple's notary service.
# Check it locally with `bash -n`, shellcheck and test-macos-sign.sh only.
#
# Mode, from the six secrets (all set, none set, or the run fails):
#   developer-id  hardened runtime + secure timestamp + notarization
#   ad-hoc        hardened runtime, no identity, no notarization (with a warning)
# Both write dist/SIGNING-<target>.txt holding the mode.
#
# SAIIFE_SIGN_DRY_RUN=1 prints the mode and the commands and runs none of them.
set -euo pipefail

SECRETS=(MACOS_SIGN_P12_BASE64 MACOS_SIGN_P12_PASSWORD MACOS_SIGN_IDENTITY
  APPLE_TEAM_ID APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD)

die() { echo "::error::$*" >&2; exit 1; }

# Prints "developer-id" or "ad-hoc"; fails naming the missing secrets.
signing_mode() {
  local name set=0 missing=()
  for name in "${SECRETS[@]}"; do
    if [ -n "${!name:-}" ]; then set=$((set + 1)); else missing+=("$name"); fi
  done
  if [ "$set" -eq "${#SECRETS[@]}" ]; then
    echo developer-id
  elif [ "$set" -eq 0 ]; then
    echo ad-hoc
  else
    echo "partial signing secrets: missing ${missing[*]}" >&2
    return 1
  fi
}

dry="${SAIIFE_SIGN_DRY_RUN:-}"

# step <display> <cmd> [args...]: show the command (secrets as $NAMES, never
# values); run it unless this is a dry run.
step() {
  local display="$1"
  shift
  echo "+ $display"
  if [ -z "$dry" ]; then "$@"; fi
}

# check_runtime <binary> [authority]: codesign -d must show the hardened runtime.
check_runtime() {
  local bin="$1" authority="${2:-}" info
  step "codesign --verify --strict --verbose=2 $bin" \
    codesign --verify --strict --verbose=2 "$bin"
  echo "+ codesign -d --verbose=4 $bin 2>&1 | grep runtime${authority:+, Authority=$authority}"
  if [ -z "$dry" ]; then
    info="$(codesign -d --verbose=4 "$bin" 2>&1)"
    grep -q 'runtime' <<<"$info" || die "$bin was not signed with the hardened runtime"
    if [ -n "$authority" ]; then
      grep -q "Authority=$authority" <<<"$info" || die "$bin is not signed by $authority"
    fi
  fi
}

main() {
  [ "${GITHUB_ACTIONS:-}" = true ] || die "macos-sign.sh runs only in GitHub Actions"
  [ "$#" -eq 2 ] || die "usage: macos-sign.sh <binary> <target>"
  local bin="$1" target="$2" mode
  case "$target" in
    *[!A-Za-z0-9_.-]*|"") die "bad target: $target" ;;
  esac
  if [ -z "$dry" ]; then
    [ -f "$bin" ] || die "no such binary: $bin"
  fi

  mode="$(signing_mode)" || die "$(signing_mode 2>&1 || true)"
  echo "signing mode: $mode"

  mkdir -p dist
  printf '%s\n' "$mode" > "dist/SIGNING-$target.txt"

  if [ "$mode" = ad-hoc ]; then
    echo "::warning::macOS binaries are not signed with a Developer ID or notarized: the signing secrets are not set"
    step "codesign --force --options runtime --sign - $bin" \
      codesign --force --options runtime --sign - "$bin"
    check_runtime "$bin"
    return 0
  fi

  # developer-id
  local tmp="${RUNNER_TEMP:-}"
  if [ -z "$tmp" ]; then
    [ -n "$dry" ] || die "RUNNER_TEMP is not set"
    tmp="${TMPDIR:-/tmp}"
  fi
  # Globals, not locals: the EXIT trap runs after main has returned.
  kc="$tmp/saiife-sign.keychain-db"
  p12="$tmp/saiife-sign.p12"
  zip="$tmp/saiife-notarize-$target.zip"
  local kcpw
  if [ -n "$dry" ]; then
    kcpw=dry-run
  else
    kcpw="$(openssl rand -hex 24)"
  fi
  # shellcheck disable=SC2329 # invoked by the EXIT trap
  cleanup() {
    if [ -z "$dry" ]; then
      security delete-keychain "$kc" >/dev/null 2>&1 || true
      rm -f "$p12" "$zip"
    fi
  }
  trap cleanup EXIT
  echo "+ trap: security delete-keychain $kc"

  step "security create-keychain -p <random> $kc" security create-keychain -p "$kcpw" "$kc"
  step "security set-keychain-settings -lut 3600 $kc" security set-keychain-settings -lut 3600 "$kc"
  step "security unlock-keychain -p <random> $kc" security unlock-keychain -p "$kcpw" "$kc"
  echo "+ base64 --decode \$MACOS_SIGN_P12_BASE64 > $p12"
  if [ -z "$dry" ]; then
    (umask 077 && printf '%s' "$MACOS_SIGN_P12_BASE64" | base64 --decode > "$p12")
  fi
  step "security import $p12 -k $kc -P \$MACOS_SIGN_P12_PASSWORD -T /usr/bin/codesign" \
    security import "$p12" -k "$kc" -P "$MACOS_SIGN_P12_PASSWORD" -T /usr/bin/codesign
  step "security set-key-partition-list -S apple-tool:,apple: -s -k <random> $kc" \
    security set-key-partition-list -S apple-tool:,apple: -s -k "$kcpw" "$kc"
  step "security list-keychains -d user -s $kc login.keychain-db" \
    security list-keychains -d user -s "$kc" login.keychain-db

  step "codesign --force --options runtime --timestamp --sign \$MACOS_SIGN_IDENTITY $bin" \
    codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$bin"
  check_runtime "$bin" "Developer ID Application"

  step "ditto -c -k --keepParent $bin $zip" ditto -c -k --keepParent "$bin" "$zip"
  echo "+ xcrun notarytool submit $zip --apple-id \$APPLE_NOTARY_APPLE_ID --team-id \$APPLE_TEAM_ID --password \$APPLE_NOTARY_PASSWORD --wait --output-format json"
  if [ -z "$dry" ]; then
    local result status
    result="$(xcrun notarytool submit "$zip" \
      --apple-id "$APPLE_NOTARY_APPLE_ID" --team-id "$APPLE_TEAM_ID" \
      --password "$APPLE_NOTARY_PASSWORD" --wait --output-format json)" \
      || { echo "$result"; die "notarytool submit failed"; }
    echo "$result"
    status="$(grep -o '"status" *: *"[^"]*"' <<<"$result" | head -n1 | sed 's/.*: *"\(.*\)"/\1/')"
    [ "$status" = Accepted ] || die "notarization status is '${status:-unknown}', expected Accepted"
  fi
  echo "notarized: $bin"
}

main "$@"
