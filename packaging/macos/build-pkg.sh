#!/usr/bin/env bash
# Build the macOS pkg for one architecture (plan 18, Task 7).
#
#   build-pkg.sh <signed thin saiife binary> <version> <arm64|x86_64> <out dir>
#
# Writes <out dir>/saiife-<version>-<arch>.pkg, and beside it a .mode file
# holding "signed" or "unsigned". Prints the pkg path on stdout.
#
# One pkg per architecture, not a universal binary: `system install` copies
# the binary it runs from to /opt/saiife/bin/saiife and refuses a universal
# binary (binary.rs inspect_macho, spec 9.2 A4).
#
# CI-only: refuses to run outside GitHub Actions on macOS, because the signed
# mode imports a certificate into a keychain and calls Apple's notary
# service. Check it locally with `bash -n` and its refusal only.
#
# Mode, from the secrets:
#   signed    productbuild --sign, notarytool, stapler, pkgutil and spctl checks
#   unsigned  no identity, nothing else (::notice:: pkg unsigned); the release
#             leaves an unsigned pkg out
# The certificate is MACOS_INSTALLER_CERT_P12 (base64) with
# MACOS_INSTALLER_CERT_PASSWORD. Without those, plan 13's MACOS_SIGN_P12_BASE64
# with MACOS_SIGN_P12_PASSWORD is tried: it may hold the Installer identity too.
# With a certificate, APPLE_TEAM_ID, APPLE_NOTARY_APPLE_ID and
# APPLE_NOTARY_PASSWORD must be set as well: half a set fails the run.
#
# SAIIFE_PKG_PRINT_MODE=1 prints the mode from the secrets and stops.
set -euo pipefail

# The paths the package owns; crates/system/tests/packaging.rs checks them.
PAYLOAD_BINARY=usr/local/libexec/saiife/saiife
PAYLOAD_LINK=usr/local/bin/saiife
IDENTIFIER=com.saiife.pkg

die() { echo "::error::$*" >&2; exit 1; }

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "$(uname -s)" != Darwin ]; then
  echo "refusing: build-pkg.sh runs only in GitHub Actions on macOS" >&2
  exit 2
fi

# Prints "signed" or "unsigned"; fails naming what is missing.
pkg_mode() {
  local p12=${MACOS_INSTALLER_CERT_P12:-} pw=${MACOS_INSTALLER_CERT_PASSWORD:-} name missing=()
  if { [ -n "$p12" ] && [ -z "$pw" ]; } || { [ -z "$p12" ] && [ -n "$pw" ]; }; then
    echo "MACOS_INSTALLER_CERT_P12 and MACOS_INSTALLER_CERT_PASSWORD must be set together" >&2
    return 1
  fi
  if [ -z "$p12" ]; then
    p12=${MACOS_SIGN_P12_BASE64:-}
    pw=${MACOS_SIGN_P12_PASSWORD:-}
    if [ -z "$p12" ]; then
      echo unsigned
      return 0
    fi
    if [ -z "$pw" ]; then
      echo "MACOS_SIGN_P12_BASE64 is set without MACOS_SIGN_P12_PASSWORD" >&2
      return 1
    fi
  fi
  for name in APPLE_TEAM_ID APPLE_NOTARY_APPLE_ID APPLE_NOTARY_PASSWORD; do
    if [ -z "${!name:-}" ]; then missing+=("$name"); fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "a pkg certificate is set, but not: ${missing[*]}" >&2
    return 1
  fi
  echo signed
}

mode="$(pkg_mode)" || die "partial pkg signing secrets"
if [ -n "${SAIIFE_PKG_PRINT_MODE:-}" ]; then
  echo "$mode"
  exit 0
fi

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <signed thin saiife binary> <version> <arm64|x86_64> <out dir>" >&2
  exit 2
fi
bin=$1
version=$2
arch=$3
out=$4
case "$arch" in
  arm64 | x86_64) ;;
  *) die "arch must be arm64 or x86_64, got '$arch'" ;;
esac
# It goes into XML and file names.
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.+-]+)?$'; then
  die "version must look like 1.2.3 or 1.2.3-rc.1, got '$version'"
fi
[ -f "$bin" ] || die "no such binary: $bin"
[ "$(lipo -archs "$bin")" = "$arch" ] || die "$bin is not a thin $arch binary: $(lipo -archs "$bin")"
codesign --verify --strict "$bin" || die "$bin has no valid signature"
sig="$(codesign -d --verbose=4 "$bin" 2>&1)"
grep -Eq 'flags=0x[0-9a-f]+\(.*runtime' <<<"$sig" || die "$bin lacks the hardened runtime"

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
name="saiife-$version-$arch.pkg"
tmp="${RUNNER_TEMP:?RUNNER_TEMP is not set}"
stage="$(mktemp -d "$tmp/saiife-pkg.XXXXXX")"
kc="$tmp/saiife-pkg-$arch.keychain-db"
p12file="$tmp/saiife-pkg-$arch.p12"
oldkcs=()
imported=""
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  if [ -n "$imported" ]; then
    if [ "${#oldkcs[@]}" -gt 0 ]; then
      security list-keychains -d user -s "${oldkcs[@]}" >/dev/null 2>&1 || true
    fi
    security delete-keychain "$kc" >/dev/null 2>&1 || true
  fi
  rm -f "$p12file"
  rm -rf "$stage"
}
trap cleanup EXIT

# 1. The payload root.
payload="$stage/root"
mkdir -p "$payload/$(dirname "$PAYLOAD_BINARY")" "$payload/$(dirname "$PAYLOAD_LINK")"
cp "$bin" "$payload/$PAYLOAD_BINARY"
chmod 0755 "$payload/$PAYLOAD_BINARY"
ln -s "/$PAYLOAD_BINARY" "$payload/$PAYLOAD_LINK"

# 2. The component pkg, with postinstall.
export COPYFILE_DISABLE=1
chmod 0755 "$root/packaging/macos/scripts/postinstall"
pkgbuild --root "$payload" --scripts "$root/packaging/macos/scripts" \
  --identifier "$IDENTIFIER" --version "$version" --install-location / \
  --ownership recommended "$stage/saiife-component.pkg" >&2

sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" \
  "$root/packaging/macos/distribution.xml" >"$stage/distribution.xml"

# 3. The certificate, when there is one.
identity=""
if [ "$mode" = signed ]; then
  from_installer_secret=""
  if [ -n "${MACOS_INSTALLER_CERT_P12:-}" ]; then
    from_installer_secret=1
    p12b64=$MACOS_INSTALLER_CERT_P12
    p12pw=$MACOS_INSTALLER_CERT_PASSWORD
  else
    p12b64=$MACOS_SIGN_P12_BASE64
    p12pw=$MACOS_SIGN_P12_PASSWORD
  fi
  # The contents must be what the signature vouches for; Apple's notary
  # would refuse an ad-hoc binary anyway, later and less plainly.
  grep -q 'Authority=Developer ID Application' <<<"$sig" ||
    die "$bin is not signed with a Developer ID Application: refusing to sign a pkg around it"
  # Same trade-off as scripts/release/macos-sign.sh: these passwords travel
  # on argv; the runner is ephemeral and single-job, and the secrets are set
  # on tag pushes only.
  kcpw="$(openssl rand -hex 24)"
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line#\"}"
    line="${line%\"}"
    if [ -n "$line" ]; then oldkcs+=("$line"); fi
  done < <(security list-keychains -d user)
  imported=1
  security create-keychain -p "$kcpw" "$kc"
  security set-keychain-settings -lut 3600 "$kc"
  security unlock-keychain -p "$kcpw" "$kc"
  (umask 077 && printf '%s' "$p12b64" | base64 --decode >"$p12file")
  security import "$p12file" -k "$kc" -P "$p12pw" -T /usr/bin/productbuild -T /usr/bin/productsign >&2
  security set-key-partition-list -S apple-tool:,apple: -s -k "$kcpw" "$kc" >/dev/null
  security list-keychains -d user -s "$kc" ${oldkcs[@]+"${oldkcs[@]}"}
  identity="$(security find-identity -v "$kc" |
    sed -n 's/.*"\(Developer ID Installer: [^"]*\)".*/\1/p' | head -n 1 || true)"
  if [ -z "$identity" ]; then
    if [ -n "$from_installer_secret" ]; then
      die "MACOS_INSTALLER_CERT_P12 holds no Developer ID Installer identity"
    fi
    mode=unsigned
  fi
fi

# 4. The product archive.
pkg="$out/$name"
if [ "$mode" = signed ]; then
  productbuild --distribution "$stage/distribution.xml" --package-path "$stage" \
    --sign "$identity" --keychain "$kc" --timestamp "$pkg" >&2
else
  productbuild --distribution "$stage/distribution.xml" --package-path "$stage" "$pkg" >&2
  echo "::notice::pkg unsigned: no Developer ID Installer identity (MACOS_INSTALLER_CERT_P12 not set); the release leaves it out" >&2
fi

# 5. Notarize, staple and check.
if [ "$mode" = signed ]; then
  result="$(xcrun notarytool submit "$pkg" \
    --apple-id "$APPLE_NOTARY_APPLE_ID" --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_NOTARY_PASSWORD" --wait --output-format json)" ||
    { echo "$result" >&2; die "notarytool submit failed"; }
  echo "$result" >&2
  status="$(grep -o '"status" *: *"[^"]*"' <<<"$result" | head -n1 | sed 's/.*: *"\(.*\)"/\1/' || true)"
  [ "$status" = Accepted ] || die "notarization status is '${status:-unknown}', expected Accepted"
  xcrun stapler staple "$pkg" >&2
  xcrun stapler validate "$pkg" >&2
  pkgutil --check-signature "$pkg" >&2
  spctl -a -vv -t install "$pkg" >&2
fi

printf '%s\n' "$mode" >"$pkg.mode"
echo "$pkg"
