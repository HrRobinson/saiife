#!/usr/bin/env bash
# Decide how one Windows release binary is signed.
#
#   windows-sign-mode.sh <target>
#
# Reads six variables (the Azure Artifact Signing settings; release.yml passes
# them only on v* tag pushes, so PRs and forks see none):
#   WINDOWS_SIGN_AZURE_TENANT_ID  WINDOWS_SIGN_AZURE_CLIENT_ID
#   WINDOWS_SIGN_AZURE_CLIENT_SECRET  WINDOWS_SIGN_ENDPOINT
#   WINDOWS_SIGN_ACCOUNT  WINDOWS_SIGN_PROFILE
#
#   all set   artifact-signing
#   none set  unsigned (with a ::warning::, never a failure)
#   some set  exit 1: partial signing secrets: missing <names>
#
# The mode goes to stdout, to dist/SIGNING-<target>.txt and, when set, to
# $GITHUB_OUTPUT as mode=<mode>. Secret values are never printed. It calls no
# signing tool, so it is safe to run anywhere.
set -euo pipefail

SECRETS=(WINDOWS_SIGN_AZURE_TENANT_ID WINDOWS_SIGN_AZURE_CLIENT_ID
  WINDOWS_SIGN_AZURE_CLIENT_SECRET WINDOWS_SIGN_ENDPOINT WINDOWS_SIGN_ACCOUNT
  WINDOWS_SIGN_PROFILE)

[ "$#" -eq 1 ] && [ -n "$1" ] || {
  echo "usage: windows-sign-mode.sh <target>" >&2
  exit 2
}
target="$1"

set_count=0
missing=()
for name in "${SECRETS[@]}"; do
  if [ -n "${!name:-}" ]; then set_count=$((set_count + 1)); else missing+=("$name"); fi
done

if [ "$set_count" -eq "${#SECRETS[@]}" ]; then
  mode=artifact-signing
elif [ "$set_count" -eq 0 ]; then
  mode=unsigned
  echo "::warning::Windows binaries are not Authenticode-signed: the signing secrets are not set" >&2
else
  echo "::error::partial signing secrets: missing ${missing[*]}" >&2
  echo "partial signing secrets: missing ${missing[*]}" >&2
  exit 1
fi

mkdir -p dist
printf '%s\n' "$mode" > "dist/SIGNING-$target.txt"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "mode=$mode" >> "$GITHUB_OUTPUT"
fi
echo "$mode"
