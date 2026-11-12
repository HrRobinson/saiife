#!/usr/bin/env bash
# OWNER-RUN ONLY: boots real Cloud Hypervisor VMs through the saiife box
# driver. Agents never run this; they lint it (bash -n, shellcheck).
#
# What it does: sources every scripts/box-smoke.d/[0-9][0-9]-*.sh in order and
# runs the smoke_<name> function each defines (plans 35-40 add one fragment
# each), then prints an ok:/FAIL: line per check and a results block.
#
# What it touches:
#   - /dev/kvm (you need to be in the kvm group)
#   - the network, for `image build` only (pinned, checksum-verified downloads)
#   - disk under $SAIIFE_BOX_SMOKE_WORK (default: a new dir under
#     $XDG_STATE_HOME/saiife-box-smoke, or ~/.local/state/saiife-box-smoke)
#   - nothing under /etc, /var, /opt or /run; no sudo, nothing runs as root
#
# Usage:
#   bash scripts/box-smoke.sh [--list | --only <name> | --help]
#
# Fragments define smoke_<name> (name = the file name without the NN- prefix
# and .sh suffix, dashes turned into underscores) and call check <label> <cmd...>.
set -euo pipefail

SMOKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/box-smoke.d"
SMOKE_WORK="${SAIIFE_BOX_SMOKE_WORK:-${XDG_STATE_HOME:-$HOME/.local/state}/saiife-box-smoke}"
RESULTS=()
FAILED=0

log() { printf '%s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

refuse_root() {
  if [ "$(id -u)" = 0 ] || [ -n "${SUDO_USER:-}" ]; then
    die "run this as your own user, not root. Nothing in the box smoke needs root."
  fi
}

# check LABEL CMD...: run CMD, record ok:/FAIL: for LABEL.
check() {
  local label="$1"
  shift
  if "$@"; then
    RESULTS+=("ok: $label")
    printf 'ok: %s\n' "$label"
  else
    RESULTS+=("FAIL: $label")
    printf 'FAIL: %s\n' "$label"
    FAILED=$((FAILED + 1))
  fi
}

fragments() {
  local f
  for f in "$SMOKE_DIR"/[0-9][0-9]-*.sh; do
    [ -e "$f" ] && printf '%s\n' "$f"
  done
  return 0
}

fragment_name() {
  local n
  n="$(basename "$1" .sh)"
  n="${n#[0-9][0-9]-}"
  printf '%s' "${n//-/_}"
}

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }

only=""
case "${1:-}" in
  --help | -h) usage; exit 0 ;;
  --list) fragments | while read -r f; do printf '%s\n' "$(basename "$f")"; done; exit 0 ;;
  --only) only="${2:-}"; [ -n "$only" ] || die "--only needs a name" ;;
  "") ;;
  *) die "unknown argument: $1 (try --help)" ;;
esac

refuse_root # before $SMOKE_WORK exists
mkdir -p "$SMOKE_WORK"

ran=0
while read -r f; do
  [ -n "$f" ] || continue
  name="$(fragment_name "$f")"
  if [ -n "$only" ] && [ "$only" != "$name" ] && [ "$only" != "$(basename "$f" .sh)" ]; then
    continue
  fi
  # shellcheck source=/dev/null
  . "$f"
  fn="smoke_$name"
  declare -F "$fn" >/dev/null || die "$f does not define $fn"
  log "== $name"
  "$fn"
  ran=$((ran + 1))
done < <(fragments)

[ -z "$only" ] || [ "$ran" -gt 0 ] || die "no fragment named $only"

echo "----- BEGIN BOX SMOKE RESULTS -----"
for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do echo "$r"; done
echo "fragments: $ran, failed checks: $FAILED"
echo "----- END BOX SMOKE RESULTS -----"
[ "$FAILED" = 0 ]
