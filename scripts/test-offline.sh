#!/usr/bin/env bash
# Run the full test suite with networking disabled (Linux only).
# Supports the spec's "no network calls" rule: network use fails inside the
# namespace, so a test that needs the network cannot pass here.
#
# The tests run as the current user, not as root: the daemon tests start
# saiifed, which refuses to run as uid 0. A new network namespace has its
# loopback interface down, and the broker's TLS tests need 127.0.0.1, so an
# outer namespace mapped to root brings `lo` up, and a nested user namespace
# (`--map-user`, util-linux >= 2.38) maps the current user back to itself.
# Only loopback exists inside; there is still no route out.
set -euo pipefail
offline() {
  # shellcheck disable=SC2016  # expanded by the inner bash
  unshare --map-root-user --net bash -c '
    ip link set lo up
    exec unshare --user --map-user="$1" --map-group="$2" "${@:3}"
  ' offline "$(id -u)" "$(id -g)" "$@"
}
cargo test --workspace --no-run --quiet
# Sanity checks: inside the namespace there must be no network, and the
# tests must not run as root.
if offline curl -sS --max-time 3 https://example.com >/dev/null 2>&1; then
  echo "network is still reachable inside the namespace" >&2
  exit 1
fi
if [ "$(offline id -u)" != "$(id -u)" ]; then
  echo "the namespace does not keep the current uid" >&2
  exit 1
fi
offline cargo test --workspace --offline --quiet
