#!/usr/bin/env bash
# Run the full test suite with networking disabled (Linux only).
# Supports the spec's "no network calls" rule: network use fails inside the
# namespace, so a test that needs the network cannot pass here.
#
# The user namespace maps the current user to itself (`--map-current-user`,
# util-linux >= 2.38), not to root: the daemon tests start saiifed, which
# refuses to run as uid 0.
set -euo pipefail
offline() { unshare --map-current-user --net "$@"; }
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
