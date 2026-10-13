#!/usr/bin/env bash
# Run the full test suite with networking disabled (Linux only).
# Proves the spec's "no network calls" rule: any network use fails a test.
set -euo pipefail
cargo test --workspace --no-run --quiet
# Sanity check: inside the namespace there must be no network.
if unshare -rn curl -sS --max-time 3 https://example.com >/dev/null 2>&1; then
  echo "network is still reachable inside the namespace" >&2
  exit 1
fi
unshare -rn cargo test --workspace --offline --quiet
