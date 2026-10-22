#!/usr/bin/env bash
# Witness hook for the live lock checks: installed in the container as
# /opt/lockcheck/witness and registered as a second managed hook on every
# tool. It proves the agent attempted a tool call: a check only counts as
# `blocked` when the witness saw the call's nonce (no marker alone could be
# a model that never tried).
#
# Appends "<epoch> TAB <stdin, newlines removed>" to /run/lockcheck/witness.log
# (under $LC_ROOT in the offline tests), prints nothing, always exits 0.
#
#   echo '{"tool_name":"Bash"}' | witness.sh
set -euo pipefail

input="$(tr -d '\n\r' || true)"
printf '%s\t%s\n' "$(date +%s)" "$input" >>"${LC_ROOT:-}/run/lockcheck/witness.log" 2>/dev/null || true
exit 0
