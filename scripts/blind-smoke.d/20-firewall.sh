# OWNER-RUN ONLY (sourced by scripts/blind-smoke.sh; never run by agents).
# Plan 44 smoke: the leak firewall at full size. Runs the blind_firewall
# example over the dataset the data fragment built (10-data.sh, 3 000 000
# customers): 1 000 generated questions, half naming a random fixture
# customer (by name in English or Danish, or by email), half clean. Checks:
# every naming question was resolved locally (stand-in or a local pick) or
# blocked, every naming question sent raw was blocked, no clean question
# was blocked, nothing leaked, and the p99 firewall scan is under 200 ms.
# Prints the counts and the p50/p99 scan time. Defines smoke_firewall; no
# top-level effects.
#
# Owner prerequisites: run after the data fragment
# (`bash scripts/blind-smoke.sh --only data`), which leaves the dataset in
# $SMOKE_WORK/data/out/smoke.

P44_MAX_P99_MS=200

P44_DATASET=""
P44_LOG=""

p44_log() { printf '%s\n' "$*" >&2; }

# p44_result KEY VALUE: append KEY=VALUE to RESULTS.
p44_result() { RESULTS+=("$1=${2-}"); }

# p44_step LABEL CMD...: check, and return 1 when that check failed (the
# later steps need it).
p44_step() {
  local before="$FAILED"
  check "$@"
  [ "$FAILED" = "$before" ]
}

p44_have_dataset() {
  [ -f "$P44_DATASET/live/manifest.json" ] || {
    p44_log "no dataset at $P44_DATASET: run the data fragment first"
    return 1
  }
}

p44_run() {
  (cd "$REPO_ROOT" && cargo build --release -q -p saiife-shield --example blind_firewall) || return 1
  local bin="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/examples/blind_firewall"
  [ -x "$bin" ] || { p44_log "no $bin"; return 1; }
  # The example exits 1 on a leak; the log is checked line by line below.
  "$bin" "$P44_DATASET" | tee "$P44_LOG"
  [ "${PIPESTATUS[0]}" = 0 ]
}

# p44_field LINE-PREFIX FIELD: the number after FIELD on the log line that
# starts with LINE-PREFIX.
p44_field() {
  sed -n "s/^$1 .* $2 \\([0-9][0-9.]*\\).*\$/\\1/p" "$P44_LOG" | head -n 1
}

p44_no_leaks() {
  local n
  n="$(sed -n 's/^leaks \([0-9][0-9]*\)$/\1/p' "$P44_LOG")"
  p44_result firewall_leaks "$n"
  [ "$n" = 0 ]
}

p44_all_resolved_or_blocked() {
  local n
  n="$(sed -n 's/^unresolved \([0-9][0-9]*\)$/\1/p' "$P44_LOG")"
  [ "$n" = 0 ]
}

p44_probes_blocked() {
  local got of
  got="$(sed -n 's/^probes blocked \([0-9][0-9]*\) of \([0-9][0-9]*\)$/\1/p' "$P44_LOG")"
  of="$(sed -n 's/^probes blocked \([0-9][0-9]*\) of \([0-9][0-9]*\)$/\2/p' "$P44_LOG")"
  p44_result firewall_probes_blocked "$got/$of"
  [ -n "$got" ] && [ "$got" = "$of" ]
}

p44_clean_pass() {
  local passed blocked
  passed="$(sed -n 's/^clean passed \([0-9][0-9]*\) blocked \([0-9][0-9]*\)$/\1/p' "$P44_LOG")"
  blocked="$(sed -n 's/^clean passed \([0-9][0-9]*\) blocked \([0-9][0-9]*\)$/\2/p' "$P44_LOG")"
  p44_result firewall_clean_passed "$passed"
  p44_result firewall_clean_blocked "$blocked"
  [ -n "$passed" ] && [ "$passed" -gt 0 ] && [ "$blocked" = 0 ]
}

p44_fast_enough() {
  local p50 p99
  p50="$(p44_field scans p50_ms)"
  p99="$(p44_field scans p99_ms)"
  p44_result firewall_p50_ms "$p50"
  p44_result firewall_p99_ms "$p99"
  [ -n "$p99" ] || return 1
  # Milliseconds with two decimals: compare the whole part.
  [ "${p99%%.*}" -lt "$P44_MAX_P99_MS" ]
}

smoke_firewall() {
  P44_DATASET="$SMOKE_WORK/data/out/smoke"
  P44_LOG="$SMOKE_WORK/firewall.log"
  p44_step "firewall: the data fragment's dataset exists" p44_have_dataset || return 0
  check "firewall: blind_firewall ran without a leak" p44_run
  [ -s "$P44_LOG" ] || return 0
  check "firewall: no value leaked" p44_no_leaks
  check "firewall: every naming question resolved or blocked" p44_all_resolved_or_blocked
  check "firewall: every raw naming question blocked" p44_probes_blocked
  check "firewall: clean questions passed" p44_clean_pass
  check "firewall: p99 scan under ${P44_MAX_P99_MS} ms" p44_fast_enough
  p44_log "$(grep -E '^(naming|scans) ' "$P44_LOG" | tr '\n' ' ')"
}
