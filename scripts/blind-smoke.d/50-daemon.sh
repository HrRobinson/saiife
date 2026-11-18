# OWNER-RUN ONLY (sourced by scripts/blind-smoke.sh; never run by agents).
# Plan 47 smoke: Data Shield in a personal daemon (`saiife daemon --user`,
# HOME and XDG_* inside $SMOKE_WORK), the live tests that talk to the real
# world, and the hook latency.
#   - live_planner_answers: the real Anthropic API, one synthetic envelope
#     (nothing personal). Needs SAIIFE_BLIND_SMOKE_KEY_FILE (a file holding
#     your API key; read by the test, never printed or logged).
#   - the live Postgres test, only when SAIIFE_BLIND_SMOKE_PG_SOCKET is set
#     (a local Unix socket directory; read-only access), with
#     SAIIFE_TEST_PG_DB, _USER, _TABLE and _PASSWORD set as the test lists.
#   - hook latency: `bash scripts/bench-check.sh` (the developer hook path,
#     never --managed); the p50/p95 lines go into the results.
# Defines smoke_daemon; no top-level effects. Needs cargo and curl-free
# local tools only.

P47_WORK=""
P47_PID=""

p47_log() { printf '%s\n' "$*" >&2; }

# p47_step DESC CMD...: check, but returns non-zero when the step failed, so
# `p47_step ... || return 0` shows the failure in RESULTS and lets the later
# fragments run (blind-smoke.sh runs under set -e).
p47_step() {
  local before="$FAILED"
  check "$@"
  [ "$FAILED" = "$before" ]
}

# p47_result KEY VALUE: append KEY=VALUE to RESULTS.
p47_result() { RESULTS+=("$1=${2-}"); }

p47_build() {
  (cd "$REPO_ROOT" && cargo build --locked -q -p saiife) || return 1
}

# The personal daemon, its whole world under $P47_WORK.
p47_env() {
  export HOME="$P47_WORK/home"
  export XDG_CONFIG_HOME="$P47_WORK/xdg/config"
  export XDG_DATA_HOME="$P47_WORK/xdg/data"
  export XDG_STATE_HOME="$P47_WORK/xdg/state"
  export XDG_RUNTIME_DIR="$P47_WORK/run"
  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
  chmod 700 "$XDG_RUNTIME_DIR"
}

# Starts the daemon and waits (bounded) until it has made its Data Shield
# state dir (0700, under its state dir) or has stopped.
p47_daemon_start() {
  local bin="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/saiife"
  [ -x "$bin" ] || { p47_log "no $bin"; return 1; }
  "$bin" daemon --user >"$P47_WORK/daemon.log" 2>&1 &
  P47_PID=$!
  local i d
  for i in $(seq 1 50); do
    d="$(find "$P47_WORK/xdg" "$P47_WORK/home" -maxdepth 5 -type d -name blind 2>/dev/null | head -n 1)"
    if [ -n "$d" ]; then
      [ "$(stat -c %a "$d")" = 700 ] || { p47_log "$d is not 0700"; return 1; }
      return 0
    fi
    kill -0 "$P47_PID" 2>/dev/null || { p47_log "the daemon stopped; see $P47_WORK/daemon.log"; return 1; }
    sleep 0.2
  done
  p47_log "the daemon made no blind state dir; see $P47_WORK/daemon.log"
  return 1
}

p47_daemon_stop() {
  if [ -n "$P47_PID" ]; then
    kill "$P47_PID" 2>/dev/null || true
    wait "$P47_PID" 2>/dev/null || true
    P47_PID=""
  fi
}

# The daemon is still up after a moment, and its log holds no warning about
# Data Shield. (`saiife blind status` arrives with plan 48's CLI; the op is
# tested by crates/daemon/tests/blind_status.rs.)
p47_daemon_healthy() {
  kill -0 "$P47_PID" 2>/dev/null || return 1
  ! grep -qi "data shield is unavailable" "$P47_WORK/daemon.log"
}

p47_live_planner() {
  (cd "$REPO_ROOT" && SAIIFE_BLIND_LIVE_KEY_FILE="$SAIIFE_BLIND_SMOKE_KEY_FILE" \
    cargo test --locked -q -p saiife-daemon --test blind_model -- --ignored live_planner_answers)
}

p47_live_pg() {
  # The test reads SAIIFE_TEST_PG_DB, _USER, _TABLE and _PASSWORD itself.
  (cd "$REPO_ROOT" && SAIIFE_TEST_PG_HOST="$SAIIFE_BLIND_SMOKE_PG_SOCKET" \
    cargo test --locked -q -p saiife-daemon --test blind_data -- --ignored pg_live)
}

# The hook bench; its summary lines are copied into the results.
p47_bench() {
  (cd "$REPO_ROOT" && bash scripts/bench-check.sh) >"$P47_WORK/bench.out" 2>&1
  local rc=$?
  cat "$P47_WORK/bench.out"
  return $rc
}

smoke_daemon() {
  P47_WORK="$SMOKE_WORK/daemon"
  mkdir -p "$P47_WORK"
  chmod 700 "$P47_WORK"
  p47_step "daemon: build saiife" p47_build || return 0

  # The real-world tests run from the repo with the real HOME (cargo needs
  # it); the personal daemon runs in a subshell with its own.
  if [ -n "${SAIIFE_BLIND_SMOKE_KEY_FILE:-}" ]; then
    p47_step "daemon: the real planner answers one synthetic question" p47_live_planner || true
  else
    p47_log "SAIIFE_BLIND_SMOKE_KEY_FILE is not set: skipping the real planner test"
    p47_result daemon_live_planner "skipped"
  fi
  if [ -n "${SAIIFE_BLIND_SMOKE_PG_SOCKET:-}" ]; then
    p47_step "daemon: the live Postgres source builds a dataset" p47_live_pg || true
  else
    p47_result daemon_live_pg "skipped"
  fi

  if (
    p47_env
    trap p47_daemon_stop EXIT
    p47_daemon_start || exit 1
    sleep 1
    p47_daemon_healthy
  ); then
    check "daemon: a personal daemon starts and makes its Data Shield state" true
  else
    check "daemon: a personal daemon starts and makes its Data Shield state" false
  fi

  p47_step "daemon: hook latency (bench-check.sh)" p47_bench || return 0
  local line
  while IFS= read -r line; do
    case "$line" in
      *p50* | *p95* | *median*) p47_result daemon_bench "$line" ;;
    esac
  done <"$P47_WORK/bench.out"
}
