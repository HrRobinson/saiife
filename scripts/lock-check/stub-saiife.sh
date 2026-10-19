#!/usr/bin/env bash
# Stub saiife for the live lock checks: installed in the container as
# /opt/saiife/bin/saiife, the command the managed hooks run (§8.3). The real
# `saiife check --managed` is plan 9; this stub only behaves as the current
# check asks, so the harness can see how each agent treats a hook that
# allows, denies, crashes, hangs, ...
#
# It reads its mode from /run/lockcheck/mode.config-change when its args
# contain `--event config-change`, else from /run/lockcheck/mode (missing
# file = allow). It first appends one line to /run/lockcheck/calls.log:
#   <epoch> TAB <event: pre-tool|config-change> TAB <mode> TAB <stdin, newlines removed>
# then acts out the mode:
#   allow  exit 0, silent        deny   stderr "blocked by stub", exit 2
#   exit1  exit 1                exit3  exit 3, no output
#   panic  Rust-like panic, 101  segv   SIGSEGV itself
#   kill9  SIGKILL itself        hang   sleep LOCKCHECK_HANG_SECS (60), exit 0
# segv/kill9 send the real signal only in the container; with LC_ROOT set
# (offline tests on a host) they just exit 139/137, the status bash reports.
# It touches nothing else. With LC_ROOT set (offline tests) the
# /run/lockcheck paths are under $LC_ROOT.
#
#   echo '{"tool_name":"Bash"}' | stub-saiife.sh check --managed --hook-exit --agent claude
set -euo pipefail

run="${LC_ROOT:-}/run/lockcheck"
event="pre-tool"
prev=""
for arg in "$@"; do
  if [[ "$prev" == --event && "$arg" == config-change ]]; then
    event="config-change"
  fi
  prev="$arg"
done
modefile="$run/mode"
if [[ "$event" == config-change ]]; then
  modefile="$run/mode.config-change"
fi
mode=""
if [[ -r "$modefile" ]]; then
  read -r mode <"$modefile" || true
fi
mode="${mode:-allow}"

input="$(tr -d '\n\r' || true)"
printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "$event" "$mode" "$input" >>"$run/calls.log" 2>/dev/null || true

case "$mode" in
  allow) exit 0 ;;
  deny)
    echo "saiife-lockcheck: blocked by stub" >&2
    exit 2
    ;;
  exit1) exit 1 ;;
  exit3) exit 3 ;;
  panic)
    echo "thread 'main' panicked at stub" >&2
    exit 101
    ;;
  segv)
    # Offline tests (LC_ROOT set) only simulate the exit status: a real
    # SIGSEGV on a desktop host triggers core dumps and crash reporters.
    if [[ -z "${LC_ROOT:-}" ]]; then
      kill -SEGV $$
    fi
    exit 139
    ;;
  kill9)
    if [[ -z "${LC_ROOT:-}" ]]; then
      kill -KILL $$
    fi
    exit 137
    ;;
  hang)
    sleep "${LOCKCHECK_HANG_SECS:-60}"
    exit 0
    ;;
  *)
    echo "saiife-lockcheck: unknown stub mode '$mode'" >&2
    exit 2
    ;;
esac
