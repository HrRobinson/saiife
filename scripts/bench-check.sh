#!/usr/bin/env bash
# Time the per-call cost of `saiife check` (the hook every agent tool call
# runs). Builds the release binary, sets up a throwaway project with its own
# HOME, data and audit dirs, runs `saiife init --agent claude` there, then
# prints the median and p95 wall time of N hook calls for a Bash and a Read
# payload, and on Windows (Git Bash) for a PowerShell payload too.
#
# With --managed it times the locked-mode hook instead: it writes a system
# config (locked = true, socket and audit dirs in the scratch dir, the
# current user as the daemon user), starts `saiife daemon --system` in the
# background and prints the median and p95 of N `saiife check --managed`
# calls per payload (worker process + daemon ack).
#
# With BENCH_MAX_P95_MS=<ms> it exits 1 when a payload's p95 is above that
# budget (the macOS CI test job uses 40 for --managed; the windows-latest test
# job uses 130 for the developer hook, which allows for slow runners; the planned
# speed-up should tighten it).
#
# On Windows (or with BENCH_SPLIT=1 anywhere) the same N calls of cheaper things
# come first, so a number over budget can be read: a program of Git Bash's own, the
# release binary and its fresh copy doing nothing, and `explain`, which loads every
# pack and judges one line but writes no audit record. They have no budget.
#
# With SAIIFE_BENCH_BIN=<file> it times that binary and builds nothing, so two
# builds can be compared with the same script. SAIIFE_BENCH_TMP=<dir> is where
# the scratch dir goes (default: next to the repo, then the system's).
#
# Usage: [BENCH_MAX_P95_MS=<ms>] scripts/bench-check.sh [--managed] [N]   (default N = 50)
set -euo pipefail

managed=0
if [[ "${1:-}" == "--managed" ]]; then
  managed=1
  shift
fi
N="${1:-50}"
max_p95="${BENCH_MAX_P95_MS:-}"
if [[ -n "$max_p95" ]]; then
  if ! [[ "$max_p95" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "BENCH_MAX_P95_MS must be a number of milliseconds, not \"$max_p95\"" >&2
    exit 2
  fi
fi
# EPOCHREALTIME is bash 5 (macOS's /bin/bash is 3.2: run this with a newer bash).
if [[ -z "${EPOCHREALTIME:-}" ]]; then
  echo "bench-check.sh needs bash 5 or later (EPOCHREALTIME); this is bash $BASH_VERSION" >&2
  exit 2
fi
repo="$(cd "$(dirname "$0")/.." && pwd)"

# Git Bash on Windows: the binary has its extension, and there is no daemon yet.
windows=0
exe=""
case "${OSTYPE:-}" in
  msys* | cygwin*)
    windows=1
    exe=".exe"
    ;;
esac
if [[ "$windows" == 1 && "$managed" == 1 ]]; then
  echo "--managed needs locked mode, which Windows does not have yet (plan 19b)" >&2
  exit 2
fi

if [[ -n "${SAIIFE_BENCH_BIN:-}" ]]; then
  bin="$SAIIFE_BENCH_BIN"
else
  cargo build --release --quiet --manifest-path "$repo/Cargo.toml" -p saiife
  bin="${CARGO_TARGET_DIR:-$repo/target}/release/saiife$exe"
fi

# /tmp can have a tight per-user quota: keep scratch next to the repo. A
# template path, not -p: BSD mktemp (macOS) has no -p. The fallback is for a
# parent that cannot be written, such as a CI checkout's on Windows.
tmp="$(mktemp -d "${SAIIFE_BENCH_TMP:-$(dirname "$repo")}/saiife-bench.XXXXXX" 2>/dev/null || mktemp -d)"
daemon_pid=""
cleanup() {
  if [[ -n "$daemon_pid" ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
mkdir -p "$tmp/project" "$tmp/home" "$tmp/data" "$tmp/audit" "$tmp/bin"
printf '#!/bin/sh\nexit 0\n' >"$tmp/bin/claude"
chmod +x "$tmp/bin/claude"
if [[ "$windows" == 1 ]]; then
  # A symlink needs a privilege on Windows, and `ln -s` would copy anyway.
  cp "$bin" "$tmp/bin/saiife$exe"
  printf '@exit /b 0\r\n' >"$tmp/bin/claude.cmd"
else
  ln -s "$bin" "$tmp/bin/saiife"
fi
echo "# bench" >"$tmp/project/README.md"
mkdir -p "$tmp/project/src"

export HOME="$tmp/home"
if [[ "$windows" == 1 ]]; then
  USERPROFILE="$(cygpath -w "$tmp/home")"
  export USERPROFILE
fi
export SAIIFE_DATA_DIR="$tmp/data"
export SAIIFE_AUDIT_DIR="$tmp/audit"
export PATH="$tmp/bin:$PATH"
unset CLAUDE_CONFIG_DIR CODEX_HOME

(cd "$tmp/project" && saiife init --agent claude >/dev/null)

# Forward slashes: the JSON below would need its backslashes escaped.
project="$tmp/project"
if [[ "$windows" == 1 ]]; then
  project="$(cygpath -m "$tmp/project")"
fi
payload() { # tool, input json
  printf '{"session_id":"bench","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"%s","tool_input":%s}' \
    "$project" "$1" "$2"
}
bash_payload="$(payload Bash '{"command":"git status && ls -la src"}')"
read_payload="$(payload Read "{\"file_path\":\"$project/README.md\"}")"
pwsh_payload="$(payload PowerShell '{"command":"git status; Get-ChildItem -Recurse src"}')"

# "median <m> ms, p95 <p> ms" of N timed calls: payload $1 on stdin to the
# command in the remaining arguments (EPOCHREALTIME is in microseconds once
# the decimal point is dropped; needs bash 5).
stats_ms() {
  local p="$1" i t0 t1
  shift
  local -a times=()
  for ((i = 0; i < N; i++)); do
    t0=${EPOCHREALTIME/[.,]/}
    "$@" <<<"$p" >/dev/null
    t1=${EPOCHREALTIME/[.,]/}
    times+=($((t1 - t0)))
  done
  printf '%s\n' "${times[@]}" | sort -n | awk -v n="$N" '
    { a[NR] = $1 }
    END {
      m = (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
      k = int((n * 95 + 99) / 100); if (k < 1) k = 1
      printf "median %.1f ms, p95 %.1f ms\n", m / 1000, a[k] / 1000
    }'
}

# `over_budget <stats line>`: true when its p95 is above BENCH_MAX_P95_MS.
over_budget() {
  [[ -n "$max_p95" ]] || return 1
  awk -v max="$max_p95" '
    { for (i = 1; i < NF; i++) if ($i == "p95") { p = $(i + 1) + 0; found = 1 } }
    END { exit !(found && p > max + 0) }' <<<"$1"
}

# Each payload's numbers, and the budget's verdict over all of them. $1 is the
# line's label prefix, the rest the command to time.
report() {
  local prefix="$1" kind p line over=0
  shift
  local -a kinds=(bash read)
  if [[ "$windows" == 1 ]]; then kinds+=(powershell); fi
  for kind in "${kinds[@]}"; do
    case "$kind" in
      bash) p="$bash_payload" ;;
      read) p="$read_payload" ;;
      *) p="$pwsh_payload" ;;
    esac
    line="$(stats_ms "$p" "$@")"
    echo "$prefix$kind: $line/call"
    if over_budget "$line"; then
      echo "$prefix$kind: p95 is above the budget of $max_p95 ms" >&2
      over=1
    fi
  done
  if [[ -n "$max_p95" ]]; then
    if [[ "$over" == 1 ]]; then
      exit 1
    fi
    echo "p95 within the budget of $max_p95 ms"
  fi
}

# What a hook call's time is made of, in steps that each add one thing. Printed
# before the budget's verdict, which ends the script.
step() {
  local label="$1"
  shift
  echo "baseline $label: $(stats_ms "" "$@")/call"
}

if [[ "$managed" == 0 ]]; then
  cd "$tmp/project"
  if [[ "$windows" == 1 || -n "${BENCH_SPLIT:-}" ]]; then
    # Not `true`: that is a bash builtin, and starts no process.
    step "process start only (/usr/bin/true)" /usr/bin/true
    step "saiife --version, the release binary" "$bin" --version
    step "saiife --version, its fresh copy on PATH" saiife --version
    step "saiife explain, all packs and one line" saiife explain 'git status && ls -la src'
  fi
  report "" saiife check --hook-exit --agent claude
  exit 0
fi

# Locked mode: a TestDaemon-style config, every path in the scratch dir.
mkdir -p "$tmp/etc" "$tmp/state"
cat >"$tmp/etc/config.toml" <<EOF
version = 2
locked = true

[daemon]
user = "$(id -un)"
socket_dir = "$tmp/run"

[audit]
dir = "$tmp/daemon-audit"
EOF
saiife daemon --system --config "$tmp/etc/config.toml" --state-dir "$tmp/state" \
  2>"$tmp/daemon.stderr" </dev/null &
daemon_pid=$!
for ((i = 0; i < 250; i++)); do
  [[ -S "$tmp/run/saiife.sock" ]] && break
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    echo "daemon exited: $(cat "$tmp/daemon.stderr")" >&2
    exit 1
  fi
  sleep 0.02
done
if [[ ! -S "$tmp/run/saiife.sock" ]]; then
  echo "daemon did not come up: $(cat "$tmp/daemon.stderr")" >&2
  exit 1
fi

cd "$tmp/project"
report "managed " saiife check --managed --system-config "$tmp/etc/config.toml" --agent claude
