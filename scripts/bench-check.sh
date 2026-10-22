#!/usr/bin/env bash
# Time the per-call cost of `saiife check` (the hook every agent tool call
# runs). Builds the release binary, sets up a throwaway project with its own
# HOME, data and audit dirs, runs `saiife init --agent claude` there, then
# prints the median wall time of N hook calls for a Bash and a Read payload.
#
# With --managed it times the locked-mode hook instead: it writes a system
# config (locked = true, socket and audit dirs in the scratch dir, the
# current user as the daemon user), starts `saiife daemon --system` in the
# background and prints the median and p95 of N `saiife check --managed`
# calls per payload (worker process + daemon ack).
#
# Usage: scripts/bench-check.sh [--managed] [N]   (default N = 50)
set -euo pipefail

managed=0
if [[ "${1:-}" == "--managed" ]]; then
  managed=1
  shift
fi
N="${1:-50}"
repo="$(cd "$(dirname "$0")/.." && pwd)"

cargo build --release --quiet --manifest-path "$repo/Cargo.toml" -p saiife
bin="${CARGO_TARGET_DIR:-$repo/target}/release/saiife"

# /tmp can have a tight per-user quota: keep scratch next to the repo.
tmp="$(mktemp -d -p "$(dirname "$repo")" saiife-bench.XXXXXX)"
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
ln -s "$bin" "$tmp/bin/saiife"
echo "# bench" >"$tmp/project/README.md"
mkdir -p "$tmp/project/src"

export HOME="$tmp/home"
export SAIIFE_DATA_DIR="$tmp/data"
export SAIIFE_AUDIT_DIR="$tmp/audit"
export PATH="$tmp/bin:$PATH"
unset CLAUDE_CONFIG_DIR CODEX_HOME

(cd "$tmp/project" && saiife init --agent claude >/dev/null)

payload() { # tool, input json
  printf '{"session_id":"bench","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"%s","tool_input":%s}' \
    "$tmp/project" "$1" "$2"
}
bash_payload="$(payload Bash '{"command":"git status && ls -la src"}')"
read_payload="$(payload Read "{\"file_path\":\"$tmp/project/README.md\"}")"

# Median wall time in ms of N calls with payload $1 (EPOCHREALTIME is in
# microseconds once the decimal point is dropped; needs bash 5).
median_ms() {
  local p="$1" i t0 t1
  local -a times=()
  for ((i = 0; i < N; i++)); do
    t0=${EPOCHREALTIME/[.,]/}
    saiife check --hook-exit --agent claude <<<"$p" >/dev/null
    t1=${EPOCHREALTIME/[.,]/}
    times+=($((t1 - t0)))
  done
  printf '%s\n' "${times[@]}" | sort -n | awk -v n="$N" '
    { a[NR] = $1 }
    END { m = (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2; printf "%.1f\n", m / 1000 }'
}

if [[ "$managed" == 0 ]]; then
  cd "$tmp/project"
  echo "bash: $(median_ms "$bash_payload") ms/call"
  echo "read: $(median_ms "$read_payload") ms/call"
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

# "median <m> ms, p95 <p> ms" of N managed calls with payload $1.
stats_ms() {
  local p="$1" i t0 t1
  local -a times=()
  for ((i = 0; i < N; i++)); do
    t0=${EPOCHREALTIME/[.,]/}
    saiife check --managed --system-config "$tmp/etc/config.toml" --agent claude <<<"$p" >/dev/null
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

cd "$tmp/project"
echo "managed bash: $(stats_ms "$bash_payload")/call"
echo "managed read: $(stats_ms "$read_payload")/call"
