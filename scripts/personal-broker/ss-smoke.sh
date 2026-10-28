#!/usr/bin/env bash
# CI ONLY. Proves the personal broker's vault key lands in a real Secret
# Service (gnome-keyring) and survives a broker restart. Do not run this on a
# developer machine: it starts a keyring daemon and a broker.
#
# Needs: dbus-run-session, gnome-keyring-daemon, secret-tool,
# python3-secretstorage, a built saiife.
# Usage: SAIIFE_BIN=target/debug/saiife bash scripts/personal-broker/ss-smoke.sh
set -euo pipefail

if [ -z "${CI:-}" ] || [ "${GITHUB_ACTIONS:-}" != "true" ]; then
  echo "ss-smoke.sh runs in GitHub Actions only (CI and GITHUB_ACTIONS=true)" >&2
  exit 2
fi

if [ -z "${SS_SMOKE_INNER:-}" ]; then
  # Never reuse an inherited session bus: dbus-run-session makes a fresh one.
  unset DBUS_SESSION_BUS_ADDRESS
  SAIIFE_BIN="$(realpath "${SAIIFE_BIN:-target/debug/saiife}")"
  export SAIIFE_BIN SS_SMOKE_INNER=1
  exec dbus-run-session -- bash "$0"
fi

root="$(mktemp -d -p "${RUNNER_TEMP:-${TMPDIR:-/tmp}}" ss.XXXXXX)"
broker_pid=""
keyring_pid=""
cleanup() {
  if [ -n "$keyring_pid" ]; then
    kill "$keyring_pid" 2>/dev/null || true
  fi
  if [ -n "$broker_pid" ]; then
    kill "$broker_pid" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

export HOME="$root/home"
export XDG_RUNTIME_DIR="$root/run"
export XDG_CONFIG_HOME="$root/config"
export XDG_STATE_HOME="$root/state"
export XDG_DATA_HOME="$root/data"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_DATA_HOME"
mkdir -m 0700 "$XDG_RUNTIME_DIR"

# A random keyring password and a random secret value, built at run time.
pw="$(head -c 18 /dev/urandom | base64 | tr -d '/+=\n')"
val="v-$(head -c 18 /dev/urandom | base64 | tr -d '/+=\n')"

# Start a fresh keyring, unlocked by the random password (no prompt, no UI).
eval "$(printf '%s' "$pw" | gnome-keyring-daemon --unlock --components=secrets)"
export GNOME_KEYRING_CONTROL SSH_AUTH_SOCK 2>/dev/null || true
# The PID gnome-keyring-daemon reports is the one this script started.
keyring_pid="${GNOME_KEYRING_PID:-}"

start_broker() {
  "$SAIIFE_BIN" daemon --user >"$root/broker.log" 2>&1 &
  broker_pid=$!
  for _ in $(seq 1 100); do
    if [ -S "$XDG_RUNTIME_DIR/saiife/saiife.sock" ]; then
      return 0
    fi
    sleep 0.1
  done
  echo "broker did not start:" >&2
  cat "$root/broker.log" >&2
  exit 1
}

stop_broker() {
  kill "$broker_pid"
  wait "$broker_pid" 2>/dev/null || true
  broker_pid=""
}

count_items() {
  secret-tool search --all application saiife saiife-item vault-key 2>&1 |
    grep -c '^\[' || true
}

start_broker
printf '%s\n' "$val" |
  "$SAIIFE_BIN" secret add smoke --kind token --service github --from-file /dev/stdin

# Exactly one keychain item, and its value is the 32-byte key.
n="$(count_items)"
if [ "$n" != 1 ]; then
  echo "expected 1 vault-key item, found $n" >&2
  exit 1
fi
# The key is raw application/octet-stream bytes, usually not valid UTF-8, so
# `secret-tool lookup` cannot print it. Read it as bytes through
# python3-secretstorage instead.
len="$(python3 -I - <<'PY'
import secretstorage

conn = secretstorage.dbus_init()
items = list(
    secretstorage.search_items(
        conn, {"application": "saiife", "saiife-item": "vault-key"}
    )
)
if len(items) != 1:
    print("items=%d" % len(items))
else:
    print(len(items[0].get_secret()))
PY
)"
if [ "$len" != 32 ]; then
  echo "expected a 32-byte key, got $len" >&2
  exit 1
fi

# The secret survives a restart, and no second key appears.
stop_broker
start_broker
listing="$("$SAIIFE_BIN" secret list)"
if ! grep -q '^smoke' <<<"$listing"; then
  echo "secret lost after restart" >&2
  exit 1
fi
n="$(count_items)"
if [ "$n" != 1 ]; then
  echo "restart left $n vault-key items" >&2
  exit 1
fi
if grep -rqF "$val" "$XDG_STATE_HOME" "$XDG_DATA_HOME"; then
  echo "the secret value is on disk in clear" >&2
  exit 1
fi

echo "ss-smoke: ok"
