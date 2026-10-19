#!/usr/bin/env bash
# saiife demo: install the Claude Code hook into a throwaway project and feed
# it three recorded Claude Code PreToolUse calls that must all be blocked.
#
# Everything happens inside a fresh sandbox directory (from `mktemp -d`,
# honoring TMPDIR). HOME, the saiife data and audit dirs and the XDG dirs all
# point into it, so the real home is never read or written.
#
#   bash scripts/demo.sh                     # builds the release binary first
#   SAIIFE_BIN=target/release/saiife bash scripts/demo.sh
#   KEEP=1 bash scripts/demo.sh              # keep the sandbox afterwards
#
# Exit 0 only if all three calls were blocked and the HTML report was written.
set -euo pipefail

# --- 1. Sandbox first, before anything else runs. ---------------------------
sandbox="$(mktemp -d)"
sandbox="$(cd "$sandbox" && pwd -P)"
real_home="${HOME:-}"
# Called from the EXIT trap below.
# shellcheck disable=SC2317
cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "sandbox kept: $sandbox"
  else
    rm -rf "$sandbox"
  fi
}
trap cleanup EXIT

# cargo and rustup locate themselves through HOME; pin them to the real
# toolchain before HOME moves (only needed when this script builds).
if [ -z "${SAIIFE_BIN:-}" ] && [ -n "$real_home" ]; then
  if [ -z "${CARGO_HOME:-}" ] && [ -d "$real_home/.cargo" ]; then
    export CARGO_HOME="$real_home/.cargo"
  fi
  if [ -z "${RUSTUP_HOME:-}" ] && [ -d "$real_home/.rustup" ]; then
    export RUSTUP_HOME="$real_home/.rustup"
  fi
fi

mkdir -p "$sandbox/home" "$sandbox/data" "$sandbox/audit" "$sandbox/bin" \
  "$sandbox/xdg/config" "$sandbox/xdg/data" "$sandbox/xdg/cache" "$sandbox/xdg/state"
export HOME="$sandbox/home"
export SAIIFE_DATA_DIR="$sandbox/data"
export SAIIFE_AUDIT_DIR="$sandbox/audit"
export XDG_CONFIG_HOME="$sandbox/xdg/config"
export XDG_DATA_HOME="$sandbox/xdg/data"
export XDG_CACHE_HOME="$sandbox/xdg/cache"
export XDG_STATE_HOME="$sandbox/xdg/state"

case "$HOME" in
  "$sandbox"/*) ;;
  *)
    echo "demo: HOME ($HOME) is not inside the sandbox ($sandbox); aborting" >&2
    exit 1
    ;;
esac
if [ -n "$real_home" ] && [ "$HOME" = "$real_home" ]; then
  echo "demo: HOME is still the real home; aborting" >&2
  exit 1
fi

start=$SECONDS
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

# --- 2. The binary. ---------------------------------------------------------
if [ -n "${SAIIFE_BIN:-}" ]; then
  case "$SAIIFE_BIN" in
    /*) bin="$SAIIFE_BIN" ;;
    *) bin="$(pwd -P)/$SAIIFE_BIN" ;;
  esac
else
  echo "== building saiife (cargo build --release)"
  (cd "$repo" && cargo build --release -q)
  bin="$repo/target/release/saiife"
fi
if [ ! -x "$bin" ]; then
  echo "demo: no saiife binary at $bin" >&2
  exit 1
fi
# A copy inside the sandbox, first on PATH: the installed hook runs this one.
cp "$bin" "$sandbox/bin/saiife"
export PATH="$sandbox/bin:$PATH"

# --- 3. A project with a secret, hooked up. ---------------------------------
project="$sandbox/home/app"
# saiife init finds its project by the nearest .saiife/config.toml or by an
# integrity record in the data dir. The data dir here is the sandbox's own,
# so only a config file can pull init (and the hook) to another project:
# refuse if TMPDIR sits inside one.
d="$sandbox"
while :; do
  if [ -e "$d/.saiife/config.toml" ]; then
    echo "demo: $d/.saiife/config.toml exists above the sandbox; saiife would act on" >&2
    echo "  that project instead. Set TMPDIR to a folder outside any saiife project." >&2
    exit 1
  fi
  [ "$d" = "/" ] && break
  d="$(dirname "$d")"
done
mkdir -p "$project"
printf 'API_KEY=demo-not-a-real-key\n' >"$project/.env"
cd "$project"

echo
echo "== saiife init --agent claude"
saiife init --agent claude
echo
echo "== saiife status"
saiife status

# --- 4. Three recorded Claude Code PreToolUse calls. ------------------------
# Same shape as crates/cli/tests/fixtures/claude/*.json.
jstr() { # escape backslashes and quotes for a JSON string (TMPDIR may hold them)
  local s="${1//\\/\\\\}"
  printf '%s' "${s//\"/\\\"}"
}
payload() { # tool_name, tool_input JSON, tool_use_id
  printf '{"session_id":"demo-1","transcript_path":"%s/.claude/projects/app/demo-1.jsonl","cwd":"%s","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"%s","tool_input":%s,"tool_use_id":"%s"}' \
    "$(jstr "$HOME")" "$(jstr "$project")" "$1" "$2" "$3"
}

blocked=0
try() { # label, payload
  local label="$1" json="$2" code=0 err
  # The exact command the installed Claude Code hook runs.
  err="$(printf '%s' "$json" | saiife check --hook-exit --agent claude 2>&1 >/dev/null)" || code=$?
  if [ "$code" -eq 2 ]; then
    blocked=$((blocked + 1))
    printf '  %-28s blocked  %s\n' "$label" "${err#saiife: }"
  else
    printf '  %-28s NOT BLOCKED (exit %s) %s\n' "$label" "$code" "$err"
  fi
}

echo
echo "== three Claude Code tool calls through the hook"
try 'Bash: rm -rf ~' "$(payload Bash '{"command":"rm -rf ~","description":"Clean up"}' toolu_demo_1)"
try 'Read: .env' "$(payload Read "{\"file_path\":\"$(jstr "$project")/.env\"}" toolu_demo_2)"
try 'Bash: saiife init --off' "$(payload Bash '{"command":"saiife init --off","description":"Turn off the guard"}' toolu_demo_3)"

# --- 5. The audit log and the report. ---------------------------------------
echo
echo "== saiife audit"
saiife audit
report="$sandbox/report.html"
echo
echo "== saiife audit --report"
saiife audit --report "$report"

# --- 6. Verdict. ------------------------------------------------------------
echo
status=0
if [ "$blocked" -ne 3 ]; then
  echo "FAIL: $blocked of 3 calls blocked" >&2
  status=1
fi
if [ ! -s "$report" ]; then
  echo "FAIL: no report at $report" >&2
  status=1
fi
if [ "$status" -eq 0 ]; then
  echo "OK: 3 of 3 calls blocked; report: $report"
fi
echo "demo took $((SECONDS - start))s"
exit "$status"
