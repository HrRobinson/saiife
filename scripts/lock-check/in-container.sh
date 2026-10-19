#!/usr/bin/env bash
# Container entrypoint for the live lock checks (scripts/live-check-locked.sh).
#
# Runs as root inside the disposable saiife-lockcheck container, never on the
# host: it refuses (exit 2) unless /.dockerenv exists, or LC_ROOT is set to a
# directory other than / (the offline tests, where every path below is under
# $LC_ROOT and nothing runs as another user).
#
#   setup        create the `agent` user if needed, print the login steps and
#                open a login shell as `agent`. Logins are stored in
#                /home/agent, the named volume saiife-lockcheck-home.
#   run <agent>  source lib.sh and /lockcheck/checks-<agent>.sh (or
#                $LC_CHECKS_DIR/checks-<agent>.sh), write the result header
#                to /out/<agent>-<UTC time>.tsv, snapshot the agent's
#                settings files, run agent_checks, append the label and print
#                the summary. Agent output goes to the sibling .log. The
#                settings snapshot is restored on exit, also on failure.
#
# What it touches (container only): /etc (managed agent settings, via the
# agent script), /opt/saiife, /opt/lockcheck, /run/lockcheck, /work/project,
# /out, and the settings files under /home/agent that it snapshots and
# restores. Login files are never touched.
#
#   bash /lockcheck/in-container.sh setup
#   bash /lockcheck/in-container.sh run <claude|codex|gemini>
#   env: SAIIFE_COMMIT, LOCKCHECK_IMAGE (header values), AGENT_TIMEOUT
#        (seconds per agent run, default 240)
set -euo pipefail

usage() {
  echo "usage: $0 setup | run <agent>" >&2
  exit 2
}

if [[ -n "${LC_ROOT:-}" ]]; then
  root_real="$(realpath -e -- "$LC_ROOT" 2>/dev/null || true)"
  if [[ -z "$root_real" || "$root_real" == / || ! -d "$root_real" ]]; then
    echo "in-container.sh: LC_ROOT must be an existing directory other than /" >&2
    exit 2
  fi
elif [[ ! -e /.dockerenv ]]; then
  echo "in-container.sh: refusing to run outside the lock-check container" >&2
  echo "  (no /.dockerenv); use scripts/live-check-locked.sh on the host." >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
action="${1:-}"

ensure_agent_user() {
  if [[ -n "${LC_ROOT:-}" ]]; then
    return 0
  fi
  if ! id agent >/dev/null 2>&1; then
    useradd -m -u 1001 agent
  fi
  mkdir -p /home/agent
  chown agent:agent /home/agent
}

case "$action" in
  setup)
    [[ $# -eq 1 ]] || usage
    ensure_agent_user
    cat <<'EOF'
Log in to each agent once; the logins stay in the saiife-lockcheck-home
volume (remove it with `live-check-locked.sh --forget`).
  Claude Code:  claude      then type /login, follow it, then /exit
  Codex:        codex login --device-auth
  Gemini CLI:   gemini      and choose "Login with Google", then /quit
Then type `exit` to leave the container.
EOF
    if [[ -n "${LC_ROOT:-}" ]]; then
      exit 0
    fi
    exec setpriv --reuid=agent --regid=agent --init-groups -- \
      env -i HOME=/home/agent PATH=/usr/local/bin:/usr/bin:/bin "TERM=${TERM:-xterm}" bash -l
    ;;
  run)
    [[ $# -eq 2 ]] || usage
    agent="$2"
    ;;
  *) usage ;;
esac

if [[ ! "$agent" =~ ^[a-z0-9]+$ ]]; then
  echo "in-container.sh: bad agent name '$agent'" >&2
  exit 2
fi
checks="${LC_CHECKS_DIR:-$here}/checks-$agent.sh"
if [[ ! -f "$checks" ]]; then
  echo "in-container.sh: no checks for '$agent' ($checks)" >&2
  exit 2
fi

ensure_agent_user
# shellcheck source=/dev/null
source "$here/lib.sh"
# shellcheck source=/dev/null
source "$checks"

mkdir -p "$LC_MARKERS" "$LC_RUN" "$LC_ROOT/out"
chmod 0755 "$LC_RUN"
lc_chown_agent "$LC_PROJECT" "$LC_MARKERS"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
LC_RESULTS="$LC_ROOT/out/$agent-$stamp.tsv"
LC_LOG="$LC_ROOT/out/$agent-$stamp.log"
: >"$LC_LOG"

version="$(lc_agent_call agent_version 2>/dev/null | head -n1 || true)"
node_version="$(node --version 2>/dev/null || true)"
{
  printf '# agent=%s\n' "$agent"
  printf '# agent_version=%s\n' "${version:-unknown}"
  printf '# node_version=%s\n' "${node_version:-none}"
  printf '# image=%s\n' "${LOCKCHECK_IMAGE:-unknown}"
  printf '# saiife_commit=%s\n' "${SAIIFE_COMMIT:-unknown}"
  printf '# kernel=%s\n' "$(uname -r)"
  printf '# date=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$LC_RESULTS"

# Hand the results to the host user (rootful Docker writes them as root).
# Done as soon as they exist, again after the summary rewrites the .tsv, and
# at exit: a `docker kill` mid-run (no EXIT trap) still leaves them editable.
hand_results() {
  if [[ -z "$LC_ROOT" && -n "${LOCKCHECK_HOST_UID:-}" ]]; then
    chown "$LOCKCHECK_HOST_UID:${LOCKCHECK_HOST_GID:-$LOCKCHECK_HOST_UID}" "$LC_RESULTS" "$LC_LOG" || true
  fi
}
hand_results

cleanup() {
  lc_restore_snapshot || true
  rm -rf "$LC_HOME/alt" "$LC_SNAPSHOT"
  hand_results
}
# The snapshot lives in the home volume: a run cut off by `docker kill`
# leaves it behind, and its settings are put back before this run starts.
if [[ -f "$LC_SNAPSHOT/list" ]]; then
  echo "[lockcheck] restoring settings left by an interrupted run"
  lc_restore_snapshot
fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
lc_snapshot

echo "[lockcheck] $agent: ${version:-unknown}, results in $LC_RESULTS"
agent_checks
echo
lc_summarize "$LC_RESULTS"
hand_results
echo "results: $LC_RESULTS"
echo "agent output: $LC_LOG"
