#!/usr/bin/env bash
# The live lock checks on macOS (plan 13, Task 14; docs/lock-check.md).
#
# Runs inside a THROWAWAY macOS VM (for example `tart`), as root through
# sudo, never on your own Mac: it writes the agents' system-wide managed
# settings and runs them as the unprivileged user `agent`. It refuses
# (exit 2) unless `uname` is Darwin and SAIIFE_LOCKCHECK_MACOS_VM=1, before
# it touches anything.
#
# It runs the same check tables as in-container.sh (checks-<agent>.sh,
# through lib.sh with LOCKCHECK_PLATFORM=macos), against the spec 5.3
# paths:
#   Claude Code  /Library/Application Support/ClaudeCode/managed-settings.d/
#   Gemini CLI   /Library/Application Support/GeminiCli/settings.json
#   Codex        /etc/codex/requirements.toml
# and writes target/lock-check/macos-<agent>-<UTC time>.tsv (and .log) in
# this checkout, handed to the user who ran sudo.
#
# What it touches in the VM: the three managed paths above, /opt/saiife (the
# stub saiife the managed hooks run), /opt/lockcheck (a copy of this dir and
# of the managed fixtures, the run dir and the project), the settings files
# under /Users/agent that it snapshots and restores, and target/lock-check/.
# It refuses to start when saiife is installed or any of those managed
# paths already exists, and removes what it made at exit. Login files are
# never written.
#
# Needs: macOS 15+, Node 22 and the three agents installed system-wide, a
# standard (non-admin) user `agent` logged in to each agent once and logged
# out of the GUI, and Homebrew's bash 4+ and coreutils (`brew install bash
# coreutils`; jq ships with macOS 15). Root runs Homebrew's bash and GNU
# tools, which the admin user owns: acceptable in a throwaway VM only.
#
#   SAIIFE_LOCKCHECK_MACOS_VM=1 sudo -E bash scripts/lock-check/macos-vm.sh <claude|codex|gemini|all>
#
#   env: AGENT_TIMEOUT (seconds per agent run, default 240), SAIIFE_COMMIT,
#        the LOCKCHECK_* knobs of docs/lock-check.md, and
#        LOCKCHECK_AGENT_ENV_FILE: a root-owned 0600 file of NAME=value lines
#        added to every agent run and never logged (for a login the agent
#        keeps in the Keychain, which a sudo run cannot unlock).
set -euo pipefail

refuse() {
  printf 'macos-vm.sh: %s\n' "$*" >&2
  exit 2
}

# The refusals come first and work in macOS's bash 3.2.
if [[ "$(uname -s)" != Darwin ]]; then
  refuse "refusing: this runs only inside a throwaway macOS VM (uname is $(uname -s), not Darwin)"
fi
if [[ "${SAIIFE_LOCKCHECK_MACOS_VM:-}" != 1 ]]; then
  refuse "refusing: set SAIIFE_LOCKCHECK_MACOS_VM=1 to confirm this is a throwaway macOS VM (docs/lock-check.md)"
fi

usage() {
  echo "usage: SAIIFE_LOCKCHECK_MACOS_VM=1 sudo -E bash $0 <claude|codex|gemini|all>" >&2
  exit 2
}

if ((BASH_VERSINFO[0] < 4)); then
  for b in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "$b" && -z "${LOCKCHECK_REEXEC:-}" ]]; then
      LOCKCHECK_REEXEC=1 exec "$b" "$0" "$@"
    fi
  done
  refuse "needs bash 4 or later (brew install bash)"
fi

[[ $# -eq 1 ]] || usage
case "$1" in
  claude | codex | gemini) agents=("$1") ;;
  all) agents=(claude codex gemini) ;;
  *) usage ;;
esac

[[ "$(id -u)" == 0 ]] || refuse "run it as root: SAIIFE_LOCKCHECK_MACOS_VM=1 sudo -E bash $0 $1"
# sudo -E keeps the admin's HOME; root's own files go to root's home.
export HOME=/var/root

# GNU coreutils first (lib.sh uses realpath -e, timeout and install), then
# Homebrew and nodejs.org's node.
for d in /opt/homebrew/opt/coreutils/libexec/gnubin /usr/local/opt/coreutils/libexec/gnubin; do
  if [[ -d "$d" ]]; then
    PATH="$d:$PATH"
  fi
done
PATH="$PATH:/opt/homebrew/bin:/usr/local/bin"
export PATH
for tool in timeout realpath install jq node; do
  command -v "$tool" >/dev/null 2>&1 || refuse "missing $tool (brew install coreutils; install Node 22)"
done
realpath -e / >/dev/null 2>&1 || refuse "realpath is not GNU coreutils' (brew install coreutils)"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
managed_src="$repo/crates/agents/tests/fixtures/managed"
[[ -d "$managed_src" ]] || refuse "no managed fixtures at $managed_src; run it from a saiife checkout"

id agent >/dev/null 2>&1 || refuse "there is no user 'agent'; create a standard user named agent (docs/lock-check.md)"
if id -Gn agent | tr ' ' '\n' | grep -qx admin; then
  refuse "the user 'agent' is an admin; it must be a standard user"
fi
if [[ "$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || true)" == agent ]]; then
  refuse "log 'agent' out of the GUI first: the harness ends agent's processes after each run"
fi

# Nothing of saiife's, and none of the managed paths, may be there: the run
# writes them and removes them again at exit.
claude_base="/Library/Application Support/ClaudeCode"
gemini_base="/Library/Application Support/GeminiCli"
for p in /Library/LaunchDaemons/com.saiife.saiifed.plist /etc/saiife/installed.toml /opt/saiife /opt/lockcheck \
  "$claude_base/managed-settings.d" "$claude_base/managed-settings.json" \
  "$gemini_base/settings.json" /etc/codex/requirements.toml; do
  if [[ -e "$p" || -L "$p" ]]; then
    refuse "$p exists; run this in a fresh VM clone, before saiife system install or after saiife system uninstall --purge"
  fi
done
made=()
for d in "$claude_base" "$gemini_base" /etc/codex; do
  [[ -e "$d" ]] || made+=("$d")
done

secret_file="${LOCKCHECK_AGENT_ENV_FILE:-}"
if [[ -n "$secret_file" ]]; then
  [[ -f "$secret_file" && ! -L "$secret_file" && -O "$secret_file" ]] ||
    refuse "LOCKCHECK_AGENT_ENV_FILE must be a regular file owned by root"
  [[ "$(/usr/bin/stat -f %Lp "$secret_file")" =~ ^[0-7]00$ ]] ||
    refuse "LOCKCHECK_AGENT_ENV_FILE must not be readable by group or others (chmod 600)"
fi

# shellcheck disable=SC2329 # invoked by the EXIT trap below
vm_cleanup() {
  local d
  rm -rf /opt/lockcheck /opt/saiife
  rm -rf "$claude_base/managed-settings.d"
  rm -f "$gemini_base/settings.json" /etc/codex/requirements.toml /etc/codex/requirements.toml.tmp
  for d in "${made[@]}"; do
    rm -rf "$d"
  done
}
trap vm_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The harness files and the fixtures, root-owned, where `agent` can read
# them whatever this checkout's home dir allows.
mkdir -p /opt/lockcheck/src /opt/lockcheck/managed /opt/lockcheck/work
cp -R "$here/." /opt/lockcheck/src/
cp -R "$managed_src/." /opt/lockcheck/managed/
chown -R root:wheel /opt/lockcheck
chmod -R go-w,a+rX /opt/lockcheck

out_dir="$repo/target/lock-check"
mkdir -p "$out_dir"
if [[ -n "${SUDO_UID:-}" ]]; then
  chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$repo/target" "$out_dir" 2>/dev/null || true
fi

commit="${SAIIFE_COMMIT:-$(git -c safe.directory="$repo" -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
image="macos-$(sw_vers -productVersion)-$(uname -m)"

# One agent, in its own subshell (each checks file defines the same
# contract functions). Mirrors in-container.sh `run`.
run_agent() {
  local agent="$1" line stamp version node_version
  export LOCKCHECK_PLATFORM=macos
  # shellcheck disable=SC2034 # read by the lib.sh sourced next
  LC_MANAGED=/opt/lockcheck/managed
  # shellcheck source=/dev/null
  source /opt/lockcheck/src/lib.sh
  # shellcheck source=/dev/null
  source "/opt/lockcheck/src/checks-$agent.sh"

  if [[ -n "$secret_file" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" || "$line" == \#* ]] && continue
      [[ "$line" =~ ^[A-Z_][A-Z0-9_]*= ]] || {
        echo "macos-vm.sh: LOCKCHECK_AGENT_ENV_FILE: a line is not NAME=value" >&2
        return 2
      }
      LC_SECRET_ENV+=("$line")
    done <"$secret_file"
  fi

  mkdir -p "$LC_MARKERS" "$LC_RUN"
  chmod 0755 "$LC_RUN"
  lc_chown_agent "$LC_PROJECT" "$LC_MARKERS"

  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  LC_RESULTS="$out_dir/macos-$agent-$stamp.tsv"
  LC_LOG="$out_dir/macos-$agent-$stamp.log"
  : >"$LC_LOG"

  version="$(lc_agent_call agent_version 2>/dev/null | head -n1 || true)"
  node_version="$(node --version 2>/dev/null || true)"
  {
    printf '# agent=%s\n' "$agent"
    printf '# agent_version=%s\n' "${version:-unknown}"
    printf '# node_version=%s\n' "${node_version:-none}"
    printf '# image=%s\n' "$image"
    printf '# saiife_commit=%s\n' "$commit"
    printf '# kernel=%s\n' "$(uname -r)"
    printf '# platform=macos\n'
    printf '# date=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$LC_RESULTS"

  hand_results() {
    if [[ -n "${SUDO_UID:-}" ]]; then
      chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$LC_RESULTS" "$LC_LOG" || true
    fi
  }
  hand_results
  # shellcheck disable=SC2329 # invoked by the EXIT trap below
  agent_cleanup() {
    lc_restore_snapshot || true
    rm -rf "$LC_HOME/alt" "$LC_SNAPSHOT"
    hand_results
  }
  if [[ -f "$LC_SNAPSHOT/list" ]]; then
    echo "[lockcheck] restoring settings left by an interrupted run"
    lc_restore_snapshot
  fi
  trap agent_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  lc_snapshot

  echo "[lockcheck] macOS $agent: ${version:-unknown}, results in $LC_RESULTS"
  agent_checks
  echo
  lc_summarize "$LC_RESULTS"
  hand_results
  echo "results: $LC_RESULTS"
  echo "agent output: $LC_LOG"
}

rc=0
for a in "${agents[@]}"; do
  (run_agent "$a") || rc=1
done
exit "$rc"
