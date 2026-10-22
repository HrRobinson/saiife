#!/usr/bin/env bash
# Live lock check: can a managed (system-level) saiife hook lock Claude Code,
# Codex and Gemini CLI? (v2 spec §6.1.3, §8.3, §9.3, §13 "Agents, live")
#
# Run this yourself, not in CI: it runs the real agents with your logins.
# Everything happens in a disposable Docker container built from
# scripts/lock-check/Dockerfile (Ubuntu 24.04, Node 22, the three agents; no
# repo files, no secrets, built with no build context). Inside, as root, it
# installs the §8.3 managed files, a stub saiife and a witness hook, then for
# each check asks the agent (as the unprivileged user `agent`) to touch a
# marker file and records whether the call ran, was blocked, or fired the
# hook. Results: target/lock-check/<agent>-<UTC time>.tsv (+ .log with the
# agent output); the last line is the agent's lock label.
#
# What it touches on the host: the Docker image saiife-lockcheck:local, the
# named volume saiife-lockcheck-home (the agents' logins and home), and
# $repo/target/lock-check. It mounts only scripts/lock-check and
# crates/agents/tests/fixtures/managed (read-only) and the output dir;
# nothing from your home folder, no agent config, no credentials.
#
# First run: `--setup` opens a shell in the container as `agent`; log in to
# each agent there (the steps are printed), then exit. `--forget` deletes the
# volume and with it those logins.
#
#   bash scripts/live-check-locked.sh --setup
#   bash scripts/live-check-locked.sh [--rebuild] <claude|codex|gemini|all>
#   bash scripts/live-check-locked.sh --print <agent>   (docker run argv only)
#   bash scripts/live-check-locked.sh --forget
#   AGENT_TIMEOUT=240 (seconds per agent run), CLAUDE_VERSION / CODEX_VERSION
#   / GEMINI_VERSION / NODE_VERSION (image build args, with --rebuild)
#   LOCKCHECK_CODEX_REQUIREMENTS / LOCKCHECK_CODEX_MHO_TABLE /
#   LOCKCHECK_CODEX_MCP_SNIPPET / LOCKCHECK_GEMINI_TOGGLE (overrides for
#   unverified agent keys; see checks-codex.sh and checks-gemini.sh)
#
# Guide: docs/lock-check.md (logins, reading results, the knobs, --forget).
# The three `*.fail.segv` checks crash a bash in the container with a real
# SIGSEGV. core_pattern is global, so the host's crash handler (e.g.
# systemd-coredump, a desktop crash reporter) may log or pop up up to 3
# entries for /usr/bin/bash during a run; no core file is written
# (--ulimit core=0).
#
# Exit 0 only if no agent's label is `not-lockable` or `unverified`.
set -euo pipefail

usage() {
  echo "usage: $0 [--setup | --forget | --print] [--rebuild] <claude|codex|gemini|all>" >&2
  echo "       (--setup and --forget take no agent; --help for more)" >&2
  exit 2
}

show_help() {
  cat <<'EOF'
usage: live-check-locked.sh [--setup | --forget | --print] [--rebuild] <claude|codex|gemini|all>

  --setup     open a shell in the container as `agent`; log in to each agent
  <agent>     run the lock checks for claude, codex, gemini or all
  --rebuild   rebuild the image first (CLAUDE_VERSION, CODEX_VERSION, ...)
  --print     print the docker run argv only
  --forget    delete the volume that holds the agents' logins

Results: target/lock-check/<agent>-<time>.tsv (+ .log).
Guide (what it touches, logins, reading results, LOCKCHECK_* knobs):
  docs/lock-check.md
EOF
  exit 0
}

action=run
rebuild=0
target=""
for arg in "$@"; do
  case "$arg" in
    -h | --help) show_help ;;
    --setup | --forget | --print)
      [[ "$action" == run ]] || usage
      action="${arg#--}"
      ;;
    --rebuild) rebuild=1 ;;
    claude | codex | gemini | all)
      [[ -z "$target" ]] || usage
      target="$arg"
      ;;
    *) usage ;;
  esac
done
case "$action" in
  setup | forget) [[ -z "$target" ]] || usage ;;
  *) [[ -n "$target" ]] || usage ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "live-check-locked: docker is not installed or not on PATH" >&2
  exit 2
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="$repo/scripts/lock-check/Dockerfile"
image="saiife-lockcheck:local"
volume="saiife-lockcheck-home"
out="$repo/target/lock-check"

if [[ "$action" == forget ]]; then
  docker volume rm "$volume"
  exit 0
fi

build_image() {
  local -a build_args=()
  local name
  for name in NODE_VERSION CLAUDE_VERSION CODEX_VERSION GEMINI_VERSION; do
    if [[ -n "${!name:-}" ]]; then
      build_args+=(--build-arg "$name=${!name}")
    fi
  done
  if ((rebuild)) || ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "live-check-locked: building $image (no build context)"
    docker build ${build_args[@]+"${build_args[@]}"} -t "$image" - < "$dockerfile"
  fi
}

# Agent runs read /dev/null: they need a TTY only for live colour output,
# and `-it` fails when the output is piped (`... all | tee run.txt`).
tty_flags=()
if [[ -t 0 && -t 1 ]]; then
  tty_flags=(-it)
fi

# docker run argv for one agent, into the array `argv`.
run_argv() {
  local agent="$1" image_id="$2" commit name
  commit="$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)"
  argv=(docker run ${tty_flags[@]+"${tty_flags[@]}"} --rm --name "saiife-lockcheck-$agent"
    --ulimit core=0 --security-opt no-new-privileges
    -v "$repo/scripts/lock-check:/lockcheck:ro"
    -v "$repo/crates/agents/tests/fixtures/managed:/lockcheck-managed:ro"
    -v "$out:/out"
    -v "$volume:/home/agent"
    -e "SAIIFE_COMMIT=$commit"
    -e "LOCKCHECK_IMAGE=$image_id"
    -e AGENT_TIMEOUT)
  # in-container.sh chowns the result files to these (not with rootless
  # Docker, where container root already is the host user).
  if [[ "$host_owner" == 1 ]]; then
    argv+=(-e "LOCKCHECK_HOST_UID=$(id -u)" -e "LOCKCHECK_HOST_GID=$(id -g)")
  fi
  # Optional per-agent knobs (every LOCKCHECK_* that checks-codex.sh and
  # checks-gemini.sh read); passed only when set on the host.
  for name in LOCKCHECK_CODEX_REQUIREMENTS LOCKCHECK_CODEX_MHO_TABLE LOCKCHECK_CODEX_MCP_SNIPPET \
    LOCKCHECK_GEMINI_TOGGLE; do
    if [[ -n "${!name+x}" ]]; then
      argv+=(-e "$name")
    fi
  done
  argv+=("$image" bash /lockcheck/in-container.sh run "$agent")
}

agents=("$target")
if [[ "$target" == all ]]; then
  agents=(claude codex gemini)
fi

host_owner=1
if [[ "$action" == run ]] && docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q rootless; then
  host_owner=0
fi

if [[ "$action" == print ]]; then
  for agent in "${agents[@]}"; do
    run_argv "$agent" "<image id>"
    printf '%s\n' "${argv[@]}"
  done
  exit 0
fi

build_image

if [[ "$action" == setup ]]; then
  exec docker run -it --rm --name saiife-lockcheck-setup \
    --ulimit core=0 --security-opt no-new-privileges \
    -v "$repo/scripts/lock-check:/lockcheck:ro" \
    -v "$volume:/home/agent" \
    "$image" bash /lockcheck/in-container.sh setup
fi

image_id="$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null || echo unknown)"
mkdir -p "$out"
status=0
results=()
for agent in "${agents[@]}"; do
  before="$(find "$out" -maxdepth 1 -name "$agent-*.tsv")"
  run_argv "$agent" "$image_id"
  "${argv[@]}" || echo "live-check-locked: $agent run exited $?" >&2
  file=""
  while IFS= read -r f; do
    if [[ -n "$f" ]] && ! grep -qxF -- "$f" <<<"$before"; then
      file="$f"
    fi
  done < <(find "$out" -maxdepth 1 -name "$agent-*.tsv" | sort)
  if [[ -z "$file" ]]; then
    echo "live-check-locked: $agent: no result file" >&2
    status=1
    continue
  fi
  label="$(sed -n 's/^# label=//p' "$file")"
  results+=("$agent: ${label:-none}  $file")
  case "$label" in
    lockable | lockable-with-gaps | lockable-with-caveats) ;;
    *) status=1 ;;
  esac
done

echo
echo "Lock check results:"
if ((${#results[@]})); then
  printf '  %s\n' "${results[@]}"
fi
exit "$status"
