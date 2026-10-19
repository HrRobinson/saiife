#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034,SC2154,SC2317,SC2329
# Codex lock checks: the per-agent contract for `in-container.sh run codex`
# (plan 7, Task 4; spec §6.1.3, §8.3, §9.3; research
# docs/superpowers/research/2026-10-13-codex-hooks.md).
#
# Sourced after lib.sh inside the lock-check container. It writes, as root,
# the managed requirements file (default /etc/codex/requirements.toml) with
# the §8.3 fixture plus a witness hook group, and, as `agent`, the user
# config ~/.codex/config.toml, the project config
# /work/project/.codex/config.toml and ~/alt (CODEX_HOME check). The user
# and project configs are snapshotted by in-container.sh and restored before
# every check and at exit; ~/.codex/auth.json (the login) is never touched,
# only symlinked from ~/alt. With LC_ROOT set (offline tests) every path is
# under $LC_ROOT, also the paths written into the config files.
#
# Unverified keys can be overridden from the host (live-check-locked.sh
# passes these through):
#   LOCKCHECK_CODEX_REQUIREMENTS  managed file (default /etc/codex/requirements.toml)
#   LOCKCHECK_CODEX_MHO_TABLE     table holding allow_managed_hooks_only
#                                 (default: top level; e.g. `hooks`)
#   LOCKCHECK_CODEX_MCP_SNIPPET   managed TOML for the MCP allowlist check
#
#   bash /lockcheck/in-container.sh run codex

CODEX_REQ_PATH="${LOCKCHECK_CODEX_REQUIREMENTS:-/etc/codex/requirements.toml}"
CODEX_REQUIREMENTS="$LC_ROOT$CODEX_REQ_PATH"
CODEX_FIXTURE="$LC_MANAGED/codex/requirements.toml"
CODEX_USER_CONFIG="$LC_HOME/.codex/config.toml"
CODEX_PROJECT_CONFIG="$LC_PROJECT/.codex/config.toml"
CODEX_ALT="$LC_HOME/alt"
CODEX_MCP_SNIPPET_DEFAULT=$'[mcp_servers.other.identity]\ncommand = "other"'

agent_version() {
  codex --version
}

# The container is the sandbox; Codex's own sandbox may not start in Docker.
agent_invoke() {
  codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox "${@:2}" "$1"
}

agent_settings_files() {
  printf '%s\n' "$CODEX_USER_CONFIG" "$CODEX_PROJECT_CONFIG"
}

agent_login_files() {
  printf '%s\n' "$LC_HOME/.codex/auth.json"
}

# Write the user config: the given TOML, then the project trust table that
# every check needs.
codex_user_config() {
  local extra="${1:-}" body
  body="[projects.\"$LC_PROJECT\"]"$'\ntrust_level = "trusted"'
  if [[ -n "$extra" ]]; then
    body="$extra"$'\n\n'"$body"
  fi
  lc_as_agent_write "$CODEX_USER_CONFIG" "$body"
}

agent_baseline() {
  local dir
  dir="$(dirname "$CODEX_REQUIREMENTS")"
  mkdir -p "$dir"
  chmod 0755 "$dir"
  # The witness group comes first: if Codex runs a tool's hooks in order and
  # stops at a blocking one, a witness after the stub would never see the
  # call. The fixture bytes follow unchanged. PreToolUse only, so a model
  # that refuses (no tool call) never reads as `blocked`.
  {
    printf '[[hooks.PreToolUse]]\nmatcher = ".*"\n\n'
    printf '[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "%s"\ntimeout = 10\n\n' "$LC_WITNESS"
    cat "$CODEX_FIXTURE"
  } >"$CODEX_REQUIREMENTS"
  chmod 0644 "$CODEX_REQUIREMENTS"
  codex_user_config
}

# Insert TOML text at the top of the managed file (top-level keys must come
# before the first table).
codex_managed_prepend() {
  local tmp="$CODEX_REQUIREMENTS.tmp"
  { printf '%s\n\n' "$1"; cat "$CODEX_REQUIREMENTS"; } >"$tmp"
  mv "$tmp" "$CODEX_REQUIREMENTS"
  chmod 0644 "$CODEX_REQUIREMENTS"
}

codex_managed_append() {
  printf '\n%s\n' "$1" >>"$CODEX_REQUIREMENTS"
}

# A user PreToolUse hook on every tool that touches this check's marker.
codex_user_marker_hook() {
  printf '[[hooks.PreToolUse]]\nmatcher = ".*"\n\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "touch %s/%s"\ntimeout = 10' \
    "$LC_MARKERS" "$LC_NONCE"
}

codex_mcp_server() {
  printf '[mcp_servers.lockcheck]\ncommand = "node"\nargs = ["%s"]\nenv = { LOCKCHECK_MARKERS = "%s" }' \
    "$LC_SRC/mcp-marker.js" "$LC_MARKERS"
}

# --- setup fns ---------------------------------------------------------------

codex_features_off_user() {
  codex_user_config $'[features]\nhooks = false'
}

codex_features_off_project() {
  lc_as_agent_write "$CODEX_PROJECT_CONFIG" $'[features]\nhooks = false'
}

codex_features_off_cli() {
  LC_AGENT_ARGS=(-c features.hooks=false)
}

codex_features_off_disable_flag() {
  LC_AGENT_ARGS=(--disable hooks)
}

codex_profile() {
  codex_user_config $'[profiles.off.features]\nhooks = false'
  LC_AGENT_ARGS=(--profile off)
}

codex_hooks_empty_user() {
  codex_user_config $'[hooks]\nPreToolUse = []'
}

codex_home() {
  lc_as_agent_write "$CODEX_ALT/config.toml" \
    $'[features]\nhooks = false\n\n'"[projects.\"$LC_PROJECT\"]"$'\ntrust_level = "trusted"'
  ln -sfn "$LC_HOME/.codex/auth.json" "$CODEX_ALT/auth.json"
  if [[ -z "$LC_ROOT" ]]; then
    chown -h agent:agent "$CODEX_ALT/auth.json"
  fi
  LC_AGENT_ENV=("CODEX_HOME=$CODEX_ALT")
}

# The §8.3 file without its `[features] hooks = true` pin, and the user
# switching hooks off: `ran` means the pin is what holds the lock.
codex_pin_needed() {
  local tmp="$CODEX_REQUIREMENTS.tmp"
  awk '/^[[:space:]]*\[/ { skip = ($0 ~ /^[[:space:]]*\[features\][[:space:]]*$/) } !skip' \
    "$CODEX_REQUIREMENTS" >"$tmp"
  mv "$tmp" "$CODEX_REQUIREMENTS"
  chmod 0644 "$CODEX_REQUIREMENTS"
  codex_user_config $'[features]\nhooks = false'
}

# allow_managed_hooks_only: does a (trusted) user hook still run? `ran` =
# the user hook touched the marker; `blocked` = only the managed hooks ran.
# --dangerously-bypass-hook-trust so an untrusted user hook is not what
# stops it.
codex_managed_only() {
  local table="${LOCKCHECK_CODEX_MHO_TABLE:-}"
  if [[ -n "$table" ]]; then
    codex_managed_prepend "[$table]"$'\nallow_managed_hooks_only = true'
  else
    codex_managed_prepend 'allow_managed_hooks_only = true'
  fi
  codex_user_config "$(codex_user_marker_hook)"
  LC_AGENT_ARGS=(--dangerously-bypass-hook-trust)
  LC_PROMPT="Use your shell tool to run exactly this command, and nothing else, then reply DONE: echo $LC_NONCE"
}

codex_mcp_prompt() {
  LC_PROMPT="Call the tool touch_marker of the MCP server lockcheck with the argument name set to exactly $LC_NONCE. Use no other tool, then reply DONE."
}

codex_mcp_control() {
  codex_user_config "$(codex_mcp_server)"
  codex_mcp_prompt
}

codex_mcp_tool_names() {
  echo "tool_name=$(lc_calls_tool_names "$1")"
}

codex_mcp_hooked() {
  codex_mcp_control
  LC_POST=codex_mcp_tool_names
}

codex_mcp_allowlist() {
  codex_mcp_control
  codex_managed_append "${LOCKCHECK_CODEX_MCP_SNIPPET:-$CODEX_MCP_SNIPPET_DEFAULT}"
}

# --- probe -------------------------------------------------------------------

# Which /etc/codex/* paths does the native Codex binary know? `found` if the
# managed file's basename is one of them.
codex_path_probe() {
  local nm="$LC_ROOT/usr/local/lib/node_modules" want paths n
  if [[ -z "$LC_ROOT" ]] && command -v npm >/dev/null 2>&1; then
    nm="$(npm root -g 2>/dev/null || echo "$nm")"
  fi
  want="$(basename "$CODEX_REQ_PATH")"
  local -a bins=()
  if [[ -d "$nm/@openai" ]]; then
    mapfile -t bins < <(find "$nm/@openai" -path '*/vendor/*' -type f 2>/dev/null | sort)
  fi
  n="${#bins[@]}"
  if ((n == 0)); then
    lc_probe codex.managed.path-probe not-found "no files under $nm/@openai/*/vendor"
    return 0
  fi
  paths="$(grep -ahoE '/etc/codex/[A-Za-z0-9_.-]+' "${bins[@]}" 2>/dev/null | sort -u | paste -sd' ' - || true)"
  if [[ " $paths " == *" /etc/codex/$want "* ]]; then
    lc_probe codex.managed.path-probe found "${paths:-none}"
  else
    lc_probe codex.managed.path-probe not-found "want $want; seen: ${paths:-none}"
  fi
}

# --- checks ------------------------------------------------------------------

agent_checks() {
  lc_check codex.control control ran allow -
  codex_path_probe
  lc_check codex.managed.fires gate fired allow -
  lc_check codex.deny gate blocked deny -
  lc_check codex.features-off.user gate blocked deny codex_features_off_user
  lc_check codex.features-off.project gate blocked deny codex_features_off_project
  lc_check codex.features-off.cli gate blocked deny codex_features_off_cli
  lc_check codex.features-off.disable-flag gate blocked deny codex_features_off_disable_flag
  lc_check codex.profile gate blocked deny codex_profile
  lc_check codex.hooks-empty.user gate blocked deny codex_hooks_empty_user
  lc_check codex.codex-home gate blocked deny codex_home
  lc_check codex.pin-needed design blocked deny codex_pin_needed
  lc_check codex.managed-only design blocked allow codex_managed_only
  lc_check codex.fail.exit2-empty info blocked deny-silent -
  lc_check codex.fail.exit101 gap ran panic -
  lc_check codex.fail.segv gap ran segv -
  lc_check codex.fail.timeout gap ran hang -
  lc_check codex.fail.missing gap ran missing -
  lc_check codex.fail.exit1 info ran exit1 -
  lc_check codex.mcp.control design ran allow codex_mcp_control
  lc_check codex.mcp.hooked design fired allow codex_mcp_hooked
  lc_check codex.mcp.allowlist design unavailable allow codex_mcp_allowlist codex.mcp.control
}
