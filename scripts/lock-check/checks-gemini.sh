#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034,SC2154,SC2317,SC2329
# checks-gemini.sh: the live lock checks for Gemini CLI (plan 7, Task 5).
#
# Sourced by in-container.sh after lib.sh (`in-container.sh run gemini`,
# started by scripts/live-check-locked.sh gemini); never run directly. It
# answers spec §6.1.3/§9.3 for Gemini: does the system settings file's
# BeforeTool hook fire, can user, project or environment settings switch it
# off, which hook failures block, and how MCP tools and the MCP allow/deny
# keys behave.
#
# What it touches (inside the container; under $LC_ROOT in the offline
# tests): the system settings /etc/gemini-cli/settings.json (root 0644),
# /work/empty-settings.json, and as `agent` ~/.gemini/settings.json,
# ~/.gemini/trustedFolders.json, /work/project/.gemini/settings.json and
# ~/alt (all restored or removed by lib.sh's reset). The login files
# ~/.gemini/oauth_creds.json and ~/.gemini/google_accounts.json are only
# ever symlinked to, never written.
#
# The hooks on/off key: `gemini_toggle_keys` reads the installed package's
# settings schema (SETTINGS_SCHEMA under the global node_modules/@google/
# gemini-cli*) for boolean settings whose dotted key contains "hook". The
# baseline pins each one on in the system file. Override the probe with
#   LOCKCHECK_GEMINI_TOGGLE="hooksConfig.enabled"   (space-separated keys)
# A key whose last part contains "disable" is pinned to false instead.
#
#   bash scripts/live-check-locked.sh gemini

GEMINI_KEY=""
GEMINI_TOGGLES=()
GEMINI_TOGGLE_SRC=""
GEMINI_TOGGLES_LOADED=""

agent_version() {
  gemini --version
}

agent_invoke() {
  gemini --approval-mode yolo "${@:2}" -p "$1"
}

# A system.fires row that reads not-fired most likely means hooks are off by
# default and the probe missed the enable key.
agent_fires_hint() {
  echo "check LOCKCHECK_GEMINI_TOGGLE / enable key (probed: ${GEMINI_TOGGLES[*]:-none})"
}

# Self-contained (run as agent through lc_agent_call).
gemini_help() {
  gemini --help 2>&1
}

agent_settings_files() {
  printf '%s\n' "$LC_HOME/.gemini/settings.json" "$LC_HOME/.gemini/trustedFolders.json" \
    "$LC_PROJECT/.gemini/settings.json"
}

agent_login_files() {
  printf '%s\n' "$LC_HOME/.gemini/oauth_creds.json" "$LC_HOME/.gemini/google_accounts.json"
}

# --- the hooks on/off key ----------------------------------------------------

# The global node_modules that holds @google/gemini-cli*.
gemini_node_modules() {
  if [[ -n "$LC_ROOT" ]]; then
    printf '%s\n' "$LC_ROOT/usr/local/lib/node_modules"
  else
    npm root -g 2>/dev/null || printf '%s\n' /usr/local/lib/node_modules
  fi
}

# Print the dotted keys of SETTINGS_SCHEMA in file $1 whose path contains
# "hook" (any case) and whose entry has `type: 'boolean'` and a true/false
# default. A small JS tokenizer (strings, comments, braces) walks the object
# literal; `properties` levels are left out of the key, objects inside arrays
# are skipped. POSIX awk (mawk in the container).
gemini_scan_schema() {
  awk '
    function emit(d,   i, p) {
      p = ""
      for (i = 2; i <= d; i++) {
        if (key[i] == "") return
        if (key[i] == "properties") continue
        p = (p == "" ? key[i] : p "." key[i])
      }
      if (p != "" && tolower(p) ~ /hook/) print p
    }
    function tok(t, isstr) {
      if (colon) {
        if (ckey == "type" && isstr && t == "boolean") isbool[depth] = 1
        if (ckey == "default" && !isstr && (t == "true" || t == "false")) hasdef[depth] = 1
        colon = 0
        last = ""
      } else {
        last = t
      }
    }
    {
      line = $0
      if (!on) {
        if (!match(line, /SETTINGS_SCHEMA[0-9]*[ \t]*(:[^=]*)?=[ \t]*\{/)) next
        on = 1
        line = substr(line, RSTART + RLENGTH - 1)
      }
      n = length(line)
      for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (blk) {
          if (c == "*" && substr(line, i + 1, 1) == "/") { blk = 0; i++ }
          continue
        }
        if (q != "") {
          if (c == "\\") { s = s substr(line, i + 1, 1); i++ }
          else if (c == q) { q = ""; tok(s, 1) }
          else s = s c
          continue
        }
        if (c ~ /[A-Za-z0-9_$]/) { w = w c; continue }
        if (w != "") { tok(w, 0); w = "" }
        if (c == "/" && substr(line, i + 1, 1) == "/") break
        if (c == "/" && substr(line, i + 1, 1) == "*") { blk = 1; i++; continue }
        if (c == "\"" || c == "\047" || c == "`") { q = c; s = ""; continue }
        if (c == ":") {
          if (last != "") { ckey = last; colon = 1; last = "" }
          continue
        }
        if (c == "{") {
          depth++
          key[depth] = (colon ? ckey : "")
          isbool[depth] = 0
          hasdef[depth] = 0
          colon = 0; last = ""
          continue
        }
        if (c == "}") {
          if (isbool[depth] && hasdef[depth]) emit(depth)
          depth--
          colon = 0; last = ""
          if (depth == 0) exit
          continue
        }
        if (c == "[" || c == ",") { colon = 0; last = "" }
      }
      if (w != "") { tok(w, 0); w = "" }
    }' "$1"
}

# The JS files of the installed package that define SETTINGS_SCHEMA.
gemini_schema_files() {
  grep -rlE --include='*.js' --include='*.mjs' --include='*.cjs' \
    'SETTINGS_SCHEMA[0-9]*[[:space:]]*(:[^=]*)?=' "$(gemini_node_modules)"/@google/gemini-cli* \
    2>/dev/null | sort || true
}

# Fill GEMINI_TOGGLES once (LOCKCHECK_GEMINI_TOGGLE, else the schema probe).
gemini_load_toggles() {
  local k f raw=""
  local -a files=()
  [[ -z "$GEMINI_TOGGLES_LOADED" ]] || return 0
  GEMINI_TOGGLES=()
  if [[ -n "${LOCKCHECK_GEMINI_TOGGLE:-}" ]]; then
    read -ra GEMINI_TOGGLES <<<"$LOCKCHECK_GEMINI_TOGGLE"
    GEMINI_TOGGLE_SRC="from LOCKCHECK_GEMINI_TOGGLE"
  else
    mapfile -t files < <(gemini_schema_files)
    for f in "${files[@]}"; do
      [[ -n "$f" ]] || continue
      raw+="$(gemini_scan_schema "$f")"$'\n'
    done
    raw="$(printf '%s' "$raw" | sed '/^$/d' | sort -u)"
    if [[ -n "$raw" ]]; then
      mapfile -t GEMINI_TOGGLES <<<"$raw"
    fi
    GEMINI_TOGGLE_SRC="from the schema in ${#files[@]} file(s) under $(gemini_node_modules)"
  fi
  for k in "${GEMINI_TOGGLES[@]}"; do
    if [[ ! "$k" =~ ^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$ ]]; then
      echo "checks-gemini.sh: bad toggle key '$k'" >&2
      return 1
    fi
  done
  GEMINI_TOGGLES_LOADED=1
}

gemini_toggle_keys() {
  gemini_load_toggles
  if ((${#GEMINI_TOGGLES[@]})); then
    printf '%s\n' "${GEMINI_TOGGLES[@]}"
  fi
}

# --- JSON helpers ------------------------------------------------------------

# stdin JSON -> stdout with each key in "${@:2}" set on ($1 = on) or off
# ($1 = off). "On" is true, except for a key whose last part says "disable".
gemini_json_set_toggles() {
  local state="$1"
  shift
  jq --arg v "$state" '
    reduce $ARGS.positional[] as $k (.;
      ($k | split(".")) as $p
      | setpath($p; (($p | last | test("disable"; "i")) != ($v == "on"))))' --args "$@"
}

# Print the JSON in $1, or {} when it is missing or empty.
gemini_read_json() {
  if [[ -s "$1" ]]; then
    cat "$1"
  else
    echo '{}'
  fi
}

# Rewrite agent-owned settings file $1 as agent: its JSON (or {}) piped
# through the command "${@:2}". Keeps whatever else is in it (the login's
# security.auth in ~/.gemini/settings.json).
gemini_update_as_agent() {
  local path="$1" new
  shift
  new="$(gemini_read_json "$path" | "$@")"
  lc_as_agent_write "$path" "$new"
}

# Rewrite the system settings file (as root) through the command "$@".
gemini_update_managed() {
  local f="$LC_ROOT/etc/gemini-cli/settings.json" new
  new="$(gemini_read_json "$f" | "$@")"
  printf '%s\n' "$new" >"$f"
  chmod 0644 "$f"
}

# System settings = the fixture with the witness handler put FIRST in the
# first BeforeTool group (so a blocking stub cannot stop it from seeing the
# call; BeforeTool only, never a prompt-bearing event), plus (pin) every
# toggle key switched on.
gemini_write_managed() {
  local pin="$1" dir="$LC_ROOT/etc/gemini-cli" new
  local -a keys=()
  gemini_load_toggles
  if [[ "$pin" == pin ]]; then
    keys=("${GEMINI_TOGGLES[@]}")
  fi
  mkdir -p "$dir"
  chmod 0755 "$dir"
  new="$(jq --arg w "$LC_WITNESS" '.hooks.BeforeTool[0].hooks = [{type: "command",
      command: $w, name: "lockcheck-witness", timeout: 10000}] + .hooks.BeforeTool[0].hooks' \
    "$LC_MANAGED/gemini/settings.json" | gemini_json_set_toggles on "${keys[@]}")"
  printf '%s\n' "$new" >"$dir/settings.json"
  chmod 0644 "$dir/settings.json"
}

agent_baseline() {
  gemini_write_managed pin
  lc_as_agent_write "$LC_HOME/.gemini/trustedFolders.json" \
    "$(jq -n --arg p "$LC_PROJECT" '{($p): "TRUST_FOLDER"}')"
}

# --- setup fns ---------------------------------------------------------------

gemini_toggle_off_user() {
  gemini_update_as_agent "$LC_HOME/.gemini/settings.json" gemini_json_set_toggles off "$GEMINI_KEY"
}

gemini_toggle_off_project() {
  gemini_update_as_agent "$LC_PROJECT/.gemini/settings.json" gemini_json_set_toggles off "$GEMINI_KEY"
}

gemini_pin_needed() {
  gemini_write_managed nopin
  gemini_toggle_off_user
}

gemini_hooks_empty_user() {
  gemini_update_as_agent "$LC_HOME/.gemini/settings.json" jq '.hooks = {BeforeTool: []}'
}

gemini_hooks_empty_project() {
  gemini_update_as_agent "$LC_PROJECT/.gemini/settings.json" jq '.hooks = {BeforeTool: []}'
}

# GEMINI_CLI_HOME=~/alt: a second home whose user settings switch every
# toggle off; it shares the login through symlinks.
gemini_home() {
  local alt="$LC_HOME/alt/.gemini" f
  lc_as_agent_write "$alt/settings.json" \
    "$(gemini_read_json "$LC_HOME/.gemini/settings.json" | gemini_json_set_toggles off "${GEMINI_TOGGLES[@]}")"
  lc_as_agent_write "$alt/trustedFolders.json" \
    "$(gemini_read_json "$LC_HOME/.gemini/trustedFolders.json")"
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    lc_require_path "$alt/$(basename "$f")" || return 1
    ln -sfn "$f" "$alt/$(basename "$f")"
    lc_chown_agent -h "$alt/$(basename "$f")"
  done < <(agent_login_files)
  LC_AGENT_ENV=("GEMINI_CLI_HOME=$LC_HOME/alt")
}

gemini_system_path_env() {
  local f="$LC_ROOT/work/empty-settings.json"
  lc_require_path "$f" || return 1
  mkdir -p "$(dirname "$f")"
  printf '{}\n' >"$f"
  chmod 0644 "$f"
  LC_AGENT_ENV=("GEMINI_CLI_SYSTEM_SETTINGS_PATH=$f")
}

gemini_mcp() {
  # jq program: $js is a jq variable, not a shell one.
  # shellcheck disable=SC2016
  gemini_update_as_agent "$LC_HOME/.gemini/settings.json" \
    jq --arg js "$LC_SRC/mcp-marker.js" '.mcpServers.lockcheck = {command: "node", args: [$js]}'
  LC_PROMPT="$(printf 'Call the tool touch_marker of the MCP server lockcheck with the argument name set to %s. Do not use any other tool. Then reply DONE.' "$LC_NONCE")"
}

gemini_mcp_tool_names() {
  local names
  names="$(lc_calls_tool_names "$1")"
  printf 'tool_name=%s (§6.1.4 expects mcp_lockcheck_touch_marker)' "${names:-none}"
}

gemini_mcp_hooked() {
  gemini_mcp
  LC_POST=gemini_mcp_tool_names
}

gemini_mcp_excluded() {
  gemini_mcp
  gemini_update_managed jq '.mcp.excluded = ["lockcheck"]'
}

gemini_mcp_allowlist() {
  gemini_mcp
  gemini_update_managed jq '.mcp.allowed = ["other"]'
}

# §6.1.3 also names "command-line settings". Gemini CLI has no flag that
# loads a settings file or switches hooks (research
# 2026-10-13-gemini-hooks.md lists only the settings files and the
# GEMINI_CLI_SYSTEM_SETTINGS_PATH / GEMINI_CLI_HOME environment overrides),
# so there is no command-line gate row. This probe re-checks that claim
# against the installed version's --help: `found` means a gate row is due.
gemini_cli_settings_probe() {
  local flags
  flags="$(lc_agent_call gemini_help 2>/dev/null | grep -oE -- '--[A-Za-z][A-Za-z0-9-]*' |
    grep -iE 'setting|hook' | sort -u | paste -sd' ' - || true)"
  if [[ -n "$flags" ]]; then
    lc_probe gemini.cli.settings-flag found "$flags: a command-line gate row is due"
  else
    lc_probe gemini.cli.settings-flag not-found "gemini --help lists no settings/hooks flag"
  fi
}

# --- the checks --------------------------------------------------------------

agent_checks() {
  local k
  gemini_load_toggles
  lc_check gemini.control control ran allow -
  if ((${#GEMINI_TOGGLES[@]})); then
    lc_probe gemini.toggle.probe found "${GEMINI_TOGGLES[*]} ($GEMINI_TOGGLE_SRC)"
  else
    lc_probe gemini.toggle.probe not-found "no hooks toggle in schema ($GEMINI_TOGGLE_SRC)"
  fi
  gemini_cli_settings_probe
  lc_check gemini.system.fires gate fired allow -
  lc_check gemini.deny gate blocked deny -
  # No toggle key found: the main "user settings switch hooks off" vector
  # would go untested, so a gate row says so and the label is `unverified`.
  if ((${#GEMINI_TOGGLES[@]} == 0)); then
    lc_record gemini.toggle-off.user gate blocked inconclusive \
      "no hooks toggle found ($GEMINI_TOGGLE_SRC); rerun with LOCKCHECK_GEMINI_TOGGLE=<key>"
  fi
  for k in "${GEMINI_TOGGLES[@]}"; do
    GEMINI_KEY="$k"
    lc_check "gemini.toggle-off.user.$k" gate blocked deny gemini_toggle_off_user
  done
  for k in "${GEMINI_TOGGLES[@]}"; do
    GEMINI_KEY="$k"
    lc_check "gemini.toggle-off.project.$k" gate blocked deny gemini_toggle_off_project
  done
  for k in "${GEMINI_TOGGLES[@]}"; do
    GEMINI_KEY="$k"
    lc_check "gemini.pin-needed.$k" design blocked deny gemini_pin_needed
  done
  GEMINI_KEY=""
  lc_check gemini.hooks-empty.user gate blocked deny gemini_hooks_empty_user
  lc_check gemini.hooks-empty.project gate blocked deny gemini_hooks_empty_project
  lc_check gemini.gemini-home gate blocked deny gemini_home
  lc_check gemini.system-path-env caveat ran deny gemini_system_path_env
  lc_check gemini.fail.exit3 gate blocked exit3 -
  lc_check gemini.fail.exit101 gate blocked panic -
  lc_check gemini.fail.segv info blocked segv -
  lc_check gemini.fail.timeout gap ran hang -
  lc_check gemini.fail.missing info blocked missing -
  lc_check gemini.fail.exit1 info ran exit1 -
  lc_check gemini.mcp.control design ran allow gemini_mcp
  lc_check gemini.mcp.hooked design fired allow gemini_mcp_hooked
  lc_check gemini.mcp.excluded design unavailable allow gemini_mcp_excluded gemini.mcp.control
  lc_check gemini.mcp.allowlist design unavailable allow gemini_mcp_allowlist gemini.mcp.control
}
