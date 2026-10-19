#!/usr/bin/env bash
# Offline test for the Claude Code lock checks (checks-claude.sh).
#
# Loads checks-claude.sh against a temp LC_ROOT with lc_check and lc_record
# replaced by recorders, runs agent_checks, and checks the ids, classes and
# modes against the plan 7 table, the managed baseline (fixture copied byte
# for byte, witness drop-in) and what every setup fn leaves behind. No agent,
# Docker or network is used; HOME is pointed at a temp dir and every path is
# under LC_ROOT. The helpers mirror test-lib.sh's; the test can move into
# test-lib.sh unchanged (it is named test_claude_checks_static).
#
#   bash scripts/lock-check/test-claude.sh
set -euo pipefail
# Tests are called by name ("test_$name"), never directly.
# shellcheck disable=SC2317,SC2329

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() {
  echo "assertion failed: $*" >&2
  exit 1
}

assert_eq() {
  if [[ "$1" != "$2" ]]; then
    fail "${3:-values differ}: expected '$2', got '$1'"
  fi
}

new_root() {
  LC_ROOT="$(mktemp -d "$SCRATCH/root.XXXXXX")"
  export LC_ROOT
  # shellcheck source=/dev/null
  source "$HERE/lib.sh"
}

# --- test ------------------------------------------------------------------

# Loads checks-claude.sh with lc_check and lc_record replaced by recorders,
# runs agent_checks, and inspects what each setup fn left behind. lc_check's
# recorder runs the real lc_reset and the setup fn (nonce 0123456789ab) and
# saves the resulting state under $LC_ROOT/state/<id>/; no agent is run.
test_claude_checks_static() {
  new_root
  export HOME="$LC_ROOT/host-home"
  mkdir -p "$HOME" "$LC_ROOT/usr/local/bin"
  printf '#!/usr/bin/env bash\necho "2.1.300 (Claude Code)"\n' >"$LC_ROOT/usr/local/bin/claude"
  chmod 0755 "$LC_ROOT/usr/local/bin/claude"
  PATH="$LC_ROOT/usr/local/bin:$PATH"
  LC_MANAGED="$REPO/crates/agents/tests/fixtures/managed"
  LC_RESULTS="$LC_ROOT/results.tsv"
  : >"$LC_RESULTS"
  # shellcheck source=/dev/null
  source "$HERE/checks-claude.sh"
  local rec="$LC_ROOT/checks.rec" state="$LC_ROOT/state" managed
  managed="$LC_ROOT/etc/claude-code/managed-settings.d"
  : >"$rec"
  lc_record() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" - "${5:-}" >>"$rec"
  }
  lc_check() {
    local id="$1" setup="${5:--}" d="$state/$1" f
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$setup" "${6:-}" >>"$rec"
    lc_reset
    LC_NONCE=0123456789ab
    if [[ "$setup" != - ]]; then
      "$setup"
    fi
    mkdir -p "$d"
    printf '%s\n' "${LC_AGENT_ARGS[@]}" >"$d/args"
    printf '%s\n' "${LC_AGENT_ENV[@]}" >"$d/env"
    printf '%s' "$LC_PROMPT" >"$d/prompt"
    printf '%s' "$LC_FIRED_EVENT" >"$d/fired-event"
    printf '%s' "$LC_POST" >"$d/post"
    find "$managed" -mindepth 1 -printf '%f\n' | sort >"$d/managed"
    cp "$LC_RUN/mode.config-change" "$d/mode.config-change"
    local i=0
    while IFS= read -r f; do
      i=$((i + 1))
      if [[ -e "$f" ]]; then
        cp "$f" "$d/settings-$i"
      fi
    done < <(agent_settings_files)
    if [[ -d "$LC_HOME/alt" ]]; then
      cp -a "$LC_HOME/alt" "$d/alt"
    fi
    return 0
  }
  lc_snapshot
  agent_checks

  # Ids, in the order of the plan's table.
  assert_eq "$(cut -f1 "$rec" | paste -sd' ' -)" "claude.control claude.managed.fires \
claude.deny claude.disable.user claude.disable.project claude.disable.local claude.disable.cli \
claude.hooks-empty.user claude.config-dir claude.setting-sources claude.fail.exit101 \
claude.fail.segv claude.fail.kill9 claude.fail.timeout claude.fail.missing claude.fail.exit1 \
claude.configchange.fires claude.configchange.control claude.configchange.blocks \
claude.managed-only claude.mcp.control claude.mcp.hooked claude.mcp.denied claude.mcp.allowlist \
claude.version.onfailure" "check ids"
  # Class, expect, mode, control.
  assert_eq "$(awk -F'\t' '$2 == "gate" && $3 != "blocked" && $3 != "fired"' "$rec")" "" \
    "gate rows that expect neither blocked nor fired"
  assert_eq "$(awk -F'\t' '{ print $1, $2, $3, $4 }' "$rec" | paste -sd'|' -)" \
    "claude.control control ran allow|claude.managed.fires gate fired allow|\
claude.deny gate blocked deny|claude.disable.user gate blocked deny|\
claude.disable.project gate blocked deny|claude.disable.local gate blocked deny|\
claude.disable.cli gate blocked deny|claude.hooks-empty.user gate blocked deny|\
claude.config-dir gate blocked deny|claude.setting-sources gate blocked deny|\
claude.fail.exit101 gate blocked panic|claude.fail.segv gate blocked segv|\
claude.fail.kill9 gate blocked kill9|claude.fail.timeout gate blocked hang|\
claude.fail.missing gate blocked missing|claude.fail.exit1 design blocked exit1|\
claude.configchange.fires design fired allow|claude.configchange.control design ran allow|\
claude.configchange.blocks design blocked allow|claude.managed-only design blocked allow|\
claude.mcp.control design ran allow|claude.mcp.hooked design fired allow|\
claude.mcp.denied design unavailable allow|claude.mcp.allowlist design unavailable allow|\
claude.version.onfailure info - found" "class, expect, mode"
  assert_eq "$(awk -F'\t' '$3 == "unavailable" { print $6 }' "$rec" | sort -u)" claude.mcp.control \
    "control of the unavailable rows"
  assert_eq "$(awk -F'\t' '$1 == "claude.version.onfailure" { print $6 }' "$rec")" \
    "2.1.300 (Claude Code)" "version probe detail"

  # Baseline: fixture byte-identical, witness drop-in parses, nothing else.
  cmp -s "$managed/50-saiife.json" "$LC_MANAGED/claude/50-saiife.json" ||
    fail "50-saiife.json differs from the fixture"
  assert_eq "$(jq -r '.hooks.PreToolUse[0] | "\(.matcher) \(.hooks[0].command) \(.hooks[0].timeout)"' \
    "$managed/60-lockcheck-witness.json")" "* $LC_WITNESS 10" "witness drop-in"
  assert_eq "$(stat -c %a "$managed" "$managed/50-saiife.json" "$managed/60-lockcheck-witness.json" |
    paste -sd' ' -)" "755 644 644" "managed modes"
  [[ ! -e "$LC_ROOT/etc/claude-code/managed-settings.json" ]] || fail "managed-settings.json exists"
  assert_eq "$(paste -sd' ' "$state/claude.control/managed")" \
    "50-saiife.json 60-lockcheck-witness.json" "baseline drop-ins"
  assert_eq "$(paste -sd' ' "$state/claude.mcp.allowlist/managed")" \
    "50-saiife.json 60-lockcheck-witness.json 70-lockcheck-mcp.json" "allowlist drop-ins"
  [[ ! -e "$state/claude.version.onfailure" ]] || fail "the probe ran a check"

  # Settings and login files all live under LC_ROOT; login files are not settings.
  while IFS= read -r f; do
    [[ "$f" == "$LC_ROOT/"* ]] || fail "path outside LC_ROOT: $f"
  done < <(agent_settings_files; agent_login_files)
  assert_eq "$(agent_settings_files | paste -sd' ' -)" "$LC_HOME/.claude/settings.json \
$LC_PROJECT/.claude/settings.json $LC_PROJECT/.claude/settings.local.json" "settings files"
  assert_eq "$(agent_login_files | paste -sd' ' -)" \
    "$LC_HOME/.claude/.credentials.json $LC_HOME/.claude.json" "login files"

  # Setups.
  local s="$state"
  assert_eq "$(jq -c . "$s/claude.disable.user/settings-1")" '{"disableAllHooks":true}'
  assert_eq "$(jq -c . "$s/claude.disable.project/settings-2")" '{"disableAllHooks":true}'
  assert_eq "$(jq -c . "$s/claude.disable.local/settings-3")" '{"disableAllHooks":true}'
  [[ ! -e "$s/claude.disable.local/settings-1" && ! -e "$s/claude.disable.local/settings-2" ]] ||
    fail "reset left settings behind"
  assert_eq "$(paste -sd' ' "$s/claude.disable.cli/args")" '--settings {"disableAllHooks":true}'
  assert_eq "$(jq -c . "$s/claude.hooks-empty.user/settings-1")" '{"hooks":{"PreToolUse":[]}}'
  assert_eq "$(cat "$s/claude.config-dir/env")" "CLAUDE_CONFIG_DIR=$LC_HOME/alt"
  assert_eq "$(jq -c . "$s/claude.config-dir/alt/settings.json")" '{"disableAllHooks":true}'
  assert_eq "$(readlink "$s/claude.config-dir/alt/.credentials.json")" "$LC_HOME/.claude/.credentials.json"
  assert_eq "$(readlink "$s/claude.config-dir/alt/.claude.json")" "$LC_HOME/.claude.json"
  [[ ! -e "$LC_HOME/alt" ]] || fail "alt dir left after the last reset"
  assert_eq "$(paste -sd' ' "$s/claude.setting-sources/args")" "--setting-sources user"
  assert_eq "$(cat "$s/claude.configchange.fires/fired-event")" config-change
  grep -qF "$LC_PROJECT/.claude/settings.local.json" "$s/claude.configchange.fires/prompt" ||
    fail "configchange.fires prompt: $(cat "$s/claude.configchange.fires/prompt")"
  grep -qF "$LC_MARKERS/0123456789ab" "$s/claude.configchange.fires/prompt" || fail "fires marker"
  assert_eq "$(cat "$s/claude.configchange.control/mode.config-change")" allow
  assert_eq "$(cat "$s/claude.configchange.blocks/mode.config-change")" deny
  assert_eq "$(cat "$s/claude.configchange.blocks/prompt")" "$(cat "$s/claude.configchange.control/prompt")" \
    "configchange prompts"
  grep -qF "$LC_HOME/.claude/settings.json" "$s/claude.configchange.control/prompt" || fail "control prompt"
  grep -qF "touch $LC_MARKERS/0123456789ab" "$s/claude.configchange.control/prompt" || fail "control hook"
  grep -qF "echo 0123456789ab" "$s/claude.configchange.control/prompt" || fail "control echo"
  assert_eq "$(paste -sd' ' "$s/claude.managed-only/managed")" \
    "50-saiife.json 60-lockcheck-witness.json 70-lockcheck-only.json" "managed-only drop-ins"
  assert_eq "$(jq -r '.hooks.PreToolUse[0] | "\(.matcher) \(.hooks[0].command)"' \
    "$s/claude.managed-only/settings-1")" "* touch $LC_MARKERS/0123456789ab" "user hook"
  grep -qF "echo 0123456789ab" "$s/claude.managed-only/prompt" || fail "managed-only prompt"
  local m
  for m in control hooked denied allowlist; do
    assert_eq "$(paste -sd' ' "$s/claude.mcp.$m/args")" "--mcp-config $LC_ROOT/work/lockcheck-mcp.json" \
      "mcp.$m args"
    grep -qF touch_marker "$s/claude.mcp.$m/prompt" || fail "mcp.$m prompt"
    grep -qF 0123456789ab "$s/claude.mcp.$m/prompt" || fail "mcp.$m nonce"
  done
  [[ -n "$(cat "$s/claude.mcp.hooked/post")" ]] || fail "mcp.hooked has no LC_POST"
  [[ -z "$(cat "$s/claude.mcp.control/post")" ]] || fail "mcp.control has LC_POST"
  printf '1\tpre-tool\tallow\t{"tool_name":"mcp__lockcheck__touch_marker","n":"0123456789ab"}\n' \
    >"$LC_RUN/calls.log"
  assert_eq "$("$(cat "$s/claude.mcp.hooked/post")" 0123456789ab)" \
    "tool_name=mcp__lockcheck__touch_marker" "mcp.hooked detail"
  assert_eq "$(jq -c . "$LC_ROOT/work/lockcheck-mcp.json")" \
    "$(jq -nc --arg js "$LC_SRC/mcp-marker.js" --arg m "$LC_MARKERS" \
      '{mcpServers:{lockcheck:{command:"node",args:[$js],env:{LOCKCHECK_MARKERS:$m}}}}')" "mcp config"
  # The denied/allowlist drop-ins (state saved before the next reset).
  lc_reset
  LC_NONCE=0123456789ab
  claude_setup_mcp_denied
  assert_eq "$(jq -c . "$managed/70-lockcheck-mcp.json")" '{"deniedMcpServers":[{"serverName":"lockcheck"}]}'
  lc_reset
  claude_setup_mcp_allowlist
  assert_eq "$(jq -c . "$managed/70-lockcheck-mcp.json")" '{"allowedMcpServers":[{"serverName":"other"}]}'
  lc_reset
  [[ ! -e "$managed/70-lockcheck-mcp.json" ]] || fail "reset kept 70-lockcheck-mcp.json"

  # agent_invoke is self-contained (shipped with declare -f).
  declare -f agent_invoke | grep -qE 'claude -p "\$1" --dangerously-skip-permissions --output-format text "\$\{@:2\}"' ||
    fail "agent_invoke: $(declare -f agent_invoke)"
  assert_eq "$(find "$HOME" -mindepth 1)" "" "files written to HOME"
}

main() {
  local name rc failed=0
  for name in claude_checks_static; do
    set +e
    (
      set -euo pipefail
      cd "$SCRATCH"
      "test_$name"
    ) >"$SCRATCH/$name.log" 2>&1
    rc=$?
    set -e
    if ((rc == 0)); then
      echo "ok $name"
    else
      echo "FAIL $name"
      sed 's/^/    /' "$SCRATCH/$name.log"
      failed=1
    fi
  done
  return "$failed"
}

main "$@"
