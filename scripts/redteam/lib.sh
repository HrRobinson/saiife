#!/usr/bin/env bash
# Attacker-side helpers for the red-team scripts (plan 9c). Sourcing this
# file only defines functions: each scripts/redteam/aNN-*.sh checks the CI
# gate and its own user (agent-ci) first, then sources the staged copy:
#
#   source "$RT_STAGE/lib.sh"; rt_init a05
#
# The runner (run.sh) starts every attack with RT_STAGE, HOME=/home/agent-ci
# and the gate variables set. scripts/redteam/test-lib.sh sources this file
# offline to test the row helpers; nothing here runs on load.
#
# Each attempt prints one row on stdout, and nothing else ever goes there:
#
#   RT<TAB><attack><TAB><type><TAB><status><TAB><agent or -><TAB><label>
#
# type: deny | allow | gap:<id> | refused | check | forge
# status: pass | fail, or held | closed for gap rows (or fail on an exit
# other than 0 and 2). Tabs and newlines in a label become spaces.
#
# A direct attempt never prints the command's stdout: a regression that let
# `cat /etc/saiife/credstore/vault-key` succeed must not put the key in a
# public CI log. Only its byte count is reported.

# The installed binary the managed hooks run. Only test-lib.sh points this
# elsewhere (a fake hook); the runner starts the attacks with env -i.
: "${RT_SAIIFE:=/opt/saiife/bin/saiife}"

# `rt_row <type> <status> <agent or -> <label>`: one row on stdout.
rt_row() {
    local label="$4"
    label="${label//$'\t'/ }"
    label="${label//$'\n'/ }"
    label="${label//$'\r'/ }"
    printf 'RT\t%s\t%s\t%s\t%s\t%s\n' "${RT_ATTACK:?rt_init first}" "$1" "$2" "$3" "$label"
}

# `rt_log <text>`: a note for the job log (stderr; never a row).
rt_log() {
    printf '  [%s] %s\n' "${RT_ATTACK:-?}" "$*" >&2
}

# `rt_init <attack>`: a fresh private scratch dir under the agent's home.
rt_init() {
    RT_ATTACK="$1"
    RT_TMP="$HOME/rt/$1"
    RT_CWD="$HOME"
    mkdir -p "$HOME/rt"
    chmod 0700 "$HOME/rt"
    rm -rf "$RT_TMP"
    mkdir -m 0700 "$RT_TMP"
    cd "$HOME" || return 1
    export RT_ATTACK RT_TMP RT_CWD
}

# `rt_payload <fixture> [jq filter]`: the path of a copy of a staged
# fixture, with `.cwd = $RT_CWD` and then the filter applied.
rt_payload() {
    local out
    out="$(mktemp -p "${RT_TMP:?rt_init first}" payload.XXXXXX)"
    jq -c --arg cwd "$RT_CWD" ".cwd = \$cwd | ${2:-.}" "${RT_STAGE:?}/fixtures/$1" >"$out" || return 1
    printf '%s\n' "$out"
}

# A JSON string literal for a jq filter (a JSON string is a valid jq
# string; `\(` arrives escaped as `\\(`).
rt_json_str() {
    jq -cn --arg s "$1" '$s'
}

# `_rt_hook_row <deny|allow> <agent> <label>`: the row for RT_CODE.
_rt_hook_row() {
    local kind="$1" status=fail
    if [[ "$kind" == deny && "$RT_CODE" == 2 ]] || [[ "$kind" == allow && "$RT_CODE" == 0 ]]; then
        status=pass
    fi
    [[ "$status" == pass ]] || rt_log "hook $kind row failed (exit $RT_CODE): $3: $RT_ERR"
    rt_row "$kind" "$status" "$2" "$3"
}

# `rt_hook <deny|allow> <agent> <payload> <label> [VAR=val...]`: the managed
# hook command, in RT_CWD, on the payload. Sets RT_CODE and RT_ERR.
rt_hook() {
    local kind="$1" agent="$2" file="$3" label="$4" err
    shift 4
    err="$(mktemp -p "${RT_TMP:?rt_init first}" hook-err.XXXXXX)"
    RT_CODE=0
    env -C "$RT_CWD" "$@" "$RT_SAIIFE" check --managed --hook-exit --agent "$agent" \
        <"$file" >/dev/null 2>"$err" || RT_CODE=$?
    RT_ERR="$(head -c 2000 "$err")"
    rm -f "$err"
    _rt_hook_row "$kind" "$agent" "$label"
}

# `rt_hook_cmd <deny|allow> <agent> <payload> <label> <command string>
# [VAR=val...]`: as rt_hook, but the payload is fed to `sh -c <command
# string>` (a managed hook command as the agent's config holds it).
rt_hook_cmd() {
    local kind="$1" agent="$2" file="$3" label="$4" cmd="$5" err
    shift 5
    err="$(mktemp -p "${RT_TMP:?rt_init first}" hook-err.XXXXXX)"
    RT_CODE=0
    env -C "$RT_CWD" "$@" sh -c "$cmd" <"$file" >/dev/null 2>"$err" || RT_CODE=$?
    RT_ERR="$(head -c 2000 "$err")"
    rm -f "$err"
    _rt_hook_row "$kind" "$agent" "$label"
}

# The shell-tool fixture for an agent, its command at .tool_input.command.
_rt_shell_fixture() {
    case "$1" in
    claude) echo claude/bash-allow.json ;;
    codex) echo codex/bash-allow.json ;;
    gemini) echo gemini/shell-allow.json ;;
    *) return 1 ;;
    esac
}

# `rt_bash <deny|allow> <command>`: a Claude Bash call of the command.
rt_bash() {
    local p
    p="$(rt_payload claude/bash-allow.json ".tool_input.command = $(rt_json_str "$2")")" || {
        rt_row "$1" fail claude "$2 (payload could not be made)"
        return 0
    }
    rt_hook "$1" claude "$p" "$2"
}

# `rt_gap <gap id> <command> [agent]`: a documented "Not covered" command,
# judged by the hook only (never run). held = allowed (exit 0, expected),
# closed = blocked (exit 2: the gap closed), fail = any other exit.
rt_gap() {
    local id="$1" cmd="$2" agent="${3:-claude}" fixture p err status
    fixture="$(_rt_shell_fixture "$agent")" || {
        rt_row "gap:$id" fail "$agent" "$cmd (unknown agent)"
        return 0
    }
    p="$(rt_payload "$fixture" ".tool_input.command = $(rt_json_str "$cmd")")" || {
        rt_row "gap:$id" fail "$agent" "$cmd (payload could not be made)"
        return 0
    }
    err="$(mktemp -p "${RT_TMP:?rt_init first}" hook-err.XXXXXX)"
    RT_CODE=0
    env -C "$RT_CWD" "$RT_SAIIFE" check --managed --hook-exit --agent "$agent" \
        <"$p" >/dev/null 2>"$err" || RT_CODE=$?
    RT_ERR="$(head -c 2000 "$err")"
    rm -f "$err"
    case "$RT_CODE" in
    0) status=held ;;
    2) status=closed ;;
    *)
        status=fail
        rt_log "gap $id: hook exit $RT_CODE: $cmd: $RT_ERR"
        ;;
    esac
    rt_row "gap:$id" "$status" "$agent" "$cmd"
}

# `rt_refused <label> <regex> <cmd...>`: a direct attempt that must fail
# with an error matching the regex in the first 200 bytes of stderr. Its
# stdout is never shown: on an unexpected success only the byte count is.
rt_refused() {
    local label="$1" regex="$2" err codef code bytes msg
    shift 2
    err="$(mktemp -p "${RT_TMP:?rt_init first}" refused-err.XXXXXX)"
    codef="$(mktemp -p "$RT_TMP" refused-code.XXXXXX)"
    bytes="$({ "$@" </dev/null 2>"$err" && echo 0 >"$codef" || echo "$?" >"$codef"; } | wc -c)"
    code="$(cat "$codef")"
    msg="$(head -c 200 "$err")"
    rm -f "$err" "$codef"
    msg="${msg//$'\n'/ }"
    if [[ "$code" == 0 ]]; then
        rt_row refused fail - "$label (succeeded; ${bytes// /} bytes of output suppressed)"
    elif [[ "$msg" =~ $regex ]]; then
        rt_row refused pass - "$label"
    else
        rt_row refused fail - "$label (exit $code; stderr does not match /$regex/: $msg)"
    fi
}

# `rt_check <label> <cmd...>`: pass on exit 0. The command's stdout is not
# shown; its stderr goes to the job log.
rt_check() {
    local label="$1" code=0
    shift
    "$@" </dev/null >/dev/null || code=$?
    if [[ "$code" == 0 ]]; then
        rt_row check pass - "$label"
    else
        rt_row check fail - "$label (exit $code)"
    fi
}

# `rt_forge <nonce>`: a forged guard append through ipc.py; the label is the
# nonce, for the runner to find the record the daemon made of it.
rt_forge() {
    local out
    out="$(python3 -I "${RT_STAGE:?}/ipc.py" forge-guard "$1" </dev/null)" || true
    if jq -e '.ok == true' >/dev/null 2>&1 <<<"$out"; then
        rt_row forge pass - "$1"
    else
        rt_log "forge-guard answered: $out"
        rt_row forge fail - "$1"
    fi
}
