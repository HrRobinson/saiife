#!/usr/bin/env bash
# Offline tests of the red-team framework (plan 9c): row pairing, gap rows,
# the summary, the gap-doc check, the row helpers on harmless commands, and
# static lints over every scripts/redteam/*.sh. Safe anywhere: it sources
# check.sh and lib.sh (functions only), works on synthetic files under a
# temp dir, and never executes run.sh or an attack script.
#
#   bash scripts/redteam/test-lib.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# shellcheck source=scripts/redteam/check.sh
source "$HERE/check.sh"
# shellcheck source=scripts/redteam/lib.sh
source "$HERE/lib.sh"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# The exact CI gate lines (plan 9c, Global Constraints), as literal text.
# shellcheck disable=SC2016
GATE_CI='[[ "${GITHUB_ACTIONS:-}" == true && "${SAIIFE_LOCKED_CI:-}" == 1 ]] || { echo "refusing: red-team scripts run only in the GitHub locked-linux job" >&2; exit 2; }'
# shellcheck disable=SC2016
GATE_AGENT='[[ "$(id -un)" == agent-ci ]] || { echo "refusing: red-team attacks run only as agent-ci" >&2; exit 2; }'

CURRENT=""

t_fail() {
    echo "FAIL $CURRENT: $*" >&2
    exit 1
}

# `t_has <haystack> <needle> <what>`
t_has() {
    [[ "$1" == *"$2"* ]] || t_fail "$3: lacks \"$2\" in: $1"
}

t_lacks() {
    [[ "$1" != *"$2"* ]] || t_fail "$3: holds \"$2\" in: $1"
}

t_eq() {
    [[ "$1" == "$2" ]] || t_fail "$3: got \"$1\", want \"$2\""
}

# `row <type> <status> <agent> <label>` (attack t1).
row() {
    printf 'RT\tt1\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"
}

# `rec <decision> [comm] [agent] [mode] [user]`: a guard record.
rec() {
    jq -cn --arg d "$1" --arg c "${2:-saiife}" --arg a "${3:-claude}" --arg m "${4:-locked}" \
        --arg u "${5:-agent-ci}" --arg p "${6:-h1}" \
        '{v: 2, kind: "guard", decision: $d, agent: $a, mode: $m, user: $u, uid: 1001, input: "x", policy: $p, peer: {pid: 1, comm: $c}}'
}

# The verdict column of rt_zip's output, space separated.
verdicts() {
    cut -f1 | paste -sd' ' -
}

# ------------------------------------------------------------ rt_zip

test_zip_pairs_in_order() {
    {
        row deny pass claude "rm -rf /"
        row allow pass claude "ls"
        row gap:lock-pid held claude "kill -TERM 1234"
    } >"$T/rows"
    { rec deny; rec allow; rec allow; } >"$T/win"
    local out
    out="$(rt_zip "$T/rows" "$T/win" agent-ci)"
    t_eq "$(verdicts <<<"$out")" "PASS PASS GAP" "verdicts"
    t_has "$out" $'GAP\tt1\tkill -TERM 1234\tdocs/packs/core.lock.md: "`kill 1234` where 1234 is saiifed\'s process id"' "gap detail"
    t_has "$out" $'PASS\tt1\trm -rf /\tdeny' "deny detail"
}

test_zip_ignores_python_records() {
    {
        row deny pass claude "rm -rf /"
        row allow pass claude "ls"
        row gap:lock-pid held claude "kill -TERM 1234"
    } >"$T/rows"
    { rec allow python3; rec deny; rec deny python3; rec allow; rec allow python3; rec allow; } >"$T/win"
    t_eq "$(rt_zip "$T/rows" "$T/win" agent-ci | verdicts)" "PASS PASS GAP" "verdicts"
}

test_zip_ignores_other_users_and_kinds() {
    row deny pass claude "rm -rf /" >"$T/rows"
    {
        rec allow saiife claude locked runner
        echo '{"kind":"daemon","event":"start"}'
        rec deny
    } >"$T/win"
    t_eq "$(rt_zip "$T/rows" "$T/win" agent-ci | verdicts)" "PASS" "verdicts"
}

test_zip_count_mismatch_fails() {
    {
        row deny pass claude a
        row allow pass claude b
        row deny pass claude c
    } >"$T/rows"
    { rec deny; rec allow; } >"$T/win"
    local out
    out="$(rt_zip "$T/rows" "$T/win" agent-ci)"
    t_has "$out" "3 hook rows, 2 records" "mismatch"
    t_has "$(head -n1 <<<"$out")" "FAIL" "first line"
    t_has "$out" $'FAIL\tt1\tc\tdeny: no guard record' "unpaired row"
}

test_zip_decision_mismatch_fails() {
    row deny pass claude "rm -rf /" >"$T/rows"
    rec allow >"$T/win"
    local out
    out="$(rt_zip "$T/rows" "$T/win" agent-ci)"
    t_eq "$(verdicts <<<"$out")" "FAIL" "verdicts"
    t_has "$out" "record decision allow, want deny" "detail"
}

test_zip_agent_and_mode_checked() {
    {
        row deny pass codex a
        row deny pass claude b
    } >"$T/rows"
    { rec deny saiife claude; rec deny saiife claude developer; } >"$T/win"
    local out
    out="$(rt_zip "$T/rows" "$T/win" agent-ci)"
    t_eq "$(verdicts <<<"$out")" "FAIL FAIL" "verdicts"
    t_has "$out" "record agent claude, want codex" "agent"
    t_has "$out" "record mode developer, want locked" "mode"
}

test_zip_hook_exit_wrong_fails() {
    row deny fail claude "rm -rf /" >"$T/rows"
    rec deny >"$T/win"
    t_has "$(rt_zip "$T/rows" "$T/win" agent-ci)" $'FAIL\tt1\trm -rf /\tdeny: hook exit was not 2' "detail"
}

test_zip_direct_rows() {
    {
        row refused pass - "cat key"
        row refused fail - "rm x (succeeded; 0 bytes of output suppressed)"
        row check pass - "mode"
        row forge pass - "rt-a08-1"
    } >"$T/rows"
    : >"$T/win"
    t_eq "$(rt_zip "$T/rows" "$T/win" agent-ci | verdicts)" "PASS FAIL PASS PASS" "verdicts"
}

test_zip_unknown_gap_fails() {
    row gap:no-such-gap held claude "x" >"$T/rows"
    rec allow >"$T/win"
    t_has "$(rt_zip "$T/rows" "$T/win" agent-ci)" "gap id no-such-gap is not in expected-gaps.tsv" "detail"
}

test_paired_field() {
    {
        row allow pass claude base
        row deny pass claude x
        row allow pass claude loose
    } >"$T/rows"
    { rec allow saiife claude locked agent-ci h1; rec deny saiife claude locked agent-ci h9; rec allow python3; rec allow saiife claude locked agent-ci h2; } >"$T/win"
    t_eq "$(rt_paired_field "$T/rows" "$T/win" agent-ci allow .policy | paste -sd' ' -)" '"h1" "h2"' "policies"
}

# ------------------------------------------------------------ rt_summary

test_gap_closed_fails_summary() {
    row gap:lock-pid closed claude "kill -TERM 1234" >"$T/rows"
    rec deny >"$T/win"
    rt_zip "$T/rows" "$T/win" agent-ci >"$T/verdicts"
    t_eq "$(verdicts <"$T/verdicts")" "GAPCLOSED" "verdicts"
    local out code=0
    out="$(GITHUB_STEP_SUMMARY="$T/step.md" rt_summary "$T/verdicts")" || code=$?
    t_eq "$code" 1 "rt_summary exit"
    t_has "$out" 'move it out of "Not covered" in docs/packs/core.lock.md' "instruction"
    t_has "$out" "drop lock-pid from scripts/redteam/expected-gaps.tsv" "instruction"
    t_has "$(cat "$T/step.md")" 'move it out of "Not covered"' "step summary"
}

test_summary_gaps_are_not_regressions() {
    {
        rt_verdict PASS a05 "systemctl stop saiifed" deny
        rt_verdict PASS a05 "kill -TERM 4321" refused
        rt_verdict PASS a05 "ls" allow
        rt_verdict PASS a05 "MainPID unchanged" check
        rt_verdict GAP a05 "kill -TERM 1234" 'docs/packs/core.lock.md: "x"'
    } >"$T/verdicts"
    local out code=0
    out="$(GITHUB_STEP_SUMMARY="$T/step.md" rt_summary "$T/verdicts")" || code=$?
    t_eq "$code" 0 "rt_summary exit"
    t_has "$out" "Known gaps (documented, expected)" "gaps header"
    t_has "$out" "kill -TERM 1234" "gap listed"
    t_has "$out" $'Regressions\n  none' "no regressions"
    t_has "$out" "$(_rt_trow a05 1 1 1 1 0)" "table row"
    t_has "$(cat "$T/step.md")" "| a05 | 1 | 1 | 1 | 1 | 0 |" "markdown row"
}

test_summary_empty_fails() {
    : >"$T/verdicts"
    local code=0
    rt_summary "$T/verdicts" >/dev/null || code=$?
    t_eq "$code" 1 "empty summary exit"
}

# ------------------------------------------------------------ gap docs

test_gap_quotes_in_docs() {
    local code=0 out
    out="$(rt_gap_doc_check "$HERE/expected-gaps.tsv" "$REPO")" || code=$?
    t_eq "$code" 0 "real tsv ($out)"
    [[ "$(wc -l <"$HERE/expected-gaps.tsv")" -eq 8 ]] || t_fail "expected-gaps.tsv is not a header and 7 rows"
    printf 'id\tattack\tdoc\tquote\nx\tA0\tdocs/packs/core.lock.md\tnonexistent words\n' >"$T/bad.tsv"
    code=0
    rt_gap_doc_check "$T/bad.tsv" "$REPO" >/dev/null || code=$?
    t_eq "$code" 1 "nonexistent quote"
    printf 'id\tattack\tdoc\tquote\nx\tA0\tdocs/packs/core.process.md\t%s\n' "pkill -f 'npm run dev'" >"$T/blocked.tsv"
    grep -qF "pkill -f 'npm run dev'" "$REPO/docs/packs/core.process.md" || t_fail "the Blocked-section probe is gone from core.process.md"
    code=0
    rt_gap_doc_check "$T/blocked.tsv" "$REPO" >/dev/null || code=$?
    t_eq "$code" 1 "quote outside Not covered"
}

# ------------------------------------------------------------ lib.sh rows

# A fake hook for rt_hook / rt_gap: exits with the number in $FAKE_EXIT.
fake_hook_env() {
    cat >"$T/fake-saiife" <<'EOF'
#!/bin/sh
cat >/dev/null
echo "fake hook stderr" >&2
exit "${FAKE_EXIT:-0}"
EOF
    chmod +x "$T/fake-saiife"
    mkdir -p "$T/stage/fixtures/claude" "$T/stage/fixtures/codex" "$T/stage/fixtures/gemini" "$T/home/rt/t1"
    cp "$REPO/crates/cli/tests/fixtures/claude/bash-allow.json" "$T/stage/fixtures/claude/"
    cp "$REPO/crates/cli/tests/fixtures/codex/bash-allow.json" "$T/stage/fixtures/codex/"
    cp "$REPO/crates/cli/tests/fixtures/gemini/shell-allow.json" "$T/stage/fixtures/gemini/"
    RT_SAIIFE="$T/fake-saiife"
    RT_STAGE="$T/stage"
    RT_ATTACK=t1
    RT_TMP="$T/home/rt/t1"
    RT_CWD="$T/home"
}

test_refused_never_prints_stdout() {
    fake_hook_env
    local out err
    out="$(rt_refused "leak" "denied" sh -c 'echo SECRET-VALUE' 2>"$T/err")"
    err="$(cat "$T/err")"
    t_eq "$out" $'RT\tt1\trefused\tfail\t-\tleak (succeeded; 13 bytes of output suppressed)' "leak row"
    t_lacks "$out$err" "SECRET-VALUE" "leak output"
    out="$(rt_refused "ok" "Permission denied" sh -c 'echo SECRET >&1; echo "Permission denied" >&2; exit 1' 2>"$T/err")"
    err="$(cat "$T/err")"
    t_eq "$out" $'RT\tt1\trefused\tpass\t-\tok' "refused row"
    t_lacks "$out$err" "SECRET" "refused output"
    out="$(rt_refused "other" "Permission denied" sh -c 'echo SECRET; echo "No such file" >&2; exit 1' 2>"$T/err")"
    t_has "$out" $'refused\tfail\t-\tother (exit 1; stderr does not match' "wrong error"
    t_lacks "$out$(cat "$T/err")" "SECRET" "wrong-error output"
}

test_hook_rows() {
    fake_hook_env
    local p out
    p="$(rt_payload claude/bash-allow.json '.tool_input.command = "x"')"
    t_eq "$(jq -r '.cwd + " " + .tool_input.command' "$p")" "$T/home x" "payload"
    out="$(FAKE_EXIT=2 rt_hook deny claude "$p" "a label" 2>/dev/null)"
    t_eq "$out" $'RT\tt1\tdeny\tpass\tclaude\ta label' "deny pass"
    out="$(FAKE_EXIT=0 rt_hook deny claude "$p" "a label" 2>/dev/null)"
    t_eq "$out" $'RT\tt1\tdeny\tfail\tclaude\ta label' "deny fail"
    out="$(rt_hook allow codex "$p" $'two\tpart\nlabel' FAKE_EXIT=0 2>/dev/null)"
    t_eq "$out" $'RT\tt1\tallow\tpass\tcodex\ttwo part label' "allow pass, label cleaned, VAR=val"
    out="$(rt_hook_cmd deny gemini "$p" "managed cmd" "\"$RT_SAIIFE\" check" FAKE_EXIT=2 2>/dev/null)"
    t_eq "$out" $'RT\tt1\tdeny\tpass\tgemini\tmanaged cmd' "hook_cmd"
    out="$(FAKE_EXIT=2 rt_bash deny "it's a \"quoted\" \\( cmd" 2>/dev/null)"
    t_eq "$out" $'RT\tt1\tdeny\tpass\tclaude\tit\'s a "quoted" \\( cmd' "rt_bash"
}

test_gap_rows() {
    fake_hook_env
    t_eq "$(FAKE_EXIT=0 rt_gap lock-pid "kill -TERM 1234" 2>/dev/null)" $'RT\tt1\tgap:lock-pid\theld\tclaude\tkill -TERM 1234' "held"
    t_eq "$(FAKE_EXIT=2 rt_gap lock-pid "kill -TERM 1234" codex 2>/dev/null)" $'RT\tt1\tgap:lock-pid\tclosed\tcodex\tkill -TERM 1234' "closed"
    t_eq "$(FAKE_EXIT=1 rt_gap lock-pid "x" gemini 2>/dev/null)" $'RT\tt1\tgap:lock-pid\tfail\tgemini\tx' "fail"
}

test_check_rows() {
    fake_hook_env
    t_eq "$(rt_check "true" true)" $'RT\tt1\tcheck\tpass\t-\ttrue' "pass"
    t_eq "$(rt_check "no" sh -c 'echo hidden; exit 3')" $'RT\tt1\tcheck\tfail\t-\tno (exit 3)' "fail, stdout hidden"
}

# ------------------------------------------------------------ static lints

# The aNN attack scripts present (none before Tasks 4 and 5).
attack_scripts() {
    compgen -G "$HERE/a[0-9][0-9]-*.sh" || true
}

# The first <n> code lines: not the shebang, a comment, blank, or
# `set -euo pipefail`.
code_lines() {
    awk -v n="$2" '
        NR == 1 && /^#!/ { next }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ || /^set -euo pipefail$/ { next }
        { print; if (++c >= n) exit }
    ' "$1"
}

test_gate_lines_first() {
    local f
    t_eq "$(code_lines "$HERE/run.sh" 1)" "$GATE_CI" "run.sh first code line"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        t_eq "$(code_lines "$f" 2)" "$GATE_CI"$'\n'"$GATE_AGENT" "$(basename "$f") gate lines"
    done < <(attack_scripts)
}

test_no_broad_kills() {
    # Built from parts so this file does not match its own pattern.
    local k5='killall''5' hits
    hits="$(grep -nE "pkill +-[a-zA-Z]*[no]\\b|kill +(-[0-9A-Z]+ +)?(--? *)?-?[01]\\b|$k5|kill +-1\\b" "$HERE"/*.sh || true)"
    [[ -z "$hits" ]] || t_fail "broad kill forms: $hits"
}

test_background_helpers_trapped() {
    local f v
    for f in "$HERE"/*.sh; do
        [[ "$f" != "$HERE/test-lib.sh" ]] || continue
        grep -q 'serve-fake' "$f" || continue
        grep -q 'trap' "$f" || t_fail "$(basename "$f") starts serve-fake without a trap"
        v="$(grep -oE 'kill "\$[A-Za-z_][A-Za-z0-9_]*"' "$f" | head -n1 | sed 's/^kill "\$//; s/"$//' || true)"
        [[ -n "$v" ]] || t_fail "$(basename "$f") never kills its helper by pid"
        grep -qE "(^|[^A-Za-z0-9_])$v=\\\$!" "$f" || t_fail "$(basename "$f"): \$$v is not assigned from \$!"
    done
}

test_gap_ids_known() {
    local f id
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        while IFS= read -r id; do
            cut -f1 "$HERE/expected-gaps.tsv" | grep -qxF "$id" || t_fail "$(basename "$f"): rt_gap $id is not in expected-gaps.tsv"
        done < <(grep -oE "rt_gap +[\"']?[a-z0-9-]+" "$f" | sed -E "s/^rt_gap +[\"']?//")
    done < <(attack_scripts)
}

test_lib_files_define_functions_only() {
    local f bad
    for f in "$HERE/lib.sh" "$HERE/check.sh"; do
        # Top-level lines outside functions: comments, blanks, function
        # heads, and the two data assignments.
        bad="$(awk '
            /^[a-zA-Z_][a-zA-Z0-9_]*\(\) *\{$/ { infn = 1; next }
            infn && /^\}$/ { infn = 0; next }
            infn { next }
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            /^: "\$\{RT_SAIIFE:=/ { next }
            /^RT_JQ_DEFS=/ { injq = 1 }
            injq { if (/^'"'"'$/) injq = 0; next }
            { print FILENAME ":" NR ": " $0 }
        ' "$f")"
        [[ -z "$bad" ]] || t_fail "top-level code in a functions-only file: $bad"
    done
}

main() {
    local t
    # A command that fails outside an assertion stops the run: say where.
    set -E
    trap 'echo "FAIL $CURRENT: unexpected failure at line $LINENO: $BASH_COMMAND" >&2' ERR
    for t in $(declare -F | awk '$3 ~ /^test_/ { print $3 }'); do
        CURRENT="$t"
        rm -rf "${T:?}"/*
        "$t"
        echo "ok  $t"
    done
    echo "all red-team offline tests passed"
}

main "$@"
