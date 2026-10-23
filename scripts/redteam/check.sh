#!/usr/bin/env bash
# Runner-side logic of the red team (plan 9c): pairing attack rows with the
# guard records the real hook wrote, the gap-doc check and the summary.
# Sourcing this file only defines functions; it reads only the files it is
# given. run.sh uses it on the CI runner, and scripts/redteam/test-lib.sh
# tests it offline on synthetic files.
#
# Verdict lines, one per judged row:
#
#   PASS|FAIL|GAP|GAPCLOSED<TAB><attack><TAB><label><TAB><detail>
#
# A PASS detail is the row type (deny, allow, refused, check, forge), which
# the summary counts by. A FAIL detail starts with the type and a colon.

# The expected-gaps table next to this file (overridable for tests).
rt_gaps_tsv() {
    printf '%s\n' "${RT_GAPS_TSV:-$(dirname "${BASH_SOURCE[0]}")/expected-gaps.tsv}"
}

# `rt_verdict <PASS|FAIL|GAP|GAPCLOSED> <attack> <label> <detail>`
rt_verdict() {
    local label="${3:--}" detail="$4"
    label="${label//$'\t'/ }"
    label="${label//$'\n'/ }"
    detail="${detail//$'\t'/ }"
    detail="${detail//$'\n'/ }"
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$label" "$detail"
}

# The jq definitions shared by rt_zip and rt_paired_field: $rows (raw
# text), $w (the window's records), $u (the agent user).
# shellcheck disable=SC2016
RT_JQ_DEFS='
def rows: $rows | split("\n") | map(select(startswith("RT\t")) | split("\t")
    | {attack: .[1], type: .[2], status: .[3], agent: .[4], label: (.[5:] | join(" "))});
def is_hook: .type == "deny" or .type == "allow" or (.type | startswith("gap:"));
def hook_rows: [rows[] | select(is_hook)];
def hook_records: [$w[] | select(.kind == "guard" and .user == $u and ((.peer.comm // "") == "saiife"))];
'

# `rt_zip <rows file> <window jsonl> <agent user>`: one verdict per row.
# Hook rows (deny, allow, gap:*) are paired in order with the window's guard
# records written by the agent user through the real hook (peer.comm
# saiife); records the agent made itself (python3) never count.
rt_zip() {
    local tsv
    tsv="$(rt_gaps_tsv)"
    # shellcheck disable=SC2016
    jq -rn --rawfile rows "$1" --slurpfile w "$2" --arg u "$3" --rawfile tsv "$tsv" "$RT_JQ_DEFS"'
        def gaps: $tsv | split("\n") | map(select(length > 0 and (startswith("id\t") | not)) | split("\t")
            | {key: .[0], value: {doc: .[2], quote: (.[3:] | join(" "))}}) | from_entries;
        def line($v; $r; $d): [$v, $r.attack, (if $r.label == "" then "-" else $r.label end), $d] | map(gsub("[\t\n]"; " ")) | join("\t");
        def want($r): if $r.type == "deny" or ($r.type != "allow" and $r.status == "closed") then "deny" else "allow" end;
        def judge($r; $rec):
            ($r.type | ltrimstr("gap:")) as $id
            | (if $r.type | startswith("gap:") then gaps[$id] else null end) as $g
            | want($r) as $want
            | [ (if $r.type | startswith("gap:") then
                    (if $r.status == "held" or $r.status == "closed" then empty
                     else "hook exit was neither 0 nor 2" end),
                    (if $g == null then "gap id \($id) is not in expected-gaps.tsv" else empty end)
                 elif $r.status != "pass" then "hook exit was not \(if $r.type == "deny" then 2 else 0 end)"
                 else empty end),
                (if $rec == null then "no guard record for this row" else
                    (if $rec.decision != $want then "record decision \($rec.decision), want \($want)" else empty end),
                    (if $rec.agent != $r.agent then "record agent \($rec.agent), want \($r.agent)" else empty end),
                    (if $rec.mode != "locked" then "record mode \($rec.mode), want locked" else empty end)
                 end) ] as $errs
            | if ($errs | length) > 0 then
                line("FAIL"; $r; "\($r.type): \($errs | join("; "))"
                    + (if $rec == null then "" else " (record input: \(($rec.input // "") | tostring | .[0:120]))" end))
              elif ($r.type | startswith("gap:")) and $r.status == "closed" then
                line("GAPCLOSED"; $r; "the guard now blocks this: move it out of \"Not covered\" in \($g.doc) and drop \($id) from scripts/redteam/expected-gaps.tsv")
              elif $r.type | startswith("gap:") then
                line("GAP"; $r; "\($g.doc): \"\($g.quote)\"")
              else line("PASS"; $r; $r.type) end;
        hook_rows as $h | hook_records as $recs
        | (if ($h | length) != ($recs | length) then
              [ "FAIL", (rows[0].attack // "?"), "pairing",
                "pairing: \($h | length) hook rows, \($recs | length) records" ] | join("\t")
           else empty end),
          (rows | to_entries[] | .value as $r
            | if ($r | is_hook) then
                ([rows[0:.key][] | select(is_hook)] | length) as $i
                | judge($r; $recs[$i])
              elif $r.status == "pass" then line("PASS"; $r; $r.type)
              else line("FAIL"; $r; "\($r.type): status \($r.status)") end)
    '
}

# `rt_paired_field <rows file> <window jsonl> <agent user> <row type>
# <jq path>`: for each hook row of the type, in order, the field of the
# record it pairs with, as compact JSON (null when there is none).
rt_paired_field() {
    jq -rn --rawfile rows "$1" --slurpfile w "$2" --arg u "$3" --arg t "$4" "$RT_JQ_DEFS"'
        hook_records as $recs
        | hook_rows | to_entries[] | select(.value.type == $t)
        | ($recs[.key] // null) | if . == null then "null" else ('"$5"' | tojson) end
    '
}

# Text with every run of whitespace collapsed to one space.
_rt_collapse() {
    tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//'
}

# `rt_gap_doc_check <tsv> <repo root>`: every quote (whitespace collapsed)
# appears in its doc between `## Not covered` and the next `## ` heading.
# Prints each miss; returns 1 on any.
rt_gap_doc_check() {
    local tsv="$1" root="$2" id attack doc quote section q bad=0
    while IFS=$'\t' read -r id attack doc quote; do
        [[ -n "$id" && "$id" != id ]] || continue
        : "$attack"
        if [[ ! -f "$root/$doc" ]]; then
            echo "MISS $id: $doc does not exist"
            bad=1
            continue
        fi
        section="$(awk '/^## / { if (p) exit; if ($0 ~ /^## Not covered[[:space:]]*$/) { p = 1; next } } p' "$root/$doc" | _rt_collapse)"
        q="$(printf '%s' "$quote" | _rt_collapse)"
        if [[ -z "$q" || "$section" != *"$q"* ]]; then
            echo "MISS $id: \"$q\" is not in the \"Not covered\" section of $doc"
            bad=1
        fi
    done <"$tsv"
    return "$bad"
}

# `rt_summary <verdict file>`: the per-attack table, the known gaps and the
# regressions, also appended to $GITHUB_STEP_SUMMARY as Markdown when set.
# Returns 1 on any FAIL or GAPCLOSED, or when there is no verdict at all.
rt_summary() {
    local file="$1" v attack label detail kind bad=0 n=0
    local -a order=() gaps=() regs=()
    local -A dr=() bl=() al=() kg=() fl=() seen=()
    while IFS=$'\t' read -r v attack label detail; do
        [[ -n "$v" ]] || continue
        n=$((n + 1))
        if [[ -z "${seen[$attack]:-}" ]]; then
            seen[$attack]=1
            order+=("$attack")
            dr[$attack]=0 bl[$attack]=0 al[$attack]=0 kg[$attack]=0 fl[$attack]=0
        fi
        case "$v" in
        PASS)
            kind="${detail%%[ :]*}"
            case "$kind" in
            deny) dr[$attack]=$((dr[$attack] + 1)) ;;
            refused) bl[$attack]=$((bl[$attack] + 1)) ;;
            allow) al[$attack]=$((al[$attack] + 1)) ;;
            esac
            ;;
        GAP)
            kg[$attack]=$((kg[$attack] + 1))
            gaps+=("$attack"$'\t'"$label"$'\t'"$detail")
            ;;
        GAPCLOSED | FAIL)
            fl[$attack]=$((fl[$attack] + 1))
            regs+=("$v"$'\t'"$attack"$'\t'"$label"$'\t'"$detail")
            bad=1
            ;;
        *)
            fl[$attack]=$((fl[$attack] + 1))
            regs+=("FAIL"$'\t'"$attack"$'\t'"$label"$'\t'"unknown verdict $v: $detail")
            bad=1
            ;;
        esac
    done <"$file"
    if ((n == 0)); then
        regs+=("FAIL"$'\t'"-"$'\t'"summary"$'\t'"no verdicts at all")
        bad=1
    fi

    local a g r f1 f2 f3 f4
    _rt_trow attack blocked+recorded blocked allowed+recorded known-gaps failures
    for a in "${order[@]}"; do
        _rt_trow "$a" "${dr[$a]}" "${bl[$a]}" "${al[$a]}" "${kg[$a]}" "${fl[$a]}"
    done
    echo
    echo "Known gaps (documented, expected)"
    if ((${#gaps[@]} == 0)); then echo "  none"; fi
    for g in "${gaps[@]}"; do
        IFS=$'\t' read -r f1 f2 f3 <<<"$g"
        echo "  GAP  $f1  $f2  -- $f3"
    done
    echo
    echo "Regressions"
    if ((${#regs[@]} == 0)); then echo "  none"; fi
    for r in "${regs[@]}"; do
        IFS=$'\t' read -r f1 f2 f3 f4 <<<"$r"
        echo "  $f1  $f2  $f3  -- $f4"
    done

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        {
            echo "### saiife red team"
            echo
            echo "| attack | blocked+recorded | blocked | allowed+recorded | known gaps | failures |"
            echo "|---|---:|---:|---:|---:|---:|"
            for a in "${order[@]}"; do
                echo "| $(_rt_md "$a") | ${dr[$a]} | ${bl[$a]} | ${al[$a]} | ${kg[$a]} | ${fl[$a]} |"
            done
            echo
            echo "#### Known gaps (documented, expected)"
            echo
            if ((${#gaps[@]} == 0)); then echo "none"; fi
            for g in "${gaps[@]}"; do
                IFS=$'\t' read -r f1 f2 f3 <<<"$g"
                echo "- **$(_rt_md "$f1")** \`$(_rt_md "$f2")\`: $(_rt_md "$f3")"
            done
            echo
            echo "#### Regressions"
            echo
            if ((${#regs[@]} == 0)); then echo "none"; fi
            for r in "${regs[@]}"; do
                IFS=$'\t' read -r f1 f2 f3 f4 <<<"$r"
                echo "- **$f1** $(_rt_md "$f2") \`$(_rt_md "$f3")\`: $(_rt_md "$f4")"
            done
            echo
        } >>"$GITHUB_STEP_SUMMARY"
    fi
    return "$bad"
}

_rt_trow() {
    printf '%-14s %17s %8s %17s %11s %9s\n' "$@"
}

# Markdown-safe text: pipes and backticks escaped.
_rt_md() {
    local s="$1"
    s="${s//|/\\|}"
    s="${s//\`/\'}"
    printf '%s' "$s"
}
