#!/usr/bin/env bash
# The red-team runner (plan 9c; spec §9.2 A1-A10, A16-A18, §13). Phase 5 of
# scripts/locked-linux/run.sh calls it on a fresh locked install.
#
# CI ONLY. It runs as the CI runner user and uses `sudo` itself: it stages
# the attack scripts read-only, runs each one wholly as the agent user
# agent-ci, pairs the attack rows with the records the real hook wrote,
# runs the runner-side cases (two scopes, the auditor read, protected files
# unchanged) and prints a summary that keeps the documented gaps apart from
# regressions. Its exit status is the summary's. Anywhere else it refuses
# before doing anything.
#
#   bash scripts/redteam/run.sh       (from scripts/locked-linux/run.sh)
set -euo pipefail

[[ "${GITHUB_ACTIONS:-}" == true && "${SAIIFE_LOCKED_CI:-}" == 1 ]] || { echo "refusing: red-team scripts run only in the GitHub locked-linux job" >&2; exit 2; }
[[ "$(id -u)" != 0 ]] || { echo "refusing: run.sh runs as the CI runner user, not root (it calls sudo itself)" >&2; exit 2; }
if [[ ! -f /etc/saiife/installed.toml ]] || ! systemctl is-active --quiet saiifed; then
    echo "refusing: run after system install (no active saiifed)" >&2
    exit 2
fi

RT_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$RT_HERE/../.." && pwd)"
HERE="$REPO/scripts/locked-linux"
LOGS="${LOGS:-${SAIIFE_LOCKED_LOGS:-$REPO/target/locked-linux-logs}}"
export REPO HERE LOGS

# shellcheck source=scripts/locked-linux/lib.sh
source "$HERE/lib.sh"
# shellcheck source=scripts/redteam/check.sh
source "$RT_HERE/check.sh"

ATTACKS=(a01 a02 a03 a04 a05 a06 a07 a08 a09 a10 a16 a17 a18)
GAPS_TSV="$RT_HERE/expected-gaps.tsv"
AUDITOR=auditor-ci
GROUP=redteam-ci
CONFIG=/etc/saiife/config.toml
PROTECTED=(
    /etc/saiife/config.toml
    /etc/saiife/installed.toml
    /etc/claude-code/managed-settings.d/50-saiife.json
    /etc/codex/requirements.toml
    /etc/gemini-cli/settings.json
    "$OPT_BIN"
    "$UNIT_FILE"
)

WORK="$(mktemp -d)"
STAGE=""
VERDICTS="$WORK/verdicts.tsv"
: >"$VERDICTS"
export WORK

# ------------------------------------------------------------ helpers

# `verdict <PASS|FAIL> <attack> <label> <detail>`: one runner-side verdict.
verdict() {
    rt_verdict "$@" | tee -a "$VERDICTS" | sed 's/^/  /'
}

# The highest .seq in the chain (0 for none).
chain_head() {
    records | jq -s '[.[] | .seq // 0] | max // 0'
}

# `window_since <seq>`: the records after it.
window_since() {
    records | jq -c --argjson s "$1" 'select((.seq // -1) > $s)'
}

# `poll <seconds> <command...>`: like wait_until, but returns 1 instead of
# stopping the run.
poll() {
    local end=$((SECONDS + $1))
    shift
    until "$@"; do
        ((SECONDS < end)) || return 1
        sleep 0.5
    done
}

agent_uid() {
    id -u "$AGENT_USER"
}

cleanup() {
    local code=$?
    set +e
    if [[ -n "$STAGE" ]] && as_root test -f "$STAGE/config.toml.saved"; then
        if [[ "$(as_root sha256sum <"$CONFIG")" != "$(as_root sha256sum <"$STAGE/config.toml.saved")" ]]; then
            echo "red team: restoring $CONFIG" >&2
            as_root cp "$STAGE/config.toml.saved" "$CONFIG"
            as_root systemctl reload saiifed
        fi
    fi
    if getent passwd "$AUDITOR" >/dev/null; then
        as_root userdel -r "$AUDITOR" 2>/dev/null
    fi
    if getent group "$GROUP" >/dev/null; then
        as_root gpasswd -d "$AGENT_USER" "$GROUP" >/dev/null 2>&1
        as_root groupdel "$GROUP"
    fi
    as_root rm -rf "$AGENT_HOME/rt"
    if [[ "$STAGE" == /tmp/saiife-redteam.* ]]; then
        as_root rm -rf "$STAGE"
    fi
    if [[ "$code" != 0 ]]; then
        # Rows, windows (audit records), verdicts and doctor output. No
        # credstore content is ever in $WORK.
        mkdir -p "$LOGS/redteam" && cp -r "$WORK"/. "$LOGS/redteam/" 2>/dev/null
    fi
    rm -rf "$WORK"
    exit "$code"
}
trap cleanup EXIT

# ------------------------------------------------------------ staging

# `script_for <id>`: the one scripts/redteam/<id>-*.sh.
script_for() {
    local -a m
    mapfile -t m < <(compgen -G "$RT_HERE/$1-*.sh" || true)
    [[ "${#m[@]}" == 1 ]] || fail "want exactly one scripts/redteam/$1-*.sh, found ${#m[@]}: ${m[*]}"
    basename "${m[0]}"
}

stage() {
    local id a
    for id in "${ATTACKS[@]}"; do
        script_for "$id" >/dev/null
    done
    STAGE="$(as_root mktemp -d /tmp/saiife-redteam.XXXXXX)"
    as_root chown root:root "$STAGE"
    as_root chmod 0755 "$STAGE"
    as_root install -o root -g root -m 0644 "$RT_HERE/lib.sh" "$RT_HERE/ipc.py" "$STAGE/"
    for id in "${ATTACKS[@]}"; do
        as_root install -o root -g root -m 0755 "$RT_HERE/$(script_for "$id")" "$STAGE/"
    done
    as_root install -d -o root -g root -m 0755 "$STAGE/fixtures"
    for a in claude codex gemini; do
        as_root install -d -o root -g root -m 0755 "$STAGE/fixtures/$a"
        as_root install -o root -g root -m 0644 "$FIXTURES/$a"/*.json "$STAGE/fixtures/$a/"
    done
    ok "staged in $STAGE (root-owned, read-only to $AGENT_USER)"
}

# ------------------------------------------------------------ attacks

run_attack() {
    local id="$1" script since code=0 n
    script="$(script_for "$id")"
    echo
    echo "-- $id ($script)"
    since="$(chain_head)"
    if declare -F "pre_$id" >/dev/null; then "pre_$id"; fi
    # The runner opens the output files; the attack runs wholly as the
    # agent user, with a clean environment.
    # shellcheck disable=SC2024
    timeout 180 sudo -n -u "$AGENT_USER" env -i HOME="$AGENT_HOME" USER="$AGENT_USER" LOGNAME="$AGENT_USER" \
        PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 GITHUB_ACTIONS=true SAIIFE_LOCKED_CI=1 \
        RT_STAGE="$STAGE" bash "$STAGE/$script" >"$WORK/$id.rows" 2>"$WORK/$id.err" || code=$?
    sed 's/^/  | /' "$WORK/$id.err" >&2
    n="$(grep -c $'^RT\t' "$WORK/$id.rows" || true)"
    if [[ "$code" == 124 ]]; then
        verdict FAIL "$id" "$script" "script: timed out after 180 s"
    elif [[ "$code" != 0 ]]; then
        verdict FAIL "$id" "$script" "script: exit $code"
    fi
    if [[ "$n" == 0 ]]; then
        verdict FAIL "$id" "$script" "script: no rows"
    fi
    if grep -qv $'^RT\t' "$WORK/$id.rows"; then
        verdict FAIL "$id" "$script" "script: $(grep -cv $'^RT\t' "$WORK/$id.rows") stray stdout lines (not shown)"
    fi
    window_since "$since" >"$WORK/$id.window.jsonl"
    rt_zip "$WORK/$id.rows" "$WORK/$id.window.jsonl" "$AGENT_USER" | tee -a "$VERDICTS" | sed 's/^/  /'
    if declare -F "post_$id" >/dev/null; then "post_$id"; fi
}

A05_PID=""
A05_STARTS=""

pre_a05() {
    A05_PID="$(daemon_pid)"
    A05_STARTS="$(start_count)"
}

post_a05() {
    local pid
    pid="$(daemon_pid)"
    if [[ "$pid" == "$A05_PID" && "$pid" -gt 0 ]]; then
        verdict PASS a05 "saiifed MainPID unchanged ($pid)" check
    else
        verdict FAIL a05 "saiifed MainPID unchanged" "check: $A05_PID -> $pid"
    fi
    local starts
    starts="$(start_count)"
    if [[ "$starts" == "$A05_STARTS" ]]; then
        verdict PASS a05 "no daemon start record during the attack ($starts)" check
    else
        verdict FAIL a05 "no daemon start record during the attack" "check: $A05_STARTS -> $starts"
    fi
}

post_a08() {
    local w="$WORK/a08.window.jsonl" nonce uid errs
    uid="$(agent_uid)"
    nonce="$(awk -F'\t' '$1 == "RT" && $3 == "forge" { print $6; exit }' "$WORK/a08.rows")"
    if [[ -z "$nonce" ]]; then
        verdict FAIL a08 "forged guard record" "forge: no forge row"
    else
        # shellcheck disable=SC2016
        errs="$(jq -rs --arg n "$nonce" --argjson uid "$uid" --arg u "$AGENT_USER" '
            [.[] | select(.kind == "guard" and .input == $n)] as $m
            | if ($m | length) != 1 then "\($m | length) records for the nonce, want 1"
              else $m[0] as $r | [
                (if $r.uid != $uid then "uid \($r.uid), want \($uid)" else empty end),
                (if $r.user != $u then "user \($r.user), want \($u)" else empty end),
                (if $r.mode != "locked" then "mode \($r.mode), want locked" else empty end),
                (if $r.host == "evil" then "host is the forged evil" else empty end),
                (if $r.ts == "2001-01-01T00:00:00.000Z" then "ts is the forged one" else empty end),
                (if $r.client_ts != "2001-01-01T00:00:00.000Z" then "client_ts \($r.client_ts), want the forged ts" else empty end),
                (if ($r.peer.comm // "") != "python3" then "peer.comm \($r.peer.comm), want python3" else empty end)
              ] | join("; ") end' "$w")"
        if [[ -z "$errs" ]]; then
            verdict PASS a08 "forged guard record $nonce carries the daemon's truth" check
        else
            verdict FAIL a08 "forged guard record $nonce" "forge: $errs"
        fi
    fi
    if jq -se --arg p "uid $uid " 'any(.[]; .kind == "daemon" and .event == "forbidden" and ((.reason // "") | contains($p)))' "$w" >/dev/null; then
        verdict PASS a08 "refused appends left a daemon/forbidden record" check
    else
        verdict FAIL a08 "refused appends left a daemon/forbidden record" "check: none in the window"
    fi
    if jq -se 'any(.[]; (.kind == "daemon" and (.event == "start" or .event == "stop")) or .kind == "policy")' "$w" >/dev/null; then
        verdict FAIL a08 "no daemon start/stop or policy record from forged appends" "check: $(jq -c 'select((.kind == "daemon" and (.event == "start" or .event == "stop")) or .kind == "policy") | {kind, event, result, seq}' "$w" | paste -sd' ' -)"
    else
        verdict PASS a08 "no daemon start/stop or policy record from forged appends" check
    fi
}

post_a09() {
    local w="$WORK/a09.window.jsonl" uid want
    uid="$(agent_uid)"
    for want in "uid $uid is over its request limits (64 in flight, 1000/s)" \
        "uid $uid is over its connection limits (32 open per uid, or the daemon's total)"; do
        if jq -se --arg r "$want" 'any(.[]; .kind == "daemon" and .event == "rate_limited" and .reason == $r)' "$w" >/dev/null; then
            verdict PASS a09 "rate_limited: $want" check
        else
            verdict FAIL a09 "rate_limited: $want" "check: no such record in the window"
        fi
    done
}

# `policies <id>`: the policy hashes of the records paired with its allow
# rows, in row order.
policies() {
    rt_paired_field "$WORK/$1.rows" "$WORK/$1.window.jsonl" "$AGENT_USER" allow .policy
}

post_a17() {
    local -a p
    mapfile -t p < <(policies a17)
    if [[ "${#p[@]}" != 3 || "${p[0]}" == null ]]; then
        verdict FAIL a17 "policy hashes" "check: want 3 allow records with a policy, got: ${p[*]}"
        return 0
    fi
    if [[ "${p[0]}" == "${p[1]}" ]]; then
        verdict PASS a17 "env and locked=false in project config leave the policy as it was" check
    else
        verdict FAIL a17 "env and locked=false in project config leave the policy as it was" "check: base ${p[0]}, loose ${p[1]}"
    fi
    if [[ "${p[0]}" != "${p[2]}" ]]; then
        verdict PASS a17 "control: an added project pack changes the policy" check
    else
        verdict FAIL a17 "control: an added project pack changes the policy" "check: base and addpack both ${p[0]}"
    fi
}

post_a18() {
    local -a p
    mapfile -t p < <(policies a18)
    if [[ "${#p[@]}" == 2 && "${p[0]}" != null && "${p[0]}" == "${p[1]}" ]]; then
        verdict PASS a18 "a project allow= for a service is dropped (equal policy)" check
    else
        verdict FAIL a18 "a project allow= for a service is dropped (equal policy)" "check: got ${p[*]}"
    fi
}

# ------------------------------------------------------------ runner-side cases

protected_snapshot() {
    as_root sha256sum "${PROTECTED[@]}" >"$WORK/protected.before"
}

protected_unchanged() {
    echo
    echo "-- protected files unchanged"
    local f before after
    for f in "${PROTECTED[@]}"; do
        before="$(awk -v f="$f" '$2 == f { print $1 }' "$WORK/protected.before")"
        after="$(as_root sha256sum "$f" | awk '{ print $1 }')" || after=missing
        if [[ -n "$before" && "$before" == "$after" ]]; then
            verdict PASS protected "$f unchanged" check
        else
            verdict FAIL protected "$f unchanged" "check: sha256 ${before:-?} -> ${after:-?}"
        fi
    done
}

policy_record_since() {
    # `policy_record_since <seq> <result> [reason substring]`
    window_since "$1" | jq -se --arg res "$2" --arg r "${3:-}" \
        'any(.[]; .kind == "policy" and .result == $res and ((.reason // "") | contains($r)))' >/dev/null
}

case_two_scopes() {
    echo
    echo "-- two scopes, policy refused (spec §8.1, §13)"
    local t=two-scopes pid since want saved allow deny code=0
    want="user $AGENT_USER matches more than one scope: ci, ci-two"
    as_root groupadd "$GROUP"
    as_root usermod -aG "$GROUP" "$AGENT_USER"
    as_root cp -p "$CONFIG" "$STAGE/config.toml.saved"
    saved="$(as_root sha256sum <"$CONFIG")"
    pid="$(daemon_pid)"
    since="$(chain_head)"
    printf '\n[[scope]]\nname = "ci-two"\nusers = ["group:%s"]\n' "$GROUP" | as_root tee -a "$CONFIG" >/dev/null
    as_root systemctl reload saiifed
    if poll 15 policy_record_since "$since" rejected "$want"; then
        verdict PASS "$t" "reload rejected: $want" check
    else
        verdict FAIL "$t" "reload rejected: $want" "check: no such policy record in 15 s; got: $(window_since "$since" | jq -c 'select(.kind == "policy") | {result, reason}' | paste -sd' ' -)"
    fi
    if [[ "$(daemon_pid)" == "$pid" ]]; then
        verdict PASS "$t" "MainPID unchanged ($pid)" check
    else
        verdict FAIL "$t" "MainPID unchanged" "check: $pid -> $(daemon_pid)"
    fi

    # The hooks still judge (scopes govern connectors, not hooks).
    allow="$(payload claude/bash-allow.json)"
    deny="$(payload claude/bash-deny.json)"
    since="$(chain_head)"
    hook claude "$allow"
    printf 'RT\t%s\tallow\t%s\tclaude\tallow while two scopes match\n' "$t" "$([[ "$HOOK_CODE" == 0 ]] && echo pass || echo fail)" >"$WORK/two-scopes.rows"
    hook claude "$deny"
    printf 'RT\t%s\tdeny\t%s\tclaude\tdeny while two scopes match\n' "$t" "$([[ "$HOOK_CODE" == 2 ]] && echo pass || echo fail)" >>"$WORK/two-scopes.rows"
    window_since "$since" >"$WORK/two-scopes.window.jsonl"
    rt_zip "$WORK/two-scopes.rows" "$WORK/two-scopes.window.jsonl" "$AGENT_USER" | tee -a "$VERDICTS" | sed 's/^/  /'

    as_root "$OPT_BIN" doctor --json >"$WORK/doctor-two-scopes.json" 2>"$WORK/doctor-two-scopes.err" || code=$?
    if [[ "$code" == 2 ]] && jq -e '[.checks[] | select((.detail // "") | contains("matches more than one scope"))] | length > 0' \
        "$WORK/doctor-two-scopes.json" >/dev/null 2>&1; then
        verdict PASS "$t" "doctor exits 2 naming the scope conflict" check
    else
        verdict FAIL "$t" "doctor exits 2 naming the scope conflict" "check: exit $code; $(jq -c '[.checks[] | select(.status != "pass") | {id, detail}]' "$WORK/doctor-two-scopes.json" 2>/dev/null | head -c 400)"
    fi

    since="$(chain_head)"
    as_root cp "$STAGE/config.toml.saved" "$CONFIG"
    if [[ "$(as_root sha256sum <"$CONFIG")" == "$saved" ]]; then
        verdict PASS "$t" "config restored byte for byte" check
    else
        verdict FAIL "$t" "config restored byte for byte" "check: sha256 differs"
    fi
    as_root systemctl reload saiifed
    if poll 15 policy_record_since "$since" loaded; then
        verdict PASS "$t" "restored config loaded" check
    else
        verdict FAIL "$t" "restored config loaded" "check: no policy loaded record in 15 s"
    fi
    as_root gpasswd -d "$AGENT_USER" "$GROUP" >/dev/null
    as_root groupdel "$GROUP"
}

# `as_auditor <command...>`: as the auditor user, reading the system log.
as_auditor() {
    sudo -n -u "$AUDITOR" env -C "/home/$AUDITOR" HOME="/home/$AUDITOR" SAIIFE_AUDIT_DIR="$AUDIT_DIR" "$@"
}

auditor_read() {
    echo
    echo "-- auditor read (spec §6.4.5)"
    local t=auditor code=0 out text
    as_root useradd -m -G saiife-audit "$AUDITOR"
    as_auditor "$OPT_BIN" audit verify >"$WORK/auditor-verify.out" 2>&1 || code=$?
    if [[ "$code" == 0 ]]; then
        verdict PASS "$t" "saiife audit verify as $AUDITOR" check
    else
        verdict FAIL "$t" "saiife audit verify as $AUDITOR" "check: exit $code: $(tail -n 3 "$WORK/auditor-verify.out")"
    fi
    code=0
    as_auditor "$OPT_BIN" audit >"$WORK/auditor-audit.out" 2>&1 || code=$?
    out="$(cat "$WORK/auditor-audit.out")"
    if [[ "$code" == 0 ]]; then
        verdict PASS "$t" "saiife audit as $AUDITOR" check
    else
        verdict FAIL "$t" "saiife audit as $AUDITOR" "check: exit $code: $(tail -n 3 "$WORK/auditor-audit.out")"
    fi
    for text in "sudo ls" "systemctl stop saiifed"; do
        if [[ "$out" == *"$text"* ]]; then
            verdict PASS "$t" "the auditor sees \"$text\"" check
        else
            verdict FAIL "$t" "the auditor sees \"$text\"" "check: not in saiife audit output"
        fi
    done
    # audit_verify (locked-linux/lib.sh) stops its shell on failure: a subshell.
    if (audit_verify) >"$WORK/root-verify.out" 2>&1; then
        verdict PASS "$t" "saiife audit verify as root" check
    else
        verdict FAIL "$t" "saiife audit verify as root" "check: $(tail -n 3 "$WORK/root-verify.out")"
    fi
    as_root userdel -r "$AUDITOR" 2>/dev/null || as_root userdel "$AUDITOR"
}

gaps_exercised() {
    local id attack doc quote
    while IFS=$'\t' read -r id attack doc quote; do
        [[ -n "$id" && "$id" != id ]] || continue
        : "$attack" "$doc" "$quote"
        if cat "$WORK"/*.rows 2>/dev/null | awk -F'\t' -v t="gap:$id" '$1 == "RT" && $3 == t { f = 1 } END { exit !f }'; then
            :
        else
            verdict FAIL gaps "$id" "gap not exercised"
        fi
    done <"$GAPS_TSV"
}

# ------------------------------------------------------------ main

main() {
    local id status=0
    echo "red team: ${#ATTACKS[@]} attacks as $AGENT_USER (uid $(agent_uid))"
    stage
    protected_snapshot
    for id in "${ATTACKS[@]}"; do
        run_attack "$id"
    done
    case_two_scopes
    auditor_read
    protected_unchanged
    gaps_exercised
    daemon_ready || verdict FAIL runner "saiifed active at the end" "check: not active or no socket"
    echo
    echo "== red-team summary"
    rt_summary "$VERDICTS" || status=$?
    return "$status"
}

main
