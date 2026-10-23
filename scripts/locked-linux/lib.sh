#!/usr/bin/env bash
# The phases of scripts/locked-linux/run.sh (CI only; see there). Sourcing
# this file only defines functions; run.sh checks the CI gate before it
# sources it. Each phase prints `== <phase>` and stops the job at the first
# broken assertion.
#
# Needs from run.sh: BIN (the static ci-locked saiife to install), HERE, REPO, LOGS,
# WORK (a scratch dir).

AGENT_USER="agent-ci"
AGENT_HOME=/home/agent-ci
OPT_BIN=/opt/saiife/bin/saiife
AUDIT_DIR=/var/log/saiife/audit
SOCKET=/run/saiife/saiife.sock
UNIT_FILE=/etc/systemd/system/saiifed.service
FIXTURES="$REPO/crates/cli/tests/fixtures"
CI_CONFIG="$HERE/config.toml"
# Set by `hook`.
HOOK_CODE=0
HOOK_ERR=""

# ------------------------------------------------------------ helpers

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ok() {
    echo "  ok: $*"
}

phase() {
    echo
    echo "== $*"
}

# A privileged command (the runner has passwordless sudo).
as_root() {
    sudo -n "$@"
}

systemd_version() {
    systemctl --version | awk 'NR == 1 { print $2 }'
}

# On any failure: the daemon's journal, the audit log, /etc/saiife and the
# unit, for the job to upload.
on_exit() {
    local code="$1"
    if [[ "$code" != 0 ]]; then
        echo "locked-linux failed (exit $code); collecting logs in $LOGS" >&2
        as_root journalctl -u saiifed --no-pager -o short-precise >"$LOGS/journal-saiifed.txt" 2>&1 || true
        as_root systemctl status saiifed --no-pager >"$LOGS/systemctl-status.txt" 2>&1 || true
        as_root sh -c 'ls -la /etc/saiife /etc/saiife/credstore /var/lib/saiife /var/lib/saiife/keys /var/log/saiife /var/log/saiife/audit /run/saiife' >"$LOGS/ls.txt" 2>&1 || true
        show_daemon_groups >"$LOGS/daemon-groups.txt" 2>&1 || true
        echo "-- daemon groups"
        cat "$LOGS/daemon-groups.txt" 2>/dev/null || true
        echo "-- journal (last 60 lines)"
        tail -n 60 "$LOGS/journal-saiifed.txt" 2>/dev/null || true
        echo "-- ls"
        cat "$LOGS/ls.txt" 2>/dev/null || true
        # Copied as root through tar, the credstore (the vault key) left
        # out at copy time: it never lands in $LOGS, not even for a moment.
        # The unprivileged tar writes the copy as the runner user.
        as_root tar -C / --exclude=etc/saiife/credstore -cf - \
            etc/saiife "${AUDIT_DIR#/}" "${UNIT_FILE#/}" 2>/dev/null |
            tar -C "$LOGS" -xf - 2>/dev/null || true
        cp -r "$WORK" "$LOGS/work" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}

# `wait_until <seconds> <what> <command...>`: poll until the command passes.
wait_until() {
    local secs="$1" what="$2"
    shift 2
    local end=$((SECONDS + secs))
    until "$@"; do
        ((SECONDS < end)) || fail "timed out after ${secs}s waiting for $what"
        sleep 0.5
    done
}

daemon_ready() {
    [[ "$(systemctl is-active saiifed 2>/dev/null || true)" == active ]] && as_root test -S "$SOCKET"
}

daemon_pid() {
    systemctl show -p MainPID --value saiifed
}

# Every audit line, month files in order.
records() {
    # shellcheck disable=SC2016
    as_root sh -c 'cat "$1"/*.jsonl' sh "$AUDIT_DIR"
}

start_count() {
    records | jq -c 'select(.kind == "daemon" and .event == "start")' | wc -l
}

restarted_since() {
    [[ "$(start_count)" -gt "$1" ]] && daemon_ready
}

# `expect_last_start <true|false> <when>`: the newest daemon start record's
# previous_clean_stop.
expect_last_start() {
    local got
    got="$(records | jq -s -r '[.[] | select(.kind == "daemon" and .event == "start")] | last | .previous_clean_stop')"
    [[ "$got" == "$1" ]] || fail "$2: previous_clean_stop is $got, want $1"
    ok "$2: previous_clean_stop $got"
}

# `expect_last_guard <agent> <decision> [input]`: the newest guard record,
# written for the agent user.
expect_last_guard() {
    local rec
    rec="$(records | jq -c 'select(.kind == "guard")' | tail -n 1)"
    jq -e --arg a "$1" --arg d "$2" --arg i "${3:-}" --arg u "$AGENT_USER" \
        '.agent == $a and .decision == $d and .user == $u and .mode == "locked" and ($i == "" or .input == $i)' \
        <<<"$rec" >/dev/null || fail "newest guard record is not $1/$2 by $AGENT_USER: $rec"
    ok "audit record: $1 $2 by $AGENT_USER"
}

# `expect_stat <path> <owner:group mode> [user]`: stat as `user` (root by
# default).
expect_stat() {
    local path="$1" want="$2" as="${3:-root}" got
    got="$(sudo -n -u "$as" stat -c '%U:%G %a' "$path")" || fail "stat $path as $as failed"
    [[ "$got" == "$want" ]] || fail "$path: $got, want $want (stat as $as)"
    ok "$path $got (as $as)"
}

# `payload <fixture> [jq filter]`: a copy of a recorded hook payload with
# its cwd in the agent user's home. Prints the copy's path.
payload() {
    local out
    out="$(mktemp -p "$WORK" payload.XXXXXX)"
    jq -c --arg home "$AGENT_HOME" ".cwd = \$home | ${2:-.}" "$FIXTURES/$1" >"$out"
    chmod 0644 "$out"
    printf '%s\n' "$out"
}

# `hook <agent> <payload file> [VAR=value...]`: the managed hook as the
# agent user, in its home, exactly as the managed configs run it. Sets
# HOOK_CODE and HOOK_ERR.
hook() {
    local agent="$1" file="$2"
    shift 2
    HOOK_CODE=0
    # The runner's shell opens the payload and the output files on purpose:
    # the agent user gets the payload on stdin, as from its agent.
    # shellcheck disable=SC2024
    sudo -n -u "$AGENT_USER" env -C "$AGENT_HOME" "$@" \
        "$OPT_BIN" check --managed --hook-exit --agent "$agent" \
        <"$file" >"$WORK/hook.out" 2>"$WORK/hook.err" || HOOK_CODE=$?
    HOOK_ERR="$(cat "$WORK/hook.err")"
}

hook_code_is() {
    local want="$1"
    shift
    hook "$@"
    [[ "$HOOK_CODE" == "$want" ]]
}

# `expect_hook <code> <stderr text or ""> <what> <agent> <payload> [VAR=value...]`
expect_hook() {
    local want="$1" text="$2" what="$3"
    shift 3
    hook "$@"
    [[ "$HOOK_CODE" == "$want" ]] || fail "$what: exit $HOOK_CODE, want $want; stderr: $HOOK_ERR"
    if [[ -n "$text" && "$HOOK_ERR" != *"$text"* ]]; then
        fail "$what: stderr lacks \"$text\": $HOOK_ERR"
    fi
    ok "$what: exit $HOOK_CODE${HOOK_ERR:+ ($HOOK_ERR)}"
}

# `expect_denied <what> <command...>`: the command, as the agent user,
# fails with a permission error.
expect_denied() {
    local what="$1" code=0 out
    shift
    # The output file is the runner's (the redirect is not the attack).
    # shellcheck disable=SC2024
    sudo -n -u "$AGENT_USER" env -C "$AGENT_HOME" "$@" >"$WORK/attack.out" 2>&1 || code=$?
    out="$(cat "$WORK/attack.out")"
    [[ "$code" != 0 ]] || fail "$what succeeded as $AGENT_USER"
    [[ "$out" == *"Permission denied"* || "$out" == *"Operation not permitted"* ]] ||
        fail "$what failed without a permission error (exit $code): $out"
    ok "$what: $out"
}

# `install_saiife <allowed exit codes...>`: `system install` with the CI
# config, its output in $WORK/install.out.
install_saiife() {
    local code=0 c
    # --allow-test-build: $BIN has debug assertions on (the fault seam);
    # install refuses such a build on a real system without it.
    as_root "$BIN" system install --config "$CI_CONFIG" --agents claude,codex,gemini \
        --non-interactive --allow-test-build >"$WORK/install.out" 2>&1 || code=$?
    cat "$WORK/install.out"
    for c in "$@"; do
        [[ "$code" == "$c" ]] && {
            ok "system install exit $code"
            return 0
        }
    done
    fail "system install exited $code, want one of: $*"
}

audit_verify() {
    local code=0
    as_root env SAIIFE_AUDIT_DIR="$AUDIT_DIR" "$OPT_BIN" audit verify >"$WORK/verify.out" 2>&1 || code=$?
    cat "$WORK/verify.out"
    [[ "$code" == 0 ]] || fail "saiife audit verify exited $code"
    ok "audit verify (as root)"
}

# The audit dir and its month files, checked as the daemon user (root
# would see them whatever their modes): the daemon regroups them to
# saiife-audit at each start (spec §5.2; systemd's LogsDirectory= gives
# the dir to Group=saiife).
audit_dir_checks() {
    local f found=0
    expect_stat "$AUDIT_DIR" "saiife:saiife-audit 2750" saiife
    id -nG saiife | tr ' ' '\n' | grep -qx saiife-audit || fail "saiife is not in saiife-audit: $(id -nG saiife)"
    while IFS= read -r f; do
        found=1
        expect_stat "$f" "saiife:saiife-audit 640" saiife
    done < <(sudo -n -u saiife find "$AUDIT_DIR" -maxdepth 1 -name '*.jsonl')
    ((found)) || fail "no month file in $AUDIT_DIR"
    sudo -n -u saiife test -w "$AUDIT_DIR" || fail "the daemon user cannot write $AUDIT_DIR"
}

# For the log: the daemon user's groups by name and the groups the running
# daemon really holds (read-only; for debugging a regroup failure).
show_daemon_groups() {
    local pid
    echo "  id saiife: $(id saiife 2>&1 || true)"
    pid="$(daemon_pid 2>/dev/null || true)"
    if [[ -n "$pid" && "$pid" != 0 ]]; then
        echo "  daemon pid $pid $(as_root grep -E '^(Uid|Gid|Groups):' "/proc/$pid/status" 2>&1 | tr '\t\n' '  ' || true)"
    else
        echo "  daemon: not running"
    fi
}

# The paths an installed.toml lists: files, managed configs and dirs.
listed_paths() {
    sed -n 's/^path = "\(.*\)"$/\1/p' "$1"
    sed -n 's/^dirs = \[\(.*\)\]$/\1/p' "$1" | tr ',' '\n' | sed 's/^ *"//; s/" *$//' | grep -v '^$' || true
}

# ------------------------------------------------------------ phases

# GitHub's runner images ship /opt as 0777. `system install` refuses to
# write below a directory group or others can write (a production
# safeguard, docs/install.md), so the throwaway runner is normalised first:
# every ancestor install writes below loses group/other write (sticky
# dirs excepted), and each change is logged. /var/log is left as the image
# has it (Ubuntu: root:syslog 0775): `uninstall --purge` must cope with it.
prepare_host() {
    phase "0. host preparation (runner image)"
    local d mode owner
    for d in /opt /etc /etc/systemd /etc/systemd/system /var /var/lib /run /usr/local; do
        [[ -d "$d" ]] || continue
        owner="$(stat -c '%U' "$d")"
        mode="$(stat -c '%a' "$d")"
        [[ "$owner" == root ]] || fail "$d is owned by $owner, not root"
        if (((8#$mode & 8#022) != 0 && (8#$mode & 8#1000) == 0)); then
            as_root chmod go-w "$d"
            echo "  changed: $d mode $mode -> $(stat -c '%a' "$d")"
        else
            echo "  kept: $d mode $mode"
        fi
    done
    echo "  kept: /var/log $(stat -c '%U:%G %a' /var/log)"
}

phase_install() {
    phase "1. system install (systemd $(systemd_version), $(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2-))"
    as_root useradd -m -s /bin/bash "$AGENT_USER"
    # 1: installed, but doctor found a failure; checked in phase 6.
    install_saiife 0 1
    [[ "$(systemctl is-active saiifed || true)" == active ]] || fail "saiifed is not active after install"
    wait_until 30 "the daemon socket" daemon_ready
    ok "saiifed active"
}

phase_modes() {
    phase "2. owners and modes (spec §5.2)"
    local p v unit
    for p in /opt/saiife /opt/saiife/bin "$OPT_BIN" /etc/saiife /etc/saiife/policy.d; do
        expect_stat "$p" "root:root 755"
    done
    for p in /etc/saiife/config.toml /etc/saiife/installed.toml "$UNIT_FILE" \
        /etc/claude-code/managed-settings.d/50-saiife.json /etc/codex/requirements.toml \
        /etc/gemini-cli/settings.json; do
        expect_stat "$p" "root:root 644"
    done
    expect_stat /etc/saiife/credstore "root:root 700"
    v="$(systemd_version)"
    unit="$(cat "$UNIT_FILE")"
    if ((v >= 250)); then
        expect_stat /etc/saiife/credstore/vault-key "root:root 600"
        grep -qx 'LoadCredentialEncrypted=vault-key:/etc/saiife/credstore/vault-key' <<<"$unit" ||
            fail "systemd $v: the unit has no LoadCredentialEncrypted= line"
    else
        expect_stat /etc/saiife/credstore/vault-key "root:saiife 640"
        grep -qx 'LoadCredential=vault-key:/etc/saiife/credstore/vault-key' <<<"$unit" ||
            fail "systemd $v: the unit has no LoadCredential= line"
        if grep -q 'LoadCredentialEncrypted' <<<"$unit"; then
            fail "systemd $v: the unit names LoadCredentialEncrypted="
        fi
    fi
    ok "systemd $v: the unit loads the vault key the matching way"
    expect_stat /var/lib/saiife "saiife:saiife 700"
    expect_stat /var/lib/saiife/keys/audit.ed25519 "saiife:saiife 600"
    expect_stat /run/saiife "saiife:saiife 755"
    expect_stat "$SOCKET" "saiife:saiife 666"
    audit_dir_checks
    show_daemon_groups
    as_root systemctl restart saiifed
    wait_until 30 "the daemon socket after a restart" daemon_ready
    echo "  after systemctl restart saiifed:"
    show_daemon_groups
    audit_dir_checks
}

phase_hooks() {
    phase "3. managed hooks as $AGENT_USER"
    # Each payload is made first: a failing `payload` inside an argument
    # list would not stop the job (set -e ignores it there).
    local allow deny codex_deny gemini_deny mcp write
    allow="$(payload claude/bash-allow.json)"
    deny="$(payload claude/bash-deny.json)"
    codex_deny="$(payload codex/bash-deny.json)"
    gemini_deny="$(payload gemini/shell-deny.json)"
    mcp="$(payload codex/mcp-tool.json)"
    write="$(payload claude/write.json '.tool_input.file_path = "/etc/saiife/x"')"
    expect_hook 0 "" "claude Bash allow" claude "$allow"
    expect_last_guard claude allow "ls -la"
    expect_hook 2 "BLOCKED by" "claude Bash deny" claude "$deny"
    expect_last_guard claude deny "rm -rf /"
    expect_hook 2 "BLOCKED by" "codex Bash deny" codex "$codex_deny"
    expect_last_guard codex deny
    expect_hook 2 "BLOCKED by" "gemini shell deny" gemini "$gemini_deny"
    expect_last_guard gemini deny
    expect_hook 2 "BLOCKED by guard.mcp" "codex MCP tool of an unlisted server" codex "$mcp"
    expect_hook 2 "BLOCKED by core.lock" "claude Write to /etc/saiife/x" claude "$write"
    as_root test ! -e /etc/saiife/x || fail "/etc/saiife/x exists"
    expect_hook 2 "" "guard worker SIGSEGV" claude "$allow" SAIIFE_EVAL_FAULT=segv
    expect_last_guard claude error_denied
    expect_hook 2 "" "guard worker hang" claude "$allow" SAIIFE_EVAL_FAULT=hang
    audit_verify
}

phase_fail_closed() {
    phase "4. fail closed (spec §9.3)"
    local spec agent fixture before p
    as_root systemctl stop saiifed
    for spec in claude:claude/bash-deny.json claude:claude/bash-allow.json \
        codex:codex/bash-deny.json codex:codex/bash-allow.json \
        gemini:gemini/shell-deny.json gemini:gemini/shell-allow.json; do
        agent="${spec%%:*}"
        fixture="${spec#*:}"
        p="$(payload "$fixture")"
        expect_hook 2 "fail closed" "daemon stopped: $fixture" "$agent" "$p"
    done
    as_root systemctl start saiifed
    wait_until 30 "the daemon socket after start" daemon_ready
    expect_last_start true "after systemctl stop + start"

    before="$(start_count)"
    as_root systemctl kill -s KILL saiifed
    wait_until 60 "the restart after SIGKILL" restarted_since "$before"
    expect_last_start false "after SIGKILL and the automatic restart"
    local allow
    allow="$(payload claude/bash-allow.json)"
    expect_hook 0 "" "allow after the restart" claude "$allow"

    as_root sed -i 's/^min_free_mb = 512$/min_free_mb = 99999999/' /etc/saiife/config.toml
    as_root grep -qx 'min_free_mb = 99999999' /etc/saiife/config.toml || fail "min_free_mb was not raised"
    as_root systemctl reload saiifed
    wait_until 15 "the disk floor to deny the allow fixture" hook_code_is 2 claude "$allow"
    ok "disk floor reached: allow fixture -> exit 2 ($HOOK_ERR)"
    # ExecReload= is spawned with LogsDirectory=, which hands the audit dir
    # back to Group=saiife; the daemon regroups it on SIGHUP.
    echo "  after systemctl reload saiifed:"
    audit_dir_checks
    as_root sed -i 's/^min_free_mb = 99999999$/min_free_mb = 512/' /etc/saiife/config.toml
    as_root grep -qx 'min_free_mb = 512' /etc/saiife/config.toml || fail "min_free_mb was not restored"
    as_root systemctl reload saiifed
    wait_until 15 "the restored floor to allow again" hook_code_is 0 claude "$allow"
    ok "floor restored: allow fixture -> exit 0"
    echo "  after the second reload:"
    audit_dir_checks
}

phase_attacks() {
    phase "5. attacks on the install as $AGENT_USER"
    local p before pid
    for p in /etc/saiife/config.toml /etc/claude-code/managed-settings.d/50-saiife.json "$OPT_BIN"; do
        before="$(as_root sha256sum "$p")"
        # shellcheck disable=SC2016
        expect_denied "write $p" sh -c 'printf x >>"$1"' sh "$p"
        [[ "$(as_root sha256sum "$p")" == "$before" ]] || fail "$p changed"
    done
    expect_denied "read /var/lib/saiife/keys/audit.ed25519" cat /var/lib/saiife/keys/audit.ed25519
    pid="$(daemon_pid)"
    [[ "$pid" -gt 0 ]] || fail "no daemon pid"
    expect_denied "kill the daemon (pid $pid)" kill -s TERM "$pid"
    [[ "$(daemon_pid)" == "$pid" ]] || fail "the daemon pid changed"
}

phase_doctor() {
    phase "6. saiife doctor --json as root"
    local code=0 id status
    as_root "$OPT_BIN" doctor --json >"$WORK/doctor.json" 2>"$WORK/doctor.err" || code=$?
    cat "$WORK/doctor.err"
    jq -r '.checks[] | "\(.status | ascii_upcase)  \(.id)  \(.title): \(.detail)"' "$WORK/doctor.json"
    [[ "$(jq -r .exit "$WORK/doctor.json")" == "$code" ]] || fail "doctor exited $code, its report says $(jq -r .exit "$WORK/doctor.json")"
    [[ "$code" == 0 || "$code" == 1 ]] || fail "doctor exited $code (a check failed)"
    for id in daemon.health files.installed keys paths.owner "user.$AGENT_USER.root"; do
        status="$(jq -r --arg id "$id" '.checks[] | select(.id == $id) | .status' "$WORK/doctor.json")"
        [[ "$status" == pass ]] || fail "doctor check $id: ${status:-missing}"
        ok "doctor $id: pass"
    done
    # The ci-locked build is static but has debug assertions on.
    status="$(jq -r '.checks[] | select(.id == "files.binary") | .status' "$WORK/doctor.json")"
    [[ "$status" == warn ]] || fail "doctor check files.binary: ${status:-missing}, want warn (test build installed)"
    ok "doctor files.binary: warn (test build installed)"
    ok "doctor exit $code"
}

phase_reinstall_uninstall() {
    phase "7a. a second system install restarts nothing"
    local before after p
    before="$(systemctl show -p MainPID -p ExecMainStartTimestampMonotonic saiifed)"
    install_saiife 0
    after="$(systemctl show -p MainPID -p ExecMainStartTimestampMonotonic saiifed)"
    [[ "$before" == "$after" ]] || fail "the daemon restarted: $before -> $after"
    ok "no restart ($after)"

    phase "7b. system uninstall keeps the config, vault key, state and audit"
    as_root cat /etc/saiife/installed.toml >"$WORK/installed.toml"
    as_root "$BIN" system uninstall || fail "system uninstall failed"
    while IFS= read -r p; do
        case "$p" in
        /etc/saiife | /etc/saiife/config.toml | /etc/saiife/policy.d | /etc/saiife/credstore | /etc/saiife/credstore/vault-key)
            as_root test -e "$p" || fail "uninstall removed $p"
            ;;
        *)
            if as_root test -e "$p"; then
                fail "uninstall left $p"
            fi
            ;;
        esac
    done < <(listed_paths "$WORK/installed.toml")
    if as_root test -e /etc/saiife/installed.toml; then
        fail "uninstall left /etc/saiife/installed.toml"
    fi
    for p in /var/lib/saiife/keys/audit.ed25519 "$AUDIT_DIR"; do
        as_root test -e "$p" || fail "uninstall removed $p"
    done
    local st
    st="$(systemctl status saiifed --no-pager 2>&1 || true)"
    [[ "$st" == *"could not be found"* ]] || fail "systemctl status saiifed: $st"
    ok "listed paths removed, kept ones kept, the unit is gone"

    phase "7c. system uninstall --purge after a reinstall"
    install_saiife 0 1
    wait_until 30 "the daemon socket after the reinstall" daemon_ready
    as_root "$BIN" system uninstall --purge || fail "system uninstall --purge failed"
    for p in /etc/saiife /var/lib/saiife /var/log/saiife /opt/saiife; do
        if as_root test -e "$p"; then
            fail "purge left $p: $(as_root find "$p" | head -n 20)"
        fi
    done
    [[ -z "$(getent passwd saiife || true)" ]] || fail "purge left the user saiife"
    [[ -z "$(getent group saiife saiife-audit || true)" ]] ||
        fail "purge left a group: $(getent group saiife saiife-audit)"
    ok "purged: nothing under /etc/saiife, /var/lib/saiife, /var/log/saiife, /opt/saiife; no user saiife, no groups saiife, saiife-audit"
}
