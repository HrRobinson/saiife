#!/usr/bin/env bash
# The phases of scripts/locked-macos/run.sh (CI only; see there). Sourcing
# this file only defines functions; run.sh checks the CI gate before it
# sources it. Each phase prints `== <phase>` and stops the job at the first
# broken assertion. The phases and helpers mirror scripts/locked-linux/
# lib.sh, with BSD tools (stat -f, shasum, dscl, launchctl); that file is
# never sourced here.
#
# Several checks here confirm on a real Mac what the Rust code could only
# assume when it was written on Linux (plan 13 as-built reports). They are
# marked "CI confirmation".
#
# Needs from run.sh: BIN (the signed ci-locked saiife to install), HERE,
# REPO, LOGS, WORK (a scratch dir the agent user can read).

AGENT_USER="agent"
AGENT_HOME=/Users/agent
APPROVER_USER="approver"
APPROVER_HOME=/Users/approver
DAEMON_USER=_saiife
DAEMON_GROUP=_saiife
AUDIT_GROUP=_saiifeaudit
OPT_BIN=/opt/saiife/bin/saiife
AUDIT_DIR=/var/log/saiife/audit
DAEMON_LOG=/var/log/saiife/daemon.log
STATE_DIR=/var/db/saiife
KEYS_DIR=/var/db/saiife/keys
VAULT_KEY=/var/db/saiife/keys/vault.key
AUDIT_KEY=/var/db/saiife/keys/audit.ed25519
RUN_DIR=/var/db/saiife-run
SOCKET=/var/db/saiife-run/saiife.sock
PLIST=/Library/LaunchDaemons/com.saiife.saiifed.plist
SERVICE=system/com.saiife.saiifed
RIGHT=com.saiife.approve
CLAUDE_DIR="/Library/Application Support/ClaudeCode/managed-settings.d"
CLAUDE_MANAGED="$CLAUDE_DIR/50-saiife.json"
CLAUDE_MCP="$CLAUDE_DIR/60-saiife-mcp.json"
GEMINI_DIR="/Library/Application Support/GeminiCli"
GEMINI_SETTINGS="$GEMINI_DIR/settings.json"
CODEX_REQUIREMENTS=/etc/codex/requirements.toml
# The same-user refusal text (saiife_system::layout::REAUTH_UNAVAILABLE).
REAUTH_UNAVAILABLE_TEXT="re-authentication unavailable"
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

# The home of a CI account.
home_of() {
    case "$1" in
    "$AGENT_USER") echo "$AGENT_HOME" ;;
    "$APPROVER_USER") echo "$APPROVER_HOME" ;;
    *) echo /var/empty ;;
    esac
}

# `as_user <user> <cwd> <command...>`: the command as `user`, in `cwd`, with
# a clean environment. macOS env(1) has no -C, so a /bin/sh does the cd.
# A variable for the command goes through `/usr/bin/env VAR=value cmd`:
# env sets it after every protected binary in the chain has started, so
# it reaches the command (the A4 control proves this).
as_user() {
    local user="$1" cwd="$2" home
    shift 2
    home="$(home_of "$user")"
    # shellcheck disable=SC2016
    sudo -n -u "$user" /usr/bin/env -i HOME="$home" USER="$user" LOGNAME="$user" \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/private/tmp \
        /bin/sh -c 'cd "$1" || exit 125; shift; exec "$@"' sh "$cwd" "$@"
}

# `/usr/bin/perl -e "$ALARM" <seconds> <command...>`: macOS has no
# timeout(1); the alarm survives exec and ends the command with SIGALRM.
# It runs as the target user, after sudo.
# shellcheck disable=SC2016
ALARM='alarm shift; exec @ARGV or die "exec: $!\n"'

sha_of() {
    as_root shasum -a 256 "$1" | awk '{ print $1 }'
}

# On any failure: daemon.log, the audit log, /etc/saiife, the plist and
# `launchctl print`, for the job to upload. The vault key and the audit
# key live in /var/db/saiife, which is never copied.
on_exit() {
    local code="$1"
    if [[ "$code" != 0 ]]; then
        echo "locked-macos failed (exit $code); collecting logs in $LOGS" >&2
        as_root launchctl print "$SERVICE" >"$LOGS/launchctl-print.txt" 2>&1 || true
        as_root ls -la /private/etc/saiife /private/var/db/saiife /private/var/db/saiife-run \
            /private/var/log/saiife "/private$AUDIT_DIR" /Library/LaunchDaemons \
            "$CLAUDE_DIR" "$GEMINI_DIR" /private/etc/codex /opt/saiife/bin \
            >"$LOGS/ls.txt" 2>&1 || true
        as_root security authorizationdb read "$RIGHT" >"$LOGS/authorizationdb-read.txt" 2>&1 || true
        {
            for u in "$DAEMON_USER" "$AGENT_USER" "$APPROVER_USER"; do
                echo "-- dscl . -read /Users/$u"
                dscl . -read "/Users/$u" UniqueID PrimaryGroupID UserShell IsHidden NFSHomeDirectory 2>&1 || true
            done
            for g in "$DAEMON_GROUP" "$AUDIT_GROUP"; do
                echo "-- dscl . -read /Groups/$g"
                dscl . -read "/Groups/$g" PrimaryGroupID GroupMembership 2>&1 || true
            done
        } >"$LOGS/accounts.txt" 2>&1
        echo "-- launchctl print"
        head -n 60 "$LOGS/launchctl-print.txt" 2>/dev/null || true
        echo "-- daemon.log (last 60 lines)"
        as_root tail -n 60 "$DAEMON_LOG" 2>/dev/null || true
        echo "-- ls"
        cat "$LOGS/ls.txt" 2>/dev/null || true
        # Copied as root through tar; the unprivileged tar writes the copy
        # as the runner user.
        as_root tar -C / -cf - private/etc/saiife "private${AUDIT_DIR}" \
            "private${DAEMON_LOG}" "${PLIST#/}" 2>/dev/null |
            tar -C "$LOGS" -xf - 2>/dev/null || true
        cp -R "$WORK" "$LOGS/work" 2>/dev/null || true
    fi
    cleanup_lockdown || true
    cleanup_config || true
    as_root rm -rf "$WORK" || true
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

# `wait_until_quiet <seconds> <command...>`: true when the command passes in time.
wait_until_quiet() {
    local secs="$1"
    shift
    local end=$((SECONDS + secs))
    until "$@"; do
        ((SECONDS < end)) || return 1
        sleep 0.5
    done
}

# The pid launchd reports for the daemon ("" when it is not running).
daemon_pid() {
    as_root launchctl print "$SERVICE" 2>/dev/null |
        awk '$1 == "pid" && $2 == "=" { print $3; exit }'
}

daemon_ready() {
    [[ -n "$(daemon_pid)" ]] && as_root test -S "$SOCKET"
}

# launchd reports no daemon process (a stale socket file may remain;
# nothing answers on it).
daemon_gone() {
    [[ -z "$(daemon_pid)" ]]
}

# CI confirmation (Task 11, doctor `daemon.unit`): `launchctl print` exits
# 0 for a loaded job and non-zero for one that is not loaded.
expect_print_code() {
    local want="$1" what="$2" code=0
    as_root launchctl print "$SERVICE" >"$WORK/print.out" 2>&1 || code=$?
    case "$want" in
    zero) [[ "$code" == 0 ]] || fail "$what: launchctl print exited $code, want 0: $(head -n 5 "$WORK/print.out")" ;;
    nonzero) [[ "$code" != 0 ]] || fail "$what: launchctl print exited 0, want non-zero" ;;
    esac
    ok "$what: launchctl print $SERVICE exit $code"
}

daemon_log_tail() {
    as_root tail -n 30 "$DAEMON_LOG" >&2 || true
}

# Every audit line, month files in order.
records() {
    # shellcheck disable=SC2016
    as_root sh -c 'cat "$1"/*.jsonl' sh "$AUDIT_DIR"
}

start_count() {
    records | jq -c 'select(.kind == "daemon" and .event == "start")' | wc -l | tr -d ' '
}

restarted_since() {
    [[ "$(start_count)" -gt "$1" ]] && daemon_ready
}

# A pid other than `$1` is running for the job.
pid_changed_from() {
    local now
    now="$(daemon_pid)"
    [[ -n "$now" && "$now" != "$1" ]]
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
# written for the agent user: its name, its uid (LOCAL_PEERCRED) and a peer
# pid (LOCAL_PEERPID).
expect_last_guard() {
    local rec uid
    uid="$(id -u "$AGENT_USER")"
    rec="$(records | jq -c 'select(.kind == "guard")' | tail -n 1)"
    jq -e --arg a "$1" --arg d "$2" --arg i "${3:-}" --arg u "$AGENT_USER" --argjson uid "$uid" \
        '.agent == $a and .decision == $d and .user == $u and .uid == $uid and .mode == "locked"
         and ((.peer.pid // 0) > 0) and ($i == "" or .input == $i)' \
        <<<"$rec" >/dev/null || fail "newest guard record is not $1/$2 by $AGENT_USER (uid $uid, with a peer pid): $rec"
    ok "audit record: $1 $2 by $AGENT_USER (uid $uid, peer pid $(jq -r '.peer.pid' <<<"$rec"))"
}

# `stat_of <path>`: "owner:group mode" (mode in octal without the type,
# setgid included), stat'ed as root.
stat_of() {
    local raw og p
    raw="$(as_root stat -f '%Su:%Sg %p' "$1")" || return 1
    og="${raw% *}"
    p="${raw##* }"
    printf '%s %o\n' "$og" "$((8#$p & 8#7777))"
}

# `expect_stat <path> <owner:group mode>`
expect_stat() {
    local path="$1" want="$2" got
    got="$(stat_of "$path")" || fail "stat $path failed"
    [[ "$got" == "$want" ]] || fail "$path: $got, want $want"
    ok "$path $got"
}

# `payload <fixture> [jq filter]`: a copy of a recorded hook payload with
# its cwd in the agent user's home. Prints the copy's path.
payload() {
    local out
    out="$(mktemp "$WORK/payload.XXXXXX")"
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
    as_user "$AGENT_USER" "$AGENT_HOME" /usr/bin/env "$@" \
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

# `attempt <what> <command...>`: the command as the agent user; sets
# ATTACK_CODE and ATTACK_OUT. Cut off after 60 s (nobody answers a prompt).
ATTACK_CODE=0
ATTACK_OUT=""
attempt() {
    shift
    ATTACK_CODE=0
    as_user "$AGENT_USER" "$AGENT_HOME" /usr/bin/perl -e "$ALARM" 60 "$@" \
        </dev/null >"$WORK/attack.out" 2>&1 || ATTACK_CODE=$?
    ATTACK_OUT="$(cat "$WORK/attack.out")"
}

# `expect_refused <what> <command...>`: the command, as the agent user, fails.
expect_refused() {
    local what="$1"
    attempt "$@"
    [[ "$ATTACK_CODE" != 0 ]] || fail "$what succeeded as $AGENT_USER: $ATTACK_OUT"
    ok "$what: refused (exit $ATTACK_CODE${ATTACK_OUT:+: $ATTACK_OUT})"
}

# `expect_denied <what> <command...>`: the command, as the agent user,
# fails with a permission error.
expect_denied() {
    local what="$1"
    attempt "$@"
    [[ "$ATTACK_CODE" != 0 ]] || fail "$what succeeded as $AGENT_USER"
    [[ "$ATTACK_OUT" == *"Permission denied"* || "$ATTACK_OUT" == *"Operation not permitted"* ]] ||
        fail "$what failed without a permission error (exit $ATTACK_CODE): $ATTACK_OUT"
    ok "$what: $ATTACK_OUT"
}

# `install_saiife <allowed exit codes...>`: `system install` with the CI
# config, its output in $WORK/install.out.
install_saiife() {
    local code=0 c
    # --allow-test-build: $BIN has debug assertions on (the fault seam) and
    # an ad-hoc signature; install refuses such a build without it.
    as_root "$BIN" system install --config "$CI_CONFIG" --agents claude,codex,gemini \
        --approvers "$APPROVER_USER" --non-interactive --allow-test-build \
        >"$WORK/install.out" 2>&1 || code=$?
    cat "$WORK/install.out"
    for c in "$@"; do
        if [[ "$code" == "$c" ]]; then
            ok "system install exit $code"
            return 0
        fi
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

# The audit dir and its month files. CI confirmation (Task 7): on BSD a new
# file takes its directory's gid, so the month files are in _saiifeaudit
# without a chown.
audit_dir_checks() {
    local f found=0
    expect_stat "$AUDIT_DIR" "$DAEMON_USER:$AUDIT_GROUP 2750"
    dscl . -read "/Groups/$AUDIT_GROUP" GroupMembership 2>/dev/null | tr ' ' '\n' | grep -qx "$DAEMON_USER" ||
        fail "$DAEMON_USER is not in $AUDIT_GROUP: $(dscl . -read "/Groups/$AUDIT_GROUP" GroupMembership 2>&1)"
    while IFS= read -r f; do
        found=1
        expect_stat "$f" "$DAEMON_USER:$AUDIT_GROUP 640"
    done < <(as_root find "/private$AUDIT_DIR" -maxdepth 1 -name '*.jsonl')
    ((found)) || fail "no month file in $AUDIT_DIR"
    as_root -u "$DAEMON_USER" test -w "$AUDIT_DIR" || fail "the daemon user cannot write $AUDIT_DIR"
}

# The paths an installed.toml lists: files, managed configs and dirs.
listed_paths() {
    sed -n 's/^path = "\(.*\)"$/\1/p' "$1"
    sed -n 's/^dirs = \[\(.*\)\]$/\1/p' "$1" | tr ',' '\n' | sed 's/^ *"//; s/" *$//' | grep -v '^$' || true
}

# `dscl_attr <record> <attribute>`: the first value, in either of dscl's
# layouts (`Key: value`, or `Key:` and the value on the next line).
dscl_attr() {
    dscl . -read "$1" "$2" 2>/dev/null | awk -v k="$2:" '
        $1 == k { if (NF > 1) { sub(/^[^:]*:[ \t]*/, ""); print; exit } want = 1; next }
        want { sub(/^[ \t]+/, ""); print; exit }'
}

# `record_absent <record>`: CI confirmation (Task 4, `dscl_read_found`):
# dscl reports a missing record with eDSRecordNotFound or -14136 and a
# non-zero exit; install relies on that text.
record_absent() {
    local code=0 out
    out="$(dscl . -read "$1" 2>&1)" || code=$?
    [[ "$code" != 0 ]] || return 1
    [[ "$out" == *eDSRecordNotFound* || "$out" == *-14136* ]] ||
        fail "dscl . -read $1 failed (exit $code) without eDSRecordNotFound / -14136: $out"
}

# The first free uid from 600 up on the local node.
free_uid() {
    dscl . -list /Users UniqueID | awk '
        { taken[$2] = 1 }
        END { for (u = 600; u < 1000; u++) if (!(u in taken)) { print u; exit } }'
}

# `create_user <name> <home>`: a standard (not admin) local account with a
# random password nobody knows, primary group staff.
create_user() {
    local name="$1" home="$2" uid pw
    record_absent "/Users/$name" || fail "the runner already has a user $name"
    uid="$(free_uid)"
    [[ -n "$uid" ]] || fail "no free uid for $name"
    # Random and never printed. It is on dscl's argv for a moment: the
    # runner is ephemeral and single-job.
    pw="$(openssl rand -hex 24)"
    as_root dscl . -create "/Users/$name"
    as_root dscl . -create "/Users/$name" UserShell /bin/bash
    as_root dscl . -create "/Users/$name" RealName "saiife CI $name"
    as_root dscl . -create "/Users/$name" UniqueID "$uid"
    as_root dscl . -create "/Users/$name" PrimaryGroupID 20
    as_root dscl . -create "/Users/$name" NFSHomeDirectory "$home"
    as_root dscl . -passwd "/Users/$name" "$pw"
    as_root mkdir -p "$home"
    as_root chown "$name:staff" "$home"
    as_root chmod 0755 "$home"
    as_root dscacheutil -flushcache || true
    wait_until 15 "the user $name to resolve" id -u "$name"
    [[ "$(id -u "$name")" == "$uid" ]] || fail "$name resolves to uid $(id -u "$name"), want $uid"
    if dseditgroup -o checkmember -m "$name" admin >/dev/null 2>&1; then
        fail "$name is an admin"
    fi
    ok "user $name (uid $uid, staff, not admin, home $home)"
}

# ------------------------------------------------------------ phases

# The runner image is normalised first, as on Linux: every root-owned
# ancestor install writes below loses group/other write (sticky dirs
# excepted), and each change is logged. Then the two accounts.
prepare_host() {
    phase "0. host preparation (runner image, macOS $(sw_vers -productVersion), $(uname -m))"
    local d mode owner base path n
    command -v jq >/dev/null || fail "jq is not installed"
    for d in /opt /Library /Library/LaunchDaemons "/Library/Application Support" \
        /private/etc /private/var /private/var/db /private/var/log; do
        [[ -d "$d" ]] || continue
        owner="$(stat -f '%Su' "$d")"
        mode="$(stat -f '%p' "$d")"
        [[ "$owner" == root ]] || fail "$d is owned by $owner, not root"
        if (((8#$mode & 8#022) != 0 && (8#$mode & 8#1000) == 0)); then
            as_root chmod go-w "$d"
            echo "  changed: $d mode $(printf '%o' $((8#$mode & 8#7777))) -> $(stat -f '%Lp' "$d")"
            echo "::warning::prepare_host: chmod go-w $d (runner image had mode $(printf '%o' $((8#$mode & 8#7777))))"
        else
            echo "  kept: $d $(stat -f '%Su:%Sg %Lp' "$d")"
        fi
    done

    # CI confirmation (Tasks 7, 9, 10): unix socket paths must stay under
    # 104 bytes. The test job's tempdirs (runner.temp/s, and the default
    # $TMPDIR) plus a tempfile name and a socket name must fit.
    for base in "${RUNNER_TEMP:-}/s" "${TMPDIR:-/tmp}"; do
        [[ "$base" != /s ]] || continue
        path="${base%/}/.tmpAbCdEf/run/saiife.sock"
        n="${#path}"
        ((n <= 103)) || fail "socket path budget: $path is $n bytes (max 103)"
        ok "socket path budget: $n bytes under $base"
    done

    create_user "$AGENT_USER" "$AGENT_HOME"
    create_user "$APPROVER_USER" "$APPROVER_HOME"
    echo "  project dir: $AGENT_HOME"
}

phase_install() {
    phase "1. system install (macOS $(sw_vers -productVersion), $(uname -m))"
    # The build under test: ad-hoc, hardened runtime (codesign's own view).
    codesign -dv "$BIN" >"$WORK/codesign.txt" 2>&1 || fail "codesign -dv $BIN: $(cat "$WORK/codesign.txt")"
    grep -Eq 'flags=0x[0-9a-f]+\(.*runtime' "$WORK/codesign.txt" ||
        fail "$BIN is not signed with the hardened runtime: $(cat "$WORK/codesign.txt")"
    grep -Eq 'flags=0x[0-9a-f]+\(.*adhoc' "$WORK/codesign.txt" ||
        fail "$BIN is not an ad-hoc signature: $(cat "$WORK/codesign.txt")"
    ok "codesign: ad hoc with the hardened runtime ($(grep -E '^CodeDirectory' "$WORK/codesign.txt"))"

    install_saiife 0
    # CI confirmation (Task 5, inspect_macho on a real ad-hoc build): the
    # test build is named, the ad-hoc signature is a warning, and the
    # hardened runtime is seen.
    grep -q 'test build' "$WORK/install.out" || fail "install did not warn about the test build"
    grep -q 'ad-hoc signature' "$WORK/install.out" || fail "install did not warn about the ad-hoc signature"
    if grep -q 'without the hardened runtime' "$WORK/install.out"; then
        fail "install did not see the hardened runtime of an ad-hoc build signed with --options runtime"
    fi
    if grep -q 'not code-signed' "$WORK/install.out"; then
        fail "install took the ad-hoc build for an unsigned one"
    fi
    ok "install: test-build and ad-hoc warnings, hardened runtime recognised"
    grep -q 'same-user approval is off on macOS: approvals need a second account' "$WORK/install.out" ||
        fail "install did not warn that same-user approval is off on macOS"
    ok "install: same-user approval is off warning"
    wait_until 30 "the daemon socket" daemon_ready
    expect_print_code zero "loaded"
    ok "saiifed running (pid $(daemon_pid))"
}

phase_modes() {
    phase "2. owners and modes (spec §5.3), accounts"
    local p uid gid out names
    for p in /opt/saiife /opt/saiife/bin "$OPT_BIN" /etc/saiife /etc/saiife/policy.d \
        "$CLAUDE_DIR" "$GEMINI_DIR" /etc/codex; do
        expect_stat "$p" "root:wheel 755"
    done
    for p in /etc/saiife/config.toml /etc/saiife/installed.toml "$PLIST" \
        "$CLAUDE_MANAGED" "$CLAUDE_MCP" "$GEMINI_SETTINGS" "$CODEX_REQUIREMENTS"; do
        expect_stat "$p" "root:wheel 644"
    done
    expect_stat "$STATE_DIR" "$DAEMON_USER:$DAEMON_GROUP 700"
    expect_stat "$KEYS_DIR" "$DAEMON_USER:$DAEMON_GROUP 700"
    expect_stat "$VAULT_KEY" "$DAEMON_USER:$DAEMON_GROUP 400"
    [[ "$(as_root stat -f '%z' "$VAULT_KEY")" == 32 ]] || fail "$VAULT_KEY is not 32 bytes"
    expect_stat "$AUDIT_KEY" "$DAEMON_USER:$DAEMON_GROUP 600"
    expect_stat "$RUN_DIR" "$DAEMON_USER:$DAEMON_GROUP 755"
    expect_stat "$SOCKET" "$DAEMON_USER:$DAEMON_GROUP 666"
    expect_stat /var/log/saiife "root:wheel 755"
    expect_stat "$DAEMON_LOG" "$DAEMON_USER:$AUDIT_GROUP 640"
    audit_dir_checks

    # The daemon account. CI confirmation (Task 4): the `dscl -read`
    # attribute layout install parses.
    dscl . -read "/Users/$DAEMON_USER" >"$WORK/dscl-user.txt" 2>&1 || fail "dscl . -read /Users/$DAEMON_USER failed"
    [[ "$(dscl_attr "/Users/$DAEMON_USER" IsHidden)" == 1 ]] ||
        fail "$DAEMON_USER is not hidden: $(cat "$WORK/dscl-user.txt")"
    [[ "$(dscl_attr "/Users/$DAEMON_USER" UserShell)" == /usr/bin/false ]] ||
        fail "$DAEMON_USER's shell is not /usr/bin/false: $(cat "$WORK/dscl-user.txt")"
    uid="$(dscl_attr "/Users/$DAEMON_USER" UniqueID)"
    [[ "$uid" =~ ^[0-9]+$ ]] || fail "$DAEMON_USER has no numeric uid: $(cat "$WORK/dscl-user.txt")"
    if ((uid < 200 || uid > 400)); then
        fail "$DAEMON_USER uid $uid is not in 200-400"
    fi
    [[ "$(id -u "$DAEMON_USER")" == "$uid" ]] || fail "dscl uid $uid and id -u $(id -u "$DAEMON_USER") differ"
    gid="$(dscl_attr "/Groups/$DAEMON_GROUP" PrimaryGroupID)"
    [[ "$(dscl_attr "/Users/$DAEMON_USER" PrimaryGroupID)" == "$gid" ]] ||
        fail "$DAEMON_USER's primary group is not $DAEMON_GROUP ($gid)"
    ok "$DAEMON_USER: IsHidden 1, UserShell /usr/bin/false, uid $uid, primary group $DAEMON_GROUP ($gid)"

    # CI confirmation (Task 4, parse_dscl_search): the `-search` layout is
    # `name<TAB><TAB>PrimaryGroupID = (`, the values, `)`. This awk is the
    # parser's rule; it must find exactly the daemon user for its own gid.
    out="$(dscl . -search /Users PrimaryGroupID "$gid")" || fail "dscl . -search /Users PrimaryGroupID $gid failed"
    printf '%s\n' "$out" | sed 's/^/    | /'
    names="$(printf '%s\n' "$out" | awk -v gid="$gid" '
        /^[^ \t]/ { cur = ""; if (index($0, "=") > 0) cur = $1; rest = substr($0, index($0, "=") + 1) }
        /^[ \t]/ || $0 ~ /^\)$/ { rest = $0 }
        { n = split(rest, w, "[ \t()]+"); for (i = 1; i <= n; i++) if (cur != "" && w[i] == gid && !(cur in seen)) { seen[cur] = 1; print cur } }')"
    [[ "$names" == "$DAEMON_USER" ]] || fail "dscl -search for gid $gid gave \"$names\" by the parser's rule, want $DAEMON_USER"
    ok "dscl -search layout: $DAEMON_USER found for gid $gid"
    record_absent /Users/saiife-ci-absent || fail "dscl . -read of a missing record exited 0"
    ok "dscl -read of a missing record: eDSRecordNotFound / -14136"
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

# `bootstrap_once`: load the job again (launchd may still be tearing the
# old one down for a moment).
bootstrap_once() {
    as_root launchctl bootstrap system "$PLIST" >"$WORK/bootstrap.out" 2>&1 || {
        [[ -n "$(daemon_pid)" ]]
    }
}

phase_fail_closed() {
    phase "4. fail closed (spec §9.3)"
    local spec agent fixture before p pid
    before="$(start_count)"
    as_root launchctl bootout "$SERVICE" || fail "launchctl bootout $SERVICE failed"
    wait_until 15 "the daemon to stop" daemon_gone
    expect_print_code nonzero "after bootout"
    for spec in claude:claude/bash-deny.json claude:claude/bash-allow.json \
        codex:codex/bash-deny.json codex:codex/bash-allow.json \
        gemini:gemini/shell-deny.json gemini:gemini/shell-allow.json; do
        agent="${spec%%:*}"
        fixture="${spec#*:}"
        p="$(payload "$fixture")"
        expect_hook 2 "fail closed" "daemon booted out: $fixture" "$agent" "$p"
    done
    wait_until 30 "launchctl bootstrap to load the job (output: work/bootstrap.out in the logs)" bootstrap_once
    wait_until 30 "the start record after bootstrap" restarted_since "$before"
    expect_print_code zero "after bootstrap"
    expect_last_start true "after bootout + bootstrap"

    before="$(start_count)"
    pid="$(daemon_pid)"
    [[ -n "$pid" ]] || fail "no daemon pid"
    # CI only: SIGKILL the daemon; KeepAlive brings it back.
    as_root kill -9 "$pid"
    wait_until 5 "launchd to restart the daemon after SIGKILL (pid $pid)" pid_changed_from "$pid"
    ok "launchd restarted the daemon: pid $pid -> $(daemon_pid)"
    wait_until 30 "the start record after SIGKILL" restarted_since "$before"
    expect_last_start false "after SIGKILL and the launchd restart"
    local allow
    allow="$(payload claude/bash-allow.json)"
    expect_hook 0 "" "allow after the restart" claude "$allow"

    # The disk floor, through a reload (SIGHUP via launchctl kill).
    set_config 's/^min_free_mb = 512$/min_free_mb = 99999999/'
    as_root grep -qx 'min_free_mb = 99999999' /etc/saiife/config.toml || fail "min_free_mb was not raised"
    as_root launchctl kill SIGHUP "$SERVICE"
    wait_until 15 "the disk floor to deny the allow fixture" hook_code_is 2 claude "$allow"
    ok "disk floor reached: allow fixture -> exit 2 ($HOOK_ERR)"
    echo "  after the reload:"
    audit_dir_checks
    set_config 's/^min_free_mb = 99999999$/min_free_mb = 512/'
    as_root grep -qx 'min_free_mb = 512' /etc/saiife/config.toml || fail "min_free_mb was not restored"
    as_root launchctl kill SIGHUP "$SERVICE"
    wait_until 15 "the restored floor to allow again" hook_code_is 0 claude "$allow"
    ok "floor restored: allow fixture -> exit 0"
}

# `set_config <sed script>`: edits /etc/saiife/config.toml in place through
# tee, so its owner and mode stay root:wheel 644 (BSD sed -i would replace
# the file).
set_config() {
    as_root cat /etc/saiife/config.toml | sed -e "$1" >"$WORK/config.edit"
    as_root tee /etc/saiife/config.toml <"$WORK/config.edit" >/dev/null
}

phase_attacks() {
    phase "5. attacks on the install as $AGENT_USER"
    local p before pid right_before allow marker control_marker
    for p in /etc/saiife/config.toml /etc/saiife/installed.toml "$PLIST" "$CLAUDE_MANAGED" \
        "$GEMINI_SETTINGS" "$CODEX_REQUIREMENTS" "$OPT_BIN"; do
        before="$(sha_of "$p")"
        # shellcheck disable=SC2016
        expect_denied "write $p" /bin/sh -c 'printf x >>"$1"' sh "$p"
        [[ "$(sha_of "$p")" == "$before" ]] || fail "$p changed"
    done
    expect_denied "read $VAULT_KEY" /bin/cat "$VAULT_KEY"
    expect_denied "read $AUDIT_KEY" /bin/cat "$AUDIT_KEY"
    expect_denied "write the audit dir" /usr/bin/touch "$AUDIT_DIR/forged.jsonl"
    as_root test ! -e "$AUDIT_DIR/forged.jsonl" || fail "$AUDIT_DIR/forged.jsonl exists"

    pid="$(daemon_pid)"
    [[ -n "$pid" ]] || fail "no daemon pid"
    expect_denied "kill the daemon (pid $pid)" /bin/kill -s TERM "$pid"
    [[ "$(daemon_pid)" == "$pid" ]] || fail "the daemon pid changed"
    expect_refused "launchctl bootout $SERVICE" /bin/launchctl bootout "$SERVICE"
    [[ "$(daemon_pid)" == "$pid" ]] || fail "the daemon pid changed after the agent's bootout"
    expect_print_code zero "after the agent's bootout"

    # shellcheck disable=SC2016
    expect_denied "create a socket in $RUN_DIR" /usr/bin/perl -MIO::Socket::UNIX -e \
        'IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => $ARGV[0], Listen => 1) or die "bind $ARGV[0]: $!\n"' \
        "$RUN_DIR/forged.sock"
    as_root test ! -e "$RUN_DIR/forged.sock" || fail "$RUN_DIR/forged.sock exists"

    right_before="$(as_root security authorizationdb read "$RIGHT" 2>/dev/null | shasum -a 256)"
    expect_refused "security authorizationdb write $RIGHT allow" /usr/bin/security authorizationdb write "$RIGHT" allow
    [[ "$(as_root security authorizationdb read "$RIGHT" 2>/dev/null | shasum -a 256)" == "$right_before" ]] ||
        fail "the right $RIGHT changed"
    ok "the right $RIGHT is unchanged"

    # A4: DYLD_INSERT_LIBRARIES into the hook. The control proves the
    # library and the delivery path work; the hardened hook ignores it.
    cc -dynamiclib -o "$WORK/inject.dylib" "$HERE/inject.c" || fail "cc -dynamiclib inject.c"
    cc -DCONTROL -o "$WORK/inject-control" "$HERE/inject.c" || fail "cc -DCONTROL inject.c"
    chmod 0644 "$WORK/inject.dylib"
    chmod 0755 "$WORK/inject-control"
    control_marker="$AGENT_HOME/a4-control.marker"
    marker="$AGENT_HOME/a4-hook.marker"
    as_root rm -f "$control_marker" "$marker"
    as_user "$AGENT_USER" "$AGENT_HOME" /usr/bin/env DYLD_INSERT_LIBRARIES="$WORK/inject.dylib" \
        SAIIFE_INJECT_MARKER="$control_marker" "$WORK/inject-control" || fail "the A4 control program failed"
    as_root test -f "$control_marker" ||
        fail "A4 control: the library did not run in a plain program, so the probe proves nothing"
    ok "A4 control: DYLD_INSERT_LIBRARIES runs the library in a program without the hardened runtime"
    allow="$(payload claude/bash-allow.json)"
    expect_hook 0 "" "A4: hook with DYLD_INSERT_LIBRARIES" claude "$allow" \
        DYLD_INSERT_LIBRARIES="$WORK/inject.dylib" SAIIFE_INJECT_MARKER="$marker"
    if as_root test -e "$marker"; then
        fail "A4: the injected library ran inside the managed hook"
    fi
    ok "A4: no marker; the hardened runtime kept the library out of the hook"
}

phase_doctor() {
    phase "6. saiife doctor --json as root"
    local code=0 id status detail
    as_root "$OPT_BIN" doctor --json >"$WORK/doctor.json" 2>"$WORK/doctor.err" || code=$?
    cat "$WORK/doctor.err"
    jq -r '.checks[] | "\(.status | ascii_upcase)  \(.id)  \(.title): \(.detail)"' "$WORK/doctor.json"
    [[ "$(jq -r .exit "$WORK/doctor.json")" == "$code" ]] || fail "doctor exited $code, its report says $(jq -r .exit "$WORK/doctor.json")"
    [[ "$code" == 1 ]] || fail "doctor exited $code, want 1 (warnings only: the test build)"
    [[ -z "$(jq -r '.checks[] | select(.status == "fail") | .id' "$WORK/doctor.json")" ]] ||
        fail "doctor checks failed: $(jq -c '[.checks[] | select(.status == "fail")]' "$WORK/doctor.json")"
    ok "doctor: no check fails"
    for id in daemon.health daemon.unit daemon.audit_group files.installed files.modes keys paths.owner; do
        status="$(jq -r --arg id "$id" '.checks[] | select(.id == $id) | .status' "$WORK/doctor.json")"
        [[ "$status" == pass ]] || fail "doctor check $id: ${status:-missing}"
        ok "doctor $id: pass"
    done
    status="$(jq -r '.checks[] | select(.id == "files.binary") | .status' "$WORK/doctor.json")"
    [[ "$status" == warn ]] || fail "doctor check files.binary: ${status:-missing}, want warn (ad-hoc test build installed)"
    ok "doctor files.binary: warn (ad-hoc test build installed)"
    # CI confirmation (Tasks 6, 11): the real `security authorizationdb
    # read` output passes read_ok, so doctor says the right is registered.
    status="$(jq -r '.checks[] | select(.id == "reauth") | .status' "$WORK/doctor.json")"
    detail="$(jq -r '.checks[] | select(.id == "reauth") | .detail' "$WORK/doctor.json")"
    [[ ("$status" == info || "$status" == pass) && "$detail" == *"$RIGHT is registered"* ]] ||
        fail "doctor reauth: $status: $detail (want the right reported registered)"
    ok "doctor reauth: $status ($detail)"
    ok "doctor exit $code"
}

# ----------------------------------------------------- approvals (plan 11)

CONFIG_BACKUP=""
# Set by `saiife_as`.
SA_CODE=0
SA_OUT=""
SA_ERR=""

# `saiife_as <user> <cwd> <args...>`: the installed saiife as `user`. Sets
# SA_CODE, SA_OUT and SA_ERR. No tty, no stdin: nobody can answer a prompt.
# A hang is cut off after 150 s (the reauth timeout is 120 s).
saiife_as() {
    local user="$1" cwd="$2"
    shift 2
    SA_CODE=0
    as_user "$user" "$cwd" /usr/bin/perl -e "$ALARM" 150 "$OPT_BIN" "$@" \
        </dev/null >"$WORK/sa.out" 2>"$WORK/sa.err" || SA_CODE=$?
    SA_OUT="$(cat "$WORK/sa.out")"
    SA_ERR="$(cat "$WORK/sa.err")"
}

# Put back the config a phase changed. Idempotent: also runs from on_exit,
# whatever state the phase stopped in.
cleanup_config() {
    if [[ -n "$CONFIG_BACKUP" && -e "$CONFIG_BACKUP" ]]; then
        as_root tee /etc/saiife/config.toml <"$CONFIG_BACKUP" >/dev/null || true
        rm -f "$CONFIG_BACKUP" || true
    fi
    CONFIG_BACKUP=""
}

# `replace_tables <table regex> <file with the new tables>`: the installed
# config without those tables (and their sub-tables), then the new ones; a
# duplicate table would make the reload fail. The old config is kept for
# cleanup_config.
replace_tables() {
    CONFIG_BACKUP="$WORK/config.backup"
    as_root cat /etc/saiife/config.toml >"$CONFIG_BACKUP"
    awk -v re="$1" '
        /^[ \t]*\[/ { skip = ($0 ~ ("^[ \t]*\\[(" re ")(\\.[A-Za-z0-9_.-]*)?\\][ \t]*(#.*)?$")) }
        !skip { print }
    ' "$CONFIG_BACKUP" >"$WORK/config.new"
    cat "$2" >>"$WORK/config.new"
    # tee rewrites the file in place: owner and mode stay root:wheel 644.
    as_root tee /etc/saiife/config.toml <"$WORK/config.new" >/dev/null
}

# The newest `refused` approval record's rule for request `$1` ("" if none).
last_refusal_rule() {
    records | jq -r --argjson id "$1" \
        'select(.kind == "approval" and .approval == $id and .action == "refused") | .rule' | tail -n 1
}

# The newest `refused` approval record's reason for request `$1`.
last_refusal_reason() {
    records | jq -r --argjson id "$1" \
        'select(.kind == "approval" and .approval == $id and .action == "refused") | .reason // ""' | tail -n 1
}

# The actions recorded for request `$1`, in order, comma separated.
approval_actions() {
    records | jq -r --argjson id "$1" 'select(.kind == "approval" and .approval == $id) | .action' | paste -sd, -
}

# The hook now answers a force-push with a request (the ask rule is live).
hook_asks() {
    hook "$@"
    [[ "$HOOK_CODE" == 2 && "$HOOK_ERR" == *"Needs approval: request #"* ]]
}

# The force-push is blocked outright again (the ask rule is gone).
hook_denied_not_asked() {
    hook "$@"
    [[ "$HOOK_CODE" == 2 && "$HOOK_ERR" == *"BLOCKED by"* ]]
}

# The request id in the hook's stderr.
asked_id() {
    local id
    id="$(sed -n 's/.*Needs approval: request #\([0-9][0-9]*\)\..*/\1/p' <<<"$HOOK_ERR" | head -n 1)"
    [[ -n "$id" ]] || fail "no request id in the hook message: $HOOK_ERR"
    printf '%s\n' "$id"
}

# `expect_pending <id> <what>`: the requester's `approvals list --json` has
# the request, pending, for the agent user.
expect_pending() {
    saiife_as "$AGENT_USER" "$AGENT_HOME" approvals list --json
    [[ "$SA_CODE" == 0 ]] || fail "$2: approvals list exited $SA_CODE: $SA_ERR"
    jq -s -e --arg id "$1" --arg u "$AGENT_USER" \
        '[.[] | if type == "array" then .[] else . end | select((.id | tostring) == $id)] | length == 1 and .[0].state == "pending" and .[0].user == $u' \
        <<<"$SA_OUT" >/dev/null || fail "$2: request #$1 is not pending for $AGENT_USER in: $SA_OUT"
    ok "$2: request #$1 pending (approvals list --json)"
}

# The agent approves its own request under same_user = "reauth": on macOS
# that is off (no prompt can show the request), so it is refused as
# reauth_unavailable and recorded.
self_approve_refused_unavailable() {
    saiife_as "$AGENT_USER" "$AGENT_HOME" approve "$1"
    [[ "$SA_CODE" != 0 && "$(last_refusal_rule "$1")" == reauth_unavailable &&
        "$(last_refusal_reason "$1")" == *"$REAUTH_UNAVAILABLE_TEXT"* ]]
}

policy_count() {
    records | jq -c 'select(.kind == "policy")' | wc -l | tr -d ' '
}

policy_grew_since() {
    [[ "$(policy_count)" -gt "$1" ]]
}

# `wait_diag <seconds> <what> <command...>`: like wait_until, but a timeout
# prints the last stderr of the hook and of saiife, and the newest refusal.
wait_diag() {
    local secs="$1" what="$2"
    shift 2
    local end=$((SECONDS + secs))
    until "$@"; do
        if ((SECONDS >= end)); then
            echo "  last hook stderr: $HOOK_ERR" >&2
            echo "  last saiife stderr: $SA_ERR (exit $SA_CODE)" >&2
            echo "  newest refusal: $(records | jq -c 'select(.kind == "approval" and .action == "refused") | {rule, reason}' | tail -n 1)" >&2
            fail "timed out after ${secs}s waiting for $what"
        fi
        sleep 0.5
    done
}

# SIGHUP through launchd, then wait for the new `policy` record and fail
# unless it was loaded (a refused config keeps the old policy).
reload_checked() {
    local before result
    before="$(policy_count)"
    as_root launchctl kill SIGHUP "$SERVICE"
    if ! wait_until_quiet 30 policy_grew_since "$before"; then
        daemon_log_tail
        fail "no new policy record 30s after the reload"
    fi
    result="$(records | jq -r 'select(.kind == "policy") | .result' | tail -n 1)"
    if [[ "$result" == rejected ]]; then
        records | jq -c 'select(.kind == "policy")' | tail -n 1 >&2
        daemon_log_tail
        fail "the daemon rejected the reloaded config"
    fi
    ok "reload: policy $result"
}

phase_approvals() {
    phase "6b. approvals: the authorization right, a second account, same_user"
    local first third forced key want got

    # The right as registered, read back with plutil (decision 4).
    as_root security authorizationdb read "$RIGHT" >"$WORK/right.plist" 2>"$WORK/right.err" ||
        fail "security authorizationdb read $RIGHT failed: $(cat "$WORK/right.err")"
    for key in class=user authenticate-user=true allow-root=false session-owner=true shared=false timeout=0; do
        want="${key#*=}"
        got="$(plutil -extract "${key%%=*}" raw -o - "$WORK/right.plist" 2>&1)" || got="(missing: $got)"
        [[ "$got" == "$want" ]] || fail "right $RIGHT: ${key%%=*} is $got, want $want"
    done
    for key in rule mechanisms k-of-n; do
        if plutil -extract "$key" raw -o - "$WORK/right.plist" >/dev/null 2>&1; then
            fail "right $RIGHT has a $key key"
        fi
    done
    ok "right $RIGHT: class user, authenticate-user, not root, session owner, not shared, timeout 0"

    # The agent is listed too, so that its own approval gets as far as
    # the same_user rule.
    cat >"$WORK/tables.approvals" <<EOF

[guard]
ask = ["core.git/force-push"]

[approval]
approvers = ["$APPROVER_USER", "$AGENT_USER"]
same_user = "deny"
EOF
    replace_tables 'guard|approval' "$WORK/tables.approvals"
    reload_checked
    forced="$(payload claude/bash-deny.json '.tool_input.command = "git push --force origin main"')"
    wait_diag 30 "the ask rule after the reload" hook_asks claude "$forced"
    first="$(asked_id)"
    ok "ask rule: git push --force -> request #$first ($HOOK_ERR)"
    expect_pending "$first" "ask"

    # A second account approves; the requester's retry is allowed once.
    saiife_as "$APPROVER_USER" "$APPROVER_HOME" approve "$first" --note "locked-macos CI"
    [[ "$SA_CODE" == 0 ]] || fail "$APPROVER_USER: approve #$first exited $SA_CODE: $SA_ERR"
    ok "$APPROVER_USER (second account) approved #$first"
    expect_hook 0 "" "retry after the approval (the grant, used once)" claude "$forced"
    hook claude "$forced"
    [[ "$HOOK_CODE" == 2 && "$HOOK_ERR" == *"Needs approval: request #"* ]] ||
        fail "third run: exit $HOOK_CODE, want a new request; stderr: $HOOK_ERR"
    third="$(asked_id)"
    [[ "$third" != "$first" ]] || fail "third run reused request #$first"
    ok "third run: asked again, request #$third"
    [[ "$(approval_actions "$first")" == *approved* ]] || fail "#$first: no approved record: $(approval_actions "$first")"

    # same_user = "deny": the requester cannot approve its own request.
    saiife_as "$AGENT_USER" "$AGENT_HOME" approve "$third"
    [[ "$SA_CODE" == 2 ]] || fail "$AGENT_USER approving its own #$third exited $SA_CODE, want 2: $SA_ERR"
    [[ "$(last_refusal_rule "$third")" == same_user ]] || fail "#$third: refusal rule is '$(last_refusal_rule "$third")', want same_user"
    expect_pending "$third" "after the refused self-approval"
    ok "same_user = deny: self-approval refused (exit 2, rule same_user)"

    # same_user = "reauth": off on macOS (Task 8 decision (b)), so the
    # self-approval is refused as unavailable, recorded, and no prompt.
    set_config 's/^same_user = "deny"$/same_user = "reauth"/'
    as_root grep -qx 'same_user = "reauth"' /etc/saiife/config.toml || fail "same_user was not set to reauth"
    reload_checked
    wait_diag 60 "the self-approval to be refused as reauth_unavailable" self_approve_refused_unavailable "$third"
    ok "same_user = reauth: self-approval refused (exit $SA_CODE, rule reauth_unavailable: $(last_refusal_reason "$third"))"
    expect_pending "$third" "after the unavailable reauth"
    [[ "$(approval_actions "$third")" != *approved* ]] || fail "#$third was approved: $(approval_actions "$third")"

    # Leave nothing pending, then put everything back.
    saiife_as "$APPROVER_USER" "$APPROVER_HOME" reject "$third"
    [[ "$SA_CODE" == 0 ]] || fail "$APPROVER_USER: reject #$third exited $SA_CODE: $SA_ERR"
    ok "$APPROVER_USER rejected #$third"
    cleanup_config
    reload_checked
    wait_diag 30 "the daemon after restoring the config" daemon_ready
    wait_diag 30 "the force-push to be blocked again, not asked" hook_denied_not_asked claude "$forced"
    ok "config restored"
}

# ------------------------------------------------------ lockdown (plan 11)

LOCKDOWN_ON=0

# The newest `lockdown` record as compact JSON ("" if none).
last_lockdown_record() {
    records | jq -c 'select(.kind == "lockdown")' | tail -n 1
}

# Lift lockdown as root (best effort): also runs from on_exit.
cleanup_lockdown() {
    if [[ "$LOCKDOWN_ON" == 1 ]]; then
        as_root "$OPT_BIN" lockdown off >/dev/null 2>&1 || true
        LOCKDOWN_ON=0
    fi
}

hook_locked_out() {
    hook "$@"
    [[ "$HOOK_CODE" == 2 && "$HOOK_ERR" == *"saiife lockdown is on"* ]]
}

phase_lockdown() {
    phase "6c. lockdown: who may set it, survives a restart, who may lift it"
    local allow rec code=0
    allow="$(payload claude/bash-allow.json)"

    # An approver who is not an admin, under same_user = "deny".
    cat >"$WORK/tables.lockdown" <<EOF

[approval]
approvers = ["$APPROVER_USER"]
same_user = "deny"
EOF
    replace_tables 'approval' "$WORK/tables.lockdown"
    reload_checked

    # A non-approver may not turn it on.
    saiife_as "$AGENT_USER" "$AGENT_HOME" lockdown on --scope all --reason "agent"
    [[ "$SA_CODE" == 2 ]] || fail "$AGENT_USER: lockdown on exited $SA_CODE, want 2: $SA_ERR"
    rec="$(last_lockdown_record)"
    jq -e '.action == "on" and .decision == "deny" and .rule == "forbidden"' <<<"$rec" >/dev/null ||
        fail "$AGENT_USER: lockdown on record is not a forbidden deny: $rec"
    expect_hook 0 "" "hook after the refused lockdown on" claude "$allow"
    ok "$AGENT_USER (not an approver): lockdown on refused (exit 2, rule forbidden)"

    # Root turns it on: every hook call is denied with the reason.
    LOCKDOWN_ON=1
    as_root "$OPT_BIN" lockdown on --scope all --reason "locked-macos CI" || fail "root: lockdown on failed"
    wait_diag 30 "the hook to be locked out" hook_locked_out claude "$allow"
    ok "lockdown on (all): hook denied ($HOOK_ERR)"

    # It survives a restart.
    as_root launchctl kickstart -k "$SERVICE"
    wait_diag 30 "the daemon after the restart" daemon_ready
    wait_diag 30 "the hook to stay locked out after the restart" hook_locked_out claude "$allow"
    ok "lockdown survives launchctl kickstart -k"

    # Neither an agent user nor an approver without re-authentication may lift it.
    saiife_as "$AGENT_USER" "$AGENT_HOME" lockdown off
    [[ "$SA_CODE" == 2 ]] || fail "$AGENT_USER: lockdown off exited $SA_CODE, want 2: $SA_ERR"
    rec="$(last_lockdown_record)"
    jq -e '.action == "off" and .decision == "deny" and .rule == "forbidden"' <<<"$rec" >/dev/null ||
        fail "$AGENT_USER: lockdown off record is not a forbidden deny: $rec"
    ok "$AGENT_USER: lockdown off refused (exit 2, rule forbidden)"
    saiife_as "$APPROVER_USER" "$APPROVER_HOME" lockdown off
    [[ "$SA_CODE" == 2 ]] || fail "$APPROVER_USER: lockdown off exited $SA_CODE, want 2: $SA_ERR"
    rec="$(last_lockdown_record)"
    jq -e '.action == "off" and .decision == "deny" and .rule == "reauth_required"' <<<"$rec" >/dev/null ||
        fail "$APPROVER_USER: lockdown off record is not a reauth_required deny: $rec"
    hook_locked_out claude "$allow" || fail "lockdown was lifted by $APPROVER_USER: $HOOK_ERR"
    ok "$APPROVER_USER (approver, not admin, same_user = deny): lockdown off refused (rule reauth_required)"

    # Root lifts it.
    as_root "$OPT_BIN" lockdown off || code=$?
    [[ "$code" == 0 ]] || fail "root: lockdown off exited $code"
    LOCKDOWN_ON=0
    expect_hook 0 "" "hook after root lifted lockdown" claude "$allow"

    cleanup_config
    reload_checked
    wait_diag 30 "the daemon after restoring the config" daemon_ready
    ok "config restored"
}

phase_reinstall_uninstall() {
    phase "7a. a second system install restarts nothing"
    local before after p
    before="$(daemon_pid)"
    install_saiife 0
    after="$(daemon_pid)"
    [[ -n "$before" && "$before" == "$after" ]] || fail "the daemon restarted: pid $before -> $after"
    ok "no restart (pid $after)"

    phase "7b. system uninstall keeps the config, vault key, state and audit"
    as_root cat /etc/saiife/installed.toml >"$WORK/installed.toml"
    as_root "$BIN" system uninstall || fail "system uninstall failed"
    while IFS= read -r p; do
        case "$p" in
        /etc/saiife | /etc/saiife/config.toml | /etc/saiife/policy.d | /var/db/saiife* | /var/log/saiife*)
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
    for p in "$VAULT_KEY" "$AUDIT_KEY" "$AUDIT_DIR"; do
        as_root test -e "$p" || fail "uninstall removed $p"
    done
    if as_root test -e "$PLIST"; then
        fail "uninstall left $PLIST"
    fi
    expect_print_code nonzero "after uninstall"
    if as_root security authorizationdb read "$RIGHT" >/dev/null 2>&1; then
        fail "uninstall left the authorization right $RIGHT"
    fi
    ok "listed paths removed, kept ones kept, the plist, the job and the right $RIGHT are gone"

    phase "7c. system uninstall --purge after a reinstall"
    install_saiife 0 1
    wait_until 30 "the daemon socket after the reinstall" daemon_ready
    as_root "$BIN" system uninstall --purge || fail "system uninstall --purge failed"
    for p in /etc/saiife "$STATE_DIR" "$RUN_DIR" /var/log/saiife /opt/saiife "$PLIST"; do
        if as_root test -e "$p"; then
            fail "purge left $p: $(as_root find "$p" | head -n 20)"
        fi
    done
    expect_print_code nonzero "after purge"
    if as_root security authorizationdb read "$RIGHT" >/dev/null 2>&1; then
        fail "purge left the authorization right $RIGHT"
    fi
    as_root dscacheutil -flushcache || true
    record_absent "/Users/$DAEMON_USER" || fail "purge left the user $DAEMON_USER"
    record_absent "/Groups/$DAEMON_GROUP" || fail "purge left the group $DAEMON_GROUP"
    record_absent "/Groups/$AUDIT_GROUP" || fail "purge left the group $AUDIT_GROUP"
    ok "purged: nothing under /etc/saiife, $STATE_DIR, $RUN_DIR, /var/log/saiife, /opt/saiife; no $DAEMON_USER, no groups $DAEMON_GROUP, $AUDIT_GROUP"
}
