# shellcheck shell=bash
# The deb phases of scripts/package-linux/run.sh (CI only; see there).
# Sourcing this file only defines functions; run.sh checks the CI gate before
# it sources it, together with scripts/locked-linux/lib.sh (phase, ok, fail,
# on_exit, wait_until, daemon_ready, daemon_pid, records, start_count).
#
# Needs from run.sh: OLD and NEW (absolute .deb paths), HERE, REPO, LOGS,
# WORK (a scratch dir).

PKG_BIN=/usr/libexec/saiife/saiife
FLEET_DIR=/etc/saiife/fleet
SYS_CONFIG=/etc/saiife/config.toml
INSTALLED_TOML=/etc/saiife/installed.toml
CLAUDE_MANAGED=/etc/claude-code/managed-settings.d/50-saiife.json
CODEX_MANAGED=/etc/codex/requirements.toml
GEMINI_MANAGED=/etc/gemini-cli/settings.json
REMOVAL_LINE="saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked"
# Set by phase_refusal once it has left the package installed.
INSTALLED_BY_REFUSAL=0

# ------------------------------------------------------------ helpers

apt_run() {
    sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get "$@"
}

# `run_logged <file> <command...>`: stdout and stderr to the file, the
# command's exit code in RC (never stops the script).
RC=0
run_logged() {
    local out="$1"
    shift
    RC=0
    "$@" >"$out" 2>&1 || RC=$?
}

show_file() {
    echo "-- $1"
    cat "$1" || true
}

# `write_fleet <fleet dir mode> [config file]`: the fleet dir and the two
# fleet files, all root's. /etc/saiife itself is made 0755 first.
write_fleet() {
    local mode="$1" cfg="${2:-$HERE/fleet-config.toml}"
    printf 'agents = ["claude", "codex"]\n' >"$WORK/p18-t3-install.toml"
    sudo -n install -d -m 0755 -o root -g root /etc/saiife
    sudo -n install -d -m "$mode" -o root -g root "$FLEET_DIR"
    sudo -n install -m 0644 -o root -g root "$cfg" "$FLEET_DIR/config.toml"
    sudo -n install -m 0644 -o root -g root "$WORK/p18-t3-install.toml" "$FLEET_DIR/install.toml"
}

# The sha256 of a file that only root can read.
root_sha() {
    sudo -n sha256sum "$1" | awk '{ print $1 }'
}

# The sha256 installed.toml records for a [[files]] path.
installed_sha() {
    sudo -n awk -v p="$1" '
        /^\[\[/ { inb = 0 }
        $0 == "path = \"" p "\"" { inb = 1 }
        inb && /^sha256 = / { gsub(/^sha256 = "|"$/, ""); print; exit }
    ' "$INSTALLED_TOML"
}

# The sha256 of a file inside a .deb.
deb_member_sha() {
    dpkg-deb --fsys-tarfile "$1" | tar -xO "$2" | sha256sum | awk '{ print $1 }'
}

# What the managed agent files and their records look like: compared before
# and after an upgrade.
managed_state() {
    sudo -n sha256sum "$CLAUDE_MANAGED" "$CODEX_MANAGED" 2>&1
    sudo -n awk '/^\[\[agents\]\]/ { on = 1; next } /^\[\[/ { on = 0 } on' "$INSTALLED_TOML"
}

# The newest start/stop daemon events, oldest first, comma separated.
last_events() {
    records | jq -s -r --argjson n "$1" '[.[] | select(.kind == "daemon" and (.event == "start" or .event == "stop")) | .event] | .[-$n:] | join(",")'
}

audit_verify() {
    # shellcheck disable=SC2024 # the redirect is meant to run as the runner user: the output file is in $WORK, the runner's
    sudo -n /usr/bin/saiife audit verify >"$WORK/p18-t3-verify.out" 2>&1 || {
        show_file "$WORK/p18-t3-verify.out"
        fail "$1: saiife audit verify failed"
    }
    ok "$1: audit verify passes"
}

installed_is_current() {
    [[ "$(dpkg-query -W -f='${db:Status-Abbrev}' saiife 2>/dev/null)" == "ii " ]]
}

# On any failure: dpkg's state and logs, then lib.sh's collection (daemon
# journal, audit, /etc/saiife).
pkg_on_exit() {
    local code="$1"
    if [[ "$code" != 0 ]]; then
        echo "package-linux failed (exit $code); collecting logs in $LOGS" >&2
        dpkg -s saiife >"$LOGS/dpkg-status.txt" 2>&1 || true
        # shellcheck disable=SC2024 # the logs are written as the runner user into $LOGS for the upload; only the read needs root
        sudo -n journalctl -t saiife --no-pager -o short-precise >"$LOGS/journal-saiife-tag.txt" 2>&1 || true
        # shellcheck disable=SC2024 # the logs are written as the runner user into $LOGS for the upload; only the read needs root
        sudo -n cat /var/log/apt/term.log /var/log/dpkg.log >"$LOGS/apt-dpkg.txt" 2>&1 || true
        # shellcheck disable=SC2024 # the logs are written as the runner user into $LOGS for the upload; only the read needs root
        sudo -n sh -c 'ls -laR /etc/saiife /usr/libexec/saiife /opt/saiife' >"$LOGS/ls-package.txt" 2>&1 || true
        cp "$WORK"/*.out "$WORK"/*.err "$LOGS/" 2>/dev/null || true
        echo "-- dpkg status"
        cat "$LOGS/dpkg-status.txt" 2>/dev/null || true
    fi
    on_exit "$code"
}

# ------------------------------------------------------------ phases

phase_refusal() {
    phase "refusal: a group-writable fleet dir leaves the package half-configured"
    write_fleet 0777
    run_logged "$WORK/p18-t3-refusal.out" apt_run install -y "$OLD"
    if [[ "$RC" == 0 ]]; then
        show_file "$WORK/p18-t3-refusal.out"
        fail "apt-get install succeeded with a group-writable $FLEET_DIR"
    fi
    grep -qF "$FLEET_DIR" "$WORK/p18-t3-refusal.out" || {
        show_file "$WORK/p18-t3-refusal.out"
        fail "the refusal does not name $FLEET_DIR"
    }
    ok "install refused, naming $FLEET_DIR (exit $RC)"
    local dstat
    dstat="$(dpkg -s saiife 2>&1 || true)"
    grep -F 'Status: install ok half-configured' >/dev/null <<<"$dstat" ||
        fail "dpkg -s saiife is not half-configured: $(grep '^Status' <<<"$dstat" || true)"
    ok "the package is half-configured"
    local p
    for p in /opt/saiife "$INSTALLED_TOML" /etc/systemd/system/saiifed.service; do
        if sudo -n test -e "$p"; then fail "the refused install left $p behind"; fi
    done
    ok "the refusal left no /opt/saiife, installed.toml or unit"
    sudo -n chmod 0755 "$FLEET_DIR"
    run_logged "$WORK/p18-t3-configure.out" sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a
    if [[ "$RC" != 0 ]]; then
        show_file "$WORK/p18-t3-configure.out"
        fail "dpkg --configure -a failed after the fleet dir was fixed"
    fi
    installed_is_current || fail "the package is not installed after dpkg --configure -a"
    ok "dpkg --configure -a completed the install"
    INSTALLED_BY_REFUSAL=1
}

phase_fresh() {
    phase "fresh: install the old deb with the fleet files"
    if [[ "$INSTALLED_BY_REFUSAL" == 0 ]]; then
        write_fleet 0755
        run_logged "$WORK/p18-t3-fresh.out" apt_run install -y "$OLD"
        if [[ "$RC" != 0 ]]; then
            show_file "$WORK/p18-t3-fresh.out"
            fail "apt-get install of the old deb failed"
        fi
        ok "old deb installed"
    else
        ok "installed by the refusal phase"
    fi
    wait_until 60 "saiifed to be active with its socket" daemon_ready

    sudo -n cmp -s "$FLEET_DIR/config.toml" "$SYS_CONFIG" || fail "$SYS_CONFIG is not byte-equal to $FLEET_DIR/config.toml"
    ok "$SYS_CONFIG equals the fleet config"
    sudo -n test -f "$CLAUDE_MANAGED" || fail "no Claude managed file"
    sudo -n test -f "$CODEX_MANAGED" || fail "no Codex managed file"
    if sudo -n test -e "$GEMINI_MANAGED"; then fail "$GEMINI_MANAGED exists, but install.toml lists only claude and codex"; fi
    ok "Claude and Codex are managed, Gemini is not"

    local pkg opt rec
    pkg="$(root_sha "$PKG_BIN")"
    opt="$(root_sha /opt/saiife/bin/saiife)"
    rec="$(installed_sha /opt/saiife/bin/saiife)"
    [[ "$pkg" == "$opt" ]] || fail "$PKG_BIN ($pkg) differs from /opt/saiife/bin/saiife ($opt)"
    [[ -n "$rec" && "$rec" == "$opt" ]] || fail "installed.toml records '$rec' for /opt/saiife/bin/saiife, the file is $opt"
    ok "staging copy, /opt binary and installed.toml agree on $opt"

    local rc=0
    # shellcheck disable=SC2024 # the redirect is meant to run as the runner user: the output file is in $WORK, the runner's
    sudo -n /usr/bin/saiife doctor >"$WORK/p18-t3-doctor.out" 2>&1 || rc=$?
    if [[ "$rc" -gt 1 ]]; then
        show_file "$WORK/p18-t3-doctor.out"
        fail "saiife doctor exited $rc"
    fi
    ok "saiife doctor exited $rc"
    audit_verify "fresh"
}

phase_config_change() {
    phase "config-change: a pushed fleet config reloads the running daemon"
    installed_is_current || fail "config-change needs the package installed (run the fresh phase)"
    local pid before after cursor
    pid="$(daemon_pid)"
    [[ "$pid" != 0 ]] || fail "saiifed has no MainPID"
    before="$(sudo -n /usr/bin/saiife policy show | grep -E '^policy: ' || true)"
    [[ -n "$before" ]] || fail "policy show prints no policy hash"
    {
        echo "# changed by the package-linux CI (config-change phase)"
        sed 's/^approvers = .*/approvers = ["group:saiife-approvers", "group:saiife-ci-extra"]/' "$HERE/fleet-config.toml"
    } >"$WORK/p18-t3-fleet-new.toml"
    cmp -s "$WORK/p18-t3-fleet-new.toml" "$HERE/fleet-config.toml" && fail "the edited fleet config is unchanged"
    sudo -n install -m 0644 -o root -g root "$WORK/p18-t3-fleet-new.toml" "$FLEET_DIR/config.toml"
    cursor="$(sudo -n journalctl -u saiifed -n 1 --show-cursor -o cat --no-pager 2>/dev/null | sed -n 's/^-- cursor: //p')"
    [[ -n "$cursor" ]] || fail "cannot read a journal cursor for saiifed"
    run_logged "$WORK/p18-t3-config-change.out" sudo -n "$PKG_BIN" system install --fleet
    if [[ "$RC" -gt 1 ]]; then
        show_file "$WORK/p18-t3-config-change.out"
        fail "system install --fleet exited $RC"
    fi
    # install confirms the reload over the socket (policy.reload).
    if grep -qF "the daemon did not take the new config" "$WORK/p18-t3-config-change.out" ||
        ! grep -qF "saiife: the daemon reloaded the new config (policy " "$WORK/p18-t3-config-change.out"; then
        show_file "$WORK/p18-t3-config-change.out"
        fail "install did not confirm that the daemon took the new config"
    fi
    ok "install confirmed the reload"
    sudo -n cmp -s "$FLEET_DIR/config.toml" "$SYS_CONFIG" || fail "$SYS_CONFIG did not follow the fleet config"
    ok "$SYS_CONFIG follows the fleet config"
    [[ "$(daemon_pid)" == "$pid" ]] || fail "the daemon restarted (MainPID $pid -> $(daemon_pid)); a config change must only reload"
    ok "MainPID unchanged ($pid)"
    # shellcheck disable=SC2329 # called by wait_until (lib.sh) by name
    config_reloaded() {
        after="$(sudo -n /usr/bin/saiife policy show | grep -E '^policy: ' || true)"
        [[ -n "$after" && "$after" != "$before" ]]
    }
    wait_until 30 "policy show to print the new hash" config_reloaded
    ok "policy show: $before -> $after"
    local jrn
    jrn="$(sudo -n journalctl -u saiifed --no-pager --after-cursor "$cursor" 2>&1 || true)"
    grep -i reload >/dev/null <<<"$jrn" || {
        echo "$jrn"
        fail "the journal shows no reload of saiifed after the cursor"
    }
    ok "the journal shows the reload"
    [[ "$(daemon_pid)" == "$pid" ]] || fail "the daemon restarted during the reload"
}

phase_upgrade() {
    phase "upgrade: the new deb replaces the binary, restarts once, keeps the managed files"
    installed_is_current || fail "upgrade needs the package installed (run the fresh phase)"
    local pid starts managed new_sha
    pid="$(daemon_pid)"
    starts="$(start_count)"
    managed="$(managed_state)"
    new_sha="$(deb_member_sha "$NEW" ./usr/libexec/saiife/saiife)"
    # A root watcher: no hook file or /opt binary may be missing at any
    # moment of the upgrade (the managed files are never removed).
    local stop="$WORK/p18-t3-watch-stop" seen="$WORK/p18-t3-watch-missing" up="$WORK/p18-t3-watch-up" watcher
    rm -f "$stop" "$seen" "$up"
    cat >"$WORK/p18-t3-watch.sh" <<'WATCH'
stop=$1 seen=$2 up=$3
shift 3
: >"$seen"
: >"$up"
while [ ! -e "$stop" ]; do
    for f in "$@"; do
        [ -e "$f" ] || echo "$f" >>"$seen"
    done
    sleep 0.02
done
for f in "$@"; do
    [ -e "$f" ] || echo "$f" >>"$seen"
done
WATCH
    sudo -n sh "$WORK/p18-t3-watch.sh" "$stop" "$seen" "$up" "$CLAUDE_MANAGED" "$CODEX_MANAGED" /opt/saiife/bin/saiife &
    watcher=$!
    wait_until 10 "the upgrade watcher to start" test -e "$up"
    run_logged "$WORK/p18-t3-upgrade.out" apt_run install -y "$NEW"
    local install_rc="$RC"
    sleep 3
    : >"$stop"
    wait "$watcher" || true
    if [[ -s "$seen" ]]; then
        sort -u "$seen"
        fail "files were missing during the upgrade (listed above)"
    fi
    ok "no hook file or /opt binary was missing at any point"
    if [[ "$install_rc" != 0 ]]; then
        show_file "$WORK/p18-t3-upgrade.out"
        fail "apt-get install of the new deb failed"
    fi
    local now
    if [[ "$OLD" != "$NEW" ]]; then
        wait_until 60 "saiifed to restart on the new binary" restarted_since "$starts"
        now="$(daemon_pid)"
        [[ "$now" != "$pid" ]] || fail "MainPID is still $pid after the upgrade"
        ok "MainPID changed ($pid -> $now)"
        [[ "$(start_count)" == "$((starts + 1))" ]] || fail "the daemon started $(($(start_count) - starts)) times during the upgrade, want exactly 1"
        ok "restarted exactly once"
        [[ "$(root_sha /opt/saiife/bin/saiife)" == "$new_sha" ]] || fail "/opt/saiife/bin/saiife is not the new binary ($new_sha)"
        [[ "$(installed_sha /opt/saiife/bin/saiife)" == "$new_sha" ]] || fail "installed.toml does not record the new binary"
        ok "the /opt binary and installed.toml carry the new binary"
    fi
    [[ "$(managed_state)" == "$managed" ]] || {
        echo "-- before"
        echo "$managed"
        echo "-- after"
        managed_state
        fail "the managed agent files or their records changed during the upgrade"
    }
    ok "managed files and records unchanged"
    audit_verify "upgrade"
    if [[ "$OLD" != "$NEW" ]]; then
        [[ "$(last_events 2)" == "stop,start" ]] || fail "the newest daemon records are '$(last_events 2)', want stop,start"
        ok "the chain ends with stop then start"
    fi
}

phase_remove() {
    phase "remove: apt-get remove uninstalls locked mode loudly and keeps the evidence"
    installed_is_current || fail "remove needs the package installed (run the fresh phase)"
    local rc=0
    apt_run remove -y saiife >"$WORK/p18-t3-remove.out" 2>"$WORK/p18-t3-remove.err" || rc=$?
    if [[ "$rc" != 0 ]]; then
        show_file "$WORK/p18-t3-remove.out"
        show_file "$WORK/p18-t3-remove.err"
        fail "apt-get remove exited $rc"
    fi
    # prerm writes the warning to its stderr; apt-get relays maintainer
    # script output on its own stdout, so look in both streams.
    grep -qxF "$REMOVAL_LINE" "$WORK/p18-t3-remove.err" "$WORK/p18-t3-remove.out" || {
        show_file "$WORK/p18-t3-remove.out"
        show_file "$WORK/p18-t3-remove.err"
        fail "apt-get output lacks the removal warning"
    }
    ok "apt-get output has the removal warning"
    # shellcheck disable=SC2329 # called by wait_until (lib.sh) by name
    journal_has_line() {
        local j
        j="$(sudo -n journalctl -t saiife --no-pager 2>/dev/null || true)"
        grep -F "$REMOVAL_LINE" >/dev/null <<<"$j"
    }
    wait_until 20 "the removal warning in the journal (journalctl -t saiife)" journal_has_line
    ok "the journal has the removal warning"

    if sudo -n test -e /etc/systemd/system/saiifed.service; then fail "the unit file is still there"; fi
    if sudo -n test -e /opt/saiife/bin/saiife; then fail "/opt/saiife/bin/saiife is still there"; fi
    if sudo -n test -e "$CLAUDE_MANAGED"; then fail "the Claude managed file is still there"; fi
    if sudo -n test -e "$CODEX_MANAGED" && sudo -n grep -qi saiife "$CODEX_MANAGED"; then fail "the Codex managed file still has saiife's entry"; fi
    ok "unit, /opt binary and managed files are gone"
    sudo -n test -d /var/log/saiife/audit || fail "the audit dir is gone"
    sudo -n test -f "$SYS_CONFIG" || fail "$SYS_CONFIG is gone"
    sudo -n test -f "$FLEET_DIR/config.toml" || fail "the fleet config is gone"
    sudo -n test -f "$FLEET_DIR/install.toml" || fail "the fleet install.toml is gone"
    ok "audit, config and fleet files are kept"
    local last
    last="$(records | jq -r 'select(.kind == "daemon") | .event' | tail -n 1)"
    [[ "$last" == stop ]] || fail "the last daemon audit record is '$last', want stop"
    ok "the chain ends with a stop record"
}

phase_purge() {
    phase "purge: uninstall --purge, then purge the package"
    run_logged "$WORK/p18-t3-purge-install.out" apt_run install -y "$OLD"
    if [[ "$RC" != 0 ]]; then
        show_file "$WORK/p18-t3-purge-install.out"
        fail "reinstalling the old deb failed"
    fi
    wait_until 60 "saiifed to be active with its socket" daemon_ready
    ok "reinstalled (users reused)"
    run_logged "$WORK/p18-t3-uninstall-purge.out" sudo -n /opt/saiife/bin/saiife system uninstall --purge
    if [[ "$RC" != 0 ]]; then
        show_file "$WORK/p18-t3-uninstall-purge.out"
        fail "system uninstall --purge exited $RC"
    fi
    ok "system uninstall --purge done"
    run_logged "$WORK/p18-t3-purge.out" apt_run purge -y saiife
    if [[ "$RC" != 0 ]]; then
        show_file "$WORK/p18-t3-purge.out"
        fail "apt-get purge exited $RC"
    fi
    grep -qF 'nothing to uninstall' "$WORK/p18-t3-purge.out" || {
        show_file "$WORK/p18-t3-purge.out"
        fail "apt-get purge output lacks 'nothing to uninstall'"
    }
    ok "prerm found nothing to uninstall"
    if dpkg -s saiife >/dev/null 2>&1; then fail "dpkg still knows saiife after purge"; fi
    local left="" p
    for p in /opt/saiife "$SYS_CONFIG" "$INSTALLED_TOML" /etc/saiife/credstore /var/lib/saiife /var/log/saiife \
        /run/saiife /etc/systemd/system/saiifed.service /usr/share/polkit-1/actions/com.saiife.approve.policy \
        "$CLAUDE_MANAGED" /usr/libexec/saiife /usr/bin/saiife; do
        if sudo -n test -e "$p" || sudo -n test -L "$p"; then left="$left $p"; fi
    done
    [[ -z "$left" ]] || fail "left behind after purge:$left"
    sudo -n test -f "$FLEET_DIR/config.toml" || fail "the fleet config is gone after purge"
    sudo -n test -f "$FLEET_DIR/install.toml" || fail "the fleet install.toml is gone after purge"
    ok "no spec §5.2 path is left; the fleet files remain"
}

phase_lintian() {
    phase "lintian: the new deb has no errors"
    command -v lintian >/dev/null || apt_run install -y lintian >/dev/null
    # packaging/linux/lintian-overrides is in override format ("saiife: tag");
    # --suppress-tags-from-file wants one tag per line.
    sed -n 's/^[^#][^:]*: *\([a-z0-9-]*\).*$/\1/p' "$REPO/packaging/linux/lintian-overrides" >"$WORK/p18-t3-suppress-tags"
    [[ -s "$WORK/p18-t3-suppress-tags" ]] || fail "no tags found in packaging/linux/lintian-overrides"
    lintian --fail-on error --suppress-tags-from-file "$WORK/p18-t3-suppress-tags" "$NEW" ||
        fail "lintian reported errors for $NEW"
    ok "lintian clean of errors"
}
