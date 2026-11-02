#!/bin/sh
# Jamf policy script (plan 18, Task 7): writes the fleet files that
# `saiife system install --fleet` reads. Set priority "Before", in the same
# policy as the saiife pkg. Runs as root.
#
#   Parameter 4: the base64 of config.toml (required; must say locked = true)
#   Parameter 5: a comma list of agents, for example claude,codex,gemini.
#                Empty: no install.toml (install uses the recorded agents).
CONFIG_B64=$4
AGENTS=$5

# --- The rest is the same as deploy/intune/macos/fleet-files.sh ---
set -eu

refuse() {
    echo "saiife: fleet-files: $*" >&2
    exit 2
}

[ -n "$CONFIG_B64" ] || refuse "no config: give the base64 of config.toml"
config=$(printf '%s' "$CONFIG_B64" | base64 --decode 2>/dev/null) ||
    refuse "the config is not valid base64"
[ -n "$config" ] || refuse "the config is empty"

# The names go into a TOML file: only the known ones.
agents_toml=""
set -f
old_ifs=$IFS
IFS=,
# shellcheck disable=SC2086 # split on the commas, on purpose
for a in $AGENTS; do
    case "$a" in
        claude | codex | gemini) ;;
        *) refuse "unknown agent: $a" ;;
    esac
    agents_toml="$agents_toml${agents_toml:+, }\"$a\""
done
IFS=$old_ifs
set +f

[ "$(id -u)" -eq 0 ] || refuse "must run as root"

ETC=/etc/saiife
FLEET=$ETC/fleet
PKG_BIN=/usr/local/libexec/saiife/saiife

# --- staging check: the same in postinstall and both fleet-files.sh ---
# /usr/local is not protected by SIP, and root runs the staging copy. Prints
# why it is not safe to run, or nothing: each step must be no symlink, owned
# by root, not writable by group or others, and with no ACL (a "+" after the
# mode: an ACL can grant write that the mode bits do not show).
STAGING_UID=0
staging_problem() {
    for p in /usr/local /usr/local/libexec /usr/local/libexec/saiife "$PKG_BIN"; do
        if [ -L "$p" ]; then
            echo "$p is a symbolic link"
            return 0
        fi
        # ls -n is the POSIX way to read a numeric owner.
        # shellcheck disable=SC2012
        if ! line=$(ls -ldn "$p" 2>/dev/null); then
            echo "$p is missing"
            return 0
        fi
        read -r mode _ uid _ <<EOF
$line
EOF
        if [ "$uid" != "$STAGING_UID" ]; then
            echo "$p is not owned by root"
            return 0
        fi
        case "$mode" in
            *+*)
                echo "$p has an ACL"
                return 0
                ;;
            ?????w* | ????????w*)
                echo "$p is writable by group or others"
                return 0
                ;;
        esac
    done
    [ -f "$PKG_BIN" ] || echo "$PKG_BIN is not a regular file"
}
# --- end staging check ---

# Before anything is written. No staging copy yet: the pkg's postinstall
# checks it.
have_staging=""
if [ -e "$PKG_BIN" ] || [ -L "$PKG_BIN" ]; then
    have_staging=1
    why=$(staging_problem)
    [ -z "$why" ] || refuse "the staging copy is not safe to run: $why; make it root's, not writable by group or others, with no ACL (chmod -N)"
fi

for d in "$ETC" "$FLEET"; do
    [ ! -L "$d" ] || refuse "$d is a symbolic link"
done
# /etc/saiife is install's once it exists: only made here when missing.
[ -d "$ETC" ] || mkdir -m 0755 "$ETC"
[ -d "$FLEET" ] || mkdir -m 0755 "$FLEET"
chown root:wheel "$FLEET"
chmod 0755 "$FLEET"

# put <path> <text>: root:wheel 0644, replaced in one step.
put() {
    tmp=$(mktemp "$FLEET/.put.XXXXXX")
    printf '%s\n' "$2" >"$tmp"
    chown root:wheel "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$1"
}

put "$FLEET/config.toml" "$config"
if [ -n "$agents_toml" ]; then
    put "$FLEET/install.toml" "agents = [$agents_toml]"
else
    rm -f "$FLEET/install.toml"
fi
echo "saiife: fleet files written to $FLEET"

# The pkg is already there (a changed config, or the pkg ran first): apply
# them now. Otherwise the pkg's postinstall does.
if [ -n "$have_staging" ]; then
    rc=0
    "$PKG_BIN" system install --fleet || rc=$?
    # 1 = installed, but doctor found failures (already printed).
    [ "$rc" -le 1 ] || exit "$rc"
fi
