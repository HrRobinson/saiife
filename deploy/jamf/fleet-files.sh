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
if [ -x "$PKG_BIN" ]; then
    rc=0
    "$PKG_BIN" system install --fleet || rc=$?
    # 1 = installed, but doctor found failures (already printed).
    [ "$rc" -le 1 ] || exit "$rc"
fi
