#!/bin/sh
# Removes the saiife pkg and locked mode (plan 18, decisions 6 and 7). A pkg has
# no removal hook, so this is the package removal on macOS: a Jamf policy
# script, or `sudo sh uninstall.sh`. It keeps what `system uninstall` keeps:
# the audit, the vault key, the state, the config and the users.
set -eu

BIN=/opt/saiife/bin/saiife
STAGING_DIR=/usr/local/libexec/saiife
LINK=/usr/local/bin/saiife

if [ "$(id -u)" -ne 0 ]; then
    echo "saiife: uninstall: must run as root" >&2
    exit 2
fi

msg="saiife: removing the package uninstalls locked mode: agents on this machine will no longer be locked"
echo "$msg" >&2
logger -t saiife -p auth.warning "$msg" 2>/dev/null || true

# A failed uninstall keeps the staging copy, so it can be run again.
if [ -x "$BIN" ]; then
    "$BIN" system uninstall
fi

rm -rf "$STAGING_DIR"
# Only our own link: /usr/local/bin is shared.
if [ -L "$LINK" ] && [ "$(readlink "$LINK")" = "$STAGING_DIR/saiife" ]; then
    rm -f "$LINK"
fi
# A pkg whose postinstall failed may have no receipt.
if pkgutil --pkg-info com.saiife.pkg >/dev/null 2>&1; then
    pkgutil --forget com.saiife.pkg
fi
