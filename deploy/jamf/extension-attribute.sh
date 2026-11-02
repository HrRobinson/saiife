#!/bin/sh
# Jamf extension attribute (plan 18, Task 7). Runs as root at inventory.
# Prints pass, warn, fail or not installed, from `saiife doctor`'s exit code.
# Only reads state.
BIN=/opt/saiife/bin/saiife

if [ ! -x "$BIN" ]; then
    echo "<result>not installed</result>"
    exit 0
fi
rc=0
"$BIN" doctor --json >/dev/null 2>&1 || rc=$?
case "$rc" in
    0) result=pass ;;
    1) result=warn ;;
    *) result=fail ;;
esac
echo "<result>$result</result>"
