#!/bin/sh
# Intune custom attribute for macOS (plan 18, Task 7). Runs as root. Prints
# `saiife doctor`'s exit code: 0 pass, 1 warnings, 2 failures; "not installed"
# when locked mode is not. Only reads state.
BIN=/opt/saiife/bin/saiife

if [ ! -x "$BIN" ]; then
    echo "not installed"
    exit 0
fi
rc=0
"$BIN" doctor --json >/dev/null 2>&1 || rc=$?
echo "$rc"
