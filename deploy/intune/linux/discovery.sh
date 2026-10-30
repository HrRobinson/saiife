#!/bin/sh
# Intune custom-compliance discovery script for Linux (plan 18, task 5).
# Intune runs it as root. It only reads state: it runs `saiife doctor --json`
# (output discarded, exit code kept) and prints one JSON line with the two
# settings that rules.json checks. No jq needed.
#
#   saiife_installed   true when /opt/saiife/bin/saiife is executable
#   saiife_doctor_exit doctor's exit code: 0 pass, 1 warnings, 2 failures;
#                      2 when saiife is not installed
BIN=/opt/saiife/bin/saiife

if [ -x "$BIN" ]; then
    installed=true
    "$BIN" doctor --json >/dev/null 2>&1
    doctor_exit=$?
else
    installed=false
    doctor_exit=2
fi

printf '{"saiife_installed":%s,"saiife_doctor_exit":%s}\n' "$installed" "$doctor_exit"
