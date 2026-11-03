#!/bin/sh
# A stand-in C compiler and archiver, for `cargo check` ONLY (see
# scripts/check-windows.sh). A build script such as ring's compiles C for the
# target, and `cargo check` never links the result. It compiles nothing: it
# writes an empty file for each output argument and exits 0. Anything linked
# against its output would be broken. Never put it on PATH.

touch_output() {
    mkdir -p "$(dirname -- "$1")"
    : >"$1"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
    -o)
        if [ "$#" -gt 1 ]; then
            shift
            touch_output "$1"
        fi
        ;;
    -Fo?*) touch_output "${1#-Fo}" ;;
    /Fo?*) touch_output "${1#/Fo}" ;;
    -out:?*) touch_output "${1#-out:}" ;;
    /OUT:?*) touch_output "${1#/OUT:}" ;;
    esac
    shift
done
exit 0
