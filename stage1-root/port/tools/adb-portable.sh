#!/bin/sh
# Windows/Git-Bash adb resolver for the PS7319 port.
# The upstream bundled XBPS adb is Linux-only; on Windows we use the
# platform-tools adb ($ADB, $HOME/adb/adb.exe, or PATH).
#
# MSYS_NO_PATHCONV: Git Bash rewrites leading-slash arguments that look like
# paths (adb push LOCAL /data/local/tmp/x -> C:/Program Files/Git/data/...).
# Disabling conversion is safe here: local paths we pass are relative, and
# device paths must stay verbatim.
export MSYS_NO_PATHCONV=1

if [ -n "${ADB:-}" ]; then
    exec "$ADB" "$@"
fi

for cand in \
    "$HOME/adb/adb.exe" \
    /c/platform-tools/adb.exe \
    /c/Android/platform-tools/adb.exe; do
    if [ -x "$cand" ]; then
        exec "$cand" "$@"
    fi
done

if command -v adb >/dev/null 2>&1; then
    exec adb "$@"
fi

echo "FATAL: adb not found. Set ADB=/path/to/adb.exe" >&2
exit 1
