#!/bin/sh

# Resolve one host adb implementation for every SnuSnuRoot host-side script.
# Prefer an explicitly supplied ADB, then the host's adb, and only then the
# bundled XBPS build.  The bundled library path is injected only when that
# bundled binary is actually selected.

snusnu_resolve_adb() {
    repo_root=$1
    bundled_adb="$repo_root/tools/xbps-root/usr/bin/adb"
    bundled_lib="$repo_root/tools/xbps-root/usr/lib"

    if [ -n "${ADB:-}" ]; then
        case "$ADB" in
            */*)
                [ -x "$ADB" ] || {
                    echo "FATAL: configured ADB is not executable: $ADB" >&2
                    return 1
                }
                ;;
            *)
                resolved_adb=$(command -v "$ADB" 2>/dev/null || true)
                [ -n "$resolved_adb" ] || {
                    echo "FATAL: configured ADB command not found: $ADB" >&2
                    return 1
                }
                ADB=$resolved_adb
                ;;
        esac
    elif resolved_adb=$(command -v adb 2>/dev/null); then
        ADB=$resolved_adb
    elif [ -x "$bundled_adb" ]; then
        ADB=$bundled_adb
    else
        echo "FATAL: adb not found; install adb or provide ADB=/path/to/adb" >&2
        return 1
    fi

    if [ "$ADB" = "$bundled_adb" ]; then
        case ":${LD_LIBRARY_PATH:-}:" in
            *":$bundled_lib:"*) ;;
            *) LD_LIBRARY_PATH="$bundled_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
        esac
        export LD_LIBRARY_PATH
    fi

    export ADB
}
