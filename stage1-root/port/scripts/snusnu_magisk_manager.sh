#!/bin/sh
#
# Snu-Snu Root -> Magisk Manager integration (Phase 2)
#
# Requires Phase 1 live Magisk runtime to already be running:
#   ./scripts/snusnu_magisk_bootstrap.sh start
#
# This script:
#   - builds a matching Magisk APK from the same local source revision
#   - extracts the matching stub.apk + Magisk BusyBox from that APK
#   - feeds those into the already-running Magisk daemon's post-fs-data stage
#   - installs the full Manager APK
#   - runs service + boot-complete stages
#   - launches the Manager
#   - can trigger a real adb-shell su authorization request
#
# Usage:
#   scripts/snusnu_magisk_manager.sh setup
#   scripts/snusnu_magisk_manager.sh status
#   scripts/snusnu_magisk_manager.sh request
#   scripts/snusnu_magisk_manager.sh launch
#   scripts/snusnu_magisk_manager.sh uninstall
#

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)

ADB=${ADB:-"$REPO_DIR/tools/adb-portable.sh"}
MAGISK_DIR="$REPO_DIR/magisk"
EXPECTED_REV="8c4341e9288360010495a2bc3b46fd2e3f505f9f"

APK="$MAGISK_DIR/out/app-release.apk"
MAGISK_HOST="$MAGISK_DIR/native/out/arm64-v8a/magisk"
POLICY_HOST="$MAGISK_DIR/native/out/arm64-v8a/magiskpolicy"

DEVICE_STAGE="/data/local/tmp/snusnu-magisk-manager-stage"
PKG_STATE="$REPO_DIR/.snusnu-magisk-manager-package"

ACTION=${1:-setup}

TMPROOT=$(mktemp -d "${TMPDIR:-/tmp}/snusnu-magisk-manager.XXXXXX")
trap 'rm -rf "$TMPROOT"' EXIT HUP INT TERM

log() {
    printf '%s\n' "[snusnu-magisk-manager] $*"
}

die() {
    printf '%s\n' "[snusnu-magisk-manager] ERROR: $*" >&2
    exit 1
}

[ -x "$ADB" ] || die "adb not found/executable: $ADB"

adb_state() {
    "$ADB" get-state 2>/dev/null || true
}

require_adb() {
    [ "$(adb_state)" = "device" ] || die "ADB device is not connected/authorized"
}

root_cmd() {
    # Longer wait than Phase 1 because --post-fs-data can legally take time.
    {
        printf '%s\n' "$1"
        printf '%s\n' 'exit'
    } | "$ADB" shell 'toybox nc -w 60 127.0.0.1 4325'
}

root_cmd_short() {
    {
        printf '%s\n' "$1"
        printf '%s\n' 'exit'
    } | "$ADB" shell 'toybox nc -w 8 127.0.0.1 4325'
}

require_root_listener() {
    out=$(root_cmd_short 'id; echo __SNU_ROOT_OK__') || die "root listener did not respond"
    printf '%s\n' "$out" | grep -q 'uid=0' || die "root listener is not uid 0"
    printf '%s\n' "$out" | grep -q '__SNU_ROOT_OK__' || die "root listener response incomplete"
}

require_phase1() {
    require_adb
    require_root_listener

    out=$(root_cmd_short '
        echo "path=$(/sbin/magisk --path 2>&1)"
        echo "version=$(/sbin/magisk -v 2>&1)"
        test -e /sbin/.magisk/device/socket && echo socket=yes || echo socket=no
        ps | grep "[m]agiskd" || true
    ') || die "cannot inspect Phase 1"

    printf '%s\n' "$out"

    printf '%s\n' "$out" | grep -q '^path=/sbin$' \
        || die "Phase 1 is not active: magisk --path is not /sbin"
    printf '%s\n' "$out" | grep -q '^socket=yes$' \
        || die "Phase 1 is not active: magiskd socket missing"
    printf '%s\n' "$out" | grep -q 'magiskd' \
        || die "Phase 1 is not active: magiskd process missing"
}

check_revision() {
    if [ -d "$MAGISK_DIR/.git" ]; then
        rev=$(git -C "$MAGISK_DIR" rev-parse HEAD)
        [ "$rev" = "$EXPECTED_REV" ] \
            || die "Magisk revision changed: $rev (expected $EXPECTED_REV)"
    elif [ -s "$MAGISK_DIR/.snusnu-revision" ]; then
        rev=$(cat "$MAGISK_DIR/.snusnu-revision")
        if [ "$rev" = "$EXPECTED_REV" ]; then
            log "using packaged prebuilt revision $rev (no git checkout; builder unavailable)"
        else
            die "packaged Magisk revision mismatch: $rev (expected $EXPECTED_REV)"
        fi
    else
        log "WARNING: neither git checkout nor revision marker present; skipping revision verification"
    fi
}

ensure_app_native() {
    cfg="$1"
    native_dir="$MAGISK_DIR/native/out/arm64-v8a"

    missing=0
    for f in magisk magiskpolicy magiskboot magiskinit libinit-ld.so; do
        if [ ! -s "$native_dir/$f" ]; then
            log "missing APK native input: $native_dir/$f"
            missing=1
        fi
    done

    if [ "$missing" = "1" ]; then
        log "building full ARM64 Magisk native set required by Manager packaging"
        (
            cd "$MAGISK_DIR"
            python3 build.py -r -c "$cfg" native
        ) || die "full Magisk native build failed"
    else
        log "full ARM64 native packaging set already present"
    fi

    for f in magisk magiskpolicy magiskboot magiskinit libinit-ld.so; do
        [ -s "$native_dir/$f" ] \
            || die "native build completed but required file is missing: $native_dir/$f"
    done
}

build_apk() {
    check_revision

    cfg="$TMPROOT/magisk-app.prop"
    cat >"$cfg" <<EOF
abiList=arm64-v8a
outdir=out
EOF

    # The app's syncReleaseJniLibs task requires the complete native set,
    # not merely magisk + magiskpolicy used by Phase 1.
    ensure_app_native "$cfg"

    if [ -s "$APK" ]; then
        log "using existing matching APK: $APK"
        return 0
    fi

    log "building matching ARM64 Magisk Manager APK from local revision"

    [ -d "$MAGISK_DIR/.git" ] \
        || die "APK missing and no Magisk source (git) in this package: rebuild is impossible; ship magisk/out/app-release.apk"

    (
        cd "$MAGISK_DIR"
        python3 build.py -r -c "$cfg" app
    ) || die "Magisk app build failed"

    [ -s "$APK" ] || die "build completed but APK was not produced at $APK"
    log "built $APK"
}

find_aapt() {
    if command -v aapt >/dev/null 2>&1; then
        command -v aapt
        return 0
    fi

    for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Android/Sdk"; do
        [ -n "$sdk" ] || continue
        [ -d "$sdk/build-tools" ] || continue
        candidate=$(find "$sdk/build-tools" -type f -name aapt -perm -u+x 2>/dev/null |
            sort -V | tail -n 1)
        if [ -n "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

resolve_package() {
    # This exact Magisk revision defines APP_PACKAGE_NAME as
    # com.topjohnwu.magisk. Verify the built APK manifest when aapt exists.
    pkg="com.topjohnwu.magisk"

    if aapt_bin=$(find_aapt 2>/dev/null); then
        manifest_pkg=$("$aapt_bin" dump badging "$APK" 2>/dev/null |
            sed -n "s/^package: name='\([^']*\)'.*/\1/p" |
            head -n 1)
        if [ -n "$manifest_pkg" ]; then
            pkg="$manifest_pkg"
        fi
    fi

    [ -n "$pkg" ] || die "could not resolve Manager package name"
    printf '%s\n' "$pkg"
}

extract_support_files() {
    command -v unzip >/dev/null 2>&1 || die "host unzip command is required"

    stub="$TMPROOT/stub.apk"
    busybox="$TMPROOT/busybox"

    unzip -p "$APK" 'assets/stub.apk' >"$stub" \
        || die "could not extract assets/stub.apk from Manager APK"
    unzip -p "$APK" 'lib/arm64-v8a/libbusybox.so' >"$busybox" \
        || die "could not extract ARM64 BusyBox from Manager APK"

    [ -s "$stub" ] || die "extracted stub.apk is empty"
    [ -s "$busybox" ] || die "extracted BusyBox is empty"
    chmod 0755 "$busybox"

    printf '%s\n' "$stub|$busybox"
}

stage_support() {
    pair=$(extract_support_files)
    stub=${pair%%|*}
    busybox=${pair#*|}
    stub_digest=$(sha256sum "$stub" | awk '{print $1}')

    log "verifying bootstrap trust binding and staging matching BusyBox"
    "$ADB" shell "rm -rf '$DEVICE_STAGE'; mkdir -p '$DEVICE_STAGE'" >/dev/null
    "$ADB" push "$busybox" "$DEVICE_STAGE/busybox" >/dev/null

    # Also retain matching copies of core binaries in /data/adb/magisk.
    # post-fs-data's setup_magisk_env explicitly requires BusyBox there.
    root_cmd "
        set -e
        mkdir -p /data/adb/magisk
        chmod 0700 /data/adb 2>/dev/null || true
        chmod 0755 /data/adb/magisk

        cp '$DEVICE_STAGE/busybox' /data/adb/magisk/busybox
        chmod 0755 /data/adb/magisk/busybox

        cp /sbin/magisk /data/adb/magisk/magisk
        cp /sbin/magiskpolicy /data/adb/magisk/magiskpolicy
        chmod 0755 /data/adb/magisk/magisk /data/adb/magisk/magiskpolicy

        test \"\$(cat /data/adb/magisk/.snusnu-trusted-stub.sha256 2>/dev/null)\" = '$stub_digest' \
            || { echo 'trusted_stub_marker=mismatch_or_missing'; exit 42; }
        echo 'trusted_stub_marker=$stub_digest'
        echo 'support_stage=ok'
        ls -l /data/adb/magisk/busybox
    " | grep -q 'support_stage=ok' || die "failed to stage Magisk support files"
}

install_manager() {
    pkg=$1

    log "installing Manager package $pkg"
    install_out=$("$ADB" install -r -g "$APK" 2>&1) || {
        printf '%s\n' "$install_out"
        die "adb install failed"
    }
    printf '%s\n' "$install_out"

    "$ADB" shell "pm path '$pkg'" 2>/dev/null | grep -q '^package:' \
        || die "APK install returned success but package $pkg is not installed"

    printf '%s\n' "$pkg" >"$PKG_STATE"
}

run_remaining_boot_stages() {
    pkg=$1

    log "running Magisk service stage"
    root_cmd '/sbin/magisk --service; echo "service_rc=$?"'

    log "running Magisk boot-complete stage (this performs Manager discovery)"
    root_cmd '/sbin/magisk --boot-complete; echo "boot_complete_rc=$?"'

    # Release Magisk may remove an APK that fails its Manager signature check.
    "$ADB" shell "pm path '$pkg'" 2>/dev/null | grep -q '^package:' \
        || die "Manager disappeared after boot-complete; signature/trusted-cert detection failed"

    dver=$(root_cmd_short '/sbin/magisk -v')
    [ -n "$dver" ] || die "magiskd stopped responding after boot stages"
    log "magiskd still responds: $dver"

    log "fixing su policy for uid=2000 (shell)"
    root_cmd_short '/sbin/magisk --sqlite "UPDATE policies SET policy=2 WHERE uid=2000;"'
}

package_uid() {
    pkg=$1
    "$ADB" shell "dumpsys package '$pkg'" 2>/dev/null |
        tr -d '\r' |
        sed -n 's/.*userId=\([0-9][0-9]*\).*/\1/p' |
        head -n 1
}

package_versions() {
    pkg=$1
    "$ADB" shell "dumpsys package '$pkg'" 2>/dev/null |
        tr -d '\r' |
        grep -E 'versionCode=|versionName=' |
        head -n 4 || true
}

launch_manager() {
    pkg=$1

    log "launching $pkg"
    resolved=$("$ADB" shell "cmd package resolve-activity --brief '$pkg'" 2>/dev/null |
        tr -d '\r' |
        tail -n 1 || true)

    case "$resolved" in
        */*)
            "$ADB" shell "am start -n '$resolved'" >/dev/null 2>&1 \
                || die "could not launch resolved Manager activity: $resolved"
            ;;
        *)
            "$ADB" shell "monkey -p '$pkg' -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1 \
                || die "could not launch Manager with package launcher"
            ;;
    esac

    log "Manager launch requested"
}

show_policies() {
    log "current MagiskSU policy rows"
    root_cmd_short "/sbin/magisk --sqlite \"SELECT uid,policy,until,logging,notification FROM policies\" 2>&1 || true"
}

status() {
    require_phase1

    pkg=""
    if [ -s "$PKG_STATE" ]; then
        pkg=$(cat "$PKG_STATE")
    elif [ -s "$APK" ]; then
        pkg=$(resolve_package)
    else
        pkg="com.topjohnwu.magisk"
    fi

    echo "package=$pkg"

    if "$ADB" shell "pm path '$pkg'" 2>/dev/null | grep -q '^package:'; then
        echo "manager_installed=yes"
        uid=$(package_uid "$pkg")
        echo "manager_uid=${uid:-unknown}"
        package_versions "$pkg"
    else
        echo "manager_installed=no"
    fi

    root_cmd_short '
        echo "magisk_path=$(/sbin/magisk --path 2>&1)"
        echo "daemon_version=$(/sbin/magisk -v 2>&1)"
        echo "selinux=$(getenforce)"
        test -e /sbin/.magisk/device/socket && echo "daemon_socket=yes" || echo "daemon_socket=no"
        test -x /data/adb/magisk/busybox && echo "persistent_busybox=yes" || echo "persistent_busybox=no"
        test -x /sbin/.magisk/busybox/busybox && echo "runtime_busybox=yes" || echo "runtime_busybox=no"
    '

    show_policies
}

setup() {
    require_phase1
    check_revision
    build_apk

    pkg=$(resolve_package)
    log "Manager APK package: $pkg"

    stage_support
    require_root_listener

    install_manager "$pkg"
    uid=$(package_uid "$pkg")
    [ -n "$uid" ] || die "could not determine installed Manager UID"
    log "Manager UID: $uid"

    run_remaining_boot_stages "$pkg"
    require_root_listener

    launch_manager "$pkg"

    log "Phase 2 setup complete"
    echo
    echo "Next:"
    echo "  $0 request"
    echo
    echo "When the authorization prompt appears on the tablet, choose Allow or Deny."
    status
}

request_su() {
    require_phase1

    if [ -s "$PKG_STATE" ]; then
        pkg=$(cat "$PKG_STATE")
    elif [ -s "$APK" ]; then
        pkg=$(resolve_package)
    else
        die "Manager package state/APK not found; run '$0 setup' first"
    fi

    "$ADB" shell "pm path '$pkg'" 2>/dev/null | grep -q '^package:' \
        || die "Manager $pkg is not installed"

    launch_manager "$pkg"

    echo
    log "triggering a real MagiskSU request from adb shell (uid 2000)"
    log "watch the tablet for the Magisk authorization dialog"
    log "this command will wait up to 80 seconds for your GUI decision"
    echo

    set +e
    if command -v timeout >/dev/null 2>&1; then
        out=$(timeout 80 "$ADB" shell '/sbin/su -c id' 2>&1)
        rc=$?
    else
        out=$("$ADB" shell '/sbin/su -c id' 2>&1)
        rc=$?
    fi
    set -e

    printf '%s\n' "$out"
    echo "su_request_rc=$rc"

    case "$rc" in
        0)
            printf '%s\n' "$out" | grep -q 'uid=0' \
                && log "SU ALLOW path proven: adb-shell request received uid 0" \
                || log "su exited 0 but output did not contain uid=0"
            ;;
        124)
            log "request timed out; Manager authorization handshake did not complete"
            ;;
        *)
            log "su request was denied or failed (rc=$rc)"
            ;;
    esac

    show_policies
}

uninstall_manager() {
    require_adb

    if [ -s "$PKG_STATE" ]; then
        pkg=$(cat "$PKG_STATE")
    elif [ -s "$APK" ]; then
        pkg=$(resolve_package)
    else
        pkg="com.topjohnwu.magisk"
    fi

    log "uninstalling Manager package $pkg"
    "$ADB" uninstall "$pkg" || true
    rm -f "$PKG_STATE"
    log "Manager APK removed; Phase 1 Magisk runtime and /data/adb were left intact"
}

case "$ACTION" in
    setup|start)
        setup
        ;;
    status)
        status
        ;;
    request)
        request_su
        ;;
    launch)
        require_phase1
        if [ -s "$PKG_STATE" ]; then
            pkg=$(cat "$PKG_STATE")
        elif [ -s "$APK" ]; then
            pkg=$(resolve_package)
        else
            die "no Manager package known; run setup first"
        fi
        launch_manager "$pkg"
        ;;
    uninstall)
        uninstall_manager
        ;;
    *)
        die "usage: $0 {setup|status|request|launch|uninstall}"
        ;;
esac
