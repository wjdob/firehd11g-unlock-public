#!/bin/sh
#
# Snu-Snu Root -> live Magisk userspace bootstrap
#
# Host-side orchestrator. Uses the existing localhost:4325 uid-0 listener
# to install a reversible Magisk runtime on /sbin without modifying /boot
# or the underlying /system/root filesystem.
#
# Usage:
#   scripts/snusnu_magisk_bootstrap.sh start
#   scripts/snusnu_magisk_bootstrap.sh status
#   scripts/snusnu_magisk_bootstrap.sh stop
#
# Optional:
#   ADB=/path/to/adb scripts/snusnu_magisk_bootstrap.sh status
#

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)

ADB=${ADB:-"$REPO_DIR/tools/adb-portable.sh"}
MAGISK_HOST="$REPO_DIR/prebuilt/device/arm64-v8a/magisk"
POLICY_HOST="$REPO_DIR/prebuilt/device/arm64-v8a/magiskpolicy"

DEVICE_HELPER="/data/local/tmp/snusnu_magisk_device.sh"
DEVICE_STAGE="/data/local/tmp/snusnu-magisk-stage"
HOST_HELPER=$(mktemp "${TMPDIR:-/tmp}/snusnu-magisk-device.XXXXXX")
HOST_STUB=$(mktemp "${TMPDIR:-/tmp}/snusnu-magisk-stub.XXXXXX")
trap 'rm -f "$HOST_HELPER" "$HOST_STUB"' EXIT HUP INT TERM

ACTION=${1:-start}

log() {
    printf '%s\n' "[snusnu-magisk] $*"
}

die() {
    printf '%s\n' "[snusnu-magisk] ERROR: $*" >&2
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
    # Commands are fed to the already-running localhost root listener.
    # Always terminate that child shell explicitly.
    {
        printf '%s\n' "$1"
        printf '%s\n' 'exit'
    } | "$ADB" shell 'toybox nc -w 60 127.0.0.1 4325'
}

check_root_listener() {
    out=$(root_cmd 'id; echo "__SNU_ROOT_OK__"') || return 1
    printf '%s\n' "$out" | grep -q 'uid=0' || return 1
    printf '%s\n' "$out" | grep -q '__SNU_ROOT_OK__' || return 1
}

require_root_listener() {
    check_root_listener || die "existing Snu-Snu root listener at 127.0.0.1:4325 is not healthy"
}

run_device_action() {
    action=$1

    out=$(root_cmd "sh '$DEVICE_HELPER' '$action'; rc=\$?; echo __SNU_DEVICE_RC=\$rc") || {
        printf '%s\n' "$out"
        return 1
    }

    printf '%s\n' "$out" | grep -v '^__SNU_DEVICE_RC='
    rc=$(printf '%s\n' "$out" |
        sed -n 's/^__SNU_DEVICE_RC=\([0-9][0-9]*\)$/\1/p' |
        tail -1)

    [ "$rc" = "0" ]
}

cat >"$HOST_HELPER" <<'DEVICE_SCRIPT'
#!/system/bin/sh

# Device-side helper. Must be executed from the existing uid-0 listener.

STATE="/data/local/tmp/snusnu-magisk-state"
ORIG="/data/local/tmp/snusnu-sbin-original"
STAGE="/data/local/tmp/snusnu-magisk-stage"
ENTRY_MOUNTS="$STATE/entry_mounts"
LOG="$STATE/bootstrap.log"

MAGISKTMP="/sbin"
WORKER="/sbin/.magisk/worker"

ACTION="${1:-status}"
IN_START=0

log() {
    mkdir -p "$STATE" 2>/dev/null
    msg="[snusnu-magisk-device] $*"
    echo "$msg"
    echo "$msg" >>"$LOG" 2>/dev/null
}

fail() {
    log "ERROR: $*"
    if [ "$IN_START" = "1" ]; then
        log "START failed; rolling back runtime mounts"
        rollback_runtime
    fi
    exit 1
}

mounted_at() {
    # $1 = exact mountpoint; paths used by this script contain no spaces.
    grep -q " $1 " /proc/mounts 2>/dev/null
}

sbin_is_magisk_tmpfs() {
    grep -q '^magisk /sbin tmpfs ' /proc/mounts 2>/dev/null
}

root_uid_ok() {
    [ "$(id -u 2>/dev/null)" = "0" ]
}

selinux_state() {
    getenforce 2>/dev/null || echo unknown
}

daemon_pid() {
    ps 2>/dev/null | grep '[m]agiskd' | awk 'NR==1 {print $2}'
}

verify_original_view() {
    [ -d "$ORIG" ] || return 1

    # At least the known baseline files must still be visible.
    [ -e "$ORIG/charger" ] || return 1
    [ -e "$ORIG/crashreport" ] || return 1
    [ -L "$ORIG/ueventd" ] || return 1
    [ -L "$ORIG/watchdogd" ] || return 1
    return 0
}

record_bind() {
    echo "$1" >>"$ENTRY_MOUNTS"
}

restore_original_entries() {
    : >"$ENTRY_MOUNTS"
    restored=0

    for src in "$ORIG"/* "$ORIG"/.[!.]* "$ORIG"/..?*; do
        if [ ! -e "$src" ] && [ ! -L "$src" ]; then
            continue
        fi

        name=${src##*/}
        dst="/sbin/$name"
        restored=$((restored + 1))

        if [ -L "$src" ]; then
            target=$(readlink "$src") || {
                log "restore failed: readlink $src"
                return 31
            }

            rm -f "$dst" 2>/dev/null
            ln -s "$target" "$dst" || {
                log "restore failed: symlink $dst -> $target"
                return 32
            }

            log "restored symlink: $dst -> $target"

        elif [ -f "$src" ]; then
            : >"$dst" || {
                log "restore failed: cannot create target $dst"
                return 33
            }

            mount --bind "$src" "$dst" || {
                log "restore failed: bind $src -> $dst"
                return 34
            }

            record_bind "$dst"
            log "restored bind file: $dst"

        elif [ -d "$src" ]; then
            mkdir -p "$dst" || {
                log "restore failed: cannot create directory $dst"
                return 35
            }

            mount --bind "$src" "$dst" || {
                log "restore failed: bind directory $src -> $dst"
                return 36
            }

            record_bind "$dst"
            log "restored bind directory: $dst"

        else
            log "restore failed: unsupported entry type: $src"
            return 37
        fi
    done

    [ "$restored" -gt 0 ] || {
        log "restore failed: preserved /sbin view is empty"
        return 38
    }

    [ -e /sbin/charger ] || {
        log "restore verification failed: charger missing"
        return 41
    }

    [ -e /sbin/crashreport ] || {
        log "restore verification failed: crashreport missing"
        return 42
    }

    [ -L /sbin/ueventd ] || {
        log "restore verification failed: ueventd missing/not symlink"
        return 43
    }

    [ -L /sbin/watchdogd ] || {
        log "restore verification failed: watchdogd missing/not symlink"
        return 44
    }

    [ "$(readlink /sbin/ueventd)" = "../init" ] || {
        log "restore verification failed: ueventd target changed"
        return 45
    }

    [ "$(readlink /sbin/watchdogd)" = "../init" ] || {
        log "restore verification failed: watchdogd target changed"
        return 46
    }

    log "restored $restored original /sbin entries"
    return 0
}

unmount_entry_binds() {
    [ -f "$ENTRY_MOUNTS" ] || return 0

    # All recorded mounts are top-level siblings, so ordering is not
    # semantically important. Retry once after the first pass.
    while IFS= read -r mnt; do
        [ -n "$mnt" ] || continue
        if mounted_at "$mnt"; then
            umount "$mnt" 2>/dev/null || true
        fi
    done <"$ENTRY_MOUNTS"

    while IFS= read -r mnt; do
        [ -n "$mnt" ] || continue
        if mounted_at "$mnt"; then
            umount "$mnt" 2>/dev/null || return 1
        fi
    done <"$ENTRY_MOUNTS"

    return 0
}

rollback_runtime() {
    IN_START=0

    if [ -x /sbin/magisk ] && sbin_is_magisk_tmpfs; then
        /sbin/magisk --stop >/dev/null 2>&1 || true
        sleep 1
    fi

    if mounted_at "$WORKER"; then
        umount "$WORKER" 2>/dev/null || true
    fi

    unmount_entry_binds || log "WARNING: one or more preserved /sbin entry mounts remain busy"

    if sbin_is_magisk_tmpfs; then
        umount /sbin 2>/dev/null || {
            log "ERROR: could not unmount Magisk tmpfs from /sbin"
            return 1
        }
    fi

    if mounted_at "$ORIG"; then
        umount "$ORIG" 2>/dev/null || {
            log "ERROR: could not unmount original /sbin preservation bind"
            return 1
        }
    fi

    rm -rf "$ORIG" "$STAGE" 2>/dev/null
    rm -f "$ENTRY_MOUNTS" 2>/dev/null

    # Underlying rootfs /sbin should now be visible again.
    if [ ! -e /sbin/charger ] || [ ! -e /sbin/crashreport ]; then
        log "ERROR: original /sbin did not reappear correctly"
        return 1
    fi

    log "runtime rollback complete; persistent /data/adb state retained"
    return 0
}

status() {
    echo "uid=$(id -u 2>/dev/null)"
    echo "context=$(cat /proc/self/attr/current 2>/dev/null)"
    echo "selinux=$(selinux_state)"

    echo "--- /sbin mount ---"
    grep ' /sbin ' /proc/mounts 2>/dev/null || echo "rootfs-backed (no separate /sbin mount)"

    echo "--- preservation ---"
    if mounted_at "$ORIG"; then
        echo "original_sbin_bind=mounted"
    else
        echo "original_sbin_bind=absent"
    fi

    echo "--- Magisk runtime ---"
    if [ -d /sbin/.magisk ]; then
        echo "magisk_runtime=present"
    else
        echo "magisk_runtime=absent"
    fi

    if [ -x /sbin/magisk ]; then
        printf 'local_version='
        /sbin/magisk -c 2>&1 || true
        printf 'magisk_path='
        /sbin/magisk --path 2>&1 || true
        printf 'daemon_version='
        /sbin/magisk -v 2>&1 || true
        printf 'daemon_version_code='
        /sbin/magisk -V 2>&1 || true
    else
        echo "local_version=unavailable"
        echo "magisk_path=unavailable"
        echo "daemon_version=unavailable"
    fi

    pid=$(daemon_pid)
    if [ -n "$pid" ]; then
        echo "magiskd_pid=$pid"
        printf 'magiskd_context='
        cat "/proc/$pid/attr/current" 2>/dev/null || echo unknown
    else
        echo "magiskd_pid=none"
    fi

    if [ -S /sbin/.magisk/device/socket ]; then
        ls -l /sbin/.magisk/device/socket 2>/dev/null
    elif [ -e /sbin/.magisk/device/socket ]; then
        ls -l /sbin/.magisk/device/socket 2>/dev/null
    else
        echo "daemon_socket=absent"
    fi

    if mounted_at "$WORKER"; then
        echo "worker_mount=present"
        grep " $WORKER " /proc/mounts 2>/dev/null
    else
        echo "worker_mount=absent"
    fi

    echo "--- /data/adb ---"
    ls -ld /data/adb /data/adb/magisk /data/adb/modules \
        /data/adb/post-fs-data.d /data/adb/service.d 2>/dev/null || true
}

start() {
    IN_START=1

    root_uid_ok || fail "helper is not running as uid 0"

    state=$(selinux_state)
    [ "$state" = "Permissive" ] || fail "SELinux is $state, expected Permissive"

    [ -d /sbin ] || fail "/sbin does not exist"
    [ ! -e /debug_ramdisk ] || log "NOTE: /debug_ramdisk exists; this script is intentionally using /sbin"

    [ -x "$STAGE/magisk" ] || fail "staged magisk binary missing"
    [ -x "$STAGE/magiskpolicy" ] || fail "staged magiskpolicy binary missing"

    if sbin_is_magisk_tmpfs; then
        if [ -x /sbin/magisk ] && [ -d /sbin/.magisk ]; then
            path=$(/sbin/magisk --path 2>/dev/null || true)
            if [ "$path" = "/sbin" ]; then
                log "Magisk /sbin runtime already present; treating start as idempotent"
                /sbin/magisk --daemon >/dev/null 2>&1 || true
                IN_START=0
                status
                return 0
            fi
        fi
        fail "/sbin is already tmpfs but does not look like a healthy Snu-Snu Magisk runtime"
    fi

    log "preflight: staged binary execution"
    ver=$("$STAGE/magisk" -c 2>&1) || fail "staged magisk binary cannot execute: $ver"
    log "magisk local version: $ver"

    mkdir -p "$STATE" "$ORIG" || fail "cannot create state/preservation directories"
    : >"$LOG"

    log "preserving original /sbin via bind mount"
    if mounted_at "$ORIG"; then
        umount "$ORIG" 2>/dev/null || fail "stale preservation mount cannot be removed"
    fi
    mount --bind /sbin "$ORIG" || fail "cannot bind-preserve original /sbin"

    # Root is shared:1 on this device. Prevent the later /sbin tmpfs mount
    # from propagating into our preserved view.
    mount -t none -o private none "$ORIG" || fail "cannot make preserved /sbin mount private"

    verify_original_view || fail "original /sbin preservation verification failed"

    log "mounting Magisk tmpfs on /sbin"
    mount -t tmpfs -o mode=0755 magisk /sbin || fail "cannot mount tmpfs on /sbin"
    chcon u:object_r:rootfs:s0 /sbin 2>/dev/null || log "WARNING: could not chcon /sbin to rootfs context"

    log "re-exposing original /sbin entries"
    restore_original_entries || fail "failed to preserve all original /sbin entries"

    log "installing Magisk runtime binaries"
    cp "$STAGE/magisk" /sbin/magisk || fail "cannot copy magisk to /sbin"
    cp "$STAGE/magiskpolicy" /sbin/magiskpolicy || fail "cannot copy magiskpolicy to /sbin"
    chmod 0755 /sbin/magisk /sbin/magiskpolicy || fail "cannot chmod Magisk runtime binaries"

    ln -s ./magisk /sbin/su || fail "cannot create /sbin/su applet"
    ln -s ./magisk /sbin/resetprop || fail "cannot create /sbin/resetprop applet"

    log "creating Magisk runtime layout"
    mkdir -p /sbin/.magisk/device /sbin/.magisk/worker || fail "cannot create .magisk runtime directories"

    # Root listener runs with umask 077. Magisk's socket itself is 0666,
    # but ordinary app/shell clients must be able to traverse these dirs.
    chmod 0755 /sbin/.magisk /sbin/.magisk/device \
        || fail "cannot make Magisk daemon socket path traversable"

    : >/sbin/.magisk/config || fail "cannot create runtime config"
    : >/sbin/.magisk/live || fail "cannot create live marker"

    log "creating persistent Magisk state directories"
    if [ ! -d /data/adb ]; then
        mkdir -p /data/adb || fail "cannot create /data/adb"
        chmod 0700 /data/adb 2>/dev/null || true
    fi
    mkdir -p /data/adb/magisk /data/adb/modules /data/adb/post-fs-data.d /data/adb/service.d \
        || fail "cannot create /data/adb Magisk directories"

    log "creating private Magisk worker tmpfs"
    mount -t tmpfs -o mode=0755 magisk /sbin/.magisk/worker \
        || fail "cannot mount Magisk worker tmpfs"
    mount -t none -o private none /sbin/.magisk/worker \
        || fail "cannot make Magisk worker mount private"

    log "verifying MAGISKTMP discovery"
    path=$(/sbin/magisk --path 2>&1) || fail "magisk --path failed: $path"
    [ "$path" = "/sbin" ] || fail "magisk --path returned '$path', expected /sbin"

    /sbin/magisk -c >/dev/null 2>&1 || fail "runtime magisk binary no longer executes"
    applets=$(/sbin/magisk --list 2>&1) || fail "magisk --list failed"
    echo "$applets" | grep -q '^su$' || fail "Magisk su applet is unavailable"
    echo "$applets" | grep -q '^resetprop$' || fail "Magisk resetprop applet is unavailable"

    log "applying Magisk live SELinux policy"

    if [ -f /vendor/etc/selinux/precompiled_sepolicy ]; then
        policy_out=$(/sbin/magiskpolicy --load /vendor/etc/selinux/precompiled_sepolicy --live --magisk 2>&1)
        policy_rc=$?
        policy_source="/vendor/etc/selinux/precompiled_sepolicy"
    elif [ -f /sepolicy ]; then
        policy_out=$(/sbin/magiskpolicy --load /sepolicy --live --magisk 2>&1)
        policy_rc=$?
        policy_source="/sepolicy"
    else
        policy_out=$(/sbin/magiskpolicy --live --magisk 2>&1)
        policy_rc=$?
        policy_source="live kernel policy"
    fi

    [ "$policy_rc" = "0" ] ||
        fail "magiskpolicy failed rc=$policy_rc source=$policy_source: $policy_out"

    log "Magisk policy applied from: $policy_source"
    [ "$(selinux_state)" = "Permissive" ] || fail "SELinux unexpectedly left Permissive mode"

    log "starting magiskd"
    daemon_out=$(/sbin/magisk --daemon 2>&1)
    daemon_rc=$?
    [ "$daemon_rc" = "0" ] || fail "magisk --daemon failed rc=$daemon_rc: $daemon_out"

    sleep 1

    dver=$(/sbin/magisk -v 2>&1)
    dver_rc=$?
    [ "$dver_rc" = "0" ] || fail "client cannot talk to magiskd: $dver"

    [ -e /sbin/.magisk/device/socket ] || fail "magiskd socket was not created"

    pid=$(daemon_pid)
    [ -n "$pid" ] || fail "magiskd process is not present"

    log "magiskd version: $dver"
    log "magiskd pid: $pid"
    log "magiskd context: $(cat "/proc/$pid/attr/current" 2>/dev/null || echo unknown)"

    # Bind the Manager's trusted certificate BEFORE any su request can trigger
    # check_orig: a cold daemon has an empty trusted_cert, and release Magisk
    # uninstalls a Manager whose certificate does not match -> on a re-run the
    # Manager would vanish before Phase 2 ever runs.
    if [ -f "$STAGE/stub.apk" ]; then
        log "staging stub.apk for trusted Manager certificate"
        cp "$STAGE/stub.apk" /sbin/stub.apk || fail "cannot stage /sbin/stub.apk"
        chmod 0644 /sbin/stub.apk

        log "running magisk post-fs-data to consume stub (sets trusted_cert)"
        pfs_out=$(/sbin/magisk --post-fs-data 2>&1)
        pfs_rc=$?
        log "post-fs-data rc=$pfs_rc"

        if [ -e /sbin/stub.apk ]; then
            fail "stub.apk was not consumed; trusted Manager certificate is NOT bound"
        else
            toybox sha256sum "$STAGE/stub.apk" | awk '{print $1}' \
                > /data/adb/magisk/.snusnu-trusted-stub.sha256 \
                || fail "cannot record trusted stub digest"
            chmod 0600 /data/adb/magisk/.snusnu-trusted-stub.sha256
            log "stub.apk consumed: trusted Manager certificate bound"
        fi

        # post-fs-data increments the bootloop counter; reset it so repeated
        # bootstrap runs can never drift into Magisk safe mode (threshold 2).
        /sbin/magisk --sqlite "INSERT OR REPLACE INTO settings (key,value) VALUES('bootloop',0)" >/dev/null 2>&1 || true

        log "testing Magisk su applet from existing uid-0 context"
        su_out=$(/sbin/su -c id 2>&1)
        su_rc=$?
        [ "$su_rc" = "0" ] || fail "root-context Magisk su test failed rc=$su_rc: $su_out"
        echo "$su_out" | grep -q 'uid=0' || fail "Magisk su test did not return uid=0: $su_out"
        log "root-context su result: $su_out"
    else
        log "WARNING: no stub.apk staged; skipping root-context su test to avoid a cold-daemon Manager uninstall"
    fi

    IN_START=0
    log "Phase 1 runtime bootstrap succeeded"
    status
}

stop() {
    root_uid_ok || {
        log "ERROR: stop must run as uid 0"
        exit 1
    }
    rollback_runtime || exit 1
    status
}

case "$ACTION" in
    start)
        start
        ;;
    status)
        status
        ;;
    stop)
        stop
        ;;
    *)
        echo "usage: $0 {start|status|stop}" >&2
        exit 2
        ;;
esac
DEVICE_SCRIPT

chmod 700 "$HOST_HELPER"

require_adb
require_root_listener

case "$ACTION" in
    start)
        [ -x "$MAGISK_HOST" ] || die "built Magisk binary missing: $MAGISK_HOST"
        [ -x "$POLICY_HOST" ] || die "built magiskpolicy binary missing: $POLICY_HOST"

        log "staging device helper and ARM64 Magisk binaries"
        "$ADB" shell "rm -rf '$DEVICE_STAGE'; mkdir -p '$DEVICE_STAGE'" >/dev/null
        "$ADB" push "$MAGISK_HOST" "$DEVICE_STAGE/magisk" >/dev/null
        "$ADB" push "$POLICY_HOST" "$DEVICE_STAGE/magiskpolicy" >/dev/null
        "$ADB" push "$HOST_HELPER" "$DEVICE_HELPER" >/dev/null
        "$ADB" shell "chmod 755 '$DEVICE_STAGE/magisk' '$DEVICE_STAGE/magiskpolicy' '$DEVICE_HELPER'" >/dev/null

        # Match the Manager's signing cert before magiskd serves su, so a
        # cold-daemon check_orig cannot uninstall the Manager on re-runs.
        if [ -s "$REPO_DIR/magisk/out/app-release.apk" ] \
            && command -v unzip >/dev/null 2>&1; then
            unzip -p "$REPO_DIR/magisk/out/app-release.apk" assets/stub.apk \
                >"$HOST_STUB" 2>/dev/null || true
        fi
        if [ -s "$HOST_STUB" ]; then
            log "staging matching stub.apk (trusted Manager certificate)"
            "$ADB" push "$HOST_STUB" "$DEVICE_STAGE/stub.apk" >/dev/null
        else
            log "WARN: no stub.apk available; device helper will skip the root-context su test"
        fi

        log "starting live Magisk runtime through existing root listener"
        if ! run_device_action start; then
            die "device bootstrap failed (device helper attempted rollback); refusing post-start tests"
        fi

        require_adb
        require_root_listener

        log "post-start checks"
        root_cmd 'echo "getenforce=$(getenforce)"; echo "magisk=$( /sbin/magisk -v 2>&1 )"; echo "path=$( /sbin/magisk --path 2>&1 )"; ps | grep "[m]agiskd" || true'

        log "verifying non-root adb-shell can reach magiskd"
        SHELL_MAGISK_VER=$("$ADB" shell '/sbin/magisk -v' 2>&1) \
            || die "adb-shell cannot reach magiskd: $SHELL_MAGISK_VER"
        printf '%s\n' "$SHELL_MAGISK_VER"

        log "probing non-root adb-shell su path (8 second limit; GUI authorization may not exist yet)"
        set +e
        if command -v timeout >/dev/null 2>&1; then
            SU_OUT=$(timeout 8 "$ADB" shell '/sbin/su -c id' 2>&1)
            SU_RC=$?
        else
            SU_OUT=$("$ADB" shell '/sbin/su -c id' 2>&1)
            SU_RC=$?
        fi
        set -e
        printf '%s\n' "$SU_OUT"
        case "$SU_RC" in
            0)
                log "non-root adb-shell su request completed successfully"
                ;;
            124)
                log "non-root adb-shell su request timed out; this is compatible with pending Manager authorization"
                ;;
            *)
                log "non-root adb-shell su returned rc=$SU_RC; Phase 1 daemon remains up, inspect before GUI integration"
                ;;
        esac

        require_root_listener
        log "start complete"
        ;;

    status)
        "$ADB" push "$HOST_HELPER" "$DEVICE_HELPER" >/dev/null
        "$ADB" shell "chmod 755 '$DEVICE_HELPER'" >/dev/null
        run_device_action status || die "device status helper failed"
        require_root_listener
        ;;

    stop)
        "$ADB" push "$HOST_HELPER" "$DEVICE_HELPER" >/dev/null
        "$ADB" shell "chmod 755 '$DEVICE_HELPER'" >/dev/null
        log "stopping live Magisk runtime"
        run_device_action stop || die "device stop/rollback helper failed"
        require_adb
        require_root_listener
        log "stop complete; original /sbin should be exposed again"
        ;;

    *)
        die "usage: $0 {start|status|stop}"
        ;;
esac
