#!/bin/sh
#
# Stage 4 - install persistent root.
#
# Replicates upstream SnuSnuRoot's `runme.sh arm` install for this device. The values
# below were read from refs/SnuSnuRoot/runme.sh and notes/persistence-v2.md rather than
# guessed. Deviations from upstream are marked "PS7319:" with the reason.
#
#   sh install-persistence.sh            # install / repair
#   sh install-persistence.sh --status   # report only
#   sh install-persistence.sh --remove   # revert
#
# Requires: adb, one device ALREADY rooted by stage1-root (uid-0 listener on 4325).
#
# ORDER MATTERS: the APK must be installed and granted BEFORE rooting. `pm install`
# succeeds while SELinux is Enforcing and HANGS INDEFINITELY afterwards (verified with
# two unrelated APKs, so it is not APK-specific).
#
# WHY EACH PATH LOOKS THE WAY IT DOES
# -----------------------------------
#   /data/snusnu_hwbinder_root   root:system 0750, system_data_file   (upstream)
#       The app uid-1000 system_app channel executes this. Group `system` (gid 1000)
#       plus 0750 is what grants that. Verified on-device: the channel can execute it
#       and it runs the hwbinder probe.
#
#   /data/securedStorageLocation/w/b   mode 0644, label shell_exec   (PS7319 change)
#       Upstream ships assetstorage_data_file. On PS7319 time_update has no read on
#       that label, so the trigger cannot read it, so the carrier is never reached.
#       Verified on-device: with shell_exec the trigger fires (the property is
#       consumed and normalised on boot).
#
#   $SNS/waiter.sh   chown 1000:1000, 0755                            (upstream)
#   $STATE           mode 0777, owned by root                         (PS7319 change)
#       The actor writes native_result here and READS IT BACK to look for
#       __SNU_NATIVE_0__. Do NOT point that at /dev/null: the read returns empty, the
#       app reports system_native_failed, and it never reaches kernel_write_ok. That
#       mistake cost several boots.
#       $STATE is deliberately NOT under /data/securedStorageLocation. That tree is
#       assetstorage_data_file and this firmware denies system_app -- the actor's
#       UID-1000 domain -- even `search` on it, so every boot failed with EACCES:
#         avc: denied { search } for name="securedStorageLocation"
#           scontext=u:r:system_app:s0 tcontext=u:object_r:assetstorage_data_file:s0
#       /data/cache is cache_file, which system_app may search/create/unlink in.
#       It must stay root-owned: time_update is exempt from DAC but has no
#       CAP_FOWNER, so a chmod of a 1000:-owned directory is denied (measured).
#
# SAFETY: everything is under /data. No partition is written.

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)
ADB=${ADB:-"$REPO_DIR/stage1-root/port/tools/adb-portable.sh"}

PORT=4325
CHANNEL=4321
SNS=/data/securedStorageLocation/snusnu
STATE=/data/cache/snusnu/state
# Watchdog disable sentinel. It must live where the uid-1000 actor can stat it:
# /data/securedStorageLocation is assetstorage_data_file, which system_app cannot
# even search. $SNS/disable is the waiter's own sentinel (root-only path).
WATCHDOG_DISABLE=/data/cache/snusnu/disable
SNS_DISABLE=$SNS/disable
SAVED_TIME_ORIG=/data/cache/snusnu/saved_time.orig
# What the boot actor must verify before it launches the carrier against the
# kernel: without this, an OTA that changes selinux_enforcing's address leaves
# the actor launching the old carrier at the old address.
EXPECTED_BUILD=/data/cache/snusnu/expected-build
# Watchdog: root-owned 0755 in a root-owned 0755 dir. The actor runs it but must
# not be able to rewrite it -- executing a script from the actor's 0777 scratch
# directory would let any local app substitute code that runs as uid 1000.
WATCHDOG_DIR=/data/snusnu_root/bin
WATCHDOG_ROOT=/data/snusnu_root
WATCHDOG=$WATCHDOG_DIR/watchdog.sh
W=/data/securedStorageLocation/w
WATER=$W/b
CARRIER=/data/snusnu_hwbinder_root
PKG=io.github.voidnullvalue.snusnuroot.persistence
TRIGGER='x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000'

NATIVE_HOST="$REPO_DIR/stage1-root/port/prebuilt/device/arm64-v8a/snusnu_hwbinder_root"
APK_HOST="$REPO_DIR/stage4-persistent/app/build/snusnu-persistence.apk"

adb() { "$ADB" "$@"; }
sh_() { adb shell "$@"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# adb-portable.sh sets MSYS_NO_PATHCONV=1 for the sake of adb device paths, which also
# stops MSYS converting absolute host paths; native adb.exe then cannot stat them.
# Normalise host paths before any push/pull (same trap as reroot_after_boot.sh).
#
# cygpath handles every MSYS form, including the /tmp/... paths mktemp returns --
# those are OUTSIDE /c and /d, so the hand-rolled case below silently passed them
# through unchanged and `adb pull` failed with "could not pull the installed APK".
# (A commented-out "-r" or a bad conversion here is invisible until a pull fails.)
to_win() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
        return
    fi
    case "$1" in
        /c/*) printf '%s' "C:${1#/c}" ;;
        /d/*) printf '%s' "D:${1#/d}" ;;
        *)    printf '%s' "$1" ;;
    esac
}

rootsh() { printf '%s\nexit\n' "$1" | adb shell "toybox nc -w 60 127.0.0.1 $PORT"; }
chansh() { printf '%s\nexit\n' "$1" | adb shell "toybox nc -w 60 127.0.0.1 $CHANNEL"; }

need_root() {
    out=$(printf 'id -u\nexit\n' | adb shell "toybox nc -w 5 127.0.0.1 $PORT" 2>/dev/null | tr -d '\r' || true)
    # Exact match, not a substring: `case *0*` also accepts uid 1000, 2000 and
    # any error text containing a zero, so a non-root listener could be mistaken
    # for the root one and the caller would treat it as uid 0.
    uid="$(printf '%s\n' "$out" | grep -E '^[0-9]+$' | head -1)"
    [ "$uid" = "0" ] || die "no uid-0 listener on 127.0.0.1:$PORT (got '$out'). Run stage1-root first:
       powershell -File stage1-root/run-root.ps1 -ConfirmRoot"
}

# Run a command in the root listener and require proof that it ran to completion.
#
# `rootsh` used to return the ADB/netcat transport status, which says nothing
# about the remote shell: a command that never executed, or executed and failed,
# still produced transport rc 0. Each call now appends an explicit completion
# marker; its absence is a hard failure regardless of transport status. Output is
# printed so existing call sites keep working.
SNU_DONE='__SNU_DONE__'
rootsh() {
    out=$(printf '%s\nprintf "%%s\\n" "%s"\nexit\n' "$1" "$SNU_DONE" \
        | adb shell "toybox nc -w 60 127.0.0.1 $PORT" 2>&1 | tr -d '\r')
    rc=$?
    case "$out" in
        *"$SNU_DONE"*) printf '%s\n' "${out%$SNU_DONE*}"; return 0 ;;
        *) printf '%s\n' "$out" >&2
           echo "FATAL: root command did not complete (marker absent; transport rc=$rc)." >&2
           echo "  command was: $(printf '%s' "$1" | head -c 200)" >&2
           return 1 ;;
    esac
}

chansh() {
    out=$(printf '%s\nprintf "%%s\\n" "%s"\nexit\n' "$1" "$SNU_DONE" \
        | adb shell "toybox nc -w 60 127.0.0.1 $CHANNEL" 2>&1 | tr -d '\r')
    case "$out" in
        *"$SNU_DONE"*) printf '%s\n' "${out%$SNU_DONE*}"; return 0 ;;
        *) printf '%s\n' "$out" >&2
           echo "FATAL: uid-1000 channel command did not complete." >&2
           return 1 ;;
    esac
}

channel_alive() {
    printf 'id -u\nexit\n' | adb shell "toybox nc -w 3 127.0.0.1 $CHANNEL" 2>/dev/null \
        | grep -qE '^1000$'
}

status() {
    echo "== stage 4 status =="
    printf 'root listener : '
    if printf 'id -u\nexit\n' | adb shell "toybox nc -w 5 127.0.0.1 $PORT" 2>/dev/null | grep -q '^0'; then
        echo "uid 0"
    else
        echo "absent"
    fi
    echo "saved_time    : $(sh_ getprop persist.sys.saved_time | tr -d '\r')"
    echo "app           : $(sh_ "pm list packages $PKG" | tr -d '\r')"
    for k in snusnu_persist_enabled snusnu_persist_status snusnu_rearm_status snusnu_retry_count; do
        printf '%-14s: %s\n' "$k" "$(sh_ "settings get global $k" | tr -d '\r')"
    done
    rootsh "ls -lZ $CARRIER; ls -lZ $WATER; ls -ldZ $STATE; ls -l $STATE; ls -lZ $SNS/waiter.sh" 2>/dev/null
}

install() {
    need_root

    echo "== 0/6 preflight: app installed and granted (must be done in CLEAN state) =="
    if ! sh_ "pm list packages $PKG" | grep -q "$PKG"; then
        cat >&2 <<EOF
FATAL: $PKG is not installed.

Install it before rooting: an install is easiest to verify and retry from a
clean boot (it does also work while Permissive - measured, despite an earlier
note in this repo claiming it hangs).

  1. sh stage4-persistent/app/build.sh
  2. adb install -r $APK_HOST
  3. adb shell pm grant $PKG android.permission.WRITE_SECURE_SETTINGS
  4. re-run this script (root must be live: stage1-root/run-root.ps1 -ConfirmRoot)
EOF
        exit 1
    fi
    sh_ "dumpsys package $PKG" | grep -q 'WRITE_SECURE_SETTINGS: granted=true' \
        || die "WRITE_SECURE_SETTINGS not granted (do it in clean state)"

    # The INSTALLED apk must be the patched build. Upstream's hardcodes
    # /data/securedStorageLocation/snusnu/state, which system_app cannot reach on
    # this firmware, so it reports system_native_failed on every boot.
    installed_apk=$(sh_ "pm path $PKG" | tr -d '\r' | sed -n 's/^package://p' | head -1)
    [ -n "$installed_apk" ] || die "pm path returned nothing for $PKG"
    # "The check did not run" must never be reported as "the check passed":
    # this used to be skipped silently when python was missing or the pull
    # failed, and the next line still printed that the app was patched.
    command -v python >/dev/null 2>&1 \
        || die "python is required to verify the installed APK is the patched build."
    probe_apk=$(mktemp)
    # Convert ONCE and use the Windows form for both the pull and the Python read:
    # adb.exe and the native Python are Windows programs, and MSYS paths like
    # /tmp/... are meaningful only inside the shell.
    probe_win=$(to_win "$probe_apk")
    adb pull "$installed_apk" "$probe_win" >/dev/null 2>&1 \
        || die "could not pull the installed APK for verification ($installed_apk)"
    python -c "
import sys, zipfile
dex = zipfile.ZipFile(sys.argv[1]).read('classes.dex')
sys.exit(0 if b'/data/cache/snusnu/state' in dex
         and b'/data/securedStorageLocation/snusnu/state' not in dex else 1)" "$probe_win" \
        || die "installed APK is upstream's, not the patched build.
   Build it:  sh stage4-persistent/app/build.sh
   Install:   adb install -r $(to_win "$APK_HOST")"
    rm -f "$probe_apk"
    echo "  app present, granted, and patched (verified against the installed dex)"
    echo

    # A freshly installed package starts in the STOPPED state, and a stopped
    # package receives no broadcasts at all -- so BOOT_COMPLETED never reaches
    # the actor, nothing re-arms the trigger, no watchdog starts, and no root
    # appears. Every check above still passes, so this is invisible until the
    # next boot. An upgrade (`install -r` over an existing package) clears the
    # flag; uninstall-then-reinstall does NOT, which is how this was found.
    #
    # Android clears it when the package is explicitly launched, which is exactly
    # what BootstrapActivity exists for.
    echo "== 0b/6 clear the package's stopped state =="
    stopped_now() { sh_ "dumpsys package $PKG | grep -o 'stopped=[a-z]*'" | tr -d '\r' | head -1; }
    st="$(stopped_now)"
    if [ "$st" = "stopped=false" ]; then
        echo "  actor is not stopped"
    else
        sh_ "am start -n $PKG/.BootstrapActivity" >/dev/null 2>&1 || true
        sleep 3
        st2="$(stopped_now)"
        [ "$st2" = "stopped=false" ] || die "could not clear the package's stopped state (was '$st', now '$st2').
   A stopped package receives no BOOT_COMPLETED broadcast, so the actor would
   never run and no root would appear. Launch it once manually:
     adb shell am start -n $PKG/.BootstrapActivity
   and confirm 'stopped=false' in: adb shell dumpsys package $PKG"
        echo "  cleared (was '$st')"
    fi
    echo

    echo "== 1/6 carrier: $CARRIER (root:system 0750 system_data_file, per upstream) =="
    adb push "$(to_win "$NATIVE_HOST")" /data/local/tmp/snusnu_carrier >/dev/null
    rootsh "cp /data/local/tmp/snusnu_carrier $CARRIER.new && chown 0:1000 $CARRIER.new && chmod 0750 $CARRIER.new && chcon u:object_r:system_data_file:s0 $CARRIER.new && mv -f $CARRIER.new $CARRIER && rm -f /data/local/tmp/snusnu_carrier && ls -lZ $CARRIER"
    echo

    echo "== 2/6 boot entry: $WATER (0644, label shell_exec -- PS7319 fix) =="
    adb push "$(to_win "$SELF_DIR/boot-entry.sh")" /data/local/tmp/boot_entry >/dev/null
    rootsh "mkdir -p $W $SNS $STATE && cp /data/local/tmp/boot_entry $WATER && chmod 0644 $WATER && chcon u:object_r:shell_exec:s0 $WATER && rm -f /data/local/tmp/boot_entry && ls -lZ $WATER"
    echo

    echo "== 3/6 waiter: $SNS/waiter.sh (1000:1000 0755, per upstream) =="
    adb push "$(to_win "$SELF_DIR/waiter.sh")" /data/local/tmp/waiter >/dev/null
    # $STATE is chowned root:root, mode 0777. Deliberately NOT upstream's 1000:1000:
    # time_update is DAC-exempt but has no CAP_FOWNER, so its boot-time
    # `chmod 0777 $STATE` on a 1000:-owned directory is denied with { fowner }
    # (measured). 0777 keeps it fully usable to the actor's UID-1000 channel, which
    # is what actually writes here, and root ownership keeps the waiter's chmod
    # legal so the mode is re-asserted rather than silently skipped.
    # sync because a metadata update followed by an immediate reboot is not
    # guaranteed to have hit the disk. The stale $SNS/state paths are the leftovers
    # of an earlier wrong turn that symlinked carrier_pid at /dev/null.
    rootsh "cp /data/local/tmp/waiter $SNS/waiter.sh && chown 1000:1000 $SNS/waiter.sh && chmod 0755 $SNS/waiter.sh && rm -f /data/local/tmp/waiter && chmod 0755 $SNS $W && mkdir -p $STATE && chown 0:0 $STATE && chmod 0777 $STATE && rm -f $SNS/disable $STATE/carrier_pid $STATE/native_result $SNS/state/carrier_pid && sync && ls -lZ $SNS/waiter.sh && ls -ldZ $STATE"
    echo

    # The watchdog runs as the actor's uid, so it must be executable by uid 1000 --
    # but it must NOT be writable by it. Installing it root:root 0755 in a
    # root:root 0755 directory separates trusted executable code from the 0777
    # scratch directory that holds untrusted output. Previously the actor wrote
    # this script into its own 0777 state dir and executed it, so any local app
    # able to write there could have run code as uid 1000 and re-armed root.
    #
    # BOTH levels get the mode: `mkdir -p` creates the parent with the root
    # shell's umask, and a 0700 parent is enough to make the script unreachable
    # even though the script itself is 0755. On-device this failed as
    # "watchdog.sh: Permission denied" with uid 1000.
    echo "== 3b/6 watchdog: $WATCHDOG (root:root 0755, parent dirs traversable) =="
    adb push "$(to_win "$SELF_DIR/watchdog.sh")" /data/local/tmp/watchdog >/dev/null
    rootsh "mkdir -p $WATCHDOG_DIR && chown 0:0 $WATCHDOG_ROOT $WATCHDOG_DIR && chmod 0755 $WATCHDOG_ROOT $WATCHDOG_DIR && cp /data/local/tmp/watchdog $WATCHDOG && chown 0:0 $WATCHDOG && chmod 0755 $WATCHDOG && rm -f /data/local/tmp/watchdog && rm -f $STATE/watchdog.sh && sync && ls -lZ $WATCHDOG && ls -ldZ $WATCHDOG_ROOT $WATCHDOG_DIR"
    echo
    # Mode checks are not enough -- the previous install passed them while uid 1000
    # could not reach the file at all. Prove the intended uid can execute it, and
    # that it cannot overwrite it.
    echo "  reachability, as the uid that will run it:"
    reach="$(chansh "if command -v $WATCHDOG >/dev/null 2>&1; then echo reachable; else echo unreachable; fi; if ( : >> $WATCHDOG ) 2>/dev/null; then echo WRITABLE_BAD; else echo not_writable; fi")"
    case "$reach" in
        *reachable*not_writable*) echo "    ok: uid 1000 can execute it and cannot modify it" ;;
        *) die "watchdog is not usable by the actor's uid 1000:
$(printf '%s\n' "$reach" | sed 's/^/      /')
   Executable and non-writable by uid 1000 is the whole point of this file's
   location; a root-owned script the actor cannot run is a dead watchdog." ;;
    esac
    echo

    echo "== 4/6 enable the actor and arm the trigger =="
    # Gate first: without snusnu_persist_enabled=1 the service returns immediately with
    # "disabled by global setting" and nothing else happens.
    sh_ "settings put global snusnu_persist_enabled 1" >/dev/null

    # The guard and the sentinel live in /data/cache/snusnu, whose ownership is
    # made deterministic here (it was previously whatever happened to create it
    # first: the installer runs as root, the actor as uid 1000). It is owned by
    # uid 1000 so the actor can create its state subdirectory, and root can still
    # write the guard and sentinel because root bypasses DAC.
    #
    # Note what the guard is NOT: uid 1000 can already execute the carrier
    # directly, so the guard is not a security boundary against that uid. It is a
    # consistency check for OTA drift. Keeping it replaceable by uid 1000 is
    # deliberate, because it makes a mismatched gate recoverable on-device (see
    # README "If the build gate refuses").
    rootsh "mkdir -p /data/cache/snusnu $STATE && rm -f $WATCHDOG_DISABLE $SNS_DISABLE $STATE/watchdog.pid && chown 1000:1000 /data/cache/snusnu && chmod 0700 /data/cache/snusnu && chown 0:0 $STATE && chmod 0777 $STATE && sync && ls -ldZ /data/cache/snusnu $STATE"

    # Record what was verified ON THIS DEVICE so the boot actor can refuse to
    # launch the carrier after an OTA changes the kernel under it. The carrier
    # targets selinux_enforcing, which is a per-build address; a permission and
    # label check says nothing about that.
    local_inc=$(sh_ getprop ro.build.version.incremental | tr -d '\r')
    local_ps=$(sh_ getprop ro.build.id | tr -d '\r')
    carrier_sha=$(rootsh "toybox sha256sum $CARRIER | cut -d' ' -f1" | tr -d '\r' | head -1)
    case "$carrier_sha" in
        ''|*[!0-9a-f]*) die "could not read the deployed carrier digest (got '$carrier_sha'); refusing to record an unverifiable guard" ;;
    esac
    for v in "$local_inc" "$local_ps"; do
        case "$v" in
            ''|*[!A-Za-z0-9._-]*) die "refusing to write a guard with a malformed build id ('$v')" ;;
        esac
    done
    # The guard content is base64'd rather than piped in, because rootsh builds its
    # own stdin (the command plus a completion marker) and does not forward a pipe.
    # Piping here silently produced an EMPTY guard file, which the boot actor would
    # then treat as "no recorded build" -- the failure mode this gate exists to
    # prevent. Same base64 trick the trigger arming already uses.
    guard_b64=$(printf 'ps=%s\nincremental=%s\ncarrier_sha=%s\n' \
        "$local_ps" "$local_inc" "$carrier_sha" | base64 | tr -d '\n')
    rootsh "printf '%s' '$guard_b64' | toybox base64 -d > $EXPECTED_BUILD.tmp && mv -f $EXPECTED_BUILD.tmp $EXPECTED_BUILD && chmod 0644 $EXPECTED_BUILD && sync" >/dev/null \
        || die "could not write the build guard file $EXPECTED_BUILD"
    # Read it back: writing a file and assuming it took is exactly how the empty
    # guard would have slipped through.
    guard_now=$(rootsh "cat $EXPECTED_BUILD" | tr -d '\r')
    case "$guard_now" in
        *"incremental=$local_inc"*"carrier_sha=$carrier_sha"*) : ;;
        *) die "build guard did not verify after writing. Expected incremental=$local_inc carrier_sha=$carrier_sha, got:
$guard_now" ;;
    esac
    echo "  guard: ps=$local_ps incremental=$local_inc carrier_sha=${carrier_sha%${carrier_sha#????????????}}..."

    # Capture the property's current numeric value so --remove can restore it.
    # Only the uid-1000 channel can write this property, so the recorded value is
    # the only way removal can put it back.
    now_time=$(sh_ getprop persist.sys.saved_time | tr -d '\r')
    case "$now_time" in
        ''|*[!0-9]*) echo "  NOTE: saved_time is not numeric ($now_time); not recording a restore value" ;;
        *)  rootsh "mkdir -p /data/cache/snusnu; printf '%s' '$now_time' > $SAVED_TIME_ORIG; sync; echo recorded=$now_time" >/dev/null ;;
    esac

    # Arm via the uid-1000 CHANNEL, not the root listener. Verified on-device: the
    # time_update domain is denied `setprop persist.sys.saved_time`, while system_app
    # (the channel) is allowed - which is how the app itself re-arms it. Using the root
    # listener here fails with "failed to set property".
    b64=$(printf '%s' "$TRIGGER" | base64 | tr -d '\n')
    chansh "setprop persist.sys.saved_time \"\$(printf '%s' '$b64' | toybox base64 -d)\"; echo armed=\$(getprop persist.sys.saved_time)"
    # sync, or a property set immediately before reboot can be lost
    chansh "sync; echo synced"
    echo

    echo "== 5/6 verify the install matches upstream shape =="
    fail=0
    chk() {
        case "$3" in
            *"$2"*) echo "  ok   $1" ;;
            *)      echo "  FAIL $1: expected '$2', got '$3'"; fail=1 ;;
        esac
    }
    chk_absent() {
        case "$2" in
            absent) echo "  ok   $1" ;;
            *)      echo "  FAIL $1: $2"; fail=1 ;;
        esac
    }
    chk "carrier mode 0750" "-rwxr-x---"      "$(rootsh "ls -l $CARRIER" | tr -d '\r')"
    chk "carrier label"     "system_data_file" "$(rootsh "ls -Z $CARRIER" | tr -d '\r')"
    chk "boot entry label"  "shell_exec"       "$(rootsh "ls -Z $WATER" | tr -d '\r')"
    chk "state dir 0777"    "drwxrwxrwx"       "$(rootsh "ls -ld $STATE" | tr -d '\r')"
    chk "state dir owned by root" "root root"  "$(rootsh "ls -ld $STATE" | tr -d '\r')"
    chk "waiter installed"  "waiter.sh"        "$(rootsh "ls -l $SNS/waiter.sh" | tr -d '\r')"
    chk "watchdog root-owned 0755" "-rwxr-xr-x 1 root root" "$(rootsh "ls -l $WATCHDOG" | tr -d '\r')"
    chk "watchdog parent traversable" "drwxr-xr-x" "$(rootsh "ls -ld $WATCHDOG_ROOT" | tr -d '\r')"
    chk "watchdog dir traversable" "drwxr-xr-x" "$(rootsh "ls -ld $WATCHDOG_DIR" | tr -d '\r')"
    chk_absent "watchdog not in the 0777 scratch dir" "$(rootsh "if [ -e $STATE/watchdog.sh ]; then echo present; else echo absent; fi" | tr -d '\r')"
    chk "build guard written"  "incremental="  "$(rootsh "cat $EXPECTED_BUILD" | tr -d '\r')"
    # The actor cannot receive BOOT_COMPLETED while the package is stopped, so a
    # successful install must leave it un-stopped.
    chk "actor not stopped"     "stopped=false" "$(sh_ "dumpsys package $PKG | grep -o 'stopped=[a-z]*'" | tr -d '\r' | head -1)"
    # Full expected value, not just the 'x[$(' prefix: a truncated or corrupted
    # arm still starts with that prefix and would then fail at boot.
    chk "trigger armed"     "$TRIGGER"         "$(sh_ getprop persist.sys.saved_time | tr -d '\r')"
    chk_absent "no disable sentinel"            "$(rootsh "if [ -e $WATCHDOG_DISABLE ] || [ -e $SNS_DISABLE ]; then echo present; else echo absent; fi" | tr -d '\r')"
    [ "$fail" -eq 0 ] || die "install verification failed - do NOT reboot into a trial yet"
    echo

    echo "== 6/6 installed =="
    echo "Validate with the host DISCONNECTED:"
    echo "    adb reboot"
    echo "    # root should appear within ~30-90 s of boot_completed"
    echo "    printf 'id -u\\nexit\\n' | adb shell 'toybox nc -w 3 127.0.0.1 4325'"
}

remove() {
    need_root
    echo "== reverting stage 4 =="

    # Order matters. The re-arm watchdog looped every 2s and re-armed
    # persist.sys.saved_time; removing payloads without stopping it meant the
    # property was immediately re-armed to point at a file that no longer
    # existed, while this function printed "reverted". Sentinel first, then the
    # process, then the payloads.
    echo "-- 1/5 stop the re-arm watchdog"
    rootsh "mkdir -p /data/cache/snusnu; : > $WATCHDOG_DISABLE; : > $SNS_DISABLE; sync; echo sentinels_written" >/dev/null \
        || die "could not write the disable sentinels; the watchdog is still armed"
    sleep 4    # let the loop reach its next tick
    # The pidfile is two lines (boot id, pid), so read the pid explicitly rather
    # than word-splitting the whole file -- and the ps sweep catches a guard whose
    # pidfile is stale or unreadable.
    rootsh "for p in \$(sed -n '2p' $STATE/watchdog.pid 2>/dev/null) \$(ps -A -o PID,ARGS 2>/dev/null | grep '[w]atchdog.sh' | awk '{print \$1}'); do kill -9 \"\$p\" 2>/dev/null; done; sleep 1; if ps -A 2>/dev/null | grep -q '[w]atchdog.sh'; then echo watchdog_still_running; else echo watchdog_stopped; fi"

    echo "-- 2/5 disable the boot actor (ordinary settings interface)"
    # Plain adb shell, not the root listener: time_update cannot reach the
    # settings service at all ("Can't find service: settings"), so the old
    # rootsh here could never have worked.
    for k in snusnu_persist_enabled snusnu_persist_status snusnu_rearm_status \
             snusnu_retry_count snusnu_native_result snusnu_persist_boot_id; do
        sh_ "settings delete global $k" >/dev/null 2>&1 || true
    done
    if sh_ "settings get global snusnu_persist_enabled" | grep -qvE '^null$'; then
        echo "  WARNING: snusnu_persist_enabled is still set; the actor may run again"
    fi

    echo "-- 3/5 restore persist.sys.saved_time"
    # Only the uid-1000 channel may write this property; the root listener is
    # denied (measured, and documented in the install section above).
    orig="$(rootsh "cat $SAVED_TIME_ORIG 2>/dev/null" | tr -d '\r')"
    case "$orig" in
        ''|*[!0-9]*) orig=0 ;;
    esac
    if channel_alive; then
        chansh "setprop persist.sys.saved_time $orig; sync; echo restored=\$(getprop persist.sys.saved_time)" \
            || echo "  WARNING: channel command did not complete"
        now=$(sh_ getprop persist.sys.saved_time | tr -d '\r')
        case "$now" in
            *'$('*) die "saved_time is STILL ARMED ($now) after restore. The watchdog may be alive.
       Re-run --remove, or finish with: powershell -File stage1-root/run-root.ps1 -Disarm" ;;
        esac
    else
        echo "  NOTE: uid-1000 channel unavailable, so the property could not be restored."
        echo "        The watchdog is stopped, but run stage1-root -Disarm if saved_time is armed."
    fi

    echo "-- 4/5 remove payloads"
    rootsh "rm -f $CARRIER $WATER $SNS/waiter.sh $WATCHDOG; rm -rf $STATE; rm -f $SAVED_TIME_ORIG $EXPECTED_BUILD; rmdir $WATCHDOG_DIR $WATCHDOG_ROOT 2>/dev/null; echo payloads_removed"

    echo "-- 5/5 uninstall the actor"
    if adb uninstall "$PKG" 2>&1 | grep -qi 'Success'; then
        echo "  actor uninstalled"
    else
        echo "  WARNING: could not uninstall $PKG. It is disabled and its payloads are gone,"
        echo "           but uninstall it manually before relying on removal."
    fi

    echo
    echo "Remaining teardown (Stage 1's own state, not Stage 4's):"
    echo "    powershell -File stage1-root/run-root.ps1 -Disarm"
    echo "Then reboot to return to stock."
}

case "${1:-}" in
    --status) status ;;
    --remove) remove ;;
    "")       install ;;
    *)        echo "usage: $0 [--status|--remove]" >&2; exit 2 ;;
esac