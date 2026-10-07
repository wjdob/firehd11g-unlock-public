# Adopted from SnuSnuRoot (GPL-3.0) -- scripts/snusnu_waiter.sh
# https://github.com/voidnullvalue/SnuSnuRoot
# Copied verbatim apart from line-ending normalisation and the state-directory
# fix described below. See NOTICE.
#
# PS7319 divergence: upstream prepares $STATE after the Permissive wait. That is
# an ordering deadlock here -- the actor's UID-1000 channel writes native_result
# into $STATE, and Permissive only appears once that write succeeded. Upstream
# never hit it because 4460N keeps saved_time armed across boots and its
# securedStorageLocation metadata survives; on this firmware a state directory
# whose mode is not re-asserted leaves the actor with EACCES, the kernel write
# never runs, and the waiter times out (measured: "system_native_failed" /
# "failed_no_reboot_1" with rm/create EACCES on $STATE). The preparation now
# runs at the top of the wait loop so it is re-asserted every second from the
# first moment of boot, before the actor's channel exists.
#!/system/bin/sh
# UID-0/time_update half of the persistent boot chain.  The installed direct-
# boot app performs the framework work, re-arms the trigger, and flips SELinux;
# this deliberately restricted process only waits and restores the root runtime.

SNS=/data/securedStorageLocation/snusnu
# Not under $SNS: that tree is assetstorage_data_file and this firmware denies
# system_app -- the actor's UID-1000 domain -- even `search` on it, so the actor
# cannot write its own state there (measured). /data/cache is cache_file, which
# system_app may search/create/unlink in. Root's mkdir here is best-effort; the
# actor also creates it itself.
STATE=/data/cache/snusnu/state
DISABLE="$SNS/disable"
ROOT_PORT=4325

logmsg() {
    /system/bin/log -t SNUSNU_WAITER "uid=$(id -u 2>/dev/null) $*" >/dev/null 2>&1
}

[ -e "$DISABLE" ] && { logmsg disabled; exit 0; }
logmsg "start saved_time=$(getprop persist.sys.saved_time 2>/dev/null)"

# getenforce is itself denied to time_update while enforcing.  Once the app's
# kernel write succeeds, the same command becomes readable and returns 0/Permissive.
permissive=0
# 300 s, not upstream's 180 s: the boot actor now retries the carrier in-boot
# (up to 5 attempts with 12 s spacing), so Permissive can arrive ~4 minutes into
# the window. A shorter wait would abandon a boot that is still making progress.
for i in $(seq 1 300); do
    # Re-asserted every second: the actor's channel must be able to write here
    # before its kernel write can succeed, and its kernel write is what makes
    # getenforce readable at all. Doing this after the loop (upstream) deadlocks.
    mkdir -p "$STATE" /data/local/tmp/rootsvc 2>/dev/null
    chmod 0777 "$STATE" /data/local/tmp/rootsvc 2>/dev/null
    [ "$(getenforce 2>/dev/null)" = Permissive ] && { permissive=1; break; }
    sleep 1
done
[ "$permissive" = 1 ] || { logmsg timeout_waiting_for_permissive; exit 1; }
logmsg selinux_permissive

if ! printf 'id -u\nexit\n' | toybox nc -w 2 127.0.0.1 "$ROOT_PORT" 2>/dev/null | grep -q '^0'; then
    toybox nc -s 127.0.0.1 -p "$ROOT_PORT" -L /system/bin/sh -l 2>/dev/null &
fi

listener=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if printf 'id -u\nexit\n' | toybox nc -w 2 127.0.0.1 "$ROOT_PORT" 2>/dev/null | grep -q '^0'; then
        listener=1
        break
    fi
    sleep 1
done
[ "$listener" = 1 ] || { logmsg root_listener_failed; exit 1; }

magisk=skipped
if [ -x "$SNS/magisk_restore.sh" ]; then
    out=$(printf 'sh %s/magisk_restore.sh start\nexit\n' "$SNS" |
        toybox nc -w 90 127.0.0.1 "$ROOT_PORT" 2>/dev/null)
    case "$out" in *__SNU_MAGISK_OK__*) magisk=ok ;; *) magisk=failed ;; esac
fi
printf '%s\n' "ok magisk=$magisk" >"$STATE/last_result" 2>/dev/null
logmsg "ok listener=uid0 magisk=$magisk"
exit 0
