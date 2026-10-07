#!/system/bin/sh
# UID-0/time_update half of the persistent boot chain.  The installed direct-
# boot app performs the framework work, re-arms the trigger, and flips SELinux;
# this deliberately restricted process only waits and restores the root runtime.

SNS=/data/securedStorageLocation/snusnu
STATE="$SNS/state"
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
for i in $(seq 1 180); do
    [ "$(getenforce 2>/dev/null)" = Permissive ] && { permissive=1; break; }
    sleep 1
done
[ "$permissive" = 1 ] || { logmsg timeout_waiting_for_permissive; exit 1; }
logmsg selinux_permissive

mkdir -p "$STATE" /data/local/tmp/rootsvc 2>/dev/null
chmod 0777 "$STATE" /data/local/tmp/rootsvc 2>/dev/null
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
