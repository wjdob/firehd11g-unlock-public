#!/system/bin/sh
# Does an in-boot carrier retry ever succeed after an ENODATA miss?
#
# reroot_after_boot.sh asserts "in-boot carrier respawn cannot clear
# ENODATA/EALREADY", and docs/ENODATA-ANALYSIS.md repeats it, so stage 4's boot
# actor attempts the carrier exactly once per boot and a miss costs a full reboot.
# That claim decides the whole reliability design: if a retry can succeed, the
# actor can simply loop; if it cannot, only per-boot probability matters.
#
# Run ON a boot whose first attempt already failed (Enforcing, channel on 4321).
# Sends this file to the channel's shell over the socket, so the caller is:
#     adb shell 'toybox nc -w 240 127.0.0.1 4321 < /data/local/tmp/<this>'
#
# Prints one line per attempt plus a verdict.
CARRIER=/data/snusnu_hwbinder_root
STATE=/data/cache/snusnu/state
TRIES=${TRIES:-8}

mkdir -p "$STATE" 2>/dev/null
out="$STATE/retry_probe.out"
rm -f "$out" 2>/dev/null

echo "retry-probe: uid=$(id -u) tries=$TRIES enforce=$(getenforce 2>&1)"
echo "retry-probe: carrier pre=$([ -x $CARRIER ] && echo executable || echo MISSING)"

success=
i=1
while [ "$i" -le "$TRIES" ]; do
    rm -f "$out" 2>/dev/null
    "$CARRIER" stateful-root-hold </dev/null >"$out" 2>&1 &
    keeper=$!
    # stateful-root-hold stays resident on success, so poll the marker rather
    # than waiting on exit; on failure it exits on its own.
    n=0
    while [ "$n" -lt 25 ]; do
        if grep -q __SNU_NATIVE_0__ "$out" 2>/dev/null; then break; fi
        if ! kill -0 "$keeper" 2>/dev/null; then break; fi
        sleep 1
        n=$((n + 1))
    done
    line=$(tr '\n' ';' <"$out" 2>/dev/null)
    case "$line" in
        *__SNU_NATIVE_0__*) success=$i ;;
    esac
    echo "attempt $i: $line"
    if [ -n "$success" ]; then
        kill "$keeper" 2>/dev/null
        break
    fi
    i=$((i + 1))
done

echo "retry-probe: enforce_after=$(getenforce 2>&1)"
if [ -n "$success" ]; then
    echo "VERDICT: IN_BOOT_RETRY_WORKS on attempt $success"
else
    echo "VERDICT: IN_BOOT_RETRY_DEAD ($TRIES attempts, none succeeded)"
fi
exit 0
