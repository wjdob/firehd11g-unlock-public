#!/system/bin/sh

SNS=/data/securedStorageLocation/snusnu
DISABLE_SENTINEL="$SNS/disable"

log -t REROOTWAIT "started uid=$(id -u) ctx=$(cat /proc/self/attr/current)"
if [ -e "$DISABLE_SENTINEL" ]; then
    log -t REROOTWAIT "disabled by sentinel"
    exit 0
fi

/system/bin/sh "$SNS/waiter.sh"
rc=$?
log -t REROOTWAIT "waiter.sh rc=$rc"
exit "$rc"
