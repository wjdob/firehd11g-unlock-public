#!/bin/sh
set -eu

# PS7319 adaptation: stage the carrier assets into the webview app's own
# data directory via a listener spawned as that app's uid (10161) with the
# amazonapp seinfo. The upstream path (/data/securedStorageLocation/, written
# by a uid-1000 system_app channel) is not writable by system_app on PS7319
# (SELinux neverallow appdomain system_data_file write).
#
# The carrier host is com.amazon.webview.chromium (uid 10161, amazon_app
# domain) - the same app whose class the agent uses as its main class.
# Same uid + same domain = full read/write to its own app_data_file dir.

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
adb_bin="${ADB:-$repo_dir/tools/adb-portable.sh}"
carrier_host_pkg=com.amazon.webview.chromium
asset_dir="${SNUSNU_ASSET_DIR:-/data/user/0/$carrier_host_pkg/files/sn}"
prebuilt_dir="$repo_dir/prebuilt/device/arm64-v8a"
prebuilt32_dir="$repo_dir/prebuilt/device/armeabi-v7a"
staging_port=4322
action="${1:-install}"

adb() { timeout 30 "$adb_bin" "$@"; }
die() { echo "FATAL: $*" >&2; exit 1; }

# Cross-version carrier selection (carriers.tsv is the single source of
# truth). The staged libhwbinder_target.so must be the variant matching
# the device's firmware: the NULL-write address differs per build.
. "$repo_dir/scripts/version_env.sh"
version_env_resolve "$repo_dir" || exit 1

# Cross-version: the staging listener runs as the webview app's uid,
# resolved at runtime (not guaranteed to be 10161 across firmware versions
# or factory data resets).
staging_uid="${SNUSNU_FORCE_CARRIER_UID:-}"
if [ -z "$staging_uid" ]; then
  staging_uid="$(adb shell pm list packages -U "$carrier_host_pkg" 2>&1 \
      | tr -d '\r' | sed -n 's/.*uid:\([0-9]*\).*/\1/p' | head -n1)"
fi
case "$staging_uid" in
  ''|*[!0-9]*) die "cannot resolve uid of $carrier_host_pkg" ;;
esac
echo "staging uid: $staging_uid"

host_file() {
    case "$1" in
        agent.jar) echo "$prebuilt_dir/agent.jar" ;;
        libcodex_jni.so) echo "$prebuilt_dir/libcodex_jni.so" ;;
        libhwbinder_target.so) echo "$SNU_CARRIER" ;;
        libhwbinder_target.arm64-v8a.so) echo "$SNU_CARRIER" ;;
        libhwbinder_target.armeabi-v7a.so) echo "$prebuilt32_dir/libhwbinder_target.so" ;;
        carrier_launcher.sh) echo "$repo_dir/scripts/carrier_launcher.sh" ;;
        *) die "unknown initial-root artifact: $1" ;;
    esac
}

device_digest() {
    # Must run through the uid-10161 listener: the shell domain cannot read
    # app_data_file, so a plain adb-side sha256sum reports absent.
    printf 'toybox sha256sum %s/%s\nexit\n' "$asset_dir" "$1" \
        | adb shell "toybox nc -w 10 127.0.0.1 $staging_port" 2>/dev/null \
        | tr -d '\r' | awk '{print $1}'
}

artifact_ready() {
    source="$(host_file "$1")"
    [ -s "$source" ] || die "missing initial-root artifact: $source"
    expected="$(sha256sum "$source" | awk '{print $1}')"
    actual="$(device_digest "$1")"
    [ "$actual" = "$expected" ]
}

verify_assets() {
    failed=0
    for name in agent.jar libcodex_jni.so libhwbinder_target.so \
        libhwbinder_target.arm64-v8a.so \
        libhwbinder_target.armeabi-v7a.so carrier_launcher.sh; do
        source="$(host_file "$name")"
        expected="$(sha256sum "$source" | awk '{print $1}')"
        actual="$(device_digest "$name")"
        if [ "$actual" = "$expected" ]; then
            echo "$name=ready sha256=$actual"
        else
            echo "$name=missing_or_mismatched expected=$expected actual=${actual:-absent}"
            failed=1
        fi
    done
    return "$failed"
}

# The staging listener runs as the webview app's runtime-resolved uid with
# the amazonapp seinfo, so it can write the app's own data dir.
#
# NOTE: verification MUST also go through the listener. Plain `adb shell`
# (shell domain) cannot read app_data_file, so a shell-side sha256sum always
# returns absent even when the file is present and correct (observed live:
# transfers verified, final verify reported all-absent).
ensure_staging_channel() {
    identity="$(printf 'id\nexit\n' | adb shell \
        "toybox nc -w 3 127.0.0.1 $staging_port" 2>/dev/null | tr -d '\r')"
    case "$identity" in *"uid=$staging_uid"*) return 0 ;; esac

    echo "starting uid-$staging_uid staging channel (consumes this boot's one-shot)"
    printf '%s' 1 > "${SNU_STAGING_MARKER:-/tmp/snu_staging_consumed}"
    {
        printf 'settings put global hidden_api_blacklist_exemptions "LClass1;->method1(\n'
        printf '10\n'
        printf -- '--runtime-args\n'
        printf -- '--setuid=%s\n' "$staging_uid"
        printf -- '--setgid=%s\n' "$staging_uid"
        printf -- '--runtime-flags=2049\n'
        printf -- '--mount-external-full\n'
        printf -- '--setgroups=3003\n'
        printf -- '--nice-name=codex-stage-webview\n'
        printf -- '--seinfo=amazonapp:targetSdkVersion=22:complete\n'
        printf -- '--invoke-with\n'
        printf 'toybox nc -s 127.0.0.1 -p %s -L /system/bin/sh -l;\n' "$staging_port"
        printf '"\n'
        printf 'settings delete global hidden_api_blacklist_exemptions\n'
    } | adb shell >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        identity="$(printf 'id\nexit\n' | adb shell \
            "toybox nc -w 3 127.0.0.1 $staging_port" 2>/dev/null | tr -d '\r')"
        case "$identity" in
            *"uid=$staging_uid"*)
                ctx="$(printf 'cat /proc/self/attr/current\nexit\n' | adb shell \
                    "toybox nc -w 3 127.0.0.1 $staging_port" 2>/dev/null | tr -d '\r')"
                case "$ctx" in
                    *amazon_app*) return 0 ;;
                    *) die "staging listener context is not amazon_app: $ctx" ;;
                esac
                ;;
        esac
        sleep 1
    done
    die "could not start uid-$staging_uid staging channel (one-shot may be spent; reboot and retry)"
}

emit_file() {
    target="$1"
    source="$2"
    encoded="$target.new.b64"
    decoded="$target.new"
    printf ': > %s\n' "$encoded"
    base64 "$source" | tr -d '\n' | fold -w 512 \
        | while IFS= read -r chunk || [ -n "$chunk" ]; do
        printf "printf '%%s' '%s' >> %s\n" "$chunk" "$encoded"
    done
    printf 'toybox base64 -d %s > %s && chmod 0555 %s && rm -f %s\n' \
        "$encoded" "$decoded" "$decoded" "$encoded"
}

install_artifact() {
    name="$1"
    source="$(host_file "$name")"
    target="$asset_dir/$name"
    expected="$(sha256sum "$source" | awk '{print $1}')"
    if artifact_ready "$name"; then
        echo "$name=already_current"
        return 0
    fi

    echo "installing $name"
    output="$({
        emit_file "$target" "$source"
        printf 'test "$(toybox sha256sum %s.new | cut -d" " -f1)" = %s && mv -f %s.new %s && sync\n' \
            "$target" "$expected" "$target" "$target"
        printf 'toybox sha256sum %s\nexit\n' "$target"
    } | timeout 180 "$adb_bin" shell \
        "toybox nc -w 150 127.0.0.1 $staging_port" 2>&1 | tr -d '\r')"
    case "$output" in
        *"$expected"*) : ;;
        *) die "transfer verification failed for $name: $output" ;;
    esac
}

case "$action" in
    verify)
        verify_assets
        ;;
    install)
        if verify_assets >/dev/null 2>&1; then
            verify_assets
            exit 0
        fi
        ensure_staging_channel
        printf 'mkdir -p %s; chmod 0755 %s\nexit\n' "$asset_dir" "$asset_dir" \
            | adb shell "toybox nc -w 10 127.0.0.1 $staging_port" >/dev/null
        for name in agent.jar libcodex_jni.so libhwbinder_target.so \
            libhwbinder_target.arm64-v8a.so \
            libhwbinder_target.armeabi-v7a.so carrier_launcher.sh; do
            install_artifact "$name"
        done
        verify_assets || die "initial-root asset verification failed"
        ;;
    *)
        die "usage: $0 [install|verify]"
        ;;
esac