#!/bin/sh
set -eu

elf_class_file() {
    file="$1"
    magic="$(od -An -t u1 -N 5 "$file" 2>/dev/null | tr -s ' ' | sed 's/^ //')"
    case "$magic" in
        "127 69 76 70 1") echo ELF32 ;;
        "127 69 76 70 2") echo ELF64 ;;
        *) echo UNKNOWN ;;
    esac
}

abi_for_elf_class() {
    case "$1" in
        ELF32) echo armeabi-v7a ;;
        ELF64) echo arm64-v8a ;;
        *) return 1 ;;
    esac
}

select_payload() {
    class="$1"
    root="$2"
    abi="$(abi_for_elf_class "$class")" || return 1
    payload="$root/$abi/libhwbinder_target.so"
    [ -s "$payload" ] || return 2
    [ "$(elf_class_file "$payload")" = "$class" ] || return 3
    printf '%s\n' "$payload"
}

carrier_identity_reset() {
    CARRIER_UID=
    CARRIER_PID=
    CARRIER_CONTEXT=
    CARRIER_GROUPS=
    CARRIER_ELF=
    CARRIER_ABI=
    CARRIER_JNI=
    CARRIER_VALIDATION_ERROR=
}

carrier_identity_field() {
    key="$1"
    value="$2"
    case "$key" in
        uid) CARRIER_UID="$value" ;;
        pid) CARRIER_PID="$value" ;;
        context) CARRIER_CONTEXT="$value" ;;
        groups) CARRIER_GROUPS="$(printf '%s' "$value" | tr ',' ' ')" ;;
        elf) CARRIER_ELF="$value" ;;
        abi) CARRIER_ABI="$value" ;;
        jni) CARRIER_JNI="$value" ;;
    esac
}

carrier_parse_identity() {
    identity="$1"
    carrier_identity_reset
    case "$identity" in
        IDV2*)
            tab="$(printf '\tX')"; tab="${tab%X}"
            old_ifs="$IFS"; IFS="$tab"
            set -- $identity
            IFS="$old_ifs"
            shift
            for field in "$@"; do
                key="${field%%=*}"
                value="${field#*=}"
                [ "$key" != "$field" ] && carrier_identity_field "$key" "$value"
            done
            ;;
        *)
            CARRIER_UID="$(printf '%s\n' "$identity" | sed -n 's/^uid=\([0-9][0-9]*\) .*/\1/p')"
            CARRIER_PID="$(printf '%s\n' "$identity" | sed -n 's/.* pid=\([0-9][0-9]*\) .*/\1/p')"
            CARRIER_CONTEXT="$(printf '%s\n' "$identity" | sed -n 's/.* context=\([^ ]*\) .*/\1/p')"
            CARRIER_ELF="$(printf '%s\n' "$identity" | sed -n 's/.* elf=\([^ ]*\).*/\1/p')"
            CARRIER_ABI="$(printf '%s\n' "$identity" | sed -n 's/.* abi=\([^ ]*\).*/\1/p')"
            CARRIER_JNI="$(printf '%s\n' "$identity" | sed -n 's/.* jni=\([^ ]*\).*/\1/p')"
            case "$identity" in
                *Groups:*)
                    group_tail="${identity#*Groups:}"
                    group_text="${group_tail% elf=*}"
                    CARRIER_GROUPS="$(printf '%s' "$group_text" | tr '=,:\t' '    ')"
                    ;;
            esac
            ;;
    esac
}

carrier_has_group() {
    wanted="$1"
    for group in $CARRIER_GROUPS; do
        [ "$group" = "$wanted" ] && return 0
    done
    return 1
}

carrier_validation_fail() {
    CARRIER_VALIDATION_ERROR="$1"
    return 0
}

carrier_validate_identity() {
    identity="$1"
    asset_dir="$2"
    carrier_parse_identity "$identity"
    # The carrier runs as the webview app's own uid (runtime-resolved by the
    # caller and exported as SNU_EXPECTED_CARRIER_UID) so it can traverse the
    # app's 0700 data dir where the assets are staged. Upstream used 10100
    # with assets in /data/securedStorageLocation.
    expected_uid="${SNU_EXPECTED_CARRIER_UID:-}"
    if [ -n "$expected_uid" ] && [ "$CARRIER_UID" != "$expected_uid" ]; then
        carrier_validation_fail "UID must be $expected_uid (reported=${CARRIER_UID:-missing})"
        return 1
    fi
    case "$CARRIER_PID" in
        ''|*[!0-9]*|0) carrier_validation_fail "invalid PID (reported=${CARRIER_PID:-missing})"; return 1 ;;
    esac
    if [ "$CARRIER_CONTEXT" != u:r:amazon_app:s0 ]; then
        carrier_validation_fail "SELinux context must be u:r:amazon_app:s0 (reported=${CARRIER_CONTEXT:-missing})"
        return 1
    fi
    if ! carrier_has_group 3003; then
        carrier_validation_fail "missing supplementary group 3003"
        return 1
    fi
    expected_abi="$(abi_for_elf_class "$CARRIER_ELF" 2>/dev/null)" \
        || { carrier_validation_fail "invalid ELF class (reported=${CARRIER_ELF:-missing})"; return 1; }
    if [ "$CARRIER_ABI" != "$expected_abi" ]; then
        carrier_validation_fail "ABI/ELF mismatch (elf=$CARRIER_ELF abi=${CARRIER_ABI:-missing})"
        return 1
    fi
    expected_jni="$asset_dir/libhwbinder_target.$expected_abi.so"
    if [ "$CARRIER_JNI" != "$expected_jni" ]; then
        carrier_validation_fail "ABI/JNI mismatch (abi=$CARRIER_ABI jni=${CARRIER_JNI:-missing})"
        return 1
    fi
    return 0
}
