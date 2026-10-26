#!/bin/sh
# version_env.sh: resolve the device's firmware variant and export the
# carrier-selection environment for the root chain.
#
# Single source of truth: stage1-root/carriers/carriers.tsv
#   PS-token <TAB> variant-key <TAB> selinux_enforcing <TAB> carrier-sha256
#
# Resolution order (first match wins):
#   1. SNUSNU_FORCE_VARIANT: explicit override (testing/recovery)
#   2. the device's ro.build.id PS token, prefix-matched against the tsv
#
# Exports on success:
#   SNU_PS_TOKEN     e.g. PS7319
#   SNU_VARIANT      variant key (carriers/<key>/libhwbinder_target.so)
#   SNU_SELINUX_ADDR selinux_enforcing VA for the device's build
#   SNU_CARRIER      host path to the selected carrier .so
#   SNU_CARRIER_SHA  expected sha256 (staging verifies against it)
#
# Fails (exit 1) with a remediation message when the device's build is not
# in the registry: the chain must NOT proceed with an unverified address.

version_env_resolve() {
    repo_dir="${1:?repo_dir required}"
    tsv="$repo_dir/../carriers/carriers.tsv"
    [ -f "$tsv" ] || { echo "FATAL: carrier registry missing: $tsv" >&2; return 1; }
    # Strip CR so a CRLF checkout (Windows core.autocrlf) parses identically
    # to an LF checkout; the last column is a hash and must not carry '\r'.
    tsv_lf="$(tr -d '\r' < "$tsv")"

    build_id="$(adb shell getprop ro.build.id 2>&1 | tr -d '\r')"
    # The full build id is kept alongside the PS token: the token selects a
    # carrier family, but the kernel address is a property of the exact build.
    # ro.build.version.incremental is the build number the compatibility matrix
    # in README.md is keyed on.
    full_build_id="$(adb shell getprop ro.build.version.incremental 2>&1 | tr -d '\r')"
    token=""
    case "$build_id" in
        PS*) token="${build_id%%.*}" ;;   # PS7326.3178N -> PS7326
    esac
    [ -n "$token" ] || { echo "FATAL: unrecognized ro.build.id: $build_id" >&2; return 1; }

    variant="${SNUSNU_FORCE_VARIANT:-}"
    addr=""; sha=""; verified=""
    if [ -n "$variant" ]; then
        while IFS="$(printf '\t')" read -r tok var adr sh ver; do
            case "$tok" in \#*|"") continue ;; esac
            if [ "$var" = "$variant" ]; then addr="$adr"; sha="$sh"; verified="$ver"; break; fi
        done <<EOF
$tsv_lf
EOF
        [ -n "$addr" ] || { echo "FATAL: SNUSNU_FORCE_VARIANT=$variant not in registry" >&2; return 1; }
    else
        while IFS="$(printf '\t')" read -r tok var adr sh ver; do
            case "$tok" in \#*|"") continue ;; esac
            if [ "$tok" = "$token" ]; then variant="$var"; addr="$adr"; sha="$sh"; verified="$ver"; break; fi
        done <<EOF
$tsv_lf
EOF
        [ -n "$addr" ] || {
            echo "FATAL: firmware $token is not in the carrier registry." >&2
            echo "The kernel write targets selinux_enforcing, whose address" >&2
            echo "differs per build; proceeding with an unverified address" >&2
            echo "would corrupt unrelated kernel memory." >&2
            echo "" >&2
            echo "Remediation: obtain the OTA for your build and run:" >&2
            echo "  python stage1-root/make-carrier.py --ota <update-kindle-*.bin>" >&2
            echo "then register it per stage1-root/carriers/carriers.tsv." >&2
            return 1
        }
    fi

    # Exact-build gate.
    #
    # The PS token selects an address FAMILY; the address itself belongs to the
    # exact kernel build. PS7319/1726 and PS7319/1735 share the token, and their
    # addresses happened to match -- established by dumping the running kernel,
    # not assumed. So a token match alone must not authorise the write: any
    # unlisted incremental has to be analysed and registered first.
    #
    # SNUSNU_FORCE_VARIANT is the deliberate escape hatch (testing/recovery) and
    # skips this, because naming a variant is already an explicit act.
    # SNUSNU_ALLOW_UNVERIFIED_BUILD=1 is the looser one, for finishing a live
    # bring-up on a build whose address was derived but not yet boot-verified.
    if [ -z "${SNUSNU_FORCE_VARIANT:-}" ] && [ "${SNUSNU_ALLOW_UNVERIFIED_BUILD:-0}" != "1" ]; then
        case ",$verified," in
            *",$full_build_id,"*) : ;;
            *)
                echo "FATAL: build '$full_build_id' ($token) is not verified for variant $variant." >&2
                echo "" >&2
                echo "  ro.build.id  : $build_id" >&2
                echo "  incremental  : $full_build_id" >&2
                echo "  variant      : $variant" >&2
                echo "  live-verified: $(if [ -n "$verified" ]; then echo "$verified"; else echo '<none registered>'; fi)" >&2
                echo "" >&2
                echo "  selinux_enforcing is a property of the exact kernel build, and" >&2
                echo "  the PS token only identifies a family -- two increments can share" >&2
                echo "  a token and still differ. Writing an unverified address can" >&2
                echo "  corrupt unrelated kernel memory." >&2
                echo "" >&2
                echo "  Remediation: derive and register this build's address:" >&2
                echo "    python stage1-root/make-carrier.py --ota <update-kindle-*.bin>" >&2
                echo "  then add its incremental to the verified-incrementals column in" >&2
                echo "    stage1-root/carriers/carriers.tsv" >&2
                echo "" >&2
                echo "  To proceed deliberately without that (logged as unverified):" >&2
                echo "    SNUSNU_ALLOW_UNVERIFIED_BUILD=1 $0 $*" >&2
                return 1
                ;;
        esac
    elif [ "${SNUSNU_ALLOW_UNVERIFIED_BUILD:-0}" = "1" ] && [ -z "${SNUSNU_FORCE_VARIANT:-}" ]; then
        echo "WARNING: SNUSNU_ALLOW_UNVERIFIED_BUILD=1 - proceeding without the" >&2
        echo "         exact-build check (incremental '$full_build_id')." >&2
    fi

    carrier="$repo_dir/../carriers/$variant/libhwbinder_target.so"
    [ -f "$carrier" ] || { echo "FATAL: carrier variant missing: $carrier" >&2; return 1; }
    actual="$(sha256sum "$carrier" | awk '{print $1}')"
    [ "$actual" = "$sha" ] || {
        echo "FATAL: carrier hash mismatch for $variant:" >&2
        echo "  registry: $sha" >&2
        echo "  actual:   $actual" >&2
        return 1
    }

    SNU_PS_TOKEN="$token"
    SNU_VARIANT="$variant"
    SNU_SELINUX_ADDR="$addr"
    SNU_CARRIER="$carrier"
    SNU_CARRIER_SHA="$sha"
    # Exported so callers can key local state on the exact build rather than on
    # the PS token alone: two increments can share a token and still need
    # different selinux_enforcing addresses.
    SNU_BUILD_ID="$build_id"
    SNU_FULL_BUILD_ID="$full_build_id"
    export SNU_PS_TOKEN SNU_VARIANT SNU_SELINUX_ADDR SNU_CARRIER SNU_CARRIER_SHA \
           SNU_BUILD_ID SNU_FULL_BUILD_ID
    echo "carrier variant: $token -> $variant (selinux_enforcing=$addr)"
}
