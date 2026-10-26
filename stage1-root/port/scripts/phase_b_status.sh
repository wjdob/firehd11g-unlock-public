#!/bin/sh

PHASE_B_PRECHECK=20
PHASE_B_CARRIER_START=21
PHASE_B_VALIDATION=22
PHASE_B_STATEFUL_SPENT=30
PHASE_B_WAITER_STATE=40
PHASE_B_POST_WRITE=50

phase_b_failure_name() {
    case "$1" in
        "$PHASE_B_PRECHECK") echo pre_exploit ;;
        "$PHASE_B_CARRIER_START") echo carrier_start ;;
        "$PHASE_B_VALIDATION") echo carrier_validation ;;
        "$PHASE_B_STATEFUL_SPENT") echo stateful_spent ;;
        "$PHASE_B_WAITER_STATE") echo waiter_state ;;
        "$PHASE_B_POST_WRITE") echo post_write ;;
        *) echo unknown ;;
    esac
}

phase_b_retry_action() {
    case "$1" in
        "$PHASE_B_STATEFUL_SPENT") echo RETRY_FRESH_BOOT ;;
        "$PHASE_B_PRECHECK"|"$PHASE_B_CARRIER_START"|"$PHASE_B_VALIDATION"|\
        "$PHASE_B_WAITER_STATE"|"$PHASE_B_POST_WRITE") echo ABORT ;;
        *) echo ABORT ;;
    esac
}

waiter_state_for_value() {
    value="$1"
    trigger="$2"
    if [ "$value" = "$trigger" ]; then
        echo ARMED
    else
        case "$value" in
            ''|*[!0-9]*) echo "INVALID($value)" ;;
            *) echo "NUMERIC($value)" ;;
        esac
    fi
}
