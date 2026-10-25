#!/usr/bin/env bash
# safety_preflight.sh - state snapshot / verification around any destructive run.
#
# Usage:
#   ./safety_preflight.sh snapshot [file]   record the current device state
#   ./safety_preflight.sh verify   [file]   compare against the snapshot
#   ./safety_preflight.sh guard             refuse to continue if the device is
#                                           not in a clean, verified-boot state
#
# Only reads properties and /proc; never writes a block device.
set -uo pipefail

ADB="${ADB:-adb}"
SNAP="${2:-/tmp/temproot-preflight.txt}"

collect() {
    $ADB shell 'getprop ro.build.fingerprint' | tr -d '\r'
    $ADB shell 'getprop ro.boot.verifiedbootstate' | tr -d '\r'
    $ADB shell 'getprop ro.boot.slot_suffix' | tr -d '\r'
    $ADB shell 'getprop sys.boot_completed' | tr -d '\r'
    $ADB shell getenforce | tr -d '\r'
    $ADB shell 'uname -r' | tr -d '\r'
    $ADB shell 'cut -d" " -f1 /proc/uptime' | tr -d '\r'
}

case "${1:-}" in
snapshot)
    collect > "$SNAP"
    echo "snapshot written to $SNAP"
    cat "$SNAP"
    ;;
verify)
    [ -f "$SNAP" ] || { echo "no snapshot at $SNAP"; exit 2; }
    now=$(collect)
    was=$(cat "$SNAP")
    fail=0
    # Uptime legitimately changes; compare the rest field by field.
    for i in 1 2 3 4 5 6; do
        a=$(echo "$was" | sed -n "${i}p")
        b=$(echo "$now" | sed -n "${i}p")
        [ "$a" = "$b" ] || { echo "DRIFT[field $i]: '$a' -> '$b'"; fail=1; }
    done
    if [ "$fail" -ne 0 ]; then
        echo "RESULT: state changed - stop and inspect before continuing"
        exit 1
    fi
    echo "RESULT: state identical (fingerprint / verified boot / slot / boot completed / selinux / kernel)"
    ;;
guard)
    fp=$($ADB shell 'getprop ro.build.fingerprint' | tr -d '\r')
    vb=$($ADB shell 'getprop ro.boot.verifiedbootstate' | tr -d '\r')
    bc=$($ADB shell 'getprop sys.boot_completed' | tr -d '\r')
    se=$($ADB shell getenforce | tr -d '\r')
    ok=1
    [ "$bc" = "1" ] || { echo "REFUSE: boot_completed=$bc"; ok=0; }
    [ "$se" = "Enforcing" ] || { echo "REFUSE: selinux=$se"; ok=0; }
    [ "$vb" = "green" ] || echo "WARN: verifiedbootstate=$vb (expected green on this unit)"
    case "$fp" in
        Xiaomi/yingtian/*) : ;;
        *) echo "REFUSE: unexpected fingerprint: $fp"; ok=0 ;;
    esac
    [ "$ok" -eq 1 ] && echo "GUARD: ok to continue (fingerprint $fp)"
    exit $((1 - ok))
    ;;
*)
    echo "usage: $0 {snapshot|verify|guard} [file]"; exit 2 ;;
esac
