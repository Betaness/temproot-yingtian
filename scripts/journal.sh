#!/usr/bin/env bash
# journal.sh - crash/reboot-proof work journal.
#
# Three layers, because a reboot kills the PalmCode environment this shell runs in:
#   1. journal/SESSION.log         inside the repo (tracked by git)
#   2. /sdcard/temproot-journal/   readable without the proot environment
#   3. GitHub                      survives a data wipe
#
# Usage:
#   ./scripts/journal.sh add "what happened"
#   ./scripts/journal.sh show [n]
#   ./scripts/journal.sh push            commit + push the journal to GitHub
#   ./scripts/journal.sh state           machine state + last entries
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/journal/SESSION.log"
MIRROR="/sdcard/temproot-journal/SESSION.log"
REPO_SLUG="Betaness/temproot-yingtian"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

append() {
    local msg="$1"
    mkdir -p "$(dirname "$LOG")"
    printf '%s  %s\n' "$(ts)" "$msg" >> "$LOG"
    mkdir -p "$(dirname "$MIRROR")" 2>/dev/null && printf '%s  %s\n' "$(ts)" "$msg" >> "$MIRROR" 2>/dev/null
    echo "logged: $msg"
}

case "${1:-}" in
add)   append "${2:?message required}" ;;
show)  tail -n "${2:-40}" "$LOG" 2>/dev/null || echo "no journal yet" ;;
push)
    cd "$ROOT" || exit 1
    unset GIT_CONFIG_COUNT GIT_CONFIG_VALUE_0 GIT_CONFIG_KEY_0
    git add journal scripts docs native app 2>/dev/null
    git commit -q -m "journal: $(ts)" 2>/dev/null || echo "(nothing to commit)"
    tok=$(gh auth token 2>/dev/null | tr -d '\n')
    if [ -n "$tok" ]; then
        git push -q "https://Betaness:${tok}@github.com/${REPO_SLUG}.git" HEAD:main && echo "pushed to github"
    else
        echo "no gh token; journal kept locally and on /sdcard"
    fi
    ;;
state)
    echo "== host =="; uname -a; id
    echo "== device =="
    adb shell 'getprop ro.build.fingerprint; getprop ro.boot.verifiedbootstate; getprop ro.boot.slot_suffix; getprop sys.boot_completed; getenforce; uname -r; cut -d" " -f1 /proc/uptime' 2>/dev/null | tr -d '\r'
    echo "== repo =="; cd "$ROOT" && git log --oneline -3 && git status --short | head -5
    echo "== last journal =="; tail -n 12 "$LOG" 2>/dev/null
    ;;
*) echo "usage: $0 {add|show|push|state}" ; exit 2 ;;
esac
