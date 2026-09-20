#!/bin/bash
set -euo pipefail

NSNCD_BIN="${NSNCD_BIN:-/usr/lib/nsncd}"
SOCKET=/var/run/nscd/socket
ENTERED=/tmp/nsncd-test-entered
RELEASE=/tmp/nsncd-test-release
LOG=/tmp/nsncd-worker-saturation.log
BLOCKED_OUT=/tmp/nsncd-blocked-lookup.out

NSNCD_PID=
BLOCKED_PID=

gcc -Wall -Wextra -o /tmp/nsncd-connect ci/connect_nscd.c

cleanup() {
    touch "$RELEASE" 2>/dev/null || true

    if [ -n "${BLOCKED_PID:-}" ]; then
        kill "$BLOCKED_PID" 2>/dev/null || true
        wait "$BLOCKED_PID" 2>/dev/null || true
    fi

    if [ -n "${NSNCD_PID:-}" ]; then
        kill "$NSNCD_PID" 2>/dev/null || true
        wait "$NSNCD_PID" 2>/dev/null || true
    fi

    rm -f "$ENTERED" "$RELEASE" "$BLOCKED_OUT" /tmp/nsncd-connect
}

trap cleanup EXIT

wait_for_file() {
    path=$1
    attempts=${2:-500}

    i=0
    while [ ! -e "$path" ]; do
        i=$((i + 1))
        if [ "$i" -ge "$attempts" ]; then
            echo "timed out waiting for $path" >&2
            return 1
        fi
        sleep 0.01
    done
}

wait_for_socket() {
    attempts=500

    i=0
    while [ ! -S "$SOCKET" ]; do
        i=$((i + 1))
        if [ "$i" -ge "$attempts" ]; then
            echo "timed out waiting for $SOCKET" >&2
            return 1
        fi

        if ! kill -0 "$NSNCD_PID" 2>/dev/null; then
            echo "nsncd exited before creating its socket" >&2
            cat "$LOG" >&2 || true
            return 1
        fi

        sleep 0.01
    done
}

assert_nsncd_alive() {
    if ! kill -0 "$NSNCD_PID" 2>/dev/null; then
        echo "nsncd exited unexpectedly" >&2
        cat "$LOG" >&2 || true
        exit 1
    fi
}

rm -f "$ENTERED" "$RELEASE" "$LOG" "$BLOCKED_OUT" "$SOCKET"

NSNCD_WORKER_COUNT=1 \
NSNCD_HANDOFF_TIMEOUT=1 \
"$NSNCD_BIN" >"$LOG" 2>&1 &
NSNCD_PID=$!

wait_for_socket
assert_nsncd_alive

echo "starting lookup that blocks the only worker"

getent passwd whatami_block >"$BLOCKED_OUT" &
BLOCKED_PID=$!

wait_for_file "$ENTERED"

if ! kill -0 "$BLOCKED_PID" 2>/dev/null; then
    echo "blocking lookup exited before release" >&2
    cat "$BLOCKED_OUT" >&2 || true
    exit 1
fi

echo "worker is blocked"

#
# Open another connection while the only worker is occupied. The acceptor
# cannot hand it to the zero-capacity worker channel, so this must exercise
# the handoff timeout.
#
/tmp/nsncd-connect &
SATURATED_PID=$!

wait "$SATURATED_PID"

grep -q "timed out waiting for an available worker" "$LOG" || {
    echo "did not observe worker handoff timeout" >&2
    cat "$LOG" >&2
    exit 1
}

echo "handoff timeout observed"

if grep -q "shutting down" "$LOG"; then
    echo "nsncd began shutting down after worker saturation" >&2
    cat "$LOG" >&2
    exit 1
fi

assert_nsncd_alive

echo "nsncd remained operational after worker saturation"

touch "$RELEASE"

wait "$BLOCKED_PID"
BLOCKED_PID=

grep -q '^whatami:' "$BLOCKED_OUT" || {
    echo "blocked lookup did not complete successfully" >&2
    cat "$BLOCKED_OUT" >&2 || true
    exit 1
}

echo "blocked lookup recovered"

RECOVERY="$(getent passwd whatami)"

echo "$RECOVERY" | grep -q '^whatami:' || {
    echo "post-saturation lookup failed" >&2
    cat "$LOG" >&2 || true
    exit 1
}

assert_nsncd_alive

echo "post-saturation lookup succeeded"
echo "PASS: nsncd survives worker saturation and recovers"
