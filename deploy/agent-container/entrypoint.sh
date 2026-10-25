#!/bin/sh
# Runs the agent unprivileged and keeps it current (see the Dockerfile).
#
#   PULSEGRID_URL, PULSEGRID_KEY  register on first start (then unused)
#   PULSEGRID_TAGS                tags to register with, e.g. web,production
#   PULSEGRID_UPDATE_INTERVAL     seconds between update checks (3600)
set -eu

BIN=/usr/local/bin/pulsegrid-agent
STATE=/var/lib/pulsegrid
RUN_AS=pulsegrid
EVERY=${PULSEGRID_UPDATE_INTERVAL:-3600}

chown -R "$RUN_AS" "$STATE"
if [ ! -s "$STATE/state.json" ]; then
    : "${PULSEGRID_URL:?set PULSEGRID_URL and PULSEGRID_KEY to register this agent}"
    : "${PULSEGRID_KEY:?set PULSEGRID_URL and PULSEGRID_KEY to register this agent}"
    su-exec "$RUN_AS" "$BIN" register --url "$PULSEGRID_URL" --key "$PULSEGRID_KEY" \
        --tags "${PULSEGRID_TAGS:-}" --state-dir "$STATE"
fi

pid=""
start() {
    su-exec "$RUN_AS" "$BIN" run --state-dir "$STATE" &
    pid=$!
}
stop() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
update() {
    before=$("$BIN" version)
    "$BIN" update --state-dir "$STATE" || echo "update check failed; trying again later" >&2
    [ "$("$BIN" version)" != "$before" ]
}
trap 'stop; exit 0' TERM INT

update || true
start
while :; do
    waited=0
    while [ "$waited" -lt "$EVERY" ]; do
        sleep 30 &
        wait $! || true
        waited=$((waited + 30))
        # The agent exited on its own: start it again.
        kill -0 "$pid" 2>/dev/null || start
    done
    if update; then
        stop
        start
    fi
done
