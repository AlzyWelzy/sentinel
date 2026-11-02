#!/bin/sh
# Nightly logical backup of Sentinel's database (accounts, rules, incidents,
# status pages...). Metrics, logs and traces live in VictoriaMetrics,
# VictoriaLogs and Tempo and age out by retention; this is the part that
# can't be rebuilt.
#
#   BACKUP_EVERY_SECONDS  how often (86400)
#   BACKUP_KEEP_DAYS      how long dumps are kept (7)
#
# Restore one into a fresh database:
#   docker exec -i <postgres container> pg_restore -U sentinel -d sentinel --clean --if-exists < sentinel-YYYYmmdd-HHMM.dump
set -u
EVERY=${BACKUP_EVERY_SECONDS:-86400}
KEEP=${BACKUP_KEEP_DAYS:-7}
mkdir -p /backups
while :; do
    ts=$(date -u +%Y%m%d-%H%M)
    out=/backups/sentinel-$ts.dump
    if PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h postgres -U sentinel -Fc sentinel >"$out.tmp"; then
        mv "$out.tmp" "$out"
        echo "backup $ts: $(du -h "$out" | cut -f1)"
    else
        # e.g. postgres still starting with the stack: try again soon, not
        # a whole interval later
        rm -f "$out.tmp"
        echo "backup $ts failed; retrying in 60s" >&2
        sleep 60
        continue
    fi
    find /backups -name 'sentinel-*.dump' -mtime +"$KEEP" -delete
    sleep "$EVERY"
done
