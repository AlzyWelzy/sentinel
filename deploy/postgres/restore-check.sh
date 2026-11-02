#!/bin/sh
# Proves a dump restores: loads it into a scratch database next to the real
# one, checks the schema version and that the core tables came back, then
# drops the scratch database.
#
#   restore-check.sh /backups/sentinel-YYYYmmdd-HHMM.dump
#
# Exit status 0 means the dump is good. Run by backup.sh after every dump,
# and by hand before relying on an old one.
set -eu
dump=$1
db=sentinel_restore_check
export PGPASSWORD="$POSTGRES_PASSWORD"
psql_() { psql -h postgres -U sentinel -v ON_ERROR_STOP=1 -Atq "$@"; }

psql_ -d postgres -c "DROP DATABASE IF EXISTS $db"
psql_ -d postgres -c "CREATE DATABASE $db"
trap 'psql_ -d postgres -c "DROP DATABASE IF EXISTS $db" >/dev/null 2>&1 || true' EXIT

# --no-owner: roles are cluster-wide and already exist; privileges aren't
# what's being checked.
pg_restore -h postgres -U sentinel -d "$db" --no-owner --no-privileges --exit-on-error "$dump"

live=$(psql_ -d sentinel -c "SELECT version_num FROM alembic_version")
restored=$(psql_ -d "$db" -c "SELECT version_num FROM alembic_version")
[ "$live" = "$restored" ] || { echo "restore check: schema $restored, live is $live" >&2; exit 1; }

# Each core table must come back, and must not come back empty when the
# live one has rows (counts can legitimately differ: rows change after the
# dump).
for t in tenants users tenant_members hosts alert_rules notification_channels; do
    r=$(psql_ -d "$db" -c "SELECT count(*) FROM $t")
    l=$(psql_ -d sentinel -c "SELECT count(*) FROM $t")
    if [ "$l" -gt 0 ] && [ "$r" -eq 0 ]; then
        echo "restore check: $t came back empty ($l rows live)" >&2
        exit 1
    fi
done
echo "restore check: $(basename "$dump") restores (schema $restored)"
