#!/bin/sh
# IPDR evidence backups: a full backup on Sundays, an incremental on top of
# the latest full every other day; two full chains kept. Each new backup is
# restored into a scratch database and its row counts compared, so a backup
# that can't be restored is noticed the day it's made.
#
#   15 2 * * * cd /srv/sentinel && ./clickhouse-backup.sh >>clickhouse-backup.log 2>&1
#
# Copy /var/lib/docker/volumes/sentinel_clickhouse-backups off the server
# with the Postgres dumps (DEPLOYMENT.md, Backups).
set -eu
set -a
. ./prod.env
set +a
c=$(docker ps -qf name=sentinel_clickhouse | head -n1)
[ -n "$c" ] || { echo "$(date -u +%FT%TZ) clickhouse isn't running"; exit 1; }
q() { docker exec -i "$c" clickhouse-client --user sentinel --password "$CLICKHOUSE_PASSWORD" --query "$1"; }
day=$(date -u +%Y%m%d)
latest_full=$(docker exec "$c" sh -c 'ls -1d /backups/full-* 2>/dev/null | sort | tail -n1 | xargs -r basename')
if [ "$(date -u +%u)" = 7 ] || [ -z "$latest_full" ]; then
	name="full-$day"
	q "BACKUP DATABASE sentinel TO Disk('backups', '$name')" >/dev/null
else
	name="incr-$day"
	q "BACKUP DATABASE sentinel TO Disk('backups', '$name') SETTINGS base_backup = Disk('backups', '$latest_full')" >/dev/null
fi
# Prove it restores.
q "DROP DATABASE IF EXISTS sentinel_restore_check SYNC"
q "RESTORE DATABASE sentinel AS sentinel_restore_check FROM Disk('backups', '$name')" >/dev/null
for t in fw_sessions flows syslog ip_users mac_table; do
	a=$(q "SELECT count() FROM sentinel.$t WHERE received_at < now() - INTERVAL 10 MINUTE")
	b=$(q "SELECT count() FROM sentinel_restore_check.$t WHERE received_at < now() - INTERVAL 10 MINUTE")
	if [ "$b" -lt "$a" ]; then
		echo "$(date -u +%FT%TZ) RESTORE CHECK FAILED: $name $t has $b rows, live has $a"
		q "DROP DATABASE sentinel_restore_check SYNC"
		exit 1
	fi
done
q "DROP DATABASE sentinel_restore_check SYNC"
# Two full chains: drop fulls older than the newest two, and their increments.
docker exec "$c" sh -c '
	keep=$(ls -1d /backups/full-* | sort | tail -n2 | head -n1 | xargs basename | cut -d- -f2)
	for d in /backups/full-* /backups/incr-*; do
		[ -e "$d" ] || continue
		[ "$(basename "$d" | cut -d- -f2)" -lt "$keep" ] && rm -rf "$d"
	done; true'
echo "$(date -u +%FT%TZ) $name done and restored"
