#!/bin/sh
# Copies every local backup (Postgres dumps, ClickHouse backups,
# VictoriaMetrics snapshots) to a Cloud Storage bucket, so they survive
# losing the server. The bucket deletes objects after 30 days.
# From cron nightly, after the other backups:
#   45 4 * * *  /srv/sentinel/offsite-backup.sh gs://<bucket>
set -eu
bucket=${1:?usage: offsite-backup.sh gs://bucket}
v=/var/lib/docker/volumes
for vol in sentinel_pg-backups sentinel_clickhouse-backups; do
	[ -d "$v/$vol/_data" ] && gcloud storage rsync -r "$v/$vol/_data" "$bucket/$vol" --quiet
done
[ -d "${VM_BACKUP_DEST:-/srv/sentinel-backups/vm}" ] &&
	gcloud storage rsync -r "${VM_BACKUP_DEST:-/srv/sentinel-backups/vm}" "$bucket/vm-backups" --quiet
echo "offsite $(date -u +%FT%TZ) ok"
