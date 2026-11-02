#!/bin/sh
# Backs up or restores Sentinel's metric stores with VictoriaMetrics' own
# tools (an instant snapshot, then a copy). Run on the database node, e.g.
# from cron nightly:  15 3 * * *  /srv/sentinel/vm-backup.sh backup
#
#   vm-backup.sh backup              both stores into $DEST/<date>/{raw,long}
#   vm-backup.sh restore <date>      stop the store services first (see DEPLOYMENT.md)
#   vm-backup.sh list
#
# DEST defaults to /srv/sentinel-backups/vm; copy it off the host (restic,
# rclone, S3) the same way as the Postgres dumps. KEEP_DAYS prunes old ones.
set -eu
VM=v1.155.0
STACK=${STACK:-sentinel}
DEST=${DEST:-/srv/sentinel-backups/vm}
KEEP_DAYS=${KEEP_DAYS:-7}
mkdir -p "$DEST"

run() { # image, volume, args...
	img=$1 vol=$2
	shift 2
	docker run --rm --network "${STACK}_backend" \
		-v "${STACK}_${vol}:/storage" -v "$DEST:/backup" "victoriametrics/$img:$VM" "$@"
}

case "${1:-}" in
backup)
	day=$(date -u +%Y%m%d)
	run vmbackup vm-data -storageDataPath=/storage \
		-snapshot.createURL=http://victoriametrics:8428/snapshot/create -dst="fs:///backup/$day/raw"
	run vmbackup vm-long-data -storageDataPath=/storage \
		-snapshot.createURL=http://victoriametrics-long:8428/snapshot/create -dst="fs:///backup/$day/long"
	find "$DEST" -mindepth 1 -maxdepth 1 -type d -mtime +"$KEEP_DAYS" -exec rm -rf {} +
	echo "metrics backed up to $DEST/$day"
	;;
restore)
	day=${2:?which backup? see: vm-backup.sh list}
	[ -d "$DEST/$day" ] || { echo "no backup $DEST/$day" >&2; exit 1; }
	run vmrestore vm-data -storageDataPath=/storage -src="fs:///backup/$day/raw"
	run vmrestore vm-long-data -storageDataPath=/storage -src="fs:///backup/$day/long"
	echo "restored $day; start the victoriametrics services again"
	;;
list) ls -1 "$DEST" ;;
*)
	echo "usage: vm-backup.sh backup | restore <date> | list" >&2
	exit 2
	;;
esac
