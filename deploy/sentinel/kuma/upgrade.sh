#!/usr/bin/env bash
# upgrade.sh — move Kuma and its MariaDB to the images in docker-compose.yml.
# Run in ~/kuma on sentinel: first `cp docker-compose.yml docker-compose.yml.prev`,
# then copy the new docker-compose.yml in.
# Kuma's checks pause for a minute or two. Newer Kuma migrates its tables and
# can't go back, so everything needed to roll back is saved first:
#   backups/kuma-<ts>.sql       full dump (restore into the old MariaDB image)
#   backups/kuma-data-<ts>.tar  Kuma's data directory
#   the previous docker-compose.yml as docker-compose.yml.prev
set -euo pipefail
cd "$(dirname "$0")"
[ -f docker-compose.yml.prev ] || { echo "!! save the current file as docker-compose.yml.prev first"; exit 1; }
ts=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p backups
db() { docker compose exec -T db sh -c "exec mariadb -uroot -p\"\$MARIADB_ROOT_PASSWORD\" $*"; }

before=$(db -N -e "'select count(*) from kuma.monitor'")
echo "monitors before: $before"
"${KUMA_BACKUP:-$HOME/.backup/kuma-backup.sh}"   # off-box copy in S3 first
docker compose exec -T db sh -c 'exec mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" --single-transaction --quick --routines --triggers --events --databases kuma' >"backups/kuma-$ts.sql"
tail -1 "backups/kuma-$ts.sql" | grep -q "^-- Dump completed" || { echo "!! dump incomplete"; exit 1; }

docker compose stop kuma
docker run --rm -v kuma_data:/d alpine tar -C /d -cf - . >"backups/kuma-data-$ts.tar"
docker compose up -d db
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q db)")" = healthy ]; do sleep 3; done
docker compose exec -T db sh -c 'mariadb-check -uroot -p"$MARIADB_ROOT_PASSWORD" --all-databases' | grep -v "OK$" || true
docker compose up -d kuma
for i in $(seq 1 60); do docker compose logs kuma 2>&1 | grep -q "Listening on" && break; sleep 3; done
after=$(db -N -e "'select count(*) from kuma.monitor'")
echo "monitors after: $after (MariaDB $(db -N -e "'select version()'"), $(docker inspect -f '{{.Config.Image}}' "$(docker compose ps -q kuma)"))"
[ "$before" = "$after" ] || { echo "!! monitor count changed"; exit 1; }
echo "done. rollback: see the comment at the top of rollback.sh"
