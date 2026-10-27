#!/usr/bin/env bash
# rollback.sh <ts> — undo upgrade.sh: old images, the dump and data saved at <ts>.
# Wipes the current Kuma database volume and data volume.
set -euo pipefail
cd "$(dirname "$0")"
ts=${1:?usage: rollback.sh <timestamp from backups/kuma-<ts>.sql>}
[ -f docker-compose.yml.prev ] && [ -f "backups/kuma-$ts.sql" ] && [ -f "backups/kuma-data-$ts.tar" ]
docker compose down
cp docker-compose.yml.prev docker-compose.yml
docker volume rm kuma_db kuma_data
docker compose up -d db
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q db)")" = healthy ]; do sleep 3; done
docker compose exec -T db sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD"' <"backups/kuma-$ts.sql"
pw=$(docker run --rm -v "$PWD/backups:/b" alpine sh -c "tar -xOf /b/kuma-data-$ts.tar ./db-config.json" | python3 -c 'import json,sys;print(json.load(sys.stdin)["password"])')
docker compose exec -T db sh -c "exec mariadb -uroot -p\"\$MARIADB_ROOT_PASSWORD\" -e \"CREATE USER IF NOT EXISTS kuma@'%' IDENTIFIED BY '$pw'; GRANT ALL ON kuma.* TO kuma@'%'; FLUSH PRIVILEGES;\""
docker compose create kuma
docker run --rm -v kuma_data:/d -v "$PWD/backups:/b" alpine tar -C /d -xf "/b/kuma-data-$ts.tar"
docker compose up -d kuma
echo "rolled back to the state at $ts"
