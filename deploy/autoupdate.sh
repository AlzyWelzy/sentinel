#!/bin/sh
# Deploys new Sentinel releases. Cron runs this every 5 minutes; a release
# is a v* tag in AlzyWelzy/pulsegrid-beyond, whose workflow publishes
# ghcr.io/alzywelzy/sentinel-{api,ingest,alerter}:<version>.
#
# When a newer version than SENTINEL_VERSION in prod.env has all three
# images: pull, migrate, redeploy, and watch for 3 minutes. If the services
# don't settle, prod.env goes back to the old version and the stack is
# redeployed (migrations are additive; the old version runs on them).
#
#   touch autoupdate.pause      skip runs
#   autoupdate.log              what happened
# GHCR read credentials: ~/.docker/config.json (docker login ghcr.io).
set -eu
cd "$(dirname "$0")"
exec 9>autoupdate.lock
flock -n 9 || exit 0
[ -e autoupdate.pause ] && exit 0

REPO=${REGISTRY_OWNER:-alzywelzy}
IMG=sentinel
log() { echo "[$(date -u '+%F %T')] $*" >>autoupdate.log; }

# Registry token from the stored docker login.
auth=$(python3 -c 'import json,os;print(json.load(open(os.path.expanduser("~/.docker/config.json")))["auths"]["ghcr.io"]["auth"])')
token() {
	curl -fsS -H "Authorization: Basic $auth" \
		"https://ghcr.io/token?service=ghcr.io&scope=repository:$REPO/$IMG-$1:pull" |
		python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])'
}
tags() {
	curl -fsS -H "Authorization: Bearer $(token "$1")" "https://ghcr.io/v2/$REPO/$IMG-$1/tags/list?n=1000" |
		python3 -c 'import json,sys;print("\n".join(json.load(sys.stdin).get("tags") or []))' |
		grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true
}

current=$(sed -n 's/^SENTINEL_VERSION=//p' prod.env)
newest=$(tags api | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
[ -n "$newest" ] || exit 0
[ "$newest" = "$current" ] && exit 0
# Only move forward.
[ "$(printf '%s\n%s\n' "$current" "$newest" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)" = "$newest" ] || exit 0
for c in ingest alerter web; do
	tags "$c" | grep -qx "$newest" || exit 0 # not all published yet
done

log "== $current -> $newest"
for c in api ingest alerter; do
	docker pull -q "ghcr.io/$REPO/$IMG-$c:$newest" >>autoupdate.log 2>&1
done
agent=$(docker image inspect "ghcr.io/$REPO/$IMG-api:$newest" \
	--format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^AGENT_VERSION=//p')
[ -n "$agent" ] && [ "$agent" != dev ] || { log "no AGENT_VERSION in the api image; skipped"; exit 1; }
tags agent | grep -qx "$agent" || exit 0 # agent image not published yet

deploy() {
	set -a; . ./prod.env; set +a
	TEMPO_CONFIG="$(sha256sum tempo/tempo.yml | cut -c1-8)"
	BACKUP_SCRIPT="$(sha256sum postgres/backup.sh | cut -c1-8)"
	RESTORE_CHECK="$(sha256sum postgres/restore-check.sh | cut -c1-8)"
	export TEMPO_CONFIG BACKUP_SCRIPT RESTORE_CHECK
	docker stack deploy -q -c stack.yml --with-registry-auth sentinel >>autoupdate.log 2>&1
}
settled() {
	# every sentinel service at its desired replica count
	docker stack services sentinel --format '{{.Replicas}}' | awk -F/ '$1!=$2{bad=1} END{exit bad}'
}

cp prod.env "prod.env.bak-$current"
# The release's own stack files (in its api image since 0.8.3); older images
# have none, and the current files stay.
rm -rf next && mkdir next
c=$(docker create "ghcr.io/$REPO/$IMG-api:$newest")
if docker cp "$c:/deploy/." next/ 2>/dev/null && [ -s next/stack.yml ]; then
	tar -czf "deploy.bak-$current.tgz" stack.yml postgres tempo caddy
	cp -R next/. .
	log "stack files from $newest"
fi
docker rm "$c" >/dev/null
rm -rf next
log "backup point before migrating"
docker exec "$(docker ps -qf name=sentinel_postgres)" sh -c \
	'pg_dump -U sentinel -Fc sentinel' >"backups/pre-$newest-$(date -u +%Y%m%dT%H%M%SZ).dump"

set -a; . ./prod.env; set +a
if ! docker run --rm --network sentinel_backend \
	-e DATABASE_OWNER_URL="postgresql+asyncpg://sentinel:$POSTGRES_PASSWORD@postgres:5432/sentinel" \
	"ghcr.io/$REPO/$IMG-api:$newest" alembic upgrade head >>autoupdate.log 2>&1; then
	log "migration failed; staying on $current"
	[ -f "deploy.bak-$current.tgz" ] && tar -xzf "deploy.bak-$current.tgz"
	exit 1
fi

sed -i "s/^SENTINEL_VERSION=.*/SENTINEL_VERSION=$newest/; s/^AGENT_VERSION=.*/AGENT_VERSION=$agent/" prod.env
deploy
i=0
until settled; do
	i=$((i + 1))
	if [ "$i" -gt 18 ]; then
		log "not healthy after 3 minutes; rolling back to $current"
		cp "prod.env.bak-$current" prod.env
		[ -f "deploy.bak-$current.tgz" ] && tar -xzf "deploy.bak-$current.tgz"
		deploy
		exit 1
	fi
	sleep 10
done
log "== live: $newest (agent $agent)"
docker image prune -af --filter "until=168h" >/dev/null 2>&1 || true
