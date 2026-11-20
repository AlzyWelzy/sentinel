#!/bin/sh
# Prepares a fresh Ubuntu 24.04 server for Sentinel and deploys it from a
# source tarball, building the images on the server. Use it when the release
# images aren't published (CI down); otherwise follow DEPLOYMENT.md.
#
#   sudo sh bootstrap.sh /tmp/sentinel-src.tar.gz
#
# Needs /srv/sentinel/prod.env filled in first (see production.env.example).
# Safe to run again: it rebuilds the images and redeploys.
set -eu

SRC_TAR=${1:?usage: bootstrap.sh <source tarball>}

if ! command -v docker >/dev/null; then
  apt-get update -q
  apt-get install -yq ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -yq docker-ce docker-ce-cli containerd.io docker-buildx-plugin
fi

if [ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != active ]; then
  docker swarm init --advertise-addr 127.0.0.1
  docker node update --label-add sentinel.db=true "$(docker node ls -q)"
fi

# A small swap file: image builds (Go, Next.js) peak above 8 GB otherwise.
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

rm -rf /srv/sentinel-src && mkdir -p /srv/sentinel-src
tar -xzf "$SRC_TAR" -C /srv/sentinel-src
mkdir -p /srv/sentinel
cp -R /srv/sentinel-src/deploy/. /srv/sentinel/
cd /srv/sentinel
[ -f prod.env ] || { echo "fill in /srv/sentinel/prod.env first" >&2; exit 1; }
set -a; . ./prod.env; set +a

cd /srv/sentinel-src
for name in api ingest alerter web; do
  docker build -q -f "$name/Dockerfile" --build-arg AGENT_VERSION="$AGENT_VERSION" \
    -t "$REGISTRY/sentinel-$name:$SENTINEL_VERSION" .
done
docker build -q -f deploy/agent-container/Dockerfile --build-arg AGENT_VERSION="$AGENT_VERSION" \
  -t "$REGISTRY/sentinel-agent:$AGENT_VERSION" .

cd /srv/sentinel
export TEMPO_CONFIG=$(sha256sum tempo/tempo.yml | cut -c1-8)
export BACKUP_SCRIPT=$(sha256sum postgres/backup.sh | cut -c1-8)
export RESTORE_CHECK=$(sha256sum postgres/restore-check.sh | cut -c1-8)
docker stack deploy -c stack.yml --resolve-image never sentinel

# Migrations once Postgres answers.
until docker run --rm --network sentinel_backend postgres:18.6-alpine \
  pg_isready -q -h postgres -U sentinel; do sleep 3; done
docker run --rm --network sentinel_backend \
  -e DATABASE_OWNER_URL="postgresql+asyncpg://sentinel:${POSTGRES_PASSWORD}@postgres:5432/sentinel" \
  "$REGISTRY/sentinel-api:$SENTINEL_VERSION" alembic upgrade head
docker stack services sentinel
