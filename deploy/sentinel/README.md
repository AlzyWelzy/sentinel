# Production: sentinel

Pulsegrid and the console's Uptime Kuma run on **sentinel** (172.23.2.15, LAN only).
The prod console (`console`, 172.23.1.160) forwards the public paths to it from its
edge nginx (`console-ops/edge/nginx.conf`):

    https://console.Example.com/api/pulsegrid/...   -> sentinel:80 -> pulsegrid-api
    https://console.Example.com/pulsegrid/ingest/   -> sentinel:80 -> pulsegrid-ingest
    console backend -> http://172.23.2.15/api/pulsegrid/internal/   (allowed from 172.23.1.160 only)
    alerter -> http://172.23.1.160/api/internal/pulsegrid/email/    (edge allows sentinel only)
    console backend -> http://172.23.2.15:3001                      Uptime Kuma (MonitoringNode 1)

On sentinel (user `server`):

| Path | What |
|---|---|
| `~/pulsegrid/` | `stack.yml` + `postgres/` + `tempo/` (from the release), `prod.env` (secrets, 0600), `gateway.yml` + `gateway/nginx.conf`, `autoupdate.sh` |
| `~/kuma/` | `docker-compose.yml` (Kuma 2.0.2 + MariaDB 11.4), `.env` (MariaDB root password) |
| `~/.backup/` | `kuma-backup.sh`, `pulsegrid-backup.sh` → restic repo in S3 `Example-console-backups` |

Swarm (single node) uses `--default-addr-pool 192.168.240.0/20`, and Docker bridges
`192.168.224.0/20` (`/etc/docker/daemon.json`), clear of the LAN and the 10.0.8.0/24 private network.

## Releases deploy themselves

Push a `v*` tag; the Release workflow publishes the images. Every 5 minutes
`autoupdate.sh` (cron) looks for a newer version on GHCR and, once all three images
exist: dumps the database, takes the release's stack files from its api image,
migrates, redeploys, and rolls back if the services don't settle in 3 minutes.
`touch ~/pulsegrid/autoupdate.pause` to hold; history in `~/pulsegrid/autoupdate.log`.

## Cron (UTC)

    45 20 * * *   ~/.backup/kuma-backup.sh        Kuma DB → S3 (pings console push monitor 24)
    30 21 * * *   ~/.backup/pulsegrid-backup.sh   newest Pulsegrid dump → S3
    */5 * * * *   ~/pulsegrid/autoupdate.sh
