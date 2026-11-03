# Deployment

Sentinel on one VPS: Docker Swarm with a single node, Caddy for TLS,
nightly backups that are restored to prove they work. The same stack scales
to more nodes later (the stateless services take `replicas`; the stores stay
on the node labelled `sentinel.db`).

## 1. Server

- Ubuntu 24.04 LTS or Debian 13, 4 vCPU / 8 GB RAM / 80 GB SSD is enough
  for a few hundred servers at 30 s; metrics take roughly 1 GB per 100
  servers per month at 90 days' retention.
- Open 80 and 443 only. SSH by key.
- Install Docker Engine, then:

```sh
docker swarm init
docker node update --label-add sentinel.db=true "$(docker node ls -q)"
```

## 2. DNS

All three hostnames point at the server (A and AAAA):

| Name | Serves |
|---|---|
| `sentinel.rajpoot.app` | the web app, and the API under `/api` |
| `ingest.sentinel.rajpoot.app` | agents |
| `get.sentinel.rajpoot.app` | `install.sh`, `install.ps1`, agent binaries |

Caddy gets certificates for them on first start (HTTP-01), so DNS must
resolve before deploying.

Keep the records **DNS only** if the domain is on Cloudflare (grey cloud, not
proxied). Behind Cloudflare's proxy, every visitor arrives from a Cloudflare
address, so the per-IP limits on sign-up and sign-in would be shared by
strangers; agent pushes would also meet Cloudflare's body limits and bot
checks.

## 3. Email

Pick an SMTP server or a provider with an SMTP relay (Amazon SES, Postmark,
Resend, Mailgun). For the sending domain (`sentinel.rajpoot.app` in
`SMTP_FROM`):

- **SPF:** `TXT @ "v=spf1 include:<provider's include> -all"`
- **DKIM:** the CNAME or TXT records the provider gives you.
- **DMARC:** `TXT _dmarc "v=DMARC1; p=quarantine; rua=mailto:ops@rajpoot.app"`,
  moving to `p=reject` once reports are clean.

Sentinel marks a contact undeliverable when the mail server refuses the
recipient during sending. Bounces the provider reports later (by webhook)
aren't processed yet: watch the provider's bounce dashboard.

## 4. Configure

```sh
git clone https://github.com/AlzyWelzy/pulsegrid-beyond.git /srv/sentinel-src
mkdir -p /srv/sentinel && cp -R /srv/sentinel-src/deploy/. /srv/sentinel/
cd /srv/sentinel
cp production.env.example prod.env && chmod 600 prod.env
```

Fill in `prod.env`. Generate every secret with `openssl rand -hex 32`:
`AUTH_SECRET`, `POSTGRES_PASSWORD`, `SENTINEL_APP_PASSWORD`,
`SENTINEL_SERVICE_PASSWORD`, `WEBHOOK_SIGNING_SECRET`, `ACK_SIGNING_SECRET`.
Then:

- `SUPERADMIN_EMAILS`: your own address.
- `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` from Cloudflare (free), or
  `CAPTCHA_DISABLED=true` for a private install with sign-up off.
- Web Push keys, once:
  `docker run --rm ghcr.io/alzywelzy/sentinel-alerter:<version> vapid`.

The registry is public by default for GitHub packages of a public repo; for
a private one, `docker login ghcr.io` with a read-only token first.

## 5. Deploy

```sh
cd /srv/sentinel
set -a; . ./prod.env; set +a
export TEMPO_CONFIG=$(sha256sum tempo/tempo.yml | cut -c1-8)
export BACKUP_SCRIPT=$(sha256sum postgres/backup.sh | cut -c1-8)
export RESTORE_CHECK=$(sha256sum postgres/restore-check.sh | cut -c1-8)
docker stack deploy -c stack.yml --with-registry-auth sentinel

# Migrations, before relying on a new release's code:
docker run --rm --network sentinel_backend \
  -e DATABASE_OWNER_URL="postgresql+asyncpg://sentinel:${POSTGRES_PASSWORD}@postgres:5432/sentinel" \
  ghcr.io/alzywelzy/sentinel-api:${SENTINEL_VERSION} alembic upgrade head
```

Check: `docker stack services sentinel` shows every service at its replica
count, and `https://sentinel.rajpoot.app/login` loads. Sign up with the
address in `SUPERADMIN_EMAILS`; the admin panel appears in the sidebar.

Never deploy the stack under the name of a compose project on the same
host: volumes are named `<name>_<volume>` and would be shared.

## 6. Releases and automatic updates

A tag `vX.Y.Z` publishes `ghcr.io/alzywelzy/sentinel-{api,ingest,alerter,web,agent}`.
`autoupdate.sh` (cron every 5 minutes, in `/srv/sentinel`) waits until all
images of a newer version exist, takes a database dump, migrates, redeploys,
and rolls back to the previous version if the services don't settle within
3 minutes:

```sh
*/5 * * * * cd /srv/sentinel && ./autoupdate.sh
```

`touch autoupdate.pause` skips runs; `autoupdate.log` says what happened. To
roll back by hand: set `SENTINEL_VERSION` back in `prod.env` and deploy
again (migrations are additive, so the old version runs on the new schema).

## 7. Backups and restores

**Postgres** (accounts, organisations, rules, incidents, status pages: the
part that can't be rebuilt). The `backup` service dumps every night into the
`sentinel_pg-backups` volume, keeps `BACKUP_KEEP_DAYS` (7), and **restores
each dump into a scratch database** (`restore-check.sh`) to prove it loads
and has the schema and data. A dump that fails is renamed `.unrestorable`
and logged:

```sh
docker service logs sentinel_backup --since 24h | grep -E "backup|restore check"
```

Restore for real (stop writers first so nothing changes underneath):

```sh
docker service scale sentinel_api=0 sentinel_ingest=0 sentinel_alerter=0 sentinel_jobs=0
docker exec -i "$(docker ps -qf name=sentinel_postgres)" \
  pg_restore -U sentinel -d sentinel --clean --if-exists < sentinel-YYYYmmdd-HHMM.dump
docker stack deploy -c stack.yml --with-registry-auth sentinel   # scales back up
```

**Metrics** (VictoriaMetrics raw and long-term): `vm-backup.sh` takes an
instant snapshot of each and copies it with `vmbackup`:

```sh
15 3 * * * /srv/sentinel/vm-backup.sh backup      # into /srv/sentinel-backups/vm/<date>
```

Restore: `docker service scale sentinel_victoriametrics=0 sentinel_victoriametrics-long=0`,
`./vm-backup.sh restore <date>`, then deploy again. Logs and traces age out
by retention and aren't backed up.

**Off the host:** copy `/var/lib/docker/volumes/sentinel_pg-backups` and
`/srv/sentinel-backups` somewhere else nightly (restic or rclone to object
storage). A backup on the same disk isn't one.

**Test the whole restore** once a quarter on a scratch VM: deploy the stack
there, restore the latest Postgres dump and metrics backup, sign in, and
check a server's charts reach back to before the backup.

## 8. Monitor Sentinel

- Install the agent on the Sentinel host itself, in your own organisation,
  with the recommended rules plus `process_down` rules for `postgres`,
  `victoria-metrics` and `caddy`.
- Add uptime checks for `https://sentinel.rajpoot.app/login`,
  `https://ingest.sentinel.rajpoot.app/healthz` and the TLS certificate.
- A monitor can't report its own death: use one external uptime service
  (any free one) on `https://sentinel.rajpoot.app/api/healthz`, alerting to
  a phone.

## 9. Moving domains

Set the new hostnames in `prod.env`, add DNS, deploy, and keep the old names
serving until agents have fetched the new ingest URL (within 2 minutes of
their next config refresh; an hour to be safe).

## 10. Secret rotation

| Secret | How |
|---|---|
| `AUTH_SECRET` | Move it to `AUTH_SECRET_PREVIOUS`, set a new one, deploy; clear the previous a day later |
| `ACK_SIGNING_SECRET` | Change and deploy: acknowledge links in old emails stop working |
| `WEBHOOK_SIGNING_SECRET` | Change, deploy, tell webhook customers the new value |
| Database passwords | `ALTER ROLE … PASSWORD` in Postgres, update `prod.env`, deploy |
| SMTP, Turnstile, VAPID | Change at the provider, update `prod.env`, deploy (new VAPID keys mean browsers subscribe again) |
