# Pulsegrid

Multi-tenant server and uptime monitoring. A lightweight agent on each
server pushes metrics every 30 seconds and runs checks (ports, URLs, files,
log patterns) and plugins (MySQL, PostgreSQL, Redis, Nginx, Apache, Docker,
Prometheus endpoints, scripts); agents marked as probes run customers'
uptime checks from several regions. Pulsegrid stores everything, evaluates
alert rules (thresholds, anomalies, forecasts), opens incidents with a
timeline, notifies verified contacts by email and Web Push, can run an
allowed fix on the server, and publishes status pages and monthly reports.

The Example console is the dashboard and the identity provider: users
sign up there, and Pulsegrid trusts the console's JWT (the same way
billing-ms does). The console's **Monitoring → Servers** tab is the UI.

```text
                 ┌──────────── Pulsegrid ─────────────────────────────────────┐
agent ──push──▶  │ ingest ──▶ VictoriaMetrics (metric samples, history)       │
 (Go, per        │   │              ▲                                         │
  server)        │   ▼              │                                         │
                 │ PostgreSQL ◀── api ◀──── console dashboard (console JWT)   │
                 │ (tenants, hosts, │  ◀──── console backend (/internal, key) │
                 │  rules, incidents,│                                        │
                 │  outbox)  ▲       │                                        │
                 │           └── alerter ──▶ email · SMS · webhooks          │
                 └────────────────────────────────────────────────────────────┘
```

| Path | What | Stack |
|---|---|---|
| `agent/` | Installed on servers: collects, buffers to disk, pushes, self-updates | Go |
| `ingest/` | Agent registration, metric intake, remote agent config | Go |
| `alerter/` | Rule evaluation, incidents, notification outbox dispatcher | Go |
| `api/` | Control plane: tenants, keys, hosts, metrics, rules, incidents, contacts | FastAPI · uv · ruff · ty |
| `proto/` | Agent ⇄ ingest wire contract (JSON v1, backward compatible) | Go |
| `deploy/` | Dev compose, production Swarm stack, Caddy, Postgres roles, OS test harness | Docker |

## Multi-tenancy

Every console user is a tenant (`tenants.source` + `external_account_id` =
the console `uid`). Isolation is layered so one mistake can't leak data:

1. **Identity from trusted credentials only**: the console JWT for the API,
   the host token for ingest. Never a request body, never an IP.
2. **Application scoping**: every query filters on `tenant_id`; metric queries
   are built server-side from a fixed catalog, never from client PromQL.
3. **Postgres row-level security**: the API connects as `pulsegrid_app`,
   which RLS always applies to. Each request sets `app.tenant_id` for its
   transaction only (`api/app/tenancy.py`), so a query with no `WHERE` still
   sees one tenant, and a pooled connection can't carry it to the next request.
4. **Metrics**: ingest stamps `host_id` itself and writes with
   `extra_label=tenant_id=…`; every read adds the same `extra_label`, so
   VictoriaMetrics scopes every selector to the tenant.
5. **Tests prove it**: `api/tests/test_rls.py`, `test_api_isolation.py`,
   `test_alerting.py`, `ingest/vm_test.go`.

Database roles: `pulsegrid` (owner, migrations only), `pulsegrid_app` (API;
RLS), `pulsegrid_service` (ingest, alerter, `/internal`; BYPASSRLS with
narrow grants).

## Agent

Tested on real systems: Ubuntu 24.04 (systemd), FreeBSD 15.1, OpenBSD 7.9,
NetBSD 10.2 and Windows Server 2025, plus macOS for development.

| Platform | Install | Runs as | Supervised by | Self-update |
|---|---|---|---|---|
| Linux (amd64, arm64) | `curl … install.sh \| sudo sh` | `pulsegrid` | systemd (`Restart=always`) or OpenRC | root systemd timer / cron |
| FreeBSD (amd64, arm64) | `fetch -qo - … \| sh` | `pulsegrid` | `daemon(8) -r` via rc.d | root cron |
| OpenBSD (amd64) | `ftp -o - … \| doas sh` | `_pulsegrid` | rc.d + 5-minute cron watchdog | root cron |
| NetBSD (amd64) | `ftp -o - … \| sh` | `pulsegrid` | rc.d (pidfile) + 5-minute cron watchdog | root cron |
| Windows Server 2016+ / 10+ | `install.ps1` in elevated PowerShell | `LocalService` | Service Control Manager (restart on failure) | SYSTEM scheduled task |

- One-line install from the dashboard; the agent never runs privileged. Its
  state (including the host token) is readable only by it and administrators.
- Buffers every batch on disk until ingest accepts it; outages lose nothing.
- Fetches its config from Pulsegrid every 2 minutes, falling back to the URL
  it registered with, so domains can move without reinstalls. The config
  also lists the processes and services to watch, taken from the host's
  alert rules: creating a "nginx isn't running" rule configures the agents.
- Collects: CPU (total, per core, and per mode including iowait and steal),
  memory, swap, load, disk usage and inodes per filesystem, disk I/O (bytes,
  operations and busy time per physical disk), network, uptime, the busiest
  processes by CPU and memory (grouped by name), and watched processes and
  services (systemd, OpenRC/SysV, rc.d, Windows SCM). On Linux it also
  reports failed systemd units. Not every OS accounts everything: iowait and
  steal exist on Linux; disk busy time on Linux and FreeBSD; NetBSD has no
  disk I/O counters and its process list comes from `ps`.
- Reports the machine's IP addresses, CPU count and memory with each push,
  and takes tags at install (`install.sh --tags web,production`).
- Checks from its config: TCP ports, HTTP(S) URLs (status, keyword, response
  time, certificate expiry), TLS certificates, DNS records, files (missing,
  changed, too old, too big) and log patterns (new lines matching an RE2
  expression; rotation-aware). A failure is held until a push delivers it, so
  one bad line between pushes is never lost. Probe checks may only reach
  public addresses, enforced when connecting (DNS rebinding can't get round it).
- Plugins from root-owned files in `/etc/pulsegrid/plugins.d/*.conf`
  (`%ProgramData%\Pulsegrid\conf` on Windows): `mysql`, `postgres`, `redis`,
  `nginx`, `apache`, `docker`, `prometheus` (any exporter or `/metrics`;
  series become `pulsegrid_custom_*`) and `script` (prints `name value`
  lines). Never configured from the dashboard: they hold passwords and a
  script runs code. `pulsegrid-agent plugins` tests them.
- Actions: the dashboard (or a rule, when it fires) can ask for a fix by
  name; only names in the root-owned `actions.conf` run. `sudo pulsegrid-agent
  allow-action restart-nginx -- /usr/bin/systemctl restart nginx` writes it,
  a sudoers rule for exactly that command, and (systemd) a drop-in that
  relaxes the unit's sandbox only while sudo actions exist.
- Inventory every 6 hours: packages (dpkg, rpm, apk, pacman, pkg, pkg_info,
  Windows registry), listening ports, kernel, CPU model, virtualization;
  ingest keeps the package changes between inventories.
- Picks up config changes within one push: ingest returns the config version
  with every push and the agent refetches when it changes.
- Self-updates hourly from a separate privileged job: downloads the advertised
  version, verifies its SHA-256, self-tests it and swaps it in atomically
  (on Windows the running `.exe` is moved aside first).
- Host identity is the OS machine id plus the hostname. Placeholder hardware
  UUIDs (all zeros, as many hypervisors report) are rejected in favour of an
  id generated once and kept with the agent's state; including the hostname
  keeps VMs cloned from one template apart.
- CPU is computed from raw counters (gopsutil's percentage double-counts
  interrupt time on Windows, and its OpenBSD reads fail intermittently).

## Alerting

- Rules: metric thresholds (CPU, memory, swap, disk, inodes, load, iowait,
  steal, disk busy, network in/out) read as the latest value or the average,
  peak or lowest over a window, with an optional recovery level (hysteresis);
  anomalies (standard deviations above the past week); forecasts (disk,
  inodes, memory or swap running out within N hours, from a short and a long
  trend); a server going silent; a process, service, Docker container or
  plugin down; a custom metric from a plugin; a check failing (uptime checks
  need N of the probe locations to agree). For every server, one server, or
  every server with a tag. Each rule has a severity, optional runbook text
  and an optional action to run on the host. "Add recommended rules" creates
  a starter set.
- Incidents keep a timeline (opened, notified, escalated, acknowledged,
  resolved, reopened, notes, actions). Customers add notes, resolve by hand
  and reopen. An alert that opens 4 times in an hour is marked flapping and
  stops notifying until it settles; a silent server holds back its other
  alerts (one problem, one alert).
- Escalation: up to 5 steps per rule ("after 15 minutes, also notify …").
  Steps stop when the incident is acknowledged (dashboard or the signed
  one-click link in every alert, `ACK_SIGNING_SECRET`) or resolves.
- Maintenance windows (one-off, or weekly in a timezone) for every server, one
  server or a tag: no incidents open and nothing is sent; a problem that
  outlasts the window fires when it ends.
- Dependencies: a server can depend on another (a gateway, a hypervisor).
  While that one is silent, the dependent server's alerts are held back.
- The alerter evaluates every 30s: `ok → pending → firing → resolved`, with
  incidents opened and resolved in the same transaction as the state change.
- Notifications go through an outbox (`outbound_messages`) with retries and
  backoff. Email (SMTP, or through the console; HTML with acknowledge and
  view buttons), Web Push to browsers and phones (VAPID; a dropped
  subscription is removed), webhooks (signed
  `X-Pulsegrid-Signature: sha256=…`, private addresses refused), Slack,
  Microsoft Teams, Discord, Telegram (the customer's bot), PagerDuty (Events
  v2: Pulsegrid incidents trigger and resolve PagerDuty incidents), SMS and
  voice calls (Twilio). Secret targets (webhook URLs, bot tokens, keys) are
  masked whenever the API returns them.
  `ENABLED_CHANNEL_TYPES` (default `email,push`) limits what customers can
  add; contacts saved earlier keep working.
- Contacts: the console email is prefilled and verified; others get a 6-digit
  code (5 attempts, 30-minute expiry) and receive nothing until verified. A
  push subscription is verified by being one. Each contact picks the lowest
  severity it receives.

## Status pages, reports, API

- Status pages (`/status/<slug>` HTML, `/public/status/<slug>` JSON): chosen
  servers and checks under the owner's labels, 90-day daily uptime, outages
  of the last week. Never hostnames, addresses or targets.
- Reports (`/v1/reports/summary`, `.csv`): availability, incidents, time to
  acknowledge and resolve, noisiest rules, resource use, days until disks
  fill. Accounts get it by email on the 1st unless they turn it off.
- API tokens (`pgt_…`, read-only by default) act as the account; managing
  tokens needs a console login. OpenAPI at `/docs`.

## Teams

The account owner invites other console users by email as **viewer** (reads
everything), **operator** (also acknowledges and resolves incidents,
schedules maintenance, runs allowed actions) or **admin** (changes anything
but members and API tokens). A member opens the shared account by sending
`X-Pulsegrid-Account: <tenant id>`; `tenancy.py` checks the membership
(`pulsegrid_member_tenant()`, SECURITY DEFINER) and the role per route, then
RLS applies as usual. Invitations are claimed by the first console login with
that verified email and pinned to it.

## Logs

Opt-in per server: a root-owned `/etc/pulsegrid/logs.conf` (`file = <glob>`,
`journal = true`). The agent ships new lines (rotation-aware, offsets kept
across restarts, no backfill) to ingest `/v1/logs`, which writes them to Loki
as the tenant (`X-Scope-OrgID`), labelled with the host from the token, at
most `LOG_LINES_PER_MINUTE` per host. The API searches (`/v1/logs`, text or
RE2, server, file, level), counts (`/v1/logs/volume`) and lists sources;
14 days kept. Off unless `LOKI_URL` is set.

## APM

Opt-in per server: `/etc/pulsegrid/apm.conf` (`listen = 127.0.0.1:4318`)
makes the agent an OTLP/HTTP receiver; apps use
`OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318` and need no key. Ingest
decodes each batch, sets `pulsegrid.host_id` from the token (replacing any
the app sent), caps `SPANS_PER_MINUTE` per host and writes to Tempo as the
tenant. The API reports services (requests, error rate, p50/p95/p99 from
TraceQL metrics over entry spans), searches traces and returns one trace's
spans; 7 days kept. Off unless `TEMPO_URL` is set.

## Hardware and network devices

- `sudo pulsegrid-agent enable-hardware` finds smartctl disks and an IPMI
  BMC, writes `plugins.d/smart.conf` / `ipmi.conf`, and a sudoers file
  allowing exactly those read-only command lines (`--remove` undoes it).
  Metrics: `pulsegrid_custom_smart_*` (healthy, temperature, reallocated and
  pending sectors, NVMe wear) and `pulsegrid_custom_ipmi_sensor{sensor,unit}`.
- `type = snmp` plugins poll a device from the server (v1/v2c/v3): uptime,
  per-interface traffic and status, and named custom OIDs
  (`pulsegrid_custom_snmp_*`).
- Alert with custom rules (e.g. `smart_healthy < 1`).

## Terraform

`terraform-provider-pulsegrid/`: alert rules, checks, maintenance windows,
status pages, install keys and a hosts data source, with an API token.

## Jobs

`python -m app.jobs` (the `jobs` service; replicas stand by on an advisory
lock): monthly report emails, hourly rollups of every series into the
long-term VictoriaMetrics (`VICTORIAMETRICS_LONG_URL`; gauges keep the hourly
average, counters the hour-end value), which charts read for ranges past raw
retention or longer than a month, and daily cleanup.

## Probes

Uptime checks run on agents staff mark as probes (`PUT
/admin/v1/hosts/{id}/probe {"region": "…"}`, or Fleet & probes in the
console). Only agents in the accounts listed in `PROBE_ACCOUNT_IDS` qualify:
a probe receives every account's uptime check targets. An agent in a
container is enough (no root needed).
- Run 2+ alerter replicas: a Postgres advisory lock keeps one active and the
  rest on standby.

## Develop

```sh
make up          # Postgres, Redis, VictoriaMetrics, Mailpit, migrations, api :8000, ingest :8080, alerter
make agent       # agent binaries for every platform + checksums into api/dist/dev
make test        # Go tests + API tests (needs `make up`)
make lint        # gofmt, go vet, ruff, ty
```

The dev stack runs with `ALLOW_AUTH_BYPASS=true`: requests **without** a
token act as a fixed dev user (a token that's present is always verified).
Emails land in Mailpit (`MAILPIT_PORT`, default 8025).

```sh
curl -s -X POST localhost:8000/v1/agent-keys -H 'content-type: application/json' -d '{"name":"laptop"}'
go run ./agent register --url http://localhost:8080 --key pg_... --state-dir ./.agent
go run ./agent run --state-dir ./.agent
```

Override host ports and public URLs through `deploy/.env` (`API_PORT`,
`PUBLIC_API_URL`, `CORS_ORIGINS`, `JWKS_URI`, …; see the compose file).

## Release

Push a tag (`v0.2.0`). The `Release` workflow publishes
`ghcr.io/example-org/pulsegrid-{api,ingest,alerter}:0.2.0` and attaches
agent binaries with `.sha256` files to the GitHub release. Upload those files
to the download host under `/agent/0.2.0/`, then bump `PULSEGRID_VERSION` and
`AGENT_VERSION` and redeploy; installed agents update within the hour.
Web Push needs `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` once per environment:
`docker run --rm ghcr.io/example-org/pulsegrid-alerter:<v> vapid`.

## Deploy behind the console (dev, prod)

Pulsegrid runs as its own Swarm stack and is served on the console's domain
through the console's nginx (`frontend/nginx/*.conf`), like billing-ms:

| Path on the console domain | Goes to |
|---|---|
| `/api/pulsegrid/...` | API (unstripped; `API_ROOT_PATH=/api/pulsegrid`), install scripts, agent binaries baked into the image |
| `/pulsegrid/ingest/...` | ingest (prefix stripped) |
| `/api/pulsegrid/internal/`, `/api/internal/` | blocked (404): service-to-service only |

```sh
docker network create --driver overlay --attachable pulsegrid-dev   # once
cp deploy/console.env.example deploy/dev.env                        # fill in; never commit
set -a; . deploy/dev.env; set +a
docker stack deploy -c deploy/stack.console.yml --with-registry-auth pulsegrid
docker run --rm --network pulsegrid_backend \
  -e DATABASE_OWNER_URL="postgresql+asyncpg://pulsegrid:${POSTGRES_PASSWORD}@postgres:5432/pulsegrid" \
  ghcr.io/example-org/pulsegrid-api:${PULSEGRID_VERSION} alembic upgrade head
```

The console stack's frontend (nginx) and backend join the same network; the
backend is aliased `console-backend` there. Email goes through the console
(`EMAIL_TRANSPORT=console`): the alerter posts to the backend's
`/api/internal/pulsegrid/email/`, which sends with the console's Mail Settings
from the `pulsegrid_alert` sender. Console settings: `PULSEGRID_ENABLED`,
`PULSEGRID_INTERNAL_URL`, `PULSEGRID_INTERNAL_API_KEY` (= Pulsegrid's
`INTERNAL_API_KEY`), `PULSEGRID_CALLBACK_API_KEY` (= Pulsegrid's
`CONSOLE_INTERNAL_API_KEY`).

## Deploy standalone (Swarm, own domains)

```sh
cp deploy/production.env.example deploy/production.env   # fill in; never commit
docker node update --label-add pulsegrid.db=true <node>  # where data lives
set -a; . deploy/production.env; set +a
docker stack deploy -c deploy/stack.yml --with-registry-auth pulsegrid

# migrations, once per release, before relying on new code:
docker run --rm --network pulsegrid_backend \
  -e DATABASE_OWNER_URL="postgresql+asyncpg://pulsegrid:${POSTGRES_PASSWORD}@postgres:5432/pulsegrid" \
  ghcr.io/example-org/pulsegrid-api:${PULSEGRID_VERSION} alembic upgrade head
```

- Caddy terminates TLS for `API_HOST`, `INGEST_HOST` and `DOWNLOAD_HOST`
  (automatic certificates) and refuses `/internal/*` from the internet.
- The API refuses to start in production with dev settings: auth bypass on,
  a placeholder or short `INTERNAL_API_KEY`, or no real console JWKS.
- Never deploy the stack under the same name as a compose project on that
  host: volumes are named `<name>_<volume>`, so they'd share Postgres data.
- Moving domains: change the hostnames, deploy, keep the old names serving
  until agents have picked up the new ingest URL (within an hour).

## Staff view

Console staff (token `role` in `STAFF_ROLES`, default `admin,super_admin`)
get `/admin/v1`: totals, every account with servers, any account's servers
and charts, incidents (with timelines) across all accounts, and the agent
fleet (versions, outdated agents, probes). The one change staff make is
which of our agents are probes; staff act for a customer through the
console's view-as-client, which Pulsegrid treats as read-only. `ADMIN_JWT_TOKEN_ISSUER` /
`ADMIN_JWT_TOKEN_AUDIENCE` default to the customer token values.

## Console integration

- **Browser → Pulsegrid**: set `VITE_PULSEGRID_API_BASE_URL` in the console
  frontend build; add the console origin to `CORS_ORIGINS`. The console's
  access token is sent as-is.
- **Identity**: `JWKS_URI`, `JWT_TOKEN_ISSUER`, `JWT_TOKEN_AUDIENCE` take the
  same values as billing-ms in that environment.
- **Console backend → `/internal/v1`** with `X-Internal-Api-Key`:
  `GET /usage` (active hosts per account, for per-host billing),
  `POST /tenants/{uid}/suspend|resume`, `DELETE /tenants/{uid}` (purges data).
