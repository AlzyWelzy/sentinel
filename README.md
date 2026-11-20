# Sentinel

Multi-tenant server, network and uptime monitoring, at
[sentinel.rajpoot.app](https://sentinel.rajpoot.app). A small agent on each
server pushes metrics every 30 seconds, runs checks (ports, URLs,
certificates, DNS, files, log patterns) and plugins (MySQL, PostgreSQL,
Redis, Nginx, Apache, Docker, SMART/IPMI, SNMP, Prometheus endpoints,
scripts). Sentinel stores everything, evaluates alert rules (thresholds,
anomalies, forecasts, silence), opens incidents with a timeline, notifies
verified contacts (email, Web Push, webhooks, Slack, Teams, Discord,
Telegram, PagerDuty), and publishes status pages and reports. Agents also
poll the switches, firewalls and Proxmox clusters at their site, so the
network is monitored with the servers: interfaces, LLDP topology,
vendor-specific health, and 95th-percentile bandwidth.

People sign up at the web app, create an organisation, invite their team,
install the agent with one command and manage everything there. Nothing
outside this repository is needed to run it.

```text
browser ──https──▶ Caddy ─┬─ /      ──▶ web (Next.js)
                          └─ /api/* ──▶ api (FastAPI) ──▶ PostgreSQL (RLS) · Redis · VictoriaMetrics
agent ───https──▶ Caddy ──▶ ingest (Go) ──▶ VictoriaMetrics · VictoriaLogs · Tempo · PostgreSQL
                            alerter (Go): rules → incidents → outbox → email, push, chat, webhooks
                            jobs (Python): rollups, reports, digests, agent rollouts
```

| Path | What | Stack |
|---|---|---|
| `agent/` | On each server: collects, buffers to disk, pushes, updates itself | Go |
| `ingest/` | Agent registration, metric/log/trace intake, remote agent config | Go |
| `alerter/` | Rule evaluation, incidents, the notification and account-email outbox | Go |
| `api/` | Accounts, organisations, servers, rules, incidents, status pages, reports | FastAPI · uv · ruff · ty |
| `web/` | The web app and public status pages | Next.js · TypeScript |
| `proto/` | Agent ⇄ ingest wire contract (JSON v1, backward compatible) | Go |
| `netmon/` | SNMP collection and vendor profiles (YAML), tested against recordings of real devices | Go |
| `e2e/` | Browser journey, network UI, live network/Proxmox/discovery runs, API access matrix (`make e2e`) | Playwright · Python |
| `deploy/` | Dev compose, production Swarm stack, Caddy, backups | Docker |

Read next: [ARCHITECTURE.md](ARCHITECTURE.md) (components, data flow,
delivery guarantees), [SECURITY.md](SECURITY.md) (accounts, tenancy, threat
model), [DEPLOYMENT.md](DEPLOYMENT.md) (one VPS, TLS, backups and restores),
[CHANGELOG.md](CHANGELOG.md).

## Accounts and organisations

- Sign up with an email and password (argon2id); the emailed link confirms
  the address and signs you in. Optional TOTP two-factor sign-in, password
  reset, and a list of signed-in browsers you can sign out.
- An **organisation** owns servers, rules, contacts and integrations. You
  can own several and belong to others. Roles: **owner**, **admin**
  (everything but API tokens and deleting the organisation), **member**
  (also acknowledges, resolves and assigns incidents, schedules maintenance,
  runs allowed actions) and **read-only**. Invitations are emailed links for
  one address, valid 7 days.
- **Superadmins** (`SUPERADMIN_EMAILS`) run the installation from the admin
  panel: organisations (suspend, resume, delete), users, the agent rollout,
  probes. They see inside an organisation only through an impersonation:
  a reason, one hour, read-only unless writes are asked for, audited.

## Agent

Tested on real systems: Ubuntu 24.04 (systemd), FreeBSD 15.1, OpenBSD 7.9,
NetBSD 10.2 and Windows Server 2025, plus macOS for development.

| Platform | Install | Runs as | Supervised by | Self-update |
|---|---|---|---|---|
| Linux (amd64, arm64) | `curl … install.sh \| sh` | `sentinel` | systemd (`Restart=always`) or OpenRC | root systemd timer / cron |
| FreeBSD (amd64, arm64) | `fetch -qo - … \| sh` | `sentinel` | `daemon(8) -r` via rc.d | root cron |
| OpenBSD (amd64) | `ftp -o - … \| doas sh` | `_sentinel` | rc.d + 5-minute cron watchdog | root cron |
| NetBSD (amd64) | `ftp -o - … \| sh` | `sentinel` | rc.d (pidfile) + 5-minute cron watchdog | root cron |
| Windows Server 2016+ / 10+ | `install.ps1` in elevated PowerShell | `LocalService` | Service Control Manager (restart on failure) | SYSTEM scheduled task |

- One-line install from the web app (`install.sh --uninstall` removes it);
  the agent never runs privileged. Its
  state (including the host token) is readable only by it and administrators.
- Buffers every batch on disk (24 hours) until ingest accepts it; see
  ARCHITECTURE.md for exactly what that guarantees.
- In a container (Docker, LXC, Kubernetes) or a capped systemd unit it
  reports the cgroup v2 limits as the server's size, CPU as a share of the
  quota and memory against the limit, not the whole machine.
- Ingest records the public address each agent connects from
  (`hosts.public_ip`), so servers behind NAT or in a VPC still match uptime
  checks and maintenance by their public IP.
- Fetches its config from Sentinel every 2 minutes, falling back to the URL
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
- Plugins from root-owned files in `/etc/sentinel/plugins.d/*.conf`
  (`%ProgramData%\Sentinel\conf` on Windows): `mysql`, `postgres`, `redis`,
  `nginx`, `apache`, `docker`, `prometheus` (any exporter or `/metrics`;
  series become `sentinel_custom_*`) and `script` (prints `name value`
  lines). Never configured from the dashboard: they hold passwords and a
  script runs code. `sentinel-agent plugins` tests them.
- Actions: the dashboard (or a rule, when it fires) can ask for a fix by
  name; only names in the root-owned `actions.conf` run. `sudo sentinel-agent
  allow-action restart-nginx -- /usr/bin/systemctl restart nginx` writes it,
  a sudoers rule for exactly that command, and (systemd) a drop-in that
  relaxes the unit's sandbox only while sudo actions exist.
- Inventory every 6 hours: packages (dpkg, rpm, apk, pacman, pkg, pkg_info,
  Windows registry), listening ports, kernel, CPU model, virtualization;
  ingest keeps the package changes between inventories.
- Picks up config changes within one push: ingest returns the config version
  with every push and the agent refetches when it changes.
- Self-updates hourly from a separate privileged job: downloads the version
  the rollout offers it, verifies its SHA-256, self-tests it and swaps it in
  atomically (on Windows the running `.exe` is moved aside first). In a
  container, the `sentinel-agent` image (`deploy/agent-container/`) does the
  same from its entrypoint and restarts the agent on the new binary.

### Agent rollouts

The agent has its own version (`agent/VERSION`), so a server-only release
ships no new agent. Ingest offers each server one version
(`agent_rollout`, `ingest/rollout.go` = `app/services/rollout.py`): the
organisation's pin if a superadmin set one, else the candidate when the server's bucket
(FNV-1a of the host id, mod 100) is below `candidate_percent`, else stable.
On a deploy with a newer `AGENT_VERSION` the jobs worker makes it the
candidate for `AGENT_CANARY_PERCENT` (10) of servers; superadmins promote it or
roll it back (`/admin/v1/agent-rollout`, Fleet & probes). The health gate
rolls a candidate back by itself once its servers go silent noticeably more
than the rest (20% and 10 points above, after 75 minutes). Each API image
carries the previous image's agent versions (`PREVIOUS_AGENTS`, newest 6), so
a rollback or a pin can still download its version.
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
  a starter set. **Preview** (`POST /v1/alert-rules/preview`) replays a
  metric or custom rule over the last 7 days before it's saved: how many
  times it would have fired, on which servers, and whether it's noisy.
- Incidents keep a timeline (opened, notified, escalated, acknowledged,
  resolved, reopened, notes, actions, snoozes). Customers add notes, resolve
  by hand, reopen, **snooze** escalations for 30 minutes to a week without
  resolving, and download a **postmortem draft** (Markdown: summary, timeline,
  notes, related alerts on the same server, prompts for impact, cause and
  action items). An alert that opens 4 times in an hour is marked flapping and
  stops notifying until it settles; a silent server holds back its other
  alerts (one problem, one alert).
- Escalation: up to 5 steps per rule ("after 15 minutes, also notify …").
  Steps stop when the incident is acknowledged (dashboard, the signed
  one-click link in every alert, `ACK_SIGNING_SECRET`, or the **Acknowledge
  button on push notifications**) or resolves, and wait while it's snoozed.
- Maintenance windows (one-off, or weekly in a timezone) for every server, one
  server or a tag: no incidents open and nothing is sent; a problem that
  outlasts the window fires when it ends.
- Dependencies: a server can depend on another (a gateway, a hypervisor).
  While that one is silent, the dependent server's alerts are held back.
- The alerter evaluates every 30s: `ok → pending → firing → resolved`, with
  incidents opened and resolved in the same transaction as the state change.
- Notifications go through an outbox (`outbound_messages`) with retries and
  backoff. Email (SMTP or a provider's relay; HTML with acknowledge and
  view buttons), Web Push to browsers and phones (VAPID; a dropped
  subscription is removed), webhooks (signed
  `X-Sentinel-Signature: sha256=…`, private addresses refused), Slack,
  Microsoft Teams, Discord, Telegram (the customer's bot), PagerDuty (Events
  v2: Sentinel incidents trigger and resolve PagerDuty incidents), SMS and
  voice calls (Twilio). Secret targets (webhook URLs, bot tokens, keys) are
  masked whenever the API returns them.
  `ENABLED_CHANNEL_TYPES` (default `email,push`) limits what customers can
  add; contacts saved earlier keep working.
- Contacts: the account email is prefilled and verified, and members' emails
  join when they accept an invitation; others get a 6-digit
  code (5 attempts, 30-minute expiry) and receive nothing until verified. A
  push subscription is verified by being one. Each contact picks the lowest
  severity it receives.

## Status pages, reports, API

- Status pages (`/status/<slug>` HTML, `/public/status/<slug>` JSON): chosen
  servers and checks under the owner's labels, 90-day daily uptime, outages
  of the last week. Never hostnames, addresses or targets. **Announcements**
  (`/v1/status-pages/{id}/updates`): incident updates (investigating →
  identified → monitoring → resolved), planned maintenance and notices; open
  ones lead the page and set its banner, closed ones stay listed for two
  weeks. One-off maintenance windows on the page's servers announce
  themselves.
- **Insights** (`/v1/insights?days=30`): noisy rules with a concrete fix
  each (flapping → recovery level; clears itself within 5 minutes → longer
  duration; several a day → higher threshold), time to acknowledge and
  resolve, **server sizing** from 7 days of busy-hour CPU and peak memory
  (oversized / undersized, with the plan size that would fit), and **SLOs**:
  each uptime check's availability against its target (`slo_target`,
  default 99.9%), error budget left and the current burn rate.
- Reports (`/v1/reports/summary`, `.csv`): availability, incidents, time to
  acknowledge and resolve, noisiest rules, resource use, days until disks
  fill. Organisations get it by email on the 1st unless they turn it off.
- API tokens (`pgt_…`, read-only by default) act as the organisation;
  managing tokens needs a signed-in owner. OpenAPI at `/api/docs`.

## Logs

Opt-in per server: a root-owned `/etc/sentinel/logs.conf` (`file = <glob>`,
`journal = true`). The agent ships new lines (rotation-aware, offsets kept
across restarts, no backfill) to ingest `/v1/logs`, which writes them to
VictoriaLogs in the tenant's own account (`AccountID` =
`tenants.logs_account_id`), with the host from the token as a stream field, at
most `LOG_LINES_PER_MINUTE` per host. The API searches (`/v1/logs`, text or
RE2, server, file, level; `after=<ns>` for live tail), counts
(`/v1/logs/volume`) and lists sources; searches can be saved
(`/v1/saved-views`). Log rules (`kind: logs`) fire when more than `threshold`
lines match within `window_seconds`; the alerter counts them with a LogsQL
stats query in the same account. 14 days kept (`LOG_RETENTION`). Off unless
`VICTORIALOGS_URL` is set.

## APM

Opt-in per server: `/etc/sentinel/apm.conf` (`listen = 127.0.0.1:4318`)
makes the agent an OTLP/HTTP receiver; apps use
`OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318` and need no key. Ingest
decodes each batch, sets `sentinel.host_id` from the token (replacing any
the app sent), caps `SPANS_PER_MINUTE` per host and writes to Tempo as the
tenant. The API reports services (requests, error rate, p50/p95/p99 from
TraceQL metrics over entry spans), searches traces and returns one trace's
spans; 7 days kept. Off unless `TEMPO_URL` is set.

## Network monitoring

Switches, firewalls, routers and Proxmox VE clusters are **network devices**:
hosts with `kind = network`, so not-reporting alerts, maintenance windows,
dependencies, tags, pausing and incidents work for them as for servers.
A device has no agent of its own: one of the organisation's servers at its
site polls it (its *poller*) and reports for it, through its own spool.

- **Adding devices:** Network › Add devices (addresses or hostnames, a
  credential, the poller, optionally a role and a pinned profile), or
  **Discover**: the poller scans a private range (up to /22) for devices
  answering SNMP and lists what each one is.
- **Credentials:** SNMP v1/v2c communities, v3 users (MD5/SHA/SHA-2 with
  DES/AES/AES-192/256, including the Cisco key extension), and Proxmox API
  tokens. Sealed with `CREDENTIALS_KEY` (AES-256-GCM); the API only says
  whether each secret is set.
- **What's collected** (`netmon/`, profiles in `netmon/profiles/*.yaml`,
  detected from sysObjectID/sysDescr): interface counters and status every
  30 s (64-bit counters when present, names from ifName), health every
  minute (CPU, memory, sensors, VPN tunnels, SD-WAN, HA, BGP/OSPF), and
  inventory and LLDP neighbours every 6 h and after a reboot. Metrics are
  `sentinel_net_*` under the device's `host_id`. Profiles: Arista EOS,
  FortiGate, Sophos SFOS, Aruba Instant On, TP-Link JetStream/Omada, and a
  generic fallback; adding a vendor is a YAML file.
- **Topology:** LLDP neighbours are matched to known devices by name,
  management address or chassis MAC. Mark the core switches (role *core*)
  and each device's upstream becomes the neighbour one hop closer to them
  (set as its dependency, unless one was set by hand), so a failed switch
  is one alert and the devices behind it are *affected*. A device without
  an upstream depends on its poller. Network › Topology draws it.
- **Servers on switch ports:** agents report their NICs' hardware
  addresses, and a server whose NIC a switch sees over LLDP shows where
  it's cabled (server › Settings) and depends on that switch, so a failed
  top-of-rack switch is one alert, not one per server. A server cabled to
  two switches, or one that polls its own switch, gets no automatic
  upstream; one set by hand is kept.
- **Alerts:** rule kind `network` with a condition from a catalog
  (`/v1/network/conditions`): interface down (ports that were up in the
  last day), utilisation, errors, LAG member down, reboots, every
  profile's alerts, and Proxmox node offline, lost quorum, guest stopped,
  node CPU/memory and full storage. They arrive, with sensible timings,
  when the first device is added. A silent device is "unreachable", with
  the poller's reason (timeout, wrong community, refused token).
- **SNMP traps:** the poller receives traps (v1, v2c, v3 and informs) from
  the devices it polls, accepting only their own community or v3 user. They
  ride the agent's spool like metrics. UDP 162 needs `install.sh --traps`
  (systemd and OpenRC grant the service CAP_NET_BIND_SERVICE only);
  otherwise the agent listens on 1162 (`SENTINEL_TRAP_PORT` picks another,
  0 turns traps off). A catalog (`netmon/traps`) maps FortiGate events
  (VPN tunnel, HA, power, fans, conserve mode, IPS, AP and FortiSwitch
  down…) and the standard ones (BGP, OSPF, link, restart) to 29 network
  conditions: paired traps open and close an alert, one-off traps clear
  after a while without a repeat, and the alert's detail names every open
  tunnel or peer. Every trap shows on the device's Events (30 days); a
  flood is one row with a count, and a sender that isn't a device never
  alerts.
- **Bandwidth:** tag ports with a customer or service (*billing tag*);
  Network › Bandwidth gives the 95th percentile of 5-minute rates (ports
  summed per sample, missing samples skipped, coverage shown), per month in
  the organisation's timezone, with CSV.
- **Proxmox VE:** a cluster's address (port 8006) with an API token
  credential (PVEAuditor is enough): nodes, VMs, containers, storage and
  quorum, polled every minute through the API.

### Hardware

- `sudo sentinel-agent enable-hardware` finds smartctl disks, an IPMI BMC
  and LVM volume groups and thin pools, writes `plugins.d/smart.conf`,
  `ipmi.conf` and `lvm.conf`, and a sudoers file allowing exactly those
  read-only command lines (`--remove` undoes it; without sudo, a root timer
  caches the output). Metrics: `sentinel_custom_smart_*`,
  `sentinel_custom_ipmi_sensor{sensor,unit}`, and LVM storage as disks
  (`lvm:<vg>`, `lvm:<vg>/<pool>`) plus `sentinel_custom_lvm_metadata_percent`.
- A `type = snmp` plugin file still polls one device from the server with
  named custom OIDs (`sentinel_custom_snmp_*`), for anything outside the
  profiles.

## Terraform

`terraform-provider-sentinel/`: alert rules, checks, maintenance windows,
status pages, install keys and a hosts data source, with an API token.

## Jobs

`python -m app.jobs` (the `jobs` service; replicas stand by on an advisory
lock): monthly report emails, hourly rollups of every series into the
long-term VictoriaMetrics (`VICTORIAMETRICS_LONG_URL`; gauges keep the hourly
average, counters the hour-end value), which charts read for ranges past raw
retention or longer than a month, daily cleanup, and agent rollouts (adopting
a new `AGENT_VERSION` as the canary, and the health gate).

## Probes

Uptime checks run on agents a superadmin marks as probes (`PUT
/admin/v1/hosts/{id}/probe {"region": "…"}`). Only agents in the
organisations listed in `PROBE_ACCOUNT_IDS` qualify: a probe receives every
organisation's uptime check targets. An agent in a
container is enough (no root needed).
- Run 2+ alerter replicas: a Postgres advisory lock keeps one active and the
  rest on standby.

## Develop

```sh
make up          # Postgres, Redis, VictoriaMetrics, Mailpit, migrations, api :8010, ingest :8090, alerter, jobs
cd web && npm ci && npm run dev    # the web app on :3000, proxying /api to :8010
make agent       # agent binaries for every platform + checksums into api/dist/dev
make test        # Go tests + API tests (needs `make up`)
make lint        # gofmt, go vet, ruff, ty, and the web app's eslint/prettier/tsc
```

Sign up at http://localhost:3000/signup; the confirmation email lands in
Mailpit at http://localhost:8035. Put your address in `SUPERADMIN_EMAILS`
(`deploy/.env`) to see the admin panel. Then, with an install key from
"Add server":

```sh
go run ./agent register --url http://localhost:8090 --key pg_... --state-dir ./.agent/state
go run ./agent run --state-dir ./.agent/state
```

After an API change, regenerate the typed client: `cd web && npm run api`
(CI fails if it's out of date).

## Release

Push a tag `vX.Y.Z` (confirm first: it publishes images that autoupdate).
The `Release` workflow publishes
`ghcr.io/alzywelzy/sentinel-{api,ingest,alerter,agent,web}:X.Y.Z` and
attaches agent binaries with `.sha256` files to the GitHub release; the API
image also serves them. A new `agent/VERSION` reaches the canary share of
servers first; superadmins promote it (or the health gate rolls it back).
