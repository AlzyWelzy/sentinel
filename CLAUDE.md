# Sentinel

Sentinel (this repo, formerly "Pulsegrid Beyond") is a multi-tenant monitoring product for servers and uptime, owned by its author, at **sentinel.rajpoot.app**.

## Sentinel stands on its own

Sentinel is its own project. It does not rely on any other project, and work here never depends on one.

- **History:** it started from a copy of an earlier monitoring codebase (Pulsegrid) at release v0.8.27 (`565b89f`, agent 0.8.11). That's history only: that product, the console it served and its services are not upstreams, dependencies or deploy targets.
- **No syncing:** don't pull from, push to, or sync with the Pulsegrid repositories. Changes start here. Anything borrowed from elsewhere is re-implemented here deliberately.
- **Own infrastructure:** use only Sentinel's own accounts, registry (`ghcr.io/alzywelzy/sentinel-*`), domain, servers, secrets and email provider. Never use another organisation's resources.
- **The repo** is `AlzyWelzy/sentinel` on GitHub (renamed from `pulsegrid-beyond` on 2026-11-20, history anonymised) and public; the Go module path matches it.

`README.md` has the feature list, `ARCHITECTURE.md` the components, data flow and delivery guarantees, `SECURITY.md` accounts, tenancy and the threat model, `DEPLOYMENT.md` the single-VPS setup, backups and restores. This file holds what they don't: how work is done here, where things stand, and what was learned running the inherited code on a real fleet of about 80 servers.

## Ground rules

- **Python (`api/`):** use uv, ruff and ty. Run `uv run ruff format`, `uv run ruff check` and `uv run ty check`.
- **Go:** run `gofmt` and `go vet ./...`.
- **Web (`web/`):** strict TypeScript, ESLint, Prettier. After any API change run `npm run api` to regenerate the typed client; CI fails if it's stale.
- `make lint` runs all three.
- **Commits:** use conventional subjects (`fix(agent): …`, `feat(api): …`). Write the subject as plain-language behaviour, as `git log` shows. Agent changes end with `; agent X.Y.Z`.
- **No AI attribution:** never add a Co-Authored-By Claude line or "Generated with Claude Code" to commits or PRs.
- **Never echo credentials or tokens** in output or logs.
- **Confirm before tagging a release.** A tag publishes images, and whatever autoupdates from them deploys.

## Names that stay short

- Token prefixes `pg_` (install keys), `pgh_` (host tokens), `pgt_` (API tokens), the `pg_refresh` cookie and `pg.*` browser storage keys are inherited and kept: they're opaque, and changing them buys nothing.
- The dev compose project is `beyond-dev` (host ports offset by 10: Postgres 5442, Redis 6389, VictoriaMetrics 8438/8439, VictoriaLogs 9438, Tempo 3210/4329, Mailpit 8035 and SMTP 1035, API 8010, ingest 8090). It must never share a name with the company Pulsegrid checkout's `pulsegrid-dev`.

## How releases work

1. **Tag:** push a tag `vX.Y.Z`. CI builds the images (api, ingest, alerter, web, agent; jobs runs from the api image) and the agent binaries.
2. **Server autoupdate:** `deploy/autoupdate.sh` on the server deploys newer images, with a dump first and an automatic rollback. The agent version lives in `agent/VERSION`, separate from the release number.
3. **Agent rollout:** a new agent version becomes the *candidate* for 10% of hosts, and `agent_rollout` in Postgres tracks it.
4. **Promote:** from the superadmin panel, or set `stable_version` to the candidate and clear `candidate_*`. The jobs service must have registered the candidate first; promoting too early just needs a re-run.
5. **Hourly update:** agents check for updates hourly through a root timer or cron, and autoconfig runs right after an update.

## Local testing

- `make up` starts the dev compose stack; `cd web && npm run dev` the web app on :3000 (it proxies `/api` to :8010).
- `go test ./...` runs the Go tests.
- `cd api && uv run pytest` runs the API tests. They need Postgres and Redis running and migrated. With the dev alerter running, it may send account emails before a test reads them; the tests then read the link from Mailpit.
- **After a reboot:** the test stack containers don't start on their own. Start postgres, redis, victoriametrics (and its `-long` copy), victorialogs, tempo and mailpit before running pytest.
- **End to end:** sign up at :3000, confirm from Mailpit (:8035), install the agent from "Add server", `docker stop beyond-dev-ingest-1` for four minutes, and watch the "not reporting" and recovery emails arrive.
- **Disk space:** image builds need several GB free. When the disk filled during a build, Docker Desktop stopped responding until it was restarted.

## Inherited state (v0.8.27, 2026-11-02)

What the code did at the fork, still true except where the roadmap below says otherwise. Names here are the old ones: `pulsegrid-*` and `pulsegrid_*` are now `sentinel-*` and `sentinel_*`.

### Agent 0.8.11 (Go)

- **Autoconfig (revision 5)** detects these and writes their config:
  - logs
  - Redis, nginx, Apache, PostgreSQL and MySQL
  - Docker
  - SMART and IPMI hardware
- **Hourly re-check:** an hourly repair re-runs detection. Services installed later are picked up once each, recorded in `.autoconfig-tried` in the state directory.
- **Hardware without sudo:** many customer servers have no sudo binary. In that case a root systemd timer (`pulsegrid-agent-hardware.timer`) runs `smartctl`/`ipmitool` and caches the output, and the plugin reads the cache. Where sudo exists, a sudoers drop-in is used instead.
  - Refused sudo calls back off.
  - A slow BMC keeps its last good reading, and the plugin reports why a run failed.
  - IPMI is skipped when the BMC returns no readings, which is normal on VMs.
- **SMART:** MegaRAID devices are supported. Disks are rescanned when every listed disk fails.
- **Logs:**
  - Every text log under `/var/log`, skipping rotated, binary and journal-duplicate files.
  - Docker container logs.
  - The Windows Event Log, read with `wevtutil`.
  - A cap of 200 files per round, choosing the most recently written files.
- **Delivery:** batches are spooled on disk for up to 24h and sent oldest first. A failed push retries every tick (30s), and the HTTP timeout is 20s.

### Alerter (Go)

- **Rule kinds:** threshold (`metric`), anomaly, forecast (`predict_linear` over 1h/6h, or 6h/24h past 24h), host_down, check, process, service, plugin, container, logs and custom.
- **Plugin alerts** name the failing plugins and their errors, and recoveries name them too. A plugin whose config file was removed closes its alert.
- **Disk and inode alerts** list the full mounts, fullest first, with the space left on each (for example "/nvme 94.6% used, 386.0 GB free").
- **Server not reporting** has these send rules:
  1. The rule's duration defaults to 180s of silence.
  2. The firing message is held 60s (`hostDownGather`).
  3. If the server is back before then, neither the alert nor the recovery is sent (`skipBlips`).
  4. Servers that drop together go out as one email per contact (`groupHostDown` in `dispatch.go`). Only first attempts on email channels are grouped.
- **Outbox retries:** 20s, 40s, 2m, 5m, 15m, 1h, then 3h, so a redeploy of the email backend loses nothing. The first transient failure is logged at Info.
- **Notification channels:** email, SMS, webhook, Slack, Teams, Telegram, Discord, PagerDuty, voice and Web Push.
- **Delivery controls:** quiet hours per contact, on-call schedules with escalation, flap detection, maintenance windows and host dependencies.

### API (FastAPI)

- **Customers:** servers, rules, incidents, checks, status pages, dashboards, reports (PDF, 22 charts), digests, audit log, team members as contacts, and recommended rules for every account.
- **Staff tools:** view-as, edit, pause or remove any server, install keys for a customer, and a fleet wall.

### Timezones

All timestamps are stored in UTC. Digests use the account's own timezone.

### Live-tested before the fork

The v0.8.27 alerter changes were verified on a demo fleet. Three servers were stopped for about 3.5 minutes:
- Alerts were held 60s before sending.
- Alerts for two servers went to each contact as one grouped email, and the three recoveries went out together.
- Alerts whose servers were back within the hold were skipped, along with their recoveries.

## Roadmap: a fully standalone app

Each phase ends with something that runs. **Done means:** a stranger can open sentinel.rajpoot.app, sign up, install the agent, get an alert email from Sentinel's own domain, and manage everything in Sentinel's own UI, with no other company's service running anywhere. On the dev stack that works end to end; production needs the server, DNS and accounts below.

### Phase 1: Own infrastructure

- [x] Images at `ghcr.io/alzywelzy/sentinel-*` (workflows, stack, autoupdate, agent image); Go module at the repo's own path.
- [x] Product name and domain: Sentinel, `sentinel.rajpoot.app` (`APP_HOST`), `ingest.` and `get.` subdomains. Links come from `PUBLIC_APP_URL`; installers from `PUBLIC_DOWNLOAD_URL`.
- [x] Console stack, console env, sentinel gateway and Kuma files deleted; console keys removed from every env example.
- [x] Ingest: 413 instead of a data-losing 400, per-token rate limits, timestamp window; VictoriaMetrics dedup; atomic spool writes (agent 0.9.0).
- [ ] **Owner's accounts:** the server, DNS records, SMTP provider with SPF/DKIM/DMARC, Turnstile keys, VAPID keys. Steps in `DEPLOYMENT.md`. GitHub Actions needs no extra secrets (it publishes with `GITHUB_TOKEN`).

### Phase 2: Own accounts and login

- [x] `users`, sessions with rotating refresh tokens, email verification, password reset, optional TOTP, session list and revoke (`api/app/auth/native.py`, `services/accounts.py`).
- [x] Console identity removed (`auth/console.py`, JWKS/JWT settings, staff roles, dev auth bypass).
- [x] Organisations: a tenant is an organisation, every member (owner too) a `tenant_members` row with a user; invitations by emailed token; owner, admin, member (`operator`), read-only (`viewer`).
- [x] Superadmins from `SUPERADMIN_EMAILS`; audited, time-limited, read-only-by-default impersonation.
- [x] Sign-up protection: Redis rate limits, Turnstile, lockout after failed sign-ins.
- [ ] Later: Google or GitHub sign-in.

### Phase 3: Own email and notifications

- [x] SMTP (or a provider's relay) is the only email path; `consoleMailer` deleted. Account emails go through `account_emails` with the alert outbox's retries.
- [x] Branded templates for account emails (`services/account_emails.py`); alert, digest and report emails were already Sentinel's own HTML.
- [x] A mail server refusing the recipient marks the contact undeliverable until it's verified again.
- [ ] Bounces and complaints a provider reports later, by webhook. Pick the provider first.
- [x] Web Push subject is configurable (`VAPID_SUBJECT`); generate keys at deploy time.
- [x] SMS and voice stay off (`ENABLED_CHANNEL_TYPES`) until there's a Twilio account.

### Phase 4: Remove the console-only API surface

- [x] `routes/internal.py` and `auth/internal.py` deleted. Suspend, resume and delete moved to the superadmin panel; recommended rules run on organisation creation; members replace team contacts; usage, ticket incidents, ticket contacts, notify, the maintenance lookup and external monitors are gone (migration 0023 drops `external_monitors`).

### Phase 5: Own frontend

- [x] `web/`: Next.js (App Router), TypeScript strict, TanStack Query, uPlot, a typed client generated from OpenAPI.
- [x] Sign-in, sign-up, verify, reset, two-factor, invitation acceptance.
- [x] Onboarding: name the organisation, install command for Linux/BSD, Windows, Docker and cloud-init, wait for the first server.
- [x] Overview; servers list and detail (Overview, Disks, Processes, Network, System, Activity; time ranges and custom).
- [x] Incidents with timeline, acknowledge, resolve, reopen, notes, assignment; alert rules; maintenance windows.
- [x] Contacts with verification; uptime checks; status pages, public ones rendered on the server.
- [x] Logs, APM, dashboards, reports (with PDF), audit log, API tokens and install keys, organisation and members, account security.
- [x] Superadmin panel: organisations, impersonation, users, agent rollout.
- [x] On-call rotations and overrides, escalation steps, rule edit, 7-day preview and test alerts, quiet hours and minimum severity per contact, incident snooze and the delivery list, server tags, dependencies, notes and allowed actions, insights (noisy rules, sizing, SLOs).
- [x] Public site in `web/`: landing page at `/` (the dashboard is `/overview`), terms, privacy, and a setup and troubleshooting guide (`/help`), all rendered on the server.
- [x] Incident merge, saved views (servers and logs), and a fleet wall with a full-screen TV mode.
- [ ] Pricing and billing, if it's ever paid (the roadmap keeps room for it; nothing is built).
- [x] Served on one origin: Caddy sends `/api/*` to the API and everything else to `web`.

### Phase 6: Polish and operations

- [x] Self-monitoring and an external uptime monitor: documented in `DEPLOYMENT.md`; set up once the server exists.
- [x] Backups: every Postgres dump is restored into a scratch database (`restore-check.sh`); VictoriaMetrics backup and restore (`vm-backup.sh`); runbook in `DEPLOYMENT.md`.
- [x] Terraform provider renamed (`terraform-provider-sentinel`).
- [x] Binaries, services and paths renamed (`sentinel-agent`, `/etc/sentinel`). No agents were installed under the old names, so no migration path is needed.
- [x] Agent uninstall: `install.sh --uninstall`, `install.ps1 -Uninstall`.
- [x] Terms and privacy pages; per-organisation export (JSON, secrets masked); owners hand an organisation to another member; users delete their own account (and organisations only they are in). The legal text is a sound starting point, not legal advice: have it reviewed before taking paying customers.

### Phase 7: Network monitoring (from Beacon) and beyond

- [x] Pulsegrid since the fork (v0.8.28-30): LVM volume groups and thin pools as disks, the clearer alert email (Sentinel's design, the organisation's timezone, the event's own time).
- [x] SNMP devices (`netmon/`, Beacon's profile engine and recordings) polled by a site agent; devices are hosts with `kind = network`; credentials sealed with `CREDENTIALS_KEY`.
- [x] LLDP topology with automatic upstreams toward core devices; a device without one depends on its poller.
- [x] Servers on switch ports: agents report burned-in NIC MACs (`HostMeta.macs`), LLDP neighbours match them, and a server seen on one switch depends on it (not dual-homed servers, nor a poller on its own switch).
- [x] Network rule kind with a catalog shared by the alerter (`alerter/network.go`) and the API (`services/netconditions.py`); a test on each side checks the keys match.
- [x] 95th-percentile bandwidth per billing tag; Proxmox VE through its API; discovery of private ranges.
- [x] SNMP traps: the agent receives v1/v2c/v3 traps itself (gosnmp) on 162 with `install.sh --traps` (CAP_NET_BIND_SERVICE) or 1162; catalog in `netmon/traps` shared by ingest and the alerter (trap conditions are network conditions, keys `trap_*`).
- [ ] Still to port from Beacon (owner's decision 2026-11-20): IPDR per organisation (syslog, sFlow/NetFlow/IPFIX, MAC/ARP, ClickHouse, audit chain, seals, approved exports), availability CSV.
- [x] Per-customer contacts: notification_channels.only_tag, filtered by host tags (incident members' tags for site incidents) in the alerter.
- [x] Reminders (tenants.reminder_minutes, alerter/reminders.go), affected hosts on a not-reporting incident (alerter/affected.go, IncidentDetail.affected), site incidents (alerter/sites.go: 5+ hosts behind one public IP or poller within 15 min, incidents.site_key). Live: `e2e/api/alerting_live.py`.
- [x] Protocol checks (agent 0.11.0, `agent/checks/protocols.go`): WebSocket, SMTP, NTP, Redis, PostgreSQL, MySQL, MongoDB, Kafka, MQTT, gRPC health, SIP, RADIUS, game servers (A2S, Minecraft), SNMP value, Docker container, system service; HTTP methods, headers, basic/bearer auth, JSON value comparisons, redirect limit; any check upside down (`invert`). Secrets in params and URL targets are answered as a mask (sending the mask back keeps them), and stay out of the export and audit log.
- [x] Push checks: `<ingest>/push/<token>` (GET/POST, status, msg, ping), down on a down push or silence past interval + grace (intervals up to a week), token rotation (`POST /v1/checks/{id}/push-token`). Live: `e2e/api/push_live.py`.
- [x] Notification catalog: 100 providers (chat, push apps, incident tools, WhatsApp/Signal bridges, regional, SMS and email services on the customer's own accounts) from one template engine (`alerter/providers.go`); source `scripts/notifiers.py` writes `proto/notifiers.json` and the API's copy (a test keeps them equal). Contacts are verified through the provider; secrets are masked; changing the destination needs verifying again. Not in it: Apprise, Nostr, Microsoft Graph, Aliyun SMS, Teltonika (private-network routers). Live: `e2e/api/notifiers_live.py`.
- [x] Check groups (`type = group`, `checks.parent_id`): down while any member below has an open incident, so members' own confirmation decides; the alert names them (`alerter/store.go downMembers`). Live: `e2e/api/groups_live.py`.
- [x] Status page badges (`/public/status/{slug}/badge.svg`, overall or per item: status, uptime, response; only what the page shows) and status pages on the customer's own domain: TXT `_sentinel.<domain>` proves it, Caddy's `on_demand_tls` asks `/public/domain-check`, the catch-all site rewrites to `/public/host/…` with `X-Status-Host`.
- [x] HTTP checks: proxy (http/https/socks5, through the probe guard), client certificate, OAuth client credentials (token cached until expiry); every HTTP method. Check params are capped (40 keys, 16 KB each).
- [x] Real-browser checks (agent 0.12.0, `agent/checks/browser.go`, chromedp): steps (goto, click, type with `{{username}}`/`{{password}}`, wait, expect_text, expect_no_text, sleep), status, keyword, load time, script errors and failed requests as limits and metrics, a JPEG of the failing page (`pg:checkshot:<id>`, `GET /v1/checks/{id}/screenshot`). On probes all browser traffic goes through a loopback proxy using the public-address guard; remote browsers (`browser_ws`) only on customers' servers. One browser at a time per agent. Probe image: `sentinel-agent-browser` (Dockerfile `BROWSER=1`). Live: `e2e/api/browser_live.py`.
- [x] Device insight (`GET /v1/network/devices/{id}/insight`, the device page's Insight card): availability, busiest and peak ports, errors, state changes, a 7×24 hourly traffic heatmap (UTC, the current hour included).
- [ ] Kuma ideas still open: none of its monitor types are missing; Apprise, Nostr and Microsoft Graph notifiers aren't in the catalog. Kuma's source was read for lessons, not copied. Beacon's console tickets and JWT sign-on don't apply.

### Verified end to end (dev stack, real containers)

- `deploy/stack.yml` resolves with every variable of `production.env.example` set; Caddy validates the production Caddyfile; actionlint and shellcheck are clean.
- Migrations run up, down to base and up again; the API suite passes (229 tests); the typed web client matches the API.
- A browser journey (Playwright, scratch script, not in the repo) through the production web image behind Caddy's production routing: landing and legal pages, sign-up and the emailed link, onboarding, a real agent arriving, every screen, rule edit, preview and test, contacts and quiet hours, on-call, status pages (public, rendered on the server, no hostnames), dashboards, PDF report, API tokens, data export, invitations, roles, an outage with the alert and recovery emails, acknowledge, assign, notes, snooze, deliveries, two-factor, password reset signing other browsers out, superadmin impersonation, account deletion, mobile width and dark mode.
- `install.sh` and `--uninstall` on Ubuntu 24.04 with systemd as PID 1: user, units, timers, autoconfig, registration, spool drained once ingest was reachable, then nothing left behind.
- The `installers` workflow passes on Linux, Windows (`install.ps1` and `-Uninstall`), FreeBSD, OpenBSD and NetBSD: install, the service runs, a metrics push arrives, uninstall leaves nothing.
- The redesigned web app passes the browser journey (41 steps) and the extras (fleet wall, saved views, incident merge).
- Backups: a real dump restores (`restore-check.sh`), a truncated one is caught, and the nightly loop runs both; `vm-backup.sh` brings back a series deleted after the backup.
- The end-to-end scripts live in `e2e/` (`make e2e` runs the journey, extras and access matrix; it clears `pg:rl:*` and the journey's `superadmin@example.com` first). Don't run the API tests at the same time: they sign up accounts from the same address and trip the hourly sign-up limit.
- Network, live (0.10.0): a real agent polled simulated Arista and FortiGate devices (snmpsim serving `netmon/testdata/walks`), a fake Proxmox API over HTTPS, and a discovery scan; the network UI passes in a browser (including cancelling a scan); the access matrix covers the network endpoints. Simulator data must be sorted by OID, one record a line: `e2e/api/snmpsim_data.py` prepares it from the recordings.
- Traps, live (`e2e/api/traps_live.py`): a real agent on SENTINEL_TRAP_PORT=11162 receives net-snmp `snmptrap` traps; VPN down opens an incident naming the tunnel, a wrong community is dropped, a 20-trap flood is one row, VPN up resolves it. Real FortiGates send traps to Beacon's production receiver on notify's UDP 162: never take that port; real-device traps weren't tried.
- Network, real gear (2026-11-20, a temporary unprivileged poller reaching a dev stack through an SSH tunnel, removed afterwards): a FortiGate and two Arista EOS switches identified, 280 interfaces with rates (both ends of a 40G link agree), LLDP resolved between the switches both ways, and a server NIC's MAC matched to its ToR port with the server's upstream set automatically. Proxmox wasn't tried on real gear.

### Not verified here

- Anything needing the real domain and accounts: TLS issuance, SMTP delivery to outside mailboxes, Turnstile, Web Push.
- The installers on BSD and Windows run in CI (`installers` workflow, against `deploy/testing/installer-stub`), not on customer-like machines with real services for autoconfig to find.

## Lessons from building it

- **A write that fails at flush can look like success:** the audit savepoint used to flush the request's own changes inside it and swallow the error (200, nothing saved). `record_safely` flushes first now; when adding a `tenants` column the API writes, grant `UPDATE (column)` to `sentinel_app` (that table has column-level grants). Tests should read a setting back, not trust the response.

- **A service that starts importing another package needs its Dockerfile to COPY it:** the alerter's build broke when it first imported `proto`. In dev, `docker compose build` the `migrate` image too, or a new migration isn't found and nothing restarts.
- **Keep test scripts in the repo.** The browser journey once lived in a scratch folder and was lost when it was cleaned up.
- **The disk fills during image builds** and Docker Desktop then stops answering; `docker builder prune -af` and the Go/npm caches free several GB.
- **CI can stop for billing:** when GitHub Actions refuses jobs ("recent account payments have failed"), every job fails in seconds with no logs. Run the CI steps locally (`make lint`, `go test -race ./...`, `uv run pytest`, `npm run build`) and hold the tag: the release workflow can't build images either.
- **A full disk breaks more than the build:** Docker Desktop's disk turns read-only (only a restart fixes it, and it restarts every container), and macOS purges `~/Library/Caches` (Playwright's Chromium went with it). Check `df -h /` before image builds; a Mailpit at its 500-message cap also slows the e2e sign-ups to timeouts (`DELETE /api/v1/messages`).
- **Fixtures from real devices** (`netmon/testdata/walks`) are anonymised with `netmon/testdata/anonymise.py` (names, serials, IPs, MACs, customer words). Run it over every new recording and read the remaining strings before committing: the repo is public.

## Lessons from the production fleet

- **Shared NAT:** many servers sit behind one public IP. A short network drop there silences a group of them at once. That's real downtime from the monitor's point of view, but customers shouldn't get one email per server, so the grouping and blip suppression exist.
- **One alert, many emails:** a client with 12 team members subscribed gets 12 emails per alert, as designed. Grouping keeps the count to one per person per event.
- **Missing sudo:** some customers' servers don't have sudo installed. Root-run fallbacks are needed for anything privileged.
- **No hardware on VMs:** VMs report no IPMI or SMART. Treat "no readings" as "not applicable", not as a failure.
- **Windows:** CI path comparisons must use forward slashes. Autoconfig must run right after an update.
- **Text from customers' servers is hostile by accident:** hostnames, log lines, mount and process names end up in PDFs (ReportLab parses markup: escape with `esc`), Slack (`<!channel>`), Discord (`@everyone`), CSVs (formulas) and Postgres (no NUL). Escape for each sink, and cut to service limits with `cut` (alerter), never by bytes: a 400 from a chat service is treated as permanent and the alert is lost.
- **Alert detail:** an alert is only useful if it says *what* failed. Plugin, check and disk alerts all carry a detail line, so keep that true for new rule kinds.

## Open ideas

- **Correlated outages:** detect several hosts behind one public IP going silent together. Open one "network" incident and link the hosts to it, instead of N incidents.
- **Dependency hint:** when several servers drop together, suggest a host dependency (`depends_on_host_id`).
