# Pulsegrid Beyond

Pulsegrid Beyond is a multi-tenant monitoring product for servers and uptime, owned by its author.

## Beyond stands on its own

Beyond is its own project. It does not rely on any other project, and work here never depends on one.

- **History:** Beyond started from a copy of Pulsegrid at release v0.8.27 (`565b89f`, agent 0.8.11). That's history only. Pulsegrid, the Example console, billing and every other Example service are not upstreams, dependencies or deploy targets.
- **No syncing:** don't pull from, push to, or sync with `example-org/pulsegrid` or `AlzyWelzy/pulsegrid`. Changes start here. Anything borrowed from elsewhere is re-implemented here deliberately.
- **Own infrastructure:** use only Beyond's own accounts, registry, domains, servers, secrets and email provider. Never use company resources.
- **Remove the coupling:** wherever the code still assumes the Example console (see "Removing inherited coupling"), Beyond's direction is to remove that dependency, not to keep it working.

To start a build session, paste `docs/kickoff-prompt.md` into Claude Code from this folder.

See `README.md` for the architecture, multi-tenancy, the agent platforms and the full feature list. This file holds what the README doesn't: how work is done here, where things stand, and what was learned running it on a real fleet of about 80 servers.

## Ground rules

- **Python (`api/`):** use uv, ruff and ty. Run `uv run ruff format`, `uv run ruff check` and `uv run ty check`.
- **Go:** run `gofmt` and `go vet ./...`. `make lint` runs both languages.
- **Commits:** use conventional subjects (`fix(agent): …`, `feat(api): …`). Write the subject as plain-language behaviour, as `git log` shows. Agent changes end with `; agent X.Y.Z`.
- **No AI attribution:** never add a Co-Authored-By Claude line or "Generated with Claude Code" to commits or PRs.
- **Never echo credentials or tokens** in output or logs.
- **Confirm before tagging a release.** A tag publishes images, and whatever autoupdates from them deploys.

## Removing inherited coupling

The inherited files still point at company infrastructure and the console. Replace each item below with Beyond's own before CI or a deploy runs from this repo. Until then, treat these as bugs:

- **Image registry:** workflows and stack files use `ghcr.io/example-org/pulsegrid-*`. Switch to a personal registry, or a build here could overwrite company images that autoupdate onto company prod.
- **Console coupling:** identity and email go through the Example console:
  - The API trusts the console JWT.
  - The alerter sends email through the console (`CONSOLE_EMAIL_URL`, the `consoleMailer` sender in `alerter/notify.go`).
  - Tenants are keyed `(source, console uid)`.

  Beyond needs its own sign-up/login and its own tenants. Email should go through `emailSender` (SMTP), not `consoleMailer`.
- **Domains, secrets and env:** see `deploy/production.env.example`, `deploy/console.env.example` and `deploy/sentinel/`.
- **GitHub Actions:** this repo has no secrets yet, so nothing publishes until you add them.

## How releases work (inherited design)

1. **Tag:** push a tag `vX.Y.Z`. CI builds the images (api, ingest, alerter, jobs) and the agent bundle.
2. **Server autoupdate:** the server autoupdates from the registry. The agent version lives in `agent/VERSION`, separate from the release number.
3. **Agent rollout:** a new agent version becomes the *candidate* for 10% of hosts, and `agent_rollout` in Postgres tracks it.
4. **Promote:** set `stable_version` to the candidate and clear `candidate_*`. The jobs service must have registered the candidate first; promoting too early just needs a re-run.
5. **Hourly update:** agents check for updates hourly through a root timer or cron, and autoconfig runs right after an update.

## Local testing

- `make up` starts the dev compose stack.
- `go test ./...` runs the Go tests.
- `cd api && uv run pytest` runs the API tests. They need Postgres and Redis running and migrated.
- **After a reboot:** the test stack containers don't start on their own. Start postgres, redis, victoriametrics (and its `-long` copy), victorialogs, tempo and mailpit before running pytest.
- **Demo fleet:** the old setup ran demo servers as Docker containers (one agent per container, Dockerfiles for apt- and dnf-based images, plus a probe container). It's a good way to test outages: `docker stop` a few containers and watch the alerts.

## Inherited state (v0.8.27, 2026-11-02)

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

The goal is for Beyond to be a complete product of its own: its own frontend, backend, accounts, email, infrastructure and domain. It should run with nothing from Example.

Today the backend (agent, ingest, alerter, API, jobs) is Beyond's, but three things live in the console:
- the user interface (the console's Monitoring pages)
- who users are (sign-up, login, staff)
- how email is sent

Work through these phases in order. Each phase ends with something that runs. Tick items off here as they land.

### Phase 1: Own infrastructure, so nothing can touch company systems

- [ ] Point images at Beyond's own registry (`ghcr.io/alzywelzy/pulsegrid-beyond-*` or similar):
  - `.github/workflows/release.yml`
  - `deploy/stack*.yml`
  - `deploy/sentinel/`
  - the agent self-update and download URLs
- [ ] Choose a product name and domain. Replace `CONSOLE_HOST`, the dashboard and ack links (`dashboardLink`, `ackURL`), status page hosts, and the installer URLs in `api/app/install.sh` and `install.ps1`.
- [ ] Set up Beyond's own server or servers, DNS, TLS (Caddy is in `deploy/caddy`), backups and GitHub Actions secrets.
- [ ] Delete `deploy/stack.console.yml`, `deploy/console.env.example` and the sentinel Kuma/gateway files that are specific to the console.
- [ ] Remove `CONSOLE_INTERNAL_API_KEY` and `CONSOLE_EMAIL_URL` from every env example.

### Phase 2: Own accounts and login (backend)

The design already allows this. `api/app/auth/console.py` is the only module that knows what a console token looks like, and everything else uses a `Principal`. Add a native identity source next to it, then delete the console one.

- [ ] Add a `users` table: email, password hash (argon2), verified, created. Then:
  - email verification
  - password reset
  - optional TOTP 2FA
  - later, optional Google or GitHub login
- [ ] Add `api/app/auth/native.py`, which issues and verifies Beyond's own tokens: short-lived access tokens plus a rotating refresh token in an httpOnly cookie. It returns the same `Principal`.
- [ ] Remove the console settings from `config.py`:
  - `TENANT_SOURCE = "console"`
  - `JWKS_URI`, `JWT_TOKEN_ISSUER`, `JWT_TOKEN_AUDIENCE`
  - `ADMIN_JWT_*`
- [ ] Tenants are keyed `(source, external_account_id)` = console uid. Make the native user or organisation the tenant: a migration that sets `source='beyond'` and a uid.
- [ ] Add organisations so a company has several users. Replace "team members" (`routes/members.py`, which shares between console users) with real invites and roles: owner, admin, member, read-only.
- [ ] **Staff and admin:** `routes/admin.py` and `admin_verifier` trust console staff roles, and staff "view-as" comes from the console's impersonation claim (`imp`). Replace these with a Beyond superadmin role, plus an impersonation flow that is audited and read-only by default.
- [ ] **Sign-up protection:** rate limits, Turnstile or hCaptcha on sign-up, and lockout after failed logins.

### Phase 3: Own email and notifications

- [ ] Make SMTP or a provider API (SES, Postmark, Resend) the only email path: `emailSender` in `alerter/notify.go`. Delete `consoleMailer` and its setting.
- [ ] Move all email to Beyond's own branded templates:
  - alerts (`alerter/emailhtml.go`)
  - verification codes
  - digests
  - reports
  - sign-up, verification and reset emails from Phase 2
- [ ] Set up SPF, DKIM and DMARC for the sending domain, plus bounce and complaint handling that marks a contact undeliverable.
- [ ] Web Push (`alerter/push.go`): generate Beyond's own VAPID keys and set its subject to Beyond's domain.
- [ ] SMS and voice: Beyond's own provider account, or switch the channels off until there is one.

### Phase 4: Remove the console-only API surface

`api/app/routes/internal.py` (guarded by `auth/internal.py`) exists only so the console backend can drive Beyond:
- usage
- incidents for ticket rules
- suspending, resuming and deleting tenants
- staff-made agent keys
- ticket contacts and team contacts
- recommended rules
- notify
- maintenance
- external monitors (Uptime Kuma checks synced from the console)

For each one, either:
- **expose it in Beyond's own API and UI**, for example tenant suspension in the admin panel, maintenance and recommended rules in settings, and external monitors replaced by Beyond's own uptime checks (probes already exist), or
- **delete it**: ticket rules and ticket contacts belong to the console's helpdesk, and usage was for console billing.

Then delete `routes/internal.py` and `auth/internal.py`, and update the migrations' comments where they describe the console.

### Phase 5: Own frontend (the big one)

The whole UI currently lives in the Example console repo (React + Vite, Monitoring → Servers and its many sections). Beyond needs its own web app in this repo, for example `web/`.

- [ ] **Stack:** React + TypeScript + Vite, TanStack Query for the API, a router, a component library, and a chart library for time series.
- [ ] Generate a typed API client from the FastAPI OpenAPI schema, so the frontend can't drift from the API.
- [ ] Rebuild the screens. Use the console's Monitoring section as the feature list, not as code to copy. In rough priority:
  1. Login, sign-up, verify, reset, 2FA, invite acceptance.
  2. Onboarding: create the organisation, show the install command (Linux/BSD/Windows/Docker), and wait for the first server.
  3. Server list (live CPU, memory, disk, load, status, tags), plus server detail with the Overview, Disks, Processes, Memory, Network, System, Forecast and Activity tabs, time ranges and a date picker.
  4. Alerts: rules (every kind), incidents with timeline, ack and snooze, merging, and maintenance windows.
  5. Contacts and channels, quiet hours, on-call schedules and escalation.
  6. Checks and uptime monitors, probes and regions, plus status pages (public pages served by Beyond itself).
  7. Logs search, APM and traces, dashboards, fleet view, insights and anomalies.
  8. Reports (PDF), digests, audit log, API tokens, organisation settings and members.
  9. Superadmin panel: tenants, suspend and resume, impersonation, agent rollout (promote and rollback), and fleet health.
  10. Help and setup guide pages (the old Field Guide content can seed these).
- [ ] A marketing and landing site, docs, and pricing if it will ever be paid. These can be a separate static site.
- [ ] Serve `web/` from Caddy or as its own container, on the same domain as the API (`/api`), so cookies stay first-party.

### Phase 6: Polish and operations

- [ ] Monitor Beyond with Beyond, plus one external uptime monitor.
- [ ] Backups with tested restores (Postgres plus VictoriaMetrics snapshots), and a runbook in `deploy/`.
- [ ] Terraform provider (`terraform-provider-pulsegrid/`): rename it and point it at Beyond's API.
- [ ] Rename the binaries, service names and paths (`pulsegrid-agent`, `/etc/pulsegrid`) if the product name changes. Ship a migration path for already-installed agents.
- [ ] Legal and product basics: terms, privacy, data deletion and export per tenant.

**Done means:** a stranger can open Beyond's domain, sign up, install the agent, get an alert email from Beyond's own domain, and manage everything in Beyond's own UI, with no Example service running anywhere.

## Lessons from the production fleet

- **Shared NAT:** many servers sit behind one public IP. A short network drop there silences a group of them at once. That's real downtime from the monitor's point of view, but customers shouldn't get one email per server, so the grouping and blip suppression exist.
- **One alert, many emails:** a client with 12 team members subscribed gets 12 emails per alert, as designed. Grouping keeps the count to one per person per event.
- **Missing sudo:** some customers' servers don't have sudo installed. Root-run fallbacks are needed for anything privileged.
- **No hardware on VMs:** VMs report no IPMI or SMART. Treat "no readings" as "not applicable", not as a failure.
- **Windows:** CI path comparisons must use forward slashes. Autoconfig must run right after an update.
- **Alert detail:** an alert is only useful if it says *what* failed. Plugin, check and disk alerts all carry a detail line, so keep that true for new rule kinds.

## Open ideas

- **Correlated outages:** detect several hosts behind one public IP going silent together. Open one "network" incident and link the hosts to it, instead of N incidents.
- **Dependency hint:** when several servers drop together, suggest a host dependency (`depends_on_host_id`).
- **Own auth and email:** replace the console coupling (see "Removing inherited coupling"). This is the first priority.
