# Pulsegrid Beyond

Pulsegrid Beyond is a multi-tenant monitoring product for servers and uptime, owned by its author.

## Beyond stands on its own

Beyond is its own project. It does not rely on any other project, and work here never depends on one.

- **History:** Beyond started from a copy of Pulsegrid at release v0.8.27 (`565b89f`, agent 0.8.11). That's history only. Pulsegrid, the Example console, billing and every other Example service are not upstreams, dependencies or deploy targets.
- **No syncing:** don't pull from, push to, or sync with `example-org/pulsegrid` or `AlzyWelzy/pulsegrid`. Changes start here. Anything borrowed from elsewhere is re-implemented here deliberately.
- **Own infrastructure:** use only Beyond's own accounts, registry, domains, servers, secrets and email provider. Never use company resources.
- **Remove the coupling:** wherever the code still assumes the Example console (see "Removing inherited coupling"), Beyond's direction is to remove that dependency, not to keep it working.

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
