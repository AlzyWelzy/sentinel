# Changelog

Sentinel's releases. Agent versions are separate (`agent/VERSION`) and noted
where they change.

## 0.10.0 (agent 0.10.0), 2026-11-20

Network monitoring, Proxmox VE and discovery, and edge cases found by
probing the running stack before going live. New deployments need
`CREDENTIALS_KEY` (see DEPLOYMENT.md).

### Added

- **Network monitoring.** Switches, firewalls and routers are polled over
  SNMP (v1, v2c, v3) by one of the organisation's servers at their site,
  and are first-class: not-reporting alerts, maintenance, dependencies,
  incidents and tags work for them. Vendor profiles (Arista EOS,
  FortiGate, Sophos SFOS, Aruba Instant On, TP-Link, generic) are detected
  automatically and tested against recordings of real devices: interfaces
  with live rates and errors, sensors, VPN tunnels, SD-WAN, HA, BGP and
  OSPF, inventory and LLDP neighbours. A Network section lists devices,
  shows each one's traffic, interfaces and neighbours, and manages SNMP
  credentials (encrypted at rest; never shown again).
- **SNMP traps.** The poller receives v1, v2c and v3 traps and informs
  from the devices it polls (their own community or user only) and sends
  them through its spool. FortiGate events and the standard BGP, OSPF,
  link and restart traps open and close alerts that name the tunnel, peer
  or unit; everything is listed on the device's Events. `install.sh
  --traps` lets the agent bind UDP 162 (systemd, OpenRC); otherwise it
  listens on 1162.
- **Per-customer contacts.** A contact limited to a tag gets alerts for
  that tag's servers and devices only.
- **Reminders, affected hosts and site incidents.** Unacknowledged
  incidents are re-sent every 4 hours (an organisation setting). A "not
  reporting" alert names the hosts behind it that are quiet too. Five or
  more servers behind one public IP (or devices behind one poller) going
  quiet within 15 minutes become one site incident that resolves when they
  all report again.
- **Topology from LLDP.** Mark the core switches and every device's
  upstream is worked out from the cabling, so a failed switch is one
  alert and the devices behind it are affected; a device without an
  upstream depends on the server that polls it. Network › Topology draws
  it.
- **Servers on switch ports.** The agent reports its NICs' hardware
  addresses (including a bonded port's own), so a switch that sees a
  server's NIC over LLDP shows it on that port, the server's settings say
  where it's cabled, and the server depends on that switch: a failed
  top-of-rack switch is one alert. Not for servers cabled to two switches,
  or a poller on its own switch.
- **Network alert rules:** interface down (only ports that were up in the
  last day), utilisation, errors, LAG member down, reboots, and each
  vendor profile's alerts (BGP, VPN, SD-WAN, sensors, optics, HA). They
  arrive with the first device. A device that stops answering is
  "unreachable", with the reason the poller saw.
- **95th-percentile bandwidth** per customer or service: tag ports, pick a
  month (in the organisation's timezone), see the billable rate, totals
  and data coverage, and download a CSV.
- **Proxmox VE clusters** through the API with a read-only token: nodes,
  VMs, containers, storage and quorum, with alerts for an offline node,
  lost quorum, a stopped guest, node CPU and memory, and full storage.
- **Discovery:** scan a private range (up to /22) from one of your servers
  for devices answering SNMP, see what each is, and add the ones you pick.
  The day's scans are listed to reopen; a scan can be cancelled, and one
  the server never starts (10 minutes) or stops reporting (2 minutes) ends
  with the reason instead of holding one of the three slots all day. Only
  RFC 1918 and 100.64/10 ranges are accepted.

- **Sentinel's own outage doesn't page everyone.** When no server anywhere
  has reported for 90 seconds, and just before that servers in at least
  three organisations were reporting, "not reporting" alerts hold until data
  arrives again, and the alerter logs an error. One organisation's outage
  (servers behind one NAT) still alerts.
- **Server diagnosis on the server page:** never reported, silent, an agent
  that's behind, plugin problems, and a clock running fast (its samples are
  discarded), each with how to fix it. The diagnosis existed in the API but
  wasn't shown.
- **Two-factor recovery codes.** Turning on two-factor sign-in now gives ten
  single-use recovery codes (stored hashed); each works in place of an
  authenticator code to sign in or turn two-factor off, and they can be
  renewed. Superadmins can reset two-factor for someone who lost both
  (audited, ends their sessions). Before, a lost phone locked the account
  for good.

- **LVM storage as disks** (agent): volume groups and thin pools have no
  filesystem, so Proxmox SAN and local-lvm storage was invisible. They're
  reported under `lvm:<vg>` and `lvm:<vg>/<pool>`, in disk lists and disk
  alerts. A group holding mounted or swap volumes (a standard LVM install)
  isn't reported as full, an inactive pool isn't reported as empty, and
  older lvm2 releases work. Set up by `enable-hardware`, and on existing
  servers by the hourly check. A recommended rule warns when a thin pool's
  metadata passes 80% (a full one stops the pool).
- **New alert email design:** a status band with a plain-English lead, the
  facts, the detail and big buttons, in Sentinel's colours. Times show in
  the organisation's timezone (Organisation › Digest timezone) and are the
  moment of the event, not of a retried send. Escalations say for how long
  nobody has acknowledged.
- **Custom-metric alerts say which series fired** (for example
  `pool=pve/data 91.2`), worst first, like disk and plugin alerts.
- **End-to-end checks in the repo** (`e2e/`, `make e2e`): the 41-step
  browser journey, the extras, the network UI, live network, Proxmox and
  discovery runs against simulated devices, and the API access matrix.
  They lived in a scratch folder before and were lost once.

### Fixed

- **Saves that failed silently:** a change the database refused when it was
  saved (a constraint, a missing column grant) answered 200 with nothing
  saved, because the audit log's savepoint swallowed the error. Such a
  request now fails.
- **Autoupdate and new settings:** a release whose stack needs a setting
  missing from `prod.env` (0.10.0: `CREDENTIALS_KEY`) used to fail to
  deploy and roll back on every run. It now waits, before migrating, and
  logs which setting to add.
- **Big devices:** a poll larger than ingest's per-request limit is split
  into several batches instead of being dropped.
- **Next.js 16.4.6:** 16.4.4 had a moderate cache-leak advisory
  (GHSA-mfr8-8qww-v76h, GHSA-vc7v-qv4w-wrv8).
- **Alert email footer** still pointed at "the console", which Sentinel
  doesn't have.
- **Docker install command didn't work:** it pulls
  `sentinel-agent:latest`, which releases never published. Releases now tag
  every image `:latest` too, and the agent image with the agent's version
  (production's `AGENT_IMAGE` uses `AGENT_VERSION`, which differs from the
  release number). Autoupdate waits for the web and agent images as well,
  so a slow web build no longer fails a deploy and rolls it back.
- **Install command failed on servers without sudo:** it was
  `curl … | sudo sh`, and many root shells have no sudo. It's
  `curl … | sh` now: as root it installs directly, otherwise the installer
  re-runs itself through sudo or doas. Cloud-init user data falls back to
  wget when curl is missing.
- An incident's delivery list answered an empty list for an incident that
  doesn't exist or belongs to another organisation; it's 404 now, like
  every other incident route.

- **Signed out during a deploy:** while the API restarted, the web app
  treated a failed session refresh as signing out. Only a refusal does now;
  a proxy error or dropped connection is retried for about 30 seconds.
- **On-call:** a daily or weekly rotation kept handing off at the same UTC
  time, so a 09:00 handoff moved to 08:00 or 10:00 when the clocks changed.
  Whole-day shifts keep their local time (the alerter and the API agree).
- **Recommended rules** were added only when the dashboard first opened, so
  an organisation used only through the API or Terraform had no "not
  reporting" rule. The jobs service now adds them to any organisation
  without them.
- **NaN and Infinity** in a request were accepted: a rule with a NaN
  threshold was saved and could never fire, and Infinity failed some
  requests. Every JSON body is checked; they get 422.
- **Agent:** one NaN or infinite value (a Prometheus summary with no
  observations, a script dividing by zero) made the whole batch fail to
  spool, so the server sent no metrics while it lasted. Those values are
  dropped; the rest arrive.
- **Charts and reports** failed when a metric was a ratio over zero
  (VictoriaMetrics returns +Inf, which JSON can't carry); those points are
  gaps now.
- **Webhooks and probe checks** also refuse NAT64 addresses that reach a
  private IPv4 address, and the alerter's webhook guard matches the probes'
  (reserved and benchmarking ranges).
- **Custom rule label values** are capped at 200 characters.
- **Server diagnosis** called an agent newer than the offered version
  "behind".
- **Superadmin panel:** the organisation list shows newest first after the
  busiest, and says when it's showing only the first 100.
- **Agent:** a server removed in Sentinel (or whose organisation is
  suspended) backed its agent off to nothing: it re-sent up to 24 h of spool
  every 30 seconds for ever. It now waits 1, 2, 4 … up to 30 minutes between
  tries, keeps the data, and resumes at once when accepted again.
- **PDF reports** failed for a server whose name looked like markup
  (ReportLab parsed it, and its `<img>` could load files). Every name in a
  report is escaped. Download filenames are ASCII, so a non-Latin hostname
  no longer fails the download.
- **Summary CSV:** names starting with `=`, `+`, `-` or `@` are written so
  spreadsheets show them as text instead of running them as formulas.
- **Email:** bodies are quoted-printable and subjects folded, so a long log
  line or a long non-ASCII subject can't exceed SMTP's line limit.
- **Slack and Discord:** alert text is escaped and Discord mentions are off,
  so a log line with `<!channel>` or `@everyone` can't ping everyone.
- **Discord, Telegram, Teams:** long or multi-byte text is cut to each
  service's limit on a character boundary. Before, such alerts were refused
  (Telegram has a 4096 limit; Discord refused a cut mid-character) and the
  refusal counted as permanent, so the alert was lost.
- **Ingest** refuses hostnames with control characters or over 253
  characters at registration (a NUL failed with 500) and cleans the other
  fields agents report.
- **API:** names and titles of only spaces are refused everywhere; text with
  a NUL character gets 422 instead of 500; passwords that are all spaces or
  one or two repeated characters are refused.
- **Web:** long hostnames wrap or truncate instead of widening pages on
  phones; the logo showed blank on phones; a missing item or mistyped link
  shows a clear page with a way back instead of a raw validation error; a
  branded 404 page.

## 0.9.0 (agent 0.9.0), 2026-11-02

The first release of Sentinel as a product of its own, at
sentinel.rajpoot.app. It started from a copy of Pulsegrid v0.8.27 (agent
0.8.11); everything that depended on the original console is replaced or
removed.

### Added

- **Accounts.** Sign-up with email and password (argon2id), confirmed by an
  emailed link; sign-in with optional TOTP; 10-minute access tokens and a
  refresh token that rotates on every use (reuse ends the session);
  password reset and change; signed-in browsers you can sign out; lockout
  after failed sign-ins; rate limits; Cloudflare Turnstile on sign-up and
  reset.
- **Organisations.** Create several, rename, delete. Owner, admin, member
  and read-only roles; emailed invitations; members' emails become alert
  contacts; incidents can be assigned to a member.
- **Superadmins** (`SUPERADMIN_EMAILS`): suspend, resume and delete
  organisations, disable users, run the agent rollout, and work inside an
  organisation through an audited, time-limited, read-only-by-default
  impersonation.
- **The web app** (`web/`, Next.js): sign-in and onboarding with the install
  command, overview, servers (list and detail with time ranges), incidents
  with timeline, alert rules, uptime checks, maintenance, status pages
  (public pages rendered on the server), logs, APM, dashboards, reports,
  contacts, organisation and members, API tokens, audit log, account
  security, superadmin panel. Light and dark themes.
- **Agent uninstall:** `install.sh --uninstall [--keep-config]` and
  `install.ps1 -Uninstall [-KeepConfig]`.
- **Backups that are proven:** every nightly Postgres dump is restored into
  a scratch database and checked; `vm-backup.sh` backs up and restores
  VictoriaMetrics with `vmbackup`/`vmrestore`.
- On-call rotations with overrides, escalation steps, rule editing with a
  7-day preview and test alerts, quiet hours and minimum severity per
  contact, incident snooze and a list of every notification sent, server
  tags, dependencies, notes and allowed actions, insights.
- Incident merge, saved views and a fleet wall (TV mode).
- A public site: landing page, terms, privacy and a setup guide. The
  dashboard moved to `/overview`.
- Data export per organisation (JSON, secrets masked), ownership transfer,
  and deleting your own account.
- After confirming their email, invited people see their invitations
  before an organisation of their own is created.
- `ARCHITECTURE.md`, `SECURITY.md`, `DEPLOYMENT.md`.
- **A new design** for the whole web app and public site: Sentinel's own
  mark and violet-to-cyan colours, Geist type, a sidebar with icons in
  sections, sign-in pages with a brand panel, a landing page with a product
  preview, terminal-style command blocks, and refined cards, tables, charts,
  status pages and dark mode.
- **Installer tests on every platform** (`installers` workflow): the real
  `install.sh` on Linux, FreeBSD, OpenBSD and NetBSD and `install.ps1` on
  Windows install the agent, check it runs and sends metrics, uninstall it
  and check nothing is left. A stand-in API (`deploy/testing/installer-stub`)
  means no secrets are needed.

### Changed

- **Email** goes only through Sentinel's own SMTP settings, for alerts and
  account emails alike; account emails use the alert outbox's retries.
- A contact whose mail server refuses the recipient is marked undeliverable
  and stops receiving until it's verified again.
- Digests start after an organisation's first full day or week, not at
  sign-up.
- Time zones default to UTC (digests, reports, PDFs).
- **Ingest** (agent 0.9.0):
  - A push over the size limit gets 413 and the agent sends fewer batches
    instead of dropping them. Before, the body was cut off and answered 400,
    which agents treated as permanent: the data was deleted.
  - Each host token is rate-limited (429 with `Retry-After`).
  - Batches stamped more than 25 h ago or 10 minutes ahead are dropped.
  - The body limit is 32 MiB and 100,000 samples.
- VictoriaMetrics deduplicates samples on (series, timestamp), so a push
  that's retried after a lost response is stored once.
- The agent writes spool files atomically (temp file, fsync, rename) with
  unique names.
- Renamed to Sentinel: binaries (`sentinel-agent`), services, paths
  (`/etc/sentinel`, `/var/lib/sentinel`), metrics (`sentinel_*`), headers
  (`X-Sentinel-*`), database roles, images
  (`ghcr.io/alzywelzy/sentinel-*`).
- One public origin: the web app and the API (under `/api`) share
  `APP_HOST`; agent binaries are served by the API image.
- The dev stack runs as its own compose project (`beyond-dev`) on host
  ports offset by 10.

### Fixed (found by testing end to end)

- Agent binaries were unreachable behind `API_ROOT_PATH` (installs failed).
- Sign-in didn't survive a page reload in development (refresh cookie path).
- Status pages defaulted a server's public label to its hostname.
- Sign-in followed `next=` links to other sites.
- Form labels named every option of a select for screen readers.
- Some failed changes showed no error; now every failure is shown.
- Assigning an incident or snoozing it from a dropdown sent an empty value.
- The PDF report sent no servers, and the button worked before the report
  had loaded.
- The organisation export failed on numeric columns.
- A superadmin's impersonation ended on any page reload; leaving now ends it
  on the server too.
- Signing out returned the next sign-in to the page you left.
- The status page address field's pattern was invalid in current browsers.
- A server that reported only briefly was described as "no gaps" in its
  PDF report.

### Removed

- The console's identity (its JWT, JWKS settings, staff roles, view-as),
  the console mailer, `/internal/*` and its key, the Uptime Kuma external
  monitors, `CUSTOMERS_READ_ONLY`, the development auth bypass, and the
  console's deploy files.

### Verified

On the dev stack with a real agent: sign-up and the confirmation email
(Mailpit), install, then ingest stopped for 273 s. The "not reporting" email
arrived 251 s in (180 s rule + 60 s hold + one cycle). After ingest came
back the spool (8 batches) drained in 10 s, the recovery email went out, and
VictoriaMetrics had all 9 samples of the outage at their original times
(largest gap 31 s, no duplicates).
