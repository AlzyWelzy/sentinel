# Changelog

Sentinel's releases. Agent versions are separate (`agent/VERSION`) and noted
where they change.

## 0.9.0 (agent 0.9.0), 2026-11-02

The first release of Sentinel as a product of its own, at
sentinel.rajpoot.app. It started from a copy of Pulsegrid v0.8.27 (agent
0.8.11); everything that depended on the Example console is replaced or
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
