# Sentinel operating policies

How Sentinel is run: who gets access, how changes ship, what happens in an
incident, how data is kept and deleted, and who else handles it. Technical
controls are in [SECURITY.md](../SECURITY.md); operations are in
[DEPLOYMENT.md](../DEPLOYMENT.md). This document says what is done and how
to prove it. It is a starting point for a SOC 2 or ISO 27001 programme, not
a certification.

Owner: the operator of sentinel.rajpoot.app. Reviewed: every 12 months,
and whenever a control below changes.

## 1. Access control

| Rule | Evidence |
|---|---|
| Customers' people get access only through membership of their organisation, with a role (owner, admin, member, read-only, investigator, auditor). | Settings → Organisation; `tenant_members` |
| Every organisation reviews who has access at least every 90 days: people, roles, two-factor status and API tokens, then confirms. | Settings → Access review; `access.review` in the audit log |
| Staff access to customer data is by superadmin only (listed in `SUPERADMIN_EMAILS`), read-only by default, time-limited and audited. | Superadmin panel → impersonations; audit log |
| Production servers: SSH by key through Google Cloud only; no web ports open (Cloudflare Tunnel). Cloud and DNS accounts use two-factor. | GCP firewall rules; Cloudflare account |
| Secrets live in `/srv/sentinel/prod.env` (mode 600, root) and the owner's password manager, never in the repository or logs. | Repository history; CI secret scanning |
| Leavers lose access the same day: their membership and tokens are removed, and shared secrets they knew are rotated. | Audit log |

## 2. Change management

| Rule | Evidence |
|---|---|
| Every change is a commit on `main` in the public repository, with a message saying what changed for users. | `git log` |
| CI runs lint, type checks and every test suite (Go, API, web, installers on five systems) on every commit; a release is tagged only when it's green. | GitHub Actions history |
| Releases are tags (`vX.Y.Z`); images are built by CI, never by hand. | Releases; `ghcr.io/alzywelzy/sentinel-*` |
| The server updates itself: a database dump first, migrations, then a rolling deploy; a failed migration rolls back to the previous version. | `/srv/sentinel/autoupdate.log` |
| New agent versions reach 10% of servers first and are promoted after they've run cleanly. | `agent_rollout`; superadmin panel |

## 3. Incident response

1. **Detect.** Sentinel watches itself from probes in three regions, and
   Google Cloud Monitoring checks it from outside and emails the owner when
   it's unreachable from more than one region.
2. **Triage.** Within 1 hour: is customer data exposed, is alerting
   delayed, or is it the console only? Alert delivery comes first.
3. **Contain and fix.** Roll back (`autoupdate.sh` keeps the previous
   version's stack files), restore from backup, revoke credentials.
4. **Tell people.** Customers whose data was exposed are told within 72
   hours of it being confirmed, with what was exposed and what to do.
   Outages longer than 30 minutes are posted on the status page.
5. **Learn.** A written review within 5 working days: timeline, cause, and
   the change that stops it happening again.

Security reports: ops@rajpoot.app (see SECURITY.md).

## 4. Backup and recovery

| What | How often | Kept | Proven by |
|---|---|---|---|
| PostgreSQL (accounts, configuration, incidents, audit) | Daily, and before each update | 7 days on the server, 30 days off it | Each dump is restored into a scratch database (`restore-check.sh`) |
| ClickHouse (IPDR evidence) | Nightly, full weekly and incremental daily | 2 full cycles on the server, 30 days off it | Each backup is restored to a scratch database |
| VictoriaMetrics (metrics) | Nightly | 7 days on the server, 30 days off it | `vm-backup.sh restore` drill |
| Off the server | Nightly copy to Cloud Storage (`offsite-backup.sh`) | 30 days (bucket lifecycle) | `offsite-backup.log` |

Recovery targets: alerting back within 1 hour; at most one day of
configuration, metrics or evidence lost.

## 5. Data handling and retention

- **Metrics:** 90 days at full resolution, 2 years downsampled.
- **Logs:** 14 days. **Traces:** 7 days.
- **IPDR evidence:** the organisation's retention (30 to 2000 days); every
  row carries its own expiry, every search and export is in a hash-chained
  audit, and daily seals prove nothing changed.
- **Audit log:** kept for the life of the organisation.
- **Deleting:** an owner deletes the organisation (or a user their account)
  in the app; data goes at once from the databases and from backups as they
  expire.
- **Export:** owners export their organisation's data as JSON at any time,
  secrets masked.

## 6. Who else handles data (subprocessors)

| Service | What for | What it sees |
|---|---|---|
| Google Cloud (asia-south1, plus probes in europe-west1, us-central1, asia-southeast1) | Servers, disks, backups | Everything stored |
| Cloudflare | DNS, TLS and the tunnel in front of the app | All web traffic, in transit |
| Resend | Account and alert email | Recipients and message contents |
| Razorpay | Subscriptions and payments, once billing is on | Billing contact and payment details (never stored by Sentinel) |
| Anthropic | AI incident summaries, only where an organisation asks for one | The incident, its timeline and titles of similar incidents |
| GitHub | Source, CI and container images | Source code only |

A new subprocessor is added to this list before it receives data.

## 7. Vulnerability management

- Dependencies are pinned and updated with each release; CI builds from
  the locked versions.
- Images are rebuilt on every release so base image fixes ship with it.
- Reported vulnerabilities are acknowledged within 2 working days and fixed
  by severity: critical within 7 days, high within 30.
