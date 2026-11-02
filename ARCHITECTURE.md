# Architecture

Sentinel is five services and a web app around three stores. This document
says how they fit, what each one owns, and exactly what is guaranteed about
data in transit. Database, API and testing notes live here too.

## Components

```text
                         ┌──────────────────────────── one host (or a Swarm) ────────────────────────────┐
 browser ──https──▶ Caddy ┼─ /        ─▶ web (Next.js)  ── server side ──▶ api  (status pages only)      │
                          ┼─ /api/*   ─▶ api (FastAPI) ─┬─▶ PostgreSQL  (RLS, app role)                  │
                          │                             ├─▶ Redis       (heartbeats, rate limits)        │
                          │                             └─▶ VictoriaMetrics / VictoriaLogs / Tempo (read) │
 agent ───https──▶ Caddy ─┼─ ingest host ─▶ ingest (Go) ┬─▶ VictoriaMetrics (write, extra_label=tenant)  │
                          │                             ├─▶ VictoriaLogs (AccountID=tenant) · Tempo      │
                          │                             └─▶ PostgreSQL (service role) · Redis            │
                          │                 alerter (Go) ─ reads VM, PG ─▶ incidents ─▶ outbox ─▶ SMTP,   │
                          │                                                   push, chat, webhooks       │
                          │                 jobs (Python) ─ rollups → VictoriaMetrics-long, reports,     │
                          │                                 digests, agent rollouts                      │
                          └─ download host ─▶ install.sh / install.ps1 (api) · agent binaries (files)      │
                         └────────────────────────────────────────────────────────────────────────────────┘
```

| Service | Owns | Talks to | Scales |
|---|---|---|---|
| **web** | Screens, sign-in flow in the browser, SSR public status pages | api only | stateless, N replicas |
| **api** | Accounts, organisations, every customer read and write, superadmin panel | PG (app role for customers, service role for auth/admin), Redis, the stores (read) | stateless, N replicas |
| **ingest** | Agent registration, metric/log/trace intake, agent config | PG (service role), Redis, the stores (write) | stateless, N replicas |
| **alerter** | Rule evaluation, incidents, escalation, the outbox (alerts and account emails) | PG (service role), VM, VictoriaLogs, SMTP and providers | N replicas; partitions held by advisory locks, standbys wait |
| **jobs** | Hourly rollups, monthly reports, digests, cleanup, agent rollout and health gate | PG, VM, VM-long | 1 active, others wait on an advisory lock |
| **agent** | Collection, checks, plugins, logs, APM receiver, spool, self-update | ingest, the download host | one per server |

The split is inherited and kept: ingest takes the write load of every agent
and must not share a process with the API's request handling; the alerter
needs single-writer semantics per partition; jobs are periodic. Nothing
here has shown a reason to merge or split further.

## Request path and tenancy

Every customer request goes through `api/app/tenancy.py`, the one place a
tenant is decided:

1. **Who:** a Sentinel access token (HS256 JWT, 10 minutes, issued only by
   this API) or an API token (`pgt_…`, looked up by hash). Never the body,
   never an IP.
2. **Which organisation:** `X-Sentinel-Account` if sent, checked in
   Postgres by `sentinel_member_tenant(tenant, user)` (SECURITY DEFINER,
   joined members only). Otherwise the user's default organisation
   (`sentinel_default_tenant`), created on first use for a new user. A
   superadmin reaches another organisation only through an impersonation
   token, and its row is checked on every request.
3. **Role:** `check_member_write` allows writes by route: read-only users
   write nothing but their own push subscription and saved views; members
   handle incidents, maintenance and actions; admins everything but API
   tokens and deleting the organisation.
4. **Isolation:** `set_config('app.tenant_id', …, true)` for this
   transaction only; RLS on every tenant table (`USING` and `WITH CHECK`)
   does the rest, so a query that forgets `WHERE tenant_id` still sees one
   tenant. Writes are audited in the same transaction.

Metrics: ingest stamps `host_id` itself and writes with
`extra_label=tenant_id=…`; every read adds the same `extra_label`, and
queries are built from a fixed catalog, never from client PromQL. Logs use
the tenant's own VictoriaLogs AccountID; traces its own Tempo tenant.

## Database

PostgreSQL 18, migrations in `api/migrations` (Alembic, plain SQL in
`op.execute`). Roles:

| Role | Used by | RLS |
|---|---|---|
| `sentinel` | migrations only; owns the tables | n/a (owner) |
| `sentinel_app` | API customer requests | always applies |
| `sentinel_service` | ingest, alerter, jobs, the API's auth and superadmin code | BYPASSRLS, narrow grants |

Account tables (`users`, `user_sessions`, `auth_tokens`, `impersonations`,
`account_emails`) are not tenant-scoped and only the service role reads
them. An organisation is a row in `tenants`; every person in it (the owner
too) is a `tenant_members` row with a `user_id`.

Migrations are additive where possible so the previous release runs on the
new schema during a rollback. CI runs every migration up, down to base and
up again.

## Agent ⇄ ingest protocol

JSON over HTTPS, gzip both ways, defined in `proto/payload.go` (v1; fields
are only ever added). An agent registers once with an install key and gets
its own host token (`pgh_…`), stored with its state. Every push carries up
to 20 spooled batches; the response returns the current config version, and
the agent refetches its config when it changes.

| Endpoint | Limit per host token (per minute / burst) |
|---|---|
| `POST /v1/register` | 30 / 60 per client address |
| `POST /v1/metrics` | 60 / 200 |
| `GET /v1/agent/config` | 20 / 30 |
| `POST /v1/logs` | 60 / 200 |
| `POST /v1/traces` | 120 / 300 |

Over a limit: 429 with `Retry-After`; the agent keeps its data and retries.
Bodies are limited to 32 MiB after decompression and 100,000 samples per
request; over that is 413.

## Delivery guarantees (agent → stores)

What the spool guarantees, precisely:

- **At-least-once.** A batch leaves the spool only after ingest answered
  2xx for the request that carried it. Network errors, timeouts (20 s), 5xx,
  401/403 (a revoked key or suspended organisation) and 429 keep it for the
  next tick (30 s).
- **Never exactly-once.** A request whose 2xx is lost in transit is sent
  again. VictoriaMetrics runs with `-dedup.minScrapeInterval=1ms`, so a
  resent sample with the same series and timestamp is stored once.
  Verified: three identical writes export as one sample.
- **Timestamps preserved.** Each batch carries the time it was collected;
  ingest writes that timestamp. Verified end to end: ingest stopped for
  273 s, the 9 batches collected meanwhile arrived afterwards at their
  original times (largest gap 31 s, no duplicates).
- **Partial uploads.** One request may write to several tenants (a probe's
  results go to each check's owner). If a later write fails the request is
  answered 503 and retried whole; the writes that succeeded are deduplicated
  as above.
- **Too big.** A 413 makes the agent halve the number of batches per push
  and retry; only a single batch that is still too big is dropped.
  (Agents before 0.9.0 dropped on 413; the server's limit sits far above
  what any agent sends.)
- **Wrong clocks.** Batches stamped more than 25 h in the past or 10 min in
  the future are dropped and counted as dropped: they'd be outside what the
  spool can hold, or would overwrite real data.
- **Buffer limit.** 2,880 batches (24 h at 30 s). When full, the oldest go
  first.
- **Safe restart.** Batches are written to a temp file, fsynced and renamed
  into place, with a random suffix so two in one millisecond don't collide.
  A crash leaves the whole batch or nothing; leftover temp files are removed
  at start.

Check results and inventory are held in memory until a push that carries
them succeeds; logs keep their file offsets on disk.

## Alerting and notifications

The alerter evaluates every 30 s: `ok → pending → firing → resolved`, with
the incident opened or resolved in the same transaction as the state
change. "Not reporting" alerts are held 60 s and dropped if the server came
back; servers that drop together go out as one email per contact.

Notifications go through `outbound_messages`, leased with
`FOR UPDATE SKIP LOCKED` so two dispatchers never send one message and a
crashed one's messages come back by themselves. Retries: 20 s, 40 s, 2 m,
5 m, 15 m, 1 h, 3 h, then `failed` (the dead-letter state, listed under
deliveries with the last error). Permanent errors fail at once; a mail
server refusing the recipient also marks the contact undeliverable and
unverified, so nothing more is sent there until it's verified again.

Account emails (verification, reset, invitations) go through
`account_emails` with the same lease and backoff, sent by the same SMTP
sender. The API never talks to a mail server.

## Web app

`web/` is Next.js (App Router), strict TypeScript, Tailwind, TanStack Query
and uPlot. The API client is generated from FastAPI's OpenAPI schema
(`npm run api`); CI regenerates it and fails if it differs.

- Screens are client components: the data is live and the access token
  lives in memory only. `lib/api/client.ts` refreshes once on a 401, with a
  Web Lock so tabs never present the same refresh token twice.
- Public status pages (`/status/[slug]`) render on the server from the
  API's public JSON over the private network, cached 30 s.
- In production Caddy serves `/api/*` from the API and everything else from
  the web container, one origin, so the refresh cookie is first-party. In
  development `next dev` proxies `/api` to the local API.

## Testing

- `go test ./...`: unit tests plus real-HTTP tests (spool and 413 handling
  against an `httptest` ingest, SMTP rejection against a real TCP server).
- `cd api && uv run pytest`: against real Postgres, Redis and
  VictoriaMetrics (tenant isolation lives in the database, so mocking it
  would test nothing). Covers RLS, cross-tenant access on every id-taking
  endpoint, accounts end to end (sign-up through the emailed link, refresh
  rotation and reuse, lockout, reset, TOTP, sessions), invitations and
  roles, impersonation.
- `web`: eslint, prettier, `tsc --noEmit`, `next build`.
- End to end on the dev stack (manual, recorded in the CHANGELOG): sign up,
  verify from the email in Mailpit, install a real agent, stop ingest for
  minutes, get the alert and recovery emails, check the spool drained with
  no gaps.
