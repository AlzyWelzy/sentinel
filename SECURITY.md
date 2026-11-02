# Security

How Sentinel authenticates people and agents, keeps organisations apart,
and what it defends against. Report a vulnerability privately to
ops@rajpoot.app; please don't open a public issue.

## Accounts

| Control | How |
|---|---|
| Passwords | argon2id (argon2-cffi defaults, RFC 9106 low-memory), 10 to 256 characters, rehashed at sign-in when parameters change |
| Email ownership | Sign-in is refused until the emailed link is followed (24 h, single use, stored as a SHA-256 hash) |
| Sessions | Access token: HS256 JWT, 10 minutes, kept in browser memory only. Refresh token: 32 random bytes, stored hashed, in an `httpOnly; Secure; SameSite=Strict` cookie scoped to `/api/auth`, 30 days |
| Refresh rotation | Every refresh issues a new token and retires the old one. An old token presented again (after a 10 s grace for tabs racing) revokes the whole session family: someone has a copy |
| CSRF | Cookie-authenticated endpoints (`/auth/refresh`, `/auth/logout`) require `X-Requested-With`, which a cross-site form can't send; everything else uses the bearer token, so cookies authorise nothing on their own |
| Two-factor | TOTP (RFC 6238, ±30 s), secret encrypted at rest with AES-GCM under a key derived from `AUTH_SECRET` |
| Brute force | 5 failures lock an account for 1, 2, 4 … up to 60 minutes (never permanently, so attackers can't keep users out); Redis limits per client address and per email on sign-in, sign-up, reset and resend; Cloudflare Turnstile on sign-up and reset |
| Enumeration | Sign-up, reset and resend answer the same for known and unknown addresses; sign-in checks a dummy hash for unknown emails so timing doesn't tell either |
| Password change or reset | Signs out every browser and emails the owner |
| Disabled users | A superadmin can disable a user: sign-in and refresh are refused and their sessions end at once |

`AUTH_SECRET` signs access tokens and encrypts TOTP secrets through
separate derived keys. To rotate it, move the current value to
`AUTH_SECRET_PREVIOUS` and set a new one: existing tokens and secrets keep
working until they're renewed; remove the previous value a day later.

## Organisations and tenancy

- The organisation for a request comes from membership checked in the
  database (`sentinel_member_tenant`), never from a client-supplied id on
  its own. A user who isn't a joined member gets 403.
- Invitations are single-use tokens for one email address, valid 7 days;
  accepting needs a signed-in user with that verified address. Membership
  is by user id, so a later account can't inherit someone's invitation.
- Isolation is enforced twice: application queries filter on the tenant,
  and Postgres row-level security filters every statement the API's role
  runs (`USING` and `WITH CHECK`). The tenant is set per transaction, so a
  pooled connection can't carry it into the next request. Metrics, logs and
  traces are scoped the same way in their stores.
- API tokens stand for one organisation, can be read-only and can expire;
  they can't manage tokens, sign-in or organisations.
- Every change is written to the organisation's audit log in the same
  transaction, with who made it.

## Superadmins and impersonation

Superadmins come only from `SUPERADMIN_EMAILS` (verified accounts); the flag
is re-checked at every sign-in and refresh. They work inside an
organisation only through an impersonation, which:

- needs a reason, lasts at most an hour and can be ended at once;
- is read-only unless writes are asked for when starting it;
- is checked against its row on every request;
- is listed in the admin panel, and every change made with it is audited as
  "… (superadmin)".
- lives in the browser tab that started it (sessionStorage), not in a
  cookie, and leaving ends it on the server.

## Agents and ingest

- Install keys are shown once and stored hashed. Registration gives each
  server its own token; revoking a key doesn't affect installed servers,
  removing a server revokes its token.
- Ingest takes the tenant only from the host token, stamps `host_id`
  itself, rate-limits each token (429), caps body size (413) and refuses
  timestamps outside a 25 h / 10 min window.
- The agent runs unprivileged. Plugins and allowed actions come only from
  root-owned files on the server, never from the dashboard. Probe checks
  may only reach public addresses, enforced at connect time (DNS rebinding
  can't get round it). Updates are verified by SHA-256 and self-tested
  before they're swapped in.

## Outbound requests

Webhooks, Slack, Teams and Discord URLs are customer-supplied: the sender
refuses private, loopback and link-local addresses at connect time, and
webhooks are signed (`X-Sentinel-Signature: sha256=…`). Secret targets are
masked whenever the API returns them.

## Transport and headers

Caddy terminates TLS with automatic certificates and sends HSTS,
`X-Content-Type-Options` and a strict referrer policy; the web app adds
`X-Frame-Options: DENY` and a restrictive `Permissions-Policy`. Request
bodies are capped at the edge (5 MB for the API, 34 MB for ingest).

## Secure defaults

The API refuses to start in production without a 32+ character
`AUTH_SECRET`, with insecure cookies, without a captcha secret (unless
`CAPTCHA_DISABLED` is set on purpose), or with a non-https `PUBLIC_APP_URL`.
There is no development auth bypass. Secrets come from the environment
only and are never logged.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Credential stuffing, password spraying | argon2id, per-address and per-email limits, temporary lockout, captcha on sign-up, optional TOTP | Users without 2FA on reused passwords |
| Stolen refresh cookie | httpOnly + Secure + Strict; rotation with reuse detection ends the session | A thief who refreshes first holds the session until the user's next refresh fails and ends it |
| Stolen access token (XSS) | 10-minute lifetime, memory only, React escaping, no `dangerouslySetInnerHTML` of user data | Any XSS can act as the user while the tab is open |
| Cross-tenant read or write | Membership in the database, RLS on every table, tests for every id-taking endpoint | A bug in a SECURITY DEFINER function; there are four, all small and tested |
| Malicious or broken agent | Per-token rate limits, body and sample caps, timestamp window, tenant from token only | One organisation can fill its own metric quota |
| SSRF through webhooks or probe checks | Private addresses refused at connect time | Public services reachable from the host |
| Insider superadmin | Impersonation needs a reason, is time-limited, read-only by default and audited | A superadmin with database access bypasses all of it: keep that set small |
| Lost database | Nightly dumps, each restored into a scratch database to prove it works | Up to a day of changes; copy backups off the host |
| Email spoofing of alerts | SPF, DKIM and DMARC on the sending domain (DEPLOYMENT.md) | Recipients whose providers ignore DMARC |
