# Sentinel roadmap

What to build next, in order. Each item ends with something that runs on sentinel.rajpoot.app.

## Now: finish going live

1. **Turnstile and Web Push keys.** Sign-up has no bot protection until Turnstile keys are set, and Web Push needs VAPID keys generated on the server.
2. **Customers' own status page domains.** Turn on Cloudflare for SaaS with the fallback origin `sentinel-customers.rajpoot.app`, and set `CF_API_TOKEN` with SSL and Certificates Edit.
3. **Watching Sentinel itself.** Set up an external uptime monitor on sentinel.rajpoot.app and `sentinel-ingest`, plus an agent on `sentinel-prod` reporting to its own organisation.
4. **Off-site backups.** Copy the nightly Postgres, ClickHouse and VictoriaMetrics backups to a GCS bucket with lifecycle rules, so the backups survive losing the VM.
5. **Bounces and complaints from Resend by webhook.** These mark contacts undeliverable.

## Next: what customers will ask for

1. **Billing:** plans, limits per organisation (servers, checks, retention), and Stripe or Razorpay. Room for it is already kept.
2. **Google and GitHub sign-in.**
3. **IPDR on real gear:** a FortiGate and Arista sending to a real collector, plus a court-ready export format review.
4. **Correlated outages:** suggest a dependency when several servers drop together (see Open ideas in CLAUDE.md).
5. **Mobile:** a PWA with push for on-call acknowledgement.
6. **Public API docs and a Terraform provider release** (`terraform-provider-sentinel`).

## Later: room to grow

1. **Scale out:** a second VM in the Swarm, Postgres on Cloud SQL or a replica, and ClickHouse on its own disk.
2. **Regions:** probes in several regions for uptime checks, and status from more than one place before declaring a site down.
3. **AI incident summaries:** what changed, likely cause, and similar past incidents.
4. **Synthetic transactions recorder:** record browser-check steps from a real browser.
5. **The remaining Kuma notifiers:** Apprise, Nostr and Microsoft Graph.
6. **SOC 2-style controls:** access reviews and the audit export already there, plus a written policy set.
