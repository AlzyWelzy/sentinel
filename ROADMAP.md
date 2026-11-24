# Sentinel roadmap

What's done, what's waiting on an account or a key, and what to build next.

## Built and waiting for a key

Each of these is built, tested and deployed, and stays off until its setting is in `/srv/sentinel/prod.env`:

| Feature | Turn it on with |
|---|---|
| Plans and Razorpay subscriptions (Free, Pro, Business) | `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`, `RAZORPAY_PLAN_PRO`, `RAZORPAY_PLAN_BUSINESS`; webhook `https://sentinel.rajpoot.app/api/webhooks/razorpay` with the `subscription.*` events |
| Bounces and complaints from Resend | `RESEND_WEBHOOK_SECRET`; webhook `https://sentinel.rajpoot.app/api/webhooks/resend` with `email.bounced` and `email.complained` |
| AI incident summaries | `ANTHROPIC_API_KEY` |
| Customers' status pages on their own domains | `CF_API_TOKEN` with SSL and Certificates Edit; Cloudflare for SaaS with fallback origin `sentinel-customers.rajpoot.app` |
| Terraform Registry listing | Repository secrets `TF_GPG_PRIVATE_KEY` and `TF_GPG_PASSPHRASE`, then publish `alzywelzy/sentinel` on the Registry; releases come from `terraform-v*` tags |

## Done

- **Uptime checks from three regions:** probe VMs in europe-west1, us-central1 and asia-southeast1. A check alerts when two regions agree.
- **Sentinel watches itself:** probe checks on the app, ingest and downloads, plus a Google Cloud Monitoring check that emails the owner if Sentinel can't alert.
- **Backups off the server:** a nightly copy to Cloud Storage, kept 30 days.
- **Dependency suggestions:** Insights finds servers that go quiet together and offers to set the dependency.
- **Installable app:** Sentinel installs on phones and computers, and alerts arrive as notifications with Acknowledge on them.
- **Developer access:** API reference at `/api/docs`, and a Terraform provider (tested against production with OpenTofu).
- **Browser checks from Chrome Recorder:** checks import a Chrome DevTools Recorder export.
- **Notifiers:** Microsoft 365 through Graph, Apprise and Nostr, making 103 notification providers.
- **Access reviews and policies:** access reviews in Settings, and the operating policies in `docs/policies.md`.

## Next

1. **IPDR on real gear:** a FortiGate and Arista switches sending to a real collector, then a review of the export format with whoever will receive it.
2. **Google and GitHub sign-in.** Skipped on 2026-11-24; this needs OAuth apps in the owner's accounts.
3. **Usage-based limits:** enforce plan retention (metrics days, log days) as well as counts.
4. **Mobile polish:** on-call schedule and incident list tuned for small screens, and a widget-style status view.
5. **Status page subscriptions:** visitors subscribe to updates by email.

## Later

1. **Scale out:** a second Swarm node, Postgres with a replica or Cloud SQL, and ClickHouse on its own disk. Do this when the server stays above 60% CPU or memory.
2. **More probe regions:** add them where customers are (South America, Africa, Australia).
3. **SOC 2 audit:** pick an auditor, collect evidence against `docs/policies.md`, and run a readiness assessment.
