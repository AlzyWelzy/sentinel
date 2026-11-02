import Link from "next/link";

import { SiteFooter, SiteHeader } from "@/components/site";

const FEATURES = [
  [
    "Servers in a minute",
    "One command installs a small agent on Linux, FreeBSD, OpenBSD, NetBSD, Windows or in Docker. It runs unprivileged, configures itself for the services it finds, and updates itself.",
  ],
  [
    "Nothing lost in an outage",
    "The agent keeps 24 hours of data on disk when the network drops and sends it when it's back, at the times it was measured.",
  ],
  [
    "Alerts that say what failed",
    "Thresholds, anomalies, disks filling up, services and processes, containers, log patterns and silence. Each alert names the mount, plugin or check that failed.",
  ],
  [
    "Fewer, better emails",
    "Servers that drop together send one email per person. Brief blips are held back. Flapping alerts quieten themselves. Quiet hours, on-call rotations and escalation.",
  ],
  [
    "Uptime from outside",
    "HTTP, TCP, TLS certificate and DNS checks from probe locations, with SLO targets and error budgets.",
  ],
  [
    "Status pages",
    "Public pages with 90 days of uptime and announcements, showing only the names you choose.",
  ],
  [
    "Logs and traces",
    "Search what your servers log, and see request rates, errors and latency from OpenTelemetry traces.",
  ],
  [
    "Teams",
    "Organisations with owner, admin, member and read-only roles, an audit log of every change, and two-factor sign-in.",
  ],
];

export default function Landing() {
  return (
    <>
      <SiteHeader />
      <main>
        <section className="mx-auto max-w-6xl px-4 pt-20 pb-16">
          <h1 className="max-w-3xl text-4xl font-semibold tracking-tight text-ink sm:text-5xl">
            Know your servers are fine. Hear about it the moment they aren&apos;t.
          </h1>
          <p className="mt-5 max-w-2xl text-lg text-ink-2">
            Sentinel monitors servers and websites: metrics every 30 seconds, uptime checks, logs
            and alerts that tell you exactly what failed, by email, chat, webhook or push.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              href="/signup"
              className="rounded-lg bg-brand px-5 py-2.5 font-medium text-brand-ink"
            >
              Start monitoring
            </Link>
            <Link
              href="/help"
              className="rounded-lg border border-line bg-panel px-5 py-2.5 font-medium text-ink"
            >
              Read the guide
            </Link>
          </div>
          <pre className="mt-10 max-w-3xl rounded-xl border border-line bg-panel p-4 font-mono text-sm break-all whitespace-pre-wrap text-ink">
            <span className="text-ink-3"># on your server</span>
            {"\n"}curl -fsSL https://get.sentinel.rajpoot.app/install.sh | sudo sh -s -- --key pg_…
          </pre>
        </section>
        <section className="border-t border-line bg-panel">
          <div className="mx-auto grid max-w-6xl gap-x-10 gap-y-8 px-4 py-16 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map(([title, body]) => (
              <div key={title}>
                <h2 className="font-semibold text-ink">{title}</h2>
                <p className="mt-2 text-sm leading-relaxed text-ink-2">{body}</p>
              </div>
            ))}
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
