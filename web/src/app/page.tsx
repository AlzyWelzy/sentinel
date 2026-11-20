import Link from "next/link";

import { Icon } from "@/components/icons";
import { SiteFooter, SiteHeader } from "@/components/site";

// The example panel in the first viewport. Names and readings are made up;
// the alert line is the exact form Sentinel's disk alerts take.
const CIRCUITS: [string, string][] = [
  ["edge-proxy-01", "cpu 22% · mem 41% · disk 38%"],
  ["edge-proxy-02", "cpu 19% · mem 39% · disk 37%"],
  ["api-01", "cpu 47% · mem 63% · disk 52%"],
  ["api-02", "cpu 44% · mem 60% · disk 51%"],
  ["worker-01", "cpu 71% · mem 58% · disk 44%"],
  ["worker-02", "cpu 68% · mem 55% · disk 43%"],
  ["db-primary", "cpu 38% · mem 72% · disk 81%"],
  ["db-replica", "cpu 21% · mem 70% · disk 79%"],
  ["cache-01", "cpu 12% · mem 34% · disk 18%"],
  ["mail-relay", "cpu 6% · mem 22% · disk 30%"],
];
const TRIPS = 6; // db-primary
const TRIP_REASON = "/var/lib/postgresql 94.6% used, 386.0 GB free";

const SCHEDULE: [string, string][] = [
  [
    "Install",
    "One command on Linux, FreeBSD, OpenBSD, NetBSD, Windows or Docker. The agent runs unprivileged, finds Redis, nginx, Apache, PostgreSQL, MySQL, Docker, disks and logs, and updates itself.",
  ],
  [
    "Hold on",
    "When the network drops, the agent keeps 24 hours of data on disk and sends it when it's back, stamped with the time it was measured.",
  ],
  [
    "Say what failed",
    "Thresholds, anomalies, forecasts, silence, services, processes, containers, log patterns. Every alert names the mount, plugin or check, with the numbers.",
  ],
  [
    "One email, not forty",
    "Servers that drop together go out as one email per person. Blips under a minute are held back. Flapping alerts quieten themselves.",
  ],
  [
    "Switches too",
    "The same agent polls the switches, firewalls and Proxmox clusters at its site. LLDP shows which port each server is cabled to, so a dead switch is one alert.",
  ],
  ["From outside", "HTTP, TCP, certificate and DNS checks, with SLO targets and error budgets."],
  [
    "Tell the right person",
    "Email, Slack, Teams, Discord, Telegram, PagerDuty, webhooks or push, with on-call rotations, escalation, quiet hours and maintenance windows.",
  ],
  [
    "Show your customers",
    "Public status pages with 90 days of uptime and announcements, showing only the names you choose. PDF reports and weekly digests.",
  ],
  [
    "Work as a team",
    "Organisations with owner, admin, member and read-only roles, an audit log of every change, and two-factor sign-in.",
  ],
];

function ExamplePanel() {
  return (
    <figure className="landing-panel relative">
      <div className="rounded-[4px] border-2 border-ink bg-panel p-1.5 shadow-[0_24px_60px_-28px_rgb(0_0_0/0.45)]">
        <div className="flex items-center justify-between gap-3 border-b border-line-2 bg-panel-2 px-3 py-2">
          <span className="plate px-2 py-0.5 text-[13px]">Panel A · example fleet</span>
          <span className="font-mono text-[11px] text-ink-3">updated every 30 s</span>
        </div>
        <ol className="grid sm:grid-cols-2">
          {CIRCUITS.map(([name, line], i) => {
            const trips = i === TRIPS;
            return (
              <li
                key={name}
                className={`flex min-w-0 items-center gap-2.5 border-b border-line px-3 py-2 sm:odd:border-r ${trips ? "circuit-trips" : ""}`}
              >
                <span className="w-5 shrink-0 text-right font-mono text-[11px] text-ink-3">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <svg viewBox="0 0 14 24" className="h-6 w-3.5 shrink-0" aria-hidden>
                  <rect
                    x="0.75"
                    y="0.75"
                    width="12.5"
                    height="22.5"
                    rx="1.5"
                    className="fill-panel-2 stroke-line-2"
                    strokeWidth="1.5"
                  />
                  <rect x="3" y="3" width="8" height="9" rx="1" className="handle fill-ink" />
                </svg>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[14px] font-medium text-ink">{name}</p>
                  <p className="relative truncate font-mono text-[11px] text-ink-3">
                    <span className="reading">{line}</span>
                    {trips && (
                      <span className="reason absolute inset-0 truncate text-bad">
                        {TRIP_REASON}
                      </span>
                    )}
                  </p>
                </div>
              </li>
            );
          })}
        </ol>
        <div className="alert-slip flex flex-wrap items-center gap-x-3 gap-y-1 bg-plate px-3 py-2.5 text-[13px] text-plate-ink">
          <Icon name="mail" className="size-4 shrink-0" />
          <span className="min-w-0 flex-1">
            <b className="font-semibold">db-primary</b>: disk above 90% · {TRIP_REASON}
          </span>
          <span className="font-mono text-[11px] opacity-70">1 email to on-call</span>
        </div>
      </div>
      <figcaption className="mt-2 text-right text-xs text-ink-3">
        Example data. One circuit trips a moment after the page loads.
      </figcaption>
    </figure>
  );
}

export default function Landing() {
  return (
    <>
      <SiteHeader />
      <main className="overflow-hidden">
        <section className="border-b-2 border-ink">
          <div className="mx-auto grid max-w-6xl items-center gap-12 px-4 pt-14 pb-16 sm:px-6 lg:grid-cols-[1fr_1.05fr] lg:pt-20 lg:pb-24">
            <div>
              <h1 className="font-plate text-[46px] leading-[0.95] font-bold tracking-[-0.01em] text-balance text-ink uppercase sm:text-[64px] lg:text-[76px]">
                Know your servers are fine.{" "}
                <span className="text-bad">Hear the moment they aren&apos;t.</span>
              </h1>
              <p className="mt-6 max-w-xl text-lg leading-relaxed text-ink-2">
                Sentinel watches your servers, websites and switches every 30 seconds. When
                something breaks, you get one message that says exactly what failed, and another
                when it&apos;s fixed.
              </p>
              <div className="mt-8 flex flex-wrap gap-3">
                <Link
                  href="/signup"
                  className="plate h-12 gap-2 px-6 text-[17px] transition-transform duration-150 ease-(--ease-out) active:scale-[0.97]"
                >
                  Start monitoring
                  <Icon name="arrow" />
                </Link>
                <Link
                  href="/help"
                  className="inline-flex h-12 items-center rounded-[3px] border border-line-2 bg-panel px-6 font-medium text-ink transition-colors hover:bg-panel-2"
                >
                  Read the guide
                </Link>
              </div>
              <pre className="mt-8 overflow-x-auto rounded-[3px] border border-line-2 bg-panel px-4 py-3 font-mono text-[13px] whitespace-pre-wrap text-ink">
                <span className="text-ink-3"># on your server</span>
                {"\n"}
                <span className="text-bad">$</span> curl -fsSL
                https://get.sentinel.rajpoot.app/install.sh | sh -s -- --key pg_…
              </pre>
            </div>
            <ExamplePanel />
          </div>
        </section>

        <section id="features" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-20 sm:px-6">
          <div className="flex flex-wrap items-end justify-between gap-4 border-b-2 border-ink pb-4">
            <h2 className="font-plate text-4xl leading-none font-bold text-ink uppercase sm:text-5xl">
              Built from running a real fleet
            </h2>
            <p className="max-w-sm text-sm text-ink-2">
              About 80 servers, many behind one shared IP. Every rule below exists because something
              went wrong there first.
            </p>
          </div>
          <dl className="grid md:grid-cols-3">
            {SCHEDULE.map(([title, body], i) => (
              <div
                key={title}
                className="border-b border-line py-6 md:px-6 md:[&:nth-child(3n+1)]:pl-0 md:[&:not(:nth-child(3n))]:border-r"
              >
                <dt className="flex items-baseline gap-3">
                  <span className="font-mono text-xs text-ink-3">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="font-plate text-xl font-semibold tracking-[0.03em] text-ink uppercase">
                    {title}
                  </span>
                </dt>
                <dd className="mt-2 text-[15px] leading-relaxed text-ink-2">{body}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="bg-plate text-plate-ink">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-6 px-4 py-14 sm:px-6">
            <div>
              <h2 className="font-plate text-4xl leading-none font-bold uppercase sm:text-5xl">
                Your first alert in five minutes
              </h2>
              <p className="mt-3 max-w-xl opacity-75">
                Sign up, run one command, and Sentinel starts watching with recommended rules
                already in place.
              </p>
            </div>
            <Link
              href="/signup"
              className="inline-flex h-12 items-center gap-2 rounded-[3px] bg-plate-ink px-6 font-plate text-[17px] font-semibold tracking-[0.07em] text-plate uppercase transition-transform duration-150 ease-(--ease-out) active:scale-[0.97]"
            >
              Create your account
              <Icon name="arrow" />
            </Link>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
