import Link from "next/link";

import { Icon, type IconName } from "@/components/icons";
import { SiteFooter, SiteHeader } from "@/components/site";

const FEATURES: [IconName, string, string][] = [
  [
    "terminal",
    "Servers in a minute",
    "One command installs a small agent on Linux, FreeBSD, OpenBSD, NetBSD, Windows or in Docker. It runs unprivileged, configures itself for the services it finds, and updates itself.",
  ],
  [
    "database",
    "Nothing lost in an outage",
    "The agent keeps 24 hours of data on disk when the network drops and sends it when it's back, at the times it was measured.",
  ],
  [
    "bolt",
    "Alerts that say what failed",
    "Thresholds, anomalies, disks filling up, services and processes, containers, log patterns and silence. Each alert names the mount, plugin or check that failed.",
  ],
  [
    "mail",
    "Fewer, better emails",
    "Servers that drop together send one email per person. Brief blips are held back. Flapping alerts quieten themselves. Quiet hours, on-call rotations and escalation.",
  ],
  [
    "globe",
    "Uptime from outside",
    "HTTP, TCP, TLS certificate and DNS checks from probe locations, with SLO targets and error budgets.",
  ],
  [
    "status",
    "Status pages",
    "Public pages with 90 days of uptime and announcements, showing only the names you choose.",
  ],
  [
    "logs",
    "Logs and traces",
    "Search what your servers log, and see request rates, errors and latency from OpenTelemetry traces.",
  ],
  [
    "users",
    "Teams",
    "Organisations with owner, admin, member and read-only roles, an audit log of every change, and two-factor sign-in.",
  ],
];

const STEPS: [string, string][] = [
  ["Install", "Paste one command on a server. It shows up in under a minute."],
  ["Autoconfigure", "Databases, web servers, Docker, disks and logs are found and watched."],
  ["Get told", "Email, Slack, Teams, Telegram, PagerDuty, webhooks or push, to whoever's on call."],
];

const CHANNELS = [
  "Email",
  "Slack",
  "Teams",
  "Discord",
  "Telegram",
  "PagerDuty",
  "Webhooks",
  "Push",
];

// A deterministic, made-up CPU trace for the product preview.
const TRACE = Array.from({ length: 48 }, (_, i) => {
  const v = 38 + 14 * Math.sin(i / 4) + 9 * Math.sin(i / 1.7) + (i > 36 ? (i - 36) * 3.2 : 0);
  return Math.max(6, Math.min(94, v));
});

function Spark({ data }: { data: number[] }) {
  const w = 560;
  const h = 140;
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - (v / 100) * h] as const);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-36 w-full" preserveAspectRatio="none" aria-hidden>
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#8b70ff" stopOpacity=".35" />
          <stop offset="1" stopColor="#8b70ff" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="spark-line" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#8b70ff" />
          <stop offset="1" stopColor="#22d3ee" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1="0" x2={w} y1={h * f} y2={h * f} stroke="#fff" strokeOpacity=".05" />
      ))}
      <line
        x1="0"
        x2={w}
        y1={h * 0.15}
        y2={h * 0.15}
        stroke="#fb7185"
        strokeOpacity=".5"
        strokeDasharray="4 4"
      />
      <path d={`${line} L${w} ${h} L0 ${h} Z`} fill="url(#spark-fill)" />
      <path
        d={line}
        fill="none"
        stroke="url(#spark-line)"
        strokeWidth="2.2"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

function Preview() {
  const hosts: [string, string, number, number][] = [
    ["web-01", "ok", 42, 61],
    ["web-02", "ok", 37, 58],
    ["db-primary", "bad", 91, 84],
    ["cache-01", "ok", 18, 33],
    ["worker-03", "warn", 76, 71],
  ];
  const tone: Record<string, string> = {
    ok: "bg-[#34d399]",
    warn: "bg-[#fbbf24]",
    bad: "bg-[#fb7185]",
  };
  return (
    <div className="relative mx-auto mt-16 max-w-5xl">
      <div className="absolute -inset-x-10 -top-10 -bottom-10 rounded-[40px] bg-[radial-gradient(closest-side,rgb(139_112_255/0.28),transparent)] blur-2xl" />
      <div className="relative overflow-hidden rounded-2xl border border-white/10 bg-[#0b0d16] text-left text-white shadow-[0_40px_120px_-30px_rgb(80_60_200/0.55)] ring-1 ring-white/5">
        <div className="flex items-center gap-2 border-b border-white/5 px-4 py-3">
          <span className="size-2.5 rounded-full bg-white/15" />
          <span className="size-2.5 rounded-full bg-white/15" />
          <span className="size-2.5 rounded-full bg-white/15" />
          <span className="ml-3 rounded-md bg-white/5 px-2.5 py-0.5 font-mono text-[11px] text-white/40">
            sentinel.rajpoot.app/overview
          </span>
        </div>
        <div className="grid gap-px bg-white/5 md:grid-cols-[1.6fr_1fr]">
          <div className="bg-[#0b0d16] p-5">
            <div className="flex items-baseline justify-between">
              <div>
                <p className="text-xs text-white/40">db-primary · CPU</p>
                <p className="mt-1 text-2xl font-semibold tracking-tight">
                  91.4<span className="text-base text-white/40">%</span>
                </p>
              </div>
              <span className="rounded-full bg-[#fb7185]/15 px-2.5 py-0.5 text-xs font-medium text-[#fb7185] ring-1 ring-[#fb7185]/30">
                Critical · 4m
              </span>
            </div>
            <div className="mt-4">
              <Spark data={TRACE} />
            </div>
          </div>
          <div className="bg-[#0b0d16] p-5">
            <p className="text-xs font-medium tracking-[0.1em] text-white/40 uppercase">Servers</p>
            <ul className="mt-3 space-y-2.5">
              {hosts.map(([name, s, cpu, mem]) => (
                <li key={name} className="flex items-center gap-3 text-sm">
                  <span className={`size-2 rounded-full ${tone[s]}`} />
                  <span className="flex-1 font-mono text-[13px] text-white/80">{name}</span>
                  <span className="w-20">
                    <span className="block h-1.5 overflow-hidden rounded-full bg-white/10">
                      <span
                        className={`block h-full rounded-full ${cpu > 85 ? "bg-[#fb7185]" : cpu > 70 ? "bg-[#fbbf24]" : "bg-gradient-to-r from-[#8b70ff] to-[#22d3ee]"}`}
                        style={{ width: `${cpu}%` }}
                      />
                    </span>
                  </span>
                  <span className="w-9 text-right text-xs text-white/40 tabular">{mem}%</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 border-t border-white/5 bg-white/[0.02] px-5 py-3.5 text-[13px]">
          <span className="grid size-7 place-items-center rounded-lg bg-[#fb7185]/15 text-[#fb7185]">
            <Icon name="mail" className="size-3.5" />
          </span>
          <span className="text-white/80">
            <b className="font-semibold text-white">db-primary</b>: CPU above 90% for 5 minutes ·{" "}
            <span className="text-white/50">/var/lib/postgresql 94.6% used, 386.0 GB free</span>
          </span>
          <span className="ml-auto text-xs text-white/35">sent to on-call · 1 email</span>
        </div>
      </div>
    </div>
  );
}

export default function Landing() {
  return (
    <>
      <SiteHeader />
      <main className="overflow-hidden">
        <section className="relative">
          <div className="bg-grid mask-fade pointer-events-none absolute inset-0" />
          <div className="pointer-events-none absolute top-[-200px] left-1/2 h-[520px] w-[900px] -translate-x-1/2 rounded-full bg-[radial-gradient(closest-side,color-mix(in_srgb,var(--brand)_22%,transparent),transparent)]" />
          <div className="relative mx-auto max-w-6xl px-4 pt-20 pb-24 text-center sm:px-6 sm:pt-28">
            <Link
              href="/help"
              className="inline-flex animate-rise items-center gap-2 rounded-full border border-line bg-panel/70 py-1 pr-3 pl-1 text-xs text-ink-2 shadow-card backdrop-blur transition hover:border-brand/40"
            >
              <span className="rounded-full bg-gradient-brand px-2 py-0.5 font-semibold text-white">
                New
              </span>
              Agent 0.9: nothing lost when the network drops
              <Icon name="arrow" className="size-3" />
            </Link>
            <h1 className="mx-auto mt-7 max-w-5xl animate-rise text-balance text-[42px] leading-[1.04] font-semibold tracking-[-0.04em] text-ink sm:text-6xl lg:text-7xl">
              Know your servers are fine.{" "}
              <span className="text-gradient">Hear the moment they aren&apos;t.</span>
            </h1>
            <p className="mx-auto mt-6 max-w-2xl animate-rise text-lg leading-relaxed text-ink-2">
              Sentinel monitors servers and websites: metrics every 30 seconds, uptime checks, logs
              and alerts that tell you exactly what failed, by email, chat, webhook or push.
            </p>
            <div className="mt-9 flex animate-rise flex-wrap justify-center gap-3">
              <Link
                href="/signup"
                className="inline-flex h-11 items-center gap-2 rounded-xl bg-gradient-brand px-6 font-medium text-white shadow-glow transition hover:brightness-110"
              >
                Start monitoring
                <Icon name="arrow" />
              </Link>
              <Link
                href="/help"
                className="inline-flex h-11 items-center rounded-xl border border-line bg-panel px-6 font-medium text-ink shadow-card transition hover:border-line-2"
              >
                Read the guide
              </Link>
            </div>
            <div className="mx-auto mt-10 max-w-2xl animate-rise rounded-xl border border-white/10 bg-[#0b0d16] p-1 text-left shadow-card">
              <pre className="overflow-x-auto px-4 py-3 font-mono text-[13px] whitespace-pre-wrap text-[#d7dbf0]">
                <span className="text-[#6a7089]"># on your server</span>
                {"\n"}
                <span className="text-[#5ee6f6]">$</span> curl -fsSL
                https://get.sentinel.rajpoot.app/install.sh | sh -s -- --key pg_…
              </pre>
            </div>
            <Preview />
          </div>
        </section>

        <section className="border-y border-line bg-panel/50">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-center gap-x-8 gap-y-3 px-4 py-6 text-sm text-ink-3 sm:px-6">
            <span className="font-medium text-ink-2">Alerts go to</span>
            {CHANNELS.map((c) => (
              <span key={c} className="font-medium">
                {c}
              </span>
            ))}
          </div>
        </section>

        <section id="features" className="mx-auto max-w-6xl scroll-mt-20 px-4 py-24 sm:px-6">
          <p className="text-sm font-semibold tracking-[0.12em] text-brand uppercase">
            Everything in one place
          </p>
          <h2 className="mt-3 max-w-2xl text-3xl font-semibold tracking-[-0.03em] sm:text-4xl">
            Built from running a real fleet, not a slide deck.
          </h2>
          <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map(([icon, title, body]) => (
              <div
                key={title}
                className="group relative overflow-hidden rounded-2xl border border-line bg-panel p-6 shadow-card transition hover:-translate-y-0.5 hover:border-brand/40"
              >
                <div className="pointer-events-none absolute -top-16 -right-16 size-40 rounded-full bg-brand/10 opacity-0 blur-2xl transition group-hover:opacity-100" />
                <span className="grid size-10 place-items-center rounded-xl bg-gradient-brand text-white shadow-glow">
                  <Icon name={icon} className="size-[18px]" />
                </span>
                <h3 className="mt-5 font-semibold tracking-tight text-ink">{title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-ink-2">{body}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-4 pb-24 sm:px-6">
          <div className="grid gap-4 md:grid-cols-3">
            {STEPS.map(([title, body], i) => (
              <div key={title} className="rounded-2xl border border-line p-6">
                <span className="font-mono text-sm text-brand">0{i + 1}</span>
                <h3 className="mt-3 text-lg font-semibold tracking-tight">{title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-ink-2">{body}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="px-4 pb-24 sm:px-6">
          <div className="relative mx-auto max-w-6xl overflow-hidden rounded-3xl bg-[#0b0d16] px-6 py-16 text-center text-white sm:px-12">
            <div className="pointer-events-none absolute -top-32 left-1/2 size-[520px] -translate-x-1/2 rounded-full bg-[radial-gradient(closest-side,rgb(139_112_255/0.4),transparent)]" />
            <h2 className="relative text-3xl font-semibold tracking-[-0.03em] sm:text-4xl">
              Your first alert in five minutes.
            </h2>
            <p className="relative mx-auto mt-4 max-w-xl text-white/60">
              Sign up, run one command, and Sentinel starts watching with recommended rules already
              in place.
            </p>
            <Link
              href="/signup"
              className="relative mt-8 inline-flex h-11 items-center gap-2 rounded-xl bg-white px-6 font-medium text-[#0b0d16] transition hover:bg-white/90"
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
