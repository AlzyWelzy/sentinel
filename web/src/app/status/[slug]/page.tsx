import type { Metadata } from "next";
import { notFound } from "next/navigation";

import type { components } from "@/lib/api/schema";

type PublicPage = components["schemas"]["PublicPage"];

// Server-side only: the API on the private network (or the dev API).
const API = process.env.API_INTERNAL_URL ?? "http://localhost:8010";

async function load(slug: string): Promise<PublicPage | null> {
  const r = await fetch(`${API}/public/status/${encodeURIComponent(slug)}`, {
    next: { revalidate: 30 },
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`status page unavailable (${r.status})`);
  return (await r.json()) as PublicPage;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const page = await load((await params).slug).catch(() => null);
  return { title: page ? page.title : "Status", robots: { index: true } };
}

const COLOR: Record<string, string> = {
  up: "bg-ok",
  down: "bg-bad",
  degraded: "bg-warn",
  unknown: "bg-idle",
};
const WORDS: Record<string, string> = {
  up: "All systems operational",
  operational: "All systems operational",
  degraded: "Some systems degraded",
  down: "Major outage",
  outage: "Major outage",
  partial: "Partial outage",
};

function dayColor(uptime: number | null | undefined) {
  if (uptime == null) return "bg-panel-2";
  if (uptime >= 99.9) return "bg-ok";
  if (uptime >= 99) return "bg-warn";
  return "bg-bad";
}

export default async function StatusPage({ params }: { params: Promise<{ slug: string }> }) {
  const page = await load((await params).slug);
  if (!page) notFound();
  const overall = page.status as string;
  return (
    <main className="relative mx-auto max-w-3xl px-4 pt-16 pb-12 sm:px-6">
      <div className="bg-grid mask-fade pointer-events-none absolute inset-x-0 top-0 -z-10 h-72" />
      <h1 className="text-3xl font-semibold tracking-[-0.03em]">{page.title}</h1>
      {page.description && <p className="mt-2 text-ink-2">{page.description}</p>}
      <div
        className={`mt-8 flex items-center gap-3 rounded-2xl px-5 py-4 font-semibold text-white shadow-card ${overall === "up" || overall === "operational" ? "bg-gradient-to-r from-emerald-500 to-teal-500" : overall === "degraded" || overall === "partial" ? "bg-gradient-to-r from-amber-500 to-orange-500" : "bg-gradient-to-r from-rose-500 to-red-500"}`}
      >
        <span className="grid size-7 place-items-center rounded-full bg-white/20">
          <span className="size-2.5 rounded-full bg-white" />
        </span>
        {WORDS[overall] ?? overall}
      </div>

      {page.active.map((u) => (
        <section
          key={`${u.title}-${u.updated_at}`}
          className="mt-4 rounded-2xl border border-line bg-panel p-5 shadow-card"
        >
          <p className="text-xs font-medium tracking-wide text-ink-3 uppercase">
            {u.kind} · {u.state}
          </p>
          <h2 className="mt-1 font-semibold">{u.title}</h2>
          {u.body && <p className="mt-1 text-sm whitespace-pre-wrap text-ink-2">{u.body}</p>}
        </section>
      ))}

      <section className="mt-6 divide-y divide-line overflow-hidden rounded-2xl border border-line bg-panel shadow-card">
        {page.items.map((i) => (
          <div key={i.label} className="p-4">
            <div className="flex items-center justify-between gap-3">
              <span className="flex items-center gap-2 font-medium">
                <span className={`size-2.5 rounded-full ${COLOR[i.status] ?? "bg-idle"}`} />
                {i.label}
              </span>
              <span className="text-sm text-ink-2 tabular">
                {i.uptime_90d != null ? `${i.uptime_90d.toFixed(2)}% uptime` : ""}
                {i.response_ms != null ? ` · ${i.response_ms.toFixed(0)} ms` : ""}
              </span>
            </div>
            <div className="mt-3 flex gap-px" aria-label="Daily uptime, last 90 days">
              {i.days.map((d) => (
                <span
                  key={d.date}
                  title={`${d.date}: ${d.uptime == null ? "no data" : `${d.uptime.toFixed(2)}%`}`}
                  className={`h-7 flex-1 rounded-[1px] ${dayColor(d.uptime)}`}
                />
              ))}
            </div>
          </div>
        ))}
      </section>

      <section className="mt-8">
        <h2 className="mb-3 font-semibold">Recent incidents</h2>
        {page.incidents.length === 0 ? (
          <p className="text-sm text-ink-2">No incidents in the past week.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {page.incidents.map((x) => (
              <li
                key={`${x.title}-${x.started_at}`}
                className="rounded-xl border border-line bg-panel px-4 py-3 shadow-card"
              >
                <p className="font-medium">{x.title}</p>
                <p className="text-ink-3">
                  {new Date(x.started_at).toUTCString()}
                  {x.resolved_at
                    ? ` · resolved ${new Date(x.resolved_at).toUTCString()}`
                    : " · ongoing"}
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>
      <footer className="mt-12 text-center text-xs text-ink-3">
        Updated {new Date(page.updated_at).toUTCString()} · Powered by Sentinel
      </footer>
    </main>
  );
}
