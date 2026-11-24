"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorState,
  Loading,
  PageHeader,
  Table,
  cx,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { duration } from "@/lib/format";
import { unwrap } from "@/lib/queries";

type Insights = {
  days: number;
  incidents: number;
  mtta_seconds: number | null;
  mttr_seconds: number | null;
  self_resolved_quickly: number;
  rules: {
    rule_id: string | null;
    rule_name: string;
    incidents: number;
    flapping: number;
    self_resolved_quickly: number;
    advice: string | null;
  }[];
  hosts: {
    host_id: string;
    hostname: string;
    cpu_avg: number | null;
    cpu_p95: number | null;
    memory_max: number | null;
    verdict: string;
    advice: string | null;
  }[];
  slos: {
    check_id: string;
    name: string;
    target: number;
    availability: number | null;
    budget_left_percent: number | null;
    burn_rate_1h: number | null;
    status: string;
  }[];
  dependencies: {
    host_ids: string[];
    hostnames: string[];
    together: number;
    upstream_host_id: string | null;
    upstream_hostname: string | null;
  }[];
};

type Suggestion = Insights["dependencies"][number];

function DependencyRow({ s }: { s: Suggestion }) {
  const qc = useQueryClient();
  const apply = useMutation({
    mutationFn: async () => {
      for (const id of s.host_ids) {
        unwrap(
          await api.PATCH("/v1/hosts/{host_id}", {
            params: { path: { host_id: id } },
            body: { depends_on_host_id: s.upstream_host_id, clear_depends_on: false },
          }),
        );
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["insights"] }),
  });
  const names = s.hostnames.join(", ");
  return (
    <tr>
      <td>
        <span title={names} className="block max-w-[28rem] truncate font-medium">
          {names}
        </span>
      </td>
      <td className="text-right tabular">{s.together}</td>
      <td>
        {s.upstream_hostname ? (
          <>
            Depend on <span className="font-medium">{s.upstream_hostname}</span>: it was down first
            in most of these outages.
          </>
        ) : (
          <>
            Nothing of yours went first: something in front of them (a router, a shared NAT, a link)
            drops. Add it as a server or network device and make these depend on it.
          </>
        )}
        {apply.error && <div className="text-bad mt-1 text-xs">{errorText(apply.error)}</div>}
      </td>
      <td className="text-right">
        {s.upstream_host_id && (
          <Button loading={apply.isPending} onClick={() => apply.mutate()}>
            Set dependency
          </Button>
        )}
      </td>
    </tr>
  );
}

const pct = (v: number | null | undefined) => (v == null ? "—" : `${v.toFixed(1)}%`);

export default function InsightsPage() {
  const [days, setDays] = useState(30);
  const q = useQuery({
    queryKey: ["insights", days],
    queryFn: async () =>
      unwrap(await api.GET("/v1/insights", { params: { query: { days } } })) as unknown as Insights,
  });
  return (
    <>
      <PageHeader
        title="Insights"
        subtitle="Noisy rules with a fix for each, servers sized wrong, and how your uptime checks track against their targets."
        actions={
          <div className="inline-flex rounded-[10px] border border-line bg-panel-2/70 p-0.5 shadow-[inset_0_1px_2px_rgb(0_0_0/0.05)]">
            {[7, 30, 90].map((d) => (
              <button
                key={d}
                type="button"
                onClick={() => setDays(d)}
                className={cx(
                  "rounded-lg px-2.5 py-1 text-xs font-medium transition",
                  days === d ? "bg-panel text-ink shadow-card ring-1 ring-line" : "text-ink-3",
                )}
              >
                {d} days
              </button>
            ))}
          </div>
        }
      />
      {q.isLoading ? (
        <Loading />
      ) : q.error ? (
        <ErrorState message={errorText(q.error)} />
      ) : (
        q.data && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                ["Incidents", String(q.data.incidents)],
                ["Time to acknowledge", duration(q.data.mtta_seconds)],
                ["Time to resolve", duration(q.data.mttr_seconds)],
                ["Cleared within 5 min", String(q.data.self_resolved_quickly)],
              ].map(([l, v]) => (
                <Card key={l}>
                  <p className="text-xs text-ink-2">{l}</p>
                  <p className="mt-1.5 text-2xl font-semibold tracking-tight tabular">{v}</p>
                </Card>
              ))}
            </div>
            <Card title="Noisy rules" pad={false}>
              {!q.data.rules.length ? (
                <Empty title="No noise">No rule fired often enough to need tuning.</Empty>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th className="text-right">Incidents</th>
                      <th className="text-right">Flapping</th>
                      <th>Advice</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.rules.map((r) => (
                      <tr key={r.rule_name}>
                        <td className="font-medium">{r.rule_name}</td>
                        <td className="text-right tabular">{r.incidents}</td>
                        <td className="text-right tabular">{r.flapping}</td>
                        <td className="text-ink-2">{r.advice ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
            <Card title="Server sizing" pad={false}>
              {!q.data.hosts.length ? (
                <Empty title="Not enough data yet">Sizing needs a week of metrics.</Empty>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <th>Server</th>
                      <th className="text-right">CPU avg / p95</th>
                      <th className="text-right">Memory peak</th>
                      <th>Verdict</th>
                      <th>Advice</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.hosts.map((h) => (
                      <tr key={h.host_id}>
                        <td className="font-medium">
                          <span title={h.hostname} className="block max-w-[18rem] truncate">
                            {h.hostname}
                          </span>
                        </td>
                        <td className="text-right tabular">
                          {pct(h.cpu_avg)} / {pct(h.cpu_p95)}
                        </td>
                        <td className="text-right tabular">{pct(h.memory_max)}</td>
                        <td>
                          <Badge
                            tone={
                              h.verdict === "ok" ? "ok" : h.verdict === "unknown" ? "idle" : "warn"
                            }
                          >
                            {h.verdict}
                          </Badge>
                        </td>
                        <td className="text-ink-2">{h.advice ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
            <Card title="Servers that go quiet together" pad={false}>
              {!(q.data.dependencies ?? []).length ? (
                <Empty title="Nothing to suggest">
                  No servers went quiet together three times or more.
                </Empty>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <th>Servers</th>
                      <th className="text-right">Times together</th>
                      <th>Suggestion</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.dependencies.map((s) => (
                      <DependencyRow key={s.host_ids.join()} s={s} />
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
            <Card title="Uptime targets (SLOs)" pad={false}>
              {!q.data.slos.length ? (
                <Empty title="No uptime checks" />
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <th>Check</th>
                      <th className="text-right">Target</th>
                      <th className="text-right">Availability</th>
                      <th className="text-right">Error budget left</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.slos.map((s) => (
                      <tr key={s.check_id}>
                        <td className="font-medium">{s.name}</td>
                        <td className="text-right tabular">{s.target}%</td>
                        <td className="text-right tabular">
                          {s.availability == null ? "—" : `${s.availability.toFixed(3)}%`}
                        </td>
                        <td className="text-right tabular">{pct(s.budget_left_percent)}</td>
                        <td>
                          <Badge
                            tone={
                              s.status === "healthy"
                                ? "ok"
                                : s.status === "breached"
                                  ? "bad"
                                  : s.status === "at_risk"
                                    ? "warn"
                                    : "idle"
                            }
                          >
                            {s.status.replace("_", " ")}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
          </div>
        )
      )}
    </>
  );
}
