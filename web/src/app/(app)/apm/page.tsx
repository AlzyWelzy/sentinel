"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { presetRange, RangePicker } from "@/components/range";
import { Badge, Card, Empty, ErrorState, Loading, PageHeader, Table, cx } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import type { Range } from "@/lib/format";
import { unwrap } from "@/lib/queries";

function ms(v: number | null | undefined) {
  return v == null ? "—" : `${v.toFixed(v < 10 ? 1 : 0)} ms`;
}

export default function ApmPage() {
  const [range, setRange] = useState<Range>(() => presetRange("1h"));
  const [service, setService] = useState<string | null>(null);
  const [trace, setTrace] = useState<string | null>(null);
  const services = useQuery({
    queryKey: ["apm", "services", range.start, range.end],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/apm/services", {
          params: { query: { start: range.start, end: range.end } },
        }),
      ),
  });
  const traces = useQuery({
    queryKey: ["apm", "traces", service, range.start, range.end],
    enabled: !!service,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/apm/traces", {
          params: { query: { service: service!, start: range.start, end: range.end } },
        }),
      ),
  });
  const spans = useQuery({
    queryKey: ["apm", "trace", trace],
    enabled: !!trace,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/apm/traces/{trace_id}", { params: { path: { trace_id: trace! } } }),
      ),
  });

  if (services.isLoading) return <Loading />;
  if (services.error) return <ErrorState message={errorText(services.error)} />;
  if (!services.data?.enabled)
    return (
      <>
        <PageHeader title="APM" />
        <Card>
          <Empty title="APM is off">
            This installation has no trace store configured (TEMPO_URL).
          </Empty>
        </Card>
      </>
    );
  const root = spans.data?.length ? Math.min(...spans.data.map((s) => s.start_ns)) : 0;
  const total = spans.data?.length
    ? Math.max(...spans.data.map((s) => s.start_ns + s.duration_ns)) - root
    : 1;

  return (
    <>
      <PageHeader
        title="APM"
        subtitle="Requests, errors and latency from apps that send OpenTelemetry traces to the agent."
        actions={<RangePicker value={range} onChange={setRange} />}
      />
      <Card title="Services" pad={false} className="mb-6">
        {!services.data.services.length ? (
          <Empty title="No traces yet">
            Point your app at the agent: OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Service</th>
                <th className="text-right">Requests/min</th>
                <th className="text-right">Errors</th>
                <th className="text-right">p50</th>
                <th className="text-right">p95</th>
                <th className="text-right">p99</th>
              </tr>
            </thead>
            <tbody>
              {services.data.services.map((s) => (
                <tr
                  key={s.name}
                  onClick={() => {
                    setService(s.name);
                    setTrace(null);
                  }}
                  className={cx(
                    "cursor-pointer hover:bg-panel-2/60",
                    service === s.name && "bg-panel-2",
                  )}
                >
                  <td className="font-medium">{s.name}</td>
                  <td className="text-right tabular">{s.requests_per_minute?.toFixed(1) ?? "—"}</td>
                  <td className="text-right tabular">
                    {s.error_rate == null ? "—" : `${(s.error_rate * 100).toFixed(1)}%`}
                  </td>
                  <td className="text-right tabular">{ms(s.p50_ms)}</td>
                  <td className="text-right tabular">{ms(s.p95_ms)}</td>
                  <td className="text-right tabular">{ms(s.p99_ms)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {service && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card title={`Traces · ${service}`} pad={false}>
            {traces.isLoading ? (
              <Loading />
            ) : !traces.data?.length ? (
              <Empty title="No traces in this range" />
            ) : (
              <Table>
                <tbody>
                  {traces.data.map((t) => (
                    <tr
                      key={t.trace_id}
                      onClick={() => setTrace(t.trace_id)}
                      className={cx(
                        "cursor-pointer hover:bg-panel-2/60",
                        trace === t.trace_id && "bg-panel-2",
                      )}
                    >
                      <td>
                        {t.root_name}
                        <p className="font-mono text-xs text-ink-3">{t.trace_id.slice(0, 16)}</p>
                      </td>
                      <td className="text-right tabular">{t.duration_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
          <Card title="Spans">
            {!trace ? (
              <p className="text-sm text-ink-3">Pick a trace.</p>
            ) : spans.isLoading ? (
              <Loading />
            ) : (
              <div className="space-y-1.5">
                {spans.data?.map((s) => (
                  <div key={s.span_id ?? s.name} className="text-xs">
                    <div className="flex justify-between gap-2">
                      <span className="truncate">
                        {s.service} · {s.name} {s.error && <Badge tone="bad">error</Badge>}
                      </span>
                      <span className="tabular text-ink-3">
                        {(s.duration_ns / 1e6).toFixed(1)} ms
                      </span>
                    </div>
                    <div className="mt-0.5 h-2 rounded bg-panel-2">
                      <div
                        className={cx("h-2 rounded", s.error ? "bg-bad" : "bg-brand")}
                        style={{
                          marginLeft: `${((s.start_ns - root) / total) * 100}%`,
                          width: `${Math.max(0.5, (s.duration_ns / total) * 100)}%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
