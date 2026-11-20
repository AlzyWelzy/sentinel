"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { TimeChart } from "@/components/chart";
import { NetworkTabs } from "@/components/network-tabs";
import {
  Button,
  Card,
  Empty,
  ErrorState,
  Field,
  Input,
  Loading,
  Notice,
  PageHeader,
  Select,
  Stat,
  Table,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { bytes } from "@/lib/format";
import { bps } from "@/lib/network";
import { unwrap } from "@/lib/queries";

function thisMonth(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

function csvCell(v: string | number): string {
  const s = String(v);
  // Spreadsheet formulas from port names or tags: neutralise.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export default function BandwidthPage() {
  const tags = useQuery({
    queryKey: ["network", "billing-tags"],
    queryFn: async () => unwrap(await api.GET("/v1/network/bandwidth/tags")),
  });
  const [tag, setTag] = useState("");
  const [month, setMonth] = useState(thisMonth);
  const chosen = tag || tags.data?.[0]?.tag || "";
  const report = useQuery({
    queryKey: ["network", "bandwidth", chosen, month],
    enabled: !!chosen && /^\d{4}-\d{2}$/.test(month),
    queryFn: async () =>
      unwrap(await api.GET("/v1/network/bandwidth", { params: { query: { tag: chosen, month } } })),
  });
  if (tags.isLoading) return <Loading />;
  if (tags.error)
    return <ErrorState message={errorText(tags.error)} retry={() => tags.refetch()} />;
  const r = report.data;
  function downloadCsv() {
    if (!r) return;
    const rows: (string | number)[][] = [
      ["billing tag", r.tag],
      [
        "period",
        `${new Date(r.start * 1000).toISOString()} to ${new Date(r.end * 1000).toISOString()}`,
      ],
      ["timezone", r.timezone],
      ["billable 95th percentile (bit/s)", Math.round(r.billable_p95_bps)],
      ["inbound 95th (bit/s)", Math.round(r.inbound.p95_bps)],
      ["outbound 95th (bit/s)", Math.round(r.outbound.p95_bps)],
      ["inbound total (bytes)", Math.round(r.inbound.total_bytes)],
      ["outbound total (bytes)", Math.round(r.outbound.total_bytes)],
      ["coverage (%)", r.coverage_pct],
      ["method", r.method],
      [],
      ["device", "interface", "alias", "speed (bit/s)"],
      ...r.ports.map((p) => [p.device, p.ifname, p.alias ?? "", p.speed_bps ?? ""]),
      [],
      ["time (UTC)", "inbound (bit/s)", "outbound (bit/s)"],
      ...r.series_in.map((point, i) => [
        new Date((point[0] ?? 0) * 1000).toISOString(),
        Math.round(point[1] ?? 0),
        Math.round(r.series_out[i]?.[1] ?? 0),
      ]),
    ];
    const blob = new Blob([rows.map((row) => row.map(csvCell).join(",")).join("\n")], {
      type: "text/csv",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `bandwidth-${r.tag.replace(/[^A-Za-z0-9_-]+/g, "_")}-${month}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }
  return (
    <>
      <PageHeader
        title="Network"
        subtitle="95th-percentile bandwidth per customer or service, from tagged ports"
      />
      <NetworkTabs />
      {!tags.data!.length ? (
        <Empty title="No ports are tagged for billing">
          On a device&apos;s page, give its customer-facing ports a billing tag (the customer or
          service name). Ports with the same tag are summed, then billed at the 95th percentile.
        </Empty>
      ) : (
        <>
          <div className="mb-6 flex flex-wrap items-end gap-4">
            <Field label="Billing tag">
              <Select
                value={chosen}
                onChange={(e) => setTag(e.target.value)}
                className="min-w-[14rem]"
              >
                {tags.data!.map((t) => (
                  <option key={t.tag} value={t.tag}>
                    {t.tag} ({t.ports} port{t.ports === 1 ? "" : "s"})
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Month">
              <Input type="month" value={month} onChange={(e) => setMonth(e.target.value)} />
            </Field>
            <Button onClick={downloadCsv} disabled={!r}>
              Download CSV
            </Button>
          </div>
          {report.isLoading ? (
            <Loading />
          ) : report.error ? (
            <ErrorState message={errorText(report.error)} retry={() => report.refetch()} />
          ) : r ? (
            <>
              {r.coverage_pct < 99 && (
                <div className="mb-4">
                  <Notice tone={r.coverage_pct < 90 ? "warn" : "idle"}>
                    Data covers {r.coverage_pct}% of the period ({r.samples} of {r.expected_samples}{" "}
                    five-minute samples). Missing samples are left out, not counted as zero.
                  </Notice>
                </div>
              )}
              <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                <Stat label="Billable (95th)" value={bps(r.billable_p95_bps)} />
                <Stat label="Inbound 95th" value={bps(r.inbound.p95_bps)} />
                <Stat label="Outbound 95th" value={bps(r.outbound.p95_bps)} />
                <Stat
                  label="Transferred"
                  value={bytes(r.inbound.total_bytes + r.outbound.total_bytes)}
                />
              </div>
              <div className="mb-6">
                <Card title={`Traffic · ${r.timezone}`}>
                  <TimeChart
                    unit="bits_per_second"
                    series={[
                      { labels: { direction: "in" }, points: r.series_in as [number, number][] },
                      { labels: { direction: "out" }, points: r.series_out as [number, number][] },
                    ]}
                    range={{ start: r.start, end: r.end }}
                  />
                </Card>
              </div>
              <Card title="Ports" pad={false}>
                <Table>
                  <thead>
                    <tr>
                      <th>Device</th>
                      <th>Interface</th>
                      <th>Alias</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.ports.map((p) => (
                      <tr key={`${p.device_id}-${p.ifname}`}>
                        <td className="font-medium">{p.device}</td>
                        <td>{p.ifname}</td>
                        <td className="text-ink-2">{p.alias ?? ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </Card>
              <p className="mt-3 text-xs text-ink-3">{r.method}.</p>
            </>
          ) : null}
        </>
      )}
    </>
  );
}
