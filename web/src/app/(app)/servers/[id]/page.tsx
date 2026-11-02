"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { TimeChart, type SeriesIn } from "@/components/chart";
import { presetRange, RangePicker } from "@/components/range";
import { SeverityBadge, StatusBadge } from "@/components/status";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorState,
  Loading,
  Meter,
  PageHeader,
  Table,
  cx,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import type { components, paths } from "@/lib/api/schema";
import { ago, bytes, dateTime, duration, stepFor, type Range } from "@/lib/format";
import { unwrap, useOverview } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

type Metric = NonNullable<
  paths["/v1/hosts/{host_id}/metrics"]["get"]["parameters"]["query"]
>["metric"];
const TABS = ["Overview", "Disks", "Processes", "Network", "System", "Activity"] as const;
type Tab = (typeof TABS)[number];

function useMetric(hostId: string, metric: Metric, range: Range) {
  return useQuery({
    queryKey: ["metric", hostId, metric, range.start, range.end],
    refetchInterval: range.key === "custom" ? false : 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/hosts/{host_id}/metrics", {
          params: {
            path: { host_id: hostId },
            query: {
              metric,
              start: range.start,
              end: range.end,
              step: stepFor(range.end - range.start),
            },
          },
        }),
      ),
  });
}

function MetricCard({
  hostId,
  metric,
  title,
  range,
  top,
}: {
  hostId: string;
  metric: Metric;
  title: string;
  range: Range;
  top?: number;
}) {
  const q = useMetric(hostId, metric, range);
  const series = useMemo(() => {
    const s = (q.data?.series ?? []) as SeriesIn[];
    if (!top) return s;
    const peak = (x: SeriesIn) => Math.max(0, ...x.points.map((p) => p[1]));
    return [...s].sort((a, b) => peak(b) - peak(a)).slice(0, top);
  }, [q.data, top]);
  const bounds = useMemo(() => ({ start: range.start, end: range.end }), [range.start, range.end]);
  return (
    <Card title={title}>
      {q.isLoading ? (
        <Loading />
      ) : q.error ? (
        <ErrorState message={errorText(q.error)} retry={() => q.refetch()} />
      ) : series.length === 0 || series.every((s) => s.points.length === 0) ? (
        <Empty title="No data in this range" />
      ) : (
        <TimeChart series={series} unit={q.data!.unit} range={bounds} fallbackName={title} />
      )}
    </Card>
  );
}

export default function ServerPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const me = useMe();
  const [tab, setTab] = useState<Tab>("Overview");
  const [range, setRange] = useState<Range>(() => presetRange("1h"));
  const overview = useOverview();
  const host = useQuery({
    queryKey: ["host", id],
    queryFn: async () =>
      unwrap(await api.GET("/v1/hosts/{host_id}", { params: { path: { host_id: id } } })),
  });
  const pause = useMutation({
    mutationFn: async (paused: boolean) =>
      unwrap(
        paused
          ? await api.POST("/v1/hosts/{host_id}/resume", { params: { path: { host_id: id } } })
          : await api.POST("/v1/hosts/{host_id}/pause", { params: { path: { host_id: id } } }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["host", id] }),
  });
  const remove = useMutation({
    mutationFn: async () =>
      unwrap(await api.DELETE("/v1/hosts/{host_id}", { params: { path: { host_id: id } } })),
    onSuccess: () => router.replace("/servers"),
  });

  if (host.isLoading) return <Loading />;
  if (host.error) return <ErrorState message={errorText(host.error, "Server not found")} />;
  const h = host.data!;
  const health = overview.data?.servers.find((s) => s.id === id);
  const editable = canEdit(me.data?.role);

  return (
    <>
      <div className="mb-2 text-sm">
        <Link href="/servers" className="text-ink-3 hover:text-ink">
          Servers
        </Link>
      </div>
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            {h.hostname} {health && <StatusBadge status={health.status} />}
          </span>
        }
        subtitle={[
          [h.platform, h.platform_version].filter(Boolean).join(" ") || h.os,
          h.arch,
          h.cpu_cores ? `${h.cpu_cores} CPUs` : null,
          h.memory_bytes ? `${bytes(h.memory_bytes)} memory` : null,
          `agent ${h.agent_version ?? "?"}`,
          `seen ${ago(h.last_seen)}`,
        ]
          .filter(Boolean)
          .join(" · ")}
        actions={
          editable && (
            <>
              <Button onClick={() => pause.mutate(h.paused)} loading={pause.isPending}>
                {h.paused ? "Resume alerts" : "Pause alerts"}
              </Button>
              <Button
                variant="danger"
                loading={remove.isPending}
                onClick={() => {
                  if (confirm(`Remove ${h.hostname}? Its agent stops being accepted.`))
                    remove.mutate();
                }}
              >
                Remove
              </Button>
            </>
          )
        }
      />
      {h.tags.length > 0 && (
        <div className="-mt-3 mb-5 flex flex-wrap gap-1">
          {h.tags.map((t) => (
            <Badge key={t}>{t}</Badge>
          ))}
        </div>
      )}
      {h.paused && (
        <p className="mb-4 rounded-lg bg-panel-2 px-3 py-2 text-sm text-ink-2">
          Alerts are paused for this server{h.paused_by ? ` by ${h.paused_by}` : ""}. Metrics are
          still collected.
        </p>
      )}

      <div className="mb-5 flex flex-wrap items-center justify-between gap-3 border-b border-line">
        <div className="flex gap-1 overflow-x-auto">
          {TABS.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={cx(
                "-mb-px border-b-2 px-3 py-2 text-sm whitespace-nowrap",
                tab === t
                  ? "border-brand font-medium text-ink"
                  : "border-transparent text-ink-3 hover:text-ink",
              )}
            >
              {t}
            </button>
          ))}
        </div>
        {["Overview", "Disks", "Network"].includes(tab) && (
          <div className="pb-2">
            <RangePicker value={range} onChange={setRange} />
          </div>
        )}
      </div>

      {tab === "Overview" && (
        <div className="space-y-6">
          {health && (
            <div className="grid gap-3 sm:grid-cols-4">
              {[
                ["CPU", health.cpu],
                ["Memory", health.memory],
                ["Fullest disk", health.disk],
              ].map(([l, v]) => (
                <Card key={l as string}>
                  <p className="mb-2 text-xs text-ink-2">{l}</p>
                  <Meter value={v as number | null} />
                </Card>
              ))}
              <Card>
                <p className="mb-2 text-xs text-ink-2">Load · uptime</p>
                <p className="text-sm tabular">
                  {health.load1?.toFixed(2) ?? "—"} · {duration(health.uptime_seconds)}
                </p>
              </Card>
            </div>
          )}
          <div className="grid gap-6 lg:grid-cols-2">
            <MetricCard hostId={id} metric="cpu" title="CPU" range={range} />
            <MetricCard hostId={id} metric="memory" title="Memory" range={range} />
            <MetricCard hostId={id} metric="load" title="Load average" range={range} />
            <MetricCard hostId={id} metric="swap" title="Swap" range={range} />
          </div>
        </div>
      )}
      {tab === "Disks" && <Disks hostId={id} range={range} />}
      {tab === "Processes" && <Processes hostId={id} />}
      {tab === "Network" && (
        <div className="grid gap-6 lg:grid-cols-2">
          <MetricCard hostId={id} metric="network" title="Throughput" range={range} />
          <MetricCard
            hostId={id}
            metric="network_interfaces"
            title="Per interface"
            range={range}
            top={6}
          />
          <MetricCard hostId={id} metric="tcp_connections" title="TCP connections" range={range} />
          <MetricCard hostId={id} metric="network_errors" title="Errors and drops" range={range} />
        </div>
      )}
      {tab === "System" && <System hostId={id} host={h} />}
      {tab === "Activity" && <Activity hostId={id} />}
    </>
  );
}

function Disks({ hostId, range }: { hostId: string; range: Range }) {
  const disks = useQuery({
    queryKey: ["disks", hostId],
    queryFn: async () =>
      unwrap(await api.GET("/v1/hosts/{host_id}/disks", { params: { path: { host_id: hostId } } })),
  });
  return (
    <div className="space-y-6">
      <Card title="Filesystems" pad={false}>
        {disks.isLoading ? (
          <Loading />
        ) : disks.error ? (
          <ErrorState message={errorText(disks.error)} />
        ) : !disks.data?.length ? (
          <Empty title="No filesystems reported yet" />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Mount</th>
                <th>Used</th>
                <th>Free</th>
                <th>Size</th>
                <th>Inodes</th>
                <th>Full in</th>
              </tr>
            </thead>
            <tbody>
              {disks.data.map((d) => (
                <tr key={d.mountpoint}>
                  <td>
                    <span className="font-medium">{d.mountpoint}</span>
                    <p className="text-xs text-ink-3">
                      {d.device} · {d.fstype}
                    </p>
                  </td>
                  <td>
                    <Meter value={d.used_percent} />
                  </td>
                  <td className="tabular">{bytes(d.free_bytes)}</td>
                  <td className="tabular">{bytes(d.total_bytes)}</td>
                  <td>
                    <Meter value={d.inodes_used_percent} />
                  </td>
                  <td className="text-ink-2">
                    {d.days_until_full == null
                      ? "—"
                      : d.days_until_full < 1
                        ? "under a day"
                        : `${d.days_until_full.toFixed(0)} days`}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <MetricCard hostId={hostId} metric="disk" title="Usage" range={range} top={6} />
        <MetricCard hostId={hostId} metric="disk_io" title="Throughput" range={range} top={6} />
        <MetricCard hostId={hostId} metric="disk_iops" title="Operations" range={range} top={6} />
        <MetricCard hostId={hostId} metric="disk_busy" title="Busy time" range={range} top={6} />
      </div>
    </div>
  );
}

function Processes({ hostId }: { hostId: string }) {
  const [sort, setSort] = useState<"cpu" | "memory">("cpu");
  const q = useQuery({
    queryKey: ["processes", hostId],
    refetchInterval: 30_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/hosts/{host_id}/processes", { params: { path: { host_id: hostId } } }),
      ),
  });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState message={errorText(q.error)} />;
  const rows = [...(q.data?.processes ?? [])].sort((a, b) =>
    sort === "cpu"
      ? (b.cpu_percent ?? 0) - (a.cpu_percent ?? 0)
      : (b.memory_bytes ?? 0) - (a.memory_bytes ?? 0),
  );
  return (
    <Card
      title={`Busiest processes (${q.data?.total ?? 0} running)`}
      pad={false}
      actions={
        <div className="flex gap-1 text-xs">
          {(["cpu", "memory"] as const).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSort(s)}
              className={cx("rounded px-2 py-1", sort === s ? "bg-panel-2 text-ink" : "text-ink-3")}
            >
              by {s}
            </button>
          ))}
        </div>
      }
    >
      {rows.length === 0 ? (
        <Empty title="No processes reported yet" />
      ) : (
        <Table>
          <thead>
            <tr>
              <th>Process</th>
              <th className="text-right">Instances</th>
              <th className="text-right">CPU</th>
              <th className="text-right">Memory</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.name}>
                <td className="font-mono text-xs">{p.name}</td>
                <td className="text-right tabular">{p.count}</td>
                <td className="text-right tabular">{p.cpu_percent?.toFixed(1) ?? "—"}%</td>
                <td className="text-right tabular">{bytes(p.memory_bytes)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function System({ hostId, host }: { hostId: string; host: components["schemas"]["HostOut"] }) {
  const inv = useQuery({
    queryKey: ["inventory", hostId],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/hosts/{host_id}/inventory", { params: { path: { host_id: hostId } } }),
      ),
  });
  const packages = (inv.data?.packages ?? []) as { name: string; version: string }[];
  const rows: [string, React.ReactNode][] = [
    ["Hostname", host.hostname],
    [
      "Operating system",
      [host.platform, host.platform_version].filter(Boolean).join(" ") || host.os,
    ],
    ["Kernel", inv.data?.kernel_version ?? "—"],
    [
      "CPU",
      inv.data?.cpu_model
        ? `${inv.data.cpu_model} · ${host.cpu_cores ?? "?"} cores`
        : host.cpu_cores,
    ],
    ["Memory", bytes(host.memory_bytes)],
    ["Virtualization", inv.data?.virtualization ?? "none detected"],
    ["IP addresses", host.ip_addresses.join(", ") || "—"],
    ["Public IP", host.public_ip ?? "—"],
    ["Agent", host.agent_version ?? "—"],
    ["Added", dateTime(host.created_at)],
    [
      "Booted",
      inv.data?.boot_time ? dateTime(new Date(inv.data.boot_time * 1000).toISOString()) : "—",
    ],
  ];
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="System">
        <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-ink-3">{k}</dt>
              <dd className="break-words">{v ?? "—"}</dd>
            </div>
          ))}
        </dl>
      </Card>
      <Card title={`Packages (${packages.length})`} pad={false}>
        {inv.isLoading ? (
          <Loading />
        ) : !packages.length ? (
          <Empty title="No inventory yet">The agent collects it every 6 hours.</Empty>
        ) : (
          <div className="max-h-96 overflow-y-auto">
            <Table>
              <tbody>
                {packages.map((p) => (
                  <tr key={`${p.name}-${p.version}`}>
                    <td className="font-mono text-xs">{p.name}</td>
                    <td className="font-mono text-xs text-ink-3">{p.version}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Card>
    </div>
  );
}

function Activity({ hostId }: { hostId: string }) {
  const q = useQuery({
    queryKey: ["incidents", "host", hostId],
    queryFn: async () =>
      unwrap(await api.GET("/v1/incidents", { params: { query: { host_id: hostId } } })),
  });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState message={errorText(q.error)} />;
  return (
    <Card title="Alert history" pad={false}>
      {!q.data?.length ? (
        <Empty title="No alerts for this server" />
      ) : (
        <Table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Alert</th>
              <th>Status</th>
              <th>Opened</th>
              <th className="text-right">Lasted</th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((i) => (
              <tr key={i.id}>
                <td>
                  <SeverityBadge severity={i.severity} />
                </td>
                <td>
                  <Link href={`/incidents/${i.id}`} className="font-medium hover:text-brand">
                    {i.summary}
                  </Link>
                </td>
                <td>
                  <Badge tone={i.status === "open" ? "bad" : "ok"}>{i.status}</Badge>
                </td>
                <td className="text-ink-2">{dateTime(i.opened_at)}</td>
                <td className="text-right text-ink-3">{duration(i.duration_seconds)}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}
