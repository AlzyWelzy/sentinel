"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  Button,
  Card,
  Empty,
  ErrorState,
  Field,
  Loading,
  Notice,
  PageHeader,
  Select,
  Table,
  cx,
} from "@/components/ui";
import { api, authed, errorText } from "@/lib/api/client";
import { duration } from "@/lib/format";
import { unwrap } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

function pct(v: number | null | undefined) {
  return v == null ? "—" : `${v.toFixed(v >= 99.995 ? 0 : 2)}%`;
}

export default function ReportsPage() {
  const qc = useQueryClient();
  const me = useMe();
  const [days, setDays] = useState(30);
  const [downloading, setDownloading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const summary = useQuery({
    queryKey: ["report", days],
    queryFn: async () =>
      unwrap(await api.GET("/v1/reports/summary", { params: { query: { days } } })),
  });
  const settings = useQuery({
    queryKey: ["report-settings"],
    queryFn: async () => unwrap(await api.GET("/v1/reports/settings")),
  });
  const save = useMutation({
    mutationFn: async (patch: Partial<NonNullable<typeof settings.data>>) =>
      unwrap(await api.PUT("/v1/reports/settings", { body: { ...settings.data!, ...patch } })),
    onSuccess: () => {
      setMsg("Saved.");
      qc.invalidateQueries({ queryKey: ["report-settings"] });
    },
    onError: (e) => setMsg(errorText(e)),
  });

  async function pdf() {
    setDownloading(true);
    const end = new Date();
    const start = new Date(end.getTime() - days * 86400_000);
    const qs = new URLSearchParams({
      start: start.toISOString(),
      end: end.toISOString(),
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    });
    const r = await authed(`/v1/reports/servers.pdf?${qs}`);
    setDownloading(false);
    if (!r.ok) return setMsg("The PDF couldn't be made. Try a shorter range.");
    const url = URL.createObjectURL(await r.blob());
    const a = Object.assign(document.createElement("a"), {
      href: url,
      download: `sentinel-report-${days}d.pdf`,
    });
    a.click();
    URL.revokeObjectURL(url);
  }

  const s = summary.data;
  return (
    <>
      <PageHeader
        title="Reports"
        subtitle="Availability, incidents and resource use over a period."
        actions={
          <>
            <div className="inline-flex rounded-lg border border-line bg-panel p-0.5">
              {[7, 30, 90].map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDays(d)}
                  className={cx(
                    "rounded-md px-2.5 py-1 text-xs font-medium",
                    days === d ? "bg-panel-2" : "text-ink-3",
                  )}
                >
                  {d} days
                </button>
              ))}
            </div>
            <Button onClick={pdf} loading={downloading}>
              Download PDF
            </Button>
          </>
        }
      />
      {msg && (
        <div className="mb-4">
          <Notice>{msg}</Notice>
        </div>
      )}
      {summary.isLoading ? (
        <Loading />
      ) : summary.error ? (
        <ErrorState message={errorText(summary.error)} />
      ) : (
        s && (
          <>
            <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                ["Availability", pct(s.availability)],
                ["Incidents", `${s.incidents_total} (${s.incidents_critical} critical)`],
                ["Time to acknowledge", duration(s.mtta_seconds)],
                ["Time to resolve", duration(s.mttr_seconds)],
              ].map(([l, v]) => (
                <Card key={l}>
                  <p className="text-xs text-ink-2">{l}</p>
                  <p className="mt-1 text-xl font-semibold tabular">{v}</p>
                </Card>
              ))}
            </div>
            <Card title="Servers" pad={false} className="mb-6">
              {!s.hosts?.length ? (
                <Empty title="No servers in this period" />
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <th>Server</th>
                      <th className="text-right">Availability</th>
                      <th className="text-right">Incidents</th>
                      <th className="text-right">CPU avg / max</th>
                      <th className="text-right">Memory avg / max</th>
                      <th className="text-right">Disk max</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.hosts?.map((h) => (
                      <tr key={h.host_id}>
                        <td className="font-medium">{h.hostname}</td>
                        <td className="text-right tabular">{pct(h.availability)}</td>
                        <td className="text-right tabular">{h.incidents}</td>
                        <td className="text-right tabular">
                          {pct(h.cpu_avg)} / {pct(h.cpu_max)}
                        </td>
                        <td className="text-right tabular">
                          {pct(h.memory_avg)} / {pct(h.memory_max)}
                        </td>
                        <td className="text-right tabular">{pct(h.disk_max)}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
          </>
        )
      )}
      {settings.data && canEdit(me.data?.role) && (
        <Card title="Scheduled emails">
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Digest">
              <Select
                value={settings.data.digest}
                onChange={(e) => save.mutate({ digest: e.target.value as "off" })}
                className="w-full"
              >
                <option value="off">Off</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly (Mondays)</option>
              </Select>
            </Field>
            <Field label="Sent at">
              <Select
                value={settings.data.digest_hour}
                onChange={(e) => save.mutate({ digest_hour: Number(e.target.value) })}
                className="w-full"
              >
                {Array.from({ length: 24 }, (_, h) => (
                  <option key={h} value={h}>
                    {String(h).padStart(2, "0")}:00 {settings.data!.digest_timezone}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Monthly PDF report">
              <Select
                value={settings.data.monthly_report ? "on" : "off"}
                onChange={(e) => save.mutate({ monthly_report: e.target.value === "on" })}
                className="w-full"
              >
                <option value="on">On</option>
                <option value="off">Off</option>
              </Select>
            </Field>
          </div>
          {settings.data.digest_timezone !== Intl.DateTimeFormat().resolvedOptions().timeZone && (
            <Button
              variant="ghost"
              className="mt-3"
              onClick={() =>
                save.mutate({ digest_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone })
              }
            >
              Use my time zone ({Intl.DateTimeFormat().resolvedOptions().timeZone})
            </Button>
          )}
        </Card>
      )}
    </>
  );
}
