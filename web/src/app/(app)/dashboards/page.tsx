"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import { TimeChart, type SeriesIn } from "@/components/chart";
import { presetRange, RangePicker } from "@/components/range";
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
  cx,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";
import { stepFor, type Range } from "@/lib/format";
import { unwrap, useHosts } from "@/lib/queries";

type Panel = components["schemas"]["Panel"];
type Metric = Panel["metric"];
// The metrics the API compares across servers.
const METRICS: Metric[] = [
  "cpu",
  "memory",
  "swap",
  "disk",
  "inodes",
  "load",
  "network",
  "disk_io",
  "disk_iops",
  "disk_busy",
  "processes",
];
// The API compares at most this many servers in one panel.
const MAX_COMPARE = 12;

function PanelChart({ panel, range }: { panel: Panel; range: Range }) {
  const q = useQuery({
    queryKey: ["compare", panel, range.start, range.end],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/metrics/compare", {
          params: {
            query: {
              metric: panel.metric,
              host_id: panel.host_ids?.length ? panel.host_ids : undefined,
              tag: panel.tag ?? undefined,
              start: range.start,
              end: range.end,
              step: stepFor(range.end - range.start),
            },
          },
        }),
      ),
  });
  const bounds = useMemo(() => ({ start: range.start, end: range.end }), [range.start, range.end]);
  const series = useMemo(
    () =>
      (q.data?.series ?? []).map((x): SeriesIn => ({
        labels: { host: x.hostname },
        points: x.points as [number, number][],
      })),
    [q.data],
  );
  return (
    <Card title={panel.title} className={panel.width === 2 ? "lg:col-span-2" : undefined}>
      {q.isLoading ? (
        <Loading />
      ) : q.error ? (
        <ErrorState message={errorText(q.error)} />
      ) : !q.data?.series.length ? (
        <Empty title="No data" />
      ) : (
        <TimeChart series={series} unit={q.data.unit} range={bounds} />
      )}
    </Card>
  );
}

export default function DashboardsPage() {
  const qc = useQueryClient();
  const hosts = useHosts();
  const [range, setRange] = useState<Range>(() => presetRange("6h"));
  const [current, setCurrent] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Panel>({
    title: "",
    metric: "cpu",
    host_ids: [],
    tag: null,
    width: 1,
  });
  const list = useQuery({
    queryKey: ["dashboards"],
    queryFn: async () => unwrap(await api.GET("/v1/dashboards")),
  });
  const dash = list.data?.find((d) => d.id === current) ?? list.data?.[0];
  const panels = (dash?.panels ?? []) as Panel[];
  const create = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/dashboards", { body: { name, panels: [] } })),
    onSuccess: (d) => {
      setName("");
      setCurrent(d.id);
      qc.invalidateQueries({ queryKey: ["dashboards"] });
    },
  });
  const save = useMutation({
    mutationFn: async (next: Panel[]) =>
      unwrap(
        await api.PUT("/v1/dashboards/{dashboard_id}", {
          params: { path: { dashboard_id: dash!.id } },
          body: { name: dash!.name, panels: next },
        }),
      ),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["dashboards"] });
    },
    onError: (e) => setError(errorText(e)),
  });
  const remove = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.DELETE("/v1/dashboards/{dashboard_id}", {
          params: { path: { dashboard_id: dash!.id } },
        }),
      ),
    onSuccess: () => {
      setCurrent(null);
      qc.invalidateQueries({ queryKey: ["dashboards"] });
    },
  });

  if (list.isLoading) return <Loading />;
  return (
    <>
      <PageHeader
        title="Dashboards"
        subtitle="Compare servers side by side."
        actions={<RangePicker value={range} onChange={setRange} />}
      />
      <div className="mb-5 flex flex-wrap items-center gap-2">
        {list.data?.map((d) => (
          <button
            key={d.id}
            type="button"
            onClick={() => setCurrent(d.id)}
            className={cx(
              "rounded-lg border px-3 py-1.5 text-sm",
              dash?.id === d.id ? "border-brand text-ink" : "border-line text-ink-2",
            )}
          >
            {d.name}
          </button>
        ))}
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (name) create.mutate();
          }}
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="New dashboard"
            className="w-44"
          />
          <Button type="submit">Create</Button>
        </form>
      </div>
      {!dash ? (
        <Card>
          <Empty title="No dashboards yet">
            Create one, then add panels comparing servers or tags.
          </Empty>
        </Card>
      ) : (
        <>
          <Card
            title="Add a panel"
            className="mb-6"
            actions={
              <Button
                variant="ghost"
                onClick={() => confirm(`Delete ${dash.name}?`) && remove.mutate()}
              >
                Delete dashboard
              </Button>
            }
          >
            {error && (
              <div className="mb-3">
                <Notice tone="bad">{error}</Notice>
              </div>
            )}
            <form
              className="grid gap-3 sm:grid-cols-[1fr_9rem_1fr_9rem_7rem_auto] sm:items-end"
              onSubmit={(e) => {
                e.preventDefault();
                // Nothing chosen: every server (as many as a panel compares).
                const hostIds = draft.tag
                  ? []
                  : draft.host_ids?.length
                    ? draft.host_ids
                    : (hosts.data ?? []).slice(0, MAX_COMPARE).map((h) => h.id);
                save.mutate([
                  ...panels,
                  { ...draft, host_ids: hostIds, title: draft.title || draft.metric },
                ]);
              }}
            >
              <Field label="Title">
                <Input
                  value={draft.title}
                  onChange={(e) => setDraft({ ...draft, title: e.target.value })}
                />
              </Field>
              <Field label="Metric">
                <Select
                  value={draft.metric}
                  onChange={(e) => setDraft({ ...draft, metric: e.target.value as Metric })}
                  className="w-full"
                >
                  {METRICS.map((m) => (
                    <option key={m}>{m}</option>
                  ))}
                </Select>
              </Field>
              <Field
                label="Servers"
                hint={`None chosen and no tag: the first ${MAX_COMPARE} servers.`}
              >
                <Select
                  multiple
                  value={draft.host_ids ?? []}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      host_ids: Array.from(e.target.selectedOptions).map((o) => o.value),
                    })
                  }
                  className="h-20 w-full"
                >
                  {hosts.data?.map((h) => (
                    <option key={h.id} value={h.id}>
                      {h.hostname}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Or a tag">
                <Input
                  value={draft.tag ?? ""}
                  onChange={(e) => setDraft({ ...draft, tag: e.target.value || null })}
                  placeholder="production"
                />
              </Field>
              <Field label="Width">
                <Select
                  value={draft.width}
                  onChange={(e) => setDraft({ ...draft, width: Number(e.target.value) as 1 | 2 })}
                  className="w-full"
                >
                  <option value={1}>Half</option>
                  <option value={2}>Full</option>
                </Select>
              </Field>
              <Button type="submit" variant="primary" loading={save.isPending}>
                Add
              </Button>
            </form>
          </Card>
          {panels.length === 0 ? (
            <Card>
              <Empty title="No panels yet" />
            </Card>
          ) : (
            <div className="grid gap-6 lg:grid-cols-2">
              {panels.map((p, i) => (
                <div
                  key={`${p.title}-${i}`}
                  className={cx("relative", p.width === 2 && "lg:col-span-2")}
                >
                  <PanelChart panel={{ ...p, width: 1 }} range={range} />
                  <button
                    type="button"
                    onClick={() => save.mutate(panels.filter((_, j) => j !== i))}
                    className="absolute top-2.5 right-3 text-xs text-ink-3 hover:text-bad"
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </>
  );
}
