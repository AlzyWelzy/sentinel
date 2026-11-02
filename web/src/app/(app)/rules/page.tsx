"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { SeverityBadge } from "@/components/status";
import {
  Badge,
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
  Table,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";
import { duration } from "@/lib/format";
import { unwrap, useHosts, type Rule } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

type RuleIn = components["schemas"]["RuleIn"];

const KINDS: { value: RuleIn["kind"]; label: string; help: string }[] = [
  {
    value: "metric",
    label: "Metric threshold",
    help: "CPU, memory, disk, load… above or below a level.",
  },
  {
    value: "host_down",
    label: "Server not reporting",
    help: "No data from the agent for a while.",
  },
  { value: "process_down", label: "Process not running", help: "A named process is missing." },
  {
    value: "service_down",
    label: "Service stopped",
    help: "A systemd, rc.d or Windows service isn't running.",
  },
  {
    value: "forecast",
    label: "Running out soon",
    help: "Disk, inodes or memory projected to fill.",
  },
  { value: "anomaly", label: "Unusual for this server", help: "Far above the past week's normal." },
];
const METRICS = [
  "cpu",
  "memory",
  "swap",
  "disk",
  "inodes",
  "load1",
  "load5",
  "iowait",
  "steal",
  "disk_busy",
  "network_in",
  "network_out",
] as const;

function describe(r: Rule): string {
  if (r.kind === "metric")
    return `${r.metric} ${r.aggregation !== "last" ? `(${r.aggregation} over ${duration(r.window_seconds)}) ` : ""}${r.operator} ${r.threshold} for ${duration(r.duration_seconds)}`;
  if (r.kind === "host_down") return `silent for ${duration(r.duration_seconds)}`;
  if (r.target) return `${r.target} · ${duration(r.duration_seconds)}`;
  return r.kind.replace("_", " ");
}

const OUTPUT_ONLY = new Set(["id", "firing_hosts", "created_at"]);

function toInput(r: Rule): RuleIn {
  return Object.fromEntries(
    Object.entries(r).filter(([k]) => !OUTPUT_ONLY.has(k)),
  ) as unknown as RuleIn;
}

export default function RulesPage() {
  const qc = useQueryClient();
  const me = useMe();
  const editable = canEdit(me.data?.role);
  const [creating, setCreating] = useState(false);
  const rules = useQuery({
    queryKey: ["rules"],
    queryFn: async () => unwrap(await api.GET("/v1/alert-rules")),
  });
  const save = useMutation({
    mutationFn: async (r: Rule) =>
      unwrap(
        await api.PUT("/v1/alert-rules/{rule_id}", {
          params: { path: { rule_id: r.id } },
          body: { ...toInput(r), enabled: !r.enabled },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(await api.DELETE("/v1/alert-rules/{rule_id}", { params: { path: { rule_id: id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
  const recommended = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/alert-rules/recommended")),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  return (
    <>
      <PageHeader
        title="Alert rules"
        subtitle="What counts as a problem, and who hears about it."
        actions={
          editable && (
            <>
              <Button onClick={() => recommended.mutate()} loading={recommended.isPending}>
                Add recommended
              </Button>
              <Button variant="primary" onClick={() => setCreating(true)}>
                New rule
              </Button>
            </>
          )
        }
      />
      {creating && <RuleForm onDone={() => setCreating(false)} />}
      <Card pad={false}>
        {rules.isLoading ? (
          <Loading />
        ) : rules.error ? (
          <ErrorState message={errorText(rules.error)} retry={() => rules.refetch()} />
        ) : !rules.data?.length ? (
          <Empty
            title="No rules yet"
            action={
              editable && (
                <Button onClick={() => recommended.mutate()}>Add the recommended set</Button>
              )
            }
          >
            Start with the recommended rules: servers not reporting, high CPU, memory and full
            disks.
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Condition</th>
                <th>Scope</th>
                <th>Severity</th>
                <th>State</th>
                {editable && <th />}
              </tr>
            </thead>
            <tbody>
              {rules.data.map((r) => (
                <tr key={r.id} className={r.enabled ? "" : "opacity-60"}>
                  <td className="font-medium">{r.name}</td>
                  <td className="text-ink-2">{describe(r)}</td>
                  <td className="text-ink-2">
                    {r.host_id ? "one server" : r.tag ? `tag: ${r.tag}` : "every server"}
                  </td>
                  <td>
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td>
                    {!r.enabled ? (
                      <Badge>disabled</Badge>
                    ) : r.firing_hosts ? (
                      <Badge tone="bad">firing on {r.firing_hosts}</Badge>
                    ) : (
                      <Badge tone="ok">ok</Badge>
                    )}
                  </td>
                  {editable && (
                    <td className="text-right whitespace-nowrap">
                      <Button variant="ghost" onClick={() => save.mutate(r)}>
                        {r.enabled ? "Disable" : "Enable"}
                      </Button>
                      <Button
                        variant="ghost"
                        onClick={() => confirm(`Delete "${r.name}"?`) && remove.mutate(r.id)}
                      >
                        Delete
                      </Button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}

function RuleForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const hosts = useHosts();
  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: async () => unwrap(await api.GET("/v1/channels")),
  });
  const [rule, setRule] = useState<RuleIn>({
    name: "",
    kind: "metric",
    metric: "cpu",
    operator: ">",
    threshold: 90,
    duration_seconds: 300,
    severity: "critical",
    aggregation: "last",
    window_seconds: 300,
    enabled: true,
    channel_ids: [],
  });
  const [scope, setScope] = useState<"all" | "host" | "tag">("all");
  const [error, setError] = useState<string | null>(null);
  const set = (patch: Partial<RuleIn>) => setRule((r) => ({ ...r, ...patch }));
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/alert-rules", {
          body: {
            ...rule,
            host_id: scope === "host" ? rule.host_id : null,
            tag: scope === "tag" ? rule.tag : null,
            ...(rule.kind === "metric" ? {} : { metric: null, operator: null, threshold: null }),
          },
        }),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      onDone();
    },
    onError: (e) => setError(errorText(e)),
  });

  return (
    <Card title="New rule" className="mb-6">
      <form
        className="grid gap-4 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        {error && (
          <div className="sm:col-span-2">
            <Notice tone="bad">{error}</Notice>
          </div>
        )}
        <Field label="Name">
          <Input
            required
            value={rule.name}
            onChange={(e) => set({ name: e.target.value })}
            placeholder="High CPU on web servers"
          />
        </Field>
        <Field label="Kind" hint={KINDS.find((k) => k.value === rule.kind)?.help}>
          <Select
            value={rule.kind}
            onChange={(e) => set({ kind: e.target.value as RuleIn["kind"] })}
            className="w-full"
          >
            {KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </Select>
        </Field>
        {(rule.kind === "metric" || rule.kind === "forecast" || rule.kind === "anomaly") && (
          <Field label="Metric">
            <Select
              value={rule.metric ?? "cpu"}
              onChange={(e) => set({ metric: e.target.value as RuleIn["metric"] })}
              className="w-full"
            >
              {METRICS.map((m) => (
                <option key={m}>{m}</option>
              ))}
            </Select>
          </Field>
        )}
        {rule.kind === "metric" && (
          <Field label="Condition">
            <div className="flex gap-2">
              <Select
                value={rule.aggregation}
                onChange={(e) => set({ aggregation: e.target.value as RuleIn["aggregation"] })}
              >
                <option value="last">latest</option>
                <option value="avg">average</option>
                <option value="max">peak</option>
                <option value="min">lowest</option>
              </Select>
              <Select
                value={rule.operator ?? ">"}
                onChange={(e) => set({ operator: e.target.value as ">" | "<" })}
              >
                <option value=">">above</option>
                <option value="<">below</option>
              </Select>
              <Input
                type="number"
                step="any"
                required
                value={rule.threshold ?? ""}
                onChange={(e) => set({ threshold: Number(e.target.value) })}
              />
            </div>
          </Field>
        )}
        {(rule.kind === "process_down" || rule.kind === "service_down") && (
          <Field label={rule.kind === "process_down" ? "Process name" : "Service name"}>
            <Input
              required
              value={rule.target ?? ""}
              onChange={(e) => set({ target: e.target.value })}
              placeholder="nginx"
            />
          </Field>
        )}
        {rule.kind === "forecast" && (
          <Field label="Warn when it fills within (hours)">
            <Input
              type="number"
              required
              value={rule.threshold ?? 24}
              onChange={(e) => set({ threshold: Number(e.target.value) })}
            />
          </Field>
        )}
        <Field label="For at least" hint="How long the condition must hold before it fires.">
          <Select
            value={rule.duration_seconds}
            onChange={(e) => set({ duration_seconds: Number(e.target.value) })}
            className="w-full"
          >
            {[0, 60, 180, 300, 600, 900, 1800, 3600].map((s) => (
              <option key={s} value={s}>
                {s === 0 ? "immediately" : duration(s)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Severity">
          <Select
            value={rule.severity}
            onChange={(e) => set({ severity: e.target.value as RuleIn["severity"] })}
            className="w-full"
          >
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </Select>
        </Field>
        <Field label="Applies to">
          <div className="flex gap-2">
            <Select value={scope} onChange={(e) => setScope(e.target.value as typeof scope)}>
              <option value="all">Every server</option>
              <option value="host">One server</option>
              <option value="tag">Servers with a tag</option>
            </Select>
            {scope === "host" && (
              <Select
                required
                value={rule.host_id ?? ""}
                onChange={(e) => set({ host_id: e.target.value })}
                className="flex-1"
              >
                <option value="">Choose…</option>
                {hosts.data?.map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.hostname}
                  </option>
                ))}
              </Select>
            )}
            {scope === "tag" && (
              <Input
                required
                placeholder="production"
                value={rule.tag ?? ""}
                onChange={(e) => set({ tag: e.target.value })}
              />
            )}
          </div>
        </Field>
        <Field label="Notify" hint="No contacts chosen: the organisation's default contact.">
          <div className="flex flex-wrap gap-3 pt-1">
            {channels.data?.map((c) => (
              <label key={c.id} className="flex items-center gap-1.5 text-sm">
                <input
                  type="checkbox"
                  checked={rule.channel_ids?.includes(c.id) ?? false}
                  onChange={(e) =>
                    set({
                      channel_ids: e.target.checked
                        ? [...(rule.channel_ids ?? []), c.id]
                        : (rule.channel_ids ?? []).filter((x) => x !== c.id),
                    })
                  }
                />
                {c.label ?? c.target}
              </label>
            ))}
          </div>
        </Field>
        <div className="flex gap-2 sm:col-span-2">
          <Button type="submit" variant="primary" loading={create.isPending}>
            Create rule
          </Button>
          <Button type="button" onClick={onDone}>
            Cancel
          </Button>
        </div>
      </form>
    </Card>
  );
}
