"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

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
import { CHECK_TYPES, checkType, type ParamField } from "@/lib/checkTypes";
import { unwrap, useHosts } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

type CheckIn = components["schemas"]["CheckIn"];

const GROUPS = ["Web", "Network", "Databases and brokers", "On the server"] as const;
const INVERT: ParamField = {
  key: "invert",
  label: "Upside down (up when unreachable)",
  kind: "bool",
};

export default function ChecksPage() {
  const qc = useQueryClient();
  const me = useMe();
  const editable = canEdit(me.data?.role);
  const checks = useQuery({
    queryKey: ["checks"],
    refetchInterval: 30_000,
    queryFn: async () => unwrap(await api.GET("/v1/checks")),
  });
  const probes = useQuery({
    queryKey: ["probes"],
    queryFn: async () => unwrap(await api.GET("/v1/probes")),
  });
  const [form, setForm] = useState<CheckIn>({
    name: "",
    type: "http",
    target: "",
    interval_seconds: 60,
    on_probes: true,
    probe_regions: [],
    min_failing: 1,
    enabled: true,
    slo_target: 99.9,
    alert: true,
    severity: "critical",
    params: {},
  });
  const hosts = useHosts();
  const [where, setWhere] = useState("probes");
  const kind = checkType(form.type);
  const pickType = (value: string) => {
    const next = checkType(value);
    setForm({ ...form, type: value as CheckIn["type"], target: "", params: {} });
    if (!next.probes && where === "probes" && hosts.data?.length)
      setWhere(hosts.data[0]?.id ?? "probes");
  };
  const setParam = (key: string, value: string) => {
    const params = { ...(form.params ?? {}) };
    if (value === "") delete params[key];
    else params[key] = value;
    setForm({ ...form, params });
  };
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/checks", {
          body:
            where === "probes"
              ? { ...form, on_probes: true, host_id: null }
              : { ...form, on_probes: false, host_id: where },
        }),
      ),
    onSuccess: () => {
      setError(null);
      setForm({ ...form, name: "", target: "", params: {} });
      qc.invalidateQueries({ queryKey: ["checks"] });
    },
    onError: (e) => setError(errorText(e)),
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(await api.DELETE("/v1/checks/{check_id}", { params: { path: { check_id: id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["checks"] }),
  });
  const noProbes = probes.data && probes.data.length === 0;

  return (
    <>
      <PageHeader
        title="Uptime checks"
        subtitle="Websites, ports, certificates, DNS, databases, brokers, game servers, containers and services, checked from probe locations or your own servers."
      />
      {editable && (
        <Card title="New check" className="mb-6">
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <div className="grid gap-3 sm:grid-cols-[12rem_1fr_2fr_8rem] sm:items-end">
              <Field label="Type">
                <Select
                  value={form.type}
                  onChange={(e) => pickType(e.target.value)}
                  className="w-full"
                >
                  {GROUPS.map((g) => (
                    <optgroup key={g} label={g}>
                      {CHECK_TYPES.filter((t) => t.group === g).map((t) => (
                        <option key={t.value} value={t.value}>
                          {t.label}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </Select>
              </Field>
              <Field label="Name">
                <Input
                  required
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Website"
                />
              </Field>
              <Field
                label={
                  kind.group === "On the server" && kind.value !== "file" && kind.value !== "log"
                    ? "Name on the server"
                    : "Target"
                }
              >
                <Input
                  required
                  value={form.target}
                  onChange={(e) => setForm({ ...form, target: e.target.value })}
                  placeholder={kind.placeholder}
                  spellCheck={false}
                  autoCapitalize="off"
                />
              </Field>
              <Field label="Every">
                <Select
                  value={form.interval_seconds}
                  onChange={(e) => setForm({ ...form, interval_seconds: Number(e.target.value) })}
                  className="w-full"
                >
                  {[30, 60, 300, 900].map((s) => (
                    <option key={s} value={s}>
                      {s < 60 ? `${s}s` : `${s / 60}m`}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
            <div className="grid gap-3 sm:grid-cols-[12rem_1fr]">
              <Field label="Runs from">
                <Select value={where} onChange={(e) => setWhere(e.target.value)} className="w-full">
                  {kind.probes && <option value="probes">Probe locations</option>}
                  {hosts.data?.map((h) => (
                    <option key={h.id} value={h.id}>
                      {h.hostname}
                    </option>
                  ))}
                </Select>
              </Field>
              {where === "probes" && !kind.probes && (
                <p className="self-end text-xs text-warn">Pick the server this runs on.</p>
              )}
            </div>
            {
              <details
                className="rounded border border-line p-3"
                open={kind.fields.length > 0 && kind.value !== "http"}
              >
                <summary className="cursor-pointer text-[13px] font-medium">Options</summary>
                <div className="mt-3 grid gap-3 sm:grid-cols-3">
                  {kind.fields
                    .filter((f) => f.kind !== "bool")
                    .map((f) => (
                      <Field key={f.key} label={f.label} hint={f.hint}>
                        {f.kind === "select" ? (
                          <Select
                            value={form.params?.[f.key] ?? ""}
                            onChange={(e) => setParam(f.key, e.target.value)}
                            className="w-full"
                          >
                            <option value="">Default</option>
                            {f.options?.map(([v, l]) => (
                              <option key={v} value={v}>
                                {l}
                              </option>
                            ))}
                          </Select>
                        ) : (
                          <Input
                            type={
                              f.kind === "password"
                                ? "password"
                                : f.kind === "number"
                                  ? "number"
                                  : "text"
                            }
                            min={f.kind === "number" ? 0 : undefined}
                            value={form.params?.[f.key] ?? ""}
                            onChange={(e) => setParam(f.key, e.target.value)}
                            placeholder={f.placeholder}
                            autoComplete={f.kind === "password" ? "new-password" : "off"}
                            spellCheck={false}
                          />
                        )}
                      </Field>
                    ))}
                </div>
                <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-[13px]">
                  {[...kind.fields.filter((f) => f.kind === "bool"), INVERT].map((f) => (
                    <label key={f.key} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={form.params?.[f.key] === "true"}
                        onChange={(e) => setParam(f.key, e.target.checked ? "true" : "")}
                      />
                      {f.label}
                    </label>
                  ))}
                </div>
              </details>
            }
            <Button type="submit" variant="primary" loading={create.isPending}>
              Add check
            </Button>
          </form>
          {error && (
            <div className="mt-3">
              <Notice tone="bad">{error}</Notice>
            </div>
          )}
          {noProbes && (
            <p className="mt-3 text-xs text-warn">
              No probe locations are running yet, so probe checks wait until one is. A superadmin
              turns servers into probes.
            </p>
          )}
        </Card>
      )}
      <Card pad={false}>
        {checks.isLoading ? (
          <Loading />
        ) : checks.error ? (
          <ErrorState message={errorText(checks.error)} />
        ) : !checks.data?.length ? (
          <Empty title="No checks yet">
            Add a URL to know when it&apos;s down before your users do.
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>From</th>
                <th>Last failure</th>
                {editable && <th />}
              </tr>
            </thead>
            <tbody>
              {checks.data.map((c) => (
                <tr key={c.id}>
                  <td>
                    <span className="font-medium">{c.name}</span>
                    <p className="font-mono text-xs text-ink-3">
                      {c.type} · {c.target}
                    </p>
                  </td>
                  <td>
                    <Badge tone={c.status === "up" ? "ok" : c.status === "down" ? "bad" : "idle"}>
                      {c.status}
                    </Badge>
                  </td>
                  <td className="text-ink-2">
                    {c.on_probes
                      ? c.probe_regions.length
                        ? c.probe_regions.join(", ")
                        : "all probes"
                      : "your servers"}
                  </td>
                  <td className="max-w-xs truncate text-xs text-ink-3">
                    {c.last_failure?.detail ?? "—"}
                  </td>
                  {editable && (
                    <td className="text-right">
                      <Button
                        variant="ghost"
                        onClick={() => confirm(`Delete ${c.name}?`) && remove.mutate(c.id)}
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
