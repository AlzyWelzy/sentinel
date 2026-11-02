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
import { unwrap } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

type CheckIn = components["schemas"]["CheckIn"];

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
    target: "https://",
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
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/checks", { body: form })),
    onSuccess: () => {
      setError(null);
      setForm({ ...form, name: "", target: form.type === "http" ? "https://" : "" });
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
        subtitle="URLs, ports, certificates and DNS, checked from probe locations or your own servers."
      />
      {editable && (
        <Card title="New check" className="mb-6">
          <form
            className="grid gap-3 sm:grid-cols-[8rem_1fr_1fr_8rem_auto] sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <Field label="Type">
              <Select
                value={form.type}
                onChange={(e) => setForm({ ...form, type: e.target.value as CheckIn["type"] })}
                className="w-full"
              >
                <option value="http">HTTP(S)</option>
                <option value="tcp">TCP port</option>
                <option value="tls">TLS certificate</option>
                <option value="dns">DNS</option>
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
            <Field label="Target">
              <Input
                required
                value={form.target}
                onChange={(e) => setForm({ ...form, target: e.target.value })}
                placeholder={
                  form.type === "http"
                    ? "https://example.com"
                    : form.type === "dns"
                      ? "example.com"
                      : "example.com:443"
                }
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
            <Button type="submit" variant="primary" loading={create.isPending}>
              Add
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
                    {typeof c.last_failure === "string"
                      ? c.last_failure
                      : c.last_failure
                        ? JSON.stringify(c.last_failure)
                        : "—"}
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
