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
import { dateTime } from "@/lib/format";
import { unwrap, useHosts } from "@/lib/queries";

function localInput(d: Date) {
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export default function MaintenancePage() {
  const qc = useQueryClient();
  const hosts = useHosts();
  const windows = useQuery({
    queryKey: ["maintenance"],
    queryFn: async () => unwrap(await api.GET("/v1/maintenance")),
  });
  const now = new Date();
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [starts, setStarts] = useState(localInput(now));
  const [ends, setEnds] = useState(localInput(new Date(now.getTime() + 3600_000)));
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/maintenance", {
          body: {
            name,
            schedule: "once",
            host_id: host || null,
            starts_at: new Date(starts).toISOString(),
            ends_at: new Date(ends).toISOString(),
            enabled: true,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          },
        }),
      ),
    onSuccess: () => {
      setName("");
      setError(null);
      qc.invalidateQueries({ queryKey: ["maintenance"] });
    },
    onError: (e) => setError(errorText(e)),
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.DELETE("/v1/maintenance/{window_id}", { params: { path: { window_id: id } } }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["maintenance"] }),
  });
  const names = new Map((hosts.data ?? []).map((h) => [h.id, h.hostname]));
  return (
    <>
      <PageHeader
        title="Maintenance"
        subtitle="No incidents open and nothing is sent during a window. Problems that outlast it fire when it ends."
      />
      <Card title="Schedule a window" className="mb-6">
        <form
          className="grid gap-3 sm:grid-cols-[1fr_12rem_13rem_13rem_auto] sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <Field label="Name">
            <Input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Kernel upgrade"
            />
          </Field>
          <Field label="Server">
            <Select value={host} onChange={(e) => setHost(e.target.value)} className="w-full">
              <option value="">Every server</option>
              {hosts.data?.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.hostname}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Starts">
            <Input
              type="datetime-local"
              required
              value={starts}
              onChange={(e) => setStarts(e.target.value)}
            />
          </Field>
          <Field label="Ends">
            <Input
              type="datetime-local"
              required
              value={ends}
              onChange={(e) => setEnds(e.target.value)}
            />
          </Field>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Schedule
          </Button>
        </form>
        {error && (
          <div className="mt-3">
            <Notice tone="bad">{error}</Notice>
          </div>
        )}
      </Card>
      <Card pad={false}>
        {windows.isLoading ? (
          <Loading />
        ) : windows.error ? (
          <ErrorState message={errorText(windows.error)} />
        ) : !windows.data?.length ? (
          <Empty title="No maintenance windows" />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Window</th>
                <th>Scope</th>
                <th>When</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {windows.data.map((w) => (
                <tr key={w.id}>
                  <td className="font-medium">{w.name}</td>
                  <td className="text-ink-2">
                    {w.host_id
                      ? (names.get(w.host_id) ?? "one server")
                      : w.tag
                        ? `tag: ${w.tag}`
                        : "every server"}
                  </td>
                  <td className="text-ink-2">
                    {w.schedule === "once"
                      ? `${dateTime(w.starts_at)} – ${dateTime(w.ends_at)}`
                      : `weekly ${w.start_time} for ${w.duration_minutes}m (${w.timezone})`}
                  </td>
                  <td>
                    {w.active ? (
                      <Badge tone="brand">active now</Badge>
                    ) : (
                      <Badge>{w.enabled ? "scheduled" : "off"}</Badge>
                    )}
                  </td>
                  <td className="text-right">
                    <Button variant="ghost" onClick={() => remove.mutate(w.id)}>
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
