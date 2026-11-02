"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { SeverityBadge } from "@/components/status";
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Loading,
  Notice,
  PageHeader,
  Select,
  Table,
  cx,
} from "@/components/ui";
import { api, authed, errorText, setOrg } from "@/lib/api/client";
import { dateTime, duration } from "@/lib/format";
import { unwrap } from "@/lib/queries";
import { useOrgs } from "@/lib/session";

const EVENT_TONE: Record<string, string> = {
  opened: "bg-bad",
  resolved: "bg-ok",
  acknowledged: "bg-brand",
  escalated: "bg-warn",
  reopened: "bg-bad",
};

export default function IncidentPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const orgs = useOrgs();
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const incident = useQuery({
    queryKey: ["incident", id],
    retry: false,
    refetchInterval: 30_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/incidents/{incident_id}", { params: { path: { incident_id: id } } }),
      ),
  });
  const deliveries = useQuery({
    queryKey: ["incident-deliveries", id],
    refetchInterval: 30_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/incidents/{incident_id}/deliveries", {
          params: { path: { incident_id: id } },
        }),
      ),
  });
  const members = useQuery({
    queryKey: ["members"],
    queryFn: async () => unwrap(await api.GET("/v1/members")),
  });

  // A link from an alert email names no organisation: look in the others.
  const searched = useRef(false);
  useEffect(() => {
    if (!incident.error || searched.current || orgs.list.length < 2) return;
    searched.current = true;
    (async () => {
      for (const o of orgs.list) {
        if (o.tenant_id === orgs.selected?.tenant_id) continue;
        const r = await authed(`/v1/incidents/${id}`, {
          headers: { "X-Sentinel-Account": o.tenant_id },
        });
        if (r.ok) {
          setOrg(o.tenant_id);
          location.reload();
          return;
        }
      }
    })();
  }, [incident.error, orgs, id]);

  const act = useMutation({
    mutationFn: async (action: () => Promise<{ data?: unknown; error?: unknown }>) =>
      unwrap(await action()),
    onSuccess: () => {
      setError(null);
      setNote("");
      qc.invalidateQueries({ queryKey: ["incident", id] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
    onError: (e) => setError(errorText(e)),
  });
  const path = { params: { path: { incident_id: id } } };

  if (incident.isLoading) return <Loading />;
  if (incident.error)
    return <ErrorState message={errorText(incident.error, "Incident not found")} />;
  const i = incident.data!;
  const open = i.status === "open";

  return (
    <>
      <div className="mb-2 text-sm">
        <Link href="/incidents" className="text-ink-3 hover:text-ink">
          Incidents
        </Link>
      </div>
      <PageHeader
        title={i.summary}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={i.severity} />
            <Badge tone={open ? "bad" : "ok"}>{i.status}</Badge>
            {i.host_id ? (
              <Link href={`/servers/${i.host_id}`} className="hover:text-brand">
                {i.hostname}
              </Link>
            ) : (
              i.hostname
            )}
            <span>· {i.rule_name}</span>
            <span>· {duration(i.duration_seconds)}</span>
            {i.snoozed_until && (
              <Badge tone="brand">snoozed until {dateTime(i.snoozed_until)}</Badge>
            )}
          </span>
        }
        actions={
          <>
            {open && !i.acknowledged_at && (
              <Button
                variant="primary"
                loading={act.isPending}
                onClick={() =>
                  act.mutate(() => api.POST("/v1/incidents/{incident_id}/acknowledge", path))
                }
              >
                Acknowledge
              </Button>
            )}
            {open &&
              (i.snoozed_until ? (
                <Button
                  onClick={() =>
                    act.mutate(() => api.DELETE("/v1/incidents/{incident_id}/snooze", path))
                  }
                >
                  Unsnooze
                </Button>
              ) : (
                <Select
                  aria-label="Snooze escalation"
                  value=""
                  onChange={(e) => {
                    const minutes = Number(e.target.value);
                    if (minutes)
                      act.mutate(() =>
                        api.POST("/v1/incidents/{incident_id}/snooze", {
                          ...path,
                          body: { minutes },
                        }),
                      );
                  }}
                >
                  <option value="">Snooze…</option>
                  <option value="30">30 minutes</option>
                  <option value="60">1 hour</option>
                  <option value="240">4 hours</option>
                  <option value="1440">1 day</option>
                  <option value="10080">1 week</option>
                </Select>
              ))}
            {open ? (
              <Button
                onClick={() =>
                  act.mutate(() => api.POST("/v1/incidents/{incident_id}/resolve", path))
                }
              >
                Resolve
              </Button>
            ) : (
              <Button
                onClick={() =>
                  act.mutate(() => api.POST("/v1/incidents/{incident_id}/reopen", path))
                }
              >
                Reopen
              </Button>
            )}
          </>
        }
      />
      {error && (
        <div className="mb-4">
          <Notice tone="bad">{error}</Notice>
        </div>
      )}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {i.detail && (
            <Card title="What failed">
              <p className="text-sm whitespace-pre-wrap">{i.detail}</p>
            </Card>
          )}
          <Card title="Timeline">
            <ol className="space-y-4">
              {i.events.map((e) => (
                <li key={e.id} className="flex gap-3">
                  <span
                    className={cx(
                      "mt-1.5 size-2 shrink-0 rounded-full",
                      EVENT_TONE[e.kind] ?? "bg-idle",
                    )}
                  />
                  <div className="min-w-0">
                    <p className="text-sm whitespace-pre-wrap">{e.message}</p>
                    <p className="text-xs text-ink-3">
                      {dateTime(e.created_at)}
                      {e.actor ? ` · ${e.actor}` : ""}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
            <form
              className="mt-6 flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (note.trim())
                  act.mutate(() =>
                    api.POST("/v1/incidents/{incident_id}/notes", {
                      ...path,
                      body: { message: note },
                    }),
                  );
              }}
            >
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Add a note for the team…"
                className="h-9 flex-1 rounded-lg border border-line bg-panel px-3 text-sm focus:border-brand focus:outline-none"
              />
              <Button type="submit">Add note</Button>
            </form>
          </Card>
        </div>
        <div className="space-y-6">
          <Card title="Details">
            <dl className="space-y-3 text-sm">
              <div>
                <dt className="text-ink-3">Assigned to</dt>
                <dd className="mt-1">
                  <Select
                    aria-label="Assigned to"
                    value={i.assigned_to ?? ""}
                    onChange={(e) => {
                      // Read it now: the controlled select snaps back before
                      // the mutation runs.
                      const userId = e.target.value || null;
                      act.mutate(() =>
                        api.POST("/v1/incidents/{incident_id}/assign", {
                          ...path,
                          body: { user_id: userId },
                        }),
                      );
                    }}
                    className="w-full"
                  >
                    <option value="">Nobody</option>
                    {(members.data ?? [])
                      .filter((m) => m.joined && m.user_id)
                      .map((m) => (
                        <option key={m.id} value={m.user_id ?? ""}>
                          {m.name ?? m.email}
                        </option>
                      ))}
                  </Select>
                </dd>
              </div>
              <div>
                <dt className="text-ink-3">Opened</dt>
                <dd>{dateTime(i.opened_at)}</dd>
              </div>
              {i.acknowledged_at && (
                <div>
                  <dt className="text-ink-3">Acknowledged</dt>
                  <dd>
                    {dateTime(i.acknowledged_at)} by {i.acknowledged_by}
                  </dd>
                </div>
              )}
              {i.resolved_at && (
                <div>
                  <dt className="text-ink-3">Resolved</dt>
                  <dd>
                    {dateTime(i.resolved_at)}
                    {i.resolved_by ? ` by ${i.resolved_by}` : ""}
                  </dd>
                </div>
              )}
              {i.value != null && (
                <div>
                  <dt className="text-ink-3">Value when it fired</dt>
                  <dd className="tabular">{i.value.toFixed(2)}</dd>
                </div>
              )}
              <div>
                <dt className="text-ink-3">Escalation step</dt>
                <dd>{i.escalation_level}</dd>
              </div>
            </dl>
          </Card>
          <Card title="Notifications" pad={false}>
            {!deliveries.data?.length ? (
              <p className="p-4 text-sm text-ink-3">Nothing sent for this incident.</p>
            ) : (
              <Table>
                <tbody>
                  {deliveries.data.map((d) => (
                    <tr key={d.id}>
                      <td>
                        <span className="text-sm">
                          {d.channel_label ?? d.channel_target ?? d.channel_type}
                        </span>
                        <p className="text-xs text-ink-3">
                          {d.kind.replace("alert_", "")} · {dateTime(d.sent_at ?? d.created_at)}
                          {d.attempts > 1 ? ` · ${d.attempts} attempts` : ""}
                        </p>
                        {d.last_error && d.status !== "sent" && (
                          <p className="text-xs text-bad">{d.last_error}</p>
                        )}
                      </td>
                      <td className="text-right">
                        <Badge
                          tone={d.status === "sent" ? "ok" : d.status === "failed" ? "bad" : "idle"}
                        >
                          {d.status === "sent" ? "delivered" : d.status}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
