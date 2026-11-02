"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { SeverityBadge } from "@/components/status";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorState,
  Loading,
  PageHeader,
  Table,
  cx,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { dateTime, duration } from "@/lib/format";
import { unwrap, useIncidents } from "@/lib/queries";

export default function IncidentsPage() {
  const [status, setStatus] = useState<"open" | "resolved" | undefined>("open");
  const q = useIncidents(status);
  const qc = useQueryClient();
  const [picked, setPicked] = useState<string[]>([]);
  const merge = useMutation({
    mutationFn: async () => {
      // Into the one that opened first: the others are its echoes.
      const chosen = (q.data ?? []).filter((i) => picked.includes(i.id));
      const into = [...chosen].sort((a, b) => a.opened_at.localeCompare(b.opened_at))[0]!;
      return unwrap(
        await api.POST("/v1/incidents/merge", {
          body: {
            into: into.id,
            incident_ids: chosen.filter((i) => i.id !== into.id).map((i) => i.id),
          },
        }),
      );
    },
    onSuccess: () => {
      setPicked([]);
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
  return (
    <>
      <PageHeader
        title="Incidents"
        subtitle="Alerts that fired, with their timelines."
        actions={
          picked.length > 1 && (
            <Button variant="primary" loading={merge.isPending} onClick={() => merge.mutate()}>
              Merge {picked.length} into the first
            </Button>
          )
        }
      />
      <div className="mb-4 inline-flex rounded-[10px] border border-line bg-panel-2/70 p-0.5 shadow-[inset_0_1px_2px_rgb(0_0_0/0.05)]">
        {(
          [
            ["open", "Open"],
            ["resolved", "Resolved"],
            [undefined, "All"],
          ] as const
        ).map(([v, label]) => (
          <button
            key={label}
            type="button"
            onClick={() => setStatus(v)}
            className={cx(
              "rounded-md px-3 py-1 text-sm",
              status === v
                ? "bg-panel font-medium text-ink shadow-card ring-1 ring-line"
                : "text-ink-3 hover:text-ink",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      <Card pad={false}>
        {q.isLoading ? (
          <Loading />
        ) : q.error ? (
          <ErrorState message={errorText(q.error)} retry={() => q.refetch()} />
        ) : !q.data?.length ? (
          <Empty title={status === "open" ? "Nothing open" : "No incidents"}>
            {status === "open"
              ? "Every alert has resolved."
              : "Incidents appear here when a rule fires."}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th className="w-8" />
                <th>Severity</th>
                <th>Incident</th>
                <th>Server</th>
                <th>State</th>
                <th>Opened</th>
                <th className="text-right">Duration</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((i) => (
                <tr key={i.id}>
                  <td>
                    {i.status === "open" && !i.merged_into && (
                      <input
                        type="checkbox"
                        aria-label={`Select ${i.summary}`}
                        checked={picked.includes(i.id)}
                        onChange={(e) =>
                          setPicked(
                            e.target.checked ? [...picked, i.id] : picked.filter((x) => x !== i.id),
                          )
                        }
                      />
                    )}
                  </td>
                  <td>
                    <SeverityBadge severity={i.severity} />
                  </td>
                  <td className="max-w-lg">
                    <Link href={`/incidents/${i.id}`} className="font-medium hover:text-brand">
                      {i.summary}
                    </Link>
                    <p className="truncate text-xs text-ink-3">{i.rule_name}</p>
                  </td>
                  <td className="text-ink-2">{i.hostname}</td>
                  <td>
                    <div className="flex flex-wrap gap-1">
                      <Badge tone={i.status === "open" ? "bad" : "ok"}>{i.status}</Badge>
                      {i.acknowledged_at && i.status === "open" && (
                        <Badge tone="brand">acknowledged</Badge>
                      )}
                      {i.assigned_name && <Badge>{i.assigned_name}</Badge>}
                      {i.flapping && <Badge tone="warn">flapping</Badge>}
                    </div>
                  </td>
                  <td className="whitespace-nowrap text-ink-2">{dateTime(i.opened_at)}</td>
                  <td className="text-right text-ink-3">{duration(i.duration_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
