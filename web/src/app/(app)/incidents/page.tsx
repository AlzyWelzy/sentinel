"use client";

import Link from "next/link";
import { useState } from "react";

import { SeverityBadge } from "@/components/status";
import { Badge, Card, Empty, ErrorState, Loading, PageHeader, Table, cx } from "@/components/ui";
import { errorText } from "@/lib/api/client";
import { dateTime, duration } from "@/lib/format";
import { useIncidents } from "@/lib/queries";

export default function IncidentsPage() {
  const [status, setStatus] = useState<"open" | "resolved" | undefined>("open");
  const q = useIncidents(status);
  return (
    <>
      <PageHeader title="Incidents" subtitle="Alerts that fired, with their timelines." />
      <div className="mb-4 inline-flex rounded-lg border border-line bg-panel p-0.5">
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
              status === v ? "bg-panel-2 font-medium" : "text-ink-3 hover:text-ink",
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
