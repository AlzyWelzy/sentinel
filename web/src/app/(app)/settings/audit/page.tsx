"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { Badge, Card, Empty, ErrorState, Input, Loading, PageHeader, Table } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";

export default function AuditPage() {
  const [q, setQ] = useState("");
  const log = useQuery({
    queryKey: ["audit", q],
    queryFn: async () =>
      unwrap(await api.GET("/v1/audit-log", { params: { query: { q: q || undefined } } })),
  });
  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Every change in this organisation, and who made it."
      />
      <Input
        className="mb-4 max-w-xs"
        placeholder="Search…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
      />
      <Card pad={false}>
        {log.isLoading ? (
          <Loading />
        ) : log.error ? (
          <ErrorState message={errorText(log.error)} />
        ) : !log.data?.length ? (
          <Empty title="Nothing recorded" />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
              </tr>
            </thead>
            <tbody>
              {log.data.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap text-ink-2">{dateTime(e.created_at)}</td>
                  <td>
                    {e.actor}{" "}
                    {e.actor_kind !== "owner" && e.actor_kind !== "member" && (
                      <Badge tone={e.actor_kind === "staff" ? "warn" : "idle"}>
                        {e.actor_kind}
                      </Badge>
                    )}
                  </td>
                  <td>
                    <span className="font-medium">{e.summary}</span>
                    <p className="font-mono text-xs text-ink-3">{e.action}</p>
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
