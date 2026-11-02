"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { presetRange, RangePicker } from "@/components/range";
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  Input,
  Loading,
  PageHeader,
  Select,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import type { Range } from "@/lib/format";
import { unwrap, useHosts } from "@/lib/queries";

const LEVELS = ["error", "warning", "info", "debug"];

export default function LogsPage() {
  const hosts = useHosts();
  const [range, setRange] = useState<Range>(() => presetRange("1h"));
  const [q, setQ] = useState("");
  const [search, setSearch] = useState("");
  const [host, setHost] = useState("");
  const [level, setLevel] = useState("");
  const logs = useQuery({
    queryKey: ["logs", search, host, level, range.start, range.end],
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/logs", {
          params: {
            query: {
              q: search || undefined,
              host_id: host || undefined,
              level: level ? [level] : undefined,
              start: range.start,
              end: range.end,
            },
          },
        }),
      ),
  });
  return (
    <>
      <PageHeader
        title="Logs"
        subtitle="Search what the agents collect from /var/log, Docker and the Windows Event Log."
      />
      <form
        className="mb-4 flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setSearch(q);
        }}
      >
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search words, e.g. timeout OR refused"
          className="max-w-md"
        />
        <Select value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">Every server</option>
          {hosts.data?.map((h) => (
            <option key={h.id} value={h.id}>
              {h.hostname}
            </option>
          ))}
        </Select>
        <Select value={level} onChange={(e) => setLevel(e.target.value)}>
          <option value="">Any level</option>
          {LEVELS.map((l) => (
            <option key={l}>{l}</option>
          ))}
        </Select>
        <RangePicker value={range} onChange={setRange} />
      </form>
      <Card pad={false}>
        {logs.isLoading ? (
          <Loading />
        ) : logs.error ? (
          <ErrorState message={errorText(logs.error)} retry={() => logs.refetch()} />
        ) : !logs.data?.enabled ? (
          <Empty title="Log search is off">
            This installation has no log store configured (VICTORIALOGS_URL).
          </Empty>
        ) : !logs.data.lines.length ? (
          <Empty title="No matching lines in this range" />
        ) : (
          <div className="max-h-[70vh] overflow-auto font-mono text-xs">
            {logs.data.lines.map((l, i) => (
              <div
                key={`${l.ts}-${i}`}
                className="flex gap-3 border-b border-line px-4 py-1.5 hover:bg-panel-2/60"
              >
                <span className="shrink-0 text-ink-3">{new Date(l.ts / 1e6).toLocaleString()}</span>
                <span className="w-24 shrink-0 truncate text-ink-2">{l.hostname}</span>
                {l.level && (
                  <Badge
                    tone={l.level === "error" ? "bad" : l.level === "warning" ? "warn" : "idle"}
                  >
                    {l.level}
                  </Badge>
                )}
                <span className="break-all whitespace-pre-wrap">{l.line}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}
