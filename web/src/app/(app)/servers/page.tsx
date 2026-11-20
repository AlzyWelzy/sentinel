"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useMemo } from "react";

import { SavedViews } from "@/components/saved-views";
import { StatusBadge, STATUS_LABEL } from "@/components/status";
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  Input,
  LinkButton,
  Loading,
  Meter,
  PageHeader,
  Select,
  Table,
} from "@/components/ui";
import { errorText } from "@/lib/api/client";
import { ago } from "@/lib/format";
import { useHosts, useOverview } from "@/lib/queries";

function Servers() {
  const router = useRouter();
  const params = useSearchParams();
  const q = params.get("q") ?? "";
  const status = params.get("status") ?? "";
  const tag = params.get("tag") ?? "";
  const overview = useOverview();
  const hosts = useHosts();

  const tags = useMemo(
    () => Array.from(new Set((hosts.data ?? []).flatMap((h) => h.tags))).sort(),
    [hosts.data],
  );
  const byId = useMemo(() => new Map((hosts.data ?? []).map((h) => [h.id, h])), [hosts.data]);

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    router.replace(`/servers?${next}`);
  }

  if (overview.isLoading || hosts.isLoading) return <Loading />;
  const err = overview.error ?? hosts.error;
  if (err) return <ErrorState message={errorText(err)} retry={() => overview.refetch()} />;

  // Network devices have their own section.
  const servers = overview.data!.servers.filter((s) => byId.get(s.id)?.kind !== "network");
  const rows = servers.filter((s) => {
    const h = byId.get(s.id);
    if (status && s.status !== status) return false;
    if (tag && !h?.tags.includes(tag)) return false;
    if (q) {
      const hay = [
        s.hostname,
        h?.platform,
        ...(h?.ip_addresses ?? []),
        h?.public_ip,
        ...(h?.tags ?? []),
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q.toLowerCase())) return false;
    }
    return true;
  });

  return (
    <>
      <PageHeader
        title="Servers"
        subtitle={`${servers.length} in this organisation`}
        actions={
          <LinkButton href="/welcome" variant="primary">
            Add server
          </LinkButton>
        }
      />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search hostname, IP, tag…"
          key={q}
          defaultValue={q}
          onChange={(e) => set("q", e.target.value)}
          className="max-w-xs"
        />
        <Select aria-label="Status" value={status} onChange={(e) => set("status", e.target.value)}>
          <option value="">Any status</option>
          {Object.entries(STATUS_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </Select>
        {tags.length > 0 && (
          <Select aria-label="Tag" value={tag} onChange={(e) => set("tag", e.target.value)}>
            <option value="">Any tag</option>
            {tags.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </Select>
        )}
        <SavedViews
          kind="servers"
          params={Object.fromEntries(params.entries())}
          onApply={(v) => router.replace(`/servers?${new URLSearchParams(v)}`)}
        />
      </div>
      <Card pad={false}>
        {rows.length === 0 ? (
          <Empty title="No servers match">Change the search or filters.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Server</th>
                <th>Status</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Disk</th>
                <th>Load</th>
                <th>Tags</th>
                <th className="text-right">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => {
                const h = byId.get(s.id);
                return (
                  <tr key={s.id} className="hover:bg-panel-2/50">
                    <td>
                      <Link
                        href={`/servers/${s.id}`}
                        title={s.hostname}
                        className="block max-w-[18rem] truncate font-medium hover:text-brand"
                      >
                        {s.hostname}
                      </Link>
                      <p className="max-w-[18rem] truncate text-xs text-ink-3">
                        {[h?.platform, h?.platform_version].filter(Boolean).join(" ") || h?.os}
                        {h?.ip_addresses?.[0] ? ` · ${h.ip_addresses[0]}` : ""}
                      </p>
                    </td>
                    <td>
                      <StatusBadge status={s.status} />
                    </td>
                    <td>
                      <Meter value={s.cpu} />
                    </td>
                    <td>
                      <Meter value={s.memory} />
                    </td>
                    <td>
                      <Meter value={s.disk} />
                    </td>
                    <td className="tabular text-ink-2">{s.load1?.toFixed(2) ?? "—"}</td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {h?.tags.map((t) => (
                          <Badge key={t}>{t}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="text-right whitespace-nowrap text-ink-3">{ago(s.last_seen)}</td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}

export default function ServersPage() {
  return (
    <Suspense>
      <Servers />
    </Suspense>
  );
}
