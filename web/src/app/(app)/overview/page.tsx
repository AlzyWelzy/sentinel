"use client";

import Link from "next/link";

import { SeverityBadge, StatusBadge, STATUS_LABEL, STATUS_TONE } from "@/components/status";
import {
  Card,
  Dot,
  Empty,
  ErrorState,
  LinkButton,
  Loading,
  Meter,
  PageHeader,
  Table,
} from "@/components/ui";
import { errorText } from "@/lib/api/client";
import { ago, duration } from "@/lib/format";
import { useIncidents, useOverview } from "@/lib/queries";
import { orgName, useMe } from "@/lib/session";

const ORDER = ["critical", "down", "warning", "up", "maintenance", "paused"] as const;

function avg(values: (number | null | undefined)[]): number | null {
  const v = values.filter((x): x is number => typeof x === "number");
  return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
}

export default function OverviewPage() {
  const me = useMe();
  const overview = useOverview();
  const incidents = useIncidents("open");

  if (overview.isLoading) return <Loading />;
  if (overview.error)
    return <ErrorState message={errorText(overview.error)} retry={() => overview.refetch()} />;
  const o = overview.data!;
  const servers = o.servers;

  if (servers.length === 0) {
    return (
      <>
        <PageHeader title={me.data ? orgName(me.data) : "Overview"} />
        <Card>
          <Empty
            title="No servers yet"
            action={
              <LinkButton href="/welcome" variant="primary">
                Add your first server
              </LinkButton>
            }
          >
            Install the agent with one command. Your server shows up here within a minute.
          </Empty>
        </Card>
      </>
    );
  }

  const live = servers.filter((s) => s.online);
  const counts = o.counts as Record<string, number>;
  const open = incidents.data ?? [];

  return (
    <>
      <PageHeader
        title={me.data ? orgName(me.data) : "Overview"}
        subtitle={`${servers.length} servers · updated every 30 seconds`}
        actions={<LinkButton href="/welcome">Add server</LinkButton>}
      />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {ORDER.map((k) => (
          <Link
            key={k}
            href={`/servers?status=${k}`}
            className="rounded-xl border border-line bg-panel p-4 hover:border-brand/40"
          >
            <div className="flex items-center gap-2 text-xs font-medium text-ink-2">
              <Dot tone={STATUS_TONE[k] ?? "idle"} />
              {STATUS_LABEL[k]}
            </div>
            <div className="mt-2 text-2xl font-semibold tabular">{counts[k] ?? 0}</div>
          </Link>
        ))}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="Fleet averages" className="lg:col-span-1">
          <dl className="space-y-4 text-sm">
            {[
              ["CPU", avg(live.map((s) => s.cpu))],
              ["Memory", avg(live.map((s) => s.memory))],
              ["Fullest disk", avg(live.map((s) => s.disk))],
            ].map(([label, value]) => (
              <div key={label as string}>
                <dt className="mb-1.5 text-ink-2">{label}</dt>
                <dd>
                  <Meter value={value as number | null} />
                </dd>
              </div>
            ))}
            <div className="flex justify-between border-t border-line pt-3 text-ink-2">
              <span>Online</span>
              <span className="tabular text-ink">
                {live.length} / {servers.length}
              </span>
            </div>
          </dl>
        </Card>

        <Card
          title={`Active incidents (${open.length})`}
          className="lg:col-span-2"
          pad={false}
          actions={
            <Link href="/incidents" className="text-sm text-brand">
              All incidents
            </Link>
          }
        >
          {incidents.isLoading ? (
            <Loading />
          ) : open.length === 0 ? (
            <Empty title="All clear">Nothing is firing right now.</Empty>
          ) : (
            <Table>
              <tbody>
                {open.slice(0, 8).map((i) => (
                  <tr key={i.id}>
                    <td>
                      <SeverityBadge severity={i.severity} />
                    </td>
                    <td className="max-w-md">
                      <Link href={`/incidents/${i.id}`} className="font-medium hover:text-brand">
                        {i.summary}
                      </Link>
                      {i.detail && <p className="truncate text-xs text-ink-3">{i.detail}</p>}
                    </td>
                    <td className="text-ink-2">{i.hostname}</td>
                    <td className="text-right whitespace-nowrap text-ink-3">
                      {duration(i.duration_seconds)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      </div>

      <Card title="Servers needing attention" className="mt-6" pad={false}>
        <Table>
          <thead>
            <tr>
              <th>Server</th>
              <th>Status</th>
              <th>CPU</th>
              <th>Memory</th>
              <th>Disk</th>
              <th className="text-right">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {[...servers]
              .sort((a, b) => ORDER.indexOf(a.status as never) - ORDER.indexOf(b.status as never))
              .slice(0, 10)
              .map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link href={`/servers/${s.id}`} className="font-medium hover:text-brand">
                      {s.hostname}
                    </Link>
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
                  <td className="text-right text-ink-3">{ago(s.last_seen)}</td>
                </tr>
              ))}
          </tbody>
        </Table>
      </Card>
    </>
  );
}
