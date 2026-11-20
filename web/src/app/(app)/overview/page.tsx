"use client";

import Link from "next/link";

import { SeverityBadge, StatusBadge, STATUS_LABEL, STATUS_TONE } from "@/components/status";
import {
  Breaker,
  Card,
  cx,
  Empty,
  ErrorState,
  LinkButton,
  Loading,
  Meter,
  Stat,
  PageHeader,
  Table,
} from "@/components/ui";
import { errorText } from "@/lib/api/client";
import { ago, duration } from "@/lib/format";
import { useIncidents, useOverview } from "@/lib/queries";
import { orgName, useMe } from "@/lib/session";

const ORDER = ["critical", "down", "warning", "up", "maintenance", "paused"] as const;
const PANEL_MAX = 40;

function breakerState(status: string): "on" | "tripped" | "off" | "warn" {
  if (status === "critical" || status === "down") return "tripped";
  if (status === "warning") return "warn";
  if (status === "paused" || status === "maintenance" || status === "unknown") return "off";
  return "on";
}

type Row = {
  online: boolean;
  last_seen?: number | null;
  cpu?: number | null;
  memory?: number | null;
  disk?: number | null;
};

/** The directory card's typed line when no incident names the problem. */
function fallbackReason(s: Row): string {
  if (!s.online)
    return s.last_seen ? `No data since ${ago(s.last_seen)}` : "Waiting for first data";
  const part = (label: string, v?: number | null) =>
    v == null ? null : `${label} ${v.toFixed(0)}%`;
  return [part("cpu", s.cpu), part("mem", s.memory), part("disk", s.disk)]
    .filter(Boolean)
    .join(" · ");
}

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
  // Circuit numbers follow the fleet's own order so a server keeps its number;
  // the panel then lists tripped circuits first.
  const numbered = [...servers]
    .sort((a, b) => a.hostname.localeCompare(b.hostname))
    .map((s, i) => ({ s, n: i + 1 }));
  const panel = numbered.sort(
    (a, b) => ORDER.indexOf(a.s.status as never) - ORDER.indexOf(b.s.status as never),
  );
  const reasons = new Map<string, string>();
  for (const i of open) if (!reasons.has(i.hostname)) reasons.set(i.hostname, i.summary);

  return (
    <>
      <PageHeader
        title={me.data ? orgName(me.data) : "Overview"}
        subtitle={`${servers.length} ${servers.length === 1 ? "server" : "servers"} · updated every 30 seconds`}
        actions={<LinkButton href="/welcome">Add server</LinkButton>}
      />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {ORDER.map((k) => (
          <Stat
            key={k}
            href={`/servers?status=${k}`}
            tone={STATUS_TONE[k] ?? "idle"}
            label={STATUS_LABEL[k]}
            value={counts[k] ?? 0}
          />
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
                    <td className="text-ink-2">
                      <span title={i.hostname} className="block max-w-[18rem] truncate">
                        {i.hostname}
                      </span>
                    </td>
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

      <Card
        title={`Panel · ${servers.length} ${servers.length === 1 ? "circuit" : "circuits"}`}
        className="mt-6"
        pad={false}
        actions={
          <Link href="/servers" className="text-sm text-brand hover:underline">
            All servers
          </Link>
        }
      >
        <ol className="grid md:grid-cols-2">
          {panel.slice(0, PANEL_MAX).map(({ s, n }) => {
            const state = breakerState(s.status);
            const reason = reasons.get(s.hostname) ?? fallbackReason(s);
            return (
              <li
                key={s.id}
                className={cx(
                  "flex min-w-0 items-center gap-3 border-b border-line px-4 py-2.5 md:odd:border-r",
                  state === "tripped" && "bg-bad/[0.07]",
                )}
              >
                <span className="w-7 shrink-0 text-right font-mono text-xs text-ink-3 tabular">
                  {String(n).padStart(2, "0")}
                </span>
                <Breaker state={state} />
                <div className="min-w-0 flex-1">
                  <Link
                    href={s.kind === "network" ? `/network/${s.id}` : `/servers/${s.id}`}
                    title={s.hostname}
                    className="block truncate font-medium hover:text-brand"
                  >
                    {s.hostname}
                  </Link>
                  <p
                    className={cx(
                      "truncate font-mono text-xs",
                      state === "tripped"
                        ? "text-bad"
                        : state === "warn"
                          ? "text-warn"
                          : "text-ink-3",
                    )}
                    title={reason}
                  >
                    {reason}
                  </p>
                </div>
                <StatusBadge status={s.status} />
              </li>
            );
          })}
        </ol>
        {panel.length > PANEL_MAX && (
          <p className="px-4 py-3 text-sm text-ink-2">
            Showing the {PANEL_MAX} that need you most.{" "}
            <Link href="/servers" className="text-brand hover:underline">
              See all {panel.length}
            </Link>
          </p>
        )}
      </Card>
    </>
  );
}
