"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";

import { TimeChart } from "@/components/chart";
import { presetRange, RangePicker } from "@/components/range";
import {
  Badge,
  Button,
  Card,
  Dot,
  ErrorState,
  Field,
  Input,
  Loading,
  Meter,
  Notice,
  PageHeader,
  Select,
  Stat,
  Table,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { ago, dateTime, duration } from "@/lib/format";
import {
  bps,
  type Device,
  ROLES,
  speed,
  useCredentials,
  usePollers,
  useProfiles,
} from "@/lib/network";
import { unwrap } from "@/lib/queries";

function Traffic({ id, interfaces }: { id: string; interfaces: Device["interfaces"] }) {
  const [range, setRange] = useState(() => presetRange("6h"));
  const [ifname, setIfname] = useState("");
  const traffic = useQuery({
    queryKey: ["network", "traffic", id, ifname, range.key, range.start],
    refetchInterval: 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/network/devices/{device_id}/traffic", {
          params: {
            path: { device_id: id },
            query: { start: range.start, end: range.end, ifname: ifname || undefined },
          },
        }),
      ),
  });
  return (
    <Card
      title="Traffic"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Select
            aria-label="Interface"
            value={ifname}
            onChange={(e) => setIfname(e.target.value)}
            className="max-w-[14rem]"
          >
            <option value="">All interfaces</option>
            {interfaces.map((i) => (
              <option key={i.ifindex} value={i.name}>
                {i.name}
                {i.alias ? ` (${i.alias})` : ""}
              </option>
            ))}
          </Select>
          <RangePicker value={range} onChange={setRange} />
        </div>
      }
    >
      {traffic.isLoading ? (
        <Loading />
      ) : traffic.error ? (
        <p className="text-sm text-bad">{errorText(traffic.error)}</p>
      ) : traffic.data?.series.some((s) => (s.points as unknown[]).length) ? (
        <TimeChart
          series={traffic.data.series as never}
          unit="bits_per_second"
          range={{ start: range.start, end: range.end }}
          fallbackName="traffic"
        />
      ) : (
        <p className="py-10 text-center text-sm text-ink-3">No traffic data in this range yet.</p>
      )}
    </Card>
  );
}

function Proxmox({ id }: { id: string }) {
  const pve = useQuery({
    queryKey: ["network", "proxmox", id],
    refetchInterval: 60_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/network/devices/{device_id}/proxmox", {
          params: { path: { device_id: id } },
        }),
      ),
  });
  if (pve.isLoading) return <Loading />;
  if (pve.error) return <p className="text-sm text-bad">{errorText(pve.error)}</p>;
  const r = pve.data!;
  const pct = (used?: number | null, size?: number | null) =>
    used != null && size ? Math.round((1000 * used) / size) / 10 : null;
  const groups: { title: string; types: string[] }[] = [
    { title: "Nodes", types: ["node"] },
    { title: "Guests", types: ["qemu", "lxc"] },
    { title: "Storage", types: ["storage"] },
  ];
  return (
    <div className="space-y-6">
      {r.quorate === false && <Notice tone="bad">The cluster has lost quorum.</Notice>}
      {groups.map((g) => {
        const rows = r.resources.filter((x) => g.types.includes(x.type));
        if (!rows.length) return null;
        return (
          <Card key={g.title} title={`${g.title} · ${rows.length}`} pad={false}>
            <Table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Node</th>
                  {g.title !== "Storage" && <th>CPU</th>}
                  {g.title !== "Storage" && <th>Memory</th>}
                  <th>{g.title === "Storage" ? "Used" : "Disk"}</th>
                  {g.title !== "Storage" && <th>Uptime</th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((x) => {
                  const mem = pct(x.memory_used, x.memory_size);
                  const disk = pct(x.disk_used, x.disk_size);
                  return (
                    <tr key={`${x.type}-${x.node}-${x.vmid ?? x.name}`}>
                      <td>
                        <span className="inline-flex items-center gap-2">
                          <Dot tone={x.up ? "ok" : x.type === "node" ? "bad" : "idle"} />
                          <span className="font-medium">{x.name}</span>
                          {x.vmid != null && <span className="text-xs text-ink-3">{x.vmid}</span>}
                          {x.shared && <Badge>shared</Badge>}
                        </span>
                      </td>
                      <td className="text-ink-2">{x.node}</td>
                      {g.title !== "Storage" && (
                        <td className="tabular">{x.cpu_pct != null ? `${x.cpu_pct}%` : "—"}</td>
                      )}
                      {g.title !== "Storage" && (
                        <td className="min-w-[8rem]">
                          {mem != null ? <Meter value={mem} /> : "—"}
                        </td>
                      )}
                      <td className="min-w-[8rem]">
                        {disk != null ? <Meter value={disk} /> : "—"}
                      </td>
                      {g.title !== "Storage" && (
                        <td className="text-ink-2">
                          {x.uptime_seconds ? duration(x.uptime_seconds) : x.up ? "—" : "stopped"}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </Card>
        );
      })}
      {!r.resources.length && <p className="text-sm text-ink-3">Nothing polled yet.</p>}
    </div>
  );
}

function BillingTag({ id, ifindex, value }: { id: string; ifindex: number; value: string | null }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [tag, setTag] = useState(value ?? "");
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/v1/network/devices/{device_id}/interfaces/{ifindex}", {
          params: { path: { device_id: id, ifindex } },
          body: { billing_tag: tag },
        }),
      ),
    onSuccess: () => {
      setEditing(false);
      qc.invalidateQueries({ queryKey: ["network", "device", id] });
    },
  });
  if (!editing) {
    return (
      <button
        type="button"
        onClick={() => setEditing(true)}
        className="text-left text-xs text-ink-3 hover:text-brand"
        title="Group ports for 95th-percentile bandwidth"
      >
        {value ? <Badge tone="brand">{value}</Badge> : "+ tag"}
      </button>
    );
  }
  return (
    <form
      className="flex items-center gap-1"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate();
      }}
    >
      <Input
        aria-label="Billing tag"
        autoFocus
        value={tag}
        maxLength={100}
        onChange={(e) => setTag(e.target.value)}
        className="h-7 w-28 text-xs"
        placeholder="customer"
      />
      <Button type="submit" loading={save.isPending} className="h-7 px-2 text-xs">
        Save
      </Button>
    </form>
  );
}

function Settings({ d }: { d: Device }) {
  const qc = useQueryClient();
  const router = useRouter();
  const creds = useCredentials();
  const pollers = usePollers();
  const profiles = useProfiles();
  const h = d.host;
  const [name, setName] = useState(h.hostname);
  const [address, setAddress] = useState(h.address ?? "");
  const [credential, setCredential] = useState(d.credential_id ?? "");
  const [poller, setPoller] = useState(h.poller_host_id ?? "");
  const [role, setRole] = useState(h.network_role ?? "");
  const [profile, setProfile] = useState(d.profile_pinned ? (d.profile ?? "") : "");
  const [msg, setMsg] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/v1/network/devices/{device_id}", {
          params: { path: { device_id: h.id } },
          body: {
            name,
            address,
            credential_id: credential || null,
            poller_host_id: poller || null,
            profile,
            network_role: (role || null) as never,
            clear_role: !role,
          },
        }),
      ),
    onSuccess: () => {
      setMsg("Saved. The poller picks the change up within a minute.");
      qc.invalidateQueries({ queryKey: ["network", "device", h.id] });
      qc.invalidateQueries({ queryKey: ["hosts"] });
    },
  });
  const remove = useMutation({
    mutationFn: async () =>
      unwrap(await api.DELETE("/v1/hosts/{host_id}", { params: { path: { host_id: h.id } } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["hosts"] });
      router.replace("/network");
    },
  });
  return (
    <Card title="Settings">
      <form
        className="grid gap-4 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          setMsg(null);
          save.mutate();
        }}
      >
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} required maxLength={255} />
        </Field>
        <Field label="Address">
          <Input value={address} onChange={(e) => setAddress(e.target.value)} required />
        </Field>
        <Field label="Credential">
          <Select value={credential} onChange={(e) => setCredential(e.target.value)}>
            {creds.data?.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} (v{c.version})
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Polled by">
          <Select value={poller} onChange={(e) => setPoller(e.target.value)}>
            {pollers.data?.map((p) => (
              <option key={p.id} value={p.id}>
                {p.hostname}
                {p.online ? "" : " (not reporting)"}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Role" hint="Upstreams are worked out from LLDP toward devices marked core.">
          <Select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="">Not set</option>
            {ROLES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Profile">
          <Select value={profile} onChange={(e) => setProfile(e.target.value)}>
            <option value="">
              Detect{d.profile && !d.profile_pinned ? ` (now ${d.profile})` : ""}
            </option>
            {profiles.data?.map((p) => (
              <option key={p.name} value={p.name}>
                {p.vendor ? `${p.vendor}: ` : ""}
                {p.description || p.name}
              </option>
            ))}
          </Select>
        </Field>
        <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save
          </Button>
          <Button
            type="button"
            variant="danger"
            loading={remove.isPending}
            onClick={() => {
              if (window.confirm(`Remove ${h.hostname}? Its history goes too.`)) remove.mutate();
            }}
          >
            Remove device
          </Button>
          {(save.error || remove.error) && (
            <span className="text-sm text-bad">{errorText(save.error ?? remove.error)}</span>
          )}
          {msg && <span className="text-sm text-ok">{msg}</span>}
        </div>
      </form>
    </Card>
  );
}

export default function DevicePage() {
  const { id } = useParams<{ id: string }>();
  const [filter, setFilter] = useState<"all" | "up" | "down">("up");
  const device = useQuery({
    queryKey: ["network", "device", id],
    refetchInterval: 30_000,
    queryFn: async () =>
      unwrap(
        await api.GET("/v1/network/devices/{device_id}", { params: { path: { device_id: id } } }),
      ),
  });
  if (device.isLoading) return <Loading />;
  if (device.error)
    return <ErrorState message={errorText(device.error)} retry={() => device.refetch()} />;
  const d = device.data!;
  const h = d.host;
  const up = d.interfaces.filter((i) => i.oper_up).length;
  const downAdmin = d.interfaces.filter((i) => i.admin_up && i.oper_up === false).length;
  const busiest = Math.max(0, ...d.interfaces.map((i) => i.utilisation ?? 0));
  const errors = d.interfaces.filter((i) => (i.errors_per_sec ?? 0) > 0.01).length;
  const shown = d.interfaces.filter((i) =>
    filter === "all"
      ? true
      : filter === "up"
        ? i.oper_up || (i.in_bps ?? 0) > 0
        : i.admin_up && i.oper_up === false,
  );
  const status = h.paused
    ? { tone: "idle" as const, label: "Paused" }
    : !h.last_seen
      ? {
          tone: (h.device_error ? "bad" : "idle") as "bad" | "idle",
          label: h.device_error ? "No answer" : "Waiting for the first poll",
        }
      : h.online
        ? {
            tone: (h.device_error ? "warn" : "ok") as "warn" | "ok",
            label: h.device_error ? "Up, some tables failed" : "Up",
          }
        : { tone: "bad" as const, label: "Unreachable" };
  return (
    <>
      <PageHeader
        title={h.hostname}
        subtitle={
          <span className="inline-flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5">
              <Dot tone={status.tone} />
              {status.label}
            </span>
            <span className="font-mono">{h.address}</span>
            {h.vendor && <span>· {h.vendor}</span>}
            {d.profile && <span>· profile {d.profile}</span>}
            {h.network_role && <Badge>{h.network_role}</Badge>}
          </span>
        }
        actions={
          <Link href="/network" className="text-sm text-ink-2 hover:text-ink">
            ← All devices
          </Link>
        }
      />
      {h.device_error && (
        <div className="mb-6">
          <Notice tone={h.online ? "warn" : "bad"}>{h.device_error}</Notice>
        </div>
      )}
      {d.profile === "proxmox" ? (
        <div className="mb-6">
          <Proxmox id={id} />
        </div>
      ) : (
        <SNMPDetail
          d={d}
          id={id}
          filter={filter}
          setFilter={setFilter}
          shown={shown}
          up={up}
          downAdmin={downAdmin}
          busiest={busiest}
          errors={errors}
        />
      )}
      <Settings key={`${d.credential_id}-${h.poller_host_id}-${h.hostname}`} d={d} />
    </>
  );
}

function SNMPDetail({
  d,
  id,
  filter,
  setFilter,
  shown,
  up,
  downAdmin,
  busiest,
  errors,
}: {
  d: Device;
  id: string;
  filter: "all" | "up" | "down";
  setFilter: (f: "all" | "up" | "down") => void;
  shown: Device["interfaces"];
  up: number;
  downAdmin: number;
  busiest: number;
  errors: number;
}) {
  return (
    <>
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Interfaces up" value={`${up} / ${d.interfaces.length}`} />
        <Stat label="Down (enabled)" value={String(downAdmin)} />
        <Stat label="Busiest port" value={`${busiest.toFixed(1)}%`} />
        <Stat
          label="Uptime"
          value={d.system.uptime_sec ? duration(Number(d.system.uptime_sec)) : "—"}
        />
      </div>
      <div className="mb-6">
        <Traffic id={id} interfaces={d.interfaces} />
      </div>
      <div className="mb-6">
        <Card
          pad={false}
          title={`Interfaces${errors ? ` · ${errors} with errors` : ""}`}
          actions={
            <Select
              aria-label="Show interfaces"
              value={filter}
              onChange={(e) => setFilter(e.target.value as typeof filter)}
              className="max-w-[12rem]"
            >
              <option value="up">Up or carrying traffic</option>
              <option value="down">Down while enabled</option>
              <option value="all">All</option>
            </Select>
          }
        >
          <Table>
            <thead>
              <tr>
                <th>Interface</th>
                <th>Speed</th>
                <th>In</th>
                <th>Out</th>
                <th>Utilisation</th>
                <th>Errors/s</th>
                <th>Neighbour</th>
                <th>Billing</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((i) => (
                <tr key={i.ifindex}>
                  <td>
                    <span className="inline-flex items-center gap-2">
                      <Dot tone={i.oper_up ? "ok" : i.admin_up ? "bad" : "idle"} />
                      <span className="font-medium">{i.name}</span>
                    </span>
                    {(i.alias || i.descr) && (
                      <p className="max-w-[16rem] truncate text-xs text-ink-3">
                        {i.alias || i.descr}
                      </p>
                    )}
                  </td>
                  <td className="tabular text-ink-2">{speed(i.speed_bps)}</td>
                  <td className="tabular">{bps(i.in_bps)}</td>
                  <td className="tabular">{bps(i.out_bps)}</td>
                  <td className="min-w-[8rem]">
                    {i.utilisation != null ? (
                      <Meter value={i.utilisation} />
                    ) : (
                      <span className="text-ink-3">—</span>
                    )}
                  </td>
                  <td
                    className={`tabular ${(i.errors_per_sec ?? 0) > 0.01 ? "text-bad" : "text-ink-3"}`}
                  >
                    {i.errors_per_sec != null ? i.errors_per_sec.toFixed(2) : "—"}
                  </td>
                  <td className="max-w-[12rem] truncate">
                    {i.neighbor_host_id ? (
                      <Link
                        className="text-brand hover:underline"
                        href={`/network/${i.neighbor_host_id}`}
                      >
                        {i.neighbor}
                      </Link>
                    ) : (
                      <span className="text-ink-2">{i.neighbor ?? ""}</span>
                    )}
                  </td>
                  <td>
                    <BillingTag id={id} ifindex={i.ifindex} value={i.billing_tag} />
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
          {!shown.length && (
            <p className="p-5 text-sm text-ink-3">
              {d.interfaces.length
                ? "None in this view."
                : "Interfaces appear after the first full poll."}
            </p>
          )}
        </Card>
      </div>
      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card title="System">
          <dl className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-2 text-sm">
            {[
              ["Description", d.system.descr],
              ["Name (sysName)", d.system.name],
              ["Location", d.system.location],
              ["Contact", d.system.contact],
              ["Object ID", d.system.object_id],
              ...Object.entries(d.inventory).map(([k, v]) => [k.replaceAll("_", " "), v]),
              ["Polled by", d.poller_hostname],
              ["Credential", d.credential_name],
              [
                "Last poll",
                d.polled_at ? `${ago(d.polled_at)} (${dateTime(d.polled_at)})` : "never",
              ],
              [
                "Poll took",
                d.poll_duration_ms != null ? `${(d.poll_duration_ms / 1000).toFixed(1)} s` : null,
              ],
            ]
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <div key={String(k)} className="contents">
                  <dt className="text-ink-3 capitalize">{String(k)}</dt>
                  <dd className="[overflow-wrap:anywhere] text-ink">{String(v)}</dd>
                </div>
              ))}
          </dl>
        </Card>
        <Card title={`Neighbours (LLDP) · ${d.links.length}`} pad={false}>
          {d.links.length ? (
            <Table>
              <thead>
                <tr>
                  <th>Local port</th>
                  <th>Neighbour</th>
                  <th>Their port</th>
                </tr>
              </thead>
              <tbody>
                {d.links.map((l) => (
                  <tr key={`${l.local_port}-${l.remote_port_id}-${l.remote_sys_name}`}>
                    <td className="font-medium">{l.local_port}</td>
                    <td className="max-w-[14rem] truncate">
                      {l.remote_host_id ? (
                        <Link
                          className="text-brand hover:underline"
                          href={`/network/${l.remote_host_id}`}
                        >
                          {l.remote_hostname ?? l.remote_sys_name}
                        </Link>
                      ) : (
                        <span>{l.remote_sys_name || l.remote_mgmt_addr || "unknown"}</span>
                      )}
                    </td>
                    <td className="text-ink-2">{l.remote_port_desc || l.remote_port_id}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="p-5 text-sm text-ink-3">
              No LLDP neighbours reported. Turn LLDP on to map the network and work out upstreams.
            </p>
          )}
        </Card>
      </div>
    </>
  );
}
