"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useMemo, useState } from "react";

import { NetworkTabs } from "@/components/network-tabs";
import {
  Badge,
  Button,
  Card,
  Dot,
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
import { ago } from "@/lib/format";
import { ROLES, useCredentials, usePollers, useProfiles } from "@/lib/network";
import { type Host, unwrap, useHosts } from "@/lib/queries";

function deviceStatus(h: Host): { tone: "ok" | "bad" | "warn" | "idle"; label: string } {
  if (h.paused) return { tone: "idle", label: "Paused" };
  if (h.in_maintenance) return { tone: "idle", label: "Maintenance" };
  if (!h.last_seen)
    return {
      tone: h.device_error ? "bad" : "idle",
      label: h.device_error ? "No answer" : "Waiting",
    };
  if (!h.online) return { tone: "bad", label: "Unreachable" };
  if (h.device_error) return { tone: "warn", label: "Partial" };
  return { tone: "ok", label: "Up" };
}

function AddDevices({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const creds = useCredentials();
  const pollers = usePollers();
  const profiles = useProfiles();
  const [addresses, setAddresses] = useState("");
  const [credential, setCredential] = useState("");
  const [poller, setPoller] = useState("");
  const [role, setRole] = useState("");
  const [profile, setProfile] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const list = addresses
    .split(/[\s,;]+/)
    .map((a) => a.trim())
    .filter(Boolean);
  const add = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/network/devices", {
          body: {
            addresses: list,
            credential_id: credential || creds.data?.[0]?.id || "",
            poller_host_id: poller || pollers.data?.find((p) => p.online)?.id || "",
            network_role: (role || null) as never,
            profile: profile || null,
            tags: [],
          },
        }),
      ),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["hosts"] });
      qc.invalidateQueries({ queryKey: ["overview"] });
      setAddresses("");
      setResult(
        `Added ${r.created.length}.` +
          (r.skipped.length ? ` Already polled by that server: ${r.skipped.join(", ")}.` : "") +
          " The first poll takes up to a minute.",
      );
    },
  });
  if (creds.isLoading || pollers.isLoading) return <Loading />;
  if (!creds.data?.length) {
    return (
      <Notice tone="warn">
        Add an SNMP credential first (a community, or an SNMPv3 user):{" "}
        <Link className="font-medium underline" href="/network/credentials">
          Credentials
        </Link>
        .
      </Notice>
    );
  }
  if (!pollers.data?.length) {
    return (
      <Notice tone="warn">
        Devices are polled by one of your servers on the same network. Install the agent on one
        first:{" "}
        <Link className="font-medium underline" href="/welcome">
          Add server
        </Link>
        .
      </Notice>
    );
  }
  return (
    <form
      className="grid gap-4 md:grid-cols-2"
      onSubmit={(e) => {
        e.preventDefault();
        setResult(null);
        add.mutate();
      }}
    >
      <div className="md:col-span-2">
        <Field
          label="Addresses"
          hint="IP addresses or hostnames, one per line or separated by commas; add :port for a port other than 161. Up to 256 at once."
        >
          <textarea
            required
            rows={4}
            value={addresses}
            onChange={(e) => setAddresses(e.target.value)}
            placeholder={"10.0.10.11\n10.0.10.12\ncore1.example.net"}
            className="w-full rounded-[10px] border border-line bg-panel px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-3 focus:border-brand focus:ring-4 focus:ring-brand/15 focus:outline-none"
          />
        </Field>
      </div>
      <Field label="Credential">
        <Select value={credential} onChange={(e) => setCredential(e.target.value)}>
          {creds.data.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} (v{c.version})
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Polled by" hint="A server that can reach these devices over SNMP (UDP 161).">
        <Select value={poller} onChange={(e) => setPoller(e.target.value)}>
          {pollers.data.map((p) => (
            <option key={p.id} value={p.id}>
              {p.hostname}
              {p.online ? "" : " (not reporting)"}
            </option>
          ))}
        </Select>
      </Field>
      <Field
        label="Role"
        hint="Mark your core switches: devices' upstreams are worked out from LLDP toward them."
      >
        <Select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="">Not set</option>
          {ROLES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </Select>
      </Field>
      <Field
        label="Profile"
        hint="Detected from the device; pin one only if detection picks the wrong one."
      >
        <Select value={profile} onChange={(e) => setProfile(e.target.value)}>
          <option value="">Detect</option>
          {profiles.data?.map((p) => (
            <option key={p.name} value={p.name}>
              {p.vendor ? `${p.vendor}: ` : ""}
              {p.description || p.name}
            </option>
          ))}
        </Select>
      </Field>
      <div className="flex flex-wrap items-center gap-3 md:col-span-2">
        <Button type="submit" variant="primary" loading={add.isPending} disabled={!list.length}>
          Add {list.length > 1 ? `${list.length} devices` : "device"}
        </Button>
        <Button type="button" onClick={onDone}>
          Close
        </Button>
        {add.error && <span className="text-sm text-bad">{errorText(add.error)}</span>}
        {result && <span className="text-sm text-ok">{result}</span>}
      </div>
    </form>
  );
}

export default function NetworkPage() {
  const hosts = useHosts();
  const [adding, setAdding] = useState(false);
  const [q, setQ] = useState("");
  const all = useMemo(() => (hosts.data ?? []).filter((h) => h.kind === "network"), [hosts.data]);
  const byId = useMemo(() => new Map((hosts.data ?? []).map((h) => [h.id, h])), [hosts.data]);
  if (hosts.isLoading) return <Loading />;
  if (hosts.error)
    return <ErrorState message={errorText(hosts.error)} retry={() => hosts.refetch()} />;
  const rows = all.filter((h) =>
    [h.hostname, h.address, h.vendor, h.network_role, ...h.tags]
      .join(" ")
      .toLowerCase()
      .includes(q.toLowerCase()),
  );
  const down = all.filter((h) => deviceStatus(h).tone === "bad").length;
  return (
    <>
      <PageHeader
        title="Network"
        subtitle={
          all.length
            ? `${all.length} device${all.length === 1 ? "" : "s"}${down ? `, ${down} unreachable` : ""}`
            : "Switches, firewalls and routers, polled over SNMP by your servers"
        }
        actions={
          !adding && (
            <Button variant="primary" onClick={() => setAdding(true)}>
              Add devices
            </Button>
          )
        }
      />
      <NetworkTabs />
      {adding && (
        <div className="mb-6">
          <Card title="Add devices">
            <AddDevices onDone={() => setAdding(false)} />
          </Card>
        </div>
      )}
      {!all.length && !adding ? (
        <Empty
          title="No network devices yet"
          action={
            <Button variant="primary" onClick={() => setAdding(true)}>
              Add devices
            </Button>
          }
        >
          Add a switch or firewall by its IP address. One of your servers polls it over SNMP:
          interfaces, traffic, errors, sensors, VPNs and neighbours, with alerts when something
          breaks.
        </Empty>
      ) : (
        <Card pad={false}>
          <div className="border-b border-line p-3">
            <Input
              placeholder="Search name, address, vendor, role or tag…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              className="max-w-sm"
            />
          </div>
          <Table>
            <thead>
              <tr>
                <th>Device</th>
                <th>Status</th>
                <th>Vendor</th>
                <th>Role</th>
                <th>Polled by</th>
                <th>Last answer</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((h) => {
                const s = deviceStatus(h);
                return (
                  <tr key={h.id}>
                    <td>
                      <Link
                        href={`/network/${h.id}`}
                        className="block max-w-[18rem] truncate font-medium text-ink hover:text-brand"
                      >
                        {h.hostname}
                      </Link>
                      <span className="font-mono text-xs text-ink-3">{h.address}</span>
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-2">
                        <Dot tone={s.tone} />
                        {s.label}
                      </span>
                      {h.device_error && s.tone !== "ok" && (
                        <p
                          className="max-w-[22rem] truncate text-xs text-ink-3"
                          title={h.device_error}
                        >
                          {h.device_error}
                        </p>
                      )}
                    </td>
                    <td className="text-ink-2">{h.vendor ?? "—"}</td>
                    <td>
                      {h.network_role ? (
                        <Badge>{h.network_role}</Badge>
                      ) : (
                        <span className="text-ink-3">—</span>
                      )}
                    </td>
                    <td className="max-w-[12rem] truncate text-ink-2">
                      {(h.poller_host_id && byId.get(h.poller_host_id)?.hostname) ?? "—"}
                    </td>
                    <td className="text-ink-2">{h.last_seen ? ago(h.last_seen) : "never"}</td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
          {!rows.length && <p className="p-5 text-sm text-ink-3">Nothing matches.</p>}
        </Card>
      )}
    </>
  );
}
