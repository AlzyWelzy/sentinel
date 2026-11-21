"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  cx,
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
import type { components } from "@/lib/api/schema";
import { dateTime } from "@/lib/format";
import { unwrap, useHosts } from "@/lib/queries";
import { useMe } from "@/lib/session";

type Kind = components["schemas"]["SearchIn"]["kind"];
type Settings = components["schemas"]["SettingsOut"];

const KINDS: { value: Kind; label: string; fields: string[] }[] = [
  {
    value: "sessions",
    label: "Firewall sessions (with NAT)",
    fields: ["ip", "port", "user", "mac"],
  },
  { value: "flows", label: "Flows (sFlow, NetFlow, IPFIX)", fields: ["ip", "port", "mac"] },
  { value: "identity", label: "Who had an IP (VPN, logins)", fields: ["ip", "user"] },
  { value: "mac", label: "MAC and ARP tables", fields: ["ip", "mac"] },
  { value: "syslog", label: "Syslog", fields: ["ip", "text"] },
];
const SEARCH_ROLES = ["owner", "admin", "investigator"];
const AUDIT_ROLES = ["owner", "admin", "auditor"];
const APPROVERS = ["owner", "admin"];
type Tab = "search" | "sources" | "exports" | "audit" | "settings";

const local = (d: Date) =>
  new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);

export default function IPDRPage() {
  const me = useMe();
  const role = me.data?.role ?? "";
  const settings = useQuery({
    queryKey: ["ipdr-settings"],
    queryFn: async () => unwrap(await api.GET("/v1/ipdr/settings")),
  });
  const tabs: [Tab, string, boolean][] = [
    ["search", "Search", SEARCH_ROLES.includes(role)],
    ["sources", "Sources", true],
    ["exports", "Exports", SEARCH_ROLES.includes(role) || AUDIT_ROLES.includes(role)],
    ["audit", "Audit and seals", AUDIT_ROLES.includes(role)],
    ["settings", "Settings", true],
  ];
  const visible = tabs.filter(([, , ok]) => ok);
  const [tab, setTab] = useState<Tab | null>(null);
  const current = tab ?? (settings.data?.enabled ? visible[0]?.[0] : "settings") ?? "settings";

  return (
    <>
      <PageHeader
        title="IPDR"
        subtitle="Who used an IP address, when, and what it talked to: firewall sessions with NAT, flows, VPN and login identities, MAC/ARP tables and syslog from your own network, kept as evidence."
      />
      <div className="mb-5 flex flex-wrap gap-1 border-b border-line" role="tablist">
        {visible.map(([k, label]) => (
          <button
            key={k}
            role="tab"
            aria-selected={current === k}
            onClick={() => setTab(k)}
            className={cx(
              "-mb-px border-b-2 px-3 py-2 text-[13px] font-medium",
              current === k
                ? "border-brand text-ink"
                : "border-transparent text-ink-3 hover:text-ink",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      {settings.isLoading ? (
        <Loading />
      ) : settings.error ? (
        <ErrorState message={errorText(settings.error)} />
      ) : !settings.data ? null : !settings.data.enabled && current !== "settings" ? (
        <Empty title="IPDR is off">An owner or admin turns it on under Settings.</Empty>
      ) : current === "search" ? (
        <Search />
      ) : current === "sources" ? (
        <Sources />
      ) : current === "exports" ? (
        <Exports role={role} />
      ) : current === "audit" ? (
        <Audit />
      ) : (
        <SettingsTab s={settings.data} canEdit={APPROVERS.includes(role)} />
      )}
    </>
  );
}

function Search() {
  const qc = useQueryClient();
  const [kind, setKind] = useState<Kind>("sessions");
  const [f, setF] = useState<Record<string, string>>({});
  const [start, setStart] = useState(() => local(new Date(Date.now() - 86400000)));
  const [end, setEnd] = useState(() => local(new Date(Date.now() + 60000)));
  const [reason, setReason] = useState("");
  const [page, setPage] = useState(0);
  const [msg, setMsg] = useState<string | null>(null);
  const fields = KINDS.find((k) => k.value === kind)?.fields ?? [];
  const body = () => ({
    kind,
    reason,
    start: new Date(start).toISOString(),
    end: new Date(end).toISOString(),
    ip: fields.includes("ip") && f.ip ? f.ip : null,
    port: fields.includes("port") && f.port ? Number(f.port) : null,
    user: fields.includes("user") && f.user ? f.user : null,
    mac: fields.includes("mac") && f.mac ? f.mac : null,
    text: fields.includes("text") && f.text ? f.text : null,
  });
  const search = useMutation({
    mutationFn: async (offset: number) =>
      unwrap(await api.POST("/v1/ipdr/search", { body: { ...body(), limit: 200, offset } })),
    onError: (e) => setMsg(errorText(e)),
    onSuccess: () => setMsg(null),
  });
  const history = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/ipdr/ip-history", {
          body: { ip: f.ip ?? "", reason, start: body().start, end: body().end },
        }),
      ),
    onError: (e) => setMsg(errorText(e)),
  });
  const exp = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/ipdr/exports", { body: body() })),
    onSuccess: (x) => {
      setMsg(
        x.status === "pending"
          ? `${x.row_count.toLocaleString()} rows: waiting for an owner or admin to approve (Exports).`
          : `Export ready (${x.row_count.toLocaleString()} rows) under Exports.`,
      );
      qc.invalidateQueries({ queryKey: ["ipdr-exports"] });
    },
    onError: (e) => setMsg(errorText(e)),
  });
  const rows = search.data?.rows ?? [];
  const cols = rows[0] ? Object.keys(rows[0]).filter((c) => c !== "raw") : [];
  return (
    <div className="space-y-5">
      <Card>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            setPage(0);
            search.mutate(0);
          }}
        >
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="Look in">
              <Select
                value={kind}
                onChange={(e) => setKind(e.target.value as Kind)}
                className="w-full"
              >
                {KINDS.map((k) => (
                  <option key={k.value} value={k.value}>
                    {k.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="From">
              <Input
                type="datetime-local"
                value={start}
                onChange={(e) => setStart(e.target.value)}
              />
            </Field>
            <Field label="To">
              <Input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
            </Field>
          </div>
          <div className="grid gap-3 sm:grid-cols-4">
            {fields.map((k) => (
              <Field
                key={k}
                label={
                  { ip: "IP address", port: "Port", user: "User", mac: "MAC", text: "Text" }[k] ?? k
                }
              >
                <Input
                  value={f[k] ?? ""}
                  onChange={(e) => setF({ ...f, [k]: e.target.value })}
                  inputMode={k === "port" ? "numeric" : undefined}
                  spellCheck={false}
                  autoCapitalize="off"
                />
              </Field>
            ))}
          </div>
          <Field
            label="Reason"
            hint="Recorded in the audit log with the search, before any data is shown"
          >
            <Input
              required
              minLength={5}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Case 2026-114: abuse report from upstream"
            />
          </Field>
          {msg && <Notice tone="warn">{msg}</Notice>}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant="primary" loading={search.isPending}>
              Search
            </Button>
            <Button
              type="button"
              disabled={!f.ip || reason.length < 5}
              loading={history.isPending}
              onClick={() => history.mutate()}
            >
              IP history
            </Button>
            <Button
              type="button"
              disabled={reason.length < 5}
              loading={exp.isPending}
              onClick={() => exp.mutate()}
            >
              Export all matches
            </Button>
          </div>
        </form>
      </Card>
      {history.data && (
        <Card title={`History of ${f.ip}`} pad={false}>
          <Table>
            <thead>
              <tr>
                <th>Day</th>
                <th>Seen as</th>
                <th>First</th>
                <th>Last</th>
                <th>Events</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              {history.data.rows.map((r, i) => (
                <tr key={i}>
                  <td>{String(r.day)}</td>
                  <td>{String(r.role)}</td>
                  <td className="text-xs">{String(r.first_seen)}</td>
                  <td className="text-xs">{String(r.last_seen)}</td>
                  <td className="tabular-nums">{Number(r.events).toLocaleString()}</td>
                  <td className="tabular-nums">{Number(r.bytes).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
      {search.data && (
        <Card
          title={`${search.data.total.toLocaleString()} matches`}
          actions={
            <span className="font-mono text-[11px] text-ink-3" title="This search's audit entry">
              audit {search.data.audit_hash.slice(0, 12)}
            </span>
          }
          pad={false}
        >
          {rows.length === 0 ? (
            <Empty title="Nothing matches" />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <thead>
                  <tr>
                    {cols.map((c) => (
                      <th key={c} className="whitespace-nowrap">
                        {c.replaceAll("_", " ")}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={i} title={typeof r.raw === "string" ? r.raw : undefined}>
                      {cols.map((c) => (
                        <td key={c} className="whitespace-nowrap font-mono text-xs">
                          {String(r[c] ?? "").replace(/^::ffff:/, "")}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}
          {search.data.total > 200 && (
            <div className="flex items-center gap-2 border-t border-line p-3 text-[13px]">
              <Button
                disabled={page === 0}
                onClick={() => {
                  setPage(page - 1);
                  search.mutate((page - 1) * 200);
                }}
              >
                Newer
              </Button>
              <Button
                disabled={(page + 1) * 200 >= search.data.total}
                onClick={() => {
                  setPage(page + 1);
                  search.mutate((page + 1) * 200);
                }}
              >
                Older
              </Button>
              <span className="text-ink-3">
                Page {page + 1} · each page is its own audited search
              </span>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function Sources() {
  const q = useQuery({
    queryKey: ["ipdr-sources"],
    refetchInterval: 60_000,
    queryFn: async () => unwrap(await api.GET("/v1/ipdr/sources")),
  });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState message={errorText(q.error)} />;
  if (!q.data?.length)
    return (
      <Empty title="Nothing received yet">
        Point your firewalls&apos; syslog and your switches&apos; flows at the collector (see
        Settings).
      </Empty>
    );
  return (
    <Card pad={false}>
      <Table>
        <thead>
          <tr>
            <th>Sender</th>
            <th>Device</th>
            <th>Kind</th>
            <th>Last 24 h</th>
            <th>Unparsed</th>
            <th>Last received (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {q.data.map((s, i) => {
            const stale = q.dataUpdatedAt - new Date(s.last_received + "Z").getTime() > 15 * 60000;
            return (
              <tr key={i}>
                <td className="font-mono text-xs">{s.source || "—"}</td>
                <td>{s.device ?? <span className="text-ink-3">not a known device</span>}</td>
                <td>{s.table.replace("_", " ")}</td>
                <td className="tabular-nums">{s.records_24h.toLocaleString()}</td>
                <td className="tabular-nums">
                  {s.unparsed_24h > 0 ? (
                    <Badge tone="warn">{s.unparsed_24h.toLocaleString()}</Badge>
                  ) : (
                    "0"
                  )}
                </td>
                <td className="text-xs">
                  {s.last_received} {stale && <Badge tone="bad">silent</Badge>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </Table>
    </Card>
  );
}

function Exports({ role }: { role: string }) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["ipdr-exports"],
    refetchInterval: 15_000,
    queryFn: async () => unwrap(await api.GET("/v1/ipdr/exports")),
  });
  const [err, setErr] = useState<string | null>(null);
  const decide = useMutation({
    mutationFn: async ({ id, approve }: { id: string; approve: boolean }) => {
      const reason = prompt(approve ? "Why is this export approved?" : "Why is it denied?") ?? "";
      return unwrap(
        await api.POST("/v1/ipdr/exports/{export_id}/decision", {
          params: { path: { export_id: id } },
          body: { approve, reason },
        }),
      );
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ipdr-exports"] }),
    onError: (e) => setErr(errorText(e)),
  });
  const download = async (id: string) => {
    const { data, response } = await api.GET("/v1/ipdr/exports/{export_id}/download", {
      params: { path: { export_id: id } },
      parseAs: "blob",
    });
    if (!response.ok || !(data instanceof Blob)) {
      setErr(`Download refused (${response.status})`);
      return;
    }
    const a = document.createElement("a");
    a.href = URL.createObjectURL(data);
    a.download = `ipdr-export-${id}.zip`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState message={errorText(q.error)} />;
  return (
    <div className="space-y-3">
      {err && <Notice tone="bad">{err}</Notice>}
      <Card pad={false}>
        {!q.data?.length ? (
          <Empty title="No exports yet">Export matches from a search.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Requested</th>
                <th>Reason</th>
                <th>Rows</th>
                <th>State</th>
                <th>SHA-256</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.map((x) => (
                <tr key={x.id}>
                  <td className="text-xs">
                    {x.requester}
                    <br />
                    <span className="text-ink-3">{dateTime(x.created_at)}</span>
                  </td>
                  <td className="max-w-xs text-xs">{x.reason}</td>
                  <td className="tabular-nums">{x.row_count.toLocaleString()}</td>
                  <td>
                    <Badge
                      tone={
                        x.status === "ready"
                          ? "ok"
                          : x.status === "pending"
                            ? "warn"
                            : x.status === "approved"
                              ? "idle"
                              : "bad"
                      }
                    >
                      {x.status}
                    </Badge>
                    {x.decided_by && (
                      <p className="mt-1 text-[11px] text-ink-3">by {x.decided_by}</p>
                    )}
                  </td>
                  <td
                    className="max-w-[10rem] truncate font-mono text-[11px]"
                    title={x.sha256 ?? ""}
                  >
                    {x.sha256 ?? "—"}
                  </td>
                  <td className="whitespace-nowrap text-right">
                    {x.status === "pending" && APPROVERS.includes(role) && (
                      <>
                        <Button onClick={() => decide.mutate({ id: x.id, approve: true })}>
                          Approve
                        </Button>
                        <Button
                          variant="ghost"
                          onClick={() => decide.mutate({ id: x.id, approve: false })}
                        >
                          Deny
                        </Button>
                      </>
                    )}
                    {x.status === "ready" && (
                      <Button onClick={() => download(x.id)}>Download</Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}

function Audit() {
  const log = useQuery({
    queryKey: ["ipdr-audit"],
    queryFn: async () => unwrap(await api.GET("/v1/ipdr/audit")),
  });
  const seals = useQuery({
    queryKey: ["ipdr-seals"],
    queryFn: async () => unwrap(await api.GET("/v1/ipdr/seals")),
  });
  const chain = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/ipdr/audit/verify")),
  });
  const sealCheck = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/ipdr/seals/verify", { params: { query: { days: 30 } } })),
  });
  const sealBad = sealCheck.data?.filter((s) => !s.chain_ok || s.data_ok === false) ?? [];
  return (
    <div className="space-y-5">
      <Card title="Integrity">
        <div className="flex flex-wrap items-center gap-3 text-[13px]">
          <Button onClick={() => chain.mutate()} loading={chain.isPending}>
            Verify the audit chain
          </Button>
          {chain.data &&
            (chain.data.ok ? (
              <Badge tone="ok">{`intact · ${chain.data.checked} entries`}</Badge>
            ) : (
              <Badge tone="bad">{`broken at entry ${chain.data.broken_at}`}</Badge>
            ))}
          <Button onClick={() => sealCheck.mutate()} loading={sealCheck.isPending}>
            Re-check the last 30 days of evidence
          </Button>
          {sealCheck.data &&
            (sealBad.length === 0 ? (
              <Badge tone="ok">{`${sealCheck.data.length} seals match`}</Badge>
            ) : (
              <Badge tone="bad">{`${sealBad.length} seal(s) don't match`}</Badge>
            ))}
        </div>
        {sealBad.length > 0 && (
          <ul className="mt-3 list-disc pl-5 text-xs text-bad">
            {sealBad.slice(0, 20).map((s, i) => (
              <li key={i}>
                {String(s.day)} {String(s.table)}: sealed {String(s.rows)} rows
                {s.found_rows !== undefined ? `, found ${String(s.found_rows)}` : ""}
                {!s.chain_ok ? " (seal chain broken)" : ""}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Audit log" pad={false}>
        {log.isLoading ? (
          <Loading />
        ) : log.error ? (
          <ErrorState message={errorText(log.error)} />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>#</th>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
                <th>Reason</th>
                <th>Rows</th>
              </tr>
            </thead>
            <tbody>
              {log.data?.map((a) => (
                <tr key={a.seq} title={JSON.stringify(a.params)}>
                  <td className="tabular-nums text-ink-3">{a.seq}</td>
                  <td className="whitespace-nowrap text-xs">{dateTime(a.at)}</td>
                  <td className="text-xs">{a.actor}</td>
                  <td>{a.action.replaceAll("_", " ")}</td>
                  <td className="max-w-xs text-xs">{a.reason}</td>
                  <td className="tabular-nums">{a.result_rows ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <Card title="Daily seals" pad={false}>
        {!seals.data?.length ? (
          <Empty title="No seals yet">
            Each day is sealed two days later, once late deliveries are in.
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Day</th>
                <th>Table</th>
                <th>Rows</th>
                <th>Seal</th>
              </tr>
            </thead>
            <tbody>
              {seals.data.map((s) => (
                <tr key={s.day + s.table}>
                  <td>{s.day}</td>
                  <td>{s.table.replace("_", " ")}</td>
                  <td className="tabular-nums">{s.rows.toLocaleString()}</td>
                  <td className="font-mono text-[11px]">{s.hash.slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}

function SettingsTab({ s, canEdit }: { s: Settings; canEdit: boolean }) {
  const qc = useQueryClient();
  const hosts = useHosts();
  const servers = (hosts.data ?? []).filter((h) => h.kind === "server");
  const [form, setForm] = useState({
    enabled: s.enabled,
    retention_days: s.retention_days,
    collector_host_id: s.collector_host_id ?? "",
    allow: s.allow.join("\n"),
    export_approval_rows: s.export_approval_rows,
  });
  const [err, setErr] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/v1/ipdr/settings", {
          body: {
            enabled: form.enabled,
            retention_days: Number(form.retention_days),
            collector_host_id: form.collector_host_id || null,
            allow: form.allow.split(/[\s,]+/).filter(Boolean),
            export_approval_rows: Number(form.export_approval_rows),
          },
        }),
      ),
    onSuccess: () => {
      setErr(null);
      qc.invalidateQueries({ queryKey: ["ipdr-settings"] });
    },
    onError: (e) => setErr(errorText(e)),
  });
  const collector = servers.find((h) => h.id === s.collector_host_id);
  const c = s.collector as {
    at?: number;
    stats?: { listening?: string[]; dropped?: number; refused?: number; spool_mb?: number };
  } | null;
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Settings">
        {!s.available && (
          <Notice tone="warn">
            This Sentinel server has no evidence store (ClickHouse), so IPDR can&apos;t be turned
            on.
          </Notice>
        )}
        <form
          className="mt-3 space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <label className="flex items-center gap-2 text-[13px]">
            <input
              type="checkbox"
              checked={form.enabled}
              disabled={!canEdit}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            Collect evidence for this organisation
          </label>
          <Field
            label="Collector"
            hint="The server (with the agent) your firewalls and switches send to"
          >
            <Select
              value={form.collector_host_id}
              disabled={!canEdit}
              onChange={(e) => setForm({ ...form, collector_host_id: e.target.value })}
              className="w-full"
            >
              <option value="">Pick a server</option>
              {servers.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.hostname}
                </option>
              ))}
            </Select>
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Keep evidence for (days)" hint="30 to 2000">
              <Input
                type="number"
                min={30}
                max={2000}
                disabled={!canEdit}
                value={form.retention_days}
                onChange={(e) => setForm({ ...form, retention_days: Number(e.target.value) })}
              />
            </Field>
            <Field label="Exports above this many rows need approval">
              <Input
                type="number"
                min={1000}
                disabled={!canEdit}
                value={form.export_approval_rows}
                onChange={(e) => setForm({ ...form, export_approval_rows: Number(e.target.value) })}
              />
            </Field>
          </div>
          <Field
            label="Also accept from"
            hint="Addresses or ranges besides the devices the collector polls, one a line"
          >
            <textarea
              rows={3}
              disabled={!canEdit}
              value={form.allow}
              onChange={(e) => setForm({ ...form, allow: e.target.value })}
              className="w-full rounded-[3px] border border-line-2 bg-panel px-3 py-1.5 font-mono text-xs text-ink"
              placeholder="10.20.0.0/24"
            />
          </Field>
          {err && <Notice tone="bad">{err}</Notice>}
          {canEdit && (
            <Button type="submit" variant="primary" loading={save.isPending}>
              Save
            </Button>
          )}
        </form>
      </Card>
      <Card title="Point your devices at the collector">
        <div className="space-y-3 text-[13px] text-ink-2">
          <p>
            Send to <b className="text-ink">{collector?.hostname ?? "the collector"}</b>
            {collector?.public_ip ? ` (${collector.public_ip} or its LAN address)` : ""}:
          </p>
          <ul className="list-disc space-y-1 pl-5 font-mono text-xs">
            <li>
              syslog over TCP {s.ports.syslog_tcp} (preferred: nothing is lost) or UDP{" "}
              {s.ports.syslog_udp}
            </li>
            <li>
              sFlow {s.ports.sflow}, NetFlow {s.ports.netflow}, IPFIX {s.ports.ipfix} (UDP)
            </li>
          </ul>
          <p>
            FortiGate: <code>set logtraffic all</code> on every policy (and the implicit deny),
            syslog in reliable (TCP) mode, NTP on. MAC and ARP tables of the devices the collector
            polls are read every 15 minutes on their own.
          </p>
          <p>
            Only the devices the collector polls, and the ranges you allow, are accepted. Run{" "}
            <code>install.sh --evidence</code> on the collector to listen on the standard ports 514
            and 601 instead.
          </p>
          {c?.stats && (
            <div className="rounded border border-line p-3 text-xs">
              <p className="font-medium text-ink">Collector report</p>
              <p>Listening: {(c.stats.listening ?? []).join(", ") || "nothing yet"}</p>
              <p>
                Refused senders: {c.stats.refused ?? 0} · dropped: {c.stats.dropped ?? 0} · waiting
                to send: {(c.stats.spool_mb ?? 0).toFixed(1)} MB
              </p>
              {c.at && (
                <p className="text-ink-3">{dateTime(new Date(c.at * 1000).toISOString())}</p>
              )}
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
