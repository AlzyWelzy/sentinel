"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  ErrorState,
  Input,
  Loading,
  Notice,
  PageHeader,
  Table,
  cx,
} from "@/components/ui";
import { api, errorText, setImpersonation } from "@/lib/api/client";
import { ago, dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";
import { useSession } from "@/lib/session";

const TABS = ["Organisations", "Users", "Agent rollout", "Impersonations"] as const;

export default function AdminPage() {
  const { user } = useSession();
  const [tab, setTab] = useState<(typeof TABS)[number]>("Organisations");
  const overview = useQuery({
    queryKey: ["admin", "overview"],
    enabled: !!user?.superadmin,
    queryFn: async () => unwrap(await api.GET("/admin/v1/overview")),
  });
  if (!user?.superadmin) return <ErrorState message="Superadmins only." />;
  const o = overview.data;
  return (
    <>
      <PageHeader title="Superadmin" subtitle="Every organisation on this installation." />
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ["Organisations", o?.tenants],
          ["Servers", o?.hosts],
          ["Online", o?.hosts_online],
          ["Open incidents", o?.open_incidents],
        ].map(([l, v]) => (
          <Card key={l as string}>
            <p className="text-xs text-ink-2">{l}</p>
            <p className="mt-1 text-2xl font-semibold tabular">{v ?? "—"}</p>
          </Card>
        ))}
      </div>
      <div className="mb-5 flex gap-1 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={cx(
              "-mb-px border-b-2 px-3 py-2 text-sm",
              tab === t ? "border-brand font-medium" : "border-transparent text-ink-3",
            )}
          >
            {t}
          </button>
        ))}
      </div>
      {tab === "Organisations" && <Orgs />}
      {tab === "Users" && <Users />}
      {tab === "Agent rollout" && <Rollout />}
      {tab === "Impersonations" && <Impersonations />}
    </>
  );
}

function Orgs() {
  const qc = useQueryClient();
  const router = useRouter();
  const [q, setQ] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const list = useQuery({
    queryKey: ["admin", "tenants", q],
    queryFn: async () =>
      unwrap(
        await api.GET("/admin/v1/tenants", {
          params: { query: { q: q || undefined, with_hosts: false } },
        }),
      ),
  });
  const status = useMutation({
    mutationFn: async ([id, suspend]: [string, boolean]) =>
      unwrap(
        suspend
          ? await api.POST("/admin/v1/tenants/{tenant_id}/suspend", {
              params: { path: { tenant_id: id } },
            })
          : await api.POST("/admin/v1/tenants/{tenant_id}/resume", {
              params: { path: { tenant_id: id } },
            }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "tenants"] }),
    onError: (e) => setMsg(errorText(e)),
  });
  const impersonate = useMutation({
    mutationFn: async ([id, writes]: [string, boolean]) => {
      const reason = prompt(
        writes
          ? "Why do you need to change things in this organisation?"
          : "Why are you looking at this organisation?",
      );
      if (!reason || reason.trim().length < 5)
        throw { detail: "A reason of at least 5 characters is required" };
      return unwrap(
        await api.POST("/admin/v1/tenants/{tenant_id}/impersonate", {
          params: { path: { tenant_id: id } },
          body: { reason, allow_writes: writes },
        }),
      );
    },
    onSuccess: (imp) => {
      setImpersonation(imp.access_token);
      qc.clear();
      router.push("/overview");
    },
    onError: (e) => setMsg(errorText(e)),
  });
  return (
    <Card pad={false}>
      <div className="border-b border-line p-3">
        <Input
          placeholder="Search name, email or id…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="max-w-sm"
        />
      </div>
      {msg && (
        <div className="p-3">
          <Notice tone="bad">{msg}</Notice>
        </div>
      )}
      {list.isLoading ? (
        <Loading />
      ) : list.error ? (
        <ErrorState message={errorText(list.error)} />
      ) : (
        <Table>
          <thead>
            <tr>
              <th>Organisation</th>
              <th>Servers</th>
              <th>Incidents</th>
              <th>Status</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data!.map((t) => (
              <tr key={t.id}>
                <td>
                  <span className="font-medium">{t.display_name ?? t.email}</span>
                  {t.display_name && t.email && <p className="text-xs text-ink-2">{t.email}</p>}
                  <p className="font-mono text-xs text-ink-3">{t.id}</p>
                </td>
                <td className="tabular">
                  {t.hosts_online} / {t.hosts}
                </td>
                <td className="tabular">{t.open_incidents}</td>
                <td>
                  <Badge tone={t.status === "active" ? "ok" : "bad"}>{t.status}</Badge>
                </td>
                <td className="text-ink-2">{dateTime(t.created_at)}</td>
                <td className="text-right whitespace-nowrap">
                  <Button variant="ghost" onClick={() => impersonate.mutate([t.id, false])}>
                    View
                  </Button>
                  <Button variant="ghost" onClick={() => impersonate.mutate([t.id, true])}>
                    Work in
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() =>
                      confirm(
                        `${t.status === "active" ? "Suspend" : "Resume"} this organisation?`,
                      ) && status.mutate([t.id, t.status === "active"])
                    }
                  >
                    {t.status === "active" ? "Suspend" : "Resume"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function Users() {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const users = useQuery({
    queryKey: ["admin", "users", q],
    queryFn: async () =>
      unwrap(await api.GET("/admin/v1/users", { params: { query: { q: q || undefined } } })),
  });
  const disable = useMutation({
    mutationFn: async ([id, disabled]: [string, boolean]) =>
      unwrap(
        await api.PUT("/admin/v1/users/{user_id}/disabled", {
          params: { path: { user_id: id } },
          body: { disabled },
        }),
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["admin", "users"] }),
  });
  return (
    <Card pad={false}>
      <div className="border-b border-line p-3">
        <Input
          placeholder="Search email or name…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="max-w-sm"
        />
      </div>
      {users.isLoading ? (
        <Loading />
      ) : (
        <Table>
          <thead>
            <tr>
              <th>User</th>
              <th>Organisations</th>
              <th>Security</th>
              <th>Joined</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.data?.map((u) => (
              <tr key={u.id} className={u.disabled ? "opacity-60" : ""}>
                <td>
                  <span className="font-medium">{u.email}</span>
                  {u.name && <p className="text-xs text-ink-3">{u.name}</p>}
                </td>
                <td className="tabular">{u.organisations}</td>
                <td>
                  <div className="flex gap-1">
                    {!u.email_verified && <Badge tone="warn">unverified</Badge>}
                    {u.totp_enabled && <Badge tone="ok">2FA</Badge>}
                    {u.superadmin && <Badge tone="brand">superadmin</Badge>}
                  </div>
                </td>
                <td className="text-ink-2">{ago(u.created_at)}</td>
                <td className="text-right">
                  <Button variant="ghost" onClick={() => disable.mutate([u.id, !u.disabled])}>
                    {u.disabled ? "Enable" : "Disable"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function Rollout() {
  const qc = useQueryClient();
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  const r = useQuery({
    queryKey: ["admin", "rollout"],
    queryFn: async () => unwrap(await api.GET("/admin/v1/agent-rollout")),
  });
  const fleet = useQuery({
    queryKey: ["admin", "fleet"],
    queryFn: async () => unwrap(await api.GET("/admin/v1/fleet")),
  });
  const act = useMutation({
    mutationFn: async (which: "promote" | "rollback") =>
      unwrap(
        which === "promote"
          ? await api.POST("/admin/v1/agent-rollout/promote")
          : await api.POST("/admin/v1/agent-rollout/rollback"),
      ),
    onSuccess: () => {
      setMsg({ tone: "ok", text: "Done." });
      qc.invalidateQueries({ queryKey: ["admin"] });
    },
    onError: (e) => setMsg({ tone: "bad", text: errorText(e) }),
  });
  if (r.isLoading) return <Loading />;
  const ro = r.data!;
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="Rollout">
        {msg && (
          <div className="mb-3">
            <Notice tone={msg.tone}>{msg.text}</Notice>
          </div>
        )}
        <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
          <dt className="text-ink-3">Stable</dt>
          <dd className="font-mono">{ro.stable_version ?? "—"}</dd>
          <dt className="text-ink-3">Candidate</dt>
          <dd className="font-mono">
            {ro.candidate_version
              ? `${ro.candidate_version} on ${ro.candidate_percent}% since ${ago(ro.candidate_since)}`
              : "none"}
          </dd>
          {ro.rolled_back_version && (
            <>
              <dt className="text-ink-3">Rolled back</dt>
              <dd>
                {ro.rolled_back_version}: {ro.rollback_reason}
              </dd>
            </>
          )}
        </dl>
        {ro.candidate_version && (
          <div className="mt-4 flex gap-2">
            <Button variant="primary" onClick={() => act.mutate("promote")} loading={act.isPending}>
              Promote to stable
            </Button>
            <Button variant="danger" onClick={() => act.mutate("rollback")}>
              Roll back
            </Button>
          </div>
        )}
      </Card>
      <Card title="Agent versions in the field" pad={false}>
        <Table>
          <tbody>
            {(fleet.data?.versions as { version: string; hosts: number }[] | undefined)?.map(
              (v) => (
                <tr key={v.version}>
                  <td className="font-mono">{v.version}</td>
                  <td className="text-right tabular">{v.hosts}</td>
                </tr>
              ),
            )}
          </tbody>
        </Table>
      </Card>
    </div>
  );
}

function Impersonations() {
  const list = useQuery({
    queryKey: ["admin", "impersonations"],
    queryFn: async () => unwrap(await api.GET("/admin/v1/impersonations")),
  });
  if (list.isLoading) return <Loading />;
  return (
    <Card pad={false}>
      <Table>
        <thead>
          <tr>
            <th>When</th>
            <th>Superadmin</th>
            <th>Organisation</th>
            <th>Reason</th>
            <th>Access</th>
          </tr>
        </thead>
        <tbody>
          {list.data?.map((i) => (
            <tr key={i.id}>
              <td className="whitespace-nowrap text-ink-2">{dateTime(i.started_at)}</td>
              <td>{i.superadmin}</td>
              <td>{i.organisation}</td>
              <td className="max-w-sm text-ink-2">{i.reason}</td>
              <td>
                {i.allow_writes ? <Badge tone="warn">writes</Badge> : <Badge>read-only</Badge>}
                {i.ended_at && <span className="ml-1 text-xs text-ink-3">ended</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}
