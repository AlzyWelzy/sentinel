"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import {
  Badge,
  Button,
  Card,
  ErrorState,
  Field,
  Input,
  Loading,
  Notice,
  PageHeader,
  Select,
  Table,
} from "@/components/ui";
import { api, authed, errorText, setOrg } from "@/lib/api/client";
import { ago } from "@/lib/format";
import { unwrap } from "@/lib/queries";
import { ROLE_LABELS, orgName, useMe } from "@/lib/session";

type Role = "viewer" | "operator" | "admin";

function Organisation() {
  const qc = useQueryClient();
  const me = useMe();
  const wantsNew = useSearchParams().get("new") === "1";
  const role = me.data?.role;
  const manager = role === "owner" || role === "admin" || role === "staff";
  const router = useRouter();
  const [name, setName] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [email, setEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("operator");
  const [confirmName, setConfirmName] = useState("");
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  const members = useQuery({
    queryKey: ["members"],
    queryFn: async () => unwrap(await api.GET("/v1/members")),
  });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["members"] });
    qc.invalidateQueries({ queryKey: ["me"] });
    qc.invalidateQueries({ queryKey: ["accounts"] });
  };
  const fail = (e: unknown) => setMsg({ tone: "bad", text: errorText(e) });
  const rename = useMutation({
    mutationFn: async () =>
      unwrap(await api.PATCH("/v1/organisation", { body: { name: name ?? "" } })),
    onSuccess: () => {
      setMsg({ tone: "ok", text: "Renamed." });
      refresh();
    },
    onError: fail,
  });
  const invite = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/members", { body: { email, role: inviteRole } })),
    onSuccess: () => {
      setMsg({ tone: "ok", text: `Invitation sent to ${email}.` });
      setEmail("");
      refresh();
    },
    onError: fail,
  });
  const changeRole = useMutation({
    mutationFn: async ([id, r]: [string, Role]) =>
      unwrap(
        await api.PATCH("/v1/members/{member_id}", {
          params: { path: { member_id: id } },
          body: { role: r },
        }),
      ),
    onSuccess: refresh,
    onError: fail,
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(await api.DELETE("/v1/members/{member_id}", { params: { path: { member_id: id } } })),
    onSuccess: refresh,
    onError: fail,
  });
  const makeOwner = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.POST("/v1/members/{member_id}/make-owner", {
          params: { path: { member_id: id } },
        }),
      ),
    onSuccess: () => {
      setMsg({ tone: "ok", text: "Ownership handed over. You're an admin now." });
      refresh();
    },
    onError: fail,
  });
  async function exportData() {
    const r = await authed("/v1/organisation/export");
    if (!r.ok) return setMsg({ tone: "bad", text: "The export couldn't be made." });
    const url = URL.createObjectURL(await r.blob());
    const a = Object.assign(document.createElement("a"), {
      href: url,
      download: `sentinel-export-${new Date().toISOString().slice(0, 10)}.json`,
    });
    a.click();
    URL.revokeObjectURL(url);
  }
  const resend = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.POST("/v1/members/{member_id}/resend", { params: { path: { member_id: id } } }),
      ),
    onSuccess: () => setMsg({ tone: "ok", text: "Invitation sent again." }),
    onError: fail,
  });
  const create = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/organisations", { body: { name: newName } })),
    onSuccess: (o) => {
      setOrg(o.tenant_id);
      qc.clear();
      router.push("/welcome");
    },
    onError: fail,
  });
  const destroy = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/organisation/delete", { body: { confirm_name: confirmName } })),
    onSuccess: () => {
      setOrg(null);
      qc.clear();
      router.push("/overview");
    },
    onError: fail,
  });

  if (me.isLoading) return <Loading />;
  return (
    <>
      <PageHeader
        title="Organisation"
        subtitle={
          me.data ? `${orgName(me.data)} · you're ${ROLE_LABELS[role ?? ""] ?? role}` : undefined
        }
      />
      {msg && (
        <div className="mb-4">
          <Notice tone={msg.tone}>{msg.text}</Notice>
        </div>
      )}
      <div className="space-y-6">
        {wantsNew && (
          <Card title="New organisation">
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                create.mutate();
              }}
            >
              <div className="min-w-64 flex-1">
                <Field
                  label="Name"
                  hint="You'll be its owner. Servers and rules are separate per organisation."
                >
                  <Input required value={newName} onChange={(e) => setNewName(e.target.value)} />
                </Field>
              </div>
              <Button type="submit" variant="primary" loading={create.isPending}>
                Create
              </Button>
            </form>
          </Card>
        )}
        {manager && (
          <Card title="Name">
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                rename.mutate();
              }}
            >
              <div className="min-w-64 flex-1">
                <Input
                  required
                  value={name ?? me.data?.display_name ?? ""}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <Button type="submit" loading={rename.isPending}>
                Save
              </Button>
            </form>
          </Card>
        )}
        <Card title="Members" pad={false}>
          {manager && (
            <form
              className="flex flex-wrap items-end gap-3 border-b border-line p-4"
              onSubmit={(e) => {
                e.preventDefault();
                invite.mutate();
              }}
            >
              <div className="min-w-64 flex-1">
                <Field label="Invite by email">
                  <Input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="teammate@example.com"
                  />
                </Field>
              </div>
              <Select value={inviteRole} onChange={(e) => setInviteRole(e.target.value as Role)}>
                <option value="admin">Admin</option>
                <option value="operator">Member</option>
                <option value="viewer">Read-only</option>
              </Select>
              <Button type="submit" variant="primary" loading={invite.isPending}>
                Send invitation
              </Button>
            </form>
          )}
          {members.isLoading ? (
            <Loading />
          ) : members.error ? (
            <ErrorState message={errorText(members.error)} />
          ) : (
            <Table>
              <thead>
                <tr>
                  <th>Person</th>
                  <th>Role</th>
                  <th>Last seen</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {members.data!.map((m) => (
                  <tr key={m.id}>
                    <td>
                      <span className="font-medium">{m.name ?? m.email}</span>{" "}
                      {m.is_you && <Badge>you</Badge>}
                      {m.name && <p className="text-xs text-ink-3">{m.email}</p>}
                    </td>
                    <td>
                      {manager && m.role !== "owner" && m.joined ? (
                        <Select
                          value={m.role}
                          onChange={(e) => changeRole.mutate([m.id, e.target.value as Role])}
                        >
                          <option value="admin">Admin</option>
                          <option value="operator">Member</option>
                          <option value="viewer">Read-only</option>
                        </Select>
                      ) : (
                        <span className="text-ink-2">{ROLE_LABELS[m.role] ?? m.role}</span>
                      )}
                    </td>
                    <td className="text-ink-2">
                      {m.joined ? ago(m.last_seen_at) : <Badge tone="warn">invited</Badge>}
                    </td>
                    <td className="text-right whitespace-nowrap">
                      {role === "owner" && m.joined && m.role !== "owner" && (
                        <Button
                          variant="ghost"
                          onClick={() =>
                            confirm(
                              `Make ${m.name ?? m.email} the owner? You'll become an admin.`,
                            ) && makeOwner.mutate(m.id)
                          }
                        >
                          Make owner
                        </Button>
                      )}
                      {manager && !m.joined && (
                        <Button variant="ghost" onClick={() => resend.mutate(m.id)}>
                          Resend
                        </Button>
                      )}
                      {m.role !== "owner" && (manager || m.is_you) && (
                        <Button
                          variant="ghost"
                          onClick={() =>
                            confirm(m.is_you ? "Leave this organisation?" : `Remove ${m.email}?`) &&
                            remove.mutate(m.id)
                          }
                        >
                          {m.is_you ? "Leave" : m.joined ? "Remove" : "Cancel"}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
        {manager && (
          <Card title="Your data">
            <p className="mb-3 text-sm text-ink-2">
              Download everything this organisation has in Sentinel as JSON: servers, rules, checks,
              contacts, incidents with timelines, status pages and the audit log. Secrets are
              masked.
            </p>
            <Button onClick={exportData}>Download export</Button>
          </Card>
        )}
        {role === "owner" && (
          <Card title="Delete organisation">
            <p className="mb-3 text-sm text-ink-2">
              Deletes every server, rule, incident and metric in this organisation. Agents stop
              being accepted. This can&apos;t be undone.
            </p>
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                destroy.mutate();
              }}
            >
              <div className="min-w-64 flex-1">
                <Field label={`Type "${me.data?.display_name ?? me.data?.email}" to confirm`}>
                  <Input value={confirmName} onChange={(e) => setConfirmName(e.target.value)} />
                </Field>
              </div>
              <Button type="submit" variant="danger" loading={destroy.isPending}>
                Delete organisation
              </Button>
            </form>
          </Card>
        )}
      </div>
    </>
  );
}

export default function OrganisationPage() {
  return (
    <Suspense>
      <Organisation />
    </Suspense>
  );
}
