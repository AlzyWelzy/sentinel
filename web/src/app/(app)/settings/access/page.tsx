"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  Badge,
  Button,
  Card,
  ErrorState,
  Loading,
  Notice,
  PageHeader,
  Table,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { ago, dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";

const ROLE: Record<string, string> = {
  owner: "Owner",
  admin: "Admin",
  operator: "Member",
  viewer: "Read-only",
  investigator: "Investigator",
  auditor: "Auditor",
};

export default function AccessReviewPage() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["access-review"],
    queryFn: async () => unwrap(await api.GET("/v1/access-review")),
  });
  const confirm = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/access-review")),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["access-review"] }),
  });
  return (
    <>
      <PageHeader
        title="Access review"
        subtitle="Who can get into this organisation and how. Check it every quarter: remove anyone who shouldn't be here, then confirm."
      />
      {q.isLoading ? (
        <Loading />
      ) : q.error ? (
        <ErrorState message={errorText(q.error)} retry={() => q.refetch()} />
      ) : (
        q.data && (
          <div className="space-y-6">
            <Notice tone={q.data.due ? "warn" : "ok"}>
              {q.data.reviewed_at
                ? `Last reviewed ${ago(q.data.reviewed_at)} by ${q.data.reviewed_by}.`
                : "Never reviewed."}{" "}
              {q.data.due ? "A review is due." : "The next one is due 90 days after it."}
            </Notice>
            <Card title={`People · ${q.data.members.length}`} pad={false}>
              <Table>
                <thead>
                  <tr>
                    <th>Who</th>
                    <th>Role</th>
                    <th>Two-factor</th>
                    <th>Last signed in</th>
                  </tr>
                </thead>
                <tbody>
                  {q.data.members.map((m) => (
                    <tr key={m.email}>
                      <td>
                        <div className="font-medium">{m.name || m.email}</div>
                        {m.name && <div className="text-ink-3 text-xs">{m.email}</div>}
                      </td>
                      <td>
                        {ROLE[m.role] ?? m.role} {m.pending && <Badge>invited</Badge>}
                      </td>
                      <td>
                        {m.pending ? (
                          "—"
                        ) : m.two_factor ? (
                          <Badge tone="ok">on</Badge>
                        ) : (
                          <Badge tone="warn">off</Badge>
                        )}
                      </td>
                      <td>{m.last_seen_at ? ago(m.last_seen_at) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>
            <Card title={`API tokens · ${q.data.tokens.length}`} pad={false}>
              {q.data.tokens.length === 0 ? (
                <p className="text-ink-3 px-4 py-3 text-sm">No API tokens.</p>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Access</th>
                      <th>Last used</th>
                      <th>Expires</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.tokens.map((k) => (
                      <tr key={k.name + k.created_at}>
                        <td className="font-medium">{k.name}</td>
                        <td>
                          {k.read_only ? "Read-only" : <Badge tone="warn">can change things</Badge>}
                        </td>
                        <td>{k.last_used_at ? ago(k.last_used_at) : "never"}</td>
                        <td>{k.expires_at ? dateTime(k.expires_at) : "never"}</td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
            <div className="flex flex-wrap items-center gap-3">
              <Button
                variant="primary"
                loading={confirm.isPending}
                onClick={() => confirm.mutate()}
              >
                Everyone here should have access
              </Button>
              <span className="text-ink-3 text-sm">
                Records the review in the audit log. Change members under Organisation and tokens
                under API tokens.
              </span>
            </div>
            {confirm.error && <Notice tone="bad">{errorText(confirm.error)}</Notice>}
          </div>
        )
      )}
    </>
  );
}
