"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  CopyBlock,
  Empty,
  ErrorState,
  Field,
  Input,
  Loading,
  Notice,
  PageHeader,
  Table,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { ago, dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";
import { useMe } from "@/lib/session";

export default function TokensPage() {
  const qc = useQueryClient();
  const me = useMe();
  const [name, setName] = useState("");
  const [readOnly, setReadOnly] = useState(true);
  const [created, setCreated] = useState<string | null>(null);
  const owner = me.data?.role === "owner";
  const tokens = useQuery({
    queryKey: ["tokens"],
    enabled: owner,
    queryFn: async () => unwrap(await api.GET("/v1/api-tokens")),
  });
  const keys = useQuery({
    queryKey: ["agent-keys"],
    queryFn: async () => unwrap(await api.GET("/v1/agent-keys")),
  });
  const create = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/api-tokens", { body: { name, read_only: readOnly } })),
    onSuccess: (t) => {
      setCreated(t.token);
      setName("");
      qc.invalidateQueries({ queryKey: ["tokens"] });
    },
  });
  const revoke = useMutation({
    mutationFn: async (id: string) =>
      unwrap(await api.DELETE("/v1/api-tokens/{token_id}", { params: { path: { token_id: id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tokens"] }),
  });
  const revokeKey = useMutation({
    mutationFn: async (id: string) =>
      unwrap(await api.DELETE("/v1/agent-keys/{key_id}", { params: { path: { key_id: id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["agent-keys"] }),
  });

  return (
    <>
      <PageHeader title="API tokens and install keys" />
      <Card title="Install keys" pad={false} className="mb-6">
        {keys.isLoading ? (
          <Loading />
        ) : !keys.data?.length ? (
          <Empty title="No install keys">Create one from Add server.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Key</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keys.data.map((k) => (
                <tr key={k.id}>
                  <td className="font-medium">{k.name}</td>
                  <td className="font-mono text-xs">{k.key_prefix}…</td>
                  <td className="text-ink-2">{dateTime(k.created_at)}</td>
                  <td className="text-right">
                    {k.revoked_at ? (
                      <Badge>revoked</Badge>
                    ) : (
                      <Button
                        variant="ghost"
                        onClick={() =>
                          confirm("Revoke? Servers already installed keep working.") &&
                          revokeKey.mutate(k.id)
                        }
                      >
                        Revoke
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <Card title="API tokens">
        {!owner ? (
          <p className="text-sm text-ink-2">
            Only the organisation&apos;s owner manages API tokens.
          </p>
        ) : (
          <div className="space-y-4">
            {created && (
              <div className="space-y-2">
                <Notice tone="ok">Copy this token now. It won&apos;t be shown again.</Notice>
                <CopyBlock text={created} />
              </div>
            )}
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                create.mutate();
              }}
            >
              <div className="min-w-60 flex-1">
                <Field label="Name">
                  <Input
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Terraform"
                  />
                </Field>
              </div>
              <label className="flex h-9 items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={readOnly}
                  onChange={(e) => setReadOnly(e.target.checked)}
                />{" "}
                Read-only
              </label>
              <Button type="submit" variant="primary" loading={create.isPending}>
                Create token
              </Button>
            </form>
            {tokens.error && <ErrorState message={errorText(tokens.error)} />}
            {!!tokens.data?.length && (
              <Table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Access</th>
                    <th>Last used</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {tokens.data.map((t) => (
                    <tr key={t.id}>
                      <td>
                        <span className="font-medium">{t.name}</span>
                        <p className="font-mono text-xs text-ink-3">{t.token_prefix}…</p>
                      </td>
                      <td>
                        {t.read_only ? (
                          <Badge>read-only</Badge>
                        ) : (
                          <Badge tone="warn">read and write</Badge>
                        )}
                      </td>
                      <td className="text-ink-2">{ago(t.last_used_at)}</td>
                      <td className="text-right">
                        {t.revoked ? (
                          <Badge>revoked</Badge>
                        ) : (
                          <Button variant="ghost" onClick={() => revoke.mutate(t.id)}>
                            Revoke
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </div>
        )}
      </Card>
    </>
  );
}
