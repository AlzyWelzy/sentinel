"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
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
import { unwrap } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

const TYPES: Record<string, { label: string; placeholder: string }> = {
  email: { label: "Email", placeholder: "oncall@example.com" },
  webhook: { label: "Webhook", placeholder: "https://example.com/hooks/pulsegrid" },
  slack: { label: "Slack", placeholder: "https://hooks.slack.com/services/…" },
  teams: { label: "Microsoft Teams", placeholder: "https://….webhook.office.com/…" },
  discord: { label: "Discord", placeholder: "https://discord.com/api/webhooks/…" },
  telegram: { label: "Telegram", placeholder: "bot-token:chat-id" },
  pagerduty: { label: "PagerDuty", placeholder: "Events v2 routing key" },
  sms: { label: "SMS", placeholder: "+15551234567" },
  voice: { label: "Voice call", placeholder: "+15551234567" },
};

export default function ContactsPage() {
  const qc = useQueryClient();
  const me = useMe();
  const editable = canEdit(me.data?.role);
  const [type, setType] = useState<components["schemas"]["ChannelIn"]["type"]>("email");
  const [target, setTarget] = useState("");
  const [label, setLabel] = useState("");
  const [codes, setCodes] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: async () => unwrap(await api.GET("/v1/channels")),
  });
  const done = (text: string) => {
    setMsg({ tone: "ok", text });
    qc.invalidateQueries({ queryKey: ["channels"] });
  };
  const fail = (e: unknown) => setMsg({ tone: "bad", text: errorText(e) });
  const add = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/channels", {
          body: { type, target, label: label || null, min_severity: "info" },
        }),
      ),
    onSuccess: (c) => {
      setTarget("");
      setLabel("");
      done(c.verified ? "Contact added." : "Contact added. Enter the code we sent to verify it.");
    },
    onError: fail,
  });
  const verify = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.POST("/v1/channels/{channel_id}/verify", {
          params: { path: { channel_id: id } },
          body: { code: codes[id] ?? "" },
        }),
      ),
    onSuccess: () => done("Verified."),
    onError: fail,
  });
  const test = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.POST("/v1/channels/{channel_id}/test", { params: { path: { channel_id: id } } }),
      ),
    onSuccess: () => done("Test message queued."),
    onError: fail,
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.DELETE("/v1/channels/{channel_id}", { params: { path: { channel_id: id } } }),
      ),
    onSuccess: () => done("Removed."),
    onError: fail,
  });

  return (
    <>
      <PageHeader
        title="Contacts"
        subtitle="Where alerts go. New contacts receive nothing until verified."
      />
      {msg && (
        <div className="mb-4">
          <Notice tone={msg.tone}>{msg.text}</Notice>
        </div>
      )}
      {editable && (
        <Card title="Add a contact" className="mb-6">
          <form
            className="grid gap-3 sm:grid-cols-[10rem_1fr_12rem_auto] sm:items-end"
            onSubmit={(e) => {
              e.preventDefault();
              add.mutate();
            }}
          >
            <Field label="Type">
              <Select
                value={type}
                onChange={(e) => setType(e.target.value as typeof type)}
                className="w-full"
              >
                {Object.entries(TYPES).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Address">
              <Input
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={TYPES[type]?.placeholder}
              />
            </Field>
            <Field label="Label">
              <Input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="Optional"
              />
            </Field>
            <Button type="submit" variant="primary" loading={add.isPending}>
              Add
            </Button>
          </form>
          <p className="mt-2 text-xs text-ink-3">
            Some types may be turned off for this installation; the API says so if you pick one.
          </p>
        </Card>
      )}
      <Card pad={false}>
        {channels.isLoading ? (
          <Loading />
        ) : channels.error ? (
          <ErrorState message={errorText(channels.error)} />
        ) : !channels.data?.length ? (
          <Empty title="No contacts" />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Contact</th>
                <th>Type</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {channels.data.map((c) => (
                <tr key={c.id}>
                  <td>
                    <span className="font-medium">{c.label ?? c.target}</span>
                    {c.label && <p className="text-xs text-ink-3">{c.target}</p>}
                  </td>
                  <td className="text-ink-2">
                    {TYPES[c.type]?.label ?? c.type}
                    {c.source === "team" && " · member"}
                  </td>
                  <td>
                    <div className="flex gap-1">
                      {c.verified ? (
                        <Badge tone="ok">verified</Badge>
                      ) : (
                        <Badge tone="warn">unverified</Badge>
                      )}
                      {c.is_default && <Badge tone="brand">default</Badge>}
                    </div>
                  </td>
                  <td className="text-right whitespace-nowrap">
                    {!c.verified && editable && (
                      <span className="mr-2 inline-flex gap-1">
                        <Input
                          className="w-24"
                          placeholder="code"
                          value={codes[c.id] ?? ""}
                          onChange={(e) => setCodes({ ...codes, [c.id]: e.target.value })}
                        />
                        <Button onClick={() => verify.mutate(c.id)}>Verify</Button>
                      </span>
                    )}
                    {c.verified && (
                      <Button variant="ghost" onClick={() => test.mutate(c.id)}>
                        Send test
                      </Button>
                    )}
                    {editable && (
                      <Button
                        variant="ghost"
                        onClick={() => confirm("Remove this contact?") && remove.mutate(c.id)}
                      >
                        Remove
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
