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
import { DevicePush } from "@/components/device-push";
import { api, errorText } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";
import { unwrap } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

const TYPES: Record<string, { label: string; placeholder: string }> = {
  email: { label: "Email", placeholder: "oncall@example.com" },
  webhook: { label: "Webhook", placeholder: "https://example.com/hooks/sentinel" },
  slack: { label: "Slack", placeholder: "https://hooks.slack.com/services/…" },
  teams: { label: "Microsoft Teams", placeholder: "https://….webhook.office.com/…" },
  discord: { label: "Discord", placeholder: "https://discord.com/api/webhooks/…" },
  telegram: { label: "Telegram", placeholder: "bot-token:chat-id" },
  pagerduty: { label: "PagerDuty", placeholder: "Events v2 routing key" },
  sms: { label: "SMS", placeholder: "+15551234567" },
  voice: { label: "Voice call", placeholder: "+15551234567" },
};

type CatalogField = {
  key: string;
  label: string;
  hint?: string;
  secret?: boolean;
  required?: boolean;
  url?: boolean;
  hosts?: string[];
  default?: string;
  options?: [string, string][];
};

export default function ContactsPage() {
  const qc = useQueryClient();
  const me = useMe();
  const editable = canEdit(me.data?.role);
  const [type, setType] = useState("email");
  const [target, setTarget] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const catalog = useQuery({
    queryKey: ["channel-catalog"],
    staleTime: Infinity,
    queryFn: async () => unwrap(await api.GET("/v1/channels/catalog")),
  });
  const provider = catalog.data?.find((p) => p.type === type);
  const groups = [...new Set(catalog.data?.map((p) => p.group) ?? [])];
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
          body: provider
            ? { type, target: "", fields, label: label || null, min_severity: "info" }
            : { type, target, label: label || null, min_severity: "info" },
        }),
      ),
    onSuccess: (c) => {
      setTarget("");
      setFields({});
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
  const resend = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.POST("/v1/channels/{channel_id}/verification", {
          params: { path: { channel_id: id } },
        }),
      ),
    onSuccess: () => done("A new code is on its way."),
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
  const [editing, setEditing] = useState<string | null>(null);
  const patch = useMutation({
    mutationFn: async ([id, body]: [string, components["schemas"]["ChannelPatch"]]) =>
      unwrap(
        await api.PATCH("/v1/channels/{channel_id}", {
          params: { path: { channel_id: id } },
          body,
        }),
      ),
    onSuccess: () => {
      setEditing(null);
      done("Saved.");
    },
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
      <DevicePush />
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
                onChange={(e) => {
                  setType(e.target.value);
                  setFields({});
                }}
                className="w-full"
              >
                <optgroup label="Built in">
                  {Object.entries(TYPES).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v.label}
                    </option>
                  ))}
                </optgroup>
                {groups.map((g) => (
                  <optgroup key={g} label={g}>
                    {catalog.data
                      ?.filter((p) => p.group === g)
                      .sort((a, b) => a.label.localeCompare(b.label))
                      .map((p) => (
                        <option key={p.type} value={p.type}>
                          {p.label}
                        </option>
                      ))}
                  </optgroup>
                ))}
              </Select>
            </Field>
            {provider ? (
              <p className="self-end pb-2 text-[13px] text-ink-2">
                Fill in {provider.label} below.
              </p>
            ) : (
              <Field label="Address">
                <Input
                  required
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder={TYPES[type]?.placeholder}
                />
              </Field>
            )}
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
            {provider && (
              <div className="grid gap-3 sm:col-span-4 sm:grid-cols-3">
                {(provider.fields as CatalogField[]).map((f) => (
                  <Field
                    key={f.key}
                    label={f.required ? f.label : `${f.label} (optional)`}
                    hint={f.hint}
                  >
                    {f.options ? (
                      <Select
                        value={fields[f.key] ?? f.default ?? ""}
                        onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}
                        className="w-full"
                      >
                        {f.options.map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </Select>
                    ) : (
                      <Input
                        required={f.required && !f.default}
                        type={f.secret ? "password" : f.url ? "url" : "text"}
                        autoComplete={f.secret ? "new-password" : "off"}
                        spellCheck={false}
                        value={fields[f.key] ?? ""}
                        placeholder={
                          f.default ??
                          (f.hosts ? `https://${f.hosts[0]?.replace(/^\./, "")}/…` : "")
                        }
                        onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}
                      />
                    )}
                  </Field>
                ))}
              </div>
            )}
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
              {channels.data.map((c) => [
                <tr key={c.id}>
                  <td>
                    <span className="font-medium">{c.label ?? c.target}</span>
                    {c.label && <p className="text-xs text-ink-3">{c.target}</p>}
                  </td>
                  <td className="text-ink-2">
                    {c.provider ?? TYPES[c.type]?.label ?? c.type}
                    {c.source === "team" && " · member"}
                  </td>
                  <td>
                    <div className="flex gap-1">
                      {c.undeliverable ? (
                        <span title={c.undeliverable_reason ?? undefined}>
                          <Badge tone="bad">bounced: verify again</Badge>
                        </span>
                      ) : c.verified ? (
                        <Badge tone="ok">verified</Badge>
                      ) : (
                        <Badge tone="warn">unverified</Badge>
                      )}
                      {c.is_default && <Badge tone="brand">default</Badge>}
                      {c.only_tag && (
                        <span title={`Only alerts for servers and devices tagged ${c.only_tag}`}>
                          <Badge tone="idle">only {c.only_tag}</Badge>
                        </span>
                      )}
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
                        <Button variant="ghost" onClick={() => resend.mutate(c.id)}>
                          Send code
                        </Button>
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
                        onClick={() => setEditing(editing === c.id ? null : c.id)}
                      >
                        Settings
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
                </tr>,
                editing === c.id && (
                  <tr key={`${c.id}-settings`}>
                    <td colSpan={4} className="bg-panel-2/50">
                      <ContactSettings
                        severity={c.min_severity}
                        quiet={c.quiet_hours ?? null}
                        onlyTag={c.only_tag ?? null}
                        onSave={(body) => patch.mutate([c.id, body])}
                      />
                    </td>
                  </tr>
                ),
              ])}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}

type Quiet = components["schemas"]["QuietHours"];

/** Lowest severity the contact receives, and hours it hears nothing (except
 * critical alerts, unless that's turned off too). */
function ContactSettings({
  severity,
  quiet,
  onlyTag,
  onSave,
}: {
  severity: string;
  quiet: Quiet | null;
  onlyTag: string | null;
  onSave: (body: components["schemas"]["ChannelPatch"]) => void;
}) {
  const [min, setMin] = useState(severity);
  const [tag, setTag] = useState(onlyTag ?? "");
  const [on, setOn] = useState(!!quiet);
  const [q, setQ] = useState<Quiet>(
    quiet ?? {
      start: "22:00",
      end: "07:00",
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      critical_breaks_through: true,
    },
  );
  return (
    <form
      className="flex flex-wrap items-end gap-3 py-2"
      onSubmit={(e) => {
        e.preventDefault();
        onSave({
          min_severity: min as "critical" | "warning" | "info",
          quiet_hours: on ? q : null,
          only_tag: tag.trim() || null,
        });
      }}
    >
      <Field label="Receives">
        <Select value={min} onChange={(e) => setMin(e.target.value)}>
          <option value="info">Everything</option>
          <option value="warning">Warning and critical</option>
          <option value="critical">Critical only</option>
        </Select>
      </Field>
      <Field
        label="Only for servers tagged"
        hint="A customer's tag: they get alerts for their own servers and devices only."
      >
        <Input
          className="w-48"
          value={tag}
          placeholder="Everything"
          onChange={(e) => setTag(e.target.value)}
        />
      </Field>
      <label className="flex h-9 items-center gap-2 text-sm">
        <input type="checkbox" checked={on} onChange={(e) => setOn(e.target.checked)} /> Quiet hours
      </label>
      {on && (
        <>
          <Field label="From">
            <Input
              type="time"
              value={q.start}
              onChange={(e) => setQ({ ...q, start: e.target.value })}
            />
          </Field>
          <Field label="To">
            <Input
              type="time"
              value={q.end}
              onChange={(e) => setQ({ ...q, end: e.target.value })}
            />
          </Field>
          <label className="flex h-9 items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={q.critical_breaks_through ?? true}
              onChange={(e) => setQ({ ...q, critical_breaks_through: e.target.checked })}
            />{" "}
            Critical alerts still come through
          </label>
        </>
      )}
      <Button type="submit" variant="primary">
        Save
      </Button>
    </form>
  );
}
