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
import { dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

type Responder = { name: string; channel_ids: string[] };

function localInput(d: Date) {
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

/** Rotations: who's on call now and next, and one-off overrides. Rules page
 * a schedule to reach whoever is on call. */
export default function OncallPage() {
  const qc = useQueryClient();
  const me = useMe();
  const editable = canEdit(me.data?.role);
  const schedules = useQuery({
    queryKey: ["oncall"],
    queryFn: async () => unwrap(await api.GET("/v1/oncall/schedules")),
  });
  const channels = useQuery({
    queryKey: ["channels"],
    queryFn: async () => unwrap(await api.GET("/v1/channels")),
  });
  const [name, setName] = useState("");
  const [hours, setHours] = useState(168);
  const [responders, setResponders] = useState<Responder[]>([{ name: "", channel_ids: [] }]);
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const refresh = () => qc.invalidateQueries({ queryKey: ["oncall"] });
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/oncall/schedules", {
          body: {
            name,
            timezone: tz,
            start_at: new Date().toISOString(),
            shift_hours: hours,
            responders: responders.filter((r) => r.name && r.channel_ids.length),
          },
        }),
      ),
    onSuccess: () => {
      setName("");
      setResponders([{ name: "", channel_ids: [] }]);
      setMsg({ tone: "ok", text: "Schedule created." });
      refresh();
    },
    onError: (e) => setMsg({ tone: "bad", text: errorText(e) }),
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.DELETE("/v1/oncall/schedules/{schedule_id}", {
          params: { path: { schedule_id: id } },
        }),
      ),
    onSuccess: refresh,
    onError: (e) => setMsg({ tone: "bad", text: errorText(e) }),
  });
  const override = useMutation({
    mutationFn: async ([id, who, from, to]: [string, Responder, string, string]) =>
      unwrap(
        await api.POST("/v1/oncall/schedules/{schedule_id}/overrides", {
          params: { path: { schedule_id: id } },
          body: {
            responder: who,
            starts_at: new Date(from).toISOString(),
            ends_at: new Date(to).toISOString(),
          },
        }),
      ),
    onSuccess: () => {
      setMsg({ tone: "ok", text: "Override added." });
      refresh();
    },
    onError: (e) => setMsg({ tone: "bad", text: errorText(e) }),
  });
  const contactName = (id: string) =>
    channels.data?.find((c) => c.id === id)?.label ??
    channels.data?.find((c) => c.id === id)?.target ??
    "contact";

  return (
    <>
      <PageHeader
        title="On-call"
        subtitle="Rotations that rules can page: whoever is on call gets the alert."
      />
      {msg && (
        <div className="mb-4">
          <Notice tone={msg.tone}>{msg.text}</Notice>
        </div>
      )}
      {editable && (
        <Card title="New rotation" className="mb-6">
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Name">
                <Input
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Primary"
                />
              </Field>
              <Field label="Hand over every" hint={`Starting now, in ${tz}.`}>
                <Select
                  value={hours}
                  onChange={(e) => setHours(Number(e.target.value))}
                  className="w-full"
                >
                  <option value={24}>Day</option>
                  <option value={168}>Week</option>
                  <option value={336}>Two weeks</option>
                </Select>
              </Field>
            </div>
            <div className="space-y-2">
              <p className="text-sm font-medium">Responders, in order</p>
              {responders.map((r, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <Input
                    value={r.name}
                    placeholder={`Person ${i + 1}`}
                    onChange={(e) =>
                      setResponders(
                        responders.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)),
                      )
                    }
                    className="max-w-48"
                    aria-label={`Responder ${i + 1} name`}
                  />
                  {channels.data
                    ?.filter((c) => c.verified)
                    .map((c) => (
                      <label key={c.id} className="flex items-center gap-1 text-sm">
                        <input
                          type="checkbox"
                          checked={r.channel_ids.includes(c.id)}
                          onChange={(e) =>
                            setResponders(
                              responders.map((x, j) =>
                                j === i
                                  ? {
                                      ...x,
                                      channel_ids: e.target.checked
                                        ? [...x.channel_ids, c.id]
                                        : x.channel_ids.filter((y) => y !== c.id),
                                    }
                                  : x,
                              ),
                            )
                          }
                        />
                        {c.label ?? c.target}
                      </label>
                    ))}
                </div>
              ))}
              <Button
                type="button"
                variant="ghost"
                onClick={() => setResponders([...responders, { name: "", channel_ids: [] }])}
              >
                Add responder
              </Button>
            </div>
            <Button type="submit" variant="primary" loading={create.isPending}>
              Create rotation
            </Button>
          </form>
        </Card>
      )}
      {schedules.isLoading ? (
        <Loading />
      ) : schedules.error ? (
        <ErrorState message={errorText(schedules.error)} />
      ) : !schedules.data?.length ? (
        <Card>
          <Empty title="No rotations">
            Create one, then choose it under Notify on an alert rule.
          </Empty>
        </Card>
      ) : (
        <div className="space-y-6">
          {schedules.data.map((s) => (
            <Schedule
              key={s.id}
              s={s}
              editable={editable}
              contactName={contactName}
              onDelete={() => confirm(`Delete ${s.name}?`) && remove.mutate(s.id)}
              onOverride={(who, from, to) => override.mutate([s.id, who, from, to])}
            />
          ))}
        </div>
      )}
    </>
  );
}

function Schedule({
  s,
  editable,
  contactName,
  onDelete,
  onOverride,
}: {
  s: {
    id: string;
    name: string;
    timezone: string;
    shift_hours: number;
    responders: Record<string, unknown>[];
    on_call?: Record<string, unknown> | null;
    next_on_call?: Record<string, unknown> | null;
    next_handoff?: string | null;
    used_by_rules: number;
    overrides: { id: string; starts_at: string; ends_at: string; responder: Responder }[];
  };
  editable: boolean;
  contactName: (id: string) => string;
  onDelete: () => void;
  onOverride: (who: Responder, from: string, to: string) => void;
}) {
  const people = s.responders as unknown as Responder[];
  const [who, setWho] = useState(0);
  const [from, setFrom] = useState(() => localInput(new Date()));
  const [to, setTo] = useState(() => localInput(new Date(Date.now() + 8 * 3600_000)));
  const now = s.on_call as Responder | null | undefined;
  const next = s.next_on_call as Responder | null | undefined;
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          {s.name} <Badge>{s.used_by_rules} rules</Badge>
        </span>
      }
      actions={
        editable && (
          <Button variant="ghost" onClick={onDelete}>
            Delete
          </Button>
        )
      }
    >
      <div className="grid gap-4 sm:grid-cols-3">
        <div>
          <p className="text-xs text-ink-3">On call now</p>
          <p className="font-medium">{now?.name ?? "nobody"}</p>
        </div>
        <div>
          <p className="text-xs text-ink-3">Next</p>
          <p className="font-medium">{next?.name ?? "—"}</p>
        </div>
        <div>
          <p className="text-xs text-ink-3">Hand-over</p>
          <p>
            {dateTime(s.next_handoff)} ({s.timezone})
          </p>
        </div>
      </div>
      <Table>
        <tbody>
          {people.map((p, i) => (
            <tr key={i}>
              <td className="font-medium">
                {i + 1}. {p.name}
              </td>
              <td className="text-ink-2">{p.channel_ids.map(contactName).join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </Table>
      {s.overrides.length > 0 && (
        <p className="mt-3 text-sm text-ink-2">
          Overrides:{" "}
          {s.overrides
            .map((o) => `${o.responder.name} ${dateTime(o.starts_at)} – ${dateTime(o.ends_at)}`)
            .join("; ")}
        </p>
      )}
      {editable && people.length > 0 && (
        <form
          className="mt-4 flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            onOverride(people[who]!, from, to);
          }}
        >
          <Field label="Cover with">
            <Select value={who} onChange={(e) => setWho(Number(e.target.value))}>
              {people.map((p, i) => (
                <option key={i} value={i}>
                  {p.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="From">
            <Input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
          </Field>
          <Field label="Until">
            <Input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
          </Field>
          <Button type="submit">Add override</Button>
        </form>
      )}
    </Card>
  );
}
