"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { QRCodeSVG } from "qrcode.react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  Field,
  Input,
  Loading,
  Notice,
  PageHeader,
  Table,
} from "@/components/ui";
import { api, errorText, setSession } from "@/lib/api/client";
import { ago, dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";

export default function AccountPage() {
  const qc = useQueryClient();
  const router = useRouter();
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  const user = useQuery({
    queryKey: ["auth-me"],
    queryFn: async () => unwrap(await api.GET("/auth/me")),
  });
  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: async () => unwrap(await api.GET("/auth/sessions")),
  });
  const [name, setName] = useState<string | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [disablePw, setDisablePw] = useState("");
  const ok = (text: string) => {
    setMsg({ tone: "ok", text });
    qc.invalidateQueries({ queryKey: ["auth-me"] });
    qc.invalidateQueries({ queryKey: ["sessions"] });
  };
  const fail = (e: unknown) => setMsg({ tone: "bad", text: errorText(e) });

  const profile = useMutation({
    mutationFn: async () =>
      unwrap(await api.PATCH("/auth/me", { body: { name: name ?? user.data?.name ?? null } })),
    onSuccess: () => ok("Saved."),
    onError: fail,
  });
  const password = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/auth/password/change", {
          body: { current_password: current, new_password: next },
        }),
      ),
    onSuccess: () => {
      setSession(null);
      router.replace("/login?reset=1");
    },
    onError: fail,
  });
  const startTotp = useMutation({
    mutationFn: async () => unwrap(await api.POST("/auth/totp/setup")),
    onSuccess: setSetup,
    onError: fail,
  });
  const enableTotp = useMutation({
    mutationFn: async () => unwrap(await api.POST("/auth/totp/enable", { body: { code } })),
    onSuccess: () => {
      setSetup(null);
      setCode("");
      ok("Two-factor sign-in is on.");
    },
    onError: fail,
  });
  const disableTotp = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/auth/totp/disable", { body: { password: disablePw, code } })),
    onSuccess: () => {
      setCode("");
      setDisablePw("");
      ok("Two-factor sign-in is off.");
    },
    onError: fail,
  });
  const [deletePw, setDeletePw] = useState("");
  const deleteAccount = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/auth/me/delete", { body: { password: deletePw } })),
    onSuccess: () => {
      setSession(null);
      router.replace("/login");
    },
    onError: fail,
  });
  const revoke = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.DELETE("/auth/sessions/{session_id}", { params: { path: { session_id: id } } }),
      ),
    onSuccess: () => ok("Signed out there."),
    onError: fail,
  });

  if (user.isLoading) return <Loading />;
  const u = user.data!;
  return (
    <>
      <PageHeader title="Your account" subtitle={`${u.email} · since ${dateTime(u.created_at)}`} />
      {msg && (
        <div className="mb-4">
          <Notice tone={msg.tone}>{msg.text}</Notice>
        </div>
      )}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Profile">
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              profile.mutate();
            }}
          >
            <Field label="Name">
              <Input value={name ?? u.name ?? ""} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Button type="submit" loading={profile.isPending}>
              Save
            </Button>
          </form>
        </Card>
        <Card title="Password">
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              password.mutate();
            }}
          >
            <Field label="Current password">
              <Input
                type="password"
                autoComplete="current-password"
                required
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
              />
            </Field>
            <Field label="New password" hint="At least 10 characters. Every browser is signed out.">
              <Input
                type="password"
                autoComplete="new-password"
                required
                value={next}
                onChange={(e) => setNext(e.target.value)}
              />
            </Field>
            <Button type="submit" loading={password.isPending}>
              Change password
            </Button>
          </form>
        </Card>
        <Card
          title={
            <span className="flex items-center gap-2">
              Two-factor sign-in {u.totp_enabled ? <Badge tone="ok">on</Badge> : <Badge>off</Badge>}
            </span>
          }
        >
          {u.totp_enabled ? (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                disableTotp.mutate();
              }}
            >
              <p className="text-sm text-ink-2">
                To turn it off, confirm your password and a current code.
              </p>
              <Field label="Password">
                <Input
                  type="password"
                  required
                  value={disablePw}
                  onChange={(e) => setDisablePw(e.target.value)}
                />
              </Field>
              <Field label="Code">
                <Input
                  inputMode="numeric"
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
              </Field>
              <Button type="submit" variant="danger" loading={disableTotp.isPending}>
                Turn off
              </Button>
            </form>
          ) : setup ? (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                enableTotp.mutate();
              }}
            >
              <p className="text-sm text-ink-2">
                Scan this with an authenticator app, then enter the code it shows.
              </p>
              <div className="inline-block rounded-lg bg-white p-3">
                <QRCodeSVG value={setup.otpauth_uri} size={160} />
              </div>
              <p className="font-mono text-xs break-all text-ink-3">{setup.secret}</p>
              <Field label="Code">
                <Input
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />
              </Field>
              <Button type="submit" variant="primary" loading={enableTotp.isPending}>
                Turn on
              </Button>
            </form>
          ) : (
            <div className="space-y-3">
              <p className="text-sm text-ink-2">
                Ask for a code from an authenticator app at every sign-in.
              </p>
              <Button onClick={() => startTotp.mutate()} loading={startTotp.isPending}>
                Set up
              </Button>
            </div>
          )}
        </Card>
        <Card title="Signed-in browsers" pad={false}>
          {sessions.isLoading ? (
            <Loading />
          ) : (
            <Table>
              <tbody>
                {sessions.data?.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <span className="text-sm">
                        {s.user_agent?.slice(0, 60) || "Unknown browser"}
                      </span>
                      <p className="text-xs text-ink-3">
                        {s.ip ?? "?"} · active {ago(s.last_used_at)}
                      </p>
                    </td>
                    <td className="text-right">
                      {s.current ? (
                        <Badge tone="brand">this one</Badge>
                      ) : (
                        <Button variant="ghost" onClick={() => revoke.mutate(s.id)}>
                          Sign out
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
        <Card title="Delete your account" className="lg:col-span-2">
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (confirm("Delete your account? This can't be undone.")) deleteAccount.mutate();
            }}
          >
            <p className="w-full text-sm text-ink-2">
              Deletes your account, and the organisations only you are in with all their data.
              Organisations with other members must be handed to one of them first.
            </p>
            <div className="min-w-64 flex-1">
              <Field label="Password">
                <Input
                  type="password"
                  required
                  value={deletePw}
                  onChange={(e) => setDeletePw(e.target.value)}
                />
              </Field>
            </div>
            <Button type="submit" variant="danger" loading={deleteAccount.isPending}>
              Delete account
            </Button>
          </form>
        </Card>
      </div>
    </>
  );
}
