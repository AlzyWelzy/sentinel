"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import {
  Button,
  Card,
  CopyBlock,
  Field,
  Input,
  Notice,
  PageHeader,
  Spinner,
  cx,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";
import { unwrap, useHosts } from "@/lib/queries";
import { orgName, useMe } from "@/lib/session";

type Key = components["schemas"]["AgentKeyCreated"];
const PLATFORMS = ["Linux / BSD", "Windows", "Docker", "cloud-init"] as const;

/** Onboarding: name the organisation, install the agent, wait for the server. */
export default function WelcomePage() {
  const qc = useQueryClient();
  const me = useMe();
  const hosts = useHosts();
  const [name, setName] = useState<string | null>(null);
  const [key, setKey] = useState<Key | null>(null);
  const [platform, setPlatform] = useState<(typeof PLATFORMS)[number]>("Linux / BSD");

  // The servers there were when the page opened: a new one is the arrival.
  const [before, setBefore] = useState<Set<string> | null>(null);
  if (hosts.data && before === null) setBefore(new Set(hosts.data.map((h) => h.id)));

  const draftName = name ?? me.data?.display_name ?? "";
  const rename = useMutation({
    mutationFn: async () =>
      unwrap(await api.PATCH("/v1/organisation", { body: { name: draftName } })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["me"] });
      qc.invalidateQueries({ queryKey: ["accounts"] });
    },
  });
  const makeKey = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/agent-keys", { body: { name: "First server", tags: [] } })),
    onSuccess: setKey,
  });
  const arrived = before ? (hosts.data?.find((h) => !before.has(h.id)) ?? null) : null;
  const canManage = me.data?.role === "owner" || me.data?.role === "admin";

  const command =
    key &&
    {
      "Linux / BSD": key.install_command,
      Windows: key.install_command_windows,
      Docker: key.docker_command,
      "cloud-init": key.cloud_init,
    }[platform];

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="Add a server" subtitle="Three steps, about two minutes." />
      <div className="space-y-6">
        {canManage && (
          <Card title="1 · Name your organisation">
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                rename.mutate();
              }}
            >
              <div className="min-w-64 flex-1">
                <Field label="Organisation name">
                  <Input
                    required
                    value={draftName}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Acme Inc"
                  />
                </Field>
              </div>
              <Button type="submit" loading={rename.isPending}>
                {rename.isSuccess ? "Saved" : "Save"}
              </Button>
            </form>
            {me.data && <p className="mt-2 text-xs text-ink-3">Currently: {orgName(me.data)}</p>}
          </Card>
        )}

        <Card title="2 · Install the agent">
          {!key ? (
            <div className="space-y-3">
              <p className="text-sm text-ink-2">
                The agent runs unprivileged, buffers data on disk if the network drops, and updates
                itself. It needs an install key; the key is shown once.
              </p>
              {makeKey.error && <Notice tone="bad">{errorText(makeKey.error)}</Notice>}
              <Button
                variant="primary"
                onClick={() => makeKey.mutate()}
                loading={makeKey.isPending}
              >
                Create install key
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="inline-flex rounded-lg border border-line p-0.5">
                {PLATFORMS.map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setPlatform(p)}
                    className={cx(
                      "rounded-md px-3 py-1 text-sm",
                      platform === p ? "bg-panel-2 font-medium" : "text-ink-3",
                    )}
                  >
                    {p}
                  </button>
                ))}
              </div>
              <p className="text-sm text-ink-2">
                {platform === "Windows"
                  ? "Run in an elevated PowerShell:"
                  : platform === "cloud-init"
                    ? "Add to a new server's user data:"
                    : platform === "Docker"
                      ? "Run on the host:"
                      : "Run on the server as root:"}
              </p>
              {command && <CopyBlock text={command} />}
              <p className="text-xs text-ink-3">
                Install key <span className="font-mono">{key.key_prefix}…</span> is saved. Revoke it
                under Settings when you&apos;ve added your servers.
              </p>
            </div>
          )}
        </Card>

        <Card title="3 · Wait for it to report">
          {arrived ? (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-sm">
                <span className="font-medium text-ok">{arrived.hostname}</span> is reporting.
              </p>
              <Link href={`/servers/${arrived.id}`} className="text-sm font-medium text-brand">
                Open it
              </Link>
            </div>
          ) : (
            <div className="flex items-center gap-3 text-sm text-ink-2">
              <Spinner /> Waiting for the first push. This page updates on its own.
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
