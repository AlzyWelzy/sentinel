"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Badge, Button, Field, Input, Notice, Select } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";
import { unwrap } from "@/lib/queries";

type Page = components["schemas"]["PageOut"];

function Copy({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2">
      <code className="min-w-0 flex-1 truncate rounded bg-panel-2 px-2 py-1 font-mono text-xs">
        {text}
      </code>
      <Button variant="ghost" type="button" onClick={() => navigator.clipboard?.writeText(text)}>
        Copy
      </Button>
    </div>
  );
}

// The page's own domain (TXT to prove it, CNAME to serve it) and badges for
// a README or website.
export function PageExtras({ page, editable }: { page: Page; editable: boolean }) {
  const qc = useQueryClient();
  const [domain, setDomain] = useState(page.domain?.domain ?? "");
  const [error, setError] = useState<string | null>(null);
  const [item, setItem] = useState("");
  const [show, setShow] = useState<"status" | "uptime" | "response">("status");
  const [style, setStyle] = useState("flat");
  const done = () => {
    setError(null);
    qc.invalidateQueries({ queryKey: ["status-pages"] });
  };
  const path = { params: { path: { page_id: page.id } } };
  const save = useMutation({
    mutationFn: async (d: string | null) =>
      unwrap(await api.PUT("/v1/status-pages/{page_id}/domain", { ...path, body: { domain: d } })),
    onSuccess: done,
    onError: (e) => setError(errorText(e)),
  });
  const verify = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/status-pages/{page_id}/domain/verify", path)),
    onSuccess: done,
    onError: (e) => setError(errorText(e)),
  });

  const origin = typeof location === "undefined" ? "" : location.origin;
  const q = new URLSearchParams();
  if (item) q.set("item", item);
  if (item && show !== "status") q.set("show", show);
  if (style !== "flat") q.set("style", style);
  const qs = q.toString() ? `?${q}` : "";
  const badge = `${origin}/api/public/status/${page.slug}/badge.svg${qs}`;
  const link = page.domain?.verified
    ? `https://${page.domain.domain}`
    : `${origin}/status/${page.slug}`;
  const d = page.domain;

  return (
    <div className="grid gap-6 py-2 lg:grid-cols-2">
      <div className="space-y-3">
        <p className="text-sm font-medium">Your own domain</p>
        {editable && (
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate(domain.trim() || null);
            }}
          >
            <Input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="status.example.com"
              spellCheck={false}
              autoCapitalize="off"
              aria-label="Domain"
            />
            <Button type="submit" loading={save.isPending}>
              {d ? "Change" : "Set"}
            </Button>
            {d && (
              <Button type="button" variant="ghost" onClick={() => save.mutate(null)}>
                Remove
              </Button>
            )}
          </form>
        )}
        {d && (
          <div className="space-y-2 text-sm">
            <p>
              {d.domain}{" "}
              {d.verified ? (
                <Badge tone="ok">verified</Badge>
              ) : (
                <Badge tone="warn">not verified</Badge>
              )}
            </p>
            {!d.verified && (
              <>
                <p className="text-xs text-ink-2">
                  Add these two DNS records at your DNS provider, then verify. The page and its
                  certificate start working within a minute of verifying.
                </p>
                <Field label={`TXT ${d.txt_name}`}>
                  <Copy text={d.txt_value} />
                </Field>
                <Field label={`CNAME ${d.domain}`}>
                  <Copy text={d.cname} />
                </Field>
                {editable && (
                  <Button onClick={() => verify.mutate()} loading={verify.isPending}>
                    Verify
                  </Button>
                )}
              </>
            )}
          </div>
        )}
        {error && <Notice tone="bad">{error}</Notice>}
      </div>
      <div className="space-y-3">
        <p className="text-sm font-medium">Badge</p>
        <div className="grid grid-cols-3 gap-2">
          <Select value={item} onChange={(e) => setItem(e.target.value)} aria-label="Badge for">
            <option value="">Whole page</option>
            {page.items.map((i) => (
              <option key={i.id} value={i.id}>
                {i.label}
              </option>
            ))}
          </Select>
          <Select
            value={show}
            disabled={!item}
            onChange={(e) => setShow(e.target.value as typeof show)}
            aria-label="Badge shows"
          >
            <option value="status">Status</option>
            <option value="uptime">Uptime (90 days)</option>
            <option value="response">Response time</option>
          </Select>
          <Select value={style} onChange={(e) => setStyle(e.target.value)} aria-label="Badge style">
            <option value="flat">Flat</option>
            <option value="flat-square">Square</option>
            <option value="for-the-badge">Large</option>
          </Select>
        </div>
        {/* eslint-disable-next-line @next/next/no-img-element -- an SVG from our own API */}
        <img src={badge} alt="badge preview" className="h-7" />
        <Field label="Markdown">
          <Copy text={`[![${page.title}](${badge})](${link})`} />
        </Field>
        <Field label="HTML">
          <Copy text={`<a href="${link}"><img src="${badge}" alt="${page.title}"></a>`} />
        </Field>
      </div>
    </div>
  );
}
