"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useState } from "react";

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
  Table,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { unwrap, useHosts } from "@/lib/queries";
import { canEdit, useMe } from "@/lib/session";

import { PageExtras } from "./PageExtras";

export default function StatusPagesPage() {
  const qc = useQueryClient();
  const me = useMe();
  const editable = canEdit(me.data?.role);
  const hosts = useHosts();
  const checks = useQuery({
    queryKey: ["checks"],
    queryFn: async () => unwrap(await api.GET("/v1/checks")),
  });
  const pages = useQuery({
    queryKey: ["status-pages"],
    queryFn: async () => unwrap(await api.GET("/v1/status-pages")),
  });
  const [title, setTitle] = useState("");
  const [slug, setSlug] = useState("");
  const [items, setItems] = useState<
    Record<string, { label: string; host_id?: string; check_id?: string }>
  >({});
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/status-pages", {
          body: {
            title,
            slug,
            published: true,
            show_values: true,
            items: Object.values(items).map((i) => ({
              label: i.label,
              host_id: i.host_id ?? null,
              check_id: i.check_id ?? null,
            })),
          },
        }),
      ),
    onSuccess: () => {
      setTitle("");
      setSlug("");
      setItems({});
      setError(null);
      qc.invalidateQueries({ queryKey: ["status-pages"] });
    },
    onError: (e) => setError(errorText(e)),
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(await api.DELETE("/v1/status-pages/{page_id}", { params: { path: { page_id: id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["status-pages"] }),
  });
  const toggle = (key: string, item: { label: string; host_id?: string; check_id?: string }) =>
    setItems((cur) => {
      const next = { ...cur };
      if (next[key]) delete next[key];
      else next[key] = item;
      return next;
    });

  return (
    <>
      <PageHeader
        title="Status pages"
        subtitle="Public pages that show your customers what's up. They never show hostnames or addresses, only your labels."
      />
      {editable && (
        <Card title="New status page" className="mb-6">
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Title">
                <Input
                  required
                  value={title}
                  onChange={(e) => {
                    setTitle(e.target.value);
                    setSlug(
                      e.target.value
                        .toLowerCase()
                        .replace(/[^a-z0-9]+/g, "-")
                        .replace(/^-|-$/g, ""),
                    );
                  }}
                  placeholder="Acme status"
                />
              </Field>
              <Field
                label="Address"
                hint={`${typeof location === "undefined" ? "" : location.origin}/status/${slug || "…"}`}
              >
                <Input
                  required
                  value={slug}
                  onChange={(e) => setSlug(e.target.value)}
                  pattern="[a-z0-9][a-z0-9\-]{2,62}"
                />
              </Field>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <p className="mb-2 text-sm font-medium">Servers</p>
                <div className="max-h-48 space-y-1 overflow-y-auto">
                  {hosts.data?.map((h) => (
                    <label key={h.id} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={!!items[`h:${h.id}`]}
                        onChange={() =>
                          toggle(`h:${h.id}`, {
                            label: `Server ${Object.keys(items).filter((k) => k.startsWith("h:")).length + 1}`,
                            host_id: h.id,
                          })
                        }
                      />{" "}
                      {h.hostname}
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <p className="mb-2 text-sm font-medium">Checks</p>
                <div className="max-h-48 space-y-1 overflow-y-auto">
                  {checks.data?.map((c) => (
                    <label key={c.id} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={!!items[`c:${c.id}`]}
                        onChange={() => toggle(`c:${c.id}`, { label: c.name, check_id: c.id })}
                      />{" "}
                      {c.name}
                    </label>
                  ))}
                </div>
              </div>
            </div>
            {Object.keys(items).length > 0 && (
              <div className="space-y-2">
                <p className="text-sm font-medium">Labels shown publicly</p>
                <p className="text-xs text-ink-3">
                  The public page shows only these names, never hostnames or addresses.
                </p>
                {Object.entries(items).map(([k, i]) => (
                  <Input
                    key={k}
                    value={i.label}
                    onChange={(e) => setItems({ ...items, [k]: { ...i, label: e.target.value } })}
                  />
                ))}
              </div>
            )}
            {error && <Notice tone="bad">{error}</Notice>}
            <Button type="submit" variant="primary" loading={create.isPending}>
              Publish
            </Button>
          </form>
        </Card>
      )}
      <Card pad={false}>
        {pages.isLoading ? (
          <Loading />
        ) : pages.error ? (
          <ErrorState message={errorText(pages.error)} />
        ) : !pages.data?.length ? (
          <Empty title="No status pages" />
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Page</th>
                <th>Shows</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {pages.data.map((p) => (
                <Fragment key={p.id}>
                  <tr>
                    <td>
                      <a
                        href={`/status/${p.slug}`}
                        target="_blank"
                        rel="noreferrer"
                        className="font-medium hover:text-brand"
                      >
                        {p.title}
                      </a>
                      <p className="text-xs text-ink-3">
                        {p.domain?.verified ? p.domain.domain : `/status/${p.slug}`}
                      </p>
                    </td>
                    <td className="text-ink-2">{p.items.length} items</td>
                    <td>{p.published ? <Badge tone="ok">public</Badge> : <Badge>draft</Badge>}</td>
                    <td className="whitespace-nowrap text-right">
                      <Button variant="ghost" onClick={() => setOpen(open === p.id ? null : p.id)}>
                        Domain and badges
                      </Button>
                      {editable && (
                        <Button
                          variant="ghost"
                          onClick={() => confirm(`Delete ${p.title}?`) && remove.mutate(p.id)}
                        >
                          Delete
                        </Button>
                      )}
                    </td>
                  </tr>
                  {open === p.id && (
                    <tr>
                      <td colSpan={4}>
                        <PageExtras page={p} editable={editable} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
