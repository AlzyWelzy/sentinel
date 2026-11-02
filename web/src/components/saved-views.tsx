"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Button, Select } from "@/components/ui";
import { api } from "@/lib/api/client";
import { unwrap } from "@/lib/queries";

type Kind = "logs" | "servers" | "incidents" | "checks";

/** Named filters for a list, shared with the organisation. */
export function SavedViews({
  kind,
  params,
  onApply,
}: {
  kind: Kind;
  params: Record<string, string>;
  onApply: (params: Record<string, string>) => void;
}) {
  const qc = useQueryClient();
  const [current, setCurrent] = useState("");
  const views = useQuery({
    queryKey: ["saved-views", kind],
    queryFn: async () => unwrap(await api.GET("/v1/saved-views", { params: { query: { kind } } })),
  });
  const save = useMutation({
    mutationFn: async (name: string) =>
      unwrap(await api.POST("/v1/saved-views", { body: { kind, name, params } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saved-views", kind] }),
  });
  const remove = useMutation({
    mutationFn: async (id: string) =>
      unwrap(await api.DELETE("/v1/saved-views/{view_id}", { params: { path: { view_id: id } } })),
    onSuccess: () => {
      setCurrent("");
      qc.invalidateQueries({ queryKey: ["saved-views", kind] });
    },
  });
  const list = views.data ?? [];
  return (
    <div className="flex items-center gap-2">
      {list.length > 0 && (
        <Select
          aria-label="Saved views"
          value={current}
          onChange={(e) => {
            const v = list.find((x) => x.id === e.target.value);
            setCurrent(v?.id ?? "");
            if (v) onApply(v.params as Record<string, string>);
          }}
        >
          <option value="">Saved views…</option>
          {list.map((v) => (
            <option key={v.id} value={v.id}>
              {v.name}
            </option>
          ))}
        </Select>
      )}
      <Button
        variant="ghost"
        onClick={() => {
          const name = prompt("Name this view");
          if (name?.trim()) save.mutate(name.trim());
        }}
      >
        Save view
      </Button>
      {current && (
        <Button variant="ghost" onClick={() => remove.mutate(current)}>
          Delete this view
        </Button>
      )}
    </div>
  );
}
