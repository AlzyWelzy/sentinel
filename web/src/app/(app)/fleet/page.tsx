"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRef } from "react";

import { Button, ErrorState, Loading, PageHeader, cx } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { ago } from "@/lib/format";
import { unwrap } from "@/lib/queries";

const TILE: Record<string, string> = {
  down: "border-bad bg-bad/15 text-bad",
  critical: "border-bad bg-bad/10 text-bad",
  warning: "border-warn bg-warn/10 text-warn",
  maintenance: "border-brand/50 bg-brand/10 text-brand",
  paused: "border-line bg-panel-2 text-ink-3",
  pending: "border-line bg-panel-2 text-ink-3",
  up: "border-ok/40 bg-ok/10 text-ok",
};

/** Every server and check as a tile, worst first, refreshed every 15
 * seconds: for a screen on the wall. */
export default function FleetWallPage() {
  const ref = useRef<HTMLDivElement>(null);
  const wall = useQuery({
    queryKey: ["fleet-wall"],
    refetchInterval: 15_000,
    queryFn: async () => unwrap(await api.GET("/v1/fleet/wall")),
  });
  if (wall.isLoading) return <Loading />;
  if (wall.error)
    return <ErrorState message={errorText(wall.error)} retry={() => wall.refetch()} />;
  const w = wall.data!;
  const counts = w.counts as Record<string, number>;
  return (
    <div ref={ref} className="bg-bg">
      <PageHeader
        title="Fleet wall"
        subtitle={`Updated ${ago(w.generated_at)} · refreshes every 15 seconds`}
        actions={<Button onClick={() => ref.current?.requestFullscreen?.()}>TV mode</Button>}
      />
      <div className="mb-4 flex flex-wrap gap-3 text-sm">
        {Object.entries(counts).map(([k, v]) => (
          <span key={k} className="text-ink-2">
            <b className="tabular text-ink">{v}</b> {k}
          </span>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8">
        {w.tiles.map((t) => (
          <Link
            key={`${t.kind}-${t.id}`}
            href={t.kind === "server" ? `/servers/${t.id}` : "/checks"}
            className={cx(
              "rounded-lg border p-3 transition hover:opacity-80",
              TILE[t.status] ?? TILE.pending,
            )}
          >
            <p className="truncate font-semibold text-ink">{t.name}</p>
            <p className="mt-0.5 text-xs font-medium">{t.status}</p>
            {t.reason && <p className="mt-1 line-clamp-2 text-xs text-ink-2">{t.reason}</p>}
          </Link>
        ))}
      </div>
    </div>
  );
}
