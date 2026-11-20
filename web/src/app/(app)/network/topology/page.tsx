"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useMemo } from "react";

import { NetworkTabs } from "@/components/network-tabs";
import { Card, Empty, ErrorState, Loading, Notice, PageHeader } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { unwrap } from "@/lib/queries";

const W = 168;
const H = 44;
const GAP_X = 24;
const GAP_Y = 72;

type Node = {
  id: string;
  hostname: string;
  kind: string;
  network_role: string | null;
  online: boolean;
  parent_id: string | null;
  parent_auto: boolean;
  parent_via?: "lldp" | "manual" | "poller" | null;
};

/** Layers by upstream depth (core and anything without an upstream on top),
 * each layer ordered under its parents so lines cross less. */
function layout(nodes: Node[]) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const depth = new Map<string, number>();
  const depthOf = (n: Node, seen = new Set<string>()): number => {
    if (depth.has(n.id)) return depth.get(n.id)!;
    const parent = n.parent_id ? byId.get(n.parent_id) : undefined;
    const d = parent && !seen.has(parent.id) ? depthOf(parent, new Set([...seen, n.id])) + 1 : 0;
    depth.set(n.id, d);
    return d;
  };
  nodes.forEach((n) => depthOf(n));
  const layers: Node[][] = [];
  for (const n of nodes) (layers[depth.get(n.id)!] ??= []).push(n);
  const x = new Map<string, number>();
  layers.forEach((layer, i) => {
    layer.sort((a, b) => {
      const pa = a.parent_id ? (x.get(a.parent_id) ?? 0) : 0;
      const pb = b.parent_id ? (x.get(b.parent_id) ?? 0) : 0;
      return pa - pb || a.hostname.localeCompare(b.hostname);
    });
    layer.forEach((n, j) => x.set(n.id, j));
    void i;
  });
  const width = Math.max(...layers.map((l) => l.length), 1) * (W + GAP_X);
  const pos = new Map<string, { x: number; y: number }>();
  layers.forEach((layer, i) => {
    const offset = (width - layer.length * (W + GAP_X)) / 2;
    layer.forEach((n, j) =>
      pos.set(n.id, { x: offset + j * (W + GAP_X) + GAP_X / 2, y: 16 + i * (H + GAP_Y) }),
    );
  });
  return { pos, width, height: layers.length * (H + GAP_Y) + 16 };
}

export default function TopologyPage() {
  const topo = useQuery({
    queryKey: ["network", "topology"],
    refetchInterval: 30_000,
    queryFn: async () => unwrap(await api.GET("/v1/network/topology")),
  });
  const data = topo.data;
  const map = useMemo(() => (data ? layout(data.nodes as Node[]) : null), [data]);
  if (topo.isLoading) return <Loading />;
  if (topo.error)
    return <ErrorState message={errorText(topo.error)} retry={() => topo.refetch()} />;
  const devices = data!.nodes.filter((n) => n.kind === "network");
  return (
    <>
      <PageHeader
        title="Network"
        subtitle="How devices connect, from LLDP, and what each one depends on"
      />
      <NetworkTabs />
      {!devices.length ? (
        <Empty title="Nothing to map yet">
          Add network devices with LLDP turned on to see how they connect.
        </Empty>
      ) : (
        <>
          {!data!.has_core && (
            <div className="mb-4">
              <Notice tone="warn">
                Mark your core switch(es) with the role Core (on the device&apos;s page). Upstreams
                are worked out from LLDP toward them, so when a switch fails, the devices behind it
                are shown as affected instead of each alerting.
              </Notice>
            </div>
          )}
          <Card pad={false}>
            <div className="max-w-full overflow-auto">
              <svg
                width={map!.width}
                height={map!.height}
                role="img"
                aria-label="Network topology"
                className="block min-w-full"
              >
                {data!.edges.map((e) => {
                  const a = map!.pos.get(e.source);
                  const b = map!.pos.get(e.target);
                  if (!a || !b) return null;
                  return (
                    <line
                      key={`${e.source}-${e.target}`}
                      x1={a.x + W / 2}
                      y1={a.y + H / 2}
                      x2={b.x + W / 2}
                      y2={b.y + H / 2}
                      className="stroke-line-2"
                      strokeWidth={1.5}
                    >
                      <title>
                        {e.source_port} ↔ {e.target_port}
                      </title>
                    </line>
                  );
                })}
                {(data!.nodes as Node[]).map((n) => {
                  const p = map!.pos.get(n.id)!;
                  const parent = n.parent_id ? map!.pos.get(n.parent_id) : undefined;
                  return (
                    <g key={n.id}>
                      {parent && (
                        <line
                          x1={p.x + W / 2}
                          y1={p.y}
                          x2={parent.x + W / 2}
                          y2={parent.y + H}
                          className="stroke-brand"
                          strokeWidth={2}
                          strokeDasharray={n.parent_auto ? undefined : "4 3"}
                        >
                          <title>
                            {n.parent_auto ? "Upstream from LLDP" : "Upstream set by hand"}
                          </title>
                        </line>
                      )}
                      <Link href={n.kind === "network" ? `/network/${n.id}` : `/servers/${n.id}`}>
                        <rect
                          x={p.x}
                          y={p.y}
                          width={W}
                          height={H}
                          rx={10}
                          className={`fill-panel ${n.online ? "stroke-ok" : "stroke-bad"}`}
                          strokeWidth={1.5}
                        />
                        <text
                          x={p.x + 12}
                          y={p.y + 19}
                          className="fill-ink text-[12px] font-medium"
                        >
                          {n.hostname.length > 22 ? `${n.hostname.slice(0, 21)}…` : n.hostname}
                        </text>
                        <text x={p.x + 12} y={p.y + 34} className="fill-ink-3 text-[11px]">
                          {n.kind === "network" ? (n.network_role ?? "device") : "server"}
                          {n.online ? "" : " · down"}
                        </text>
                      </Link>
                    </g>
                  );
                })}
              </svg>
            </div>
          </Card>
          <p className="mt-3 text-xs text-ink-3">
            Grey lines are LLDP links. Violet lines point to each device&apos;s upstream (dashed
            when set by hand). A device without an upstream of its own depends on the server that
            polls it.
          </p>
        </>
      )}
    </>
  );
}
