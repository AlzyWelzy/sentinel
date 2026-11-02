"use client";

import { useEffect, useRef } from "react";
import uPlot, { type AlignedData, type Options } from "uplot";
import "uplot/dist/uPlot.min.css";

import { bytes } from "@/lib/format";

export type SeriesIn = { labels: Record<string, string>; points: [number, number][] };

// A palette that reads on both themes.
const COLORS = [
  "#8b70ff",
  "#22d3ee",
  "#f59e0b",
  "#f472b6",
  "#34d399",
  "#60a5fa",
  "#c084fc",
  "#fb7185",
];

function seriesName(labels: Record<string, string>, fallback: string): string {
  const v = Object.values(labels);
  return v.length ? v.join(" · ") : fallback;
}

/** Many series with their own timestamps, aligned on one x axis. */
function align(series: SeriesIn[]): AlignedData {
  const xs = Array.from(new Set(series.flatMap((s) => s.points.map((p) => p[0])))).sort(
    (a, b) => a - b,
  );
  const index = new Map(xs.map((x, i) => [x, i]));
  const ys = series.map((s) => {
    const row: (number | null)[] = new Array(xs.length).fill(null);
    for (const [t, v] of s.points) row[index.get(t)!] = v;
    return row;
  });
  return [xs, ...ys] as AlignedData;
}

function formatValue(unit: string, v: number | null): string {
  if (v == null) return "—";
  if (unit === "percent") return `${v.toFixed(1)}%`;
  if (unit === "bytes") return bytes(v);
  if (unit === "bytes_per_second") return `${bytes(v)}/s`;
  if (unit === "seconds") return `${(v * 1000).toFixed(0)} ms`;
  return Math.abs(v) >= 100 ? v.toFixed(0) : v.toFixed(2);
}

export function TimeChart({
  series,
  unit,
  height = 200,
  fallbackName = "value",
  range,
}: {
  series: SeriesIn[];
  unit: string;
  height?: number;
  fallbackName?: string;
  range?: { start: number; end: number };
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const dark = document.documentElement.classList.contains("dark");
    const grid = dark ? "#1a1e2c" : "#ececf3";
    const axis = dark ? "#6a7089" : "#8a8ea3";
    const opts: Options = {
      width: el.clientWidth,
      height,
      cursor: { drag: { x: false, y: false }, points: { size: 7, fill: COLORS[0] } },
      legend: { show: series.length > 1 },
      scales: {
        x: { time: true, ...(range ? { min: range.start, max: range.end } : {}) },
        y: unit === "percent" ? { range: [0, 100] } : { range: (_u, _min, max) => [0, max || 1] },
      },
      axes: [
        { stroke: axis, grid: { stroke: grid, width: 1 }, ticks: { show: false } },
        {
          stroke: axis,
          grid: { stroke: grid, width: 1 },
          ticks: { show: false },
          size: 64,
          values: (_u, vals) => vals.map((v) => formatValue(unit, v)),
        },
      ],
      series: [
        {},
        ...series.map((s, i) => ({
          label: seriesName(s.labels, fallbackName),
          stroke: COLORS[i % COLORS.length],
          width: 1.75,
          fill:
            series.length === 1
              ? (u: uPlot) => {
                  const g = u.ctx.createLinearGradient(
                    0,
                    u.bbox.top,
                    0,
                    u.bbox.top + u.bbox.height,
                  );
                  g.addColorStop(0, `${COLORS[0]}55`);
                  g.addColorStop(1, `${COLORS[0]}00`);
                  return g;
                }
              : undefined,
          points: { show: false },
          value: (_u: uPlot, v: number | null) => formatValue(unit, v),
        })),
      ],
    };
    const plot = new uPlot(opts, align(series), el);
    const ro = new ResizeObserver(() => plot.setSize({ width: el.clientWidth, height }));
    ro.observe(el);
    return () => {
      ro.disconnect();
      plot.destroy();
    };
  }, [series, unit, height, fallbackName, range]);
  return <div ref={ref} className="w-full" />;
}
