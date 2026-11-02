export function ago(input: string | number | null | undefined): string {
  if (input == null) return "never";
  const t = typeof input === "number" ? input * 1000 : Date.parse(input);
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

export function bytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function dateTime(input: string | null | undefined): string {
  if (!input) return "—";
  return new Date(input).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export const RANGES = [
  { key: "15m", label: "15m", seconds: 900 },
  { key: "1h", label: "1h", seconds: 3600 },
  { key: "6h", label: "6h", seconds: 21600 },
  { key: "24h", label: "24h", seconds: 86400 },
  { key: "7d", label: "7d", seconds: 604800 },
] as const;

export type Range = { start: number; end: number; key: string };

/** A step that gives a chart a few hundred points. */
export function stepFor(seconds: number): number {
  return Math.max(15, Math.ceil(seconds / 300 / 15) * 15);
}
