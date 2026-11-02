import { Badge, Dot, type Tone } from "@/components/ui";

export const STATUS_TONE: Record<string, Tone> = {
  up: "ok",
  healthy: "ok",
  warning: "warn",
  critical: "bad",
  down: "bad",
  offline: "bad",
  maintenance: "brand",
  paused: "idle",
  unknown: "idle",
};

export const STATUS_LABEL: Record<string, string> = {
  up: "Healthy",
  warning: "Warning",
  critical: "Critical",
  down: "Offline",
  maintenance: "Maintenance",
  paused: "Paused",
  unknown: "Unknown",
};

export function StatusBadge({ status }: { status: string }) {
  const tone = STATUS_TONE[status] ?? "idle";
  return (
    <Badge tone={tone}>
      <Dot tone={tone} />
      {STATUS_LABEL[status] ?? status}
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const tone: Tone = severity === "critical" ? "bad" : severity === "warning" ? "warn" : "brand";
  return <Badge tone={tone}>{severity}</Badge>;
}
