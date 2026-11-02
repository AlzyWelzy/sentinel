"use client";

import { useState } from "react";

import { Button, Input, cx } from "@/components/ui";
import { RANGES, type Range } from "@/lib/format";

export function presetRange(key: string): Range {
  const preset = RANGES.find((r) => r.key === key) ?? RANGES[1];
  const end = Math.floor(Date.now() / 1000);
  return { key: preset.key, start: end - preset.seconds, end };
}

function toLocalInput(unix: number) {
  const d = new Date(unix * 1000);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

/** 15m · 1h · 6h · 24h · 7d, or a custom start and end. */
export function RangePicker({ value, onChange }: { value: Range; onChange: (r: Range) => void }) {
  const [custom, setCustom] = useState(false);
  const [from, setFrom] = useState(toLocalInput(value.start));
  const [to, setTo] = useState(toLocalInput(value.end));
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="inline-flex rounded-lg border border-line bg-panel p-0.5">
        {RANGES.map((r) => (
          <button
            key={r.key}
            type="button"
            onClick={() => {
              setCustom(false);
              onChange(presetRange(r.key));
            }}
            className={cx(
              "rounded-md px-2.5 py-1 text-xs font-medium",
              value.key === r.key ? "bg-panel-2 text-ink" : "text-ink-3 hover:text-ink",
            )}
          >
            {r.label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => setCustom((c) => !c)}
          className={cx(
            "rounded-md px-2.5 py-1 text-xs font-medium",
            value.key === "custom" ? "bg-panel-2 text-ink" : "text-ink-3 hover:text-ink",
          )}
        >
          Custom
        </button>
      </div>
      {custom && (
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const start = Math.floor(new Date(from).getTime() / 1000);
            const end = Math.floor(new Date(to).getTime() / 1000);
            if (start < end) onChange({ key: "custom", start, end });
          }}
        >
          <Input
            type="datetime-local"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="w-auto"
          />
          <span className="text-ink-3">to</span>
          <Input
            type="datetime-local"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="w-auto"
          />
          <Button type="submit">Apply</Button>
        </form>
      )}
    </div>
  );
}
