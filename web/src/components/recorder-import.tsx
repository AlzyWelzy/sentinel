"use client";

import { useState } from "react";

import { Button } from "@/components/ui";
import { fromRecorder } from "@/lib/recorder";

/** Paste a Chrome DevTools Recorder export (JSON) to fill a browser check. */
export function RecorderImport({
  onImport,
}: {
  onImport: (r: { steps: string; target: string | null; secrets: Record<string, string> }) => void;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [note, setNote] = useState<{ bad: boolean; text: string } | null>(null);
  if (!open)
    return (
      <button
        type="button"
        className="text-brand mt-1 text-xs hover:underline"
        onClick={() => setOpen(true)}
      >
        Import from Chrome Recorder
      </button>
    );
  return (
    <div className="border-line mt-2 space-y-2 rounded-[3px] border p-3">
      <p className="text-ink-3 text-xs">
        In Chrome: DevTools → Recorder → record the flow → Export → JSON. Paste it here. Typed
        passwords move to the Password field.
      </p>
      <textarea
        rows={4}
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        placeholder='{"title": "…", "steps": [ … ]}'
        className="border-line-2 bg-panel text-ink focus:border-brand w-full rounded-[3px] border px-3 py-1.5 font-mono text-xs focus:outline-none"
      />
      <div className="flex items-center gap-2">
        <Button
          type="button"
          onClick={() => {
            try {
              const r = fromRecorder(text);
              onImport({
                steps: JSON.stringify(r.steps, null, 1),
                target: r.target,
                secrets: r.secrets,
              });
              setNote({
                bad: false,
                text:
                  `${r.steps.length} steps imported.` +
                  (r.skipped.length ? ` Skipped: ${r.skipped.join(", ")}.` : ""),
              });
              setText("");
            } catch (e) {
              setNote({ bad: true, text: (e as Error).message });
            }
          }}
        >
          Import
        </Button>
        <Button type="button" onClick={() => setOpen(false)}>
          Close
        </Button>
      </div>
      {note && <p className={note.bad ? "text-bad text-xs" : "text-ink-2 text-xs"}>{note.text}</p>}
    </div>
  );
}
