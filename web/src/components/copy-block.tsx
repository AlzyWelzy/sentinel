"use client";

import { useState } from "react";

/** A command or secret in a small terminal window, with a copy button. */
export function CopyBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="overflow-hidden rounded-[3px] bg-plate text-plate-ink">
      <div className="flex items-center gap-1.5 border-b border-plate-ink/15 px-3 py-1.5">
        <span className="font-plate text-[12px] font-semibold tracking-[0.12em] uppercase opacity-60">
          Command
        </span>
        <button
          type="button"
          onClick={async () => {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
          className="ml-auto rounded-[2px] border border-plate-ink/30 px-2 py-0.5 text-xs font-medium transition-[transform,background-color] duration-150 hover:bg-plate-ink/10 active:scale-[0.97]"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed ">{text}</pre>
    </div>
  );
}
