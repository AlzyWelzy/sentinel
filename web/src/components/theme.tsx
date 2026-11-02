"use client";

import { useSyncExternalStore } from "react";

type Mode = "light" | "dark" | "system";
const listeners = new Set<() => void>();

function readMode(): Mode {
  try {
    return (localStorage.getItem("pg.theme") as Mode | null) ?? "system";
  } catch {
    return "system";
  }
}

function subscribe(fn: () => void) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Light, dark or the system's; remembered per browser. */
export function ThemeToggle() {
  const mode = useSyncExternalStore(subscribe, readMode, (): Mode => "system");
  function apply(next: Mode) {
    try {
      if (next === "system") localStorage.removeItem("pg.theme");
      else localStorage.setItem("pg.theme", next);
    } catch {
      // Not remembered; applies to this page.
    }
    const dark =
      next === "dark" || (next === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
    for (const fn of listeners) fn();
  }
  const next = mode === "system" ? "light" : mode === "light" ? "dark" : "system";
  return (
    <button
      type="button"
      onClick={() => apply(next)}
      className="rounded-md px-2 py-1 text-xs text-ink-3 hover:bg-panel-2 hover:text-ink"
      title="Theme"
    >
      Theme: {mode}
    </button>
  );
}

/** Runs before paint so the page doesn't flash the wrong theme. */
export const themeScript = `(function(){try{var t=localStorage.getItem("pg.theme");var d=t==="dark"||(!t&&matchMedia("(prefers-color-scheme: dark)").matches);if(d)document.documentElement.classList.add("dark")}catch(e){}})()`;
