"use client";

import { useEffect, useSyncExternalStore } from "react";

type Toast = { id: number; text: string };
let toasts: Toast[] = [];
let next = 1;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((fn) => fn());

/** Show a short error message at the bottom of the screen. */
export function toastError(text: string) {
  toasts = [...toasts.slice(-2), { id: next++, text }];
  emit();
}

function dismiss(id: number) {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

const subscribe = (fn: () => void) => {
  listeners.add(fn);
  return () => listeners.delete(fn);
};

export function Toasts() {
  const list = useSyncExternalStore(
    subscribe,
    () => toasts,
    () => toasts,
  );
  useEffect(() => {
    if (!list.length) return;
    const t = setTimeout(() => dismiss(list[0]!.id), 6000);
    return () => clearTimeout(t);
  }, [list]);
  return (
    <div
      aria-live="polite"
      className="fixed inset-x-0 bottom-4 z-50 flex flex-col items-center gap-2 px-4"
    >
      {list.map((t) => (
        <div
          key={t.id}
          role="alert"
          className="flex max-w-lg items-start gap-3 animate-rise rounded-xl border border-bad/30 bg-panel px-4 py-3 text-sm text-bad shadow-pop"
        >
          <span className="flex-1">{t.text}</span>
          <button
            type="button"
            onClick={() => dismiss(t.id)}
            className="text-ink-3 hover:text-ink"
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
