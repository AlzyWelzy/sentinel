"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Button, Card, Notice } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { unwrap } from "@/lib/queries";

function b64ToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const raw = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function deviceLabel(): string {
  const ua = navigator.userAgent;
  const os = /iPhone|iPad/.test(ua)
    ? "iPhone/iPad"
    : /Android/.test(ua)
      ? "Android"
      : /Mac/.test(ua)
        ? "Mac"
        : /Windows/.test(ua)
          ? "Windows"
          : "Linux";
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : "Safari";
  return `${browser} on ${os}`;
}

const supported = () =>
  typeof window !== "undefined" &&
  "serviceWorker" in navigator &&
  "PushManager" in window &&
  "Notification" in window;

/** Alerts as notifications on this phone or computer, with Acknowledge on
 * them (public/sw.js). On iPhone, Safari allows it only once Sentinel is
 * added to the Home Screen. */
export function DevicePush() {
  const qc = useQueryClient();
  const [override, setState] = useState<"on" | "denied" | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const cfg = useQuery({
    queryKey: ["push-config"],
    queryFn: async () => unwrap(await api.GET("/v1/channels/push/config")),
  });
  const device = useQuery({
    queryKey: ["push-device"],
    queryFn: async (): Promise<"on" | "off" | "denied" | "unsupported"> => {
      if (!supported()) return "unsupported";
      if (Notification.permission === "denied") return "denied";
      try {
        const reg = await navigator.serviceWorker.register("/sw.js");
        return (await reg.pushManager.getSubscription()) ? "on" : "off";
      } catch {
        return "off";
      }
    },
  });
  const state = override ?? device.data ?? "unknown";

  if (!cfg.data?.enabled) return null;

  const turnOn = async () => {
    setBusy(true);
    setErr(null);
    try {
      if ((await Notification.requestPermission()) !== "granted") {
        setState("denied");
        return;
      }
      const reg = await navigator.serviceWorker.register("/sw.js");
      await navigator.serviceWorker.ready;
      const sub =
        (await reg.pushManager.getSubscription()) ??
        (await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: b64ToBytes(cfg.data.public_key),
        }));
      const json = sub.toJSON() as { endpoint: string; keys: { p256dh: string; auth: string } };
      unwrap(
        await api.POST("/v1/channels/push", {
          body: {
            endpoint: json.endpoint,
            keys: json.keys,
            label: deviceLabel(),
            min_severity: "info",
          },
        }),
      );
      setState("on");
      qc.invalidateQueries({ queryKey: ["channels"] });
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const ios = typeof navigator !== "undefined" && /iPhone|iPad/.test(navigator.userAgent);
  const standalone =
    typeof window !== "undefined" && window.matchMedia("(display-mode: standalone)").matches;

  return (
    <Card title="Notifications on this device" className="mb-6">
      {state === "unsupported" ? (
        <p className="text-ink-3 text-sm">
          {ios && !standalone
            ? "On iPhone and iPad: tap Share, then “Add to Home Screen”, open Sentinel from there and turn notifications on."
            : "This browser can't receive push notifications."}
        </p>
      ) : state === "denied" ? (
        <p className="text-ink-3 text-sm">
          Notifications are blocked for Sentinel in this browser. Allow them in the site settings,
          then come back here.
        </p>
      ) : state === "on" ? (
        <p className="text-sm">
          This device gets alerts as notifications, with <b>Acknowledge</b> on them. It&apos;s
          listed below as a contact; remove it there to stop.
        </p>
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-ink-3 text-sm">
            Get alerts on this phone or computer and acknowledge them from the notification.
          </p>
          <Button variant="primary" loading={busy} onClick={turnOn}>
            Turn on notifications
          </Button>
        </div>
      )}
      {err && (
        <div className="mt-3">
          <Notice tone="bad">{err}</Notice>
        </div>
      )}
    </Card>
  );
}
