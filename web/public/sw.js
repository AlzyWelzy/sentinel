// Sentinel's service worker: shows alerts pushed by the alerter
// (alerter/push.go) and acknowledges them from the notification itself
// through the signed one-click link (no sign-in needed). Nothing is cached:
// a monitoring console must show what's true now.

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let p = {};
  try {
    p = event.data ? event.data.json() : {};
  } catch {
    p = { title: "Sentinel", body: event.data ? event.data.text() : "" };
  }
  const actions = [];
  if (p.ack_url && !p.resolved) actions.push({ action: "ack", title: "Acknowledge" });
  actions.push({ action: "open", title: "Open" });
  event.waitUntil(
    self.registration.showNotification(p.title || "Sentinel", {
      body: p.body || "",
      tag: p.tag || undefined,
      renotify: Boolean(p.tag) && !p.resolved,
      requireInteraction: p.severity === "critical" && !p.resolved,
      icon: "/icons/icon-192.png",
      badge: "/icons/badge-96.png",
      data: { url: p.url || "/incidents", ack: p.ack_url || null },
      actions,
    }),
  );
});

async function focusOrOpen(url) {
  const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  for (const c of all) {
    if (new URL(c.url).origin === self.location.origin && "focus" in c) {
      await c.navigate(url).catch(() => {});
      return c.focus();
    }
  }
  return self.clients.openWindow(url);
}

self.addEventListener("notificationclick", (event) => {
  const n = event.notification;
  const { url, ack } = n.data || {};
  n.close();
  if (event.action === "ack" && ack) {
    event.waitUntil(
      fetch(ack, { method: "POST", credentials: "omit" })
        .then((r) =>
          self.registration.showNotification(r.ok ? "Acknowledged" : "Couldn't acknowledge", {
            body: r.ok ? n.title : "Open Sentinel to acknowledge it there.",
            tag: n.tag || undefined,
            icon: "/icons/icon-192.png",
            badge: "/icons/badge-96.png",
            data: { url },
          }),
        )
        .catch(() => focusOrOpen(url || "/incidents")),
    );
    return;
  }
  event.waitUntil(focusOrOpen(url || "/incidents"));
});
