"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import {
  Badge,
  Button,
  Card,
  ErrorState,
  Loading,
  Notice,
  PageHeader,
  Table,
  cx,
} from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { dateTime } from "@/lib/format";
import { unwrap } from "@/lib/queries";
import { useMe } from "@/lib/session";

declare global {
  interface Window {
    Razorpay?: new (opts: Record<string, unknown>) => { open: () => void };
  }
}

const CHECKOUT = "https://checkout.razorpay.com/v1/checkout.js";

function loadCheckout(): Promise<void> {
  if (window.Razorpay) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = CHECKOUT;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("Razorpay Checkout didn't load"));
    document.head.appendChild(s);
  });
}

const LIMITS: [key: "hosts" | "checks" | "status_pages" | "members", label: string][] = [
  ["hosts", "Servers and devices"],
  ["checks", "Uptime checks"],
  ["status_pages", "Status pages"],
  ["members", "Members"],
];

const money = (n: number, currency: string) =>
  n === 0
    ? "Free"
    : `${new Intl.NumberFormat("en-IN", { style: "currency", currency, maximumFractionDigits: 0 }).format(n)}/month`;

export default function BillingPage() {
  const qc = useQueryClient();
  const me = useMe();
  const owner = me.data?.role === "owner";
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  const q = useQuery({
    queryKey: ["billing"],
    queryFn: async () => unwrap(await api.GET("/v1/billing")),
  });

  const subscribe = useMutation({
    mutationFn: async (plan: "pro" | "business") => {
      const sub = unwrap(await api.POST("/v1/billing/subscribe", { body: { plan } }));
      await loadCheckout();
      await new Promise<void>((resolve, reject) => {
        const rz = new window.Razorpay!({
          key: sub.key_id,
          subscription_id: sub.subscription_id,
          name: "Sentinel",
          description: `${sub.name} plan`,
          prefill: { email: sub.email ?? undefined },
          theme: { color: "#2563eb" },
          handler: () => resolve(),
          modal: { ondismiss: () => reject(new Error("Payment window closed")) },
        });
        rz.open();
      });
    },
    onSuccess: () => {
      setMsg({
        tone: "ok",
        text: "Payment received. Your plan changes as soon as Razorpay confirms it, usually within a minute.",
      });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["billing"] }), 5000);
    },
    onError: (e) => setMsg({ tone: "bad", text: errorText(e) }),
  });

  const cancel = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/billing/cancel")),
    onSuccess: () => {
      setMsg({
        tone: "ok",
        text: "Cancelled. The plan stays until the end of the period you've paid for.",
      });
      qc.invalidateQueries({ queryKey: ["billing"] });
    },
    onError: (e) => setMsg({ tone: "bad", text: errorText(e) }),
  });

  return (
    <>
      <PageHeader
        title="Billing"
        subtitle="Your organisation's plan, what it includes and what you use."
      />
      {q.isLoading ? (
        <Loading />
      ) : q.error ? (
        <ErrorState message={errorText(q.error)} retry={() => q.refetch()} />
      ) : (
        q.data && (
          <div className="space-y-6">
            {msg && <Notice tone={msg.tone}>{msg.text}</Notice>}
            {!q.data.enabled && (
              <Notice>
                Plans aren&apos;t switched on for this Sentinel yet, so nothing is limited.
              </Notice>
            )}
            <Card title="Current plan">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-lg font-semibold">{q.data.plan.name}</span>
                <Badge
                  tone={
                    q.data.plan_status === "active"
                      ? "ok"
                      : q.data.plan_status === "past_due"
                        ? "warn"
                        : "idle"
                  }
                >
                  {q.data.plan_status.replace("_", " ")}
                </Badge>
                {q.data.renews_at && (
                  <span className="text-ink-3 text-sm">Renews {dateTime(q.data.renews_at)}</span>
                )}
                {owner && q.data.subscribed && (
                  <Button
                    className="ml-auto"
                    loading={cancel.isPending}
                    onClick={() => {
                      if (confirm("Cancel the subscription at the end of this period?"))
                        cancel.mutate();
                    }}
                  >
                    Cancel subscription
                  </Button>
                )}
              </div>
              {q.data.plan_status === "past_due" && (
                <p className="text-warn mt-2 text-sm">
                  The last payment didn&apos;t go through. Razorpay retries it; update the card in
                  the email Razorpay sent you.
                </p>
              )}
            </Card>
            <Card title="Usage" pad={false}>
              <Table>
                <thead>
                  <tr>
                    <th>What</th>
                    <th className="text-right">Used</th>
                    <th className="text-right">Included</th>
                  </tr>
                </thead>
                <tbody>
                  {LIMITS.map(([k, label]) => {
                    const limit = q.data.plan.limits[k] as number | null;
                    const used = q.data.usage[k] ?? 0;
                    return (
                      <tr key={k}>
                        <td>{label}</td>
                        <td
                          className={cx(
                            "text-right tabular",
                            limit != null && used >= limit && "text-bad font-medium",
                          )}
                        >
                          {used}
                        </td>
                        <td className="text-right tabular">{limit ?? "No limit"}</td>
                      </tr>
                    );
                  })}
                  <tr>
                    <td>IPDR evidence</td>
                    <td />
                    <td className="text-right">{q.data.plan.limits.ipdr ? "Included" : "—"}</td>
                  </tr>
                </tbody>
              </Table>
            </Card>
            <div className="grid gap-4 md:grid-cols-3">
              {q.data.plans.map((p) => {
                const current = p.id === q.data.plan.id;
                return (
                  <Card key={p.id} title={p.name}>
                    <div className="text-xl font-semibold">
                      {money(p.price_monthly, q.data.currency)}
                    </div>
                    <p className="text-ink-3 mt-1 text-sm">{p.blurb}</p>
                    <ul className="mt-3 space-y-1 text-sm">
                      {LIMITS.map(([k, label]) => (
                        <li key={k}>
                          {(p.limits[k] as number | null) ?? "Unlimited"} {label.toLowerCase()}
                        </li>
                      ))}
                      <li>{p.limits.ipdr ? "IPDR evidence collection" : "No IPDR"}</li>
                    </ul>
                    <div className="mt-4">
                      {current ? (
                        <Badge tone="ok">Your plan</Badge>
                      ) : p.buyable && owner && !q.data.subscribed ? (
                        <Button
                          variant="primary"
                          loading={subscribe.isPending && subscribe.variables === p.id}
                          onClick={() => {
                            setMsg(null);
                            subscribe.mutate(p.id as "pro" | "business");
                          }}
                        >
                          Choose {p.name}
                        </Button>
                      ) : p.buyable && !owner ? (
                        <span className="text-ink-3 text-sm">The owner can change the plan.</span>
                      ) : null}
                    </div>
                  </Card>
                );
              })}
            </div>
          </div>
        )
      )}
    </>
  );
}
