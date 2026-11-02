"use client";

import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { ThemeToggle } from "@/components/theme";
import { Loading, cx } from "@/components/ui";
import { isImpersonating, setImpersonation, signOut } from "@/lib/api/client";
import { orgName, useMe, useOrgs, useSession } from "@/lib/session";

const NAV = [
  { href: "/overview", label: "Overview" },
  { href: "/servers", label: "Servers" },
  { href: "/incidents", label: "Incidents" },
  { href: "/rules", label: "Alert rules" },
  { href: "/checks", label: "Uptime checks" },
  { href: "/oncall", label: "On-call" },
  { href: "/maintenance", label: "Maintenance" },
  { href: "/status-pages", label: "Status pages" },
  { href: "/logs", label: "Logs" },
  { href: "/apm", label: "APM" },
  { href: "/dashboards", label: "Dashboards" },
  { href: "/reports", label: "Reports" },
  { href: "/insights", label: "Insights" },
];
const SETTINGS = [
  { href: "/settings/contacts", label: "Contacts" },
  { href: "/settings/organisation", label: "Organisation" },
  { href: "/settings/tokens", label: "API tokens" },
  { href: "/settings/audit", label: "Audit log" },
  { href: "/settings", label: "Your account" },
];

function NavLink({ href, label, onClick }: { href: string; label: string; onClick?: () => void }) {
  const path = usePathname();
  const active = path === href || path.startsWith(`${href}/`);
  const exact = href === "/settings" ? path === "/settings" : active;
  return (
    <Link
      href={href}
      onClick={onClick}
      className={cx(
        "block rounded-md px-2.5 py-1.5 text-sm",
        exact ? "bg-panel-2 font-medium text-ink" : "text-ink-2 hover:bg-panel-2 hover:text-ink",
      )}
    >
      {label}
    </Link>
  );
}

function OrgSwitcher() {
  const orgs = useOrgs();
  const router = useRouter();
  if (isImpersonating()) return null;
  if (orgs.loading || !orgs.selected) return <div className="h-9" />;
  return (
    <select
      aria-label="Organisation"
      value={orgs.selected.tenant_id}
      onChange={(e) => {
        if (e.target.value === "__new") router.push("/settings/organisation?new=1");
        else orgs.select(e.target.value);
      }}
      className="h-9 w-full truncate rounded-lg border border-line bg-panel px-2 text-sm font-medium"
    >
      {orgs.list.map((o) => (
        <option key={o.tenant_id} value={o.tenant_id}>
          {orgName(o)}
        </option>
      ))}
      <option value="__new">+ New organisation</option>
    </select>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { status, user } = useSession();
  const router = useRouter();
  const path = usePathname();
  const qc = useQueryClient();
  const me = useMe();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (status === "signed-out") router.replace(`/login?next=${encodeURIComponent(path)}`);
  }, [status, path, router]);

  if (status !== "signed-in") return <Loading />;

  const sidebar = (
    <nav className="flex h-full flex-col gap-6 p-4">
      <Link href="/overview" className="flex items-center gap-2 px-1 font-semibold">
        <span className="inline-block size-5 rounded-md bg-brand" aria-hidden />
        Sentinel
      </Link>
      <OrgSwitcher />
      <div className="space-y-0.5">
        {NAV.map((n) => (
          <NavLink key={n.href} {...n} onClick={() => setOpen(false)} />
        ))}
      </div>
      <div className="space-y-0.5">
        <p className="px-2.5 pb-1 text-xs font-medium tracking-wide text-ink-3 uppercase">
          Settings
        </p>
        {SETTINGS.map((n) => (
          <NavLink key={n.href} {...n} onClick={() => setOpen(false)} />
        ))}
        {user.superadmin && !isImpersonating() && (
          <NavLink href="/admin" label="Superadmin" onClick={() => setOpen(false)} />
        )}
      </div>
      <div className="mt-auto space-y-2 border-t border-line pt-4">
        <p className="truncate px-1 text-xs text-ink-3" title={user.email}>
          {user.email}
        </p>
        <div className="flex items-center justify-between">
          <ThemeToggle />
          <button
            type="button"
            className="rounded-md px-2 py-1 text-xs text-ink-3 hover:bg-panel-2 hover:text-ink"
            onClick={async () => {
              await signOut();
              qc.clear();
              router.replace("/login");
            }}
          >
            Sign out
          </button>
        </div>
      </div>
    </nav>
  );

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[232px_1fr]">
      <aside className="hidden border-r border-line bg-panel lg:sticky lg:top-0 lg:block lg:h-screen">
        {sidebar}
      </aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-black/30" />
          <aside
            className="absolute inset-y-0 left-0 w-64 border-r border-line bg-panel"
            onClick={(e) => e.stopPropagation()}
          >
            {sidebar}
          </aside>
        </div>
      )}
      <div className="min-w-0">
        <div className="flex items-center gap-3 border-b border-line bg-panel px-4 py-2.5 lg:hidden">
          <button
            type="button"
            onClick={() => setOpen(true)}
            className="rounded-md border border-line px-2 py-1 text-sm"
            aria-label="Menu"
          >
            Menu
          </button>
          <span className="font-semibold">Sentinel</span>
        </div>
        {me.data?.impersonating && (
          <div className="flex flex-wrap items-center justify-between gap-2 bg-warn/15 px-4 py-2 text-sm text-warn">
            <span>
              Superadmin view of <b>{me.data.display_name ?? me.data.email}</b>
              {me.data.impersonation_writes ? " · changes allowed" : " · read-only"}
            </span>
            <button
              type="button"
              className="font-medium underline"
              onClick={() => {
                setImpersonation(null);
                qc.clear();
                router.push("/admin");
              }}
            >
              Leave
            </button>
          </div>
        )}
        <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
