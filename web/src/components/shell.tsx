"use client";

import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { Icon, Logo, type IconName } from "@/components/icons";
import { ThemeToggle } from "@/components/theme";
import { Loading, cx } from "@/components/ui";
import { endImpersonation, isImpersonating, signOut, signedOutOnPurpose } from "@/lib/api/client";
import { orgName, useMe, useOrgs, useSession } from "@/lib/session";

type Item = { href: string; label: string; icon: IconName };

const NAV: { title: string; items: Item[] }[] = [
  {
    title: "Monitor",
    items: [
      { href: "/overview", label: "Overview", icon: "overview" },
      { href: "/servers", label: "Servers", icon: "servers" },
      { href: "/network", label: "Network", icon: "network" },
      { href: "/fleet", label: "Fleet wall", icon: "fleet" },
      { href: "/checks", label: "Uptime checks", icon: "checks" },
      { href: "/logs", label: "Logs", icon: "logs" },
      { href: "/apm", label: "APM", icon: "apm" },
    ],
  },
  {
    title: "Respond",
    items: [
      { href: "/incidents", label: "Incidents", icon: "incidents" },
      { href: "/rules", label: "Alert rules", icon: "rules" },
      { href: "/oncall", label: "On-call", icon: "oncall" },
      { href: "/maintenance", label: "Maintenance", icon: "maintenance" },
    ],
  },
  {
    title: "Share",
    items: [
      { href: "/status-pages", label: "Status pages", icon: "status" },
      { href: "/dashboards", label: "Dashboards", icon: "dashboards" },
      { href: "/reports", label: "Reports", icon: "reports" },
      { href: "/insights", label: "Insights", icon: "insights" },
    ],
  },
];
const SETTINGS: Item[] = [
  { href: "/settings/contacts", label: "Contacts", icon: "contacts" },
  { href: "/settings/organisation", label: "Organisation", icon: "organisation" },
  { href: "/settings/tokens", label: "API tokens", icon: "tokens" },
  { href: "/settings/audit", label: "Audit log", icon: "audit" },
  { href: "/settings", label: "Your account", icon: "account" },
];

function NavLink({ href, label, icon, onClick }: Item & { onClick?: () => void }) {
  const path = usePathname();
  const active = path === href || path.startsWith(`${href}/`);
  const exact = href === "/settings" ? path === "/settings" : active;
  return (
    <Link
      href={href}
      onClick={onClick}
      aria-current={exact ? "page" : undefined}
      className={cx(
        "group relative flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[13px] transition",
        exact
          ? "bg-panel-2 font-medium text-ink shadow-card"
          : "text-ink-2 hover:bg-panel-2/70 hover:text-ink",
      )}
    >
      {exact && (
        <span className="absolute top-1.5 bottom-1.5 -left-3 w-[3px] rounded-r-full bg-gradient-brand" />
      )}
      <Icon
        name={icon}
        className={cx(
          "size-4 shrink-0",
          exact ? "text-brand" : "text-ink-3 group-hover:text-ink-2",
        )}
      />
      {label}
    </Link>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5">
      <p className="px-2.5 pb-1.5 text-[10.5px] font-semibold tracking-[0.12em] text-ink-3 uppercase">
        {title}
      </p>
      {children}
    </div>
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
      className="h-10 w-full truncate rounded-xl border border-line bg-panel-2 px-2.5 text-sm font-medium shadow-card transition hover:border-line-2"
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
    // An expired session comes back to this page after signing in; signing
    // out on purpose doesn't.
    if (status === "signed-out")
      router.replace(signedOutOnPurpose() ? "/login" : `/login?next=${encodeURIComponent(path)}`);
  }, [status, path, router]);

  if (status !== "signed-in") return <Loading />;

  const close = () => setOpen(false);
  const initial = (user.name || user.email).slice(0, 1).toUpperCase();
  const sidebar = (
    <nav className="flex h-full flex-col gap-5 overflow-y-auto px-4 py-5">
      <Link href="/overview" className="flex items-center gap-2.5 px-1">
        <Logo className="size-7" />
        <span className="text-[15px] font-semibold tracking-tight">Sentinel</span>
      </Link>
      <OrgSwitcher />
      {NAV.map((group) => (
        <Section key={group.title} title={group.title}>
          {group.items.map((n) => (
            <NavLink key={n.href} {...n} onClick={close} />
          ))}
        </Section>
      ))}
      <Section title="Settings">
        {SETTINGS.map((n) => (
          <NavLink key={n.href} {...n} onClick={close} />
        ))}
        {user.superadmin && !isImpersonating() && (
          <NavLink href="/admin" label="Superadmin" icon="shield" onClick={close} />
        )}
      </Section>
      <div className="mt-auto rounded-xl border border-line bg-panel-2/60 p-2.5">
        <div className="flex items-center gap-2.5">
          <span className="grid size-8 shrink-0 place-items-center rounded-full bg-gradient-brand text-xs font-semibold text-white">
            {initial}
          </span>
          <p className="min-w-0 flex-1 truncate text-xs text-ink-2" title={user.email}>
            {user.email}
          </p>
        </div>
        <div className="mt-2 flex items-center justify-between">
          <ThemeToggle />
          <button
            type="button"
            className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-ink-3 transition hover:bg-panel hover:text-ink"
            onClick={async () => {
              await signOut();
              qc.clear();
            }}
          >
            <Icon name="logout" className="size-3.5" />
            Sign out
          </button>
        </div>
      </div>
    </nav>
  );

  return (
    <div className="app-bg min-h-screen lg:grid lg:grid-cols-[248px_1fr]">
      <aside className="hidden border-r border-line bg-panel/70 backdrop-blur-xl lg:sticky lg:top-0 lg:block lg:h-screen">
        {sidebar}
      </aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
          <aside
            className="absolute inset-y-0 left-0 w-72 animate-rise border-r border-line bg-panel shadow-pop"
            onClick={(e) => e.stopPropagation()}
          >
            {sidebar}
          </aside>
        </div>
      )}
      <div className="min-w-0">
        <div className="sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-panel/80 px-4 py-2.5 backdrop-blur-xl lg:hidden">
          <button
            type="button"
            onClick={() => setOpen(true)}
            className="grid size-9 place-items-center rounded-lg border border-line text-ink-2"
            aria-label="Menu"
          >
            <Icon name="menu" />
          </button>
          <Logo className="size-6" />
          <span className="font-semibold tracking-tight">Sentinel</span>
        </div>
        {me.data?.impersonating && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-warn/25 bg-warn/10 px-4 py-2 text-sm text-warn">
            <span>
              Superadmin view of <b>{me.data.display_name ?? me.data.email}</b>
              {me.data.impersonation_writes ? " · changes allowed" : " · read-only"}
            </span>
            <button
              type="button"
              className="font-medium underline"
              onClick={async () => {
                await endImpersonation();
                qc.clear();
                router.push("/admin");
              }}
            >
              Leave
            </button>
          </div>
        )}
        <main className="mx-auto max-w-[1360px] px-4 py-8 sm:px-6 lg:px-10 lg:py-10">
          {children}
        </main>
      </div>
    </div>
  );
}
