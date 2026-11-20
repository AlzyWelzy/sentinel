"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cx } from "@/components/ui";

const TABS = [
  { href: "/network", label: "Devices" },
  { href: "/network/topology", label: "Topology" },
  { href: "/network/bandwidth", label: "Bandwidth" },
  { href: "/network/credentials", label: "Credentials" },
];

export function NetworkTabs() {
  const path = usePathname();
  return (
    <nav className="mb-6 flex max-w-full min-w-0 gap-1 overflow-x-auto border-b border-line">
      {TABS.map((t) => {
        const active = t.href === "/network" ? path === "/network" : path.startsWith(t.href);
        return (
          <Link
            key={t.href}
            href={t.href}
            className={cx(
              "-mb-px border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap transition",
              active ? "border-brand text-ink" : "border-transparent text-ink-2 hover:text-ink",
            )}
          >
            {t.label}
          </Link>
        );
      })}
    </nav>
  );
}
