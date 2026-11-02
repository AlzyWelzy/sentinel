"use client";

import Link from "next/link";

import { useSession } from "@/lib/session";

/** "Open dashboard" when signed in, sign-in links otherwise. */
export function SiteAccountLink() {
  const { status } = useSession();
  if (status === "signed-in")
    return (
      <Link href="/overview" className="rounded-lg bg-brand px-3 py-1.5 font-medium text-brand-ink">
        Open dashboard
      </Link>
    );
  return (
    <>
      <Link href="/login" className="text-ink-2 hover:text-ink">
        Sign in
      </Link>
      <Link href="/signup" className="rounded-lg bg-brand px-3 py-1.5 font-medium text-brand-ink">
        Start monitoring
      </Link>
    </>
  );
}
