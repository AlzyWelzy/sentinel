"use client";

import Link from "next/link";

import { useSession } from "@/lib/session";

/** "Open dashboard" when signed in, sign-in links otherwise. */
export function SiteAccountLink() {
  const { status } = useSession();
  if (status === "signed-in")
    return (
      <Link
        href="/overview"
        className="rounded-[10px] bg-gradient-brand px-3.5 py-1.5 font-medium text-white shadow-glow transition hover:brightness-110"
      >
        Open dashboard
      </Link>
    );
  return (
    <>
      <Link href="/login" className="rounded-lg px-3 py-1.5 text-ink-2 transition hover:text-ink">
        Sign in
      </Link>
      <Link
        href="/signup"
        className="rounded-[10px] bg-gradient-brand px-3.5 py-1.5 font-medium text-white shadow-glow transition hover:brightness-110"
      >
        Start monitoring
      </Link>
    </>
  );
}
