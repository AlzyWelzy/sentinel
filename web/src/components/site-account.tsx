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
        className="plate rounded-[3px] px-3.5 py-1.5 text-[15px] transition-transform duration-150 active:scale-[0.97]"
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
        className="plate rounded-[3px] px-3.5 py-1.5 text-[15px] transition-transform duration-150 active:scale-[0.97]"
      >
        Start monitoring
      </Link>
    </>
  );
}
