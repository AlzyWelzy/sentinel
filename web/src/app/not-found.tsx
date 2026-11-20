import Link from "next/link";

import { Icon, Logo } from "@/components/icons";

export default function NotFound() {
  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden px-4">
      <div className="relative text-center">
        <Link href="/" className="inline-flex items-center gap-2.5">
          <Logo className="size-8" />
          <span className="font-plate text-2xl font-bold tracking-[0.12em] uppercase">
            Sentinel
          </span>
        </Link>
        <p className="mt-12 font-mono text-sm text-bad">404 · circuit not found</p>
        <h1 className="mt-2 font-plate text-5xl leading-none font-bold uppercase">
          This page isn&apos;t here
        </h1>
        <p className="mx-auto mt-3 max-w-sm text-ink-2">
          The address may be mistyped, or the page was moved or removed.
        </p>
        <div className="mt-8 flex justify-center gap-3">
          <Link
            href="/overview"
            className="plate h-10 gap-2 px-5 text-[15px] transition-transform duration-150 active:scale-[0.97]"
          >
            Open dashboard
            <Icon name="arrow" />
          </Link>
          <Link
            href="/"
            className="inline-flex h-10 items-center rounded-xl border border-line bg-panel px-5 text-sm font-medium shadow-card"
          >
            Home
          </Link>
        </div>
      </div>
    </main>
  );
}
