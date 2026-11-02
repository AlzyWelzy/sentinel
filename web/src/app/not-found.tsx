import Link from "next/link";

import { Icon, Logo } from "@/components/icons";

export default function NotFound() {
  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden px-4">
      <div className="bg-grid mask-fade pointer-events-none absolute inset-0" />
      <div className="pointer-events-none absolute top-[-160px] left-1/2 h-[420px] w-[720px] -translate-x-1/2 rounded-full bg-[radial-gradient(closest-side,color-mix(in_srgb,var(--brand)_20%,transparent),transparent)]" />
      <div className="relative animate-rise text-center">
        <Link href="/" className="inline-flex items-center gap-2.5">
          <Logo className="size-8" />
          <span className="text-lg font-semibold tracking-tight">Sentinel</span>
        </Link>
        <p className="mt-12 font-mono text-sm text-brand">404</p>
        <h1 className="mt-2 text-4xl font-semibold tracking-[-0.03em]">
          This page isn&apos;t here
        </h1>
        <p className="mx-auto mt-3 max-w-sm text-ink-2">
          The address may be mistyped, or the page was moved or removed.
        </p>
        <div className="mt-8 flex justify-center gap-3">
          <Link
            href="/overview"
            className="inline-flex h-10 items-center gap-2 rounded-xl bg-gradient-brand px-5 text-sm font-medium text-white shadow-glow transition hover:brightness-110"
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
