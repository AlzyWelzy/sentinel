import Link from "next/link";
import type { ReactNode } from "react";

import { Logo } from "@/components/icons";
import { SiteAccountLink } from "@/components/site-account";

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-line/70 bg-bg/70 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5">
          <Logo className="size-7" />
          <span className="text-[15px] font-semibold tracking-tight">Sentinel</span>
        </Link>
        <nav className="flex items-center gap-1 text-sm sm:gap-2">
          <Link
            href="/#features"
            className="hidden rounded-lg px-3 py-1.5 text-ink-2 transition hover:text-ink sm:block"
          >
            Features
          </Link>
          <Link
            href="/help"
            className="rounded-lg px-3 py-1.5 text-ink-2 transition hover:text-ink"
          >
            Guide
          </Link>
          <SiteAccountLink />
        </nav>
      </div>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-10 text-sm text-ink-3 sm:px-6">
        <div className="flex items-center gap-2.5">
          <Logo className="size-5" />
          <span>© {new Date().getFullYear()} Sentinel</span>
        </div>
        <nav className="flex gap-5">
          <Link href="/help" className="transition hover:text-ink">
            Guide
          </Link>
          <Link href="/privacy" className="transition hover:text-ink">
            Privacy
          </Link>
          <Link href="/terms" className="transition hover:text-ink">
            Terms
          </Link>
          <a href="mailto:ops@rajpoot.app" className="transition hover:text-ink">
            Contact
          </a>
        </nav>
      </div>
    </footer>
  );
}

/** A long-form page (terms, privacy, the guide). */
export function Prose({
  title,
  updated,
  children,
}: {
  title: string;
  updated?: string;
  children: ReactNode;
}) {
  return (
    <>
      <SiteHeader />
      <div className="relative">
        <div className="bg-grid mask-fade pointer-events-none absolute inset-x-0 top-0 h-72" />
        <main className="relative mx-auto max-w-3xl px-4 pt-16 pb-20 sm:px-6">
          <h1 className="text-4xl font-semibold tracking-[-0.03em]">{title}</h1>
          {updated && <p className="mt-3 text-sm text-ink-3">Last updated {updated}</p>}
          <div className="mt-10 space-y-4 text-[15px] leading-7 text-ink-2 [&_a]:font-medium [&_a]:text-brand [&_a]:underline-offset-4 hover:[&_a]:underline [&_b]:font-semibold [&_b]:text-ink [&_code]:rounded-md [&_code]:border [&_code]:border-line [&_code]:bg-panel-2 [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:font-mono [&_code]:text-[13px] [&_code]:text-ink [&_h2]:mt-12 [&_h2]:border-t [&_h2]:border-line [&_h2]:pt-8 [&_h2]:text-xl [&_h2]:font-semibold [&_h2]:tracking-tight [&_h2]:text-ink [&_h3]:mt-6 [&_h3]:font-semibold [&_h3]:text-ink [&_li]:ml-5 [&_li]:list-disc [&_li]:pl-1 [&_li::marker]:text-brand [&_pre]:overflow-x-auto [&_pre]:rounded-xl [&_pre]:border [&_pre]:border-white/5 [&_pre]:bg-[#0b0d16] [&_pre]:p-4 [&_pre]:font-mono [&_pre]:text-[13px] [&_pre]:text-[#d7dbf0] [&_pre_code]:border-0 [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_pre_code]:text-inherit">
            {children}
          </div>
        </main>
      </div>
      <SiteFooter />
    </>
  );
}
