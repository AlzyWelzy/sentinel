import Link from "next/link";
import type { ReactNode } from "react";

import { SiteAccountLink } from "@/components/site-account";

export function SiteHeader() {
  return (
    <header className="border-b border-line bg-panel">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <span className="inline-block size-5 rounded-md bg-brand" aria-hidden />
          Sentinel
        </Link>
        <nav className="flex items-center gap-4 text-sm">
          <Link href="/help" className="text-ink-2 hover:text-ink">
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
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-6 text-sm text-ink-3">
        <span>© {new Date().getFullYear()} Sentinel</span>
        <nav className="flex gap-4">
          <Link href="/help" className="hover:text-ink">
            Guide
          </Link>
          <Link href="/privacy" className="hover:text-ink">
            Privacy
          </Link>
          <Link href="/terms" className="hover:text-ink">
            Terms
          </Link>
          <a href="mailto:ops@rajpoot.app" className="hover:text-ink">
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
      <main className="mx-auto max-w-3xl px-4 py-12">
        <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
        {updated && <p className="mt-2 text-sm text-ink-3">Last updated {updated}</p>}
        <div className="prose-sentinel mt-8 space-y-4 text-[15px] leading-relaxed text-ink-2 [&_code]:rounded [&_code]:bg-panel-2 [&_code]:px-1 [&_code]:font-mono [&_code]:text-[13px] [&_h2]:mt-10 [&_h2]:text-lg [&_h2]:font-semibold [&_h2]:text-ink [&_h3]:mt-6 [&_h3]:font-semibold [&_h3]:text-ink [&_li]:ml-5 [&_li]:list-disc [&_pre]:overflow-x-auto [&_pre]:rounded-lg [&_pre]:border [&_pre]:border-line [&_pre]:bg-panel-2 [&_pre]:p-3 [&_pre]:font-mono [&_pre]:text-[13px] [&_a]:text-brand">
          {children}
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
