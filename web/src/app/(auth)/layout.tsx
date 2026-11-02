import Link from "next/link";

import { Icon, Logo } from "@/components/icons";

const POINTS = [
  "Install in one command on Linux, BSD, Windows or Docker",
  "Alerts that name the disk, plugin or check that failed",
  "One email when a whole rack drops, not forty",
];

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_minmax(0,560px)]">
      <aside className="relative hidden overflow-hidden border-r border-line bg-[#07080d] text-white lg:flex lg:flex-col lg:justify-between lg:p-12">
        <div className="pointer-events-none absolute -top-40 -left-40 size-[620px] rounded-full bg-[radial-gradient(closest-side,rgb(139_112_255/0.35),transparent)]" />
        <div className="pointer-events-none absolute -right-32 -bottom-48 size-[560px] rounded-full bg-[radial-gradient(closest-side,rgb(34_211_238/0.22),transparent)]" />
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40 [--ink:#fff]" />
        <Link href="/" className="relative flex items-center gap-2.5">
          <Logo className="size-8" />
          <span className="text-lg font-semibold tracking-tight">Sentinel</span>
        </Link>
        <div className="relative max-w-md">
          <h2 className="text-4xl leading-[1.1] font-semibold tracking-[-0.03em]">
            Quiet when it&apos;s fine.
            <br />
            <span className="bg-gradient-to-r from-[#a796ff] to-[#5ee6f6] bg-clip-text text-transparent">
              Loud when it isn&apos;t.
            </span>
          </h2>
          <ul className="mt-8 space-y-3.5 text-[15px] text-white/70">
            {POINTS.map((p) => (
              <li key={p} className="flex gap-3">
                <span className="mt-0.5 grid size-5 shrink-0 place-items-center rounded-full bg-white/10 text-[#5ee6f6]">
                  <Icon name="check" className="size-3" />
                </span>
                {p}
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-sm text-white/40">sentinel.rajpoot.app</p>
      </aside>
      <main className="relative flex flex-col items-center justify-center px-4 py-12 sm:px-8">
        <div className="bg-grid mask-fade pointer-events-none absolute inset-x-0 top-0 h-80 lg:hidden" />
        <Link href="/" className="relative mb-10 flex items-center gap-2.5 lg:hidden">
          <Logo className="size-8" />
          <span className="text-lg font-semibold tracking-tight">Sentinel</span>
        </Link>
        <div className="relative w-full max-w-sm animate-rise [&_h1]:text-2xl [&_h1]:tracking-[-0.02em]">
          {children}
        </div>
      </main>
    </div>
  );
}
